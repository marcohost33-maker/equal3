"""Negative-first tests for the explicit anchor-before-commit writer path."""
from __future__ import annotations
import hashlib
import os
import secrets
import socket
import tempfile
import threading
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from anchor_protocol import AnchorHold, MemoryCASAnchor, position_for_genesis, CoordinatedStore
from anchor_wire import PersistentCASAnchor, RPCAnchor, _UnixAuthority, _Handler
from state_store import StateStore, ReplayError, IntegrityError
from writer_service_v0714 import STATUS, SET, ZERO_REQUEST, _Server, _Handler as WriterHandler, client_request
from anchored_writer_v0715 import AnchoredWriterCore, WriterError

KEY=b'S'*32
REVIEW=b'R'*32
SEAL=b'A'*32
RPC_KEY=b'P'*32

class AnchoredWriterTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.home=Path(temp.name)
        self.db=self.home/'store.db'
        self.store=StateStore.create(self.db,key=KEY,initial=b'old',journal_mode='DELETE')
        self.anchor=MemoryCASAnchor(position_for_genesis(self.store),reviewer_key=REVIEW)
        self.core=AnchoredWriterCore(self.store,self.anchor)
        self.rid=b'Z'*16

    def _finalize(self):
        p=self.anchor.status().pending
        token=self.anchor.test_only_review_token(p,'FINALIZE_COMMIT')
        return CoordinatedStore(self.store,self.anchor).adjudicate('FINALIZE_COMMIT',token)

    def test_happy_path_requires_out_of_band_review(self):
        r=self.core.dispatch(SET,self.rid,b'new')
        self.assertFalse(r['ok'])
        self.assertEqual(r['assessment'],'COMMITTED_PENDING_HOLD')
        self.assertEqual(r['error'],'EXTERNAL_REVIEW_REQUIRED')
        self.assertEqual(self.core.dispatch(STATUS,ZERO_REQUEST,b'')['assessment'],'COMMITTED_PENDING_HOLD')
        self.assertEqual(self.core.dispatch(SET,self.rid,b'new')['ok'],False)
        self.assertEqual(self.store.read().version,1)
        self.assertEqual(self.anchor.status().committed.version,0)
        self.assertEqual(self._finalize().code,'MATCH')
        again=self.core.dispatch(SET,self.rid,b'new')
        self.assertTrue(again['ok']);self.assertTrue(again['already_committed'])
        self.assertEqual(self.core.dispatch(STATUS,ZERO_REQUEST,b'')['version'],1)

    def test_new_request_holds_while_previous_pending(self):
        self.core.dispatch(SET,self.rid,b'new')
        r=self.core.dispatch(SET,b'Y'*16,b'newer')
        self.assertFalse(r['ok']);self.assertEqual(self.store.read().version,1)

    def test_replay_forged_target_refused_after_review(self):
        self.core.dispatch(SET,self.rid,b'new');self._finalize()
        with self.assertRaises(ReplayError):self.core.dispatch(SET,self.rid,b'wrong')

    def test_restart_keeps_pending_not_auto_finalized(self):
        self.core.dispatch(SET,self.rid,b'new')
        newstore=StateStore(self.db,key=KEY,journal_mode='DELETE')
        newcore=AnchoredWriterCore(newstore,self.anchor)
        self.assertFalse(newcore.dispatch(SET,self.rid,b'new')['ok'])
        self.assertEqual(self.anchor.status().committed.version,0)

    def test_unauthorized_review_has_no_public_writer_route(self):
        self.core.dispatch(SET,self.rid,b'new')
        with self.assertRaises(WriterError):self.core.dispatch(4,self.rid,b'')
        self.assertIsNotNone(self.anchor.status().pending)

    def test_different_store_and_anchor_refused(self):
        other=StateStore.create(self.home/'other.db',key=KEY,initial=b'old',journal_mode='DELETE')
        c=AnchoredWriterCore(other,self.anchor)
        self.assertEqual(c.dispatch(STATUS,ZERO_REQUEST,b'')['assessment'],'FORK_HOLD')
        self.assertFalse(c.dispatch(SET,self.rid,b'new')['ok'])

    def test_raw_write_bypass_is_identified_and_held(self):
        from state_store import prepare_update
        p,_=prepare_update(self.store,b'raw')
        self.store.apply(p)
        result=self.core.dispatch(SET,self.rid,b'new')
        self.assertFalse(result['ok']);self.assertEqual(result['assessment'],'DIVERGENCE_HOLD')

    def test_corrupt_authenticated_history_denies_response(self):
        self.core.dispatch(SET,self.rid,b'new');self._finalize()
        with closing(self.store._db()) as db,db:
            db.execute('UPDATE receipts SET digest=? WHERE request_id=?',(b'x'*32,self.rid))
        self.assertFalse(self.core.dispatch(SET,self.rid,b'new')['ok'])
        self.assertEqual(self.core.dispatch(STATUS,ZERO_REQUEST,b'')['assessment'],'INVALID_DB_HOLD')

    def test_writer_rejects_legacy_wal(self):
        other=StateStore.create(self.home/'wal.db',key=KEY,initial=b'old')
        with self.assertRaisesRegex(WriterError,'DELETE'):
            AnchoredWriterCore(other,self.anchor)

    def test_status_rejects_noncanonical(self):
        with self.assertRaises(WriterError):self.core.dispatch(STATUS,self.rid,b'')
        with self.assertRaises(WriterError):self.core.dispatch(STATUS,ZERO_REQUEST,b'n')

    def test_zero_rid_rejected(self):
        with self.assertRaises(WriterError):self.core.dispatch(SET,ZERO_REQUEST,b'a')

    def test_no_commit_when_authority_unavailable(self):
        class Unavailable:
            def status(self):raise AnchorHold('unavailable')
        c=AnchoredWriterCore.__new__(AnchoredWriterCore)
        c._coordinator=CoordinatedStore(self.store,Unavailable());c._lock=threading.RLock()
        with self.assertRaises(AnchorHold):c.dispatch(SET,self.rid,b'new')
        self.assertEqual(self.store.read().version,0)

    def test_lost_prepare_response_stays_held(self):
        class CommitThenLose:
            def __init__(self,b):self.b=b;self.once=True
            def status(self):return self.b.status()
            def prepare(self,i):
                self.b.prepare(i)
                if self.once:self.once=False;raise AnchorHold('reply dropped after prepared')
        wrapped=CommitThenLose(self.anchor)
        c=AnchoredWriterCore(self.store,wrapped)
        r=c.dispatch(SET,self.rid,b'new')
        self.assertFalse(r['ok']);self.assertEqual(r['assessment'],'NOT_COMMITTED_HOLD')
        self.assertEqual(self.store.read().version,0)

    def test_network_timeout_after_sqlite_commit_does_not_report_success(self):
        class LostStatus:
            def __init__(self,a):self.a=a;self.once=False
            def status(self):
                if self.once:self.once=False;raise AnchorHold('temporary timeout')
                return self.a.status()
            def prepare(self,i):return self.a.prepare(i)
        anchor=LostStatus(self.anchor)
        c=AnchoredWriterCore(self.store,anchor)
        # Failure after SQLite commit at the final diagnostic: injection into store.
        original=self.store.apply
        def patched(p):
            receipt=original(p)
            anchor.once=True
            return receipt
        with patch.object(self.store,'apply',side_effect=patched):
            r=c.dispatch(SET,self.rid,b'new')
        self.assertFalse(r['ok']);self.assertEqual(r['assessment'],'COMMITTED_PENDING_HOLD')
        self.assertEqual(self.anchor.status().committed.version,0)

    def test_manual_abort_only_when_no_sqlite_commit(self):
        from state_store import prepare_update
        p,_=prepare_update(self.store,b'new',request_id=self.rid)
        def crash(stage):
            if stage=='after_anchor_prepare':raise OSError('test kill')
        with self.assertRaises(AnchorHold):
            CoordinatedStore(self.store,self.anchor).apply(p,fault=crash)
        self.assertEqual(self.core.dispatch(SET,self.rid,b'new')['assessment'],'NOT_COMMITTED_HOLD')
        token=self.anchor.test_only_review_token(self.anchor.status().pending,'ABORT_NOT_COMMITTED')
        self.assertEqual(CoordinatedStore(self.store,self.anchor).adjudicate('ABORT_NOT_COMMITTED',token).code,'MATCH')
        self.assertEqual(self.core.dispatch(SET,self.rid,b'new')['assessment'],'COMMITTED_PENDING_HOLD')


    def test_anchor_unreachable_live_socket_fail_closed(self):
        class Unreachable:
            def status(self):raise AnchorHold('partition')
        # Force the service request to experience remote loss after boot.
        core=AnchoredWriterCore(self.store,self.anchor)
        core._coordinator.anchor=Unreachable()
        sock_path=str(self.home/'dead-anchor.sock')
        with _Server(sock_path,WriterHandler) as svr:
            svr.core=core;svr.writer_uid=os.geteuid()
            t=threading.Thread(target=svr.serve_forever,kwargs={'poll_interval':.02},daemon=True);t.start()
            try:
                response=client_request(sock_path,op=SET,request_id=self.rid,target=b'new')
                self.assertEqual(response,{'ok':False,'error':'HOLD'})
                self.assertEqual(self.store.read().version,0)
            finally:svr.shutdown();t.join(2)

    def test_remote_reviewer_bad_approval_never_unlocks(self):
        self.core.dispatch(SET,self.rid,b'new')
        from anchor_protocol import ReviewDenied
        with self.assertRaises(ReviewDenied):
            CoordinatedStore(self.store,self.anchor).adjudicate('FINALIZE_COMMIT',b'x'*32)
        self.assertFalse(self.core.dispatch(STATUS,ZERO_REQUEST,b'')['ok'])
        self.assertEqual(self.anchor.status().committed.version,0)

    def test_remote_reviewer_wrong_decision_blocked(self):
        self.core.dispatch(SET,self.rid,b'new')
        token=self.anchor.test_only_review_token(self.anchor.status().pending,'ABORT_NOT_COMMITTED')
        from anchor_protocol import ReviewDenied
        with self.assertRaises(ReviewDenied):
            CoordinatedStore(self.store,self.anchor).adjudicate('ABORT_NOT_COMMITTED',token)
        self.assertEqual(self.store.read().version,1)
        self.assertEqual(self.anchor.status().committed.version,0)

    def test_duplicate_id_during_pending_does_not_commit_twice(self):
        r=self.core.dispatch(SET,self.rid,b'new')
        for _ in range(8):
            retry=self.core.dispatch(SET,self.rid,b'new')
            self.assertFalse(retry['ok'])
        self.assertEqual(self.store.read().version,1)
        self.assertEqual(self.anchor.status().committed.version,0)

    def test_bad_rpc_writer_key_does_not_change_any_state(self):
        anchorpath=self.home/'anchor2';anchorpath.mkdir(mode=0o700)
        db=anchorpath/'anchor.db'
        PersistentCASAnchor.bootstrap(db,position_for_genesis(self.store),reviewer_key=REVIEW,seal_key=SEAL)
        backend=PersistentCASAnchor(db,reviewer_key=REVIEW,seal_key=SEAL)
        sock=str(self.home/'authority2.sock')
        with _UnixAuthority(sock,_Handler) as server:
            server.backend=backend;server.writer_uid=os.geteuid();server.writer_key=RPC_KEY
            thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.02},daemon=True);thread.start()
            try:
                bad=RPCAnchor(sock,writer_key=b'X'*32)
                with self.assertRaises(AnchorHold):AnchoredWriterCore(self.store,bad)
                self.assertEqual(backend.status().committed.version,0)
                self.assertEqual(self.store.read().version,0)
            finally:server.shutdown();thread.join(2)

    def test_live_writer_socket_returns_hold_until_review(self):
        sock_path=str(self.home/'writer.sock')
        with _Server(sock_path,WriterHandler) as svr:
            svr.core=self.core;svr.writer_uid=os.geteuid()
            t=threading.Thread(target=svr.serve_forever,kwargs={'poll_interval':.02},daemon=True);t.start()
            try:
                r=client_request(sock_path,op=SET,request_id=self.rid,target=b'new')
                self.assertFalse(r['ok']);self.assertEqual(r['error'],'EXTERNAL_REVIEW_REQUIRED')
                self.assertFalse(client_request(sock_path,op=STATUS)['ok'])
                self._finalize()
                self.assertTrue(client_request(sock_path,op=SET,request_id=self.rid,target=b'new')['ok'])
            finally:svr.shutdown();t.join(2)


    def test_joint_local_rollback_still_undetectable_without_independent_anchor(self):
        """A documented NO-GO counterexample, not a passing security assertion."""
        import shutil,hmac
        from anchor_protocol import _review_message
        anchor_dir=self.home/'joint-anchor';anchor_dir.mkdir(mode=0o700)
        live=anchor_dir/'authority.db'
        PersistentCASAnchor.bootstrap(live,position_for_genesis(self.store),reviewer_key=REVIEW,seal_key=SEAL)
        anchor=PersistentCASAnchor(live,reviewer_key=REVIEW,seal_key=SEAL)
        coord=CoordinatedStore(self.store,anchor)
        core=AnchoredWriterCore(self.store,anchor)
        def one(rid,payload):
            result=core.dispatch(SET,rid,payload)
            self.assertEqual(result['assessment'],'COMMITTED_PENDING_HOLD')
            intent=anchor.status().pending
            token=hmac.new(REVIEW,_review_message(intent,'FINALIZE_COMMIT'),hashlib.sha256).digest()
            self.assertEqual(coord.adjudicate('FINALIZE_COMMIT',token).code,'MATCH')
        one(b'1'*16,b'first')
        snap_state=self.home/'older-state.bin'
        snap_anchor=self.home/'older-anchor.bin'
        shutil.copy2(self.db,snap_state);shutil.copy2(live,snap_anchor)
        one(b'2'*16,b'second')
        self.assertEqual(anchor.status().committed.version,2)
        # Authorized service was stopped/offline for a hypothetical joint restore.
        shutil.copy2(snap_state,self.db);shutil.copy2(snap_anchor,live)
        # Neither same-domain HMAC nor monotonic counter is hardware anchored;
        # pair rollback restores a previously genuine MATCH at version 1.
        restored_store=StateStore(self.db,key=KEY,journal_mode='DELETE')
        restored_anchor=PersistentCASAnchor(live,reviewer_key=REVIEW,seal_key=SEAL)
        self.assertEqual(CoordinatedStore(restored_store,restored_anchor).diagnose().code,'MATCH')
        self.assertEqual(restored_anchor.status().committed.version,1)

    def test_persistent_remote_anchor_with_authenticated_rpc(self):
        # Simulated separate authority with durable sealed DB and MAC-signed RPC.
        # Test-only same-UID topology is NOT a real OS trust-domain split.
        anchorpath=self.home/'anchor'
        anchorpath.mkdir(mode=0o700)
        db=anchorpath/'anchor.db'
        PersistentCASAnchor.bootstrap(db,position_for_genesis(self.store),reviewer_key=REVIEW,seal_key=SEAL)
        backend=PersistentCASAnchor(db,reviewer_key=REVIEW,seal_key=SEAL)
        sock=str(self.home/'authority.sock')
        with _UnixAuthority(sock,_Handler) as server:
            server.backend=backend;server.writer_uid=os.geteuid();server.writer_key=RPC_KEY
            thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.02},daemon=True);thread.start()
            try:
                rpc=RPCAnchor(sock,writer_key=RPC_KEY)
                w=AnchoredWriterCore(self.store,rpc)
                r=w.dispatch(SET,self.rid,b'remote')
                self.assertEqual(r['assessment'],'COMMITTED_PENDING_HOLD')
                self.assertEqual(backend.status().committed.version,0)
                p=backend.status().pending
                from anchor_protocol import _review_message
                import hmac
                token=hmac.new(REVIEW,_review_message(p,'FINALIZE_COMMIT'),hashlib.sha256).digest()
                CoordinatedStore(self.store,rpc).adjudicate('FINALIZE_COMMIT',token)
                self.assertTrue(w.dispatch(SET,self.rid,b'remote')['ok'])
                # Reopen durable anchor, simulate restart.
                self.assertEqual(PersistentCASAnchor(db,reviewer_key=REVIEW,seal_key=SEAL).status().committed.version,1)
            finally:server.shutdown();thread.join(2)
