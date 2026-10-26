"""Fail-closed synthetic contract tests for the VOLATILE external anchor model."""
from __future__ import annotations

import concurrent.futures
import hashlib
import pathlib
import secrets
import sqlite3
import tempfile
import unittest
from contextlib import closing

from anchor_protocol import (AnchorHold, ReviewDenied, MemoryCASAnchor,
                             CoordinatedStore, Intent, Position, position_for_genesis)
from state_store import StateStore, IntegrityError, prepare_update


class AnchorProtocolTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path=pathlib.Path(self.tmp.name)/'db.sqlite'
        self.store=StateStore.create(self.path,key=secrets.token_bytes(32),initial=b'genesis')
        self.anchor=MemoryCASAnchor(position_for_genesis(self.store),reviewer_key=secrets.token_bytes(32))
        self.client=CoordinatedStore(self.store,self.anchor)

    def proposal(self,b=b'value'):
        return prepare_update(self.store,b)[0]

    def authorize(self,action):
        return self.anchor.test_only_review_token(self.anchor.status().pending,action)

    def finalize(self):
        return self.client.adjudicate('FINALIZE_COMMIT',self.authorize('FINALIZE_COMMIT'))

    def test_fresh_genesis_match(self):
        self.assertEqual(self.client.diagnose().code,'MATCH')
        self.assertEqual(self.client.read().value,b'genesis')

    def test_happy_commit_requires_separate_review(self):
        r=self.client.apply(self.proposal(b'hello'))
        self.assertEqual(r.version,1)
        self.assertEqual(self.client.diagnose().code,'COMMITTED_PENDING_HOLD')
        with self.assertRaises(AnchorHold): self.client.read()
        self.assertEqual(self.finalize().code,'MATCH')
        self.assertEqual(self.client.read().value,b'hello')

    def test_abort_prepared_before_commit_is_explicit(self):
        with self.assertRaises(AnchorHold):
            self.client.apply(self.proposal(b'v1'),fault=lambda stage: (_ for _ in ()).throw(OSError('injected')) if stage=='after_anchor_prepare' else None)
        self.assertEqual(self.client.diagnose().code,'NOT_COMMITTED_HOLD')
        self.client.adjudicate('ABORT_NOT_COMMITTED',self.authorize('ABORT_NOT_COMMITTED'))
        self.assertEqual(self.client.diagnose().code,'MATCH')
        self.assertEqual(self.store.read().version,0)

    def test_commit_gap_injection_then_manual_finalization(self):
        with self.assertRaises(AnchorHold):
            self.client.apply(self.proposal(b'after'),fault=lambda stage: (_ for _ in ()).throw(OSError('postcommit')) if stage=='after_sqlite_commit' else None)
        self.assertEqual(self.client.diagnose().code,'COMMITTED_PENDING_HOLD')
        self.assertEqual(self.finalize().code,'MATCH')

    def test_invalid_review_action_never_advances(self):
        self.client.apply(self.proposal())
        with self.assertRaises(ReviewDenied):
            self.client.adjudicate('ABORT_NOT_COMMITTED',self.authorize('ABORT_NOT_COMMITTED'))
        self.assertEqual(self.anchor.status().committed.version,0)

    def test_wrong_review_token_is_rejected(self):
        self.client.apply(self.proposal())
        with self.assertRaises(ReviewDenied):self.client.adjudicate('FINALIZE_COMMIT',b'x'*32)
        self.assertEqual(self.client.diagnose().code,'COMMITTED_PENDING_HOLD')

    def test_review_token_bound_to_specific_request(self):
        self.client.apply(self.proposal(b'one'))
        token=self.authorize('FINALIZE_COMMIT')
        self.finalize()
        self.client.apply(self.proposal(b'two'))
        with self.assertRaises(ReviewDenied):self.client.adjudicate('FINALIZE_COMMIT',token)
        self.assertEqual(self.anchor.status().committed.version,1)

    def test_pending_prevents_another_write(self):
        self.client.apply(self.proposal(b'one'))
        with self.assertRaises(AnchorHold):self.client.apply(self.proposal(b'two'))
        self.assertEqual(self.store.read().version,1)

    def test_raw_writer_ahead_blocks(self):
        self.store.apply(self.proposal(b'uncooperative'))
        self.assertEqual(self.client.diagnose().code,'DIVERGENCE_HOLD')
        with self.assertRaises(AnchorHold):self.client.apply(self.proposal(b'two'))

    def test_same_version_fork_detected(self):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('UPDATE head SET value=?, digest=? WHERE id=1',(b'fraud',hashlib.sha256(b'fraud').digest()))
        # Authenticated genesis now fails before anchor comparison.
        self.assertEqual(self.client.diagnose().code,'INVALID_DB_HOLD')

    def test_joint_db_rollback_after_anchor_advance_detected(self):
        self.client.apply(self.proposal(b'one'))
        self.finalize()
        older=pathlib.Path(self.tmp.name)/'old.sqlite'
        with closing(sqlite3.connect(self.path)) as src, closing(sqlite3.connect(older)) as dst:src.backup(dst)
        self.client.apply(self.proposal(b'two'))
        self.finalize()
        with closing(sqlite3.connect(older)) as src, closing(sqlite3.connect(self.path)) as dst:src.backup(dst)
        self.assertEqual(self.client.diagnose().code,'ROLLBACK_HOLD')

    def test_corrupt_receipt_chain_forces_hold(self):
        self.client.apply(self.proposal(b'one'))
        self.finalize()
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('UPDATE receipt_auth SET tag=? WHERE committed_version=1',(b'x'*32,))
        self.assertEqual(self.client.diagnose().code,'INVALID_DB_HOLD')

    def test_altered_proposal_hash_blocks_review(self):
        self.client.apply(self.proposal(b'one'))
        p=self.anchor.status().pending
        forged=Intent(p.store_id,p.base_version,p.base_digest,p.version,p.digest,p.request_id,'f'*64)
        with self.assertRaises(AnchorHold):self.anchor.adjudicate(forged,'FINALIZE_COMMIT',self.authorize('FINALIZE_COMMIT'))

    def test_stale_update_rejected_before_anchor_prepare(self):
        proposal=self.proposal(b'one')
        self.client.apply(proposal)
        self.finalize()
        with self.assertRaises(AnchorHold):self.client.apply(proposal)
        self.assertEqual(self.anchor.status().pending,None)

    def test_cas_rejects_concurrent_prepares(self):
        s=self.anchor.status().committed
        intent=Intent(s.store_id,0,s.digest,1,hashlib.sha256(b'new').hexdigest(),secrets.token_hex(16),'0'*64)
        def prepare():
            try:self.anchor.prepare(intent);return 'PASS'
            except AnchorHold:return 'HOLD'
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            results=list(ex.map(lambda _:prepare(),range(8)))
        self.assertEqual(results.count('PASS'),1)
        self.assertEqual(results.count('HOLD'),7)

    def test_inspect_request_is_coherent(self):
        p,rid=prepare_update(self.store,b'hello')
        self.client.apply(p)
        audit,snap=self.store.inspect_request(rid)
        self.assertEqual(audit['version'],snap.version)
        self.assertEqual(audit['request']['digest_sha256'],snap.digest.hex())
        self.assertEqual(audit['request']['proposal_hash'],hashlib.sha256(p).hexdigest())

    def test_missing_receipt_with_advanced_head_holds(self):
        self.client.apply(self.proposal(b'one'))
        with closing(sqlite3.connect(self.path)) as db, db:db.execute('DELETE FROM receipts')
        self.assertEqual(self.client.diagnose().code,'INVALID_DB_HOLD')

    def test_no_late_genesis(self):
        self.client.apply(self.proposal(b'one'))
        self.finalize()
        with self.assertRaises(AnchorHold): position_for_genesis(self.store)

    def test_write_after_abort_with_new_request(self):
        with self.assertRaises(AnchorHold):
            self.client.apply(self.proposal(b'never'),fault=lambda stage: (_ for _ in ()).throw(RuntimeError('x')) if stage=='after_anchor_prepare' else None)
        self.client.adjudicate('ABORT_NOT_COMMITTED',self.authorize('ABORT_NOT_COMMITTED'))
        self.client.apply(self.proposal(b'did'))
        self.finalize()
        self.assertEqual(self.client.read().value,b'did')

    def test_read_detects_db_advancing_between_anchor_and_snapshot(self):
        class RacyAnchor:
            def __init__(self, original, store): self.original=original; self.store=store; self.calls=0
            def status(self):
                state=self.original.status()
                self.calls+=1
                if self.calls==1:
                    self.store.apply(prepare_update(self.store,b'unanchored')[0])
                return state
        bad=CoordinatedStore(self.store,RacyAnchor(self.anchor,self.store))
        with self.assertRaises(AnchorHold):bad.read()

    def test_malformed_intent_does_not_create_pending(self):
        s=self.anchor.status().committed
        invalid=Intent(s.store_id,0,s.digest,1,'invalid',secrets.token_hex(16),'a'*64)
        with self.assertRaises(ValueError):self.anchor.prepare(invalid)
        self.assertIsNone(self.anchor.status().pending)

    def test_invalid_hex_genesis_rejected(self):
        with self.assertRaises(ValueError):
            MemoryCASAnchor(Position('not_hex_value___',0,'z'*64),reviewer_key=b'Q'*32)

    def test_negative_version_in_intent_rejected(self):
        s=self.anchor.status().committed
        bad=Intent(s.store_id,-1,s.digest,1,hashlib.sha256(b'new').hexdigest(),secrets.token_hex(16),'0'*64)
        with self.assertRaises(ValueError): self.anchor.prepare(bad)
        self.assertIsNone(self.anchor.status().pending)

    def test_boolean_version_does_not_pass_intent_type_check(self):
        s=self.anchor.status().committed
        bad=Intent(s.store_id,False,s.digest,1,hashlib.sha256(b'new').hexdigest(),secrets.token_hex(16),'0'*64)
        with self.assertRaises(ValueError): self.anchor.prepare(bad)
        self.assertIsNone(self.anchor.status().pending)

    def test_wrong_store_prepare_rejected(self):
        s=self.anchor.status().committed
        bad=Intent('e'*32,0,s.digest,1,hashlib.sha256(b'new').hexdigest(),secrets.token_hex(16),'0'*64)
        with self.assertRaises(AnchorHold): self.anchor.prepare(bad)
        self.assertIsNone(self.anchor.status().pending)

    def test_simulated_anchor_reset_cannot_establish_real_antirollback(self):
        # Explicit counterexample: when BOTH store and VOLATILE anchor reset,
        # the simulator sees an old valid genesis as fresh. A real external
        # monotonic anchor MUST be independently persistent and attest bootstrap.
        old=pathlib.Path(self.tmp.name)/'genesis-backup.sqlite'
        with closing(sqlite3.connect(self.path)) as src, closing(sqlite3.connect(old)) as dest:
            src.backup(dest)
        self.client.apply(self.proposal(b'second'))
        self.finalize()
        self.assertEqual(self.anchor.status().committed.version,1)
        with closing(sqlite3.connect(old)) as src, closing(sqlite3.connect(self.path)) as dst:
            src.backup(dst)
        reset_anchor=MemoryCASAnchor(position_for_genesis(self.store),reviewer_key=secrets.token_bytes(32))
        self.assertEqual(CoordinatedStore(self.store,reset_anchor).diagnose().code,'MATCH')
        self.assertEqual(self.client.diagnose().code,'ROLLBACK_HOLD')

if __name__=='__main__':unittest.main()
