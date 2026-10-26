"""Commit witness v0720: positive, negative-first, RPC, key trust and CAS tests."""
import hashlib
import multiprocessing
import time
import os
import shutil
import sqlite3
import tempfile
import threading
import unittest
from contextlib import closing
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from anchor_protocol import AnchorHold, MemoryCASAnchor, CoordinatedStore, position_for_genesis
from state_store import StateStore, prepare_update
from external_commit_witness_v0720 import issue_final_checkpoint
from external_commit_witness_v0720 import (CommitWitnessLedger,CommitWitnessServer,
    CommitWitnessClient,CommitGatedWriterCore)
from writer_service_v0714 import STATUS,SET,ZERO_REQUEST


def _child_commit_service(db,socket_path,signing_key,attester_key,seal,deploy):
    ledger=CommitWitnessLedger(db,signing_key=signing_key,attester_public_key=attester_key,
        seal_key=seal,deployment_id=deploy)
    with CommitWitnessServer(socket_path,ledger) as server:
        server.serve_forever(poll_interval=.01)

KEY=b'k'*32;DEPLOY='commit-v0720-research';REVIEW=b'R'*32;SEAL=b'S'*32
class CommitWitnessTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.base=Path(temp.name);self.db=self.base/'store.db'
        self.store=StateStore.create(self.db,key=KEY,initial=b'genesis',journal_mode='DELETE')
        self.genesis=position_for_genesis(self.store)
        self.genesis_backup=self.base/'genesis.db';shutil.copyfile(self.db,self.genesis_backup)
        self.anchor=MemoryCASAnchor(self.genesis,reviewer_key=REVIEW)
        self.co=CoordinatedStore(self.store,self.anchor)
        self.signer=Ed25519PrivateKey.generate();self.observer=Ed25519PrivateKey.generate()
        self.rogue=Ed25519PrivateKey.generate()
        self.dir=self.base/'witness';self.dir.mkdir(mode=0o700)
        self.path=self.dir/'commits.db';self.sock=self.dir/'commit.sock'
        self.ledger=CommitWitnessLedger.bootstrap(self.path,self.genesis,signing_key=self.signer,
            attester_public_key=self.observer.public_key(),seal_key=SEAL,deployment_id=DEPLOY)
        self.server=CommitWitnessServer(self.sock,self.ledger)
        self.thread=threading.Thread(target=self.server.serve_forever,kwargs={'poll_interval':0.01},daemon=True)
        self.thread.start();self.addCleanup(self.close)
        self.client=CommitWitnessClient(self.sock,public_key=self.signer.public_key())
    def close(self):self.server.shutdown();self.server.server_close();self.thread.join(timeout=2)
    def floor(self):return self.client.floor(deployment_id=DEPLOY,store_id=self.genesis.store_id)
    def prepare(self,body=b'next',rid=None):
        p,_=prepare_update(self.store,body,request_id=rid or os.urandom(16))
        self.co.apply(p)
        intent=self.anchor.status().pending
        return intent
    def finalize(self,intent):
        self.co.adjudicate('FINALIZE_COMMIT',self.anchor.test_only_review_token(intent,'FINALIZE_COMMIT'))
    def evidence(self,intent):
        return issue_final_checkpoint(store=self.store,anchor=self.anchor,intent=intent,
               deployment_id=DEPLOY,signing_key=self.observer)
    def publish(self,intent,evidence):return self.client.publish(intent,evidence)
    def test_bootstrap_committed_floor_at_genesis(self):
        self.assertEqual(self.floor()['version'],0)
        self.assertEqual(self.floor()['digest'],self.genesis.digest)
    def test_complete_commit_publish_then_guarded_read(self):
        i=self.prepare();self.finalize(i);self.publish(i,self.evidence(i))
        g=CommitGatedWriterCore(self.store,self.anchor,commit_witness=self.client,deployment_id=DEPLOY)
        self.assertEqual(g.dispatch(STATUS,ZERO_REQUEST,b'')['version'],1)
        self.assertTrue(g.dispatch(SET,bytes.fromhex(i.request_id),b'next')['already_committed'])
    def test_without_commit_publication_must_hold_even_if_anchor_matches(self):
        i=self.prepare();self.finalize(i)
        self.assertEqual(self.co.diagnose().code,'MATCH')
        with self.assertRaises(AnchorHold):
            CommitGatedWriterCore(self.store,self.anchor,commit_witness=self.client,deployment_id=DEPLOY)
    def test_no_checkpoint_before_anchor_finalization(self):
        from anchor_protocol import ReviewDenied
        i=self.prepare()
        with self.assertRaises(ReviewDenied):self.evidence(i)
        self.assertEqual(self.floor()['version'],0)
        self.finalize(i);self.publish(i,self.evidence(i))
        self.assertEqual(CommitGatedWriterCore(self.store,self.anchor,commit_witness=self.client,deployment_id=DEPLOY).dispatch(STATUS,ZERO_REQUEST,b'')['version'],1)
    def test_retransmission_idempotent_exact_same_evidence(self):
        i=self.prepare();self.finalize(i);e=self.evidence(i);a=self.publish(i,e);b=self.publish(i,e)
        self.assertEqual(a,b)
    def test_reject_publish_without_evidence(self):
        i=self.prepare();self.finalize(i)
        with self.assertRaises(AnchorHold):self.publish(i,{})
        self.assertEqual(self.floor()['version'],0)
    def test_reject_foreign_observer_signature(self):
        i=self.prepare();self.finalize(i);e=self.evidence(i)
        from external_commit_witness_v0720 import OBS_DOMAIN
        from commit_evidence_v0716 import _canonical
        e['signature']=self.rogue.sign(OBS_DOMAIN+_canonical(e['statement'])).hex()
        with self.assertRaises(AnchorHold):self.publish(i,e)
    def test_reject_modified_observation_after_signing(self):
        i=self.prepare();self.finalize(i);e=self.evidence(i);e['statement']['digest']='f'*64
        with self.assertRaises(AnchorHold):self.publish(i,e)
    def test_reject_skip_or_old_version_commit(self):
        i=self.prepare();self.finalize(i);e=self.evidence(i);self.publish(i,e)
        # After version 1 publication, replaying version 1 EXACT is idempotent,
        # not a path to another version, and a conflicting repeated request fails.
        from dataclasses import replace
        with self.assertRaises(AnchorHold):self.publish(replace(i,request_id='f'*32),e)
        self.assertEqual(self.floor()['version'],1)
    def test_two_commits_monotone_chain(self):
        i=self.prepare();self.finalize(i);self.publish(i,self.evidence(i))
        j=self.prepare(body=b'twice');self.finalize(j);self.publish(j,self.evidence(j))
        self.assertEqual(self.floor()['version'],2)
        self.assertEqual(self.floor()['digest'],j.digest)
    def test_mutation_in_remote_head_detected_by_seal(self):
        with closing(sqlite3.connect(self.path)) as db:
            db.execute('UPDATE commit_floor SET body=? WHERE id=1',(b'{}',));db.commit()
        with self.assertRaises(AnchorHold):self.floor()
    def test_mutation_of_signed_seal_detected(self):
        with closing(sqlite3.connect(self.path)) as db:
            db.execute('UPDATE commit_floor SET seal=? WHERE id=1',(b'X'*32,));db.commit()
        with self.assertRaises(AnchorHold):self.floor()
    def test_insert_extra_floor_row_detected(self):
        with closing(sqlite3.connect(self.path)) as db:
            row=db.execute('SELECT body,seal FROM commit_floor').fetchone()
            db.execute('DROP TABLE commit_floor')
            db.execute('CREATE TABLE commit_floor(id INTEGER PRIMARY KEY,body BLOB,seal BLOB)')
            db.executemany('INSERT INTO commit_floor VALUES(?,?,?)',[(1,*row),(2,*row)])
            db.commit()
        with self.assertRaises(AnchorHold):self.floor()
    def test_forged_witness_response_detected(self):
        wrong=CommitWitnessClient(self.sock,public_key=self.rogue.public_key())
        with self.assertRaises(AnchorHold):wrong.floor(deployment_id=DEPLOY,store_id=self.genesis.store_id)
    def test_replayed_witness_nonce_detected(self):
        saved=self.client._rpc({'op':'challenge','nonce':'0'*64})
        f=CommitWitnessClient(self.sock,public_key=self.signer.public_key());f._rpc=lambda req:saved
        with self.assertRaises(AnchorHold):f.floor(deployment_id=DEPLOY,store_id=self.genesis.store_id)
    def test_commit_witness_outage_must_hold(self):
        c=CommitWitnessClient(self.dir/'missing.sock',public_key=self.signer.public_key(),timeout=.1)
        with self.assertRaises(AnchorHold):CommitGatedWriterCore(self.store,self.anchor,commit_witness=c,deployment_id=DEPLOY)
    def test_store_and_anchor_joint_rollback_detected_when_witness_survives(self):
        i=self.prepare();self.finalize(i);self.publish(i,self.evidence(i))
        shutil.copyfile(self.genesis_backup,self.db)
        restored=StateStore(self.db,key=KEY,journal_mode='DELETE')
        old_anchor=MemoryCASAnchor(self.genesis,reviewer_key=REVIEW)
        self.assertEqual(CoordinatedStore(restored,old_anchor).diagnose().code,'MATCH')
        with self.assertRaises(AnchorHold):
            CommitGatedWriterCore(restored,old_anchor,commit_witness=self.client,deployment_id=DEPLOY)
    def test_joint_rollback_including_witness_still_possible(self):
        snap=self.base/'old-witness.db';shutil.copyfile(self.path,snap)
        i=self.prepare();self.finalize(i);self.publish(i,self.evidence(i))
        shutil.copyfile(self.genesis_backup,self.db);shutil.copyfile(snap,self.path)
        restored=StateStore(self.db,key=KEY,journal_mode='DELETE')
        old_anchor=MemoryCASAnchor(self.genesis,reviewer_key=REVIEW)
        # Deliberate falsification of a same-failure-domain deployment.
        g=CommitGatedWriterCore(restored,old_anchor,commit_witness=self.client,deployment_id=DEPLOY)
        self.assertEqual(g.dispatch(STATUS,ZERO_REQUEST,b'')['version'],0)
    def test_stale_signed_postfinal_checkpoint_cannot_prevent_later_rollback(self):
        i=self.prepare();self.finalize(i);e=self.evidence(i)
        shutil.copyfile(self.genesis_backup,self.db)
        # Attestation was true at signing time; state is now stale. The witness
        # cannot re-read SQLite, but the client's check must HOLD afterwards.
        self.publish(i,e)
        restored=StateStore(self.db,key=KEY,journal_mode='DELETE')
        old_anchor=MemoryCASAnchor(self.genesis,reviewer_key=REVIEW)
        with self.assertRaises(AnchorHold):
            CommitGatedWriterCore(restored,old_anchor,commit_witness=self.client,deployment_id=DEPLOY)

    def test_bootstrap_existing_witness_denied(self):
        with self.assertRaises(FileExistsError):
            CommitWitnessLedger.bootstrap(self.path,self.genesis,signing_key=self.signer,
                attester_public_key=self.observer.public_key(),seal_key=SEAL,deployment_id=DEPLOY)
    def test_wrong_attester_or_seal_on_reopen(self):
        with self.assertRaises(AnchorHold):CommitWitnessLedger(self.path,signing_key=self.signer,
            attester_public_key=self.rogue.public_key(),seal_key=SEAL,deployment_id=DEPLOY)
        with self.assertRaises(AnchorHold):CommitWitnessLedger(self.path,signing_key=self.signer,
            attester_public_key=self.observer.public_key(),seal_key=b'X'*32,deployment_id=DEPLOY)
    def test_actual_separate_os_process_serves_nonce_challenge(self):
        # Same host and same UID; process separation is NOT administrative independence.
        path=self.dir/'second.sock'
        ctx=multiprocessing.get_context('fork')
        proc=ctx.Process(target=_child_commit_service,args=(self.path,path,self.signer,
                         self.observer.public_key(),SEAL,DEPLOY))
        proc.start()
        try:
            c=CommitWitnessClient(path,public_key=self.signer.public_key(),timeout=.5)
            found=None
            for _ in range(60):
                if path.exists():
                    try:found=c.floor(deployment_id=DEPLOY,store_id=self.genesis.store_id);break
                    except AnchorHold:pass
                time.sleep(.02)
            self.assertIsNotNone(found)
            self.assertEqual(found['version'],0)
            self.assertNotEqual(proc.pid,os.getpid())
        finally:
            proc.terminate();proc.join(timeout=2)
            if proc.is_alive():proc.kill();proc.join()
        with self.assertRaises(AnchorHold):c.floor(deployment_id=DEPLOY,store_id=self.genesis.store_id)

    def test_unapproved_witness_signer_replacement_denied_on_reopen(self):
        with self.assertRaises(AnchorHold):
            CommitWitnessLedger(self.path,signing_key=self.rogue,
                attester_public_key=self.observer.public_key(),seal_key=SEAL,deployment_id=DEPLOY)

    def test_writer_default_without_witness_remains_unsafe_and_not_production(self):
        i=self.prepare();self.finalize(i)
        from anchored_writer_v0715 import AnchoredWriterCore
        core=AnchoredWriterCore(self.store,self.anchor)
        self.assertTrue(core.dispatch(STATUS,ZERO_REQUEST,b'')['ok'])
        # This is the historical research bypass; production may not expose it.

if __name__=='__main__':unittest.main()
