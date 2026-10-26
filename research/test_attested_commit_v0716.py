"""Negative-first attested external approval tests; RESEARCH ONLY."""
from __future__ import annotations
from copy import deepcopy
from contextlib import closing
import hashlib
import hmac
import tempfile
import threading
import time
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from anchor_protocol import CoordinatedStore, AnchorHold, ReviewDenied, Intent, _review_message, position_for_genesis
from anchor_wire import PersistentCASAnchor, _UnixAuthority, _Handler, RPCAnchor
from anchored_writer_v0715 import AnchoredWriterCore
from writer_service_v0714 import SET
from state_store import StateStore, prepare_update
from commit_evidence_v0716 import (EvidenceRequiredCASAnchor, issue_observation,
                                   verify_observation)

KEY=b'K'*32;REVIEW=b'R'*32;SEAL=b'S'*32;RPC_KEY=b'P'*32
DEPLOY='equal3-lab-0716'

class AttestedCommitTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
        self.dir=Path(t.name);self.db=self.dir/'db.sqlite'
        self.store=StateStore.create(self.db,key=KEY,initial=b'init',journal_mode='DELETE')
        self.key=Ed25519PrivateKey.generate();self.trusted=self.key.public_key()
        self.wrong=Ed25519PrivateKey.generate()
        parent=self.dir/'anchor';parent.mkdir(mode=0o700)
        self.anchor=EvidenceRequiredCASAnchor.bootstrap(parent/'db.sqlite',position_for_genesis(self.store),
            reviewer_key=REVIEW,seal_key=SEAL,attester_public_key=self.trusted,deployment_id=DEPLOY)
        self.core=AnchoredWriterCore(self.store,self.anchor)
        self.rid=b'J'*16

    def prepare(self, *, apply=True, body=b'new'):
        if apply:
            result=self.core.dispatch(SET,self.rid,body)
            self.assertFalse(result['ok'])
        else:
            proposal,_=prepare_update(self.store,body,request_id=self.rid)
            info,snap=self.store.read_verified()
            intent=Intent(info['store_id'],snap.version,snap.digest.hex(),snap.version+1,
                          hashlib.sha256(body).hexdigest(),self.rid.hex(),hashlib.sha256(proposal).hexdigest())
            self.anchor.prepare(intent)
        return self.anchor.status().pending

    def token(self,intent,decision):
        return hmac.new(REVIEW,_review_message(intent,decision),hashlib.sha256).digest()

    def observation(self,intent,decision,**kwargs):
        return issue_observation(store=self.store,anchor=self.anchor,intent=intent,
                                 decision=decision, deployment_id=DEPLOY,signing_key=self.key,**kwargs)

    def test_original_persistent_anchor_accepts_review_with_no_commit(self):
        # Actual v0.7.15 vulnerability reproduced as an explicit negative control.
        legacy_dir=self.dir/'legacy';legacy_dir.mkdir(mode=0o700)
        unsafe=PersistentCASAnchor.bootstrap(legacy_dir/'anchor.db',position_for_genesis(self.store),reviewer_key=REVIEW,seal_key=SEAL)
        original,_=prepare_update(self.store,b'forged',request_id=self.rid)
        i,s=self.store.read_verified()
        intent=Intent(i['store_id'],s.version,s.digest.hex(),1,hashlib.sha256(b'forged').hexdigest(),
                      self.rid.hex(),hashlib.sha256(original).hexdigest())
        unsafe.prepare(intent)
        unsafe.adjudicate(intent,'FINALIZE_COMMIT',self.token(intent,'FINALIZE_COMMIT'))
        self.assertEqual(unsafe.status().committed.version,1)
        self.assertEqual(self.store.read().version,0)  # no actual SQLite commit

    def test_attested_anchor_refuses_token_without_observation(self):
        i=self.prepare(apply=False)
        with self.assertRaises(ReviewDenied):
            self.anchor.adjudicate(i,'FINALIZE_COMMIT',self.token(i,'FINALIZE_COMMIT'))
        self.assertEqual(self.anchor.status().committed.version,0)
        self.assertIsNotNone(self.anchor.status().pending)

    def test_cannot_issue_commit_observation_without_commit(self):
        i=self.prepare(apply=False)
        with self.assertRaises(ReviewDenied):self.observation(i,'FINALIZE_COMMIT')
        self.assertEqual(self.anchor.status().committed.version,0)

    def test_full_commit_positive_with_signed_attestation(self):
        i=self.prepare()
        evidence=self.observation(i,'FINALIZE_COMMIT')
        r=CoordinatedStore(self.store,self.anchor).adjudicate('FINALIZE_COMMIT',self.token(i,'FINALIZE_COMMIT'),evidence=evidence)
        self.assertEqual(r.code,'MATCH')
        self.assertTrue(self.core.dispatch(SET,self.rid,b'new')['ok'])
        self.assertEqual(self.anchor.status().committed.version,1)

    def test_valid_reviewer_token_wrong_attester_signer_rejected(self):
        i=self.prepare()
        ev=issue_observation(store=self.store,anchor=self.anchor,intent=i,decision='FINALIZE_COMMIT',
                             deployment_id=DEPLOY,signing_key=self.wrong)
        with self.assertRaises(ReviewDenied):
            self.anchor.adjudicate(i,'FINALIZE_COMMIT',self.token(i,'FINALIZE_COMMIT'),evidence=ev)
        self.assertEqual(self.anchor.status().committed.version,0)

    def test_expired_evidence_rejected(self):
        i=self.prepare();ev=self.observation(i,'FINALIZE_COMMIT',now=int(time.time())-100)
        with self.assertRaises(ReviewDenied):
            self.anchor.adjudicate(i,'FINALIZE_COMMIT',self.token(i,'FINALIZE_COMMIT'),evidence=ev)

    def test_future_evidence_rejected(self):
        i=self.prepare();ev=self.observation(i,'FINALIZE_COMMIT',now=int(time.time())+100)
        with self.assertRaises(ReviewDenied):
            self.anchor.adjudicate(i,'FINALIZE_COMMIT',self.token(i,'FINALIZE_COMMIT'),evidence=ev)

    def test_wrong_deployment_rejected_even_with_valid_signature(self):
        i=self.prepare()
        ev=issue_observation(store=self.store,anchor=self.anchor,intent=i,decision='FINALIZE_COMMIT',
                             deployment_id='another-site',signing_key=self.key)
        with self.assertRaises(ReviewDenied):
            self.anchor.adjudicate(i,'FINALIZE_COMMIT',self.token(i,'FINALIZE_COMMIT'),evidence=ev)

    def test_tampered_statement_rejected(self):
        i=self.prepare();ev=self.observation(i,'FINALIZE_COMMIT');ev=deepcopy(ev)
        ev['statement']['observed_digest']='f'*64
        with self.assertRaises(ReviewDenied):
            self.anchor.adjudicate(i,'FINALIZE_COMMIT',self.token(i,'FINALIZE_COMMIT'),evidence=ev)

    def test_tampered_signature_rejected(self):
        i=self.prepare();ev=self.observation(i,'FINALIZE_COMMIT')
        ev['signature']='0'*128
        with self.assertRaises(ReviewDenied):
            self.anchor.adjudicate(i,'FINALIZE_COMMIT',self.token(i,'FINALIZE_COMMIT'),evidence=ev)

    def test_unknown_json_field_rejected(self):
        i=self.prepare();ev=self.observation(i,'FINALIZE_COMMIT')
        ev['statement']['new_field']='downgrade'
        with self.assertRaises(ReviewDenied):
            self.anchor.adjudicate(i,'FINALIZE_COMMIT',self.token(i,'FINALIZE_COMMIT'),evidence=ev)

    def test_wrong_request_intent_rejected(self):
        i=self.prepare();ev=self.observation(i,'FINALIZE_COMMIT')
        tampered=Intent(i.store_id,i.base_version,i.base_digest,i.version,i.digest,(b'x'*16).hex(),i.proposal_hash)
        with self.assertRaises(ReviewDenied):
            self.anchor.adjudicate(tampered,'FINALIZE_COMMIT',self.token(tampered,'FINALIZE_COMMIT'),evidence=ev)

    def test_observer_refuses_abort_after_real_commit(self):
        i=self.prepare()
        with self.assertRaises(ReviewDenied):self.observation(i,'ABORT_NOT_COMMITTED')

    def test_abort_before_commit_with_signed_observation(self):
        i=self.prepare(apply=False)
        ev=self.observation(i,'ABORT_NOT_COMMITTED')
        result=CoordinatedStore(self.store,self.anchor).adjudicate('ABORT_NOT_COMMITTED',self.token(i,'ABORT_NOT_COMMITTED'),evidence=ev)
        self.assertEqual(result.code,'MATCH')
        self.assertIsNone(self.anchor.status().pending)

    def test_double_replay_attestation_does_not_duplicate_commit(self):
        i=self.prepare();ev=self.observation(i,'FINALIZE_COMMIT');token=self.token(i,'FINALIZE_COMMIT')
        self.anchor.adjudicate(i,'FINALIZE_COMMIT',token,evidence=ev)
        with self.assertRaises(AnchorHold):
            self.anchor.adjudicate(i,'FINALIZE_COMMIT',token,evidence=ev)
        self.assertEqual(self.anchor.status().committed.version,1)

    def test_invalid_public_key_configuration_refused(self):
        with self.assertRaises(ValueError):
            EvidenceRequiredCASAnchor(self.anchor.path,reviewer_key=REVIEW,seal_key=SEAL,
                                      attester_public_key=b'bad',deployment_id=DEPLOY)

    def test_live_rpc_refuses_unattested_and_accepts_attested(self):
        sock=str(self.dir/'authority.sock')
        with _UnixAuthority(sock,_Handler) as srv:
            srv.backend=self.anchor;srv.writer_uid=__import__('os').geteuid();srv.writer_key=RPC_KEY
            th=threading.Thread(target=srv.serve_forever,kwargs={'poll_interval':.02},daemon=True)
            th.start()
            try:
                rpc=RPCAnchor(sock,writer_key=RPC_KEY)
                remote_core=AnchoredWriterCore(self.store,rpc)
                response=remote_core.dispatch(SET,self.rid,b'new')
                self.assertFalse(response['ok'])
                i=self.anchor.status().pending
                token=self.token(i,'FINALIZE_COMMIT')
                with self.assertRaises(ReviewDenied):
                    rpc.adjudicate(i,'FINALIZE_COMMIT',token)
                ev=self.observation(i,'FINALIZE_COMMIT')
                out=CoordinatedStore(self.store,rpc).adjudicate('FINALIZE_COMMIT',token,evidence=ev)
                self.assertEqual(out.code,'MATCH')
                self.assertTrue(remote_core.dispatch(SET,self.rid,b'new')['ok'])
            finally:
                srv.shutdown();th.join(3)

    def test_evidence_not_sufficient_without_reviewer_approval(self):
        i=self.prepare();ev=self.observation(i,'FINALIZE_COMMIT')
        with self.assertRaises(ReviewDenied):
            self.anchor.adjudicate(i,'FINALIZE_COMMIT',b'X'*32,evidence=ev)
        self.assertEqual(self.anchor.status().committed.version,0)

    def test_live_authority_serve_default_denies_unattested_backend(self):
        from anchor_wire import serve
        with self.assertRaisesRegex(AnchorHold,'attested authority required'):
            serve(self.anchor.path,str(self.dir/'no-unsafe.sock'),writer_key=RPC_KEY,
                  reviewer_key=REVIEW,seal_key=SEAL,writer_uid=54321)
        self.assertFalse((self.dir/'no-unsafe.sock').exists())

    def test_attested_service_invalid_deployment_fails_closed(self):
        from anchor_wire import serve
        with self.assertRaises(ValueError):
            serve(self.anchor.path,str(self.dir/'invalid.sock'),writer_key=RPC_KEY,
                  reviewer_key=REVIEW,seal_key=SEAL,writer_uid=54321,
                  attester_public_key=self.trusted,deployment_id='with spaces')
        self.assertFalse((self.dir/'invalid.sock').exists())

    def test_invalid_attestation_layout_fails_closed(self):
        i=self.prepare();ev=self.observation(i,'FINALIZE_COMMIT')
        for wrong in (None,{},[],{'statement':ev['statement']},
                      {'statement':ev['statement'],'signature':b'bytes'},
                      {'statement':ev['statement'],'signature':'a'*4000}):
            with self.subTest(wrong=type(wrong).__name__),self.assertRaises(ReviewDenied):
                self.anchor.adjudicate(i,'FINALIZE_COMMIT',self.token(i,'FINALIZE_COMMIT'),evidence=wrong)
        self.assertEqual(self.anchor.status().committed.version,0)

    def test_attested_mode_restart_keeps_reviewer_gate(self):
        i=self.prepare();ev=self.observation(i,'FINALIZE_COMMIT')
        after=EvidenceRequiredCASAnchor(self.anchor.path,reviewer_key=REVIEW,seal_key=SEAL,
                                        attester_public_key=self.trusted,deployment_id=DEPLOY)
        with self.assertRaises(ReviewDenied):
            after.adjudicate(i,'FINALIZE_COMMIT',self.token(i,'FINALIZE_COMMIT'))
        after.adjudicate(i,'FINALIZE_COMMIT',self.token(i,'FINALIZE_COMMIT'),evidence=ev)
        self.assertEqual(after.status().committed.version,1)

    def test_attestation_key_pin_refuses_rotated_signer(self):
        i=self.prepare()
        ev=issue_observation(store=self.store,anchor=self.anchor,intent=i,
                             decision='FINALIZE_COMMIT',deployment_id=DEPLOY,
                             signing_key=self.wrong)
        with self.assertRaises(ReviewDenied):
            self.anchor.adjudicate(i,'FINALIZE_COMMIT',self.token(i,'FINALIZE_COMMIT'),evidence=ev)

    def test_signature_cannot_prevent_post_observation_joint_storage_rollback(self):
        """Known NO-GO: signature authenticates an observation, not permanence."""
        import shutil
        saved=self.dir/'genesis-copy.sqlite'
        shutil.copy2(self.db,saved)
        i=self.prepare()
        valid=self.observation(i,'FINALIZE_COMMIT')
        # Hypothetical hostile recovery domain can replace local StateStore
        # *after* observer signed. On this host no independent durable root.
        shutil.copy2(saved,self.db)
        self.anchor.adjudicate(i,'FINALIZE_COMMIT',self.token(i,'FINALIZE_COMMIT'),evidence=valid)
        self.assertEqual(self.anchor.status().committed.version,1)
        self.assertEqual(self.store.read().version,0)
        self.assertEqual(CoordinatedStore(self.store,self.anchor).diagnose().code,'ROLLBACK_HOLD')

if __name__=='__main__':unittest.main()
