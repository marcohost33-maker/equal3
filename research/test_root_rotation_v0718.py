"""Root authorization, replay, downgrade and rollback falsification tests."""
import json
import hmac
import hashlib
import sqlite3
import shutil
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from anchor_protocol import AnchorHold, ReviewDenied, Intent, _review_message, position_for_genesis
from state_store import StateStore, prepare_update
from commit_evidence_v0716 import EvidenceRequiredCASAnchor, issue_observation
from trust_rotation_v0718 import (RootControlledCASAnchor, sign_rotation, fingerprint,
                                  verify_rotation,statement)

STOREKEY=b'K'*32;REVIEW=b'R'*32;SEAL=b'S'*32
DEPLOY='deployment-main'
class RootRotationTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
        self.d=Path(t.name);self.store=StateStore.create(self.d/'s.db',key=STOREKEY,initial=b'zero',journal_mode='DELETE')
        self.a_dir=self.d/'authority';self.a_dir.mkdir(mode=0o700)
        self.anchor_path=self.a_dir/'a.db'
        self.root_private=Ed25519PrivateKey.generate();self.old=Ed25519PrivateKey.generate();self.new=Ed25519PrivateKey.generate();self.rogue=Ed25519PrivateKey.generate()
        self.a=RootControlledCASAnchor.bootstrap(self.anchor_path,position_for_genesis(self.store),reviewer_key=REVIEW,seal_key=SEAL,
                   root_public_key=self.root_private.public_key(),attester_public_key=self.old.public_key(),deployment_id=DEPLOY)
    def reopen(self,att=None,root=None,floor=0):
        return RootControlledCASAnchor(self.anchor_path,reviewer_key=REVIEW,seal_key=SEAL,
            root_public_key=(root or self.root_private).public_key(),attester_public_key=(att or self.old).public_key(),
            deployment_id=DEPLOY,min_epoch=floor)
    def authorization(self,**kw):
        args=dict(store_id=self.store.store_id.hex() if isinstance(self.store.store_id,bytes) else self.store.store_id,
                  deployment_id=DEPLOY,from_key=self.old.public_key(),to_key=self.new.public_key(),from_epoch=0)
        args.update(kw);return sign_rotation(self.root_private,**args)
    def mutate(self,sql,params=()):
        with closing(sqlite3.connect(self.anchor_path)) as db:
            db.execute(sql,params);db.commit()
    def test_genesis_pin_and_restart(self):
        self.assertEqual(self.reopen().status().committed.version,0)
        with self.assertRaises(AnchorHold):self.reopen(root=self.rogue)
    def test_reject_reusing_attester_as_root(self):
        with self.assertRaises((AnchorHold,ValueError)):self.reopen(root=self.old)
    def test_rotation_authorized_and_old_key_denied(self):
        self.assertEqual(self.a.rotate_attester(new_attester_public_key=self.new.public_key(),authorization=self.authorization()),1)
        self.assertEqual(self.reopen(att=self.new,floor=1).status().committed.version,0)
        with self.assertRaises(AnchorHold):self.reopen(att=self.old)
        self.assertEqual(self.a.status().committed.version,0)
    def test_old_key_cannot_sign_post_rotation_commit(self):
        self.a.rotate_attester(new_attester_public_key=self.new.public_key(),authorization=self.authorization())
        rid=b'Q'*16;proposal,_=prepare_update(self.store,b'next',request_id=rid)
        info,s=self.store.read_verified()
        intent=Intent(info['store_id'],s.version,s.digest.hex(),1,hashlib.sha256(b'next').hexdigest(),rid.hex(),hashlib.sha256(proposal).hexdigest())
        self.a.prepare(intent);self.store.apply(proposal)
        token=hmac.new(REVIEW,_review_message(intent,'FINALIZE_COMMIT'),hashlib.sha256).digest()
        ev=issue_observation(store=self.store,anchor=self.a,intent=intent,decision='FINALIZE_COMMIT',deployment_id=DEPLOY,signing_key=self.old)
        with self.assertRaises(ReviewDenied):self.a.adjudicate(intent,'FINALIZE_COMMIT',token,evidence=ev)
        ev=issue_observation(store=self.store,anchor=self.a,intent=intent,decision='FINALIZE_COMMIT',deployment_id=DEPLOY,signing_key=self.new)
        self.a.adjudicate(intent,'FINALIZE_COMMIT',token,evidence=ev)
        self.assertEqual(self.a.status().committed.version,1)
    def test_rotation_requires_true_root_signature(self):
        auth=self.authorization();auth['signature']='0'*128
        with self.assertRaises(ReviewDenied):self.a.rotate_attester(new_attester_public_key=self.new.public_key(),authorization=auth)
        self.assertEqual(self.reopen().status().committed.version,0)
    def test_reject_wrong_root_surety(self):
        auth=sign_rotation(self.rogue,store_id=self.store.store_id.hex() if isinstance(self.store.store_id,bytes) else self.store.store_id,deployment_id=DEPLOY,
               from_key=self.old.public_key(),to_key=self.new.public_key(),from_epoch=0)
        with self.assertRaises(ReviewDenied):self.a.rotate_attester(new_attester_public_key=self.new.public_key(),authorization=auth)
    def test_reject_expired(self):
        auth=self.authorization(now=int(time.time())-500)
        with self.assertRaises(ReviewDenied):self.a.rotate_attester(new_attester_public_key=self.new.public_key(),authorization=auth)
    def test_reject_future(self):
        auth=self.authorization(now=int(time.time())+300)
        with self.assertRaises(ReviewDenied):self.a.rotate_attester(new_attester_public_key=self.new.public_key(),authorization=auth)
    def test_reject_wrong_attester_target(self):
        auth=self.authorization(to_key=self.rogue.public_key())
        with self.assertRaises(ReviewDenied):self.a.rotate_attester(new_attester_public_key=self.new.public_key(),authorization=auth)
    def test_reject_wrong_deployment(self):
        auth=self.authorization(deployment_id='other')
        with self.assertRaises(ReviewDenied):self.a.rotate_attester(new_attester_public_key=self.new.public_key(),authorization=auth)
    def test_reject_epoch_jump(self):
        auth=self.authorization(from_epoch=2)
        with self.assertRaises(ReviewDenied):self.a.rotate_attester(new_attester_public_key=self.new.public_key(),authorization=auth)
    def test_pending_commit_blocks_rotation(self):
        info,s=self.store.read_verified();rid=b'P'*16;proposal,_=prepare_update(self.store,b'next',request_id=rid)
        i=Intent(info['store_id'],s.version,s.digest.hex(),1,hashlib.sha256(b'next').hexdigest(),rid.hex(),hashlib.sha256(proposal).hexdigest())
        self.a.prepare(i)
        with self.assertRaises(AnchorHold):self.a.rotate_attester(new_attester_public_key=self.new.public_key(),authorization=self.authorization())
    def test_second_replay_of_signed_rotation_rejected(self):
        auth=self.authorization();self.a.rotate_attester(new_attester_public_key=self.new.public_key(),authorization=auth)
        with self.assertRaises((ReviewDenied,ValueError)):
            self.a.rotate_attester(new_attester_public_key=self.new.public_key(),authorization=auth)
    def test_root_binding_mutation_detected(self):
        self.mutate('UPDATE root_binding SET binding=? WHERE id=1',(b'{}',))
        with self.assertRaises(AnchorHold):self.a.status()
    def test_root_binding_deletion_detected(self):
        self.mutate('DELETE FROM root_binding')
        with self.assertRaises(AnchorHold):self.a.status()
    def test_extra_root_binding_detected(self):
        with closing(sqlite3.connect(self.anchor_path)) as db:
            row=db.execute('SELECT binding,seal FROM root_binding').fetchone()
            db.execute('DROP TABLE root_binding');db.execute('CREATE TABLE root_binding(id INTEGER PRIMARY KEY,binding BLOB,seal BLOB)')
            db.execute('INSERT INTO root_binding VALUES(1,?,?)',row)
            db.execute('INSERT INTO root_binding VALUES(2,?,?)',(b'fake',b'0'*32));db.commit()
        with self.assertRaises(AnchorHold):self.a.status()
    def test_external_epoch_floor_rejects_rollback(self):
        snap=self.d/'old-anchor.db';shutil.copyfile(self.anchor_path,snap)
        self.a.rotate_attester(new_attester_public_key=self.new.public_key(),authorization=self.authorization())
        shutil.copyfile(snap,self.anchor_path)
        with self.assertRaisesRegex(AnchorHold,'epoch rollback'):
            self.reopen(floor=1)
        # A caller that irresponsibly resets the trusted epoch to zero can
        # still accept an old state. An external floor is a non-negotiable P0.
        self.assertEqual(self.reopen(floor=0).status().committed.version,0)
    def test_min_epoch_cannot_be_omitted(self):
        with self.assertRaises(TypeError):RootControlledCASAnchor(self.anchor_path,reviewer_key=REVIEW,
               seal_key=SEAL,root_public_key=self.root_private.public_key(),attester_public_key=self.old.public_key(),deployment_id=DEPLOY)
    def test_old_v0717_authority_not_auto_migrated(self):
        olddir=self.d/'old';olddir.mkdir(mode=0o700)
        old=EvidenceRequiredCASAnchor.bootstrap(olddir/'a.db',position_for_genesis(self.store),reviewer_key=REVIEW,
                       seal_key=SEAL,attester_public_key=self.old.public_key(),deployment_id=DEPLOY)
        with self.assertRaisesRegex(AnchorHold,'unbound legacy root'):
            RootControlledCASAnchor(olddir/'a.db',reviewer_key=REVIEW,seal_key=SEAL,attester_public_key=self.old.public_key(),
                                    deployment_id=DEPLOY,root_public_key=self.root_private.public_key(),min_epoch=0)
    def test_root_key_cannot_double_as_attester(self):
        other=self.d/'newroot';other.mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError,'must be distinct'):
            RootControlledCASAnchor.bootstrap(other/'a.db',position_for_genesis(self.store),
                  reviewer_key=REVIEW,seal_key=SEAL,
                  root_public_key=self.old.public_key(),
                  attester_public_key=self.old.public_key(),deployment_id=DEPLOY)
        self.assertFalse((other/'a.db').exists())

    def test_rotation_cannot_install_root_as_attester(self):
        with self.assertRaises(ReviewDenied):
            self.a.rotate_attester(new_attester_public_key=self.root_private.public_key(),
                authorization=self.authorization(to_key=self.root_private.public_key()))
        self.assertEqual(self.a.status().committed.version,0)

    def test_service_requires_rooted_authority_by_default(self):
        from anchor_wire import serve
        sock=self.d/'never.sock'
        with self.assertRaisesRegex(AnchorHold,'root authorization missing'):
            serve(self.anchor_path,sock,writer_key=b'W'*32,reviewer_key=REVIEW,
                  seal_key=SEAL,writer_uid=1001,attester_public_key=self.old.public_key(),deployment_id=DEPLOY)
        self.assertFalse(sock.exists())

    def test_service_rejects_unsourced_epoch_floor(self):
        from anchor_wire import serve
        sock=self.d/'never.sock'
        with self.assertRaisesRegex(AnchorHold,'minimum epoch required'):
            serve(self.anchor_path,sock,writer_key=b'W'*32,reviewer_key=REVIEW,
                  seal_key=SEAL,writer_uid=1001,attester_public_key=self.old.public_key(),
                  deployment_id=DEPLOY,root_public_key=self.root_private.public_key())
        self.assertFalse(sock.exists())

    def test_signed_rotation_cannot_override_foreign_root(self):
        auth=self.authorization()
        with self.assertRaises(AnchorHold):
            self.reopen(root=self.rogue)
        with self.assertRaises(ReviewDenied):
            from trust_rotation_v0718 import verify_rotation
            verify_rotation(auth,root_public_key=self.rogue.public_key(),
                            expected=auth['statement'])

    def test_transactional_rotation_rolls_back_when_sql_update_fails(self):
        # An injected SQLite abort between policy updates must leave both keys intact.
        with closing(sqlite3.connect(self.anchor_path)) as db:
            db.execute("CREATE TRIGGER rotation_fail BEFORE UPDATE ON root_binding "
                       "BEGIN SELECT RAISE(ABORT,'fault injection'); END")
            db.commit()
        with self.assertRaises(sqlite3.DatabaseError):
            self.a.rotate_attester(new_attester_public_key=self.new.public_key(),
                                   authorization=self.authorization())
        self.assertEqual(self.reopen().status().committed.version,0)
        with closing(sqlite3.connect(self.anchor_path)) as db:
            db.execute('DROP TRIGGER rotation_fail');db.commit()
        self.a.rotate_attester(new_attester_public_key=self.new.public_key(),
                               authorization=self.authorization())
        self.assertEqual(self.reopen(att=self.new,floor=1).status().committed.version,0)

    def test_rpc_rooted_anchor_status_after_reopen(self):
        import os,threading
        from anchor_wire import _UnixAuthority,_Handler,RPCAnchor
        self.a.rotate_attester(new_attester_public_key=self.new.public_key(),
                               authorization=self.authorization())
        rooted=self.reopen(att=self.new,floor=1)
        sock=str(self.d/'local.sock')
        with _UnixAuthority(sock,_Handler) as srv:
            srv.backend=rooted;srv.writer_uid=os.geteuid();srv.writer_key=b'W'*32
            th=threading.Thread(target=srv.serve_forever,
                                kwargs={'poll_interval':.02},daemon=True)
            th.start()
            try:
                client=RPCAnchor(sock,writer_key=b'W'*32)
                self.assertEqual(client.status().committed.version,0)
            finally:
                srv.shutdown();th.join(3)

    def test_negative_first_seal_key_only_cannot_rebind_rooted_attester(self):
        # Baseline v0717 HMAC policy: authority seal-key holder can replace
        # signer binding with an arbitrary new Ed25519 key and restart.
        from commit_evidence_v0716 import _attester_policy,_policy_seal
        olddir=self.d/'legacy2';olddir.mkdir(mode=0o700)
        olddb=olddir/'a.db'
        EvidenceRequiredCASAnchor.bootstrap(olddb,position_for_genesis(self.store),
            reviewer_key=REVIEW,seal_key=SEAL,
            attester_public_key=self.old.public_key(),deployment_id=DEPLOY)
        fake_policy=_attester_policy(pubkey=self.rogue.public_key(),
               deployment_id=DEPLOY,store_id=self.store.store_id.hex() if isinstance(self.store.store_id,bytes) else self.store.store_id)
        with closing(sqlite3.connect(olddb)) as db:
            db.execute('UPDATE trust_binding SET policy=?,seal=? WHERE id=1',
                       (fake_policy,_policy_seal(SEAL,fake_policy)));db.commit()
        # Legacy accepts the forged trust if the seal key is compromised.
        baseline=EvidenceRequiredCASAnchor(olddb,reviewer_key=REVIEW,seal_key=SEAL,
                   attester_public_key=self.rogue.public_key(),deployment_id=DEPLOY)
        self.assertEqual(baseline.status().committed.version,0)
        # The rooted variant rejects the same policy replacement because it
        # has a separately persisted root-owned attester fingerprint.
        with closing(sqlite3.connect(self.anchor_path)) as db:
            db.execute('UPDATE trust_binding SET policy=?,seal=? WHERE id=1',
                       (fake_policy,_policy_seal(SEAL,fake_policy)));db.commit()
        with self.assertRaises(AnchorHold):
            self.reopen(att=self.rogue)
        with self.assertRaises(AnchorHold):self.a.status()

    def test_policy_divergence_detected(self):
        policy=b'{}';self.mutate('UPDATE trust_binding SET policy=? WHERE id=1',(policy,))
        with self.assertRaises(AnchorHold):self.a.status()

if __name__=='__main__':unittest.main()
