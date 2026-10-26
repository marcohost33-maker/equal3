"""Fail-closed epoch witness: attacks, stale/replay, split-state, joint rollback."""
import shutil
import sqlite3
import os
import tempfile
import threading
import unittest
from contextlib import closing
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from anchor_protocol import AnchorHold, ReviewDenied, position_for_genesis
from state_store import StateStore
from trust_rotation_v0718 import RootControlledCASAnchor, sign_rotation, fingerprint
from external_epoch_witness_v0719 import (WitnessLedger,WitnessServer,WitnessClient,
                                           WitnessGatedCASAnchor)

KEY=b'Q'*32;SEAL=b'S'*32;REVIEW=b'R'*32;DEPLOY='main-prod-research'
class WitnessTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
        self.base=Path(t.name);self.store=StateStore.create(self.base/'store.db',key=KEY,initial=b'x',journal_mode='DELETE')
        self.root=Ed25519PrivateKey.generate();self.old=Ed25519PrivateKey.generate()
        self.new=Ed25519PrivateKey.generate();self.rogue=Ed25519PrivateKey.generate()
        self.signer=Ed25519PrivateKey.generate();self.bad_signer=Ed25519PrivateKey.generate()
        self.dir=self.base/'authority';self.dir.mkdir(mode=0o700)
        self.local=self.dir/'anchor.db';self.remote=self.base/'witness'
        self.remote.mkdir(mode=0o700)
        self.a=RootControlledCASAnchor.bootstrap(self.local,position_for_genesis(self.store),
                 reviewer_key=REVIEW,seal_key=SEAL,attester_public_key=self.old.public_key(),
                 root_public_key=self.root.public_key(),deployment_id=DEPLOY)
        self.ledger=WitnessLedger.bootstrap(self.remote/'counter.db',private_key=self.signer,
               root_public_key=self.root.public_key(),attester_public_key=self.old.public_key(),
               deployment_id=DEPLOY,store_id=self.a.status().committed.store_id)
        self.sock=self.remote/'w.sock'
        self.server=WitnessServer(self.sock,self.ledger)
        self.thread=threading.Thread(target=self.server.serve_forever,
                 kwargs={'poll_interval':0.01},daemon=True)
        self.thread.start()
        self.addCleanup(self._close_server)
        self.client=WitnessClient(self.sock,public_key=self.signer.public_key())
    def _close_server(self):
        self.server.shutdown();self.server.server_close();self.thread.join(timeout=2)
    def gated(self,*,att=None,client=None):
        return WitnessGatedCASAnchor(self.local,reviewer_key=REVIEW,seal_key=SEAL,
              attester_public_key=(att or self.old).public_key(),deployment_id=DEPLOY,
              root_public_key=self.root.public_key(),min_epoch=0,
              witness_client=client or self.client)
    def auth(self):
        return sign_rotation(self.root,deployment_id=DEPLOY,
                    store_id=self.store.store_id.hex(),from_key=self.old.public_key(),
                    to_key=self.new.public_key(),from_epoch=0)
    def test_genesis_live_remote_challenge(self):
        self.assertEqual(self.gated().status().committed.version,0)
    def test_challenge_changes_between_requests(self):
        r1=self.ledger.challenge('a'*64);r2=self.ledger.challenge('b'*64)
        self.assertNotEqual(r1['signature'],r2['signature'])
    def test_offline_witness_fails_closed(self):
        # A nonexistent endpoint is not a permit to use a local fallback.
        other=WitnessClient(self.base/'missing.sock',public_key=self.signer.public_key(),timeout=.1)
        with self.assertRaises(AnchorHold):self.gated(client=other).status()
    def test_wrong_witness_key_rejected(self):
        other=WitnessClient(self.sock,public_key=self.bad_signer.public_key())
        with self.assertRaises(AnchorHold):self.gated(client=other).status()
    def test_rogue_store_and_deployment_bound(self):
        with self.assertRaises(AnchorHold):self.client.floor(
            deployment_id='foreign',store_id=self.store.store_id.hex(),
            root_fingerprint=fingerprint(self.root.public_key()),
            attester_fingerprint=fingerprint(self.old.public_key()))
    def test_wrong_root_fingerprint_rejected(self):
        with self.assertRaises(AnchorHold):self.client.floor(
            deployment_id=DEPLOY,store_id=self.store.store_id.hex(),
            root_fingerprint=fingerprint(self.rogue.public_key()),
            attester_fingerprint=fingerprint(self.old.public_key()))
    def test_nonces_cannot_replay_signed_response(self):
        saved=self.client._rpc({'op':'challenge','nonce':'a'*64})
        other=WitnessClient(self.sock,public_key=self.signer.public_key())
        other._rpc=lambda _req:saved
        with self.assertRaises(AnchorHold):self.gated(client=other).status()
    def test_untrusted_old_min_epoch_zero_cannot_bypass_remote(self):
        saved=self.base/'old.db';shutil.copyfile(self.local,saved)
        auth=self.auth();self.a.rotate_attester(new_attester_public_key=self.new.public_key(),authorization=auth)
        # The new trusted floor must be advanced independently before returning service.
        self.client.advance(auth)
        self.assertEqual(self.gated(att=self.new).status().committed.version,0)
        shutil.copyfile(saved,self.local)
        # Local caller-supplied floor=0 would accept old snapshot. Live external floor will not.
        self.assertEqual(RootControlledCASAnchor(self.local,reviewer_key=REVIEW,seal_key=SEAL,
            root_public_key=self.root.public_key(),attester_public_key=self.old.public_key(),
            deployment_id=DEPLOY,min_epoch=0).status().committed.version,0)
        with self.assertRaisesRegex(AnchorHold,'remote witness'):
            self.gated(att=self.old).status()
    def test_rotated_local_but_remote_not_advanced_hold(self):
        auth=self.auth();self.a.rotate_attester(new_attester_public_key=self.new.public_key(),authorization=auth)
        with self.assertRaisesRegex(AnchorHold,'remote witness'):
            self.gated(att=self.new).status()
        self.client.advance(auth)
        self.assertEqual(self.gated(att=self.new).status().committed.version,0)
    def test_remote_advanced_before_local_hold_and_offline_recovery(self):
        auth=self.auth()
        self.client.advance(auth)
        with self.assertRaises(AnchorHold):self.gated().status()
        # Only independently root-authorized rotation can repair the local side.
        self.a.rotate_attester(new_attester_public_key=self.new.public_key(),authorization=auth)
        self.assertEqual(self.gated(att=self.new).status().committed.version,0)
    def test_replay_witness_advance_denied(self):
        auth=self.auth();self.client.advance(auth)
        with self.assertRaises(AnchorHold):self.client.advance(auth)
    def test_unauthorized_advance_denied(self):
        bad=sign_rotation(self.rogue,deployment_id=DEPLOY,
             store_id=self.store.store_id.hex(),from_key=self.old.public_key(),
             to_key=self.new.public_key(),from_epoch=0)
        with self.assertRaises(AnchorHold):self.client.advance(bad)
        self.assertEqual(self.gated().status().committed.version,0)
    def test_witness_remote_floor_cannot_skip_epoch(self):
        bad=sign_rotation(self.root,deployment_id=DEPLOY,
            store_id=self.store.store_id.hex(),from_key=self.old.public_key(),
            to_key=self.new.public_key(),from_epoch=2)
        with self.assertRaises(AnchorHold):self.client.advance(bad)
    def test_witness_bad_db_row_fail_closed(self):
        with closing(sqlite3.connect(self.remote/'counter.db')) as db:
            db.execute('UPDATE floor SET body=? WHERE id=1',(b'{}',));db.commit()
        with self.assertRaises(AnchorHold):self.gated().status()
    def test_witness_duplicate_row_fail_closed(self):
        with closing(sqlite3.connect(self.remote/'counter.db')) as db:
            row=db.execute('SELECT body FROM floor').fetchone()[0]
            db.execute('DROP TABLE floor');db.execute('CREATE TABLE floor(id INTEGER PRIMARY KEY,body BLOB)')
            db.execute('INSERT INTO floor VALUES(1,?)',(row,))
            db.execute('INSERT INTO floor VALUES(2,?)',(row,));db.commit()
        with self.assertRaises(AnchorHold):self.gated().status()
    def test_remote_witness_rollback_still_possible_under_joint_compromise(self):
        # Deliberate falsification: the witness itself is in the same rollback domain.
        saved=self.base/'old.db';shutil.copyfile(self.local,saved)
        witness_snapshot=self.base/'w-old.db';shutil.copyfile(self.remote/'counter.db',witness_snapshot)
        auth=self.auth();self.a.rotate_attester(new_attester_public_key=self.new.public_key(),authorization=auth)
        self.client.advance(auth)
        shutil.copyfile(saved,self.local);shutil.copyfile(witness_snapshot,self.remote/'counter.db')
        self.assertEqual(self.gated(att=self.old).status().committed.version,0)
    def test_service_rejects_static_floor_without_explicit_research_gate(self):
        from anchor_wire import serve
        with self.assertRaisesRegex(AnchorHold,'live witness mandatory'):
            serve(self.local,self.base/'out.sock',writer_key=b'W'*32,
                  reviewer_key=REVIEW,seal_key=SEAL,writer_uid=1001,
                  attester_public_key=self.old.public_key(),deployment_id=DEPLOY,
                  root_public_key=self.root.public_key(),trusted_min_epoch=0)
        self.assertFalse((self.base/'out.sock').exists())
    def test_service_rejects_missing_or_forged_witness_at_boot(self):
        from anchor_wire import serve
        with self.assertRaises(AnchorHold):
            serve(self.local,self.base/'out.sock',writer_key=b'W'*32,
                  reviewer_key=REVIEW,seal_key=SEAL,writer_uid=1001,
                  attester_public_key=self.old.public_key(),deployment_id=DEPLOY,
                  root_public_key=self.root.public_key(),
                  witness_socket_path=self.sock,
                  witness_public_key=self.bad_signer.public_key())
        self.assertFalse((self.base/'out.sock').exists())
    def test_service_witness_preflight_before_socket_creation(self):
        from unittest.mock import patch
        from anchor_wire import serve
        with patch('anchor_wire._require_socket_parent',side_effect=RuntimeError('witness-check-passed')):
            with self.assertRaisesRegex(RuntimeError,'witness-check-passed'):
                serve(self.local,self.base/'out.sock',writer_key=b'W'*32,
                      reviewer_key=REVIEW,seal_key=SEAL,writer_uid=1001,
                      attester_public_key=self.old.public_key(),deployment_id=DEPLOY,
                      root_public_key=self.root.public_key(),
                      witness_socket_path=self.sock,
                      witness_public_key=self.signer.public_key())
        self.assertFalse((self.base/'out.sock').exists())
    def test_witness_rejects_unsafe_database_file_mode(self):
        os.chmod(self.remote/'counter.db',0o644)
        with self.assertRaises(AnchorHold):self.gated().status()
        os.chmod(self.remote/'counter.db',0o600)
    def test_witness_rejects_symlink_alias(self):
        original=self.remote/'counter.db'
        symlink=self.remote/'symlink.db';symlink.symlink_to(original)
        bad=WitnessLedger(symlink,private_key=self.signer,root_public_key=self.root.public_key())
        with self.assertRaises(AnchorHold):bad.challenge('a'*64)
    def test_remote_mismatched_fingerprint_requires_hold(self):
        auth=self.auth();self.a.rotate_attester(new_attester_public_key=self.new.public_key(),authorization=auth)
        self.client.advance(auth)
        with self.assertRaises(AnchorHold):self.gated(att=self.old).status()

    def test_witness_root_key_reuse_rejected(self):
        with self.assertRaisesRegex(ValueError,'distinct keys'):
            WitnessLedger(self.remote/'counter.db',private_key=self.root,
                          root_public_key=self.root.public_key())
    def test_witness_attester_key_reuse_rejected(self):
        with self.assertRaisesRegex(ValueError,'distinct keys'):
            WitnessLedger.bootstrap(self.remote/'another.db',private_key=self.old,
                root_public_key=self.root.public_key(),attester_public_key=self.old.public_key(),
                deployment_id=DEPLOY,store_id=self.store.store_id.hex())
    def test_witness_private_key_required(self):
        with self.assertRaisesRegex(TypeError,'private key'):
            WitnessLedger(self.remote/'counter.db',private_key=b'0'*32,
                          root_public_key=self.root.public_key())

    def test_root_rotation_does_not_leak_signer(self):
        self.assertFalse(hasattr(self.client,'private_key'))
        self.assertNotEqual(fingerprint(self.signer.public_key()),fingerprint(self.root.public_key()))

if __name__=='__main__':unittest.main()
