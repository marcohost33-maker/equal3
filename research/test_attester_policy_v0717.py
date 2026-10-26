"""v0.7.17 negative-first persistence tests: signer/deployment binding and rekey HOLD."""
import hashlib
import hmac
import sqlite3
import tempfile
import unittest
from pathlib import Path
from contextlib import closing

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from anchor_protocol import AnchorHold, Intent, _review_message, position_for_genesis
from anchor_wire import PersistentCASAnchor
from commit_evidence_v0716 import EvidenceRequiredCASAnchor, issue_observation
from state_store import StateStore, prepare_update

KEY=b'K'*32; REVIEW=b'R'*32;SEAL=b'S'*32

class PolicyBindingTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
        self.root=Path(t.name)
        self.d=(self.root/'authority');self.d.mkdir(mode=0o700)
        self.path=self.d/'anchor.sqlite'
        self.store=StateStore.create(self.root/'state.sqlite',key=KEY,initial=b'initial',journal_mode='DELETE')
        self.private=Ed25519PrivateKey.generate()
        self.attacker=Ed25519PrivateKey.generate()
        self.a=EvidenceRequiredCASAnchor.bootstrap(self.path,position_for_genesis(self.store),
                    reviewer_key=REVIEW,seal_key=SEAL,
                    attester_public_key=self.private.public_key(),deployment_id='production-one')

    def other(self, *, signer=None, deployment='production-one'):
        return EvidenceRequiredCASAnchor(self.path,reviewer_key=REVIEW,seal_key=SEAL,
                      attester_public_key=(signer or self.private).public_key(),deployment_id=deployment)

    def mutate(self, sql, params=()):
        with closing(sqlite3.connect(self.path)) as db:
            db.execute(sql,params)
            db.commit()

    def pending(self):
        rid=b'V'*16
        proposal,_=prepare_update(self.store,b'next-value',request_id=rid)
        info,snap=self.store.read_verified()
        i=Intent(info['store_id'],snap.version,snap.digest.hex(),snap.version+1,
                 hashlib.sha256(b'next-value').hexdigest(),rid.hex(),hashlib.sha256(proposal).hexdigest())
        self.a.prepare(i);self.store.apply(proposal)
        return i

    def test_pinned_signer_survives_restart(self):
        i=self.pending()
        b=self.other()
        ev=issue_observation(store=self.store,anchor=b,intent=i,decision='FINALIZE_COMMIT',
                             deployment_id='production-one',signing_key=self.private)
        token=hmac.new(REVIEW,_review_message(i,'FINALIZE_COMMIT'),hashlib.sha256).digest()
        b.adjudicate(i,'FINALIZE_COMMIT',token,evidence=ev)
        self.assertEqual(b.status().committed.version,1)

    def test_forged_rekey_after_restart_is_rejected(self):
        self.pending()
        with self.assertRaisesRegex(AnchorHold,'identity/deployment mismatch'):
            self.other(signer=self.attacker)
        self.assertEqual(self.a.status().committed.version,0)

    def test_forged_deployment_swap_after_restart_is_rejected(self):
        with self.assertRaisesRegex(AnchorHold,'identity/deployment mismatch'):
            self.other(deployment='attacker-env')

    def test_pending_policy_mutation_is_rejected_on_adjudicate(self):
        i=self.pending()
        ev=issue_observation(store=self.store,anchor=self.a,intent=i,
             decision='FINALIZE_COMMIT',deployment_id='production-one',signing_key=self.private)
        token=hmac.new(REVIEW,_review_message(i,'FINALIZE_COMMIT'),hashlib.sha256).digest()
        self.mutate('UPDATE trust_binding SET seal=? WHERE id=1',(b'X'*32,))
        with self.assertRaises(AnchorHold):
            self.a.adjudicate(i,'FINALIZE_COMMIT',token,evidence=ev)

    def test_policy_replaced_without_seal_rejected(self):
        self.mutate('UPDATE trust_binding SET policy=? WHERE id=1',(b'{}',))
        with self.assertRaises(AnchorHold):self.a.status()

    def test_policy_deleted_rejected(self):
        self.mutate('DELETE FROM trust_binding')
        with self.assertRaisesRegex(AnchorHold,'unauthorized attester trust binding'):
            self.a.status()

    def test_policy_table_dropped_rejected(self):
        self.mutate('DROP TABLE trust_binding')
        with self.assertRaisesRegex(AnchorHold,'unbound legacy attester policy'):
            self.a.status()

    def test_invalid_policy_type_rejected(self):
        self.mutate('UPDATE trust_binding SET seal=?',(42,))
        with self.assertRaises(AnchorHold):self.a.status()

    def test_policy_change_after_init_prevents_new_prepare(self):
        self.mutate('UPDATE trust_binding SET policy=?',(b'garbage',))
        with self.assertRaises(AnchorHold):self.a.status()

    def test_legacy_unbound_v0716_cannot_silently_migrate(self):
        old=self.d/'old.sqlite'
        PersistentCASAnchor.bootstrap(old,position_for_genesis(self.store),reviewer_key=REVIEW,seal_key=SEAL)
        with self.assertRaisesRegex(AnchorHold,'unbound legacy attester policy'):
            EvidenceRequiredCASAnchor(old,reviewer_key=REVIEW,seal_key=SEAL,
                     attester_public_key=self.private.public_key(),deployment_id='production-one')

    def test_cannot_rebootstrap_existing_authority_with_new_key(self):
        with self.assertRaises(FileExistsError):
            EvidenceRequiredCASAnchor.bootstrap(self.path,position_for_genesis(self.store),
                 reviewer_key=REVIEW,seal_key=SEAL,attester_public_key=self.attacker.public_key(),
                 deployment_id='production-one')

    def test_extra_trust_binding_row_rejected(self):
        # An adversary with offline DDL access can weaken the SQL constraint,
        # then inject a second policy row while retaining the valid first row.
        with closing(sqlite3.connect(self.path)) as db:
            record=db.execute('SELECT policy,seal FROM trust_binding WHERE id=1').fetchone()
            db.execute('DROP TABLE trust_binding')
            db.execute('CREATE TABLE trust_binding(id INTEGER PRIMARY KEY,policy BLOB,seal BLOB)')
            db.execute('INSERT INTO trust_binding VALUES(1,?,?)',record)
            db.execute('INSERT INTO trust_binding VALUES(2,?,?)',(b'rogue',b'Z'*32))
            db.commit()
        with self.assertRaisesRegex(AnchorHold,'duplicate'):
            self.a.status()

    def test_seal_key_mismatch_is_rejected(self):
        with self.assertRaises(AnchorHold):
            EvidenceRequiredCASAnchor(self.path,reviewer_key=REVIEW,seal_key=b'T'*32,
                    attester_public_key=self.private.public_key(),deployment_id='production-one')

    def test_no_automatic_repair_when_policy_missing(self):
        self.mutate('DELETE FROM trust_binding')
        with self.assertRaises(AnchorHold):self.other()
        with self.assertRaises(AnchorHold):self.a.status()

if __name__=='__main__':unittest.main()
