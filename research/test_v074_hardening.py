from contextlib import closing
"""Independent added negative regressions for === v0.7.4 RESEARCH candidate."""
import os, pathlib, random, secrets, sqlite3, tempfile, unittest
from unittest.mock import patch

import witness
from state_store import StateStore, prepare_update, IntegrityError, AuthenticationError
from guarded_store import GuardedStore

class Version074Tests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=pathlib.Path(self.temp.name)
        self.key=secrets.token_bytes(32)
        self.wkey=secrets.token_bytes(32)
        self.path=self.root/'state.sqlite'
        self.store=StateStore.create(self.path,key=self.key,initial=b'genesis')
        self.trust=self.root/'private'
        self.trust.mkdir(mode=0o700)
        self.anchor=self.trust/'witness.txt'
        witness.initialize(self.store,self.anchor,self.wkey)
        self.guard=GuardedStore(self.store,self.anchor,self.wkey)

    def update(self, data):
        return self.guard.apply(prepare_update(self.store,data)[0])

    def test_new_store_has_chained_receipts(self):
        self.assertEqual(self.store.verify()['receipt_auth'],'HMAC_CHAIN_V2')
        for value in (b'A',b'B',b'C'):
            self.update(value)
        self.assertEqual(self.store.verify()['receipt_count'],3)
        self.assertEqual(self.guard.read().value,b'C')
        self.assertEqual(self.guard.read().version,3)

    def test_tampered_old_receipt_32_byte_hash_is_detected(self):
        self.update(b'A');self.update(b'B')
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('UPDATE receipts SET proposal_hash=? WHERE committed_version=1',(b'X'*32,))
        with self.assertRaises(IntegrityError):self.store.verify()
        with self.assertRaises(IntegrityError):self.guard.read()
        with self.assertRaises(IntegrityError):self.update(b'C')

    def test_tampered_old_digest_valid_length_is_detected(self):
        self.update(b'A');self.update(b'B')
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('UPDATE receipts SET digest=? WHERE committed_version=1',(b'Y'*32,))
        with self.assertRaises(IntegrityError): self.store.verify()

    def test_raw_apply_refuses_corrupt_chain_tail(self):
        self.update(b'A')
        proposal,_=prepare_update(self.store,b'B')
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('UPDATE receipt_auth SET tag=? WHERE committed_version=1',(b'X'*32,))
        with self.assertRaises(IntegrityError):self.store.apply(proposal)
        # A corrupted chain must now also block raw reads, not just writes.
        with self.assertRaises(IntegrityError):self.store.read()
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute('SELECT version FROM head').fetchone()[0],1)

    def test_tampered_chain_tag_is_detected(self):
        self.update(b'A')
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('UPDATE receipt_auth SET tag=? WHERE committed_version=1',(b'0'*32,))
        with self.assertRaises(IntegrityError):self.store.verify()

    def test_deleted_chain_tag_is_detected(self):
        self.update(b'A')
        with closing(sqlite3.connect(self.path)) as db, db:db.execute('DELETE FROM receipt_auth WHERE committed_version=1')
        with self.assertRaises(IntegrityError):self.store.verify()

    def test_extra_chain_tag_is_detected(self):
        with closing(sqlite3.connect(self.path)) as db, db:db.execute('INSERT INTO receipt_auth VALUES (99,?)',(b'0'*32,))
        with self.assertRaises(IntegrityError):self.store.verify()

    def test_forged_genesis_digest_is_detected(self):
        with closing(sqlite3.connect(self.path)) as db, db:db.execute('UPDATE meta SET genesis_digest=?',(b'Z'*32,))
        with self.assertRaises(IntegrityError):self.store.verify()

    def test_structural_legacy_receipt_corruption_is_detected(self):
        # Only simulate a read-only legacy schema; NEVER claim legacy history is sealed.
        self.update(b'A');self.update(b'B')
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('UPDATE meta SET schema_version=1')
            db.execute('DROP TABLE receipt_auth')
        self.assertEqual(self.store.verify()['receipt_auth'],'LEGACY_UNSEALED')
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('UPDATE receipts SET proposal_hash=? WHERE committed_version=1',(b'bad',))
        with self.assertRaises(IntegrityError):self.store.verify()

    def test_legacy_same_size_history_edit_not_detectable(self):
        self.update(b'A');self.update(b'B')
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute('UPDATE meta SET schema_version=1')
            db.execute('DROP TABLE receipt_auth')
            db.execute('UPDATE receipts SET proposal_hash=? WHERE committed_version=1',(b'Y'*32,))
        self.assertEqual(self.store.verify()['receipt_auth'],'LEGACY_UNSEALED')

    def test_raw_write_ahead_blocks_guarded_read(self):
        self.store.apply(prepare_update(self.store,b'raw')[0])
        with self.assertRaises(witness.AheadOfWitness): self.guard.read()

    def test_read_witness_rejects_symlink_without_guard_facade(self):
        alias=self.trust/'witness_link'
        alias.symlink_to(self.anchor)
        with self.assertRaises(OSError): witness.read_witness(alias,self.wkey)

    def test_witness_lock_rejects_symlink(self):
        (self.trust/'witness.txt.lock').unlink()
        (self.trust/'witness.txt.lock').symlink_to(self.anchor)
        with self.assertRaises(OSError): witness._with_lock(self.anchor,lambda:None)

    def test_witness_lock_rejects_weak_mode(self):
        p=self.trust/'witness.txt.lock'
        os.chmod(p,0o666)
        with self.assertRaises(witness.WitnessError): witness._with_lock(self.anchor,lambda:None)

    def test_verified_read_db_and_witness_uses_one_version(self):
        self.update(b'A')
        report,snapshot=self.store.read_verified()
        self.assertEqual(report['version'],snapshot.version)
        self.assertEqual(report['digest_sha256'],snapshot.digest.hex())

    def test_invalid_proposals_fuzz_refused(self):
        p,rid=prepare_update(self.store,b'new')
        rand=random.Random(20261024)
        for _ in range(250):
            b=bytearray(p);idx=rand.randrange(len(b));b[idx]^=1 << rand.randrange(8)
            with self.assertRaises((ValueError, OSError, RuntimeError)):
                self.guard.apply(bytes(b))
        self.assertEqual(self.guard.assess(),'MATCH')
        self.assertEqual(self.store.read().version,0)

    def test_chain_rollback_on_sql_exception(self):
        prop,rid=prepare_update(self.store,b'new')
        def fault(stage):
            if stage=='after_receipt_insert':raise RuntimeError('abort before sqlite commit')
        with self.assertRaises(RuntimeError):self.guard.apply(prop,fault=fault)
        self.assertEqual(self.store.verify()['receipt_count'],0)
        with closing(sqlite3.connect(self.path)) as db, db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM receipt_auth').fetchone()[0],1)

if __name__=='__main__':unittest.main()
