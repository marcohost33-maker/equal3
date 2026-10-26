"""v0.7.12 negative-first: hash-only head vs authenticated genesis/receipts."""
import hashlib
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

import state_store as st
import equal3
import witness
from guarded_store import GuardedStore

KEY = b'v0712-regression-secret-' + b'X'*32


class AuthenticatedReadAndGenesisTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db = st.StateStore.create(Path(tmp.name) / 'state.sqlite', key=KEY, initial=b'original')

    def mutate_head(self, payload: bytes):
        with closing(sqlite3.connect(self.db.path)) as conn:
            conn.execute('UPDATE head SET value=?,digest=? WHERE id=1',
                         (payload, hashlib.sha256(payload).digest()))
            conn.commit()

    def test_unmodified_genesis_passes_verified_read(self):
        report, snapshot = self.db.read_verified()
        self.assertEqual(report['receipt_auth'], 'HMAC_CHAIN_V2')
        self.assertEqual(snapshot.value, b'original')
        self.assertEqual(self.db.read(), snapshot)

    def test_genesis_head_offline_forgery_denied_in_every_read_api(self):
        self.mutate_head(b'forged')
        for operation in (self.db.read, self.db.verify, self.db.read_verified):
            with self.subTest(operation=operation.__name__), self.assertRaises(st.IntegrityError):
                operation()

    def test_genesis_head_forgery_refuses_existing_signed_write(self):
        proposal, _ = st.prepare_update(self.db, b'legitimate future')
        self.mutate_head(b'forged')
        with self.assertRaises((st.IntegrityError, equal3.CodecError)):
            self.db.apply(proposal)
        with closing(sqlite3.connect(self.db.path)) as db:
            self.assertEqual(db.execute('SELECT version FROM head WHERE id=1').fetchone()[0], 0)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM receipts').fetchone()[0], 0)

    def test_post_commit_hash_forgery_refused_at_read(self):
        prop, _ = st.prepare_update(self.db, b'committed')
        self.db.apply(prop)
        self.mutate_head(b'forged')
        for operation in (self.db.read, self.db.verify, self.db.read_verified):
            with self.subTest(operation=operation.__name__), self.assertRaises(st.IntegrityError):
                operation()

    def test_post_commit_forgery_refuses_next_authenticated_write(self):
        first,_=st.prepare_update(self.db, b'committed')
        self.db.apply(first)
        second,_=st.prepare_update(self.db, b'next')
        self.mutate_head(b'forged')
        with self.assertRaises((st.IntegrityError, st.ConflictError, equal3.CodecError)):
            self.db.apply(second)
        with closing(sqlite3.connect(self.db.path)) as db:
            self.assertEqual(db.execute('SELECT version FROM head WHERE id=1').fetchone()[0],1)

    def test_legacy_version_is_never_reported_as_authenticated_read(self):
        with closing(sqlite3.connect(self.db.path)) as conn:
            conn.execute('UPDATE meta SET schema_version=1 WHERE id=1'); conn.commit()
        self.assertEqual(self.db.verify()['receipt_auth'], 'LEGACY_UNSEALED')
        with self.assertRaises(st.IntegrityError):
            self.db.read()

    def test_legacy_head_does_not_enable_new_write(self):
        p,_=st.prepare_update(self.db, b'next')
        with closing(sqlite3.connect(self.db.path)) as conn:
            conn.execute('UPDATE meta SET schema_version=1 WHERE id=1'); conn.commit()
        with self.assertRaises(st.IntegrityError):
            self.db.apply(p)

    def test_legacy_downgrade_cannot_report_guarded_match(self):
        root = self.db.path.parent / 'anchor'
        root.mkdir(mode=0o700)
        secret = b'W'*32
        anchor = root / 'witness.txt'
        witness.initialize(self.db, anchor, secret)
        guard = GuardedStore(self.db, anchor, secret)
        self.assertEqual(guard.assess(), 'MATCH')
        with closing(sqlite3.connect(self.db.path)) as conn:
            conn.execute('UPDATE meta SET schema_version=1 WHERE id=1')
            conn.commit()
        with self.assertRaises(witness.WitnessError):
            guard.assess()
        with self.assertRaises(witness.WitnessError):
            guard.read()

    def test_unsealed_schema_forbids_witness_initialization(self):
        with closing(sqlite3.connect(self.db.path)) as conn:
            conn.execute('UPDATE meta SET schema_version=1 WHERE id=1')
            conn.commit()
        root = self.db.path.parent / 'anchor'
        root.mkdir(mode=0o700)
        path = root / 'witness.txt'
        with self.assertRaises(witness.WitnessError):
            witness.initialize(self.db, path, b'W'*32)
        self.assertFalse(path.exists())

    def test_tampered_genesis_tag_fails_read(self):
        with closing(sqlite3.connect(self.db.path)) as conn:
            conn.execute('UPDATE receipt_auth SET tag=? WHERE committed_version=0',(b'Q'*32,));conn.commit()
        with self.assertRaises(st.IntegrityError):
            self.db.read()

if __name__ == '__main__':
    unittest.main()
