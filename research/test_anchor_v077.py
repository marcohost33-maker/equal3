"""Negative-first security regression tests, research-only, synthetic authority DB."""
from contextlib import closing
from dataclasses import replace
from pathlib import Path
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import tempfile
import unittest

from anchor_protocol import AnchorHold, Intent, Position, _review_message
from anchor_wire import PersistentCASAnchor, sqlite_wal_reset_safe, require_sqlite_wal_safe

class AnchorSealTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        os.chmod(self.root, 0o700)
        self.path=self.root/'authority.db'
        self.sealkey=secrets.token_bytes(32)
        self.reviewkey=secrets.token_bytes(32)
        self.genesis=Position('a'*32,0,'b'*64)
        self.a=PersistentCASAnchor.bootstrap(self.path,self.genesis,reviewer_key=self.reviewkey,
                                            seal_key=self.sealkey,research_unsafe_sqlite=True)

    def sql(self,query,params=()):
        with closing(sqlite3.connect(self.path)) as db:
            db.execute(query,params)
            db.commit()

    def pending(self):
        p=self.a.status().committed
        return Intent(p.store_id,p.version,p.digest,p.version+1,hashlib.sha256(b'value').hexdigest(),secrets.token_hex(16),'c'*64)

    def approve(self,intent,decision):
        return hmac.new(self.reviewkey,_review_message(intent,decision),hashlib.sha256).digest()

    def test_offline_commit_version_and_digest_mutation_rejected(self):
        self.sql('UPDATE authority SET version=?,digest=? WHERE id=1',(5,'c'*64))
        with self.assertRaisesRegex(AnchorHold,'seal mismatch'):self.a.status()
        with self.assertRaises(AnchorHold):self.a.prepare(self.pending_from_genesis())

    def pending_from_genesis(self):
        return Intent(self.genesis.store_id,0,self.genesis.digest,1,'d'*64,'e'*32,'f'*64)

    def test_offline_pending_change_rejected(self):
        p=self.pending_from_genesis()
        self.a.prepare(p)
        changed=replace(p, digest='9'*64)
        self.sql('UPDATE authority SET pending=? WHERE id=1',(json.dumps(changed.__dict__).encode(),))
        with self.assertRaisesRegex(AnchorHold,'seal mismatch'):self.a.status()

    def test_removed_seal_rejected(self):
        self.sql('UPDATE authority SET seal=? WHERE id=1',(b'\0'*32,))
        with self.assertRaisesRegex(AnchorHold,'seal mismatch'):self.a.status()

    def test_wrong_seal_credential_denied_on_restart(self):
        with self.assertRaisesRegex(AnchorHold,'seal mismatch'):
            PersistentCASAnchor(self.path,reviewer_key=self.reviewkey,seal_key=secrets.token_bytes(32),research_unsafe_sqlite=True)

    def test_prepare_abort_and_finalize_seals_stay_valid_after_reopen(self):
        i=self.pending_from_genesis()
        self.a.prepare(i)
        again=PersistentCASAnchor(self.path,reviewer_key=self.reviewkey,seal_key=self.sealkey,research_unsafe_sqlite=True)
        self.assertEqual(again.status().pending,i)
        again.adjudicate(i,'ABORT_NOT_COMMITTED',self.approve(i,'ABORT_NOT_COMMITTED'))
        self.assertIsNone(self.a.status().pending)
        j=replace(i,request_id='1'*32)
        again.prepare(j)
        self.a.adjudicate(j,'FINALIZE_COMMIT',self.approve(j,'FINALIZE_COMMIT'))
        third=PersistentCASAnchor(self.path,reviewer_key=self.reviewkey,seal_key=self.sealkey,research_unsafe_sqlite=True)
        self.assertEqual(third.status().committed.version,1)
        self.assertIsNone(third.status().pending)

    def test_plain_v076_legacy_authority_refused(self):
        # Legacy schema cannot be authenticated retroactively. Negative migration gate.
        legacy=self.root/'legacy.db'
        legacy.touch(mode=0o600)
        with closing(sqlite3.connect(legacy)) as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('CREATE TABLE authority(id INTEGER PRIMARY KEY,store_id TEXT,version INTEGER,digest TEXT,pending BLOB)')
            db.execute('INSERT INTO authority VALUES(1,?,?,?,NULL)',(self.genesis.store_id,0,self.genesis.digest))
            db.commit()
        with self.assertRaisesRegex(AnchorHold,'unsealed legacy'):
            PersistentCASAnchor(legacy,reviewer_key=self.reviewkey,seal_key=self.sealkey,research_unsafe_sqlite=True)

    def test_sqlite_wal_reset_runtime_gate(self):
        self.assertFalse(sqlite_wal_reset_safe((3,46,1)))
        self.assertFalse(sqlite_wal_reset_safe((3,51,2)))
        self.assertTrue(sqlite_wal_reset_safe((3,51,3)))
        self.assertTrue(sqlite_wal_reset_safe((3,50,7)))
        self.assertTrue(sqlite_wal_reset_safe((3,44,6)))
        self.assertFalse(sqlite_wal_reset_safe((3,50,6)))
        if not sqlite_wal_reset_safe():
            # v0.7.9 narrow migration: anchor uses DELETE/EXTRA; WAL StateStore
            # and every other WAL user retain the unpatched-runtime block.
            a=PersistentCASAnchor(self.path,reviewer_key=self.reviewkey,seal_key=self.sealkey)
            with a._db() as db:
                self.assertEqual(db.execute('PRAGMA journal_mode').fetchone()[0], 'delete')
                self.assertEqual(db.execute('PRAGMA synchronous').fetchone()[0], 3)
            with self.assertRaisesRegex(AnchorHold,'WAL-reset'):
                require_sqlite_wal_safe()
        require_sqlite_wal_safe(research_override=True)

    def test_same_key_as_reviewer_denied(self):
        with self.assertRaises(ValueError):
            PersistentCASAnchor(self.path,reviewer_key=self.sealkey,seal_key=self.sealkey,research_unsafe_sqlite=True)

    def test_joint_rollback_still_undetectable(self):
        # HMAC confirms authentication but not freshness if authority DB itself can roll back.
        with closing(sqlite3.connect(self.path)) as src,closing(sqlite3.connect(self.root/'backup.sqlite')) as dst:
            src.backup(dst)
        i=self.pending_from_genesis();self.a.prepare(i)
        self.a.adjudicate(i,'FINALIZE_COMMIT',self.approve(i,'FINALIZE_COMMIT'))
        with closing(sqlite3.connect(self.root/'backup.sqlite')) as src,closing(sqlite3.connect(self.path)) as dst:
            src.backup(dst)
        self.assertEqual(self.a.status().committed.version,0)
        # A prior valid seal does not provide independent monotonic freshness.

if __name__=='__main__': unittest.main()
