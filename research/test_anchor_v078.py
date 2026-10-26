"""Equal3 v0.7.8 – adversarial audit-ledger checks; synthetic data only."""
from contextlib import closing
from pathlib import Path
import hashlib
import hmac
import os
import secrets
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

from anchor_protocol import AnchorHold, Intent, Position, _review_message
from anchor_wire import PersistentCASAnchor

class LedgerIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name); os.chmod(self.root,0o700)
        self.path=self.root/'anchor.sqlite'
        self.reviewer=secrets.token_bytes(32); self.seal=secrets.token_bytes(32)
        self.genesis=Position('a'*32,0,'b'*64)
        self.backend=PersistentCASAnchor.bootstrap(self.path,self.genesis,reviewer_key=self.reviewer,seal_key=self.seal,research_unsafe_sqlite=True)

    def offline(self,sql,params=()):
        with closing(sqlite3.connect(self.path)) as db:
            db.execute(sql,params); db.commit()

    def commit_one(self):
        i=Intent('a'*32,0,'b'*64,1,'c'*64,secrets.token_hex(16),'d'*64)
        self.backend.prepare(i,nonce='e'*32)
        token=hmac.new(self.reviewer,_review_message(i,'FINALIZE_COMMIT'),hashlib.sha256).digest()
        self.backend.adjudicate(i,'FINALIZE_COMMIT',token,nonce='f'*32)
        self.assertEqual(self.backend.status().committed.version,1)
        return i

    def test_genesis_audit_root_present(self):
        with closing(sqlite3.connect(self.path)) as db:
            row=db.execute('SELECT audit_root FROM authority WHERE id=1').fetchone()
        self.assertEqual(len(row[0]),32)

    def test_valid_prepare_finalize_restart(self):
        self.commit_one()
        reopened=PersistentCASAnchor(self.path,reviewer_key=self.reviewer,seal_key=self.seal,research_unsafe_sqlite=True)
        self.assertEqual(reopened.status().committed.version,1)

    def test_consume_nonce_deletion_fail_closed(self):
        self.commit_one(); self.offline("DELETE FROM consumed WHERE nonce=?",('e'*32,))
        with self.assertRaises(AnchorHold):self.backend.status()

    def test_consume_operation_modified_fail_closed(self):
        self.commit_one();self.offline("UPDATE consumed SET operation='prepare' WHERE nonce=?",('f'*32,))
        with self.assertRaises(AnchorHold):self.backend.status()

    def test_review_row_modified_fail_closed(self):
        self.commit_one();self.offline("UPDATE review_log SET decision='ABORT_NOT_COMMITTED' WHERE id=1")
        with self.assertRaises(AnchorHold):self.backend.status()

    def test_review_row_deleted_fail_closed(self):
        self.commit_one();self.offline("DELETE FROM review_log WHERE id=1")
        with self.assertRaises(AnchorHold):self.backend.status()

    def test_root_modified_without_seal_key_fail_closed(self):
        self.commit_one();self.offline("UPDATE authority SET audit_root=? WHERE id=1",(b'\x77'*32,))
        with self.assertRaises(AnchorHold):self.backend.status()

    def test_inserted_fake_review_fail_closed(self):
        self.offline("INSERT INTO review_log(request_id,decision,version) VALUES(?,?,?)",('a'*32,'FINALIZE_COMMIT',1))
        with self.assertRaises(AnchorHold):self.backend.status()

    def test_inserted_fake_nonce_fail_closed(self):
        self.offline("INSERT INTO consumed(nonce,operation) VALUES(?,?)",('b'*32,'prepare'))
        with self.assertRaises(AnchorHold):self.backend.status()

    def test_raw_sql_cannot_mend_root_without_seal(self):
        self.commit_one();self.offline('DELETE FROM review_log')
        self.offline('UPDATE authority SET audit_root=? WHERE id=1',(b'\x00'*32,))
        with self.assertRaises(AnchorHold):self.backend.status()

    def test_read_snapshot_stable_during_simultaneous_status_requests(self):
        self.commit_one()
        with ThreadPoolExecutor(max_workers=6) as pool:
            versions=list(pool.map(lambda _:self.backend.status().committed.version,range(24)))
        self.assertEqual(versions,[1]*24)

    def test_legacy_v077_schema_without_audit_root_is_no_go(self):
        with closing(sqlite3.connect(self.path)) as db:
            # Synthetically re-create legacy schema; no silent migration.
            db.execute('ALTER TABLE authority RENAME TO old_authority')
            db.execute('CREATE TABLE authority(id INTEGER PRIMARY KEY CHECK(id=1),store_id TEXT,version INTEGER,digest TEXT,pending BLOB,seal BLOB)')
            db.execute('INSERT INTO authority SELECT id,store_id,version,digest,pending,seal FROM old_authority')
            db.execute('DROP TABLE old_authority');db.commit()
        with self.assertRaises(AnchorHold):
            PersistentCASAnchor(self.path,reviewer_key=self.reviewer,seal_key=self.seal,research_unsafe_sqlite=True)

if __name__=='__main__':unittest.main()
