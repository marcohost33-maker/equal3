"""SQLite DELETE/EXTRA reference-mode regression. This is NOT a patched-runtime attestation."""
from __future__ import annotations
import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from contextlib import closing
from state_store import StateStore, StoreError, prepare_update, IntegrityError

KEY = bytes.fromhex('32' * 32)

class RollbackJournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'data.sqlite'
        self.store=StateStore.create(self.path,key=KEY,initial=b'origin',journal_mode='DELETE')

    def test_header_delete_and_extra_sync(self):
        h=self.path.read_bytes()[:100]
        self.assertEqual(h[18:20],b'\x01\x01')
        with closing(self.store._db()) as db:
            self.assertEqual(db.execute('PRAGMA journal_mode').fetchone()[0],'delete')
            self.assertEqual(db.execute('PRAGMA synchronous').fetchone()[0],3)

    def test_create_read_apply_receipt_reopen(self):
        pkt,rid=prepare_update(self.store,b'new values')
        result=self.store.apply(pkt)
        self.assertEqual(result.version,1)
        self.assertEqual(self.store.read().value,b'new values')
        self.assertEqual(self.store.receipt(rid).version,1)
        reopened=StateStore(self.path,key=KEY,journal_mode='DELETE')
        self.assertEqual(reopened.verify()['receipt_count'],1)
        self.assertTrue(reopened.apply(pkt).already_committed)

    def test_wal_database_rejected_before_sqlite_connect(self):
        wal=Path(self.tmp.name)/'wal.sqlite'
        StateStore.create(wal,key=KEY,initial=b'origin')
        with mock.patch('state_store._connect',side_effect=AssertionError('should not open SQLite')):
            with self.assertRaisesRegex(StoreError,'not a DELETE-journal'):
                StateStore(wal,key=KEY,journal_mode='DELETE')

    def test_rollback_database_rejected_when_caller_expects_wal(self):
        with self.assertRaisesRegex(StoreError,'journal policy drift'):
            StateStore(self.path,key=KEY)

    def test_refuse_stale_wal_sidecars(self):
        p=Path(str(self.path)+'-wal')
        p.write_bytes(b'dummy')
        with self.assertRaisesRegex(StoreError,'WAL sidecar'):
            self.store.read()

    def test_refuse_rollback_database_symlink(self):
        link=Path(self.tmp.name)/'link.sqlite'; link.symlink_to(self.path)
        with self.assertRaisesRegex(StoreError,'symlink'):
            StateStore(link,key=KEY,journal_mode='DELETE')

    def test_bad_policy_rejected(self):
        for p in ('delete','WAL;ATTACH',None,123,'TRUNCATE'):
            with self.subTest(policy=p),self.assertRaisesRegex(StoreError,'journal policy'):
                StateStore(self.path,key=KEY,journal_mode=p)

    def test_wal_checkpoint_forbidden(self):
        with self.assertRaisesRegex(StoreError,'WAL checkpoint unavailable'):
            self.store.checkpoint(mode='TRUNCATE')

    def test_backup_restores_rollback_journal_policy(self):
        pkt,_=prepare_update(self.store,b'backup target')
        self.store.apply(pkt)
        dest=Path(self.tmp.name)/'backup.sqlite'
        report=self.store.backup_verified(dest)
        self.assertEqual(report['version'],1)
        self.assertEqual(dest.read_bytes()[18:20],b'\x01\x01')
        self.assertEqual(StateStore(dest,key=KEY,journal_mode='DELETE').read().value,b'backup target')

    def test_precommit_exception_rolls_back(self):
        pkt,_=prepare_update(self.store,b'not committed')
        def failure(phase):
            if phase=='after_cas':raise RuntimeError('injected stop')
        with self.assertRaisesRegex(RuntimeError,'injected stop'):
            self.store.apply(pkt,fault=failure)
        self.assertEqual(self.store.read().version,0)

    def test_child_process_abort_after_begin_recovers(self):
        pkt,_=prepare_update(self.store,b'crash')
        script='''import os,sys
from state_store import StateStore
p=sys.argv[1]
s=StateStore(p,key=bytes.fromhex('32'*32),journal_mode='DELETE')
s.apply(bytes.fromhex(sys.argv[2]),fault=lambda x: os._exit(42) if x=='after_cas' else None)
'''
        result=subprocess.run([sys.executable,'-c',script,str(self.path),pkt.hex()],
                              cwd=Path(__file__).resolve().parent,timeout=12,check=False)
        self.assertEqual(result.returncode,42)
        self.assertEqual(self.store.verify()['version'],0)

if __name__=='__main__':unittest.main()

class RollbackMultiProcessTests(unittest.TestCase):
    def test_separate_readers_and_two_concurrent_writers_preserve_cas(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'store.sqlite'
            store=StateStore.create(path,key=KEY,initial=b'origin',journal_mode='DELETE')
            first, _=prepare_update(store,b'first')
            second,_=prepare_update(store,b'second')
            code='''import sys
from state_store import StateStore,ConflictError
p=StateStore(sys.argv[1],key=bytes.fromhex('32'*32),journal_mode='DELETE')
try:
 p.apply(bytes.fromhex(sys.argv[2]));sys.exit(0)
except ConflictError:sys.exit(17)
'''
            p1=subprocess.Popen([sys.executable,'-c',code,str(path),first.hex()],cwd=Path(__file__).resolve().parent)
            p2=subprocess.Popen([sys.executable,'-c',code,str(path),second.hex()],cwd=Path(__file__).resolve().parent)
            rc1=p1.wait(timeout=20);rc2=p2.wait(timeout=20)
            self.assertEqual(sorted((rc1,rc2)),[0,17])
            self.assertEqual(store.verify()['version'],1)
            self.assertIn(store.read().value,(b'first',b'second'))

    def test_missing_rollback_store_not_created_by_open(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'absent.sqlite'
            with self.assertRaises(StoreError):StateStore(p,key=KEY,journal_mode='DELETE')
            self.assertFalse(p.exists())

    def test_abort_after_commit_reports_unknown_but_receipt_is_authentic(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'store.sqlite'
            store=StateStore.create(path,key=KEY,initial=b'origin',journal_mode='DELETE')
            pkt,rid=prepare_update(store,b'committed')
            code='''import os,sys
from state_store import StateStore
s=StateStore(sys.argv[1],key=bytes.fromhex('32'*32),journal_mode='DELETE')
s.apply(bytes.fromhex(sys.argv[2]),fault=lambda x: os._exit(43) if x=='after_commit' else None)
'''
            result=subprocess.run([sys.executable,'-c',code,str(path),pkt.hex()],cwd=Path(__file__).resolve().parent,timeout=15)
            self.assertEqual(result.returncode,43)
            self.assertEqual(store.read().value,b'committed')
            self.assertEqual(store.receipt(rid).version,1)

class RollbackCLIIntegrationTests(unittest.TestCase):
    def test_cli_create_and_status_delete_mode(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);db=root/'db.sqlite';key=root/'secret';initial=root/'initial'
            key.write_bytes(KEY);os.chmod(key,0o600)
            initial.write_bytes(b'hello')
            base=[sys.executable,str(Path(__file__).parent/'store_cli.py')]
            proc=subprocess.run(base+['init',str(db),str(initial),'--key-file',str(key),'--journal-mode','DELETE'],capture_output=True,text=True,timeout=10)
            self.assertEqual(proc.returncode,0,proc.stderr)
            proc=subprocess.run(base+['status',str(db),'--key-file',str(key),'--journal-mode','DELETE'],capture_output=True,text=True,timeout=10)
            self.assertEqual(proc.returncode,0,proc.stderr)
            self.assertIn('"version": 0',proc.stdout)
            proc=subprocess.run(base+['status',str(db),'--key-file',str(key)],capture_output=True,text=True,timeout=10)
            self.assertNotEqual(proc.returncode,0,'WAL-only CLI must not open DELETE database')
