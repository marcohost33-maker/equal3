"""Equal3 v0.7.1: backups, SQL faults, ENOSPC-style SQLITE_FULL, defensive schema."""
from __future__ import annotations
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest import mock
import state_store as ss

KEY=b'Equal3-v071-test-only-key-32-byte-secret-not-for-production'

class StoreDurabilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder=Path(self.tmp.name)
        self.path=self.folder/'store.db'
        self.store=ss.StateStore.create(self.path,key=KEY,initial=b'old'*512)

    def change(self, target=b'new'*512):
        proposal, rid=ss.prepare_update(self.store,target)
        return self.store.apply(proposal),rid

    def test_backup_roundtrip_and_receipts(self):
        self.change()
        snap=self.store.read()
        dest=self.folder/'backup.db'
        report=self.store.backup_verified(dest)
        b=ss.StateStore(dest,key=KEY)
        self.assertEqual(b.read(),snap)
        self.assertEqual(report['version'],1)
        self.assertEqual(b.verify()['receipt_count'],1)
        self.assertTrue(dest.is_file())
        self.assertFalse(any(p.name.startswith('.eq3-backup-') for p in self.folder.iterdir()))

    def test_backup_refuses_existing_path_without_overwrite(self):
        dest=self.folder/'backup.db'
        dest.write_bytes(b'KEEP-ME')
        with self.assertRaises(ss.StoreError):self.store.backup_verified(dest)
        self.assertEqual(dest.read_bytes(),b'KEEP-ME')

    def test_concurrent_destination_creator_not_overwritten(self):
        dest=self.folder/'backup.db'
        def adversary(stage):
            if stage=='before_replace':dest.write_bytes(b'RACE-WINNER')
        with self.assertRaises(FileExistsError):self.store.backup_verified(dest,fault=adversary)
        self.assertEqual(dest.read_bytes(),b'RACE-WINNER')
        self.assertFalse(any(p.name.startswith('.eq3-backup-') for p in self.folder.iterdir()))

    def test_prepublication_failure_cleanup(self):
        dest=self.folder/'backup.db'
        for event in ('after_temp','after_sqlite_backup','after_validation','before_replace'):
            with self.subTest(event=event):
                def fail(step):
                    if step==event:raise OSError('injected')
                with self.assertRaises(OSError):self.store.backup_verified(dest,fault=fail)
                self.assertFalse(dest.exists())
                self.assertFalse(any(p.name.startswith('.eq3-backup-') for p in self.folder.iterdir()))

    def test_postpublication_uncertainty_and_cleanup(self):
        dest=self.folder/'backup.db'
        def fail(step):
            if step=='after_replace':raise OSError('simulated acknowledgement failure')
        with self.assertRaises(ss.BackupOutcomeUnknown):self.store.backup_verified(dest,fault=fail)
        self.assertTrue(dest.exists())
        self.assertEqual(ss.StateStore(dest,key=KEY).read(),self.store.read())
        self.assertFalse(any(p.name.startswith('.eq3-backup-') for p in self.folder.iterdir()))

    def test_key_check_enforced_on_backup(self):
        dest=self.folder/'backup.db'
        self.store.backup_verified(dest)
        with self.assertRaises(ss.AuthenticationError):ss.StateStore(dest,key=b'Z'*32)

    def test_backup_refuses_corrupted_head_and_stays_unpublished(self):
        with closing(self.store._db()) as db, db:
            db.execute('UPDATE head SET digest=? WHERE id=1',(b'\xFF'*32,))
        with self.assertRaises(ss.IntegrityError):self.store.backup_verified(self.folder/'corrupt.db')
        self.assertFalse((self.folder/'corrupt.db').exists())

    def test_sqlite_full_with_page_limit_preserves_state_and_receipt(self):
        target=os.urandom(300_000)
        proposal,rid=ss.prepare_update(self.store,target)
        original=self.store._db
        def limited():
            db=original()
            pages=db.execute('PRAGMA page_count').fetchone()[0]
            actual=db.execute(f'PRAGMA max_page_count={pages+2}').fetchone()[0]
            self.assertLessEqual(actual,pages+2)
            return db
        with mock.patch.object(self.store,'_db',side_effect=limited):
            with self.assertRaises(sqlite3.OperationalError) as ctx:
                self.store.apply(proposal)
        self.assertIn('full',str(ctx.exception).lower())
        fresh=ss.StateStore(self.path,key=KEY)
        self.assertEqual(fresh.read().version,0)
        self.assertIsNone(fresh.receipt(rid))
        self.assertEqual(fresh.verify()['receipt_count'],0)
        # Recovery: retry same proposal in a healthy connection (not new request).
        self.assertEqual(fresh.apply(proposal).version,1)

    def test_receipt_insert_sql_abort_rolls_back_cas(self):
        proposal,rid=ss.prepare_update(self.store,b'new')
        with closing(self.store._db()) as db, db:
            db.execute('CREATE TRIGGER block_receipt BEFORE INSERT ON receipts BEGIN SELECT RAISE(ABORT,"test-sql-fault"); END;')
        with self.assertRaises(sqlite3.DatabaseError):self.store.apply(proposal)
        self.assertEqual(self.store.read().version,0)
        self.assertIsNone(self.store.receipt(rid))
        with closing(self.store._db()) as db, db:db.execute('DROP TRIGGER block_receipt')
        self.assertEqual(self.store.apply(proposal).version,1)

    def test_invalid_schema_types_fail_cleanly(self):
        with closing(self.store._db()) as db, db:
            db.execute('UPDATE head SET digest=? WHERE id=1',(b'broken',))
        with self.assertRaises(ss.IntegrityError):ss.StateStore(self.path,key=KEY)
        with self.assertRaises(ss.IntegrityError):self.store.verify()

    def test_checkpoint_starvation_is_reported_not_misread_as_corruption(self):
        reader=self.store._db()
        reader.execute('BEGIN')
        reader.execute('SELECT version FROM head').fetchone()
        try:
            for i in range(4):
                self.change(bytes([i])*10000)
            with closing(self.store._db()) as maintenance, maintenance:
                maintenance.execute('PRAGMA busy_timeout=100')
                busy,log_frames,done=maintenance.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()
                self.assertEqual(busy,1)
                self.assertGreater(log_frames,0)
                self.assertLessEqual(done,log_frames)
        finally:
            reader.execute('ROLLBACK')
            reader.close()
        with closing(self.store._db()) as maintenance, maintenance:
            busy,log_frames,done=maintenance.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()
            self.assertEqual((busy,log_frames,done),(0,0,0))
        self.assertEqual(self.store.verify()['version'],4)

    def test_backup_under_concurrent_updates_is_consistent_snapshot(self):
        errors=[]
        def worker():
            try:
                for i in range(15):
                    msg,_=ss.prepare_update(self.store, i.to_bytes(4,'big'))
                    self.store.apply(msg)
            except Exception as exc:errors.append(str(exc))
        thread=threading.Thread(target=worker)
        thread.start()
        dst=self.folder/'during.db'
        self.store.backup_verified(dst)
        thread.join(timeout=15)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors,[])
        report=ss.StateStore(dst,key=KEY).verify()
        self.assertGreaterEqual(report['version'],0)
        self.assertLessEqual(report['version'],15)
        self.assertEqual(self.store.verify()['version'],15)

if __name__=='__main__':unittest.main()

class CommandTests(unittest.TestCase):
    def test_cli_backup_and_checkpoint(self):
        import subprocess,sys,json
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            keyf=root/'secret.key';keyf.write_bytes(KEY);os.chmod(keyf,0o600)
            store=ss.StateStore.create(root/'store.db',key=KEY,initial=b'seed')
            cmd=[sys.executable,str(Path(__file__).parent/'store_cli.py')]
            backup=subprocess.run(cmd+['backup',str(store.path),str(root/'backup.db'),'--key-file',str(keyf)],capture_output=True,text=True,timeout=20)
            self.assertEqual(backup.returncode,0,backup.stderr)
            self.assertTrue(json.loads(backup.stdout)['backup_created'])
            self.assertEqual(ss.StateStore(root/'backup.db',key=KEY).read().value,b'seed')
            checkpoint=subprocess.run(cmd+['checkpoint',str(store.path),'--key-file',str(keyf),'--mode','PASSIVE'],capture_output=True,text=True,timeout=20)
            self.assertEqual(checkpoint.returncode,0,checkpoint.stderr)
            self.assertEqual(json.loads(checkpoint.stdout)['mode'],'PASSIVE')

class ProcessCrashBackupTests(unittest.TestCase):
    def test_backup_process_abort_before_and_after_publish(self):
        import subprocess,sys
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);source=root/'source.db';destination=root/'backup.db'
            ss.StateStore.create(source,key=KEY,initial=b'survives')
            for stage,expected_visible in [('after_validation',False),('after_replace',True)]:
                script=('import os,sys,state_store as s; '
                        'store=s.StateStore(sys.argv[1],key=bytes.fromhex(sys.argv[3])); '
                        'store.backup_verified(sys.argv[2],fault=lambda stage:os._exit(77) if stage==sys.argv[4] else None)')
                run=subprocess.run([sys.executable,'-c',script,str(source),str(destination),KEY.hex(),stage],
                                  cwd=str(Path(__file__).parent),capture_output=True,text=True,timeout=15)
                self.assertEqual(run.returncode,77,run.stderr)
                self.assertEqual(destination.exists(),expected_visible)
                self.assertEqual(ss.StateStore(source,key=KEY).read().value,b'survives')
                if expected_visible:
                    self.assertEqual(ss.StateStore(destination,key=KEY).read().value,b'survives')
                # A process kill does not run finally; orphan temp names may remain.
                for orphan in root.glob('.eq3-backup-*'):
                    orphan.unlink()
