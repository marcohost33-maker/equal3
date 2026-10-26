"""v0.7.9 rollback-journal migration and runtime policy negative tests.
Research only; not power-loss/VFS/hardware evidence.
"""
from contextlib import closing
from unittest import mock
from pathlib import Path
import hmac, hashlib, os, secrets, sqlite3, tempfile, unittest
from concurrent.futures import ThreadPoolExecutor
from anchor_protocol import Position, Intent, AnchorHold, _review_message
from anchor_wire import PersistentCASAnchor

class RollbackAnchorTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);os.chmod(self.root,0o700)
        self.path=self.root/'anchor.db'
        self.review_key=secrets.token_bytes(32);self.seal_key=secrets.token_bytes(32)
        self.genesis=Position('a'*32,0,'b'*64)

    def new(self, **kw):
        return PersistentCASAnchor.bootstrap(self.path,self.genesis,
            reviewer_key=self.review_key,seal_key=self.seal_key,**kw)

    def test_withdrawn_sqlite_352_not_approved(self):
        from anchor_wire import sqlite_wal_reset_safe
        self.assertFalse(sqlite_wal_reset_safe((3,52,0)))
        self.assertTrue(sqlite_wal_reset_safe((3,54,1)))
        self.assertTrue(sqlite_wal_reset_safe((3,53,4)))
        self.assertFalse(sqlite_wal_reset_safe((3,46,1)))

    def test_bootstrap_uses_delete_extra_even_with_unpatched_sqlite(self):
        self.new()
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute('PRAGMA journal_mode').fetchone()[0],'delete')
        with PersistentCASAnchor(self.path,reviewer_key=self.review_key,seal_key=self.seal_key)._db() as db:
            self.assertEqual(db.execute('PRAGMA synchronous').fetchone()[0],3)


    def test_restart_without_research_override(self):
        self.new()
        again=PersistentCASAnchor(self.path,reviewer_key=self.review_key,seal_key=self.seal_key)
        self.assertEqual(again.status().committed.version,0)

    def test_legacy_wal_anchor_refused_without_auto_migration(self):
        self.new()
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute('PRAGMA journal_mode=WAL').fetchone()[0],'wal')
            db.commit()
        for opts in ({},{'research_unsafe_sqlite':True}):
            with self.assertRaisesRegex(AnchorHold,'WAL/non-DELETE'):
                PersistentCASAnchor(self.path,reviewer_key=self.review_key,seal_key=self.seal_key,**opts)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute('PRAGMA journal_mode').fetchone()[0],'wal')

    def test_nonexistent_anchor_never_auto_genesis(self):
        with self.assertRaises(FileNotFoundError):
            PersistentCASAnchor(self.path,reviewer_key=self.review_key,seal_key=self.seal_key)

    def test_rollback_journal_status_and_write_after_restart(self):
        a=self.new()
        intent=Intent('a'*32,0,'b'*64,1,'c'*64,secrets.token_hex(16),'d'*64)
        a.prepare(intent)
        assert a.status().pending == intent
        b=PersistentCASAnchor(self.path,reviewer_key=self.review_key,seal_key=self.seal_key)
        self.assertEqual(b.status().pending,intent)
        auth=hmac.new(self.review_key,_review_message(intent,'FINALIZE_COMMIT'),hashlib.sha256).digest()
        b.adjudicate(intent,'FINALIZE_COMMIT',auth)
        self.assertEqual(a.status().committed.version,1)
        self.assertIsNone(a.status().pending)
        self.assertFalse((self.root/'anchor.db-wal').exists())

    def test_failed_transaction_does_not_corrupt_state(self):
        a=self.new()
        invalid=Intent('a'*32,1,'b'*64,2,'c'*64,secrets.token_hex(16),'d'*64)
        with self.assertRaises(AnchorHold):a.prepare(invalid)
        self.assertEqual(a.status().committed.version,0)
        self.assertIsNone(a.status().pending)

    def test_concurrent_reads_deterministic(self):
        a=self.new()
        with ThreadPoolExecutor(max_workers=6) as pool:
            versions=list(pool.map(lambda _:a.status().committed.version, range(30)))
        self.assertEqual(versions,[0]*30)

    def test_external_sqlite_mode_switch_detected(self):
        a=self.new()
        with closing(sqlite3.connect(self.path)) as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.commit()
        with self.assertRaisesRegex(AnchorHold,'WAL/non-DELETE'):
            a.status()

    def test_preopen_wal_header_rejected_before_sqlite_connect(self):
        self.new()
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute('PRAGMA journal_mode=WAL').fetchone()[0], 'wal')
        with mock.patch('anchor_wire.sqlite3.connect',side_effect=AssertionError('must not open WAL')):
            with self.assertRaisesRegex(AnchorHold,'WAL/non-DELETE'):
                PersistentCASAnchor(self.path,reviewer_key=self.review_key,seal_key=self.seal_key)

    def test_wal_sidecar_rejected_before_sqlite_connect(self):
        self.new()
        (self.root/'anchor.db-wal').write_bytes(b'artificial sidecar')
        with mock.patch('anchor_wire.sqlite3.connect',side_effect=AssertionError('must not open WAL')):
            with self.assertRaisesRegex(AnchorHold,'sidecar'):
                PersistentCASAnchor(self.path,reviewer_key=self.review_key,seal_key=self.seal_key)

    def test_invalid_file_header_rejected_without_sqlite_connect(self):
        self.new()
        data=bytearray(self.path.read_bytes());data[0]=0
        self.path.write_bytes(data)
        with mock.patch('anchor_wire.sqlite3.connect',side_effect=AssertionError('must not open corrupt header')):
            with self.assertRaisesRegex(AnchorHold,'invalid SQLite header'):
                PersistentCASAnchor(self.path,reviewer_key=self.review_key,seal_key=self.seal_key)

    def test_no_downgrade_to_memory_or_off(self):
        self.new()
        a=PersistentCASAnchor(self.path,reviewer_key=self.review_key,seal_key=self.seal_key)
        with a._db() as db:
            self.assertEqual(db.execute('PRAGMA journal_mode').fetchone()[0],'delete')
            self.assertEqual(db.execute('PRAGMA synchronous').fetchone()[0],3)

    def test_research_override_does_not_enable_wal(self):
        self.new(research_unsafe_sqlite=True)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute('PRAGMA journal_mode').fetchone()[0],'delete')

if __name__ == '__main__':unittest.main()

class GroupSocketIsolationTests(unittest.TestCase):
    def test_group_socket_directory_policy(self):
        import anchor_wire
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);os.chmod(root,0o700)
            # mode 0710 prevents non-group users from traversing.
            with self.assertRaises(PermissionError):
                anchor_wire._require_socket_parent(root/'sock',os.getegid())
            os.chmod(root,0o710)
            anchor_wire._require_socket_parent(root/'sock',os.getegid())

    @unittest.skipUnless(os.geteuid()==0 and hasattr(os,'setuid'),'requires isolated root-capable test container')
    def test_separate_uid_can_connect_but_cannot_read_anchor(self):
        import subprocess, sys, time, socket, anchor_wire
        root_uid=os.geteuid()
        nobody=65534
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);os.chmod(base,0o700)
            private=base/'private'; private.mkdir(mode=0o700)
            socket_dir=base/'socket';socket_dir.mkdir(mode=0o700)
            os.chown(socket_dir,root_uid,nobody);os.chmod(socket_dir,0o710)
            os.chmod(base,0o711)
            dbpath=private/'anchor.db';sockpath=socket_dir/'authority.sock'
            reviewer=secrets.token_bytes(32);seal=secrets.token_bytes(32);writer=secrets.token_bytes(32)
            a=PersistentCASAnchor.bootstrap(dbpath,Position('a'*32,0,'b'*64),reviewer_key=reviewer,seal_key=seal)
            keys={}
            for name,value in [('writer',writer),('reviewer',reviewer),('seal',seal)]:
                keyfile=private/(name+'.key');keyfile.write_bytes(value);os.chmod(keyfile,0o600);keys[name]=keyfile
            proc=subprocess.Popen([sys.executable,'-u',str(Path(anchor_wire.__file__)),
                '--db',str(dbpath),'--socket',str(sockpath),
                '--writer-key-file',str(keys['writer']),
                '--reviewer-key-file',str(keys['reviewer']),
                '--seal-key-file',str(keys['seal']),
                '--writer-uid',str(nobody),'--writer-gid',str(nobody),
                '--allow-unattested-research-only'],
                stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            try:
                deadline=time.monotonic()+4
                while not sockpath.exists() and proc.poll() is None and time.monotonic()<deadline:
                    time.sleep(.025)
                if proc.poll() is not None:
                    self.fail('daemon failed: '+proc.stderr.read().decode(errors='replace'))
                self.assertTrue(sockpath.exists())
                uid_script='''import os,sys\nfrom anchor_wire import RPCAnchor\np=sys.argv[1];key=bytes.fromhex(sys.argv[2]);private=sys.argv[3]\nassert os.geteuid()==65534\nassert RPCAnchor(p,writer_key=key).status().committed.version==0\ntry:\n open(private+'/anchor.db','rb')\n raise AssertionError('writer must not read anchor DB')\nexcept PermissionError:pass\ntry:\n open(private+'/reviewer.key','rb')\n raise AssertionError('writer must not read reviewer key')\nexcept PermissionError:pass\n'''
                def drop():
                    os.setgroups([]);os.setgid(nobody);os.setuid(nobody)
                result=subprocess.run([sys.executable,'-c',uid_script,str(sockpath),writer.hex(),str(private)],
                    cwd=str(Path(anchor_wire.__file__).parent),preexec_fn=drop,capture_output=True,text=True,timeout=6)
                self.assertEqual(result.returncode,0,result.stderr)
                with self.assertRaises(AnchorHold):
                    anchor_wire.RPCAnchor(sockpath,writer_key=writer,timeout=0.2).status()
            finally:
                proc.terminate()
                try:proc.wait(timeout=4)
                except subprocess.TimeoutExpired:proc.kill();proc.wait()
                if proc.stderr:proc.stderr.close()
                os.chmod(base,0o700)
