"""Non-production integration probes for the v0.7.6 persistent anchor prototype."""
import concurrent.futures
from contextlib import closing
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

from anchor_protocol import (CoordinatedStore, AnchorHold, ReviewDenied,
                             Position, Intent, _review_message, position_for_genesis)
from anchor_wire import (PersistentCASAnchor, RPCAnchor, WireError, _auth_mac,
                         canonical, read_credential)
from state_store import StateStore, prepare_update


class PersistentAnchorTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.spath=self.root/'state.sqlite'
        self.dbpath=self.root/'anchor.sqlite'
        self.sock=self.root/'authority.sock'
        self.wkey=secrets.token_bytes(32)
        self.rkey=secrets.token_bytes(32)
        self.skey=secrets.token_bytes(32)
        self.store=StateStore.create(self.spath,key=secrets.token_bytes(32),initial=b'genesis')
        self.initial=position_for_genesis(self.store)
        self.backend=PersistentCASAnchor.bootstrap(self.dbpath,self.initial,reviewer_key=self.rkey,seal_key=self.skey,research_unsafe_sqlite=True)
        self.proc=None
        self.start()

    def start(self):
        self.proc=subprocess.Popen([sys.executable,'-u','anchor_wire.py',
            '--db',str(self.dbpath),'--socket',str(self.sock),
            '--writer-key-file',str(self._secret('writer.key',self.wkey)),
            '--reviewer-key-file',str(self._secret('review.key',self.rkey)),
            '--seal-key-file',str(self._secret('seal.key',self.skey)),
            '--allow-unsafe-sqlite-research-only','--allow-unattested-research-only',
            '--writer-uid',str(os.getuid())],cwd=str(Path(__file__).parent),
            stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        self.addCleanup(self.stop)
        deadline=time.monotonic()+4
        while time.monotonic()<deadline:
            if self.proc.poll() is not None:
                out=self.proc.stderr.read().decode(errors='replace')
                self.fail('anchor daemon startup failed: '+out)
            if self.sock.exists():
                try:
                    c=RPCAnchor(self.sock,writer_key=self.wkey)
                    c.status()
                    self.proxy=c
                    self.client=CoordinatedStore(self.store,c)
                    return
                except AnchorHold:pass
            time.sleep(.02)
        self.fail('anchor daemon startup timed out')

    def _secret(self,name,data):
        p=self.root/name
        if not p.exists():
            fd=os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
            with os.fdopen(fd,'wb') as f:f.write(data)
        return p

    def stop(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:self.proc.kill();self.proc.wait(timeout=2)
        if self.sock.exists():self.sock.unlink()
        if self.proc is not None and self.proc.stderr is not None: self.proc.stderr.close()
        self.proc=None

    def propose(self,value=b'new'):
        return prepare_update(self.store,value)[0]

    def review(self,decision):
        intent=self.proxy.status().pending
        return hmac.new(self.rkey,_review_message(intent,decision),hashlib.sha256).digest()

    def test_rpc_status_genesis(self):
        s=self.proxy.status()
        self.assertEqual(s.committed,self.initial)
        self.assertIsNone(s.pending)
        self.assertEqual(self.client.diagnose().code,'MATCH')

    def test_coordinated_prepare_restart_finalize(self):
        r=self.client.apply(self.propose(b'once'))
        self.assertEqual(r.version,1)
        self.assertEqual(self.client.diagnose().code,'COMMITTED_PENDING_HOLD')
        t=self.review('FINALIZE_COMMIT')
        self.stop();self.start()
        self.assertEqual(self.client.diagnose().code,'COMMITTED_PENDING_HOLD')
        self.client.adjudicate('FINALIZE_COMMIT',t)
        self.assertEqual(self.client.diagnose().code,'MATCH')
        self.assertEqual(self.client.read().value,b'once')

    def test_aborted_prepare_survives_restart(self):
        with self.assertRaises(AnchorHold):
            self.client.apply(self.propose(),fault=lambda where:(_ for _ in ()).throw(OSError('synthetic')) if where=='after_anchor_prepare' else None)
        self.stop();self.start()
        self.assertEqual(self.client.diagnose().code,'NOT_COMMITTED_HOLD')
        self.client.adjudicate('ABORT_NOT_COMMITTED',self.review('ABORT_NOT_COMMITTED'))
        self.assertEqual(self.client.diagnose().code,'MATCH')

    def test_commit_gap_survives_restart(self):
        with self.assertRaises(AnchorHold):
            self.client.apply(self.propose(b'postcommit'),fault=lambda where:(_ for _ in ()).throw(OSError('lost response')) if where=='after_sqlite_commit' else None)
        self.stop();self.start()
        self.assertEqual(self.client.diagnose().code,'COMMITTED_PENDING_HOLD')
        self.client.adjudicate('FINALIZE_COMMIT',self.review('FINALIZE_COMMIT'))
        self.assertEqual(self.client.read().value,b'postcommit')

    def test_wrong_reviewer_key_no_finalize(self):
        self.client.apply(self.propose())
        with self.assertRaises(ReviewDenied):
            self.client.adjudicate('FINALIZE_COMMIT',hmac.new(b'w'*32,_review_message(self.proxy.status().pending,'FINALIZE_COMMIT'),hashlib.sha256).digest())
        self.assertEqual(self.proxy.status().committed.version,0)

    def test_wrong_writer_credential_no_state(self):
        c=RPCAnchor(self.sock,writer_key=b'Z'*32,timeout=.5)
        with self.assertRaises(AnchorHold):c.status()
        self.assertEqual(self.proxy.status().committed.version,0)

    def test_credential_files_permissions(self):
        p=self.root/'world-key'
        p.write_bytes(self.wkey);os.chmod(p,0o644)
        with self.assertRaises(PermissionError):read_credential(p)

    def test_no_implicit_anchor_recreate(self):
        with self.assertRaises(FileExistsError):
            PersistentCASAnchor.bootstrap(self.dbpath,self.initial,reviewer_key=self.rkey,seal_key=self.skey,research_unsafe_sqlite=True)
        with self.assertRaises(FileNotFoundError):
            PersistentCASAnchor(self.root/'missing',reviewer_key=self.rkey,seal_key=self.skey,research_unsafe_sqlite=True)

    def test_invalid_db_symlink_refused(self):
        symlink=self.root/'alias.sqlite'
        symlink.symlink_to(self.dbpath)
        with self.assertRaises(PermissionError):PersistentCASAnchor(symlink,reviewer_key=self.rkey,seal_key=self.skey,research_unsafe_sqlite=True)

    def test_stale_version_cas_across_independent_connections(self):
        pos=self.initial
        intent=Intent(pos.store_id,0,pos.digest,1,hashlib.sha256(b'a').hexdigest(),secrets.token_hex(16),'a'*64)
        def req(_):
            try:
                RPCAnchor(self.sock,writer_key=self.wkey).prepare(intent)
                return 'PASS'
            except AnchorHold:return 'HOLD'
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            got=list(ex.map(req,range(8)))
        self.assertEqual(got.count('PASS'),1)
        self.assertEqual(got.count('HOLD'),7)
        self.assertEqual(self.proxy.status().pending,intent)

    def test_repeated_request_same_nonce_rejected(self):
        pos=self.initial
        intent=Intent(pos.store_id,0,pos.digest,1,hashlib.sha256(b'b').hexdigest(),secrets.token_hex(16),'c'*64)
        nonce=secrets.token_hex(16)
        self.backend.prepare(intent,nonce=nonce)
        # Match could no longer prepare anyway; verify persisted nonce ledger explicitly.
        with closing(sqlite3.connect(self.dbpath)) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM consumed WHERE nonce=?',(nonce,)).fetchone()[0],1)
        with self.assertRaises(AnchorHold):self.backend.prepare(intent,nonce=nonce)

    def test_rollback_of_user_db_detected_after_restart(self):
        old=self.root/'old.sqlite'
        with closing(sqlite3.connect(self.spath)) as src, closing(sqlite3.connect(old)) as dst:src.backup(dst)
        self.client.apply(self.propose(b'moved'))
        self.client.adjudicate('FINALIZE_COMMIT',self.review('FINALIZE_COMMIT'))
        self.stop()
        with closing(sqlite3.connect(old)) as src,closing(sqlite3.connect(self.spath)) as dst:src.backup(dst)
        self.start()
        self.assertEqual(self.client.diagnose().code,'ROLLBACK_HOLD')
        with self.assertRaises(AnchorHold):self.client.read()

    def test_atomic_crash_after_prepare(self):
        # Abruptly kill service while PREPARED; SQLite authority journal survives.
        pos=self.initial
        intent=Intent(pos.store_id,0,pos.digest,1,hashlib.sha256(b'y').hexdigest(),secrets.token_hex(16),'a'*64)
        self.proxy.prepare(intent)
        self.proc.kill();self.proc.wait(timeout=2)
        if self.proc.stderr is not None:self.proc.stderr.close()
        if self.sock.exists():self.sock.unlink()
        self.start()
        self.assertEqual(self.proxy.status().pending,intent)

    def test_wrong_local_uid_rejected_even_with_correct_key(self):
        self.stop()
        # Launch the server with a different expected UID; shared MAC alone cannot connect.
        self.proc=subprocess.Popen([sys.executable,'-u','anchor_wire.py',
            '--db',str(self.dbpath),'--socket',str(self.sock),
            '--writer-key-file',str(self._secret('writer.key',self.wkey)),
            '--reviewer-key-file',str(self._secret('review.key',self.rkey)),
            '--seal-key-file',str(self._secret('seal.key',self.skey)),
            '--allow-unsafe-sqlite-research-only','--allow-unattested-research-only',
            '--writer-uid',str(os.getuid()+1000)],cwd=str(Path(__file__).parent),
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        deadline=time.monotonic()+3
        while not self.sock.exists() and time.monotonic()<deadline:time.sleep(.02)
        self.assertTrue(self.sock.exists())
        with self.assertRaises(AnchorHold):RPCAnchor(self.sock,writer_key=self.wkey,timeout=.4).status()

    def test_missing_authority_service_holds(self):
        self.stop()
        with self.assertRaises(AnchorHold):self.client.read()

    def test_review_token_cannot_be_reused(self):
        self.client.apply(self.propose(b'v1'))
        t=self.review('FINALIZE_COMMIT')
        intent=self.proxy.status().pending
        self.client.adjudicate('FINALIZE_COMMIT',t)
        with self.assertRaises(ReviewDenied):self.proxy.adjudicate(intent,'FINALIZE_COMMIT',t)
        self.assertEqual(self.proxy.status().committed.version,1)

    def test_joint_storage_rollback_counterexample(self):
        # Negative result: if BOTH SQLite DBs are restored, local persistence
        # cannot prove anti-rollback. A separate trust/rollback domain is required.
        old_db=self.root/'db-backup.sqlite';old_anchor=self.root/'anchor-backup.sqlite'
        with closing(sqlite3.connect(self.spath)) as src, closing(sqlite3.connect(old_db)) as dst:src.backup(dst)
        with closing(sqlite3.connect(self.dbpath)) as src,closing(sqlite3.connect(old_anchor)) as dst:src.backup(dst)
        self.client.apply(self.propose(b'new'))
        self.client.adjudicate('FINALIZE_COMMIT',self.review('FINALIZE_COMMIT'))
        self.stop()
        with closing(sqlite3.connect(old_db)) as src, closing(sqlite3.connect(self.spath)) as dst:src.backup(dst)
        with closing(sqlite3.connect(old_anchor)) as src,closing(sqlite3.connect(self.dbpath)) as dst:src.backup(dst)
        self.start()
        self.assertEqual(self.client.diagnose().code,'MATCH')
        self.assertEqual(self.proxy.status().committed.version,0)

    def test_rpc_signed_nonce_cannot_be_replayed(self):
        pos=self.initial
        intent=Intent(pos.store_id,0,pos.digest,1,hashlib.sha256(b'z').hexdigest(),secrets.token_hex(16),'a'*64)
        body={'v':1,'op':'prepare','nonce':secrets.token_hex(16),'payload':{'intent':intent.__dict__}}
        frame=dict(body,mac=_auth_mac(self.wkey,body,'request'))
        def send():
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
                s.settimeout(2);s.connect(str(self.sock));s.sendall(canonical(frame)+b'\n')
                return json.loads(s.recv(4096))
        first=send();second=send()
        self.assertTrue(first['ok'])
        self.assertFalse(second['ok'])
        self.assertEqual(self.proxy.status().pending,intent)

    def test_missing_authentication_does_not_mutate(self):
        pos=self.initial
        intent=Intent(pos.store_id,0,pos.digest,1,hashlib.sha256(b'z').hexdigest(),secrets.token_hex(16),'a'*64)
        body={'v':1,'op':'prepare','nonce':secrets.token_hex(16),'payload':{'intent':intent.__dict__}}
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
            s.settimeout(1);s.connect(str(self.sock));s.sendall(canonical(dict(body,mac='0'*64))+b'\n')
            self.assertEqual(s.recv(4096),b'')
        self.assertIsNone(self.proxy.status().pending)

    def test_fail_closed_on_untrusted_directory(self):
        outside=self.root/'untrusted'
        outside.mkdir(mode=0o755)
        with self.assertRaises(PermissionError):
            PersistentCASAnchor.bootstrap(outside/'state.sqlite',self.initial,reviewer_key=self.rkey,seal_key=self.skey,research_unsafe_sqlite=True)

    def test_daemon_rejects_corrupted_anchor_database(self):
        self.stop()
        with open(self.dbpath,'r+b') as f:
            f.seek(0);f.write(b'CORRUPT!');f.flush();os.fsync(f.fileno())
        with self.assertRaises((sqlite3.DatabaseError,AnchorHold)):
            PersistentCASAnchor(self.dbpath,reviewer_key=self.rkey,seal_key=self.skey,research_unsafe_sqlite=True)

    def test_offline_client_rejects_mismatched_authority(self):
        self.stop()
        with closing(sqlite3.connect(self.dbpath)) as db:
            db.execute('UPDATE authority SET store_id=? WHERE id=1',('a'*32,));db.commit()
        with self.assertRaises(AnchorHold):
            PersistentCASAnchor(self.dbpath,reviewer_key=self.rkey,seal_key=self.skey,research_unsafe_sqlite=True)

    def test_ambiguous_duplicate_json_key_rejected(self):
        # Duplicate JSON keys are not canonical and must not be accepted by
        # the service, even if the trailing field would decode successfully.
        body={'v':1,'op':'status','nonce':secrets.token_hex(16),'payload':{}}
        good=_auth_mac(self.wkey,body,'request')
        broken=(b'{"v":1,"op":"status","op":"prepare","nonce":"'+
                body['nonce'].encode()+b'","payload":{},"mac":"'+good.encode()+b'"}\n')
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
            s.settimeout(2);s.connect(str(self.sock));s.sendall(broken)
            self.assertEqual(s.recv(4096),b'')
        self.assertIsNone(self.proxy.status().pending)

    def test_abrupt_subprocess_death_inside_anchor_sqlite_transaction(self):
        # SIGKILL-like process death, NOT power-loss/VFS failure. Demonstrates
        # incomplete local SQL transaction is not considered a committed anchor.
        command=("import os,sqlite3; db=sqlite3.connect(%r); "
                 "db.execute('BEGIN IMMEDIATE'); "
                 "db.execute('UPDATE authority SET version=99 WHERE id=1'); "
                 "os._exit(9)") % str(self.dbpath)
        child=subprocess.run([sys.executable,'-c',command],capture_output=True,timeout=5)
        self.assertEqual(child.returncode,9)
        self.assertEqual(self.proxy.status().committed.version,0)
        self.assertEqual(self.client.diagnose().code,'MATCH')

    def test_clean_sigterm_releases_endpoint(self):
        self.proc.terminate()
        self.proc.wait(timeout=3)
        self.assertFalse(self.sock.exists(),'graceful SIGTERM must remove stale socket')

    def test_uppercase_hex_intent_refused_before_persist(self):
        pos=self.initial
        uppercase=Intent(pos.store_id,0,pos.digest,1,'A'*64,secrets.token_hex(16),'0'*64)
        with self.assertRaises(AnchorHold):self.proxy.prepare(uppercase)
        self.assertIsNone(self.proxy.status().pending)
        with self.assertRaises(ValueError):self.backend.prepare(uppercase)

    def test_non_sequential_intent_rejected_before_persist(self):
        pos=self.initial
        malformed=Intent(pos.store_id,0,pos.digest,2,hashlib.sha256(b'next').hexdigest(),secrets.token_hex(16),'0'*64)
        with self.assertRaises(AnchorHold):self.proxy.prepare(malformed)
        self.assertIsNone(self.proxy.status().pending)

    def test_server_never_exposes_signer_api(self):
        with self.assertRaises(AnchorHold):self.proxy._call('test_only_review_token',{})


if __name__=='__main__':unittest.main()
