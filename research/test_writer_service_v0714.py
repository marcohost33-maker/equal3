"""Negative-first protected writer tests; real Linux UID test when root."""
from __future__ import annotations
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
from concurrent.futures import ThreadPoolExecutor

from state_store import StateStore, IntegrityError, ReplayError
import writer_service_v0714 as ws

KEY=b'W'*32
class WriterBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.db=self.root/'data.sqlite'
        self.store=StateStore.create(self.db,key=KEY,initial=b'init',journal_mode='DELETE')
        self.core=ws.WriterCore(self.store)
    def test_status_fingerprint(self):
        r=self.core.dispatch(ws.STATUS,ws.ZERO_REQUEST,b'')
        self.assertEqual(r['version'],0)
        self.assertEqual(r['digest'],hashlib.sha256(b'init').hexdigest())
    def test_set_idempotent_same_id_and_target(self):
        rid=bytes.fromhex('11'*16)
        a=self.core.dispatch(ws.SET,rid,b'updated')
        b=self.core.dispatch(ws.SET,rid,b'updated')
        self.assertEqual((a['version'],a['already_committed']),(1,False))
        self.assertEqual((b['version'],b['already_committed']),(1,True))
        self.assertEqual(self.store.read().version,1)
    def test_reused_id_different_target_refused(self):
        rid=b'R'*16
        self.core.dispatch(ws.SET,rid,b'A')
        with self.assertRaises(ReplayError):self.core.dispatch(ws.SET,rid,b'B')
        self.assertEqual(self.store.read().value,b'A')
    def test_concurrent_same_id_one_commit(self):
        rid=b'Q'*16
        with ThreadPoolExecutor(max_workers=6) as pool:
            rows=list(pool.map(lambda _:self.core.dispatch(ws.SET,rid,b'B'),range(6)))
        self.assertEqual(sum(not x['already_committed'] for x in rows),1)
        self.assertEqual(self.store.read().version,1)
    def test_concurrent_distinct_ids_serialized(self):
        with ThreadPoolExecutor(max_workers=6) as pool:
            rows=list(pool.map(lambda i:self.core.dispatch(ws.SET,bytes([i+1])*16,b'C'),range(6)))
        self.assertEqual(sorted(x['version'] for x in rows),list(range(1,7)))
    def test_reopen_then_idempotent_replay(self):
        rid=b'H'*16
        self.core.dispatch(ws.SET,rid,b'committed')
        new=ws.WriterCore(StateStore(self.db,key=KEY,journal_mode='DELETE'))
        out=new.dispatch(ws.SET,rid,b'committed')
        self.assertTrue(out['already_committed'])
    def test_corrupt_receipt_triggers_hold(self):
        rid=b'D'*16
        self.core.dispatch(ws.SET,rid,b'committed')
        with closing(self.store._db()) as db:
            db.execute('UPDATE receipts SET digest=? WHERE request_id=?',(bytes.fromhex('44'*32),rid))
        with self.assertRaises(IntegrityError):self.core.dispatch(ws.SET,rid,b'committed')
    def test_refuse_wal_mode(self):
        with self.assertRaisesRegex(ws.WriterError,'DELETE'):
            ws.WriterCore(StateStore.create(self.root/'wal.db',key=KEY,initial=b'a'))
    def test_invalid_frame_lengths_rejected_without_payload(self):
        for op, rid, n in [(ws.STATUS,b'a'*16,0),(ws.STATUS,bytes(16),1),(ws.SET,bytes(16),0),(ws.SET,b'1'*16,ws.MAX_REQUEST+1),(99,b'1'*16,0)]:
            one,two=socket.socketpair()
            with one,two:
                one.sendall(ws.HEADER.pack(ws.MAGIC,op,rid,n))
                with self.assertRaises(ws.WriterError): ws._request(two)
    def test_truncated_request_rejected(self):
        a,b=socket.socketpair()
        with a,b:
            a.sendall(ws.HEADER.pack(ws.MAGIC,ws.SET,b'2'*16,100)+b'abc')
            a.shutdown(socket.SHUT_WR)
            with self.assertRaisesRegex(ws.WriterError,'incomplete'):
                ws._request(b)
    def test_reject_client_noncanonical_requests(self):
        with self.assertRaises(ws.WriterError):ws.client_request('/absent',op=ws.SET,request_id=bytes(16))
        with self.assertRaises(ws.WriterError):ws.client_request('/absent',op=ws.STATUS,target=b'junk')
        with self.assertRaises(ws.WriterError):ws.client_request('/absent',op=ws.SET,request_id=b'X'*16,target=b'*'*(ws.MAX_REQUEST+1))
    def test_private_file_symlink_rejected(self):
        key=self.root/'key'; key.write_bytes(KEY); key.chmod(0o600)
        self.assertEqual(ws._private_file(key,name='key'),KEY)
        sym=self.root/'sym'; sym.symlink_to(key)
        with self.assertRaises(OSError):ws._private_file(sym,name='key')
    def test_private_file_world_readable_rejected(self):
        p=self.root/'key';p.write_bytes(KEY);p.chmod(0o644)
        with self.assertRaises(ws.WriterError):ws._private_file(p,name='key')
    def test_untrusted_public_key_and_parent(self):
        if os.geteuid()!=0:self.skipTest('needs root-owned trust directory')
        p=self.root/'pk';p.write_bytes(bytes(32));p.chmod(0o644)
        # TemporaryDirectory is 0700 root-owned in this test environment.
        self.assertEqual(ws._root_provisioned_public_key(p),bytes(32))
        p.chmod(0o666)
        with self.assertRaises(ws.WriterError):ws._root_provisioned_public_key(p)
    def test_unanchored_production_path_is_unconditionally_blocked(self):
        with self.assertRaisesRegex(ws.WriterError,'P0 independent anchor'):
            ws.serve('/ignored',database_path=str(self.db),key_file='ignored',writer_uid=1234,
                     socket_gid=1234,policy_file='ignored',signature_file='ignored',
                     public_key_file='ignored',deployment_id='production')
    def test_production_start_rejects_same_uid_before_runtime_gate(self):
        with self.assertRaisesRegex(ws.WriterError,'distinct'):
            ws.serve('/ignored',database_path=str(self.db),key_file='ignored',writer_uid=os.geteuid(),_research_unanchored=True,
                     socket_gid=os.getegid(),policy_file='ignored',signature_file='ignored',
                     public_key_file='ignored',deployment_id='one')
    def test_cli_target_bounded_and_symlink_rejected(self):
        p=self.root/'payload';p.write_bytes(b'OK')
        self.assertEqual(ws._bounded_local_target(p),b'OK')
        sym=self.root/'target-link';sym.symlink_to(p)
        with self.assertRaises(ws.WriterError):ws._bounded_local_target(sym)
        with mock.patch.object(ws,'MAX_REQUEST',1):
            with self.assertRaises(ws.WriterError):ws._bounded_local_target(p)
    def test_failclosed_on_invalid_response(self):
        class FakeSocket:
            def settimeout(self,*args):pass
            def connect(self,*args):pass
            def sendall(self,*args):pass
            def close(self):pass
        with mock.patch.object(ws,'_read_exact',return_value=struct.pack('>I',20000)):
            with mock.patch.object(ws.socket,'socket',return_value=FakeSocket()):
                with self.assertRaises(ws.WriterError):ws.client_request('/tmp/dummy',op=ws.STATUS)
    def test_reject_request_with_oversized_json(self):
        a,b=socket.socketpair()
        with a,b:
            with self.assertRaises(ws.WriterError):ws._json_reply(a,{'ok':True,'padding':'x'*(ws.MAX_REPLY+1)})
    def test_runtime_gate_called_at_startup_and_failclosed(self):
        if sys.platform!='linux' or not hasattr(socket,'SO_PEERCRED'):self.skipTest('Linux only')
        self.db.chmod(0o600)
        if os.geteuid()!=0:self.skipTest('Linux UID isolation test below requires root')
        # Need a distinct nonzero UID, and an ACL-isolated socket parent.
        writer=65534; sockdir=self.root/'sockdir';sockdir.mkdir();os.chown(sockdir,0,writer);sockdir.chmod(0o710)
        private=self.root/'dbpriv';private.mkdir();private.chmod(0o700)
        dbfile=private/'store.sqlite'; StateStore.create(dbfile,key=KEY,initial=b'zero',journal_mode='DELETE')
        keyfile=private/'key';keyfile.write_bytes(KEY);keyfile.chmod(0o600)
        policy=self.root/'policy';policy.write_bytes(b'p')
        sig=self.root/'sig';sig.write_bytes(b's')
        public=self.root/'public';public.write_bytes(b'\x33'*32);public.chmod(0o644)
        sock=sockdir/'writer.sock'
        with mock.patch.object(ws,'verify_signed_runtime_policy',side_effect=ws.WriterError('expected policy failure')):
            with self.assertRaisesRegex(ws.WriterError,'expected policy failure'):
                ws.serve(sock,database_path=dbfile,key_file=keyfile,writer_uid=writer,socket_gid=writer,_research_unanchored=True,
                         policy_file=policy,signature_file=sig,public_key_file=public,deployment_id='demo')
        self.assertFalse(os.path.lexists(sock))
    def test_real_linux_uid_boundary_separate_client(self):
        if os.geteuid()!=0 or sys.platform!='linux':self.skipTest('requires Linux root for separate UID test')
        writer=65534;unauth=65533
        # Private key/DB remains root-owned 0700; socket dir traversable to gid 65534.
        priv=self.root/'private';priv.mkdir();priv.chmod(0o700)
        db=priv/'db.sqlite';StateStore.create(db,key=KEY,initial=b'original',journal_mode='DELETE')
        key=priv/'secret';key.write_bytes(KEY);key.chmod(0o600)
        gate=self.root/'gate';gate.write_bytes(b'gate')
        sign=self.root/'sig';sign.write_bytes(b'sign')
        pub=self.root/'pub';pub.write_bytes(b'\x22'*32);pub.chmod(0o644)
        shared=self.root/'shared';shared.mkdir();os.chown(shared,0,writer);shared.chmod(0o710)
        sock=shared/'s.sock'
        status={'error':None}
        stop=threading.Event()
        def service():
            try:
                ws.serve(sock,database_path=db,key_file=key,writer_uid=writer,socket_gid=writer,_research_unanchored=True,
                         policy_file=gate,signature_file=sign,public_key_file=pub,deployment_id='integration',
                         _research_stop_event=stop)
            except BaseException as exc:
                status['error']=repr(exc)
        # Explicitly synthetic patched-runtime attestation, not real release approval.
        with mock.patch.object(ws,'verify_signed_runtime_policy',return_value={'runtime_gate':'SIGNED_POLICY_AND_RUNTIME_MATCH'}):
            thread=threading.Thread(target=service,daemon=True);thread.start()
            self.addCleanup(lambda:(stop.set(),thread.join(timeout=5)))
            for _ in range(250):
                if sock.exists() or status['error']:break
                time.sleep(0.01)
            self.assertIsNone(status['error'])
            self.assertTrue(sock.exists())
            program="""import sys,os,json
from writer_service_v0714 import client_request,SET,STATUS
s=sys.argv[1]
if sys.argv[2]=='set':
    print(json.dumps(client_request(s,op=SET,request_id=b'\\x31'*16,target=b'new')))
else: print(json.dumps(client_request(s,op=STATUS)))
"""
            def run_as(uid,cmd):
                def drop():
                    os.setgroups([]);os.setgid(writer);os.setuid(uid)
                # The outer tempfile root is 0700, so create a traverse-only gateway
                # for the parent to permit a real separated-UID client to reach the socket.
                return subprocess.run([sys.executable,'-c',program,str(sock),cmd],
                                      cwd=str(Path(__file__).parent),preexec_fn=drop,
                                      capture_output=True,text=True,timeout=8)
            # Child must traverse root parent; grant only search (0711), not file read.
            self.root.chmod(0o711)
            good=run_as(writer,'set')
            self.assertEqual(good.returncode,0,(good.stdout,good.stderr))
            self.assertEqual(json.loads(good.stdout)['version'],1)
            again=run_as(writer,'set')
            self.assertTrue(json.loads(again.stdout)['already_committed'])
            bad=run_as(unauth,'status')
            self.assertNotEqual(bad.returncode,0)
            # root-owned DB/secret must remain inaccessible to UID 65534.
            blocked=subprocess.run([sys.executable,'-c',"import os,sys;open(sys.argv[1],'rb')",
                                     str(key)],preexec_fn=lambda:(os.setgroups([]),os.setgid(writer),os.setuid(writer)),
                                     capture_output=True,text=True,timeout=8)
            self.assertNotEqual(blocked.returncode,0)
            self.assertEqual(StateStore(db,key=KEY,journal_mode='DELETE').read().value,b'new')
            # No shutdown RPC is exposed: fixture shutdown uses an internal event.

if __name__=='__main__':unittest.main()
