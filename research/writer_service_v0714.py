"""Equal3 v0.7.14: POSIX-only protected-writer reference protocol.

Research candidate, NOT an independently isolated production deployment.
The public serve() path REQUIRES signed runtime preflight and a distinct writer
UID; a research-only in-memory server fixture is explicitly separate.

Clients never possess the StateStore master key and cannot submit signed SQL
or unverified proposals. Stable request IDs permit safe retry after disconnect.
"""
from __future__ import annotations
import argparse
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import socketserver
import stat
import struct
import sys
import threading

from state_store import StateStore, MAX_STORED_STATE, prepare_update, ReplayError, IntegrityError
from runtime_gate_v0711 import verify_signed_runtime_policy
from anchor_protocol import AnchorHold

MAGIC = b'EQW1'
HEADER = struct.Struct('>4sB16sI')
STATUS = 1
SET = 2
MAX_REPLY = 2048
MAX_REQUEST = MAX_STORED_STATE
ZERO_REQUEST = bytes(16)

class WriterError(ValueError):
    pass

def _read_exact(sock:socket.socket, count:int) -> bytes:
    result = bytearray()
    while len(result) < count:
        part = sock.recv(min(65536, count-len(result)))
        if not part:
            raise WriterError('incomplete frame')
        result.extend(part)
    return bytes(result)

def _peer_uid(sock):
    if sys.platform != 'linux' or not hasattr(socket, 'SO_PEERCRED'):
        raise WriterError('Linux SO_PEERCRED required')
    creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
    _, uid, _ = struct.unpack('3i',creds)
    return uid

def _private_file(path, *, name):
    path=Path(path).absolute()
    flags=os.O_RDONLY | getattr(os,'O_CLOEXEC',0)
    if not hasattr(os,'O_NOFOLLOW'):
        raise WriterError('O_NOFOLLOW required')
    fd=os.open(path,flags|os.O_NOFOLLOW)
    try:
        s=os.fstat(fd); l=os.lstat(path)
        if (not stat.S_ISREG(s.st_mode) or s.st_uid!=os.geteuid() or
            stat.S_IMODE(s.st_mode)!=0o600 or
            (s.st_ino,s.st_dev)!=(l.st_ino,l.st_dev)):
            raise WriterError(f'{name} is not a private, owner-controlled regular file')
        if s.st_size>4096 or s.st_size<32:
            raise WriterError(f'{name} size invalid')
        data=os.read(fd,4097)
        if len(data)<32 or len(data)>4096:
            raise WriterError(f'{name} size changed')
        return data
    finally:
        os.close(fd)

def _root_provisioned_public_key(path):
    """Require public key to be held in a root-owned, nonwritable trust-root path."""
    p=Path(path).absolute()
    if not hasattr(os,'O_NOFOLLOW'):
        raise WriterError('O_NOFOLLOW required for public-key trust root')
    parent=os.lstat(p.parent)
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid!=0 or
        stat.S_IMODE(parent.st_mode)&0o022):
        raise WriterError('public key parent not root managed')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|getattr(os,'O_CLOEXEC',0))
    try:
        st=os.fstat(fd); ls=os.lstat(p)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or
            stat.S_IMODE(st.st_mode)&0o022 or
            (st.st_ino,st.st_dev)!=(ls.st_ino,ls.st_dev) or st.st_size!=32):
            raise WriterError('public key not root provisioned')
        key=os.read(fd,33)
        if len(key)!=32: raise WriterError('public key truncated')
        return key
    finally:
        os.close(fd)

def _private_parent(p, *, group_gid=None):
    p=Path(p).absolute()
    s=os.lstat(p)
    if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.geteuid():
        raise WriterError('directory not privately owned by service UID')
    expected = 0o700 if group_gid is None else 0o710
    if stat.S_IMODE(s.st_mode)!=expected:
        raise WriterError('directory permissions fail closed')
    if group_gid is not None and s.st_gid!=group_gid:
        raise WriterError('socket directory group mismatch')

def _json_reply(sock, payload):
    b=json.dumps(payload,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')
    if len(b)>MAX_REPLY:
        raise WriterError('internal response too large')
    sock.sendall(struct.pack('>I',len(b))+b)

def _request(sock):
    sock.settimeout(4)
    magic,op,rid,n = HEADER.unpack(_read_exact(sock, HEADER.size))
    if magic != MAGIC or op not in (STATUS,SET):
        raise WriterError('invalid request type')
    if op == STATUS and (n or rid != ZERO_REQUEST):
        raise WriterError('noncanonical status frame')
    if op == SET and (rid == ZERO_REQUEST or n > MAX_REQUEST):
        raise WriterError('invalid set frame or excessive state')
    return op,rid,_read_exact(sock,n)

class WriterCore:
    """Trusted single-writer transaction entrypoint. No raw store instance escapes."""
    def __init__(self, store:StateStore):
        self._mutex=threading.RLock()
        if store.journal_mode != 'DELETE':
            raise WriterError('only DELETE/EXTRA StateStore allowed')
        self._store = store
        report=store.verify()
        if report.get('receipt_auth') != 'HMAC_CHAIN_V2':
            raise WriterError('legacy state history not authenticated')
    def dispatch(self,op,rid,body):
        with self._mutex:
            return self._dispatch_locked(op,rid,body)
    def _dispatch_locked(self,op,rid,body):
        if op==STATUS:
            snap=self._store.read()
            return {'ok':True,'version':snap.version,'digest':snap.digest.hex(),'bytes':len(snap.value)}
        if op!=SET or rid==ZERO_REQUEST or not isinstance(body,bytes) or len(body)>MAX_REQUEST:
            raise WriterError('invalid SET')
        # Authenticated receipt retrieval and digest comparison make retries
        # after ambiguous commit deterministic without generating new proposals.
        old=self._store.receipt(rid)
        target_hash=hashlib.sha256(body).digest()
        if old is not None:
            if not secrets.compare_digest(old.digest,target_hash):
                raise ReplayError('request ID previously bound to other target digest')
            return {'ok':True,'version':old.version,'digest':old.digest.hex(),
                    'already_committed':True,'request_id':rid.hex()}
        proposal,_=prepare_update(self._store,body,request_id=rid)
        r=self._store.apply(proposal)
        return {'ok':True,'version':r.version,'digest':r.digest.hex(),
                'already_committed':r.already_committed,'request_id':rid.hex()}

class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        server=self.server
        try:
            if _peer_uid(self.request) != server.writer_uid:
                # Refuse before reading attacker-controlled framing.
                return
            op,rid,body=_request(self.request)
            try:
                ans=server.core.dispatch(op,rid,body)
            except (ValueError, OSError, AnchorHold):
                # Do not emit detailed cryptographic/storage errors to the client.
                ans={'ok':False,'error':'HOLD'}
            _json_reply(self.request,ans)
        except (OSError, ValueError, TimeoutError):
            return

class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    allow_reuse_address = False
    request_queue_size = 8
    daemon_threads = True
    block_on_close = True
    def server_activate(self):
        self._slots=threading.BoundedSemaphore(8)
        super().server_activate()
    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request,client_address)
        except BaseException:
            self._slots.release()
            raise
    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request,client_address)
        finally:
            self._slots.release()


def serve(socket_path, *, database_path, key_file, writer_uid, socket_gid,
          policy_file, signature_file, public_key_file, deployment_id,
          _research_stop_event=None, _research_unanchored=False):
    """Production-shaped CLI. Never bypass mandatory signed patched-runtime gate."""
    if sys.platform != 'linux' or not hasattr(socket,'SO_PEERCRED'):
        raise WriterError('Linux peer credentials required')
    # No usable production trust domain exists yet. The service is an isolated
    # RESEARCH fixture until it routes commits via an independent CAS anchor.
    if _research_unanchored is not True:
        raise WriterError('P0 independent anchor and commit attestation missing; HOLD')
    if type(writer_uid) is not int or writer_uid <= 0 or writer_uid == os.geteuid():
        raise WriterError('writer UID must be distinct non-root UID')
    if type(socket_gid) is not int or socket_gid < 0:
        raise WriterError('dedicated writer socket GID required')
    db=Path(database_path).absolute(); sock=Path(socket_path).absolute()
    _private_parent(db.parent)
    dbstat=os.lstat(db)
    if (not stat.S_ISREG(dbstat.st_mode) or dbstat.st_uid != os.geteuid() or
        stat.S_IMODE(dbstat.st_mode) != 0o600):
        raise WriterError('database file must be private service-owned file')
    _private_parent(sock.parent,group_gid=socket_gid)
    if os.path.lexists(sock):
        raise WriterError('socket path exists; never unlink unknown socket')
    # The trust-root public key needs externally managed provisioning.
    # File-level requirement deliberately mirrors runtime gate provenance.
    policy=Path(policy_file).read_bytes()
    signature=Path(signature_file).read_bytes()
    trusted_public=_root_provisioned_public_key(public_key_file)
    approved=verify_signed_runtime_policy(policy,signature,trusted_public,
                                          deployment_id=deployment_id)
    if approved.get('runtime_gate')!='SIGNED_POLICY_AND_RUNTIME_MATCH':
        raise WriterError('signed runtime gate did not pass')
    key=_private_file(key_file,name='StateStore key')
    core=WriterCore(StateStore(db,key=key,journal_mode='DELETE'))
    old=os.umask(0o077)
    try:
        server=_Server(str(sock),_Handler)
    finally:
        os.umask(old)
    with server:
        try:
            os.chown(sock,-1,socket_gid)
            os.chmod(sock,0o660)
            s=os.lstat(sock)
            if (not stat.S_ISSOCK(s.st_mode) or s.st_uid!=os.geteuid() or
                s.st_gid!=socket_gid or stat.S_IMODE(s.st_mode)!=0o660):
                raise WriterError('socket ACL mismatch')
            server.core=core; server.writer_uid=writer_uid
            if _research_stop_event is not None:
                # Test-only shutdown injection; never exposed through the RPC or CLI.
                threading.Thread(target=lambda:(_research_stop_event.wait(),server.shutdown()),
                                 daemon=True).start()
            server.serve_forever(poll_interval=0.1)
        finally:
            if sock.is_socket():
                os.unlink(sock)

def client_request(socket_path,*,op,request_id=ZERO_REQUEST,target=b'',timeout=5):
    if type(request_id) is not bytes or len(request_id)!=16:
        raise WriterError('bad request_id')
    if op not in (SET,STATUS) or type(target) is not bytes or len(target)>MAX_REQUEST:
        raise WriterError('bad request')
    if op==STATUS and (target or request_id!=ZERO_REQUEST):
        raise WriterError('noncanonical status request')
    if op==SET and request_id==ZERO_REQUEST:
        raise WriterError('SET requires nonzero stable request ID')
    with closing(socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)) as s:
        s.settimeout(timeout)
        s.connect(str(socket_path))
        s.sendall(HEADER.pack(MAGIC,op,request_id,len(target))+target)
        size=struct.unpack('>I',_read_exact(s,4))[0]
        if size<2 or size>MAX_REPLY: raise WriterError('invalid reply length')
        # Reject duplicate keys, malformed/non-object responses and excess data.
        def unique(pairs):
            d={}
            for k,v in pairs:
                if k in d: raise WriterError('duplicate JSON response')
                d[k]=v
            return d
        data=json.loads(_read_exact(s,size),object_pairs_hook=unique)
        if type(data) is not dict or type(data.get('ok')) is not bool:
            raise WriterError('invalid reply schema')
        return data

def _bounded_local_target(path):
    p=Path(path)
    if p.is_symlink(): raise WriterError('target symlink not allowed')
    if p.stat().st_size>MAX_REQUEST: raise WriterError('target file exceeds limit')
    with p.open('rb') as f:
        data=f.read(MAX_REQUEST+1)
    if len(data)>MAX_REQUEST: raise WriterError('target file grew beyond limit')
    return data

def main(argv=None):
    p=argparse.ArgumentParser(prog='equal3-writer',description='Linux protected writer (NO-GO research)')
    sub=p.add_subparsers(dest='command',required=True)
    s=sub.add_parser('serve')
    for a in ('socket','database','key_file','writer_uid','socket_gid','policy_file','signature_file','public_key_file','deployment_id'):
        s.add_argument('--'+a.replace('_','-'),required=True,type=int if a in ('writer_uid','socket_gid') else str)
    c=sub.add_parser('status');c.add_argument('socket')
    c=sub.add_parser('set');c.add_argument('socket');c.add_argument('target');c.add_argument('--request-id',required=True)
    v=p.parse_args(argv)
    try:
        if v.command=='serve':
            if os.geteuid()==0: raise WriterError('writer service must run under dedicated nonroot UID')
            serve(v.socket,database_path=v.database,key_file=v.key_file,writer_uid=v.writer_uid,
                  socket_gid=v.socket_gid,policy_file=v.policy_file,
                  signature_file=v.signature_file,public_key_file=v.public_key_file,deployment_id=v.deployment_id)
            return 0
        if v.command=='status':
            ret=client_request(v.socket,op=STATUS)
        else:
            rid=bytes.fromhex(v.request_id)
            if len(rid)!=16: raise WriterError('16-byte request ID required')
            target=_bounded_local_target(v.target)
            ret=client_request(v.socket,op=SET,request_id=rid,target=target)
        print(json.dumps(ret,sort_keys=True))
        return 0 if ret['ok'] else 2
    except (OSError,ValueError) as e:
        print('Equal3 writer HOLD: '+type(e).__name__,file=sys.stderr)
        return 2

if __name__=='__main__': raise SystemExit(main())
