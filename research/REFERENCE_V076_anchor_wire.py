"""Equal3 v0.7.6 research: persistent SQLite CAS authority + authenticated AF_UNIX RPC.

This is NOT a hardware-protected independent monotonic anchor. It demonstrates
crash/restart, interprocess CAS, role-separated authorization and rollback HOLD
with two SQLite databases. The operator MUST protect the authority DB and
secrets in a separate trust/rollback domain for a production design.
Linux/POSIX only. No network listener. Never auto-create an absent anchor on
startup, auto-heal, auto-finalize, or expose a reviewer-token signing RPC.
"""
from __future__ import annotations
import argparse
from contextlib import closing
from dataclasses import asdict
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import socketserver
import sqlite3
import stat
import struct
import threading
import time
from urllib.parse import quote
from typing import Any

from anchor_protocol import (
    Position, Intent, AnchorStatus, AnchorHold, ReviewDenied,
    _review_message,
)

WIRE_DOMAIN = b'EQ3-ANCHOR-RPC-V076\x00'
MAX_FRAME = 16384

class WireError(AnchorHold):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def unique_json(raw:bytes):
    def refuse_duplicate(pairs):
        d={}
        for k,v in pairs:
            if k in d:raise ValueError('ambiguous duplicate JSON key')
            d[k]=v
        return d
    return json.loads(raw,object_pairs_hook=refuse_duplicate)


def strict_object(v: Any, fields: set[str]) -> dict:
    if type(v) is not dict or set(v) != fields:
        raise WireError('malformed RPC fields')
    return v


def from_position(d: dict) -> Position:
    strict_object(d, {'store_id', 'version', 'digest'})
    return Position(**d)


def validate_intent(i: Intent) -> Intent:
    _review_message(i,'FINALIZE_COMMIT')
    for field in ('store_id','base_digest','digest','request_id','proposal_hash'):
        s=getattr(i,field)
        if s!=s.lower() or any(ch not in '0123456789abcdef' for ch in s):
            raise ValueError('intent field is not canonical lowercase hexadecimal')
    if i.version!=i.base_version+1:
        raise ValueError('intent version must advance exactly one')
    return i


def from_intent(d: dict) -> Intent:
    strict_object(d, set(Intent.__dataclass_fields__))
    return validate_intent(Intent(**d))


def validate_position(p: Position, *, genesis: bool=False):
    if (type(p.store_id) is not str or len(p.store_id) != 32 or
        type(p.digest) is not str or len(p.digest) != 64 or
        type(p.version) is not int or p.version < 0 or p.version >= (1 << 63) or
        (genesis and p.version != 0)):
        raise ValueError('noncanonical anchor position')
    for item in (p.store_id,p.digest):
        if item != item.lower() or any(c not in '0123456789abcdef' for c in item):
            raise ValueError('noncanonical anchor hex')


def _require_file(path:Path, *,mode:int=0o600):
    s=os.lstat(path)
    if not stat.S_ISREG(s.st_mode) or stat.S_IMODE(s.st_mode) != mode or s.st_uid != os.geteuid():
        raise PermissionError('anchor file owner/type/permissions mismatch')


def _require_parent(path:Path):
    d=path.parent
    s=os.lstat(d)
    if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.geteuid() or (stat.S_IMODE(s.st_mode)&0o077):
        raise PermissionError('anchor directory must be private and owned')


class PersistentCASAnchor:
    """Dedicated SQLite journal for authority state; NOT separate physical trust.

    Every mutating transition uses BEGIN IMMEDIATE, WAL FULL, and a single
    local DB transaction. It forbids an implicit genesis on restart.
    """
    def __init__(self, db_path:str|Path, *, reviewer_key: bytes):
        self.path=Path(db_path).absolute()
        if type(reviewer_key) is not bytes or len(reviewer_key)<32:
            raise ValueError('invalid private reviewer credential')
        _require_parent(self.path)
        _require_file(self.path)
        self._reviewer_key=reviewer_key
        with self._db() as db:
            if db.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
                raise AnchorHold('SQLite authority integrity check failed')
            row=db.execute('SELECT store_id, version, digest, pending FROM authority WHERE id=1').fetchone()
            if row is None: raise AnchorHold('anchor missing canonical genesis')
            validate_position(Position(*row[:3]))

    @classmethod
    def bootstrap(cls, db_path:str|Path, position:Position, *,reviewer_key:bytes):
        validate_position(position,genesis=True)
        target=Path(db_path).absolute()
        _require_parent(target)
        flags=os.O_RDWR|os.O_CREAT|os.O_EXCL
        if hasattr(os,'O_NOFOLLOW'): flags |= os.O_NOFOLLOW
        fd=os.open(target,flags,0o600)
        os.close(fd)
        try:
            with closing(sqlite3.connect(str(target),timeout=5)) as db:
                if db.execute('PRAGMA journal_mode=WAL').fetchone()[0].lower()!='wal':
                    raise WireError('WAL unavailable')
                db.execute('PRAGMA synchronous=FULL')
                db.execute('CREATE TABLE authority(id INTEGER PRIMARY KEY CHECK(id=1), store_id TEXT NOT NULL, version INTEGER NOT NULL, digest TEXT NOT NULL, pending BLOB)')
                db.execute('CREATE TABLE consumed(nonce TEXT PRIMARY KEY, operation TEXT NOT NULL)')
                db.execute('CREATE TABLE review_log(id INTEGER PRIMARY KEY, request_id TEXT NOT NULL, decision TEXT NOT NULL, version INTEGER NOT NULL)')
                db.execute('INSERT INTO authority VALUES(1,?,?,?,NULL)',(position.store_id,position.version,position.digest))
                db.commit()
        except BaseException:
            # Unknown failure: leave file in place; operator must inspect. Never
            # opportunistically replace/re-bootstrap an ambiguous anchor.
            raise
        return cls(target,reviewer_key=reviewer_key)

    def _db(self):
        _require_parent(self.path)
        _require_file(self.path)
        uri='file:'+quote(str(self.path),safe='/')+'?mode=rw'
        db=sqlite3.connect(uri,uri=True,timeout=5,isolation_level=None)
        try:
            db.execute('PRAGMA busy_timeout=5000')
            db.execute('PRAGMA synchronous=FULL')
            if db.execute('PRAGMA journal_mode').fetchone()[0].lower()!='wal':
                raise WireError('WAL invariant failed')
        except BaseException:
            db.close()
            raise
        return closing(db)

    @staticmethod
    def _load(db):
        row=db.execute('SELECT store_id,version,digest,pending FROM authority WHERE id=1').fetchone()
        if row is None: raise AnchorHold('missing authority record')
        pos=Position(*row[:3]); validate_position(pos)
        pending=from_intent(unique_json(row[3])) if row[3] else None
        return AnchorStatus(pos,pending)

    def status(self):
        with self._db() as db:
            return self._load(db)

    @staticmethod
    def _consume(db,nonce:str,operation:str):
        if type(nonce) is not str or len(nonce)!=32 or nonce!=nonce.lower() or any(x not in '0123456789abcdef' for x in nonce):
            raise WireError('bad nonce')
        try:db.execute('INSERT INTO consumed VALUES (?,?)',(nonce,operation))
        except sqlite3.IntegrityError as exc: raise WireError('replayed mutation request') from exc

    def prepare(self,intent:Intent,*,nonce:str|None=None):
        validate_intent(intent)
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                old=self._load(db)
                if old.pending is not None or old.committed.store_id!=intent.store_id or old.committed.version!=intent.base_version or not hmac.compare_digest(old.committed.digest,intent.base_digest) or intent.version != old.committed.version+1:
                    raise AnchorHold('CAS prepare rejected')
                self._consume(db,nonce or secrets.token_hex(16),'prepare')
                db.execute('UPDATE authority SET pending=? WHERE id=1',(canonical(asdict(intent)),))
                db.commit()
            except BaseException:
                db.rollback()
                raise

    def adjudicate(self,intent:Intent,decision:str,token:bytes,*,nonce:str|None=None):
        if type(token) is not bytes or len(token)!=32:
            raise ReviewDenied('bad reviewer approval')
        validate_intent(intent)
        msg=_review_message(intent,decision)
        expected=hmac.new(self._reviewer_key,msg,hashlib.sha256).digest()
        if not hmac.compare_digest(expected,token):
            raise ReviewDenied('reviewer approval mismatch')
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                state=self._load(db)
                if state.pending!=intent:
                    raise AnchorHold('unmatched pending review intent')
                if decision=='FINALIZE_COMMIT':
                    if intent.version != state.committed.version+1:
                        raise AnchorHold('nonmonotonic finalize')
                    db.execute('UPDATE authority SET version=?,digest=?,pending=NULL WHERE id=1',(intent.version,intent.digest))
                elif decision=='ABORT_NOT_COMMITTED':
                    db.execute('UPDATE authority SET pending=NULL WHERE id=1')
                else: raise ReviewDenied('unsupported review decision')
                self._consume(db,nonce or secrets.token_hex(16),'adjudicate')
                db.execute('INSERT INTO review_log(request_id,decision,version) VALUES(?,?,?)', (intent.request_id,decision,intent.version))
                db.commit()
            except BaseException:
                db.rollback()
                raise


def _auth_mac(key:bytes,body:dict, direction:str) -> str:
    return hmac.new(key, WIRE_DOMAIN+direction.encode('ascii')+b'\0'+canonical(body),hashlib.sha256).hexdigest()


class RPCAnchor:
    """Authenticated writer client. No credential for signing reviewer approvals."""
    def __init__(self,socket_path:str|Path,*, writer_key:bytes,timeout:float=4):
        if type(writer_key) is not bytes or len(writer_key)<32:
            raise ValueError('bad writer credential')
        self.path=str(socket_path)
        self.key=writer_key
        self.timeout=timeout

    def _call(self,op:str,payload:dict):
        nonce=secrets.token_hex(16)
        body={'v':1,'op':op,'nonce':nonce,'payload':payload}
        frame=dict(body,mac=_auth_mac(self.key,body,'request'))
        raw=canonical(frame)+b'\n'
        if len(raw)>MAX_FRAME: raise WireError('request too large')
        try:
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect(self.path)
                sock.sendall(raw)
                response=b''
                while not response.endswith(b'\n'):
                    piece=sock.recv(min(4096,MAX_FRAME+1-len(response)))
                    if not piece: raise WireError('truncated authority reply')
                    response+=piece
                    if len(response)>MAX_FRAME: raise WireError('oversized reply')
        except (OSError,TimeoutError) as exc:
            raise WireError('authority unavailable / outcome uncertain; HOLD') from exc
        try:
            outer=unique_json(response)
            strict_object(outer,{'v','nonce','ok','payload','mac'})
            check=dict(outer);check.pop('mac')
            if (type(outer['v']) is not int or outer['v']!=1 or outer['nonce']!=nonce or
                not hmac.compare_digest(outer['mac'],_auth_mac(self.key,check,'response'))):
                raise WireError('invalid authority response MAC/nonce')
            if outer['ok'] is not True:
                if op=='adjudicate':raise ReviewDenied('authority refused adjudication')
                raise AnchorHold('authority rejected '+op)
            return outer['payload']
        except (TypeError,ValueError,KeyError) as exc:
            raise WireError('malformed authority reply') from exc

    def status(self)->AnchorStatus:
        p=self._call('status',{})
        strict_object(p,{'committed','pending'})
        return AnchorStatus(from_position(p['committed']), from_intent(p['pending']) if p['pending'] is not None else None)

    def prepare(self,intent:Intent):
        self._call('prepare',{'intent':asdict(intent)})

    def adjudicate(self,intent:Intent,decision:str,token:bytes):
        self._call('adjudicate',{'intent':asdict(intent),'decision':decision,'token':token.hex()})


class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(2.0)  # bound stalled local peers
        srv=self.server
        # Peer UID gate (Linux-only): identity factor in addition to writer MAC.
        if not hasattr(socket,'SO_PEERCRED'):
            return
        peer=self.request.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize('3i'))
        uid=struct.unpack('3i',peer)[1]
        if uid!=srv.writer_uid:
            return
        try:
            raw=self.rfile.readline(MAX_FRAME+1)
            if not raw.endswith(b'\n') or len(raw)>MAX_FRAME:
                return
            frame=unique_json(raw)
            strict_object(frame,{'v','op','nonce','payload','mac'})
            core=dict(frame);core.pop('mac')
            if type(frame['v']) is not int or frame['v']!=1 or type(frame['op']) is not str or type(frame['nonce']) is not str or not isinstance(frame['mac'],str):
                return
            if not hmac.compare_digest(frame['mac'],_auth_mac(srv.writer_key,core,'request')):
                return
            op=frame['op'];p=frame['payload']
            try:
                if op=='status':
                    strict_object(p,set())
                    s=srv.backend.status()
                    answer={'committed':asdict(s.committed),'pending':asdict(s.pending) if s.pending else None}
                elif op=='prepare':
                    strict_object(p,{'intent'})
                    srv.backend.prepare(from_intent(p['intent']),nonce=frame['nonce']);answer={}
                elif op=='adjudicate':
                    strict_object(p,{'intent','decision','token'})
                    if type(p['token']) is not str or len(p['token'])!=64:raise WireError('bad token')
                    token=bytes.fromhex(p['token'])
                    srv.backend.adjudicate(from_intent(p['intent']),p['decision'],token,nonce=frame['nonce']);answer={}
                else:
                    raise WireError('unknown operation')
                ok=True
            except (AnchorHold,ValueError,TypeError,KeyError,sqlite3.Error):
                ok=False; answer={}
            reply={'v':1,'nonce':frame['nonce'],'ok':ok,'payload':answer}
            signed=dict(reply,mac=_auth_mac(srv.writer_key,reply,'response'))
            self.wfile.write(canonical(signed)+b'\n')
        except (OSError,ValueError,TypeError,UnicodeError,KeyError,OverflowError):
            return


class _UnixAuthority(socketserver.ThreadingMixIn,socketserver.UnixStreamServer):
    daemon_threads=True
    allow_reuse_address=False
    request_queue_size=16

    def __init__(self,*args,**kwargs):
        self._slots=threading.BoundedSemaphore(32)
        super().__init__(*args,**kwargs)

    def process_request(self,request,client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:super().process_request(request,client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self,request,client_address):
        try:super().process_request_thread(request,client_address)
        finally:self._slots.release()


def read_credential(path:str|Path) -> bytes:
    path=Path(path).absolute();_require_parent(path);_require_file(path)
    flags=os.O_RDONLY| (getattr(os,'O_NOFOLLOW',0))
    fd=os.open(path,flags)
    with os.fdopen(fd,'rb') as f:
        observed=os.fstat(f.fileno())
        expected=os.lstat(path)
        if (not stat.S_ISREG(observed.st_mode) or observed.st_ino!=expected.st_ino or
            observed.st_dev!=expected.st_dev or stat.S_IMODE(observed.st_mode)!=0o600 or
            observed.st_uid!=os.geteuid()):
            raise PermissionError('credential changed during secure open')
        key=f.read(65)
    if len(key)!=32: raise PermissionError('credential must contain 32 raw bytes')
    return key


def serve(db_path:str|Path,sock_path:str|Path,*,writer_key:bytes,reviewer_key:bytes,writer_uid:int):
    if not hasattr(socket,'SO_PEERCRED'):raise RuntimeError('SO_PEERCRED unsupported; refusing to serve')
    backend=PersistentCASAnchor(db_path,reviewer_key=reviewer_key)
    sock_path=Path(sock_path).absolute()
    _require_parent(sock_path)
    if os.path.lexists(sock_path):raise FileExistsError('socket path exists; no automatic unlink')
    with _UnixAuthority(str(sock_path),_Handler) as server:
        try:
            os.chmod(sock_path,0o600)
            server.backend=backend
            server.writer_uid=writer_uid
            server.writer_key=writer_key
            def orderly_exit(signum, frame):
                # shutdown() must execute in another thread from serve_forever().
                threading.Thread(target=server.shutdown,daemon=True).start()
            previous=signal.signal(signal.SIGTERM,orderly_exit)
            try:
                server.serve_forever(poll_interval=0.1)
            finally:
                signal.signal(signal.SIGTERM,previous)
        finally:
            if sock_path.exists():os.unlink(sock_path)


def main():
    ap=argparse.ArgumentParser(description='Equal3 v0.7.6 research UNIX anchor (NOT production)')
    ap.add_argument('--db',required=True)
    ap.add_argument('--socket',required=True)
    ap.add_argument('--writer-key-file',required=True)
    ap.add_argument('--reviewer-key-file',required=True)
    ap.add_argument('--writer-uid',required=True,type=int)
    cfg=ap.parse_args()
    serve(cfg.db,cfg.socket,writer_key=read_credential(cfg.writer_key_file),
          reviewer_key=read_credential(cfg.reviewer_key_file),writer_uid=cfg.writer_uid)

if __name__=='__main__':main()
