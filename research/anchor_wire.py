"""Equal3 v0.7.9 research: DELETE-journal CAS authority + authenticated AF_UNIX RPC.

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
SEAL_DOMAIN = b'EQ3-ANCHOR-STATE-V078\x00'
AUDIT_DOMAIN = b'EQ3-AUTHORITY-AUDIT-V078\x00'
MAX_AUDIT_ROWS = 100000

# SQLite upstream WAL-reset race fixed in 3.51.3, 3.50.7, 3.44.6.
# Third-party or distro backports require independently verified provenance.
def sqlite_wal_reset_safe(version=None):
    version = sqlite3.sqlite_version_info if version is None else tuple(version)
    # 3.52.0 was withdrawn for compatibility defects; never endorse as a release.
    if version[:2] == (3,52):
        return False
    return version >= (3,51,3) or (version[:2] == (3,50) and version >= (3,50,7)) or (version[:2] == (3,44) and version >= (3,44,6))

def require_sqlite_wal_safe(*, research_override=False):
    if not sqlite_wal_reset_safe() and not research_override:
        raise AnchorHold("unverified SQLite WAL-reset security; patched runtime required (research override explicit)")

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


def _verify_delete_header(path: Path):
    """Refuse WAL / unknown headers BEFORE sqlite3 opens the authority.

    SQLite bytes 18/19 are the file-format write/read versions:
    01 01 for rollback journal and 02 02 for WAL.
    This is defense-in-depth, NOT an atomic pathname-to-SQLite FD binding.
    """
    _require_parent(path)
    _require_file(path)
    if os.path.lexists(str(path)+'-wal') or os.path.lexists(str(path)+'-shm'):
        raise AnchorHold('WAL authority sidecar present; offline migration required')
    flags=os.O_RDONLY | getattr(os,'O_NOFOLLOW',0) | getattr(os,'O_CLOEXEC',0)
    fd=os.open(path,flags)
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or stat.S_IMODE(st.st_mode)!=0o600:
            raise PermissionError('authority FD safety mismatch')
        header=os.read(fd,100)
        if len(header)<100 or header[:16]!=b'SQLite format 3\x00':
            raise AnchorHold('authority missing or invalid SQLite header')
        if header[18:20] != b'\x01\x01':
            raise AnchorHold('unsealed legacy or WAL/non-DELETE authority blocked; independent offline migration required')
        observed=os.lstat(path)
        if (observed.st_dev,observed.st_ino) != (st.st_dev,st.st_ino):
            raise AnchorHold('authority path changed during header check')
    finally:
        os.close(fd)


class PersistentCASAnchor:
    """Dedicated rollback-journal SQLite authority; NOT independent physical trust.

    Newly bootstrapped databases use journal_mode=DELETE, synchronous=EXTRA.
    WAL databases require separate, independently attested migration (fail-closed).
    The research_unsafe_sqlite parameter is retained for legacy callers but
    never bypasses DELETE-journal enforcement. This does NOT fix the WAL StateStore.
    """
    def __init__(self, db_path:str|Path, *, reviewer_key: bytes, seal_key: bytes, research_unsafe_sqlite: bool=False):
        self.path=Path(db_path).absolute()
        if type(reviewer_key) is not bytes or len(reviewer_key)<32:
            raise ValueError('invalid private reviewer credential')
        _require_parent(self.path)
        _verify_delete_header(self.path)
        if type(seal_key) is not bytes or len(seal_key)<32:
            raise ValueError('invalid independent authority seal credential')
        if hmac.compare_digest(seal_key, reviewer_key):
            raise ValueError('review and seal credentials must be distinct')
        self._reviewer_key=reviewer_key
        self._seal_key=seal_key
        with self._db() as db:
            if db.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
                raise AnchorHold('SQLite authority integrity check failed')
            self._load(db)  # Fail closed for old unsealed schema or invalid seal

    @classmethod
    def bootstrap(cls, db_path:str|Path, position:Position, *,reviewer_key:bytes,seal_key:bytes,research_unsafe_sqlite:bool=False):
        validate_position(position,genesis=True)
        if type(seal_key) is not bytes or len(seal_key)<32 or type(reviewer_key) is not bytes or len(reviewer_key)<32:
            raise ValueError('invalid authority key')
        if hmac.compare_digest(seal_key,reviewer_key):
            raise ValueError('credentials must be distinct')
        target=Path(db_path).absolute()
        _require_parent(target)
        flags=os.O_RDWR|os.O_CREAT|os.O_EXCL
        if hasattr(os,'O_NOFOLLOW'): flags |= os.O_NOFOLLOW
        fd=os.open(target,flags,0o600)
        os.close(fd)
        try:
            with closing(sqlite3.connect(str(target),timeout=5)) as db:
                if db.execute('PRAGMA journal_mode=DELETE').fetchone()[0].lower()!='delete':
                    raise AnchorHold('DELETE rollback journal unavailable')
                db.execute('PRAGMA synchronous=EXTRA')
                if db.execute('PRAGMA synchronous').fetchone()[0] != 3:
                    raise AnchorHold('EXTRA synchronization unavailable')
                db.execute('PRAGMA trusted_schema=OFF')
                db.execute('CREATE TABLE authority(id INTEGER PRIMARY KEY CHECK(id=1), store_id TEXT NOT NULL, version INTEGER NOT NULL, digest TEXT NOT NULL, pending BLOB, audit_root BLOB NOT NULL, seal BLOB NOT NULL)')
                db.execute('CREATE TABLE consumed(nonce TEXT PRIMARY KEY, operation TEXT NOT NULL)')
                db.execute('CREATE TABLE review_log(id INTEGER PRIMARY KEY, request_id TEXT NOT NULL, decision TEXT NOT NULL, version INTEGER NOT NULL)')
                root=cls._audit_digest(db)
                db.execute('INSERT INTO authority VALUES(1,?,?,?,?,?,?)', (position.store_id,position.version,position.digest,None,root,cls._make_seal(seal_key,position,None,root)))
                db.commit()
        except BaseException:
            # Unknown failure: leave file in place; operator must inspect. Never
            # opportunistically replace/re-bootstrap an ambiguous anchor.
            raise
        return cls(target,reviewer_key=reviewer_key,seal_key=seal_key,research_unsafe_sqlite=research_unsafe_sqlite)

    def _db(self):
        _verify_delete_header(self.path)
        uri='file:'+quote(str(self.path),safe='/')+'?mode=rw'
        db=sqlite3.connect(uri,uri=True,timeout=5,isolation_level=None)
        try:
            db.execute('PRAGMA busy_timeout=5000')
            # Do not convert existing WAL databases automatically: the v0.7.8
            # authority could contain uncheckpointed WAL state and sidecars.
            if db.execute('PRAGMA journal_mode').fetchone()[0].lower() != 'delete':
                raise AnchorHold('unsealed legacy or WAL/non-DELETE authority blocked; independent offline migration required')
            db.execute('PRAGMA synchronous=EXTRA')
            if db.execute('PRAGMA synchronous').fetchone()[0] != 3:
                raise AnchorHold('EXTRA synchronization invariant failed')
            db.execute('PRAGMA trusted_schema=OFF')
        except BaseException:
            db.close()
            raise
        return closing(db)

    @staticmethod
    def _audit_digest(db) -> bytes:
        """Full ordered audit-ledger commitment; deliberately O(n) per verification.

        An untrusted mutation to either SQLite ledger table changes this digest.
        The digest is bound inside the authority HMAC seal. It is *not* a
        non-rollbackable remote audit log. All reads must be in one snapshot.
        """
        h=hashlib.sha256(AUDIT_DOMAIN)
        count=0
        try:
            for nonce,op in db.execute('SELECT nonce,operation FROM consumed ORDER BY nonce'):
                count+=1
                if count>MAX_AUDIT_ROWS: raise AnchorHold('audit ledger capacity exceeded; operator review required')
                if type(nonce) is not str or len(nonce)!=32 or nonce!=nonce.lower() or any(x not in '0123456789abcdef' for x in nonce) or op not in ('prepare','adjudicate'):
                    raise AnchorHold('invalid consumed ledger entry')
                packet=canonical(['nonce',nonce,op]);h.update(len(packet).to_bytes(4,'big'));h.update(packet)
            last_id=0
            for id_,rid,decision,version in db.execute('SELECT id,request_id,decision,version FROM review_log ORDER BY id'):
                count+=1
                if count>MAX_AUDIT_ROWS: raise AnchorHold('audit ledger capacity exceeded; operator review required')
                if (type(id_) is not int or id_!=last_id+1 or type(rid) is not str or len(rid)!=32 or rid!=rid.lower() or any(x not in '0123456789abcdef' for x in rid) or decision not in ('FINALIZE_COMMIT','ABORT_NOT_COMMITTED') or type(version) is not int or version<=0 or version>=(1<<63)):
                    raise AnchorHold('invalid review ledger entry')
                last_id=id_
                packet=canonical(['review',id_,rid,decision,version]);h.update(len(packet).to_bytes(4,'big'));h.update(packet)
        except sqlite3.DatabaseError as exc:
            raise AnchorHold('audit ledger unavailable or corrupted') from exc
        return h.digest()

    @staticmethod
    def _make_seal(key: bytes, position: Position, pending: bytes|None, audit_root: bytes):
        validate_position(position)
        if pending is not None and type(pending) is not bytes:
            raise AnchorHold('noncanonical pending bytes')
        if type(audit_root) is not bytes or len(audit_root)!=32:
            raise AnchorHold('invalid audit root')
        body=canonical({'store_id':position.store_id,'version':position.version,
                        'digest':position.digest, 'pending_hex':None if pending is None else pending.hex(),
                        'audit_root_hex':audit_root.hex()})
        return hmac.new(key,SEAL_DOMAIN+body,hashlib.sha256).digest()

    def _load(self,db):
        try:
            row=db.execute('SELECT store_id,version,digest,pending,audit_root,seal FROM authority WHERE id=1').fetchone()
        except sqlite3.DatabaseError as exc:
            # Incompatible previous schema: no upgrade without external attestation.
            raise AnchorHold('unsealed legacy authority/audit ledger: independent migration required') from exc
        if row is None:raise AnchorHold('missing authority record')
        pos=Position(*row[:3]);validate_position(pos)
        root=row[4];observed=row[5]
        if type(observed) is not bytes or len(observed)!=32 or not hmac.compare_digest(observed,self._make_seal(self._seal_key,pos,row[3],root)):
            raise AnchorHold('authority seal mismatch; offline modification or corruption detected')
        if not hmac.compare_digest(root,self._audit_digest(db)):
            raise AnchorHold('consumed/review audit ledger mismatch; HOLD')
        pending=from_intent(unique_json(row[3])) if row[3] is not None else None
        return AnchorStatus(pos,pending)

    def status(self):
        with self._db() as db:
            db.execute('BEGIN')  # one read snapshot for state and BOTH ledgers
            try:
                return self._load(db)
            finally:
                db.rollback()

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
                pending=canonical(asdict(intent))
                root=self._audit_digest(db)
                db.execute('UPDATE authority SET pending=?,audit_root=?,seal=? WHERE id=1',
                           (pending,root,self._make_seal(self._seal_key,old.committed,pending,root)))
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
                    newpos=Position(intent.store_id,intent.version,intent.digest)
                elif decision=='ABORT_NOT_COMMITTED':
                    newpos=state.committed
                else:raise ReviewDenied('unsupported review decision')
                self._consume(db,nonce or secrets.token_hex(16),'adjudicate')
                db.execute('INSERT INTO review_log(request_id,decision,version) VALUES(?,?,?)', (intent.request_id,decision,intent.version))
                root=self._audit_digest(db)
                db.execute('UPDATE authority SET version=?,digest=?,pending=NULL,audit_root=?,seal=? WHERE id=1',
                           (newpos.version,newpos.digest,root,self._make_seal(self._seal_key,newpos,None,root)))
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

    def adjudicate(self,intent:Intent,decision:str,token:bytes,*,evidence=None):
        data={'intent':asdict(intent),'decision':decision,'token':token.hex()}
        if evidence is not None: data['evidence']=evidence
        self._call('adjudicate',data)


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
                    if set(p) not in ({'intent','decision','token'}, {'intent','decision','token','evidence'}):
                        raise WireError('noncanonical adjudication frame')
                    strict_object(p,set(p))
                    if type(p['token']) is not str or len(p['token'])!=64:raise WireError('bad token')
                    token=bytes.fromhex(p['token'])
                    if 'evidence' in p:
                        srv.backend.adjudicate(from_intent(p['intent']),p['decision'],token,nonce=frame['nonce'],evidence=p['evidence'])
                    else:
                        srv.backend.adjudicate(from_intent(p['intent']),p['decision'],token,nonce=frame['nonce'])
                    answer={}
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


def _require_socket_parent(sock_path:Path, socket_gid:int|None):
    if socket_gid is None:
        _require_parent(sock_path)
        return
    if type(socket_gid) is not int or socket_gid < 0:
        raise PermissionError('invalid writer socket group')
    s=os.lstat(sock_path.parent)
    if (not stat.S_ISDIR(s.st_mode) or s.st_uid != os.geteuid() or
        s.st_gid != socket_gid or stat.S_IMODE(s.st_mode) != 0o710):
        raise PermissionError('group socket directory requires owner=anchor, group=writer and mode=0710')

def serve(db_path:str|Path,sock_path:str|Path,*,writer_key:bytes,reviewer_key:bytes,seal_key:bytes,writer_uid:int,research_unsafe_sqlite:bool=False,socket_gid:int|None=None,
          attester_public_key=None,deployment_id=None, research_unattested=False,
          root_public_key=None, trusted_min_epoch=None, research_unrooted=False,
          witness_socket_path=None, witness_public_key=None, research_static_floor_only=False):
    if not hasattr(socket,'SO_PEERCRED'):raise RuntimeError('SO_PEERCRED unsupported; refusing to serve')
    if attester_public_key is None:
        if research_unattested is not True:
            raise AnchorHold('P0 signed independent commit observation missing; attested authority required')
        backend=PersistentCASAnchor(db_path,reviewer_key=reviewer_key,seal_key=seal_key,
                                    research_unsafe_sqlite=research_unsafe_sqlite)
    else:
        # Validate deployment before choosing a backend (legacy error contract).
        from commit_evidence_v0716 import DEPLOY
        if type(deployment_id) is not str or DEPLOY.fullmatch(deployment_id) is None:
            raise ValueError('invalid deployment identity')
        if root_public_key is None:
            if research_unrooted is not True:
                raise AnchorHold('P0 root authorization missing; rooted authority required')
            from commit_evidence_v0716 import EvidenceRequiredCASAnchor
            backend=EvidenceRequiredCASAnchor(db_path,reviewer_key=reviewer_key,seal_key=seal_key,
                                              attester_public_key=attester_public_key,
                                              deployment_id=deployment_id)
        else:
            if witness_socket_path is not None or witness_public_key is not None:
                if witness_socket_path is None or witness_public_key is None:
                    raise AnchorHold('witness socket and pinned verification key both required')
                if trusted_min_epoch is not None:
                    raise AnchorHold('caller-supplied epoch floor forbidden in witnessed mode')
                from external_epoch_witness_v0719 import WitnessClient, WitnessGatedCASAnchor
                backend=WitnessGatedCASAnchor(db_path,reviewer_key=reviewer_key,seal_key=seal_key,
                    attester_public_key=attester_public_key,deployment_id=deployment_id,
                    root_public_key=root_public_key,min_epoch=0,
                    witness_client=WitnessClient(witness_socket_path,public_key=witness_public_key))
                # Must refuse to expose an RPC socket if independent witness is absent.
                backend.status()
            elif research_static_floor_only is True:
                if type(trusted_min_epoch) is not int or trusted_min_epoch < 0:
                    raise AnchorHold('trusted external minimum epoch required')
                from trust_rotation_v0718 import RootControlledCASAnchor
                backend=RootControlledCASAnchor(db_path,reviewer_key=reviewer_key,seal_key=seal_key,
                    attester_public_key=attester_public_key,deployment_id=deployment_id,
                    root_public_key=root_public_key,min_epoch=trusted_min_epoch)
            else:
                if trusted_min_epoch is None:
                    raise AnchorHold('trusted external minimum epoch required; live witness is mandatory')
                raise AnchorHold('live witness mandatory; static-floor mode is unsafe research only')
    sock_path=Path(sock_path).absolute()
    _require_socket_parent(sock_path,socket_gid)
    if os.path.lexists(sock_path):raise FileExistsError('socket path exists; no automatic unlink')
    # Create socket inaccessible to group until group ownership + mode are set.
    old_umask=os.umask(0o077)
    try:
        server_obj=_UnixAuthority(str(sock_path),_Handler)
    finally:
        os.umask(old_umask)
    with server_obj as server:
        try:
            if socket_gid is None:
                os.chmod(sock_path,0o600)
            else:
                if writer_uid == os.geteuid():
                    raise PermissionError('group socket mode requires distinct writer UID')
                os.chown(sock_path,-1,socket_gid)
                os.chmod(sock_path,0o660)
                st=os.lstat(sock_path)
                if (not stat.S_ISSOCK(st.st_mode) or st.st_uid!=os.geteuid() or
                    st.st_gid!=socket_gid or stat.S_IMODE(st.st_mode)!=0o660):
                    raise PermissionError('socket owner/group/mode mismatch')
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
    ap=argparse.ArgumentParser(description='Equal3 v0.7.9 research UNIX anchor (NOT production)')
    ap.add_argument('--db',required=True)
    ap.add_argument('--socket',required=True)
    ap.add_argument('--writer-key-file',required=True)
    ap.add_argument('--reviewer-key-file',required=True)
    ap.add_argument('--seal-key-file',required=True)
    ap.add_argument('--allow-unsafe-sqlite-research-only',action='store_true',
                    help='UNSAFE: bypass WAL runtime safety gate for synthetic research only')
    ap.add_argument('--writer-uid',required=True,type=int)
    ap.add_argument('--writer-gid',type=int,default=None,
                    help='Optional separate writer group: socket directory must be 0710 anchor:group')
    ap.add_argument('--attester-public-key-file',default=None,
                    help='Root-provisioned 32-byte Ed25519 public key; mandatory except unsafe RESEARCH mode')
    ap.add_argument('--deployment-id',default=None)
    ap.add_argument('--root-public-key-file',default=None,
                    help='32 raw bytes of externally provisioned Ed25519 ROOT verification key')
    ap.add_argument('--trusted-min-epoch',type=int,default=None,
                    help='MUST originate from an independently trusted monotonic epoch source')
    ap.add_argument('--witness-socket',default=None,help='live independently run epoch witness socket')
    ap.add_argument('--witness-public-key-file',default=None,help='pinned 32-byte witness verification key')
    ap.add_argument('--allow-static-floor-research-only',action='store_true',
                    help='UNSAFE: allow caller-supplied static floor in local research')
    ap.add_argument('--allow-unrooted-research-only',action='store_true',
                    help='UNSAFE: allow legacy v0717 local trust, for synthetic research tests only')
    ap.add_argument('--allow-unattested-research-only',action='store_true')
    cfg=ap.parse_args()
    attester_key=None
    if cfg.attester_public_key_file is not None:
        # Provisioned out of band by the system operator; the client/writer
        # must not be able to substitute the trust root.
        from writer_service_v0714 import _root_provisioned_public_key
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        attester_key=Ed25519PublicKey.from_public_bytes(
            _root_provisioned_public_key(cfg.attester_public_key_file))
    root_key=None
    if cfg.root_public_key_file is not None:
        from writer_service_v0714 import _root_provisioned_public_key
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        root_key=Ed25519PublicKey.from_public_bytes(
                 _root_provisioned_public_key(cfg.root_public_key_file))
    witness_key=None
    if cfg.witness_public_key_file is not None:
        from writer_service_v0714 import _root_provisioned_public_key
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        witness_key=Ed25519PublicKey.from_public_bytes(
                    _root_provisioned_public_key(cfg.witness_public_key_file))
    serve(cfg.db,cfg.socket,writer_key=read_credential(cfg.writer_key_file),
          reviewer_key=read_credential(cfg.reviewer_key_file),seal_key=read_credential(cfg.seal_key_file),
          writer_uid=cfg.writer_uid,socket_gid=cfg.writer_gid,
          research_unsafe_sqlite=cfg.allow_unsafe_sqlite_research_only,
          attester_public_key=attester_key,deployment_id=cfg.deployment_id,
          research_unattested=cfg.allow_unattested_research_only,
          root_public_key=root_key,trusted_min_epoch=cfg.trusted_min_epoch,
          research_unrooted=cfg.allow_unrooted_research_only,
          witness_socket_path=cfg.witness_socket,witness_public_key=witness_key,
          research_static_floor_only=cfg.allow_static_floor_research_only)

if __name__=='__main__':main()
