"""Equal3 v0.7.19 research: challenge-bound externally held epoch floor.

Demonstration ONLY: the witness must run in an independent administrative / rollback
failure domain before any non-rollback guarantee can be made.  A socket on the same
machine is not an external trust boundary. Do not expose its signing key to writers.
"""
from __future__ import annotations
import hashlib
import json
import os
import socket
import socketserver
import sqlite3
import stat
import threading
from contextlib import closing
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey
from anchor_protocol import AnchorHold, ReviewDenied
from anchor_wire import unique_json
from trust_rotation_v0718 import RootControlledCASAnchor, fingerprint, verify_rotation, statement
from commit_evidence_v0716 import _canonical, DEPLOY

DOMAIN=b'Equal3/external-epoch-witness/v0719\x00'
PROTO='Equal3-external-epoch-witness-v0719'
MAX_REPLY=8192

def _strict_hex(x,n):
    if type(x) is not str or len(x)!=n or any(c not in '0123456789abcdef' for c in x):
        raise ValueError('noncanonical hex value')
    return x

def _record(*, deployment_id,store_id,root_fingerprint,attester_fingerprint,epoch):
    if type(deployment_id) is not str or DEPLOY.fullmatch(deployment_id) is None:
        raise ValueError('bad deployment')
    _strict_hex(store_id,32)
    _strict_hex(root_fingerprint,64);_strict_hex(attester_fingerprint,64)
    if type(epoch) is not int or epoch<0 or epoch>=2**63:raise ValueError('bad epoch')
    return dict(protocol=PROTO,deployment_id=deployment_id,store_id=store_id,
                root_fingerprint=root_fingerprint,attester_fingerprint=attester_fingerprint,
                epoch=epoch)

class WitnessLedger:
    """Single-writer research reference; key retained only by witness process."""
    def __init__(self,db_path,*,private_key,root_public_key):
        if not isinstance(private_key,Ed25519PrivateKey) or not isinstance(root_public_key,Ed25519PublicKey):
            raise TypeError('separate witness signing private key and root public key required')
        if fingerprint(private_key.public_key())==fingerprint(root_public_key):
            raise ValueError('witness signer and root authority must have distinct keys')
        self.db_path=Path(db_path)
        self.private_key=private_key
        self.root_public_key=root_public_key
        self.lock=threading.Lock()

    @classmethod
    def bootstrap(cls,db_path,*,private_key,root_public_key,attester_public_key,
                  deployment_id,store_id):
        if fingerprint(private_key.public_key())==fingerprint(attester_public_key):
            raise ValueError('witness signer and attester must have distinct keys')
        db_path=Path(db_path)
        if db_path.exists():raise FileExistsError('witness already exists: refusing bootstrap')
        db_path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        st=db_path.parent.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.geteuid() or stat.S_IMODE(st.st_mode)!=0o700:
            raise PermissionError('witness directory must be owned and mode 0700')
        data=_record(deployment_id=deployment_id,store_id=store_id,
                     root_fingerprint=fingerprint(root_public_key),
                     attester_fingerprint=fingerprint(attester_public_key),epoch=0)
        with closing(sqlite3.connect(db_path)) as db:
            db.execute('PRAGMA journal_mode=DELETE');db.execute('PRAGMA synchronous=EXTRA')
            db.execute('CREATE TABLE floor(id INTEGER PRIMARY KEY CHECK(id=1), body BLOB NOT NULL)')
            db.execute('INSERT INTO floor VALUES(1,?)',(_canonical(data),));db.commit()
        os.chmod(db_path,0o600)
        return cls(db_path,private_key=private_key,root_public_key=root_public_key)

    def _connect(self):
        try:
            parent=self.db_path.parent.lstat()
            leaf=self.db_path.lstat()
        except OSError as exc:
            raise AnchorHold('witness database unavailable') from exc
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid!=os.geteuid() or
            stat.S_IMODE(parent.st_mode)!=0o700 or not stat.S_ISREG(leaf.st_mode) or
            leaf.st_uid!=os.geteuid() or stat.S_IMODE(leaf.st_mode)!=0o600 or leaf.st_nlink!=1):
            raise AnchorHold('witness filesystem boundary violated')
        db=sqlite3.connect(self.db_path,timeout=2,isolation_level=None)
        db.execute('PRAGMA trusted_schema=OFF');db.execute('PRAGMA synchronous=EXTRA')
        if db.execute('PRAGMA journal_mode').fetchone()[0].lower()!='delete':
            db.close();raise AnchorHold('witness journal mismatch')
        return db

    @staticmethod
    def _load(db):
        rows=db.execute('SELECT id,body FROM floor LIMIT 2').fetchall()
        if len(rows)!=1 or rows[0][0]!=1 or type(rows[0][1]) is not bytes:
            raise AnchorHold('invalid witness rows')
        try:
            data=unique_json(rows[0][1])
            if type(data) is not dict or set(data)!={'protocol','deployment_id','store_id','root_fingerprint','attester_fingerprint','epoch'}:
                raise ValueError('bad witness schema')
            if data!=_record(**{k:v for k,v in data.items() if k!='protocol'}):
                raise ValueError('invalid witness record')
        except (ValueError,TypeError) as exc:raise AnchorHold('noncanonical witness record') from exc
        return data

    def challenge(self,nonce):
        _strict_hex(nonce,64)
        with self.lock,closing(self._connect()) as db:
            db.execute('BEGIN')
            try:
                current=self._load(db)
                if current['root_fingerprint']!=fingerprint(self.root_public_key):
                    raise AnchorHold('witness root binding corrupted')
                db.commit()
            except BaseException:
                db.rollback();raise
        response={'nonce':nonce, 'floor':current}
        signature=self.private_key.sign(DOMAIN+_canonical(response)).hex()
        return {'response':response,'signature':signature}

    def advance(self,authorization):
        """CAS only for a valid ROOT signed attester rotation statement."""
        with self.lock,closing(self._connect()) as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                current=self._load(db)
                if current['root_fingerprint']!=fingerprint(self.root_public_key):
                    raise AnchorHold('witness root binding corrupted')
                body=authorization['statement'] if type(authorization) is dict else None
                if type(body) is not dict:
                    raise ReviewDenied('missing rotation statement')
                expected=statement(deployment_id=current['deployment_id'],
                    store_id=current['store_id'],root_fingerprint=current['root_fingerprint'],
                    from_fingerprint=current['attester_fingerprint'],
                    to_fingerprint=body.get('to_fingerprint'),from_epoch=current['epoch'],
                    to_epoch=current['epoch']+1,issued_unix=body.get('issued_unix'),
                    expires_unix=body.get('expires_unix'))
                verify_rotation(authorization,root_public_key=self.root_public_key,expected=expected)
                next_floor=_record(deployment_id=current['deployment_id'],store_id=current['store_id'],
                    root_fingerprint=current['root_fingerprint'],
                    attester_fingerprint=body['to_fingerprint'],epoch=current['epoch']+1)
                db.execute('UPDATE floor SET body=? WHERE id=1',(_canonical(next_floor),))
                db.commit()
                return next_floor
            except BaseException:
                db.rollback();raise

class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            raw=self.rfile.readline(MAX_REPLY+1)
            if len(raw)>MAX_REPLY or not raw.endswith(b'\n'):raise ValueError('oversized or incomplete RPC')
            req=unique_json(raw.strip())
            if type(req) is not dict:raise ValueError('bad request')
            if set(req)=={'op','nonce'} and req['op']=='challenge':
                result=self.server.ledger.challenge(req['nonce'])
            elif set(req)=={'op','authorization'} and req['op']=='advance':
                result={'floor':self.server.ledger.advance(req['authorization'])}
            else:raise ValueError('unsupported request')
            reply={'ok':True,'result':result}
        except Exception as exc:
            reply={'ok':False,'error':type(exc).__name__} # no secrets in errors
        self.wfile.write(_canonical(reply)+b'\n')

class WitnessServer(socketserver.ThreadingMixIn,socketserver.UnixStreamServer):
    daemon_threads=True
    allow_reuse_address=False
    def __init__(self,socket_path,ledger):
        super().__init__(str(socket_path),_Handler)
        self.ledger=ledger
        os.chmod(socket_path,0o600)

class WitnessClient:
    def __init__(self,socket_path,*,public_key,timeout=2):
        if not isinstance(public_key,Ed25519PublicKey):raise TypeError('independently pinned witness public key required')
        self.socket_path=str(socket_path);self.public_key=public_key;self.timeout=timeout
    def _rpc(self,req):
        try:
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout);s.connect(self.socket_path)
                s.sendall(_canonical(req)+b'\n')
                recv=b''
                while not recv.endswith(b'\n') and len(recv)<=MAX_REPLY:
                    piece=s.recv(min(4096,MAX_REPLY+1-len(recv)))
                    if not piece:break
                    recv+=piece
            if not recv.endswith(b'\n') or len(recv)>MAX_REPLY:raise ValueError('malformed reply')
            result=unique_json(recv.strip())
            if type(result) is not dict or set(result)!= {'ok','result'} or result['ok'] is not True:
                raise ValueError('witness unavailable or denied')
            return result['result']
        except (OSError,ValueError,TimeoutError) as exc:raise AnchorHold('trusted external witness unavailable / invalid response; HOLD') from exc

    def floor(self,*,deployment_id,store_id,root_fingerprint,attester_fingerprint):
        nonce=os.urandom(32).hex()
        body=self._rpc({'op':'challenge','nonce':nonce})
        try:
            if type(body) is not dict or set(body)!={'response','signature'}:
                raise ValueError('bad signed response')
            response=body['response'];sig=_strict_hex(body['signature'],128)
            if type(response) is not dict or set(response)!={'nonce','floor'} or response['nonce']!=nonce:
                raise ValueError('not the current challenge')
            self.public_key.verify(bytes.fromhex(sig),DOMAIN+_canonical(response))
            floor=response['floor']
            if type(floor) is not dict or set(floor)!={'protocol','deployment_id','store_id','root_fingerprint','attester_fingerprint','epoch'}:
                raise ValueError('wrong witness floor format')
            if floor!=_record(**{k:v for k,v in floor.items() if k!='protocol'}):
                raise ValueError('noncanonical floor')
            if (floor['deployment_id']!=deployment_id or floor['store_id']!=store_id or
                floor['root_fingerprint']!=root_fingerprint):
                raise ValueError('foreign witness deployment/store/root')
            return floor
        except (InvalidSignature,ValueError,TypeError,KeyError) as exc:
            raise AnchorHold('witness signature / identity verification failed; HOLD') from exc

    def advance(self,authorization):
        return self._rpc({'op':'advance','authorization':authorization})

class WitnessGatedCASAnchor(RootControlledCASAnchor):
    """Explicitly gated research authority; every anchor `_load` rechecks live witness.

    Strict equality of epoch and signer means: after local rotation, writer HOLDS
    until an independently authorized witness CAS catches up. If the witness was
    advanced first, authority also HOLDS. This is a deliberately fail-closed
    distributed transition, NOT an atomic cross-host transaction.
    """
    def __init__(self, db_path, *, witness_client, **kwargs):
        if not isinstance(witness_client,WitnessClient):raise TypeError('witness client required')
        self._witness_client=witness_client
        super().__init__(db_path,**kwargs)
    def _load_root(self,db,status):
        epoch=super()._load_root(db,status)
        floor=self._witness_client.floor(
            deployment_id=self._deployment_id,store_id=status.committed.store_id,
            root_fingerprint=fingerprint(self._root_public_key),
            attester_fingerprint=fingerprint(self._attester_public_key))
        if floor['epoch']!=epoch or floor['attester_fingerprint']!=fingerprint(self._attester_public_key):
            raise AnchorHold('remote witness does not match local root epoch/attester: HOLD')
        return epoch
