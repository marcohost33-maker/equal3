"""Equal3 v0.7.20 research: separately signed monotone COMMIT position witness.

A witness signs current checkpoint challenges and accepts only sequential attester-signed
commit observations. It DOES NOT prove the observer really saw stable storage, or
prevent rollback of its own database. A shared local host is not an independent trust
boundary. Never issue attester observations from untrusted writers.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
import socket
import socketserver
import sqlite3
import stat
import threading
from contextlib import closing
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from anchor_protocol import AnchorHold, ReviewDenied, Intent, Position, CoordinatedStore
from anchor_wire import unique_json, from_intent, validate_position, _verify_delete_header
from commit_evidence_v0716 import _canonical, _intent_hash, DEPLOY
from trust_rotation_v0718 import fingerprint
from anchored_writer_v0715 import AnchoredWriterCore

PROTOCOL='Equal3-commit-witness-v0720'
SIGN_DOMAIN=b'Equal3/commit-witness/challenge/v0720\x00'
OBS_DOMAIN=b'Equal3/commit-witness/postfinal-observation/v0720\x00'
SEAL_DOMAIN=b'Equal3/commit-witness/seal/v0720\x00'
MAX_FRAME=16384


def _hex(x,n):
    if type(x) is not str or len(x)!=n or any(c not in '0123456789abcdef' for c in x):
        raise ValueError('invalid canonical hexadecimal field')
    return x


def _record(*,deployment_id,store_id,version,digest,attester_fingerprint,signer_fingerprint,request_id):
    if type(deployment_id) is not str or DEPLOY.fullmatch(deployment_id) is None:
        raise ValueError('invalid deployment id')
    _hex(store_id,32);_hex(digest,64);_hex(attester_fingerprint,64);_hex(signer_fingerprint,64)
    if type(version) is not int or version<0 or version>=2**63:raise ValueError('invalid version')
    if version==0:
        if request_id is not None:raise ValueError('genesis must not have request id')
    else:_hex(request_id,32)
    return dict(protocol=PROTOCOL,deployment_id=deployment_id,store_id=store_id,
                version=version,digest=digest,attester_fingerprint=attester_fingerprint,
                signer_fingerprint=signer_fingerprint,request_id=request_id)


def _seal(key,record):return hmac.new(key,SEAL_DOMAIN+_canonical(record),hashlib.sha256).digest()


def issue_final_checkpoint(*,store,anchor,intent:Intent,signing_key:Ed25519PrivateKey,
                           deployment_id:str,now=None,lifetime_seconds=30):
    """REFERENCE ONLY: observer must run in independent identity with read-only access.

    Sign only after final anchor decision and authenticated DB read. This is a
    point-in-time assertion, NOT an atomic distributed commit or anti-TOCTOU proof.
    """
    from anchor_wire import validate_intent
    validate_intent(intent)
    if not isinstance(signing_key,Ed25519PrivateKey):raise TypeError('independent observer private key required')
    if type(deployment_id) is not str or DEPLOY.fullmatch(deployment_id) is None:
        raise ValueError('noncanonical deployment')
    if type(lifetime_seconds) is not int or not 1<=lifetime_seconds<=60:
        raise ValueError('invalid checkpoint lifetime')
    remote=anchor.status()
    if remote.pending is not None or remote.committed != Position(intent.store_id,intent.version,intent.digest):
        raise ReviewDenied('final anchor commit not independently observed')
    if store.journal_mode != 'DELETE':raise ReviewDenied('observer requires DELETE/EXTRA StateStore')
    info,snap=store.inspect_request(bytes.fromhex(intent.request_id))
    receipt=info.get('request')
    if (info.get('receipt_auth')!='HMAC_CHAIN_V2' or info.get('store_id')!=intent.store_id or
        snap.version!=intent.version or snap.digest.hex()!=intent.digest or
        type(receipt) is not dict or receipt.get('request_id')!=intent.request_id or
        receipt.get('base_version')!=intent.base_version or receipt.get('version')!=intent.version or
        receipt.get('proposal_hash')!=intent.proposal_hash or receipt.get('digest_sha256')!=intent.digest):
        raise ReviewDenied('authenticated post-finalization state does not match intent')
    if now is None:now=int(time.time())
    if type(now) is not int or now<0 or now>=2**63-61:raise ValueError('invalid observer time')
    stmt={'protocol':'Equal3-final-checkpoint-v0720', 'deployment_id':deployment_id,
          'observation_id':secrets.token_hex(16),'intent_sha256':_intent_hash(intent),
          'store_id':intent.store_id,'version':intent.version,'digest':intent.digest,
          'request_id':intent.request_id,'issued_unix':now,'expires_unix':now+lifetime_seconds}
    return {'statement':stmt,'signature':signing_key.sign(OBS_DOMAIN+_canonical(stmt)).hex()}


def verify_final_checkpoint(evidence,*,intent:Intent,public_key:Ed25519PublicKey,deployment_id:str,now=None):
    if not isinstance(public_key,Ed25519PublicKey):raise ReviewDenied('untrusted observer key')
    if type(evidence) is not dict or set(evidence)!={'statement','signature'}:
        raise ReviewDenied('postfinal observation required')
    stmt=evidence['statement'];signature=evidence['signature']
    expected_fields={'protocol','deployment_id','observation_id','intent_sha256','store_id',
                     'version','digest','request_id','issued_unix','expires_unix'}
    if type(stmt) is not dict or set(stmt)!=expected_fields or type(signature) is not str:
        raise ReviewDenied('malformed postfinal observation')
    try:
        _hex(signature,128);_hex(stmt['observation_id'],32)
        if (stmt['protocol']!='Equal3-final-checkpoint-v0720' or stmt['deployment_id']!=deployment_id or
            stmt['intent_sha256']!=_intent_hash(intent) or stmt['store_id']!=intent.store_id or
            type(stmt['version']) is not int or stmt['version']!=intent.version or
            stmt['digest']!=intent.digest or stmt['request_id']!=intent.request_id):
            raise ValueError('postfinal checkpoint identity mismatch')
        start,end=stmt['issued_unix'],stmt['expires_unix']
        if type(start) is not int or type(end) is not int or start<0 or not 1<=end-start<=60:
            raise ValueError('invalid checkpoint lifetime')
        if now is None:now=int(time.time())
        if type(now) is not int or not start<=now<=end:raise ValueError('stale postfinal checkpoint')
        public_key.verify(bytes.fromhex(signature),OBS_DOMAIN+_canonical(stmt))
    except (ValueError,TypeError,KeyError,InvalidSignature) as exc:
        raise ReviewDenied('invalid final commit checkpoint evidence') from exc



class CommitWitnessLedger:
    """Append-only CAS head protected by a witness-only seal key; local research."""
    def __init__(self,path,*,signing_key,attester_public_key,seal_key,deployment_id):
        if not isinstance(signing_key,Ed25519PrivateKey) or not isinstance(attester_public_key,Ed25519PublicKey):
            raise TypeError('separate witness signing and attester verifying keys required')
        if fingerprint(signing_key.public_key())==fingerprint(attester_public_key):
            raise ValueError('witness cannot share attester signing identity')
        if type(seal_key) is not bytes or len(seal_key)<32:raise ValueError('witness-only seal key required')
        self.path=Path(path).absolute();self.signing_key=signing_key
        self.attester_public_key=attester_public_key;self.seal_key=seal_key
        self.deployment_id=deployment_id;self.lock=threading.RLock()
        with closing(self._db()) as db:
            db.execute('BEGIN')
            try:self._load(db);db.commit()
            except BaseException:db.rollback();raise

    @classmethod
    def bootstrap(cls,path,genesis:Position,*,signing_key,attester_public_key,seal_key,deployment_id):
        validate_position(genesis,genesis=True)
        p=Path(path).absolute()
        s=p.parent.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.geteuid() or stat.S_IMODE(s.st_mode)!=0o700:
            raise PermissionError('witness directory must be private, owned and mode 0700')
        if p.exists():raise FileExistsError('witness already exists')
        record=_record(deployment_id=deployment_id,store_id=genesis.store_id,version=0,
                       digest=genesis.digest,attester_fingerprint=fingerprint(attester_public_key),
                       signer_fingerprint=fingerprint(signing_key.public_key()),request_id=None)
        flags=os.O_CREAT|os.O_EXCL|os.O_RDWR|getattr(os,'O_NOFOLLOW',0)
        fd=os.open(p,flags,0o600);os.close(fd)
        try:
            with closing(sqlite3.connect(p)) as db:
                db.execute('PRAGMA journal_mode=DELETE');db.execute('PRAGMA synchronous=EXTRA')
                db.execute('PRAGMA trusted_schema=OFF')
                db.execute('CREATE TABLE commit_floor(id INTEGER PRIMARY KEY CHECK(id=1),body BLOB NOT NULL,seal BLOB NOT NULL)')
                db.execute('INSERT INTO commit_floor VALUES(1,?,?)',(_canonical(record),_seal(seal_key,record)))
                db.commit()
        except BaseException:
            # No silent recreation of potentially ambiguous or partial database.
            raise
        return cls(p,signing_key=signing_key,attester_public_key=attester_public_key,
                   seal_key=seal_key,deployment_id=deployment_id)

    def _db(self):
        s=self.path.lstat();parent=self.path.parent.lstat()
        if (not stat.S_ISREG(s.st_mode) or s.st_uid!=os.geteuid() or
            stat.S_IMODE(s.st_mode)!=0o600 or s.st_nlink!=1 or
            not stat.S_ISDIR(parent.st_mode) or parent.st_uid!=os.geteuid() or
            stat.S_IMODE(parent.st_mode)!=0o700):raise AnchorHold('witness filesystem boundary violated')
        _verify_delete_header(self.path)
        from urllib.parse import quote
        db=sqlite3.connect('file:'+quote(str(self.path),safe='/')+'?mode=rw',uri=True,timeout=3,isolation_level=None)
        try:
            db.execute('PRAGMA trusted_schema=OFF');db.execute('PRAGMA synchronous=EXTRA')
            if db.execute('PRAGMA journal_mode').fetchone()[0].lower()!='delete':raise AnchorHold('witness journal changed')
            if db.execute('PRAGMA synchronous').fetchone()[0]!=3:raise AnchorHold('witness sync downgraded')
        except BaseException:db.close();raise
        return db

    def _load(self,db):
        try:rows=db.execute('SELECT id,body,seal FROM commit_floor LIMIT 2').fetchall()
        except sqlite3.DatabaseError as exc:raise AnchorHold('missing witness schema') from exc
        if len(rows)!=1 or rows[0][0]!=1:raise AnchorHold('malformed commit witness cardinality')
        _,raw,seal=rows[0]
        if type(raw) is not bytes or type(seal) is not bytes or len(seal)!=32:
            raise AnchorHold('malformed witness seal')
        try:
            item=unique_json(raw)
            if type(item) is not dict or set(item)!=set(_record(deployment_id='d',store_id='a'*32,version=0,digest='a'*64,attester_fingerprint='a'*64,signer_fingerprint='a'*64,request_id=None)):
                raise ValueError('invalid witness fields')
            canonical=_record(**{k:v for k,v in item.items() if k!='protocol'})
            if item!=canonical or raw!=_canonical(canonical):raise ValueError('noncanonical witness row')
            if (item['deployment_id']!=self.deployment_id or item['attester_fingerprint']!=fingerprint(self.attester_public_key) or
                item['signer_fingerprint']!=fingerprint(self.signing_key.public_key())):
                raise ValueError('witness trust identity mismatch')
        except (ValueError,TypeError,KeyError) as exc:raise AnchorHold('malformed commit witness record') from exc
        if not hmac.compare_digest(seal,_seal(self.seal_key,item)):
            raise AnchorHold('witness seal broken')
        return item

    def challenge(self,nonce):
        _hex(nonce,64)
        with self.lock,closing(self._db()) as db:
            db.execute('BEGIN')
            try:item=self._load(db);db.commit()
            except BaseException:db.rollback();raise
            payload={'nonce':nonce,'floor':item}
            return {'response':payload,'signature':self.signing_key.sign(SIGN_DOMAIN+_canonical(payload)).hex()}

    def publish(self,intent:Intent,evidence):
        """CAS publication after a signed observer has seen an authenticated SQLite commit.

        The attester signs a bounded POST-FINAL observation. A signature does NOT prevent subsequent
        SQLite rollback; clients must revalidate local DB+anchor against remote floor.
        """
        from anchor_wire import validate_intent
        validate_intent(intent)
        verify_final_checkpoint(evidence,intent=intent,
                           deployment_id=self.deployment_id,public_key=self.attester_public_key)
        with self.lock,closing(self._db()) as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                old=self._load(db)
                # Time-of-check/time-of-use: the signature was checked before BEGIN IMMEDIATE.
                # Enforce the (already authenticated) lifetime again after acquiring the
                # write lock, immediately before accepting an idempotent response or CAS.
                # This uses the local wall clock; independent trusted time is still P0.
                expires=evidence['statement']['expires_unix']
                issued=evidence['statement']['issued_unix']
                current=int(time.time())
                if current < issued or current > expires:
                    raise ReviewDenied('postfinal observation expired before witness CAS')
                if old['store_id']!=intent.store_id:raise AnchorHold('foreign store')
                if old['version']==intent.version:
                    if old['digest']!=intent.digest or old['request_id']!=intent.request_id:
                        raise AnchorHold('conflicting duplicate commit')
                    db.commit();return old
                if (intent.base_version!=old['version'] or intent.base_digest!=old['digest'] or
                    intent.version!=old['version']+1):
                    raise AnchorHold('nonmonotonic commit witness CAS')
                nxt=_record(deployment_id=self.deployment_id,store_id=intent.store_id,
                     version=intent.version,digest=intent.digest,
                     attester_fingerprint=fingerprint(self.attester_public_key),
                     signer_fingerprint=fingerprint(self.signing_key.public_key()),request_id=intent.request_id)
                db.execute('UPDATE commit_floor SET body=?,seal=? WHERE id=1',(_canonical(nxt),_seal(self.seal_key,nxt)))
                db.commit();return nxt
            except BaseException:db.rollback();raise


class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            raw=self.rfile.readline(MAX_FRAME+1)
            if not raw.endswith(b'\n') or len(raw)>MAX_FRAME:raise ValueError('invalid frame')
            msg=unique_json(raw.strip())
            if type(msg) is not dict:raise ValueError('invalid request')
            if set(msg)=={'op','nonce'} and msg['op']=='challenge':
                result=self.server.ledger.challenge(msg['nonce'])
            elif set(msg)=={'op','intent','evidence'} and msg['op']=='publish':
                result=self.server.ledger.publish(from_intent(msg['intent']),msg['evidence'])
            else:raise ValueError('unsupported operation')
            reply={'ok':True,'result':result}
        except Exception as exc:reply={'ok':False,'error':type(exc).__name__}
        self.wfile.write(_canonical(reply)+b'\n')


class CommitWitnessServer(socketserver.ThreadingMixIn,socketserver.UnixStreamServer):
    daemon_threads=True
    allow_reuse_address=False
    def __init__(self,path,ledger):
        super().__init__(str(path),_Handler);self.ledger=ledger;os.chmod(path,0o600)


class CommitWitnessClient:
    def __init__(self,path,*,public_key,timeout=2):
        if not isinstance(public_key,Ed25519PublicKey):raise TypeError('pinned witness public key required')
        self.path=str(path);self.public_key=public_key;self.timeout=timeout
    def _rpc(self,msg):
        try:
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout);s.connect(self.path);s.sendall(_canonical(msg)+b'\n')
                r=b''
                while not r.endswith(b'\n') and len(r)<=MAX_FRAME:
                    piece=s.recv(min(4096,MAX_FRAME+1-len(r)))
                    if not piece:break
                    r+=piece
            if not r.endswith(b'\n') or len(r)>MAX_FRAME:raise ValueError('malformed response')
            body=unique_json(r.strip())
            if type(body) is not dict or set(body)!={'ok','result'} or body['ok'] is not True:
                raise ValueError('remote witness denied')
            return body['result']
        except (OSError,ValueError,TimeoutError) as exc:
            raise AnchorHold('commit witness unavailable/invalid: HOLD') from exc
    def floor(self,*,deployment_id,store_id):
        nonce=os.urandom(32).hex()
        body=self._rpc({'op':'challenge','nonce':nonce})
        try:
            if type(body) is not dict or set(body)!={'response','signature'}:raise ValueError('bad signature envelope')
            resp=body['response']
            if type(resp) is not dict or set(resp)!={'nonce','floor'} or resp['nonce']!=nonce:
                raise ValueError('nonce mismatch')
            sig=_hex(body['signature'],128)
            self.public_key.verify(bytes.fromhex(sig),SIGN_DOMAIN+_canonical(resp))
            f=resp['floor']
            if type(f) is not dict or set(f)!= {'protocol','deployment_id','store_id','version','digest','attester_fingerprint','signer_fingerprint','request_id'}:
                raise ValueError('invalid floor structure')
            if f!=_record(**{k:v for k,v in f.items() if k!='protocol'}):raise ValueError('bad floor')
            if f['deployment_id']!=deployment_id or f['store_id']!=store_id:
                raise ValueError('wrong deployment or store')
            return f
        except (ValueError,TypeError,KeyError,InvalidSignature) as exc:
            raise AnchorHold('commit witness signature/binding failed: HOLD') from exc
    def publish(self,intent,evidence):
        from dataclasses import asdict
        return self._rpc({'op':'publish','intent':asdict(intent),'evidence':evidence})


class CommitGatedWriterCore(AnchoredWriterCore):
    """Research adapter; successful STATUS and idempotent SET require remote COMMIT floor.

    Does not make the older raw writer entrypoint inaccessible. Production must expose
    ONLY this adapter after privilege separation, and enforce pinned keys externally.
    """
    def __init__(self,store,anchor,*,commit_witness, deployment_id):
        if not isinstance(commit_witness,CommitWitnessClient):raise TypeError('commit witness client required')
        self._commit_witness=commit_witness;self._commit_deployment=deployment_id
        super().__init__(store,anchor)
        self._check_floor()
    def _check_floor(self):
        a=self._coordinator.anchor.status()
        if a.pending is not None:raise AnchorHold('pending anchor review; HOLD')
        floor=self._commit_witness.floor(deployment_id=self._commit_deployment,store_id=a.committed.store_id)
        # A version and final-state hash do not identify the committing request.
        # Two fully authenticated forks can write identical bytes at the same
        # version using different request IDs.  Bind the WITNESS request ID to
        # the receipt at that exact version in one pinned, authenticated
        # StateStore snapshot.  Do not trust an unauthenticated SQL lookup.
        if floor['version'] == 0:
            if floor['request_id'] is not None:
                raise AnchorHold('genesis commit witness carries request identity: HOLD')
            info, snap = self._coordinator.store.read_verified()
        else:
            rid = floor['request_id']
            if type(rid) is not str or len(rid) != 32:
                raise AnchorHold('commit witness request identity absent: HOLD')
            try:
                raw_rid = bytes.fromhex(rid)
            except ValueError as exc:
                raise AnchorHold('commit witness request identity malformed: HOLD') from exc
            info, snap = self._coordinator.store.inspect_request(raw_rid)
            receipt = info.get('request')
            if (info.get('receipt_auth') != 'HMAC_CHAIN_V2' or
                type(receipt) is not dict or
                receipt.get('request_id') != rid or
                receipt.get('version') != floor['version'] or
                receipt.get('digest_sha256') != floor['digest']):
                raise AnchorHold('commit witness disagrees with authenticated final receipt: HOLD')
        if (info.get('receipt_auth') != 'HMAC_CHAIN_V2' or
            info.get('store_id') != a.committed.store_id or
            snap.version != floor['version'] or snap.digest.hex() != floor['digest'] or
            a.committed.version != floor['version'] or a.committed.digest != floor['digest']):
            raise AnchorHold('external commit floor mismatches local state: HOLD')
        later=self._commit_witness.floor(deployment_id=self._commit_deployment,store_id=a.committed.store_id)
        if (later['version']!=floor['version'] or later['digest']!=floor['digest'] or
            later['request_id']!=floor['request_id']):
            raise AnchorHold('external witness changed while reading: HOLD')
        # This does not create atomicity across the local DB and independent
        # services, but detects an intervening authority transition.
        again=self._coordinator.anchor.status()
        if again.pending is not None or again.committed != a.committed:
            raise AnchorHold('anchor changed during witnessed read: HOLD')
        return floor
    def dispatch(self,op,rid,body):
        with self._lock:
            try:self._check_floor()
            except AnchorHold:return {'ok':False,'error':'EXTERNAL_COMMIT_FLOOR_HOLD'}
            result=super().dispatch(op,rid,body)
            if result.get('ok'):
                try:self._check_floor()
                except AnchorHold:return {'ok':False,'error':'EXTERNAL_COMMIT_FLOOR_HOLD'}
            return result
