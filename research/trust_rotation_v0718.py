"""Equal3 v0.7.18 research: root-authorized attester rotation with epoch flooring.

This is NOT a nonrollbackable trust root. A trustworthy external minimum epoch
is required to reject a coherent rollback of BOTH local trust databases and policy.
Never embed or expose a root signing private key in an anchor service.
"""
from __future__ import annotations
import hashlib
import hmac
import re
import sqlite3
import time
from dataclasses import asdict
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey
from anchor_protocol import AnchorHold, ReviewDenied
from commit_evidence_v0716 import (_canonical, _attester_policy, _policy_seal,
     EvidenceRequiredCASAnchor, DEPLOY)

ROOT_DOMAIN = b'Equal3/root-authorized-rotation/v0718\x00'
ROOT_SEAL_DOMAIN = b'Equal3/root-binding-integrity/v0718\x00'
HEX64 = re.compile(r'^[0-9a-f]{64}$')
PROTOCOL = 'Equal3-root-rotation-v0718'
MAX_AUTH_AGE = 300


def fingerprint(pub):
    if not isinstance(pub, Ed25519PublicKey):
        raise ValueError('an Ed25519 public key is required')
    return hashlib.sha256(pub.public_bytes(serialization.Encoding.Raw,
                                           serialization.PublicFormat.Raw)).hexdigest()


def statement(*, deployment_id, store_id, root_fingerprint, from_fingerprint,
              to_fingerprint, from_epoch, to_epoch, issued_unix, expires_unix):
    """Exact canonical authorization schema, with no untrusted extension keys."""
    if type(deployment_id) is not str or DEPLOY.fullmatch(deployment_id) is None:
        raise ValueError('invalid deployment')
    for name, value in {'store_id':store_id,'root_fingerprint':root_fingerprint,
                        'from_fingerprint':from_fingerprint,'to_fingerprint':to_fingerprint}.items():
        size=32 if name=='store_id' else 64
        if type(value) is not str or len(value)!=size or any(c not in '0123456789abcdef' for c in value):
            raise ValueError('noncanonical '+name)
    if type(from_epoch) is not int or type(to_epoch) is not int or not 0<=from_epoch<(1<<63)-1 or to_epoch!=from_epoch+1:
        raise ValueError('nonconsecutive epoch')
    if type(issued_unix) is not int or type(expires_unix) is not int or issued_unix<0 or not 1<=expires_unix-issued_unix<=MAX_AUTH_AGE:
        raise ValueError('invalid authorization lifetime')
    if from_fingerprint==to_fingerprint:
        raise ValueError('identity must actually change')
    return dict(protocol=PROTOCOL,deployment_id=deployment_id,store_id=store_id,
                root_fingerprint=root_fingerprint,from_fingerprint=from_fingerprint,
                to_fingerprint=to_fingerprint,from_epoch=from_epoch,to_epoch=to_epoch,
                issued_unix=issued_unix,expires_unix=expires_unix)


def sign_rotation(root_private_key:Ed25519PrivateKey, *, store_id, deployment_id,
                  from_key, to_key, from_epoch, now=None, lifetime_seconds=120):
    """OFFLINE TEST HELPER: the production root signer MUST be externally operated."""
    if not isinstance(root_private_key,Ed25519PrivateKey):
        raise TypeError('root private key required')
    if now is None: now=int(time.time())
    body=statement(deployment_id=deployment_id,store_id=store_id,
        root_fingerprint=fingerprint(root_private_key.public_key()),
        from_fingerprint=fingerprint(from_key),to_fingerprint=fingerprint(to_key),
        from_epoch=from_epoch,to_epoch=from_epoch+1,
        issued_unix=now,expires_unix=now+lifetime_seconds)
    return {'statement':body,
            'signature':root_private_key.sign(ROOT_DOMAIN+_canonical(body)).hex()}


def verify_rotation(auth, *, root_public_key, expected, now=None):
    if type(auth) is not dict or set(auth)!={'statement','signature'} or type(auth['statement']) is not dict:
        raise ReviewDenied('malformed rotation authorization')
    body=auth['statement']
    if set(body)!=set(expected) or body!=expected:
        raise ReviewDenied('rotation authorization identity/epoch mismatch')
    try:
        statement(**{k:v for k,v in body.items() if k!='protocol'})
    except (ValueError,TypeError) as exc:
        raise ReviewDenied('noncanonical rotation authorization') from exc
    if body['protocol']!=PROTOCOL:
        raise ReviewDenied('wrong rotation protocol')
    if now is None: now=int(time.time())
    if type(now) is not int or not body['issued_unix']<=now<=body['expires_unix']:
        raise ReviewDenied('rotation authorization expired/not yet valid')
    sig=auth['signature']
    if type(sig) is not str or len(sig)!=128 or any(c not in '0123456789abcdef' for c in sig):
        raise ReviewDenied('bad rotation signature encoding')
    try:
        root_public_key.verify(bytes.fromhex(sig),ROOT_DOMAIN+_canonical(body))
    except (InvalidSignature,ValueError,TypeError) as exc:
        raise ReviewDenied('invalid independent root signature') from exc


def root_record(*, root_key, attester_key, deployment_id, store_id, epoch):
    if type(epoch) is not int or epoch<0 or epoch>=(1<<63):
        raise ValueError('bad epoch')
    return _canonical({'protocol':'Equal3-root-binding-v0718',
                       'root_fingerprint':fingerprint(root_key),
                       'attester_fingerprint':fingerprint(attester_key),
                       'deployment_id':deployment_id,'store_id':store_id,
                       'epoch':epoch})


def root_seal(seal_key,record):
    return hmac.new(seal_key,ROOT_SEAL_DOMAIN+record,hashlib.sha256).digest()


class RootControlledCASAnchor(EvidenceRequiredCASAnchor):
    """Optional v0718 strict authority, not a production remote trust service.

    min_epoch MUST be supplied by the caller's separately provisioned/trusted
    epoch source at each restart. Setting it to zero each time is insecure.
    """
    def __init__(self, db_path, *, reviewer_key, seal_key,attester_public_key,
                 deployment_id, root_public_key, min_epoch):
        fingerprint(root_public_key)
        if fingerprint(root_public_key)==fingerprint(attester_public_key):
            raise ValueError('root and attester key roles must be distinct')
        if type(min_epoch) is not int or not 0<=min_epoch<(1<<63):
            raise ValueError('external minimum epoch must be explicit')
        self._root_public_key=root_public_key
        self._min_epoch=min_epoch
        super().__init__(db_path,reviewer_key=reviewer_key,seal_key=seal_key,
                         attester_public_key=attester_public_key,deployment_id=deployment_id)

    @classmethod
    def bootstrap(cls, db_path, position, *, reviewer_key, seal_key,
                  attester_public_key, deployment_id,root_public_key,min_epoch=0):
        if type(min_epoch) is not int or min_epoch!=0:
            raise ValueError('genesis must initialize at epoch zero')
        fingerprint(root_public_key)
        if fingerprint(root_public_key)==fingerprint(attester_public_key):
            raise ValueError('root and attester key roles must be distinct')
        base=EvidenceRequiredCASAnchor.bootstrap(db_path,position,
            reviewer_key=reviewer_key,seal_key=seal_key,
            attester_public_key=attester_public_key,deployment_id=deployment_id)
        blob=root_record(root_key=root_public_key,attester_key=attester_public_key,
                         deployment_id=deployment_id,store_id=position.store_id,epoch=0)
        with base._db() as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                db.execute('CREATE TABLE root_binding(id INTEGER PRIMARY KEY CHECK(id=1),'
                           'binding BLOB NOT NULL, seal BLOB NOT NULL)')
                db.execute('INSERT INTO root_binding(id,binding,seal) VALUES(1,?,?)',
                           (blob,root_seal(seal_key,blob)))
                db.commit()
            except BaseException:
                db.rollback()
                raise
        return cls(db_path,reviewer_key=reviewer_key,seal_key=seal_key,
                   attester_public_key=attester_public_key,
                   deployment_id=deployment_id,root_public_key=root_public_key,min_epoch=0)

    def _load_root(self, db, status):
        try:
            rows=db.execute('SELECT id,binding,seal FROM root_binding LIMIT 2').fetchall()
        except sqlite3.DatabaseError as exc:
            raise AnchorHold('unbound legacy root trust: offline migration required') from exc
        if len(rows)!=1 or rows[0][0]!=1:
            raise AnchorHold('missing or duplicate root trust binding; HOLD')
        _,blob,seal=rows[0]
        if type(blob) is not bytes or type(seal) is not bytes or len(seal)!=32 or not hmac.compare_digest(seal,root_seal(self._seal_key,blob)):
            raise AnchorHold('invalid root trust binding seal; HOLD')
        try:
            from anchor_wire import unique_json
            policy=unique_json(blob)
            if type(policy) is not dict or set(policy)!={'protocol','root_fingerprint','attester_fingerprint','deployment_id','store_id','epoch'}:
                raise ValueError('malformed root binding')
            epoch=policy['epoch']
            if type(epoch) is not int or not 0<=epoch<(1<<63): raise ValueError('invalid epoch')
            expected=root_record(root_key=self._root_public_key,attester_key=self._attester_public_key,
                 deployment_id=self._deployment_id,store_id=status.committed.store_id,epoch=epoch)
            if not hmac.compare_digest(blob,expected):raise ValueError('root/attester trust mismatch')
        except (ValueError,TypeError,KeyError) as exc:
            raise AnchorHold('invalid bound root trust identity/epoch; HOLD') from exc
        if epoch<self._min_epoch:
            raise AnchorHold('anchor trust epoch rollback below trusted floor; HOLD')
        return epoch

    def _load(self,db):
        state=super()._load(db)
        self._load_root(db,state)
        return state

    def rotate_attester(self, *, new_attester_public_key, authorization, now=None):
        """Transactional root-signed single-step key rotation. No pending intent.

        An operator must independently publish the new minimum epoch BEFORE
        relying on rollback rejection after restart. This function does not
        modify a remote epoch registry, and makes no antirollback claim.
        """
        fingerprint(new_attester_public_key)
        if fingerprint(new_attester_public_key)==fingerprint(self._root_public_key):
            raise ReviewDenied('attester cannot be root key')
        if now is None:now=int(time.time())
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                status=self._load(db)
                if status.pending is not None:
                    raise AnchorHold('rotation forbidden while commit intent pending')
                epoch=self._load_root(db,status)
                expected=statement(store_id=status.committed.store_id,
                    deployment_id=self._deployment_id,
                    root_fingerprint=fingerprint(self._root_public_key),
                    from_fingerprint=fingerprint(self._attester_public_key),
                    to_fingerprint=fingerprint(new_attester_public_key),
                    from_epoch=epoch,to_epoch=epoch+1,
                    issued_unix=authorization.get('statement',{}).get('issued_unix') if type(authorization) is dict and type(authorization.get('statement')) is dict else None,
                    expires_unix=authorization.get('statement',{}).get('expires_unix') if type(authorization) is dict and type(authorization.get('statement')) is dict else None)
                verify_rotation(authorization,root_public_key=self._root_public_key,expected=expected,now=now)
                next_policy=_attester_policy(pubkey=new_attester_public_key,
                       deployment_id=self._deployment_id,store_id=status.committed.store_id)
                next_root=root_record(root_key=self._root_public_key,
                       attester_key=new_attester_public_key,
                       deployment_id=self._deployment_id,store_id=status.committed.store_id,epoch=epoch+1)
                db.execute('UPDATE trust_binding SET policy=?, seal=? WHERE id=1',
                           (next_policy,_policy_seal(self._seal_key,next_policy)))
                db.execute('UPDATE root_binding SET binding=?, seal=? WHERE id=1',
                           (next_root,root_seal(self._seal_key,next_root)))
                db.commit()
            except BaseException:
                db.rollback()
                raise
        self._attester_public_key=new_attester_public_key
        self._min_epoch=max(self._min_epoch,epoch+1)
        return epoch+1
