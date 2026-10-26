"""Equal3 v0.7.16: independently SIGNED observation gate (RESEARCH ONLY).

An observation attests that a designated observer verified a SQLite snapshot.
It is *not* proof of independent storage, atomic distributed commit, secure
hardware, or non-rollbackability. The signer must be outside writer control.
This module deliberately never exposes a writer-side reviewer signer.
"""
from __future__ import annotations
from dataclasses import asdict
from contextlib import closing
import hmac
import sqlite3
from cryptography.hazmat.primitives import serialization
import hashlib
import json
import re
import secrets
import time
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from anchor_protocol import AnchorHold, ReviewDenied, Intent
from anchor_wire import PersistentCASAnchor, validate_intent
from state_store import StateStore

DOMAIN = b'Equal3/independent-commit-observation/v0716\x00'
FIELDS = frozenset({'protocol', 'deployment_id', 'observation_id', 'intent_sha256',
                    'decision', 'observed_version', 'observed_digest', 'issued_unix',
                    'expires_unix', 'receipt_present', 'observed_store_id'})
HEX32 = re.compile(r'^[0-9a-f]{32}$')
DEPLOY = re.compile(r'^[a-zA-Z0-9_.:-]{1,96}$')
VALID_DECISIONS = {'FINALIZE_COMMIT', 'ABORT_NOT_COMMITTED'}
MAX_VALIDITY = 60
POLICY_DOMAIN = b'Equal3/attester-binding/v0717\x00'
POLICY_PROTOCOL = 'Equal3-attester-binding-v0717'


def _attester_policy(*, pubkey: Ed25519PublicKey, deployment_id: str, store_id: str) -> bytes:
    if not isinstance(pubkey, Ed25519PublicKey):
        raise ValueError('Ed25519 attester public key required')
    if type(deployment_id) is not str or DEPLOY.fullmatch(deployment_id) is None:
        raise ValueError('invalid deployment identity')
    if type(store_id) is not str or not HEX32.fullmatch(store_id):
        raise ValueError('invalid store binding')
    raw = pubkey.public_bytes(encoding=serialization.Encoding.Raw,
                              format=serialization.PublicFormat.Raw)
    return _canonical({'protocol': POLICY_PROTOCOL, 'store_id': store_id,
                       'deployment_id': deployment_id,
                       'attester_public_key_sha256': hashlib.sha256(raw).hexdigest()})


def _policy_seal(seal_key: bytes, policy: bytes) -> bytes:
    return hmac.new(seal_key, POLICY_DOMAIN + policy, hashlib.sha256).digest()



def _canonical(value):
    # This fixed-field, integer/string/boolean-only encoding is deliberate,
    # not an implementation of the full RFC 8785 standard.
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def _intent_hash(intent: Intent) -> str:
    validate_intent(intent)
    return hashlib.sha256(_canonical(asdict(intent))).hexdigest()


def _fields_match(intent, decision, info, snap):
    if info['receipt_auth'] != 'HMAC_CHAIN_V2' or info['store_id'] != intent.store_id:
        raise ReviewDenied('not a valid authenticated V2 store')
    record = info.get('request')
    if decision == 'FINALIZE_COMMIT':
        ok = (snap.version == intent.version and snap.digest.hex() == intent.digest and
              record is not None and record['request_id'] == intent.request_id and
              record['version'] == intent.version and
              record['base_version'] == intent.base_version and
              record['proposal_hash'] == intent.proposal_hash and
              record['digest_sha256'] == intent.digest)
    elif decision == 'ABORT_NOT_COMMITTED':
        ok = (snap.version == intent.base_version and snap.digest.hex() == intent.base_digest and
              record is None)
    else:
        raise ReviewDenied('invalid decision')
    if not ok:
        raise ReviewDenied('observer found no matching durable state')
    return record is not None


def issue_observation(*, store: StateStore, anchor, intent: Intent, decision: str,
                      deployment_id: str, signing_key: Ed25519PrivateKey,
                      now: int|None = None, lifetime_seconds: int = 30) -> dict:
    """REFERENCE OBSERVER, ONLY run with a securely isolated signer + read-only source.

    Can verify and sign a *currently* authenticated store snapshot. The caller is
    responsible for proving that it is an independent, stable source of truth.
    """
    if not isinstance(signing_key, Ed25519PrivateKey):
        raise TypeError('Ed25519 signer required')
    if type(deployment_id) is not str or DEPLOY.fullmatch(deployment_id) is None:
        raise ValueError('noncanonical deployment id')
    if type(lifetime_seconds) is not int or not 1 <= lifetime_seconds <= MAX_VALIDITY:
        raise ValueError('lifetime out of range')
    if store.journal_mode != 'DELETE':
        raise ReviewDenied('observer requires DELETE/EXTRA store')
    remote = anchor.status()
    if remote.pending != intent or remote.committed.version != intent.base_version or remote.committed.store_id != intent.store_id or remote.committed.digest != intent.base_digest:
        raise ReviewDenied('observer anchor intent mismatch')
    info,snap=store.inspect_request(bytes.fromhex(intent.request_id))
    present=_fields_match(intent,decision,info,snap)
    if now is None:
        now=int(time.time())
    if type(now) is not int or now<0 or now>=(1<<63)-MAX_VALIDITY:
        raise ValueError('observer clock out of range')
    statement={
        'protocol':'Equal3-observation-1', 'deployment_id':deployment_id,
        'observation_id':secrets.token_hex(16), 'intent_sha256':_intent_hash(intent),
        'decision':decision, 'observed_version':snap.version,
        'observed_digest':snap.digest.hex(), 'observed_store_id':info['store_id'],
        'issued_unix':now, 'expires_unix':now+lifetime_seconds,
        'receipt_present':present
    }
    signature=signing_key.sign(DOMAIN+_canonical(statement))
    return {'statement':statement, 'signature':signature.hex()}


def verify_observation(evidence, *, intent: Intent, decision: str,
                       deployment_id: str, public_key: Ed25519PublicKey,
                       now:int|None = None) -> None:
    """Validate observation against pending intent and trusted out-of-band public key."""
    if not isinstance(public_key, Ed25519PublicKey):
        raise ReviewDenied('untrusted evidence verification key')
    if type(deployment_id) is not str or DEPLOY.fullmatch(deployment_id) is None:
        raise ReviewDenied('invalid verifier deployment id')
    if type(evidence) is not dict or set(evidence) != {'statement','signature'}:
        raise ReviewDenied('missing or unexpected evidence fields')
    statement=evidence['statement'];signature=evidence['signature']
    if type(statement) is not dict or set(statement) != FIELDS:
        raise ReviewDenied('noncanonical statement structure')
    if type(signature) is not str or len(signature)!=128:
        # Ed25519 signatures encode as 128 lowercase hexadecimal characters.
        raise ReviewDenied('bad signature encoding')
    if not all(ch in '0123456789abcdef' for ch in signature):
        raise ReviewDenied('noncanonical signature encoding')
    if (statement['protocol'] != 'Equal3-observation-1' or
        statement['deployment_id'] != deployment_id or
        type(statement['observation_id']) is not str or not HEX32.fullmatch(statement['observation_id']) or
        statement['intent_sha256'] != _intent_hash(intent) or statement['decision'] != decision or
        statement['observed_store_id'] != intent.store_id):
        raise ReviewDenied('evidence identity mismatch')
    want_ver = intent.version if decision=='FINALIZE_COMMIT' else intent.base_version
    want_digest = intent.digest if decision=='FINALIZE_COMMIT' else intent.base_digest
    if (type(statement['observed_version']) is not int or statement['observed_version'] != want_ver or
        statement['observed_digest'] != want_digest or
        type(statement['receipt_present']) is not bool or
        statement['receipt_present'] != (decision == 'FINALIZE_COMMIT')):
        raise ReviewDenied('evidence does not prove requested decision')
    start=statement['issued_unix'];end=statement['expires_unix']
    if (type(start) is not int or type(end) is not int or start<0 or
        not 1<=end-start<=MAX_VALIDITY):
        raise ReviewDenied('invalid evidence validity interval')
    if now is None:now=int(time.time())
    if type(now) is not int or not start <= now <= end:
        raise ReviewDenied('evidence expired or outside validity interval')
    try:
        public_key.verify(bytes.fromhex(signature),DOMAIN+_canonical(statement))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise ReviewDenied('invalid independent observer signature') from exc


class EvidenceRequiredCASAnchor(PersistentCASAnchor):
    """Research attested authority with a persistent, HMAC-sealed trust policy.

    The policy is checked for every authority load, including status, prepare,
    and adjudicate. Provisioning the first policy requires an externally
    attested operator step; a v0716 authority cannot silently migrate.

    This HMAC is not a tamperproof root against an administrator with seal_key,
    a joint DB+seal-key rollback, or a deliberately launched unsealed legacy
    service. Those remain production release blockers.
    """
    def __init__(self, db_path, *, reviewer_key, seal_key,
                 attester_public_key: Ed25519PublicKey, deployment_id: str):
        if not isinstance(attester_public_key, Ed25519PublicKey):
            raise ValueError('independent Ed25519 public key required')
        if type(deployment_id) is not str or DEPLOY.fullmatch(deployment_id) is None:
            raise ValueError('deployment id required')
        self._attester_public_key = attester_public_key
        self._deployment_id = deployment_id
        super().__init__(db_path, reviewer_key=reviewer_key, seal_key=seal_key)

    @classmethod
    def bootstrap(cls, db_path, position, *, reviewer_key, seal_key,
                  attester_public_key, deployment_id):
        """Create a NEW bound authority, fail-closed if interrupted mid-bootstrap."""
        policy = _attester_policy(pubkey=attester_public_key,
                                  deployment_id=deployment_id,
                                  store_id=position.store_id)
        # The base constructor refuses an existing DB; cannot overwrite a
        # v0716 anchor or silently reset an existing monotonic version.
        base = PersistentCASAnchor.bootstrap(db_path, position,
                                             reviewer_key=reviewer_key,
                                             seal_key=seal_key)
        with base._db() as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                db.execute('CREATE TABLE trust_binding('
                           'id INTEGER PRIMARY KEY CHECK(id=1), '
                           'policy BLOB NOT NULL, seal BLOB NOT NULL)')
                db.execute('INSERT INTO trust_binding(id,policy,seal) VALUES(1,?,?)',
                           (policy, _policy_seal(seal_key,policy)))
                db.commit()
            except BaseException:
                db.rollback()
                raise
        return cls(db_path, reviewer_key=reviewer_key, seal_key=seal_key,
                   attester_public_key=attester_public_key,
                   deployment_id=deployment_id)

    def _load(self, db):
        result = super()._load(db)
        try:
            rows = db.execute('SELECT id,policy,seal FROM trust_binding LIMIT 2').fetchall()
        except sqlite3.DatabaseError as exc:
            raise AnchorHold('unbound legacy attester policy: offline independent migration required') from exc
        if len(rows) != 1 or rows[0][0] != 1:
            raise AnchorHold('missing, duplicate, or unauthorized attester trust binding; HOLD')
        _, policy, seal = rows[0]
        if type(policy) is not bytes or type(seal) is not bytes or len(seal) != 32:
            raise AnchorHold('malformed persisted trust binding; HOLD')
        expected = _attester_policy(pubkey=self._attester_public_key,
                                    deployment_id=self._deployment_id,
                                    store_id=result.committed.store_id)
        if (not hmac.compare_digest(policy,expected) or
            not hmac.compare_digest(seal,_policy_seal(self._seal_key,policy))):
            raise AnchorHold('persisted attester identity/deployment mismatch; HOLD')
        return result

    def adjudicate(self, intent, decision, token, *, nonce=None, evidence=None):
        # A changed trust policy is rechecked under the same SQLite transaction
        # in super().adjudicate() via our _load override, before mutation.
        verify_observation(evidence,intent=intent,decision=decision,
                           public_key=self._attester_public_key,
                           deployment_id=self._deployment_id)
        return super().adjudicate(intent,decision,token,nonce=nonce)
