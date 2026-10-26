"""=== / Equal3 v0.7.5: explicit two-phase *research* anchor protocol.

The included MemoryCASAnchor is ONLY a concurrency-correct, process-local test
DOUBLE: it is not durable, independent, authenticated as a remote caller, or a
replacement for an actual monotonic external trust service. Never use it with
valuable or sensitive data. The entire StoreWriter is trusted here; untrusted
clients can still bypass it via StateStore.apply().

Guarantees within the modeled single-writer, trusted-coordinator scope:
* An anchor prepare is recorded before the SQLite commit.
* Neither a committed-but-unanchored nor a prepared-but-uncommitted transaction
  is silently recovered; all further writes hold until explicit adjudication.
* A review authorization binds exactly one pending transition and decision.
* Independent monotonically committed anchor versions cannot decrease via API.

In production, replace both the test double and the trust boundary. The anchor
MUST persist its own state outside the DB recovery domain; reject untrusted
coordinators, verify provenance, and enforce sole-writer OS/identity isolation.
"""
from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from typing import Callable
import hashlib
import hmac
import secrets

import equal3
from state_store import StateStore, _parse_proposal, IntegrityError, AuthenticationError

DOMAIN = b'EQ3-ANCHOR-REVIEW-v075\0'

class AnchorHold(RuntimeError):
    """An unanchored transaction or fork requires external adjudication."""

class ReviewDenied(AnchorHold):
    pass

@dataclass(frozen=True)
class Position:
    store_id: str
    version: int
    digest: str

@dataclass(frozen=True)
class Intent:
    store_id: str
    base_version: int
    base_digest: str
    version: int
    digest: str
    request_id: str
    proposal_hash: str

@dataclass(frozen=True)
class AnchorStatus:
    committed: Position
    pending: Intent | None

@dataclass(frozen=True)
class Assessment:
    code: str
    version: int | None
    anchored_version: int
    request_id: str | None
    detail: str


def _safe_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)


def _review_message(intent: Intent, decision: str) -> bytes:
    if decision not in ('FINALIZE_COMMIT', 'ABORT_NOT_COMMITTED'):
        raise ValueError('unrecognized manual decision')
    # Fixed-length bytes + domain separation, with one canonical representation.
    parts=(intent.store_id, intent.base_digest, intent.digest,
           intent.request_id, intent.proposal_hash)
    if (type(intent.base_version) is not int or type(intent.version) is not int or
        not 0 <= intent.base_version < 2**63-1 or not 0 < intent.version < 2**63-1):
        raise ValueError('invalid intent version')
    if not all(isinstance(s,str) and len(s)==n for s,n in zip(parts,(32,64,64,32,64))):
        raise ValueError('invalid intent identifier')
    blob=b''.join(bytes.fromhex(s) for s in parts)
    return DOMAIN+decision.encode('ascii')+b'\0'+intent.base_version.to_bytes(8,'big')+intent.version.to_bytes(8,'big')+blob


class MemoryCASAnchor:
    """Thread-safe, VOLATILE simulator of a separate monotonic authority.

    reviewer_key stands for an independently held human/reviewer credential;
    here it is just a bytes parameter in the SAME process, NOT isolated.
    """
    def __init__(self, initial: Position, *, reviewer_key: bytes):
        if not isinstance(reviewer_key,bytes) or len(reviewer_key)<32:
            raise ValueError('reviewer key must contain >= 32 bytes')
        if (not isinstance(initial.store_id,str) or len(initial.store_id)!=32 or
            not isinstance(initial.digest,str) or len(initial.digest)!=64 or
            type(initial.version) is not int or initial.version!=0):
            raise ValueError('only canonical genesis anchoring allowed')
        try:
            bytes.fromhex(initial.store_id);bytes.fromhex(initial.digest)
        except ValueError as exc:
            raise ValueError('invalid genesis hex encoding') from exc
        self._committed=initial
        self._pending: Intent|None=None
        self._reviewer_key=reviewer_key
        self._lock=RLock()
        self._used=set()

    def status(self) -> AnchorStatus:
        with self._lock:
            return AnchorStatus(self._committed,self._pending)

    def prepare(self, intent: Intent):
        with self._lock:
            old=self._committed
            if self._pending is not None:
                raise AnchorHold('another pending transition exists')
            # Validate canonical intent before modifying the simulated anchor.
            _review_message(intent, 'FINALIZE_COMMIT')
            if (intent.store_id!=old.store_id or intent.base_version!=old.version or
                not _safe_equal(intent.base_digest,old.digest) or intent.version!=old.version+1):
                raise AnchorHold('prepare CAS failed')
            self._pending=intent

    def _approve(self, intent: Intent, decision: str, token: bytes):
        if not isinstance(token,bytes) or len(token)!=32:
            raise ReviewDenied('invalid review token')
        expected=hmac.new(self._reviewer_key,_review_message(intent,decision),hashlib.sha256).digest()
        if not hmac.compare_digest(expected,token):
            raise ReviewDenied('review authorization invalid')
        if token in self._used:
            raise ReviewDenied('review token was already consumed')
        self._used.add(token)

    def adjudicate(self, intent:Intent, decision:str, token: bytes):
        """CAS transition after coordinator performed fresh deterministic triage.

        In a real service the verifier must enforce that a trustworthy attester
        supplied the evidence; this simulator DOES NOT authenticate the DB.
        """
        with self._lock:
            if self._pending != intent:
                raise AnchorHold('different/missing intent; fail-closed')
            self._approve(intent,decision,token)
            if decision == 'FINALIZE_COMMIT':
                if self._committed.version+1!=intent.version:
                    raise AnchorHold('nonmonotonic anchor commit')
                self._committed=Position(intent.store_id,intent.version,intent.digest)
            elif decision != 'ABORT_NOT_COMMITTED':
                raise AnchorHold('unsupported decision')
            self._pending=None

    # DO NOT expose a production signer API. This utility is an external
    # test fixture to model a reviewer, and must not be wired into clients.
    def test_only_review_token(self, intent:Intent, decision:str) -> bytes:
        return hmac.new(self._reviewer_key,_review_message(intent,decision),hashlib.sha256).digest()


class CoordinatedStore:
    """Protocol/reference client for a trusted local StateStore writer.

    Even valid memory-anchor behavior is not a production safety proof.
    The live SQLite master key is held by this process; a true separate
    writer identity and authenticated remote anchor remain P0 OPEN.
    """
    def __init__(self, store:StateStore, anchor:MemoryCASAnchor):
        self.store=store
        self.anchor=anchor

    def diagnose(self) -> Assessment:
        """Never writes the SQLite state or advances the anchor."""
        remote=self.anchor.status()
        request=remote.pending.request_id if remote.pending else None
        try:
            if remote.pending:
                info,snap=self.store.inspect_request(bytes.fromhex(remote.pending.request_id))
            else:
                info,snap=self.store.read_verified()
        except Exception as exc:
            return Assessment('INVALID_DB_HOLD',None,remote.committed.version,request,type(exc).__name__)
        if info['receipt_auth']!='HMAC_CHAIN_V2':
            return Assessment('LEGACY_UNSEALED_HOLD',snap.version,remote.committed.version,request,'no authenticated receipt history')
        committed=remote.committed
        if info['store_id']!=committed.store_id:
            return Assessment('FORK_HOLD',snap.version,committed.version,request,'store identity mismatch')
        if remote.pending is None:
            if snap.version==committed.version and _safe_equal(snap.digest.hex(),committed.digest):
                return Assessment('MATCH',snap.version,committed.version,None,'trusted snapshot matches modeled anchor')
            if snap.version<committed.version:
                return Assessment('ROLLBACK_HOLD',snap.version,committed.version,None,'DB older than anchor')
            return Assessment('DIVERGENCE_HOLD',snap.version,committed.version,None,'DB ahead or conflicting digest')
        p=remote.pending
        if (p.store_id!=committed.store_id or p.base_version!=committed.version or
            not _safe_equal(p.base_digest,committed.digest) or p.version!=committed.version+1):
            return Assessment('INVALID_INTENT_HOLD',snap.version,committed.version,request,'pending transition disagrees with anchor')
        receipt=info['request']
        if snap.version==p.base_version and _safe_equal(snap.digest.hex(),p.base_digest) and receipt is None:
            return Assessment('NOT_COMMITTED_HOLD',snap.version,committed.version,request,'prepared intent, no durable receipt')
        if (snap.version==p.version and _safe_equal(snap.digest.hex(),p.digest) and receipt is not None and
            receipt['base_version']==p.base_version and receipt['version']==p.version and
            _safe_equal(receipt['digest_sha256'],p.digest) and
            _safe_equal(receipt['proposal_hash'],p.proposal_hash)):
            return Assessment('COMMITTED_PENDING_HOLD',snap.version,committed.version,request,'SQLite committed; anchor confirmation absent')
        return Assessment('CONFLICT_HOLD',snap.version,committed.version,request,'state or receipt conflicts with prepared intent')

    def read(self):
        # Compare the EXACT returned snapshot against one remote CAS status;
        # do not diagnose() and then read a potentially different DB version.
        remote=self.anchor.status()
        if remote.pending is not None:
            raise AnchorHold('read denied: PENDING_ANCHOR_REVIEW')
        info,snapshot=self.store.read_verified()
        if info['receipt_auth']!='HMAC_CHAIN_V2':
            raise AnchorHold('read denied: LEGACY_UNSEALED_HOLD')
        if (info['store_id']!=remote.committed.store_id or
            snapshot.version!=remote.committed.version or
            not _safe_equal(snapshot.digest.hex(),remote.committed.digest)):
            raise AnchorHold('read denied: ANCHOR_SNAPSHOT_MISMATCH')
        return snapshot

    def apply(self, proposal:bytes, *, fault:Callable|None=None):
        if self.diagnose().code!='MATCH':
            raise AnchorHold('anchor/store out of sync')
        sid,base,rid,_,packet=_parse_proposal(proposal,key=self.store.key)
        info,snapshot=self.store.read_verified()
        if sid.hex()!=info['store_id'] or base!=snapshot.version:
            raise AnchorHold('stale/wrong-store proposal')
        target=equal3.decode_bytes(snapshot.value,packet,key=self.store.key,require_auth=True)
        remote=self.anchor.status()
        if remote.pending or remote.committed.version!=snapshot.version or remote.committed.digest!=snapshot.digest.hex():
            raise AnchorHold('anchor changed before prepare')
        intent=Intent(info['store_id'],base,snapshot.digest.hex(),base+1,
                      hashlib.sha256(target).hexdigest(),rid.hex(),hashlib.sha256(proposal).hexdigest())
        self.anchor.prepare(intent)
        try:
            if fault: fault('after_anchor_prepare')
            receipt=self.store.apply(proposal)
            if fault: fault('after_sqlite_commit')
            result=self.diagnose()
            if result.code!='COMMITTED_PENDING_HOLD':
                raise AnchorHold('cannot prove committed receipt')
        except BaseException as exc:
            raise AnchorHold('transaction may be pending; read-only diagnosis and independent review required') from exc
        # A deliberate design: successful DB commit STILL requires separate
        # independent review before anchor promotion. No secret auto-advance.
        return receipt

    def adjudicate(self, decision: str, token: bytes, *, evidence=None) -> Assessment:
        remote=self.anchor.status()
        if remote.pending is None:
            raise ReviewDenied('nothing pending')
        state=self.diagnose()
        required=('COMMITTED_PENDING_HOLD' if decision=='FINALIZE_COMMIT' else
                  'NOT_COMMITTED_HOLD' if decision=='ABORT_NOT_COMMITTED' else None)
        if required is None or state.code!=required:
            raise ReviewDenied('review decision inconsistent with verified SQLite state')
        # Separate human/authority signature verified by the backend simulator.
        if evidence is None:
            self.anchor.adjudicate(remote.pending,decision,token)
        else:
            self.anchor.adjudicate(remote.pending,decision,token,evidence=evidence)
        return self.diagnose()


def position_for_genesis(store:StateStore) -> Position:
    info,_=store.read_verified()
    if info['version'] != 0 or info['receipt_auth']!='HMAC_CHAIN_V2':
        raise AnchorHold('late / legacy genesis bootstrapping refused')
    return Position(info['store_id'],0,info['digest_sha256'])
