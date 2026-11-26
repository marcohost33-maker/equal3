"""ADR-003 candidate (prototype): two-phase anchor coordinator on the engine.

Derived from research/anchor_protocol.py CoordinatedStore and position_for_genesis (v0.7.5,
unchanged in v0.7.22). The assessment codes, their order and the HOLD semantics are the same.
Differences: the coordinator gets the engine and its CommitCapability instead of a StateStore,
it never touches the master key (the engine authenticates and decodes proposals), and the
commit goes through the capability, which re-checks the anchor's prepared intent.
The anchor itself is not here: an independently operated anchor does not exist (roadmap P0-3);
eq3_anchor_lab holds the volatile in-process test double. Release decision: NO-GO.
"""
from __future__ import annotations

from typing import Callable

from eq3_anchor_types import (AnchorHold, Assessment, Intent, Position, ReviewDenied,
                              safe_equal)
from eq3_engine import CommitCapability, StateEngine


class CoordinatedStore:
    def __init__(self, engine: StateEngine, capability: CommitCapability, anchor):
        if type(engine) is not StateEngine or type(capability) is not CommitCapability:
            raise AnchorHold('coordinator requires the engine and its commit capability')
        if not capability.bound_to(engine, anchor):
            raise AnchorHold('capability is bound to another engine or anchor')
        self.engine = engine
        self.anchor = anchor
        self._capability = capability

    def diagnose(self) -> Assessment:
        """Never writes the SQLite state or advances the anchor."""
        remote = self.anchor.status()
        request = remote.pending.request_id if remote.pending else None
        try:
            if remote.pending:
                info, snap = self.engine.inspect_request(bytes.fromhex(remote.pending.request_id))
            else:
                info, snap = self.engine.read_verified()
        except Exception as exc:
            return Assessment('INVALID_DB_HOLD', None, remote.committed.version, request, type(exc).__name__)
        if info['receipt_auth'] != 'HMAC_CHAIN_V2':
            return Assessment('LEGACY_UNSEALED_HOLD', snap.version, remote.committed.version, request,
                              'no authenticated receipt history')
        committed = remote.committed
        if info['store_id'] != committed.store_id:
            return Assessment('FORK_HOLD', snap.version, committed.version, request, 'store identity mismatch')
        if remote.pending is None:
            if snap.version == committed.version and safe_equal(snap.digest.hex(), committed.digest):
                return Assessment('MATCH', snap.version, committed.version, None,
                                  'trusted snapshot matches modeled anchor')
            if snap.version < committed.version:
                return Assessment('ROLLBACK_HOLD', snap.version, committed.version, None, 'DB older than anchor')
            return Assessment('DIVERGENCE_HOLD', snap.version, committed.version, None,
                              'DB ahead or conflicting digest')
        p = remote.pending
        if (p.store_id != committed.store_id or p.base_version != committed.version or
                not safe_equal(p.base_digest, committed.digest) or p.version != committed.version+1):
            return Assessment('INVALID_INTENT_HOLD', snap.version, committed.version, request,
                              'pending transition disagrees with anchor')
        receipt = info['request']
        if snap.version == p.base_version and safe_equal(snap.digest.hex(), p.base_digest) and receipt is None:
            return Assessment('NOT_COMMITTED_HOLD', snap.version, committed.version, request,
                              'prepared intent, no durable receipt')
        if (snap.version == p.version and safe_equal(snap.digest.hex(), p.digest) and receipt is not None and
                receipt['base_version'] == p.base_version and receipt['version'] == p.version and
                safe_equal(receipt['digest_sha256'], p.digest) and
                safe_equal(receipt['proposal_hash'], p.proposal_hash)):
            return Assessment('COMMITTED_PENDING_HOLD', snap.version, committed.version, request,
                              'SQLite committed; anchor confirmation absent')
        return Assessment('CONFLICT_HOLD', snap.version, committed.version, request,
                          'state or receipt conflicts with prepared intent')

    def read(self):
        remote = self.anchor.status()
        if remote.pending is not None:
            raise AnchorHold('read denied: PENDING_ANCHOR_REVIEW')
        info, snapshot = self.engine.read_verified()
        if info['receipt_auth'] != 'HMAC_CHAIN_V2':
            raise AnchorHold('read denied: LEGACY_UNSEALED_HOLD')
        if (info['store_id'] != remote.committed.store_id or
                snapshot.version != remote.committed.version or
                not safe_equal(snapshot.digest.hex(), remote.committed.digest)):
            raise AnchorHold('read denied: ANCHOR_SNAPSHOT_MISMATCH')
        return snapshot

    def apply(self, proposal: bytes, *, fault: Callable | None = None):
        if self.diagnose().code != 'MATCH':
            raise AnchorHold('anchor/store out of sync')
        facts = self.engine.describe_proposal(proposal)
        remote = self.anchor.status()
        if (remote.pending or remote.committed.version != facts.base_version
                or remote.committed.digest != facts.base_digest):
            raise AnchorHold('anchor changed before prepare')
        intent = Intent(facts.store_id, facts.base_version, facts.base_digest, facts.base_version+1,
                        facts.target_digest, facts.request_id, facts.proposal_hash)
        self.anchor.prepare(intent)
        try:
            if fault: fault('after_anchor_prepare')
            receipt = self._capability.commit(proposal)
            if fault: fault('after_sqlite_commit')
            if self.diagnose().code != 'COMMITTED_PENDING_HOLD':
                raise AnchorHold('cannot prove committed receipt')
        except BaseException as exc:
            raise AnchorHold('transaction may be pending; read-only diagnosis and independent review required') from exc
        return receipt

    def adjudicate(self, decision: str, token: bytes) -> Assessment:
        remote = self.anchor.status()
        if remote.pending is None:
            raise ReviewDenied('nothing pending')
        state = self.diagnose()
        required = ('COMMITTED_PENDING_HOLD' if decision == 'FINALIZE_COMMIT' else
                    'NOT_COMMITTED_HOLD' if decision == 'ABORT_NOT_COMMITTED' else None)
        if required is None or state.code != required:
            raise ReviewDenied('review decision inconsistent with verified SQLite state')
        self.anchor.adjudicate(remote.pending, decision, token)
        return self.diagnose()


def position_for_genesis(engine: StateEngine) -> Position:
    info, _ = engine.read_verified()
    if info['version'] != 0 or info['receipt_auth'] != 'HMAC_CHAIN_V2':
        raise AnchorHold('late / legacy genesis bootstrapping refused')
    return Position(info['store_id'], 0, info['digest_sha256'])
