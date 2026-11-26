"""ADR-003 candidate (prototype): anchored writer core on the engine and its capability.

Derived from research/anchored_writer_v0715.py (unchanged in v0.7.22). dispatch() and the HOLD
replies are the same; the core is built from (engine, capability, anchor) instead of a
StateStore, and a SET commits only through CoordinatedStore -> CommitCapability. There is no
unanchored write path in the candidate: writer_service_v0714.WriterCore, which called
StateStore.apply directly behind a research flag, has no counterpart. Release: NO-GO.
"""
from __future__ import annotations

import secrets
import threading

from eq3_anchor_types import AnchorHold
from eq3_coordinator import CoordinatedStore
from eq3_engine import CommitCapability, ReplayError, StateEngine, digest
from eq3_wire import MAX_REQUEST, SET, STATUS, ZERO_REQUEST, WriterError


class AnchoredWriterCore:
    """Fail-closed adapter behind the UID-authenticated writer RPC.

    A pending anchor transition is NOT a success response. A retry may become success only
    AFTER independent review finalized that exact transition.
    """
    def __init__(self, engine: StateEngine, capability: CommitCapability, anchor):
        if type(engine) is not StateEngine or engine.journal_mode != 'DELETE':
            raise WriterError('anchored writer requires the DELETE/EXTRA engine')
        if engine.verify().get('receipt_auth') != 'HMAC_CHAIN_V2':
            raise WriterError('authenticated V2 receipt history required')
        try:
            self._coordinator = CoordinatedStore(engine, capability, anchor)
        except AnchorHold as exc:
            raise WriterError('commit capability not bound to this engine and anchor') from exc
        self._lock = threading.RLock()
        self._assessment()

    def _assessment(self):
        return self._coordinator.diagnose()

    @staticmethod
    def _held(assessment, *, rid=None, reason='HOLD'):
        result = {'ok': False, 'error': reason, 'assessment': assessment.code,
                  'anchored_version': assessment.anchored_version}
        if rid is not None:
            result['request_id'] = rid.hex()
        return result

    def dispatch(self, op, rid, body):
        with self._lock:
            if op == STATUS:
                if rid != ZERO_REQUEST or body != b'':
                    raise WriterError('noncanonical STATUS request')
                a = self._assessment()
                if a.code != 'MATCH':
                    return self._held(a)
                snap = self._coordinator.read()
                return {'ok': True, 'version': snap.version, 'digest': snap.digest.hex(), 'bytes': len(snap.value)}
            if (op != SET or type(rid) is not bytes or len(rid) != 16 or
                    rid == ZERO_REQUEST or type(body) is not bytes or len(body) > MAX_REQUEST):
                raise WriterError('invalid SET')
            return self._set(rid, body)

    def _set(self, rid, body):
        a = self._assessment()
        if a.code != 'MATCH':
            return self._held(a, rid=rid)
        engine = self._coordinator.engine
        prior = engine.receipt(rid)
        if prior is not None:
            if not secrets.compare_digest(prior.digest, digest(body)):
                raise ReplayError('request ID already bound to another target')
            self._coordinator.read()
            return {'ok': True, 'version': prior.version, 'digest': prior.digest.hex(),
                    'request_id': rid.hex(), 'already_committed': True}
        proposal, _ = engine.prepare_update(body, request_id=rid)
        try:
            self._coordinator.apply(proposal)
        except AnchorHold:
            return self._held(self._assessment(), rid=rid)
        assessment = self._assessment()
        if assessment.code != 'COMMITTED_PENDING_HOLD':
            return self._held(assessment, rid=rid)
        return self._held(assessment, rid=rid, reason='EXTERNAL_REVIEW_REQUIRED')
