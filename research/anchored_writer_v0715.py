"""Equal3 0.7.15: research-only coordinator-connected protected writer.

The *writer* has no reviewer signing credential. Every new commit remains HOLD
until a separately authorised reviewer calls the authority to finalize.
There is NO production serve entrypoint in this module; keys/attestation,
external anchor trust and crash durability are NOT proven by local tests.
"""
from __future__ import annotations

import hashlib
import secrets
import threading

from anchor_protocol import AnchorHold, CoordinatedStore
from state_store import StateStore, ReplayError, prepare_update
from writer_service_v0714 import STATUS, SET, ZERO_REQUEST, MAX_REQUEST, WriterError


class AnchoredWriterCore:
    """Fail-closed adapter used behind the existing UID-authenticated writer RPC.

    A pending anchor transition is NOT a success response. A retry may become
    success only AFTER independent review finalized that exact transition.
    """
    def __init__(self, store: StateStore, anchor):
        if store.journal_mode != 'DELETE':
            raise WriterError('anchored writer requires DELETE/EXTRA StateStore')
        info = store.verify()
        if info.get('receipt_auth') != 'HMAC_CHAIN_V2':
            raise WriterError('authenticated V2 receipt history required')
        self._coordinator = CoordinatedStore(store, anchor)
        self._lock = threading.RLock()
        # Deliberately allow restart while PENDING, but never auto-finalize.
        # Inaccessible/invalid anchor must fail closed rather than bootstrap.
        self._assessment()

    def _assessment(self):
        # A malformed/unreachable remote authority is a hold condition.
        # CoordinatedStore.diagnose() performs a coherent DB inspection.
        return self._coordinator.diagnose()

    @staticmethod
    def _held(assessment, *, rid=None, reason='HOLD'):
        result = {'ok': False, 'error': reason,
                  'assessment': assessment.code,
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
                # Recheck the exact read snapshot against the external anchor.
                snap = self._coordinator.read()
                return {'ok': True, 'version': snap.version,
                        'digest': snap.digest.hex(), 'bytes': len(snap.value)}
            if (op != SET or type(rid) is not bytes or len(rid) != 16 or
                rid == ZERO_REQUEST or type(body) is not bytes or len(body) > MAX_REQUEST):
                raise WriterError('invalid SET')
            return self._set(rid, body)

    def _set(self, rid, body):
        a = self._assessment()
        if a.code != 'MATCH':
            return self._held(a, rid=rid)
        store = self._coordinator.store
        prior = store.receipt(rid)  # authenticated full history
        target_digest = hashlib.sha256(body).digest()
        if prior is not None:
            if not secrets.compare_digest(prior.digest, target_digest):
                raise ReplayError('request ID already bound to another target')
            # The MATCH diagnostic checked that anchor and DB are aligned.
            # A second read below refuses a concurrent remote anchor change.
            self._coordinator.read()
            return {'ok': True, 'version': prior.version, 'digest': prior.digest.hex(),
                    'request_id': rid.hex(), 'already_committed': True}
        proposal, _ = prepare_update(store, body, request_id=rid)
        try:
            self._coordinator.apply(proposal)
        except AnchorHold:
            # A timeout or lost reply MUST NOT turn into a false success.  A
            # fresh diagnosis is for diagnostics only, not auto-adjudication.
            return self._held(self._assessment(), rid=rid)
        # SQLite may now be committed, but authority is still pending.
        assessment = self._assessment()
        if assessment.code != 'COMMITTED_PENDING_HOLD':
            return self._held(assessment, rid=rid)
        return self._held(assessment, rid=rid, reason='EXTERNAL_REVIEW_REQUIRED')
