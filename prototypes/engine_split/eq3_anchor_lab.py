"""ADR-003 candidate (prototype): volatile in-process anchor TEST DOUBLE. Lab only.

Copied from research/anchor_protocol.py MemoryCASAnchor (v0.7.5) without semantic change,
on the shared leaf types. It is not durable, not independent and not authenticated as a remote
party; the reviewer key sits in the same process. It is excluded from DISTRIBUTION.txt and the
candidate's closure check forbids it by name (`*_lab`). Release decision: NO-GO.
"""
from __future__ import annotations

import hashlib
import hmac
from threading import RLock

from eq3_anchor_types import AnchorHold, AnchorStatus, Intent, Position, ReviewDenied, review_message, safe_equal


class MemoryCASAnchor:
    def __init__(self, initial: Position, *, reviewer_key: bytes):
        if not isinstance(reviewer_key, bytes) or len(reviewer_key) < 32:
            raise ValueError('reviewer key must contain >= 32 bytes')
        if (not isinstance(initial.store_id, str) or len(initial.store_id) != 32 or
                not isinstance(initial.digest, str) or len(initial.digest) != 64 or
                type(initial.version) is not int or initial.version != 0):
            raise ValueError('only canonical genesis anchoring allowed')
        try:
            bytes.fromhex(initial.store_id); bytes.fromhex(initial.digest)
        except ValueError as exc:
            raise ValueError('invalid genesis hex encoding') from exc
        self._committed = initial
        self._pending: Intent | None = None
        self._reviewer_key = reviewer_key
        self._lock = RLock()
        self._used = set()

    def status(self) -> AnchorStatus:
        with self._lock:
            return AnchorStatus(self._committed, self._pending)

    def prepare(self, intent: Intent):
        with self._lock:
            old = self._committed
            if self._pending is not None:
                raise AnchorHold('another pending transition exists')
            review_message(intent, 'FINALIZE_COMMIT')
            if (intent.store_id != old.store_id or intent.base_version != old.version or
                    not safe_equal(intent.base_digest, old.digest) or intent.version != old.version+1):
                raise AnchorHold('prepare CAS failed')
            self._pending = intent

    def _approve(self, intent: Intent, decision: str, token: bytes):
        if not isinstance(token, bytes) or len(token) != 32:
            raise ReviewDenied('invalid review token')
        expected = hmac.new(self._reviewer_key, review_message(intent, decision), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, token):
            raise ReviewDenied('review authorization invalid')
        if token in self._used:
            raise ReviewDenied('review token was already consumed')
        self._used.add(token)

    def adjudicate(self, intent: Intent, decision: str, token: bytes):
        with self._lock:
            if self._pending != intent:
                raise AnchorHold('different/missing intent; fail-closed')
            self._approve(intent, decision, token)
            if decision == 'FINALIZE_COMMIT':
                if self._committed.version+1 != intent.version:
                    raise AnchorHold('nonmonotonic anchor commit')
                self._committed = Position(intent.store_id, intent.version, intent.digest)
            elif decision != 'ABORT_NOT_COMMITTED':
                raise AnchorHold('unsupported decision')
            self._pending = None

    def test_only_review_token(self, intent: Intent, decision: str) -> bytes:
        return hmac.new(self._reviewer_key, review_message(intent, decision), hashlib.sha256).digest()
