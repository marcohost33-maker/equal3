"""ADR-003 candidate (prototype, NOT a research version): anchor data types, leaf module.

Derived from research/anchor_protocol.py (v0.7.5, unchanged in v0.7.22): the exception
classes, the four dataclasses and the canonical review message are copied without semantic
change. They live in a leaf module so that the engine (commit capability), the coordinator
and the lab anchor can share them without an import cycle (ADR-003 item 4).
Release decision: NO-GO.
"""
from __future__ import annotations

from dataclasses import dataclass
import hmac

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


def safe_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)


def review_message(intent: Intent, decision: str) -> bytes:
    if decision not in ('FINALIZE_COMMIT', 'ABORT_NOT_COMMITTED'):
        raise ValueError('unrecognized manual decision')
    parts = (intent.store_id, intent.base_digest, intent.digest,
             intent.request_id, intent.proposal_hash)
    if (type(intent.base_version) is not int or type(intent.version) is not int or
            not 0 <= intent.base_version < 2**63-1 or not 0 < intent.version < 2**63-1):
        raise ValueError('invalid intent version')
    if not all(isinstance(s, str) and len(s) == n for s, n in zip(parts, (32, 64, 64, 32, 64))):
        raise ValueError('invalid intent identifier')
    blob = b''.join(bytes.fromhex(s) for s in parts)
    return (DOMAIN + decision.encode('ascii') + b'\0' + intent.base_version.to_bytes(8, 'big')
            + intent.version.to_bytes(8, 'big') + blob)
