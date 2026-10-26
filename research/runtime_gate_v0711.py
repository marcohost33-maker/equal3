"""Optional signed SQLite-runtime approval gate for Equal3 research.

A passing result asserts only that this process matches a *trusted external*
Ed25519 allowlist entry. It is not a production-release authorization.
Public keys MUST be provisioned out of band, outside the Equal3 data/anchor
rollback and writer administrator domains. This module bundles no private keys.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import platform
import re
import sqlite3
import sys
import time
from typing import Any

from runtime_evidence_v0710 import RuntimeEvidenceError, runtime_inventory
from anchor_wire import sqlite_wal_reset_safe

SCHEMA = 'equal3.sqlite-runtime-approval.v1'
PURPOSE = 'equal3-state-store-wal-runtime'
EXACT_FIELDS = frozenset({
    'schema', 'purpose', 'deployment_id', 'sqlite_version', 'sqlite_source_id',
    'loaded_library_sha256', 'python_abi', 'machine', 'not_before', 'expires_at'
})
_HEX64 = re.compile(r'[a-f0-9]{64}\Z')


def _strict_object(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            raise ValueError('duplicate JSON key')
        result[k] = v
    return result


def _clean_string(value: Any, max_len: int = 200) -> bool:
    return type(value) is str and 1 <= len(value) <= max_len and value.isascii()


def verify_signed_runtime_policy(
    approval_bytes: bytes,
    signature: bytes,
    trusted_ed25519_public_key: bytes,
    *,
    deployment_id: str,
    now: int | None = None,
) -> dict:
    """Check raw signed bytes and bind approval to THIS loaded SQLite runtime.

    No trust-on-first-use, unsigned dictionary, environment-supplied public key,
    or package-embedded approval is accepted. Caller owns the key trust root.
    Avoid treating an authenticated policy as an external security review.
    """
    if not (_clean_string(deployment_id, 128) and
            type(approval_bytes) is bytes and 1 <= len(approval_bytes) <= 16384 and
            type(signature) is bytes and len(signature) == 64 and
            type(trusted_ed25519_public_key) is bytes and len(trusted_ed25519_public_key) == 32):
        raise RuntimeEvidenceError('invalid signed runtime policy inputs; HOLD')
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
    except ImportError as exc:
        raise RuntimeEvidenceError('Ed25519 verification library unavailable; HOLD') from exc
    try:
        # Signature covers ORIGINAL bytes: no ambiguous canonicalization layer.
        Ed25519PublicKey.from_public_bytes(trusted_ed25519_public_key).verify(signature, approval_bytes)
    except (ValueError, InvalidSignature) as exc:
        raise RuntimeEvidenceError('runtime approval signature not verified; HOLD') from exc
    try:
        info = json.loads(approval_bytes.decode('utf-8'), object_pairs_hook=_strict_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))
    except (ValueError, UnicodeError, TypeError) as exc:
        raise RuntimeEvidenceError('malformed or ambiguous signed runtime approval; HOLD') from exc
    if type(info) is not dict or set(info) != EXACT_FIELDS:
        raise RuntimeEvidenceError('unknown/missing runtime approval fields; HOLD')
    if info['schema'] != SCHEMA or info['purpose'] != PURPOSE:
        raise RuntimeEvidenceError('runtime policy purpose/version mismatch; HOLD')
    if (not _clean_string(info['deployment_id'], 128) or
        not hmac.compare_digest(info['deployment_id'], deployment_id) or
        not _clean_string(info['sqlite_version'], 32) or
        not _clean_string(info['sqlite_source_id'], 128) or
        not _clean_string(info['python_abi'], 32) or
        not _clean_string(info['machine'], 64) or
        type(info['loaded_library_sha256']) is not str or
        not _HEX64.fullmatch(info['loaded_library_sha256']) or
        type(info['not_before']) is not int or type(info['expires_at']) is not int):
        raise RuntimeEvidenceError('runtime approval field invalid or wrong deployment; HOLD')
    # Public-key issuer must enforce its own narrow authorization and issuance
    # policy; this verifier additionally limits validity to 30 days.
    instant = int(time.time()) if now is None else now
    if (type(instant) is not int or info['expires_at'] <= instant or
        info['not_before'] > instant or
        info['expires_at'] - info['not_before'] > 30*86400 or
        info['not_before'] <= 0):
        raise RuntimeEvidenceError('expired, future, or overlong runtime approval; HOLD')
    try:
        facts = runtime_inventory()
    except (OSError, ValueError, RuntimeEvidenceError) as exc:
        raise RuntimeEvidenceError('effective SQLite runtime not inventoried; HOLD') from exc
    if (facts.get('mapped_file_identity_consistent') is not True or
        not sqlite_wal_reset_safe() or
        facts.get('sqlite_source_id') != info['sqlite_source_id'] or
        facts.get('sqlite_version') != info['sqlite_version'] or
        not hmac.compare_digest(str(facts.get('loaded_sqlite_shared_object_sha256') or ''),
                                info['loaded_library_sha256']) or
        f'{sys.version_info.major}.{sys.version_info.minor}' != info['python_abi'] or
        platform.machine() != info['machine']):
        raise RuntimeEvidenceError('signed approval does not match executing SQLite runtime; HOLD')
    # Deliberately do not return a production GO claim. This is only one gate.
    return {'runtime_gate': 'SIGNED_POLICY_AND_RUNTIME_MATCH',
            'release_verdict': 'NO_GO_OTHER_P0_GATES',
            'effective_runtime': facts,
            'policy_sha256': hashlib.sha256(approval_bytes).hexdigest(),
            'deployment_id': deployment_id}
