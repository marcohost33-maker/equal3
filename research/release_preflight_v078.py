"""Read-only Equal3 v0.7.8 runtime inventory / mandatory release NO-GO report.

An upstream version check is NOT a signed software-supply-chain attestation.
No simulated override is permitted here. This tool does not modify DBs or keys.
"""
from __future__ import annotations
import hashlib
from contextlib import closing
import json
from pathlib import Path
import platform
import sqlite3
import sys
import _sqlite3

from anchor_wire import sqlite_wal_reset_safe
from runtime_evidence_v0710 import runtime_inventory

REQUIRED = (
    'separately administered and nonrollbackable external monotonic anchor',
    'real writer/anchor OS identity and secret isolation',
    'independent commit evidence with rollback/fork adversarial tests',
    'encrypted database, WAL, SHM, temporary files and backups',
    'physical/VFS power-loss fault lab',
    'independent security and privacy release review',
    'attested effective SQLite library/build for ALL WAL components',
)

def assess() -> dict:
    binary=Path(_sqlite3.__file__).resolve()
    with closing(sqlite3.connect(':memory:')) as db:
        source_id=db.execute('select sqlite_source_id()').fetchone()[0]
        options=[x[0] for x in db.execute('pragma compile_options')]
    runtime_patched_by_upstream_version=sqlite_wal_reset_safe()
    return {
        'project':'=== / Equal3','candidate_version':'0.7.10-research',
        'python':platform.python_version(),'sqlite_version':sqlite3.sqlite_version,
        'sqlite_source_id':source_id, 'sqlite_extension_path':str(binary),
        'sqlite_extension_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
        'sqlite_compile_options':sorted(options),
        'upstream_wal_reset_version_policy': 'PASS' if runtime_patched_by_upstream_version else 'FAIL',
        'runtime_attestation': 'NOT_ATTESTED',
        'effective_linked_sqlite':runtime_inventory(),
        'note_extension_digest':'_sqlite3 extension hash is NOT the linked SQLite library fingerprint',
        'research_unsafe_sqlite_override_accepted':False,
        'release_verdict':'NO_GO',
        'blocking_gates':list(REQUIRED),
        'scope':'Read-only inventory. Version checks do not prove distro backport provenance or deployment isolation.'
    }

if __name__=='__main__':
    print(json.dumps(assess(),indent=2,sort_keys=True))
    sys.exit(2)
