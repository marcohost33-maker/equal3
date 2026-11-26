"""ADR-003 candidate (prototype): genesis provisioning, NOT part of the writer distribution.

Derived from research/state_store.py StateStore.create (v0.7.22), DELETE/EXTRA and schema v2
only. Creating a store is an administrative step done once, before the writer starts; it is
kept out of the writer's import closure and out of DISTRIBUTION.txt (the closure check of the
candidate forbids this module by name). Release decision: NO-GO.
"""
from __future__ import annotations

from contextlib import closing
import os
from pathlib import Path
import secrets

from eq3_engine import (MAX_STORED_STATE, JOURNAL_MODE, StoreError, StateEngine, chain_genesis,
                        check_key, connect, digest, key_check)


def create_store(path, *, key, initial: bytes) -> StateEngine:
    p = Path(path).absolute()
    check_key(key)
    if not isinstance(initial, bytes) or len(initial) > MAX_STORED_STATE:
        raise StoreError('initial state outside 8 MiB limit')
    if p.exists():
        raise StoreError('refusing to overwrite existing path')
    fd = os.open(p, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    try:
        with closing(connect(p, create=True)) as db:
            mode = db.execute('PRAGMA journal_mode=' + JOURNAL_MODE).fetchone()[0]
            if mode.upper() != JOURNAL_MODE:
                raise StoreError('requested journal mode unavailable')
            db.execute('PRAGMA synchronous=EXTRA')
            db.execute('PRAGMA foreign_keys=ON')
            db.execute('BEGIN IMMEDIATE')
            db.execute('CREATE TABLE meta (id INTEGER PRIMARY KEY CHECK(id=1), schema_version INTEGER NOT NULL, store_id BLOB NOT NULL, key_check BLOB NOT NULL, genesis_digest BLOB)')
            db.execute('CREATE TABLE head (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL, value BLOB NOT NULL, digest BLOB NOT NULL)')
            db.execute('CREATE TABLE receipts (request_id BLOB PRIMARY KEY, proposal_hash BLOB NOT NULL, base_version INTEGER NOT NULL, committed_version INTEGER NOT NULL UNIQUE, digest BLOB NOT NULL)')
            db.execute('CREATE TABLE receipt_auth (committed_version INTEGER PRIMARY KEY, tag BLOB NOT NULL)')
            sid = secrets.token_bytes(16)
            db.execute('INSERT INTO meta VALUES (1,2,?,?,?)', (sid, key_check(key, sid), digest(initial)))
            db.execute('INSERT INTO receipt_auth VALUES (0,?)', (chain_genesis(key, sid, digest(initial)),))
            db.execute('INSERT INTO head VALUES (1,0,?,?)', (initial, digest(initial)))
            db.execute('COMMIT')
    except BaseException:
        for suffix in ('', '-journal', '-wal', '-shm'):
            try:
                Path(str(p) + suffix).unlink()
            except FileNotFoundError:
                pass
        raise
    return StateEngine(p, key=key)
