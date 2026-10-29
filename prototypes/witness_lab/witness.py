"""C2SP tlog-witness add-checkpoint logic with atomic SQLite state (lab prototype).

Follows c2sp.org/tlog-witness (editor's copy @ fea9004): the request body is "old <size>",
up to 63 consistency-proof lines, an empty line and a checkpoint. Status codes:
400 malformed / old > size, 403 no valid trusted log signature, 404 unknown origin,
409 old size differs from the latest cosigned size (body: that size), 422 proof, empty-tree or
same-size root mismatch, 200 with timestamped Ed25519 cosignature lines.

Checking the old size and recording the new checkpoint happen in one BEGIN IMMEDIATE
transaction, so the rollback race described by the spec (a smaller checkpoint cosigned
after a larger one) cannot occur. Rejected but validly signed requests are kept as
misbehaviour evidence (the spec allows this) - that is the raw material for fork detection.
"""
from __future__ import annotations

import sqlite3
import sys
import time
from contextlib import closing
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Tuple

import note as n

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'merkle_audit_log'))
import merkle_log  # noqa: E402

MAX_PROOF_LINES = 63
EMPTY_ROOT = merkle_log.mth([])

Response = Tuple[int, str]


class Witness:
    def __init__(self, db_path, signer: n.Signer, trusted_logs: Dict[str, Iterable[n.Verifier]],
                 clock: Callable[[], int] = lambda: int(time.time())):
        if signer.sig_type != n.TYPE_COSIGNATURE_V1:
            raise ValueError('a witness signs with Ed25519 checkpoint cosignatures (type 0x04)')
        self.db_path, self.signer, self.clock = str(db_path), signer, clock
        self.trusted = {origin: list(keys) for origin, keys in trusted_logs.items()}
        with closing(self._connect()) as db:
            db.execute('CREATE TABLE IF NOT EXISTS latest (origin TEXT PRIMARY KEY, size INTEGER NOT NULL, '
                       'root BLOB NOT NULL, note BLOB NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS evidence (id INTEGER PRIMARY KEY, origin TEXT NOT NULL, '
                       'status INTEGER NOT NULL, reason TEXT NOT NULL, request BLOB NOT NULL)')
            db.commit()

    def _connect(self):
        db = sqlite3.connect(self.db_path, timeout=10, isolation_level=None)
        db.execute('PRAGMA journal_mode=DELETE')
        db.execute('PRAGMA synchronous=FULL')
        return db

    def latest(self, origin: str):
        with closing(self._connect()) as db:
            row = db.execute('SELECT size, root, note FROM latest WHERE origin=?', (origin,)).fetchone()
        return row

    def evidence(self, origin: str) -> List[tuple]:
        with closing(self._connect()) as db:
            return db.execute('SELECT status, reason, request FROM evidence WHERE origin=? ORDER BY id',
                              (origin,)).fetchall()

    def add_checkpoint(self, body: bytes) -> Response:
        try:
            old, proof, note_bytes = parse_request(body)
            note = n.parse_note(note_bytes)
            checkpoint = n.parse_checkpoint_text(note.text)
        except (n.NoteError, UnicodeDecodeError, ValueError) as exc:
            return 400, 'malformed request: %s\n' % exc
        keys = self.trusted.get(checkpoint.origin)
        if not keys:
            return 404, 'unknown origin\n'
        try:
            verified = n.verify_note(note, [k for k in keys if k.sig_type == n.TYPE_ED25519])
        except n.NoteError as exc:
            return 403, '%s\n' % exc
        # store and later serve only the log signatures verified here: a request may carry extra
        # lines, e.g. a forged one under this witness's own key ID, that would break the served note
        kept = {(v.name, v.key_id) for v in verified}
        note_bytes = note.text + b'\n' + ''.join(
            '%s %s %s\n' % (n.EM_DASH, sig.name, n.b64encode(sig.key_id + sig.payload))
            for sig in note.signatures if (sig.name, sig.key_id) in kept).encode('utf-8')
        if old > checkpoint.size:
            return 400, 'old size larger than checkpoint size\n'
        with closing(self._connect()) as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                row = db.execute('SELECT size, root FROM latest WHERE origin=?', (checkpoint.origin,)).fetchone()
                stored_size, stored_root = (row[0], row[1]) if row else (0, EMPTY_ROOT)
                status, reason = self._check(old, proof, checkpoint, stored_size, stored_root)
                if status != 200:
                    db.execute('INSERT INTO evidence (origin, status, reason, request) VALUES (?,?,?,?)',
                               (checkpoint.origin, status, reason, body))
                    db.execute('COMMIT')
                    return status, ('%d\n' % stored_size) if status == 409 else reason + '\n'
                db.execute('INSERT INTO latest VALUES (?,?,?,?) ON CONFLICT(origin) DO UPDATE SET '
                           'size=excluded.size, root=excluded.root, note=excluded.note',
                           (checkpoint.origin, checkpoint.size, checkpoint.root, note_bytes))
                db.execute('COMMIT')  # persisted before the cosignature leaves the witness
            except BaseException:
                if db.in_transaction:
                    db.execute('ROLLBACK')
                raise
        return 200, self.signer.signature_line(note.text, self.clock())

    @staticmethod
    def _check(old, proof, checkpoint, stored_size, stored_root) -> Tuple[int, str]:
        if old != stored_size:
            return 409, 'old size %d differs from latest cosigned size %d' % (old, stored_size)
        if checkpoint.size == 0 and checkpoint.root != EMPTY_ROOT:
            return 422, 'size zero needs the empty-tree root'
        if old == 0:
            return (422, 'proof must be empty for old size 0') if proof else (200, '')
        if old == checkpoint.size:
            if proof or checkpoint.root != stored_root:
                return 422, 'same size, different root (or non-empty proof)'
            return 200, ''
        if not merkle_log.verify_consistency(old, checkpoint.size, stored_root, checkpoint.root, proof):
            return 422, 'consistency proof does not verify'
        return 200, ''


def parse_request(body: bytes):
    text = body.decode('utf-8')
    head, sep, rest = text.partition('\n\n')
    if not sep:
        raise ValueError('missing empty line before the checkpoint')
    lines = head.split('\n')
    if not lines[0].startswith('old '):
        raise ValueError('first line must be "old <size>"')
    old = n.parse_decimal(lines[0][4:])
    proof_lines = lines[1:]
    if len(proof_lines) > MAX_PROOF_LINES:
        raise ValueError('more than 63 proof lines')
    proof = [n.b64decode_canonical(p) for p in proof_lines]
    if any(len(p) != 32 for p in proof):
        raise ValueError('proof hashes must be 32 bytes')
    return old, proof, rest.encode('utf-8')


def build_request(old: int, proof: List[bytes], note_bytes: bytes) -> bytes:
    lines = ['old %d' % old] + [n.b64encode(p) for p in proof]
    return ('\n'.join(lines) + '\n\n').encode('utf-8') + note_bytes
