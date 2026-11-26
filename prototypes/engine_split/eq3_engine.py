"""ADR-003 candidate (prototype, NOT a research version): storage engine without public mutators.

Derived from research/state_store.py (v0.7.13 DELETE/EXTRA policy, unchanged in v0.7.22). The
on-disk format, the proposal format and the HMAC receipt chain are the same, so a database
created by the research StateStore (journal_mode='DELETE') opens here and vice versa; the tests
check this in both directions.

What changed against StateStore (ADR-003 decision items 1 and 2):
- No public mutator. StateStore.create moved to eq3_provision (not part of the writer
  distribution); StateStore.checkpoint (WAL only) and backup_verified are not carried over;
  StateStore.apply became the private _commit, reachable only through CommitCapability.
- CommitCapability.commit() writes exactly the proposal that the anchor has PREPARED: the
  anchor's pending intent must name this proposal's hash, request id, store id and base, and
  the committed digest must equal the intent's digest. In v0.7.22 StateStore.apply() writes
  any validly signed proposal whether or not an anchor intent exists (the legacy bypass).
- The master key is not a public attribute (StateStore.key is). Proposal signing and
  authenticated decoding are engine methods, so callers never handle the key.
- DELETE journal only (the anchored writer of v0.7.15 already refused WAL), schema v2 only
  (v0.7.15 already refused unauthenticated v1 history).

What this does NOT change: Python cannot stop code in the same process from reaching a private
attribute. Possession of the capability object is a discipline that the static import-closure
check supports (it fails on introspection and dynamic imports); the boundary stays the OS
(separate writer UID, ADR-003 item 3). Release decision: NO-GO.
"""
from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import struct
from urllib.parse import quote

import equal3
from eq3_anchor_types import AnchorHold

MAX_STORED_STATE = 8 * 1024 * 1024
MAX_PACKET = (MAX_STORED_STATE + ((MAX_STORED_STATE + equal3.MIN_CHUNK - 1) // equal3.MIN_CHUNK)
              * equal3.RECORD.size + equal3.HEADER.size + 32)
MAGIC = b'EQ6\x01'
PROPOSAL_HDR = struct.Struct('>4s16sQ16sQ32s')
MAC_SIZE = 32
PROPOSAL_DOMAIN = b'EQ3-PROPOSAL-V06\x00'
DERIVE_DOMAIN = b'EQ3-PROPOSAL-KEY-V06\x00'
KEY_CHECK_DOMAIN = b'EQ3-STORE-KEY-CHECK-V06\x00'
CHAIN_DOMAIN = b'EQ3-RECEIPT-CHAIN-V074\x00'
JOURNAL_MODE = 'DELETE'


class StoreError(ValueError): pass
class AuthenticationError(StoreError): pass
class ConflictError(StoreError): pass
class ReplayError(StoreError): pass
class IntegrityError(StoreError): pass


class CommitOutcomeUnknown(OSError):
    """Call receipt(request_id) after reconnect; never blindly reissue as new request."""


@dataclass(frozen=True)
class Snapshot:
    version: int
    value: bytes
    digest: bytes


@dataclass(frozen=True)
class Receipt:
    request_id: bytes
    base_version: int
    version: int
    digest: bytes
    already_committed: bool = False


@dataclass(frozen=True)
class ProposalFacts:
    """What an authenticated proposal does to the snapshot it was checked against."""
    store_id: str
    base_version: int
    base_digest: str
    request_id: str
    target_digest: str
    proposal_hash: str


def check_key(key):
    if not isinstance(key, bytes) or len(key) < 32:
        raise StoreError('requires a secret master key of at least 32 bytes')
    return key


def _proposal_key(master):
    return hmac.new(check_key(master), DERIVE_DOMAIN, hashlib.sha256).digest()


def digest(blob):
    return hashlib.sha256(blob).digest()


def key_check(key, store_id):
    return hmac.new(check_key(key), KEY_CHECK_DOMAIN + store_id, hashlib.sha256).digest()


def chain_key(master, store_id):
    return hmac.new(check_key(master), CHAIN_DOMAIN + store_id, hashlib.sha256).digest()


def chain_genesis(key, store_id, initial_digest):
    return hmac.new(chain_key(key, store_id), b'GENESIS\x00' + initial_digest, hashlib.sha256).digest()


def chain_next(key, store_id, prior, request_id, proposal_hash, base_version, committed_version, dig):
    body = (b'RECEIPT\x00' + prior + request_id + proposal_hash +
            struct.pack('>QQ', base_version, committed_version) + dig)
    return hmac.new(chain_key(key, store_id), body, hashlib.sha256).digest()


def _make_proposal(store_id: bytes, base_version: int, request_id: bytes, packet: bytes, *, key: bytes) -> bytes:
    if not isinstance(store_id, bytes) or len(store_id) != 16:
        raise StoreError('store_id must be 16 bytes')
    if not isinstance(request_id, bytes) or len(request_id) != 16:
        raise StoreError('request_id must be 16 bytes')
    if not isinstance(base_version, int) or not 0 <= base_version < 2**63-1:
        raise StoreError('base version out of range')
    if not isinstance(packet, bytes) or len(packet) > MAX_PACKET or len(packet) < equal3.HEADER.size + 32:
        raise StoreError('packet length out of range')
    hdr = PROPOSAL_HDR.pack(MAGIC, store_id, base_version, request_id, len(packet), digest(packet))
    body = hdr + packet
    return body + hmac.new(_proposal_key(key), PROPOSAL_DOMAIN + body, hashlib.sha256).digest()


def _parse_proposal(blob: bytes, *, key: bytes):
    if (not isinstance(blob, bytes) or len(blob) < PROPOSAL_HDR.size + MAC_SIZE
            or len(blob) > MAX_PACKET + PROPOSAL_HDR.size + MAC_SIZE):
        raise StoreError('proposal size out of bounds')
    try:
        magic, sid, expected, rid, size, fingerprint = PROPOSAL_HDR.unpack(blob[:PROPOSAL_HDR.size])
    except struct.error as exc:
        raise StoreError('invalid proposal header') from exc
    if magic != MAGIC or expected >= 2**63-1 or size < equal3.HEADER.size+32 or size > MAX_PACKET:
        raise StoreError('invalid proposal fields')
    if len(blob) != PROPOSAL_HDR.size + size + MAC_SIZE:
        raise StoreError('proposal framing mismatch')
    tag = blob[-MAC_SIZE:]
    expected_tag = hmac.new(_proposal_key(key), PROPOSAL_DOMAIN + blob[:-MAC_SIZE], hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected_tag):
        raise AuthenticationError('proposal HMAC mismatch')
    packet = blob[PROPOSAL_HDR.size:-MAC_SIZE]
    if not hmac.compare_digest(digest(packet), fingerprint):
        raise IntegrityError('embedded packet hash mismatch')
    try:
        inner_magic, inner_flags, inner_reserved, inner_base_len, inner_target_len, *_ = \
            equal3.HEADER.unpack(packet[:equal3.HEADER.size])
    except struct.error as exc:
        raise StoreError('invalid embedded packet header') from exc
    if (inner_magic != equal3.MAGIC or inner_flags != equal3.FLAG_AUTH or inner_reserved
            or inner_base_len > MAX_STORED_STATE or inner_target_len > MAX_STORED_STATE):
        raise StoreError('embedded packet invalid or exceeds local store limits')
    return sid, expected, rid, fingerprint, packet


def rollback_file_preflight(path):
    """Reject a WAL-mode database before an SQLite connection might recover it."""
    p = Path(path).absolute()
    if p.is_symlink():
        raise StoreError('rollback store must not be a symlink')
    for suffix in ('-wal', '-shm'):
        if Path(str(p) + suffix).exists() or Path(str(p) + suffix).is_symlink():
            raise StoreError('WAL sidecar present; explicit offline migration required')
    if not hasattr(os, 'O_NOFOLLOW'):
        raise StoreError('rollback preflight requires O_NOFOLLOW')
    fd = os.open(p, os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0) | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size < 100:
            raise StoreError('invalid rollback database file')
        hdr = os.read(fd, 100)
        if hdr[:16] != b'SQLite format 3\x00' or hdr[18:20] != b'\x01\x01':
            raise StoreError('not a DELETE-journal database; explicit migration required')
    finally:
        os.close(fd)


def connect(path: Path, *, create=False):
    mode = 'rwc' if create else 'rw'
    uri = 'file:' + quote(path.resolve().as_posix(), safe='/') + '?mode=' + mode
    db = sqlite3.connect(uri, uri=True, isolation_level=None, timeout=10)
    db.execute('PRAGMA busy_timeout=10000')
    db.execute('PRAGMA trusted_schema=OFF')
    db.execute('PRAGMA cell_size_check=ON')
    db.execute('PRAGMA mmap_size=0')
    db.execute('PRAGMA journal_size_limit=16777216')
    db.execute('PRAGMA synchronous=FULL')
    return db


class StateEngine:
    """Read and verify side of the store. It has no public method that writes the database."""

    journal_mode = JOURNAL_MODE

    def __init__(self, path, *, key):
        self.path = Path(path).absolute()
        self._key = check_key(key)
        if not self.path.is_file():
            raise StoreError('store not found; provisioning is a separate, explicit step')
        rollback_file_preflight(self.path)
        with closing(self._db()) as db:
            self._verify_schema(db)
            sid, check = db.execute('SELECT store_id,key_check FROM meta WHERE id=1').fetchone()
            if not hmac.compare_digest(key_check(self._key, sid), check):
                raise AuthenticationError('incorrect store key')

    def _db(self):
        rollback_file_preflight(self.path)
        db = connect(self.path)
        try:
            db.execute('PRAGMA foreign_keys=ON')
            mode = db.execute('PRAGMA journal_mode').fetchone()[0]
            if mode.upper() != JOURNAL_MODE:
                raise StoreError('journal policy drift; explicit migration required')
            db.execute('PRAGMA synchronous=EXTRA')
            if db.execute('PRAGMA synchronous').fetchone()[0] != 3:
                raise StoreError('required synchronous durability unavailable')
            return db
        except BaseException:
            db.close()
            raise

    @staticmethod
    def _verify_schema(db):
        """Schema-shape preflight; intentionally not a hostile-SQLite sandbox. Schema v2 only."""
        try:
            row = db.execute('SELECT schema_version, store_id, key_check FROM meta WHERE id=1').fetchone()
            head = db.execute('SELECT version, length(value), digest FROM head WHERE id=1').fetchone()
        except sqlite3.DatabaseError as exc:
            raise IntegrityError('invalid store schema') from exc
        if (row is None or len(row) != 3 or type(row[0]) is not int or row[0] != 2
                or not isinstance(row[1], bytes) or len(row[1]) != 16
                or not isinstance(row[2], bytes) or len(row[2]) != 32
                or head is None or len(head) != 3
                or type(head[0]) is not int or not 0 <= head[0] < 2**63-1
                or type(head[1]) is not int or not 0 <= head[1] <= MAX_STORED_STATE
                or not isinstance(head[2], bytes) or len(head[2]) != 32):
            raise IntegrityError('unsupported, legacy (v1) or malformed store')
        try:
            initial_digest = db.execute('SELECT genesis_digest FROM meta WHERE id=1').fetchone()[0]
            auth = db.execute('SELECT tag FROM receipt_auth WHERE committed_version=0').fetchone()
        except sqlite3.DatabaseError as exc:
            raise IntegrityError('v2 receipt chain schema missing') from exc
        if (not isinstance(initial_digest, bytes) or len(initial_digest) != 32 or not auth
                or not isinstance(auth[0], bytes) or len(auth[0]) != 32):
            raise IntegrityError('v2 receipt chain genesis missing or invalid')

    @property
    def store_id(self):
        with closing(self._db()) as db:
            return db.execute('SELECT store_id FROM meta WHERE id=1').fetchone()[0]

    def _verified_snapshot(self, *, request_id=None):
        """Audit the whole keyed history and return head and receipt from one read transaction."""
        if request_id is not None and (not isinstance(request_id, bytes) or len(request_id) != 16):
            raise StoreError('request id must be 16 bytes')
        with closing(self._db()) as db:
            db.execute('BEGIN')
            try:
                self._verify_schema(db)
                _, sid, key_tag = db.execute('SELECT schema_version,store_id,key_check FROM meta WHERE id=1').fetchone()
                if not hmac.compare_digest(key_check(self._key, sid), key_tag):
                    raise AuthenticationError('store key binding changed')
                if db.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
                    raise IntegrityError('SQLite integrity_check failed')
                if db.execute('PRAGMA foreign_key_check').fetchone() is not None:
                    raise IntegrityError('SQLite foreign key violation')
                version, value, head_digest = db.execute('SELECT version,value,digest FROM head WHERE id=1').fetchone()
                if not isinstance(value, bytes) or not hmac.compare_digest(digest(value), head_digest):
                    raise IntegrityError('head content hash mismatch')
                genesis = db.execute('SELECT genesis_digest FROM meta WHERE id=1').fetchone()[0]
                prior = chain_genesis(self._key, sid, genesis)
                row = db.execute('SELECT tag FROM receipt_auth WHERE committed_version=0').fetchone()
                if not row or not isinstance(row[0], bytes) or not hmac.compare_digest(row[0], prior):
                    raise IntegrityError('genesis authentication failed')
                rows = db.execute('SELECT request_id,proposal_hash,base_version,committed_version,digest '
                                  'FROM receipts ORDER BY committed_version')
                count = 0
                last_digest = None
                for seq, (rid, prop_hash, base, committed, rec_digest) in enumerate(rows, 1):
                    count = seq
                    last_digest = rec_digest
                    if (not isinstance(rid, bytes) or len(rid) != 16 or
                            not isinstance(prop_hash, bytes) or len(prop_hash) != 32 or
                            type(base) is not int or base != seq-1 or
                            type(committed) is not int or committed != seq or
                            not isinstance(rec_digest, bytes) or len(rec_digest) != 32):
                        raise IntegrityError('malformed historic receipt')
                    expected_tag = chain_next(self._key, sid, prior, rid, prop_hash, base, committed, rec_digest)
                    tag = db.execute('SELECT tag FROM receipt_auth WHERE committed_version=?', (seq,)).fetchone()
                    if not tag or not isinstance(tag[0], bytes) or not hmac.compare_digest(tag[0], expected_tag):
                        raise IntegrityError('receipt chain mismatch')
                    prior = expected_tag
                if count != version:
                    raise IntegrityError('receipt/version length differs')
                if version and not hmac.compare_digest(last_digest, head_digest):
                    raise IntegrityError('last receipt digest mismatch')
                if version == 0 and not hmac.compare_digest(genesis, head_digest):
                    raise IntegrityError('head does not match authenticated genesis')
                if db.execute('SELECT COUNT(*) FROM receipt_auth').fetchone()[0] != version + 1:
                    raise IntegrityError('receipt chain has extra or missing entries')
                report = {'store_id': sid.hex(), 'version': version, 'receipt_count': count,
                          'digest_sha256': head_digest.hex(), 'sqlite_integrity': 'ok',
                          'receipt_auth': 'HMAC_CHAIN_V2'}
                if request_id is not None:
                    rr = db.execute('SELECT proposal_hash,base_version,committed_version,digest '
                                    'FROM receipts WHERE request_id=?', (request_id,)).fetchone()
                    report['request'] = (None if rr is None else {
                        'request_id': request_id.hex(), 'proposal_hash': rr[0].hex(),
                        'base_version': rr[1], 'version': rr[2], 'digest_sha256': rr[3].hex()})
                return report, Snapshot(version, value, head_digest)
            finally:
                db.execute('ROLLBACK')

    def verify(self):
        return self._verified_snapshot()[0]

    def read_verified(self):
        return self._verified_snapshot()

    def inspect_request(self, request_id: bytes):
        return self._verified_snapshot(request_id=request_id)

    def read(self):
        return self.read_verified()[1]

    def receipt(self, request_id: bytes):
        if not isinstance(request_id, bytes) or len(request_id) != 16:
            raise StoreError('request id must be 16 bytes')
        entry = self.inspect_request(request_id)[0]['request']
        return (Receipt(request_id, entry['base_version'], entry['version'],
                        bytes.fromhex(entry['digest_sha256']), True)
                if entry is not None else None)

    def prepare_update(self, target: bytes, *, request_id=None, strategy='adaptive'):
        """Sign a proposal from the verified head to target. Reads only; nothing is written."""
        info, snap = self.read_verified()
        if not isinstance(target, bytes) or len(target) > MAX_STORED_STATE:
            raise StoreError('target exceeds state size limit')
        rid = secrets.token_bytes(16) if request_id is None else request_id
        packet = equal3.encode_bytes(snap.value, target, key=self._key, strategy=strategy)
        return _make_proposal(bytes.fromhex(info['store_id']), snap.version, rid, packet, key=self._key), rid

    def describe_proposal(self, proposal: bytes) -> ProposalFacts:
        """Authenticate a proposal and decode it against the verified head. Reads only."""
        sid, base, rid, _, packet = _parse_proposal(proposal, key=self._key)
        info, snap = self.read_verified()
        if sid.hex() != info['store_id'] or base != snap.version:
            raise AnchorHold('stale/wrong-store proposal')
        target = equal3.decode_bytes(snap.value, packet, key=self._key, require_auth=True)
        if len(target) > MAX_STORED_STATE:
            raise StoreError('decoded target exceeds state limit')
        return ProposalFacts(info['store_id'], base, snap.digest.hex(), rid.hex(),
                             digest(target).hex(), digest(proposal).hex())

    def _authenticated_replay(self, request_id: bytes, proposal_hash: bytes) -> Receipt:
        info, _ = self.inspect_request(request_id)
        r = info['request']
        if r is None:
            raise IntegrityError('duplicate receipt disappeared during verification')
        if not hmac.compare_digest(bytes.fromhex(r['proposal_hash']), proposal_hash):
            raise ReplayError('request ID reused with different proposal')
        return Receipt(request_id, r['base_version'], r['version'], bytes.fromhex(r['digest_sha256']), True)

    def _commit(self, proposal: bytes, *, guard=None, expect=None, fault=None):
        """The CAS write primitive of StateStore.apply (v0.7.22), unchanged in substance.

        Private: the only caller is CommitCapability.commit after its anchor-intent check.
        guard() runs inside the write transaction (after BEGIN IMMEDIATE, before any change)
        and raises to refuse the write; the capability uses it to re-read the anchor.
        expect (an anchor intent) is compared inside the same transaction with the base the
        CAS holds and the target digest it is about to write.
        """
        sid, expected_version, rid, _, packet = _parse_proposal(proposal, key=self._key)
        proposal_hash = digest(proposal)
        if sid != self.store_id:
            raise AuthenticationError('proposal bound to another store')
        db = self._db()
        started = False
        attempted_commit = False
        try:
            if db.execute('SELECT 1 FROM receipts WHERE request_id=?', (rid,)).fetchone():
                return self._authenticated_replay(rid, proposal_hash)
            head = db.execute('SELECT version,value,digest FROM head WHERE id=1').fetchone()
            if head is None:
                raise IntegrityError('head missing')
            version, current, head_digest = head
            if version != expected_version:
                raise ConflictError(f'stale version {expected_version}; actual {version}')
            if version >= 2**63-2:
                raise StoreError('version exhausted')
            if len(current) > MAX_STORED_STATE or not hmac.compare_digest(digest(current), head_digest):
                raise IntegrityError('head corruption')
            target = equal3.decode_bytes(current, packet, key=self._key, require_auth=True)
            if len(target) > MAX_STORED_STATE:
                raise StoreError('decoded target exceeds state limit')
            target_digest = digest(target)
            if fault: fault('after_preflight')
            db.execute('BEGIN IMMEDIATE')
            started = True
            if guard is not None:
                guard()
            if db.execute('SELECT 1 FROM receipts WHERE request_id=?', (rid,)).fetchone():
                db.execute('ROLLBACK'); started = False
                return self._authenticated_replay(rid, proposal_hash)
            actual = db.execute('SELECT version,digest FROM head WHERE id=1').fetchone()
            if actual is None or actual[0] != version or not hmac.compare_digest(actual[1], head_digest):
                raise ConflictError('state advanced or changed after preflight')
            if expect is not None and (expect.base_version != version or expect.version != version + 1
                                       or expect.base_digest != head_digest.hex()
                                       or expect.digest != target_digest.hex()):
                raise AnchorHold('proposal is not the prepared anchor intent; commit refused')
            schema_row = db.execute('SELECT schema_version,genesis_digest,store_id,key_check FROM meta WHERE id=1').fetchone()
            if schema_row is None or schema_row[0] != 2:
                raise IntegrityError('unsealed schema cannot authorize write')
            _, genesis_digest, chain_sid, chain_key_tag = schema_row
            if not hmac.compare_digest(key_check(self._key, chain_sid), chain_key_tag):
                raise AuthenticationError('store key binding changed')
            genesis_tag = chain_genesis(self._key, chain_sid, genesis_digest)
            tag0 = db.execute('SELECT tag FROM receipt_auth WHERE committed_version=0').fetchone()
            if not tag0 or not isinstance(tag0[0], bytes) or not hmac.compare_digest(tag0[0], genesis_tag):
                raise IntegrityError('genesis authentication failed before write')
            if version == 0:
                if not hmac.compare_digest(head_digest, genesis_digest):
                    raise IntegrityError('head does not match authenticated genesis before write')
            else:
                tail = db.execute('SELECT digest FROM receipts WHERE committed_version=?', (version,)).fetchone()
                if not tail or not isinstance(tail[0], bytes) or not hmac.compare_digest(tail[0], head_digest):
                    raise IntegrityError('head differs from last receipt before write')
                prior_tag = db.execute('SELECT tag FROM receipt_auth WHERE committed_version=?', (version-1,)).fetchone()
                prior_receipt = db.execute('SELECT request_id,proposal_hash,base_version,committed_version,digest '
                                           'FROM receipts WHERE committed_version=?', (version,)).fetchone()
                terminal_tag = db.execute('SELECT tag FROM receipt_auth WHERE committed_version=?', (version,)).fetchone()
                if not prior_tag or not prior_receipt or not terminal_tag:
                    raise IntegrityError('receipt chain tail missing')
                if not hmac.compare_digest(terminal_tag[0], chain_next(self._key, chain_sid, prior_tag[0], *prior_receipt)):
                    raise IntegrityError('receipt chain tail modified')
            updated = db.execute('UPDATE head SET version=?,value=?,digest=? WHERE id=1 AND version=? AND digest=?',
                                 (version+1, target, target_digest, version, head_digest))
            if updated.rowcount != 1:
                raise ConflictError('compare-and-swap failed')
            db.execute('INSERT INTO receipts VALUES (?,?,?,?,?)', (rid, proposal_hash, version, version+1, target_digest))
            prior_row = db.execute('SELECT tag FROM receipt_auth WHERE committed_version=?', (version,)).fetchone()
            if not prior_row or not isinstance(prior_row[0], bytes) or len(prior_row[0]) != 32:
                raise IntegrityError('missing receipt predecessor authentication')
            tag = chain_next(self._key, chain_sid, prior_row[0], rid, proposal_hash, version, version+1, target_digest)
            db.execute('INSERT INTO receipt_auth VALUES (?,?)', (version+1, tag))
            if fault: fault('before_commit')
            attempted_commit = True
            db.execute('COMMIT')
            started = False
            if fault: fault('after_commit')
            return Receipt(rid, version, version+1, target_digest, False)
        except BaseException as exc:
            if started and db.in_transaction:
                try:
                    db.execute('ROLLBACK')
                except sqlite3.Error:
                    pass
            if attempted_commit and not isinstance(exc, CommitOutcomeUnknown):
                raise CommitOutcomeUnknown('commit may have occurred; look up request receipt before retrying') from exc
            raise
        finally:
            db.close()


class CommitCapability:
    """The only route to the engine's write primitive (ADR-003 item 2).

    It commits a proposal only while the bound anchor holds a PREPARED intent for exactly that
    proposal, and it checks that the committed digest is the one the anchor recorded.
    Construct it with bind_writer(); the composition root hands it to the coordinator only.
    """
    __slots__ = ('_engine', '_anchor')

    def __init__(self, engine: StateEngine, anchor):
        if type(engine) is not StateEngine:
            raise StoreError('capability requires a StateEngine')
        self._engine = engine
        self._anchor = anchor

    def bound_to(self, engine, anchor) -> bool:
        return self._engine is engine and self._anchor is anchor

    def commit(self, proposal: bytes, *, fault=None) -> Receipt:
        status = self._anchor.status()
        pending = status.pending
        if pending is None:
            raise AnchorHold('no prepared anchor intent; commit refused')
        committed = status.committed
        if (pending.store_id != committed.store_id or pending.base_version != committed.version
                or pending.base_digest != committed.digest):
            raise AnchorHold('prepared intent is not based on the anchor position; commit refused')
        # Header fields are authenticated by the proposal HMAC; base digest and target digest are
        # compared inside the write transaction (_commit, expect=), on the values it writes.
        sid, base, rid, _, _ = _parse_proposal(proposal, key=self._engine._key)
        if (pending.proposal_hash != digest(proposal).hex() or pending.request_id != rid.hex()
                or pending.store_id != sid.hex() or pending.base_version != base
                or pending.version != base + 1):
            raise AnchorHold('proposal is not the prepared anchor intent; commit refused')

        def still_prepared():
            # Re-read inside the write transaction: an ABORT or another transition that landed
            # after the first check must stop the write. A remote anchor needs a lease or fence
            # on the pending intent for this re-read to mean the same (roadmap P0-3).
            now = self._anchor.status()
            if now.pending != pending or now.committed != committed:
                raise AnchorHold('anchor intent changed before the write; commit refused')
        receipt = self._engine._commit(proposal, guard=still_prepared, expect=pending, fault=fault)
        if receipt.already_committed or receipt.digest.hex() != pending.digest or receipt.version != pending.version:
            raise AnchorHold('committed result differs from the prepared anchor intent')
        return receipt


def bind_writer(path, *, key, anchor):
    """Open the engine for the writer and mint its commit capability, bound to anchor."""
    engine = StateEngine(path, key=key)
    return engine, CommitCapability(engine, anchor)
