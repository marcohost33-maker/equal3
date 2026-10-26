"""=== Equal3 v0.7: SQLite-backed local transactional state store.

Research reference, NOT independently security-audited. Single host, trusted filesystem.
Signed proposals bind a v0.5 authenticated patch, request ID, store ID, and base version.
"""
from __future__ import annotations
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import sqlite3
import tempfile
import struct
from urllib.parse import quote
from dataclasses import dataclass
from contextlib import closing
import equal3

MAX_STORED_STATE = 8 * 1024 * 1024  # memory-based reference store, explicit constraint
MAX_PACKET = MAX_STORED_STATE + ((MAX_STORED_STATE + equal3.MIN_CHUNK - 1)//equal3.MIN_CHUNK)*equal3.RECORD.size + equal3.HEADER.size + 32
MAGIC = b'EQ6\x01'
PROPOSAL_HDR = struct.Struct('>4s16sQ16sQ32s')
MAC_SIZE = 32
PROPOSAL_DOMAIN = b'EQ3-PROPOSAL-V06\x00'
DERIVE_DOMAIN = b'EQ3-PROPOSAL-KEY-V06\x00'
KEY_CHECK_DOMAIN = b'EQ3-STORE-KEY-CHECK-V06\x00'
CHAIN_DOMAIN = b'EQ3-RECEIPT-CHAIN-V074\x00'

# DELETE/EXTRA is a narrow WAL-reset mitigation, not an independently approved runtime.
VALID_JOURNAL_MODES = frozenset(('WAL', 'DELETE'))

def _journal_policy(mode):
    if type(mode) is not str or mode not in VALID_JOURNAL_MODES:
        raise StoreError('journal policy must be WAL or DELETE')
    return mode

def _rollback_file_preflight(path):
    """Reject WAL-mode database before an SQLite connection might recover it.

    Conservative fail-closed check on a trusted owner-controlled directory.
    For hostile same-UID filesystem access use OS-isolated writer instead.
    """
    p = Path(path).absolute()
    if p.is_symlink():
        raise StoreError('rollback store must not be a symlink')
    for suffix in ('-wal', '-shm'):
        if Path(str(p) + suffix).exists() or Path(str(p) + suffix).is_symlink():
            raise StoreError('WAL sidecar present; explicit offline migration required')
    flags = os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0)
    if not hasattr(os, 'O_NOFOLLOW'):
        raise StoreError('rollback preflight requires O_NOFOLLOW')
    fd = os.open(p, flags | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        import stat
        if not stat.S_ISREG(st.st_mode) or st.st_size < 100:
            raise StoreError('invalid rollback database file')
        hdr = os.read(fd, 100)
        if (hdr[:16] != b'SQLite format 3\x00' or hdr[18:20] != b'\x01\x01'):
            raise StoreError('not a DELETE-journal database; explicit migration required')
    finally:
        os.close(fd)


class StoreError(ValueError): pass
class AuthenticationError(StoreError): pass
class ConflictError(StoreError): pass
class ReplayError(StoreError): pass
class IntegrityError(StoreError): pass
class BackupOutcomeUnknown(OSError):
    """The backup rename happened; destination durability may be unknown."""

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


def _check_key(key):
    if not isinstance(key, bytes) or len(key) < 32:
        raise StoreError('requires a secret master key of at least 32 bytes')
    return key


def _proposal_key(master):
    return hmac.new(_check_key(master), DERIVE_DOMAIN, hashlib.sha256).digest()


def _digest(blob):
    return hashlib.sha256(blob).digest()


def _key_check(key, store_id):
    return hmac.new(_check_key(key), KEY_CHECK_DOMAIN + store_id, hashlib.sha256).digest()


def make_proposal(store_id: bytes, base_version: int, request_id: bytes,
                  packet: bytes, *, key: bytes) -> bytes:
    """Caller must also sign the embedded Equal3 v0.5 packet with key."""
    if not isinstance(store_id, bytes) or len(store_id) != 16:
        raise StoreError('store_id must be 16 bytes')
    if not isinstance(request_id, bytes) or len(request_id) != 16:
        raise StoreError('request_id must be 16 bytes')
    if not isinstance(base_version, int) or not 0 <= base_version < 2**63-1:
        raise StoreError('base version out of range')
    if not isinstance(packet, bytes) or len(packet) > MAX_PACKET or len(packet) < equal3.HEADER.size + 32:
        raise StoreError('packet length out of range')
    hdr = PROPOSAL_HDR.pack(MAGIC, store_id, base_version, request_id, len(packet), _digest(packet))
    body = hdr + packet
    tag = hmac.new(_proposal_key(key), PROPOSAL_DOMAIN + body, hashlib.sha256).digest()
    return body + tag


def _parse_proposal(blob: bytes, *, key: bytes):
    # Keep header parsing and HMAC validation before any codec decompression.
    if not isinstance(blob, bytes) or len(blob) < PROPOSAL_HDR.size + MAC_SIZE or len(blob) > MAX_PACKET + PROPOSAL_HDR.size + MAC_SIZE:
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
    if not hmac.compare_digest(_digest(packet), fingerprint):
        raise IntegrityError('embedded packet hash mismatch')
    # Reject oversized claimed output BEFORE invoking decompression.
    try:
        inner_magic, inner_flags, inner_reserved, inner_base_len, inner_target_len, *_ = equal3.HEADER.unpack(packet[:equal3.HEADER.size])
    except struct.error as exc:
        raise StoreError('invalid embedded packet header') from exc
    if (inner_magic != equal3.MAGIC or inner_flags != equal3.FLAG_AUTH or inner_reserved
            or inner_base_len > MAX_STORED_STATE or inner_target_len > MAX_STORED_STATE):
        raise StoreError('embedded packet invalid or exceeds local store limits')
    return sid, expected, rid, fingerprint, packet


def _connect(path: Path, *, create=False):
    # SQLite URI mode=rw makes missing database an error rather than silently reinitializing.
    mode = 'rwc' if create else 'rw'
    uri = 'file:' + quote(path.resolve().as_posix(), safe='/') + '?mode=' + mode
    db = sqlite3.connect(uri, uri=True, isolation_level=None, timeout=10)
    db.execute('PRAGMA busy_timeout=10000')
    # Defense-in-depth, not a hostile-database sandbox.
    db.execute('PRAGMA trusted_schema=OFF')
    db.execute('PRAGMA cell_size_check=ON')
    db.execute('PRAGMA mmap_size=0')
    db.execute('PRAGMA journal_size_limit=16777216')
    db.execute('PRAGMA synchronous=FULL')
    return db


def _chain_key(master, store_id):
    return hmac.new(_check_key(master), CHAIN_DOMAIN + store_id, hashlib.sha256).digest()


def _chain_genesis(key, store_id, initial_digest):
    return hmac.new(_chain_key(key, store_id), b'GENESIS\x00' + initial_digest, hashlib.sha256).digest()


def _chain_next(key, store_id, prior, request_id, proposal_hash, base_version, committed_version, digest):
    body = (b'RECEIPT\x00' + prior + request_id + proposal_hash +
            struct.pack('>QQ', base_version, committed_version) + digest)
    return hmac.new(_chain_key(key, store_id), body, hashlib.sha256).digest()


class StateStore:
    """Trusted local paths, SQLite WAL+FULL, single-current-state, monotonic version.
    The database is the transaction boundary; no external blob files or torn manifest.
    """
    def __init__(self, path, *, key, journal_mode='WAL'):
        self.journal_mode = _journal_policy(journal_mode)
        self.path = Path(path).absolute()
        self.key = _check_key(key)
        if not self.path.is_file():
            raise StoreError('store not found; explicit create required')
        if self.journal_mode == 'DELETE':
            _rollback_file_preflight(self.path)
        with closing(self._db()) as db:
            self._verify_schema(db)
            sid,check = db.execute('SELECT store_id,key_check FROM meta WHERE id=1').fetchone()
            if not hmac.compare_digest(_key_check(self.key,sid),check):
                raise AuthenticationError('incorrect store key')

    @classmethod
    def create(cls, path, *, key, initial: bytes, journal_mode='WAL'):
        p = Path(path).absolute()
        _check_key(key)
        journal_mode = _journal_policy(journal_mode)
        if not isinstance(initial, bytes) or len(initial) > MAX_STORED_STATE:
            raise StoreError('initial state outside 8 MiB limit')
        if p.exists():
            raise StoreError('refusing to overwrite existing path')
        # Exclusive creation prevents accidental recreation of a missing store via open().
        fd = os.open(p, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        try:
            with closing(_connect(p, create=True)) as db:
                mode = db.execute('PRAGMA journal_mode=' + journal_mode).fetchone()[0]
                if mode.upper() != journal_mode:
                    raise StoreError('requested journal mode unavailable')
                if journal_mode == 'DELETE':
                    db.execute('PRAGMA synchronous=EXTRA')
                db.execute('PRAGMA foreign_keys=ON')
                db.execute('BEGIN IMMEDIATE')
                db.execute('CREATE TABLE meta (id INTEGER PRIMARY KEY CHECK(id=1), schema_version INTEGER NOT NULL, store_id BLOB NOT NULL, key_check BLOB NOT NULL, genesis_digest BLOB)')
                db.execute('CREATE TABLE head (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL, value BLOB NOT NULL, digest BLOB NOT NULL)')
                db.execute('CREATE TABLE receipts (request_id BLOB PRIMARY KEY, proposal_hash BLOB NOT NULL, base_version INTEGER NOT NULL, committed_version INTEGER NOT NULL UNIQUE, digest BLOB NOT NULL)')
                db.execute('CREATE TABLE receipt_auth (committed_version INTEGER PRIMARY KEY, tag BLOB NOT NULL)')
                sid=secrets.token_bytes(16)
                db.execute('INSERT INTO meta VALUES (1,2,?,?,?)', (sid,_key_check(key,sid),_digest(initial)))
                db.execute('INSERT INTO receipt_auth VALUES (0,?)', (_chain_genesis(key,sid,_digest(initial)),))
                db.execute('INSERT INTO head VALUES (1,0,?,?)', (initial, _digest(initial)))
                db.execute('COMMIT')
        except BaseException:
            # Only for initial creation failure; never remove existing store on later error.
            for suffix in ('', '-wal', '-shm'):
                try: Path(str(p)+suffix).unlink()
                except FileNotFoundError: pass
            raise
        return cls(p, key=key, journal_mode=journal_mode)

    def _db(self):
        if self.journal_mode == 'DELETE':
            _rollback_file_preflight(self.path)
        db = _connect(self.path)
        try:
            db.execute('PRAGMA foreign_keys=ON')
            mode = db.execute('PRAGMA journal_mode').fetchone()[0]
            if mode.upper() != self.journal_mode:
                raise StoreError('journal policy drift; explicit migration required')
            if self.journal_mode == 'DELETE':
                db.execute('PRAGMA synchronous=EXTRA')
            sync = db.execute('PRAGMA synchronous').fetchone()[0]
            if sync != (3 if self.journal_mode == 'DELETE' else 2):
                raise StoreError('required synchronous durability unavailable')
            return db
        except BaseException:
            db.close()
            raise

    @staticmethod
    def _verify_schema(db):
        """Schema-shape preflight; intentionally not a hostile-SQLite sandbox."""
        try:
            row = db.execute('SELECT schema_version, store_id, key_check FROM meta WHERE id=1').fetchone()
            head = db.execute('SELECT version, length(value), digest FROM head WHERE id=1').fetchone()
        except sqlite3.DatabaseError as exc:
            raise IntegrityError('invalid store schema') from exc
        if (row is None or len(row)!=3 or type(row[0]) is not int or row[0] not in (1,2)
            or not isinstance(row[1], bytes) or len(row[1])!=16
            or not isinstance(row[2],bytes) or len(row[2])!=32
            or head is None or len(head)!=3
            or type(head[0]) is not int or not 0<=head[0]<2**63-1
            or type(head[1]) is not int or not 0<=head[1]<=MAX_STORED_STATE
            or not isinstance(head[2],bytes) or len(head[2])!=32):
            raise IntegrityError('unsupported or malformed store')
        if row[0] == 2:
            try:
                initial_digest = db.execute('SELECT genesis_digest FROM meta WHERE id=1').fetchone()[0]
                auth = db.execute('SELECT tag FROM receipt_auth WHERE committed_version=0').fetchone()
            except sqlite3.DatabaseError as exc:
                raise IntegrityError('v2 receipt chain schema missing') from exc
            if not isinstance(initial_digest,bytes) or len(initial_digest)!=32 or not auth or not isinstance(auth[0],bytes) or len(auth[0])!=32:
                raise IntegrityError('v2 receipt chain genesis missing or invalid')

    @property
    def store_id(self):
        with closing(self._db()) as db:
            return db.execute('SELECT store_id FROM meta WHERE id=1').fetchone()[0]

    def read(self):
        """Authenticated coherent snapshot; never trust a bare head SHA-256.

        Full historical HMAC-chain validation is intentionally O(N), pending
        an independently attested checkpoint design. Legacy v1 is not allowed
        to assert the authenticity of a read.
        """
        report, snap = self.read_verified()
        if report['receipt_auth'] != 'HMAC_CHAIN_V2':
            raise IntegrityError('legacy unsealed head cannot authorize a read')
        return snap

    def receipt(self, request_id:bytes):
        if not isinstance(request_id,bytes) or len(request_id)!=16:
            raise StoreError('request id must be 16 bytes')
        # Authenticated historical evidence is required even for read-only
        # receipts: a bare SQLite SELECT must never be treated as a proof of
        # committed state, especially after suspected media/offline tampering.
        report, _ = self.inspect_request(request_id)
        if report['receipt_auth'] != 'HMAC_CHAIN_V2':
            raise IntegrityError('legacy unsealed receipt cannot authorize a result')
        entry = report['request']
        return (Receipt(request_id, entry['base_version'], entry['version'],
                        bytes.fromhex(entry['digest_sha256']), True)
                if entry is not None else None)

    def _verified_snapshot(self, *, request_id=None):
        """Use one pinned WAL read transaction for audit AND returned snapshot.

        Legacy v1 receipts are checked for structure but have no historic keyed
        linkage. V2 chains all receipts to genesis with a secret-derived HMAC;
        a joint rollback of DB and witness remains outside this guarantee.
        """
        if request_id is not None and (not isinstance(request_id, bytes) or len(request_id) != 16):
            raise StoreError('request id must be 16 bytes')
        with closing(self._db()) as db:
            db.execute('BEGIN')
            try:
                self._verify_schema(db)
                schema_version,sid,key_tag = db.execute('SELECT schema_version,store_id,key_check FROM meta WHERE id=1').fetchone()
                if not hmac.compare_digest(_key_check(self.key,sid),key_tag):
                    raise AuthenticationError('store key binding changed')
                if db.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
                    raise IntegrityError('SQLite integrity_check failed')
                if db.execute('PRAGMA foreign_key_check').fetchone() is not None:
                    raise IntegrityError('SQLite foreign key violation')
                version,value,digest=db.execute('SELECT version,value,digest FROM head WHERE id=1').fetchone()
                if not isinstance(value,bytes) or not hmac.compare_digest(_digest(value),digest):
                    raise IntegrityError('head content hash mismatch')
                receipt_rows=db.execute('SELECT request_id,proposal_hash,base_version,committed_version,digest FROM receipts ORDER BY committed_version')
                prior = None
                if schema_version == 2:
                    genesis=db.execute('SELECT genesis_digest FROM meta WHERE id=1').fetchone()[0]
                    prior=_chain_genesis(self.key,sid,genesis)
                    row=db.execute('SELECT tag FROM receipt_auth WHERE committed_version=0').fetchone()
                    if not row or not isinstance(row[0],bytes) or not hmac.compare_digest(row[0],prior):
                        raise IntegrityError('genesis authentication failed')
                count=0
                last_digest=None
                for seq, (rid,prop_hash,base,committed,rec_digest) in enumerate(receipt_rows,1):
                    count=seq
                    last_digest=rec_digest
                    if (not isinstance(rid,bytes) or len(rid)!=16 or
                        not isinstance(prop_hash,bytes) or len(prop_hash)!=32 or
                        type(base) is not int or base!=seq-1 or
                        type(committed) is not int or committed!=seq or
                        not isinstance(rec_digest,bytes) or len(rec_digest)!=32):
                        raise IntegrityError('malformed historic receipt')
                    if schema_version == 2:
                        expected_tag=_chain_next(self.key,sid,prior,rid,prop_hash,base,committed,rec_digest)
                        tag=db.execute('SELECT tag FROM receipt_auth WHERE committed_version=?',(seq,)).fetchone()
                        if not tag or not isinstance(tag[0],bytes) or not hmac.compare_digest(tag[0],expected_tag):
                            raise IntegrityError('receipt chain mismatch')
                        prior=expected_tag
                if count != version:
                    raise IntegrityError('receipt/version length differs')
                if version and not hmac.compare_digest(last_digest,digest):
                    raise IntegrityError('last receipt digest mismatch')
                # At version zero there is no last receipt. The genesis digest
                # is the ONLY authenticated commitment to the original value.
                # A matching SHA-256(value) alone is not authentication.
                if schema_version == 2 and version == 0 and not hmac.compare_digest(genesis, digest):
                    raise IntegrityError('head does not match authenticated genesis')
                if schema_version == 2:
                    auth_count=db.execute('SELECT COUNT(*) FROM receipt_auth').fetchone()[0]
                    if auth_count != version + 1:
                        raise IntegrityError('receipt chain has extra or missing entries')
                report={'store_id':sid.hex(),'version':version,'receipt_count':count,
                        'digest_sha256':digest.hex(),'sqlite_integrity':'ok',
                        'receipt_auth': 'HMAC_CHAIN_V2' if schema_version==2 else 'LEGACY_UNSEALED'}
                if request_id is not None:
                    rr=db.execute('SELECT proposal_hash,base_version,committed_version,digest FROM receipts WHERE request_id=?', (request_id,)).fetchone()
                    report['request'] = (None if rr is None else {
                        'request_id': request_id.hex(), 'proposal_hash': rr[0].hex(),
                        'base_version': rr[1], 'version': rr[2], 'digest_sha256': rr[3].hex()
                    })
                return report, Snapshot(version,value,digest)
            finally:
                db.execute('ROLLBACK')

    def verify(self):
        return self._verified_snapshot()[0]

    def read_verified(self):
        """Return audit and data from exactly the same verified SQLite snapshot."""
        return self._verified_snapshot()

    def inspect_request(self, request_id: bytes):
        """Audit history, request receipt, and head within one SQLite snapshot."""
        return self._verified_snapshot(request_id=request_id)

    def checkpoint(self, *, mode='PASSIVE', busy_timeout_ms=1000):
        """Report SQLite WAL maintenance; checkpoint is not a verification primitive.

        A busy TRUNCATE does not mean corruption. Do not run TRUNCATE under
        continuous readers without explicit maintenance policy.
        """
        if self.journal_mode == 'DELETE':
            raise StoreError('WAL checkpoint unavailable for DELETE-journal store')
        if mode not in ('PASSIVE','FULL','RESTART','TRUNCATE','NOOP'):
            raise StoreError('unsupported checkpoint mode')
        if not isinstance(busy_timeout_ms,int) or not 0<=busy_timeout_ms<=60000:
            raise StoreError('invalid checkpoint timeout')
        with closing(self._db()) as db:
            db.execute(f'PRAGMA busy_timeout={busy_timeout_ms}')
            row=db.execute(f'PRAGMA wal_checkpoint({mode})').fetchone()
            if row is None or len(row)!=3:
                raise IntegrityError('unrecognized WAL checkpoint response')
            busy,log,checkpointed=row
            return {'mode':mode, 'busy':bool(busy), 'log_frames':log,
                    'checkpointed_frames':checkpointed,
                    'complete':busy==0 and (mode!='PASSIVE' or log==checkpointed)}

    def backup_verified(self, destination, *, fault=None):
        """Online snapshot backup, fail-closed verification, atomically publish at POSIX path.

        Not a coordinated anti-rollback solution or continuous backup. Destination is a
        new file on a trusted local directory and is never overwritten. Always keep
        the original Store secret private: the backup contains plaintext state.
        """
        dest = Path(destination).absolute()
        if os.name != 'posix':
            raise StoreError('atomic backup publishing is implemented for POSIX only')
        if dest == self.path:
            raise StoreError('source and destination must differ')
        if dest.exists():
            raise StoreError('destination already exists; refusing overwrite')
        if not dest.parent.is_dir():
            raise StoreError('backup parent is not a directory')
        temp_path = None
        renamed = False
        try:
            # mkstemp ensures target temp is in same filesystem and not attacker-chosen.
            fd, tmp = tempfile.mkstemp(dir=dest.parent,prefix='.eq3-backup-',suffix='.sqlite')
            temp_path = Path(tmp)
            os.close(fd)
            if fault: fault('after_temp')
            # The SQLite online backup API copies one logically consistent DB image.
            with closing(self._db()) as source:
                with closing(sqlite3.connect(str(temp_path), isolation_level=None)) as target:
                    source.backup(target, pages=64, sleep=0.01)
                    if fault: fault('after_sqlite_backup')
                    # Ensure that target's on-disk mode will be accepted by StateStore.
                    mode = target.execute('PRAGMA journal_mode=' + self.journal_mode).fetchone()[0]
                    if mode.upper() != self.journal_mode:
                        raise IntegrityError('backup journal policy not retained')
                    if self.journal_mode == 'DELETE':
                        target.execute('PRAGMA synchronous=EXTRA')
            # Verification uses independent connections after copy/close.
            backed = StateStore(temp_path,key=self.key,journal_mode=self.journal_mode)
            report = backed.verify()
            if fault: fault('after_validation')
            # Do not publish a standalone DB file when associated WAL contents remain.
            # Final close/checkpoint is expected to remove WAL sidecars.
            for suffix in ('-wal','-shm'):
                if Path(str(temp_path)+suffix).exists():
                    raise IntegrityError('backup WAL sidecar unexpectedly remains')
            with open(temp_path,'rb') as stream:
                os.fsync(stream.fileno())
            if fault: fault('before_replace')
            # Hard link atomically publishes without overwriting an existing destination.
            # Source and target live in the same trusted local directory/filesystem.
            os.link(temp_path, dest, follow_symlinks=False)
            renamed = True
            if fault: fault('after_replace')
            os.unlink(temp_path)
            dir_fd = os.open(dest.parent,os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
            if fault: fault('after_dirsync')
            return report
        except BaseException as exc:
            if renamed:
                raise BackupOutcomeUnknown('backup is visible but durable publication is uncertain; inspect the destination') from exc
            raise
        finally:
            if temp_path is not None:
                for suffix in ('','-wal','-shm'):
                    try: Path(str(temp_path)+suffix).unlink()
                    except FileNotFoundError: pass

    def _authenticated_replay(self, request_id: bytes, proposal_hash: bytes) -> Receipt:
        """Only expose a replay after verifying the complete keyed receipt history.

        This intentionally costs O(number-of-receipts); fast unauthenticated
        replies are forbidden. Concurrent writers can advance the head, but
        the authenticated receipt for this request remains immutable under the
        supported append-only transaction model. An independent trust anchor
        remains mandatory to detect a joint historic rollback.
        """
        info, _ = self.inspect_request(request_id)
        if info['receipt_auth'] != 'HMAC_CHAIN_V2':
            raise IntegrityError('legacy unsealed receipt cannot authorize a replay')
        r = info['request']
        if r is None:
            raise IntegrityError('duplicate receipt disappeared during verification')
        if not hmac.compare_digest(bytes.fromhex(r['proposal_hash']), proposal_hash):
            raise ReplayError('request ID reused with different proposal')
        return Receipt(request_id, r['base_version'], r['version'],
                       bytes.fromhex(r['digest_sha256']), True)

    def apply(self, proposal: bytes, *, fault=None):
        """Optimistic authenticated pre-decode, then single SQLite CAS + receipt transaction.

        Fault hook is for deterministic testing only. Caller checks receipt(request_id)
        after an indeterminate commit. External systems are NOT covered by this commit.
        """
        sid, expected_version, rid, packet_hash, packet = _parse_proposal(proposal, key=self.key)
        proposal_hash = _digest(proposal)
        if sid != self.store_id:
            raise AuthenticationError('proposal bound to another store')
        db = self._db()
        started = False
        attempted_commit = False
        try:
            # Fast duplicate reply before expensive decoding. Rechecked after BEGIN.
            old = db.execute('SELECT proposal_hash,base_version,committed_version,digest FROM receipts WHERE request_id=?',(rid,)).fetchone()
            if old:
                return self._authenticated_replay(rid, proposal_hash)
            head = db.execute('SELECT version,value,digest FROM head WHERE id=1').fetchone()
            if head is None:
                raise IntegrityError('head missing')
            version, current, digest = head
            if version != expected_version:
                raise ConflictError(f'stale version {expected_version}; actual {version}')
            if version >= 2**63-2:
                raise StoreError('version exhausted')
            if len(current) > MAX_STORED_STATE or not hmac.compare_digest(_digest(current), digest):
                raise IntegrityError('head corruption')
            # Do not hold a write lock across decompression; signed data checked first.
            target = equal3.decode_bytes(current, packet, key=self.key, require_auth=True)
            if len(target) > MAX_STORED_STATE:
                raise StoreError('decoded target exceeds state limit')
            target_digest = _digest(target)
            if fault: fault('after_preflight')
            db.execute('BEGIN IMMEDIATE')
            started = True
            if fault: fault('after_begin')
            old = db.execute('SELECT proposal_hash,base_version,committed_version,digest FROM receipts WHERE request_id=?',(rid,)).fetchone()
            if old:
                db.execute('ROLLBACK'); started = False
                return self._authenticated_replay(rid, proposal_hash)
            if fault: fault('after_receipt_check')
            # Both version and contents rechecked: no lost update / ABA after pre-decode.
            actual = db.execute('SELECT version,digest FROM head WHERE id=1').fetchone()
            if actual is None or actual[0] != version or not hmac.compare_digest(actual[1], digest):
                raise ConflictError('state advanced or changed after preflight')
            # An authenticated base is mandatory even for a freshly created
            # store. Otherwise an offline edit to BOTH value and SHA-256 digest
            # could be accepted as the legitimate genesis when applying.
            schema_row = db.execute('SELECT schema_version,genesis_digest,store_id,key_check FROM meta WHERE id=1').fetchone()
            if schema_row is None or schema_row[0] != 2:
                raise IntegrityError('unsealed schema cannot authorize write')
            _, genesis_digest, chain_sid, chain_key_tag = schema_row
            if not hmac.compare_digest(_key_check(self.key,chain_sid),chain_key_tag):
                raise AuthenticationError('store key binding changed')
            genesis_auth=db.execute('SELECT tag FROM receipt_auth WHERE committed_version=0').fetchone()
            if (not genesis_auth or not isinstance(genesis_auth[0],bytes) or
                not hmac.compare_digest(genesis_auth[0],_chain_genesis(self.key,chain_sid,genesis_digest))):
                raise IntegrityError('genesis authentication failed before write')
            if version == 0:
                if not hmac.compare_digest(digest,genesis_digest):
                    raise IntegrityError('head does not match authenticated genesis before write')
            else:
                tail=db.execute('SELECT digest FROM receipts WHERE committed_version=?',(version,)).fetchone()
                if not tail or not isinstance(tail[0],bytes) or not hmac.compare_digest(tail[0],digest):
                    raise IntegrityError('head differs from last receipt before write')
            updated=db.execute('UPDATE head SET version=?,value=?,digest=? WHERE id=1 AND version=? AND digest=?',
                               (version+1,target,target_digest,version,digest))
            if updated.rowcount != 1:
                raise ConflictError('compare-and-swap failed')
            if fault: fault('after_cas')
            db.execute('INSERT INTO receipts VALUES (?,?,?,?,?)',
                       (rid,proposal_hash,version,version+1,target_digest))
            schema_version=db.execute('SELECT schema_version FROM meta WHERE id=1').fetchone()[0]
            if schema_version == 2:
                sid_for_chain,init_digest, key_binding=db.execute('SELECT store_id,genesis_digest,key_check FROM meta WHERE id=1').fetchone()
                if not hmac.compare_digest(_key_check(self.key,sid_for_chain),key_binding):
                    raise AuthenticationError('store binding changed inside write transaction')
                genesis_tag=_chain_genesis(self.key,sid_for_chain,init_digest)
                tag0=db.execute('SELECT tag FROM receipt_auth WHERE committed_version=0').fetchone()
                if not tag0 or not hmac.compare_digest(tag0[0],genesis_tag):
                    raise IntegrityError('receipt genesis chain changed')
                if version:
                    prior_tag=db.execute('SELECT tag FROM receipt_auth WHERE committed_version=?',(version-1,)).fetchone()
                    prior_receipt=db.execute('SELECT request_id,proposal_hash,base_version,committed_version,digest FROM receipts WHERE committed_version=?',(version,)).fetchone()
                    terminal_tag=db.execute('SELECT tag FROM receipt_auth WHERE committed_version=?',(version,)).fetchone()
                    if not prior_tag or not prior_receipt or not terminal_tag:
                        raise IntegrityError('receipt chain tail missing')
                    expected_terminal=_chain_next(self.key,sid_for_chain,prior_tag[0],*prior_receipt)
                    if not hmac.compare_digest(terminal_tag[0],expected_terminal):
                        raise IntegrityError('receipt chain tail modified')
                prior_row=db.execute('SELECT tag FROM receipt_auth WHERE committed_version=?',(version,)).fetchone()
                if not prior_row or not isinstance(prior_row[0],bytes) or len(prior_row[0])!=32:
                    raise IntegrityError('missing receipt predecessor authentication')
                tag=_chain_next(self.key,sid_for_chain,prior_row[0],rid,proposal_hash,version,version+1,target_digest)
                db.execute('INSERT INTO receipt_auth VALUES (?,?)',(version+1,tag))
            if fault: fault('after_receipt_insert')
            if fault: fault('before_commit')
            attempted_commit = True
            db.execute('COMMIT')
            started = False
            if fault: fault('after_commit')
            return Receipt(rid,version,version+1,target_digest,False)
        except BaseException as exc:
            if started and db.in_transaction:
                try: db.execute('ROLLBACK')
                except sqlite3.Error: pass
            if attempted_commit and not isinstance(exc, CommitOutcomeUnknown):
                raise CommitOutcomeUnknown('commit may have occurred; look up request receipt before retrying') from exc
            raise
        finally:
            db.close()


def prepare_update(store:StateStore, target:bytes, *, request_id=None, strategy='adaptive'):
    """Convenience for trusted local producer; remote producers use signed proposal API."""
    snap=store.read()
    if not isinstance(target,bytes) or len(target)>MAX_STORED_STATE:
        raise StoreError('target exceeds state size limit')
    rid=secrets.token_bytes(16) if request_id is None else request_id
    packet=equal3.encode_bytes(snap.value,target,key=store.key,strategy=strategy)
    return make_proposal(store.store_id,snap.version,rid,packet,key=store.key),rid
