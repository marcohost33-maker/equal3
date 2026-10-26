"""Equal3 v0.5 research reference: bounded chunked lossless state codec.

No confidentiality, replay prevention, multiwriter transaction, or hard CPU-time cap.
Unsigned packets are for local trusted use only. Requires Python >=3.10.
"""
from __future__ import annotations
import hashlib
import hmac
import io
import os
import struct
import tempfile
import zlib

MAGIC = b'EQ3\x05'
HEADER = struct.Struct('>4sBBQQI32s32s')  # 90 bytes
RECORD = struct.Struct('>BI')              # mode, payload size
TRAILER_SIZE = 32
MAX_STATE = 64 * 1024 * 1024
MIN_CHUNK, MAX_CHUNK, DEFAULT_CHUNK = 1024, 1024 * 1024, 65536
RAW, ZLIB, XOR_ZLIB, SAME, SPARSE = range(5)
FLAG_AUTH = 1
SHA_DOMAIN = b'EQ3-v05-SHA256\x00'
MAC_DOMAIN = b'EQ3-v05-HMAC-SHA256\x00'

class CodecError(ValueError):
    pass

class CommitIndeterminate(OSError):
    """Rename completed but directory fsync failed; outcome/durability is uncertain."""
    pass


def _key(key):
    if key is None:
        return None
    if not isinstance(key, bytes) or len(key) < 32:
        raise CodecError('HMAC key must contain at least 32 bytes')
    return key


def _hash(data):
    return hashlib.sha256(data).digest()


def _authenticator(key):
    if key is None:
        return hashlib.sha256(SHA_DOMAIN)
    return hmac.new(key, MAC_DOMAIN, hashlib.sha256)


def _chunkcheck(chunk):
    if not isinstance(chunk, int) or not MIN_CHUNK <= chunk <= MAX_CHUNK or chunk & (chunk-1):
        raise CodecError('chunk size must be power of 2 between 1024 and 1048576')


def _read_exact(f, n):
    parts = []
    while n:
        piece = f.read(n)
        if not piece:
            raise CodecError('truncated input')
        parts.append(piece)
        n -= len(piece)
    return b''.join(parts)


def _scan(f):
    """Hash seekable stream, then rewind to initial position."""
    try:
        start = f.tell()
    except (OSError, AttributeError) as exc:
        raise CodecError('input must be seekable') from exc
    h = hashlib.sha256()
    total = 0
    while True:
        chunk = f.read(DEFAULT_CHUNK)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_STATE:
            raise CodecError('state exceeds maximum permitted length')
        h.update(chunk)
    f.seek(start)
    return total, h.digest()


def _varint(n):
    assert n >= 0
    out = bytearray()
    while n >= 128:
        out.append((n & 127) | 128)
        n >>= 7
    out.append(n)
    return out


def _parse_varint(blob, pos):
    value, shift = 0, 0
    for i in range(5):
        if pos >= len(blob):
            raise CodecError('truncated sparse varint')
        byte = blob[pos]
        pos += 1
        value |= (byte & 0x7f) << shift
        if not (byte & 0x80):
            if i > 0 and byte == 0:
                raise CodecError('nonminimal sparse varint')
            return value, pos
        shift += 7
    raise CodecError('sparse varint too long')


def _plausibly_sparse(base, target):
    """Fast non-binding heuristic; min_size deliberately does not use it."""
    if len(base) != len(target):
        return False
    n = len(target)
    if n < 256:
        return True
    # Evenly spaced probes; dense differences rarely justify a sparse mode.
    sample = min(256, n)
    diffs = sum(base[(i * (n-1)) // (sample-1)] != target[(i * (n-1)) // (sample-1)]
                for i in range(sample))
    return diffs <= sample//8


def _sparse(base, target, ceiling):
    if len(base) != len(target):
        return None
    out = bytearray()
    prev = -1
    # Compare blocks with the optimized byte equality primitive; only descend
    # to Python-level comparisons in blocks that actually changed.
    block = 256
    for start in range(0, len(target), block):
        old_block = base[start:start+block]
        new_block = target[start:start+block]
        if old_block == new_block:
            continue
        for j, (a,b) in enumerate(zip(old_block,new_block)):
            if a != b:
                pos = start+j
                out.extend(_varint(pos-prev-1))
                out.append(b)
                if len(out) >= ceiling:
                    return None
                prev = pos
    return bytes(out)


def _unsparse(base, body):
    result = bytearray(base)
    previous = -1
    p = 0
    while p < len(body):
        gap, p = _parse_varint(body, p)
        if p >= len(body):
            raise CodecError('missing sparse value')
        index = previous + 1 + gap
        value = body[p]
        p += 1
        if index >= len(result) or result[index] == value:
            raise CodecError('sparse index out of bounds or unchanged')
        result[index] = value
        previous = index
    if not body:
        raise CodecError('empty sparse record is noncanonical')
    return bytes(result)


def _inflate(body, expected):
    dec = zlib.decompressobj()
    try:
        value = dec.decompress(body, expected+1)
    except zlib.error as exc:
        raise CodecError('corrupt compressed data') from exc
    if len(value) != expected or not dec.eof or dec.unconsumed_tail or dec.unused_data:
        raise CodecError('invalid decompression length or stream boundaries')
    return value


def _choose(base, target, strategy):
    if base == target:
        return SAME, b''
    mode, payload = RAW, target
    if len(base) == len(target) and (strategy == 'min_size' or _plausibly_sparse(base,target)):
        sp = _sparse(base, target, len(payload))
        if sp is not None and len(sp) < len(payload):
            mode, payload = SPARSE, sp
    if strategy in ('adaptive', 'min_size'):
        full = zlib.compress(target, 6)
        if len(full) < len(payload):
            mode, payload = ZLIB, full
        if len(base) == len(target) and (strategy == 'min_size' or len(payload) > len(target)//16):
            diff = bytes(a ^ b for a,b in zip(base, target))
            compressed = zlib.compress(diff, 6)
            if len(compressed) < len(payload):
                mode, payload = XOR_ZLIB, compressed
    return mode, payload


def encode_stream(base_in, target_in, dest_out, *, key=None, chunk_size=DEFAULT_CHUNK, strategy='adaptive'):
    """Encode seekable streams with bounded per-chunk working memory.
    Never expose destination to untrusted consumers until this call succeeds.
    Returns number of packet bytes written.
    """
    key = _key(key)
    _chunkcheck(chunk_size)
    if strategy not in ('adaptive', 'fast', 'min_size'):
        raise CodecError('unknown strategy')
    base_len, base_hash = _scan(base_in)
    target_len, target_hash = _scan(target_in)
    flags = FLAG_AUTH if key is not None else 0
    hdr = HEADER.pack(MAGIC, flags, 0, base_len, target_len, chunk_size, base_hash, target_hash)
    auth = _authenticator(key)
    auth.update(hdr)
    dest_out.write(hdr)
    written = len(hdr)
    base_seen, target_seen = hashlib.sha256(), hashlib.sha256()
    consumed_base = 0
    for offset in range(0, target_len, chunk_size):
        count = min(chunk_size, target_len - offset)
        target_chunk = _read_exact(target_in, count)
        base_count = min(count, base_len-consumed_base)
        base_chunk = _read_exact(base_in, base_count)
        consumed_base += base_count
        base_seen.update(base_chunk)
        target_seen.update(target_chunk)
        mode, body = _choose(base_chunk, target_chunk, strategy)
        record = RECORD.pack(mode, len(body))
        auth.update(record)
        auth.update(body)
        dest_out.write(record)
        dest_out.write(body)
        written += len(record) + len(body)
    # Consume any extra base bytes if base is longer than target.
    while consumed_base < base_len:
        piece = _read_exact(base_in, min(DEFAULT_CHUNK, base_len-consumed_base))
        consumed_base += len(piece)
        base_seen.update(piece)
    if (base_seen.digest() != base_hash or target_seen.digest() != target_hash
            or base_in.read(1) or target_in.read(1)):
        raise CodecError('input changed during encoding')
    dest_out.write(auth.digest())
    return written + TRAILER_SIZE


def decode_stream(base_in, packet_in, dest_out, *, key=None, require_auth=False):
    """Decode into a QUARANTINED output stream: output is untrusted until success.
    Caller MUST discard output if this call raises. Use apply_file for publication.
    """
    key = _key(key)
    base_len, base_hash = _scan(base_in)
    hdr = _read_exact(packet_in, HEADER.size)
    magic, flags, reserved, claimed_base, target_len, chunk_size, b_hash, t_hash = HEADER.unpack(hdr)
    if magic != MAGIC or reserved or flags not in (0, FLAG_AUTH):
        raise CodecError('unsupported format, flags or reserved field')
    if (claimed_base != base_len or target_len > MAX_STATE or b_hash != base_hash):
        raise CodecError('base mismatch or length limit')
    _chunkcheck(chunk_size)
    signed = bool(flags & FLAG_AUTH)
    if require_auth and not signed:
        raise CodecError('authenticated packet required')
    if signed and key is None:
        raise CodecError('HMAC key required')
    if not signed and key is not None:
        raise CodecError('key supplied to unsigned packet')
    # A signed stream is authenticated *before* processing compressed content.
    # Require a seekable packet so that verification is bounded-memory.
    # Recheck the MAC during the decode pass to detect file changes.
    if signed:
        try:
            position_after_header = packet_in.tell()
            packet_in.seek(0, os.SEEK_END)
            end = packet_in.tell()
            begin = position_after_header - HEADER.size
            allowed = (HEADER.size + TRAILER_SIZE + target_len
                       + ((target_len + chunk_size - 1)//chunk_size)*RECORD.size)
            if end-begin < HEADER.size+TRAILER_SIZE or end-begin > allowed:
                raise CodecError('authenticated packet exceeds framing limit')
            packet_in.seek(begin)
            pre = _authenticator(key)
            remain = end-begin-TRAILER_SIZE
            while remain:
                data = _read_exact(packet_in, min(DEFAULT_CHUNK, remain))
                pre.update(data)
                remain -= len(data)
            claimed_tag = _read_exact(packet_in, TRAILER_SIZE)
            if not hmac.compare_digest(pre.digest(), claimed_tag):
                raise CodecError('authentication failed before decompression')
            packet_in.seek(position_after_header)
        except (OSError, AttributeError, io.UnsupportedOperation) as exc:
            raise CodecError('signed streams require seekable packet input') from exc
    auth = _authenticator(key if signed else None)
    auth.update(hdr)
    result_hash = hashlib.sha256()
    base_seen = hashlib.sha256()
    consumed_base = 0
    for offset in range(0, target_len, chunk_size):
        count = min(chunk_size, target_len-offset)
        record = _read_exact(packet_in, RECORD.size)
        mode, pay_len = RECORD.unpack(record)
        if mode not in (RAW,ZLIB,XOR_ZLIB,SAME,SPARSE) or pay_len > count:
            raise CodecError('invalid chunk record')
        if mode == SAME and pay_len != 0:
            raise CodecError('nonempty SAME record')
        body = _read_exact(packet_in, pay_len)
        auth.update(record)
        auth.update(body)
        base_count = min(count, base_len-consumed_base)
        base_chunk = _read_exact(base_in, base_count)
        consumed_base += base_count
        base_seen.update(base_chunk)
        if mode == RAW:
            if pay_len != count:
                raise CodecError('invalid RAW length')
            value = body
        elif mode == SAME:
            if len(base_chunk) != count:
                raise CodecError('SAME requires exact base length')
            value = base_chunk
        elif mode == SPARSE:
            if len(base_chunk) != count:
                raise CodecError('SPARSE requires matching lengths')
            value = _unsparse(base_chunk, body)
        else:
            inflated = _inflate(body, count)
            if mode == XOR_ZLIB:
                if len(base_chunk) != count:
                    raise CodecError('XOR requires matching lengths')
                value = bytes(a ^ b for a,b in zip(base_chunk, inflated))
            else:
                value = inflated
        result_hash.update(value)
        dest_out.write(value)
    while consumed_base < base_len:
        piece = _read_exact(base_in, min(DEFAULT_CHUNK, base_len-consumed_base))
        consumed_base += len(piece)
        base_seen.update(piece)
    tag = _read_exact(packet_in, TRAILER_SIZE)
    if packet_in.read(1):
        raise CodecError('unexpected bytes after trailer')
    if not hmac.compare_digest(auth.digest(), tag):
        raise CodecError('packet authentication/checksum failure')
    if not hmac.compare_digest(base_seen.digest(), b_hash):
        raise CodecError('base changed during decoding')
    if not hmac.compare_digest(result_hash.digest(), t_hash):
        raise CodecError('reconstructed target mismatch')
    if base_in.read(1):
        raise CodecError('base input changed length')
    return target_len


def encode_bytes(base:bytes, target:bytes, *, key=None, chunk_size=DEFAULT_CHUNK, strategy='adaptive'):
    if not isinstance(base, bytes) or not isinstance(target, bytes):
        raise TypeError('states must be bytes')
    sink = io.BytesIO()
    encode_stream(io.BytesIO(base), io.BytesIO(target), sink, key=key, chunk_size=chunk_size, strategy=strategy)
    return sink.getvalue()


def decode_bytes(base:bytes, packet:bytes, *, key=None, require_auth=False):
    if not isinstance(base, bytes) or not isinstance(packet, bytes):
        raise TypeError('base and packet must be bytes')
    sink = io.BytesIO()
    decode_stream(io.BytesIO(base), io.BytesIO(packet), sink, key=key, require_auth=require_auth)
    return sink.getvalue()


def _publish_posix(destination, producer):
    if os.name != 'posix':
        raise CodecError('atomic publish helper requires POSIX')
    parent = os.path.abspath(os.path.dirname(os.fspath(destination)) or '.')
    fd, tmp = tempfile.mkstemp(dir=parent, prefix='.eq3-v05-')
    replaced = False
    try:
        with os.fdopen(fd, 'wb') as out:
            producer(out)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, destination)
        replaced = True
        try:
            dirfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dirfd)
            finally:
                os.close(dirfd)
        except OSError as exc:
            raise CommitIndeterminate('rename happened, but directory fsync failed; verify state before retry') from exc
    finally:
        if not replaced:
            try: os.unlink(tmp)
            except FileNotFoundError: pass


def encode_file(base_path, target_path, packet_path, *, key=None, chunk_size=DEFAULT_CHUNK, strategy='adaptive'):
    """Trusted single-writer local directory; not multiwriter CAS or hostile-path safe."""
    def producer(out):
        with open(base_path, 'rb') as b, open(target_path, 'rb') as t:
            encode_stream(b,t,out,key=key,chunk_size=chunk_size,strategy=strategy)
    _publish_posix(packet_path, producer)


def apply_file(base_path, packet_path, target_path, *, key=None, require_auth=True):
    """Never publishes partial/unauthenticated decoded target; trusted local POSIX paths.
    require_auth=True by default. Does not prevent rollback/replay or lost updates.
    """
    def producer(out):
        with open(base_path,'rb') as b, open(packet_path,'rb') as p:
            decode_stream(b,p,out,key=key,require_auth=require_auth)
    _publish_posix(target_path, producer)
