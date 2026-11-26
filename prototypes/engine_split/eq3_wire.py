"""ADR-003 candidate (prototype): writer RPC framing, leaf of the writer distribution.

Copied from research/writer_service_v0714.py (v0.7.22): frame constants, WriterError, the
bounded reader, request parsing, the JSON reply and client_request, without semantic change.
In the research tree anchored_writer_v0715 imports these constants from the service module;
as a leaf they let the service import the anchored writer without a cycle. Release: NO-GO.
"""
from __future__ import annotations

from contextlib import closing
import json
import socket
import struct

from eq3_engine import MAX_STORED_STATE

MAGIC = b'EQW1'
HEADER = struct.Struct('>4sB16sI')
STATUS = 1
SET = 2
MAX_REPLY = 2048
MAX_REQUEST = MAX_STORED_STATE
ZERO_REQUEST = bytes(16)


class WriterError(ValueError):
    pass


def read_exact(sock: socket.socket, count: int) -> bytes:
    result = bytearray()
    while len(result) < count:
        part = sock.recv(min(65536, count-len(result)))
        if not part:
            raise WriterError('incomplete frame')
        result.extend(part)
    return bytes(result)


def json_reply(sock, payload):
    b = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')
    if len(b) > MAX_REPLY:
        raise WriterError('internal response too large')
    sock.sendall(struct.pack('>I', len(b)) + b)


def read_request(sock):
    sock.settimeout(4)
    magic, op, rid, n = HEADER.unpack(read_exact(sock, HEADER.size))
    if magic != MAGIC or op not in (STATUS, SET):
        raise WriterError('invalid request type')
    if op == STATUS and (n or rid != ZERO_REQUEST):
        raise WriterError('noncanonical status frame')
    if op == SET and (rid == ZERO_REQUEST or n > MAX_REQUEST):
        raise WriterError('invalid set frame or excessive state')
    return op, rid, read_exact(sock, n)


def client_request(socket_path, *, op, request_id=ZERO_REQUEST, target=b'', timeout=5):
    if type(request_id) is not bytes or len(request_id) != 16:
        raise WriterError('bad request_id')
    if op not in (SET, STATUS) or type(target) is not bytes or len(target) > MAX_REQUEST:
        raise WriterError('bad request')
    if op == STATUS and (target or request_id != ZERO_REQUEST):
        raise WriterError('noncanonical status request')
    if op == SET and request_id == ZERO_REQUEST:
        raise WriterError('SET requires nonzero stable request ID')
    with closing(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)) as s:
        s.settimeout(timeout)
        s.connect(str(socket_path))
        s.sendall(HEADER.pack(MAGIC, op, request_id, len(target)) + target)
        size = struct.unpack('>I', read_exact(s, 4))[0]
        if size < 2 or size > MAX_REPLY:
            raise WriterError('invalid reply length')

        def unique(pairs):
            d = {}
            for k, v in pairs:
                if k in d:
                    raise WriterError('duplicate JSON response')
                d[k] = v
            return d
        data = json.loads(read_exact(s, size), object_pairs_hook=unique)
        if type(data) is not dict or type(data.get('ok')) is not bool:
            raise WriterError('invalid reply schema')
        return data
