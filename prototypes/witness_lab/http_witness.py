"""Minimal HTTP front end for the lab witness (c2sp.org/tlog-witness routes), stdlib only.

POST /add-checkpoint            body as in witness.parse_request; 409 uses text/x.tlog.size
GET  /<sha256(origin) hex>/checkpoint   latest cosigned checkpoint with the stored log note
                                         and a fresh witness cosignature (404 if none)

Request framing follows RFC 9112 section 6 strictly: one Content-Length of ASCII digits, no
Transfer-Encoding, at most MAX_BODY bytes, the whole body read before the witness sees it, and a
socket timeout (408 if the body stalls). Every error response (>= 400) sends
"Connection: close" and closes the connection, so unread body bytes are never parsed as a request.

Lab use only: binds to 127.0.0.1, no TLS, no rate limits. Run:
  python http_witness.py --db DIR/witness.sqlite --port 0 --witness-key-file KEY \
         --name witness.example/w1 --log-vkey <vkey> [--log-vkey ...]
It prints "LISTENING <port> <witness vkey>" once ready.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import note as n
from witness import Witness

MAX_BODY = 64 * 1024
DIGITS = re.compile(r'[0-9]{1,20}')
OWS = ' \t'


def body_length(headers):
    """Return (status, message) for a request whose body cannot be framed, else (None, length).

    RFC 9112 section 6: Content-Length = 1*DIGIT, a single value; Transfer-Encoding is not supported
    here, and together with Content-Length it is a framing error (section 6.3, item 3).
    """
    if headers.get_all('Transfer-Encoding'):
        if headers.get_all('Content-Length'):
            return 400, 'Transfer-Encoding with Content-Length\n'
        return 501, 'Transfer-Encoding not supported\n'
    values = headers.get_all('Content-Length') or []
    if not values:
        return 411, 'Content-Length required\n'
    if len(values) != 1:
        return 400, 'more than one Content-Length\n'
    value = values[0].strip(OWS)
    if len(value) > 20 and value.isascii() and value.isdigit():
        return 413, 'body too large\n'
    if not DIGITS.fullmatch(value):
        return 400, 'invalid Content-Length\n'
    length = int(value)
    if length == 0:
        return 400, 'empty body\n'
    if length > MAX_BODY:
        return 413, 'body too large\n'
    return None, length


def make_handler(witness: Witness, timeout: float = 5.0):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: int, body: str, content_type: str = 'text/plain; charset=utf-8'):
            data = body.encode('utf-8')
            self.send_response(status)
            if status >= 400:
                # an error may leave request body bytes unread; never reuse the connection
                # (RFC 9112 section 9.3). send_header sets close_connection for this header.
                self.send_header('Connection', 'close')
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            if self.path != '/add-checkpoint':
                return self._send(404, 'not found\n')
            status, length_or_error = body_length(self.headers)
            if status is not None:
                return self._send(status, length_or_error)
            length = length_or_error
            try:
                data = self.rfile.read(length)
            except TimeoutError:
                return self._send(408, 'request body timed out\n')
            if len(data) != length:
                return self._send(400, 'incomplete body\n')
            status, body = witness.add_checkpoint(data)
            self._send(status, body, 'text/x.tlog.size' if status == 409 else 'text/plain; charset=utf-8')

        def do_GET(self):
            parts = self.path.strip('/').split('/')
            if len(parts) != 2 or parts[1] != 'checkpoint':
                return self._send(404, 'not found\n')
            for origin in witness.trusted:
                if hashlib.sha256(origin.encode('utf-8')).hexdigest() == parts[0]:
                    row = witness.latest(origin)
                    if row is None:
                        break
                    note = n.parse_note(row[2])
                    cosig = witness.signer.signature_line(note.text, witness.clock())
                    return self._send(200, row[2].decode('utf-8') + cosig)
            return self._send(404, 'never cosigned\n')

        def log_message(self, *args):  # keep test output clean
            pass

    Handler.timeout = timeout  # socket timeout for request line, headers and body (StreamRequestHandler)
    return Handler


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--db', required=True)
    ap.add_argument('--port', type=int, default=0)
    ap.add_argument('--name', required=True)
    ap.add_argument('--witness-key-file', required=True, help='32-byte raw Ed25519 private key')
    ap.add_argument('--log-vkey', action='append', required=True)
    args = ap.parse_args(argv)
    key = Ed25519PrivateKey.from_private_bytes(Path(args.witness_key_file).read_bytes())
    signer = n.Signer(args.name, n.TYPE_COSIGNATURE_V1, key)
    trusted = {}
    for vkey in args.log_vkey:
        v = n.Verifier.from_vkey(vkey)
        trusted.setdefault(v.name, []).append(v)
    witness = Witness(args.db, signer, trusted)
    server = ThreadingHTTPServer(('127.0.0.1', args.port), make_handler(witness))
    print('LISTENING %d %s' % (server.server_address[1], signer.verifier.vkey()), flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
