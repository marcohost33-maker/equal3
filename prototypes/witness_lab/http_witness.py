"""Minimal HTTP front end for the lab witness (c2sp.org/tlog-witness routes), stdlib only.

POST /add-checkpoint            body as in witness.parse_request; 409 uses text/x.tlog.size
GET  /<sha256(origin) hex>/checkpoint   latest cosigned checkpoint with the stored log note
                                         and a fresh witness cosignature (404 if none)

Lab use only: binds to 127.0.0.1, no TLS, no rate limits. Run:
  python http_witness.py --db DIR/witness.sqlite --port 0 --witness-key-file KEY \
         --name witness.example/w1 --log-vkey <vkey> [--log-vkey ...]
It prints "LISTENING <port> <witness vkey>" once ready.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import note as n
from witness import Witness

MAX_BODY = 64 * 1024


def make_handler(witness: Witness):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: int, body: str, content_type: str = 'text/plain; charset=utf-8'):
            data = body.encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            if self.path != '/add-checkpoint':
                return self._send(404, 'not found\n')
            length = int(self.headers.get('Content-Length') or 0)
            if not 0 < length <= MAX_BODY:
                return self._send(400, 'body size\n')
            status, body = witness.add_checkpoint(self.rfile.read(length))
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
