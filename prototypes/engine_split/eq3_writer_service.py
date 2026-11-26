"""ADR-003 candidate (prototype): Linux writer service, entry point of the writer distribution.

Derived from research/writer_service_v0714.py (v0.7.22). File, socket and UID checks, the
signed runtime gate, the handler and the bounded threaded server are carried over without
semantic change. Differences:
- every SET goes through AnchoredWriterCore (engine + commit capability + anchor); the
  unanchored WriterCore and the `_research_unanchored` flag, which let serve() call
  StateStore.apply directly, are gone;
- serve() HOLDs unless a research anchor object is passed explicitly, because an independently
  operated anchor does not exist (roadmap P0-3); the lab anchor is not part of DISTRIBUTION.txt;
- imports form no cycle: eq3_wire and eq3_wal_gate are leaves (ADR-003 item 4).
Release decision: NO-GO.
"""
from __future__ import annotations

import os
from pathlib import Path
import socket
import socketserver
import stat
import struct
import sys
import threading

from eq3_anchor_types import AnchorHold
from eq3_anchored_writer import AnchoredWriterCore
from eq3_engine import bind_writer
from eq3_runtime_gate import verify_signed_runtime_policy
from eq3_wire import WriterError, json_reply, read_request


def peer_uid(sock):
    if sys.platform != 'linux' or not hasattr(socket, 'SO_PEERCRED'):
        raise WriterError('Linux SO_PEERCRED required')
    creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
    _, uid, _ = struct.unpack('3i', creds)
    return uid


def private_file(path, *, name):
    path = Path(path).absolute()
    if not hasattr(os, 'O_NOFOLLOW'):
        raise WriterError('O_NOFOLLOW required')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0) | os.O_NOFOLLOW)
    try:
        s = os.fstat(fd); l = os.lstat(path)
        if (not stat.S_ISREG(s.st_mode) or s.st_uid != os.geteuid() or
                stat.S_IMODE(s.st_mode) != 0o600 or (s.st_ino, s.st_dev) != (l.st_ino, l.st_dev)):
            raise WriterError(f'{name} is not a private, owner-controlled regular file')
        if s.st_size > 4096 or s.st_size < 32:
            raise WriterError(f'{name} size invalid')
        data = os.read(fd, 4097)
        if len(data) < 32 or len(data) > 4096:
            raise WriterError(f'{name} size changed')
        return data
    finally:
        os.close(fd)


def root_provisioned_public_key(path):
    p = Path(path).absolute()
    if not hasattr(os, 'O_NOFOLLOW'):
        raise WriterError('O_NOFOLLOW required for public-key trust root')
    parent = os.lstat(p.parent)
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or stat.S_IMODE(parent.st_mode) & 0o022:
        raise WriterError('public key parent not root managed')
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0))
    try:
        st = os.fstat(fd); ls = os.lstat(p)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o022 or
                (st.st_ino, st.st_dev) != (ls.st_ino, ls.st_dev) or st.st_size != 32):
            raise WriterError('public key not root provisioned')
        key = os.read(fd, 33)
        if len(key) != 32:
            raise WriterError('public key truncated')
        return key
    finally:
        os.close(fd)


def private_parent(p, *, group_gid=None):
    p = Path(p).absolute()
    s = os.lstat(p)
    if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.geteuid():
        raise WriterError('directory not privately owned by service UID')
    if stat.S_IMODE(s.st_mode) != (0o700 if group_gid is None else 0o710):
        raise WriterError('directory permissions fail closed')
    if group_gid is not None and s.st_gid != group_gid:
        raise WriterError('socket directory group mismatch')


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        server = self.server
        try:
            if peer_uid(self.request) != server.writer_uid:
                return  # refuse before reading attacker-controlled framing
            op, rid, body = read_request(self.request)
            try:
                ans = server.core.dispatch(op, rid, body)
            except (ValueError, OSError, AnchorHold):
                ans = {'ok': False, 'error': 'HOLD'}
            json_reply(self.request, ans)
        except (OSError, ValueError, TimeoutError):
            return


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    allow_reuse_address = False
    request_queue_size = 8
    daemon_threads = True
    block_on_close = True

    def server_activate(self):
        self._slots = threading.BoundedSemaphore(8)
        super().server_activate()

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def serve(socket_path, *, database_path, key_file, writer_uid, socket_gid,
          policy_file, signature_file, public_key_file, deployment_id,
          _research_anchor=None, _research_stop_event=None):
    """Production-shaped entry point. HOLDs: no independent anchor exists (P0-3)."""
    if sys.platform != 'linux' or not hasattr(socket, 'SO_PEERCRED'):
        raise WriterError('Linux peer credentials required')
    if _research_anchor is None:
        raise WriterError('P0 independent anchor and commit attestation missing; HOLD')
    if type(writer_uid) is not int or writer_uid <= 0 or writer_uid == os.geteuid():
        raise WriterError('writer UID must be distinct non-root UID')
    if type(socket_gid) is not int or socket_gid < 0:
        raise WriterError('dedicated writer socket GID required')
    db = Path(database_path).absolute(); sock = Path(socket_path).absolute()
    private_parent(db.parent)
    dbstat = os.lstat(db)
    if (not stat.S_ISREG(dbstat.st_mode) or dbstat.st_uid != os.geteuid() or
            stat.S_IMODE(dbstat.st_mode) != 0o600):
        raise WriterError('database file must be private service-owned file')
    private_parent(sock.parent, group_gid=socket_gid)
    if os.path.lexists(sock):
        raise WriterError('socket path exists; never unlink unknown socket')
    policy = Path(policy_file).read_bytes()
    signature = Path(signature_file).read_bytes()
    trusted_public = root_provisioned_public_key(public_key_file)
    approved = verify_signed_runtime_policy(policy, signature, trusted_public, deployment_id=deployment_id)
    if approved.get('runtime_gate') != 'SIGNED_POLICY_AND_RUNTIME_MATCH':
        raise WriterError('signed runtime gate did not pass')
    key = private_file(key_file, name='StateStore key')
    engine, capability = bind_writer(db, key=key, anchor=_research_anchor)
    core = AnchoredWriterCore(engine, capability, _research_anchor)
    old = os.umask(0o077)
    try:
        server = Server(str(sock), Handler)
    finally:
        os.umask(old)
    with server:
        try:
            os.chown(sock, -1, socket_gid)
            os.chmod(sock, 0o660)
            s = os.lstat(sock)
            if (not stat.S_ISSOCK(s.st_mode) or s.st_uid != os.geteuid() or
                    s.st_gid != socket_gid or stat.S_IMODE(s.st_mode) != 0o660):
                raise WriterError('socket ACL mismatch')
            server.core = core; server.writer_uid = writer_uid
            if _research_stop_event is not None:
                threading.Thread(target=lambda: (_research_stop_event.wait(), server.shutdown()),
                                 daemon=True).start()
            server.serve_forever(poll_interval=0.1)
        finally:
            if sock.is_socket():
                os.unlink(sock)
