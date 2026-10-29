"""Tests for the witness lab: C2SP formats, tlog-witness protocol, and the NR-01 rollback lab.

Run (needs the research dependency `cryptography`):
  python -m unittest -v prototypes/witness_lab/test_witness_lab.py
"""
import base64
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import note as n  # noqa: E402
from lab_log import ClientState, LabLog, RollbackDetected, accept_checkpoint  # noqa: E402
from witness import Witness, build_request  # noqa: E402

ORIGIN = 'lab.equal3.example/anchor'
SPEC_VKEY = 'example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k'
SPEC_NOTE = ('This is an example message.\n\n— example.com/foo Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXp'
             'pzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM=\n').encode('utf-8')


def events(prefix, start, stop):
    return [b'%s-%d' % (prefix, i) for i in range(start, stop)]


class Clock:
    def __init__(self, t=1_800_000_000):
        self.t = t

    def __call__(self):
        self.t += 1
        return self.t


class TempDirTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def witness(self, name, log, db=None):
        signer = n.Signer(name, n.TYPE_COSIGNATURE_V1)
        return Witness(db or self.dir / (name.replace('/', '_') + '.sqlite'), signer,
                       {log.origin: [log.signer.verifier]}, clock=Clock())


class NoteFormat(unittest.TestCase):
    def test_signed_note_spec_example(self):
        verifier = n.Verifier.from_vkey(SPEC_VKEY)
        self.assertEqual(verifier.key_id.hex(), '530d903a')
        self.assertEqual(verifier.vkey(), SPEC_VKEY)
        self.assertIn(verifier, n.verify_note(n.parse_note(SPEC_NOTE), [verifier]))

    def test_vkey_roundtrip_with_plus_in_base64(self):
        # base64 may contain '+'; only the first two '+' separate the vkey fields
        for _ in range(200):
            v = n.Signer('lab.example/k', n.TYPE_ED25519).verifier
            if '+' in v.vkey().split('+', 2)[2]:
                self.assertEqual(n.Verifier.from_vkey(v.vkey()), v)
                break
        else:
            self.fail('no key with + in its base64 found in 200 tries')
        with self.assertRaises(n.NoteError):
            n.Verifier.from_vkey(SPEC_VKEY.replace('530d903a', '530d903b'))

    def test_spec_example_tampered_text_fails(self):
        verifier = n.Verifier.from_vkey(SPEC_VKEY)
        with self.assertRaises(n.NoteError):
            n.verify_note(n.parse_note(SPEC_NOTE.replace(b'example', b'exampel', 1)), [verifier])

    def test_checkpoint_spec_example_text(self):
        cp = n.parse_checkpoint_text(b'example.com/behind-the-sofa\n20852163\n'
                                     b'CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n')
        self.assertEqual((cp.origin, cp.size, len(cp.root)), ('example.com/behind-the-sofa', 20852163, 32))
        self.assertEqual(cp.text(), b'example.com/behind-the-sofa\n20852163\n'
                                    b'CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n')

    def test_strict_parsing(self):
        root = base64.b64encode(bytes(32)).decode()
        bad_texts = [b'o\n01\n' + root.encode() + b'\n',            # leading zero
                     b'o\n1\n' + root[:-2].encode() + b'==\n',       # wrong length / non-canonical
                     b'o+x\n1\n' + root.encode() + b'\n',            # plus in origin
                     b'o\n1\n' + root.encode() + b'\n\n',            # empty extension line
                     b'o\n1\n']                                      # too few lines
        for text in bad_texts:
            with self.assertRaises(n.NoteError, msg=text):
                n.parse_checkpoint_text(text)
        with self.assertRaises(n.NoteError):
            n.b64decode_canonical('AB==')  # non-zero padding bits: not canonical
        with self.assertRaises(n.NoteError):
            n.parse_note(b'text\x07\n\n\xe2\x80\x94 a AAAAAAAA\n')     # control character
        with self.assertRaises(n.NoteError):
            n.parse_note(b'text\n\xe2\x80\x94 a AAAAAAAA\n')            # no blank line

    def test_unknown_keys_ignored_known_failure_rejects(self):
        log = n.Signer(ORIGIN, n.TYPE_ED25519)
        other = n.Signer('other.example/k', n.TYPE_ED25519)
        cp = n.Checkpoint(ORIGIN, 1, bytes(32))
        signed = n.sign_checkpoint(cp, [log, other])
        self.assertEqual(list(n.verify_note(n.parse_note(signed), [log.verifier])), [log.verifier])
        with self.assertRaises(n.NoteError):  # no known key at all
            n.verify_note(n.parse_note(signed), [n.Signer('x.example/y', n.TYPE_ED25519).verifier])
        impostor = n.Signer(ORIGIN, n.TYPE_ED25519)  # same name, other key: different key ID -> ignored
        forged = n.sign_checkpoint(cp, [impostor])
        with self.assertRaises(n.NoteError):
            n.verify_note(n.parse_note(forged), [log.verifier])
        tampered = signed.replace(b'\n1\n', b'\n2\n', 1)  # known key, text changed -> whole note rejected
        with self.assertRaises(n.NoteError):
            n.verify_note(n.parse_note(tampered), [log.verifier, other.verifier])

    def test_cosignature_binds_timestamp_and_text(self):
        w = n.Signer('w.example/1', n.TYPE_COSIGNATURE_V1)
        text = n.Checkpoint(ORIGIN, 3, bytes(32)).text()
        line = w.signature_line(text, 1_800_000_123)
        sig = n.parse_signature_line(line.rstrip('\n'))
        self.assertEqual(w.verifier.verify(text, sig.payload), {'timestamp': 1_800_000_123})
        moved = (1_800_000_124).to_bytes(8, 'big') + sig.payload[8:]
        with self.assertRaises(Exception):
            w.verifier.verify(text, moved)
        with self.assertRaises(n.NoteError):
            w.signature_line(text, 0)
        self.assertNotEqual(w.verifier.key_id, n.key_id(w.name, n.TYPE_ED25519, w.verifier.public_key))


class WitnessProtocol(TempDirTest):
    def setUp(self):
        super().setUp()
        self.log = LabLog(ORIGIN)
        self.w = self.witness('witness.example/w1', self.log)

    def add(self, old, body=None):
        return self.w.add_checkpoint(body or self.log.request_for(old))

    def test_first_checkpoint_then_growth(self):
        self.log.append(*events(b'e', 0, 5))
        status, body = self.add(0)
        self.assertEqual(status, 200)
        cosigned = self.log.signed_checkpoint() + body.encode()
        verified = n.verify_note(n.parse_note(cosigned), [self.log.signer.verifier, self.w.signer.verifier])
        self.assertIn(self.w.signer.verifier, verified)
        self.log.append(*events(b'e', 5, 13))
        self.assertEqual(self.add(5)[0], 200)
        self.assertEqual(self.w.latest(ORIGIN)[0], 13)
        self.assertEqual(self.add(13)[0], 200)  # same size, same root: cosigned again

    def test_status_codes(self):
        self.log.append(*events(b'e', 0, 8))
        self.assertEqual(self.add(0)[0], 200)
        self.log.append(*events(b'e', 8, 12))
        self.assertEqual(self.add(3), (409, '8\n'))
        self.assertEqual(self.add(20)[0], 400)  # old > size
        stranger = LabLog('stranger.example/log')
        stranger.append(b'x')
        self.assertEqual(self.w.add_checkpoint(stranger.request_for(0))[0], 404)
        impostor = LabLog(ORIGIN)  # right origin, untrusted key
        impostor.append(*events(b'e', 0, 12))
        self.assertEqual(self.w.add_checkpoint(impostor.request_for(8))[0], 403)
        proof = self.log.tree.consistency_proof(8)
        bad = build_request(8, [bytes(32)] + proof[1:], self.log.signed_checkpoint())
        self.assertEqual(self.w.add_checkpoint(bad)[0], 422)
        self.assertEqual(self.w.add_checkpoint(build_request(8, [bytes(32)] * 64,
                                                             self.log.signed_checkpoint()))[0], 400)
        self.assertEqual(self.w.add_checkpoint(b'old 8\n')[0], 400)
        self.assertEqual(self.w.latest(ORIGIN)[0], 8, 'rejected requests must not move the state')
        self.assertEqual(self.add(8)[0], 200)

    def test_same_size_different_root_and_nonempty_proof_at_zero(self):
        self.log.append(*events(b'e', 0, 4))
        self.assertEqual(self.add(0)[0], 200)
        fork = LabLog(ORIGIN, self.log.signer)
        fork.append(*events(b'X', 0, 4))
        self.assertEqual(self.w.add_checkpoint(fork.request_for(4))[0], 422)
        other = self.witness('witness.example/fresh', self.log)
        req = build_request(0, [bytes(32)], self.log.signed_checkpoint())
        self.assertEqual(other.add_checkpoint(req)[0], 422)

    def test_state_survives_restart(self):
        self.log.append(*events(b'e', 0, 6))
        self.assertEqual(self.add(0)[0], 200)
        again = Witness(self.w.db_path, self.w.signer, {ORIGIN: [self.log.signer.verifier]})
        self.assertEqual(again.latest(ORIGIN)[0], 6)
        self.assertEqual(again.add_checkpoint(self.log.request_for(0)), (409, '6\n'))

    def test_concurrent_requests_cannot_roll_back(self):
        # c2sp tlog-witness: checking the old size and persisting must be atomic.
        self.log.append(*events(b'e', 0, 10))
        self.assertEqual(self.add(0)[0], 200)
        for round_ in range(10):
            base = len(self.log.tree)
            small = self.log.snapshot()
            small.append(*events(b'r%d' % round_, 0, 3))
            self.log.append(*events(b'r%d' % round_, 0, 7))
            reqs = [small.request_for(base), self.log.request_for(base)]
            results, barrier = [None, None], threading.Barrier(2)

            def send(i):
                barrier.wait()
                results[i] = Witness(self.w.db_path, self.w.signer,
                                     {ORIGIN: [self.log.signer.verifier]}).add_checkpoint(reqs[i])
            threads = [threading.Thread(target=send, args=(i,)) for i in range(2)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            statuses = sorted(r[0] for r in results)
            self.assertEqual(statuses, [200, 409], results)
            stored = self.w.latest(ORIGIN)[0]
            if results[0][0] == 200:  # the small one won: continue from it
                self.log = small
            self.assertEqual(stored, len(self.log.tree))

    def test_misbehaviour_evidence_is_kept(self):
        self.log.append(*events(b'e', 0, 4))
        self.assertEqual(self.add(0)[0], 200)
        fork = LabLog(ORIGIN, self.log.signer)
        fork.append(*events(b'X', 0, 4))
        self.w.add_checkpoint(fork.request_for(4))
        (status, reason, request), = self.w.evidence(ORIGIN)
        self.assertEqual(status, 422)
        # the evidence carries a valid log signature over a conflicting root: proof of a fork
        note = n.parse_note(request.split(b'\n\n', 1)[1])
        n.verify_note(note, [self.log.signer.verifier])
        self.assertNotEqual(n.parse_checkpoint_text(note.text).root, self.w.latest(ORIGIN)[1])


class JointRollbackLab(TempDirTest):
    """NR-01: store, anchor and local witness are restored together to an older valid state."""

    def setUp(self):
        super().setUp()
        self.log = LabLog(ORIGIN)
        self.local_dir, self.ext_dir = self.dir / 'local', self.dir / 'external'
        self.local_dir.mkdir()
        self.ext_dir.mkdir()
        self.local = self.witness('local.equal3.example/w', self.log, self.local_dir / 'w.sqlite')
        self.w1 = self.witness('ext1.example/w', self.log, self.ext_dir / 'w1.sqlite')
        self.w2 = self.witness('ext2.example/w', self.log, self.ext_dir / 'w2.sqlite')
        self.externals = [self.w1.signer.verifier, self.w2.signer.verifier]

    def publish(self, log, old, witnesses):
        lines, statuses = '', []
        for w in witnesses:
            status, body = w.add_checkpoint(log.request_for(old))
            statuses.append(status)
            if status == 200:
                lines += body
        return log.signed_checkpoint() + lines.encode(), statuses

    def test_joint_rollback_is_invisible_locally_and_caught_externally(self):
        self.log.append(*events(b'e', 0, 10))
        signed, st = self.publish(self.log, 0, [self.local, self.w1, self.w2])
        self.assertEqual(st, [200, 200, 200])
        client = accept_checkpoint(ClientState(), signed, self.log.signer.verifier, self.externals, 2, [])
        # snapshot of the whole local rollback domain at size 10
        snap_log, snap_client = self.log.snapshot(), client
        shutil.copy(self.local.db_path, self.dir / 'local_w_snapshot.sqlite')

        self.log.append(*events(b'e', 10, 20))
        signed, st = self.publish(self.log, 10, [self.local, self.w1, self.w2])
        self.assertEqual(st, [200, 200, 200])
        client = accept_checkpoint(client, signed, self.log.signer.verifier, self.externals, 2,
                                   self.log.tree.consistency_proof(10))
        self.assertEqual(client.size, 20)

        # joint rollback: log, local witness DB and local client state restored together
        forked, client = snap_log, snap_client
        shutil.copy(self.dir / 'local_w_snapshot.sqlite', self.local.db_path)
        forked.append(*events(b'FORK', 10, 15))
        signed, st = self.publish(forked, 10, [self.local, self.w1, self.w2])
        self.assertEqual(st, [200, 409, 409], 'local witness accepts the fork, external witnesses refuse')

        # NR-01 reproduced: with only the local witness, the fork is accepted as valid history
        accepted = accept_checkpoint(client, signed, forked.signer.verifier, [self.local.signer.verifier], 1,
                                     forked.tree.consistency_proof(10))
        self.assertEqual(accepted.size, 15)
        # with the external quorum the fork cannot be accepted
        with self.assertRaises(n.NoteError):
            accept_checkpoint(client, signed, forked.signer.verifier, self.externals, 2,
                              forked.tree.consistency_proof(10))
        # and the external witnesses keep a newer checkpoint than the restored client: rollback visible
        self.assertGreater(self.w1.latest(ORIGIN)[0], client.size)

    def test_fork_cannot_be_extended_past_the_witnessed_size(self):
        self.log.append(*events(b'e', 0, 20))
        self.publish(self.log, 0, [self.w1])
        fork = LabLog(ORIGIN, self.log.signer)
        fork.append(*events(b'e', 0, 10), *events(b'FORK', 10, 25))
        status, _ = self.w1.add_checkpoint(fork.request_for(20))  # proof from the fork's own size 20
        self.assertEqual(status, 422)
        self.assertEqual(self.w1.evidence(ORIGIN)[-1][0], 422)

    def test_compromised_witness_needs_quorum(self):
        self.log.append(*events(b'e', 0, 10))
        self.publish(self.log, 0, [self.w1, self.w2])
        shutil.copy(self.w1.db_path, self.dir / 'w1_old.sqlite')
        snap = self.log.snapshot()
        self.log.append(*events(b'e', 10, 20))
        self.publish(self.log, 10, [self.w1, self.w2])
        shutil.copy(self.dir / 'w1_old.sqlite', self.w1.db_path)  # w1's own state rolled back too
        snap.append(*events(b'FORK', 10, 15))
        signed, st = self.publish(snap, 10, [self.w1, self.w2])
        self.assertEqual(st, [200, 409])
        old = ClientState(10, snap.tree.leaves and __import__('merkle_log').mth(snap.tree.leaves[:10]))
        accept_checkpoint(old, signed, snap.signer.verifier, self.externals, 1, snap.tree.consistency_proof(10))
        with self.assertRaises(n.NoteError):
            accept_checkpoint(old, signed, snap.signer.verifier, self.externals, 2, snap.tree.consistency_proof(10))

    def test_client_that_saw_the_newer_checkpoint_rejects_the_fork(self):
        self.log.append(*events(b'e', 0, 20))
        signed, _ = self.publish(self.log, 0, [self.w1, self.w2])
        client = accept_checkpoint(ClientState(), signed, self.log.signer.verifier, self.externals, 2, [])
        fork = LabLog(ORIGIN, self.log.signer)
        fork.append(*events(b'e', 0, 10), *events(b'FORK', 10, 25))
        fake = n.sign_checkpoint(fork.checkpoint(), [fork.signer])
        with self.assertRaises(RollbackDetected):
            accept_checkpoint(client, fake, fork.signer.verifier, [], 0, fork.tree.consistency_proof(20))
        older = LabLog(ORIGIN, self.log.signer)
        older.append(*events(b'e', 0, 10))
        with self.assertRaises(RollbackDetected):
            accept_checkpoint(client, older.signed_checkpoint(), older.signer.verifier, [], 0, [])


class HttpWitnessProcess(TempDirTest):
    def test_separate_process_over_http(self):
        log = LabLog(ORIGIN)
        key = self.dir / 'w.key'
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
        key.write_bytes(Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
        os.chmod(key, 0o600)
        proc = subprocess.Popen([sys.executable, str(HERE / 'http_witness.py'), '--db', str(self.dir / 'h.sqlite'),
                                 '--name', 'http.example/w', '--witness-key-file', str(key),
                                 '--log-vkey', log.signer.verifier.vkey()],
                                stdout=subprocess.PIPE, text=True, cwd=str(HERE))
        try:
            first = proc.stdout.readline().split()
            self.assertEqual(first[0], 'LISTENING', first)
            port, wvkey = int(first[1]), n.Verifier.from_vkey(first[2])
            base = 'http://127.0.0.1:%d' % port

            def post(body):
                req = urllib.request.Request(base + '/add-checkpoint', data=body, method='POST')
                try:
                    with urllib.request.urlopen(req, timeout=10) as r:
                        return r.status, r.read().decode(), r.headers.get('Content-Type')
                except urllib.error.HTTPError as e:
                    return e.code, e.read().decode(), e.headers.get('Content-Type')

            log.append(*events(b'e', 0, 7))
            status, body, _ = post(log.request_for(0))
            self.assertEqual(status, 200)
            n.verify_note(n.parse_note(log.signed_checkpoint() + body.encode()), [wvkey])
            self.assertEqual(post(log.request_for(3)), (409, '7\n', 'text/x.tlog.size'))
            origin_hash = hashlib.sha256(ORIGIN.encode()).hexdigest()
            with urllib.request.urlopen(base + '/%s/checkpoint' % origin_hash, timeout=10) as r:
                served = r.read()
            verified = n.verify_note(n.parse_note(served), [log.signer.verifier, wvkey])
            self.assertEqual(set(verified), {log.signer.verifier, wvkey})
        finally:
            proc.terminate()
            proc.wait(timeout=10)
            proc.stdout.close()


class RecordingWitness:
    """Stands in for Witness: records every body the HTTP layer hands over."""
    trusted = {}

    def __init__(self):
        self.bodies = []

    def add_checkpoint(self, body):
        self.bodies.append(body)
        return 200, 'ok\n'


class HttpFraming(unittest.TestCase):
    """RFC 9112 section 6 message framing of POST /add-checkpoint (negative first)."""

    def setUp(self):
        import http_witness
        self.witness = RecordingWitness()
        handler = http_witness.make_handler(self.witness, timeout=0.5)
        self.server = http_witness.ThreadingHTTPServer(('127.0.0.1', 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=10)

    def exchange(self, head, body=b'', half_close=True, path=b'/add-checkpoint'):
        import socket
        with socket.create_connection(self.server.server_address, timeout=10) as s:
            s.sendall(b'POST ' + path + b' HTTP/1.1\r\nHost: lab\r\n' + head + b'\r\n' + body)
            if half_close:
                s.shutdown(socket.SHUT_WR)
            data = b''
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
        status = int(data.split(b' ', 2)[1]) if data.startswith(b'HTTP/') else None
        return status, data

    def assert_rejected(self, head, body, status):
        got, raw = self.exchange(head, body)
        self.assertEqual(got, status, raw)
        self.assertEqual(self.witness.bodies, [], 'a rejected request reached the witness')

    def test_well_formed_body_reaches_the_witness(self):
        self.assertEqual(self.exchange(b'Content-Length: 5\r\n', b'hello')[0], 200)
        self.assertEqual(self.witness.bodies, [b'hello'])

    def test_content_length_must_be_ascii_digits(self):
        # int() accepts all of these; RFC 9112 Content-Length = 1*DIGIT does not
        for value in (b'abc', b'+5', b'5_0', b' 5 5', b'0x5', b'-5', b'5.0', '５'.encode()):
            with self.subTest(value=value):
                self.assert_rejected(b'Content-Length: ' + value + b'\r\n', b'hello', 400)

    def test_empty_body_rejected(self):
        self.assert_rejected(b'Content-Length: 0\r\n', b'', 400)

    def test_duplicate_or_list_content_length_rejected(self):
        self.assert_rejected(b'Content-Length: 5\r\nContent-Length: 6\r\n', b'hello!', 400)
        self.assert_rejected(b'Content-Length: 5\r\nContent-Length: 5\r\n', b'hello', 400)
        self.assert_rejected(b'Content-Length: 5, 5\r\n', b'hello', 400)

    def test_transfer_encoding_rejected(self):
        self.assert_rejected(b'Transfer-Encoding: chunked\r\nContent-Length: 5\r\n', b'5\r\nhello\r\n0\r\n\r\n', 400)
        self.assert_rejected(b'Transfer-Encoding: chunked\r\n', b'5\r\nhello\r\n0\r\n\r\n', 501)

    def test_missing_content_length_rejected(self):
        self.assert_rejected(b'', b'hello', 411)

    def test_oversized_body_rejected_before_reading(self):
        import http_witness
        self.assert_rejected(b'Content-Length: %d\r\n' % (http_witness.MAX_BODY + 1), b'', 413)
        self.assert_rejected(b'Content-Length: ' + b'9' * 5000 + b'\r\n', b'', 413)

    def test_truncated_body_never_reaches_the_witness(self):
        # the client announces 100 bytes, sends 10 and closes its side
        self.assert_rejected(b'Content-Length: 100\r\n', b'0123456789', 400)

    def test_http11_error_without_reading_the_body_closes_the_connection(self):
        # RFC 9112 section 9.3: read the whole body or close before reusing the connection. The server
        # speaks HTTP/1.0 by default; this test enables HTTP/1.1 keep-alive to check the error paths.
        self.server.RequestHandlerClass.protocol_version = 'HTTP/1.1'
        smuggled = b'GET /x HTTP/1.1\r\nHost: lab\r\n\r\n'
        for path, head in ((b'/wrong', b'Content-Length: %d\r\n' % len(smuggled)),
                           (b'/add-checkpoint', b'Content-Length: +%d\r\n' % len(smuggled)),
                           (b'/add-checkpoint', b'Transfer-Encoding: chunked\r\n')):
            with self.subTest(path=path, head=head):
                status, raw = self.exchange(head, smuggled, half_close=False, path=path)
                self.assertIn(status, (400, 404, 501), raw)
                self.assertEqual(raw.count(b'HTTP/1.1 '), 1, raw)
                self.assertIn(b'\r\nConnection: close\r\n', raw)
        self.assertEqual(self.witness.bodies, [])

    def test_http11_keep_alive_still_serves_well_formed_requests(self):
        self.server.RequestHandlerClass.protocol_version = 'HTTP/1.1'
        one = b'POST /add-checkpoint HTTP/1.1\r\nHost: lab\r\nContent-Length: 5\r\n\r\nhello'
        status, raw = self.exchange(b'Content-Length: 5\r\n', b'hello' + one)
        self.assertEqual(status, 200, raw)
        self.assertEqual(raw.count(b'HTTP/1.1 200 '), 2, raw)
        self.assertEqual(self.witness.bodies, [b'hello', b'hello'])

    def test_stalled_body_times_out(self):
        # the client announces 100 bytes, sends 10 and keeps the connection open
        got, raw = self.exchange(b'Content-Length: 100\r\n', b'0123456789', half_close=False)
        self.assertEqual(got, 408, raw)
        self.assertEqual(self.witness.bodies, [])


class RecordingProxy:
    """The real Witness behind the HTTP layer; records every body handed to add_checkpoint."""

    def __init__(self, inner):
        self._inner = inner
        self.bodies = []

    def add_checkpoint(self, body):
        self.bodies.append(body)
        return self._inner.add_checkpoint(body)

    def __getattr__(self, name):  # trusted, latest, signer, clock
        return getattr(self._inner, name)


def parse_responses(raw, head_first=False):
    """Split a byte stream into Content-Length framed responses; any leftover byte is an error."""
    out, rest = [], raw
    while rest:
        end = rest.find(b'\r\n\r\n')
        if end < 0:
            raise AssertionError('incomplete response head: %r' % rest[:300])
        status_line, *fields = rest[:end].split(b'\r\n')
        headers = {}
        for line in fields:
            name, sep, value = line.partition(b':')
            if not sep:
                raise AssertionError('malformed header line %r' % line)
            headers.setdefault(name.strip().lower(), []).append(value.strip(b' \t'))
        lengths = headers.get(b'content-length', [])
        if len(lengths) != 1 or not lengths[0].isdigit():
            raise AssertionError('need exactly one numeric Content-Length: %r' % rest[:end])
        # a HEAD response announces the GET length but carries no body (RFC 9110 section 9.3.2)
        size = 0 if (head_first and not out) else int(lengths[0])
        body = rest[end + 4:end + 4 + size]
        if len(body) != size:
            raise AssertionError('body shorter than Content-Length: %r' % rest[:300])
        out.append((status_line, headers, body))
        rest = rest[end + 4 + size:]
    return out


class HttpConnectionClose(TempDirTest):
    """Invariant (reviews R10/R12): after one response the lab witness never serves another request on
    the same connection, for every method and status path, under HTTP/1.0 (default) and HTTP/1.1.

    Each response says "Connection: close" (RFC 9112 section 9.6: a server without persistent
    connections MUST send it in every non-1xx response) and has a Content-Length matching its body.
    Each case is followed by a pipelined canary POST; served, it would show up as a second response and
    as a body at the witness. The server must also close by itself, before its idle timeout.
    """
    CANARY = b'POST /add-checkpoint HTTP/1.1\r\nHost: lab\r\nContent-Length: 6\r\n\r\ncanary'
    IDLE = 3.0      # handler socket timeout: a server that keeps the connection waits this long
    DEADLINE = 1.5  # client read timeout, shorter than IDLE: no EOF by then means no server close

    def setUp(self):
        super().setUp()
        self.log = LabLog(ORIGIN)
        self.log.append(*events(b'e', 0, 7))
        self.cosigned = self.log.request_for(0)
        self.log.append(*events(b'e', 7, 12))
        self.n = 0

    def serve(self, protocol):
        import http_witness
        self.n += 1
        inner = self.witness('w%d.example/w' % self.n, self.log)
        self.assertEqual(inner.add_checkpoint(self.cosigned)[0], 200)  # witness state: size 7
        proxy = RecordingProxy(inner)
        handler = http_witness.make_handler(proxy, timeout=self.IDLE)
        handler.protocol_version = protocol
        server = http_witness.ThreadingHTTPServer(('127.0.0.1', 0), handler)
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True)
        thread.start()

        def stop():
            server.shutdown()
            server.server_close()
            thread.join(timeout=10)
        self.addCleanup(stop)
        return server, proxy

    def talk(self, server, payload):
        """Send payload in one write, read until the server closes; None if it did not close in time."""
        import socket
        with socket.create_connection(server.server_address, timeout=10) as s:
            s.sendall(payload)
            s.settimeout(self.DEADLINE)
            data = b''
            try:
                while True:
                    chunk = s.recv(65536)
                    if not chunk:
                        return data
                    data += chunk
            except TimeoutError:
                return None

    def cases(self):
        post = b'POST /add-checkpoint HTTP/1.1\r\nHost: lab\r\n'
        unread = b'X'  # one body byte the handler never reads on this path
        origin_hash = hashlib.sha256(ORIGIN.encode()).hexdigest().encode()
        stranger = LabLog('stranger.example/log')
        stranger.append(b'x')
        good = self.log.request_for(7)
        stale = self.log.request_for(3)
        alien = stranger.request_for(0)

        def with_body(head, body):
            return head + b'Content-Length: %d\r\n\r\n' % len(body) + body
        return (
            ('POST 200', with_body(post, good), 200, False),
            ('POST 200, client asks keep-alive', with_body(post + b'Connection: keep-alive\r\n', good), 200,
             False),
            ('POST 200, HTTP/1.0 client asks keep-alive',
             with_body(b'POST /add-checkpoint HTTP/1.0\r\nConnection: keep-alive\r\n', good), 200, False),
            ('POST 409 stale old size', with_body(post, stale), 409, False),
            ('POST 404 unknown log', with_body(post, alien), 404, False),
            ('POST 404 wrong path, body unread', with_body(b'POST /wrong HTTP/1.1\r\nHost: lab\r\n', unread),
             404, False),
            ('POST 400 bad Content-Length, body unread', post + b'Content-Length: +1\r\n\r\n' + unread, 400,
             False),
            ('POST 411 no Content-Length', post + b'\r\n', 411, False),
            ('POST 413 announced too large', post + b'Content-Length: 99999999\r\n\r\n' + unread, 413, False),
            ('POST 501 Transfer-Encoding', post + b'Transfer-Encoding: chunked\r\n\r\n1\r\nX\r\n0\r\n\r\n', 501,
             False),
            ('GET 200 checkpoint', b'GET /' + origin_hash + b'/checkpoint HTTP/1.1\r\nHost: lab\r\n\r\n', 200,
             False),
            ('GET 404 never cosigned', b'GET /' + b'0' * 64 + b'/checkpoint HTTP/1.1\r\nHost: lab\r\n\r\n', 404,
             False),
            ('GET 404 wrong path, body unread', with_body(b'GET /wrong HTTP/1.1\r\nHost: lab\r\n', unread), 404,
             False),
            ('HEAD 501 (stdlib send_error)', b'HEAD / HTTP/1.1\r\nHost: lab\r\n\r\n', 501, True),
            ('PUT 501 (stdlib send_error), body unread', with_body(b'PUT /add-checkpoint HTTP/1.1\r\nHost: lab\r\n',
                                                                     unread), 501, False),
            ('POST 431 too many header fields (stdlib send_error)', post + b'X-H: 1\r\n' * 101 + b'\r\n', 431,
             False),
        )

    def test_positive_control_the_canary_is_served_on_its_own(self):
        # without this the canary could be dropped for an unrelated reason and the checks below be blind
        for protocol in ('HTTP/1.0', 'HTTP/1.1'):
            with self.subTest(protocol=protocol):
                server, proxy = self.serve(protocol)
                raw = self.talk(server, self.CANARY)
                self.assertIsNotNone(raw, 'server did not close')
                responses = parse_responses(raw)
                self.assertEqual(len(responses), 1, raw)
                self.assertEqual(proxy.bodies, [b'canary'])

    def test_every_response_closes_the_connection(self):
        for protocol in ('HTTP/1.0', 'HTTP/1.1'):
            for name, request, status, head_first in self.cases():
                with self.subTest(protocol=protocol, case=name):
                    server, proxy = self.serve(protocol)
                    raw = self.talk(server, request + self.CANARY)
                    self.assertIsNotNone(raw, 'server kept the connection open after its response')
                    responses = parse_responses(raw, head_first)
                    self.assertEqual(len(responses), 1, raw)
                    status_line, headers, _ = responses[0]
                    version, code = status_line.split(b' ')[:2]
                    self.assertEqual(version, protocol.encode(), raw)
                    self.assertEqual(int(code), status, raw)
                    self.assertEqual(headers.get(b'connection'), [b'close'], raw)
                    self.assertNotIn(b'canary', proxy.bodies, 'the pipelined request reached the witness')

    def test_malformed_request_line_is_answered_once_and_closed(self):
        # CPython answers an unparsable request line HTTP/0.9 style (no status line, no headers), so the
        # header checks above do not apply; the connection must still end without serving the canary.
        for protocol in ('HTTP/1.0', 'HTTP/1.1'):
            for line in (b'GARBAGE\r\n', b'GET / HTTP/9.9\r\n', b'GET / HTTP/x\r\n'):
                with self.subTest(protocol=protocol, line=line):
                    server, proxy = self.serve(protocol)
                    raw = self.talk(server, line + b'\r\n' + self.CANARY)
                    self.assertIsNotNone(raw, 'server kept the connection open')
                    self.assertLessEqual(raw.count(b'HTTP/1.'), 1, raw)
                    self.assertEqual(proxy.bodies, [])


if __name__ == '__main__':
    unittest.main()
