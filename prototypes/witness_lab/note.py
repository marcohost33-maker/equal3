"""C2SP signed notes, checkpoints and Ed25519 checkpoint cosignatures (lab prototype).

Implements, from the C2SP editor's copies (github.com/C2SP/C2SP @ fea9004, 2026-10-27):
- signed-note: text, blank line, signature lines "— <name> base64(keyID || sig)";
  key ID = SHA-256(name || 0x0A || type || public key)[:4]; vkeys "name+hex(keyID)+base64(type||pk)";
  type 0x01 Ed25519 signs the note text.
- tlog-checkpoint: note text = origin, tree size (ASCII decimal), base64 root hash, optional
  extension lines.
- tlog-cosignature: type 0x04 Ed25519 checkpoint cosignature over
  "cosignature/v1\\ntime <t>\\n" || checkpoint note text; signature bytes = keyID || uint64 t || sig.

Parsing is strict (fail closed): valid UTF-8, no control characters except newline,
canonical base64, key-name rules. Not part of any research version (see docs/ADR-002).
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
import struct
from dataclasses import dataclass
from typing import Dict, List, Sequence, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

TYPE_ED25519 = 0x01
TYPE_COSIGNATURE_V1 = 0x04
MAX_SIGNATURES = 64
EM_DASH = '—'
DECIMAL = re.compile(r'(0|[1-9][0-9]*)\Z')
MAX_U63 = (1 << 63) - 1


class NoteError(ValueError):
    pass


def b64decode_canonical(text: str) -> bytes:
    try:
        raw = base64.b64decode(text.encode('ascii'), validate=True)
    except (binascii.Error, UnicodeEncodeError) as exc:
        raise NoteError('invalid base64') from exc
    if base64.b64encode(raw).decode('ascii') != text:
        raise NoteError('non-canonical base64')
    return raw


def b64encode(raw: bytes) -> str:
    return base64.b64encode(raw).decode('ascii')


def check_key_name(name: str) -> None:
    if not name or len(name.encode('utf-8')) > 255 or '+' in name or any(c.isspace() for c in name) \
            or any(ord(c) < 0x20 for c in name):
        raise NoteError('invalid key name')


def key_id(name: str, sig_type: int, public_key: bytes) -> bytes:
    return hashlib.sha256(name.encode('utf-8') + b'\n' + bytes([sig_type]) + public_key).digest()[:4]


def parse_decimal(text: str) -> int:
    if not DECIMAL.match(text) or int(text) > MAX_U63:
        raise NoteError('invalid decimal %r' % text)
    return int(text)


# --- keys -------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Verifier:
    name: str
    sig_type: int
    public_key: bytes

    @property
    def key_id(self) -> bytes:
        return key_id(self.name, self.sig_type, self.public_key)

    def vkey(self) -> str:
        return '%s+%s+%s' % (self.name, self.key_id.hex(), b64encode(bytes([self.sig_type]) + self.public_key))

    @classmethod
    def from_vkey(cls, vkey: str) -> 'Verifier':
        parts = vkey.split('+', 2)  # the base64 part may itself contain '+'
        if len(parts) != 3:
            raise NoteError('vkey must have three parts')
        name, hex_id, blob = parts
        check_key_name(name)
        raw = b64decode_canonical(blob)
        if len(raw) != 33 or raw[0] not in (TYPE_ED25519, TYPE_COSIGNATURE_V1):
            raise NoteError('unsupported vkey type or length')
        verifier = cls(name, raw[0], raw[1:])
        if hex_id != verifier.key_id.hex():
            raise NoteError('vkey key ID does not match key')
        return verifier

    def verify(self, note_text: bytes, signature: bytes) -> dict:
        """Verify the signature bytes after the key ID; returns {'timestamp': t} for cosignatures."""
        key = Ed25519PublicKey.from_public_bytes(self.public_key)
        if self.sig_type == TYPE_ED25519:
            if len(signature) != 64:
                raise NoteError('Ed25519 signature must be 64 bytes')
            key.verify(signature, note_text)
            return {}
        if len(signature) != 72:
            raise NoteError('cosignature must be 8 + 64 bytes')
        (timestamp,) = struct.unpack('>Q', signature[:8])
        if timestamp == 0 or timestamp > MAX_U63:
            raise NoteError('cosignature timestamp must be non-zero and below 2^63')
        key.verify(signature[8:], cosigned_message(timestamp, note_text))
        return {'timestamp': timestamp}


class Signer:
    def __init__(self, name: str, sig_type: int, private_key: Ed25519PrivateKey | None = None):
        check_key_name(name)
        if sig_type not in (TYPE_ED25519, TYPE_COSIGNATURE_V1):
            raise NoteError('unsupported signature type')
        self.name, self.sig_type = name, sig_type
        self._key = private_key or Ed25519PrivateKey.generate()
        pub = self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.verifier = Verifier(name, sig_type, pub)

    def signature_line(self, note_text: bytes, timestamp: int | None = None) -> str:
        if self.sig_type == TYPE_ED25519:
            payload = self._key.sign(note_text)
        else:
            if not timestamp or timestamp > MAX_U63:
                raise NoteError('cosignature needs a non-zero timestamp')
            payload = struct.pack('>Q', timestamp) + self._key.sign(cosigned_message(timestamp, note_text))
        return '%s %s %s\n' % (EM_DASH, self.name, b64encode(self.verifier.key_id + payload))


def cosigned_message(timestamp: int, note_text: bytes) -> bytes:
    return b'cosignature/v1\ntime %d\n' % timestamp + note_text


# --- notes ------------------------------------------------------------------------------------

@dataclass(frozen=True)
class SignatureLine:
    name: str
    key_id: bytes
    payload: bytes


@dataclass(frozen=True)
class Note:
    text: bytes
    signatures: Tuple[SignatureLine, ...]


def parse_signature_line(line: str) -> SignatureLine:
    if not line.startswith(EM_DASH + ' '):
        raise NoteError('signature line must start with an em dash and a space')
    fields = line[2:].split(' ')
    if len(fields) != 2:
        raise NoteError('signature line must be "— name signature"')
    name, sig = fields
    check_key_name(name)
    raw = b64decode_canonical(sig)
    if len(raw) < 5:
        raise NoteError('signature too short')
    return SignatureLine(name, raw[:4], raw[4:])


def parse_note(data: bytes) -> Note:
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise NoteError('note is not UTF-8') from exc
    if any(ord(c) < 0x20 and c != '\n' for c in text):
        raise NoteError('control character in note')
    if not text.endswith('\n'):
        raise NoteError('note must end with a newline')
    split = text.rfind('\n\n')
    if split < 0:
        raise NoteError('no blank line before the signatures')
    body, sig_block = text[:split + 1], text[split + 2:]
    lines = sig_block.split('\n')
    if lines[-1] != '' or len(lines) < 2:
        raise NoteError('missing signature lines')
    sigs = tuple(parse_signature_line(line) for line in lines[:-1])
    if len(sigs) > MAX_SIGNATURES:
        raise NoteError('too many signatures')
    return Note(body.encode('utf-8'), sigs)


def verify_note(note: Note, verifiers: Sequence[Verifier]) -> Dict[Verifier, dict]:
    """Verify every signature from a known (name, key ID); return the verified ones.

    Unknown keys are ignored. A known key whose signature fails rejects the whole note,
    and so does a note without any verified signature (signed-note, Signatures).
    """
    known = {(v.name, v.key_id): v for v in verifiers}
    verified: Dict[Verifier, dict] = {}
    for sig in note.signatures:
        verifier = known.get((sig.name, sig.key_id))
        if verifier is None:
            continue
        try:
            verified[verifier] = verifier.verify(note.text, sig.payload)
        except (InvalidSignature, NoteError) as exc:
            raise NoteError('signature from known key %s failed to verify' % sig.name) from exc
    if not verified:
        raise NoteError('no signature from a known key')
    return verified


# --- checkpoints ------------------------------------------------------------------------------

@dataclass(frozen=True)
class Checkpoint:
    origin: str
    size: int
    root: bytes
    extensions: Tuple[str, ...] = ()

    def text(self) -> bytes:
        lines = [self.origin, str(self.size), b64encode(self.root), *self.extensions]
        return ('\n'.join(lines) + '\n').encode('utf-8')


def parse_checkpoint_text(text: bytes) -> Checkpoint:
    lines = text.decode('utf-8').split('\n')
    if lines[-1] != '' or len(lines) < 4 or any(not line for line in lines[:-1]):
        raise NoteError('checkpoint needs at least three non-empty lines')
    origin, size, root, *extensions = lines[:-1]
    check_key_name(origin)
    raw_root = b64decode_canonical(root)
    if len(raw_root) != 32:
        raise NoteError('root hash must be 32 bytes')
    return Checkpoint(origin, parse_decimal(size), raw_root, tuple(extensions))


def sign_checkpoint(checkpoint: Checkpoint, signers: List[Signer], timestamp: int | None = None) -> bytes:
    text = checkpoint.text()
    return text + b'\n' + ''.join(s.signature_line(text, timestamp) for s in signers).encode('utf-8')
