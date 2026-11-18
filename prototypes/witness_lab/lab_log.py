"""A log operator and a client for the witness lab (prototype, see README).

LabLog plays the role an Equal3 anchor would take under ADR-002: audit events become leaves,
the operator signs checkpoints with its Ed25519 log key (type 0x01) and asks witnesses to
cosign them. Its whole state can be snapshotted and restored to model the joint local
rollback of finding NR-01.

Client policy: a checkpoint is accepted only with a valid log signature AND cosignatures from
at least `quorum` distinct trusted witnesses, and it must be consistent with the largest
checkpoint the client accepted before.

Freshness (optional, `Freshness`): a cosignature states what the witness had seen at its
timestamp. C2SP tlog-cosignature only says that verifiers MAY reject timestamps in the future;
how old a cosignature may be is left to the client. With a `Freshness` policy only cosignatures
with  now - max_age <= timestamp <= now + max_future  count towards the quorum, so a replayed
old checkpoint, whose signatures are all genuine, no longer satisfies a client whose own state
was rolled back. `now` comes from the caller: the bound is only as good as that clock.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Sequence

import note as n

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'merkle_audit_log'))
import merkle_log  # noqa: E402


class LabLog:
    def __init__(self, origin: str, signer: n.Signer | None = None):
        self.origin = origin
        self.signer = signer or n.Signer(origin, n.TYPE_ED25519)
        self.tree = merkle_log.MerkleLog()
        self.cosignatures: Dict[int, List[str]] = {}

    def append(self, *events: bytes) -> None:
        for event in events:
            self.tree.append(event)

    def checkpoint(self) -> n.Checkpoint:
        size, root = self.tree.checkpoint()
        return n.Checkpoint(self.origin, size, root)

    def signed_checkpoint(self) -> bytes:
        return n.sign_checkpoint(self.checkpoint(), [self.signer])

    def request_for(self, old_size: int) -> bytes:
        from witness import build_request
        # no proof for old size 0, an unchanged size, or (to exercise the witness's 400) a larger one
        proof = [] if old_size == 0 or old_size >= len(self.tree) else self.tree.consistency_proof(old_size)
        return build_request(old_size, proof, self.signed_checkpoint())

    def snapshot(self) -> 'LabLog':
        """Copy of the log state (same signing key), as a backup restore would produce."""
        copy = LabLog(self.origin, self.signer)
        copy.tree.leaves = list(self.tree.leaves)
        copy.tree._frontier = list(self.tree._frontier)
        return copy


@dataclass
class ClientState:
    size: int = 0
    root: bytes = merkle_log.mth([])


class RollbackDetected(Exception):
    pass


class StaleCosignatures(n.NoteError):
    """Enough valid witness cosignatures, but too few inside the freshness window."""


@dataclass(frozen=True)
class Freshness:
    """Seconds since the UNIX epoch, like the cosignature timestamp. Both bounds are inclusive."""
    now: int
    max_age: int
    max_future: int = 0

    def __post_init__(self):
        for field in ('now', 'max_age', 'max_future'):
            value = getattr(self, field)
            if type(value) is not int or value < 0 or value > n.MAX_U63:
                raise ValueError('%s must be a non-negative integer below 2^63' % field)
        if self.now == 0:
            raise ValueError('now must be a real time, not zero')

    def admits(self, timestamp: int) -> bool:
        return self.now - self.max_age <= timestamp <= self.now + self.max_future


def accept_checkpoint(state: ClientState, signed: bytes, log_key: n.Verifier, witnesses: Sequence[n.Verifier],
                      quorum: int, proof: Sequence[bytes], freshness: Freshness | None = None) -> ClientState:
    """Return the new client state, or raise if the checkpoint must not be trusted.

    Without `freshness` the cosignature timestamps are not bounded (replay of an old,
    genuinely cosigned checkpoint is then accepted by a client with rolled-back state).
    """
    note = n.parse_note(signed)
    checkpoint = n.parse_checkpoint_text(note.text)
    verified = n.verify_note(note, [log_key, *witnesses])
    if log_key not in verified:
        raise n.NoteError('no valid log signature')
    cosigned = {v.name: info['timestamp'] for v, info in verified.items()
                if v.sig_type == n.TYPE_COSIGNATURE_V1}
    if len(cosigned) < quorum:
        raise n.NoteError('%d of %d required witness cosignatures' % (len(cosigned), quorum))
    if freshness is not None:
        fresh = {name for name, timestamp in cosigned.items() if freshness.admits(timestamp)}
        if len(fresh) < quorum:
            outside = ', '.join('%s (time %d)' % (name, cosigned[name]) for name in sorted(set(cosigned) - fresh))
            raise StaleCosignatures('%d of %d required witness cosignatures inside [%d, %d]; outside: %s' % (
                len(fresh), quorum, freshness.now - freshness.max_age, freshness.now + freshness.max_future,
                outside))
    if checkpoint.size < state.size:
        raise RollbackDetected('checkpoint size %d below accepted size %d' % (checkpoint.size, state.size))
    if state.size and not merkle_log.verify_consistency(state.size, checkpoint.size, state.root, checkpoint.root,
                                                        proof):
        raise RollbackDetected('checkpoint not consistent with the accepted one (fork or rewritten history)')
    return ClientState(checkpoint.size, checkpoint.root)
