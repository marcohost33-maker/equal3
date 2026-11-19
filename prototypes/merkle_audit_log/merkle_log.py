"""RFC 9162 section 2.1 Merkle tree log: tree hash, inclusion and consistency proofs.

Prototype for Equal3 roadmap P1 / finding NR-07 (see docs/ADR-002). It is NOT
part of any research version and is not wired into the anchor: it shows the
data structure that would replace the full O(n) audit digest with O(log n)
appends and proofs, and that external witnesses can check (P0-3).

Definitions (RFC 9162 section 2.1.1), SHA-256:
  MTH({})        = HASH()
  MTH({d0})      = HASH(0x00 || d0)                 leaf hash
  MTH(D[n])      = HASH(0x01 || MTH(D[0:k]) || MTH(D[k:n])),  k largest power of 2 < n
Proof generation follows PATH (2.1.3.1) and PROOF/SUBPROOF (2.1.4.1); verification
follows the algorithms of 2.1.3.2 and 2.1.4.2. Stdlib only.
"""
from __future__ import annotations

import hashlib
from typing import List, Sequence

HASH_SIZE = 32


class ProofError(ValueError):
    pass


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b'\x00' + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b'\x01' + left + right).digest()


def _split(n: int) -> int:
    """Largest power of two strictly smaller than n (n > 1)."""
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


def mth(leaf_hashes: Sequence[bytes]) -> bytes:
    """Merkle Tree Hash over already-hashed leaves."""
    n = len(leaf_hashes)
    if n == 0:
        return hashlib.sha256(b'').digest()
    if n == 1:
        return leaf_hashes[0]
    k = _split(n)
    return node_hash(mth(leaf_hashes[:k]), mth(leaf_hashes[k:]))


def inclusion_path(index: int, leaf_hashes: Sequence[bytes]) -> List[bytes]:
    """PATH(m, D[n]) of RFC 9162 2.1.3.1."""
    n = len(leaf_hashes)
    if not 0 <= index < n:
        raise ProofError('leaf index outside tree')
    if n == 1:
        return []
    k = _split(n)
    if index < k:
        return inclusion_path(index, leaf_hashes[:k]) + [mth(leaf_hashes[k:])]
    return inclusion_path(index - k, leaf_hashes[k:]) + [mth(leaf_hashes[:k])]


def _subproof(m: int, leaves: Sequence[bytes], complete: bool) -> List[bytes]:
    n = len(leaves)
    if m == n:
        return [] if complete else [mth(leaves)]
    k = _split(n)
    if m <= k:
        return _subproof(m, leaves[:k], complete) + [mth(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [mth(leaves[:k])]


def consistency_proof(first: int, leaf_hashes: Sequence[bytes]) -> List[bytes]:
    """PROOF(m, D[n]) of RFC 9162 2.1.4.1 for 0 < m <= n."""
    if not 0 < first <= len(leaf_hashes):
        raise ProofError('first tree size must satisfy 0 < first <= second')
    return _subproof(first, leaf_hashes, True)


def _check_hashes(values) -> None:
    if any(type(v) is not bytes or len(v) != HASH_SIZE for v in values):
        raise ProofError('every hash must be 32 bytes')


def verify_inclusion(index: int, tree_size: int, leaf: bytes, path: Sequence[bytes], root: bytes) -> bool:
    """RFC 9162 2.1.3.2. Returns True only for a valid proof; never raises on bad proofs."""
    try:
        _check_hashes([leaf, root, *path])
    except ProofError:
        return False
    if not 0 <= index < tree_size:
        return False
    fn, sn, r = index, tree_size - 1, leaf
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_consistency(first: int, second: int, first_root: bytes, second_root: bytes,
                       proof: Sequence[bytes]) -> bool:
    """RFC 9162 2.1.4.2. Returns True only for a valid proof; never raises on bad proofs."""
    try:
        _check_hashes([first_root, second_root, *proof])
    except ProofError:
        return False
    if not 0 < first <= second:
        return False
    if first == second:
        return not proof and first_root == second_root
    if not proof:
        return False
    path = list(proof)
    if first & (first - 1) == 0:  # exact power of two: the first tree is a node of the second
        path.insert(0, first_root)
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == first_root and sr == second_root


class MerkleLog:
    """Append-only log with an O(log n) frontier of perfect subtrees.

    append() and root() cost O(log n) hash operations; the leaf hashes are kept
    only to generate proofs. A verifier that holds a previous (size, root)
    checkpoint checks growth with verify_consistency() in O(log n).
    """

    def __init__(self):
        self.leaves: List[bytes] = []
        self._frontier: List[tuple] = []  # (subtree size, hash), sizes strictly decreasing

    def __len__(self) -> int:
        return len(self.leaves)

    def append(self, data: bytes) -> int:
        h = leaf_hash(data)
        self.leaves.append(h)
        size = 1
        while self._frontier and self._frontier[-1][0] == size:
            left_size, left = self._frontier.pop()
            h, size = node_hash(left, h), left_size + size
        self._frontier.append((size, h))
        return len(self.leaves) - 1

    def root(self) -> bytes:
        if not self._frontier:
            return mth([])
        h = self._frontier[-1][1]
        for _, left in reversed(self._frontier[:-1]):
            h = node_hash(left, h)
        return h

    def checkpoint(self) -> tuple:
        return len(self.leaves), self.root()

    def inclusion_proof(self, index: int, tree_size: int | None = None) -> List[bytes]:
        size = len(self.leaves) if tree_size is None else tree_size
        if not 0 < size <= len(self.leaves):
            raise ProofError('tree size outside log')
        return inclusion_path(index, self.leaves[:size])

    def consistency_proof(self, first: int, second: int | None = None) -> List[bytes]:
        size = len(self.leaves) if second is None else second
        if not 0 < size <= len(self.leaves):
            raise ProofError('tree size outside log')
        return consistency_proof(first, self.leaves[:size])
