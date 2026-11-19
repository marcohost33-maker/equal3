"""Tests for merkle_log.py (stdlib unittest).

Known answers: the 7-leaf example tree of RFC 9162 section 2.1.5
(leaves d0..d6, nodes a..f, j leaves; g=(a,b) h=(c,d) i=(e,f) k=(g,h) l=(i,j)):
  inclusion  d0 -> [b, h, l]   d3 -> [c, g, l]   d4 -> [f, j, k]   d6 -> [i, k]
  consistency  3 -> 7: [c, d, g, l]   4 -> 7: [l]   6 -> 7: [i, j, k]
Then exhaustive checks for every tree size up to 64 and every index / first
size, and negative checks that every single-element tamper is rejected.
Run: python -m unittest -v prototypes/merkle_audit_log/test_merkle_log.py
"""
import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import merkle_log as ml  # noqa: E402

DATA = [b'd%d' % i for i in range(7)]


class Rfc9162ExampleTree(unittest.TestCase):
    def setUp(self):
        a, b, c, d, e, f, j = (ml.leaf_hash(x) for x in DATA)
        g, h, i = ml.node_hash(a, b), ml.node_hash(c, d), ml.node_hash(e, f)
        k, l = ml.node_hash(g, h), ml.node_hash(i, j)
        self.n = dict(a=a, b=b, c=c, d=d, e=e, f=f, j=j, g=g, h=h, i=i, k=k, l=l)
        self.root = ml.node_hash(k, l)
        self.leaves = [a, b, c, d, e, f, j]

    def names(self, *keys):
        return [self.n[x] for x in keys]

    def test_tree_hash(self):
        self.assertEqual(ml.mth(self.leaves), self.root)
        log = ml.MerkleLog()
        for x in DATA:
            log.append(x)
        self.assertEqual(log.checkpoint(), (7, self.root))

    def test_inclusion_paths(self):
        for index, expected in ((0, 'bhl'), (3, 'cgl'), (4, 'fjk'), (6, 'ik')):
            path = ml.inclusion_path(index, self.leaves)
            self.assertEqual(path, self.names(*expected), index)
            self.assertTrue(ml.verify_inclusion(index, 7, self.leaves[index], path, self.root))

    def test_consistency_proofs(self):
        for first, expected in ((3, 'cdgl'), (4, 'l'), (6, 'ijk')):
            proof = ml.consistency_proof(first, self.leaves)
            self.assertEqual(proof, self.names(*expected), first)
            self.assertTrue(ml.verify_consistency(first, 7, ml.mth(self.leaves[:first]), self.root, proof))


class IndependentOracle(unittest.TestCase):
    """Expected values computed with hashlib straight from the RFC 9162 definitions, not with
    merkle_log helpers, so a wrong domain-separation byte cannot confirm itself."""

    @staticmethod
    def sha(data):
        return hashlib.sha256(data).digest()

    def test_leaf_and_node_domain_separation(self):
        leaf = self.sha(b'\x00' + b'd0')
        self.assertEqual(ml.leaf_hash(b'd0'), leaf)
        self.assertEqual(ml.node_hash(leaf, leaf), self.sha(b'\x01' + leaf + leaf))
        self.assertNotEqual(ml.node_hash(leaf, leaf), self.sha(b'\x00' + leaf + leaf))

    def test_three_leaf_tree_root(self):
        l0, l1, l2 = (self.sha(b'\x00' + x) for x in (b'd0', b'd1', b'd2'))
        expected = self.sha(b'\x01' + self.sha(b'\x01' + l0 + l1) + l2)  # k = 2 for n = 3
        log = ml.MerkleLog()
        for x in (b'd0', b'd1', b'd2'):
            log.append(x)
        self.assertEqual(log.root(), expected)
        self.assertEqual(ml.mth([l0, l1, l2]), expected)


class Exhaustive(unittest.TestCase):
    MAX = 64

    @classmethod
    def setUpClass(cls):
        cls.log = ml.MerkleLog()
        cls.roots = {}
        for i in range(cls.MAX):
            cls.log.append(b'event-%d' % i)
            cls.roots[i + 1] = cls.log.root()

    def test_incremental_root_equals_definition(self):
        for size, root in self.roots.items():
            self.assertEqual(root, ml.mth(self.log.leaves[:size]), size)

    def test_every_inclusion_proof_verifies(self):
        for size in range(1, self.MAX + 1):
            for index in range(size):
                path = self.log.inclusion_proof(index, size)
                self.assertTrue(ml.verify_inclusion(index, size, self.log.leaves[index], path, self.roots[size]),
                                (index, size))

    def test_every_consistency_proof_verifies(self):
        for second in range(1, self.MAX + 1):
            for first in range(1, second + 1):
                proof = self.log.consistency_proof(first, second)
                self.assertTrue(ml.verify_consistency(first, second, self.roots[first], self.roots[second], proof),
                                (first, second))

    def test_proof_sizes_are_logarithmic(self):
        for size in range(2, self.MAX + 1):
            bound = (size - 1).bit_length()  # ceil(log2(size))
            for index in range(size):
                self.assertLessEqual(len(self.log.inclusion_proof(index, size)), bound)
            for first in range(1, size):
                self.assertLessEqual(len(self.log.consistency_proof(first, size)), bound + 1)


def _flip(h: bytes) -> bytes:
    return bytes([h[0] ^ 1]) + h[1:]


class Tampering(unittest.TestCase):
    SIZE = 21

    @classmethod
    def setUpClass(cls):
        cls.log = ml.MerkleLog()
        for i in range(cls.SIZE):
            cls.log.append(b'e%d' % i)
        cls.root = cls.log.root()
        cls.root22 = ml.mth(cls.log.leaves + [ml.leaf_hash(b'e21')])

    def test_proof_alone_does_not_bind_tree_size(self):
        # documents the property the checkpoint design relies on (see docs/ADR-002)
        accepted = [i for i in range(self.SIZE) if ml.verify_inclusion(
            i, self.SIZE + 1, self.log.leaves[i], self.log.inclusion_proof(i), self.root)]
        self.assertTrue(accepted, 'expected shape-equal sizes for some indices')

    def test_inclusion_rejects_every_single_change(self):
        for index in range(self.SIZE):
            leaf, path = self.log.leaves[index], self.log.inclusion_proof(index)
            self.assertFalse(ml.verify_inclusion(index, self.SIZE, _flip(leaf), path, self.root))
            self.assertFalse(ml.verify_inclusion(index, self.SIZE, leaf, path, _flip(self.root)))
            for pos in range(len(path)):
                bad = list(path)
                bad[pos] = _flip(bad[pos])
                self.assertFalse(ml.verify_inclusion(index, self.SIZE, leaf, bad, self.root), (index, pos))
            for wrong in {index - 1, index + 1} & set(range(self.SIZE)):
                self.assertFalse(ml.verify_inclusion(wrong, self.SIZE, leaf, path, self.root), (index, wrong))
            self.assertFalse(ml.verify_inclusion(index, self.SIZE, leaf, path[:-1], self.root))
            self.assertFalse(ml.verify_inclusion(index, self.SIZE, leaf, path + [self.root], self.root))
            # A proof does not bind the tree size by itself (RFC 9162 derives only the path shape
            # from it): sizes 21 and 22 share the shape for many indices. What binds is the
            # (size, root) pair of a checkpoint; against the real root of size 22 it must fail.
            self.assertFalse(ml.verify_inclusion(index, self.SIZE + 1, leaf, path, self.root22), index)

    def test_consistency_rejects_every_single_change(self):
        for first in range(1, self.SIZE):
            old = ml.mth(self.log.leaves[:first])
            proof = self.log.consistency_proof(first)
            self.assertFalse(ml.verify_consistency(first, self.SIZE, _flip(old), self.root, proof), first)
            self.assertFalse(ml.verify_consistency(first, self.SIZE, old, _flip(self.root), proof), first)
            for pos in range(len(proof)):
                bad = list(proof)
                bad[pos] = _flip(bad[pos])
                self.assertFalse(ml.verify_consistency(first, self.SIZE, old, self.root, bad), (first, pos))
            self.assertFalse(ml.verify_consistency(first, self.SIZE, old, self.root, proof[:-1]), first)
            self.assertFalse(ml.verify_consistency(first, self.SIZE + 1, old, self.root22, proof), first)

    def test_rewritten_history_is_not_consistent(self):
        # a log that rewrote one early event cannot prove consistency with the old checkpoint
        old_size, old_root = 10, ml.mth(self.log.leaves[:10])
        forged = ml.MerkleLog()
        for i in range(self.SIZE):
            forged.append(b'X' if i == 3 else b'e%d' % i)
        proof = forged.consistency_proof(old_size)
        self.assertFalse(ml.verify_consistency(old_size, self.SIZE, old_root, forged.root(), proof))

    def test_malformed_inputs(self):
        path = self.log.inclusion_proof(0)
        self.assertFalse(ml.verify_inclusion(0, self.SIZE, b'short', path, self.root))
        self.assertFalse(ml.verify_inclusion(-1, self.SIZE, self.log.leaves[0], path, self.root))
        self.assertFalse(ml.verify_consistency(0, self.SIZE, self.root, self.root, []))
        self.assertFalse(ml.verify_consistency(5, 4, self.root, self.root, [self.root]))
        self.assertTrue(ml.verify_consistency(self.SIZE, self.SIZE, self.root, self.root, []))
        self.assertFalse(ml.verify_consistency(self.SIZE, self.SIZE, self.root, self.root, [self.root]))
        with self.assertRaises(ml.ProofError):
            self.log.inclusion_proof(self.SIZE)
        with self.assertRaises(ml.ProofError):
            ml.consistency_proof(0, self.log.leaves)

    def test_empty_tree_hash(self):
        self.assertEqual(ml.MerkleLog().root(), hashlib.sha256(b'').digest())


if __name__ == '__main__':
    unittest.main()
