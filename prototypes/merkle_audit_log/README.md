# RFC 9162 Merkle log prototype (ADR-002)

Not part of any research version and not wired into the anchor. It shows the data structure proposed
in [docs/ADR-002](../../docs/ADR-002_checkpointed-audit-log.md) to replace the full O(n) audit digest
(finding NR-07): an append-only Merkle tree with RFC 9162 §2.1 hashing, inclusion and consistency
proofs, and an O(log n) frontier.

- `merkle_log.py`: tree hash, `inclusion_path` / `consistency_proof`, `verify_inclusion` /
  `verify_consistency` (RFC 9162 §2.1.3.2 / §2.1.4.2), `MerkleLog` with an O(log n) append. Stdlib only.
- `test_merkle_log.py`: tests run in CI.
  - known answers of the RFC's 7-leaf example tree;
  - an independent `hashlib` oracle for the 0x00/0x01 domain separation;
  - exhaustive inclusion and consistency checks for every size up to 64;
  - logarithmic proof sizes;
  - every single-element tamper rejected.
  Mutation checks were run by hand: a swapped hash order, a missing `sn == 0` check and a wrong
  interior prefix each turn the tests red.
- `bench_merkle_log.py`: costs at 1k/10k/100k events, results in
  [verification/2026-10-27_history-scaling](../../verification/2026-10-27_history-scaling/README.md).

A proof alone does not fix the tree size. Checkpoints must bind `(tree_size, root)` together;
`test_proof_alone_does_not_bind_tree_size` documents this.

Run: `python -m unittest -v prototypes/merkle_audit_log/test_merkle_log.py`
