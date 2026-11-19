# ADR-002: Replace the full O(n) audit recomputation with an RFC 9162 checkpointed log

- Status: **proposed** (2026-10-27). Not implemented in any research version. Implementation belongs
  in a research round (v0.7.23 or later) with its own manifest, evidence and audit (CONTRIBUTING rule 1).
- Addresses: roadmap P1, finding NR-07 ("HMAC/audit chains are O(n): DoS/scaling risk at 10k/100k").
  Prepares P0-3 (signed checkpoints, inclusion/consistency proofs, independent witness).
- Evidence: [verification/2026-10-27_history-scaling](../verification/2026-10-27_history-scaling/README.md),
  prototype [prototypes/merkle_audit_log](../prototypes/merkle_audit_log/).

## Context

Two checks run over the whole history on every operation:

- `PersistentCASAnchor._audit_digest` (`research/anchor_wire.py`) streams every consumed nonce
  (ordered by nonce value, not by insertion) and every review row into one SHA-256 and binds it
  into the authority seal. It is capped at `MAX_AUDIT_ROWS = 100000`.
- `StateStore.read()` (`research/state_store.py`) re-verifies the whole HMAC receipt chain and runs
  `PRAGMA integrity_check` on every authenticated read.

Measured on 2026-10-27 (exploratory: one machine, N = 30 to 100 per point, nearest-rank
percentiles, so P99 at N = 30 is the maximum, not a tail estimate; Linux, Python 3.13.17, SQLite 3.45.1):

| Operation | 1 000 | 10 000 | 100 000 |
|---|---:|---:|---:|
| anchor audit digest, P50 / P99 (per anchor operation) | 8.4 / 11.8 ms | 74 / 107 ms | 904 / 1 097 ms |
| `StateStore.read()`, P50 / P99 (per authenticated read) | 14.2 / 24.0 ms | 142 / 204 ms | 1 746 / 2 379 ms |

At the cap one anchor operation costs about one second, and one row more turns the anchor into a
permanent HOLD ("operator review required"). With 2 consumed nonces and 1 review row per commit, the
cap is reached after about 33 000 commits. The cap is therefore an availability limit built into the
design, not only a slowdown.

Because the nonces are hashed in nonce order, a new row can land anywhere in the stream; the digest
cannot be updated incrementally. That is why every operation must rescan.

## Decision (proposed)

1. **Append-only Merkle log in insertion order.** Every anchor audit event (consumed nonce,
   review decision) becomes a leaf of an RFC 9162 §2.1 Merkle tree:
   - leaf hash `H(0x00 ‖ canonical_event)`, interior node `H(0x01 ‖ left ‖ right)`;
   - the events get a dense sequence number;
   - the anchor keeps the O(log n) frontier of perfect subtrees.
2. **The seal binds the checkpoint `(tree_size, root)`** instead of a full-scan digest. Each
   operation appends its events and checks the step from the sealed checkpoint to the new one.
   That costs O(log n): the frontier update, or a consistency proof between the two checkpoints.
   **This step alone gives no protection against rewriting history.** Whoever can rewrite the
   ledger and recompute the seal (the local rollback domain of NR-01: same host, same seal key)
   produces a new, self-consistent `(tree_size, root)`. Only a checkpoint kept outside that domain
   (item 4) can contradict it. Locally, the seal only guards against accidental or partial
   corruption, as the full-scan digest does today.
3. **The full audit moves out of the hot path.** A periodic full verification recomputes the root
   from all stored rows and compares it with the sealed checkpoint; a mismatch sets HOLD. Rows that
   an operation actually depends on (e.g. a nonce lookup) are checked by an inclusion proof against
   the sealed root.
4. **Checkpoints leave the rollback domain.** The anchor exports `(origin, tree_size, root)` as a
   signed note in the C2SP tlog-checkpoint style. Independent witnesses keep the latest checkpoint they
   cosigned and accept a new one only with a valid consistency proof (C2SP tlog-cosignature /
   tlog-witness). This is the mechanism P0-3 asks for: a joint rollback of store, anchor and local
   witness (NR-01) produces an older checkpoint that a witness holding a newer one rejects. This only
   helps if a witness outside the local administrative domain is consulted. This ADR does not supply
   that witness. The protocol side is prototyped and lab-tested in
   [prototypes/witness_lab](../prototypes/witness_lab/README.md): joint local rollback reproduced, then
   caught by external witnesses.
5. **The same pattern for `StateStore.read()`.** Seal `(version, chain_tag)` as a checkpoint, verify
   only the tail since the last verified checkpoint per read, and move `PRAGMA integrity_check` and
   the full-chain check to the periodic audit.
6. **Size and root are always signed together.** An inclusion or consistency proof alone does not
   fix the tree size: RFC 9162 verification derives only the shape of the path from the size, and
   sizes 21 and 22 share that shape for many indices (`test_proof_alone_does_not_bind_tree_size`).
   Only the pair inside a seal or signed note binds it.

## Consequences

- Per-operation cost becomes logarithmic. Prototype, verification of a consistency proof from
  10 000 to 100 000 events: P50 about 21 µs with 14 hashes. That is about four orders of magnitude
  below the 904 ms full recomputation at the same size. The 100k cap is no longer needed for
  performance; storage stays O(n).
- **Trade-off, stated plainly:** historical rows are no longer re-proven on every operation.
  Tampering with an old row is detected at the next periodic full audit, or when that row is read
  with an inclusion proof, not at the next operation. The audit interval becomes a security
  parameter. The research's negative-first test for tampered historical rows must move to the
  periodic audit and stay mandatory.
  - The interval must be **derived, not picked**: from the accepted detection window (how long an
    undetected manipulation may persist), the recovery point and recovery time objectives (RPO/RTO)
    of the store, and the threat model of who can write the database files.
  - At the measured 9 µs per row, a full audit of 100 000 rows costs about 1 s, so the interval is
    limited by policy, not by cost.
  - This ADR leaves the number open on purpose; the implementing round must justify it.
- Event ordering changes from "sorted by nonce" to "insertion order". This is a format change and
  needs a migration with an explicit checkpoint of the migrated history.
- Proof generation in the prototype recomputes subtree hashes (O(n)). An implementation stores
  interior nodes (or the tile layout used by static transparency logs) to make proofs O(log n).

## Acceptance tests for the research round that implements it

- Known answers of the RFC 9162 example tree, plus exhaustive inclusion/consistency checks up to at
  least 64 leaves (as in the prototype). Mutation checks must kill a swapped hash order, a
  missing `sn == 0` check and a wrong domain-separation byte.
- Negative-first:
  - a tampered historical row passes per-operation checks but fails the periodic audit and the
    inclusion check of that row;
  - a rewritten history fails consistency with an older checkpoint;
  - a rolled-back anchor (store, anchor and local witness restored together) is rejected by a
    witness that holds a newer checkpoint.
- Latency P50/P95/P99 at 10k/100k/1M events, measured with `tools/bench_history_scaling.py`
  extended to the new path, against the numbers above.
- The release decision stays NO-GO until every P0 gate is met. This ADR closes none of them alone.

## References

- RFC 9162, Certificate Transparency Version 2.0, section 2.1 (Merkle tree hash, inclusion and
  consistency proofs). Primary text could not be fetched from this environment; the definitions
  used were cross-checked against secondary sources and against the RFC's own 7-leaf example
  (known-answer tests in the prototype).
- C2SP tlog-checkpoint, tlog-cosignature, tlog-witness (signed checkpoint notes and witness cosigning).
