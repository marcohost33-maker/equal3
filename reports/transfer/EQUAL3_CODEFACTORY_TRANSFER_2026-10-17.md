# === → CodeFactory — reusable reference modules & contracts (2026-10-17)

## Modules (read-only knowledge transfer; no git commits)
1. `witness.py` — canonical authenticated checkpoint: `Checkpoint`, `initialize`, `read_witness`, `assess`, `advance`; **NOT** deploy until external trust boundary specified.
2. `test_fault_lab.py` — subprocess crash oracle verifies state+receipt old-or-new, seven hooks. Library candidate: generic `FaultCampaign` injector.
3. `state_store.py` — optimistic CAS, receipt idempotency, SQLite WAL FULL, backup_verification (reference only).
4. `equal3.py` — chunked codec RAW, SAME, SPARSE, ZLIB, XOR_ZLIB, authenticated parse; research only.
5. `info_theory.py` — Shannon and conditional entropy estimation; model assumptions must be stated.
6. `minimalmaschine.py` — a tiny SUBLEQ interpreter for formal operation semantics.
7. `benchmark_witness.py` — metrics with n/median/p95 and effect sizes; add host fingerprint to production benchmark harness.

## Contracts / Integrations
`verify(store)` checks current SQLite invariants. `assess(store,witness,key)` yields MATCH or typed exception (RollbackDetected/ForkDetected/AheadOfWitness). `advance` runs **after** DB commit; separate commit uncertainty requires recovery policy. Inputs bounded / secrets not embedded in artifacts. For host-critical systems, replace witness file with KMS/HSM/transparency service or TPM monotonic state.

## Security & governance gates
Require deterministic pinned source digest, reproducible tests, no pure-assert runtime guards, independent reviewer, signed provenance, no GitHub push by assistant, no auto-promote to product. Source may serve as design reference not certified component. Zero sensitive sample data in publications.

## Key algorithms & workflow
Information bottleneck = optimize C=(transferred bits, encode time, decode time, peak-RSS, energy, verifiability). Adopt `Compare-and-Swap + idempotency receipt + external witness`. Pair each positive claim with a falsifying counterexample. Maintain PR/NR (positive/negative results) separately from GitHub PR requests.
