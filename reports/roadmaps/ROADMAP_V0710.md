# Equal3 – next technical gates after 0.7.10 (2026-10-25)

## Priority P0: mandatory release hold

1. **G0 supply-chain:** fetch official SQLite 3.54.1 artifact from sqlite.org, verify official SHA3-256 and `sqlite_source_id`, compile hermetically for actual target interpreter/OS; attest runtime mapping, reproducible build, SBOM, provenance. Local installation of the patch was NOT accomplished here; existing 3.46.1 is still blocked. Upstream SHA3 matches source but is not an independent signature of package owner.
2. **G1 full WAL matrix:** run both store and checkpoint tests, simultaneous connections, and failure injection on the patched effective library (not merely `_sqlite3` extension). Strong stress under contention; investigate TOCTOU on DB/WAL/SHM paths.
3. **G2 independent anchor:** separate administration/OS host/rollback namespace, least privilege, monotonic HSM/KMS external state, signed receipts, independent reviewer approval and fork/rollback fault cases; no auto reconciliation.
4. **G3 storage/keys:** authenticated data encryption, SQLite WAL/journals/temp/backups, secret rotation and restore; test deletion and access controls under compromised writer.
5. **G4 physical fault/security:** isolated crash-testing VFS, power cuts, fsync failures, ENOSPC, concurrent checkpoint, torn writes; independent pentest & privacy governance.

## P1 performance

6. Current `StateStore.receipt()` and repeated `apply()` verify the whole history. Pre-register P50/P95/P99 and memory budgets at N={1,100,1000,10000}. Do not weaken checks to remove regression. Evaluate **authenticated external checkpoint + per-receipt proof** against falsification from reordered/deleted old receipts, revoked and rolled-back checkpoints, replays.
7. Preserve both trusted and untrusted read API semantics, document what authenticates against joint database/Witness rollback; avoid ambiguous boolean success status.
8. Independent cross-runtime tests on Linux/Windows/macOS with appropriate effective binary provenance and explicit unsupported-platform HOLD.

## P2 research scope

Bit/entropy image-codec and incremental compression improvements remain separate from trust/correctness architecture.

**No production release, GitHub push/merge, or central compliance sheet update.**
