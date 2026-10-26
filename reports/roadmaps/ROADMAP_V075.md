# Equal3 v0.7.5 — risk-prioritized roadmap and acceptance gates

Every item is OPEN unless separately evidenced by a signed/pinned artifact. No GitHub push, merge or deployment by this delivery.

| Rank | Item | Strict acceptance oracle | Dependencies |
|---|---|---|---|
| P0 | Durable independent anchor backend | Service outside shared rollback domain; monotonic atomic compare-and-swap; persistent journal; authentication/authorization; restart, fork and joint rollback adversarial tests; independent attestation | Secret manager, deployment identity |
| P0 | Sole-writer capability | OS file permissions/proc identity isolate SQLite/keys; no client can open raw DB or call raw writer; fork and symlink tests on target OS | Platform deployment design |
| P0 | Independent commit proof | Cryptographic service-side verification of prepared intent and independently attested SQLite outcome, crash-safe RECONCILE; signed/manual policy only for indeterminate cases | Anchor backend and writer service |
| P0 | Encryption and key lifecycle | Authenticated at-rest protection for DB/WAL/SHM/temp/backup with established engine or volume policy; key rotation, revocation, restore and dump tests | Threat model; approved key store |
| P0 | Powercut/crash VFS | SQLite C crash VFS test harness with reordered/partial writes, injected sync/space faults; old-or-new invariants checked over corpus and supported hardware | Isolated filesystem/VM lab |
| P0 | Independent security verdict | Third-party review, exploitation attempts and signed release attestation linked to precise source SHA | All above |
| P1 | Protocol formal model | TLA+/PlusCal/Apalache model; safety properties single writer, monotonicity, no unauthorized finalize, eventual recovery only under fairness; check counterexamples | Stable backend API |
| P1 | Performance & bounded audit | Define SLO, N>=1000 per method on controlled host, P50/P95/P99, CI and baseline; remove O(n) per-write verification without weakening audit proofs | Trusted checkpoints design |
| P1 | Stateful fuzz | Coverage-guided mutation of intents, proposals, witness and DB schemas including crash/restart/snapshot restores; corpus replay | Test harness |
| P1 | Legacy V1 migration | Independently attested source hash + explicit approval; copy/backup/read-only migration; no silent HMAC retrofitting | External anchor |
| P2 | Compression/image research | Common test corpus including headers, RAM, CPU, energy and reversibility, against PNG/JPEG XL/zstd in supported versions | Benchmark specification |

**Priority for immediate next sprint:** make the independent anchor and writer identities real before optimizing cryptographic verification. The current simulator is a correct *model within stated assumptions*, not the P0 deliverable.
