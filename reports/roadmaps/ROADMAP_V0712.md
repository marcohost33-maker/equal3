# Equal3 v0.7.12 — technical decision roadmap

**Current:** RESEARCH / NO-GO. Do not push, merge, deploy, or expose to real datasets by inference from green unit tests.

1. **P0: Patched SQLite linked in the actual writer and crash-test clients.** Obtain independently verified 3.54.1 source, check upstream ZIP SHA3 `92281c86e2957f9b9305890f9ac04204caa7b677cc868dc326d942689df28e30`, `sqlite3.c` SHA3 `e2b869d3003b33c942b7dd7063604fbc53553e1b66609570df39b9b7b558ee81`. Compile in dedicated environment. At process startup pin file identity, `.so` hash, source ID, compiler flags and isolated policy signer; run full suite + multi-process WAL writer/checkpointer test. No downloaded source/build was available in this session.
2. **P0: Mandatory secure writer service.** Introduce separately owned OS identity for SQLite store and keys, prevent direct raw StateStore file access for clients, enforce signed runtime policy on privileged process startup, block untrusted API bypass; test as unprivileged client, not just as root.
3. **P0: Independent anchor.** External persistent monotonic CAS in independently administered trust domain; verify cross-host joint rollback and partition/replay faults. Keep recovery and manual adjudication fail-closed.
4. **P0: Confidentiality/faults.** Encrypt actual DB, WAL/SHM/temp and backups with lifecycle/retention, secure keys and privileged access. Physical power-loss / SQLite VFS adversarial tests, then external review.
5. **P1: Authenticated checkpoint efficiency.** Current full-history read is O(N) and in n=250 microbenchmark about 9.7× slower than previous unauthenticated read. Explore HMAC-chain-signed checkpoints/append-only proofs with independent root, version binding, bounded validation and mutation tests. Never restore hash-only read.
6. **P1: Legacy migration.** Signed independent v1 source attestations, separate read-only compatibility path with explicit `LEGACY_UNSEALED`; never mark legacy `MATCH` or use old data to authorize new transactions without trusted migration.

**Acceptance:** Each gate needs SHA-bound code, negative-first tests, environmental inventory, independent reviewer signoff, explicit report. No production GO in this bundle.
