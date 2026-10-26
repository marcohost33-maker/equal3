# Equal3 v0.7.11 — release-gated roadmap (2026-10-25)

## G0 [P0] SQLite 3.54.1 full-runtime source + binary attestation (OPEN)
- Operator obtain official amalgamation package through independently secured channel. Verify archive SHA3-256 `92281c86e2957f9b9305890f9ac04204caa7b677cc868dc326d942689df28e30`, `sqlite3.c` SHA3-256 `e2b869d3003b33c942b7dd7063604fbc53553e1b66609570df39b9b7b558ee81`, and source ID `2026-10-16 14:45:20 555e07ef33f69a0957d24d8e555b702464a131d6f1607f4c3c1e4551e8e6ca76` (SQLite release documentation).
- Compile in isolated reproducible container, pin compiler and compile options; compare before/after ABI; review build provenance and SBOM. No interactive trust-on-first-use.
- New Python process with fixed known lib mapping must show actual `sqlite3.sqlite_version`, `sqlite_source_id`, loaded library sha256, dev/inode; validate ABI and Linux distro. Run original and new full suite with simultaneous WAL writer/checkpointer processes and fault lab.
- Independent release issuer must sign a narrowly scoped deployment approval with externally managed Ed25519 private key and externally pinned verification key. Approval expires after at most 30 days. Signed authorization is only one prerequisite; never a global GO.

## G1 [P0] complete writer/anchor process separation (OPEN)
- Immutable signed runtime policy only at privileged writer entry point; prevent direct `StateStore` path bypass via filesystem and key ACLs. Protected OS identities, seccomp/AppArmor/SELinux policies, ptrace/core-dump restrictions, and IPC peer credentials. Separate host/admin domain for external monotonic anchor; operator-generated policy cannot establish independent trust.

## G2 [P0] database/commit crash safety (OPEN)
- Partition-aware monotonic CAS + signed external attestation + unambiguous response/replay recovery; injected lost and reordered messages; WAL/VFS fsync fault simulation; genuine power-loss rig; cold restore joint rollback counterexample.

## G3 [P0] confidentiality and compliance (OPEN)
- Authenticated encryption for live SQLite/sidecars/temp/backups and keys, leakage budget, per-host key management, log minimization, lifecycle/retention; DSG/DSFA conditional on actual datasets; independent signoff.

## G4 [P1] latency and memory (OPEN)
- Existing full HMAC receipt/nonce-history verification is O(N). Benchmark n={1,100,1000,10000}, paired ABBA time/CPU/RSS, verified checkpoints with independent attestation. No reverting replay safety to improve speed.

**Stop:** Research package may NOT be deployed or merged as production code until independent release board signs off every P0 gate with fresh evidence.

## G0a [P1 after G0] Standard supply-chain attestation
Prefer SLSA in-toto provenance v1 and verified issuer/builder identities (or Sigstore bundle and separately trusted identity); the local raw Ed25519 policy is a limited operational gate only, not full build provenance. See https://slsa.dev/spec/v1.1/provenance and https://docs.sigstore.dev/quickstart/quickstart-cosign/ .
