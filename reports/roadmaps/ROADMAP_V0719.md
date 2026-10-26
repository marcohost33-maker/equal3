# Equal3 v0.7.19 – updated staged roadmap

| Gate | Next step | Required acceptance evidence | State |
|---|---|---|---|
| G2a Protocol | signed nonce fresh read + monotone root signed epoch CAS | malicious replay, old signer, split recovery, 26 new tests | RESEARCH IMPLEMENTED |
| G2b Independence | deploy witness with its own admin, host, OS identity and rollback-proof monotonic storage | joint rollback of Store+Anchor detected by external witness maintained independently; rollback of witness prevented/alerted | P0 OPEN |
| G2c Commit registry | record version+digest+store+request ID under independently verified commits; enforce monotonic CAS and log proof | rollback of commits without epoch rotation detected, fail-closed on outage; crash/TOCTOU | P0 OPEN |
| G3 Recovery | durable two-party commit + evidence and manual adjudication | each phase fault-injected, stale attestations rejected | P0 OPEN |
| G1 Root governance | offline root and witness key ceremonies, quorum, approvals and recovery | provable independent identity and actual revocation | P0 OPEN |
| G4 SQLite | patched library artifact actually downloaded, verified, loaded in child process | SHA3 source provenance and complete regression, powercut | P0 OPEN |
| G5 OS isolation | cross-host TLS/mTLS, ACL, MAC, hardening and key protection | two-UID plus independently administered host failover evidence | P0 OPEN |
| G6 Storage | confidentiality of DB, journal, backup; retention and erasure | policy/DSG Swiss review and key lifecycle | P0 OPEN |
| G7 Fault lab | poweroff, fsync, ENOSPC, corrupted filesystems, split-brain, time rollback | reproducible lab and independent security review | P0 OPEN |
| G8 Performance | 10k/100k histories, p50/p95/p99, throughput, capacity, full IPC | neutral repeatable B/A balanced workloads | P1 OPEN |

**Release status: NO-GO.** Strict research-only. No repository changes and no automatic local-to-remote migration.
