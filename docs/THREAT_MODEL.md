# Threat model and explicit non-protections

This is a summary of what the audits say Equal3 does **not** protect against. It is not a new
threat analysis; every row cites its source in [`reports/audits/`](../reports/audits/). An
independent threat model is itself an open gate (G6).

## Assumed environment of the research code

- One Linux host, trusted filesystem, synthetic data only (`state_store.py` docstring:
  "Single host, trusted filesystem"; all reports: synthetic data).
- Cooperative callers: the guarded facade only helps if **all** writers use it
  (`guarded_store.py` docstring, v0.7.3 audit G-01).
- The witness and its key are *supposed* to live in an independent, non-rollbackable trust
  domain; the local implementations only demonstrate the protocol (`witness.py`,
  `guarded_store.py` docstrings).

## Negative results register (v0.7.21 overall audit, §3)

| No. | Finding / attack | Consequence | Status (v0.7.21) |
|---|---|---|---|
| NR-01 | store, anchor and commit witness are rolled back together | any older valid position is accepted again | P0 open |
| NR-02 | directly importable legacy writer/coordinator paths | witness gate can be bypassed | P0 open |
| NR-03 | signed commit observation is only point-in-time | later DB rollback / TOCTOU possible | P0 open |
| NR-04 | evidence that expired before the CAS | commit floor advanced after the deadline | fixed locally in v0.7.21 |
| NR-05 | witness service and writer on the same UID/host | joint key/data theft | P0 open |
| NR-06 | unattested SQLite 3.46.1 runtime | WAL reset and other old-version problems | P0 open |
| NR-07 | HMAC/audit chains are O(n) | DoS/scaling risk at 10k/100k history | P1 open |
| NR-08 | SHA-256 manifest not independently signed | no supply-chain provenance | P0 open |
| NR-09 | system clock locally manipulable | deadlines abusable despite the check | P0 open |
| NR-10 | DB/logs may disclose request metadata | Swiss FADP and privacy by default not evidenced | P1 open |
| NR-11 | RFC 9162 alone is no complete fork-detection protocol | split view without gossip/monitors | P0 open |
| NR-12 | no real power-loss/fsync fault, no ENOSPC | commit durability unproven | P0 open |

## Additional limits stated by the v0.7.22 re-audit

The request-lineage check of v0.7.22 "does not protect against a joint rollback of all three
databases, compromised keys, a compromised witness, a later fork of the HMAC chain or concurrent
cross-service TOCTOU. Neither Merkle consistency proofs nor independent reviewers were
implemented." (`AUDIT_V0722.md`, translated.) The bundle README adds: no protection against
same-key forgery, time/source compromise, or bypass through legacy API/imports.

## Earlier register (2026-10-17, historical)

The first overall audit (`EQUAL3_GESAMTAUDIT_2026-10-17.md`) listed EQ-P0-01 plaintext
snapshots/backups, EQ-P0-02 missing independently enforced monotonic anchor, EQ-P0-03 no VFS
torn-sector simulation, EQ-P0-04 no coverage-guided fuzzing or external pen-test, EQ-P0-05 no key
lifecycle/rotation/revocation, EQ-P1-06 orphan plaintext backup temp files, EQ-P1-07 encoder
cost vs. bit savings, EQ-P1-08 unlimited receipt growth and actor metadata, EQ-P1-09 single BLOB
up to 8 MiB, EQ-P2-10 pixel codecs not implemented. Later rounds addressed parts of EQ-P0-05
(rotation research) and EQ-P0-02 (witness research) without closing them.

## Explicitly out of scope of every round

- Production data, personal data, health data (all rounds: synthetic data only).
- Root / same-UID attackers, host compromise, NFS, path TOCTOU (v0.7.3 audit G-07).
- Physical power loss, torn sectors, untrusted SQLite files, independent external attestation
  (v0.7.3 audit NR-04).
- Confidentiality at rest: store, WAL/journal, snapshots and backups are plaintext
  (EQ-P0-01; v0.7.22 open P0 "encryption including backups and journals").

## Test keys

All keys in the repository are synthetic (see README, "Test material"). Ed25519 keys are generated
at test run time; HMAC keys are fixed byte strings such as `b'K'*32`. None protect anything.
