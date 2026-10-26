# Equal3 v0.7.10 — Compliance matrix draft, not merged

| ID | Control | State | Required evidence |
|--|--|--|--|
| EQ710-01 | Authenticated receipt and idempotent replay | Local software control PASS | Negative-first output + 13 added tests |
| EQ710-02 | Runtime SQLite WAL defect & verified build provenance | OPEN P0 | official release source, signed independent attestation, effective loaded shared object, full regression |
| EQ710-03 | Historical v1 unsealed records | HOLD | external historical attestation and migration |
| EQ710-04 | Privacy + storage encryption | OPEN P0 | state, WAL, backup/sidecar encryption, key lifecycle, DSFA depending on personal data |
| EQ710-05 | Separate rollback domains | OPEN P0 | administrator fault test, external monotonic CAS, no shared snapshot |
| EQ710-06 | Reproducibility/supply chain | PARTIAL | local file hashes only, no independent signing |
| EQ710-07 | Verification scale | OPEN P1 | authenticated checkpoint and complete falsification suite |

No live personal data used. No central Google Sheet modified in this turn.
