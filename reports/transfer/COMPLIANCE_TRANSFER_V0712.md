# Equal3 v0.7.12 — suggested compliance matrix entries

These are proposals for the active compliance matrix; **the actual matrix was not modified**.

| ID | Finding | Risk / action | Status |
|---|---|---|---|
| EQ0712-INTEGRITY-HEAD | hash-only `read` accepted forged DB | now authenticated; verify coverage and migration | RESEARCH FIXED |
| EQ0712-GENESIS-BIND | zero-commit authenticated audit accepted forged genesis | current head bound to HMAC genesis | RESEARCH FIXED |
| EQ0712-LEGACY-WITNESS | `LEGACY_UNSEALED` could be reported as witness MATCH | fail closed; independently attested migration | RESEARCH FIXED |
| EQ0712-SQLITE-G0 | current SQLite 3.46.1 not upstream-safe for WAL reset | patch + actual runtime attestation | P0 OPEN |
| EQ0712-OS-ANCHOR | independent writer/key/anchor administration absent | trust-domain and multi-host rollback test | P0 OPEN |
| EQ0712-DATA-AT-REST | DB/WAL/backup plaintext possible | encryption + retention + KMS | P0 OPEN |
| EQ0712-SW-PROVENANCE | SHA-256 manifest is not independent signature | signed SLSA/in-toto provenance + key separation | P0 OPEN |
| EQ0712-PRIVACY | actual personal-data scope unassessed | CH-DSG review/DSFA where applicable, minimization | CONDITIONAL OPEN |

All current regression data are synthetic. No assertion of Swiss legal compliance or production readiness.
