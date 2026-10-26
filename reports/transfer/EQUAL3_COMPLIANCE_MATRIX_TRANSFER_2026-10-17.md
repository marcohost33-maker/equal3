# === / Equal3 — Datenschutz- & Compliance-Matrixübertrag (2026-10-17)

Scope: Stand-alone offline reference research; **no live personal data used in tests** (synthetic data only). Applicability of specific sector/CH canton/EU provisions requires concrete deployment context assessment.

| Control | Domain | Requirement | Evidence | Status | Next gate |
| EQ-DSG-01 | CH DSG Art. 6/7 | Purpose limitation, data minimization, privacy by design/default | Synthetic fixtures; no productive processing | POLICY_GAP | processing inventory, legal basis, DPIA trigger |
| EQ-DSG-02 | CH DSG Art. 8 | Risk-appropriate security | HMAC + SQLite transaction; no encrypted at-rest backups | PARTIAL | encrypt data, protected keys, file ACL, pen-test |
| EQ-DSG-03 | Confidentiality | Avoid storing plaintext sensitive blobs in backup, logs, intermediary files | Current backups contain plaintext | OPEN_P0 | encryption & cleanup/retention |
| EQ-DSG-04 | Integrity/Replay | signed checkpoint requires external independent trust domain | counterexample confirms joint rollback weakness | PARTIAL | external trusted monotonic witness |
| EQ-DSG-05 | Availability | bounded output state; process crash test | 77 tests, no VFS powerloss | PARTIAL | fault VFS, resource limits, backup drills |
| EQ-DSG-06 | Deletion rights | content-addressed dedup/replay retention can hamper erasure | no deletion design | OPEN_P1 | TTL, key deletion policy, backup expiry & legal holds |
| EQ-DSG-07 | Breach response | DSG Art. 24 incident procedures | No incident runbook | OPEN_P1 | incident classification, notifications, response roles |
| EQ-DSG-08 | Third-party transfer | CH DSG Art.16 and GDPR if applicable | none in local demo; cloud Drive transfers only docs | CONDITIONAL | data flows, contracts, international transfers |
| EQ-DSG-09 | Key management | lifecycle per NIST 800-57 | no rotation; 2 distinct local secrets in demo | OPEN_P0 | secure storage / rotation / revocation |
| EQ-DSG-10 | Side channels | hashes, existence and sizes may reveal sensitive patterns | informational leakage possible | OPEN_P1 | traffic analysis and metadata minimization |

This is a technical control inventory, not a legal compliance certification or DPIA.
