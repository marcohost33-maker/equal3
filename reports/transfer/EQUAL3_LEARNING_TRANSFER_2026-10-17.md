# === / Equal3 — Lernzuwachs 2026-10-17

| Metric | Value | Denominator | Status | Limitation |
| Historical regression and v0.7.2 | 77/77 passed | unittest: inherited 65 + 11 witness + 1 fault lab (7 subtests) | EXECUTED_LOCAL | Not an exhaustive proof |
| Child-process abort | 7/7 expected | seven distinct fault hooks | EXECUTED_LOCAL | Not power loss / torn sector |
| Witness security positive | old DB + newer independent witness -> RollbackDetected | one deterministic scenario | EXECUTED_LOCAL | trusted external witness required |
| Witness counterexample negative | joint rollback old DB + old valid witness -> MATCH | one deterministic scenario | FALSIFIED_ABSOLUTE_CLAIM | local file not anti-rollback |
| Witness benchmark | median 1.037 ms assess | n=80, localhost | MEASURED_LOCAL | dependent on storage+machine |
| Store verify comparator | median 0.405 ms | n=40, localhost | MEASURED_LOCAL | separate sample different code paths |
| Witness size | 201 bytes | one signed checkpoint | MEASURED_LOCAL | excludes lock and file system metadata |
| Production readiness | NOT RELEASED | physical powerloss, independent anchor, third-party audit absent | HOLD | next steps required |
