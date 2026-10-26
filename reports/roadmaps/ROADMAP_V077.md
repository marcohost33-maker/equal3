# === / Equal3 Roadmap v0.7.7 – konkrete Abnahmekriterien

| Priorität | Task | Vorbedingung/Orakel | Stand |
|---|---|---|---|
| P0-00 | Gepatchte SQLite-Laufzeit für StateStore UND Anchor | exact runtime SHA/SQLite version/backport proof, WAL concurrent-writer test | BLOCKED: current 3.46.1 |
| P0-01 | OS-/Speicher-Domänentrennung von Writer, Anchor, Reviewer, Seal-Key | echte separate UIDs, ACL-/proc-/FD-/hardlink-/symlink-Negativtests, externe Identity | BLOCKED: same-UID lab |
| P0-02 | Externer monotoner nicht gemeinsam rücksetzbarer Anker | VM/TPM/HSM/KMS/remote audit with rollback/fork and disaster restore simulations | OPEN |
| P0-03 | unabhängige Commit-Evidence | signierter DB-State aus vertrauenswürdiger Quelle, an request-ID gebunden, adverse replay and stale checks | OPEN |
| P0-04 | at-rest encryption, WAL, backups, log retention, key rotation | ciphertext & restore check, environment hardening | OPEN |
| P0-05 | physische File-System-Faults | C VFS/hardware fault lab, fsync/ENOSPC/reorder/torn writes | OPEN |
| P0-06 | unabhängige Security-/Compliance-Abnahme | SHA-bound cross-family audit, legal DSFA scope where applicable | OPEN |
| P1-01 | Authentisierung von Nonce-/Review-Logs | hash-chain incl. monotonic checkpoint, pruning-proof replay checks | OPEN |
| P1-02 | Skalierung, Histogramme P50/P95/P99 | 1000+ operations/workload, CPU/RSS/I/O, baselines, ABBA randomized | OPEN |
| P1-03 | V1/V076 Datenmigration | unveränderte Quell-Hashes, unabhängiger Snapshot und externally attested genesis | BLOCKED |
| P2 | Fairer verlustfreier Codec-Vergleich | zstd/JXL/PNG, matching corpus, RAM/time/full bytes/metadata | OPEN |

Die zentrale Freigabe ist NO_GO; kein lokaler "Research override" darf als Release-Beleg verwendet werden.
