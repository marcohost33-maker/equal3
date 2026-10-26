# === / Equal3 Roadmap nach v0.7.8, Priorisierung und Definition of Done

| Prio | Task | Präziser Abnahmetest | Urteil |
|---|---|---|---|
| P0 | Alle WAL-Nutzer auf tatsächlich gepatchte SQLite-Builds heben | SHA + `sqlite_source_id`, Distribution/Backport-Evidenz, reale WAL-Lese-/Writer-/Checkpoint-Konkurrenz | OFFEN; aktuelle Python-Runtime 3.46.1 |
| P0 | OS-Trennung StateStore / Anchor / Reviewer | verschiedene UIDs oder Maschinen, ACLs, proc/ptrace, Dateideskriptoren, Symlink/Hardlink/Backup, negative untrusted writer tests | OFFEN |
| P0 | Externe Monotonie/Nicht-Rücksetzbarkeit | Fremddienst mit Anti-Rollback-Eigenschaft, mehrere Klone und gemeinsamer Snapshot-Rollback müssen erkannt werden | OFFEN |
| P0 | Unabhängige Commit-Evidence | DB-signierte/attestierte Zustandsbeweise, Anfrage- und Versionsbindung, Adversarial-Review | OFFEN |
| P0 | At-rest-Schutz | SQLite+WAL+SHM+Temp+Backups verschlüsselt, HSM/KMS-Key-Lifecycle, Restore & Destroy prüfbar | OFFEN |
| P0 | Fehlerlabor | C-VFS oder hardwareähnlicher Crash-/ENOSPC-/torn-write-/fsync-Fault-Injektor; Konsistenzorakel | OFFEN |
| P0 | Unabhängiger Pen-Test & Privacy-Go | SHA-gebundener externer Review und kontextabhängige DSFA, dokumentiertes Release-Verdikt | OFFEN |
| P1 | Audit-Schutz von Nonces & Review-Historie | Mutation/Löschung/Einfügung/Neustart/Fork, atomare Root-Aktualisierung | **LOKAL PASS** (kein Anti-Rollback) |
| P1 | Ledger-Skalierung | 1k/10k/100k Einträge, P50/P95/P99/RSS/CPU, gegen Baseline; extern attestierte Root-Checkpoints mit Falsifikation | OFFEN; v0.7.8 O(n) |
| P1 | DoS/Retention | Größe & Aufbewahrung sicher begrenzt, Purge nur via nachweislich attestierten Checkpoint + gesetzliche Fristen | OFFEN |
| P1 | Migration aus v0.7.7 | Quellhash, signierter externer Originalstand, Recovery-Walkthrough und Abnahme | HOLD |
| P2 | Kompression & Informationstheorie | Faire Baselines gegen zstd, PNG/JPEG XL; Payload+Overhead+Fidelity, P50/P95, Peak RSS | OFFEN |

**Go/No-Go:** Diese Forschungsrunde ist **NO-GO**, ungeachtet grüner Unit-Tests. `release_preflight_v078.py` erteilt prinzipiell kein Produkt-GO.
