# === / Equal3 – Roadmap ab v0.7.9 (25.10.2026)

## Belegt (lokal, synthetische Daten)

- **P0-Teilmaßnahme**: Ankerjournal auf SQLite `DELETE` + `synchronous=EXTRA`, vor-/nach-Open-Modeprüfung und harte WAL-Migrationssperre: implementiert.
- **P0-Teilmaßnahme**: SOCK-UID Trennung: unter Test-Container mit zwei Unix-UIDs implementiert und positiv/negativ getestet; realer Hostbetrieb und Administratorkompromiss bleiben offen.
- Historische v0.7.8-HMAC-Log-Versiegelung weiterverwendet. Testbericht und Benchmark als Einzelbeweise, nicht als Produktionsfreigabe.

## P0 – nächste Schritte in Gate-Reihenfolge

| Gate | Unverzichtbarer Nachweis | Status |
|---|---|---|
| G0 Source | Unveränderliche Quell-Hashes, vollständiger Rebuild, negative Tests, Quelle/Runtime/Deployment eindeutig gebunden | PARTIAL: lokales ZIP, kein unabhängiges Signing |
| G1 StateStore-SQLite | Gepatchte, attestierte Laufzeit für **alle** WAL-Nutzer (z.B. offiziell SQLite 3.54.1 mit geprüfter Build-Provenienz). Reale Testmatrix WAL writer/read/checkpoint, Supply-Chain-SBOM | OPEN |
| G2 Owner/Writer UID | Zwei reale nichtprivilegierte Service-Accounts, ACL-/Gruppe, Schlüssel-, File-, Backup-, ptrace- und Socket-Gegenproben, Dienst-Neustarts, Root-Bedrohung separat | PARTIAL: Test-Container, nicht Deploy |
| G3 Independent monotonic | Externer Anker in **separat administrierter, nicht gemeinsam zurücksetzbarer Domäne**; Snapshot-Fork- und Joint-Rollback-Versuche erkennen | OPEN |
| G4 Commit+Recovery | Verbindlich authentifizierte externe Commit-Attestation, Crash-Gap-Reconcile, Request-IDs, kein Auto-Heal, autorisiertes Manual-Go | OPEN |
| G5 Encryption | Live DB + WAL/SHM + `-journal` + Temp/Backups/Snapshots verschlüsselt; unabhängiger KMS/HSM-Key-Lifecycle; Restore und Purge überprüft | OPEN |
| G6 VFS Fault Lab | C-VFS/isoliertes Volume: powerloss, fsync, ENOSPC, Reorder, torn write; Fail-Closed-Orakel | OPEN |
| G7 Independent Review | Externe Security Review, Datenschutz/DSFA falls notwendig, versionierte evidenzgebundene Gate-Signierung | OPEN |

## P1

1. Audit-Root mit 1k/10k/100k Ledger-Einträgen und P50/P95/P99/CPU/RSS messen; O(n) Statuskosten, Ledger-Retention und sichere Checkpoint-Policy.
2. Socket-Dienst unter rootlosen systemd-Nutzern und mit echter Netzwerk-/Unix-Sandbox untersuchen; `SO_PEERCRED`/Gruppenrechte gegen unabhängigen Test-Operator prüfen.
3. Vollständiges Migrationslabor für ursprüngliche WAL-Anker (ohne stillschweigende Konvertierung), Signaturen für Off-Host-Originalzustand; Test-Wiederherstellung.
4. Dateipfad-TOCTOU, SQLite-File-Open über getrennten FD, Sidecar- und Swap-Szenarien adversarial untersuchen.
5. ABBA-Benchmarks auf stiller Maschine, ausreichende Wiederholungen und gepatchte Runtime; Effizienz nur mit Konfidenz- und Korrektheitsgates.

## P2

Delta-/Bit-Kodierung, Chunking sowie JPEG XL/PNG/zstd-Vergleiche getrennt von Sicherheitsarchitektur untersuchen; mathematische Gleichungen nicht als Leistungsbeweis ersetzen.

**Release-Gate**: NO-GO. Keine Ausführung auf Echtdaten, kein Push/Merge/Deployment in dieser Forschungswelle.
