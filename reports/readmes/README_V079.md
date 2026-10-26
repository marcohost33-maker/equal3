# === / Equal3 v0.7.9 Research – SQLite-Ankerjournal und OS-getrennte Writer-UID

**Datum:** 2026-10-25. **Release: NO-GO.** Synthetisches, lokales Forschungsartefakt. Keine Änderungen an GitHub oder fremden produktiven Diensten.

## Was wurde geändert?

1. Der *Ankerdienst* (nicht der WAL-basierte StateStore) verwendet für neue Datenbanken `journal_mode=DELETE` und `synchronous=EXTRA`. Beide Zustände werden bei jedem Öffnen überprüft; er setzt sie nicht stillschweigend bei bestehenden WAL-Ankern um. Der SQLite-WAL-Reset-Fehler betrifft diese DELETE-Ankerkonfiguration nicht, aber andere Fehlerquellen und WAL-Klienten bleiben offen.
2. Vor dem Öffnen durch SQLite werden die Header-Bytes 18/19 (`01 01`: rollback; `02 02`: WAL), `-wal`- und `-shm`-Sidecars sowie Inode, Eigentümer, Dateityp und Modus kontrolliert. **TOCTOU-Limit:** Der Header-FD und die spätere SQLite-Dateiverbindung sind nicht atomar gebunden; ein gleichprivilegierter Gegner/Host-Admin bleibt außerhalb dieser Garantie.
3. Optionaler Socket-Gruppenmodus über `--writer-gid`. Socketverzeichnis nur `0710` (anchor owner, writer group), Socket `0660` und `SO_PEERCRED` muss die exakte Writer-UID bestätigen. Ankerdatenbank und Reviewer-/Seal-Schlüssel bleiben in privatem Anchor-Verzeichnis `0700/0600`. Linux only. Ohne `--writer-gid`: alter Forschungssocket-Modus `0600` und privates Verzeichnis.
4. Die SQLite-Versionsfunktion weist die vom SQLite-Projekt zurückgezogene 3.52.x-Linie zurück. `require_sqlite_wal_safe()` ist weiterhin nötig für WAL-Nutzer. Die derzeitige Forschungsumgebung nutzt SQLite 3.46.1; produktive WAL-Clients sind damit **nicht freigegeben**.
5. V0.7.8-Audit-Root, Request-Auth, Read-Snapshot und Commit-Recovery sind unverändert übernommen. Keine automatische WAL-Migration. Kein Hardware-Anchor.

## Prüfen

```bash
# Nach Entpacken, nur isoliert mit synthetischen Daten:
cd Equal3_v079_Research
sha256sum -c MANIFEST_V079.sha256
python -m unittest discover -p 'test_*.py'
python -m unittest -q test_anchor_v079
```

Der separierte UID-Integrationstest läuft nur bei root-berechtigtem Test-Container und verwendet temporär UID/GID 65534 im abgesenkten Subprozess; andernfalls wird er übersprungen. Keine Accounts werden eingerichtet, keine Dateisystempfade außerhalb des Test-Tempverzeichnisses geändert.

Das frühere `research_unsafe_sqlite`-Argument bleibt als historische Test-API vorhanden, öffnet aber keinen WAL-Anker mehr; StateStore-WAL-Benutzer sind davon *nicht* befreit. **Produktive Inbetriebnahme ist untersagt, solange die P0-Gates offen sind.**

## Sichere Migrationsgrenze

Ein produktiver v0.7.8-WAL-Anker darf **nicht** durch Umstellen des Pragmas migriert werden. Erforderlich sind Stop aller Clients, Quell- und Sidecar-Backup, externer Originalstand, Recovery- und Integritätsprüfung, unabhängige Attestation, separate Neuinitialisierung, Rollback-Probe und dokumentiertes Owner-Go. Kein solcher Lauf wurde hier ausgeführt.

## Verzeichnis

- `anchor_wire.py`: geänderte Implementierung
- `test_anchor_v079.py`: 16 zusätzliche Tests, darunter Linux-UID-Integration
- `test_anchor_v077.py`: eine an die neue Journalpolitik angepasste historische Testassertion
- `AUDIT_V079.md`: kritische Befunde, genaue Grenzen, Tests, Benchmark
- `ROADMAP_V079.md`: priorisierte offenen Sicherheitsgates
- `DEPLOYMENT_ISOLATION_V079.md`: nicht ausgeführte Betriebskonzeption
- `COMPLIANCE_TRANSFER_V079.md`: Daten- und Rollenfolgen
- `RELEASE_GATES_V079.json`: maschinenlesbares NO-GO
- `EVIDENCE_V079/`: Testprotokolle, source-bound Benchmarks, Patch, SQLite-Supply-Chain-Info

Referenzen: https://www.sqlite.org/wal.html ; https://www.sqlite.org/pragma.html#pragma_synchronous ; https://www.sqlite.org/fileformat.html ; https://www.sqlite.org/news.html .
