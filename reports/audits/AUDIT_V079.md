# === / Equal3 v0.7.9 – kritisches Re-Audit und implementierte P0-Teilmaßnahmen

**Datum:** 25.10.2026 | **Release-Gate: NO-GO** | Forschung, nur synthetische Daten. Keine GitHub-Änderung, kein Merge/Deploy, keine Migration von Echtdaten.

## 1. Evidenzbasis und Quellbindung

- Auslieferungsquelle ist das bisherige v0.7.8-ZIP `EQUAL3_v078_AUDIT_LEDGER_RESEARCH_2026-10-24.zip`, SHA-256 `f733a60775815b9500a6152f85274127ad5ab140b0ec4811111c3d30037ad4fc`. Originalmanifest geprüft, Alttests lokal erneut 190/190 in 74,516 s.
- Quelle geänderte Datei `anchor_wire.py` im Kandidaten: SHA-256 `b65a5488be7c4e0dd275e65b574de645490bd2e45bbecf2b500e63673dcffa3b`. Unveränderte Originalfassung separat mitlieferbar über ursprüngliches ZIP.
- Kandidat v0.7.9: final **206/206 Tests bestanden**, Python 3.13.5 und SQLite 3.46.1, Laufzeit **78,902 s**. New 16 tests, inkl. UID/GID-Sandbox nur auf root-fähigem POSIX-Container. Veränderte historische Test-Assertion `test_sqlite_wal_reset_runtime_gate` dokumentiert; keine Testfälle entfernt.
- Diese Sicherheitstests waren keine unabhängige Pentest-Abnahme. Kein Hardware-Fault-Lab, keine ungepatchte WAL-Produktivfreigabe.

## 2. Warum die Architektur geändert wurde

**Risiko:** Der Ankerdienst nutzte v0.7.8 `journal_mode=WAL` unter SQLite 3.46.1. Upstream dokumentiert einen WAL-Reset-Race-Fehler unter bestimmten Konkurrenzausführungen in SQLite 3.7.0–3.51.2. Im Jahr 2026 gibt es für den Fix freigegebene Releases ab 3.51.3; das jüngste am 25.10.2026 verifizierte SQLite ist 3.54.1 (Release 16.10.2026). Unsere Python-Laufzeit wurde hier **nicht** aktualisiert. V3.52.0 wurde vom Hersteller zurückgezogen; die lokale Versions-Allowlist weist sie jetzt ebenfalls zurück.

**Entscheidung:** Für den dedizierten Ankerprozess den WAL-Pfad komplett vermeiden: SQLite-Rollback-Journal `DELETE` + `synchronous=EXTRA`, einschließlich der Directory-Sync-Anforderung nach Journal-Delete. Damit wird nur die **spezifische** WAL-Reset-Bug-Klasse dieses Ankerpfads adressiert. Der WAL-basierte StateStore wurde **nicht** geändert, bleibt P0-BLOCKED.

## 3. Implementierung

- `bootstrap()` erstellt nur neue DELETE-Authorities, setzt und kontrolliert `PRAGMA synchronous=EXTRA` (Wert 3).
- `__init__` und `_db()` prüfen den gewünschten Journalmodus strikt und wechseln alte WAL-Authorities nicht automatisch um.
- `_verify_delete_header()` nutzt `O_NOFOLLOW`, fd-basierte Validierung und die offiziellen SQLite-Headerbytes 18/19; `-wal`- oder `-shm`-Sidecars blockieren vor dem SQLite-Open.
- `serve(...,socket_gid=...)` gestattet eine getrennte Writer-UID mit Gruppenmode: Socket-Elternverzeichnis `0710`, Socket `0660`, `SO_PEERCRED` exakt auf `writer_uid`. Socket bleibt vor chgrp/chmod durch restriktive umask privat.
- Das ursprüngliche `0600`-Socketverhalten bleibt als Forschungskompatibilität erhalten; es ist ausdrücklich **keine** echte UID-Trennung.
- Vorherige HMAC-Integrität von State/Audit-Root, Prepare, Finalize, Abort und Fail-Closed-Recovery bleibt erhalten.

## 4. Durchgeführte Negativ- und Positivtests

1. Start auf neuem DELETE-Anker mit der installierten SQLite 3.46.1 gelingt **ohne** WAL-Forschungs-Bypass.
2. `PRAGMA journal_mode` bleibt DELETE; `PRAGMA synchronous` ist für die Verbindung EXTRA.
3. Alter WAL-Header, noch vorhandene WAL-Sidecars und beschädigter SQLite-Header werden **vor** dem regulären SQLite-Open abgewiesen (Mock-Negativkontrolle).
4. Keine implizite Initialisierung bei fehlender Ankerdatei, kein stilles Legacy-Migrationsergebnis.
5. Prepare/Finalize nach Neustart, Abort-Fehlversuche und parallele Status-Aufrufe reproduziert.
6. UID-Integration unter einem privilegierten, isolierten Container: Server UID 0, Writer UID 65534; Writer kann RPC `status`, aber weder Anchor-DB noch Reviewer-Key lesen. Der Server weist dieselbe Nachricht von falscher UID trotz bekanntem MAC zurück.
7. Negative Versions-Allowlist: SQLite 3.52.0 (withdrawn) gilt nicht als freigegeben.
8. 206/206 Gesamttests nach Änderungen, kein `ResourceWarning` bei der finalen `-W error::ResourceWarning`-Ausführung.

**Test-Grenze:** Der UID-Test belegt Rechte im getesteten Linux-Container, nicht den Schutz gegen root, Host-Admin, eine gleichprivilegierte Dateisystemmanipulation oder Backups. Header-Vorprüfung und SQLite-Dateiöffnung sind nicht atomar FD-gebunden (TOCTOU). CPU-/VFS-Fault-Injektion und echter Crash unter physischen Stromunterbrechungen fehlen.

## 5. Performance – unbelasteter ABBA-Mikrobenchmark

Daten: vier sequenzielle Runden v0.7.8 → v0.7.9 → v0.7.9 → v0.7.8, je N=80 Operationen nach fünf Warmups. Gemessen werden `prepare+adjudicate` sowie `status`, getrennte neue Temp-DB pro Runde; derselbe Host/SQLite 3.46.1, keine parallel laufende Testsuite. Quelle: `EVIDENCE_V079/benchmark_uncontended_abba.csv` mit getrennten Quellcode-SHA-256-Werten.

| Runde | Version | Journal | Prepare+Finalize P50 | Status P50 |
|---|---|---|---:|---:|
| 1 | v0.7.8 | WAL/FULL | 5,3435 ms | 1,0667 ms |
| 2 | v0.7.9 | DELETE/EXTRA | 7,6615 ms | 1,1400 ms |
| 3 | v0.7.9 | DELETE/EXTRA | 8,1225 ms | 1,1421 ms |
| 4 | v0.7.8 | WAL/FULL | 4,8298 ms | 1,0759 ms |

Durchschnitt der beiden **Durchlauf-Mediane**: v0.7.9 / v0.7.8 = 1.552×, ca. +55.2 % bei Prepare+Finalize. **Kein SLA**: kleines N, keine Konfidenzintervalle, unterschiedliche Journal-Technik und aufeinanderfolgende Runden; echtes Produktiv-RPC mit mehreren UIDs wurde nicht benchmarkiert. Der Vorteil besteht im engeren Bedrohungsmodell, nicht in einem Geschwindigkeitsgewinn.

## 6. Verbleibende P0/P1-Probleme

**P0 OFFEN:** StateStore-WAL-Runtime aktualisieren und build-hash-/source-id-gebunden prüfen; OS-Isolation real unter zwei privilegienarmen Nutzern deployen; externer monotonic antirollback Anchor; unabhängige Commit-Evidence; verschlüsselte DB + Journals/Temp/Backups; Powerloss-/VFS-Fault-Labor; externes Security/Privacy Review.

**P1 OFFEN:** SQLite-Dateipfad-TOCTOU, Ledger-O(n)-Verifikation, Datenminimierung, Retention/Checkpointing, vollständige Performance-/P99- und Ressourcentests.

Kein Produktiv-GO, kein unabhängiger Beweis nicht-rücksetzbarer Daten. Review und Deployment-Freigaben fehlen. Compliance- und CodeFactory-Wissenstransfer erstellt, aber **keine** zentrale Tabelle oder fremdes Repo verändert.

## 7. Externe Hersteller-/Fachreferenzen

- SQLite WAL-Reset-Fehler: https://www.sqlite.org/wal.html
- SQLite `synchronous=EXTRA`: https://www.sqlite.org/pragma.html#pragma_synchronous
- SQLite Dateiheader 18/19: https://www.sqlite.org/fileformat.html
- SQLite neueste Releases 2026-10-16: https://www.sqlite.org/news.html
- SQLite Version 3.52.0 withdrawn: https://www.sqlite.org/news.html
- OWASP Cryptographic Storage: https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html

**Urteil:** gezielte Code-/Betriebshärtung lokal gelungen, Produktionsfreigabe `NO_GO`.
