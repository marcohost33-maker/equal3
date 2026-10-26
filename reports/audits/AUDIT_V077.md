# Equal3 / === – Kritisches Cross-Version-Re-Audit v0.7.4 → v0.7.7
**Datum:** 2026-10-24. **Urteil:** Forschung / NO-GO. Keine GitHub-Pushes oder Produktfreigaben.

## 1. Prüfgegenstand und Quellstand

Quell-ZIP-SHA256 siehe `EVIDENCE_V077/SOURCE_ZIP_HASHES.json`.
Die älteren Pakete wurden nochmals gegen die jeweilige MANIFEST-Datei geprüft:
- v0.7.4: 31/31 SHA-256-Einträge gültig; 113 Tests im historischen Bericht.
- v0.7.5: 46/46 SHA-256-Einträge gültig; 139 Tests im historischen Bericht.
- v0.7.6: 66/66 SHA-256-Einträge gültig; 167 Tests im historischen Bericht.
Die historischen Testzahlen sind Quellenangaben, nicht alle drei Versionen erneut ausgeführte Tests.

## 2. Falsifikation v0.7.6 – unversiegelte Authority

In einer mit v0.7.6 gebootstrappten Authority-DB wurde offline mit einem SQL-UPDATE
`version=9`, `digest='c'*64` gesetzt. `PersistentCASAnchor.status()` meldete danach
`version=9` ohne kryptografische Unregelmäßigkeit. Reproduzierter Negativfall.

Gegenmaßnahme v0.7.7: `SEAL_DOMAIN`-separierte, kanonisch serialisierte HMAC-SHA256-
Versiegelung von `(store_id, version, digest, pending_hex)`. Das Siegel wird in
jeder Authority-Transaktion mit dem Zustand geschrieben und beim Lesen verifiziert.
Ein eigenständiger Siegel-Schlüssel ist von der Reviewer-Freigabe und dem RPC-Writer-
Schlüssel verschieden. Das verhindert beliebige Offline-Manipulationen nur, wenn
Angreifer den Siegel-Schlüssel **nicht** besitzen. Same-UID, Root oder gemeinsame
Backups verletzen diese Voraussetzung weiterhin.

## 3. Neue externe Erkenntnis: SQLite WAL-reset race

Der Python-SQLite-Build dieser Umgebung ist **3.46.1**. SQLite dokumentiert
unter `https://sqlite.org/wal.html` Abschnitt "WAL-Reset Bug" einen Datenrace-
Korruptionsfehler bei parallelen WAL-Verbindungen. Betroffene upstream-Versionen
umfassen 3.46.1. Der Fix ist in 3.51.3, den Backports 3.50.7 und 3.44.6
enthalten; eine distributionsspezifische Rückportierung muss separat attestiert
werden. Der v0.7.7-Anker verweigert seine normale Eröffnung auf einer nicht
als korrigiert klassifizierten Laufzeit. Die synthetischen Tests nutzen eine
**ausdrückliche UNSAFE-Research-Ausnahme**.

Nicht gelöst: `StateStore` und andere ältere Komponenten haben noch eigene WAL-
Pfade. Eine produktive Gesamtanwendung muss **sämtliche** SQLite-Runtimes und
konkurrierenden Verbindungsszenarien auf eine gepatchte Version/validierte
Backport-Build-Identität binden. Kein Release ohne diesen Nachweis.

## 4. Ausgeführte Nachweise

- Vollsuite v0.7.7: **176/176 PASS**, Laufzeit 60,277 s, `EVIDENCE_V077/full_regression_176_tests.log`.
- Neu: 9 Tests (`test_anchor_v077.py`), zusätzlich zu 167 historischen v0.7.6-Fällen.
- Fokussiert: **37/37 PASS**, Coverage `anchor_wire.py` 63 %, zwei fokussierte Module
  zusammen 62 %. RPC-Subprozesse nicht voll instrumentiert → Coverage kein
  unabhängiger Code-Vollbeleg.
- Neue Negative: Offline-Version/Digest, Pending-Austausch, Siegelentfernung,
  falsches Siegelgeheimnis, unversiegelte Altdatenbank, identischer Reviewer/Siegel-
  Key, Runtime-Verweigerung.
- Positive: Prepare→Abort, Prepare→Finalize, Wiedereröffnung versiegelter Authority.
- Explizit falsifiziert: gemeinsamer Rücksprung eines zuvor gültig versiegelten
  Authority-Stands ist weiterhin möglich. Kein unabhängiger Monotonic-Anchor.

## 5. Benchmarkmethodik und Messgrenze

Synthetischer Mikrobenchmark (`bench_seal_v077.py`), vier ABBA-Runden, je 60
gewertete Transitionen mit fünf Warmups; separat `status` und
`prepare + adjudicate`. Beide Stände laufen auf demselben Build in separaten
Temporärdatenbanken. Rohdaten: `EVIDENCE_V077/benchmark_seal_v077.csv`.

| Version | Runde | Prepare + Finalize P50 [ms] | Status P50 [ms] |
|---|---:|---:|---:|
| v0.7.6 | 1 | 3,423 | 0,299 |
| v0.7.7 | 2 | 3,428 | 0,337 |
| v0.7.7 | 3 | 5,510 | 0,402 |
| v0.7.6 | 4 | 6,331 | 0,425 |

Die starke Run-Drift und kleine Anzahl von Clustern verbieten eine belastbare
Aussage zum isolierten Siegel-Mehraufwand. Kein P99, keine echte Stromausfall-
oder HSM-Latenz-Messung. Auch kein Beweis höherer Performance.

## 6. Kritische, offen gebliebene Defizite

- P0: kein unabhängig und unveränderbar gespeicherter Monotoniezähler; Rollback-
  oder Klonangriffe auf die gemeinsame administrative Domäne bleiben möglich.
- P0: sowohl Datenbank als auch Anker werden in den Tests unter einer UID betrieben;
  gleiche Rechte können Raw-Schreibzugriff, Key-Diebstahl und File-TOCTOU erlauben.
- P0: kein attestierter SQLite-Commit von einem **unabhängigen** Evidence-Dienst;
  Reviewer bewilligt weiterhin ein Coordinator-gestütztes Ergebnis.
- P0: unverifizierte SQLite 3.46.1-Laufzeit für WAL in dieser Testumgebung. Die
  neue Research-Ausnahme ist absichtlich unsicher und Release-blockierend.
- P0: keine verschlüsselte DB, WAL/SHM, Temp-Dateien oder Backups; Schlüsselrotation,
  sichere Löschung und Audit-Retention fehlen.
- P0: kein C-VFS-Powerloss-/ENOSPC-/torn-write-/fsync-Fehlerlabor;
  kein unabhängiger Security-Review, Cross-OS-ACL-Test oder Pen-Test.
- P1: neue Versiegelung schützt `consumed` Nonces und `review_log` nicht separat;
  bei autorisiertem DB-Zugriff sind Loglöschung/Replay-Risiken separat zu untersuchen.
- P1: O(n)-historische Receipt-Prüfung, P95/P99/RSS/Energie unter Dauerlast,
  Backpressure/DoS, Schlüsseltrennung über tatsächliche Maschinen.
- P1: keine rückwirkende Authentizität historischer v0.7.6-Anker oder v1-StateStore-
  Daten. Migration nur nach externer unabhängiger Attestation.
- P2: Codec-/Informationstheorieziele, faire zstd/PNG/JXL-Benchmarks und eigene
  Bildprädiktoren weiterhin Forschungsaufgaben.

## 7. SOTA / Normen

- Offizielle SQLite-WAL-Information, WAL-reset Bug: https://www.sqlite.org/wal.html
- Offizielle SQLite-Crash-Simulation: https://www.sqlite.org/testing.html
- SQLite Synchronisierung und Journal: https://www.sqlite.org/pragma.html#pragma_synchronous
- OWASP Schlüsselmanagement: https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html
- OWASP kryptografische Datenspeicherung: https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
- NIST SP 800-57: https://csrc.nist.gov/Projects/Key-Management/key-management-guidelines

## 8. Schlussfolgerung

Die zwei konkret nachgewiesenen neuen P0/P1-Themen – fehlende Authority-
Datensatz-Authentifizierung und das ungepatchte SQLite-WAL-Race – wurden
unterschiedlich behandelt: Der erste Bug ist in v0.7.7 lokal korrigiert und
falsifiziert; für den zweiten ist ein fail-closed Preflight integriert, während
**die Runtime selbst NICHT aktualisiert wurde**. Kein Produktionsrelease.
