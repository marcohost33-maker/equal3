# === / Equal3 v0.7.8 – unabhängiges internes Entwicklungs- und Negativaudit

**Datum:** 24.10.2026 · **Release-Verdikt: NO-GO** · Kein GitHub-Push, Merge oder Deploy. Diese Prüfung ist ein selbst durchgeführtes, kein unabhängiges externes Security-Audit.

## Quelle

Unverändertes v0.7.7 ZIP `EQUAL3_v077_SEALED_ANCHOR_RESEARCH_2026-10-24.zip`, SHA-256 `de138f92a9d8076d83a28e1de6f8cde898f7b3b239621b56920c32da078fc8e9`. Das Quell-ZIP ist nicht überschrieben worden. Neues Paket v0.7.8 als additive Entwicklung isoliert erstellt.

## Technisch reproduzierter Fehler (negativ vor Fix)

`consumed` und `review_log` wurden in v0.7.7 nicht mit der Zustands-HMAC versiegelt. Test: nach einer normalen Prepare/Finalize-Transaktion `DELETE FROM consumed WHERE nonce=...` per SQL und danach `status()` aufrufen. v0.7.7 akzeptiert dies **ohne** HOLD. Ebenso Änderungen an Review-Einträgen. Aus zwölf neuen erwarteten Schutzprüfungen gingen vor der Reparatur sieben als FAIL und drei als ERROR durch (zwei PASS). **Fehlernachweis**: `EVIDENCE_V078/negative_first_v077.log`.

## Implementierte Reparatur

- Neues `authority.audit_root` (32 Bytes) über **alle** sortierten `consumed`-Zeilen und alle `review_log`-Zeilen in ID-Reihenfolge, domain-separiert SHA-256.
- Neues `SEAL_DOMAIN ...V078` bindet `store_id,version,digest,pending,audit_root` durch HMAC-SHA256 unter demselben bestehenden Seal-Secret.
- Mutation: `BEGIN IMMEDIATE` → ursprünglichen versiegelten Zustand und Audit verifizieren → Nonce/Review-Insert → neuen Root berechnen → Authority inkl. MAC aktualisieren → `COMMIT`.
- Status: explizite `BEGIN`-Read-Transaktion; Authority + beide Audit-Relationen stammen aus demselben Snapshot. Schema, Feldkodierung, ID-Lücken und maximales Volumen geprüft.
- Ältere Authorities haben kein `audit_root`; Folge ist `AnchorHold` mit Legacy-Hinweis. Kein automatischer Upgrade-/Genesis-Pfad.
- `PRAGMA trusted_schema=OFF` nun auch am Ankerdienst gesetzt.
- Maschinenlesbares `release_preflight_v078.py`: tatsächliche SQLite-Version, `sqlite_source_id`, binären SHA-256, Compile-Options und offenes NO-GO.

## Testergebnis und Grenze

- Der originale v0.7.7-Stand dokumentierte **176/176** Tests, nicht aus dem neuen Audit heraus neu gerechnet.
- V0.7.8: **190/190** `unittest`-Fälle im finalen Volltest **PASS**, darunter **14 neue** (12 Ledger-/Manipulationsprüfungen, 2 Runtime-Preflight-Prüfungen), **55,807 s** unter Python 3.13.5/SQLite 3.46.1. Kein ResourceWarning im finalen Testlauf. Evidenz: `EVIDENCE_V078/final_full_suite.log`.
- Python 3.13.5, SQLite 3.46.1: WAL-Reset-Fix im verwendeten Build nicht belegt, deshalb Produktionsgate **BLOCKED**. Alle Tests verwenden die ausdrücklich unsichere Forschungsausnahme für synthetische Daten.
- Kein Extern-Attest: DB+Audit+Seal-Key unter einer Host-/UID-Domäne könnten gemeinsam zurückgesetzt werden. Ein MAC ist weder externes Audit noch Hardwaretrust.

## Benchmarkdesign und Kritik

Ein ABBA-Vergleich aus vier sequenziellen Einzelrunden: v0.7.7 / v0.7.8 / v0.7.8 / v0.7.7; je 40 oder 250 Transitionen. Je Transition `prepare + adjudicate` und eine `status`-Prüfung. Gleicher Host und synthetische Anfragen, neue DBs, aber kein CPU-/I/O-Isolationsnachweis, keine Konfidenzintervalle. Rohdaten in `EVIDENCE_V078/benchmark_v078.csv`. Die Namen der Varianten und Quellcode-SHA256-Werte sind je Zeile enthalten.

- **40 Transaktionen (Run 1 und 4), v0.7.7**: Transition-P50 4,003 bzw. 3,389 ms; Status-P50 0,334 bzw. 0,317 ms.
- **40 Transaktionen (Run 2 und 3), v0.7.8**: Transition-P50 5,267 bzw. 4,631 ms; Status-P50 0,667 bzw. 0,624 ms.
- **250 Transaktionen (Run 1 und 4), v0.7.7**: Transition-P50 4,251 bzw. 3,309 ms; Status-P50 0,326 bzw. 0,288 ms.
- **250 Transaktionen (Run 2 und 3), v0.7.8**: Transition-P50 10,388 bzw. 9,915 ms; Status-P50 2,028 bzw. 1,977 ms. Protokollprüfung v0.7.8 ist O(n) je Operation, die Kosten steigen messbar mit der Historienlänge. **Keine Effizienzsteigerung behauptet.**

## Offene reale Sicherheitsgrenzen

1. Kein gepatchter, attestierter SQLite-Build für alle WAL-Nutzer; die verwendete 3.46.1 ist vom offiziellen WAL-Reset-Risiko betroffen.
2. Kein fremdverwalteter, nicht gemeinsam rollbackbarer monotonic Anchor; Same-UID- und Host-Kompromittierung möglich.
3. Kein OS-erzwungener Single-Writer, keine echte Dritt-Partei-Commit-Attestation.
4. Keine Verschlüsselung für DB, WAL/SHM, Temp und Backups; Key-Lifecycle offen.
5. Kein SQLite C-VFS-Faultlab für torn writes, fsync, ENOSPC, Powerloss.
6. Keine externe Security-/Compliance-Abnahme, keine produktive Last-/P99-Prüfung.
7. Ledger-Historie wächst und der gesamte Root wird pro Operation neu berechnet. `MAX_AUDIT_ROWS=100000` stoppt unkontrolliertes Wachstum, ersetzt aber keine sichere Retention-/Archivierungsstrategie.

## Externe Best-Practice-Grundlagen (keine Produktzertifizierung)

- Offizielle SQLite-WAL-Fehlerbeschreibung: https://www.sqlite.org/wal.html
- SQLite `trusted_schema`-Empfehlung: https://www.sqlite.org/pragma.html#pragma_trusted_schema
- SQLite Crash-Fault-VFS: https://www.sqlite.org/testing.html
- OWASP Logging: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- NIST SP 800-92: https://csrc.nist.gov/pubs/sp/800/92/final

**Urteil:** Funktionale Forschungs-Härtung positiv; Produktion bleibt ausdrücklich **NO-GO**.
