# === / Equal3 v0.7.3 — unabhängiges kritisches Folgeaudit
Datum: 2026-10-17. Status: RESEARCH ONLY; RELEASE-GATE NO-GO.

## Herkunft und Scope
Vollständige, lokale Prüfung des Arbeitsstands v0.7.2 als Quelle; additive Implementierung `guarded_store.py`, Korrektur `state_store.verify()` und `witness.py`, zusätzliche 19 Tests gegenüber den 77 v0.7.2-Tests (insgesamt 96). Python 3.13.5 / SQLite 3.46.1 / Linux 6.18.55. Keine GitHub-Änderungen. Nur synthetische Daten. Die offizielle SQLite-Library ist nicht erneut eigenständig auditiert.

## Konkrete alte Schwachstellen und Behebung
| ID | Kritischer Befund | Korrektur in v0.7.3 | Restrisiko |
|---|---|---|---|
| G-01 | Witness nur nachträglicher Check; StateStore.apply umgehbar | `GuardedStore.apply` prüft witness vor Write und nach Witness-Publish | Raw API bleibt erreichbar; alle Writer müssen Guard erzwingen |
| G-02 | SQLite-COMMIT ≠ Witness-Publish | `AnchorPendingError`, Halt statt irreführender Rollback-Behauptung, Receipt-basierte Diagnose | Keine verteilte atomare Transaktion; externe Adjudikation weiterhin nötig |
| G-03 | `witness.advance` erlaubt Versionssprung | Nur genau ein Schritt pro Advance | Angreifer mit Schlüssel/Dateizugriff und raw API kann Kontrollfluss umgehen |
| G-04 | Initialisierung von Witness nach beliebigen DB-Updates möglich | Standardmäßig Genesis-Version 0 erforderlich | Migrieren bestehender Systeme benötigt unabhängige Bootstrap-Attestation |
| G-05 | `verify()` gefolgt von getrenntem `read()` ergibt keine gemeinsame DB-Snapshot-Garantie | `StateStore.verify` liefert Store-ID, Version, Digest aus EINER SQLite-Lesetransaktion; Witness verwendet dieses Audit | Nichtcooperating Writers können nach Snapshot ändern; Guard-Lock nur advisory |
| G-06 | `verify()` erkennt geänderte Key-Binding-Metadaten erst beim erneuten Öffnen | Bindung innerhalb konsistenter Verify-Transaktion geprüft | Ein Angreifer mit Schlüssel und DB-Schreibrechten bleibt außerhalb Bedrohungsmodell |
| G-07 | Unsichere Zeugen-Pfade | POSIX-Owner-, Verzeichnisrechte-, Symlink-/Dateityp-Vorprüfung | Keine Sicherheit gegen same-UID/root, Pfad-TOCTOU, NFS, Host-Kompromittierung |

## Mess- und Falsifikationsregister
**Positive Resultate (PR):**
- PR-01: 96/96 unittest-Testfälle (alte 77 + neue 19) bestanden; direkte Thread- und separate Prozesskonkurrenz; jeweils genau ein Commit bei gemeinsamem Ausgangsstand.
- PR-02: `AnchorPendingError` nach injiziertem Witness-I/O-Fehler trotz bestätigtem SQLite-Commit; Folgeschreibversuche fail-closed.
- PR-03: Alter DB-Stand gegen aktuelleren Zeugen erkannt; manipulierte Meta-Key-Bindung in `verify` erkannt.
- PR-04: Versionssprung des alten Witness-API und späte Initialisierung abgewiesen.
- PR-05: Erfolgreiche Datenrekonstruktion und Quittungsprüfung aus v0.7.2 erhalten.

**Negative Resultate (NR):**
- NR-01: Annahme 'Lokale HMAC-Datei ist ein absoluter Rollbackschutz' weiterhin falsifiziert (Joint-Rollback von DB + Witness kann bestehen).
- NR-02: Annahme 'Geschützter Apply ist ebenso schnell wie raw Apply' widerlegt (synthetische Benchmarkwerte unten).
- NR-03: SQLite-Commit und externes Anchor-Update sind nicht atomar: Ein Verbindungs-/FS-Abbruch kann das Commit-Ergebnis unklar lassen.
- NR-04: Physikalische Stromunterbrechungen, torn sectors, VFS-Fehler, untrusted SQLite-Dateien, unabhängige extern attestation NICHT getestet.

## Benchmarks
40 sequentielle Zustandswechsel je Konfiguration; beide Methoden verwenden denselben Codec-Strategiemodus `fast`; Zeitmessung umfasst NUR `apply`, nicht Paketvorbereitung. Verschiedene temporäre SQLite-Datenbanken, kein randomisiertes AB/BA-Reihenfolgendesign, keine systematische CPU-/I/O-Isolation. Siehe `bench_guard_results.csv`.

| State | Direkter Apply Median | Guarded Apply Median | Faktor |
|---|---:|---:|---:|
| 1 KiB | 1.8289 ms | 4.2522 ms | 2.32x |
| 64 KiB | 2.1007 ms | 4.5628 ms | 2.17x |

Die zusätzliche Zeit ist ein messbarer Trade-off der Prüfarbeit. Keine globale Aussage zur Leistung auf anderen Maschinen.

## Formale Modellierung / Invarianten
- `State = (store_id, version, sha256(value))`
- `Witness = MAC_K(domain || canonical(State))`
- `ValidBeforeWrite = verify(db_snapshot) AND current_witness == db_snapshot`
- `Commit = CompareAndSwap(expected_version, expected_digest, next_version, next_digest) AND receipt_persisted`
- `PublishWitness: witness_version(next) == prior_witness_version + 1`
- `UnknownOutcome => STOP/REVIEW; never auto-advance witness`
- Shannon: `H(X)=-sum(p(x)log2(p(x)))`; `H(Y|X)=H(X,Y)-H(X)`.
- Cost vector: `C=(bits, encode_ms, decode_ms, peak_RSS, energy, assurance_risk)`; Pareto dominance depends on a shared workload.

## Neue Architektur- und Governance-Entscheidungen
1. Produktiver Write-API müsste die ungeschützte `StateStore.apply()`-Schnittstelle für alle untrusted Clients vollständig kapseln. Der Wrapper dieser Forschungsfassung erzwingt dies **nicht**, sofern Raw API extern verfügbar bleibt.
2. Zeuge muss in nicht gemeinsam rücksetzbarer Trust-Domäne liegen (separater KMS/HSM/monotoner Dienst), die selbst eigene Authorisierungs-/Replay-Checks erzwingt.
3. Recovery nach Commit-Lücke: Request-ID und Quittung prüfen; Witness-Versionskette gegen unabhängigen Auditanker abgleichen; kein blindes `advance`; Freigabe nur mit dokumentierter Adjudikation.
4. Persistenter Datenschutz: SQLite, WAL, SHM, Snapshots und Backups enthalten ggf. vertrauliche Klartextwerte. Verschlüsselung und Retention per Bedrohungsmodell. Keine Patientendaten in Testlogs.
5. Keine Produktfreigabe bis VFS Fault-Lab, Encryption/Key Lifecycle, unabhängiger Anchor, Fuzzing und External Review erfüllt.

## SOTA/Best-Practice Quellen
- SQLite Teststrategie inklusive VFS-I/O- und Crashsimulation: https://sqlite.org/testing.html
- WAL-Komponenten und Checkpoints: https://www.sqlite.org/wal.html
- SQLite PRAGMA FULL: https://www.sqlite.org/pragma.html#pragma_synchronous
- OWASP Cryptographic Storage: https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
- OWASP Key Management: https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html
- OWASP Logging: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- Schweizer DSG: https://www.fedlex.admin.ch/eli/oc/2022/491/de
- EDOEB DSFA: https://www.edoeb.admin.ch/de/datenschutz-folgenabschaetzung

## Roadmap Priorisierung
P0: unabhängiger Trust Anchor + kontrollierte Recovery; P0: OS-Level/SQLite VFS Powerloss-Emulation; P0: Authenticated Encryption für sensible Stores/Backups; P0: Coverage-guided Fuzzing; P1: Chunked Store/Performance und Entropiekontext; P1: Formalmodell zu Zeugen-Recovery; P2: minimaldeutsche Computersprache und Bildprädiktoren.
