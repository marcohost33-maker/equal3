# Equal3 v0.7.20 — kritisch-konstruktives Cross-Review

**25.10.2026 | Forschungsmuster | RELEASE: NO-GO**

## 1. Prüfgegenstand / unveränderte Aussagen aus v0.7.18–v0.7.19

v0.7.18 band Root-signierte Attester-Rotation an eine lokale Epoche; eine statisch mitgelieferte Mindest-Epoche war keine unabhängige Rücksetzungssperre. v0.7.19 erweiterte dies um einen frisch per Nonce abgefragten, signierten Epochenzeugen. **Der Zeuge erfasste ausschließlich Schlüsselerhöhungen, nicht jeden Commit.** Ein lokaler Writer ohne Commit-Zeugenpflicht konnte Erfolg auf einem später zurückgesetzten, gemeinsam gültigen Store+Anker-Paar liefern. Der bereits dokumentierte gemeinsame Rollback des Epochenzeugen blieb möglich. 401 grüne Tests beweisen die geprüften Szenarien, keine Realwelt-Trennung.

## 2. Implementierte v0.7.20-Korrektur

- `external_commit_witness_v0720.py`: separater COMMIT-Stand `(deployment_id,store_id,version,digest,request_id,attester_fingerprint,signer_fingerprint)` als versiegelter SQLite-CAS-Kopf (DELETE/EXTRA). Initialisierung **nur bei Genesis**, alte Datenbanken werden nicht automatisch migriert. Geheimnisse liegen konzeptionell im Zeugenprozess.
- Nach Finalisierung ausgestellte, domain-separierte Ed25519-Beobachtung: `issue_final_checkpoint` prüft *sowohl* finalisierten Anker als auch eine authentifizierte V2-SQLite-Quittung für genau den Intent. Eine vor der Finalisierung ausgestellte V0716-Intent-Beobachtung wird nicht mehr akzeptiert.
- `publish()` validiert das exakte signierte Post-Final-Statement, Signer, Deployment und strikt fortlaufende Version/Digest-CAS-Kette. Exakter Retransmit ist idempotent, abweichender ist HOLD.
- `CommitWitnessClient.floor()` prüft jeweils eine frische signierte Challenge; `CommitGatedWriterCore` verweigert Erfolgsantworten bei fehlendem Register, noch offener Ankerfreigabe, abweichender Position oder geändertem Zeugenstand während der Abfrage. Er prüft *vor* und *nach* einer Erfolgsantwort.
- Neue Prozessstartreferenz `commit_witness_daemon_v0720.py`: niemals automatische DB-Wiedererzeugung; Dienstgeheimnisse werden ausschließlich aus privaten Dateien gelesen, der öffentliche Attester-Schlüssel aus root-kontrollierter Datei; Unix-Socket nur in geschütztem Verzeichnis.
- Der Zeugen-Signierschlüssel ist nun zusätzlich persistent und versiegelt an den Zeugenbestand gebunden (unvermerkter Ersatz beim Neustart: HOLD).

## 3. Falsifikation / Grenzen

| Szenario | Befund |
|---|---|
| Store+Anker auf authentische alte Version 0 zurückgesetzt, Zeuge auf Version 1 | `CommitGatedWriterCore`: **HOLD**. Der alte `CoordinatedStore` meldet dagegen `MATCH`. |
| Vollständiger Rollback auch des separaten Commit-Zeugen | Alte Version 0 wird akzeptiert: **geplanter Negativnachweis**; P0-Blocker. |
| Writer nach Anker-Commit, aber vor Zeugen-Publikation | HOLD statt bestätigtem Erfolg. |
| Attester-Unterschrift VOR Ankerfinalisierung durch Referenzbeobachter | Verweigert. |
| Alte, nachträglich inkorrekte *einst* wahre Post-Final-Signatur | Kann Zeugenfortschritt auslösen; der nachfolgende Leser hält. **TOCTOU nicht eliminiert.** |
| Gefälschte Attestierung, Replay, fremder Zeugen-Signer, fremde Deployment-ID, korrupte/duplizierte SQLite-Zeile | Verweigert. |
| Authentifizierter, alter Legacy-Writer-/Coordinator-Zugang | Immer noch zugänglich in Forschungscode: Produktions-Bypass möglich. |

**Wichtig:** Der Zeuge erhält eine signierte Beobachtung. Er beobachtet die Platte nicht selbst. Ein kompromittierter Beobachter oder eine spätere Rücksetzung kann diese Aussage falsch/stale machen. Auch mit zwei lokalen Unix-Sockets entsteht keine unabhängig administrierte Vertrauensdomäne. Es gibt keine garantierte transaktionsübergreifende Atomarität, kein HSM, keine hardwaregestützte Monotonie und keine RFC-9162-Merkle-Konsistenzbeweise.

## 4. Testdesign und Reproduzierbarkeit

Voriger Stand: 401 Tests. Neue v0.7.20-Fälle: 24. Erwarteter Gesamtumfang: 425 in elf getrennten Prozessen unter `-W error::ResourceWarning`. Für die finale Freigabedokumentation zählen ausschließlich die Logs des zuletzt geprüften, eingefrorenen Quellstands sowie des frisch entpackten ZIP. `run_v0720_suites.py` beendet sich bei jeder roten/zeitüberschrittenen Gruppe mit nonzero.

Ein gruppenweise bestandener Lauf darf nicht als monolithische Testausführung ausgegeben werden. Die Quelle dieser Forschungsimplementierung sowie die exakten Test-Suites stehen im Paket. Benchmark-Methode: 4 ABBA-Runden × 80 Statusabfragen pro Variante/Nutzlast, gleiches lokales Python/SQLite, keine Mehrhost-Netzwerkverzögerung oder echte Prüferentscheidung. Wichtig: Alte und neue Status-API haben verschiedene Sicherheitssemantik; ein vollständiger Leistungs-/Sicherheitsvergleich ist damit noch nicht möglich.

## 5. Offene P0-Release-Gates

1. **Echte unabhängige, nicht gemeinsam rücksetzbare Registry** auf getrennt kontrollierter Hardware/Service, inklusive dauerhaft bezeugtem Commit-Fortschritt und Prüfungen gegen Equivocation/Split-View.
2. **Verpflichtender einziger Entry Point** mit isoliertem Writer-, Observer-, Anker- und Zeugenprozess; die alten research-only Bypass-Klassen dürfen in einer Produktionsdistribution nicht importier- oder nutzbar sein.
3. **Stabile externe Commit-Observation / TOCTOU**: geschützte, konsistente Commit-Quelle und Recovery-State-Machine; getrennte Attester/Reviewer-Rechte und nachweisliche OS-/Schlüsselisolation.
4. **Laufzeitprovenienz:** gepatchte, tatsächlich geladene SQLite-Bibliothek und unabhängige Attestierung; aktuell im Testhost weiterhin SQLite 3.46.1.
5. **Powerloss/VFS/ENOSPC/FSYNC**, Parallelitäts-/Netzwerkpartitionstests, Schlüsselrotation samt Revocation, Verschlüsselung, Schweizer DSG- und unabhängiger Security-Prüfung.
6. **Latenz & historische Skalierung** inkl. Commit-P50/P95/P99, 10k/100k Quittungen, unabhängige Last-/Langzeitreplikation und messbare Recovery-SLO.

## 6. Web-Fachquellen und bewusste Nicht-Übernahme

- RFC 9162, Konsistenz-/Inklusionsbeweise und Split-View-Risiko: https://www.rfc-editor.org/rfc/rfc9162.html — Referenz für eine spätere echte Transparenzebene, **nicht** aktuell implementiert.
- SQLite ACID-Garantien gelten **für eine SQLite-Transaktion**, nicht für zwei Dienste oder zwei DB-Dateien: https://www.sqlite.org/transactional.html ; https://www.sqlite.org/howtocorrupt.html
- SQLite PRAGMA synchronisation: `DELETE`/`EXTRA` ist die eng gefasste Wahl für diese Research-Datenbanken: https://www.sqlite.org/pragma.html#pragma_synchronous
- Dieses ZIP-Manifest ist SHA-256-konsistent, aber **nicht extern signiert**. Freigabestatus bleibt strikt **NO-GO**.

## 7. Geprüfter Abschlussstand

**425/425 erfolgreich**, 11 isolierte vollständige Gruppen; 401 historische und 24 neue Fälle. Originalquelle: `EVIDENCE_V0720/full_suite_v0720.log`, maschinenlesbar `suite_summary.json`. Gleichwertiger vollständiger ZIP-Wiederholungslauf wird separat protokolliert.

Lokaler ABBA-Status-Benchmark (je 4×80 Operationen): 1 KiB: historischer Core 0,6517 ms versus Commit-Floor-Core 5,3803 ms (ca. 8,3×); 64 KiB: 0,7440 ms versus 5,3005 ms (ca. 7,1×). Beide Wege benutzen dieselben aktuellen Bibliotheken und dieselbe DB; verschiedene Sicherheitssemantik. Rohdaten: `EVIDENCE_V0720/benchmark_commit_floor_abba.csv`.
