# Equal3 v0.7.15 – Koordinierter Writer / unabhängige Freigabe (FORSCHUNG, NO-GO)

**Datum:** 25.10.2026 · **Quelle:** unverändertes lokales ZIP `EQUAL3_v0714_PROTECTED_WRITER_RESEARCH_2026-10-25.zip`; daraus extrahierte Basis · **Ziel:** G0 der Roadmap, keine GitHub-/Produktionsänderungen.

## 1. Falsifikation am bisherigen Quellstand

Im Modul `writer_service_v0714.py` führte `WriterCore._dispatch_locked(SET)` nach `prepare_update()` den lokalen Aufruf `self._store.apply(proposal)` aus und meldete `ok=True`, **ohne** zuvor `RPCAnchor.prepare` zu kontaktieren oder auf eine externe Bestätigung zu warten. Somit schützte die OS-UID-Grenze nur den lokalen Schlüssel, aber nicht die behauptete Ankerbindung aller Commits. Der öffentliche `serve`-Befehl blieb zwar ausdrücklich blockiert, die noch nicht integrierte Ankerabfolge war jedoch das zentrale G0-Entwicklungsdefizit.

## 2. Tatsächlich implementiert

**Neues Modul:** `anchored_writer_v0715.py` – `AnchoredWriterCore` für `DELETE/EXTRA`-StateStore mit authentifizierter V2-Historie, einer kooperativen Serializer-Sperre und bestehendem `CoordinatedStore`-Protokoll. Die Writer-RPC-Protokollklassen bleiben dieselben wie im Vorstand.

1. `STATUS`: zustandsgebundener Anker-Abgleich; nur bei `MATCH` ein positives `ok=True`.
2. `SET` ohne alten Request: Diagnose `MATCH` -> authentifizierte Quittungsprüfung -> Vorschlag mit stabiler Request-ID -> `anchor.prepare` -> SQLite-Commit -> Diagnose `COMMITTED_PENDING_HOLD` -> **explizit `ok=False` / `EXTERNAL_REVIEW_REQUIRED`**.
3. Reviewer unter separater Vertrauensrolle prüft außerhalb des Writer-RPC-Pfads die DB und erteilt eine genau zum Intent passende Autorisierung. `FINALIZE_COMMIT` kann erst danach den Anker fortschreiben. (Im Test: HMAC-basierte **synthetische** Review-Tokens, niemals produktive Reviewer-Keys.)
4. Anschließender `SET`-Retry mit gleicher ID/Nutzlast meldet nur nach `MATCH` einen authentifizierten bereits bestätigten Commit. Ein abweichender Ziel-Digest zur gleichen ID wird abgewiesen.
5. Bei fehlendem Anker, verlorener Prepare-Antwort oder inkonsistentem Ledger entstehen `HOLD` oder Socket-Fehler, **kein vermeintlicher Commit-Erfolg**.
6. `writer_service_v0714._Handler` wurde so gehärtet, dass auch `AnchorHold` als generisches `HOLD` gemeldet wird, statt einen Handler-Thread mit nicht behandelter Exception zu beenden.

**Keine** Änderung am produktiv gesperrten `serve`-Pfad: Es gibt **keinen** in der ausgelieferten Version verwendbaren Produktions-Writer/Anker-Verbund. Der Forschungsprototyp kann über die in Tests demonstrierten bestehenden Socketserver betrieben werden.

## 3. Tests und gezielte Gegenbeispiele

- Sechs unabhängige Regressionstest-Lanes mit `-W error::ResourceWarning`: 91 + 57 + 96 + 21 + 21 + 23 = **309/309 PASS** (Python 3.13.5, SQLite 3.46.1, Linux 6.18.55).
- 23 neue Tests: Remote-CAS-RPC mit persistenter SQLite-Autorität; normaler Review-Ablauf; Pending bei Neustart; verlorene Prepare-Antwort; unbekannter Commit; konkurrierende Request-IDs; falsche Reviewer-Tokens; falsche Reviewer-Entscheidung; Manipulation der Quittung; unerlaubte Rohschreiber; GET/SET über echten Writer-Unix-Socket; falscher RPC-Authentifizierungsschlüssel; weitere Negativfälle.
- **Kritische Falsifikation (NO-GO bleibt):** Bei gemeinsamer Wiederherstellung **beider** lokal verwalteten DB-Dateien auf früher gültige Versionen melden StateStore und Anker wieder `MATCH`. Ohne unabhängig monotones, physisch/logisch isoliertes Trust-Root ist gemeinsamer Rollback nicht sicher erkennbar.
- Ein Ein-Prozess-Monolith ist hier nicht als bestanden behauptet; getestet wurden getrennte Lanes, konsistent mit den zuvor dokumentierten Mehrprozess-/Harness-Problemen.

## 4. Benchmarks / Interpretation

Synthetische 4-Sweep-ABBA-Messung, **80 Transaktionen pro Modus und Nutzlast**: Direkt-WriterCore vs. koordinierter in-process Commit mit künstlich zeitnah bereitgestellter Review-Freigabe und anschließendem Retry.

| Zustand | Direkt P50/P95 | Koordiniert P50/P95 |
|--|--|--|
| 1 KiB | 4,349 / 8,446 ms | 9,871 / 17,014 ms |
| 64 KiB | 4,998 / 9,030 ms | 11,795 / 20,181 ms |

Eine **zweite** Messung über **zwei echte lokale Unix-Sockets** (Writer + persistente HMAC-authentifizierte Ankerinstanz, gleiche UID, automatische *simulierte* Freigabe, je 24 Commits je Nutzlast) ergab 1 KiB **25,268 ms P50 / 39,868 ms P95** und 64 KiB **28,689 ms P50 / 33,676 ms P95**. Diese zwei Versuche messen **verschiedene Workflows**, sind kein statistisch belastbarer Produktionsvergleich; insbesondere ist die menschliche Review-Zeit nicht enthalten. Ausgangsdateien/Hashbindungen und Rohsamples liegen unter `EVIDENCE_V0715/`.

## 5. Unveränderte P0-Risiken

- **Anker-Unabhängigkeit:** Bisheriger Anker ist lokal persistent, nicht physisch oder administrativ unabhängig; gemeinsam rücksetzbar, wie negativ nachgewiesen.
- **Externe Evidenz:** Der Anker überprüft Reviewer-HMAC und CAS-Intent, **nicht** unabhängig, ob der SQLite-Commit tatsächlich bestand. Der Reviewer muss vertrauenswürdige und attestierte Commit-Evidenz bekommen.
- **Produktionspfad:** `serve` bleibt bewusst fail-closed. Signiertes Runtime-Gate, getrennte UID-/Gruppen-Topologie und externe Attestation noch nicht als eine produktive Ende-zu-Ende-Kette bereitgestellt.
- **SQLite/Dateisystem:** SQLite 3.46.1; keine hardware- oder VFS-basierten Stromausfalltests, kein unabhängig validierter gepatchter Build; `DELETE/EXTRA` reduziert den spezifischen WAL-Race-Angriffsbereich, ersetzt keine Build-/VFS-Prüfung.
- **Schlüssel/Datenschutz:** DB, Journale, Backups und Recovery-Medien derzeit nicht nachweislich verschlüsselt; keine HSM/KMS-Rotation oder unabhängige DSG-/DSFA-Freigabe.
- **Historienwachstum:** Vollauthentifizierung der Quittungen ist O(n) und kann große Latenz-/DoS-Budgets auslösen; keine attestierte komprimierte Checkpoint-Strategie.

## 6. Fachgrundlagen / Entscheidungsbegründung

1. SQLite `ATTACH`-Transaktionen können *bei Rollback-Journal* unter Bedingungen lokal atomar über Dateien sein, **nicht jedoch** über separate RPC-/Trust-Domänen. Ein privater externer CAS-Anker darf nicht durch einen SQLite-`ATTACH`-Shortcut zu einer Scheinsicherheit erklärt werden: https://sqlite.org/lang_attach.html
2. SQLite-Dokumentation zur mehrstufigen Commit-Mechanik und den Annahmen zum Dateisystem: https://www.sqlite.org/atomiccommit.html
3. SQLite-WAL-Grenzen und konkurrierende Nutzung: https://www.sqlite.org/wal.html
4. OWASP Lebenszyklus, Trennung und Schutz kryptografischer Schlüssel: https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html

**Urteil: v0.7.15 ist ein getesteter, ankergebundener Forschungs-Writer-Kern mit vorsichtigem HOLD-Verhalten, keine Produktion. Freigabe: NO-GO.**
