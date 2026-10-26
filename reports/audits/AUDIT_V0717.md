# === / Equal3 v0.7.17: Cross-Version-Audit und Attester-Policy-Bindung

**Datum:** 25.10.2026. **Status:** RESEARCH / NO_GO. Ausgangsstand v0.7.16 vom unveränderten, SHA-256-gelisteten Artefakt. Quellcode nur lokal geändert.

## 1. Kritik an den letzten vier Entwicklungsreaktionen

**Stärken:** v0.7.14/15 eingeführter getrennter Writer und zweistufiges Anchor-Commit; v0.7.16 verlangt signierte Beobachtung an der Authority-Grenze; crash/rollback mit HOLD statt Auto-Freigabe; negative-first Falsifikation und getrennte Tests.

**Neu nachgewiesene Schwäche (NR-0717-01):** In v0.7.16 speichert die Authority keinen persistent versiegelten Fingerprint des Attestierungs-Verifikationsschlüssels bzw. der Deployment-ID. Beim Re-Open mit fremdem `Ed25519PublicKey` und veränderter Deployment-ID akzeptiert der Prozess signierte Beobachtungen des neuen Schlüssels. Mit weiterhin gültigem Reviewer-HMAC wurde ein vorbereiteter Commit finalisiert. Dies belegt die fehlende Policy-Bindung beim Neustart; eine Kompromittierung der Reviewer-Rolle allein wurde nicht gezeigt.

## 2. Implementierung

1. `trust_binding(id=1,policy,seal)` wird beim erstmaligen Bootstrap mit Store-ID, Deployment-ID und SHA-256-Fingerprint des Ed25519-Public-Key als kanonisches JSON erstellt und mit einem domänenseparierten HMAC-SHA256 versiegelt.
2. Der Konstruktor lehnt einen bereits existierenden Anker ohne versiegelte Richtlinie ab. Bei Absturz zwischen dem ursprünglichen Bootstrap und dem neuen Policy-Commit bleibt ein manuell zu klärender HOLD statt stiller Neuanlage.
3. Jede Authority-Operation, die den persistenten Zustand über `_load` aufnimmt (Status, Prepare, Adjudicate), prüft Policy-Fingerprint und Seal im selben SQLite-Snapshot. Keinerlei automatische Rekey- oder Schema-Migration.
4. Die Richtlinienprüfung verweigert fehlende, zusätzliche oder mehrfach ersetzte Trust-Binding-Einträge, ungeeignete BLOB-Typen, Manipulation des Seal sowie Änderungen des Public Key oder der Deployment-ID beim Restart.
5. Bestehende v0.7.16-Attestierungs-Tests bleiben erhalten; `test_attester_policy_v0717.py` ergänzt 14 neue negative und positive Prüfungen.

Die Baseline-Falsifikation und die Abwehr-Nachweise liegen in `EVIDENCE_V0717/negative_first.json`; die präzisen Source-Diffs in `EVIDENCE_V0717/v0716_to_v0717.patch`.

## 3. Performance

ABBA, 4 Durchläufe, je 160 Status-Aufrufe, jede Variante in einem frischen Python-Prozess und neuer SQLite-DB, Proposal-/Bootstrap-Dauer nicht gemessen. P50 der vier Durchlauf-Mediane:

- v0.7.16: 0.166817 ms
- v0.7.17: 0.201042 ms
- Relative Änderung: **+20.5 %**.

Mikrobenchmark eines leeren Authority-Audit-Ledgers. Keine Aussage zu Netzwerklatenz, P99, 100k Einträgen oder produktiver Ende-zu-Ende-Performance; sehr kurze Zeiten und geringe Messdauer können Messrauschen zeigen. Quellcode-SHA-256 in der CSV ausgewiesen.

## 4. Sicherheit / Restlücken und Falsifizierbarkeit

**P0 bleibt OFFEN:** Die lokale HMAC-Versiegelung ist **kein unabhängiger Trust Root**. Betreiber/Angreifer mit der Authority-Seal-Key kann die Richtlinie neu signieren; eine gemeine Datei+Schlüssel-Rücksetzung ist nicht erkannt. Der historische `PersistentCASAnchor` ist als Forschungs-API enthalten und kann mit legitimem Review-/Seal-Credential weiterhin direkt geöffnet werden. Ungepatchtes Python-SQLite 3.46.1 auf diesem Host, kein VFS-Stromausfall-Labor, kein kryptografisch attestierter echter unabhängiger Commit-Zeuge. Die alten Authority-Dateien dürfen nicht automatisch in diese v0717-Pinning-Politik überführt werden.

**P1:** signierte Offline-Provenienz für Policy-Bootstrap, explizite Mehrparteien-Rekey-/Revocation-Prozedur, Authentizität des Manifestes, Cross-System-Spiegelung, Benchmarks 10k/100k Ledger, Einbettung des policy gate in den einzigen produktiven Boot-Pfad.

**Datenschutz:** Nur synthetische Testdaten. Private Ed25519-Testschlüssel werden pro Test generiert; nicht als produktive Schlüssel verteilen. Vertraulichkeit von Daten, Logs, Journals und Backups weiterhin separat sicherstellen.

## 5. Fachliche Referenzen

- NIST SP 800-57 Part 1 Rev.5 (Trust Anchor, Key Lifecycle, Kompromittierung/Revocation): https://doi.org/10.6028/NIST.SP.800-57pt1r5
- OWASP Key Management Cheat Sheet (Integrität der Schlüssel-Assoziation, Rotation): https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html
- RFC 8032, Ed25519: https://www.rfc-editor.org/rfc/rfc8032
- SQLite WAL-Bug, konkurrierende Verbindungen: https://www.sqlite.org/wal.html

**Gesamturteil NO_GO:** Präzise nachgewiesener Reboot-Rekey-Angriff erschwert; Produktionsreife und dauerhaft unabhängige Schlüsselhoheit weiterhin nicht belegt.
