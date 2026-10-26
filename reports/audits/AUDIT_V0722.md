# Equal3 v0.7.22 — unabhängiges Follow-up-Re-Audit (25.10.2026)

## Gesamturteil
Research NO-GO. Quelle: tatsächlich entpackte v0.7.21-Lieferdatei, keine Produktivfreigabe. Die früheren 427/427 bestehen als **historischer** Nachweis v0.7.21. In dieser Runde kam der monolithische `anchor_wire`-Mehrprozesstest nicht zum Abschluss. Neue 430/430 wird **nicht** behauptet.

## Kritischer bestätigter Fehler
`CommitGatedWriterCore._check_floor` verglich Version und Wert-Digest, aber nicht die eindeutige Request-ID. Unabhängig authentifizierte Zweige A und B aus demselben Genesis-Stand konnten jeweils `v=1` und SHA-256 des identischen Zielwertes aufweisen, während `request_id(A)!=request_id(B)`. Ein auf A fortgeschriebener signierter Zeuge akzeptierte zuvor Zweig B als `MATCH`. Negativtest auf unmodifiziertem v0.7.21: **FAIL** (Schutzinvariante verletzt). Positivtest nach der Änderung: **PASS**.

## Korrektur und Beweisgrenze
Bei Witness-Version >0 liest der Writer `StateStore.inspect_request(floor.request_id)` in einem authentifizierten SQLite-Snapshot. Nur wenn die HMAC-verifizierte Quittung exakt zu Witness-Request-ID, Head-Version und Digest gehört, darf MATCH gelten. Genesis verlangt null-Request-ID. Zweite Witness-Challenge prüft `request_id` ebenso wie Version und Digest; danach wird der Ankerstand erneut gelesen.

Diese zusätzliche Lesepfadprüfung schützt nicht gegen einen gemeinsamen Rollback aller drei Datenbanken, kompromittierte Schlüssel, kompromittierten Zeugen, nachträglichen Fork der HMAC-Kette oder concurrent cross-service TOCTOU. Weder Merkle-Konsistenzbeweise noch unabhängige Reviewer wurden implementiert.

## Regressionen und Benchmark
29/29 fokussierte Tests PASS (24 geerbte Witness, 2 Expiry, 3 neue Request-Bindung). Weitere abgeschlossene ältere Gruppen: Equal 57, Store 96, Runtime 21; Koordinator 23, Attester 24, Policy 14, Rotation 28, Epochenzeuge 26, Writer 21, Ankerbasis 63. Der alte `anchor_wire`-Block lief in dieser Umgebung nicht zu Ende; daraus wird **kein** Gesamt-PASS abgeleitet.

4+4 ABBA-Run-Mediane, je 45 abgesicherte Abfragen, getrennte Prozesse/Quellcodes: v0.7.21 **2.162565 ms**, v0.7.22 **2.1602665 ms** (Median der vier Run-Mediane). Kein belastbarer Leistungsgewinn oder -verlust; IPC und Background-Work können die Streuung dominieren.

## Positive blinde Flecken
(1) Authentifizierte Quittungen erlauben Request-lineage-Oracle ohne pauschale Neuentwicklung des Protokolls. (2) Die signierte Floor-Struktur enthielt bereits request_id, der Verifier nutzte es nicht: geringer Patch, hoher semantischer Nutzen. (3) Der Differenzialtest kann für Digi, Insandbox und CodeFactory zur Fork-Erkennung adaptiert werden, **nur** nach eigener Sicherheitsprüfung.

## Offen / Production P0
Echte unabhängige, monotone Mehrhost-Vertrauensdomäne; direkter Import-/Legacy-Bypass; SQLite 3.46.1 ungepatcht und Provenienz; Schlüssel-KMS/HSM/Rotation; Commit-/Observer-Fencing und Recovery; physischer Stromausfall/ENOSPC/VFS-Test; manipulationssichere Transparenzlog-/Konsistenzbeweise; Verschlüsselung inkl. Backups und Journale; Schweizer DSG-Dateninventar/Retention/DSFA, unabhängiger Penetrationstest. `NO-GO` bis reale Nachweise vorliegen.

## Externe Referenzen
- RFC 9162: https://www.rfc-editor.org/rfc/rfc9162.html (Inklusions-/Konsistenzbeweise; Equal3 behauptet keine RFC-9162-Konformität)
- SQLite-Isolation: https://www.sqlite.org/isolation.html (SQLite DB-Serialisierung ersetzt keine RPC-Atomizität)
- OWASP Key Management: https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html

## Provenienz
`EVIDENCE_V0722/test_evidence.json`, `source_diff.patch`, `focused_tests.log`, `ABBA_request_binding.json`; Manifest nur SHA-256 ohne unabhängige Signatur.
