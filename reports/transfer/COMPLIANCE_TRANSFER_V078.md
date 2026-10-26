# Equal3 v0.7.8 – Datenschutz, Audit und Governance: Transfer (Vorschlag)

Status RESEARCH. Die Tests verarbeiten ausschließlich synthetische Daten; keine Rechtsberatung und kein Update der zentralen Matrix ohne deren aktuellen Schemaabgleich.

| ID | Kontrolle | Test-/Sachstand | Status |
|---|---|---|---|
| EQ078-01 | Integrität von Audit-Log und Anti-Replay-Nonce | Domänengetrennte Versiegelung mit v0.7.8 implementiert, gezielte Negativtests grün | PARTIAL; same-trust und common rollback offen |
| EQ078-02 | Zugriff / Privilegien | Code in gleicher Test-UID; keine OS-ACL-/FD-/Root-Isolation | P0 OPEN |
| EQ078-03 | Vertraulichkeit / DSG | DB/WAL/SHM/Backup/Log teilweise Klartext; Schlüssellebenszyklus ungeprüft | P0 OPEN |
| EQ078-04 | Laufzeit-Härtung | SQLite 3.46.1 upstream WAL-reset fix nicht nachgewiesen | P0 HOLD |
| EQ078-05 | Rechenschaft / Protokoll-Authentizität | HMAC dient der lokalen Manipulationserkennung; keine unabhängige Signatur, kein Fremdanker | P0 OPEN |
| EQ078-06 | Retention / Speicherwachstum | 100.000 Logzeilen als fail-closed Obergrenze ohne Archivierungsprozess | P1 OPEN |
| EQ078-07 | DSFA Schweiz | Nur bei konkretem personenbezogenem Hochrisiko-Einsatz zu bewerten | CONDITIONAL |

Vor Echtdatenbetrieb: Rollen-/Zugriffsmatrix, technische und organisatorische Maßnahmen, Zweck, Löschfristen, DSFA-Bedarf und verifizierte Restore-Prozesse klären.

Referenz: OWASP Logging Cheat Sheet, OWASP Cryptographic Storage, schweizerisches DSG.
