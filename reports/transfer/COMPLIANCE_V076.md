# Equal3 v0.7.6 — Datenschutz-/Compliance-Wissenstransfer

**Status:** Planungs-/Risikoeinträge zur Aufnahme in die zentrale Matrix, **keine** abgeschlossene Compliancefreigabe oder Rechtsberatung. Sämtliche realisierten Tests verwenden synthetische Daten.

| ID | Risiko | Kontrollziel | Evidenz | Reststatus |
|---|---|---|---|---|
| EQ076-01 | DB/WAL/SHM/Backups/Temp im Klartext | Verschlüsselung ruhender Daten mit Key-Lifecycle, sichere Speicherung und Löschung | Verschlüsselungsimplementierung fehlt | P0 OPEN |
| EQ076-02 | Gemeinsame administrative Rücksetzung | Unabhängiger monotoner Auditanker | Joint-Rollback-Gegenbeispiel in Tests | P0 OPEN |
| EQ076-03 | Gleiche UID für Dienst und Client | Strenge prozess- und dateisystemseitige Rollen | Test-Peer-UID funktioniert nur unter derselben Test-UID | P0 OPEN |
| EQ076-04 | Review-Token/Request-ID/Hash pseudonyme Metadaten | Minimierung, Aufbewahrung und ACL | Struktur des Nonce-Ledgers und Reviewlogs dokumentiert | P1 OPEN |
| EQ076-05 | Sicherheitsvorfälle und ungeklärte Commits | Adjudikation, Vier-Augen, Incident-Runbook | Pending bleibt fail-closed; externe Evidenz fehlt | PARTIAL |
| EQ076-06 | Schlüssel & Wiederherstellung | Getrennte KMS/KEK/DEK-Kontrollen, Revision, Rotationsplan | Testdateien nur Mode 0600; kein Schlüsseldienst | P0 OPEN |
| EQ076-07 | Personendaten im späteren Einsatz | DSG Schweiz, Verhältnismäßigkeit, ggf. DSFA nach Art. 22 DSG | Im Labor keine Echtdaten | CONDITIONAL |
| EQ076-08 | Dritte/Cloud/Grenzüberschreitung | Auftragsbearbeiter-, Zugriff- und Standortprüfung | Kein Cloudservice im Labortest; späteres Backend offen | NOT_ASSESSED |

Referenzen: https://www.fedlex.admin.ch/eli/cc/2022/491/de ; https://www.edoeb.admin.ch/de/datenschutz-folgenabschaetzung ; https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html
