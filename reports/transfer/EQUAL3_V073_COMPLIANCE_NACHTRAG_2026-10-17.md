# Equal3 Datenschutz-/Compliance-Nachtrag v0.7.3 – 2026-10-17
Aktualisierungsvorschlag für die bestehende Matrix; **kein gesetzliches Gutachten**. Nur synthetische Testdaten.

| Control-ID | Thema | Evidenz | Status | Folge |
|---|---|---|---|---|
| EQ-V073-01 | Datenvertraulichkeit | State+WAL+Backup können Klartext enthalten | P0 OPEN | Verschlüsselung at-rest, Zugriffsrechte, Key-Rotation |
| EQ-V073-02 | Korrekte Attestation | HMAC-Witness in eigenem Ordner ist keine echte fremde Trust-Domain | P0 HOLD | unabhängig unveränderbarer Monotonic Anchor |
| EQ-V073-03 | Datenminimierung | Witness enthält State-Digest/Store-ID, Linkability möglich | P1 OPEN | Metadaten minimieren, HMAC-Commitment prüfen |
| EQ-V073-04 | Vorfallmanagement | ungeklärtes Commit wird als AnchorPendingError gemeldet | PARTIAL | Runbook, Vorfallklassifikation und Eskalation |
| EQ-V073-05 | DSFA | Einsatz mit Personen-/Gesundheitsdaten möglich, hier nicht vorhanden | CONDITIONAL | DSFA bei potenziell hohem Risiko (Schweiz DSG Art.22) |
| EQ-V073-06 | Auftragsbearbeiter / Drittland | Keine Übertragung personenbezogener Echtdaten in lokalen Tests | NOT_ASSESSED | Datenfluss- und Rollenprüfung vor Einsatz |
| EQ-V073-07 | Backup und Retention | verifizierte Backups, derzeit ohne at-rest-Verschlüsselung | P0 OPEN | TTL, Key Lifecycle, Löschkonzept |
| EQ-V073-08 | Sicherheit / Resilienz | 96 lokale Tests; keine echte VFS-Stromausfallsimulation | RESEARCH_ONLY | VFS Fault Lab + Secure Review |
| EQ-V073-09 | Protokollierung | Request-ID/Hashes können rückverfolgbar sein | P1 OPEN | OWASP Log Minimisation/Retention/ACL |
| EQ-V073-10 | Rechenschaft | unveränderliches Audit-Protokoll noch nicht unabhängig verankert | P0 HOLD | externer, signierter (asym.) oder hardwaregestützter Anchor |

Quellen: DSG https://www.fedlex.admin.ch/eli/oc/2022/491/de; EDOEB https://www.edoeb.admin.ch/de/datenschutz-folgenabschaetzung; OWASP https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
