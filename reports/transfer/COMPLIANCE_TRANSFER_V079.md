# Equal3 v0.7.9 – Datenschutz-/Compliance-Wissenstransfer

Synthetische Daten, kein Echtpersoneneinsatz und kein Rechtsgutachten. Vorschläge für die bestehende Compliance-Matrix, nicht deren bereits erfolgte Änderung.

| Control | Thema | Nachweis / Grenze | Status |
|---|---|---|---|
| EQ079-01 | SQLite WAL Safety | Anchor neu `DELETE/EXTRA`, aber StateStore WAL 3.46.1; aktueller Upstream 3.54.1 (Stand 25.10.2026) | P0 OPEN G1 |
| EQ079-02 | Rollen-/Dateitrennung | Zwei unterschiedliche POSIX UIDs im isolierten Root-Test; echte Deployment-ACLs fehlen | P0 PARTIAL |
| EQ079-03 | Unabhängige Integrität | Lokaler HMAC/Audit-Root schützt nur gegen begrenzte DB-Manipulation, kein gemeinsamer Rücksetzschutz | P0 OPEN |
| EQ079-04 | Aufbewahrung/Logs | Audit-Log enthält potenziell identifizierbare Request-Metadaten; TTL/Purge/Rechtsgrundlage und Archivierung offen | P1 OPEN |
| EQ079-05 | Vertraulichkeit | Klartextdaten in DB, `-journal`, Temp, Backups, Snapshots möglich | P0 OPEN |
| EQ079-06 | Incident/Recovery | Unbestimmter Commit bleibt HOLD, unabhängige Wiederherstellungsfreigabe fehlt | P0 OPEN |
| EQ079-07 | DSG/DSFA | Für produktive Nutzung mit Personen-/Gesundheitsdaten Risikoeinstufung/DSFA anhand realer Datenflüsse erforderlich | CONDITIONAL |

Keine produktiven Secrets oder Echtdaten im Paket. Keine automatische Migration vorhandener Anker. Vor Deployment Schweizer DSG/DSFA und Verträge mit Auftragsbearbeitern anhand der tatsächlichen Architektur prüfen.

Quellen: https://www.fedlex.admin.ch/eli/cc/2022/491/de ; https://www.edoeb.admin.ch/de/datenschutz-folgenabschaetzung ; https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
