# Equal3 v0.7.15 – Compliance-/Datenschutz-Transfer

Nur synthetische Daten im aktuellen Test. Folgende Einträge in die operative Matrix übernehmen (hier **nicht** als erledigt markiert):

- `EQ715-01 WRITER_ANCHOR_G0_RESEARCH_ONLY`: lokaler Coordinator eingeführt; Produktions-Deployment weiterhin technisch blockiert.
- `EQ715-02 JOINT_ROLLBACK_P0_OPEN`: zwei DB-Dateien gemeinsam rücksetzbar; negativer Gegenbeweis im Test.
- `EQ715-03 REVIEW_EVIDENCE_P0_OPEN`: Reviewer-MAC autorisiert Entscheidung, belegt ohne unabhängige DB-Provenienz nicht deren Wahrheit.
- `EQ715-04 SQLITE_PATCH_P0_OPEN`: geladene SQLite-Laufzeit 3.46.1, nicht durch einen unabhängig attestierten gepatchten Build ersetzt.
- `EQ715-05 AT_REST_ENCRYPTION_P0_OPEN`: Zustandsdaten, Quittungsprotokolle, Journals und Backupmedien.
- `EQ715-06 MINIMIZATION_RETENTION_DSFA_OPEN`: mögliche Personenbezüge in Zustandswerten, Request-IDs, Quittungen und Review-Logs, Rollenmodell, Löschung/Aufbewahrung, Logging.
- `EQ715-07 BENCHMARK_SYNTHETIC_ONLY`: 80 x 2 In-process-Varianten und 24 x 2 Doppel-Socket-Transaktionen ohne human review oder echte unabhängige Domäne.

Schweizer Datenschutzgesetz / Verordnung im Einsatzfall gesondert prüfen; keine rechtliche Compliance-Freigabe aus dieser Forschungsrunde.
