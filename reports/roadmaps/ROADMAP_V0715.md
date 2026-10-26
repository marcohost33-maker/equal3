# Equal3 v0.7.15 – nächste Roadmap / harte Gates

Stand: 25. Oktober 2026. Ausgangspunkt v0.7.14, 23 neue Tests und sechs Regressionstest-Lanes. Kein Deployment und kein Push.

| Priorität | Entwicklungsziel | Abnahmebeleg | Stand |
| --- | --- | --- | --- |
| P0-A | Koordinierter Writer blockiert vor unabhängiger Freigabe | Positive/negative Tests für Prepare, Commit, HOLD, Review, Retry über Writer+RPCAnchor | Forschungs-Prototyp IMPLEMENTIERT |
| P0-B | Eigenständiges, nicht gemeinsam rücksetzbares Trust-Root | Separate Host-/HSM-/KMS-Domäne; Joint-Rollback-Angriff MUSS FAIL; attestierte Provenienz der Commit-Evidenz | OFFEN |
| P0-C | Betriebsfähiger geschützter Startpfad | Nur genau ein Writer-Service, verbindlicher Anker-RPC, separate OS-Identitäten, geschützte Schlüssel, aktive Systemdienst-Sandbox und unveränderliches Deployment-Gate | OFFEN |
| P0-D | Gepatchter SQLite-Build | Offizielle Quell- und Binärhashes + unabhängige Signatur + tatsächlich geladene Bibliothek; kompletter Regression-/Stresstest | OFFEN |
| P0-E | Manipulationssichere Review-Evidenz | Vom Writer unabhängige Prüfinstanz bindet COMMITTED vs NOT_COMMITTED an Intent, Request-ID und DB-Snapshot; Review-Key nie im Writer | OFFEN |
| P0-F | Crash-/Dateisystem-Fault-Labor | Strom-/Disk-Fault an `prepare`, Commit und Finalize; fSync/ENOSPC/torn sectors; keine stillen Resets | OFFEN |
| P0-G | Schlüssel, DSG und Security-Abnahme | Verschlüsselung aller Datenträger+Backups, KMS-Rotation/Recovery, Retention/DSFA, unabhängige Freigabe | OFFEN |
| P1-H | Skalierbarkeit und Performance | O(n)-Historienkosten mit 10k/100k Quittungen; authentifizierte Checkpoints und vollständige Replay-Baseline, RSS/P99/Throughput | OFFEN |

**Entscheidungsregel:** Kein automatisches Finalize, kein unbekannter Commit als Erfolg, kein Rückschritt des Ankers, kein GO allein aufgrund grüner Tests. Die `serve`-CLI bleibt blockiert bis P0-B bis P0-G operativ nachgewiesen sind.
