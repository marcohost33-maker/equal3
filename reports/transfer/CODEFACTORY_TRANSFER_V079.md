# Equal3 v0.7.9 – CodeFactory Wissenstransfer (ohne Integration)

Sinnvolle wiederverwendbare Referenzbausteine, nicht in CodeFactory produktiv eingebaut:

- **Source-bound negative-first**: SQLite-Dateiformat vor Öffnung ohne Vertrauen auf nachträgliches PRAGMA prüfen; expliziter Legacy-/Migrations-HOLD.
- **No implicit downgrade**: `PRAGMA journal_mode=DELETE`, `PRAGMA synchronous=EXTRA` verpflichtend und verifiziert; Ausnahme-Flags dürfen Journal-Invariante nicht umgehen.
- **OS identity proof**: Isolierter Test mit verschiedenen Unix-UIDs, Socket-GID und `SO_PEERCRED`, negative Dateizugriffstests; root-Abhängigkeit offengelegt.
- **Operational assurance**: `NO_GO` als maschinenlesbares Gate, Release-Datum/SQLite-Runtime/SHA getrennt.
- **Bench provenance**: ABBA-Mikrobenchmark, per Variante SHA-256 und SQLite-Version; kein allgemeiner Performance-SLA.

Wichtig: Die ursprüngliche CodeFactory in anderen Repos wurde nicht verändert und seine tatsächliche Schnittstellen-/Lizenzkompatibilität wurde nicht geprüft. Die SQLite-DELETE-Entscheidung gilt ausschließlich für den Equal3-Ankerdienst, nicht pauschal für alle SQLite-Anwendungen.
