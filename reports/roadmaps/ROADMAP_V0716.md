# Equal3 v0.7.16 – priorisierte Nachfolge-Roadmap

**Stand:** 2026-10-25; Research/NO_GO. Kein GitHub-Push, keine Produktionsfreigabe.

| Gate | Priorität | Kriterium | Status |
| --- | --- | --- | --- |
| EQ16-G0 | P0 | Der neue Behördentyp verlangt Reviewer-Token **und** separat signierte Momentaufnahme; unzulässiges Finalize wird zurückgewiesen | Im Forschungsprototyp getestet |
| EQ16-G1 | P0 | Die private Attestierungs-Signatur entsteht ausschließlich in getrenntem Betriebskonto/HSM; key ID/pinned root, Revocation, Deployment und sichere Uhr | OFFEN |
| EQ16-G2 | P0 | Attestierung beweist tatsächliche dauerhafte Commit-Tatsache aus unabhängigem, gegen Rollback geschütztem Speicher/Zeugen, selbst bei nachfolgendem DB-Rollback | OFFEN; Gegenbeispiel reproduziert |
| EQ16-G3 | P0 | Anker wird auf physisch/logisch eigenständigen Trust-Service verlagert; gemeinsame Rollback-Gegenprobe schlägt nachweislich fehl | OFFEN |
| EQ16-G4 | P0 | Gepatchte SQLite-Bibliothek (3.54.1 oder verifiziert gepatchter Build) tatsächlich in der Python-Laufzeit geladen und signiert attestiere Herkunft | OFFEN |
| EQ16-G5 | P0 | Einziger writer service + OS Mandatory Access Control + root provisionierte Richtlinie, kein `research_only`-Bypass | OFFEN |
| EQ16-G6 | P0 | Crash-VFS, Hardware-Powerloss, ENOSPC, DB/Witness-Faults, Review-Time-of-check/Time-of-use unter realem Mehrprozess-Betrieb | OFFEN |
| EQ16-G7 | P0 | Verschlüsselung (DB, Journal, Temp, Backup), Schlüssel-Rotation/Wiederherstellung, DSG-Löschung/Retention und unabhängige Security-Abnahme | OFFEN |
| EQ16-G8 | P1 | 10k/100k Quittungen, P99, RSS, sichere authentifizierte Checkpoints, kontinuierliches Stateful-Fuzzing | OFFEN |

**Reihenfolge:** (1) Unabhängige Beobachtungsdomäne mit beweisbarer Quelle; (2) effektive nicht-rücksetzbare Anker-Domäne; (3) Integration von Service-Boot und signierten Runtime-Policy; (4) Fault-Labor und Release-Gates; (5) Performanceskalierung. Weiteres Modell-Tuning ohne unabhängige Sicherheitsevidenz schließt diese P0-Gates nicht.
