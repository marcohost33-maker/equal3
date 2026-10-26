# Equal3 v0.7.21 – Konsolidierte priorisierte Roadmap

| Gate | Priorität | Maßnahme | überprüfbares Exit-Kriterium | Stand |
|---|---|---|---|---|
| R0 | P0 | Minimal-Härtung Expiry/CAS | Negativ-v0720 akzeptiert, v0721 verweigert; 427 Tests | LOKAL IMPLEMENTIERT |
| R1 | P0 | Vertrauensdomäne Witness | Multi-Host, unabhängiger Storage/Admin, unabhängige irreversible Version, Restore-Fork-Test | OFFEN |
| R2 | P0 | Legacy Bypass entfernen | Distribution/UID/Fs ACL verhindern jeden unsicheren StateStore/Coordinator-Zugang | OFFEN |
| R3 | P0 | Verlässlicher Post-Final Commit Proof | Ende-zu-Ende-Recovery, Witness Persistenz + Observer Session Fencing, keine Zeit-/ACK-Lücke | OFFEN |
| R4 | P0 | SQLite / Build Provenienz | echter gepatchter Build, sha3 sqlite3.c, DSO mapped hash, unabhängiger Verification-Bericht | OFFEN |
| R5 | P0 | Key Ceremony / Rotation / KMS | getrennte Rollen, HSM/KMS, Ablauf/Widerruf, zerstörbare Backups | OFFEN |
| R6 | P0 | Fault Lab | physisches Power-Cut, fsync, ENOSPC, journal corruption, partition + split-brain, SLO | OFFEN |
| R7 | P0 | Privacy / Compliance | Dateninventar, DSFA, CH DSG Art. 6–8/22–24, externes Review | OFFEN |
| R8 | P0 | Unabhängiger Review | Red-team, Security audit, revisionsfeste Freigabe, Threat Model | OFFEN |
| R9 | P1 | Checkpoint-/Audit-Performance | 10k/100k, P50/95/99, Auth-Ketten-/Checkpoint-Sicherheit formalisieren | OFFEN |

## Entscheidung
Nur ausdrücklich markierte Forschungsmodi erlauben lokale Simulation. **Production: NO-GO.** Kein stilles Migrieren, kein GitHub-Push. Freigaben nur über protokollierte Gates.
