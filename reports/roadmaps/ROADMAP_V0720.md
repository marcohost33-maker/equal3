# Equal3 v0.7.20 – Roadmap / Acceptance Matrix (25.10.2026)

| Prio | Schritt | Nachweis und Exit-Kriterium | Stand |
|---|---|---|---|
| P0 | Commit-Floor signiert + CAS | v0720 lokaler Zeuge, Post-Final-Attestation, version+digest+request_id, gefälschte/Stale/Replay/Joint-Rollback-Tests | RESEARCH IMPLEMENTED |
| P0 | Extern nicht rücksetzbarer Zeuge | physisch/administrativ unabhängige Verwaltung, Monotonie auch unter Host-Rollback; zwei unabhängige Zeugen oder hardwaregestützte Register | OFFEN |
| P0 | Keine erfolgreichen Altpfade | alle `STATUS`-, `read`-, `SET`-Replay-Erfolge benötigen aktiven Commit-Floor; kein Import/RPC/Direktzugriff auf alte Forschungs-APIs | OFFEN: Wrapper ist nur Referenz |
| P0 | Observer-Provenienz | attestierte, nachweislich stabile Commit-Quelle, Reviewer-Governance und unabhängige Identität, kein TOCTOU-Fehler | OFFEN |
| P0 | Getrennte Multi-Host-Architektur | mTLS/Peer-ACL, unabhängiger Host/UID/Storage, root-/attester-/witness-Keyceremony | OFFEN |
| P0 | Recovery-Protokoll | Lost-ACK, Timeout, Observer-Ausfall, Crash nach Anker-Finalisierung/vor Witness-CAS; eindeutig HOLD/Retry ohne doppeltes Commit | OFFEN |
| P0 | Anti-Equivocation | mindestens extern überprüfte/gespiegelte signierte Checkpoints, Fork-Erkennung, Transparenzlog/Consistency Proofs | OFFEN |
| P0 | SQLite-Provenienz und Fault-Labor | gepatchte geladene SQLite-Version, Stromausfall-, fsync-, VFS-, ENOSPC-, Crash-/Split-Brain-Tests | OFFEN |
| P0 | Key Lifecycle/DSG | Verschlüsselung von SQLite/Journals/Backups, KMS/HSM, Widerruf, Swiss DSG Review | OFFEN |
| P1 | Read/Commit-Performance | 1 KiB bis 64 KiB, 10k/100k Historie, ABBA P50/95/99 End-to-End unter unabhängiger Last | ERSTE LOKALE STATUS-MESSUNG |

**Keine Produktivfreigabe.** Nicht stillschweigend migrieren, keinen GitHub-Push und keine Überschreibung bestehender Audit-Bundles. Priorität: externe Trust-Domäne statt immer weiterer lokaler Siegel.
