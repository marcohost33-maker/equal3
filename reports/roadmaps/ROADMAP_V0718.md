# Equal3 v0.7.18 – Priorisierte Umsetzung / Abnahmekriterien

| Gate | Nächster Schritt | Nachweis | Status |
|---|---|---|---|
| G0 root-signierte Attesterrotation | Bindung, Epochenfolge, Update atomar, Negativtests | neue lokale Tests | RESEARCH IMPLEMENTIERT |
| G1 Root Provisioning | separater KMS/HSM Root-Key, auth. Trust-Policy, 2-Personen-Approval | echte unabhängige signierte Rollenzuweisung | P0 OFFEN |
| G2 External Epoch Floor | remote monotones CAS und unabhängige Rücksetzdomäne | Test gemeinsamer DB-Rollback gegen externen Floor | P0 OFFEN |
| G3 Commit Evidence | reproduzierbarer TOCTOU-freier Beobachtungs-/Freigabe-Flow | Crash/Pause/Adversarial Review-Lab | P0 OFFEN |
| G4 SQLite Binary | gepatchter verifiziert geladener Build, CVE-/Source-Provenienz | sha3 + ABI + 100% Regression | P0 OFFEN |
| G5 Infrastruktursicherheit | getrennter Writer/Anker/Signer, Keys, Disk-Encryption | OS ACL/MAC und Sicherheitskontrollen nachgewiesen | P0 OFFEN |
| G6 Root Rotation | root-of-root Recovery/Threshold über Schlüsselwechsel | Zweifachsignatur/Trust Chain + Root-Revoke | P0 OFFEN |
| G7 Fault + Compliance | Stromausfall-VFS, KMS-Retention, DSFA/DSG, unabhängige Prüfung | reale Evidenz/Owner-Freigabe | P0 OFFEN |
| G8 Performance | 10k/100k log, P50/95/99, RSS, Energie, unabhängige Last | ABBA und reproduzierbarer Korpus | P1 OFFEN |

**Freigabe:** NO-GO. Kein GitHub Push/Merge/Deploy. Alle neuen Artefakte dienen Forschungs- und Wissenstransferzwecken.
