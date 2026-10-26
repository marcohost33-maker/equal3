# Equal3 v0.7.14 – nächste verbindliche Gates (NO-GO)

**G0, akute Integrität:** WriterCore darf im Produkt nicht direkt `StateStore.apply()` ausführen; bauen Sie eine *remote attested coordinator*-Schnittstelle, die `prepare -> SQLite Commit -> independent signed finalize` unterstützt und für Crashfenster MANUAL HOLD ohne stilles Auto-Finalize erzwingt. Nachweis: joint-rollback und partition/in-doubt Negativtests.

**G1, gepatchter SQLite-Build:** Offizielle `sqlite3.c` und Amalgamation ZIP gegen sqlite.org SHA3-256 prüfen, in eigener hermetischer CI bauen; unabhängige Ed25519-Approval, unveränderliche Identitätsbindung des tatsächlich gemappten Objects, vollständige Regression inklusive WAL-Writer-Checkpoints. Aktuelle 3.46.1 ist NO-GO.

**G2, realer Prozess:** Dienst unter eigenem nichtroot `equal3svc`, Client unter separatem `equal3writer`, dedizierte Socket-Gruppe; Code/State/Keys strikt nur Dienst, DB/Key 0600 und Verzeichnis 0700, Socket 0660/0710. systemd ProtectSystem=strict, NoNewPrivileges, PrivateTmp, ReadWritePaths begrenzen. Vorhandene alte CLI nur im Forschungsnetz. Verbot direkter Schlüssel-/DB-Mounts der Clients als harte Deployment-Verifikation.

**G3, API/Betrieb:** Externe CAS-Attestation, Audit-Log, Timeout/Rate und Retry, Monitoring/Rotation. Stabiler Request-ID-Cache ist nur so vertrauenswürdig wie authentifizierte Receipt-Historie. Negative tests für unknown commit, partial response, Slowloris, socket replacement, same-group wrong UID und unprivilegierte Dateizugriffe.

**G4, Schlüssel/Datenschutz:** Key Vault/HSM; DB/Journale/Backups verschlüsseln; Wiederherstellung testen; Löschung/Retention/DSFA abhängig von produktiver Verwendung.

**G5, Benchmarks:** Socket P50/P95/P99, TCP ist nicht vorgesehen; getrennte Nutzer und realistische 1 KiB/64 KiB/8 MiB, 1/50/250/10k receipts; RSS/CPU/wall-clock; 4+ randomisierte Trials; reale Fsync/Powercut-Faults und nachvollziehbare Build-Provenienz.

**Release:** Keine automatische Freigabe aus Testgrün. Owner + unabhängiges Security-Review der exakten SHA-gebundenen Artefakte.
