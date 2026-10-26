# Equal3 v0.7.22 – priorisierte verifizierbare Roadmap
P0-1: Sicherheitstest `same value + different request_id` dauerhaft in unabhängige CI übernehmen; vollständige `anchor_wire`-Testsuite stabilisieren und 430er Regression aus frischem Paket erbringen.
P0-2: Produktionsschnittstelle auf attestierten Writer begrenzen, OS-Zugriffsrechte (separate UID) erzwingen, alle Legacy-Binärmodule vom produktiven Startpfad ausschließen; adversarial bypass test.
P0-3: Unabhängig betriebenes monotones Witness-/Trust-Register, Replay- und Fork-Gossip-Protokoll, signierte Checkpoints, Inklusions-/Konsistenzbeweise und Rollback-Labortests.
P0-4: Offiziell gepatchtes SQLite-Binary samt unabhängiger Signatur/Buildnachweise in tatsächlichem Python-Prozess, komplett neue Regression.
P0-5: End-to-end Observer-Fencing, Crashrecovery und dauerhaftes Commit-Proof an echter separater Identität; offline/timeout partition tests.
P0-6: KMS/HSM, Datenschutzinventar/CH-DSG, vollständige encryption-at-rest backups, log privacy, VFS/powerloss lab.
P1: Laufzeitkosten O(n) historischer Audit, authentifizierte Checkpoints mit adversarial proof tests und P50/P95/P99 auf 10k/100k Historie.
Status: NO-GO. Keine Produktion und kein GitHub-Push.
