# Equal3 v0.7.8 – CodeFactory transferierbare Methoden, keine Integration behauptet

- **Adversarial-first**: zuvor akzeptierte Offline-Löschung eines Nonce-Eintrags zuerst am Quellpaket reproduzieren (`EVIDENCE_V078/negative_first_v077.log`).
- **Kanonischer Ledger-Digest**: beide Relationstabellen, Feldschema, deterministische Reihenfolge und Längenkodierung; Root wird von einem getrennten, domänenspezifischen MAC authentifiziert.
- **Atomic Update**: Audit-Insert + Root-Neuberechnung + Autoritätszustand im selben `BEGIN IMMEDIATE`.
- **Snapshot-Konsistenz**: mehrere SELECTs erfordern einen expliziten konsistenten Read-Transaction-Snapshot.
- **Fail-closed**: fehlendes Feld, fehlender Key, ungültige Signatur oder kaputtes Protokoll => HOLD; keine stillschweigende Migration.
- **Regression als Befund**: O(n) Vollprüfung verschlechtert Median/P95 bei 250 Einträgen; vor Skalierung Benchmark-Gate setzen.
- **Provenance**: immutable Quell-ZIP SHA, reproduzierbare `unittest`-Logs, Manifeste, NO-GO im Paket.

**Kein CodeFactory-Repo geändert**; Material dient als prüfbare Vorlage, nicht als bereits integrierte produktive Implementierung.
