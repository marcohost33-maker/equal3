# Equal3 v0.7.6 — CodeFactory-Transfer (nur referenzierbar, kein Repo-Einbau)

Wiederverwendbar nach Lizenz-/Sicherheitsprüfung:

- `anchor_wire.PersistentCASAnchor`: atomisches SQLite-CAS, `BEGIN IMMEDIATE`, kein implizites erneutes Bootstrap, persistentes Pending.
- `anchor_wire.RPCAnchor`: lokales, versionsgebundenes, HMAC-authentifiziertes Request-/Response-Protokoll.
- `test_anchor_wire.py`: Negativkontrollen für UID, HMAC, Replay, Double-JSON-Key, Dienststopp/-neustart, getrennten DB-Rollback und gemeinsamen Rollback-Gegenbeleg.
- `bench_anchor_v076.py`: zwei Durchläufe je Payload/Modus, synthetische End-to-End-Messung, dokumentiertes Sampling.
- `README_V076.md`/`ROADMAP_V076.md`/`RELEASE_GATES_V076.json`: verbindliche Sicherheitsgrenzen und Gate-Entscheidungen.

**Keine Übernahme eines produktiven „monotonic anchor“-Sicherheitsclaims.** Diese Demonstration verwendet denselben Host und die gleiche UID. Production Adapter benötigt isolierte Identität, unveränderbares externes Attestation-Ledger, echten Security-Review und Key-Vault. Keine Änderung an GitHub-Repos/CodeFactory; kein Transfer in eine aktive Runtime ohne neue Freigabe.
