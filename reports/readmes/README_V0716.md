# Equal3 0.7.16 – Signierter Commit-Beobachtungsgate (RESEARCH/NO-GO)

Ausgangspunkt: `EQUAL3_v0715_ANCHORED_WRITER_RESEARCH_2026-10-25.zip`.

## Neue Komponenten

- `commit_evidence_v0716.py` mit `EvidenceRequiredCASAnchor`, `issue_observation` und `verify_observation`.
- `anchor_wire.py`: RPC-Nachricht `adjudicate` kann `evidence` enthalten. Der normale CLI-Daemonstart verlangt einen root-provisionierten, Ed25519-Öffentlichschlüssel (`--attester-public-key-file`) sowie `--deployment-id`. Nur ausdrücklich markierte Legacy-Forschungs-Fixures nutzen `--allow-unattested-research-only`.
- `anchor_protocol.py`: optionales `evidence` in `CoordinatedStore.adjudicate`.
- `test_attested_commit_v0716.py`: negatives Legacy-Repro, neue Attestierungsprüfung, RPC, Recovery und Race-Gegenbeispiel.

`issue_observation()` ist ein Referenz-Signer **nur für unabhängige Inspektionsdienste**. Der private Ed25519-Schlüssel DARF nicht im Writer oder im gewöhnlichen Anker-RPC-Dienst liegen. Die Tests verwenden lokale synthetische Schlüssel und bieten keine echte unabhängige Authentizität.

## Tests

```bash
python -W error::ResourceWarning -m unittest -q test_attested_commit_v0716
python run_v0716_suites.py
python bench_attestation_v0716.py
```

**Kein** normales produktives Deploy: Legacy-API, gleiche Vertrauensdomäne, SQLite 3.46.1, Hardware-Nachweise und echte Schlüsselsicherheit bleiben P0 OFFEN. Das README ist keine Laufzeitfreigabe.
