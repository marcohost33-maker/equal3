# Equal3 v0.7.17 — Pinned Attester Policy (RESEARCH ONLY)

Code-Stand von v0.7.16 kopiert. Neu: `EvidenceRequiredCASAnchor` persistiert und prüft eine `trust_binding` mit `store_id`, `deployment_id` und SHA-256 des Ed25519-Öffentlichschlüssels. Die policy erhält einen HMAC-SHA256 mit getrennter Domain-Label-Konstante und bestehendem Anker-Seal-Schlüssel. Fehlende, zusätzliche oder manipulierte Richtlinien führen zu HOLD. Keine automatische Migration eines alten v0716-Ankers.

## Lokale Prüfung

```bash
python -W error::ResourceWarning -m unittest -q test_attester_policy_v0717 test_attested_commit_v0716
python -W error::ResourceWarning -m unittest -q test_attester_policy_v0717
```

Die Original-Tests sowie neue Tests sind mit `EVIDENCE_V0717_suite.json` in separaten Testprozessen nachgewiesen. `EVIDENCE_V0717/policy_benchmark.csv` misst ausschliesslich Anchor.status().

**Sicherheitsgrenze:** HMAC-Seal, Attestierer und SQLite-Datei liegen im Forschungsaufbau in derselben Trust-/Admin-Domäne. Kein nicht-rücksetzbarer Anker, keine produktive Signer-Isolation, keine externe Commit-Evidenz, kein Hardware-Powerloss-Test, und weiterhin ungepatchtes SQLite auf dieser Testmaschine. Kein Production-Go.
