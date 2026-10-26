# Equal3 v0.7.5 — privacy/security matrix candidates (not legal opinion)

| ID | Category | Status | Required action |
|---|---|---|---|
| EQ075-01 | Live DB/WAL/SHM, temporary file and backup plaintext | P0 OPEN | Approved encryption, access model, KMS, rotation and deletion |
| EQ075-02 | Anchor independence | P0 OPEN | Deploy monotonic storage in separate trust/rollback domain; audit identities |
| EQ075-03 | Writer-secret separation | P0 OPEN | Effective OS ACLs, independent service and endpoint authorization |
| EQ075-04 | Audit/review metadata | P1 OPEN | Minimize linkable store IDs, hashes and request IDs; retention/erasure control |
| EQ075-05 | Commit incident classification | P0 PARTIAL / RESEARCH | Preserve evidence, automated verified incident export, human process for indeterminate outcome |
| EQ075-06 | DSFA Swiss DSG Art.22 | CONDITIONAL | Conduct case-specific DPIA if intended use presents high risk; no real subjects used in tests |
| EQ075-07 | Third-party/offshore processor flows | NOT ASSESSED | Data-flow, controller/processor contracts, transfers, location |
| EQ075-08 | Persistent authority and reviewer credential lifecycle | P0 OPEN | HSM/KMS/revocation/rotation/recovery drills; separation of duties |
| EQ075-09 | Subprocess fault vs. hardware loss | P0 OPEN | Real VFS power-cut testing and supported OS matrix |

These entries are an additive transfer candidate. The canonical Google Sheet was not modified in this isolated experiment.
