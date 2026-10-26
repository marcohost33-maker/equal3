# ADR-001: Publish Equal3 as a research record with NO-GO status, without a release

- Status: accepted (repository assembly, 2026-10-26)
- Deciders: owner (publication request); assembling agent (form of publication)

## Context

The v0.7.22 roadmap ends with "Status: NO-GO. Keine Produktion und kein GitHub-Push." Every audit
round from v0.7.3 to v0.7.22 kept the release decision at NO-GO, and the release-gate files state
that "NO-GO cannot be changed by green tests, self-signed metadata, or a process-local simulator".
The owner nevertheless asked for a public GitHub repository built from all Equal3 inputs.

Two candidate ADR topics existed:

1. the central architecture decision of the research — the witness must live in a separate trust
   domain that cannot be rolled back together with the store; and
2. the decision how to publish material that its own gates mark as not releasable.

The first is the research's design hypothesis, but it is **not fulfilled** by any version
(NR-01, gate `independent_monotone_witness` open) and is already documented in the audits and in
[THREAT_MODEL.md](THREAT_MODEL.md). An ADR recording it as "decided" would overstate the state.
The second is the decision this repository actually embodies and the one a reader must understand
before trusting anything in it. It is therefore the load-bearing decision here.

## Decision

Publish the material as a **research record**:

- Status everywhere: research, release decision NO-GO, not for production, not a security product
  (README status box, SECURITY.md, CITATION.cff abstract).
- **No release tag, no package publication, no "latest release"**; the version string is
  `0.7.22-research` to mark that it is not a SemVer release of usable software.
- Imported code, tests, audits and evidence are **byte-identical** to their sources; only paths
  changed. `tools/verify_provenance.py` and CI check this against the manifest shipped in the
  bundle. Corrections go into new documents, never into imported files.
- Test results are labelled as self-reported unless produced by this repository's CI; the
  incomplete `anchor_wire` group is not counted as passed.
- Synthetic keys stay in place and are labelled as test material.

## Consequences

- The publication does not resolve the roadmap item "no GitHub push"; it overrides it by owner
  decision, and the reason is recorded here.
- Readers get the full negative-first history, including the findings that later versions fixed.
- Stale texts inside imported files (for example the bundle root README describing v0.7.8) remain
  and are pointed out in [PATH_MAPPING.md](PATH_MAPPING.md) instead of being edited.
- Any future change to the NO-GO status requires the P0 gates in [ROADMAP.md](ROADMAP.md),
  including an external security review; a green CI run does not.

## Alternatives considered

- *Publish only the newest source without evidence and audits*: rejected, it would hide the
  NO-GO reasoning and the negative results.
- *Clean up and refactor into a package*: rejected for this step, it would break the byte-identity
  with the audited artefacts and invalidate every hash in the reports.
- *Tag a release `v0.7.22`*: rejected, a release tag reads as "usable version".
