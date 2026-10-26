# Security policy

## Status

Equal3 is **research code with release decision NO-GO**. It is not a security product and must not
protect real data. There is no supported version in the sense of security fixes for deployments.

| Version | Supported for production | Receives fixes |
|---|---|---|
| 0.7.22-research | no | research follow-up only (new version, never in place) |
| earlier (≤ 0.7.21) | no | no |

## What a report is useful for

Findings that show a protection claimed by the code or the reports does not hold — in the style of
the existing negative-first findings (see [docs/AUDIT_HISTORY.md](docs/AUDIT_HISTORY.md)) — are
welcome. Known open limitations are listed in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)
(for example NR-01 joint rollback, legacy bypass, untrusted clock); a report that only restates
one of them does not need private handling.

## How to report

Please use GitHub's private vulnerability reporting for this repository if it is enabled
("Security" tab → "Report a vulnerability"). If it is not available, open an issue that asks for a
private contact and contains **no** exploit details. Do not include real secrets or personal data
in any report.

## Test material

All keys in this repository are synthetic and must never be used productively:

- fixed HMAC test keys in tests and benchmarks (for example `b'K'*32`, `b'S'*32`,
  `b'Test-only shared secret 32+ bytes - change before deployment!'`,
  `b'Equal3-v071-test-only-key-32-byte-secret-not-for-production'`);
- Ed25519 keys generated at test run time with `Ed25519PrivateKey.generate()`.

No private key files, tokens or credentials are included. Absolute paths such as
`/mnt/data/equal3_v0722_review/...` inside evidence logs are working directories of the research
environment, not user directories.

## Hardening notes (from the audits)

- Run the code only in disposable environments with synthetic data.
- Several components require Linux-specific features (`AF_UNIX`, `SO_PEERCRED`, file-mode checks)
  and some tests require a root-capable container; do not run them as root on a shared machine.
- The SQLite runtime of the research environment (3.46.1) is affected by the upstream WAL-reset
  bug; the code refuses unpatched WAL for the anchor unless a research override is set. See
  `reports/audits/AUDIT_V077.md` and later.
