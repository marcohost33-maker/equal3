# Equal3 v0.7.13 – evidence-driven follow-up roadmap

**Decision: research only, NO-GO.** The installed sqlite3 runtime remains 3.46.1.

**G0 / P0: Patched SQLite origin and integration.** Download official SQLite 3.54.1 source
in an authorized networked build environment. Require the official amalgamation ZIP
SHA3-256 `92281c86e2957f9b9305890f9ac04204caa7b677cc868dc326d942689df28e30`,
`sqlite3.c` SHA3-256 `e2b869d3003b33c942b7dd7063604fbc53553e1b66609570df39b9b7b558ee81`,
and source ID as documented by sqlite.org. Build clean and actually load in a fresh Python
process; pin mapped file identity and signed independent policy; verify WAL concurrency,
backup/restore, fault-injection and full tests. No claim of this step being done here.

**G1 / P0: DELETE/EXTRA operating boundary.** Explicitly select journal_mode=DELETE on
new StateStores, enforce a privileged writer service and mandatory signed startup gate.
Disallow direct client key/DB access via separate POSIX UID, directory permissions and
cgroup/namespace where appropriate. Verify all deployed paths – old CLI invocation still
defaults to WAL for research compatibility. Disallow production until runtime verified.

**G2 / P0: Migration discipline.** Existing WAL DBs are intentionally rejected by the
DELETE-mode constructor. Design an offline owner-approved maintenance window, exclusive
source lock, source state/receipt HMAC check, SQLite online backup or VACUUM INTO with
provable source runtime, post-copy verification, journal/header checks, independent
monotonic anchor attestation and operator signoff; preserve immutable old source and
run rollback/recovery drills. Never switch journal modes automatically on open.

**G3 / P0: Independent trust.** External monotonic CAS authority, separate admin root,
secret provisioning, signed commit receipts, idempotent post-crash adjudication and
joint rollback/partition negative controls; present local HMAC only as partial integrity.

**G4 / P0: Confidentiality and fault robustness.** Encryption DB / journal / SHM / temp /
backup, end-to-end key lifecycle, retention/deletion policy and privacy assessment.
Run VFS/torn-sector/power-loss/fsync/error-injection across supported hardware and OS.

**G5 / P1: Authenticated performance.** Profile 1, 50, 250, 10k+ signed receipts,
P50/P95/P99, RSS, concurrent client latencies, backup/recovery. Consider externally
attested checkpoints while retaining explicit historical HMAC guarantees.

**Release policy:** Only independently reviewed P0 evidence for the exact signed SHA-bound
artifact could authorize a future release. Passing current local unit tests cannot.
