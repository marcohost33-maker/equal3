# ADR-003: Close the legacy write bypass by separating the storage engine from the legacy API

- Status: **proposed** (2026-10-27). Not implemented in any research version; implementation belongs in
  a research round with its own manifest, evidence and audit (CONTRIBUTING rule 1).
  **2026-11-26:** an implementation candidate of items 1, 2 and 4 exists as a prototype next to the
  research tree, [`prototypes/engine_split`](../prototypes/engine_split/README.md). Its writer closure
  passes the import-closure check without a baseline. Item 3 (OS policy) is not implemented.
- Addresses: roadmap **P0-2** ("restrict the production interface to the attested writer, enforce OS
  access rights (separate UID), exclude all legacy modules from the production start path;
  adversarial bypass test") and release gate `legacy_bypass_elimination`.

## Context (measured on the v0.7.22 tree, 2026-10-27)

**There is no production start path today.** `writer_service_v0714.serve()` raises
`WriterError('P0 independent anchor and commit attestation missing; HOLD')` unless the research-only
flag `_research_unanchored=True` is passed. `test_unanchored_production_path_is_unconditionally_blocked`
pins this behaviour.

**Every service path imports the legacy write API.** Import graph of the non-test research modules
(AST, first-party imports only):

```text
writer_service_v0714  -> anchor_protocol, runtime_gate_v0711, state_store
anchored_writer_v0715 -> anchor_protocol, state_store, writer_service_v0714
anchor_protocol       -> equal3, state_store
anchor_wire           -> anchor_protocol, commit_evidence_v0716, external_epoch_witness_v0719,
                         trust_rotation_v0718, writer_service_v0714
commit_evidence_v0716 <-> anchor_wire <-> trust_rotation_v0718 <-> external_epoch_witness_v0719 (cycle)
runtime_gate_v0711    -> anchor_wire, runtime_evidence_v0710   (added 2026-11-18, see below)
store_cli             -> equal3, state_store                (calls StateStore.apply directly)
guarded_store         -> state_store, witness               (local witness only, NR-01)
```

`state_store` is both the storage engine and the legacy direct-write API (`StateStore.create`,
`apply`, `checkpoint`, `backup_verified`). It is reachable from every service module. A rule like
"exclude legacy modules from the start path" therefore cannot be met by choosing modules. The
anchor, the protocol and the writer modules also import each other in a cycle.

**Correction, 2026-11-18.** The cycle is larger than the four modules listed above.
`tools/check_import_closure.py` finds one strongly connected group of six: the four above plus
`writer_service_v0714` and `runtime_gate_v0711` (`anchor_wire` imports `writer_service_v0714`, which
imports `runtime_gate_v0711`, which imports `sqlite_wal_reset_safe` from `anchor_wire`). The writer
service is therefore inside the cycle, not only next to it. `trust_rotation_v0718` imports
`anchor_wire` inside a function, which a module-level scan misses.

**What enforces the boundary today is the operating system, inside the research fixture:**
- `serve()` requires a distinct non-root writer UID;
- `serve()` requires the database to be a regular file owned by the service with mode 0600 in a
  private parent directory;
- the socket sits in a directory restricted to the writer group;
- `test_real_linux_uid_boundary_separate_client` and
  `test_separate_uid_can_connect_but_cannot_read_anchor` show that another UID cannot read or write
  the DB or the secrets.

Since 2026-10-27 CI runs these tests as root, including a child at UID 65534 that maps the intended
libsqlite3 (PR #1). A process running **as the writer UID** can still import `state_store` and call
`StateStore.apply()` directly, which bypasses anchor and witness. That is the remaining bypass.

## Decision (proposed)

1. **Split the module.** `state_store` keeps an internal engine without public mutators (schema,
   chain verification, the CAS write primitive behind a capability object). The legacy API moves to
   `legacy_state_store`, a research-only shim that the production distribution does not contain.
2. **One writer entry point.** The only object that can call the CAS primitive is constructed by the
   anchored writer after a valid anchor PREPARE/FINALIZE. A direct call without that capability
   raises. Python cannot enforce this against code in the same process, so the real boundary stays
   point 3.
3. **The OS boundary stays mandatory.**
   - The database and the key are readable and writable only by the writer UID.
   - No other code runs as that UID: no shells, no CLIs, no debug entry points. The writer
     executable is fixed and its interpreter is started with `-I`.
   - The production distribution is an explicit allowlist of files. A build check fails if it
     contains `legacy_state_store`, `store_cli`, `guarded_store`, `run_*`, `bench*` or test modules,
     or if the import closure of the writer entry point reaches any of them.
4. **Break the import cycle** between `anchor_wire`, `commit_evidence_v0716`, `trust_rotation_v0718`,
   `external_epoch_witness_v0719`, `writer_service_v0714` and `runtime_gate_v0711` (six modules, see
   the correction above), so that the import closure becomes a meaningful, checkable artifact.

## Acceptance tests for the implementing round (negative first)

- **Import closure.** The writer entry point is computed statically (AST), and the build fails if
  `StateStore.apply` or any legacy module is reachable. On today's tree this check must fail
  (red first).
  **Check built 2026-11-18:** `tools/check_import_closure.py`. It is red on the v0.7.22 tree, as
  required: 4 legacy mutators reachable through `state_store` and the six-module cycle. CI pins
  that red state against `verification/2026-11-18_import-closure/baseline.json`, so a new legacy
  edge fails and an unrecorded improvement fails too. The implementing round turns the step into
  a plain run without a baseline. The check does not see `exec`/`eval` of source text, and it is
  not a boundary against code in the same process (decision item 3 stays the boundary).
  **Scope (2026-11-21, cross-family review A7-R8):** the check is a structure and dependency
  contract for first-party code that the project writes and reviews. It is not a sandbox for
  untrusted code; no static analysis of Python can be one, because the set of spellings of a
  dynamic import is open. The complement for one concrete run is
  `tools/runtime_import_witness.py`: it imports the entry point in a child interpreter under a
  PEP 578 audit hook and fails if a first-party module is loaded that the static closure does not
  contain or whose name is forbidden (including routes the static check cannot see: `exec` of
  encoded source, pickle, string annotations, executing a source file directly). It only sees
  what that run executes and is not a boundary either.
- **Distribution.** The allowlist build contains no legacy module, and importing `legacy_state_store`
  from the installed production package raises `ImportError`.
- **Adversarial, same UID.** Code started as the writer UID through any path other than the writer
  executable is refused by OS policy, for example the systemd unit `ExecStart` plus
  `NoNewPrivileges` / `ProtectSystem`. The lab must show this; the claim is not enough.
- **Adversarial, other UID.** The existing UID tests stay mandatory in CI as root (no skip allowed).
- The release decision stays NO-GO until every P0 gate is met. This ADR closes none of them alone.

## Implementation candidate (2026-11-26)

[`prototypes/engine_split`](../prototypes/engine_split/README.md) builds the decision outside the
research tree. Measured in [verification/2026-11-26_engine-split](../verification/2026-11-26_engine-split/README.md).

- **Item 1.** `eq3_engine.StateEngine` has a read-only public surface (pinned by a test). Genesis
  creation is in `eq3_provision`, which is not in the distribution. The research `state_store`
  plays the role of the legacy shim, unchanged.
- **Item 2.** The write primitive is reachable only through `CommitCapability`. It commits only
  the proposal that the bound anchor holds as its PREPARED intent: proposal hash, request id,
  store, base, base digest and target digest are compared before the write. This is stricter
  than the ADR text, which only asked that the anchored writer construct the capability.
- **Item 4.** The cycle is gone. `sqlite_wal_reset_safe` and the frame constants are leaves
  (`eq3_wal_gate`, `eq3_wire`), and the service no longer has an unanchored core.
- **Acceptance test "import closure":** 0 violations for `eq3_writer_service` on the full tree,
  with no baseline. `anchored_writer_v0715` on the same tree still has 5. Four mutants turn the
  candidate red.
- **Acceptance test "distribution":** `DISTRIBUTION.txt` lists 10 files. From that build,
  `state_store`, `anchor_protocol`, `anchor_wire`, `writer_service_v0714`, `store_cli`, the lab
  anchor and provisioning raise `ImportError`. The PEP 578 witness sees only the 10 closure
  modules.
- **Behaviour:** answers and SQLite tables are equal to research v0.7.15 on a shared operation
  sequence, and on the fault points after anchor PREPARE and after the SQLite commit.
- **Not done:** the adversarial same-UID test (item 3, systemd policy), an independent anchor
  (P0-3), and a research round with an audit outside this channel.

## Consequences

- The research history stays as it is. The split is a new version with a migration note.
- Some research tests use the legacy API on purpose. They move to the shim's own test group, which
  is excluded from the production build check but still runs in CI.
- Without an independent anchor and witness (P0-3, see ADR-002 and `prototypes/witness_lab`), even
  a perfectly closed writer path does not address NR-01. P0-2 and P0-3 are both needed.
