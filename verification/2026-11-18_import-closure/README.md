# Import closure of the writer entry point — 2026-11-18 (roadmap P0-2, ADR-003 acceptance test 1)

**Result: the check is red on the v0.7.22 tree, as ADR-003 requires.** From the writer entry point
`anchored_writer_v0715`, 11 first-party modules are reachable. Among them:

- `state_store`, which defines the legacy direct-write API: `StateStore.create`, `apply`,
  `checkpoint` and `backup_verified` (4 violations);
- one import cycle of six modules: `anchor_wire`, `commit_evidence_v0716`,
  `external_epoch_witness_v0719`, `runtime_gate_v0711`, `trust_rotation_v0718` and
  `writer_service_v0714` (1 violation).

No module with a forbidden name (`store_cli`, `guarded_store`, `run_*`, `bench*`, `test_*`) is
reachable, and the closure contains no dynamic import.

The release decision stays **NO-GO**. Nothing under `research/` changed; the gate
`legacy_bypass_elimination` is open. This folder is not part of the import. Produced in the Claude
Code maintenance channel.

## What is new against ADR-003 as written on 2026-10-27

ADR-003 listed a cycle of four modules. The check finds six: `anchor_wire` imports
`writer_service_v0714`, which imports `runtime_gate_v0711`, which imports `sqlite_wal_reset_safe`
from `anchor_wire`. The writer service is inside the cycle. The edge
`trust_rotation_v0718 -> anchor_wire` is an import inside a function (line 167). Each edge was read
in the sources. ADR-003 is corrected.

The same four legacy mutators are reachable from every service entry tried:
`writer_service_v0714`, `anchored_writer_v0715`, `anchor_wire`, `anchor_protocol`
(`tools/test_check_import_closure.py`, class `ResearchTree`).

## Method

- Tool: [`tools/check_import_closure.py`](../../tools/check_import_closure.py), standard library only.
  It parses the source (AST) and imports nothing. Imports inside functions, classes, `try` and
  `if TYPE_CHECKING` count. `__import__` / `import_module` with a string literal are followed; with
  any other argument, when used indirectly, or for file loaders (`spec_from_file_location`,
  `exec_module`, `runpy`), the check fails closed.
- `baseline.json` is the tool's own JSON output for the default entry. CI runs
  `python tools/check_import_closure.py --expect-baseline verification/2026-11-18_import-closure/baseline.json`,
  which passes only while the violation set equals the baseline.
- Environment: Linux 6.18, Python 3.13.18, branch based on `7d104ea`.

| Command | Result |
|---|---|
| `python tools/check_import_closure.py` | exit 1, 5 violations (the red state) |
| `python tools/check_import_closure.py --expect-baseline …/baseline.json` | exit 0, `BASELINE_MATCH` |
| `python -m unittest tools/test_check_import_closure.py` | 23 tests, OK |

**Mutation check of the tool's tests:** 22 mutants, each a single text replacement in a copy of the
tool, all killed. They cover: legacy mutator check removed; name patterns ignored; closure not
transitive; only module-level imports scanned; `from` imports ignored; non-literal dynamic import
accepted; literal dynamic import not followed; indirect use, renamed import, file loaders and
relative imports accepted; cycles not reported; self-import not a cycle; every component reported
as a cycle; unparsable module accepted; baseline comparison ignoring new violations, improvements
or entries; baseline format unchecked; exit 0 despite violations or mismatch; missing entry
tolerated.

## What this does not show

- **Not a boundary, not a sandbox.** A static closure says what the source imports; it is a
  structure contract for the project's own reviewed code, not a defence against hostile code.
  Code in the same process can load a module by other routes; `exec`/`eval` of source text is not
  detected. The enforcement remains the OS boundary of ADR-003 item 3.
- **Addendum 2026-11-21 (cross-family review A7-R8).** The reported counterexample
  (`__builtins__.__dict__[chr(105)+...]('o'+'s')`) and three more (`getattr` on `importlib`,
  `__import__` through `globals()`, `exec` of a base64 string) were run through this CLI: the first
  three fail closed (`dynamic-import`), `exec` of base64, `exec(compile(...))`, a string annotation
  evaluated by `typing.get_type_hints` and `pickle.loads` pass, as the tool's docstring states.
  For one concrete run these are reported by `tools/runtime_import_witness.py` (PEP 578 audit
  hook in a child interpreter; `tools/test_runtime_import_witness.py`). It is a witness of one
  run, not a sandbox.
- **One entry point.** The default entry is the coordinated writer. A production distribution would
  have to name its real executable; none exists today (`serve()` HOLDs).
- **A pinned red state is not progress.** The baseline makes drift visible in both directions. It
  closes nothing.
