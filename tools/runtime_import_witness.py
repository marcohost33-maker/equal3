#!/usr/bin/env python3
"""Runtime witness for the static import-closure check (ADR-003, roadmap P0-2).

`check_import_closure.py` reads source text. It cannot see an import whose target is built at
run time by a route it does not recognise (exec/eval/compile of source text, pickle, string
annotations evaluated by typing.get_type_hints, ...), and it says so. This tool covers the
other half for one concrete run: it imports the entry modules in a child interpreter whose
first action is a PEP 578 audit hook, records which first-party modules that run really
loads, and reports as violations:

  runtime-forbidden       a loaded first-party module whose name matches a forbidden pattern
                          (the same list as the static check)
  runtime-outside-static  a loaded first-party module that the static closure does not contain,
                          i.e. the static check missed an edge
  runtime-error           the run itself failed (entry import raised, child crashed, or the
                          event record is incomplete); fails closed

A first-party module counts as loaded when the "import" audit event names it, or when the
child opens its source or cached bytecode under the research directory (the "open" event; this
also covers spec_from_file_location, runpy.run_path and exec(open(...).read())).
With --deny, a forbidden "import" event also raises ImportError inside the child. The event is
recorded before that, so code that catches the ImportError is still reported.

What this does NOT show (scope, part of the contract):
- It is a witness of one run, not a closure: code that the run does not execute is not seen.
- It is not a sandbox and not a boundary. PEP 578 says so: an audit hook observes, and code in
  the same process can still act without an event (ctypes, C extensions, objects already in
  memory). It cannot be removed from Python, which is why the tests run it in a child process.
- The record goes to a file named on the child's command line; code in the child can write to
  it too. The real boundary stays the operating system (ADR-003 item 3). Release stays NO-GO.

Exit status: 0 no violation, 1 violations, 2 the check could not run.
Usage: python tools/runtime_import_witness.py [--research-dir DIR] [--entry MODULE ...]
                                              [--deny] [--json OUT]
Stdlib only.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Sequence, Set

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_import_closure as cic  # noqa: E402

SCHEMA = 'equal3.runtime-import-witness/1'
END = 'END'


def _child(research_dir: str, record: str, deny: bool, forbidden: Sequence[str],
           entries: Sequence[str]) -> int:
    """Runs in the child interpreter. Installs the hook before any first-party import."""
    root = os.path.normcase(os.path.abspath(research_dir)) + os.sep
    out = open(record, 'a', encoding='utf-8')

    def write(kind: str, value: str) -> None:
        out.write('%s\t%s\n' % (kind, value))
        out.flush()

    def hook(event, args):
        if event == 'import':
            name = str(args[0]).split('.')[0]
            write('import', name)
            if deny and any(fnmatch.fnmatchcase(name, p) for p in forbidden):
                raise ImportError('runtime import witness: %s is forbidden' % name)
        elif event == 'open' and isinstance(args[0], (str, bytes, os.PathLike)):
            try:
                path = os.path.normcase(os.path.abspath(os.fsdecode(args[0])))
            except (TypeError, ValueError):
                return
            if path.startswith(root) and path.endswith(('.py', '.pyc')):
                write('open', os.path.basename(path).split('.')[0])

    sys.addaudithook(hook)
    sys.path.insert(0, research_dir)
    import importlib
    for entry in entries:
        try:
            importlib.import_module(entry)
        except BaseException as exc:  # the run failed; the parent fails closed
            write('error', '%s: %s' % (entry, type(exc).__name__))
            write(END, '1')
            return 1
    write(END, '0')
    return 0


def observe(research_dir: Path, entries: Sequence[str], deny: bool = False,
            forbidden: Sequence[str] = cic.FORBIDDEN_MODULES, timeout: float = 120) -> dict:
    """Import `entries` in a child interpreter and compare what it loads with the static closure."""
    static = cic.analyse(research_dir, entries, forbidden)
    first_party = set(cic.first_party_modules(research_dir))
    fd, record = tempfile.mkstemp(prefix='eq3-witness-', suffix='.tsv')
    os.close(fd)
    try:
        cmd = [sys.executable, '-I', '-B', str(Path(__file__).resolve()), '--child', str(research_dir),
               record, '1' if deny else '0', ','.join(forbidden), *entries]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            returncode, stderr = proc.returncode, proc.stderr
        except subprocess.TimeoutExpired:
            returncode, stderr = None, 'timeout after %s s' % timeout
        lines = Path(record).read_text(encoding='utf-8').splitlines()
    finally:
        os.unlink(record)
    events = [tuple(line.split('\t', 1)) for line in lines if '\t' in line]
    loaded: Set[str] = {v for k, v in events if k in ('import', 'open') and v in first_party}
    violations: Set[tuple] = set()
    complete = bool(events) and events[-1] == (END, '0') and returncode == 0
    if not complete:
        detail = '; '.join(v for k, v in events if k == 'error') or \
            'child exit %s, record %s' % (returncode, 'complete' if events and events[-1][0] == END else 'incomplete')
        violations.add(('runtime-error', ','.join(entries), detail))
    for name in sorted(loaded):
        if name not in entries and any(fnmatch.fnmatchcase(name, p) for p in forbidden):
            violations.add(('runtime-forbidden', name, 'loaded at run time'))
        if name not in static['closure']:
            violations.add(('runtime-outside-static', name, 'loaded at run time, not in the static closure'))
    return {
        'schema': SCHEMA,
        'entries': sorted(entries),
        'deny': deny,
        'static_closure': static['closure'],
        'loaded_first_party': sorted(loaded),
        'child_exit': returncode,
        'child_stderr_tail': stderr[-2000:],
        'violations': [list(v) for v in sorted(violations)],
    }


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ['--child']:
        research_dir, record, deny, forbidden, *entries = argv[1:]
        return _child(research_dir, record, deny == '1', forbidden.split(','), entries)
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--research-dir', type=Path, default=cic.RESEARCH)
    parser.add_argument('--entry', action='append', default=None)
    parser.add_argument('--deny', action='store_true')
    parser.add_argument('--json', type=Path)
    args = parser.parse_args(argv)
    try:
        report = observe(args.research_dir, args.entry or cic.DEFAULT_ENTRIES, deny=args.deny)
    except cic.ClosureError as exc:
        print('ERROR: %s' % exc, file=sys.stderr)
        return 2
    print('loaded first-party (%d): %s' % (len(report['loaded_first_party']),
                                           ', '.join(report['loaded_first_party'])))
    for kind, subject, detail in report['violations']:
        print('VIOLATION %-22s %s (%s)' % (kind, subject, detail))
    ok = not report['violations']
    report['result'] = 'PASS' if ok else 'FAIL'
    print('%s: %d violation(s); a witness of one run, not a sandbox' % (report['result'], len(report['violations'])))
    if args.json:
        args.json.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
