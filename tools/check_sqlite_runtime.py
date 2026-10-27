#!/usr/bin/env python3
"""Check which SQLite library this Python process really runs, and what the
research WAL-reset gate decides for it. Writes JSON evidence; read-only.

It imports the unmodified research modules and calls
release_preflight_v078.assess() (version, source id, compile options and the
library actually mapped from /proc/self/maps with its SHA-256, via
runtime_evidence_v0710.runtime_inventory) and anchor_wire.require_sqlite_wal_safe()
without the research override.

--expect-gate open   the gate must pass without override (patched runtime)
--expect-gate hold   the gate must refuse without override (unpatched runtime)
Optional pins (--expect-version, --expect-source-id, --expect-library,
--expect-library-sha256) fail the check when the loaded library differs, so a
silent fallback to another libsqlite3 cannot pass.

--check-child-uid UID (root only) starts a child the way the separate-UID tests
do (setgroups([]), setgid, setuid before exec) and requires that the child maps
the same libsqlite3 file with the same version and source id as this process.
The dynamic loader skips a library the child cannot read and silently falls
back to another one, so checking the parent alone is not enough.

What a pass does NOT show: an upstream version number is not a signed build
attestation, and the release decision stays NO-GO (release_preflight_v078).

Usage: python tools/check_sqlite_runtime.py --expect-gate open|hold [pins] [--json OUT]
Linux only (needs /proc/self/maps). Stdlib only plus the research modules.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

RESEARCH = Path(__file__).resolve().parent.parent / 'research'


def inspect(research_dir: Path = RESEARCH) -> dict:
    sys.path.insert(0, str(research_dir))
    import anchor_wire  # noqa: E402  (research module, imported unmodified)
    import release_preflight_v078  # noqa: E402

    report = release_preflight_v078.assess()
    try:
        anchor_wire.require_sqlite_wal_safe()
        gate = 'open'
    except anchor_wire.AnchorHold as exc:
        gate = 'hold: %s' % exc
    report['wal_gate_without_override'] = gate
    report['ld_library_path'] = os.environ.get('LD_LIBRARY_PATH')
    return report


CHILD_PROBE = (
    'import json,os,sqlite3\n'
    'db=sqlite3.connect(":memory:");sid=db.execute("select sqlite_source_id()").fetchone()[0];db.close()\n'
    'libs=sorted({os.path.realpath(l.split()[-1]) for l in open("/proc/self/maps") if "libsqlite3" in l})\n'
    'print(json.dumps({"euid":os.geteuid(),"sqlite_version":sqlite3.sqlite_version,'
    '"sqlite_source_id":sid,"mapped":libs}))')


def child_mapping(uid=None, python: str = sys.executable) -> dict:
    """Run CHILD_PROBE in a new interpreter, optionally dropped to `uid` (and gid `uid`) first."""
    def drop():
        os.setgroups([])
        os.setgid(uid)
        os.setuid(uid)
    proc = subprocess.run([python, '-c', CHILD_PROBE], capture_output=True, text=True, timeout=60, cwd='/',
                          preexec_fn=drop if uid is not None else None)
    if proc.returncode != 0:
        raise RuntimeError('child probe failed (rc %d): %s' % (proc.returncode, proc.stderr.strip()[-300:]))
    return json.loads(proc.stdout)


def evaluate_child(report: dict, child: dict, uid: int) -> list:
    problems = []
    loaded = (report.get('effective_linked_sqlite') or {}).get('loaded_sqlite_shared_object')
    if child.get('euid') != uid:
        problems.append('child ran as euid %r, expected %d' % (child.get('euid'), uid))
    if loaded is None or child.get('mapped') != [os.path.realpath(loaded)]:
        problems.append('child (uid %d) maps %r, parent maps %r' % (uid, child.get('mapped'), loaded))
    for key in ('sqlite_version', 'sqlite_source_id'):
        if child.get(key) != report.get(key):
            problems.append('child %s %r differs from parent %r' % (key, child.get(key), report.get(key)))
    return problems


def evaluate(report: dict, *, expect_gate: str, version=None, source_id=None, library=None,
             library_sha256=None) -> list:
    problems = []
    linked = report.get('effective_linked_sqlite') or {}
    gate = report.get('wal_gate_without_override', '')
    policy = report.get('upstream_wal_reset_version_policy')
    if expect_gate == 'open' and not (gate == 'open' and policy == 'PASS'):
        problems.append('WAL-reset gate should open: gate=%r policy=%r' % (gate, policy))
    if expect_gate == 'hold' and not (gate.startswith('hold') and policy == 'FAIL'):
        problems.append('WAL-reset gate should hold: gate=%r policy=%r' % (gate, policy))
    if not linked.get('mapped_file_identity_consistent'):
        problems.append('loaded SQLite library could not be identified consistently from /proc/self/maps')
    if version is not None and report.get('sqlite_version') != version:
        problems.append('SQLite %r loaded, expected %r' % (report.get('sqlite_version'), version))
    if source_id is not None and report.get('sqlite_source_id') != source_id:
        problems.append('SQLite source id %r, expected %r' % (report.get('sqlite_source_id'), source_id))
    loaded = linked.get('loaded_sqlite_shared_object')
    if library is not None and (loaded is None or os.path.realpath(loaded) != os.path.realpath(library)):
        problems.append('mapped library %r, expected %r' % (loaded, library))
    if library_sha256 is not None and linked.get('loaded_sqlite_shared_object_sha256') != library_sha256:
        problems.append('mapped library SHA-256 %r, expected %r'
                        % (linked.get('loaded_sqlite_shared_object_sha256'), library_sha256))
    return problems


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--expect-gate', choices=('open', 'hold'), required=True)
    ap.add_argument('--expect-version')
    ap.add_argument('--expect-source-id')
    ap.add_argument('--expect-library')
    ap.add_argument('--expect-library-sha256')
    ap.add_argument('--check-child-uid', type=int, metavar='UID',
                    help='as root: a child dropped to UID must map the same libsqlite3 as this process')
    ap.add_argument('--research-dir', default=str(RESEARCH))
    ap.add_argument('--json', help='write evidence JSON to this path')
    args = ap.parse_args(argv)
    try:
        report = inspect(Path(args.research_dir))
    except Exception as exc:  # any failure to inspect is a failed check, never a pass
        report, problems = {'inspect_error': '%s: %s' % (type(exc).__name__, exc)}, ['inspection failed']
    else:
        problems = evaluate(report, expect_gate=args.expect_gate, version=args.expect_version,
                            source_id=args.expect_source_id, library=args.expect_library,
                            library_sha256=args.expect_library_sha256)
        if args.check_child_uid is not None:
            try:
                if os.geteuid() != 0:
                    raise PermissionError('--check-child-uid needs root')
                report['child_process'] = child_mapping(args.check_child_uid)
            except Exception as exc:  # a child that cannot be checked is a failed check
                report['child_process'] = {'error': '%s: %s' % (type(exc).__name__, exc)}
                problems.append('child process check failed')
            else:
                problems += evaluate_child(report, report['child_process'], args.check_child_uid)
    report.update(check_tool='tools/check_sqlite_runtime.py', expect_gate=args.expect_gate,
                  passed=not problems, problems=problems)
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    linked = report.get('effective_linked_sqlite') or {}
    print('SQLite %s from %s; WAL gate without override: %s' % (
        report.get('sqlite_version'), linked.get('loaded_sqlite_shared_object'),
        report.get('wal_gate_without_override')))
    if problems:
        print('SQLITE RUNTIME FAIL: ' + '; '.join(problems))
        return 1
    if 'child_process' in report:
        print('child uid %s maps %s' % (args.check_child_uid, report['child_process'].get('mapped')))
    print('SQLITE RUNTIME OK (expected gate: %s)' % args.expect_gate)
    return 0


if __name__ == '__main__':
    sys.exit(main())
