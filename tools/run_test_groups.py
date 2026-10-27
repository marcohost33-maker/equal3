#!/usr/bin/env python3
"""Run the Equal3 research test groups with a hang detector and write JSON evidence.

Single source of truth for the test groups used in CI and in the README. Each
group runs as `python -B -W error::ResourceWarning -m unittest -q <modules>` in
its own process group inside the research directory (the modules import each
other flat, as shipped).

Fail-closed (exit 1) when any of these holds:
  - a group exits non-zero, or its unittest summary cannot be parsed;
  - a group exceeds --timeout (the whole process group is killed; a timeout is
    a failure, never a pass);
  - the summary contradicts the exit code (e.g. rc 0 without "OK");
  - --require-no-skips is set and any test was skipped;
  - --expect-total is set and the number of tests run differs.

What a pass does NOT show: it does not change the release decision NO-GO. Some
tests only run as root (separate-UID isolation); without root they are skipped
and counted under "skipped", so a non-root pass is weaker than a root pass.

Usage: python tools/run_test_groups.py [--research-dir DIR] [--groups a,b]
       [--timeout S] [--json OUT] [--require-no-skips] [--expect-total N]
Stdlib only, Python >= 3.9.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

# (name, modules, count reported by the v0.7.22 audit / v0.7.21 run for anchor_wire)
GROUPS = (
    ('witness', ('test_commit_request_binding_v0722', 'test_external_commit_witness_v0720',
                 'test_commit_floor_expiry_v0721'), 29),
    ('equal', ('test_equal3', 'test_extensions', 'test_fault_lab', 'test_guarded_store',
               'test_release_preflight_v078', 'test_v0713_rollback'), 57),
    ('store', ('test_store', 'test_v07', 'test_v071', 'test_v0710_security', 'test_v0712_integrity',
               'test_v074_hardening', 'test_witness'), 96),
    ('runtime', ('test_runtime_gate_v0711', 'test_sqlite_build_v0711'), 21),
    ('writer', ('test_writer_service_v0714',), 21),
    ('coordinator', ('test_anchored_writer_v0715',), 23),
    ('attester', ('test_attested_commit_v0716',), 24),
    ('policy', ('test_attester_policy_v0717',), 14),
    ('rotation', ('test_root_rotation_v0718',), 28),
    ('epoch_witness', ('test_external_epoch_witness_v0719',), 26),
    ('anchor_base', ('test_anchor_protocol', 'test_anchor_v077', 'test_anchor_v078', 'test_anchor_v079'), 63),
    ('anchor_wire', ('test_anchor_wire',), 28),
)
REPORTED_TOTAL = 430
DEFAULT_TIMEOUT = 300.0
TAIL_CHARS = 4000

RAN = re.compile(r'^Ran (\d+) tests? in ([0-9.]+)s$', re.M)
FINAL = re.compile(r'^(OK|FAILED)(?: \(([^)]*)\))?$', re.M)
COUNT = re.compile(r'^(failures|errors|skipped|expected failures|unexpected successes)=(\d+)$')


class SummaryError(Exception):
    pass


def parse_summary(output: str) -> dict:
    """Parse the last unittest summary in `output`; raise SummaryError if absent or malformed."""
    ran = RAN.findall(output)
    final = FINAL.findall(output)
    if not ran or not final:
        raise SummaryError('no unittest summary found')
    verdict, detail = final[-1]
    counts = {'failures': 0, 'errors': 0, 'skipped': 0, 'expected failures': 0, 'unexpected successes': 0}
    if detail:
        for part in detail.split(', '):
            m = COUNT.match(part)
            if not m:
                raise SummaryError('unknown summary field %r' % part)
            counts[m.group(1)] = int(m.group(2))
    if verdict == 'OK' and (counts['failures'] or counts['errors'] or counts['unexpected successes']):
        raise SummaryError('OK summary with failure counts')
    if verdict == 'FAILED' and not (counts['failures'] or counts['errors'] or counts['unexpected successes']):
        raise SummaryError('FAILED summary without failure counts')
    return {'ok': verdict == 'OK', 'ran': int(ran[-1][0]), 'failures': counts['failures'],
            'errors': counts['errors'], 'skipped': counts['skipped'],
            'unexpected_successes': counts['unexpected successes']}


def _kill_group(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def run_group(name: str, modules, research_dir: Path, timeout: float, python: str = sys.executable) -> dict:
    cmd = [python, '-B', '-W', 'error::ResourceWarning', '-m', 'unittest', '-q', *modules]
    start = time.monotonic()
    proc = subprocess.Popen(cmd, cwd=str(research_dir), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            stdin=subprocess.DEVNULL, start_new_session=True)
    try:
        out, _ = proc.communicate(timeout=timeout)
        timed_out = False
    except subprocess.TimeoutExpired:
        _kill_group(proc)
        out, _ = proc.communicate()
        timed_out = True
    # Helper processes left behind in the group would outlive the run; never leak them.
    _kill_group(proc)
    duration = round(time.monotonic() - start, 3)
    text = out.decode('utf-8', 'replace')
    result = {'name': name, 'modules': list(modules), 'returncode': proc.returncode,
              'duration_s': duration, 'status': 'ok', 'ran': None, 'failures': None, 'errors': None,
              'skipped': None, 'detail': None}
    if timed_out:
        result.update(status='timeout', detail='exceeded %.0f s; process group killed' % timeout)
    else:
        try:
            summary = parse_summary(text)
        except SummaryError as exc:
            result.update(status='unparsed', detail=str(exc))
        else:
            result.update({k: summary[k] for k in ('ran', 'failures', 'errors', 'skipped')})
            if summary['ok'] != (proc.returncode == 0):
                result.update(status='inconsistent', detail='summary %s but returncode %d'
                              % ('OK' if summary['ok'] else 'FAILED', proc.returncode))
            elif not summary['ok']:
                result['status'] = 'failed'
    if result['status'] != 'ok':
        result['output_tail'] = text[-TAIL_CHARS:]
    return result


def environment(python: str) -> dict:
    probe = ('import json,os,platform,sqlite3,sys\n'
             'try:\n import cryptography; c=cryptography.__version__\nexcept ImportError: c=None\n'
             'print(json.dumps({"python":sys.version.split()[0],"sqlite":sqlite3.sqlite_version,'
             '"cryptography":c,"euid":os.geteuid() if hasattr(os,"geteuid") else None,'
             '"platform":platform.platform()}))')
    try:
        env = json.loads(subprocess.run([python, '-c', probe], capture_output=True, text=True,
                                        timeout=60, check=True).stdout)
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        env = {'probe_error': str(exc)}
    commit = os.environ.get('GITHUB_SHA')
    if not commit:
        try:
            commit = subprocess.run(['git', 'rev-parse', 'HEAD'], capture_output=True, text=True, timeout=10,
                                    cwd=str(Path(__file__).resolve().parent), check=True).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            commit = None
    env.update(commit=commit, runner_platform=platform.platform())
    return env


def evaluate(results, require_no_skips: bool, expect_total) -> list:
    problems = ['%s: %s%s' % (r['name'], r['status'], ' (%s)' % r['detail'] if r['detail'] else '')
                for r in results if r['status'] != 'ok']
    skipped = sum(r['skipped'] or 0 for r in results)
    if require_no_skips and skipped:
        problems.append('%d test(s) skipped: %s' % (skipped, ', '.join(
            '%s=%d' % (r['name'], r['skipped']) for r in results if r['skipped'])))
    total = sum(r['ran'] or 0 for r in results)
    if expect_total is not None and total != expect_total:
        problems.append('ran %d tests, expected %d' % (total, expect_total))
    return problems


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    repo = Path(__file__).resolve().parent.parent
    ap.add_argument('--research-dir', default=str(repo / 'research'))
    ap.add_argument('--groups', help='comma-separated subset of: ' + ','.join(g[0] for g in GROUPS))
    ap.add_argument('--timeout', type=float, default=DEFAULT_TIMEOUT, help='seconds per group')
    ap.add_argument('--python', default=sys.executable)
    ap.add_argument('--json', help='write evidence JSON to this path')
    ap.add_argument('--require-no-skips', action='store_true')
    ap.add_argument('--expect-total', type=int)
    args = ap.parse_args(argv)

    if not (args.timeout > 0):
        ap.error('--timeout must be a positive number')
    selected = GROUPS
    if args.groups:
        wanted = args.groups.split(',')
        known = {g[0] for g in GROUPS}
        unknown = [w for w in wanted if w not in known]
        if unknown or len(set(wanted)) != len(wanted):
            ap.error('unknown or repeated group(s): %s' % ', '.join(unknown or wanted))
        selected = tuple(g for g in GROUPS if g[0] in wanted)
    research_dir = Path(args.research_dir).resolve()
    missing = [m for _, mods, _ in selected for m in mods if not (research_dir / (m + '.py')).is_file()]
    if missing:
        print('TEST GROUPS FAIL: missing test modules in %s: %s' % (research_dir, ', '.join(missing)))
        return 1

    env = environment(args.python)
    results = []
    for name, modules, reported in selected:
        r = run_group(name, modules, research_dir, args.timeout, args.python)
        r['reported_v0722'] = reported
        results.append(r)
        print('%-14s %-12s ran=%-4s skipped=%-3s failures=%-3s errors=%-3s %7.2fs' % (
            name, r['status'], r['ran'], r['skipped'], r['failures'], r['errors'], r['duration_s']), flush=True)
    problems = evaluate(results, args.require_no_skips, args.expect_total)
    total = sum(r['ran'] or 0 for r in results)
    skipped = sum(r['skipped'] or 0 for r in results)
    evidence = {'tool': 'tools/run_test_groups.py', 'environment': env, 'timeout_s': args.timeout,
                'require_no_skips': args.require_no_skips, 'expect_total': args.expect_total,
                'total_ran': total, 'total_skipped': skipped, 'passed': not problems,
                'problems': problems, 'groups': results}
    if args.json:
        Path(args.json).write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
    if problems:
        print('TEST GROUPS FAIL: ' + '; '.join(problems))
        return 1
    print('TEST GROUPS OK: %d groups, %d tests run, %d skipped (euid %s)'
          % (len(results), total, skipped, env.get('euid')))
    return 0


if __name__ == '__main__':
    sys.exit(main())
