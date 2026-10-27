#!/usr/bin/env python3
"""Run the Equal3 research test groups with a hang detector and write JSON evidence.

Single source of truth for the test groups used in CI and in the README. Each
group runs as `python -B -W error::ResourceWarning -m unittest -v <modules>` in
its own process group inside the research directory (the modules import each
other flat, as shipped).

Fail-closed (exit 1) when any of these holds:
  - preflight: TMPDIR is too long for the AF_UNIX sockets the tests create, or,
    as root, a path the UID-drop tests need is not reachable by other users;
  - a group exits non-zero, or its unittest summary cannot be parsed;
  - a group exceeds --timeout (the whole process group is killed; a timeout is
    a failure, never a pass);
  - the summary contradicts the exit code (e.g. rc 0 without "OK");
  - --require-no-skips is set and any test was skipped, or --allow-skip is set
    and a skipped test is not in that list (or its id cannot be read);
  - --expect-total / --expect-reported is set and the counts differ.

Process handling: output goes to a temporary file, not a pipe, so a helper that
leaves the process group cannot hold the reader open (bpo-26534). The group
leader is waited for with waitid(WNOWAIT) and the group is killed before the
leader is reaped, so the process-group id cannot have been reused by then.
Helpers still alive in the group after the run are killed and counted in
"leftover_processes" (Linux /proc only; null elsewhere).

What a pass does NOT show: it does not change the release decision NO-GO. Some
tests only run as root (separate-UID isolation); without root they are skipped
and counted under "skipped", so a non-root pass is weaker than a root pass.

Usage: python tools/run_test_groups.py [--research-dir DIR] [--groups a,b]
       [--timeout S] [--json OUT] [--require-no-skips | --allow-skip ID ...]
       [--expect-total N] [--expect-reported]
POSIX only (like the research code). Stdlib only, Python >= 3.9.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
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
POLL_S = 0.05
# Longest TMPDIR for which every group passes as root on Linux (sun_path is 108 bytes incl. NUL):
# 73 characters passed, 74 failed with "OSError: AF_UNIX path too long" in test_anchor_v079
# (socket at <TMPDIR>/tmpXXXXXXXX/socket/authority.sock). Measured 2026-10-27.
MAX_TMPDIR_LEN = 73

RAN = re.compile(r'^Ran (\d+) tests? in ([0-9.]+)s$', re.M)
FINAL = re.compile(r'^(OK|FAILED)(?: \(([^)]*)\))?$', re.M)
COUNT = re.compile(r'^(failures|errors|skipped|expected failures|unexpected successes)=(\d+)$')
# unittest -v: "test_x (module.Class.test_x) ... skipped 'why'", with an optional docstring line
SKIP_LINE = re.compile(r'^\w+ \(([\w.]+)\)(?:\n[^\n]*)? \.\.\. skipped ', re.M)


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


def _wait_unreaped(pid: int, deadline: float) -> bool:
    """Wait until `pid` exits without reaping it; False if the deadline passes first."""
    while True:
        if os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(POLL_S)


def _group_members(pgid: int, exclude: int):
    """Live processes in process group `pgid` other than `exclude`; None if /proc is unavailable."""
    proc = Path('/proc')
    if not (proc / 'self' / 'stat').exists():
        return None
    members = []
    for entry in proc.iterdir():
        if not entry.name.isdigit() or int(entry.name) == exclude:
            continue
        try:
            fields = (entry / 'stat').read_text().rsplit(')', 1)[1].split()
        except (OSError, IndexError):
            continue  # exited meanwhile
        if fields[0] != 'Z' and int(fields[2]) == pgid:
            members.append(int(entry.name))
    return members


def _kill_group(pgid: int) -> None:
    try:
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def run_group(name: str, modules, research_dir: Path, timeout: float, python: str = sys.executable) -> dict:
    cmd = [python, '-B', '-W', 'error::ResourceWarning', '-m', 'unittest', '-v', *modules]
    start = time.monotonic()
    with tempfile.TemporaryFile() as out:
        proc = subprocess.Popen(cmd, cwd=str(research_dir), stdout=out, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, start_new_session=True)
        exited, leftover = False, None
        try:
            exited = _wait_unreaped(proc.pid, start + timeout)
            if exited:
                leftover = _group_members(proc.pid, exclude=proc.pid)
        finally:
            # The leader is a zombie or still running, never reaped before this point, so its
            # pid and process-group id cannot belong to an unrelated process yet. Killing first
            # also keeps an interrupted run from waiting on a live leader.
            _kill_group(proc.pid)
            proc.wait()
        duration = round(time.monotonic() - start, 3)
        out.seek(0)
        text = out.read().decode('utf-8', 'replace')
    result = {'name': name, 'modules': list(modules), 'returncode': proc.returncode,
              'duration_s': duration, 'status': 'ok', 'ran': None, 'failures': None, 'errors': None,
              'skipped': None, 'skipped_ids': SKIP_LINE.findall(text),
              'leftover_processes': None if leftover is None else len(leftover), 'detail': None}
    if not exited:
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
    probe = ('import json,os,platform,sqlite3,sys,tempfile\n'
             'try:\n import cryptography; c=cryptography.__version__\nexcept ImportError: c=None\n'
             'print(json.dumps({"python":sys.version.split()[0],"sqlite":sqlite3.sqlite_version,'
             '"cryptography":c,"euid":os.geteuid() if hasattr(os,"geteuid") else None,'
             '"platform":platform.platform(),"tmpdir":tempfile.gettempdir(),'
             '"executable":sys.executable}))')
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
    env['commit'] = commit
    return env


def _unreachable_for_others(path: Path, need_file_mode: int) -> list:
    """Components of `path` that a different, unprivileged UID cannot traverse/read/execute.

    Both the path as given and its symlink target are checked: a venv interpreter is a
    symlink, and the child process is started through the link, so the link's own
    directories must be traversable too.
    """
    bad = []
    for candidate in dict.fromkeys((Path(os.path.abspath(path)), Path(os.path.realpath(path)))):
        for parent in reversed(candidate.parents):
            if not os.stat(parent).st_mode & stat.S_IXOTH:
                bad.append(str(parent))
    target = Path(os.path.realpath(path))
    mode = os.stat(target).st_mode
    if stat.S_ISDIR(mode):
        if mode & (stat.S_IXOTH | stat.S_IROTH) != (stat.S_IXOTH | stat.S_IROTH):
            bad.append(str(target))
    elif mode & need_file_mode != need_file_mode:
        bad.append(str(target))
    return bad


def preflight(env: dict, research_dir: Path) -> list:
    """Environment problems that would make test results meaningless; empty list if none."""
    if 'probe_error' in env:
        return ['interpreter probe failed: %s' % env['probe_error']]
    problems = []
    tmpdir = env['tmpdir']
    if len(tmpdir) > MAX_TMPDIR_LEN:
        problems.append('TMPDIR %r has %d characters; the AF_UNIX socket paths of the tests need at most %d '
                        '(set a short TMPDIR, e.g. /tmp)' % (tmpdir, len(tmpdir), MAX_TMPDIR_LEN))
    if env.get('euid') == 0:
        # The separate-UID tests drop to UID 65534 and then import the research modules,
        # run the interpreter and use TMPDIR; as root a failure there is an environment error.
        bad = []
        for path, file_mode in ((env['executable'], stat.S_IXOTH), (research_dir, stat.S_IROTH),
                                (tmpdir, stat.S_IXOTH)):
            try:
                bad += _unreachable_for_others(Path(path), file_mode)
            except OSError as exc:
                bad.append('%s (%s)' % (path, exc))
        if bad:
            problems.append('as root, these paths must be reachable by other users for the UID-drop tests: %s '
                            '(stage a world-readable copy, as the CI root job does)' % ', '.join(sorted(set(bad))))
    return problems


def evaluate(results, *, require_no_skips: bool = False, allow_skips=(), expect_total=None,
             expect_reported: bool = False) -> list:
    problems = ['%s: %s%s' % (r['name'], r['status'], ' (%s)' % r['detail'] if r['detail'] else '')
                for r in results if r['status'] != 'ok']
    if require_no_skips or allow_skips:
        allowed = set(allow_skips)
        unexpected = sorted(i for r in results for i in r['skipped_ids'] if i not in allowed)
        unidentified = sum((r['skipped'] or 0) - len(r['skipped_ids']) for r in results)
        if unexpected:
            problems.append('%d test(s) skipped that are not allowed: %s' % (len(unexpected), ', '.join(unexpected)))
        if unidentified > 0:
            problems.append('%d skipped test(s) could not be identified from the output' % unidentified)
    if expect_total is not None:
        total = sum(r['ran'] or 0 for r in results)
        if total != expect_total:
            problems.append('ran %d tests, expected %d' % (total, expect_total))
    if expect_reported:
        drift = ['%s %s/%s' % (r['name'], r['ran'], r['reported_v0722']) for r in results
                 if r['ran'] != r['reported_v0722']]
        if drift:
            problems.append('per-group counts differ from the v0.7.22 report (ran/reported): ' + ', '.join(drift))
    return problems


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    repo = Path(__file__).resolve().parent.parent
    ap.add_argument('--research-dir', default=str(repo / 'research'))
    ap.add_argument('--groups', help='comma-separated subset of: ' + ','.join(g[0] for g in GROUPS))
    ap.add_argument('--timeout', type=float, default=DEFAULT_TIMEOUT, help='seconds per group')
    ap.add_argument('--python', default=sys.executable)
    ap.add_argument('--json', help='write evidence JSON to this path')
    skips = ap.add_mutually_exclusive_group()
    skips.add_argument('--require-no-skips', action='store_true')
    skips.add_argument('--allow-skip', action='append', default=[], metavar='ID',
                       help='test id (module.Class.test) allowed to skip; any other skip fails')
    ap.add_argument('--expect-total', type=int)
    ap.add_argument('--expect-reported', action='store_true',
                    help='every group must run exactly the count reported for v0.7.22')
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
    evidence = {'tool': 'tools/run_test_groups.py', 'environment': env, 'timeout_s': args.timeout,
                'require_no_skips': args.require_no_skips, 'allow_skips': sorted(args.allow_skip),
                'expect_total': args.expect_total, 'expect_reported': args.expect_reported}
    problems = preflight(env, research_dir)
    results = []
    if not problems:
        for name, modules, reported in selected:
            r = run_group(name, modules, research_dir, args.timeout, args.python)
            r['reported_v0722'] = reported
            results.append(r)
            print('%-14s %-12s ran=%-4s skipped=%-3s failures=%-3s errors=%-3s leftover=%-4s %7.2fs' % (
                name, r['status'], r['ran'], r['skipped'], r['failures'], r['errors'],
                r['leftover_processes'], r['duration_s']), flush=True)
        problems = evaluate(results, require_no_skips=args.require_no_skips, allow_skips=args.allow_skip,
                            expect_total=args.expect_total, expect_reported=args.expect_reported)
    total = sum(r['ran'] or 0 for r in results)
    skipped = sum(r['skipped'] or 0 for r in results)
    evidence.update(total_ran=total, total_skipped=skipped, passed=not problems, problems=problems, groups=results)
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
