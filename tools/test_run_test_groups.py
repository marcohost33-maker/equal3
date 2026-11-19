"""Tests for tools/run_test_groups.py (stdlib unittest).

Run: python -m unittest -v tools/test_run_test_groups.py
The run_group cases use tiny synthetic test modules in a temporary directory,
not the research code, so they are fast and independent of the research tree.
"""
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_test_groups as rtg  # noqa: E402

REPO = Path(__file__).resolve().parent.parent


class ParseSummaryTests(unittest.TestCase):
    def test_ok(self):
        s = rtg.parse_summary('....\n----\nRan 4 tests in 0.010s\n\nOK\n')
        self.assertEqual((s['ok'], s['ran'], s['skipped']), (True, 4, 0))

    def test_ok_with_skips(self):
        s = rtg.parse_summary('Ran 21 tests in 0.259s\n\nOK (skipped=3)\n')
        self.assertEqual((s['ok'], s['ran'], s['skipped']), (True, 21, 3))

    def test_failed_mixed(self):
        s = rtg.parse_summary('Ran 9 tests in 1.0s\n\nFAILED (failures=1, errors=2, skipped=1)\n')
        self.assertEqual((s['ok'], s['failures'], s['errors'], s['skipped']), (False, 1, 2, 1))

    def test_last_summary_wins(self):
        out = 'Ran 1 test in 0.1s\n\nOK\nnoise\nRan 3 tests in 0.2s\n\nFAILED (errors=1)\n'
        s = rtg.parse_summary(out)
        self.assertEqual((s['ok'], s['ran']), (False, 3))

    def test_rejects_missing_summary(self):
        for out in ('', 'Traceback ...\nImportError: x\n', 'Ran 3 tests in 0.1s\n', 'OK\n'):
            with self.assertRaises(rtg.SummaryError, msg=out):
                rtg.parse_summary(out)

    def test_rejects_unknown_field(self):
        with self.assertRaises(rtg.SummaryError):
            rtg.parse_summary('Ran 1 test in 0.1s\n\nOK (bogus=1)\n')

    def test_rejects_contradictions(self):
        with self.assertRaises(rtg.SummaryError):
            rtg.parse_summary('Ran 1 test in 0.1s\n\nOK (failures=1)\n')
        with self.assertRaises(rtg.SummaryError):
            rtg.parse_summary('Ran 1 test in 0.1s\n\nFAILED (skipped=1)\n')


class RunGroupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def module(self, name, body):
        (self.dir / (name + '.py')).write_text('import unittest\n' + textwrap.dedent(body), encoding='utf-8')

    def test_passing_group(self):
        self.module('test_ok', '''
            class T(unittest.TestCase):
                def test_a(self): pass
                @unittest.skip('x')
                def test_b(self): pass
            ''')
        r = rtg.run_group('g', ['test_ok'], self.dir, timeout=60)
        self.assertEqual((r['status'], r['ran'], r['skipped']), ('ok', 2, 1))
        self.assertNotIn('output_tail', r)

    def test_failing_group(self):
        self.module('test_bad', '''
            class T(unittest.TestCase):
                def test_a(self): self.fail('boom')
            ''')
        r = rtg.run_group('g', ['test_bad'], self.dir, timeout=60)
        self.assertEqual((r['status'], r['failures']), ('failed', 1))
        self.assertIn('boom', r['output_tail'])

    def test_import_error_is_not_a_pass(self):
        r = rtg.run_group('g', ['test_does_not_exist'], self.dir, timeout=60)
        self.assertNotEqual(r['status'], 'ok')

    def test_unparsable_output_is_not_a_pass(self):
        self.module('test_exit0', 'import os\nos._exit(0)\n')
        r = rtg.run_group('g', ['test_exit0'], self.dir, timeout=60)
        self.assertEqual(r['status'], 'unparsed')

    def test_hang_is_timeout_and_helper_is_killed(self):
        marker = self.dir / 'child.pid'
        self.module('test_hang', '''
            import subprocess, sys, time
            class T(unittest.TestCase):
                def test_a(self):
                    p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])
                    open(%r, 'w').write(str(p.pid))
                    time.sleep(120)
            ''' % str(marker))
        start = time.monotonic()
        r = rtg.run_group('g', ['test_hang'], self.dir, timeout=3)
        self.assertLess(time.monotonic() - start, 30)
        self.assertEqual(r['status'], 'timeout')
        pid = int(marker.read_text())
        for _ in range(50):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            # a killed child of a killed parent may linger briefly as a zombie of init
            time.sleep(0.1)
        else:
            with open('/proc/%d/stat' % pid) as f:
                self.assertIn(' Z ', f.read(), 'helper process survived the timeout')


    def test_skipped_ids_are_recorded(self):
        self.module('test_ok', '''
            class T(unittest.TestCase):
                def test_a(self): pass
                @unittest.skip('x')
                def test_b(self): pass
            ''')
        r = rtg.run_group('g', ['test_ok'], self.dir, timeout=60)
        self.assertEqual(r['skipped_ids'], ['test_ok.T.test_b'])

    def test_detached_helper_does_not_block_a_passing_group(self):
        # A helper in its own session escapes killpg and keeps the inherited stdout open.
        # Reading a pipe to EOF would block until it exits (bpo-26534); the group passed.
        marker = self.dir / 'detached.pid'
        self.module('test_detach', '''
            import subprocess, sys
            class T(unittest.TestCase):
                def test_a(self):
                    p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(40)'],
                                         start_new_session=True)
                    open(%r, 'w').write(str(p.pid))
            ''' % str(marker))
        start = time.monotonic()
        try:
            r = rtg.run_group('g', ['test_detach'], self.dir, timeout=15)
            self.assertLess(time.monotonic() - start, 12)
            self.assertEqual((r['status'], r['ran']), ('ok', 1))
        finally:
            if marker.exists():
                try:
                    os.kill(int(marker.read_text()), 9)
                except ProcessLookupError:
                    pass

    def test_leftover_helper_in_group_is_counted_and_killed(self):
        marker = self.dir / 'left.pid'
        self.module('test_left', '''
            import subprocess, sys
            class T(unittest.TestCase):
                def test_a(self):
                    p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'],
                                         stdout=subprocess.DEVNULL)
                    open(%r, 'w').write(str(p.pid))
            ''' % str(marker))
        r = rtg.run_group('g', ['test_left'], self.dir, timeout=30)
        self.assertEqual((r['status'], r['leftover_processes']), ('ok', 1))
        pid = int(marker.read_text())
        time.sleep(0.3)
        try:
            with open('/proc/%d/stat' % pid) as f:
                self.assertIn(' Z ', f.read(), 'leftover helper survived')
        except FileNotFoundError:
            pass


class EvaluateTests(unittest.TestCase):
    def r(self, **kw):
        base = {'name': 'g', 'status': 'ok', 'ran': 2, 'skipped': 0, 'skipped_ids': [], 'detail': None,
                'reported_v0722': 2}
        base.update(kw)
        return base

    def test_clean(self):
        self.assertEqual(rtg.evaluate([self.r()], require_no_skips=True, expect_total=2,
                                      expect_reported=True), [])

    def test_skips_only_fail_when_gated(self):
        skipped = self.r(skipped=1, skipped_ids=['m.T.t'])
        self.assertEqual(rtg.evaluate([skipped]), [])
        self.assertTrue(rtg.evaluate([skipped], require_no_skips=True))

    def test_allow_skips_is_exact(self):
        skipped = self.r(skipped=1, skipped_ids=['m.T.t'])
        self.assertEqual(rtg.evaluate([skipped], allow_skips={'m.T.t'}), [])
        self.assertTrue(rtg.evaluate([skipped], allow_skips={'m.T.other'}))
        # a skip whose id could not be read from the output is never silently allowed
        self.assertTrue(rtg.evaluate([self.r(skipped=2, skipped_ids=['m.T.t'])], allow_skips={'m.T.t'}))

    def test_total_mismatch(self):
        self.assertTrue(rtg.evaluate([self.r()], expect_total=3))

    def test_per_group_reported_counts(self):
        # totals can match while two groups drift in opposite directions
        a, b = self.r(name='a', ran=3, reported_v0722=2), self.r(name='b', ran=1, reported_v0722=2)
        self.assertEqual(rtg.evaluate([a, b], expect_total=4), [])
        self.assertTrue(rtg.evaluate([a, b], expect_total=4, expect_reported=True))

    def test_any_non_ok_status_fails(self):
        for status in ('failed', 'timeout', 'unparsed', 'inconsistent'):
            self.assertTrue(rtg.evaluate([self.r(status=status, ran=None)]), status)


class PreflightTests(unittest.TestCase):
    def env(self, **kw):
        base = {'tmpdir': '/tmp', 'euid': 1000, 'executable': sys.executable}
        base.update(kw)
        return base

    def test_expected_sqlite_version(self):
        env = self.env(sqlite='3.45.1', sqlite_library='/usr/lib/libsqlite3.so.0')
        self.assertEqual(rtg.preflight(env, REPO / 'research', '3.45.1'), [])
        problems = rtg.preflight(env, REPO / 'research', '3.54.1')
        self.assertTrue(problems and '3.54.1' in problems[0], problems)

    def test_short_tmpdir_passes(self):
        self.assertEqual(rtg.preflight(self.env(), REPO / 'research'), [])

    def test_tmpdir_over_af_unix_budget_fails(self):
        # measured: 73 characters pass, 74 fail with "AF_UNIX path too long"
        ok = '/' + 'x' * (rtg.MAX_TMPDIR_LEN - 1)
        self.assertEqual(rtg.preflight(self.env(tmpdir=ok), REPO / 'research'), [])
        self.assertTrue(rtg.preflight(self.env(tmpdir=ok + 'x'), REPO / 'research'))

    def test_root_needs_paths_reachable_by_other_uids(self):
        with tempfile.TemporaryDirectory() as d:
            private = Path(d) / 'private'
            private.mkdir(mode=0o700)
            os.chmod(d, 0o755)
            os.chmod(private, 0o700)
            problems = rtg.preflight(self.env(euid=0, tmpdir=str(private)), REPO / 'research')
            self.assertTrue(any('other users' in p for p in problems), problems)
            # an interpreter reached through a symlink in a private directory (a venv there)
            link = private / 'python'
            link.symlink_to(sys.executable)
            problems = rtg.preflight(self.env(euid=0, executable=str(link)), REPO / 'research')
            self.assertTrue(any(str(private) in p for p in problems), problems)
            # a libsqlite3 in a private directory: the loader would skip it for UID 65534
            lib = private / 'libsqlite3.so.0'
            lib.write_bytes(b'x')
            problems = rtg.preflight(self.env(euid=0, sqlite_library=str(lib)), REPO / 'research')
            self.assertTrue(any(str(private) in p for p in problems), problems)
            # the same layout is fine without root (the UID-drop tests skip there)
            self.assertEqual(rtg.preflight(self.env(euid=1000, tmpdir=str(private)), REPO / 'research'), [])


class GroupDefinitionTests(unittest.TestCase):
    def test_modules_exist_and_are_unique(self):
        mods = [m for _, ms, _ in rtg.GROUPS for m in ms]
        self.assertEqual(len(mods), len(set(mods)))
        for m in mods:
            self.assertTrue((REPO / 'research' / (m + '.py')).is_file(), m)

    def test_every_research_test_module_is_in_a_group(self):
        grouped = {m for _, ms, _ in rtg.GROUPS for m in ms}
        present = {p.stem for p in (REPO / 'research').glob('test_*.py')}
        self.assertEqual(present - grouped, set())

    def test_reported_total(self):
        self.assertEqual(sum(n for _, _, n in rtg.GROUPS), rtg.REPORTED_TOTAL)


class CiLockTests(unittest.TestCase):
    """tools/requirements-ci.lock must stay a valid hash lock of the imported pin."""

    def requirements(self):
        lines = (REPO / 'tools' / 'requirements-ci.lock').read_text(encoding='utf-8').splitlines()
        reqs, current = {}, None
        for n, line in enumerate(lines, 1):
            s = line.strip()
            if not s or (s.startswith('#') and current is None):
                continue
            if s.startswith('--hash=sha256:'):
                self.assertIsNotNone(current, 'hash without requirement, line %d' % n)
                self.assertRegex(s, r'^--hash=sha256:[0-9a-f]{64}( \\)?$')
                reqs[current].append(s)
                if not s.endswith('\\'):
                    current = None
            elif s.startswith('#'):
                self.fail('comment inside a continued requirement, line %d (pip drops the hashes)' % n)
            else:
                self.assertRegex(s, r'^[A-Za-z0-9_.-]+==[0-9][0-9A-Za-z.]* \\$', 'line %d' % n)
                current = s.split(' ')[0]
                reqs[current] = []
        return reqs

    def test_every_requirement_is_exact_and_hashed(self):
        reqs = self.requirements()
        self.assertTrue(reqs)
        for req, hashes in reqs.items():
            self.assertTrue(hashes, req)

    def test_top_level_pin_matches_the_imported_requirements(self):
        gate = (REPO / 'research' / 'REQUIREMENTS_RESEARCH_GATE.txt').read_text(encoding='utf-8').split()
        self.assertEqual(gate, ['cryptography==46.0.4'])
        self.assertIn('cryptography==46.0.4', self.requirements())


class MainTests(unittest.TestCase):
    def test_rejects_unknown_group(self):
        with self.assertRaises(SystemExit):
            rtg.main(['--groups', 'nope'])

    def test_rejects_nonpositive_timeout(self):
        with self.assertRaises(SystemExit):
            rtg.main(['--timeout', '0'])

    def test_missing_research_dir_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(rtg.main(['--research-dir', d, '--groups', 'runtime']), 1)

    def test_json_evidence_and_gates(self):
        # Stand-in modules under the real names of the 'runtime' group (one test, one skip).
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            d.chmod(0o755)  # as root the preflight requires a tree other UIDs can read
            for m in ('test_runtime_gate_v0711', 'test_sqlite_build_v0711'):
                (d / (m + '.py')).write_text(
                    'import unittest\nclass T(unittest.TestCase):\n    def test_a(self): pass\n'
                    '    @unittest.skip("x")\n    def test_b(self): pass\n', encoding='utf-8')
            out = d / 'e.json'
            base = ['--research-dir', str(d), '--groups', 'runtime', '--json', str(out)]
            self.assertEqual(rtg.main(base), 0)
            data = json.loads(out.read_text())
            self.assertEqual((data['passed'], data['total_ran'], data['total_skipped']), (True, 4, 2))
            self.assertEqual(data['groups'][0]['name'], 'runtime')
            self.assertIn('sqlite', data['environment'])
            self.assertEqual(rtg.main(base + ['--require-no-skips']), 1)
            self.assertFalse(json.loads(out.read_text())['passed'])
            self.assertEqual(rtg.main(base + ['--expect-total', '5']), 1)
            self.assertEqual(rtg.main(base + ['--allow-skip', 'test_runtime_gate_v0711.T.test_b',
                                              '--allow-skip', 'test_sqlite_build_v0711.T.test_b']), 0)
            self.assertEqual(rtg.main(base + ['--allow-skip', 'test_runtime_gate_v0711.T.test_b']), 1)
            self.assertEqual(rtg.main(base + ['--expect-reported']), 1)  # 4 run, 21 reported

    def test_preflight_failure_runs_nothing(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as d:
            out = Path(d) / 'e.json'
            # must exist: tempfile silently falls back to /tmp for a missing TMPDIR
            long_dir = Path(d) / ('x' * (rtg.MAX_TMPDIR_LEN + 1 - len(d)))
            long_dir.mkdir()
            env = dict(os.environ, TMPDIR=str(long_dir))
            proc = subprocess.run([sys.executable, str(REPO / 'tools' / 'run_test_groups.py'), '--groups',
                                   'runtime', '--json', str(out)], env=env, capture_output=True, text=True,
                                  timeout=120)
            self.assertEqual(proc.returncode, 1, proc.stdout)
            data = json.loads(out.read_text())
            self.assertEqual((data['passed'], data['groups']), (False, []))
            self.assertIn('AF_UNIX', data['problems'][0])


if __name__ == '__main__':
    unittest.main()
