"""Tests for tools/run_test_groups.py (stdlib unittest).

Run: python -m unittest -v tools/test_run_test_groups.py
The run_group cases use tiny synthetic test modules in a temporary directory,
not the research code, so they are fast and independent of the research tree.
"""
import json
import os
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


class EvaluateTests(unittest.TestCase):
    def r(self, **kw):
        base = {'name': 'g', 'status': 'ok', 'ran': 2, 'skipped': 0, 'detail': None}
        base.update(kw)
        return base

    def test_clean(self):
        self.assertEqual(rtg.evaluate([self.r()], True, 2), [])

    def test_skips_only_fail_when_required(self):
        self.assertEqual(rtg.evaluate([self.r(skipped=1)], False, None), [])
        self.assertTrue(rtg.evaluate([self.r(skipped=1)], True, None))

    def test_total_mismatch(self):
        self.assertTrue(rtg.evaluate([self.r()], False, 3))

    def test_any_non_ok_status_fails(self):
        for status in ('failed', 'timeout', 'unparsed', 'inconsistent'):
            self.assertTrue(rtg.evaluate([self.r(status=status, ran=None)], False, None), status)


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


if __name__ == '__main__':
    unittest.main()
