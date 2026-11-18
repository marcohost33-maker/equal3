"""Tests for tools/check_import_closure.py (stdlib unittest, ADR-003 acceptance test 1).

Synthetic module trees show what the check accepts and rejects; the last class runs it on the
real research tree, which is red today and pinned by a recorded baseline.
Run: python -m unittest -v tools/test_check_import_closure.py
"""
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_import_closure as cic  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
BASELINE = REPO / 'verification' / '2026-11-18_import-closure' / 'baseline.json'

ENGINE = 'class Engine:\n    def read(self):\n        return 1\n'
LEGACY_STORE = ('class StateStore:\n    def read(self):\n        return 1\n'
                '    def apply(self, x):\n        return x\n')


class TreeTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def tree(self, **modules):
        for name, source in modules.items():
            (self.dir / (name + '.py')).write_text(source, encoding='utf-8')

    def violations(self, *entries):
        return [tuple(v) for v in cic.analyse(self.dir, entries or ('writer',))['violations']]

    def kinds(self, *entries):
        return sorted({v[0] for v in self.violations(*entries)})

    def run_main(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            rc = cic.main(['--research-dir', str(self.dir), '--entry', 'writer', *argv])
        return rc, out.getvalue()


class CleanTree(TreeTest):
    def test_clean_tree_passes(self):
        self.tree(writer='import os\nimport engine\nfrom proto import X\n', engine=ENGINE,
                  proto='import engine\nX = 1\n', store_cli='import engine\n')
        report = cic.analyse(self.dir, ['writer'])
        self.assertEqual(report['violations'], [])
        self.assertEqual(report['closure'], ['engine', 'proto', 'writer'])  # store_cli is not reachable
        self.assertEqual(self.run_main()[0], 0)

    def test_third_party_and_stdlib_imports_are_not_followed(self):
        self.tree(writer='import json, sqlite3\nfrom cryptography.x import y\nimport engine\n', engine=ENGINE)
        self.assertEqual(cic.analyse(self.dir, ['writer'])['closure'], ['engine', 'writer'])

    def test_a_class_named_statestore_without_mutators_is_allowed(self):
        self.tree(writer='import state_store\n', state_store='class StateStore:\n    def read(self):\n        return 1\n')
        self.assertEqual(self.violations(), [])


class Violations(TreeTest):
    def test_legacy_write_api_reachable(self):
        self.tree(writer='import mid\n', mid='from state_store import StateStore\n', state_store=LEGACY_STORE)
        self.assertEqual(self.violations(), [('legacy-write-api', 'state_store', 'StateStore.apply')])
        self.assertEqual(self.run_main()[0], 1)

    def test_every_legacy_mutator_is_reported(self):
        body = 'class StateStore:\n' + ''.join('    def %s(self):\n        pass\n' % m
                                               for m in ('create', 'apply', 'checkpoint', 'backup_verified'))
        self.tree(writer='import state_store\n', state_store=body)
        self.assertEqual([v[2] for v in self.violations()],
                         ['StateStore.apply', 'StateStore.backup_verified', 'StateStore.checkpoint',
                          'StateStore.create'])

    def test_forbidden_module_names(self):
        for name in ('legacy_state_store', 'store_cli', 'guarded_store', 'run_suites', 'bench_x',
                     'benchmark_y', 'test_z'):
            with self.subTest(name=name):
                self.tree(**{'writer': 'import %s\n' % name, name: 'X = 1\n'})
                self.assertEqual(self.violations(), [('legacy-module', name, self.violations()[0][2])])

    def test_import_inside_function_try_and_type_checking_counts(self):
        sources = ('def f():\n    import store_cli\n',
                   'try:\n    import store_cli\nexcept ImportError:\n    pass\n',
                   'from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from store_cli import X\n',
                   'class C:\n    def m(self):\n        from store_cli import X\n')
        for source in sources:
            with self.subTest(source=source):
                self.tree(writer=source, store_cli='X = 1\n')
                self.assertEqual(self.kinds(), ['legacy-module'])

    def test_transitive_reach_is_found(self):
        self.tree(writer='import a\n', a='import b\n', b='import c\n', c='import guarded_store\n',
                  guarded_store='X = 1\n')
        self.assertEqual(self.kinds(), ['legacy-module'])

    def test_import_cycle(self):
        self.tree(writer='import a\n', a='import b\n', b='import c\n', c='import a\n')
        self.assertEqual(self.violations(), [('import-cycle', 'a b c', '3 modules')])

    def test_two_separate_cycles_and_a_self_import(self):
        self.tree(writer='import a\nimport c\nimport e\n', a='import b\n', b='import a\n',
                  c='import d\n', d='import c\n', e='import e\n')
        self.assertEqual([v[1] for v in self.violations()], ['a b', 'c d', 'e'])

    def test_diamond_is_not_a_cycle(self):
        self.tree(writer='import a\nimport b\n', a='import c\n', b='import c\n', c='X = 1\n')
        self.assertEqual(self.violations(), [])

    def test_dynamic_import_with_literal_is_followed(self):
        for call in ("__import__('store_cli')", "importlib.import_module('store_cli')",
                     "import_module('store_cli')"):
            with self.subTest(call=call):
                self.tree(writer='import importlib\nfrom importlib import import_module\nm = %s\n' % call,
                          store_cli='X = 1\n')
                self.assertEqual(self.kinds(), ['legacy-module'])

    def test_dynamic_import_fails_closed(self):
        sources = ('import importlib\nm = importlib.import_module(name)\n',
                   'm = __import__("store" + "_cli")\n',
                   'm = __import__()\n',
                   'f = __import__\n',
                   'import importlib\nf = importlib.import_module\n',
                   'from importlib import import_module as load\n',
                   'import builtins\nm = getattr(builtins, "x")\ng = builtins.__import__\n',
                   'from . import sibling\n',
                   'import importlib.util\ns = importlib.util.spec_from_file_location("m", p)\n',
                   'from importlib.util import module_from_spec\n',
                   'import runpy\nrunpy.run_path(p)\n')
        for source in sources:
            with self.subTest(source=source):
                self.tree(writer=source)
                self.assertEqual(self.kinds(), ['dynamic-import'])
                self.assertEqual(self.run_main()[0], 1)

    def test_unparsable_module_fails_closed(self):
        self.tree(writer='import broken\n', broken='def f(:\n')
        self.assertEqual(self.violations(), [('unparsable', 'broken', 'SyntaxError')])

    def test_entry_is_not_judged_by_its_own_name_but_by_what_it_reaches(self):
        self.tree(store_cli='import engine\n', engine=ENGINE)
        self.assertEqual(self.violations('store_cli'), [])
        self.tree(store_cli='import state_store\n', state_store=LEGACY_STORE)
        self.assertEqual(self.kinds('store_cli'), ['legacy-write-api'])


class Baseline(TreeTest):
    def record(self):
        path = self.dir / 'baseline.json'
        rc, _ = self.run_main('--json', str(path))
        return path, rc

    def test_known_red_tree_matches_its_baseline(self):
        self.tree(writer='import state_store\n', state_store=LEGACY_STORE)
        path, rc = self.record()
        self.assertEqual(rc, 1)
        rc, out = self.run_main('--expect-baseline', str(path))
        self.assertEqual(rc, 0, out)
        self.assertIn('still red', out)

    def test_new_violation_fails_against_the_baseline(self):
        self.tree(writer='import state_store\n', state_store=LEGACY_STORE)
        path, _ = self.record()
        self.tree(writer='import state_store\nimport store_cli\n', store_cli='X = 1\n')
        rc, out = self.run_main('--expect-baseline', str(path))
        self.assertEqual(rc, 1)
        self.assertIn('new violation: legacy-module | store_cli', out)

    def test_unrecorded_improvement_fails_against_the_baseline(self):
        self.tree(writer='import state_store\n', state_store=LEGACY_STORE)
        path, _ = self.record()
        self.tree(writer='import engine\n', engine=ENGINE)
        rc, out = self.run_main('--expect-baseline', str(path))
        self.assertEqual(rc, 1)
        self.assertIn('no longer present', out)

    def test_baseline_for_other_entries_does_not_match(self):
        self.tree(writer='import engine\n', other='import engine\n', engine=ENGINE)
        path, _ = self.record()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = cic.main(['--research-dir', str(self.dir), '--entry', 'other', '--expect-baseline', str(path)])
        self.assertEqual(rc, 1)
        self.assertIn('entries differ', out.getvalue())

    def test_bad_baseline_and_missing_entry_are_errors_not_passes(self):
        self.tree(writer='X = 1\n')
        for content in ('', '[]', '{}', json.dumps({'schema': cic.SCHEMA, 'entries': ['writer']}),
                        json.dumps({'schema': 'other/1', 'entries': ['writer'], 'violations': []}),
                        json.dumps({'schema': cic.SCHEMA, 'entries': ['writer'], 'violations': [['a', 'b']]})):
            with self.subTest(content=content):
                path = self.dir / 'bad.json'
                path.write_text(content, encoding='utf-8')
                self.assertEqual(self.run_main('--expect-baseline', str(path))[0], 2)
        self.assertEqual(self.run_main('--expect-baseline', str(self.dir / 'missing.json'))[0], 2)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cic.main(['--research-dir', str(self.dir), '--entry', 'nope']), 2)


class ResearchTree(unittest.TestCase):
    """The v0.7.22 tree. ADR-003 requires this check to be red until the engine/legacy split."""

    def test_writer_entry_point_is_red_today(self):
        report = cic.analyse(cic.RESEARCH, cic.DEFAULT_ENTRIES)
        found = {(v[0], v[2]) for v in report['violations']}
        self.assertIn(('legacy-write-api', 'StateStore.apply'), found)
        self.assertIn('import-cycle', {v[0] for v in report['violations']})
        self.assertIn('state_store', report['closure'])

    def test_recorded_baseline_matches(self):
        report = cic.analyse(cic.RESEARCH, cic.DEFAULT_ENTRIES)
        self.assertEqual(cic.compare_with_baseline(report, cic.load_baseline(BASELINE)), [])

    def test_every_service_entry_reaches_the_legacy_write_api(self):
        for entry in ('writer_service_v0714', 'anchored_writer_v0715', 'anchor_wire', 'anchor_protocol'):
            with self.subTest(entry=entry):
                report = cic.analyse(cic.RESEARCH, [entry])
                self.assertIn(['legacy-write-api', 'state_store', 'StateStore.apply'], report['violations'])


if __name__ == '__main__':
    unittest.main()
