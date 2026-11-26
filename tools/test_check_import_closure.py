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

    def test_extra_forbidden_pattern_from_the_command_line(self):
        # ADR-003 candidate: the lab anchor and provisioning must stay out of the writer closure
        self.tree(writer='import anchor_lab\n', anchor_lab='X = 1\n')
        self.assertEqual(self.run_main()[0], 0)
        rc, out = self.run_main('--forbid', '*_lab')
        self.assertEqual(rc, 1)
        self.assertIn('VIOLATION legacy-module    anchor_lab (matches *_lab)', out)

    def test_extra_forbidden_patterns_add_to_the_defaults(self):
        self.tree(writer='import store_cli\nimport provision\n', store_cli='X = 1\n', provision='Y = 1\n')
        out_json = self.dir / 'report.json'
        rc, out = self.run_main('--forbid', 'provision', '--forbid', '*_lab', '--json', str(out_json))
        self.assertEqual(rc, 1)
        report = json.loads(out_json.read_text(encoding='utf-8'))
        self.assertEqual(report['forbidden_modules'], list(cic.FORBIDDEN_MODULES) + ['provision', '*_lab'])
        self.assertEqual(sorted(v[1] for v in report['violations']), ['provision', 'store_cli'])

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

    def assert_fails_closed(self, sources):
        for source in sources:
            with self.subTest(source=source):
                self.tree(writer=source, helper='X = 1\n')
                self.assertEqual(self.kinds(), ['dynamic-import'])
                self.assertEqual(self.run_main()[0], 1)

    def test_reported_exploits_e3_v1(self):
        # both passed with exit 0 at be0ec99: the function name is computed, not written
        self.assert_fails_closed((
            'import importlib\nm = getattr(importlib, "import_" + "module")("legacy_state_store")\n',
            'import builtins\nm = vars(builtins)["__imp" + "ort__"]("legacy_state_store")\n'))

    def test_any_mention_of_the_import_machinery_fails_closed(self):
        n = 'n = input()\n'
        self.assert_fails_closed((
            'import builtins\nm = builtins.__dict__["__imp" + "ort__"]("x")\n',
            'import importlib\nm = importlib.__dict__["import_" + "module"]("x")\n',
            n + 'm = globals()["__builtins__"]["__import__"](n)\n',
            'import importlib\nm = locals()["import" + "lib"]\n',
            n + 'm = __builtins__["__import__"](n)\n',
            'import builtins\nm = getattr(builtins, "__imp" + "ort__")("x")\n',
            'import sys\nm = getattr(sys.modules["importlib"], "import_" + "module")("x")\n',
            'import importlib as il\nm = il\n',
            'import importlib, operator\nm = operator.attrgetter("import_" + "module")(importlib)\n',
            'import importlib\nfrom operator import methodcaller\nm = methodcaller("import_module", "x")(importlib)\n',
            n + 'import pkgutil\nm = pkgutil.resolve_name(n)\n',
            n + 'import zipimport\nm = zipimport.zipimporter(n)\n',
            n + 'import imp\nm = imp.load_source(n, n)\n',
            n + 'm = __spec__.loader\n',
            n + 'm = __loader__\n',
            'import sys\nsys.meta_path.insert(0, object())\n',
            'import sys\nsys.path_hooks.append(object)\n',
            'import sys\nsys.path.insert(0, "/elsewhere")\n',
            'import os\nm = os.sys.modules\n',
            'from helper import importlib\n',
            'from helper import import_module\n',
            'm = __import__("importlib")\n',
            'import importlib\nm = importlib.import_module("builtins")\n',
            'import importlib\nm = importlib.import_module(".x", package="p")\n',
            'm = __import__("x", None, None, ["y"])\n',
            'import importlib.util\nf = importlib.util.find_spec\n',
            'import site\nsite.addsitedir("/elsewhere")\n',
            'import sys\nb = sys._getframe().f_back\n',
            'b = (lambda: 0).__globals__["x"]\n',
            's = ().__class__.__base__.__subclasses__()\n',
            'import gc\nm = gc.get_objects()\n',
            'import inspect, helper\nm = inspect.getmembers(helper)\n',
            'import helper\nm = helper.__getattribute__("import" + "lib")\n',
            'import helper\nmatch helper:\n    case object(importlib=m):\n        pass\n',
            # Codex P2 on 2dc2dce: a class pattern captures attrgetter / methodcaller
            'import operator\nmatch operator:\n    case object(attrgetter=lookup):\n        pass\n',
            'import operator\nmatch operator:\n    case object(methodcaller=call):\n        pass\n',
            'from sys import *\n',
            'from sys import modules\n',
            'import sys as s\n',
            'import sys\nx = sys\n',
            'from builtins import getattr\n'))

    def test_attribute_lookup_by_a_computed_name_fails_closed(self):
        # a first-party module that imported importlib re-exports it as an attribute
        self.assert_fails_closed((
            'import helper\nm = getattr(helper, "import" + "lib")\n',
            'import operator, helper\nm = operator.attrgetter("import" + "lib")(helper)\n',
            'import helper\ng = getattr\n',
            'import helper\na = (helper, "x")\nm = getattr(*a)\n',
            'from operator import attrgetter as ag\n',
            'import helper\nfor f in ("importlib",):\n    m = getattr(helper, f)\n',
            'import helper\nm = getattr(helper, "sys")\n',
            'import helper\nm = [getattr(helper, f) for f in ("a",)]\n',
            'import helper\nfor f in ("a",):\n    m = getattr(helper, f)\n',  # module scope
            'import helper\ndef g(n):\n    for f in ("a",):\n        f = n\n        m = getattr(helper, f)\n',
            'import helper\ndef g(n):\n    for f in ("a",):\n        m = getattr(helper, f)\n'
            '    def h():\n        nonlocal f\n        f = n\n',
            'import helper\ndef g(n):\n    for f in ("a", n):\n        m = getattr(helper, f)\n'))

    def test_innocent_code_is_not_caught_by_the_machinery_rule(self):
        sources = (
            '"""Mentions importlib, __import__ and sys.modules in prose."""\n'
            '# import importlib; vars(builtins)["__import__"]\nNAME = "importlib"\n',
            'class C:\n    module = 1\n    def modules(self):\n        return 2\n'
            'x = C().module + C().modules()\n',
            'import os, sys\nx = sys.platform, sys.version_info\nf = getattr(os, "O_CLOEXEC", 0)\n'
            'print(x, file=sys.stderr)\n',
            'def check(i):\n    for field in ("store_id", "digest"):\n        s = getattr(i, field)\n'
            '        if s != s.lower():\n            raise ValueError(field)\n',
            'import importlib\nfrom importlib import import_module\na = importlib.import_module("engine")\n'
            'b = __import__("engine")\nc = import_module("engine")\n',
            'import json\nfrom pathlib import Path\nx = json.dumps({"module": Path(".").name})\n')
        for source in sources:
            with self.subTest(source=source):
                self.tree(writer=source, engine=ENGINE)
                self.assertEqual(self.violations(), [])
                self.assertEqual(self.run_main()[0], 0)

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

    def test_the_machinery_rule_finds_nothing_in_the_real_closures(self):
        # positive control for E3-V1: anchor_wire.validate_intent loops getattr over literal names
        for entry in ('writer_service_v0714', 'anchored_writer_v0715', 'anchor_wire', 'anchor_protocol'):
            with self.subTest(entry=entry):
                report = cic.analyse(cic.RESEARCH, [entry])
                self.assertEqual([v for v in report['violations'] if v[0] == 'dynamic-import'], [])
        self.assertIn('anchor_wire', cic.analyse(cic.RESEARCH, cic.DEFAULT_ENTRIES)['closure'])


if __name__ == '__main__':
    unittest.main()
