"""Tests for tools/runtime_import_witness.py (stdlib unittest, ADR-003 / P0-2).

Every run happens in a child interpreter, so no audit hook is ever installed in the test
process (PEP 578 hooks cannot be removed). Synthetic module trees only: the real writer entry
point needs POSIX (anchor_wire uses socketserver.UnixStreamServer).
Run: python -m unittest -v tools/test_runtime_import_witness.py
"""
import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_import_closure as cic  # noqa: E402
import runtime_import_witness as riw  # noqa: E402

ENGINE = 'X = 1\n'
# Gemini A7-R8 (2026-11-19) and further routes that build the import target at run time.
# The static check fails closed on the first five; the last five are outside what it can see.
BYPASSES = {
    # in an imported module __builtins__ is the dict itself; the reported line (.__dict__) only
    # works in __main__, so both spellings are covered
    'gemini_builtins_dict_chr': "b = __builtins__\nd = b if isinstance(b, dict) else b.__dict__\n"
                                "m = d[chr(95)*2 + chr(105)+chr(109)+chr(112)+chr(111)"
                                "+chr(114)+chr(116) + chr(95)*2]('store' + '_cli')\n",
    'getattr_importlib': "import importlib\nm = getattr(importlib, 'import_' + 'module')('store_cli')\n",
    'globals_builtins_import': "g = globals()['__builtins__']\n"
                               "f = g['__import__'] if isinstance(g, dict) else g.__import__\nm = f('store_cli')\n",
    'spec_from_file_location': "import importlib.util, os\n"
                               "p = os.path.join(os.path.dirname(__file__), 'store' + '_cli.py')\n"
                               "s = importlib.util.spec_from_file_location('x', p)\n"
                               "s.loader.exec_module(importlib.util.module_from_spec(s))\n",
    'runpy_run_path': "import runpy, os\nrunpy.run_path(os.path.join(os.path.dirname(__file__), 'store_cli.py'))\n",
    'exec_base64': "import base64\nexec(base64.b64decode('aW1wb3J0IHN0b3JlX2NsaQ=='))\n",
    'exec_compile': "exec(compile('import store' + '_cli', 'x', 'exec'))\n",
    'string_annotation': "import typing\ndef f(x: \"__import__('store_cli')\"): pass\ntyping.get_type_hints(f)\n",
    'pickle_global': "import pickle\nnl = bytes([10])\npickle.loads(b'cstore_cli' + nl + b'X' + nl + b'.')\n",
    'exec_source_file': "import os\nexec(open(os.path.join(os.path.dirname(__file__), 'store_cli.py')).read())\n",
}
STATIC_BLIND = ('exec_base64', 'exec_compile', 'string_annotation', 'pickle_global', 'exec_source_file')


class Tree(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def tree(self, **modules):
        for name, source in modules.items():
            (self.dir / (name + '.py')).write_text(source, encoding='utf-8')

    def observe(self, deny=False):
        return riw.observe(self.dir, ['writer'], deny=deny)

    def kinds(self, report):
        return sorted({v[0] for v in report['violations']})

    def run_main(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            rc = riw.main(['--research-dir', str(self.dir), '--entry', 'writer', *argv])
        return rc, out.getvalue()


class NegativeControl(Tree):
    def test_allowed_imports_pass(self):
        self.tree(writer='import json, os\nimport engine\nfrom proto import Y\n', engine=ENGINE,
                  proto='import engine\nY = 2\n', store_cli='X = 1\n')
        report = self.observe()
        self.assertEqual(report['violations'], [])
        self.assertEqual(report['loaded_first_party'], ['engine', 'proto', 'writer'])
        self.assertEqual(self.run_main()[0], 0)
        self.assertEqual(self.run_main('--deny')[0], 0)

    def test_literal_dynamic_import_inside_the_static_closure_passes(self):
        self.tree(writer="import importlib\nm = importlib.import_module('engine')\n", engine=ENGINE)
        self.assertEqual(self.observe()['violations'], [])


class PositiveControl(Tree):
    def test_every_bypass_is_seen_at_run_time(self):
        for label, source in BYPASSES.items():
            with self.subTest(bypass=label):
                self.tree(writer=source, store_cli='X = 1\n')
                report = self.observe()
                self.assertIn('store_cli', report['loaded_first_party'])
                self.assertIn(['runtime-forbidden', 'store_cli', 'loaded at run time'], report['violations'])
                self.assertIn('runtime-outside-static', self.kinds(report))
                self.assertEqual(self.run_main()[0], 1)

    def test_the_static_check_is_blind_to_these_and_says_so(self):
        # pins the documented limit of check_import_closure.py: exit 0 there, red here
        for label in STATIC_BLIND:
            with self.subTest(bypass=label):
                self.tree(writer=BYPASSES[label], store_cli='X = 1\n')
                self.assertEqual(cic.analyse(self.dir, ['writer'])['violations'], [])
                self.assertEqual(self.run_main()[0], 1)

    def test_a_non_forbidden_module_missed_by_the_static_check_is_reported(self):
        self.tree(writer="exec('import state' + '_store')\n", state_store='X = 1\n')
        self.assertEqual(self.observe()['violations'],
                         [['runtime-outside-static', 'state_store',
                           'loaded at run time, not in the static closure']])

    def test_deny_raises_in_the_child_and_a_caught_denial_is_still_reported(self):
        self.tree(writer="try:\n    exec('import store_cli')\nexcept ImportError:\n    OK = 1\n",
                  store_cli='raise SystemExit("module body ran")\n')
        report = self.observe(deny=True)
        self.assertIn(['runtime-forbidden', 'store_cli', 'loaded at run time'], report['violations'])
        self.assertNotIn('runtime-error', self.kinds(report))  # the body did not run: denied before it
        self.tree(writer="exec('import store_cli')\n")
        self.assertIn('runtime-error', self.kinds(self.observe(deny=True)))


class FailsClosed(Tree):
    def test_failing_entry_is_an_error(self):
        self.tree(writer='raise RuntimeError("boom")\n')
        report = self.observe()
        self.assertEqual(report['violations'], [['runtime-error', 'writer', 'writer: RuntimeError']])
        self.assertEqual(self.run_main()[0], 1)

    def test_incomplete_record_is_an_error(self):
        self.tree(writer='import os\nos._exit(0)\n')
        self.assertEqual(self.kinds(self.observe()), ['runtime-error'])

    def test_missing_entry_is_an_error_not_a_pass(self):
        self.tree(engine=ENGINE)
        self.assertEqual(self.run_main()[0], 2)


if __name__ == '__main__':
    unittest.main()
