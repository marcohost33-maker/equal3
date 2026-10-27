"""Tests for tools/check_sqlite_runtime.py (stdlib unittest).

evaluate() is tested with synthetic reports, so these tests need neither the
research dependency nor a particular SQLite build. The real inspection runs in
CI: --expect-gate hold on the runner's system SQLite and --expect-gate open on
the SQLite 3.54.1 built from the official amalgamation.
Run: python -m unittest -v tools/test_check_sqlite_runtime.py
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_sqlite_runtime as csr  # noqa: E402

LIB = '/srv/sqlite-3.54.1/libsqlite3.so.0'
SHA = 'a' * 64
SOURCE = '2026-10-16 14:45:20 555e07ef33f69a0957d24d8e555b702464a131d6f1607f4c3c1e4551e8e6ca76'


def report(**kw):
    base = {'sqlite_version': '3.54.1', 'sqlite_source_id': SOURCE,
            'upstream_wal_reset_version_policy': 'PASS', 'wal_gate_without_override': 'open',
            'effective_linked_sqlite': {'loaded_sqlite_shared_object': LIB,
                                        'loaded_sqlite_shared_object_sha256': SHA,
                                        'mapped_file_identity_consistent': True}}
    base.update(kw)
    return base


PINS = dict(version='3.54.1', source_id=SOURCE, library=LIB, library_sha256=SHA)


class EvaluateTests(unittest.TestCase):
    def test_patched_runtime_with_all_pins(self):
        self.assertEqual(csr.evaluate(report(), expect_gate='open', **PINS), [])

    def test_open_expected_but_gate_holds(self):
        held = report(upstream_wal_reset_version_policy='FAIL', wal_gate_without_override='hold: x')
        self.assertTrue(csr.evaluate(held, expect_gate='open'))
        self.assertEqual(csr.evaluate(held, expect_gate='hold'), [])

    def test_gate_and_policy_must_agree(self):
        # an open gate with a failing version policy (or the reverse) is never accepted
        self.assertTrue(csr.evaluate(report(upstream_wal_reset_version_policy='FAIL'), expect_gate='open'))
        self.assertTrue(csr.evaluate(report(wal_gate_without_override='hold: x'), expect_gate='open'))
        self.assertTrue(csr.evaluate(report(), expect_gate='hold'))

    def test_each_pin_detects_a_different_library(self):
        cases = {'version': report(sqlite_version='3.45.1'),
                 'source_id': report(sqlite_source_id='other'),
                 'library': report(effective_linked_sqlite=dict(report()['effective_linked_sqlite'],
                                   loaded_sqlite_shared_object='/usr/lib/libsqlite3.so.0')),
                 'library_sha256': report(effective_linked_sqlite=dict(report()['effective_linked_sqlite'],
                                          loaded_sqlite_shared_object_sha256='b' * 64))}
        for pin, rep in cases.items():
            self.assertTrue(csr.evaluate(rep, expect_gate='open', **PINS), pin)

    def test_unidentified_library_fails(self):
        rep = report(effective_linked_sqlite={'loaded_sqlite_shared_object': None,
                                              'mapped_file_identity_consistent': False})
        self.assertTrue(csr.evaluate(rep, expect_gate='open'))
        self.assertTrue(csr.evaluate(rep, expect_gate='open', library=LIB))


class ChildTests(unittest.TestCase):
    def child(self, **kw):
        base = {'euid': 65534, 'sqlite_version': '3.54.1', 'sqlite_source_id': SOURCE, 'mapped': [LIB]}
        base.update(kw)
        return base

    def test_child_mapping_same_library(self):
        self.assertEqual(csr.evaluate_child(report(), self.child(), 65534), [])

    def test_child_fallback_is_detected(self):
        # the loader skipped the unreadable library and mapped the system SQLite instead
        fallback = self.child(mapped=['/usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6'], sqlite_version='3.45.1')
        problems = csr.evaluate_child(report(), fallback, 65534)
        self.assertEqual(len(problems), 2, problems)

    def test_child_must_run_as_the_dropped_uid_and_map_one_library(self):
        self.assertTrue(csr.evaluate_child(report(), self.child(euid=0), 65534))
        self.assertTrue(csr.evaluate_child(report(), self.child(mapped=[LIB, '/other/libsqlite3.so.0']), 65534))
        self.assertTrue(csr.evaluate_child(report(), self.child(mapped=[]), 65534))

    def test_real_child_without_uid_drop(self):
        import os
        import sqlite3
        child = csr.child_mapping(None)
        self.assertEqual((child['euid'], child['sqlite_version']), (os.geteuid(), sqlite3.sqlite_version))
        self.assertEqual(len(child['mapped']), 1, child)


class MainTests(unittest.TestCase):
    def test_inspection_failure_is_never_a_pass(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:  # no research modules there
            self.assertEqual(csr.main(['--expect-gate', 'hold', '--research-dir', d]), 1)


if __name__ == '__main__':
    unittest.main()
