"""Preflight never authorizes promotion simply because a version string looks safe."""
import json
import sqlite3
import unittest
from release_preflight_v078 import assess

class PreflightTests(unittest.TestCase):
    def test_full_release_stays_hold(self):
        info=assess()
        self.assertEqual(info['release_verdict'],'NO_GO')
        self.assertEqual(info['runtime_attestation'],'NOT_ATTESTED')
        self.assertFalse(info['research_unsafe_sqlite_override_accepted'])
        self.assertGreaterEqual(len(info['blocking_gates']),7)

    def test_effective_runtime_reported_not_hardcoded(self):
        info=assess()
        self.assertEqual(info['sqlite_version'],sqlite3.sqlite_version)
        self.assertEqual(len(info['sqlite_extension_sha256']),64)
        self.assertIn('sqlite_source_id',info)
        json.dumps(info)

if __name__=='__main__':unittest.main()
