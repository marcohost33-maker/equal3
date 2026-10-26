"""Tests for tools/verify_provenance.py (stdlib unittest).

Each negative case starts from a fixture that passes (positive control), applies
exactly one corruption, and must fail. Run: python -m unittest -v tools/test_verify_provenance.py
"""
import hashlib
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_provenance as vp  # noqa: E402

PREFIX = vp.BUNDLE_PREFIX
SRC = vp.BUNDLE_SOURCE


def h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Fixture:
    """Small synthetic repository: 2 manifest entries + manifest + 1 supplementary file."""

    def __init__(self, base: Path):
        self.root = base / 'repo'
        self.files = {'research/a.py': b'print(1)\n', 'reports/b.md': b'# b\n',
                      'reports/supp.md': b'supplementary\n'}
        for rel, data in self.files.items():
            p = self.root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
        self.manifest_bytes = ('%s  a.py\n%s  b.md\n' % (h(self.files['research/a.py']),
                                                         h(self.files['reports/b.md']))).encode()
        self.write_manifest(self.manifest_bytes)
        self.rows = [[SRC, PREFIX + 'a.py', 'research/a.py', h(self.files['research/a.py'])],
                     [SRC, PREFIX + 'b.md', 'reports/b.md', h(self.files['reports/b.md'])],
                     [SRC, PREFIX + 'MANIFEST_V0722.sha256', vp.MANIFEST_REL, h(self.manifest_bytes)],
                     ['007acc2:06_WISSEN', '06_WISSEN/supp.md', 'reports/supp.md',
                      h(self.files['reports/supp.md'])]]
        self.write_mapping()

    def write_manifest(self, data: bytes):
        p = self.root / vp.MANIFEST_REL
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)

    def write_mapping(self, header='\t'.join(vp.HEADER), rows=None):
        rows = self.rows if rows is None else rows
        text = header + '\n' + ''.join('\t'.join(r) + '\n' for r in rows)
        (self.root / vp.MAPPING_REL).write_text(text, encoding='utf-8', newline='\n')

    def verify(self, **kw):
        args = dict(expected_bundle=3, expected_manifest=2, manifest_sha256=h(self.manifest_bytes))
        args.update(kw)
        return vp.verify(self.root, **args)


class VerifyProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.fx = Fixture(self.tmp)

    def assertFails(self, fragment, **kw):
        with self.assertRaises(vp.ProvenanceError) as ctx:
            self.fx.verify(**kw)
        self.assertIn(fragment, str(ctx.exception))

    def test_positive_control_passes(self):
        result = self.fx.verify()
        self.assertEqual(result, {'rows': 4, 'bundle_rows': 3, 'manifest_entries': 2, 'other_rows': 1})

    def test_tampered_file_fails(self):
        (self.fx.root / 'research/a.py').write_bytes(b'print(2)\n')
        self.assertFails('content differs')

    def test_strongest_forger_file_and_mapping_rewritten_fails_on_manifest(self):
        forged = b'print(666)\n'
        (self.fx.root / 'research/a.py').write_bytes(forged)
        self.fx.rows[0][3] = h(forged)
        self.fx.write_mapping()
        self.assertFails('mapping hash differs from manifest')

    def test_rewritten_manifest_fails_on_pinned_hash(self):
        self.fx.write_manifest(self.fx.manifest_bytes.replace(b'a.py', b'c.py'))
        self.assertFails('pinned value')

    def test_tampered_supplementary_file_fails(self):
        (self.fx.root / 'reports/supp.md').write_bytes(b'changed\n')
        self.assertFails('content differs')

    def test_missing_file_fails(self):
        (self.fx.root / 'reports/b.md').unlink()
        self.assertFails('not a regular file')

    def test_manifest_entry_without_mapping_fails(self):
        self.fx.write_mapping(rows=[r for r in self.fx.rows if r[2] != 'reports/b.md'])
        self.assertFails('mapping has 2 bundle rows', expected_bundle=3)
        self.assertFails('manifest entries without mapping', expected_bundle=2)

    def test_bundle_row_not_in_manifest_fails(self):
        extra = self.fx.root / 'research/x.py'
        extra.write_bytes(b'x\n')
        self.fx.rows.append([SRC, PREFIX + 'x.py', 'research/x.py', h(b'x\n')])
        self.fx.write_mapping()
        self.assertFails('not listed in manifest', expected_bundle=4)

    def test_planted_unmapped_file_fails(self):
        (self.fx.root / 'research/planted_test.py').write_bytes(b'import os\n')
        self.assertFails('unmapped files')

    def test_planted_file_in_nested_evidence_dir_fails(self):
        p = self.fx.root / 'evidence/v9/x.log'
        p.parent.mkdir(parents=True)
        p.write_bytes(b'x\n')
        self.assertFails('unmapped files')

    def test_pycache_and_allowed_notes_are_ignored(self):
        cache = self.fx.root / 'research/__pycache__/a.cpython-313.pyc'
        cache.parent.mkdir()
        cache.write_bytes(b'\x00')
        (self.fx.root / 'evidence/README.md').write_bytes(b'# notes\n')
        self.assertEqual(self.fx.verify()['rows'], 4)

    def test_duplicate_repo_path_fails(self):
        self.fx.rows.append(list(self.fx.rows[0]))
        self.fx.write_mapping()
        self.assertFails('mapped twice')

    def test_path_traversal_fails(self):
        self.fx.rows[0][2] = '../outside.py'
        self.fx.write_mapping()
        self.assertFails('forbidden segment')

    def test_absolute_and_backslash_paths_fail(self):
        for bad in ('/etc/passwd', 'C:/x.py', 'research\\a.py'):
            self.fx.rows[0][2] = bad
            self.fx.write_mapping()
            self.assertFails('not a relative POSIX path')

    def test_empty_manifest_fails(self):
        self.fx.manifest_bytes = b''
        self.fx.write_manifest(b'')
        self.assertFails('manifest has 0 entries')

    def test_empty_mapping_fails(self):
        self.fx.write_mapping(rows=[])
        self.assertFails('mapping has 0 bundle rows')

    def test_wrong_header_fails(self):
        self.fx.write_mapping(header='a\tb\tc\td')
        self.assertFails('header')

    def test_malformed_row_fails(self):
        (self.fx.root / vp.MAPPING_REL).write_text('\t'.join(vp.HEADER) + '\nonly\ttwo\n', encoding='utf-8')
        self.assertFails('4 non-empty fields')

    def test_malformed_manifest_line_fails(self):
        data = self.fx.manifest_bytes + b'not a manifest line\n'
        self.fx.manifest_bytes = data
        self.fx.write_manifest(data)
        self.assertFails('malformed')

    def test_cli_returns_nonzero_for_foreign_tree(self):
        # The CLI always uses the pinned production constants; a foreign tree must fail.
        self.assertEqual(vp.main(['--root', str(self.fx.root)]), 1)

    def test_cli_returns_nonzero_for_missing_root(self):
        self.assertEqual(vp.main(['--root', str(self.tmp / 'does-not-exist')]), 1)


class RealRepositoryTest(unittest.TestCase):
    ROOT = Path(__file__).resolve().parent.parent

    def test_repository_matches_bundle_manifest(self):
        result = vp.verify(self.ROOT)
        self.assertEqual(result['bundle_rows'], vp.EXPECTED_BUNDLE_FILES)
        self.assertEqual(result['manifest_entries'], vp.EXPECTED_MANIFEST_ENTRIES)
        self.assertGreater(result['other_rows'], 0)

    def test_cli_returns_zero_for_repository(self):
        self.assertEqual(vp.main(['--root', str(self.ROOT)]), 0)


if __name__ == '__main__':
    unittest.main()
