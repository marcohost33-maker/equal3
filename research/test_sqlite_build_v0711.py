import os
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import build_sqlite_v0711 as b

class OfflineBuildSafetyTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.p=Path(self.tmp.name)/b.ARCHIVE_NAME
    def test_absent_official_zip_fails_closed(self):
        with self.assertRaises(b.BuildHold): b.verify_archive(self.p)
    def test_wrong_filename_fails_closed(self):
        (Path(self.tmp.name)/'sqlite-other.zip').write_bytes(b'aaa')
        with self.assertRaises(b.BuildHold):b.verify_archive(Path(self.tmp.name)/'sqlite-other.zip')
    def test_fake_zip_with_expected_entries_fails_sha3(self):
        with zipfile.ZipFile(self.p,'w') as z:
            for n in ('sqlite3.c','sqlite3.h','sqlite3ext.h','shell.c'):
                z.writestr(b.DIR+n,b'not signed release content')
        with self.assertRaisesRegex(b.BuildHold,'archive SHA3-256'):
            b.verify_archive(self.p)
    def test_path_symlink_zip_rejected(self):
        orig=Path(self.tmp.name)/'orig.zip';orig.write_bytes(b'not zip')
        self.p.symlink_to(orig)
        with self.assertRaises(b.BuildHold): b.verify_archive(self.p)
    def test_reject_nonempty_output_dir_before_compilation(self):
        out=Path(self.tmp.name)/'output';out.mkdir();(out/'existing').write_text('x')
        with patch.object(b,'verify_archive',return_value={'sqlite3.c':b'a','sqlite3.h':b'b'}):
            with self.assertRaisesRegex(b.BuildHold,'empty'):
                b.isolated_build(self.p,out)

if __name__=='__main__':unittest.main()

class RuntimeCLIFileTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
    def test_symlinked_policy_is_rejected(self):
        from check_sqlite_runtime_v0711 import _read_bound_file
        from runtime_evidence_v0710 import RuntimeEvidenceError
        d=Path(self.tmp.name)
        target=d/'target';target.write_text('a')
        link=d/'link';link.symlink_to(target)
        with self.assertRaises(OSError):_read_bound_file(link,16384)
    def test_oversized_file_rejected(self):
        from check_sqlite_runtime_v0711 import _read_bound_file
        from runtime_evidence_v0710 import RuntimeEvidenceError
        d=Path(self.tmp.name)/'blob';d.write_bytes(b'x'*65)
        with self.assertRaises(RuntimeEvidenceError):_read_bound_file(d,64)
    def test_command_missing_files_returns_hold(self):
        from check_sqlite_runtime_v0711 import main
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit): # argparse requires all arguments
                main([])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(['--policy-file',str(Path(self.tmp.name)/'missing'),
                '--signature-file','/no','--public-key-file','/no', '--deployment-id','research']),2)
