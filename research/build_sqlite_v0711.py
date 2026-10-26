"""Offline SQLite 3.54.1 source verification and isolated Linux build helper.

NO network access; never installs over host SQLite. Input must be the EXACT
sqlite.org amalgamation ZIP. Published SHA3 pins are SOURCE INTEGRITY
checks, not digital signatures or trusted release-signing credentials.

After compiling, use the NEW Python process via LD_LIBRARY_PATH for a research
smoke test. A successful build/smoke test is NOT Equal3 production approval.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import sys
import zipfile

OFFICIAL_URL = 'https://www.sqlite.org/2026/sqlite-amalgamation-3540100.zip'
ZIP_SHA3_256 = '92281c86e2957f9b9305890f9ac04204caa7b677cc868dc326d942689df28e30'
C_SHA3_256 = 'e2b869d3003b33c942b7dd7063604fbc53553e1b66609570df39b9b7b558ee81'
SOURCE_ID = '2026-10-16 14:45:20 555e07ef33f69a0957d24d8e555b702464a131d6f1607f4c3c1e4551e8e6ca76'
ARCHIVE_NAME = 'sqlite-amalgamation-3540100.zip'
DIR = 'sqlite-amalgamation-3540100/'
MAX_ZIP = 10 * 1024 * 1024
MAX_C = 15 * 1024 * 1024

class BuildHold(RuntimeError):
    pass


def verify_archive(archive_path: Path):
    path = Path(archive_path)
    if path.name != ARCHIVE_NAME or not path.is_file() or path.is_symlink():
        raise BuildHold('required exact official amalgamation ZIP filename; HOLD')
    if path.stat().st_size > MAX_ZIP:
        raise BuildHold('archive size exceeds budget; HOLD')
    data = path.read_bytes()
    if hashlib.sha3_256(data).hexdigest() != ZIP_SHA3_256:
        raise BuildHold('archive SHA3-256 differs from official download listing; HOLD')
    try:
        with zipfile.ZipFile(path) as z:
            if z.testzip() is not None:
                raise BuildHold('archive CRC mismatch')
            names = z.namelist()
            if len(names)!=len(set(names)) or len(names)>16:
                raise BuildHold('invalid amalgamation ZIP entries')
            expected = {DIR+'sqlite3.c',DIR+'sqlite3.h',DIR+'sqlite3ext.h',DIR+'shell.c'}
            if not expected.issubset(set(names)):
                raise BuildHold('required SQLite source files missing')
            for item in z.infolist():
                if item.filename not in expected and item.filename != DIR:
                    raise BuildHold('unrecognized ZIP contents')
                if item.file_size > MAX_C or item.filename.startswith('/') or '..' in Path(item.filename).parts:
                    raise BuildHold('unsafe ZIP entry')
            c = z.read(DIR+'sqlite3.c')
            if hashlib.sha3_256(c).hexdigest() != C_SHA3_256:
                raise BuildHold('sqlite3.c differs from official release log; HOLD')
            header = z.read(DIR+'sqlite3.h')
            if SOURCE_ID.encode() not in header:
                raise BuildHold('SQLite SOURCE_ID not confirmed in header; HOLD')
            return {f:z.read(DIR+f) for f in ('sqlite3.c','sqlite3.h')}
    except (zipfile.BadZipFile, RuntimeError, OSError, KeyError) as exc:
        raise BuildHold('could not validate upstream amalgamation ZIP; HOLD') from exc


def isolated_build(archive_path: Path, output_dir: Path) -> dict:
    if platform.system() != 'Linux':
        raise BuildHold('Linux-only proof-of-build; other targets require separate attestation')
    source = verify_archive(archive_path)
    output_dir = Path(output_dir).absolute()
    if output_dir.is_symlink():
        raise BuildHold('output directory symlink forbidden')
    if output_dir.exists() and any(output_dir.iterdir()):
        raise BuildHold('output directory must be empty, not an existing deployment')
    output_dir.mkdir(parents=True,exist_ok=True,mode=0o700)
    os.chmod(output_dir,0o700)
    c = output_dir/'sqlite3.c'
    c.write_bytes(source['sqlite3.c'])
    (output_dir/'sqlite3.h').write_bytes(source['sqlite3.h'])
    output = output_dir/'libsqlite3.so.0'
    args=['gcc','-O2','-fPIC','-shared','-Wl,-soname,libsqlite3.so.0',
          '-DSQLITE_THREADSAFE=1','-DSQLITE_ENABLE_FTS5=1',
          '-DSQLITE_ENABLE_RTREE=1','-DSQLITE_ENABLE_MATH_FUNCTIONS=1',
          '-o',str(output),str(c),'-ldl','-lpthread','-lm']
    try:
        subprocess.run(args,check=True,timeout=180,cwd=str(output_dir),capture_output=True)
    except (OSError,subprocess.CalledProcessError,subprocess.TimeoutExpired) as exc:
        raise BuildHold('local native compilation failed; HOLD') from exc
    if not output.is_file():
        raise BuildHold('shared library missing after compilation; HOLD')
    # Execute in a NEW interpreter to ensure it maps the staged library.
    smoke = '''import json,sqlite3,sys
from pathlib import Path
from runtime_evidence_v0710 import runtime_inventory
v=runtime_inventory()
print(json.dumps(v,sort_keys=True))
sys.exit(0 if v['sqlite_version']=='3.54.1' and v['sqlite_source_id']==sys.argv[1] and v['mapped_file_identity_consistent'] and Path(v['loaded_sqlite_shared_object']).resolve()==Path(sys.argv[2]).resolve() else 7)
'''
    env=os.environ.copy();env['LD_LIBRARY_PATH']=str(output_dir)
    env['PYTHONPATH']=str(Path(__file__).resolve().parent)
    try:
        proc=subprocess.run([sys.executable,'-c',smoke,SOURCE_ID,str(output)],
            env=env,text=True,capture_output=True,timeout=20)
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise BuildHold('effective-library smoke test unavailable; HOLD') from exc
    if proc.returncode != 0:
        raise BuildHold('Python did not demonstrably map the staged SQLite; HOLD: '+proc.stderr[:250])
    facts=json.loads(proc.stdout.strip())
    evidence={'approval':'NO_GO_LOCAL_BUILD_ONLY','archive_url':OFFICIAL_URL,
        'archive_sha3_256':ZIP_SHA3_256,'sqlite3_c_sha3_256':C_SHA3_256,
        'source_id':SOURCE_ID,'shared_library_sha256':hashlib.sha256(output.read_bytes()).hexdigest(),
        'library_file':str(output),'python_extension_actual_runtime':facts,
        'command':args,'python':sys.version,'machine':platform.machine(),
        'note':'No external build signature, independent provenance or deployment approval.'}
    (output_dir/'build_evidence.json').write_text(json.dumps(evidence,indent=2,sort_keys=True))
    return evidence

if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('downloaded_upstream_zip',type=Path)
    p.add_argument('empty_build_output_dir',type=Path)
    a=p.parse_args()
    try:
        print(json.dumps(isolated_build(a.downloaded_upstream_zip,a.empty_build_output_dir),indent=2))
    except BuildHold as exc:
        print('HOLD:',exc,file=sys.stderr)
        sys.exit(2)
