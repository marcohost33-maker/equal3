"""Research-only runtime inventory: report the *loaded* SQLite library, not just _sqlite3.

Linux /proc/self/maps implementation. A hash of a pathname is NOT proof of
what bytes were loaded if the file was replaced; mapped dev+inode must match.
A trusted deployment must additionally supply a separately authenticated
allowlist / build attestation. This module grants no Equal3 production GO.
"""
from __future__ import annotations
from contextlib import closing
from pathlib import Path
import hashlib
import os
import stat
import sqlite3
import _sqlite3


class RuntimeEvidenceError(RuntimeError):
    pass


def mapped_sqlite_identity(map_text: str) -> tuple[str, int, tuple[int,int]]:
    """Return mapped libsqlite3 absolute path, inode and Linux dev major/minor.

    Refuse unlinked mappings, anonymous shared objects and inconsistent paths.
    No matching shared lib means the build may be static: manual provenance HOLD.
    """
    identities=set()
    for line in map_text.splitlines():
        parts=line.split(maxsplit=5)
        if len(parts)!=6: continue
        _,_,_,dev,inode,path=parts
        if 'libsqlite3.so' not in path: continue
        if not path.startswith('/') or path.endswith(' (deleted)'):
            raise RuntimeEvidenceError('SQLite mapping is deleted or not a stable file')
        try:
            major,minor=(int(x,16) for x in dev.split(':'))
            inode_number=int(inode)
        except (ValueError,TypeError) as exc:
            raise RuntimeEvidenceError('cannot parse loaded SQLite mapping') from exc
        if inode_number<=0: raise RuntimeEvidenceError('SQLite inode unavailable')
        identities.add((path,inode_number,(major,minor)))
    if len(identities)!=1:
        raise RuntimeEvidenceError('SQLite loaded library unavailable or ambiguous')
    return identities.pop()


def runtime_inventory() -> dict:
    with closing(sqlite3.connect(':memory:')) as db:
        source=db.execute('SELECT sqlite_source_id()').fetchone()[0]
    extension=Path(_sqlite3.__file__)
    evidence={
        'sqlite_version': sqlite3.sqlite_version,
        'sqlite_source_id': source,
        'python_extension':str(extension),
        'python_extension_sha256':hashlib.sha256(extension.read_bytes()).hexdigest(),
        'loaded_sqlite_shared_object':None,
        'loaded_sqlite_shared_object_sha256':None,
        'mapped_file_identity_consistent':False,
        'runtime_attestation':'NOT_ATTESTED',
        'release_verdict':'NO_GO',
    }
    try:
        path,inode,dev = mapped_sqlite_identity(Path('/proc/self/maps').read_text())
        # Hash via the same O_NOFOLLOW descriptor that we fstat, not by
        # independently reopening a pathname after examining its inode.
        flags = os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0)
        if not hasattr(os, 'O_NOFOLLOW'):
            raise RuntimeEvidenceError('no O_NOFOLLOW for mapped library; HOLD')
        fd = os.open(path, flags | os.O_NOFOLLOW)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size <= 0 or st.st_size > 64*1024*1024:
                raise RuntimeEvidenceError('mapped SQLite file type/size invalid')
            if (st.st_ino, (os.major(st.st_dev),os.minor(st.st_dev))) != (inode,dev):
                raise RuntimeEvidenceError('mapped SQLite inode differs from opened object')
            digest = hashlib.sha256()
            while True:
                block = os.read(fd, 1024*1024)
                if not block:
                    break
                digest.update(block)
            new = os.fstat(fd)
            if (new.st_dev,new.st_ino,new.st_mtime_ns,new.st_ctime_ns,new.st_size) != \
               (st.st_dev,st.st_ino,st.st_mtime_ns,st.st_ctime_ns,st.st_size):
                raise RuntimeEvidenceError('SQLite library changed during descriptor hashing')
            hash_bytes = digest.hexdigest()
        finally:
            os.close(fd)
        if mapped_sqlite_identity(Path('/proc/self/maps').read_text()) != (path,inode,dev):
            raise RuntimeEvidenceError('mapped SQLite library identity changed during inventory')
        evidence.update(loaded_sqlite_shared_object=path,
                        loaded_sqlite_shared_object_sha256=hash_bytes,
                        mapped_file_identity_consistent=True)
    except (OSError,RuntimeEvidenceError) as exc:
        evidence['loaded_library_error']=str(exc)
    return evidence


def require_approved_sqlite(approved:dict) -> dict:
    """BLOCK deprecated unsigned allowlist. Use runtime_gate_v0711 instead.

    Historical code accepted a freely constructed dictionary as an approval.
    A public API that validates unsigned caller input cannot prove independent
    supply-chain authorization even if the binary digest and version match.
    """
    raise RuntimeEvidenceError(
        'unsigned runtime approval deprecated; independent signed policy required; HOLD')

if __name__=='__main__':
    import json
    print(json.dumps(runtime_inventory(),indent=2,sort_keys=True))
