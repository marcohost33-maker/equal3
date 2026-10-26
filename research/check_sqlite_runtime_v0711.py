"""Read-only SQLite runtime validation for Equal3 (exit 2 on any HOLD).

Example: python check_sqlite_runtime_v0711.py \\
  --policy-file /trusted/approval.json --signature-file /trusted/approval.ed25519 \\
  --public-key-file /trusted/root.pub --deployment-id prod-west-01

The Ed25519 public key MUST be pinned independently of Equal3's own storage.
An accepted runtime policy does not authorize production without OTHER gates.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

from runtime_evidence_v0710 import RuntimeEvidenceError
from runtime_gate_v0711 import verify_signed_runtime_policy


def _read_bound_file(path: Path, limit: int) -> bytes:
    import os, stat
    if not hasattr(os, 'O_NOFOLLOW'):
        raise RuntimeEvidenceError('secure file open not supported; HOLD')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|getattr(os,'O_CLOEXEC',0))
    try:
        s=os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_size < 1 or s.st_size > limit:
            raise RuntimeEvidenceError('invalid approval file size or type; HOLD')
        raw=os.read(fd,limit+1)
        if len(raw)!=s.st_size or len(raw)>limit:
            raise RuntimeEvidenceError('approval file changed during read; HOLD')
        t=os.fstat(fd)
        if (s.st_dev,s.st_ino,s.st_mtime_ns,s.st_ctime_ns,s.st_size)!= \
           (t.st_dev,t.st_ino,t.st_mtime_ns,t.st_ctime_ns,t.st_size):
            raise RuntimeEvidenceError('approval file mutated; HOLD')
        return raw
    finally:
        os.close(fd)


def main(argv=None) -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--policy-file',required=True,type=Path)
    p.add_argument('--signature-file',required=True,type=Path)
    p.add_argument('--public-key-file',required=True,type=Path)
    p.add_argument('--deployment-id',required=True)
    a=p.parse_args(argv)
    try:
        outcome=verify_signed_runtime_policy(
            _read_bound_file(a.policy_file,16384),
            _read_bound_file(a.signature_file,64),
            _read_bound_file(a.public_key_file,32),
            deployment_id=a.deployment_id)
    except (RuntimeEvidenceError,OSError,ValueError) as exc:
        print(json.dumps({'runtime_gate':'HOLD','release_verdict':'NO_GO',
                         'reason':str(exc)},sort_keys=True))
        return 2
    # A full release decision is OUT OF SCOPE of this CLI.
    print(json.dumps(outcome,sort_keys=True))
    return 0

if __name__=='__main__':
    sys.exit(main())
