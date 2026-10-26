"""Research-only witness daemon CLI. Provision database and keys separately.

Operational requirement: run on independently administered host/storage with a
real antirollback source. Same-host service cannot guarantee this. NO-GO.
"""
from pathlib import Path
import argparse
import signal
import stat
import threading
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
from writer_service_v0714 import _root_provisioned_public_key
from anchor_wire import read_credential
from external_epoch_witness_v0719 import WitnessLedger,WitnessServer


def main():
    parser=argparse.ArgumentParser(description='Equal3 external epoch witness RESEARCH ONLY')
    parser.add_argument('--db',required=True)
    parser.add_argument('--socket',required=True)
    parser.add_argument('--witness-private-key-file',required=True)
    parser.add_argument('--root-public-key-file',required=True)
    args=parser.parse_args()
    db=Path(args.db).absolute();sock=Path(args.socket).absolute()
    if not db.exists():parser.error('witness must be provisioned offline: no implicit bootstrap')
    if sock.exists():parser.error('socket exists: refusing unlink')
    folder=sock.parent
    info=folder.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=__import__('os').geteuid() or stat.S_IMODE(info.st_mode)!=0o700:
        parser.error('witness socket directory must be owner-private 0700')
    witness_private=Ed25519PrivateKey.from_private_bytes(read_credential(args.witness_private_key_file))
    root_public=Ed25519PublicKey.from_public_bytes(_root_provisioned_public_key(args.root_public_key_file))
    ledger=WitnessLedger(db,private_key=witness_private,root_public_key=root_public)
    # Refuse to serve an invalid/foreign root witness DB.
    with __import__('contextlib').closing(ledger._connect()) as conn:
        data=ledger._load(conn)
        from trust_rotation_v0718 import fingerprint
        if data['root_fingerprint']!=fingerprint(root_public):
            parser.error('witness DB root does not match offline provisioned root key')
    with WitnessServer(sock,ledger) as server:
        def on_term(signum,frame):
            threading.Thread(target=server.shutdown,daemon=True).start()
        previous=signal.signal(signal.SIGTERM,on_term)
        try:server.serve_forever(poll_interval=0.1)
        finally:
            signal.signal(signal.SIGTERM,previous)
            sock.unlink(missing_ok=True)

if __name__=='__main__':main()
