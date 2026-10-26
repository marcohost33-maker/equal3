"""Equal3 v0.7.20 commit checkpoint witness: LOCAL POSIX RESEARCH daemon.

Manual offline bootstrap is required. No auto-bootstrap, no unsafe fallback,
no command-line secret arguments. This daemon alone does not create an independent
antirollback domain. Provision separate service accounts/hosts and root-owned
attester public key using a real deployment system before considering production.
"""
import argparse
import os
import stat
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
from external_commit_witness_v0720 import CommitWitnessLedger,CommitWitnessServer
from writer_service_v0714 import _private_file, _root_provisioned_public_key


def serve(*,db_path,socket_path,signer_key_file,seal_key_file,attester_public_key_file,deployment_id):
    skraw=_private_file(signer_key_file,name='witness signing secret')
    seal=_private_file(seal_key_file,name='witness seal secret')
    if len(skraw)!=32 or len(seal)!=32:
        raise ValueError('raw Ed25519 witness seed and seal credential must both be 32 bytes')
    signing_key=Ed25519PrivateKey.from_private_bytes(skraw)
    attester=Ed25519PublicKey.from_public_bytes(_root_provisioned_public_key(attester_public_key_file))
    path=Path(socket_path).absolute()
    st=path.parent.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.geteuid() or stat.S_IMODE(st.st_mode)!=0o700:
        raise PermissionError('socket directory must be private mode 0700 owned by witness service')
    if path.exists() or path.is_symlink():raise FileExistsError('preexisting witness socket must be resolved offline')
    ledger=CommitWitnessLedger(db_path,signing_key=signing_key,attester_public_key=attester,
                               seal_key=seal,deployment_id=deployment_id)
    with CommitWitnessServer(path,ledger) as server:
        server.serve_forever()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--db-path',required=True)
    p.add_argument('--socket-path',required=True)
    p.add_argument('--signer-key-file',required=True)
    p.add_argument('--seal-key-file',required=True)
    p.add_argument('--attester-public-key-file',required=True)
    p.add_argument('--deployment-id',required=True)
    args=p.parse_args();serve(**vars(args))

if __name__=='__main__':main()
