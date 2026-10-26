"""Offline research operator command: consume an independently issued root signature.

NEVER use on live/valuable data. Stop the authority daemon first. A real deployment
must use an external root signer AND independently monotonically recorded epoch.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from anchor_wire import read_credential, unique_json
from writer_service_v0714 import _root_provisioned_public_key
from trust_rotation_v0718 import RootControlledCASAnchor


def main():
    ap=argparse.ArgumentParser(description='Equal3 v0718 offline root-authorized attester rotation (research only)')
    for field in ('db','reviewer-key-file','seal-key-file','old-attester-public-file',
                  'new-attester-public-file','root-public-file','deployment-id','authorization-file'):
        ap.add_argument('--'+field,required=True)
    ap.add_argument('--trusted-min-epoch',type=int,required=True)
    ap.add_argument('--research-offline-apply',action='store_true',
                    help='Explicitly authorize offline mutation, no production guarantee')
    args=ap.parse_args()
    if not args.research_offline_apply:
        ap.error('fail closed: --research-offline-apply must be explicitly supplied')
    def pub(filename):
        return Ed25519PublicKey.from_public_bytes(_root_provisioned_public_key(filename))
    path=Path(args.authorization_file)
    if path.is_symlink() or not path.is_file() or path.stat().st_size>4096:
        ap.error('authorization file must be a small regular non-symlink file')
    evidence=unique_json(path.read_bytes())
    a=RootControlledCASAnchor(args.db,reviewer_key=read_credential(args.reviewer_key_file),
          seal_key=read_credential(args.seal_key_file),
          attester_public_key=pub(args.old_attester_public_file),
          deployment_id=args.deployment_id,root_public_key=pub(args.root_public_file),
          min_epoch=args.trusted_min_epoch)
    epoch=a.rotate_attester(new_attester_public_key=pub(args.new_attester_public_file),
                            authorization=evidence)
    print(json.dumps({'research_only':True,'new_epoch':epoch,
                      'P0':'Independent monotonic floor publication and operator review REQUIRED'}))


if __name__=='__main__': main()
