"""Minimal auditable CLI; keys accepted only via a file, never argv values."""
import argparse
import os
import stat
import sys
import equal3 as e


def get_key(path):
    if path is None:
        return None
    st = os.stat(path)
    if os.name == 'posix' and stat.S_IMODE(st.st_mode) & 0o077:
        raise e.CodecError('key file permissions must be private (0600)')
    with open(path,'rb') as f:
        key=f.read(4097)
    if not 32 <= len(key) <= 4096:
        raise e.CodecError('key length outside permitted bounds 32..4096')
    return key


def main(argv=None):
    ap=argparse.ArgumentParser(prog='equal3',description='=== / Equal3 v0.5 local trusted-path research CLI')
    sub=ap.add_subparsers(dest='action',required=True)
    enc=sub.add_parser('encode',help='base + new state -> EQ3 v0.5 packet')
    enc.add_argument('base');enc.add_argument('target');enc.add_argument('packet')
    enc.add_argument('--key-file');enc.add_argument('--allow-unsigned-local',action='store_true')
    enc.add_argument('--strategy',choices=('fast','adaptive','min_size'),default='adaptive')
    dec=sub.add_parser('apply',help='base + packet -> atomically published new state')
    dec.add_argument('base');dec.add_argument('packet');dec.add_argument('target')
    dec.add_argument('--key-file');dec.add_argument('--allow-unsigned-local',action='store_true')
    args=ap.parse_args(argv)
    try:
        key=get_key(args.key_file)
        if args.action=='encode':
            if key is None and not args.allow_unsigned_local:
                raise e.CodecError('supply --key-file or explicit --allow-unsigned-local')
            e.encode_file(args.base,args.target,args.packet,key=key,strategy=args.strategy)
        else:
            e.apply_file(args.base,args.packet,args.target,key=key,require_auth=not args.allow_unsigned_local)
    except (e.CodecError, OSError, TypeError) as ex:
        print('Equal3 error:',ex,file=sys.stderr)
        return 2
    return 0

if __name__=='__main__':sys.exit(main())
