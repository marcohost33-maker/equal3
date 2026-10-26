"""Local trusted-path command line for Equal3 v0.7.1."""
import argparse
import json
import os
from pathlib import Path
import secrets
import stat
import sys
from state_store import StateStore, StoreError, MAX_STORED_STATE, MAX_PACKET, PROPOSAL_HDR, MAC_SIZE, prepare_update
from equal3 import _publish_posix


def _key_read(filename):
    flags=os.O_RDONLY | getattr(os,'O_NOFOLLOW',0) | getattr(os,'O_CLOEXEC',0)
    fd=os.open(filename,flags)
    with os.fdopen(fd,'rb') as f:
        st=os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode): raise StoreError('key must be regular file')
        if os.name=='posix' and (stat.S_IMODE(st.st_mode)&0o077 or st.st_uid!=os.getuid()):
            raise StoreError('key file must belong to current user with private permissions')
        key=f.read(4097)
    if not 32 <= len(key) <= 4096: raise StoreError('key length outside 32..4096')
    return key


def _bounded_file(path,limit):
    # Trusted input paths only; reject oversized files before reading into memory.
    if os.path.getsize(path)>limit:raise StoreError('input exceeds configured limit')
    data=Path(path).read_bytes()
    if len(data)>limit:raise StoreError('input grew beyond configured limit')
    return data


def _output(obj):print(json.dumps(obj,sort_keys=True))


def main(argv=None):
    ap=argparse.ArgumentParser(prog='store_cli',description='Equal3 v0.7.1 local reference state store')
    sub=ap.add_subparsers(dest='command',required=True)
    kg=sub.add_parser('keygen');kg.add_argument('path')
    init=sub.add_parser('init');init.add_argument('database');init.add_argument('initial');init.add_argument('--key-file',required=True)
    for name in ('status','verify'):
        parser=sub.add_parser(name);parser.add_argument('database');parser.add_argument('--key-file',required=True)
    prop=sub.add_parser('propose');prop.add_argument('database');prop.add_argument('target');prop.add_argument('proposal');prop.add_argument('--key-file',required=True)
    prop.add_argument('--strategy',choices=['fast','adaptive','min_size'],default='adaptive')
    apply=sub.add_parser('apply');apply.add_argument('database');apply.add_argument('proposal');apply.add_argument('--key-file',required=True)
    rr=sub.add_parser('receipt');rr.add_argument('database');rr.add_argument('request_id_hex');rr.add_argument('--key-file',required=True)
    exp=sub.add_parser('export');exp.add_argument('database');exp.add_argument('target');exp.add_argument('--key-file',required=True)
    backup=sub.add_parser('backup');backup.add_argument('database');backup.add_argument('target');backup.add_argument('--key-file',required=True)
    cp=sub.add_parser('checkpoint');cp.add_argument('database');cp.add_argument('--key-file',required=True)
    cp.add_argument('--mode',choices=['PASSIVE','FULL','RESTART','TRUNCATE','NOOP'],default='PASSIVE')
    cp.add_argument('--timeout-ms',type=int,default=1000)
    # Explicit opt-in; no silent conversion of existing WAL databases.
    for command in (init,*[sub.choices[k] for k in ('status','verify','propose','apply','receipt','export','backup','checkpoint')]):
        command.add_argument('--journal-mode', choices=('WAL','DELETE'), default='WAL')
    args=ap.parse_args(argv)
    try:
        if args.command=='keygen':
            fd=os.open(args.path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'wb') as f:
                f.write(secrets.token_bytes(32));f.flush();os.fsync(f.fileno())
            _output({'created':True});return 0
        key=_key_read(args.key_file)
        if args.command=='init':
            initial=_bounded_file(args.initial,MAX_STORED_STATE)
            store=StateStore.create(args.database,key=key,initial=initial,journal_mode=args.journal_mode)
            _output({'created':True,'store_id':store.store_id.hex(),'version':0});return 0
        store=StateStore(args.database,key=key,journal_mode=args.journal_mode)
        if args.command=='status':
            snap=store.read()
            _output({'version':snap.version,'bytes':len(snap.value),'digest':snap.digest.hex(),'store_id':store.store_id.hex()})
        elif args.command=='verify':_output(store.verify())
        elif args.command=='propose':
            target=_bounded_file(args.target,MAX_STORED_STATE)
            payload,rid=prepare_update(store,target,strategy=args.strategy)
            _publish_posix(args.proposal,lambda f:f.write(payload))
            _output({'request_id':rid.hex(),'bytes':len(payload)})
        elif args.command=='apply':
            data=_bounded_file(args.proposal,MAX_PACKET+PROPOSAL_HDR.size+MAC_SIZE)
            rec=store.apply(data)
            _output({'request_id':rec.request_id.hex(),'version':rec.version,'already_committed':rec.already_committed})
        elif args.command=='receipt':
            rid=bytes.fromhex(args.request_id_hex)
            rec=store.receipt(rid)
            _output({'found':rec is not None,'version':rec.version if rec else None})
        elif args.command=='backup':
            report=store.backup_verified(args.target)
            _output({'backup_created':True,'destination':str(Path(args.target).absolute()),**report})
        elif args.command=='checkpoint':
            _output(store.checkpoint(mode=args.mode,busy_timeout_ms=args.timeout_ms))
        elif args.command=='export':
            snap=store.read()
            _publish_posix(args.target,lambda f:f.write(snap.value))
            _output({'version':snap.version,'bytes':len(snap.value)})
        return 0
    except (ValueError,OSError) as exc:
        print(f'Equal3 error: {type(exc).__name__}: {exc}',file=sys.stderr)
        return 2

if __name__=='__main__':raise SystemExit(main())
