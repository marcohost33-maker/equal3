"""Equal3 experimental external monotonic witness.

Security boundary: witness directory AND witness secret must remain independent,
trusted, non-rollbackable relative to the SQLite store. Local file alone does
NOT provide physical anti-rollback or protection against admin/root compromise.

The witness is updated AFTER a SQLite commit; if interrupted in-between, the
store may be ahead of witness and MUST be reviewed, not silently accepted.
"""
from __future__ import annotations
from dataclasses import dataclass
import os, tempfile, json, hmac, hashlib, fcntl, stat
from pathlib import Path

DOMAIN = b'EQ3-WITNESS-v1\x00'
MAX_BLOB = 4096

class WitnessError(ValueError): pass
class RollbackDetected(WitnessError): pass
class ForkDetected(WitnessError): pass
class AheadOfWitness(WitnessError): pass
class CommitUnknown(OSError): pass

@dataclass(frozen=True)
class Checkpoint:
    store_id: str
    version: int
    digest: str

def _key(secret):
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise WitnessError('independent witness secret must have >=32 bytes')
    return secret

def _serialized(c):
    if len(c.store_id) != 32 or len(c.digest) != 64 or c.version < 0 or c.version >= 2**63-1:
        raise WitnessError('invalid checkpoint')
    try: bytes.fromhex(c.store_id); bytes.fromhex(c.digest)
    except ValueError as e: raise WitnessError('invalid hex') from e
    return json.dumps({'digest':c.digest,'store_id':c.store_id,'version':c.version},sort_keys=True,separators=(',',':')).encode('ascii')

def _pack(c, secret):
    payload=_serialized(c)
    tag=hmac.new(_key(secret),DOMAIN+payload,hashlib.sha256).hexdigest()
    return payload+b'\n'+tag.encode('ascii')+b'\n'

def read_witness(path, secret):
    _key(secret)
    # No symlink-following or unbounded read even for direct witness callers.
    flags=os.O_RDONLY | getattr(os,'O_NOFOLLOW',0) | getattr(os,'O_CLOEXEC',0)
    fd=os.open(path,flags)
    try:
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise WitnessError('witness is not a regular file')
        if st.st_size > MAX_BLOB:
            raise WitnessError('oversized witness')
        with os.fdopen(fd,'rb',closefd=False) as stream:
            raw=stream.read(MAX_BLOB+1)
    finally:
        os.close(fd)
    if len(raw)>MAX_BLOB: raise WitnessError('oversized witness')
    try:
        payload,tag,empty=raw.split(b'\n')
        if empty: raise ValueError('trailing bytes')
        obj=json.loads(payload)
        if set(obj)!={'digest','store_id','version'} or type(obj['version']) is not int: raise ValueError('fields')
        ck=Checkpoint(obj['store_id'],obj['version'],obj['digest'])
        if payload != _serialized(ck): raise ValueError('noncanonical')
    except (ValueError,TypeError,UnicodeError,KeyError) as e:
        raise WitnessError('malformed witness') from e
    expected=hmac.new(secret, DOMAIN+payload, hashlib.sha256).hexdigest().encode('ascii')
    if not hmac.compare_digest(tag, expected): raise WitnessError('witness authentication failure')
    return ck

def state_checkpoint(store):
    # Important: store.verify() obtains one consistent SQLite read transaction;
    # separate read() / store_id calls can observe different committed versions.
    audit=store.verify()
    if audit.get('receipt_auth') != 'HMAC_CHAIN_V2':
        raise WitnessError('legacy unsealed history cannot establish authenticated checkpoint')
    return Checkpoint(audit['store_id'],audit['version'],audit['digest_sha256'])

def _compare_checkpoint(c, w):
    if c.store_id!=w.store_id: raise ForkDetected('wrong store ID')
    if c.version < w.version: raise RollbackDetected('database version below witness')
    if c.version > w.version: raise AheadOfWitness('database version exceeds witness; investigate commit gap')
    if not hmac.compare_digest(c.digest,w.digest): raise ForkDetected('same version different digest')
    return 'MATCH'


def assess(store, path, secret):
    """Return MATCH or raise, FAIL CLOSED for unanchored newer store."""
    # Single verified read snapshot; do not compare two separate DB snapshots.
    w=read_witness(path,secret)
    c=state_checkpoint(store)
    return _compare_checkpoint(c,w)

def _write_atomic(path, data, *, initial):
    path=Path(path).absolute()
    if not path.parent.is_dir(): raise WitnessError('witness directory missing')
    fd,tmp=tempfile.mkstemp(prefix='.eq3-witness-',dir=str(path.parent))
    visible=False
    try:
        with os.fdopen(fd,'wb') as out:
            os.fchmod(out.fileno(),0o600)
            out.write(data)
            out.flush(); os.fsync(out.fileno())
        if initial:
            os.link(tmp,path,follow_symlinks=False)
        else:
            os.replace(tmp,path)
        visible=True
        dfd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try: os.fsync(dfd)
        finally: os.close(dfd)
    except OSError as e:
        if visible: raise CommitUnknown('witness visible but persistence indeterminate') from e
        raise
    finally:
        if os.path.exists(tmp): os.unlink(tmp)

def _with_lock(path, cb):
    p=Path(path).absolute()
    # Separate lock file assumes protected directory. Never claim hostile FS safety.
    fd=os.open(str(p)+'.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        s=os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.getuid() or s.st_mode & 0o077:
            raise WitnessError('unsafe lock file permissions or owner')
        fcntl.flock(fd,fcntl.LOCK_EX)
        return cb()
    finally:
        try: fcntl.flock(fd,fcntl.LOCK_UN)
        finally: os.close(fd)

def initialize(store,path,secret):
    _key(secret)
    p=Path(path).absolute()
    def work():
        if p.exists(): raise WitnessError('witness exists')
        checkpoint=state_checkpoint(store)
        if checkpoint.version != 0:
            raise WitnessError('late bootstrap forbidden; requires independently verified migration procedure')
        _write_atomic(p,_pack(checkpoint,secret),initial=True)
    return _with_lock(p,work)

def advance(store,path,secret):
    """Advance only after verified SQLite commit. Not transactionally coupled to store."""
    _key(secret)
    p=Path(path).absolute()
    def work():
        old=read_witness(p,secret)
        new=state_checkpoint(store)
        if new.store_id!=old.store_id: raise ForkDetected('store identity changed')
        if new.version<old.version: raise RollbackDetected('refuse decreasing version')
        if new.version==old.version:
            if new.digest != old.digest: raise ForkDetected('divergence at same version')
            return 'UNCHANGED'
        if new.version != old.version+1:
            raise AheadOfWitness('multiple unanchored versions; hold for independent adjudication')
        _write_atomic(p,_pack(new,secret),initial=False)
        return 'ADVANCED'
    return _with_lock(p,work)
