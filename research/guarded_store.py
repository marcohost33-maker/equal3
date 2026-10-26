"""Equal3 v0.7.3 optional fail-closed witness-coordinated write facade.

Threat boundary: ALL writers must use this facade; the witness and its key
must live in an INDEPENDENT, non-rollbackable trust domain. A local file is
only a functional demo. SQLite commit and witness publication are NOT atomic.
"""
from __future__ import annotations
from pathlib import Path
import hmac
import os
import stat

import witness
from state_store import StateStore, _parse_proposal, StoreError, CommitOutcomeUnknown

class AnchorPendingError(RuntimeError):
    """Commit outcome or witness publication not jointly established; fail closed."""

class WitnessPathUnsafe(ValueError): pass

def _path_preflight(path):
    """Additional hardening for trusted single-host POSIX directories.

    This does NOT secure against root, hostile remote filesystems or rollback.
    """
    if os.name != 'posix':
        raise WitnessPathUnsafe('POSIX only')
    p = Path(path).absolute()
    parent = p.parent
    if parent.is_symlink():
        raise WitnessPathUnsafe('symlink witness directory forbidden')
    st = parent.stat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o022:
        raise WitnessPathUnsafe('witness directory requires owner control and no group/world writes')
    for f in (p, Path(str(p)+'.lock')):
        if f.is_symlink():
            raise WitnessPathUnsafe('symlink witness/lock forbidden')
        if f.exists():
            fst=f.stat()
            if not stat.S_ISREG(fst.st_mode) or fst.st_uid != os.getuid() or fst.st_mode & 0o077:
                raise WitnessPathUnsafe('witness/lock owner or permissions unsafe')
    return p

class GuardedStore:
    def __init__(self, store: StateStore, witness_path, witness_key: bytes):
        self.store=store
        self.path=_path_preflight(witness_path)
        self.key=witness._key(witness_key)

    def assess(self):
        _path_preflight(self.path)
        return witness.assess(self.store,self.path,self.key)

    def read(self):
        """Guarded coherent read under the cooperating-writer lock.

        In contrast with assess() then read(), the returned value and audited
        version originate from a single pinned SQLite read transaction.
        """
        _path_preflight(self.path)
        def work():
            audit, snap = self.store.read_verified()
            if audit.get('receipt_auth') != 'HMAC_CHAIN_V2':
                raise witness.WitnessError('legacy unsealed history cannot authorize guarded read')
            local = witness.Checkpoint(audit['store_id'],audit['version'],audit['digest_sha256'])
            anchor = witness.read_witness(self.path,self.key)
            witness._compare_checkpoint(local,anchor)
            return snap
        return witness._with_lock(self.path,work)

    def apply(self, proposal:bytes, *, fault=None):
        """Serialize cooperating writers; commit+checkpoint is NOT all-or-nothing.

        If any error happens during/after the SQLite apply, return a pending
        state and require explicit, independently authorized recovery.
        """
        _path_preflight(self.path)
        def transaction():
            # This must be checked BEFORE any modifying operation.
            witness.assess(self.store,self.path,self.key)
            old=witness.read_witness(self.path,self.key)
            sid, base_version, rid, _, _ = _parse_proposal(proposal,key=self.store.key)
            if sid.hex()!=old.store_id:
                raise witness.ForkDetected('proposal for another store')
            if base_version != old.version:
                # Old replay may be idempotent; the underlying StateStore resolves it.
                # A NEW proposal must not bypass the anchored version.
                r=self.store.receipt(rid)
                if r is None:
                    raise witness.RollbackDetected('proposal not based on anchored head')
            # This operation can commit before returning an exception.
            try:
                receipt=self.store.apply(proposal,fault=fault)
            except CommitOutcomeUnknown as exc:
                raise AnchorPendingError('commit indeterminate; investigate receipt and witness') from exc
            except BaseException:
                # Some injected errors may be raised after a committed transaction.
                # Re-evaluate the receipt before declaring that nothing changed.
                r=self.store.receipt(rid)
                if r is not None and r.version > old.version:
                    raise AnchorPendingError('commit may be visible without updated anchor')
                raise
            if receipt.already_committed:
                if receipt.version > old.version:
                    raise AnchorPendingError('replay receipt ahead of witness')
                return receipt
            if receipt.base_version!=old.version or receipt.version!=old.version+1:
                raise AnchorPendingError('unexpected step across witness versions')
            try:
                # STRICT: exactly one version and same digest, not arbitrary fast-forward.
                audit=self.store.verify()
                if audit['version'] != receipt.version or audit['digest_sha256'] != receipt.digest.hex():
                    raise witness.ForkDetected('committed state and receipt mismatch')
                new=witness.Checkpoint(old.store_id, receipt.version, receipt.digest.hex())
                witness._write_atomic(self.path,witness._pack(new,self.key),initial=False)
                witness.assess(self.store,self.path,self.key)
            except BaseException as exc:
                raise AnchorPendingError('DB committed but witness not conclusively confirmed; STOP writes') from exc
            return receipt
        return witness._with_lock(self.path,transaction)

def diagnostics(store: StateStore, witness_path, witness_key:bytes, *, request_id=None):
    """Read-only triage; never silently repairs or advances witness."""
    try:
        status=witness.assess(store,witness_path,witness_key)
    except witness.RollbackDetected: status='ROLLBACK_DETECTED'
    except witness.AheadOfWitness: status='AHEAD_OF_WITNESS_HOLD'
    except witness.ForkDetected: status='FORK_DETECTED'
    except witness.WitnessError: status='INVALID_WITNESS'
    receipt=None
    if request_id is not None:
        r=store.receipt(request_id)
        if r is not None:
            receipt={'version':r.version,'base_version':r.base_version,'digest':r.digest.hex()}
    return {'status':status,'receipt':receipt,'action':'HOLD' if status!='MATCH' else 'READ_ONLY_OK'}
