from contextlib import closing
"""Guard boundary and negative fault tests, separate from v0.7.2 tests."""
import os, pathlib, secrets, shutil, tempfile, unittest
from unittest.mock import patch
from state_store import StateStore, prepare_update
import guarded_store as g
import witness

@unittest.skipUnless(os.name=='posix','POSIX required')
class GuardedStoreTests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory(); self.addCleanup(self.t.cleanup)
        self.dir=pathlib.Path(self.t.name);self.trust=self.dir/'trust';self.trust.mkdir(mode=0o700)
        self.key=secrets.token_bytes(32);self.wkey=secrets.token_bytes(32)
        self.db=self.dir/'db.sqlite';self.w=self.trust/'witness.txt'
        self.store=StateStore.create(self.db,key=self.key,initial=b'old')
        witness.initialize(self.store,self.w,self.wkey)
        self.g=g.GuardedStore(self.store,self.w,self.wkey)
    def proposal(self,data=b'new'):return prepare_update(self.store,data)
    def test_post_publish_indeterminate_is_hold_without_state_loss(self):
        p,rid=self.proposal()
        original=witness._write_atomic
        def published_then_error(*a,**kw):
            original(*a,**kw)
            raise witness.CommitUnknown('simulated fsync failure after rename')
        with patch.object(witness,'_write_atomic',side_effect=published_then_error):
            with self.assertRaises(g.AnchorPendingError): self.g.apply(p)
        self.assertEqual(self.store.read().version,1)
        self.assertEqual(self.g.assess(),'MATCH')
        # A repeated identical request must not duplicate the commit.
        self.assertTrue(self.g.apply(p).already_committed)
    def test_multiprocess_guarded_writers_one_commit(self):
        # Independent Python processes contend on the POSIX advisory lock.
        import subprocess, sys, concurrent.futures
        proposals=[]
        for i in range(4):
            pkt,_=self.proposal(bytes([40+i]))
            path=self.dir/f'p{i}.bin'; path.write_bytes(pkt);proposals.append(path)
        script="""import sys
from state_store import StateStore
from guarded_store import GuardedStore
import witness
s=StateStore(sys.argv[1],key=bytes.fromhex(sys.argv[2]))
g=GuardedStore(s,sys.argv[3],bytes.fromhex(sys.argv[4]))
try:
 g.apply(open(sys.argv[5],'rb').read());sys.exit(0)
except witness.RollbackDetected:sys.exit(22)
"""
        def run(p):
            return subprocess.run([sys.executable,'-c',script,str(self.db),self.key.hex(),str(self.w),self.wkey.hex(),str(p)],
                                  cwd=pathlib.Path(__file__).parent,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results=list(pool.map(run,proposals))
        self.assertEqual(sorted(x.returncode for x in results),[0,22,22,22],[(x.returncode,x.stderr) for x in results])
        self.assertEqual(self.g.assess(),'MATCH')
        self.assertEqual(self.store.read().version,1)
    def test_concurrent_proposals_one_writer(self):
        from concurrent.futures import ThreadPoolExecutor
        proposals=[self.proposal(bytes([i+1]))[0] for i in range(5)]
        def do(p):
            try:return ('ok',self.g.apply(p).version)
            except witness.RollbackDetected:return ('stale',None)
        with ThreadPoolExecutor(max_workers=5) as pool:
            results=list(pool.map(do,proposals))
        self.assertEqual(sum(r[0]=='ok' for r in results),1)
        self.assertEqual(sum(r[0]=='stale' for r in results),4)
        self.assertEqual(self.g.assess(),'MATCH')
        self.assertEqual(self.store.read().version,1)
    def test_late_witness_bootstrap_blocked(self):
        # Never silently trust an arbitrary already-progressed DB as genesis.
        p,_=self.proposal(); self.store.apply(p)
        alternate=self.trust/'later.txt'
        with self.assertRaises(witness.WitnessError): witness.initialize(self.store,alternate,self.wkey)
    def test_original_advance_refuses_version_gap(self):
        # Raw writer can still bypass API; witness must not silently bless gap.
        p,_=self.proposal();self.store.apply(p)
        q,_=self.proposal(b'two');self.store.apply(q)
        with self.assertRaises(witness.AheadOfWitness): witness.advance(self.store,self.w,self.wkey)
        self.assertEqual(witness.read_witness(self.w,self.wkey).version,0)
    def test_verify_rejects_replaced_key_binding(self):
        import sqlite3
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute('UPDATE meta SET key_check=? WHERE id=1', (b'0'*32,))
        from state_store import AuthenticationError
        with self.assertRaises(AuthenticationError): self.store.verify()
    def test_good_apply_and_assess(self):
        p,_=self.proposal();r=self.g.apply(p)
        self.assertEqual(r.version,1);self.assertEqual(self.g.assess(),'MATCH')
        self.assertEqual(self.store.read().value,b'new')
    def test_idempotent_replay(self):
        p,_=self.proposal();self.g.apply(p)
        r=self.g.apply(p)
        self.assertTrue(r.already_committed)
        self.assertEqual(self.g.assess(),'MATCH')
    def test_stale_proposal_rejected(self):
        stale,_=self.proposal(b'stale')
        fresh,_=self.proposal(b'good'); self.g.apply(fresh)
        with self.assertRaises(witness.RollbackDetected): self.g.apply(stale)
    def test_unanchored_raw_writer_blocked(self):
        p,_=self.proposal();self.store.apply(p)
        q,_=self.proposal(b'later')
        with self.assertRaises(witness.AheadOfWitness):self.g.apply(q)
    def test_tampered_witness_blocks(self):
        self.w.write_bytes(b'bad')
        with self.assertRaises(witness.WitnessError):self.g.apply(self.proposal()[0])
    def test_missing_witness_blocks(self):
        self.w.unlink()
        with self.assertRaises(FileNotFoundError): self.g.apply(self.proposal()[0])
    def test_commit_before_anchor_fault_is_pending(self):
        p,_=self.proposal()
        with patch.object(witness,'_write_atomic',side_effect=OSError('injected witness IO failure')):
            with self.assertRaises(g.AnchorPendingError):self.g.apply(p)
        self.assertEqual(self.store.read().version,1)
        self.assertEqual(g.diagnostics(self.store,self.w,self.wkey)['status'],'AHEAD_OF_WITNESS_HOLD')
        with self.assertRaises(witness.AheadOfWitness):self.g.apply(self.proposal(b'next')[0])
    def test_after_commit_fault_is_pending(self):
        p,rid=self.proposal()
        def hook(stage):
            if stage=='after_commit':raise RuntimeError('after commit')
        with self.assertRaises(g.AnchorPendingError):self.g.apply(p,fault=hook)
        self.assertIsNotNone(self.store.receipt(rid))
        self.assertEqual(self.store.read().version,1)
    def test_before_commit_fault_does_not_advance(self):
        p,rid=self.proposal()
        def hook(stage):
            if stage=='before_commit':raise ValueError('injected')
        with self.assertRaises(ValueError):self.g.apply(p,fault=hook)
        self.assertIsNone(self.store.receipt(rid))
        self.assertEqual(self.g.assess(),'MATCH')
    def test_bad_permission_rejected(self):
        os.chmod(self.trust,0o777)
        with self.assertRaises(g.WitnessPathUnsafe):g.GuardedStore(self.store,self.w,self.wkey)
    def test_bad_symlink_rejected(self):
        link=self.trust/'alias';link.symlink_to(self.w)
        with self.assertRaises(g.WitnessPathUnsafe):g.GuardedStore(self.store,link,self.wkey)
    def test_diagnostics_never_repairs(self):
        p,rid=self.proposal();self.store.apply(p)
        before=self.w.read_bytes()
        d=g.diagnostics(self.store,self.w,self.wkey,request_id=rid)
        self.assertEqual(d['action'],'HOLD');self.assertEqual(d['receipt']['version'],1)
        self.assertEqual(before,self.w.read_bytes())
    def test_old_db_new_anchor_rejected(self):
        backup=self.dir/'bak.sqlite';self.store.backup_verified(backup)
        self.g.apply(self.proposal()[0]);self.store=None
        for ext in ('','-wal','-shm'):
            p=pathlib.Path(str(self.db)+ext)
            if p.exists():p.unlink()
        shutil.copy2(backup,self.db)
        old=StateStore(self.db,key=self.key)
        with self.assertRaises(witness.RollbackDetected):g.GuardedStore(old,self.w,self.wkey).apply(prepare_update(old,b'X')[0])
if __name__=='__main__':unittest.main()
