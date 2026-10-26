from contextlib import closing
"""Equal3 v0.6 transactional state-store regression/adversarial tests."""
import hmac
import os
import multiprocessing as mp
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
import state_store as s
import equal3 as e

KEY=b'S' * 32

def proposal(store, target, *, rid=None, base=None):
    snap = store.read() if base is None else base
    packet=e.encode_bytes(snap.value,target,key=KEY)
    rid=secrets.token_bytes(16) if rid is None else rid
    return s.make_proposal(store.store_id,snap.version,rid,packet,key=KEY),rid


def _worker(db_path, payload, queue):
    try:
        db=s.StateStore(db_path,key=KEY)
        receipt=db.apply(payload)
        queue.put(('ok',receipt.version))
    except s.ConflictError:
        queue.put(('conflict',0))
    except Exception as exc:
        queue.put(('unexpected',str(exc)))

class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.path=Path(self.tmp.name)/'store.sqlite'
        self.store=s.StateStore.create(self.path,key=KEY,initial=b'base'*1000)
    def tearDown(self):self.tmp.cleanup()

    def test_commit_and_receipt_after_reopen(self):
        blob,rid=proposal(self.store,b'after'*1000)
        result=self.store.apply(blob)
        self.assertEqual(result.version,1)
        later=s.StateStore(self.path,key=KEY)
        self.assertEqual(later.read().value,b'after'*1000)
        self.assertEqual(later.receipt(rid).version,1)
        self.assertEqual(self.store.apply(blob).already_committed, True)
        self.assertEqual(later.read().version,1)

    def test_stale_conflict_and_aba(self):
        initial=self.store.read()
        stale,rid=proposal(self.store,b'new-state',base=initial)
        self.store.apply(proposal(self.store,b'other')[0])
        self.store.apply(proposal(self.store,initial.value)[0])
        self.assertEqual(self.store.read().value,initial.value)
        self.assertEqual(self.store.read().version,2)
        with self.assertRaises(s.ConflictError):self.store.apply(stale)
        self.assertIsNone(self.store.receipt(rid))

    def test_replay_same_id_different_proposal_rejected(self):
        rid=bytes.fromhex('00112233445566778899aabbccddeeff')
        first,_=proposal(self.store,b'first',rid=rid)
        self.store.apply(first)
        # same packet but edited expected-version (correctly re-signed) must not be treated as same request
        second=s.make_proposal(self.store.store_id,1,rid,first[s.PROPOSAL_HDR.size:-32],key=KEY)
        with self.assertRaises(s.ReplayError):self.store.apply(second)
        self.assertEqual(self.store.read().value,b'first')

    def test_cross_store_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            other=s.StateStore.create(Path(tmp)/'store.sqlite',key=KEY,initial=self.store.read().value)
            blob,_=proposal(self.store,b'new')
            with self.assertRaises(s.AuthenticationError):other.apply(blob)

    def test_proposal_tamper_and_truncation(self):
        blob,_=proposal(self.store,b'A'*4000)
        for p in (blob[:-1],blob+b'A',blob[:20],blob[:0]):
            with self.assertRaises(s.StoreError): self.store.apply(p)
        for ix in (5,25,50,90,len(blob)-1):
            z=bytearray(blob);z[ix]^=1
            with self.assertRaises(s.StoreError):self.store.apply(bytes(z))
        self.assertEqual(self.store.read().version,0)

    def test_unsigned_inner_packet_rejected(self):
        b=self.store.read()
        unkeyed=e.encode_bytes(b.value,b'new')
        p=s.make_proposal(self.store.store_id,b.version,secrets.token_bytes(16),unkeyed,key=KEY)
        with self.assertRaises(s.StoreError):self.store.apply(p)
        self.assertEqual(self.store.read().version,0)

    def test_invalid_inner_packet_rejected(self):
        snap=self.store.read()
        packet=bytearray(e.encode_bytes(snap.value,b'new',key=KEY));packet[-1]^=0x01
        p=s.make_proposal(self.store.store_id,0,secrets.token_bytes(16),bytes(packet),key=KEY)
        with self.assertRaises(e.CodecError):self.store.apply(p)
        self.assertEqual(self.store.read().value,snap.value)

    def test_before_commit_fault_rolls_back_all_tables(self):
        p,rid=proposal(self.store,b'after')
        def fault(stage):
            if stage=='before_commit':raise RuntimeError('injected failure')
        with self.assertRaises(RuntimeError):self.store.apply(p,fault=fault)
        self.assertEqual(self.store.read().version,0)
        self.assertIsNone(self.store.receipt(rid))
        self.assertEqual(self.store.apply(p).version,1)

    def test_crash_before_commit_rolls_back(self):
        p,rid=proposal(self.store,b'after')
        src="import os,sys;from state_store import StateStore;db=StateStore(sys.argv[1],key=b'S'*32); p=bytes.fromhex(sys.argv[2]);db.apply(p,fault=lambda stage:os._exit(91) if stage=='before_commit' else None)"
        result=subprocess.run([sys.executable,'-c',src,str(self.path),p.hex()],cwd=str(Path(__file__).parent))
        self.assertEqual(result.returncode,91)
        self.assertEqual(self.store.read().version,0)
        self.assertIsNone(self.store.receipt(rid))
        self.assertEqual(self.store.apply(p).version,1)

    def test_crash_after_commit_persists_and_idempotent(self):
        p,rid=proposal(self.store,b'after')
        src="import os,sys;from state_store import StateStore;db=StateStore(sys.argv[1],key=b'S'*32);p=bytes.fromhex(sys.argv[2]);db.apply(p,fault=lambda stage:os._exit(92) if stage=='after_commit' else None)"
        result=subprocess.run([sys.executable,'-c',src,str(self.path),p.hex()],cwd=str(Path(__file__).parent))
        self.assertEqual(result.returncode,92)
        self.assertEqual(self.store.read().version,1)
        self.assertEqual(self.store.read().value,b'after')
        self.assertEqual(self.store.receipt(rid).version,1)
        self.assertTrue(self.store.apply(p).already_committed)
        self.assertEqual(self.store.read().version,1)

    def test_wrong_key_rejected_on_open(self):
        with self.assertRaises(s.AuthenticationError):
            s.StateStore(self.path,key=b'X'*32)
        self.assertEqual(self.store.read().version,0)

    def test_open_missing_refuses_reset(self):
        with self.assertRaises(s.StoreError):s.StateStore(Path(self.tmp.name)/'missing.sqlite',key=KEY)

    def test_create_refuses_overwrite(self):
        with self.assertRaises(s.StoreError):s.StateStore.create(self.path,key=KEY,initial=b'oops')
        self.assertEqual(self.store.read().version,0)

    def test_concurrent_writers(self):
        snapshot=self.store.read()
        proposals=[proposal(self.store,('payload-%d'%i).encode())[0] for i in range(8)]
        ctx=mp.get_context('spawn')
        queue=ctx.Queue()
        processes=[ctx.Process(target=_worker,args=(str(self.path),x,queue)) for x in proposals]
        for p in processes:p.start()
        for p in processes:p.join(20)
        self.assertTrue(all(p.exitcode==0 for p in processes))
        statuses=[queue.get(timeout=5)[0] for _ in processes]
        self.assertEqual(statuses.count('ok'),1)
        self.assertEqual(statuses.count('conflict'),7)
        self.assertEqual(self.store.read().version,1)

    def test_randomized_version_chain_and_receipts(self):
        import random
        rng=random.Random(20261017)
        for i in range(100):
            target=rng.randbytes(rng.randrange(0,2048))
            pkt,rid=proposal(self.store,target)
            receipt=self.store.apply(pkt)
            self.assertEqual(receipt.version,i+1)
            self.assertEqual(self.store.read().value,target)
            self.assertIsNotNone(self.store.receipt(rid))

    def test_verify_integrity_and_history(self):
        self.assertEqual(self.store.verify()['version'],0)
        p,_=proposal(self.store,b'after')
        self.store.apply(p)
        self.assertEqual(self.store.verify()['receipt_count'],1)
        with closing(sqlite3.connect(self.path)) as c, c:
            c.execute('UPDATE receipts SET base_version=-1 WHERE committed_version=1')
        with self.assertRaises(s.IntegrityError):self.store.verify()

    def test_oversized_claimed_inner_output_rejected_early(self):
        snap=self.store.read()
        raw=bytearray(e.encode_bytes(snap.value,b'small',key=KEY))
        import struct
        struct.pack_into('>Q',raw,4+1+1+8,s.MAX_STORED_STATE+1)
        p=s.make_proposal(self.store.store_id,0,secrets.token_bytes(16),bytes(raw),key=KEY)
        with self.assertRaises(s.StoreError):self.store.apply(p)
        self.assertEqual(self.store.read().version,0)

    def test_randomized_proposal_bitflips_rolled_back(self):
        import random
        randomizer=random.Random(7711)
        p,_=proposal(self.store,b'z'*5000)
        for _ in range(250):
            corrupted=bytearray(p)
            offset=randomizer.randrange(len(corrupted))
            corrupted[offset]^=1<<randomizer.randrange(8)
            with self.assertRaises(s.StoreError):self.store.apply(bytes(corrupted))
        self.assertEqual(self.store.read().version,0)

    def test_cli_full_flow_and_secure_key_reader(self):
        here=Path(__file__).parent
        with tempfile.TemporaryDirectory() as root:
            dr=Path(root);cli=str(here/'store_cli.py')
            key=dr/'key';ini=dr/'initial';target=dr/'target';db=dr/'db';prop=dr/'proposal';out=dr/'output'
            ini.write_bytes(b'A'*8000);target.write_bytes(b'B'*8000)
            def call(*args):
                return subprocess.run([sys.executable,cli,*map(str,args)],capture_output=True,text=True)
            self.assertEqual(call('keygen',key).returncode,0)
            self.assertEqual(call('init',db,ini,'--key-file',key).returncode,0)
            self.assertEqual(call('propose',db,target,prop,'--key-file',key).returncode,0)
            self.assertEqual(call('apply',db,prop,'--key-file',key).returncode,0)
            self.assertEqual(call('apply',db,prop,'--key-file',key).returncode,0)
            self.assertEqual(call('export',db,out,'--key-file',key).returncode,0)
            self.assertEqual(out.read_bytes(),target.read_bytes())
            self.assertEqual(call('verify',db,'--key-file',key).returncode,0)
            if os.name=='posix':
                link=dr/'key-link'
                link.symlink_to(key)
                self.assertNotEqual(call('status',db,'--key-file',link).returncode,0)

    def test_integrity_detects_external_corruption(self):
        with closing(sqlite3.connect(self.path)) as conn, conn:
            conn.execute("UPDATE head SET value=? WHERE id=1",(b'tampered',))
        with self.assertRaises(s.IntegrityError):self.store.read()

if __name__=='__main__':unittest.main()
