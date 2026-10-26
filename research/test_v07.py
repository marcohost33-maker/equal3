from contextlib import closing
"""v0.7 fault matrix, optimistic CAS races, consistent audits, and key/parser fuzz."""
import os, random, sqlite3, subprocess, sys, tempfile, threading, unittest
from pathlib import Path
import equal3
import state_store as s

KEY = b'v07-validation-secret-strong-key'  # fixed test key, not for production
HERE = Path(__file__).resolve().parent

class HardeningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)/'store.db'
        self.store = s.StateStore.create(self.path, key=KEY, initial=b'A'*8192)
    def new_proposal(self, target=b'B'*8192, rid=None):
        return s.prepare_update(self.store, target, request_id=rid)

    def test_crash_matrix_all_transaction_stages(self):
        stages = ['after_preflight', 'after_begin', 'after_receipt_check',
                  'after_cas', 'after_receipt_insert', 'before_commit', 'after_commit']
        for stage in stages:
            with self.subTest(stage=stage):
                # A fresh database per stage, no state from prior iterations.
                p = Path(self.tmp.name)/(stage+'.db')
                db=s.StateStore.create(p,key=KEY,initial=b'seed')
                msg,rid=s.prepare_update(db,b'target')
                script=("import os,sys,state_store as s; "
                        "db=s.StateStore(sys.argv[1],key=bytes.fromhex(sys.argv[3])); "
                        "db.apply(bytes.fromhex(sys.argv[2]),fault=lambda stage:os._exit(77) "
                        "if stage==sys.argv[4] else None)")
                run=subprocess.run([sys.executable,'-c',script,str(p),msg.hex(),KEY.hex(),stage],cwd=HERE,
                                   capture_output=True,timeout=20)
                self.assertEqual(run.returncode,77,run.stderr.decode(errors='replace'))
                reopened=s.StateStore(p,key=KEY)
                expected=1 if stage=='after_commit' else 0
                self.assertEqual(reopened.read().version,expected)
                self.assertEqual(reopened.verify()['receipt_count'],expected)
                r=reopened.receipt(rid)
                self.assertEqual(r is not None, bool(expected))
                if not expected:
                    self.assertEqual(reopened.apply(msg).version,1)
                else:
                    self.assertTrue(reopened.apply(msg).already_committed)

    def test_race_rechecks_version_after_predecode(self):
        msg,_=self.new_proposal(b'first')
        def concurrent(stage):
            if stage=='after_preflight':
                other=s.StateStore(self.path,key=KEY)
                proposal,_=s.prepare_update(other,b'second')
                self.assertEqual(other.apply(proposal).version,1)
        with self.assertRaises(s.ConflictError):
            self.store.apply(msg,fault=concurrent)
        self.assertEqual(self.store.read().value,b'second')
        self.assertEqual(self.store.verify()['version'],1)

    def test_idempotent_race_rechecks_request_after_predecode(self):
        msg,rid=self.new_proposal(b'first')
        def concurrent(stage):
            if stage=='after_preflight':
                other=s.StateStore(self.path,key=KEY)
                self.assertEqual(other.apply(msg).version,1)
        receipt=self.store.apply(msg,fault=concurrent)
        self.assertTrue(receipt.already_committed)
        self.assertEqual(receipt.version,1)
        self.assertEqual(self.store.verify()['receipt_count'],1)

    def test_commit_callback_failure_is_unknown_not_false_rollback(self):
        msg,rid=self.new_proposal(b'after')
        def fail(stage):
            if stage=='after_commit':
                raise RuntimeError('lost acknowledgement')
        with self.assertRaises(s.CommitOutcomeUnknown):
            self.store.apply(msg,fault=fail)
        self.assertEqual(self.store.receipt(rid).version,1)
        self.assertTrue(self.store.apply(msg).already_committed)

    def test_precommit_failure_is_known_rollback(self):
        msg,rid=self.new_proposal()
        def fail(stage):
            if stage=='after_receipt_insert':
                raise RuntimeError('injected')
        with self.assertRaises(RuntimeError):self.store.apply(msg,fault=fail)
        self.assertIsNone(self.store.receipt(rid))
        self.assertEqual(self.store.verify()['version'],0)

    def test_connection_defense_settings(self):
        with closing(self.store._db()) as db, db:
            self.assertEqual(db.execute('PRAGMA trusted_schema').fetchone()[0],0)
            self.assertEqual(db.execute('PRAGMA mmap_size').fetchone()[0],0)
            self.assertEqual(db.execute('PRAGMA synchronous').fetchone()[0],2)
            self.assertEqual(db.execute('PRAGMA journal_mode').fetchone()[0].lower(),'wal')

    def test_audit_during_concurrent_commits(self):
        failures=[]
        start=threading.Event()
        def writer():
            start.wait()
            try:
                for i in range(60):
                    msg,_=s.prepare_update(self.store, i.to_bytes(4,'big'))
                    self.store.apply(msg)
            except Exception as exc:failures.append(repr(exc))
        t=threading.Thread(target=writer)
        t.start(); start.set()
        try:
            for _ in range(100):
                report=self.store.verify()
                self.assertEqual(report['version'],report['receipt_count'])
        finally:
            t.join(timeout=30)
        self.assertFalse(failures, failures)
        self.assertEqual(self.store.verify()['version'],60)

    def test_parser_random_mutations_and_recovered_exactly(self):
        msg,rid=self.new_proposal(b'new-value'*900)
        rng=random.Random(20261017)
        for i in range(2500):
            mutant=bytearray(msg)
            if i%5==0:
                mutant=mutant[:rng.randrange(len(mutant))]
            elif i%5==1:
                mutant.extend(rng.randbytes(rng.randrange(1,20)))
            else:
                at=rng.randrange(len(mutant))
                mutant[at] ^= (1 << rng.randrange(8))
            with self.assertRaises(s.StoreError):
                self.store.apply(bytes(mutant))
        self.assertEqual(self.store.read().version,0)
        self.assertIsNone(self.store.receipt(rid))
        self.assertEqual(self.store.apply(msg).version,1)

    def test_signed_but_semantically_invalid_inner_packet_rejected(self):
        base=self.store.read().value
        packet=bytearray(equal3.encode_bytes(base,b'C'*1024,key=KEY))
        # Recompute the *inner* HMAC after deliberate packet damage.
        packet[equal3.HEADER.size+equal3.RECORD.size+3] ^= 0x80
        auth=equal3._authenticator(KEY)
        auth.update(packet[:-equal3.TRAILER_SIZE])
        packet[-equal3.TRAILER_SIZE:]=auth.digest()
        forged=s.make_proposal(self.store.store_id,0,os.urandom(16),bytes(packet),key=KEY)
        with self.assertRaises((s.StoreError,equal3.CodecError)):self.store.apply(forged)
        self.assertEqual(self.store.read().version,0)

    @unittest.skipUnless(os.name=='posix','resource limits only on POSIX')
    def test_guarded_cli_and_resource_parameters(self):
        cli=HERE/'run_guarded_cli.py'
        key_path=Path(self.tmp.name)/'keyfile'
        key_path.write_bytes(KEY)
        os.chmod(key_path,0o600)
        ok=subprocess.run([sys.executable,str(cli),'--memory-mib','768','--cpu-seconds','10',
                           '--wall-seconds','10','--file-mib','128','--','status',
                           str(self.path),'--key-file',str(key_path)],capture_output=True,text=True,timeout=20)
        self.assertEqual(ok.returncode,0,ok.stderr)
        invalid=subprocess.run([sys.executable,str(cli),'--memory-mib','0','--','status',
                                str(self.path),'--key-file',str(key_path)],capture_output=True,text=True,timeout=10)
        self.assertNotEqual(invalid.returncode,0)
        self.assertEqual(self.store.read().version,0)

    def test_missing_database_does_not_recreate(self):
        self.path.unlink()
        for suffix in ('-wal','-shm'):
            p=Path(str(self.path)+suffix)
            if p.exists():p.unlink()
        with self.assertRaises(s.StoreError):
            s.StateStore(self.path,key=KEY)

if __name__=='__main__':unittest.main()
