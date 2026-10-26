"""Process-abort injection; POSIX only, NOT sector-torn / power-loss VFS."""
import os, unittest, tempfile, pathlib, subprocess, sys, secrets
from state_store import StateStore,prepare_update

HOOKS=['after_preflight','after_begin','after_receipt_check','after_cas','after_receipt_insert','before_commit','after_commit']
class FaultLab(unittest.TestCase):
    @unittest.skipUnless(os.name=='posix','process-abort lab currently POSIX only')
    def test_each_crash_point_has_atomic_state_and_receipt(self):
        for hook in HOOKS:
            with self.subTest(hook=hook), tempfile.TemporaryDirectory() as d:
                db=pathlib.Path(d)/'store.sqlite'; key=secrets.token_bytes(32)
                s=StateStore.create(db,key=key,initial=b'OLD')
                proposal,rid=prepare_update(s,b'NEW')
                payload=pathlib.Path(d)/'request.bin';payload.write_bytes(proposal)
                script='''
import os,sys
from state_store import StateStore
s=StateStore(sys.argv[1],key=bytes.fromhex(sys.argv[2]))
proposal=open(sys.argv[3],'rb').read()
def fail(stage):
    if stage==sys.argv[4]: os._exit(79)
s.apply(proposal,fault=fail)
'''
                run=subprocess.run([sys.executable,'-c',script,str(db),key.hex(),str(payload),hook],cwd=pathlib.Path(__file__).parent,
                                   stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
                self.assertEqual(run.returncode,79,run.stderr.decode())
                recovered=StateStore(db,key=key)
                snap=recovered.read();receipt=recovered.receipt(rid);verify=recovered.verify()
                if hook=='after_commit':
                    self.assertEqual((snap.version,snap.value),(1,b'NEW'))
                    self.assertIsNotNone(receipt)
                else:
                    self.assertEqual((snap.version,snap.value),(0,b'OLD'))
                    self.assertIsNone(receipt)
                self.assertEqual(verify['version'],snap.version)
if __name__=='__main__': unittest.main()
