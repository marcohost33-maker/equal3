import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import equal3 as e
from minimalmaschine import execute, MachineError
from info_theory import entropy, conditional_entropy, binary_entropy
KEY = b'Z'*32
class Extensions(unittest.TestCase):
    def test_signature_verified_before_inflate(self):
        b=b'X'*8192;t=b'Y'*8192
        p=bytearray(e.encode_bytes(b,t,key=KEY,chunk_size=8192))
        self.assertEqual(p[e.HEADER.size],e.ZLIB)
        p[-1] ^= 1
        with patch.object(e,'_inflate',side_effect=AssertionError('bad packet reached decoder')):
            with self.assertRaises(e.CodecError):
                e.decode_bytes(b,bytes(p),key=KEY,require_auth=True)
    def test_packet_requires_seekable_for_preverification(self):
        class NoSeek(io.BytesIO):
            def tell(self):raise io.UnsupportedOperation()
        b=b'a'*1024;t=b'b'*1024
        p=e.encode_bytes(b,t,key=KEY,chunk_size=1024)
        with self.assertRaises(e.CodecError):
            e.decode_stream(io.BytesIO(b),NoSeek(p),io.BytesIO(),key=KEY,require_auth=True)
    def test_min_size_never_larger_than_adaptive_fast(self):
        import random
        r=random.Random(919)
        for _ in range(80):
            b=r.randbytes(r.randrange(0,12000))
            t=bytearray(b)
            for i in range(r.randrange(0,130)):
                if t:t[r.randrange(len(t))]=r.randrange(256)
            packets=[e.encode_bytes(b,bytes(t),strategy=st,chunk_size=1024)
                     for st in ('fast','adaptive','min_size')]
            self.assertLessEqual(len(packets[2]),len(packets[0]))
            self.assertLessEqual(len(packets[2]),len(packets[1]))
    def test_subl_equivalence_example(self):
        # m[1]=5-3 => 2, not <=0, advance/halt at end
        state,trace=execute([(0,1,-1)],[3,5]);self.assertEqual(state,(3,2))
        self.assertEqual(len(trace),1)
        # m[1]=2-3 => -1, <=0 -> -1 halt
        state,trace=execute([(0,1,-1)],[3,2]);self.assertEqual(state,(3,-1))
        self.assertIn('Ergebnis -1',trace[0].deutsch)
    def test_subl_reject_invalid_infinite(self):
        for prog,mem in [([(0,5,-1)],[3,2]), ([(0,0,0)],[0])]:
            with self.assertRaises(MachineError): execute(prog,mem,max_steps=25)
    def test_entropy_distinction(self):
        self.assertAlmostEqual(binary_entropy(.5),1)
        self.assertAlmostEqual(binary_entropy(0),0)
        seq=[64,128,192]*200
        self.assertAlmostEqual(entropy(seq),__import__('math').log2(3),places=10)
        self.assertAlmostEqual(conditional_entropy(seq),0,places=10)
    def test_commit_indeterminate_after_rename(self):
        if os.name!='posix': self.skipTest('POSIX only')
        with tempfile.TemporaryDirectory() as tmp:
            target=Path(tmp)/'out'
            target.write_bytes(b'old')
            original=e.os.fsync
            count=[0]
            def fail_directory(fd):
                count[0]+=1
                if count[0]==2: raise OSError('injected directory fsync failure')
                return original(fd)
            with patch.object(e.os,'fsync',side_effect=fail_directory):
                with self.assertRaises(e.CommitIndeterminate):
                    e._publish_posix(target,lambda out:out.write(b'new'))
            self.assertEqual(target.read_bytes(),b'new')

    def test_cli_hardened_roundtrip(self):
        if os.name!='posix':self.skipTest('POSIX CLI atomic publication')
        here=Path(__file__).parent
        with tempfile.TemporaryDirectory() as root:
            p=Path(root);bp=p/'base';tp=p/'target';packet=p/'packet';result=p/'result';key=p/'secret'
            bp.write_bytes(b'A'*4096);tp.write_bytes(b'Z'*4096);key.write_bytes(KEY);key.chmod(0o600)
            cmd=[sys.executable,str(here/'cli.py')]
            a=subprocess.run(cmd+['encode',str(bp),str(tp),str(packet),'--key-file',str(key)],capture_output=True,text=True)
            self.assertEqual(a.returncode,0,a.stderr)
            a=subprocess.run(cmd+['apply',str(bp),str(packet),str(result),'--key-file',str(key)],capture_output=True,text=True)
            self.assertEqual(a.returncode,0,a.stderr)
            self.assertEqual(result.read_bytes(),tp.read_bytes())
            key.chmod(0o644)
            a=subprocess.run(cmd+['apply',str(bp),str(packet),str(result),'--key-file',str(key)],capture_output=True,text=True)
            self.assertNotEqual(a.returncode,0)
if __name__=='__main__':unittest.main()
