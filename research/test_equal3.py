"""Independent deterministic reference tests for Equal3 v0.5."""
import io
import os
import random
import struct
import tempfile
import unittest
import zlib
from pathlib import Path
import equal3 as e

KEY = b'Test-only shared secret 32+ bytes - change before deployment!'

class Equal3Tests(unittest.TestCase):
    def test_empty_and_length_changes(self):
        for b,t in [(b'',b''),(b'',b'abc'),(b'abc',b''),(b'A'*1024,b'BB'),(b'ABCD',b'ABCDEF')]:
            for strategy in ('fast','adaptive'):
                for key in (None, KEY):
                    p=e.encode_bytes(b,t,key=key,strategy=strategy,chunk_size=1024)
                    self.assertEqual(e.decode_bytes(b,p,key=key,require_auth=bool(key)),t)

    def test_modes_and_64k_boundary(self):
        rng=random.Random(867)
        for length in (1,1023,1024,1025,65535,65536,65537,131105):
            b=rng.randbytes(length)
            examples=[b, bytes(length), rng.randbytes(length), b[:length//2]+b'X'+b[length//2+1:]]
            for t in examples:
                for strategy in ('fast','adaptive'):
                    p=e.encode_bytes(b,t,chunk_size=1024,strategy=strategy)
                    self.assertEqual(e.decode_bytes(b,p),t)

    def test_varint_sparse_compact(self):
        b=bytes(4096); t=bytearray(b)
        for j in (1,2,128,129,1500,2500): t[j]=33
        p=e.encode_bytes(b,bytes(t),strategy='fast',chunk_size=4096)
        self.assertEqual(p[e.HEADER.size],e.SPARSE)
        self.assertEqual(e.decode_bytes(b,p),bytes(t))

    def test_random_property(self):
        r=random.Random(20261017)
        for i in range(1000):
            size=r.randint(0,4000)
            base=r.randbytes(size)
            target=bytearray(base)
            for _ in range(r.randrange(0,25)):
                if size:
                    target[r.randrange(size)] = r.randrange(256)
            if i%7==0: target=bytearray(r.randbytes(r.randrange(0,4000)))
            key=KEY if i%3==0 else None
            strategy='adaptive' if i%2==0 else 'fast'
            packet=e.encode_bytes(base,bytes(target),chunk_size=1024,key=key,strategy=strategy)
            self.assertEqual(e.decode_bytes(base,packet,key=key,require_auth=bool(key)),bytes(target))
            damaged=bytearray(packet); j=r.randrange(len(damaged)); damaged[j]^=1<<r.randrange(8)
            with self.assertRaises(e.CodecError):
                e.decode_bytes(base,bytes(damaged),key=key,require_auth=bool(key))

    def test_key_policy_and_tamper(self):
        b=b'A'*1024; t=b'B'*1024
        signed=e.encode_bytes(b,t,key=KEY,chunk_size=1024)
        unsigned=e.encode_bytes(b,t,chunk_size=1024)
        with self.assertRaises(e.CodecError): e.decode_bytes(b,signed)
        with self.assertRaises(e.CodecError): e.decode_bytes(b,unsigned,require_auth=True)
        with self.assertRaises(e.CodecError): e.decode_bytes(b,unsigned,key=KEY)
        with self.assertRaises(e.CodecError): e.decode_bytes(b,signed,key=b'X'*32)
        altered=bytearray(signed); altered[e.HEADER.size+e.RECORD.size+2]^=0x20
        with self.assertRaises(e.CodecError): e.decode_bytes(b,bytes(altered),key=KEY,require_auth=True)
        with self.assertRaises(e.CodecError): e.encode_bytes(b,t,key=b'weak')

    def _packet(self,base,target,mode,body, *, key=None, chunk=1024):
        import hashlib
        header=e.HEADER.pack(e.MAGIC,e.FLAG_AUTH if key else 0,0,len(base),len(target),chunk,
                             hashlib.sha256(base).digest(),hashlib.sha256(target).digest())
        body_with_record=e.RECORD.pack(mode,len(body))+body
        auth=e._authenticator(key); auth.update(header+body_with_record)
        return header+body_with_record+auth.digest()

    def test_sparse_noncanonical(self):
        base=bytes(1024); target=bytes([1])+bytes(1023)
        # redundant varint for position 0
        for bad in (b'\x80\x00\x01', b'\x00\x00', b'\x81\x80\x80\x80\x80\x00\x01', b'\xff'):
            pkt=self._packet(base,target,e.SPARSE,bad)
            with self.assertRaises(e.CodecError): e.decode_bytes(base,pkt)
        # index 1024 is out of range
        pkt=self._packet(base,target,e.SPARSE,bytes(e._varint(1024))+b'\x01')
        with self.assertRaises(e.CodecError): e.decode_bytes(base,pkt)

    def test_truncated_extra_reserved_bad_mode(self):
        b=b'1234'*500; t=b'5678'*500
        pkt=e.encode_bytes(b,t,key=KEY,chunk_size=1024)
        for blob in (pkt[:0],pkt[:9],pkt[:-1],pkt+b'X'):
            with self.assertRaises(e.CodecError): e.decode_bytes(b,blob,key=KEY)
        for index in (0,4,5,6,9,13,18,23,54):
            changed=bytearray(pkt);changed[index]^=1
            with self.assertRaises(e.CodecError):e.decode_bytes(b,bytes(changed),key=KEY)
        malformed=self._packet(bytes(1024),bytes(1024),99,b'')
        with self.assertRaises(e.CodecError):e.decode_bytes(bytes(1024),malformed)

    def test_zlib_trailer_and_truncation(self):
        base=b'X'*1024; target=b'Z'*1024
        compressed=zlib.compress(target,6)
        for bad in (compressed[:-2], compressed+b'ignore',zlib.compress(target+b'Y')):
            packet=self._packet(base,target,e.ZLIB,bad)
            with self.assertRaises(e.CodecError):e.decode_bytes(base,packet)

    def test_bounded_claim_and_chunk(self):
        b=b'B'*1024
        pkt=e.encode_bytes(b,b,chunk_size=1024)
        for bad_chunk in (1,1023,1025,2*1024*1024):
            with self.assertRaises(e.CodecError):e.encode_bytes(b,b,chunk_size=bad_chunk)
            tampered=bytearray(pkt)
            struct.pack_into('>I',tampered,22,bad_chunk)
            with self.assertRaises(e.CodecError):e.decode_bytes(b,bytes(tampered))
        tampered=bytearray(pkt)
        # target size at offset 14, no decode allocation should occur
        struct.pack_into('>Q',tampered,14,e.MAX_STATE+1)
        with self.assertRaises(e.CodecError):e.decode_bytes(b,bytes(tampered))

    def test_streams_and_short_reads(self):
        class ShortRead(io.BytesIO):
            def read(self,n=-1):return super().read(min(n,13) if n>=0 else 13)
        b=b'xyz'*9000; t=b'w'*50000
        dest=io.BytesIO()
        e.encode_stream(ShortRead(b),ShortRead(t),dest,key=KEY,chunk_size=1024)
        decoded=io.BytesIO()
        e.decode_stream(ShortRead(b),ShortRead(dest.getvalue()),decoded,key=KEY,require_auth=True)
        self.assertEqual(decoded.getvalue(),t)

    def test_atomic_file_publication(self):
        if os.name!='posix': self.skipTest('requires POSIX')
        with tempfile.TemporaryDirectory() as tmp:
            tmp=Path(tmp)
            bp,tp,pp,out= [tmp/x for x in ('base','target','packet','result')]
            bp.write_bytes(b'old'*1000);tp.write_bytes(b'NEW'*1000);out.write_bytes(b'safe-before')
            e.encode_file(bp,tp,pp,key=KEY,chunk_size=1024)
            corrupted=pp.read_bytes()[:-1];pp.write_bytes(corrupted)
            with self.assertRaises(e.CodecError): e.apply_file(bp,pp,out,key=KEY)
            self.assertEqual(out.read_bytes(),b'safe-before')
            e.encode_file(bp,tp,pp,key=KEY,chunk_size=1024)
            e.apply_file(bp,pp,out,key=KEY)
            self.assertEqual(out.read_bytes(),tp.read_bytes())
            # Unsigned packets are rejected by file publication by default
            e.encode_file(bp,tp,pp,key=None,chunk_size=1024)
            with self.assertRaises(e.CodecError): e.apply_file(bp,pp,out)
            self.assertEqual(out.read_bytes(),tp.read_bytes())

    def test_no_expansion_within_chunk_payload_choice(self):
        rnd=random.Random(17)
        for size in (1024,2048,65536,70000):
            b=rnd.randbytes(size); t=rnd.randbytes(size)
            packet=e.encode_bytes(b,t,chunk_size=1024)
            n_chunks=(size+1023)//1024
            self.assertLessEqual(len(packet),e.HEADER.size+e.TRAILER_SIZE+size+n_chunks*e.RECORD.size)

if __name__=='__main__': unittest.main(verbosity=2)
