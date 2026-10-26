"""Optional coverage-guided authenticated codec fuzz harness.

Requires 'pip install atheris' in an isolated test environment. NOT executed by
standard library tests. Uses only fixed test secrets. No database modification.
"""
import hashlib, hmac, sys
try:
    import atheris
except ImportError as exc:
    raise SystemExit('Install optional test-only dependency: pip install atheris') from exc
import equal3

KEY=b'Equal3-fuzzer-synthetic-key-32byte'
BASE=b'0'*8192
TARGET=b'1'*8192
VALID=equal3.encode_bytes(BASE,TARGET,key=KEY)

def TestOneInput(data):
    if len(data)>2048:
        return
    # Construct structured mutations of a valid authenticated packet. Unlike
    # random broken MACs this penetrates the packet authenticator and decoder.
    packet=bytearray(VALID)
    if data:
        pos=int.from_bytes(data[:2].ljust(2,b'\0'),'big')%(len(packet)-equal3.TRAILER_SIZE)
        end=min(pos+len(data[2:]),len(packet)-equal3.TRAILER_SIZE)
        packet[pos:end]=data[2:2+(end-pos)]
    tag=equal3._authenticator(KEY)
    tag.update(packet[:-equal3.TRAILER_SIZE])
    packet[-equal3.TRAILER_SIZE:]=tag.digest()
    try:
        decoded=equal3.decode_bytes(BASE,bytes(packet),key=KEY,require_auth=True)
    except equal3.CodecError:
        return
    assert decoded==TARGET, 'authenticated mutated packet returned unexpected value'

if __name__=='__main__':
    atheris.Setup(sys.argv,TestOneInput)
    atheris.Fuzz()
