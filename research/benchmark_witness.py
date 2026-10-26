"""Median/p95 from same local environment, not a cross-host performance claim."""
import tempfile,time,statistics,json,pathlib,secrets,sys,hashlib
from state_store import StateStore,prepare_update
import witness
N=40
with tempfile.TemporaryDirectory() as d:
    root=pathlib.Path(d)
    key=secrets.token_bytes(32);wkey=secrets.token_bytes(32)
    s=StateStore.create(root/'state.db',key=key,initial=b'0'*65536)
    anchor=root/'external'/'witness.txt';anchor.parent.mkdir()
    witness.initialize(s,anchor,wkey)
    bare=[];anchored=[];advance=[]
    for i in range(N):
        t=time.perf_counter_ns();s.verify();bare.append((time.perf_counter_ns()-t)/1e6)
        t=time.perf_counter_ns();witness.assess(s,anchor,wkey);anchored.append((time.perf_counter_ns()-t)/1e6)
    p,r=prepare_update(s, b'1'*65536);s.apply(p)
    t=time.perf_counter_ns();witness.advance(s,anchor,wkey);advance.append((time.perf_counter_ns()-t)/1e6)
    for i in range(N):
        t=time.perf_counter_ns();witness.assess(s,anchor,wkey);anchored.append((time.perf_counter_ns()-t)/1e6)
    def stats(v):
        v=sorted(v);return {'n':len(v),'median_ms':round(statistics.median(v),3),'p95_ms':round(v[int(0.95*(len(v)-1))],3),'min_ms':round(v[0],3),'max_ms':round(v[-1],3)}
    result={'baseline_verify':stats(bare),'assess_with_witness':stats(anchored),'witness_advance':stats(advance),
            'witness_bytes':anchor.stat().st_size,'python':sys.version.split()[0]}
    (pathlib.Path(__file__).parent/'benchmark_witness.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
