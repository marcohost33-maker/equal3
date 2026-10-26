"""Self-contained ABBA benchmark orchestrator: v0.7.3 vs research candidate v0.7.4.
No network; no writes to original sources, no production-grade throughput claim.
"""
import subprocess,sys,json,csv,pathlib,statistics

ROOT=pathlib.Path(__file__).parent
CHILD=r'''
import json,sys,os,random,statistics,secrets,tempfile,pathlib,time,platform,sqlite3
sys.path.insert(0,sys.argv[1])
from state_store import StateStore,prepare_update
from guarded_store import GuardedStore
import witness
rng=random.Random(20261024)
results=[]
for state_bytes in (1024,65536):
 with tempfile.TemporaryDirectory() as td:
  states={}
  for mode in ('raw','guard'):
   d=pathlib.Path(td)/mode;d.mkdir()
   key=secrets.token_bytes(32); wkey=secrets.token_bytes(32)
   state=bytes([42])*state_bytes
   s=StateStore.create(d/'state.sqlite',key=key,initial=state)
   g=None
   if mode=='guard':
    w=d/'trust';w.mkdir(mode=0o700);wpath=w/'witness.bin'
    witness.initialize(s,wpath,wkey);g=GuardedStore(s,wpath,wkey)
   states[mode]={'store':s,'guard':g,'state':state,'times':[]}
  # Balanced random mode order per iteration: work is prepared OUTSIDE measured span.
  for i in range(45):
   modes=['raw','guard'];rng.shuffle(modes)
   for mode in modes:
    st=states[mode];current=bytearray(st['state'])
    current[(i*131)%state_bytes]=(current[(i*131)%state_bytes]+1)%256
    nxt=bytes(current)
    proposal,_=prepare_update(st['store'],nxt,strategy='fast')
    t0=time.perf_counter_ns()
    if st['guard']: st['guard'].apply(proposal)
    else: st['store'].apply(proposal)
    us=(time.perf_counter_ns()-t0)/1000
    if i>=5:st['times'].append(us)
    st['state']=nxt
  for mode,st in states.items():
   assert st['store'].read().value==st['state']
   assert st['store'].verify()['version']==45
   if st['guard']:assert st['guard'].assess()=='MATCH'
   series=sorted(st['times'])
   results.append({'state_bytes':state_bytes,'mode':mode,'n':len(series),
                   'median_ms':round(statistics.median(series)/1000,4),
                   'p95_ms':round(series[min(len(series)-1,int(.95*(len(series)-1)))]/1000,4),
                   'min_ms':round(series[0]/1000,4),'max_ms':round(series[-1]/1000,4)})
print(json.dumps({'python':platform.python_version(),'sqlite':sqlite3.sqlite_version,
                  'results':results}))
'''

def main():
    dirs={'v073':str(ROOT/'equal3_v073'),'v074':str(ROOT/'equal3_v074_candidate')}
    observations=[]
    for sweep,variant in enumerate(('v073','v074','v074','v073'),1):
        c=subprocess.run([sys.executable,'-c',CHILD,dirs[variant]],capture_output=True,text=True,timeout=90,check=True)
        doc=json.loads(c.stdout)
        for x in doc['results']:observations.append({'sweep':sweep,'variant':variant,'python':doc['python'],'sqlite':doc['sqlite'],**x})
    out={'design':'ABBA variant order; randomized within-iteration operation order; 5 warmup + 40 timed writes per condition per sweep; fresh DB each sweep; proposal preparation outside timer; same OS machine; synthetic data', 'observations':observations}
    (ROOT/'benchmark_compare.json').write_text(json.dumps(out,indent=2)+'\n')
    with (ROOT/'benchmark_compare.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=observations[0].keys());w.writeheader();w.writerows(observations)
    groups={}
    for x in observations:groups.setdefault((x['variant'],x['state_bytes'],x['mode']),[]).append(x['median_ms'])
    for k,x in sorted(groups.items()):print(*k, 'median of sweep medians', round(statistics.median(x),4),'ms',x)
    return 0
if __name__=='__main__':raise SystemExit(main())
