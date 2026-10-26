"""Equal3 v0.7.1 backup publication benchmark, stdlib-only."""
import csv, json, os, platform, sqlite3, statistics, tempfile, time
from pathlib import Path
import state_store as s
REPS=30
KEY=b'Equal3-v071-public-benchmark-only-key-never-use-in-production'
with tempfile.TemporaryDirectory() as td:
    root=Path(td)
    store=s.StateStore.create(root/'store.db',key=KEY,initial=os.urandom(64*1024))
    for i in range(5):
        blob=os.urandom(1024) + store.read().value[:64*1024-1024]
        prop,rid=s.prepare_update(store,blob,strategy='fast')
        store.apply(prop)
    rows=[]
    for i in range(REPS):
        start=time.perf_counter_ns()
        res=store.backup_verified(root/f'backup_{i:03}.sqlite')
        elapsed=(time.perf_counter_ns()-start)/1e6
        assert res['version']==5
        dest=root/f'backup_{i:03}.sqlite'
        assert s.StateStore(dest,key=KEY).read()==store.read()
        rows.append({'iteration':i+1,'milliseconds':round(elapsed,5),'backup_bytes':dest.stat().st_size,'version':res['version']})
    with open(Path(__file__).parent/'benchmark_v071.csv','w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=rows[0].keys());w.writeheader();w.writerows(rows)
    lat=sorted(r['milliseconds'] for r in rows)
    obj={'runs':len(rows),'median_ms':round(statistics.median(lat),3),
         'p95_nearest_rank_ms':lat[(95*len(lat)+99)//100-1],
         'min_ms':min(lat),'max_ms':max(lat),
         'mean_backup_bytes':round(statistics.mean(r['backup_bytes'] for r in rows)),
         'python':platform.python_version(),'sqlite':sqlite3.sqlite_version,
         'system':platform.system(),
         'meaning':'online SQLite backup + checksum/receipts verification + file fsync + exclusive new-name publication + dir fsync; local host'}
    (Path(__file__).parent/'benchmark_v071.json').write_text(json.dumps(obj,indent=2)+'\n')
    print(json.dumps(obj,indent=2))
