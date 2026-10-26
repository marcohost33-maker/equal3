"""Synthetic isolated microbenchmark for v0.7.8 WAL vs v0.7.9 rollback authority.
Usage: python benchmark_journal_v079.py SOURCE_DIR N ROUND_ID OUTPUT_JSON
"""
import hashlib,hmac,json,os,pathlib,secrets,sqlite3,statistics,sys,tempfile,time
sys.path.insert(0,sys.argv[1]); import anchor_wire
from anchor_protocol import Position,Intent,_review_message
n=int(sys.argv[2]); trial=int(sys.argv[3]); target=sys.argv[4]
s=pathlib.Path(sys.argv[1]);source_hash=hashlib.sha256((s/'anchor_wire.py').read_bytes()).hexdigest()
with tempfile.TemporaryDirectory() as tmp:
  p=pathlib.Path(tmp);os.chmod(p,0o700)
  review=b'r'*32;seal=b's'*32
  a=anchor_wire.PersistentCASAnchor.bootstrap(p/'anchor.db',Position('a'*32,0,'0'*64),reviewer_key=review,seal_key=seal,research_unsafe_sqlite=True)
  with sqlite3.connect(p/'anchor.db') as db: journal=db.execute('PRAGMA journal_mode').fetchone()[0]
  transitions=[];statuses=[]
  for i in range(n+5):
    old='0'*64 if i==0 else hashlib.sha256((str(i-1)+'new').encode()).hexdigest()
    new=hashlib.sha256((str(i)+'new').encode()).hexdigest()
    intent=Intent('a'*32,i,old,i+1,new,secrets.token_hex(16),'d'*64)
    token=hmac.new(review,_review_message(intent,'FINALIZE_COMMIT'),hashlib.sha256).digest()
    t0=time.perf_counter_ns();a.prepare(intent);a.adjudicate(intent,'FINALIZE_COMMIT',token)
    t1=time.perf_counter_ns();snapshot=a.status();t2=time.perf_counter_ns()
    assert snapshot.committed.version==i+1
    if i>=5:
      transitions.append((t1-t0)/1e6);statuses.append((t2-t1)/1e6)
  def m(arr):return {'p50_ms':round(statistics.median(arr),4),'p95_ms':round(sorted(arr)[int(0.95*(len(arr)-1))],4),'count':len(arr)}
  payload={'variant':s.name,'journal':journal,'sqlite_version':sqlite3.sqlite_version,'source_sha256':source_hash,'round':trial,'n':n,'transition':m(transitions),'status':m(statuses)}
  pathlib.Path(target).write_text(json.dumps(payload,indent=2))
  print(json.dumps(payload))
