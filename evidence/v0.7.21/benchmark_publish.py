"""Workload: one post-finalization witness CAS per fresh private SQLite fixture.
Run as an isolated subprocess with cwd set to the baseline/new source tree.
Every run loads Python modules from os.getcwd(), never from the benchmark script path.
"""
import os,sys,time,json,statistics
sys.path.insert(0,os.getcwd())
import external_commit_witness_v0720 as w
from test_external_commit_witness_v0720 import CommitWitnessTests
N=int(sys.argv[1]) if len(sys.argv)>1 else 12
elapsed=[]
for _ in range(N):
    f=CommitWitnessTests('test_complete_commit_publish_then_guarded_read')
    f.setUp()
    try:
        intent=f.prepare();f.finalize(intent);e=f.evidence(intent)
        begin=time.perf_counter_ns();result=f.ledger.publish(intent,e);end=time.perf_counter_ns()
        assert result['version']==1
        elapsed.append((end-begin)/1e6)
    finally:f.doCleanups()
print(json.dumps({'source':w.__file__,'samples':N,'p50_ms':statistics.median(elapsed),'p95_ms':sorted(elapsed)[int((len(elapsed)-1)*.95)],'values_ms':elapsed}))
