"""An explicitly controlled and repeatable before/after security test.
Baseline acceptance represents a security defect, not success.
"""
import sys,os,json
from unittest import mock
sys.path.insert(0,os.getcwd())
import external_commit_witness_v0720 as w
import test_external_commit_witness_v0720 as tests
from anchor_protocol import ReviewDenied
f=tests.CommitWitnessTests('test_complete_commit_publish_then_guarded_read')
f.setUp()
try:
    intent=f.prepare();f.finalize(intent);e=f.evidence(intent)
    issued=e['statement']['issued_unix']; now={'v':issued};real=w.verify_final_checkpoint
    def advance_clock(*a,**kw):
        real(*a,**{**kw,'now':issued})
        now['v']=issued+61
    with mock.patch.object(w,'verify_final_checkpoint',side_effect=advance_clock),mock.patch.object(w.time,'time',side_effect=lambda:now['v']):
        try:
            v=f.ledger.publish(intent,e)
            result={'accepted_expired_commit':True,'version':v['version']}
        except ReviewDenied:
            result={'accepted_expired_commit':False,'denial':'ReviewDenied'}
    print(json.dumps({'source_file':w.__file__,**result},sort_keys=True))
finally:f.doCleanups()
