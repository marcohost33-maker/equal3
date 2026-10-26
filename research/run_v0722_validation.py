"""Bounded new-feature validation; does NOT claim comprehensive release assurance."""
import subprocess,sys,re,os
cmd=[sys.executable,'-W','error::ResourceWarning','-m','unittest','-q','test_commit_request_binding_v0722','test_external_commit_witness_v0720','test_commit_floor_expiry_v0721']
r=subprocess.run(cmd,timeout=20,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
sys.exit(r.returncode)
