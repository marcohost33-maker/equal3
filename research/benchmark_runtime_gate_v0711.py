"""CPU-only offline synthetic Ed25519 gate verification; NOT a storage/production benchmark."""
from __future__ import annotations
import csv
import hashlib
import json
from pathlib import Path
import platform
import statistics
import sys
import time
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import runtime_gate_v0711 as gate

NOW=1793000000
key=Ed25519PrivateKey.generate()
public=key.public_key().public_bytes(encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw)
facts={'sqlite_version':'3.54.1','sqlite_source_id':'2026-10-16 14:45:20 '+'a'*64,
    'loaded_sqlite_shared_object_sha256':'b'*64,'mapped_file_identity_consistent':True}
policy={'schema':gate.SCHEMA,'purpose':gate.PURPOSE,'deployment_id':'synthetic-only',
    'sqlite_version':facts['sqlite_version'],'sqlite_source_id':facts['sqlite_source_id'],
    'loaded_library_sha256':facts['loaded_sqlite_shared_object_sha256'],
    'python_abi':f'{sys.version_info.major}.{sys.version_info.minor}',
    'machine':platform.machine(),'not_before':NOW-1,'expires_at':NOW+60}
raw=json.dumps(policy,sort_keys=True).encode();signature=key.sign(raw)
iterations=300
results=[]
with patch.object(gate,'runtime_inventory',return_value=facts),patch.object(gate,'sqlite_wal_reset_safe',return_value=True):
    for _ in range(20):
        gate.verify_signed_runtime_policy(raw,signature,public,deployment_id='synthetic-only',now=NOW)
    for _ in range(iterations):
        start=time.perf_counter_ns()
        gate.verify_signed_runtime_policy(raw,signature,public,deployment_id='synthetic-only',now=NOW)
        results.append((time.perf_counter_ns()-start)/1e6)
p50=statistics.median(results); p95=sorted(results)[int(.95*len(results))-1]
summary={'benchmark':'Ed25519+JSON+policy binding, mock-mapped patched SQLite, no I/O',
        'measurement_scope':'SYNTHETIC cryptographic gate only, not production SQLite',
        'n':iterations,'median_ms':p50,'p95_ms':p95,'platform':platform.platform(),
        'python':sys.version.split()[0], 'release_verdict':'NO_GO'}
folder=Path('EVIDENCE_V0711');folder.mkdir(exist_ok=True)
(folder/'synthetic_gate_bench.json').write_text(json.dumps(summary,indent=2,sort_keys=True))
with (folder/'synthetic_gate_bench.csv').open('w',newline='') as f:
    w=csv.writer(f);w.writerow(['index','latency_ms','note']);
    for i,x in enumerate(results):w.writerow([i,format(x,'.9f'),'synthetic_only'])
print(json.dumps(summary,sort_keys=True))
