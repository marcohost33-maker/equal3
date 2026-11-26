#!/usr/bin/env python3
"""Hand mutants of the ADR-003 candidate; each must make test_engine_split.py fail.

Usage (from the repository root): python prototypes/engine_split/mutate_engine_split.py [OUT.json]
Each mutant is applied to a temporary copy of this directory (research/ and tools/ are linked,
unchanged); the test module runs there and must exit non-zero. Exit 0 here means every mutant
outside EQUIVALENT was killed. Stdlib only, POSIX (symlinks).
"""
import json, os, shutil, subprocess, sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
# post-commit re-check: after the pre-commit comparison of every intent field, the CAS and the
# chain-tail checks leave no state in which the committed receipt can differ (defence in depth)
EQUIVALENT = {'M05 post-commit check off'}
M = [
 ('M01 no pending-intent check', 'eq3_engine.py', "        if pending is None:\n            raise AnchorHold('no prepared", "        if False:\n            raise AnchorHold('no prepared"),
 ('M02 intent comparison off', 'eq3_engine.py', "        if (pending.proposal_hash != facts.proposal_hash", "        if False and (pending.proposal_hash != facts.proposal_hash"),
 ('M03 target digest not compared', 'eq3_engine.py', "                or pending.digest != facts.target_digest):", "                ):"),
 ('M04 request id not compared', 'eq3_engine.py', "pending.request_id != facts.request_id", "False"),
 ('M05 post-commit check off', 'eq3_engine.py', "        if receipt.already_committed or receipt.digest.hex()", "        if False and receipt.already_committed or receipt.digest.hex()"),
 ('M06 public apply alias', 'eq3_engine.py', "    def verify(self):\n", "    def apply(self, proposal):\n        return self._commit(proposal)\n\n    def verify(self):\n"),
 ('M07 key as public attribute', 'eq3_engine.py', "        self._key = check_key(key)\n", "        self._key = check_key(key)\n        self.key = self._key\n"),
 ('M08 coordinator skips anchor prepare', 'eq3_coordinator.py', "        self.anchor.prepare(intent)\n", "        pass\n"),
 ('M09 coordinator writes around the capability', 'eq3_coordinator.py', "receipt = self._capability.commit(proposal)", "receipt = self.engine._commit(proposal)"),
 ('M10 capability binding not checked', 'eq3_coordinator.py', "        if not capability.bound_to(engine, anchor):", "        if False:"),
 ('M11 serve without anchor', 'eq3_writer_service.py', "    if _research_anchor is None:", "    if False:"),
 ('M12 handler ignores peer UID', 'eq3_writer_service.py', "            if peer_uid(self.request) != server.writer_uid:\n                return", "            if peer_uid(self.request) != server.writer_uid:\n                pass"),
 ('M13 WAL gate boundary', 'eq3_wal_gate.py', "(3, 51, 3)", "(3, 51, 2)"),
 ('M14 runtime approval window', 'eq3_runtime_gate.py', "30*86400", "31*86400"),
 ('M15 wire imports the service (cycle)', 'eq3_wire.py', "from eq3_engine import MAX_STORED_STATE\n", "from eq3_engine import MAX_STORED_STATE\nimport eq3_writer_service\n"),
 ('M16 writer imports state_store', 'eq3_anchored_writer.py', "import secrets\n", "import secrets\nimport state_store\n"),
 ('M18 proposal hash not compared', 'eq3_engine.py', "pending.proposal_hash != facts.proposal_hash or ", ""),
 ('M17 writer core trusts unbound capability', 'eq3_anchored_writer.py', "        except AnchorHold as exc:\n            raise WriterError('commit capability", "        except ZeroDivisionError as exc:\n            raise WriterError('commit capability"),
]
results = []
for name, fname, old, new in M:
    with tempfile.TemporaryDirectory(prefix='eq3mut-') as t:
        t = Path(t)
        (t / 'prototypes').mkdir()
        shutil.copytree(ROOT / 'prototypes/engine_split', t / 'prototypes/engine_split',
                        ignore=shutil.ignore_patterns('__pycache__'))
        os.symlink(ROOT / 'research', t / 'research'); os.symlink(ROOT / 'tools', t / 'tools')
        f = t / 'prototypes/engine_split' / fname
        src = f.read_text()
        assert src.count(old) == 1, (name, src.count(old))
        f.write_text(src.replace(old, new))
        r = subprocess.run([sys.executable, '-B', '-m', 'unittest', 'prototypes/engine_split/test_engine_split.py'],
                           cwd=t, capture_output=True, text=True, timeout=600)
        failed = [l.split('(')[0].replace('FAIL: ', '').replace('ERROR: ', '').strip()
                  for l in r.stderr.splitlines() if l.startswith(('FAIL:', 'ERROR:'))]
        results.append({'mutant': name, 'killed': r.returncode != 0, 'failing_tests': failed})
        print('%-48s %s %s' % (name, 'KILLED ' if r.returncode else 'SURVIVED', ', '.join(failed)[:150]))
out = Path(sys.argv[1]) if len(sys.argv) > 1 else None
if out:
    out.write_text(json.dumps({'python': sys.version.split()[0], 'equivalent': sorted(EQUIVALENT),
                               'mutants': results}, indent=2) + '\n')
survivors = [r['mutant'] for r in results if not r['killed'] and r['mutant'] not in EQUIVALENT]
print('killed %d of %d; equivalent %d; unexpected survivors: %s'
      % (sum(r['killed'] for r in results), len(results), len(EQUIVALENT), survivors or 'none'))
sys.exit(1 if survivors else 0)
