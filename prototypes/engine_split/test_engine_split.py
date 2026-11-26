"""Tests of the ADR-003 candidate (prototype, NOT a research version). Release: NO-GO.

Run from the repository root:  python -m unittest -v prototypes/engine_split/test_engine_split.py
Needs Linux (AF_UNIX, SO_PEERCRED), Python >= 3.10; the research tree is imported unchanged as
the reference. Keys are synthetic test material.

LegacyBypass      negative first: what v0.7.22 allows, and that the candidate refuses it
EngineSurface     no public engine method writes; the key is not an attribute
Differential      the candidate answers like research v0.7.15 and leaves byte-identical tables
Faults            anchor prepare / SQLite commit interruptions give the same HOLD states
Compatibility     databases move between research StateStore and the engine in both directions
Distribution      allowlist build: closure clean without baseline, legacy/lab not importable
Service           serve() HOLDs without an anchor; the RPC handler reaches the anchored core
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
RESEARCH = ROOT / 'research'
TOOLS = ROOT / 'tools'
for p in (str(RESEARCH), str(HERE)):
    if p not in sys.path:
        sys.path.insert(0, p)

import anchor_protocol as r_anchor  # noqa: E402  research reference, unchanged
import anchored_writer_v0715 as r_writer  # noqa: E402
import state_store as r_store  # noqa: E402

import eq3_anchor_lab as lab  # noqa: E402
import eq3_anchor_types as types_  # noqa: E402
import eq3_anchored_writer as c_writer  # noqa: E402
import eq3_coordinator as c_coord  # noqa: E402
import eq3_engine as engine_mod  # noqa: E402
import eq3_provision as provision  # noqa: E402
import eq3_wire as wire  # noqa: E402
import eq3_writer_service as service  # noqa: E402

KEY = b'K' * 32                    # synthetic test key
REVIEWER = b'Test-only reviewer key 32+ bytes!!'  # synthetic test key
GENESIS = b'genesis state ' * 8
TABLES = ('meta', 'head', 'receipts', 'receipt_auth')


def tables(path):
    with closing(sqlite3.connect('file:%s?mode=ro' % path, uri=True)) as db:
        return {t: db.execute('SELECT * FROM %s ORDER BY 1' % t).fetchall() for t in TABLES}


def file_sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def rid(n):
    return bytes([n]) * 16


class Tmp(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix='eq3split-')
        self.dir = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def research_genesis(self, name='db.sqlite'):
        path = self.dir / name
        r_store.StateStore.create(path, key=KEY, initial=GENESIS, journal_mode='DELETE')
        return path

    def candidate(self, path):
        engine = engine_mod.StateEngine(path, key=KEY)
        anchor = lab.MemoryCASAnchor(c_coord.position_for_genesis(engine), reviewer_key=REVIEWER)
        engine, cap = engine_mod.bind_writer(path, key=KEY, anchor=anchor)
        return engine, cap, anchor

    def research(self, path):
        store = r_store.StateStore(path, key=KEY, journal_mode='DELETE')
        anchor = r_anchor.MemoryCASAnchor(r_anchor.position_for_genesis(store), reviewer_key=REVIEWER)
        return store, anchor


class LegacyBypass(Tmp):
    """Negative first: v0.7.22 writes without any anchor intent; the candidate has no such path."""

    def test_research_store_writes_without_anchor_intent(self):
        path = self.research_genesis()
        store, anchor = self.research(path)
        proposal, _ = r_store.prepare_update(store, b'bypass', request_id=rid(1))
        receipt = store.apply(proposal)                       # no prepare, no review
        self.assertEqual((receipt.version, anchor.status().pending), (1, None))
        coord = r_anchor.CoordinatedStore(store, anchor)
        self.assertEqual(coord.diagnose().code, 'DIVERGENCE_HOLD')  # detected only afterwards
        self.assertTrue(hasattr(store, 'key') and store.key == KEY)  # key is a public attribute

    def test_candidate_capability_refuses_without_prepared_intent(self):
        path = self.research_genesis()
        engine, cap, anchor = self.candidate(path)
        proposal, _ = engine.prepare_update(b'bypass', request_id=rid(1))
        before = tables(path)
        with self.assertRaisesRegex(types_.AnchorHold, 'no prepared anchor intent'):
            cap.commit(proposal)
        self.assertEqual(tables(path), before)

    def test_candidate_capability_refuses_a_proposal_other_than_the_prepared_one(self):
        path = self.research_genesis()
        engine, cap, anchor = self.candidate(path)
        prepared, _ = engine.prepare_update(b'prepared', request_id=rid(1))
        facts = engine.describe_proposal(prepared)
        anchor.prepare(types_.Intent(facts.store_id, 0, facts.base_digest, 1, facts.target_digest,
                                     facts.request_id, facts.proposal_hash))
        before = tables(path)
        for other_target, other_rid in ((b'other', rid(1)), (b'prepared', rid(2)), (b'other', rid(2))):
            with self.subTest(target=other_target, rid=other_rid[0]):
                other, _ = engine.prepare_update(other_target, request_id=other_rid)
                with self.assertRaisesRegex(types_.AnchorHold, 'not the prepared anchor intent'):
                    cap.commit(other)
                self.assertEqual(tables(path), before)
        self.assertEqual(cap.commit(prepared).version, 1)   # positive control

    def test_candidate_capability_refuses_an_intent_with_any_field_that_does_not_fit(self):
        # The anchor checks only store, base and format of an intent; digest, request id and
        # proposal hash are the writer's claims, so the capability compares every one of them.
        path = self.research_genesis()
        engine, cap, _ = self.candidate(path)
        proposal, _ = engine.prepare_update(b'target', request_id=rid(1))
        f = engine.describe_proposal(proposal)
        good = dict(store_id=f.store_id, base_version=0, base_digest=f.base_digest, version=1,
                    digest=f.target_digest, request_id=f.request_id, proposal_hash=f.proposal_hash)
        before = tables(path)
        for field, wrong in (('digest', 'ab' * 32), ('request_id', rid(2).hex()), ('proposal_hash', 'cd' * 32)):
            with self.subTest(field=field):
                anchor = lab.MemoryCASAnchor(c_coord.position_for_genesis(engine), reviewer_key=REVIEWER)
                anchor.prepare(types_.Intent(**dict(good, **{field: wrong})))
                _, fresh_cap = engine_mod.bind_writer(path, key=KEY, anchor=anchor)
                with self.assertRaisesRegex(types_.AnchorHold, 'not the prepared anchor intent'):
                    fresh_cap.commit(proposal)
                self.assertEqual(tables(path), before)   # refused before the write, not after
        anchor = lab.MemoryCASAnchor(c_coord.position_for_genesis(engine), reviewer_key=REVIEWER)
        anchor.prepare(types_.Intent(**good))
        _, fresh_cap = engine_mod.bind_writer(path, key=KEY, anchor=anchor)
        self.assertEqual(fresh_cap.commit(proposal).version, 1)   # positive control

    def test_abort_between_intent_check_and_write_is_honoured(self):
        # Review F2: the anchor is re-read inside the write transaction, so an ABORT that lands
        # after the capability's first check (legal: the DB still shows NOT_COMMITTED_HOLD)
        # stops the write instead of committing behind the anchor's back.
        path = self.research_genesis()
        engine, cap, anchor = self.candidate(path)
        coord = c_coord.CoordinatedStore(engine, cap, anchor)
        proposal, _ = engine.prepare_update(b'aborted meanwhile', request_id=rid(1))
        f = engine.describe_proposal(proposal)
        anchor.prepare(types_.Intent(f.store_id, 0, f.base_digest, 1, f.target_digest, f.request_id, f.proposal_hash))
        before = tables(path)

        def abort(point):
            if point == 'after_preflight':
                self.assertEqual(coord.diagnose().code, 'NOT_COMMITTED_HOLD')
                pending = anchor.status().pending
                coord.adjudicate('ABORT_NOT_COMMITTED',
                                 anchor.test_only_review_token(pending, 'ABORT_NOT_COMMITTED'))
        with self.assertRaisesRegex(types_.AnchorHold, 'anchor intent changed'):
            cap.commit(proposal, fault=abort)
        self.assertEqual(tables(path), before)
        self.assertEqual(coord.diagnose().code, 'MATCH')

    def test_a_concurrent_commit_of_the_same_intent_is_not_a_success(self):
        # Review F3: a second capability (another anchor holding the same intent) commits first;
        # the outer call then meets the replay path and must not report success.
        path = self.research_genesis()
        engine, cap, anchor = self.candidate(path)
        proposal, _ = engine.prepare_update(b'twice', request_id=rid(1))
        f = engine.describe_proposal(proposal)
        intent = types_.Intent(f.store_id, 0, f.base_digest, 1, f.target_digest, f.request_id, f.proposal_hash)
        anchor.prepare(intent)
        twin = lab.MemoryCASAnchor(c_coord.position_for_genesis(engine), reviewer_key=REVIEWER)
        twin.prepare(intent)
        _, twin_cap = engine_mod.bind_writer(path, key=KEY, anchor=twin)

        def race(point):
            if point == 'after_preflight':
                self.assertEqual(twin_cap.commit(proposal).version, 1)
        with self.assertRaisesRegex(types_.AnchorHold, 'differs from the prepared anchor intent'):
            cap.commit(proposal, fault=race)
        self.assertEqual(engine.read().version, 1)   # written once, by the twin

    def test_capability_checks_the_intent_base_against_the_anchor_position(self):
        # Review F6: do not rely on the anchor's own prepare() check of the base.
        path = self.research_genesis()
        engine, _, _ = self.candidate(path)
        proposal, _ = engine.prepare_update(b'x', request_id=rid(1))
        f = engine.describe_proposal(proposal)
        intent = types_.Intent(f.store_id, 0, f.base_digest, 1, f.target_digest, f.request_id, f.proposal_hash)

        class LaxAnchor:   # an anchor that accepted an intent not based on its committed position
            def status(self):
                return types_.AnchorStatus(types_.Position(f.store_id, 0, 'ee' * 32), intent)
        _, lax_cap = engine_mod.bind_writer(path, key=KEY, anchor=LaxAnchor())
        before = tables(path)
        with self.assertRaisesRegex(types_.AnchorHold, 'not based on the anchor position'):
            lax_cap.commit(proposal)
        self.assertEqual(tables(path), before)

    def test_adjudicate_passes_evidence_to_the_anchor(self):
        # Review F4: research CoordinatedStore.adjudicate forwards evidence (needed by the
        # attested anchors of v0.7.16-v0.7.22); the candidate must too.
        path = self.research_genesis()
        engine, cap, anchor = self.candidate(path)
        coord = c_coord.CoordinatedStore(engine, cap, anchor)
        proposal, _ = engine.prepare_update(b'with evidence', request_id=rid(1))
        coord.apply(proposal)
        seen = {}
        original = anchor.adjudicate

        def recording(intent, decision, token, **kw):
            seen.update(kw)
            return original(intent, decision, token)
        anchor.adjudicate = recording
        token = anchor.test_only_review_token(anchor.status().pending, 'FINALIZE_COMMIT')
        self.assertEqual(coord.adjudicate('FINALIZE_COMMIT', token, evidence={'obs': 1}).code, 'MATCH')
        self.assertEqual(seen, {'evidence': {'obs': 1}})

    def test_capability_is_bound_to_its_engine_and_anchor(self):
        path = self.research_genesis()
        engine, cap, anchor = self.candidate(path)
        other_anchor = lab.MemoryCASAnchor(c_coord.position_for_genesis(engine), reviewer_key=REVIEWER)
        _, foreign_cap = engine_mod.bind_writer(path, key=KEY, anchor=other_anchor)
        with self.assertRaises(types_.AnchorHold):
            c_coord.CoordinatedStore(engine, foreign_cap, anchor)
        with self.assertRaises(wire.WriterError):
            c_writer.AnchoredWriterCore(engine, foreign_cap, anchor)
        with self.assertRaises(types_.AnchorHold):
            c_coord.CoordinatedStore(engine, object(), anchor)
        c_writer.AnchoredWriterCore(engine, cap, anchor)   # positive control


class EngineSurface(Tmp):
    PUBLIC = {'describe_proposal', 'inspect_request', 'journal_mode', 'path', 'prepare_update',
              'read', 'read_verified', 'receipt', 'store_id', 'verify'}

    def test_public_surface_is_the_reviewed_read_only_set(self):
        engine, _, _ = self.candidate(self.research_genesis())
        self.assertEqual({n for n in dir(engine) if not n.startswith('_')}, self.PUBLIC)
        self.assertFalse(hasattr(engine, 'key'))
        for legacy in ('create', 'apply', 'checkpoint', 'backup_verified'):
            self.assertFalse(hasattr(engine_mod.StateEngine, legacy), legacy)

    def test_no_public_method_changes_the_database(self):
        path = self.research_genesis()
        engine, _, _ = self.candidate(path)
        proposal, _ = engine.prepare_update(b'never written', request_id=rid(7))
        calls = {
            'describe_proposal': lambda: engine.describe_proposal(proposal),
            'inspect_request': lambda: engine.inspect_request(rid(7)),
            'prepare_update': lambda: engine.prepare_update(b'x' * 5000, request_id=rid(8)),
            'read': engine.read, 'read_verified': engine.read_verified,
            'receipt': lambda: engine.receipt(rid(7)), 'verify': engine.verify,
            'store_id': lambda: engine.store_id,
        }
        self.assertEqual(set(calls) | {'journal_mode', 'path'}, EngineSurface.PUBLIC)
        before = (file_sha256(path), tables(path))
        for name, call in calls.items():
            with self.subTest(method=name):
                call()
                self.assertEqual((file_sha256(path), tables(path)), before)

    def test_provisioning_is_not_reachable_from_the_engine_module(self):
        self.assertFalse(hasattr(engine_mod, 'create_store'))
        self.assertFalse(hasattr(engine_mod, 'StateStore'))

    def test_engine_internals_are_used_only_inside_the_engine_module(self):
        # The write primitive and the key must not be reached around the capability. Python
        # cannot enforce this; the structure contract is checked over the candidate sources.
        import ast
        internal = {'_commit', '_key', '_engine', '_anchor', '_capability'}
        allowed = {'eq3_engine.py': {'_commit', '_key', '_engine', '_anchor'},
                   'eq3_coordinator.py': {'_capability'}}
        # Review F1: whoever mints a capability chooses its anchor; minting happens only in the
        # engine (definition) and in the composition root (the service).
        minting = {'CommitCapability', 'bind_writer'}
        mint_allowed = {'eq3_engine.py', 'eq3_writer_service.py'}
        for path in sorted(HERE.glob('eq3_*.py')):
            tree = ast.parse(path.read_text(encoding='utf-8'))
            used = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute) and n.attr in internal}
            calls = {(n.func.id if isinstance(n.func, ast.Name) else getattr(n.func, 'attr', None))
                     for n in ast.walk(tree) if isinstance(n, ast.Call)} & minting
            with self.subTest(module=path.name):
                self.assertLessEqual(used, allowed.get(path.name, set()))
                if path.name not in mint_allowed:
                    self.assertEqual(calls, set())


class Derivation(unittest.TestCase):
    """Copied research code stays pinned to its source (only the documented changes differ)."""

    def test_wal_gate_equals_the_research_function(self):
        import anchor_wire
        import eq3_wal_gate
        grid = [(a, b, c) for a in (3,) for b in range(40, 56) for c in range(0, 12)]
        for v in grid:
            self.assertIs(eq3_wal_gate.sqlite_wal_reset_safe(v), anchor_wire.sqlite_wal_reset_safe(v), v)
        self.assertIs(eq3_wal_gate.sqlite_wal_reset_safe(), anchor_wire.sqlite_wal_reset_safe())

    def test_runtime_gate_is_the_research_file_with_two_imports_changed(self):
        original = (RESEARCH / 'runtime_gate_v0711.py').read_text(encoding='utf-8')
        copy = (HERE / 'eq3_runtime_gate.py').read_text(encoding='utf-8')
        body = copy.split('The text below is the original module docstring.\n\n', 1)[1]
        body = body.replace('from eq3_wal_gate import sqlite_wal_reset_safe',
                            'from anchor_wire import sqlite_wal_reset_safe')
        body = body.replace('from eq3_runtime_evidence import RuntimeEvidenceError, runtime_inventory',
                            'from runtime_evidence_v0710 import RuntimeEvidenceError, runtime_inventory')
        self.assertEqual(body, original[len('"""'):])
        self.assertTrue(copy.startswith('"""ADR-003 candidate'))

    def test_runtime_evidence_differs_from_research_only_in_the_built_in_case(self):
        import difflib
        original = (RESEARCH / 'runtime_evidence_v0710.py').read_text(encoding='utf-8')
        copy = (HERE / 'eq3_runtime_evidence.py').read_text(encoding='utf-8')
        body = '"""' + copy.split('The text below is the original module docstring.\n\n', 1)[1]
        changed = [l for l in difflib.unified_diff(original.splitlines(), body.splitlines(), lineterm='', n=0)
                   if l[:1] in '+-' and not l.startswith(('+++', '---'))]
        self.assertEqual(len(changed), 11, changed)   # 3 lines out, 8 lines in (pinned)
        self.assertTrue(all('extension' in l or 'built' in l or 'statically' in l or 'return evidence' in l
                            for l in changed), changed)


class RuntimeEvidence(unittest.TestCase):
    """A built-in _sqlite3 (static SQLite, e.g. python-build-standalone) must HOLD, classified."""

    def test_research_inventory_raises_an_unclassified_error_on_a_built_in_sqlite3(self):
        import types
        from unittest import mock
        import runtime_evidence_v0710 as research_evidence
        with mock.patch.object(research_evidence, '_sqlite3', types.SimpleNamespace()):
            with self.assertRaises(AttributeError):        # negative first: not RuntimeEvidenceError
                research_evidence.runtime_inventory()

    def test_candidate_inventory_reports_built_in_and_the_gate_holds_classified(self):
        import types
        from unittest import mock
        import eq3_runtime_evidence as evidence
        import eq3_runtime_gate as gate
        with mock.patch.object(evidence, '_sqlite3', types.SimpleNamespace()):
            facts = evidence.runtime_inventory()
            self.assertEqual((facts['python_extension'], facts['mapped_file_identity_consistent']),
                             ('built-in', False))
            self.assertIn('statically', facts['loaded_library_error'])
            try:
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            except ImportError:
                self.skipTest('cryptography not installed')
            import time as _time
            now = int(_time.time())
            policy = json.dumps({'schema': gate.SCHEMA, 'purpose': gate.PURPOSE, 'deployment_id': 'lab',
                                 'sqlite_version': facts['sqlite_version'],
                                 'sqlite_source_id': facts['sqlite_source_id'],
                                 'loaded_library_sha256': '0' * 64,
                                 'python_abi': '%d.%d' % sys.version_info[:2], 'machine': 'x',
                                 'not_before': now - 10, 'expires_at': now + 3600}).encode()
            signer = Ed25519PrivateKey.generate()
            from cryptography.hazmat.primitives import serialization
            public = signer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            with self.assertRaisesRegex(evidence.RuntimeEvidenceError, 'does not match executing SQLite runtime'):
                gate.verify_signed_runtime_policy(policy, signer.sign(policy), public, deployment_id='lab')


class Differential(Tmp):
    """Same genesis file, same operations: research v0.7.15 and candidate must agree exactly."""

    def drive(self, core, coordinator, anchor, finalize_name='adjudicate'):
        out = []

        def step(op, r, body):
            try:
                out.append(core.dispatch(op, r, body))
            except Exception as exc:   # compare the failure class, not its module
                out.append(('raise', type(exc).__name__))

        def review(decision='FINALIZE_COMMIT'):
            pending = anchor.status().pending
            out.append(getattr(coordinator, finalize_name)(
                decision, anchor.test_only_review_token(pending, decision)).code)

        z = wire.ZERO_REQUEST
        step(wire.STATUS, z, b'')
        step(wire.SET, rid(1), b'alpha ' * 50)
        step(wire.SET, rid(2), b'beta')                 # pending -> HOLD
        step(wire.STATUS, z, b'')                       # pending -> HOLD
        review()
        step(wire.SET, rid(1), b'alpha ' * 50)          # replay
        step(wire.SET, rid(1), b'different')            # conflicting replay
        step(wire.STATUS, z, b'x')                      # noncanonical
        step(wire.SET, z, b'zero request id')
        step(wire.SET, rid(2), bytes(range(256)) * 40)
        review()
        step(wire.SET, rid(3), b'')
        review()
        step(wire.STATUS, z, b'')
        return out

    def test_answers_and_tables_equal_research_v0715(self):
        genesis = self.research_genesis('genesis.sqlite')
        a, b = self.dir / 'research.sqlite', self.dir / 'candidate.sqlite'
        shutil.copyfile(genesis, a); shutil.copyfile(genesis, b)
        store, r_anc = self.research(a)
        r_core = r_writer.AnchoredWriterCore(store, r_anc)
        engine, cap, c_anc = self.candidate(b)
        c_core = c_writer.AnchoredWriterCore(engine, cap, c_anc)
        r_out = self.drive(r_core, r_core._coordinator, r_anc)
        c_out = self.drive(c_core, c_core._coordinator, c_anc)
        self.assertEqual(c_out, r_out)
        self.assertIn(('raise', 'ReplayError'), r_out)
        self.assertEqual(r_out[-1]['version'], 3)
        self.assertEqual(tables(b), tables(a))
        self.assertEqual(r_anc.status().committed.__dict__, c_anc.status().committed.__dict__)


class Faults(Tmp):
    """Interruptions around the commit: both implementations reach the same HOLD and recovery."""

    def run_fault(self, point, decision, *, candidate):
        genesis = self.research_genesis('g-%s-%s.sqlite' % (point, candidate))
        if candidate:
            engine, cap, anchor = self.candidate(genesis)
            coord = c_coord.CoordinatedStore(engine, cap, anchor)
            proposal, _ = engine.prepare_update(b'faulted target', request_id=rid(9))
            hold = types_.AnchorHold
        else:
            store, anchor = self.research(genesis)
            coord = r_anchor.CoordinatedStore(store, anchor)
            proposal, _ = r_store.prepare_update(store, b'faulted target', request_id=rid(9))
            hold = r_anchor.AnchorHold

        def fault(name):
            if name == point:
                raise OSError('injected at ' + name)
        with self.assertRaises(hold):
            coord.apply(proposal, fault=fault)
        held = coord.diagnose().code
        pending = anchor.status().pending
        after = coord.adjudicate(decision, anchor.test_only_review_token(pending, decision)).code
        return held, after, tables(genesis)

    def test_fault_matrix_matches_research(self):
        for point, decision in (('after_anchor_prepare', 'ABORT_NOT_COMMITTED'),
                                ('after_sqlite_commit', 'FINALIZE_COMMIT')):
            with self.subTest(point=point):
                research = self.run_fault(point, decision, candidate=False)
                candidate = self.run_fault(point, decision, candidate=True)
                self.assertEqual(candidate[:2], research[:2])
                self.assertEqual(candidate[0], 'NOT_COMMITTED_HOLD' if decision.startswith('ABORT')
                                 else 'COMMITTED_PENDING_HOLD')
                self.assertEqual(candidate[1], 'MATCH')
                # store ids differ (two genesis files); the shape of the history must not
                self.assertEqual([len(candidate[2][t]) for t in TABLES], [len(research[2][t]) for t in TABLES])


    def test_same_target_committed_by_another_proposal_is_a_conflict_not_a_commit(self):
        # Mutant M25: the anchor PREPARED proposal A; a legacy writer (same key and UID, the
        # bypass ADR-003 item 3 must close) commits proposal B for the same request id and the
        # same target through another codec strategy. Digest and version match the intent, the
        # proposal hash does not: both implementations must say CONFLICT_HOLD and refuse FINALIZE.
        def run(candidate):
            path = self.research_genesis('conflict-%s.sqlite' % candidate)
            legacy = r_store.StateStore(path, key=KEY, journal_mode='DELETE')
            target = b'x' * 250 + b'y' * 60
            if candidate:
                engine, cap, anchor = self.candidate(path)
                coord = c_coord.CoordinatedStore(engine, cap, anchor)
                proposal, _ = engine.prepare_update(target, request_id=rid(5))
                hold, denied = types_.AnchorHold, types_.ReviewDenied
            else:
                anchor = r_anchor.MemoryCASAnchor(r_anchor.position_for_genesis(legacy), reviewer_key=REVIEWER)
                coord = r_anchor.CoordinatedStore(legacy, anchor)
                proposal, _ = r_store.prepare_update(legacy, target, request_id=rid(5))
                hold, denied = r_anchor.AnchorHold, r_anchor.ReviewDenied

            def stop(point):
                if point == 'after_anchor_prepare':
                    raise OSError('crash after prepare')
            with self.assertRaises(hold):
                coord.apply(proposal, fault=stop)
            other, _ = r_store.prepare_update(legacy, target, request_id=rid(5), strategy='fast')
            self.assertNotEqual(other, proposal)
            legacy.apply(other)                         # the bypass
            code = coord.diagnose().code
            pending = anchor.status().pending
            with self.assertRaises(denied):
                coord.adjudicate('FINALIZE_COMMIT', anchor.test_only_review_token(pending, 'FINALIZE_COMMIT'))
            return code
        self.assertEqual(run(False), 'CONFLICT_HOLD')
        self.assertEqual(run(True), 'CONFLICT_HOLD')


class Compatibility(Tmp):
    def test_research_reads_what_the_candidate_wrote_and_back(self):
        path = self.dir / 'prov.sqlite'
        provision.create_store(path, key=KEY, initial=GENESIS)
        engine, cap, anchor = self.candidate(path)
        core = c_writer.AnchoredWriterCore(engine, cap, anchor)
        self.assertEqual(core.dispatch(wire.SET, rid(4), b'written by the candidate')['error'],
                         'EXTERNAL_REVIEW_REQUIRED')
        pending = anchor.status().pending
        core._coordinator.adjudicate('FINALIZE_COMMIT', anchor.test_only_review_token(pending, 'FINALIZE_COMMIT'))
        research = r_store.StateStore(path, key=KEY, journal_mode='DELETE')
        self.assertEqual(research.verify(), engine.verify())
        self.assertEqual(research.read().value, b'written by the candidate')
        # research writes on top; the engine verifies the extended chain
        proposal, _ = r_store.prepare_update(research, b'written by research', request_id=rid(5))
        research.apply(proposal)
        self.assertEqual(engine.read().value, b'written by research')
        self.assertEqual(engine.verify(), research.verify())

    def test_engine_refuses_wal_and_legacy_stores(self):
        wal = self.dir / 'wal.sqlite'
        r_store.StateStore.create(wal, key=KEY, initial=GENESIS, journal_mode='WAL')
        with self.assertRaises(engine_mod.StoreError):
            engine_mod.StateEngine(wal, key=KEY)
        with self.assertRaises(engine_mod.AuthenticationError):
            engine_mod.StateEngine(self.research_genesis(), key=b'W' * 32)

    def test_tampered_history_is_refused(self):
        path = self.research_genesis()
        engine, cap, anchor = self.candidate(path)
        core = c_writer.AnchoredWriterCore(engine, cap, anchor)
        core.dispatch(wire.SET, rid(6), b'one')
        with closing(sqlite3.connect(str(path), isolation_level=None)) as db:
            db.execute("UPDATE receipts SET digest=? WHERE committed_version=1", (b'\0' * 32,))
        with self.assertRaises(engine_mod.IntegrityError):
            engine.verify()
        self.assertEqual(core.dispatch(wire.SET, rid(7), b'two')['assessment'], 'INVALID_DB_HOLD')


class Distribution(Tmp):
    """ADR-003 acceptance tests 1 and 2 on an allowlist build."""

    def stage(self, files, name):
        d = self.dir / name
        d.mkdir()
        for rel in files:
            shutil.copyfile(ROOT / rel, d / Path(rel).name)
        return d

    def allowlist(self):
        lines = (HERE / 'DISTRIBUTION.txt').read_text(encoding='utf-8').splitlines()
        return [l.strip() for l in lines if l.strip() and not l.startswith('#')]

    def tool(self, name, *argv):
        return subprocess.run([sys.executable, '-I', str(TOOLS / name), *argv],
                              capture_output=True, text=True, timeout=300)

    def test_allowlist_is_complete_and_excludes_lab_and_provisioning(self):
        files = self.allowlist()
        self.assertEqual(len(files), len(set(files)))
        names = {Path(f).name for f in files}
        self.assertNotIn('eq3_anchor_lab.py', names)
        self.assertNotIn('eq3_provision.py', names)
        self.assertFalse(names & {'state_store.py', 'anchor_protocol.py', 'anchor_wire.py',
                                  'writer_service_v0714.py', 'anchored_writer_v0715.py'})
        staged = self.stage(files, 'dist')
        r = self.tool('check_import_closure.py', '--research-dir', str(staged), '--entry', 'eq3_writer_service')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        closure = r.stdout.split('closure (', 1)[1].split('\n', 1)[0]
        self.assertEqual(int(closure.split(')')[0]), len(files))   # every listed file is needed

    def test_closure_over_the_full_tree_is_clean_without_baseline(self):
        full = [str(p.relative_to(ROOT)) for p in sorted(RESEARCH.glob('*.py'))] + \
               [str(p.relative_to(ROOT)) for p in sorted(HERE.glob('eq3_*.py'))]
        staged = self.stage(full, 'full')
        forbid = ('--forbid', '*_lab', '--forbid', 'eq3_provision')
        candidate = self.tool('check_import_closure.py', '--research-dir', str(staged),
                              '--entry', 'eq3_writer_service', *forbid)
        self.assertEqual(candidate.returncode, 0, candidate.stdout)
        self.assertIn('PASS: 0 violation(s)', candidate.stdout)
        research = self.tool('check_import_closure.py', '--research-dir', str(staged),
                             '--entry', 'anchored_writer_v0715', *forbid)
        self.assertEqual(research.returncode, 1)                 # negative control: v0.7.22 is red
        self.assertIn('import-cycle', research.stdout)
        # mutants: one legacy edge, one lab edge, one provisioning edge, one cycle
        for module, line in (('eq3_coordinator', 'import state_store\n'),
                             ('eq3_anchored_writer', 'import eq3_anchor_lab\n'),
                             ('eq3_writer_service', 'import eq3_provision\n'),
                             ('eq3_wire', 'import eq3_writer_service\n')):
            with self.subTest(mutant=module):
                target = staged / (module + '.py')
                original = target.read_text(encoding='utf-8')
                target.write_text(original + line, encoding='utf-8')
                try:
                    r = self.tool('check_import_closure.py', '--research-dir', str(staged),
                                  '--entry', 'eq3_writer_service', *forbid)
                    self.assertEqual(r.returncode, 1, r.stdout)
                finally:
                    target.write_text(original, encoding='utf-8')

    def test_runtime_witness_on_the_allowlist_build(self):
        staged = self.stage(self.allowlist(), 'dist')
        r = self.tool('runtime_import_witness.py', '--research-dir', str(staged),
                      '--entry', 'eq3_writer_service', '--deny', '--forbid', '*_lab', '--forbid', 'eq3_provision')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_legacy_lab_and_provisioning_are_not_importable_from_the_build(self):
        staged = self.stage(self.allowlist(), 'dist')
        probe = ('import sys, json\nsys.path.insert(0, sys.argv[1])\nimport eq3_writer_service\nres = {}\n'
                 'for name in sys.argv[2:]:\n'
                 '    try:\n        __import__(name)\n        res[name] = "imported"\n'
                 '    except ImportError:\n        res[name] = "ImportError"\n'
                 'print(json.dumps(res))\n')
        names = ['state_store', 'legacy_state_store', 'anchor_protocol', 'anchor_wire',
                 'writer_service_v0714', 'store_cli', 'eq3_anchor_lab', 'eq3_provision']
        r = subprocess.run([sys.executable, '-I', '-B', '-c', probe, str(staged), *names],
                           capture_output=True, text=True, timeout=60, cwd=str(staged.parent))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout), {n: 'ImportError' for n in names})


class ResearchAnchors(Tmp):
    """The candidate drives the persistent (v0.7.7+) and attested (v0.7.16+) research anchors."""

    def run(self, result=None):
        try:
            import cryptography  # noqa: F401
        except ImportError:
            self.skipTest('cryptography not installed')
        return super().run(result)

    def anchors(self, kind, position, tag):
        import anchor_wire
        seal = b'S' * 32
        if kind == 'persistent':
            return anchor_wire.PersistentCASAnchor.bootstrap(self.dir / ('a-%s.sqlite' % tag), position,
                                                             reviewer_key=REVIEWER, seal_key=seal), None
        import commit_evidence_v0716 as ce
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        if not hasattr(self, '_attester'):
            self._attester = Ed25519PrivateKey.generate()
        anchor = ce.EvidenceRequiredCASAnchor.bootstrap(
            self.dir / ('a-%s.sqlite' % tag), position, reviewer_key=REVIEWER, seal_key=seal,
            attester_public_key=self._attester.public_key(), deployment_id='equal3-lab-0716')
        return anchor, self._attester

    def drive(self, kind, impl):
        import anchor_protocol
        import commit_evidence_v0716 as ce
        genesis = self.dir / ('%s-%s.sqlite' % (kind, impl))
        shutil.copyfile(self.genesis, genesis)
        if impl == 'research':
            store = r_store.StateStore(genesis, key=KEY, journal_mode='DELETE')
            anchor, attester = self.anchors(kind, r_anchor.position_for_genesis(store), kind + '-' + impl)
            core = r_writer.AnchoredWriterCore(store, anchor)
            observed = store
        else:
            engine = engine_mod.StateEngine(genesis, key=KEY)
            anchor, attester = self.anchors(kind, c_coord.position_for_genesis(engine), kind + '-' + impl)
            engine, cap = engine_mod.bind_writer(genesis, key=KEY, anchor=anchor)
            core = c_writer.AnchoredWriterCore(engine, cap, anchor)
            # the observer reads with the research store: independent code path, read only
            observed = r_store.StateStore(genesis, key=KEY, journal_mode='DELETE')
        out = []
        for n, body in ((1, b'first'), (2, b'second' * 30)):
            out.append(core.dispatch(wire.SET, rid(n), body))
            pending = anchor.status().pending
            import hmac as _hmac
            token = _hmac.new(REVIEWER, anchor_protocol._review_message(pending, 'FINALIZE_COMMIT'),
                              hashlib.sha256).digest()
            if attester is not None:
                with self.assertRaises(anchor_protocol.ReviewDenied):   # evidence is mandatory
                    core._coordinator.adjudicate('FINALIZE_COMMIT', token)
                evidence = ce.issue_observation(store=observed, anchor=anchor, intent=pending,
                                                decision='FINALIZE_COMMIT', deployment_id='equal3-lab-0716',
                                                signing_key=attester)
                out.append(core._coordinator.adjudicate('FINALIZE_COMMIT', token, evidence=evidence).code)
            else:
                out.append(core._coordinator.adjudicate('FINALIZE_COMMIT', token).code)
        out.append(core.dispatch(wire.STATUS, wire.ZERO_REQUEST, b''))
        return out, tables(genesis)

    def test_persistent_and_attested_anchors_match_research(self):
        self.genesis = self.research_genesis('genesis.sqlite')
        for kind in ('persistent', 'attested'):
            with self.subTest(anchor=kind):
                research = self.drive(kind, 'research')
                candidate = self.drive(kind, 'candidate')
                self.assertEqual(candidate, research)
                self.assertEqual(candidate[0][-1]['version'], 2)


class RootBoundary(Tmp):
    """Port of test_writer_service_v0714.test_real_linux_uid_boundary_separate_client (root only)."""

    def test_real_separate_uid_client_against_the_candidate_service(self):
        if os.geteuid() != 0 or sys.platform != 'linux':
            self.skipTest('requires Linux root for the separate-UID test')
        import time as _time
        from unittest import mock
        writer, unauth = 65534, 65533
        self.dir.chmod(0o711)
        priv = self.dir / 'private'; priv.mkdir(); priv.chmod(0o700)
        db = priv / 'db.sqlite'
        r_store.StateStore.create(db, key=KEY, initial=b'original', journal_mode='DELETE')
        key = priv / 'secret'; key.write_bytes(KEY); key.chmod(0o600)
        for name, data in (('gate', b'gate'), ('sig', b'sign')):
            (self.dir / name).write_bytes(data)
        pub = self.dir / 'pub'; pub.write_bytes(b'\x22' * 32); pub.chmod(0o644)
        shared = self.dir / 'shared'; shared.mkdir(); os.chown(shared, 0, writer); shared.chmod(0o710)
        sock = shared / 's.sock'
        engine = engine_mod.StateEngine(db, key=KEY)
        anchor = lab.MemoryCASAnchor(c_coord.position_for_genesis(engine), reviewer_key=REVIEWER)
        status, stop = {'error': None}, threading.Event()

        def run_service():
            try:
                service.serve(sock, database_path=db, key_file=key, writer_uid=writer, socket_gid=writer,
                              policy_file=self.dir / 'gate', signature_file=self.dir / 'sig',
                              public_key_file=pub, deployment_id='integration',
                              _research_anchor=anchor, _research_stop_event=stop)
            except BaseException as exc:
                status['error'] = repr(exc)
        # explicitly synthetic runtime approval, as in the research test; not a release approval
        with mock.patch.object(service, 'verify_signed_runtime_policy',
                               return_value={'runtime_gate': 'SIGNED_POLICY_AND_RUNTIME_MATCH'}):
            thread = threading.Thread(target=run_service, daemon=True); thread.start()
            self.addCleanup(lambda: (stop.set(), thread.join(timeout=5)))
            for _ in range(500):
                if sock.exists() or status['error']:
                    break
                _time.sleep(0.01)
            self.assertIsNone(status['error'])
            program = ('import sys, json\nsys.path.insert(0, sys.argv[3])\n'
                       'from eq3_wire import client_request, SET, STATUS\n'
                       'op = SET if sys.argv[2] == "set" else STATUS\n'
                       'kw = dict(request_id=b"\\x31" * 16, target=b"new") if op == SET else {}\n'
                       'print(json.dumps(client_request(sys.argv[1], op=op, **kw)))\n')
            stage = self.dir / 'code'; stage.mkdir()
            for f in ('eq3_wire.py', 'eq3_engine.py', 'eq3_anchor_types.py'):
                shutil.copyfile(HERE / f, stage / f)
            shutil.copyfile(RESEARCH / 'equal3.py', stage / 'equal3.py')
            stage.chmod(0o755)
            for f in stage.iterdir():
                f.chmod(0o644)

            def run_as(uid, cmd):
                def drop():
                    os.setgroups([]); os.setgid(writer); os.setuid(uid)
                return subprocess.run([sys.executable, '-I', '-B', '-c', program, str(sock), cmd, str(stage)],
                                      preexec_fn=drop, capture_output=True, text=True, timeout=15)
            good = run_as(writer, 'set')
            self.assertEqual(good.returncode, 0, (good.stdout, good.stderr))
            self.assertEqual(json.loads(good.stdout)['error'], 'EXTERNAL_REVIEW_REQUIRED')
            again = run_as(writer, 'status')
            self.assertEqual(json.loads(again.stdout)['assessment'], 'COMMITTED_PENDING_HOLD')
            bad = run_as(unauth, 'status')
            self.assertNotEqual(bad.returncode, 0)
            blocked = subprocess.run([sys.executable, '-c', 'import sys; open(sys.argv[1], "rb")', str(key)],
                                     preexec_fn=lambda: (os.setgroups([]), os.setgid(writer), os.setuid(writer)),
                                     capture_output=True, text=True, timeout=15)
            self.assertNotEqual(blocked.returncode, 0)
            self.assertEqual(r_store.StateStore(db, key=KEY, journal_mode='DELETE').read().value, b'new')


class Service(Tmp):
    def test_serve_holds_without_an_anchor(self):
        with self.assertRaisesRegex(wire.WriterError, 'independent anchor .* missing; HOLD'):
            service.serve(self.dir / 's', database_path=self.dir / 'db', key_file=self.dir / 'k',
                          writer_uid=12345, socket_gid=12345, policy_file=self.dir / 'p',
                          signature_file=self.dir / 'sig', public_key_file=self.dir / 'pub',
                          deployment_id='lab')

    def exchange(self, core, frame, *, writer_uid):
        server_end, client_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

        class FakeServer:
            pass
        fake = FakeServer(); fake.core = core; fake.writer_uid = writer_uid
        t = threading.Thread(target=service.Handler, args=(server_end, None, fake))
        t.start()
        try:
            client_end.sendall(frame)
            t.join(10)
            self.assertFalse(t.is_alive())
            server_end.close()   # socketserver shuts the request down after handle()
            client_end.settimeout(5)
            try:
                head = client_end.recv(4)
            except ConnectionResetError:   # the unread request frame turns the close into a reset
                return None
            if not head:
                return None
            size = struct.unpack('>I', head)[0]
            return json.loads(wire.read_exact(client_end, size))
        finally:
            server_end.close(); client_end.close()

    def test_handler_reaches_the_anchored_core_and_refuses_other_uids(self):
        engine, cap, anchor = self.candidate(self.research_genesis())
        core = c_writer.AnchoredWriterCore(engine, cap, anchor)
        body = b'over the wire'
        frame = wire.HEADER.pack(wire.MAGIC, wire.SET, rid(11), len(body)) + body
        reply = self.exchange(core, frame, writer_uid=os.geteuid())
        self.assertEqual((reply['ok'], reply['error']), (False, 'EXTERNAL_REVIEW_REQUIRED'))
        status = wire.HEADER.pack(wire.MAGIC, wire.STATUS, wire.ZERO_REQUEST, 0)
        self.assertEqual(self.exchange(core, status, writer_uid=os.geteuid())['assessment'],
                         'COMMITTED_PENDING_HOLD')
        self.assertIsNone(self.exchange(core, status, writer_uid=os.geteuid() + 1))  # other UID: no reply


if __name__ == '__main__':
    unittest.main()
