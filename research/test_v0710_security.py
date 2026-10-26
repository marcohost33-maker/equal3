"""Negative-first tests for v0.7.9 unverified replay and runtime provenance."""
import hashlib
import os
from pathlib import Path
import secrets
import sqlite3
import tempfile
import unittest
from contextlib import closing
from unittest import mock

import state_store as store
import runtime_evidence_v0710 as evidence

KEY=b'R'*32

class AuthenticatedReplayTests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup)
        self.db=store.StateStore.create(Path(self.t.name)/'store.sqlite', key=KEY,initial=b'genesis')
        self.proposal,self.rid=store.prepare_update(self.db,b'updated')
        self.authentic=self.db.apply(self.proposal)

    def mutate(self, sql, params=()):
        with closing(sqlite3.connect(self.db.path)) as conn:
            conn.execute(sql,params);conn.commit()

    def test_untouched_healthy_idempotent_replay(self):
        a=self.db.receipt(self.rid)
        b=self.db.apply(self.proposal)
        self.assertEqual(a.digest,self.authentic.digest)
        self.assertEqual(b.digest,self.authentic.digest)
        self.assertTrue(a.already_committed and b.already_committed)

    def test_modified_receipt_digest_fails_for_receipt_and_duplicate_apply(self):
        self.mutate('UPDATE receipts SET digest=? WHERE request_id=?',(b'F'*32,self.rid))
        for method in (lambda:self.db.receipt(self.rid),lambda:self.db.apply(self.proposal)):
            with self.assertRaises(store.IntegrityError):method()

    def test_modified_receipt_hash_fails_for_receipt_and_duplicate_apply(self):
        self.mutate('UPDATE receipts SET proposal_hash=? WHERE request_id=?',(b'D'*32,self.rid))
        for method in (lambda:self.db.receipt(self.rid),lambda:self.db.apply(self.proposal)):
            with self.assertRaises(store.IntegrityError):method()

    def test_deleted_chain_authentication_fails(self):
        self.mutate('DELETE FROM receipt_auth WHERE committed_version=1')
        with self.assertRaises(store.IntegrityError):self.db.apply(self.proposal)
        with self.assertRaises(store.IntegrityError):self.db.receipt(self.rid)

    def test_reused_request_id_with_different_packet_is_replay_error(self):
        other=store.make_proposal(self.db.store_id,1,self.rid,
                 self.proposal[store.PROPOSAL_HDR.size:-store.MAC_SIZE],key=KEY)
        with self.assertRaises(store.ReplayError):self.db.apply(other)

    def test_missing_request_receipt_reports_none_only_if_history_valid(self):
        self.assertIsNone(self.db.receipt(secrets.token_bytes(16)))
        self.mutate('UPDATE receipts SET base_version=-1 WHERE request_id=?',(self.rid,))
        with self.assertRaises(store.IntegrityError):self.db.receipt(secrets.token_bytes(16))

    def test_legacy_schema_downgrade_cannot_certify_replay(self):
        # A schema-v1 history is structurally auditable, never HMAC-authenticated.
        self.mutate('UPDATE meta SET schema_version=1 WHERE id=1')
        self.assertEqual(self.db.verify()['receipt_auth'], 'LEGACY_UNSEALED')
        with self.assertRaises(store.IntegrityError):self.db.receipt(self.rid)
        with self.assertRaises(store.IntegrityError):self.db.apply(self.proposal)

    def test_older_historic_receipt_authentication(self):
        later,_=store.prepare_update(self.db,b'later')
        self.db.apply(later)
        self.mutate('UPDATE receipts SET digest=? WHERE request_id=?',(b'B'*32,self.rid))
        with self.assertRaises(store.IntegrityError):self.db.apply(self.proposal)

class RuntimeEvidenceTests(unittest.TestCase):
    def test_maps_parsing_realistic(self):
        inp='7fab-8fab r-xp 0000 00:1b 321 /usr/lib/libsqlite3.so.0.8.6\n'
        self.assertEqual(evidence.mapped_sqlite_identity(inp),('/usr/lib/libsqlite3.so.0.8.6',321,(0,27)))

    def test_deleted_mapping_refused(self):
        inp='7fab-8fab r-xp 0000 00:1b 321 /usr/lib/libsqlite3.so.0 (deleted)\n'
        with self.assertRaises(evidence.RuntimeEvidenceError):evidence.mapped_sqlite_identity(inp)

    def test_conflicting_mapping_refused(self):
        inp=('7fab-8fab r-xp 0000 00:1b 321 /usr/lib/libsqlite3.so.0\n'
             '7fab-8fab r-xp 0000 00:1b 322 /usr/local/libsqlite3.so.1\n')
        with self.assertRaises(evidence.RuntimeEvidenceError):evidence.mapped_sqlite_identity(inp)

    def test_unattested_library_no_runtime_release(self):
        self.assertEqual(evidence.runtime_inventory()['release_verdict'],'NO_GO')
        with self.assertRaises(evidence.RuntimeEvidenceError):evidence.require_approved_sqlite({})

    def test_wrong_library_pin_rejected(self):
        inv=evidence.runtime_inventory()
        with self.assertRaises(evidence.RuntimeEvidenceError):
            evidence.require_approved_sqlite({'source_id':inv['sqlite_source_id'],
                 'loaded_library_sha256':'0'*64})

if __name__=='__main__':unittest.main()
