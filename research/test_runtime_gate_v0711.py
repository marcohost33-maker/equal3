"""Negative-first, signed-policy tests. Entirely synthetic policy keys/data."""
from __future__ import annotations
import json
import hashlib
import platform
import sqlite3
import sys
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from runtime_evidence_v0710 import RuntimeEvidenceError
import runtime_gate_v0711 as gate

NOW = 1793000000
class SignedRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.private = Ed25519PrivateKey.generate()
        self.public = self.private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw)
        self.facts = {'sqlite_version':'3.54.1',
                      'sqlite_source_id':'2026-10-16 14:45:20 '+'a'*64,
                      'loaded_sqlite_shared_object_sha256':'b'*64,
                      'mapped_file_identity_consistent':True}
        self.record = {'schema':gate.SCHEMA,'purpose':gate.PURPOSE,
            'deployment_id':'test-svc-A','sqlite_version':'3.54.1',
            'sqlite_source_id':self.facts['sqlite_source_id'],
            'loaded_library_sha256':self.facts['loaded_sqlite_shared_object_sha256'],
            'python_abi':f'{sys.version_info.major}.{sys.version_info.minor}',
            'machine':platform.machine(),'not_before':NOW-60,'expires_at':NOW+3600}
    def signed(self, override=None, raw=None):
        if raw is None:
            d={**self.record,**(override or {})}
            raw=json.dumps(d,sort_keys=True,separators=(',',':')).encode()
        return raw,self.private.sign(raw)
    def evaluate(self, raw, signature, **kwargs):
        with patch.object(gate,'runtime_inventory',return_value=self.facts),\
             patch.object(gate,'sqlite_wal_reset_safe',return_value=True):
            return gate.verify_signed_runtime_policy(raw,signature,self.public,
                deployment_id=kwargs.get('deployment_id','test-svc-A'),now=kwargs.get('now',NOW))
    def test_valid_signed_mock_runtime_does_not_promote_release(self):
        b,s=self.signed()
        output=self.evaluate(b,s)
        self.assertEqual(output['runtime_gate'],'SIGNED_POLICY_AND_RUNTIME_MATCH')
        self.assertEqual(output['release_verdict'],'NO_GO_OTHER_P0_GATES')
        self.assertEqual(output['policy_sha256'],hashlib.sha256(b).hexdigest())
    def test_rejects_byte_tamper(self):
        b,s=self.signed()
        with self.assertRaises(RuntimeEvidenceError):self.evaluate(b+b' ',s)
    def test_rejects_wrong_signer(self):
        b,_=self.signed()
        other=Ed25519PrivateKey.generate().sign(b)
        with self.assertRaises(RuntimeEvidenceError):self.evaluate(b,other)
    def test_rejects_duplicate_json_keys_even_when_signed(self):
        b,s=self.signed(raw=b'{"schema":"a","schema":"b"}')
        with self.assertRaises(RuntimeEvidenceError):self.evaluate(b,s)
    def test_rejects_cross_deployment_approval(self):
        b,s=self.signed()
        with self.assertRaises(RuntimeEvidenceError):self.evaluate(b,s,deployment_id='test-svc-B')
    def test_rejects_expired_or_not_yet_valid(self):
        for props in ({'expires_at':NOW},{'not_before':NOW+1},
                      {'expires_at':NOW+40*86400}):
            b,s=self.signed(props)
            with self.subTest(props=props),self.assertRaises(RuntimeEvidenceError):self.evaluate(b,s)
    def test_rejects_fake_library_digest(self):
        b,s=self.signed({'loaded_library_sha256':'c'*64})
        with self.assertRaises(RuntimeEvidenceError):self.evaluate(b,s)
    def test_rejects_old_or_withdrawn_runtime(self):
        b,s=self.signed()
        with patch.object(gate,'runtime_inventory',return_value=self.facts),\
             patch.object(gate,'sqlite_wal_reset_safe',return_value=False):
            with self.assertRaises(RuntimeEvidenceError):
                gate.verify_signed_runtime_policy(b,s,self.public,deployment_id='test-svc-A',now=NOW)
    def test_rejects_unstable_mapped_file(self):
        b,s=self.signed()
        self.facts['mapped_file_identity_consistent']=False
        with self.assertRaises(RuntimeEvidenceError):self.evaluate(b,s)
    def test_rejects_extra_or_missing_fields(self):
        for change in ({'unsafe_skip':True},):
            b,s=self.signed(change)
            with self.assertRaises(RuntimeEvidenceError):self.evaluate(b,s)
        d=dict(self.record);d.pop('machine')
        b=json.dumps(d).encode();s=self.private.sign(b)
        with self.assertRaises(RuntimeEvidenceError):self.evaluate(b,s)
    def test_rejects_bad_key_lengths_and_oversized_policy(self):
        b,s=self.signed()
        for public in (b'xx',b'',b'0'*64):
            with self.assertRaises(RuntimeEvidenceError):
                gate.verify_signed_runtime_policy(b,s,public,deployment_id='test-svc-A')
        with self.assertRaises(RuntimeEvidenceError):
            gate.verify_signed_runtime_policy(b*500,s,self.public,deployment_id='test-svc-A')
    def test_current_host_must_hold_even_if_doc_claims_patched(self):
        b,s=self.signed()
        # No mock: current actual 3.46.1 Linux host is non-approved.
        with self.assertRaises(RuntimeEvidenceError):
            gate.verify_signed_runtime_policy(b,s,self.public,deployment_id='test-svc-A',now=NOW)

if __name__ == '__main__':unittest.main()

class DeprecatedUnsignedApprovalTests(unittest.TestCase):
    def test_caller_generated_matching_unsigned_dictionary_never_approves(self):
        from runtime_evidence_v0710 import require_approved_sqlite
        with self.assertRaisesRegex(RuntimeEvidenceError,'unsigned runtime approval deprecated'):
            require_approved_sqlite({'source_id':'a','loaded_library_sha256':'b'})
