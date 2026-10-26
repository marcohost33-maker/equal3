#!/usr/bin/env python3
"""Verify that this repository's imported files are byte-identical to their sources.

What it checks (fail-closed, exit 1 on any deviation):
  1. evidence/manifests/MANIFEST_V0722.sha256 has the pinned SHA-256 below
     (the manifest shipped inside the v0.7.22 research bundle).
  2. Every row of evidence/manifests/PATH_MAPPING.tsv is well formed, points to a
     regular file inside the repository, and that file has the recorded SHA-256.
  3. Every manifest entry is mapped exactly once, with the manifest's own hash.
     Bundle rows that are not in the manifest are rejected (only the manifest
     file itself is allowed, because a manifest cannot list itself).
  4. Expected counts (bundle files, manifest entries) match, so an empty or
     truncated manifest/mapping cannot pass silently.
  5. The imported directories (research/, reports/, evidence/) contain no
     unmapped files, except the explicitly allowed repository notes below and
     __pycache__ directories (bytecode is never part of the import).

What it does NOT prove: authenticity. The manifest is an unsigned SHA-256 list
produced by the same research process (finding NR-08 in the audits). This tool
detects drift and accidental edits relative to that list; it cannot detect a
coordinated rewrite of files, mapping, manifest and this script.

Usage: python tools/verify_provenance.py [--root DIR]
Stdlib only, Python >= 3.9.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path, PurePosixPath

MAPPING_REL = 'evidence/manifests/PATH_MAPPING.tsv'
MANIFEST_REL = 'evidence/manifests/MANIFEST_V0722.sha256'
MANIFEST_SHA256 = 'fa6256361d7a9d45b52e1f4eae6880631e7851a6fae6422247575aea0f8ff5f8'
BUNDLE_PREFIX = 'Equal3_v0722_Research/'
BUNDLE_SOURCE = 'bundle:EQUAL3_v0722_REQUEST_LINEAGE_REAUDIT_2026-10-25.zip'
HEADER = ['source', 'original_path', 'repo_path', 'sha256']
EXPECTED_BUNDLE_FILES = 382
EXPECTED_MANIFEST_ENTRIES = 381
IMPORTED_DIRS = ('research', 'reports', 'evidence')
ALLOWED_UNMAPPED = frozenset({MAPPING_REL, 'evidence/README.md', 'reports/README.md'})
HEX64 = re.compile(r'^[0-9a-f]{64}$')
MANIFEST_LINE = re.compile(r'^([0-9a-f]{64}) [ *](.+)$')


class ProvenanceError(Exception):
    pass


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def _safe_rel(rel: str, what: str) -> PurePosixPath:
    if not rel or '\\' in rel or rel.startswith('/') or re.match(r'^[A-Za-z]:', rel):
        raise ProvenanceError('%s is not a relative POSIX path: %r' % (what, rel))
    p = PurePosixPath(rel)
    if any(part in ('', '.', '..') for part in p.parts):
        raise ProvenanceError('%s contains a forbidden segment: %r' % (what, rel))
    return p


def parse_manifest(text: str) -> dict:
    entries = {}
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        m = MANIFEST_LINE.match(line)
        if not m:
            raise ProvenanceError('manifest line %d malformed' % n)
        digest, rel = m.group(1), m.group(2)
        _safe_rel(rel, 'manifest line %d path' % n)
        if rel in entries:
            raise ProvenanceError('manifest lists %r twice' % rel)
        entries[rel] = digest
    return entries


def parse_mapping(text: str) -> list:
    lines = text.splitlines()
    if not lines or lines[0].split('\t') != HEADER:
        raise ProvenanceError('mapping header must be %r' % '\t'.join(HEADER))
    rows = []
    for n, line in enumerate(lines[1:], 2):
        fields = line.split('\t')
        if len(fields) != 4 or not all(fields):
            raise ProvenanceError('mapping line %d must have 4 non-empty fields' % n)
        source, original, repo_path, digest = fields
        if not HEX64.match(digest):
            raise ProvenanceError('mapping line %d: bad sha256' % n)
        _safe_rel(original, 'mapping line %d original_path' % n)
        _safe_rel(repo_path, 'mapping line %d repo_path' % n)
        rows.append((source, original, repo_path, digest))
    return rows


def verify(root: Path, expected_bundle: int = EXPECTED_BUNDLE_FILES,
           expected_manifest: int = EXPECTED_MANIFEST_ENTRIES,
           manifest_sha256: str = MANIFEST_SHA256) -> dict:
    root = Path(root).resolve()
    manifest_path = root / MANIFEST_REL
    mapping_path = root / MAPPING_REL
    for p in (manifest_path, mapping_path):
        if not p.is_file():
            raise ProvenanceError('missing %s' % p.relative_to(root).as_posix())
    if _sha256(manifest_path) != manifest_sha256:
        raise ProvenanceError('manifest SHA-256 differs from the pinned value')
    manifest = parse_manifest(manifest_path.read_text(encoding='utf-8'))
    if len(manifest) != expected_manifest:
        raise ProvenanceError('manifest has %d entries, expected %d' % (len(manifest), expected_manifest))
    rows = parse_mapping(mapping_path.read_text(encoding='utf-8'))
    seen_targets, seen_bundle = set(), {}
    for source, original, repo_path, digest in rows:
        if repo_path in seen_targets:
            raise ProvenanceError('repo_path mapped twice: %s' % repo_path)
        seen_targets.add(repo_path)
        target = root / repo_path
        try:
            target.resolve().relative_to(root)
        except ValueError:
            raise ProvenanceError('repo_path escapes the repository: %s' % repo_path)
        if target.is_symlink() or not target.is_file():
            raise ProvenanceError('not a regular file: %s' % repo_path)
        if _sha256(target) != digest:
            raise ProvenanceError('content differs from recorded SHA-256: %s' % repo_path)
        if source == BUNDLE_SOURCE:
            if not original.startswith(BUNDLE_PREFIX):
                raise ProvenanceError('bundle row without bundle prefix: %s' % original)
            inner = original[len(BUNDLE_PREFIX):]
            if inner in seen_bundle:
                raise ProvenanceError('bundle file mapped twice: %s' % inner)
            seen_bundle[inner] = digest
    if len(seen_bundle) != expected_bundle:
        raise ProvenanceError('mapping has %d bundle rows, expected %d' % (len(seen_bundle), expected_bundle))
    manifest_name = PurePosixPath(MANIFEST_REL).name
    for inner, digest in seen_bundle.items():
        if inner == manifest_name:
            if digest != manifest_sha256:
                raise ProvenanceError('manifest row hash differs from pinned value')
            continue
        if inner not in manifest:
            raise ProvenanceError('bundle row not listed in manifest: %s' % inner)
        if manifest[inner] != digest:
            raise ProvenanceError('mapping hash differs from manifest: %s' % inner)
    missing = sorted(set(manifest) - set(seen_bundle))
    if missing:
        raise ProvenanceError('manifest entries without mapping: %s' % ', '.join(missing[:5]))
    unmapped = []
    for top in IMPORTED_DIRS:
        for p in sorted((root / top).rglob('*')) if (root / top).is_dir() else []:
            rel = p.relative_to(root).as_posix()
            if '__pycache__' in p.relative_to(root).parts or p.is_dir():
                continue
            if rel not in seen_targets and rel not in ALLOWED_UNMAPPED:
                unmapped.append(rel)
    if unmapped:
        raise ProvenanceError('unmapped files in imported directories: %s' % ', '.join(unmapped[:5]))
    return {'rows': len(rows), 'bundle_rows': len(seen_bundle), 'manifest_entries': len(manifest),
            'other_rows': len(rows) - len(seen_bundle)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--root', default=str(Path(__file__).resolve().parent.parent))
    args = ap.parse_args(argv)
    try:
        result = verify(Path(args.root))
    except (ProvenanceError, OSError, UnicodeDecodeError) as exc:
        print('PROVENANCE FAIL: %s' % exc)
        return 1
    print('PROVENANCE OK: %(rows)d mapped files verified (%(bundle_rows)d bundle files against '
          '%(manifest_entries)d manifest entries + manifest itself; %(other_rows)d supplementary files)' % result)
    return 0


if __name__ == '__main__':
    sys.exit(main())
