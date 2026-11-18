#!/usr/bin/env python3
"""Static import-closure check for the writer entry point (ADR-003, roadmap P0-2).

Computes, from the source text only (AST, nothing is imported or executed), every
first-party module that the entry modules can reach, and reports as violations:

  legacy-module        a module in the closure whose name matches a forbidden pattern
                       (legacy_state_store, store_cli, guarded_store, run_*, bench*, test_*)
  legacy-write-api     a module in the closure that defines a public mutator of the legacy
                       direct-write API (StateStore.create / apply / checkpoint / backup_verified)
  import-cycle         a group of closure modules that import each other (ADR-003 item 4);
                       a module that imports itself counts too
  dynamic-import       __import__ / importlib.import_module / importlib.__import__ with a
                       target that is not a string literal, or any use of these names other
                       than a direct call, or a file/source module loader (importlib.util
                       spec_from_file_location, exec_module, runpy, ...): the closure cannot be
                       computed, so the check fails closed. exec/eval of source text is NOT
                       detected
  unparsable           a closure module that is not valid Python source

Imports inside functions, classes, `try` blocks and `if TYPE_CHECKING` blocks all count:
the check is about what can be loaded, not about what one particular run loads.

Exit status
  default               0 only when there is no violation
  --expect-baseline F   0 only when the violation set equals the one recorded in F. This is
                        how a tree that is known to be red is pinned: a new legacy edge fails
                        the check, and so does an improvement that was not recorded (the
                        baseline must then be regenerated and reviewed).

What a pass does NOT show: Python cannot stop code in the same process from importing a
module by another route (sys.path, importlib machinery, C extensions, exec). The real
boundary stays the operating system (ADR-003 item 3). The release decision stays NO-GO.

Usage: python tools/check_import_closure.py [--research-dir DIR] [--entry MODULE ...]
                                            [--expect-baseline FILE] [--json OUT]
Stdlib only.
"""
from __future__ import annotations

import argparse
import ast
import fnmatch
import json
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Set, Tuple

RESEARCH = Path(__file__).resolve().parent.parent / 'research'
DEFAULT_ENTRIES = ('anchored_writer_v0715',)
FORBIDDEN_MODULES = ('legacy_state_store', 'store_cli', 'guarded_store', 'run_*', 'bench*', 'test_*')
LEGACY_WRITE_API = {'StateStore': ('create', 'apply', 'checkpoint', 'backup_verified')}
DYNAMIC_IMPORT_NAMES = {'__import__', 'import_module'}
# loading a module from a file path or from source text has no statically known target
LOADER_NAMES = {'spec_from_file_location', 'module_from_spec', 'exec_module', 'load_module',
                'SourceFileLoader', 'run_path', 'run_module'}
SCHEMA = 'equal3.import-closure/1'

Violation = Tuple[str, str, str]  # (kind, subject, detail)


class ClosureError(Exception):
    """The check itself could not run (bad arguments, missing entry, unreadable baseline)."""


def first_party_modules(research_dir: Path) -> Dict[str, Path]:
    return {p.stem: p for p in sorted(research_dir.glob('*.py'))}


def _literal(node: ast.AST):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _is_dynamic_import_callee(func: ast.AST) -> bool:
    if isinstance(func, ast.Name):
        return func.id in DYNAMIC_IMPORT_NAMES
    if isinstance(func, ast.Attribute):
        return func.attr in DYNAMIC_IMPORT_NAMES
    return False


def scan_module(name: str, path: Path) -> Tuple[Set[str], List[Violation]]:
    """Return (imported top-level module names, violations found in this module's source)."""
    violations: List[Violation] = []
    try:
        tree = ast.parse(path.read_bytes(), filename=str(path))
    except (SyntaxError, ValueError, OSError) as exc:
        return set(), [('unparsable', name, type(exc).__name__)]
    imports: Set[str] = set()
    callees: Set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split('.')[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:  # the research tree is flat; a relative import has no defined target
                violations.append(('dynamic-import', name, 'relative import at line %d' % node.lineno))
            elif node.module:
                imports.add(node.module.split('.')[0])
        elif isinstance(node, ast.Call) and _is_dynamic_import_callee(node.func):
            callees.add(id(node.func))
            target = _literal(node.args[0]) if node.args else None
            if target is None:
                violations.append(('dynamic-import', name, 'non-literal target at line %d' % node.lineno))
            else:
                imports.add(target.split('.')[0])
        elif isinstance(node, ast.ClassDef) and node.name in LEGACY_WRITE_API:
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                        and item.name in LEGACY_WRITE_API[node.name]:
                    violations.append(('legacy-write-api', name, '%s.%s' % (node.name, item.name)))
    # a dynamic-import name that is referenced without being called directly (aliased, passed on,
    # stored) can be called later with any target
    for node in ast.walk(tree):
        if id(node) in callees:
            continue
        if (isinstance(node, ast.Name) and node.id in DYNAMIC_IMPORT_NAMES) or \
                (isinstance(node, ast.Attribute) and node.attr in DYNAMIC_IMPORT_NAMES):
            violations.append(('dynamic-import', name, 'indirect use at line %d' % node.lineno))
        elif isinstance(node, ast.alias) and node.name.split('.')[-1] in DYNAMIC_IMPORT_NAMES \
                and node.asname and node.asname not in DYNAMIC_IMPORT_NAMES:
            violations.append(('dynamic-import', name, 'renamed import at line %d' % node.lineno))
        elif (isinstance(node, ast.Name) and node.id in LOADER_NAMES) or \
                (isinstance(node, ast.Attribute) and node.attr in LOADER_NAMES) or \
                (isinstance(node, ast.alias) and node.name.split('.')[-1] in LOADER_NAMES):
            violations.append(('dynamic-import', name, 'module loader %s at line %d' % (
                getattr(node, 'id', None) or getattr(node, 'attr', None) or node.name, node.lineno)))
    return imports, violations


def strongly_connected(graph: Dict[str, Set[str]]) -> List[List[str]]:
    """Tarjan, iterative. Returns the components that are cycles, each sorted, list sorted."""
    index: Dict[str, int] = {}
    low: Dict[str, int] = {}
    on_stack: Set[str] = set()
    stack: List[str] = []
    cycles: List[List[str]] = []
    counter = 0
    for root in sorted(graph):
        if root in index:
            continue
        work = [(root, iter(sorted(graph[root])))]
        index[root] = low[root] = counter
        counter += 1
        stack.append(root)
        on_stack.add(root)
        while work:
            node, successors = work[-1]
            for nxt in successors:
                if nxt not in index:
                    index[nxt] = low[nxt] = counter
                    counter += 1
                    stack.append(nxt)
                    on_stack.add(nxt)
                    work.append((nxt, iter(sorted(graph[nxt]))))
                    break
                if nxt in on_stack:
                    low[node] = min(low[node], index[nxt])
            else:
                work.pop()
                if work:
                    parent = work[-1][0]
                    low[parent] = min(low[parent], low[node])
                if low[node] == index[node]:
                    component = []
                    while True:
                        member = stack.pop()
                        on_stack.discard(member)
                        component.append(member)
                        if member == node:
                            break
                    if len(component) > 1 or node in graph[node]:
                        cycles.append(sorted(component))
    return sorted(cycles)


def analyse(research_dir: Path, entries: Sequence[str],
            forbidden: Iterable[str] = FORBIDDEN_MODULES) -> dict:
    modules = first_party_modules(research_dir)
    if not entries:
        raise ClosureError('no entry module given')
    for entry in entries:
        if entry not in modules:
            raise ClosureError('entry module %r not found in %s' % (entry, research_dir))
    graph: Dict[str, Set[str]] = {}
    violations: Set[Violation] = set()
    todo = list(entries)
    while todo:
        name = todo.pop()
        if name in graph:
            continue
        imports, found = scan_module(name, modules[name])
        violations.update(found)
        graph[name] = {m for m in imports if m in modules}
        todo.extend(sorted(graph[name] - set(graph)))
    forbidden = tuple(forbidden)
    for name in graph:
        if name in entries:
            continue  # an entry is checked through what it reaches, not through its own name
        for pattern in forbidden:
            if fnmatch.fnmatchcase(name, pattern):
                violations.add(('legacy-module', name, 'matches %s' % pattern))
    for cycle in strongly_connected(graph):
        violations.add(('import-cycle', ' '.join(cycle), '%d modules' % len(cycle)))
    return {
        'schema': SCHEMA,
        'entries': sorted(entries),
        'forbidden_modules': list(forbidden),
        'legacy_write_api': {k: list(v) for k, v in LEGACY_WRITE_API.items()},
        'closure': sorted(graph),
        'edges': {name: sorted(graph[name]) for name in sorted(graph)},
        'violations': [list(v) for v in sorted(violations)],
    }


def load_baseline(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        raise ClosureError('baseline %s unreadable: %s' % (path, exc)) from exc
    if not isinstance(data, dict) or data.get('schema') != SCHEMA \
            or not isinstance(data.get('violations'), list) or not isinstance(data.get('entries'), list) \
            or not all(isinstance(v, list) and len(v) == 3 and all(isinstance(x, str) for x in v)
                       for v in data['violations']):
        raise ClosureError('baseline %s has an unexpected format' % path)
    return data


def compare_with_baseline(report: dict, baseline: dict) -> List[str]:
    """Return human-readable differences; empty means the report equals the baseline."""
    diffs = []
    if report['entries'] != sorted(baseline['entries']):
        diffs.append('entries differ: now %s, baseline %s' % (report['entries'], sorted(baseline['entries'])))
    now = {tuple(v) for v in report['violations']}
    then = {tuple(v) for v in baseline['violations']}
    diffs += ['new violation: %s | %s | %s' % v for v in sorted(now - then)]
    diffs += ['no longer present (regenerate and review the baseline): %s | %s | %s' % v
              for v in sorted(then - now)]
    return diffs


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--research-dir', type=Path, default=RESEARCH)
    parser.add_argument('--entry', action='append', default=None,
                        help='entry module name (repeatable); default: %s' % ', '.join(DEFAULT_ENTRIES))
    parser.add_argument('--expect-baseline', type=Path)
    parser.add_argument('--json', type=Path)
    args = parser.parse_args(argv)
    try:
        report = analyse(args.research_dir, args.entry or DEFAULT_ENTRIES)
        baseline = load_baseline(args.expect_baseline) if args.expect_baseline else None
    except ClosureError as exc:
        print('ERROR: %s' % exc, file=sys.stderr)
        return 2
    print('entries: %s' % ', '.join(report['entries']))
    print('closure (%d): %s' % (len(report['closure']), ', '.join(report['closure'])))
    for kind, subject, detail in report['violations']:
        print('VIOLATION %-16s %s (%s)' % (kind, subject, detail))
    if baseline is None:
        ok = not report['violations']
        report['result'] = 'PASS' if ok else 'FAIL'
        print('%s: %d violation(s)' % (report['result'], len(report['violations'])))
    else:
        diffs = compare_with_baseline(report, baseline)
        ok = not diffs
        report['result'] = 'BASELINE_MATCH' if ok else 'BASELINE_MISMATCH'
        report['baseline_differences'] = diffs
        for diff in diffs:
            print('DIFF %s' % diff)
        print('%s: %d violation(s), %d difference(s) to the baseline; the tree is %s'
              % (report['result'], len(report['violations']), len(diffs),
                 'still red (known)' if report['violations'] else 'clean'))
    if args.json:
        args.json.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
