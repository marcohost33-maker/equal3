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
  dynamic-import       a module computes an import target at run time or reaches an import
                       function indirectly; the closure cannot be computed, so the check fails
                       closed. Reported for
                       - __import__ / importlib.import_module / importlib.__import__ called with
                         anything but one string literal (absolute, outside the import
                         machinery), and any other use of these names (renamed, stored, passed);
                       - any mention of the import machinery other than such a direct call: the
                         modules importlib, builtins, imp, pkgutil, zipimport, runpy and the name
                         __builtins__, as a name, as an attribute of any object, or as an imported
                         or renamed name; sys other than as sys.<attribute>, sys renamed, and
                         sys.modules / meta_path / path_hooks / path_importer_cache / path or a
                         private sys attribute;
                       - module loaders by name (spec_from_file_location, exec_module, run_path,
                         find_spec, reload, site.addsitedir, ...), also as an attribute of any
                         object;
                       - lookups that turn names into strings or enumerate live objects:
                         globals(), locals(), vars(), __dict__, __globals__, f_globals /
                         f_locals / f_builtins, _getframe, __subclasses__, __getattribute__,
                         __getattr__, inspect.getmembers, gc.get_objects / get_referents /
                         get_referrers;
                       - getattr / operator.attrgetter / methodcaller whose attribute name is not
                         a string literal (sole exception: inside a function, a loop variable
                         whose only binding is a `for` over a tuple or list of string literals)
                         or names one of the identifiers above; a match-class keyword pattern
                         naming one of them;
                       - a relative import.
                       NOT detected, so a pass does not exclude them: exec / eval / compile of
                       source text; ctypes and other C extensions; library code that imports by a
                       string internally (pickle and copyreg, logging.config, unittest.mock.patch,
                       pydoc.locate, string.Formatter.get_field, ...); a third-party or stdlib
                       module that re-exports an import function under an unrelated name; a
                       sys.path changed from outside the module (PYTHONPATH, .pth files)
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
# Fail-closed rule (E3-V1): the import machinery may appear only inside a direct call with one
# string literal. Every other mention fails, instead of listing the ways it can be reached.
MACHINERY_MODULES = {'importlib', 'builtins', 'imp', 'pkgutil', 'zipimport', 'runpy'}
# sys is used everywhere, so it is allowed as sys.<attr>, except for the import state
SYS_IMPORT_STATE = {'modules', 'meta_path', 'path_hooks', 'path_importer_cache', 'path'}
# loading a module from a file path or from source text has no statically known target
LOADER_NAMES = {'spec_from_file_location', 'module_from_spec', 'exec_module', 'load_module',
                'SourceFileLoader', 'run_path', 'run_module', 'find_spec', 'find_loader',
                'find_module', 'get_loader', 'load_source', 'load_compiled', 'load_dynamic',
                'load_package', 'zipimporter', 'resolve_name', 'reload', 'addsitedir'}
# lookups that hand out a namespace by string, or enumerate live objects, so that an import
# function can be found by a computed name without its name appearing in the source
INTROSPECTION_NAMES = {'globals', 'locals', 'vars', '__dict__', '__globals__', '__builtins__',
                       '__loader__', '__spec__', 'f_globals', 'f_locals', 'f_builtins', '_getframe',
                       '__subclasses__', '__getattribute__', '__getattr__', 'getattr_static',
                       'getmembers', 'getmembers_static', 'get_objects', 'get_referents',
                       'get_referrers', 'meta_path', 'path_hooks', 'path_importer_cache'}
# every identifier that reaches the machinery when it appears as a name, an attribute of any
# object, an imported name or a looked-up string
MACHINERY_IDENTIFIERS = (DYNAMIC_IMPORT_NAMES | MACHINERY_MODULES | {'sys', '__builtins__'}
                         | LOADER_NAMES | INTROSPECTION_NAMES)
# attribute lookup by a string; allowed only when every possible string is known
GETATTR_NAMES = {'getattr', 'attrgetter', 'methodcaller'}
_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef, ast.Module,
           ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
SCHEMA = 'equal3.import-closure/1'

Violation = Tuple[str, str, str]  # (kind, subject, detail)


class ClosureError(Exception):
    """The check itself could not run (bad arguments, missing entry, unreadable baseline)."""


def first_party_modules(research_dir: Path) -> Dict[str, Path]:
    return {p.stem: p for p in sorted(research_dir.glob('*.py'))}


def _literal(node: ast.AST):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _callee_name(func: ast.AST):
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _bindings(scope: ast.AST, ident: str) -> int:
    """Count the places in `scope` (nested scopes included) that bind or rebind `ident`."""
    count = 0
    for node in ast.walk(scope):
        if isinstance(node, ast.Name):
            count += node.id == ident and not isinstance(node.ctx, ast.Load)
        elif isinstance(node, ast.arg):
            count += node.arg == ident
        elif isinstance(node, ast.alias):
            count += (node.asname or node.name.split('.')[0]) == ident
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            count += ident in node.names
        elif isinstance(node, ast.MatchMapping):
            count += node.rest == ident
        elif isinstance(getattr(node, 'name', None), str):  # def, class, except-as, match-as, type params
            count += node.name == ident
    return count


def _loop_literals(name: ast.Name, parent: Dict[int, ast.AST], tree: ast.Module):
    """The strings a loop variable can hold, or None when they are not statically known.

    Known only when `name` sits in the body of a `for` over a tuple/list of string literals that
    binds it, inside a function (a module or class variable can be rebound from outside while
    the loop runs), and nothing else in that function (or any `global`) rebinds it.
    """
    node: ast.AST = name
    while True:
        up = parent.get(id(node))
        if up is None or isinstance(up, _SCOPES):
            return None
        if isinstance(up, (ast.For, ast.AsyncFor)) and isinstance(up.target, ast.Name) \
                and up.target.id == name.id and any(node is stmt for stmt in up.body):
            loop = up
            break
        node = up
    if not isinstance(loop.iter, (ast.Tuple, ast.List)) or not loop.iter.elts:
        return None
    values = [_literal(elt) for elt in loop.iter.elts]
    if any(v is None for v in values):
        return None
    scope = loop
    while not isinstance(scope, _SCOPES):
        scope = parent[id(scope)]
    if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)) or _bindings(scope, name.id) != 1:
        return None
    if any(isinstance(n, ast.Global) and name.id in n.names for n in ast.walk(tree)):
        return None
    return set(values)


def _attribute_lookup_problem(call: ast.Call, kind: str, parent: Dict[int, ast.AST],
                              tree: ast.Module):
    """Why a getattr/attrgetter/methodcaller call may reach the machinery, or None."""
    if kind == 'getattr':
        head, names = call.args[:2], call.args[1:2]
    elif kind == 'methodcaller':
        head, names = call.args[:1], call.args[:1]
    else:
        head, names = list(call.args), list(call.args)
    # a starred argument can stand for the name; methodcaller's keywords go to the method
    if any(isinstance(arg, ast.Starred) for arg in head) or (call.keywords and kind != 'methodcaller'):
        return 'unpacked or keyword arguments to %s' % kind
    for arg in names:
        value = _literal(arg)
        if value is not None:
            strings = {value}
        elif isinstance(arg, ast.Name):
            strings = _loop_literals(arg, parent, tree)
        else:
            strings = None
        if strings is None:
            return 'computed attribute name in %s' % kind
        for string in strings:
            hit = sorted(set(string.split('.')) & (MACHINERY_IDENTIFIERS | GETATTR_NAMES))
            if hit:
                return 'attribute %s looked up by %s' % (hit[0], kind)
    return None


def scan_module(name: str, path: Path) -> Tuple[Set[str], List[Violation]]:
    """Return (imported top-level module names, violations found in this module's source)."""
    violations: List[Violation] = []
    try:
        tree = ast.parse(path.read_bytes(), filename=str(path))
    except (SyntaxError, ValueError, OSError) as exc:
        return set(), [('unparsable', name, type(exc).__name__)]

    def flag(detail: str, node: ast.AST) -> None:
        violations.append(('dynamic-import', name, '%s at line %d' % (detail, node.lineno)))

    parent: Dict[int, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parent[id(child)] = node
    imports: Set[str] = set()
    allowed: Set[int] = set()  # nodes that belong to a checked direct call
    guarded = MACHINERY_MODULES | {'sys'}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split('.')[0]
                imports.add(top)
                if alias.asname and alias.asname != top and \
                        (top in guarded or alias.asname in MACHINERY_IDENTIFIERS | GETATTR_NAMES):
                    flag('renamed import of %s' % alias.name, alias)
        elif isinstance(node, ast.ImportFrom):
            if node.level:  # the research tree is flat; a relative import has no defined target
                flag('relative import', node)
                continue
            if not node.module:
                continue
            top = node.module.split('.')[0]
            imports.add(top)
            for alias in node.names:
                bound = alias.asname or alias.name
                if top in MACHINERY_MODULES:
                    ok = alias.name in DYNAMIC_IMPORT_NAMES and bound == alias.name
                elif top == 'sys':
                    ok = alias.name != '*' and alias.name not in SYS_IMPORT_STATE \
                        and not alias.name.startswith('_') and bound not in MACHINERY_IDENTIFIERS
                else:
                    ok = alias.name not in MACHINERY_IDENTIFIERS and bound not in MACHINERY_IDENTIFIERS \
                        and (bound == alias.name or not ({bound, alias.name} & GETATTR_NAMES))
                if not ok:
                    flag('%s imported from %s%s' % (alias.name, node.module,
                                                    ' as %s' % alias.asname if alias.asname else ''), alias)
        elif isinstance(node, ast.Call) and _callee_name(node.func) in DYNAMIC_IMPORT_NAMES:
            allowed.add(id(node.func))
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) \
                    and node.func.value.id in MACHINERY_MODULES:
                allowed.add(id(node.func.value))  # importlib.import_module / builtins.__import__
            target = _literal(node.args[0]) if node.args else None
            if target is None:
                flag('non-literal target', node)
            elif len(node.args) != 1 or node.keywords:
                flag('import call with further arguments', node)
            elif not target or target.startswith('.'):
                flag('relative import target', node)
            elif target.split('.')[0] in guarded:
                flag('import machinery %s loaded by a call' % target, node)
            else:
                imports.add(target.split('.')[0])
        elif isinstance(node, ast.Call) and _callee_name(node.func) in GETATTR_NAMES:
            allowed.add(id(node.func))
            problem = _attribute_lookup_problem(node, _callee_name(node.func), parent, tree)
            if problem:
                flag(problem, node)
        elif isinstance(node, ast.MatchClass):
            for attr in node.kwd_attrs:
                if attr in MACHINERY_IDENTIFIERS:
                    flag('match pattern on attribute %s' % attr, node)
        elif isinstance(node, ast.ClassDef) and node.name in LEGACY_WRITE_API:
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                        and item.name in LEGACY_WRITE_API[node.name]:
                    violations.append(('legacy-write-api', name, '%s.%s' % (node.name, item.name)))
    # every other mention of the machinery: the object can then be called, stored, passed on or
    # searched by a computed name, so the target is unknown
    for node in ast.walk(tree):
        if id(node) in allowed:
            continue
        if isinstance(node, ast.Name):
            ident = node.id
            if ident == 'sys':
                up = parent.get(id(node))
                if not (isinstance(up, ast.Attribute) and up.value is node
                        and up.attr not in SYS_IMPORT_STATE and not up.attr.startswith('_')):
                    flag('sys%s' % ('.' + up.attr if isinstance(up, ast.Attribute) else ' used as a value'), node)
            elif ident in DYNAMIC_IMPORT_NAMES or ident in GETATTR_NAMES:
                flag('indirect use of %s' % ident, node)
            elif ident in LOADER_NAMES:
                flag('module loader %s' % ident, node)
            elif ident in MACHINERY_IDENTIFIERS:
                flag('import machinery %s' % ident, node)
        elif isinstance(node, ast.Attribute):
            attr = node.attr
            if attr in DYNAMIC_IMPORT_NAMES or attr in GETATTR_NAMES:
                flag('indirect use of %s' % attr, node)
            elif attr in LOADER_NAMES:
                flag('module loader %s' % attr, node)
            elif attr in MACHINERY_IDENTIFIERS:
                flag('import machinery reached as attribute .%s' % attr, node)
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
