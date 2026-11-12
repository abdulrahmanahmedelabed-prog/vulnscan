"""PHP ``include`` / ``require``: splice the code of statically known included files in at the include.

PHP runs an included file in the scope of the include statement: variables flow both ways. A front controller
that includes ``source/{$level}.php`` reads the ``$file`` that file assigned (DVWA's File Inclusion lab), and a
view included by a controller prints the ``$name`` the controller assigned. Each file is lowered on its own, so
without this neither flow exists.

For every ``include``/``require``(``_once``) statement whose path the analysis can work out (string literals,
``define()`` constants, ``__DIR__`` / ``dirname(__FILE__)``, and local variables that are only ever given string
literals, e.g. a ``switch`` over the security level), the top-level code of each possible target (not its
functions or classes, which PHP declares globally and the engine already resolves) is copied in right after the
include. Several possible targets become a nondeterministic ``if``/``elif`` chain: exactly one of them runs.

The copied nodes carry the include statement's line and remember their file (``MARK``); ``INLINED`` records
``(includer, line) -> targets``. A source in spliced code gets an ``include <file>`` step, so the engine can tell a
flow that crosses the include (reported) from one that lies wholly inside the included file (already reported in
that file itself).
"""

from __future__ import annotations

import ast
import copy
import itertools
import posixpath

INCLUDES = frozenset({"include", "include_once", "require", "require_once"})
CHOICE = "__kashif_include_choice__"     # an unknown condition: which of several possible files is included
MAX_CANDIDATES = 8
MAX_DEPTH = 3
MAX_SPLICED_NODES = 40_000               # per including file: large libraries are not copied over and over
# per project: spliced code at most doubles what the engine analyses (a big top-level header included by hundreds of
# pages would otherwise multiply the analysis time by the number of pages)
MIN_PROJECT_SPLICE = 300_000
_DIR = "\0dir\0"
_ANY = "\0any\0"
MARK = "kashif_included_from"            # attribute set on every spliced node: the file it was copied from

# (including file, line of the include statement) -> the files whose code was spliced in there
INLINED: dict = {}


def _scope_stmts(body):
    """Statement lists of a scope (not of nested functions / classes)."""
    yield body
    for st in body:
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        for field in ("body", "orelse", "finalbody"):
            b = getattr(st, field, None)
            if isinstance(b, list) and b and isinstance(b[0], ast.stmt):
                yield from _scope_stmts(b)
        for h in getattr(st, "handlers", ()) or ():
            yield from _scope_stmts(h.body)
        for c in getattr(st, "cases", ()) or ():
            yield from _scope_stmts(c.body)


def _scope_nodes(body):
    for stmts in _scope_stmts(body):
        for st in stmts:
            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            yield from ast.walk(st)


def _string_locals(body) -> dict:
    """Variables of a scope that are only ever given string literals: name -> the set of those strings."""
    out: dict = {}
    literal_targets: set = set()
    nodes = list(_scope_nodes(body))
    for n in nodes:
        if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str):
            for t in n.targets:
                if isinstance(t, ast.Name):
                    out.setdefault(t.id, set()).add(n.value.value)
                    literal_targets.add(id(t))
    bad = {n.id for n in nodes if isinstance(n, ast.Name) and not isinstance(n.ctx, ast.Load) and id(n) not in literal_targets}
    return {k: v for k, v in out.items() if k not in bad}


def _defines(trees) -> dict:
    """`define('NAME', 'literal')` across the project; a name defined with different values is left out."""
    seen: dict = {}
    for tree in trees:
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "define" and len(n.args) >= 2 \
                    and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str):
                v = n.args[1].value if isinstance(n.args[1], ast.Constant) and isinstance(n.args[1].value, str) else None
                seen.setdefault(n.args[0].value, set()).add(v)
    return {k: next(iter(v)) for k, v in seen.items() if len(v) == 1 and None not in v}


def _eval(node, consts, locs, here) -> set | None:
    """The strings a path expression can be, or None when some part is unknown."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value}
    if isinstance(node, ast.Name):
        if node.id == "__DIR__":
            return {_DIR + here}
        if node.id in locs:
            return set(locs[node.id])
        if node.id in consts:
            return {consts[node.id]}
        if node.id.isupper() and not node.id.startswith("$"):
            return {_ANY}                        # an install-root constant set elsewhere: match by the rest
        return None
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "dirname" and node.args \
            and isinstance(node.args[0], ast.Name) and node.args[0].id == "__FILE__":
        return {_DIR + here}
    parts = None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        parts = [node.left, node.right]
    elif isinstance(node, ast.JoinedStr):
        parts = [v.value if isinstance(v, ast.FormattedValue) else v for v in node.values]
    if parts is None:
        return None
    sets = []
    for p in parts:
        s = _eval(p, consts, locs, here)
        if s is None:
            return None
        sets.append(s)
    out = set()
    for combo in itertools.product(*sets):
        out.add("".join(combo))
        if len(out) > MAX_CANDIDATES:
            return None
    return out


def _resolve(path: str, here: str, known: set) -> str | None:
    """The project file an include path names, seen from directory `here`."""
    if path.startswith(_DIR):
        p = posixpath.normpath(path[len(_DIR):].replace("\\", "/"))
        return p if p in known else None
    p = path.replace("\\", "/")
    anchored = not p.startswith(_ANY)
    p = p if anchored else p[len(_ANY):]
    if not p or p.endswith("/") or "\0" in p:
        return None
    if anchored and not p.startswith("/"):
        cand = posixpath.normpath(posixpath.join(here, p)) if here else posixpath.normpath(p)
        if cand in known:
            return cand
    tail = posixpath.normpath(p.lstrip("/"))
    while tail.startswith(("../", "./")):
        tail = tail.split("/", 1)[1]
    if not tail or tail.startswith(".."):
        return None
    hits = [k for k in known if k == tail or k.endswith("/" + tail)]
    if len(hits) == 1:
        return hits[0]
    near = [k for k in hits if here and k.startswith(here + "/")]
    return near[0] if len(near) == 1 else None


def _top_code(tree) -> list:
    """The statements an include of this file runs: its top-level code without function / class declarations;
    a top-level `return` (the include's value) only ends the included file, so it becomes `pass`."""
    out = [st for st in tree.body if not isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                                                             ast.Import, ast.ImportFrom))]
    return out


class _Unreturn(ast.NodeTransformer):
    def visit_FunctionDef(self, node):
        return node

    visit_AsyncFunctionDef = visit_ClassDef = visit_Lambda = visit_FunctionDef

    def visit_Return(self, node):
        return ast.copy_location(ast.Pass(), node)


def _relocate(stmts, line, target):
    """Spliced code sits at the include's line; each node remembers the file it came from (MARK)."""
    for st in stmts:
        for n in ast.walk(st):
            if hasattr(n, "lineno"):
                n.lineno = line
                n.end_lineno = line
            if getattr(n, MARK, None) is None:
                setattr(n, MARK, target)


def _include_target(st):
    if isinstance(st, ast.Expr) and isinstance(st.value, ast.Call) and isinstance(st.value.func, ast.Name) \
            and st.value.func.id in INCLUDES and len(st.value.args) == 1:
        return st.value.args[0]
    return None


def inline_includes(files: dict) -> None:
    """`files`: rel path -> lowered module of every PHP file in the project. Splices the code of each statically
    resolvable include target into the including file (in place) and fills INLINED."""
    INLINED.clear()
    if not files:
        return
    known = {r.replace("\\", "/"): r for r in files}
    project_consts = _defines(files.values())
    file_consts = {r: _defines([t]) for r, t in files.items()}      # a file's own define() wins
    originals = {r: _top_code(t) for r, t in files.items()}
    sizes = {r: sum(1 for st in code for _ in ast.walk(st)) for r, code in originals.items()}
    known_set = set(known)
    if not any(_include_target(st) is not None for t in files.values() for st in ast.walk(t) if isinstance(st, ast.stmt)):
        return

    def spliced(rel, body_owner, depth, visiting, budget):
        """Rewrite the include statements in the statement lists of one scope (module or function body)."""
        here = posixpath.dirname(rel.replace("\\", "/"))
        locs = _string_locals(body_owner)
        consts = {**project_consts, **file_consts.get(rel, {})}
        for stmts in list(_scope_stmts(body_owner)):
            i = 0
            while i < len(stmts):
                st = stmts[i]
                arg = _include_target(st)
                i += 1
                if arg is None:
                    continue
                paths = _eval(arg, consts, locs, here)
                if not paths:
                    continue
                targets = []
                for p in sorted(paths):
                    t = _resolve(p, here, known_set)
                    if t is not None and known[t] not in visiting and known[t] not in targets:
                        targets.append(known[t])
                if not targets:
                    continue
                bodies = []
                for t in targets:
                    if sizes[t] > budget[0] or sizes[t] > total[0]:
                        bodies = []                  # over budget: checked before paying for the copy
                        break
                    code = copy.deepcopy(originals[t])
                    holder = ast.Module(body=code, type_ignores=[])
                    _Unreturn().visit(holder)
                    code = holder.body
                    if depth + 1 < MAX_DEPTH:
                        spliced(t, code, depth + 1, visiting | {t}, budget)
                    size = sum(1 for s in code for _ in ast.walk(s))
                    if size > budget[0] or size > total[0]:
                        bodies = []
                        break
                    budget[0] -= size
                    total[0] -= size
                    # with several possible files the analysis cannot tell which one a value came from: name them all
                    _relocate(code, getattr(st, "lineno", 0), t if len(targets) == 1 else " | ".join(targets))
                    bodies.append(code)
                bodies = [b for b in bodies if b]
                if not bodies:
                    continue
                line = getattr(st, "lineno", 0)
                if len(bodies) == 1:
                    new = bodies[0]
                else:
                    new = bodies[-1]
                    for b in reversed(bodies[:-1]):
                        new = [ast.If(test=ast.Name(id=CHOICE, ctx=ast.Load()), body=b, orelse=new)]
                _relocate(new, line, None)
                INLINED.setdefault((rel, line), set()).update(targets)
                stmts[i:i] = new
                i += len(new)

    total = [max(MIN_PROJECT_SPLICE, sum(1 for t in files.values() for _ in ast.walk(t)))]
    for rel, tree in files.items():
        budget = [MAX_SPLICED_NODES]
        spliced(rel, tree.body, 0, {rel}, budget)
        for n in ast.walk(tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                spliced(rel, n.body, 0, {rel}, budget)
