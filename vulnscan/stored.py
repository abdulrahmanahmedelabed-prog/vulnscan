"""Stored (second-order) data flow for every language.  (vulnscan: ignore-file)

Works on the lowered AST shared by all frontends. Database writes and reads are made explicit so the taint
engine can carry user data *through a table*:

* a write of expression ``e`` into ``TABLE.COLUMN`` adds ``stored_db_write__TABLE__COLUMN(e)`` after the
  statement (an internal sink: the engine learns which columns receive user data);
* a read of ``TABLE.COLUMN`` becomes ``stored_db.TABLE.COLUMN or <original expression>``; in the second pass
  ``stored_db.TABLE.COLUMN`` is a source for exactly the columns users wrote.

Recognised writes / reads:

* raw SQL with bound parameters (``?``, ``%s``, ``%(name)s``, ``$1``, ``:name``, ``@name``):
  ``cur.execute(sql, params)`` / ``db.query(sql, [..])`` / ``db.Exec(sql, a, b)`` / prepared statements
  (``conn.prepareStatement(sql)`` + ``ps.setString(1, x)``, PDO ``prepare`` + ``execute([..])`` /
  ``bindParam``, mysqli ``bind_param``, ADO.NET ``SqlCommand`` + ``Parameters.AddWithValue``, chained
  ``db.prepare(sql).run(a)``); ``SELECT`` results (call results, cursors, result sets) read the selected columns;
* ORMs: model classes (Django/SQLAlchemy/Peewee/SQLModel ``Model``, ActiveRecord, Mongoose ``model()``,
  Sequelize ``define``/``Model``, TypeORM/JPA ``@Entity``, Prisma ``prisma.<model>``):
  ``M.objects.create(f=x)``, ``M.create({f: x})``, ``M(f=x)``, ``….update(f=x)``, ``obj.f = x``,
  ``obj.setF(x)`` write; ``obj.f`` / ``obj.getF()`` on a fetched instance or loop variable read.
"""

from __future__ import annotations

import ast
import copy
import re

WRITE_SQL = re.compile(r"^\s*(insert|update|merge|replace|upsert)\b", re.I)
READ_SQL = re.compile(r"^\s*(select|with)\b", re.I)
_PH = re.compile(r"%\((\w+)\)s|%s|\?|\$(\d+)|(?<![:\w]):([A-Za-z_]\w*)|@([A-Za-z_]\w*)")
EXEC_METHODS = {"execute", "executemany", "exec", "run", "query", "all", "get", "each", "executeupdate", "executequery",
                "executenonquery", "executescalar", "executereader", "execsql", "queryrow", "queryrowcontext", "execcontext",
                "querycontext", "fetch", "fetchall", "fetchone", "raw", "prepare", "unsafe", "none", "one", "any", "many",
                "oneornone", "result", "select", "first"}
MODEL_BASES = {"Model", "models.Model", "db.Model", "ApplicationRecord", "ActiveRecord.Base", "Document", "mongoengine.Document",
               "SQLModel", "DeclarativeBase", "peewee.Model", "ormar.Model", "BaseEntity", "Sequelize.Model", "Base"}
ENTITY_DECOS = {"Entity", "Table", "Document", "entity", "Model", "model"}
MODEL_FACTORIES = ("mongoose.model", "model", "sequelize.define", "define", "connection.model", "db.model")
ORM_WRITE = {"create", "insert", "update", "update_or_create", "get_or_create", "insert_many", "insertMany", "insertOne", "build",
             "findByIdAndUpdate", "findOneAndUpdate", "updateOne", "updateMany", "upsert", "create_many", "createMany", "save",
             "bulk_create", "new", "replaceOne", "findOneAndReplace", "update_attributes", "update_attribute", "update_columns"}
ORM_READ_HINT = {"objects", "query", "get", "filter", "all", "first", "last", "find", "findOne", "findById", "findAll", "findByPk",
                 "findUnique", "findFirst", "findMany", "where", "select", "one", "one_or_none", "scalar", "scalars", "exclude",
                 "order_by", "limit", "find_by", "take", "pluck", "fetch", "lean", "exec", "populate", "execute", "getById",
                 "findOneBy", "findBy", "getOne", "getReferenceById", "orElseThrow", "orElse", "get_object_or_404"}


FETCH_METHODS = {"fetchone", "fetchall", "fetchmany", "fetchval", "fetchrow", "first", "one", "scalar", "scalars", "all",
                 "next", "getString", "getInt", "getObject", "getLong", "GetString", "GetValue", "GetInt32", "Read", "read",
                 "row", "rows", "Scan", "fetch", "fetch_assoc", "fetch_array", "fetchAll", "fetchColumn", "fetchObject",
                 "fetch_row", "fetch_object", "get_result", "toArray", "results"}
NON_COLUMN_METHODS = {"save", "destroy", "delete", "reload", "valid", "valid?", "errors", "to_json", "as_json", "to_h", "to_s",
                      "attributes", "id", "persisted?", "new_record?", "update", "touch", "lock", "toJSON", "toObject",
                      "populate", "remove", "deleteOne", "exec", "lean", "then", "catch", "next", "close", "hasNext"}


def _const_str(n):
    return n.value if isinstance(n, ast.Constant) and isinstance(n.value, str) else None


def _root_name(n):
    while isinstance(n, (ast.Attribute, ast.Call, ast.Subscript, ast.Await)):
        n = n.func if isinstance(n, ast.Call) else n.value
    return n.id if isinstance(n, ast.Name) else None


def _chain(n) -> list[str]:
    """Attribute / call names along an expression chain, outermost last: Note.objects.filter(..).first() -> [Note, objects, filter, first]."""
    out = []
    while True:
        if isinstance(n, ast.Await):
            n = n.value
        elif isinstance(n, ast.Call):
            n = n.func
        elif isinstance(n, ast.Attribute):
            out.append(n.attr)
            n = n.value
        elif isinstance(n, ast.Subscript):
            n = n.value
        elif isinstance(n, ast.Name):
            out.append(n.id)
            break
        else:
            break
    return list(reversed(out))


def _dotted(n) -> str:
    if isinstance(n, ast.Name):
        return n.id
    if isinstance(n, ast.Attribute):
        b = _dotted(n.value)
        return f"{b}.{n.attr}" if b else n.attr
    if isinstance(n, ast.Call):
        return _dotted(n.func)
    return ""


# --------------------------------------------------------------------------------------------- SQL parsing
def _normalize(sql: str) -> tuple[str, int]:
    """Placeholders -> PL/SQL binds :__p<i> (positional) / :__k_<name> (named)."""
    count = [0]

    def sub(m):
        if m.group(1):
            return f" :__k_{m.group(1).lower()} "
        if m.group(2):
            return f" :__p{int(m.group(2)) - 1} "
        if m.group(3):
            return f" :__k_{m.group(3).lower()} "
        if m.group(4):
            return f" :__k_{m.group(4).lower()} "
        count[0] += 1
        return f" :__p{count[0] - 1} "
    out = _PH.sub(sub, re.sub(r"'(?:''|[^'])*'", "''", sql))
    return out, count[0]


def parse_write(sql: str) -> list[tuple[str, str, tuple]]:
    """INSERT / UPDATE text -> [(TABLE, COLUMN, ('pos', i) | ('key', name))] for columns bound to a placeholder."""
    from .plsql_frontend import tokenize
    norm, _ = _normalize(sql)
    toks = tokenize(norm)
    vals = [t.val for t in toks]
    out = []
    try:
        if vals and vals[0] in ("insert", "replace", "upsert") and "into" in vals[:3]:
            j = vals.index("into") + 1
            table = toks[j].val
            j += 1
            while j + 1 < len(toks) and vals[j] == "." and toks[j + 1].kind == "id":
                table = toks[j + 1].val
                j += 2
            if vals[j] != "(":
                return []
            cols, j = [], j + 1
            while j < len(toks) and vals[j] != ")":
                if toks[j].kind == "id":
                    cols.append(toks[j].val)
                j += 1
            k = vals.index("values", j) if "values" in vals[j:] else -1
            if k < 0 or vals[k + 1] != "(":
                return []
            items, cur, depth = [], [], 0
            for t in toks[k + 2:]:
                if t.val == "(":
                    depth += 1
                elif t.val == ")":
                    if depth == 0:
                        items.append(cur)
                        break
                    depth -= 1
                if t.val == "," and depth == 0:
                    items.append(cur)
                    cur = []
                    continue
                cur.append(t)
            for col, item in zip(cols, items):
                ref = _ref(item)
                if ref:
                    out.append((table.upper(), col.upper(), ref))
        elif vals and vals[0] == "update":
            table = toks[1].val
            j = 2
            while j + 1 < len(toks) and vals[j] == "." and toks[j + 1].kind == "id":
                table = toks[j + 1].val
                j += 2
            j = vals.index("set", j) + 1
            while j < len(toks):
                col = toks[j].val
                j += 1
                while j + 1 < len(toks) and vals[j] == "." and toks[j + 1].kind == "id":
                    col = toks[j + 1].val
                    j += 2
                if j >= len(toks) or vals[j] != "=":
                    break
                j += 1
                item, depth = [], 0
                while j < len(toks) and not (depth == 0 and (vals[j] in (",", "where", "returning", "from", ";") or toks[j].kind == "eof")):
                    depth += vals[j] == "("
                    depth -= vals[j] == ")"
                    item.append(toks[j])
                    j += 1
                ref = _ref(item)
                if ref:
                    out.append((table.upper(), col.upper(), ref))
                if j < len(toks) and vals[j] == ",":
                    j += 1
                    continue
                break
    except (ValueError, IndexError):
        return out
    return out


def _ref(item):
    binds = [t for t in item if t.kind == "bind"]
    if len(binds) != 1:
        return None
    v = binds[0].val
    if v.startswith("__p"):
        return ("pos", int(v[3:]))
    if v.startswith("__k_"):
        return ("key", v[4:])
    return None


def parse_read(sql: str) -> list[tuple[str, str]]:
    from .plsql_frontend import Parser
    norm, _ = _normalize(sql)
    try:
        p = Parser(norm)
        info = p.select_info(0, len(p.toks) - 1)
    except Exception:  # noqa: BLE001
        return []
    out = []
    for c in info.get("cols", []):
        if c:
            out.append((c[0], c[1]))
    if not out:                    # select * : unknown columns -> whole table marker
        m = re.search(r"\bfrom\s+([A-Za-z_][\w$#.]*)", norm, re.I)
        if m and re.search(r"select\s+(\w+\.)?\*", norm, re.I):
            out.append((m.group(1).split(".")[-1].upper(), "*"))
    return out


# --------------------------------------------------------------------------------------------- naming
_ALIASES: dict = {}      # canonical table alias -> canonical table (e.g. Django BLOG_NOTE -> NOTE), set per project


def canon_table(name: str) -> str:
    """notes / Note / "public"."notes" / [dbo].[Notes] / categories -> NOTE / CATEGORY (lower-case singular, no schema)."""
    n = str(name).strip().strip('`"[]').split(".")[-1].strip('`"[]').lower()
    if n.endswith("ies") and len(n) > 4:
        n = n[:-3] + "y"
    elif n.endswith(("sses", "xes", "zes", "ches", "shes")):
        n = n[:-2]
    elif n.endswith("s") and not n.endswith(("ss", "us", "is")) and len(n) > 3:
        n = n[:-1]
    t = re.sub(r"\W", "_", n).upper()
    return _ALIASES.get(t, t)


def canon_col(name: str) -> str:
    """created_at / createdAt / CREATED_AT -> CREATEDAT; '*' stays."""
    return "*" if name == "*" else re.sub(r"[^0-9A-Za-z]", "", str(name)).upper()


# --------------------------------------------------------------------------------------------- instrumentation
def _load(table, col, line):
    table, col = canon_table(table), canon_col(col)
    n = ast.Attribute(value=ast.Attribute(value=ast.Name(id="stored_db", ctx=ast.Load()), attr=table, ctx=ast.Load()),
                      attr=col, ctx=ast.Load())
    for x in ast.walk(n):
        x.lineno = x.end_lineno = line
        x.col_offset = x.end_col_offset = 0
    return n


def _db_read(node):
    """stored_db_read(<call>): keeps the call (sinks on it still fire) but drops the taint of its arguments."""
    line = getattr(node, "lineno", 1)
    c = ast.Call(func=ast.Name(id="stored_db_read", ctx=ast.Load()), args=[node], keywords=[])
    for x in (c, c.func):
        x.lineno = x.end_lineno = line
        x.col_offset = x.end_col_offset = 0
    return c


def _either(loads, node):
    line = getattr(node, "lineno", 1)
    b = ast.BoolOp(op=ast.Or(), values=list(loads) + [node])
    b.lineno = b.end_lineno = line
    b.col_offset = b.end_col_offset = 0
    return b


ANY_TABLE = "ANY_TABLE"     # a table chosen at run time (from the database, a service, an unknown variable)


def _resolve(table, col, in_helper: bool):
    """(table, column) for a write / read, or None.

    An unresolved table becomes ANY_TABLE (the column still links writes and reads) except inside a generic helper,
    which is modelled precisely at each call site; an unresolved column becomes '*'."""
    t = canon_table(table) if table else ""
    c = canon_col(col) if col else ""
    if not t or "DYN" in t:
        if in_helper:
            return None
        t = ANY_TABLE
    if not c or c == "DYN":
        c = "*"
    return t, c


def _loads(reads, line) -> list:
    """Loads for read columns, plus the run-time-table view of each column (matched by writes to unknown tables)."""
    out = []
    for t, c in reads:
        out.append(_load(t, c, line))
        if t != ANY_TABLE:
            out.append(_load(ANY_TABLE, c, line))
    return out


def _write_stmt(table, col, expr, line):
    table, col = canon_table(table), canon_col(col)
    e = copy.deepcopy(expr)
    call = ast.Call(func=ast.Name(id=f"stored_db_write__{table}__{col}", ctx=ast.Load()), args=[e], keywords=[])
    st = ast.Expr(value=call)
    for x in (call, call.func, st):
        x.lineno = x.end_lineno = line
        x.col_offset = x.end_col_offset = 0
    return st


def _explicit_table(cls: ast.ClassDef) -> str | None:
    """The table a model class maps to, when the class says so (SQLAlchemy, Django Meta, Rails, JPA, TypeORM)."""
    for st in cls.body:
        if isinstance(st, ast.Assign):
            for t in st.targets:
                name = t.id if isinstance(t, ast.Name) else (t.attr if isinstance(t, ast.Attribute) else "")
                if name in ("__tablename__", "table_name", "tableName", "_table", "collection") and _const_str(st.value):
                    return _const_str(st.value)                    # __tablename__ = "x" / self.table_name = "x"
        if isinstance(st, ast.ClassDef) and st.name == "Meta":
            for m in st.body:
                if isinstance(m, ast.Assign) and any(isinstance(t, ast.Name) and t.id in ("db_table", "table_name", "collection")
                                                     for t in m.targets) and _const_str(m.value):
                    return _const_str(m.value)                     # Django / Peewee Meta
    for d in cls.decorator_list:
        if isinstance(d, ast.Call) and _dotted(d.func).split(".")[-1] in ("Table", "Entity", "Document", "table", "entity"):
            for k in d.keywords:
                if k.arg in ("name", "collection", "tableName") and _const_str(k.value):
                    return _const_str(k.value)                     # @Table(name = "x") / @Entity(name = "x")
            if d.args and _const_str(d.args[0]):
                return _const_str(d.args[0])                       # @Entity("x")
            if d.args and isinstance(d.args[0], ast.Dict):
                for k, v in zip(d.args[0].keys, d.args[0].values):
                    if _const_str(k) in ("name", "tableName", "collection") and _const_str(v):
                        return _const_str(v)
    return None


def model_names(trees: list) -> dict:
    """Model class simple name -> canonical table, across a project (and table aliases for raw SQL)."""
    out, aliases = {}, {}
    for item in trees:
        text, tree = item[0], item[1]
        rel = item[2] if len(item) > 2 else ""
        sqlalchemy = "sqlalchemy" in text or "declarative_base" in text
        django = "django.db" in text
        for n in ast.walk(tree):
            if isinstance(n, ast.ClassDef):
                bases = {_dotted(b) for b in n.bases}
                decos = {_dotted(d).split(".")[-1] for d in n.decorator_list}
                if (bases & (MODEL_BASES - {"Base"})) or ("Base" in bases and sqlalchemy) or (decos & ENTITY_DECOS):
                    table = canon_table(_explicit_table(n) or n.name)
                    out[n.name] = table
                    aliases[canon_table(n.name)] = table
                    if django and rel:                             # Django default table: <app label>_<model>
                        parts = rel.replace("\\", "/").split("/")
                        app = parts[-2] if len(parts) >= 2 else ""
                        if app:
                            aliases[canon_table(f"{app}_{n.name}")] = table
            elif isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and isinstance(n.value, ast.Call):
                canon = _dotted(n.value.func)
                if canon.endswith(MODEL_FACTORIES) and n.value.args and _const_str(n.value.args[0]):
                    explicit = None
                    for a in n.value.args[1:]:
                        if _const_str(a):
                            explicit = _const_str(a)               # mongoose.model('Note', schema, 'collection')
                        elif isinstance(a, ast.Dict):
                            for k, v in zip(a.keys, a.values):
                                if _const_str(k) in ("tableName", "collection") and _const_str(v):
                                    explicit = _const_str(v)       # sequelize.define('Note', {...}, {tableName})
                    table = canon_table(explicit or _const_str(n.value.args[0]))
                    out[n.targets[0].id] = table
                    aliases[canon_table(_const_str(n.value.args[0]))] = table
            elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "init" and len(n.args) >= 2 \
                    and isinstance(n.func.value, ast.Name) and isinstance(n.args[1], ast.Dict):
                for k, v in zip(n.args[1].keys, n.args[1].values):
                    if _const_str(k) == "tableName" and _const_str(v):   # class Note extends Model; Note.init(attrs, {tableName})
                        aliases[canon_table(_const_str(v))] = canon_table(n.func.value.id)
    for k, v in list(aliases.items()):
        if k == v:
            del aliases[k]
    out["__aliases__"] = aliases
    return out


def helper_signatures(trees: list, models: dict) -> dict:
    """Generic data-access helpers whose table / model and data arrive as arguments.

    save(table, data): db.execute(f"INSERT INTO {table} …", data.values())   -> ('sql', table param, data param)
    create(model, **fields): model.objects.create(**fields) / Model.create(data) -> ('orm', model param, data)
    fetch(table, id): db.execute(f"SELECT * FROM {table} …")                    -> ('read', table param)"""
    sigs: dict = {}
    for item in trees:
        tree = item[1]
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) or fn.name in sigs:
                continue
            params = [a.arg for a in fn.args.posonlyargs + fn.args.args if a.arg not in ("self", "cls")]
            kwarg = fn.args.kwarg.arg if fn.args.kwarg else None
            if not params and not kwarg:
                continue
            dict_params = {n.func.value.id for n in _walk(fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                           and n.func.attr in ("keys", "values", "items") and isinstance(n.func.value, ast.Name)}
            dict_params |= {k.value.id for n in _walk(fn) if isinstance(n, ast.Call) for k in n.keywords
                            if k.arg is None and isinstance(k.value, ast.Name)}
            data = None
            for p in params:
                if p in dict_params:
                    data = ("idx", params.index(p), p)
                    break
            if data is None and kwarg and kwarg in dict_params | {kwarg}:
                data = ("kwargs", kwarg)
            for c in _walk(fn):
                if not isinstance(c, ast.Call):
                    continue
                for a in c.args[:2]:
                    head, tbl = _dynamic_sql(a)
                    if tbl is None or not isinstance(tbl, ast.Name) or tbl.id not in params:
                        continue
                    if re.match(r"^\s*(insert\s+into|replace\s+into|update)\s+$", head, re.I) and data:
                        sigs[fn.name] = {"kind": "sql", "table": (params.index(tbl.id), tbl.id), "data": data}
                    elif re.match(r"^\s*select\b.*\bfrom\s+$", head, re.I | re.S):
                        sigs[fn.name] = {"kind": "read", "table": (params.index(tbl.id), tbl.id)}
                if fn.name in sigs:
                    break
                chain = _chain(c)
                root = chain[0] if chain else None
                if root in params and data is None:
                    arg_param = next((a.id for a in c.args if isinstance(a, ast.Name) and a.id in params and a.id != root), None)
                    if arg_param:
                        data = ("idx", params.index(arg_param), arg_param)
                if root in params:
                    if any(m in ORM_WRITE for m in chain[1:]) and data:
                        sigs[fn.name] = {"kind": "orm", "model": (params.index(root), root), "data": data}
                        break
                    if len(chain) == 1 and data:                    # model(**fields)
                        sigs[fn.name] = {"kind": "orm", "model": (params.index(root), root), "data": data}
                        break
                    if any(m in ORM_READ_HINT for m in chain[1:]):
                        sigs[fn.name] = {"kind": "read_orm", "model": (params.index(root), root)}
                        break
    return sigs


def _dynamic_sql(node):
    """f"INSERT INTO {table} …" / "SELECT * FROM " + table -> (constant text before the first value, that value)."""
    pieces = []
    if isinstance(node, ast.JoinedStr):
        for v in node.values:
            pieces.append(v.value if isinstance(v, ast.FormattedValue) else v)
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        def flat(n):
            if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
                flat(n.left)
                flat(n.right)
            else:
                pieces.append(n)
        flat(node)
    else:
        return "", None
    head = ""
    for p in pieces:
        s = _const_str(p)
        if s is None:
            return head, p
        head += s
    return head, None


class _Scope:
    def __init__(self, models, ctor_params, sigs=None, fc=None, in_helper=False):
        self.in_helper = in_helper
        self.models = {k: v for k, v in models.items() if k != "__aliases__"}
        self.ctor_params = ctor_params
        self.sigs = sigs or {}
        self.fc = fc
        self.prepared: dict = {}     # var -> SQL text
        self.cursors: dict = {}      # cursor var -> columns of the last SELECT it executed (in statement order)
        self.bound: dict = {}        # var -> table (ORM instance / loop row / JPA entity)
        self.consts: dict = {}       # var -> string constant

    # ------------------------------------------------------------------ helpers
    def _text(self, a):
        """Text of an argument: literal, local constant, or folded (config / helpers / format / concatenation)."""
        s = _const_str(a)
        if s is None and isinstance(a, ast.Name):
            s = self.consts.get(a.id)
        if s is None and self.fc is not None and not isinstance(a, (ast.Dict, ast.List, ast.Tuple)):
            v = fold(a, self.fc, self.consts)
            s = v if isinstance(v, str) else None
        return s

    def sql_of(self, call):
        """(sql, index of the sql argument) for a call that carries SQL text."""
        for i, a in enumerate(call.args[:2]):
            s = self._text(a)
            if s is None and isinstance(a, ast.Call) and a.args and _dotted(a.func).split(".")[-1] in ("text", "sql", "raw", "SQL"):
                s = _const_str(a.args[0])
            if s and (WRITE_SQL.match(s) or READ_SQL.match(s)):
                return s, i
        for k in call.keywords:
            s = _const_str(k.value)
            if k.arg in ("sql", "query", "text", "statement") and s and (WRITE_SQL.match(s) or READ_SQL.match(s)):
                return s, -1
        return None, None

    def prepared_sql(self, call):
        """SQL bound to the receiver of an exec-style call (prepared statement variable or chained prepare())."""
        if not isinstance(call.func, ast.Attribute):
            return None
        recv = call.func.value
        if isinstance(recv, ast.Attribute) and recv.attr.lower() == "parameters":
            recv = recv.value
        if isinstance(recv, ast.Name) and recv.id in self.prepared:
            return self.prepared[recv.id]
        if isinstance(recv, ast.Call):
            s, _ = self.sql_of(recv)
            return s
        return None

    def model_of(self, expr):
        """Table of an ORM model instance expression (fetched / constructed), or None."""
        root = _root_name(expr)
        if root is None:
            return None
        if isinstance(expr, ast.Name) and root in self.bound:
            return self.bound[root]
        chain = _chain(expr)
        if root in self.models and len(chain) >= 2 and any(c in ORM_READ_HINT or c in ORM_WRITE for c in chain[1:]):
            return self.models[root]
        if root in self.models and isinstance(expr, ast.Call) and len(chain) == 1:
            return self.models[root]                     # constructor
        if root in ("prisma",) and len(chain) >= 3:
            return chain[1].upper()
        if isinstance(expr, (ast.Call, ast.Await)):
            c = expr.value if isinstance(expr, ast.Await) else expr
            if isinstance(c, ast.Call):
                sig = self.sigs.get(c.func.id if isinstance(c.func, ast.Name) else (c.func.attr if isinstance(c.func, ast.Attribute) else ""))
                if sig and sig["kind"] == "read_orm":
                    return self._sig_table(c, sig)
        # session.query(Item) / session.get(Item, 1) / select(Item) / db.session.scalars(select(Item))
        for n in ast.walk(expr):
            if isinstance(n, ast.Call) and n.args and isinstance(n.args[0], ast.Name) and n.args[0].id in self.models \
                    and _dotted(n.func).split(".")[-1] in ("query", "get", "scalars", "execute", "select", "get_or_404",
                                                           "first_or_404", "exec", "get_one", "find", "getRepository",
                                                           "createQueryBuilder", "findOneBy", "findBy"):
                return self.models[n.args[0].id]
        # noteRepository.findById(..) / this.noteRepository… -> Note (Spring Data / DAO naming)
        names = [c for c in chain if c not in ("self", "this")]
        if names and len(chain) >= 2:
            low = names[0].lower()
            for suffix in ("repository", "repo", "dao", "service"):
                if low.endswith(suffix):
                    stem = low[: -len(suffix)].rstrip("_")
                    for m, t in self.models.items():
                        if m.lower() == stem:
                            return t
        return None

    # ------------------------------------------------------------------ learning
    def learn(self, st):
        if isinstance(st, ast.AugAssign) and isinstance(st.target, ast.Name) and isinstance(st.op, ast.Add):
            cur = self.consts.get(st.target.id)
            if isinstance(cur, str):                              # q += " WHERE …"
                add = self._text(st.value)
                self.consts[st.target.id] = cur + (add if isinstance(add, str) else DYN)
                if WRITE_SQL.match(self.consts[st.target.id]) or READ_SQL.match(self.consts[st.target.id]):
                    self.prepared[st.target.id] = self.consts[st.target.id]
            return
        if isinstance(st, (ast.Assign, ast.AnnAssign)) and getattr(st, "value", None) is not None:
            tgts = st.targets if isinstance(st, ast.Assign) else [st.target]
            v = st.value.value if isinstance(st.value, ast.Await) else st.value
            for t in tgts:
                if isinstance(t, ast.Name):
                    s = self._text(v) if not isinstance(v, ast.Call) or self.fc is not None else _const_str(v)
                    if isinstance(s, str):
                        self.consts[t.id] = s
                    if isinstance(v, ast.Call):
                        sql, _ = self.sql_of(v)
                        if sql:
                            self.prepared[t.id] = sql
                    tbl = self.model_of(v)
                    if tbl:
                        self.bound[t.id] = tbl
                elif isinstance(t, ast.Attribute) and t.attr.lower() in ("commandtext", "sql", "query") and isinstance(t.value, ast.Name):
                    s = _const_str(v) or (self.consts.get(v.id) if isinstance(v, ast.Name) else None)
                    if s:
                        self.prepared[t.value.id] = s

    def learn_for(self, target, it):
        tbl = self.model_of(it)
        if tbl and isinstance(target, ast.Name):
            self.bound[target.id] = tbl

    # ------------------------------------------------------------------ writes
    def _params(self, args, kws):
        if len(args) == 1 and isinstance(args[0], (ast.Tuple, ast.List)):
            args = list(args[0].elts)
        named = {}
        for a in args:
            if isinstance(a, ast.Dict):
                for k, v in zip(a.keys, a.values):
                    ks = _const_str(k)
                    if ks:
                        named[ks.lstrip(":@$").lower()] = v
        for k in kws:
            if k.arg:
                named[k.arg.lower()] = k.value
        return args, named

    def _map(self, sql, args, kws):
        out = []
        pos, named = self._params(args, kws)
        refs = parse_write(sql)
        if len(pos) == 1 and isinstance(pos[0], ast.Dict) and not named:
            pos = list(pos[0].values)
        if refs and all(r[2][0] == "key" for r in refs) and not any(r[2][1] in named for r in refs) and len(pos) == len(refs):
            refs = [(t, c, ("pos", i)) for i, (t, c, _r) in enumerate(refs)]     # named placeholders bound by order
        for table, col, ref in refs:
            if ref[0] == "pos" and ref[1] < len(pos) and not isinstance(pos[ref[1]], ast.Dict):
                out.append((table, col, pos[ref[1]]))
            elif ref[0] == "key" and ref[1] in named:
                out.append((table, col, named[ref[1]]))
            elif len(pos) == 1 and isinstance(pos[0], ast.Name):        # params passed as one variable: coarse
                out.append((table, col, pos[0]))
        return out

    def writes(self, node) -> list:
        out = []
        for n in _walk(node):
            if isinstance(n, ast.Call):
                out.extend(self.call_writes(n))
            elif isinstance(n, (ast.Assign, ast.AnnAssign)) and getattr(n, "value", None) is not None:
                for t in (n.targets if isinstance(n, ast.Assign) else [n.target]):
                    if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) and t.value.id in self.bound:
                        out.append((self.bound[t.value.id], t.attr.upper(), n.value))
        return out

    def _sig_arg(self, call, pos):
        idx, name = pos
        for k in call.keywords:
            if k.arg == name:
                return k.value
        return call.args[idx] if idx < len(call.args) else None

    def _sig_table(self, call, sig):
        if "table" in sig:
            a = self._sig_arg(call, sig["table"])
            return self._text(a) if a is not None else None
        a = self._sig_arg(call, sig["model"])
        if isinstance(a, ast.Name) and a.id in self.models:
            return self.models[a.id]
        return None

    def helper_writes(self, call) -> list:
        """Calls to generic save/create helpers: the table comes from this call site's arguments."""
        name = call.func.id if isinstance(call.func, ast.Name) else (call.func.attr if isinstance(call.func, ast.Attribute) else "")
        sig = self.sigs.get(name)
        if not sig or sig["kind"] not in ("sql", "orm"):
            return []
        table = self._sig_table(call, sig)
        if not table:
            return []
        data = sig["data"]
        if data[0] == "idx":
            d = self._sig_arg(call, (data[1], data[2]))
            return _dict_items(table, d) if isinstance(d, ast.Dict) else []
        skip = {sig.get("table", (0, None))[1], sig.get("model", (0, None))[1]}
        return [(table, k.arg.upper(), k.value) for k in call.keywords if k.arg and k.arg not in skip]

    def call_writes(self, call) -> list:
        out = self.helper_writes(call)
        sql, idx = self.sql_of(call)
        if sql and WRITE_SQL.match(sql):
            rest = call.args[idx + 1:] if idx is not None and idx >= 0 else call.args
            out.extend(self._map(sql, rest, [k for k in call.keywords if k.arg not in ("sql", "query", "text")]))
        meth = call.func.attr if isinstance(call.func, ast.Attribute) else ""
        psql = self.prepared_sql(call)
        if psql and WRITE_SQL.match(psql):
            low = meth.lower()
            if low in EXEC_METHODS or low in ("bind", "bindvalue", "bindparam", "bind_param", "addwithvalue", "add", "setparameter"):
                if low in ("bindvalue", "bindparam", "addwithvalue", "add", "setparameter") and len(call.args) >= 2:
                    key = (_const_str(call.args[0]) or "").lstrip(":@$").lower()
                    pos_i = call.args[0].value - 1 if isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, (int, float)) else None
                    for table, col, ref in parse_write(psql):
                        if (ref[0] == "key" and ref[1] == key) or (ref[0] == "pos" and pos_i is not None and ref[1] == int(pos_i)):
                            out.append((table, col, call.args[1]))
                elif low == "bind_param" and call.args:
                    out.extend(self._map(psql, call.args[1:], []))
                else:
                    out.extend(self._map(psql, call.args, call.keywords))
            elif re.match(r"set[A-Z]\w*$", meth) and len(call.args) == 2 and isinstance(call.args[0], ast.Constant):
                for table, col, ref in parse_write(psql):        # JDBC: ps.setString(1, x)
                    if ref[0] == "pos" and ref[1] == int(call.args[0].value) - 1:
                        out.append((table, col, call.args[1]))
        # ORM writes
        if isinstance(call.func, ast.Attribute):
            recv = call.func.value
            if meth in ORM_WRITE:
                tbl = self.model_of(recv) or (self.models.get(recv.id) if isinstance(recv, ast.Name) else None)
                if tbl is None and isinstance(recv, ast.Attribute) and isinstance(recv.value, ast.Name) and recv.value.id in self.models:
                    tbl = self.models[recv.value.id]                    # Note.objects.create
                if tbl is None and _root_name(recv) == "prisma" and len(_chain(call)) >= 3:
                    tbl = _chain(call)[1].upper()
                if tbl:
                    out.extend(self._orm_values(tbl, call))
            if re.match(r"set[A-Z]\w*$", meth) and len(call.args) == 1 and isinstance(recv, ast.Name) and recv.id in self.bound:
                out.append((self.bound[recv.id], meth[3:].upper(), call.args[0]))       # entity.setBody(x)
        elif isinstance(call.func, ast.Name) and call.func.id in self.models:            # Note(body=x) / new Note(x)
            tbl = self.models[call.func.id]
            out.extend(self._orm_values(tbl, call))
            params = self.ctor_params.get(call.func.id, [])
            for p, a in zip(params, call.args):
                if not isinstance(a, ast.Dict):
                    out.append((tbl, p.upper(), a))
        return out

    @staticmethod
    def _orm_values(tbl, call) -> list:
        out = []
        for k in call.keywords:
            if k.arg and k.arg not in ("defaults", "where", "filter", "id"):
                out.append((tbl, k.arg.upper(), k.value))
            elif k.arg == "defaults" and isinstance(k.value, ast.Dict):
                out.extend(_dict_items(tbl, k.value))
        for a in call.args:
            if isinstance(a, ast.Dict):
                for key, v in zip(a.keys, a.values):
                    ks = _const_str(key)
                    if ks in ("data", "$set", "set", "values", "attributes") and isinstance(v, ast.Dict):
                        out.extend(_dict_items(tbl, v))                 # prisma {data: {...}} / mongo {$set: {...}}
                    elif ks and not ks.startswith("$") and ks not in ("where", "id", "_id"):
                        out.append((tbl, ks.upper(), v))
            elif isinstance(a, (ast.List, ast.Tuple)):
                for e in a.elts:
                    if isinstance(e, ast.Dict):
                        out.extend(_dict_items(tbl, e))
        return out

    # ------------------------------------------------------------------ reads
    def call_reads(self, call) -> list:
        out = []
        for t, c in self._call_reads(call):
            r = _resolve(t, c, self.in_helper)
            if r and r not in out:
                out.append(r)
        return out

    def _call_reads(self, call) -> list:
        name = call.func.id if isinstance(call.func, ast.Name) else (call.func.attr if isinstance(call.func, ast.Attribute) else "")
        if name in _FORMAT_FUNCS:
            return []           # fmt.Sprintf("SELECT … %s", x) BUILDS the query text, it does not run it
        sig = self.sigs.get(name)
        if sig and sig["kind"] in ("read", "read_orm"):
            table = self._sig_table(call, sig)
            if table:
                return [(table, "*")]
        sql, _ = self.sql_of(call)
        if sql and READ_SQL.match(sql):
            return parse_read(sql)
        psql = self.prepared_sql(call)
        if psql and READ_SQL.match(psql) and isinstance(call.func, ast.Attribute) and call.func.attr.lower() in EXEC_METHODS:
            return parse_read(psql)
        if isinstance(call.func, ast.Attribute) and not call.args and isinstance(call.func.value, ast.Name) \
                and call.func.value.id in self.bound:
            meth = call.func.attr
            if re.match(r"get[A-Z]\w*$", meth):
                return [(self.bound[call.func.value.id], meth[3:].upper())]        # entity.getBody()
            if meth not in NON_COLUMN_METHODS and meth not in ORM_WRITE and not meth.startswith(("set", "is_", "has_")):
                return [(self.bound[call.func.value.id], meth.rstrip("?!").upper())]  # Ruby: note.body
        return []

    def is_fetch(self, call) -> bool:
        """An ORM / SQL lookup whose result is table data (its arguments are only the key)."""
        fname = call.func.id if isinstance(call.func, ast.Name) else (call.func.attr if isinstance(call.func, ast.Attribute) else "")
        if fname in _FORMAT_FUNCS:
            return False
        if self.model_of(call):
            return True
        sql, _ = self.sql_of(call)
        return bool(sql and READ_SQL.match(sql))

    def attr_reads(self, node) -> list:
        if isinstance(node.value, ast.Name) and node.value.id in self.bound:
            return [(self.bound[node.value.id], node.attr.upper())]
        if isinstance(node.value, (ast.Call, ast.Await, ast.Subscript)):
            tbl = self.model_of(node.value)
            if tbl:
                return [(tbl, node.attr.upper())]
        return []


_FORMAT_FUNCS = frozenset({"Sprintf", "sprintf", "vsprintf", "format", "Format", "formatted", "Sprint", "Sprintln",
                           "Errorf", "concat", "Concat", "join", "Join", "replace", "Replace", "str", "String", "f"})


def _dict_items(tbl, d) -> list:
    out = []
    for key, v in zip(d.keys, d.values):
        ks = _const_str(key)
        if ks and not ks.startswith("$"):
            out.append((tbl, ks.upper(), v))
    return out


def _walk(node):
    """ast.walk without entering nested functions, classes or lambdas."""
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        for c in ast.iter_child_nodes(n):
            if not isinstance(c, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                stack.append(c)


def _trusted(node):
    """stored_db_config(<lookup>): a configuration value defined in the project's own files (operator-controlled)."""
    line = getattr(node, "lineno", 1)
    c = ast.Call(func=ast.Name(id="stored_db_config", ctx=ast.Load()), args=[node], keywords=[])
    for x in (c, c.func):
        x.lineno = x.end_lineno = line
        x.col_offset = x.end_col_offset = 0
    return c


def _is_config_lookup(node) -> bool:
    if isinstance(node, ast.Call):
        canon = _dotted(node.func)
        return canon in ENV_CALLS or canon.split(".")[-1] in ("getenv", "Getenv", "getProperty", "GetEnvironmentVariable")
    if isinstance(node, ast.Subscript):
        base = _dotted(node.value)
        return base in CONFIG_ROOTS or base.split(".")[0] in CONFIG_ROOTS
    if isinstance(node, ast.Attribute):
        d = _dotted(node)
        root = d.rsplit(".", 1)[0] if "." in d else ""
        return root in ("process.env", "os.environ", "ENV", "settings", "config", "app.config")
    return False


class _Rewriter(ast.NodeTransformer):
    def __init__(self, scope: _Scope):
        self.s = scope

    def _config(self, node):
        """Lookups resolved from the project's configuration files are trusted values, not user input."""
        fc = self.s.fc
        if fc is not None and fc.config and _is_config_lookup(node):
            v = fold(node, fc)
            if isinstance(v, str) and DYN not in v:
                return _trusted(node)
        return None

    def visit_Subscript(self, node):
        node.value = self.visit(node.value)
        node.slice = self.visit(node.slice)
        if isinstance(node.ctx, ast.Load):
            t = self._config(node)
            if t is not None:
                return t
        return node

    def visit_FunctionDef(self, node):
        return node

    visit_AsyncFunctionDef = visit_ClassDef = visit_Lambda = visit_FunctionDef

    def visit_Call(self, node):
        if isinstance(node.func, ast.Attribute):
            node.func.value = self.visit(node.func.value)
        else:
            node.func = self.visit(node.func)
        node.args = [self.visit(a) for a in node.args]
        for k in node.keywords:
            k.value = self.visit(k.value)
        t = self._config(node)
        if t is not None:
            return t
        reads = self.s.call_reads(node)
        if not reads and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) \
                and node.func.value.id in self.s.cursors and node.func.attr in FETCH_METHODS:
            reads = self.s.cursors[node.func.value.id]          # cur.fetchone() after cur.execute("SELECT …")
        if reads:
            line = getattr(node, "lineno", 1)
            return _either(_loads(reads, line), _db_read(node))
        if self.s.is_fetch(node):
            return _db_read(node)
        return node

    def visit_Attribute(self, node):
        node.value = self.visit(node.value)
        if isinstance(node.ctx, ast.Load):
            t = self._config(node)
            if t is not None:
                return t
            reads = self.s.attr_reads(node)
            if reads:
                line = getattr(node, "lineno", 1)
                return _either(_loads(reads, line), _db_read(node))
        return node


def _block(stmts, scope: _Scope) -> list:
    out = []
    rw = _Rewriter(scope)
    for st in stmts:
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.append(st)
            continue
        line = getattr(st, "lineno", 1)
        if isinstance(st, (ast.For, ast.AsyncFor)):
            scope.learn_for(st.target, st.iter)
            if isinstance(st.iter, ast.Name) and st.iter.id in scope.cursors:     # for row in cur:
                st.iter = _either(_loads(scope.cursors[st.iter.id], line), _db_read(st.iter))
            else:
                st.iter = rw.visit(st.iter)
            st.body = _block(st.body, scope)
            st.orelse = _block(st.orelse, scope)
            out.append(st)
            continue
        if isinstance(st, (ast.If, ast.While)):
            writes = []
            for n in _walk(st.test):
                if isinstance(n, ast.Call):
                    writes.extend(scope.call_writes(n))
            st.test = rw.visit(st.test)
            st.body = _block(st.body, scope)
            st.orelse = _block(st.orelse, scope)
            out.append(st)
            out.extend(_write_stmt(*_resolve(t, c, scope.in_helper), e, line) for t, c, e in writes if _resolve(t, c, scope.in_helper))
            continue
        if isinstance(st, ast.Try) or (hasattr(ast, "TryStar") and isinstance(st, ast.TryStar)):
            st.body = _block(st.body, scope)
            for h in st.handlers:
                h.body = _block(h.body, scope)
            st.orelse = _block(st.orelse, scope)
            st.finalbody = _block(st.finalbody, scope)
            out.append(st)
            continue
        if isinstance(st, (ast.With, ast.AsyncWith)):
            for item in st.items:
                item.context_expr = rw.visit(item.context_expr)
            st.body = _block(st.body, scope)
            out.append(st)
            continue
        scope.learn(st)
        writes = scope.writes(st)
        cursor_read = None
        # cur.execute("SELECT …") as a statement: the cursor now holds the selected columns
        if isinstance(st, ast.Expr) and isinstance(st.value, (ast.Call, ast.Await)):
            c = st.value.value if isinstance(st.value, ast.Await) else st.value
            if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute) and isinstance(c.func.value, ast.Name):
                reads = scope.call_reads(c)
                if reads:
                    cursor_read = (c.func.value.id, reads)
        scan = None
        if isinstance(st, ast.Expr) and isinstance(st.value, ast.Call) and isinstance(st.value.func, ast.Attribute) \
                and st.value.func.attr in ("Scan", "scan", "bind_result", "fetch_into", "StructScan", "Get"):
            scan = (st.value.func.value, [a for a in st.value.args if isinstance(a, ast.Name)])
        st = rw.visit(st)
        out.append(st)
        out.extend(_write_stmt(*_resolve(t, c, scope.in_helper), e, line) for t, c, e in writes if _resolve(t, c, scope.in_helper))
        if scan and scan[1]:
            recv, names = scan
            for nm in names:                                   # out-parameters receive the row
                a = ast.Assign(targets=[ast.Name(id=nm.id, ctx=ast.Store())], value=copy.deepcopy(recv))
                for x in ast.walk(a):
                    x.lineno = x.end_lineno = line
                    x.col_offset = x.end_col_offset = 0
                out.append(a)
        if cursor_read:
            scope.cursors[cursor_read[0]] = cursor_read[1]      # later fetches on this cursor read these columns
    return out


def instrument(tree: ast.Module, models: dict, ctor_params: dict, sigs: dict | None = None, fc: FoldContext | None = None) -> ast.Module:
    """Rewrite a module in place: explicit table writes / reads for the stored-data passes."""
    _ALIASES.clear()
    _ALIASES.update(models.get("__aliases__", {}))
    tree.body = _block(tree.body, _Scope(models, ctor_params, sigs, fc))
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            n.body = _block(n.body, _Scope(models, ctor_params, sigs, fc, in_helper=n.name in (sigs or {}))) or n.body
    return tree


def ctor_param_names(trees: list, models: dict) -> dict:
    """Model class -> constructor parameter names (for positional `new Note(title, body)`)."""
    out = {}
    for item in trees:
        tree = item[1]
        for n in ast.walk(tree):
            if isinstance(n, ast.ClassDef) and n.name in models:
                for f in n.body:
                    if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef)) and f.name == "__init__":
                        out[n.name] = [a.arg for a in f.args.args if a.arg not in ("self", "cls")]
    return out


def has_store_writes(trees) -> bool:
    return any(isinstance(n, ast.Name) and n.id.startswith("stored_db_write__") for _, tree in trees for n in ast.walk(tree))


# =========================================================================================== folding SQL text
# Table names and queries are often not literals: they come from configuration (.env, settings, YAML, @Value),
# module constants, `q += …` sequences, str.format / % / join, or helper functions that build the SQL.
# fold() evaluates such expressions to text so the writes / reads above still see real tables and columns.
DYN = "__dyn__"


def parse_config(rel: str, text: str) -> dict:
    """Key/value pairs of a configuration file (flattened, keys lower-cased; nested keys dotted)."""
    low = rel.lower().replace("\\", "/")
    name = low.rsplit("/", 1)[-1]
    out: dict = {}
    try:
        if name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile") or name == "containerfile":
            for ln in text.splitlines():
                m = re.match(r"\s*(?:ENV|ARG)\s+(.*)$", ln, re.I)
                if not m:
                    continue
                body = m.group(1).strip()
                pairs = re.findall(r'([\w.\-]+)=("(?:[^"\\]|\\.)*"|\S+)', body)
                if pairs:
                    for k, v in pairs:
                        out[k.lower()] = v.strip('"')
                else:
                    kv = body.split(None, 1)                       # ENV KEY value
                    if len(kv) == 2:
                        out[kv[0].lower()] = kv[1].strip().strip('"')
            return out
        if name.startswith(".env") or name.endswith((".properties", ".env")):
            for ln in text.splitlines():
                m = re.match(r"\s*(?:export\s+)?([\w.\-]+)\s*[=:]\s*(.*?)\s*$", ln)
                if m and not ln.lstrip().startswith(("#", "!")):
                    out[m.group(1).lower()] = m.group(2).strip().strip("'\"")
        elif name.endswith((".ini", ".cfg", ".conf", ".toml")):
            section = ""
            for ln in text.splitlines():
                s = ln.strip()
                if not s or s.startswith(("#", ";")):
                    continue
                m = re.match(r"\[\s*([^\]]+?)\s*\]$", s)
                if m:
                    section = m.group(1).lower()
                    continue
                m = re.match(r"([\w.\-]+)\s*[=:]\s*(.*)$", s)
                if m:
                    v = m.group(2).strip().strip("'\"")
                    out[m.group(1).lower()] = v
                    if section:
                        out[f"{section}.{m.group(1).lower()}"] = v
        elif name.endswith(".json"):
            import json

            def flat(o, prefix=""):
                if isinstance(o, dict):
                    for k, v in o.items():
                        flat(v, f"{prefix}{str(k).lower()}.")
                elif isinstance(o, (str, int, float)) and prefix:
                    key = prefix[:-1]
                    out[key] = str(o)
                    leaf = key.rsplit(".", 1)[-1]
                    out.setdefault(leaf, str(o))
                    if leaf == "value" and key.count(".") >= 1:     # Heroku app.json: env.KEY.value
                        out.setdefault(key.rsplit(".", 2)[-2], str(o))
            flat(json.loads(text))
        elif name.endswith((".yaml", ".yml")):
            stack: list = []
            lines = text.splitlines()
            for k, ln in enumerate(lines):
                s2 = ln.strip()
                # docker-compose `environment:` list form:  - KEY=VALUE  /  - "KEY=VALUE"
                m = re.match(r"^-\s*[\"']?([A-Za-z_][\w.\-]*)=([^\"'#]*)[\"']?\s*$", s2)
                if m:
                    out[m.group(1).lower()] = m.group(2).strip()
                    continue
                # Kubernetes / GitHub Actions env pairs:  - name: KEY  /  value: VALUE
                m = re.match(r"^-\s*name\s*:\s*[\"']?([\w.\-]+)[\"']?\s*$", s2)
                if m:
                    for nxt in lines[k + 1:k + 4]:
                        m2 = re.match(r"^\s*value\s*:\s*(.*?)\s*$", nxt)
                        if m2:
                            out[m.group(1).lower()] = m2.group(1).strip("'\"")
                            break
                    continue
                if not ln.strip() or ln.lstrip().startswith(("#", "-")):
                    continue
                m = re.match(r"^(\s*)([\w.\-]+)\s*:\s*(.*?)\s*$", ln)
                if not m:
                    continue
                ind = len(m.group(1))
                while stack and stack[-1][0] >= ind:
                    stack.pop()
                key = ".".join([k for _, k in stack] + [m.group(2).lower()])
                val = m.group(3)
                if val and not val.startswith(("|", ">", "&", "*")):
                    out[key] = val.strip("'\"")
                    out.setdefault(m.group(2).lower(), val.strip("'\""))
                else:
                    stack.append((ind, m.group(2).lower()))
    except Exception:  # noqa: BLE001 - a broken config file is simply ignored
        return out
    return out


CONFIG_NAMES = (".env", ".ini", ".cfg", ".conf", ".toml", ".properties", ".json", ".yaml", ".yml")


def is_config_file(rel: str) -> bool:
    low = rel.lower().replace("\\", "/")
    name = low.rsplit("/", 1)[-1]
    if name in ("package.json", "package-lock.json", "tsconfig.json", "composer.lock") or "node_modules/" in low:
        return False
    return (name.startswith((".env", "dockerfile")) or name.endswith(CONFIG_NAMES + (".dockerfile",))
            or name in ("containerfile", "procfile"))


class FoldContext:
    """Project-wide facts used to evaluate SQL text: functions, module constants, instance fields, configuration."""

    def __init__(self, trees: list, config: dict | None = None):
        self.funcs: dict = {}
        self.consts: dict = {}
        self.fields: dict = {}
        self.config = {str(k).lower(): v for k, v in (config or {}).items()}
        for item in trees:
            tree = item[1]
            for st in tree.body:
                if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name):
                    self.consts.setdefault(st.targets[0].id, st.value)
            for n in ast.walk(tree):
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.funcs.setdefault(n.name, n)
                elif isinstance(n, ast.ClassDef):
                    for st in n.body:              # class-level constants (Java static final / Python class attrs)
                        if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name):
                            self.consts.setdefault(st.targets[0].id, st.value)
                elif isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Attribute) \
                        and isinstance(n.targets[0].value, ast.Name) and n.targets[0].value.id in ("self", "this"):
                    self.fields.setdefault(n.targets[0].attr, n.value)

    def config_value(self, key: str):
        if not key:
            return None
        k = key.lower().strip()
        k = re.sub(r"^\$\{(.*?)(:.*)?\}$", r"\1", k)          # Spring ${a.b:default}
        for cand in (k, k.replace("_", "."), k.replace(".", "_"), k.rsplit(".", 1)[-1]):
            if cand in self.config:
                return self.config[cand]
        return None


ENV_CALLS = {"getenv", "os.getenv", "os.environ.get", "environ.get", "System.getenv", "os.Getenv", "Getenv", "env",
             "ENV.fetch", "config.get", "settings.get", "cfg.get", "conf.get", "app.config.get", "config_value",
             "Environment.GetEnvironmentVariable", "GetEnvironmentVariable", "getProperty", "System.getProperty",
             "ConfigurationManager.AppSettings.get", "config"}
CONFIG_ROOTS = {"settings", "config", "cfg", "conf", "CONFIG", "SETTINGS", "Config", "Settings", "app.config", "environ",
                "os.environ", "process.env", "ENV", "env", "_ENV", "$_ENV", "configuration", "Configuration"}


def fold(expr, fc: FoldContext, local: dict | None = None, depth: int = 0):
    """Evaluate an expression to text (or a list of texts) when possible; unknown parts become __dyn__."""
    if expr is None or depth > 6:
        return None
    local = local or {}
    if isinstance(expr, ast.Constant):
        return expr.value if isinstance(expr.value, str) else (str(expr.value) if isinstance(expr.value, (int, float)) else None)
    if isinstance(expr, ast.Name):
        if expr.id in local:
            return local[expr.id]
        if expr.id in fc.consts:
            return fold(fc.consts[expr.id], fc, {}, depth + 1)
        return None
    if isinstance(expr, ast.JoinedStr):
        parts = []
        for v in expr.values:
            if isinstance(v, ast.FormattedValue):
                r = fold(v.value, fc, local, depth)
                parts.append(r if isinstance(r, str) else DYN)
            else:
                parts.append(v.value)
        return "".join(parts)
    if isinstance(expr, ast.BinOp):
        left = fold(expr.left, fc, local, depth)
        if isinstance(expr.op, ast.Add):
            right = fold(expr.right, fc, local, depth)
            if isinstance(left, str) or isinstance(right, str):
                return (left if isinstance(left, str) else DYN) + (right if isinstance(right, str) else DYN)
            return None
        if isinstance(expr.op, ast.Mod) and isinstance(left, str):
            vals = expr.right.elts if isinstance(expr.right, ast.Tuple) else [expr.right]
            args = [fold(v, fc, local, depth) for v in vals]
            try:
                return left % tuple(a if isinstance(a, str) else DYN for a in args)
            except (TypeError, ValueError):
                return left
        return None
    if isinstance(expr, (ast.List, ast.Tuple)):
        vals = [fold(e, fc, local, depth) for e in expr.elts]
        return [v if isinstance(v, str) else DYN for v in vals]
    if isinstance(expr, ast.Attribute):
        dotted = _dotted(expr)
        root = dotted.rsplit(".", 1)[0] if "." in dotted else ""
        if isinstance(expr.value, ast.Name) and expr.value.id in ("self", "this") and expr.attr in fc.fields:
            return fold(fc.fields[expr.attr], fc, {}, depth + 1)
        if root in CONFIG_ROOTS or root.split(".")[0] in CONFIG_ROOTS:
            v = fc.config_value(dotted.split(".", 1)[1] if root.split(".")[0] in CONFIG_ROOTS and "." in dotted else expr.attr)
            if v is None:
                v = fc.config_value(expr.attr)
            if v is not None:
                return v
        if expr.attr in fc.consts:                                 # Config.NOTES_TABLE / Constants.TABLE
            return fold(fc.consts[expr.attr], fc, {}, depth + 1)
        return None
    if isinstance(expr, ast.Subscript):
        key = fold(expr.slice, fc, local, depth)
        base = _dotted(expr.value)
        if isinstance(key, str):
            if base in CONFIG_ROOTS or base.split(".")[0] in CONFIG_ROOTS or isinstance(expr.value, ast.Subscript):
                prefix = ""
                if isinstance(expr.value, ast.Subscript):        # config["db"]["table"] -> db.table
                    p = fold(expr.value.slice, fc, local, depth)
                    prefix = f"{p}." if isinstance(p, str) else ""
                v = fc.config_value(prefix + key) or fc.config_value(key)
                if v is not None:
                    return v
        return None
    if isinstance(expr, ast.Call):
        func = expr.func
        canon = _dotted(func)
        # configuration lookups
        if canon in ENV_CALLS or canon.split(".")[-1] in ("getenv", "Getenv", "getProperty", "GetEnvironmentVariable", "config_value"):
            keys = [fold(a, fc, local, depth) for a in expr.args]
            keys = [k for k in keys if isinstance(k, str)]
            if keys:
                v = fc.config_value(".".join(keys[:2]) if len(keys) >= 2 and canon.endswith(("config.get", "cfg.get", "conf.get")) else keys[0])
                if v is None and len(keys) >= 2:
                    v = fc.config_value(keys[0]) or keys[-1]          # default argument
                if v is not None:
                    return v
        if isinstance(func, ast.Attribute):
            recv = fold(func.value, fc, local, depth)
            if func.attr == "format" and isinstance(recv, str):
                args = [fold(a, fc, local, depth) for a in expr.args]
                kws = {k.arg: fold(k.value, fc, local, depth) for k in expr.keywords if k.arg}
                try:
                    return recv.format(*[a if isinstance(a, str) else DYN for a in args],
                                       **{k: (v if isinstance(v, str) else DYN) for k, v in kws.items()})
                except (IndexError, KeyError, ValueError):
                    return recv
            if func.attr == "join" and isinstance(recv, str) and expr.args:
                items = fold(expr.args[0], fc, local, depth)
                if isinstance(items, list):
                    return recv.join(items)
                return DYN
            if func.attr in ("upper", "lower", "strip", "trim", "toUpperCase", "toLowerCase") and isinstance(recv, str):
                return recv
            if func.attr == "concat" and isinstance(recv, str):
                rest = [fold(a, fc, local, depth) for a in expr.args]
                return recv + "".join(r if isinstance(r, str) else DYN for r in rest)
        # helper functions in the project that build SQL text from their parameters
        name = func.id if isinstance(func, ast.Name) else (func.attr if isinstance(func, ast.Attribute) else "")
        fn = fc.funcs.get(name)
        if fn is not None:
            params = [a.arg for a in fn.args.posonlyargs + fn.args.args if a.arg not in ("self", "cls")]
            env = {}
            for p, a in zip(params, expr.args):
                v = fold(a, fc, local, depth)
                if v is not None:
                    env[p] = v
            for k in expr.keywords:
                v = fold(k.value, fc, local, depth)
                if k.arg and v is not None:
                    env[k.arg] = v
            return run_text_function(fn, fc, env, depth + 1)
        return None
    return None


def run_text_function(fn, fc: FoldContext, env: dict, depth: int):
    """Evaluate a straight-line function body (assignments, +=, return) to the text it returns."""
    local = dict(env)
    for st in fn.body:
        if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name):
            v = fold(st.value, fc, local, depth)
            if v is not None:
                local[st.targets[0].id] = v
        elif isinstance(st, ast.AugAssign) and isinstance(st.target, ast.Name) and isinstance(st.op, ast.Add):
            cur = local.get(st.target.id)
            add = fold(st.value, fc, local, depth)
            if isinstance(cur, str):
                local[st.target.id] = cur + (add if isinstance(add, str) else DYN)
            elif isinstance(cur, list) and isinstance(add, list):
                local[st.target.id] = cur + add
        elif isinstance(st, ast.Expr) and isinstance(st.value, ast.Call) and isinstance(st.value.func, ast.Attribute) \
                and st.value.func.attr in ("append", "push", "add") and isinstance(st.value.func.value, ast.Name) \
                and isinstance(local.get(st.value.func.value.id), list) and st.value.args:
            v = fold(st.value.args[0], fc, local, depth)
            local[st.value.func.value.id].append(v if isinstance(v, str) else DYN)
        elif isinstance(st, ast.Return):
            return fold(st.value, fc, local, depth)
    return None
