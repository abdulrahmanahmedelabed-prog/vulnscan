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


# --------------------------------------------------------------------------------------------- instrumentation
def _load(table, col, line):
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


def _write_stmt(table, col, expr, line):
    e = copy.deepcopy(expr)
    call = ast.Call(func=ast.Name(id=f"stored_db_write__{table}__{col}", ctx=ast.Load()), args=[e], keywords=[])
    st = ast.Expr(value=call)
    for x in (call, call.func, st):
        x.lineno = x.end_lineno = line
        x.col_offset = x.end_col_offset = 0
    return st


def model_names(trees: list) -> dict:
    """Model class simple name -> table name, across a project."""
    out = {}
    for text, tree in trees:
        sqlalchemy = "sqlalchemy" in text or "declarative_base" in text
        for n in ast.walk(tree):
            if isinstance(n, ast.ClassDef):
                bases = {_dotted(b) for b in n.bases}
                decos = {_dotted(d).split(".")[-1] for d in n.decorator_list}
                if (bases & (MODEL_BASES - {"Base"})) or ("Base" in bases and sqlalchemy) or (decos & ENTITY_DECOS):
                    out[n.name] = n.name.upper()
            elif isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and isinstance(n.value, ast.Call):
                canon = _dotted(n.value.func)
                if canon.endswith(MODEL_FACTORIES) and n.value.args and _const_str(n.value.args[0]):
                    out[n.targets[0].id] = _const_str(n.value.args[0]).upper()
    return out


class _Scope:
    def __init__(self, models, ctor_params):
        self.models = models
        self.ctor_params = ctor_params
        self.prepared: dict = {}     # var -> SQL text
        self.bound: dict = {}        # var -> table (ORM instance / loop row / JPA entity)
        self.consts: dict = {}       # var -> string constant

    # ------------------------------------------------------------------ helpers
    def sql_of(self, call):
        """(sql, index of the sql argument) for a call that carries SQL text."""
        for i, a in enumerate(call.args[:2]):
            s = _const_str(a)
            if s is None and isinstance(a, ast.Name):
                s = self.consts.get(a.id)
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
        if isinstance(st, (ast.Assign, ast.AnnAssign)) and getattr(st, "value", None) is not None:
            tgts = st.targets if isinstance(st, ast.Assign) else [st.target]
            v = st.value.value if isinstance(st.value, ast.Await) else st.value
            for t in tgts:
                if isinstance(t, ast.Name):
                    s = _const_str(v)
                    if s is not None:
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

    def call_writes(self, call) -> list:
        out = []
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


class _Rewriter(ast.NodeTransformer):
    def __init__(self, scope: _Scope):
        self.s = scope

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
        reads = self.s.call_reads(node)
        if reads:
            line = getattr(node, "lineno", 1)
            return _either([_load(t, c, line) for t, c in reads], _db_read(node))
        if self.s.is_fetch(node):
            return _db_read(node)
        return node

    def visit_Attribute(self, node):
        node.value = self.visit(node.value)
        if isinstance(node.ctx, ast.Load):
            reads = self.s.attr_reads(node)
            if reads:
                line = getattr(node, "lineno", 1)
                return _either([_load(t, c, line) for t, c in reads], _db_read(node))
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
            out.extend(_write_stmt(t, c, e, line) for t, c, e in writes)
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
        out.extend(_write_stmt(t, c, e, line) for t, c, e in writes)
        if scan and scan[1]:
            recv, names = scan
            for nm in names:                                   # out-parameters receive the row
                a = ast.Assign(targets=[ast.Name(id=nm.id, ctx=ast.Store())], value=copy.deepcopy(recv))
                for x in ast.walk(a):
                    x.lineno = x.end_lineno = line
                    x.col_offset = x.end_col_offset = 0
                out.append(a)
        if cursor_read:
            name, reads = cursor_read
            tgt = ast.Name(id=name, ctx=ast.Store())
            val = _either([_load(t, c, line) for t, c in reads], ast.Name(id=name, ctx=ast.Load()))
            a = ast.Assign(targets=[tgt], value=val)
            for x in (a, tgt, val.values[-1]):
                x.lineno = x.end_lineno = line
                x.col_offset = x.end_col_offset = 0
            out.append(a)
    return out


def instrument(tree: ast.Module, models: dict, ctor_params: dict) -> ast.Module:
    """Rewrite a module in place: explicit table writes / reads for the stored-data passes."""
    tree.body = _block(tree.body, _Scope(models, ctor_params))
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            n.body = _block(n.body, _Scope(models, ctor_params)) or n.body
    return tree


def ctor_param_names(trees: list, models: dict) -> dict:
    """Model class -> constructor parameter names (for positional `new Note(title, body)`)."""
    out = {}
    for _, tree in trees:
        for n in ast.walk(tree):
            if isinstance(n, ast.ClassDef) and n.name in models:
                for f in n.body:
                    if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef)) and f.name == "__init__":
                        out[n.name] = [a.arg for a in f.args.args if a.arg not in ("self", "cls")]
    return out


def has_store_writes(trees) -> bool:
    return any(isinstance(n, ast.Name) and n.id.startswith("stored_db_write__") for _, tree in trees for n in ast.walk(tree))
