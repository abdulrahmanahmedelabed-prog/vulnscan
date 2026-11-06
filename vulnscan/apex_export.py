"""Oracle APEX export reader.  (vulnscan: ignore-file)

An APEX application, page or plug-in export (``f100.sql``, ``application/pages/page_00010.sql``,
``plugin_*.sql``) is PL/SQL that *calls* ``wwv_flow_imp*.create_…`` procedures; the application's own code
lives inside their string arguments (``wwv_flow_string.join(wwv_flow_t_varchar2('line', 'line'))``, older
``'…'||unistr('\\000a')||'…'`` concatenations, and hex-encoded static files). This module:

1. walks every ``create_…`` call, decodes its arguments and classifies each code-bearing one by the
   component's type attributes (PL/SQL block, function body, function body returning SQL, PL/SQL
   expression, SQL query, JavaScript, HTML, AI prompt);
2. returns the code with its exact line in the export and a component label ("Page 10 › Process: Save")
   so the PL/SQL and JavaScript frontends can analyse it and findings point back into the export;
3. reports APEX-specific issues that are not data flow: ``&ITEM.`` substitution strings inside SQL /
   PL/SQL / JavaScript / AI prompts, ``!RAW`` substitutions in HTML, and disabled output escaping;
4. decodes plug-in / application static JavaScript files so they are analysed as well.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .model import Finding
from .plsql_frontend import tokenize

_DETECT = re.compile(r"wwv_flow_(?:imp|api)(?:_page|_shared)?\s*\.\s*create_", re.I)
_SUBST = re.compile(r"&([A-Z][A-Z0-9_$#]*)(?:!([A-Z]+))?\.")
BUILTIN_SUBST = {"APP_ID", "APP_PAGE_ID", "APP_SESSION", "APP_ALIAS", "APP_PAGE_ALIAS", "APP_IMAGES", "IMAGE_PREFIX",
                 "WORKSPACE_IMAGES", "THEME_IMAGES", "THEME_DB_IMAGES", "APP_FILES", "WORKSPACE_FILES", "APEX_FILES",
                 "APP_VERSION", "APP_TITLE", "DEBUG", "PRINTER_FRIENDLY", "WORKSPACE_ID", "HOME_LINK", "LOGIN_URL",
                 "LOGOUT_URL", "APP_DATE_TIME_FORMAT", "APP_NLS_DECIMAL_SEPARATOR", "APP_NLS_GROUP_SEPARATOR",
                 "JET_BASE_DIRECTORY", "JET_CSS_DIRECTORY", "APP_TEXT$", "APEX_CSP_NONCE_VALUE", "APP_BUILDER_SESSION",
                 "THEME_STYLE_CSS", "APP_UNIQUE_PAGE_ID", "FLOW_ID", "FLOW_PAGE_ID", "SESSION"}

COMPONENT_AR = {"page_process": "عملية", "flow_process": "عملية تطبيق", "page_plug": "منطقة", "page_item": "عنصر",
                "page_validation": "تحقق", "page_computation": "حساب", "flow_computation": "حساب تطبيق",
                "page_branch": "تفرّع", "page_da_event": "إجراء ديناميكي", "page_da_action": "إجراء ديناميكي",
                "plugin": "إضافة", "list_of_values": "قائمة قيم", "authentication": "مصادقة",
                "security_scheme": "تفويض", "page": "صفحة", "report_columns": "عمود", "worksheet_column": "عمود",
                "region_column": "عمود", "flow_item": "عنصر تطبيق", "ai_config": "إعداد الذكاء الاصطناعي",
                "ai_config_rag_source": "مصدر RAG", "web_source_module": "مصدر ويب", "page_button": "زر",
                "plugin_file": "ملف إضافة", "app_static_file": "ملف ثابت للتطبيق", "workspace_static_file": "ملف ثابت لمساحة العمل",
                "theme_file": "ملف سمة"}
APEX_RULES = [
    {"id": "APX001", "severity": "high", "cwe": "CWE-89", "title": "Substitution string inside SQL / PL/SQL",
     "title_ar": "سلسلة استبدال &ITEM. داخل SQL أو PL/SQL (حقن)", "advice": "استخدم متغير الربط :ITEM بدل &ITEM."},
    {"id": "APX002", "severity": "medium", "cwe": "CWE-79", "title": "Substitution string inside JavaScript without !JS",
     "title_ar": "سلسلة استبدال داخل JavaScript دون مرشّح !JS", "advice": "استخدم &ITEM!JS. أو apex.item().getValue()."},
    {"id": "APX003", "severity": "medium", "cwe": "CWE-79", "title": "Unescaped !RAW substitution in HTML",
     "title_ar": "استبدال غير مُهرَّب !RAW في HTML", "advice": "أزل !RAW أو هرّب القيمة."},
    {"id": "APX004", "severity": "medium", "cwe": "CWE-79", "title": "Output escaping disabled",
     "title_ar": "تهريب المخرجات معطّل", "advice": "أعد تفعيل Escape special characters."},
    {"id": "APX005", "severity": "high", "cwe": "CWE-1427", "title": "User-controlled item substituted into an AI prompt",
     "title_ar": "عنصر يتحكم به المستخدم يُستبدل داخل تعليمات المساعد الذكي", "advice": "لا تضع قيم المستخدم في تعليمات النظام."},
]

PLSQL_BLOCK = {"p_process_sql_clob", "p_process_sql", "p_plsql_function_body", "p_function_body", "p_plsql_process"}
PLSQL_DECLS = {"p_plsql_code"}
JS_PARAMS = {"p_javascript_code", "p_javascript_code_onload", "p_javascript_expression", "p_inline_js", "p_page_javascript_code"}
HTML_PARAMS = {"p_plug_header", "p_plug_footer", "p_html_expression", "p_column_html_expression", "p_pre_element_text",
               "p_post_element_text", "p_html_page_header", "p_html_page_onload", "p_tag_attributes", "p_help_text",
               "p_inline_help_text", "p_header", "p_footer", "p_column_link_text", "p_column_linktext", "p_link_text",
               "p_region_header", "p_region_footer", "p_body_header", "p_static_content"}
AI_PARAMS = {"p_system_prompt", "p_welcome_message", "p_user_prompt", "p_prompt", "p_initial_prompt"}
CODE_PARAMS = {"p_source", "p_item_default", "p_computation", "p_validation", "p_validation2", "p_condition_expression1",
               "p_display_when", "p_plug_source", "p_lov", "p_lov_query", "p_query", "p_query_text", "p_read_only_when",
               "p_plug_display_when_condition", "p_scheme", "p_source_query", "p_rag_source", "p_sql_query", "p_where_clause",
               "p_order_by_clause", "p_default_value"}
TYPE_OF = {"p_source": ["p_source_type", "p_source_language"], "p_item_default": ["p_item_default_type"],
           "p_computation": ["p_computation_type"], "p_validation": ["p_validation_type"], "p_validation2": ["p_validation_type"],
           "p_condition_expression1": ["p_condition_type"], "p_display_when": ["p_display_when_type"],
           "p_plug_source": ["p_query_type", "p_plug_source_type", "p_location", "p_function_body_language"],
           "p_read_only_when": ["p_read_only_when_type"], "p_plug_display_when_condition": ["p_plug_display_condition_type"],
           "p_scheme": ["p_scheme_type"], "p_default_value": ["p_default_value_type"], "p_rag_source": ["p_rag_source_type"],
           "p_source_query": ["p_source_type"], "p_sql_query": ["p_source_type"]}
ATTR_TYPES = ["p_action", "p_process_type", "p_scheme_type", "p_plug_source_type", "p_item_type", "p_display_as", "p_attribute_01"]
ESCAPE_OFF = {("p_display_as", "WITHOUT_MODIFICATION"), ("p_display_text_as", "WITHOUT_MODIFICATION"),
              ("p_escape_on_http_output", "N"), ("p_escape_on_http_output", "FALSE"), ("p_escape_on_http_input", "N")}
STATIC_FILE_CALLS = {"create_plugin_file", "create_app_static_file", "create_workspace_static_file", "create_theme_file"}


@dataclass
class Block:
    kind: str          # plsql | plsql_decls | plsql_fn | plsql_fn_sql | plsql_fn_html | plsql_expr | sql | js | html | ai
    code: str
    line: int          # export line of the first code line
    label: str         # "صفحة 10 › عملية: Save"
    unit: str          # identifier used for the lowered unit


def is_apex_export(text: str) -> bool:
    return bool(_DETECT.search(text[:400_000]))


def _value(toks: list) -> tuple:
    """Decode an argument expression -> (string or None, first line, raw upper-case scalar)."""
    if not toks:
        return None, 0, ""
    raw = " ".join(t.val for t in toks if t.kind in ("id", "num", "str")).upper()
    first = next((t.line for t in toks if t.kind == "str"), toks[0].line)
    vals = [t.val for t in toks]
    if len(toks) > 4 and vals[0] == "wwv_flow_string" and vals[2] == "join":
        # wwv_flow_string.join(wwv_flow_t_varchar2('a', 'b' || 'c', …))
        inner = toks[6:-2] if len(toks) > 8 else []
        elems, cur, depth = [], [], 0
        for t in inner:
            if t.kind == "punct" and t.val == "(":
                depth += 1
            elif t.kind == "punct" and t.val == ")":
                depth -= 1
            if t.kind == "punct" and t.val == "," and depth == 0:
                elems.append(cur)
                cur = []
                continue
            cur.append(t)
        if cur:
            elems.append(cur)
        return "\n".join(_concat(e) for e in elems), first, raw
    if any(t.kind == "str" for t in toks):
        return _concat(toks), first, raw
    return None, first, raw


def _concat(toks: list) -> str:
    out, i = [], 0
    while i < len(toks):
        t = toks[i]
        if t.kind == "str":
            out.append(t.val)
        elif t.kind == "id" and t.val == "unistr" and i + 2 < len(toks) and toks[i + 2].kind == "str":
            out.append(re.sub(r"\\([0-9A-Fa-f]{4})", lambda m: chr(int(m.group(1), 16)), toks[i + 2].val))
            i += 3
        elif t.kind == "id" and t.val == "chr" and i + 2 < len(toks) and toks[i + 2].kind == "num":
            try:
                out.append(chr(int(float(toks[i + 2].val))))
            except ValueError:
                pass
            i += 3
        elif t.kind == "id" and t.val in ("lf", "crlf") and i and toks[i - 1].val == ".":
            out.append("\n")
        i += 1
    return "".join(out)


def _args(toks: list, i: int) -> tuple[dict, int]:
    """At the '(' of a create_… call: {param: token list}, index after ')'."""
    depth, j = 0, i
    params: dict = {}
    name, cur = None, []
    while j < len(toks):
        t = toks[j]
        if t.kind == "punct" and t.val == "(":
            depth += 1
            if depth == 1:
                j += 1
                continue
        elif t.kind == "punct" and t.val == ")":
            depth -= 1
            if depth == 0:
                if name:
                    params[name] = cur
                return params, j + 1
        if depth == 1 and t.kind == "id" and j + 1 < len(toks) and toks[j + 1].val == "=>":
            if name:
                params[name] = cur
            name, cur = t.val, []
            j += 2
            continue
        if depth == 1 and t.kind == "punct" and t.val == ",":
            if name:
                params[name] = cur
            name, cur = None, []
            j += 1
            continue
        cur.append(t)
        j += 1
    return params, j


def _strip_comments(code: str) -> str:
    return re.sub(r"--[^\n]*|/\*.*?\*/", " ", code, flags=re.S).strip()


def _classify(fname: str, pname: str, text: str, decoded: dict) -> str | None:
    if re.fullmatch(r"[A-Z0-9_$#,:. \-]*", text.strip()):
        return None                                  # item lists, type codes, numbers
    if pname in JS_PARAMS:
        return "js"
    action = decoded.get("p_action", ("", 0, ""))[2]
    ai_attr = ("_AI" in action or "AI_" in action) and pname.startswith("p_attribute_")
    if pname in AI_PARAMS or "prompt" in pname or ai_attr or (fname.startswith("create_ai") and "message" in pname):
        body = _strip_comments(text).lower()
        if not body.startswith(("select", "with", "begin", "declare", "return")):
            return "ai"
    if pname in HTML_PARAMS:
        return "html"
    if pname in PLSQL_DECLS:
        return "plsql_decls" if re.search(r"\b(procedure|function)\b", text, re.I) else "plsql"
    if pname in PLSQL_BLOCK:
        return "plsql"
    if pname not in CODE_PARAMS and not pname.startswith("p_attribute_"):
        return None
    tparams = TYPE_OF.get(pname, []) if not pname.startswith("p_attribute_") else ATTR_TYPES
    typ = " ".join(decoded[p][2] for p in tparams if p in decoded and p != pname)
    if "JAVASCRIPT" in typ or (action == "NATIVE_JAVASCRIPT_CODE" and pname == "p_attribute_01"):
        return "js"
    body = _strip_comments(text).lower()
    if "RETURNING_SQL" in typ or "FUNC_BODY_RETURNING" in typ and "SQL" in typ:
        return "plsql_fn_sql"
    if "DYNAMIC_CONTENT" in typ:
        return "plsql_fn_html"
    if body.startswith(("select", "with")) or "QUERY" in typ or ("SQL" in typ and "PLSQL" not in typ):
        return "sql"
    if any(w in typ for w in ("FUNCTION_BODY", "FUNC_BODY", "FUNC_BOOLEAN", "FUNCTION_RETURNING", "FUNC_RETURN")):
        return "plsql_fn"
    if "EXPRESSION" in typ:
        return "plsql_expr"
    if "PLSQL" in typ or "EXECUTE_PLSQL" in action:
        return "plsql"
    if re.search(r":=|\bbegin\b.*\bend\b|;\s*$", body, re.S):
        return "plsql_fn" if re.search(r"\breturn\b", body) and not re.search(r"\bbegin\b", body) else "plsql"
    if pname == "p_plug_source":
        return "html"
    return None


def _wrap(kind: str, unit: str, code: str) -> str:
    """Wrap extracted APEX code as a PL/SQL unit; the prefix stays on the first code line so line numbers match."""
    if kind == "plsql_decls":
        return f"create package body {unit} as " + code + "\nend;\n/\n"
    if kind == "plsql":
        return f"create procedure {unit} is begin " + code + "\n;\nend;\n/\n"
    if kind in ("plsql_fn", "plsql_fn_sql", "plsql_fn_html"):
        sink = {"plsql_fn": "apex_eval", "plsql_fn_sql": "apex_dynamic_query", "plsql_fn_html": "htp.p"}[kind]
        return f"create procedure {unit} is function body_ return varchar2 is begin " + code + f"\n;\nend; begin {sink}(body_()); end;\n/\n"
    if kind == "plsql_expr":
        return f"create procedure {unit} is begin apex_eval(" + code + "\n); end;\n/\n"
    return ""


def _finding(rule, sev, title, title_ar, rel, line, snippet, advice, cwe, label):
    f = Finding(rule, sev, title, title_ar, rel, line, (f"[{label}] " if label else "") + snippet.strip()[:180], advice, cwe, source="apex")
    if label:
        f.extra["apex_component"] = label
    return f


def _subst_findings(block: Block, rel: str) -> list[Finding]:
    out = []
    for k, ln in enumerate(block.code.split("\n")):
        for m in _SUBST.finditer(ln):
            item, flt = m.group(1), (m.group(2) or "")
            if item in BUILTIN_SUBST or item.startswith("APP_TEXT$"):
                continue
            line = block.line + k
            if block.kind in ("sql", "plsql", "plsql_decls", "plsql_fn", "plsql_fn_sql", "plsql_fn_html", "plsql_expr"):
                code_kind = "SQL" if block.kind == "sql" else "PL/SQL"
                out.append(_finding("APX001", "high", f"Substitution string &{item}. inside {code_kind}",
                                    f"سلسلة استبدال &{item}. داخل {code_kind} (حقن)", rel, line, ln,
                                    f"APEX يستبدل &{item}. نصيًا قبل التنفيذ فيمكن حقن {code_kind}. استخدم متغير الربط :{item} أو v('{item}') بدلًا منها.",
                                    "CWE-89" if block.kind == "sql" else "CWE-94", block.label))
            elif block.kind == "js" and flt != "JS" and item not in ("APP_USER",):
                out.append(_finding("APX002", "medium", f"Substitution string &{item}. inside JavaScript",
                                    f"سلسلة استبدال &{item}. داخل JavaScript دون مرشّح !JS", rel, line, ln,
                                    f"استخدم &{item}!JS. أو اقرأ القيمة بـ apex.item('{item}').getValue() بدل الاستبدال النصي.",
                                    "CWE-79", block.label))
            elif block.kind == "html" and flt == "RAW":
                out.append(_finding("APX003", "medium", f"Unescaped substitution &{item}!RAW. in HTML",
                                    f"استبدال غير مُهرَّب &{item}!RAW. في HTML", rel, line, ln,
                                    "أزل !RAW (الافتراضي يهرّب HTML) أو هرّب القيمة قبل تخزينها في العنصر.", "CWE-79", block.label))
            elif block.kind == "ai" and item not in ("APP_USER",):
                out.append(_finding("APX005", "high", f"User-controlled item &{item}. substituted into an AI prompt",
                                    f"عنصر يتحكم به المستخدم &{item}. يُستبدل داخل تعليمات المساعد الذكي (حقن التعليمات)", rel, line, ln,
                                    "لا تضع قيم المستخدم في تعليمات النظام؛ مرّرها كرسالة مستخدم، وقيّد ما يستطيع المساعد الوصول إليه.",
                                    "CWE-1427", block.label))
    return out


def extract(text: str, rel: str) -> tuple[list[Block], list[Finding], list[tuple[str, str]]]:
    """Returns (code blocks, APEX findings, decoded static files [(virtual path, text)])."""
    toks = tokenize(text)
    lines = text.split("\n")
    blocks: list[Block] = []
    findings: list[Finding] = []
    files: list[tuple[str, str]] = []
    page = None
    da_event = None
    hexbuf: list[str] = []
    seq = 0
    region_tables: dict = {}         # region id (raw) -> table, for form regions
    form_tables: dict = {}           # page -> table of a legacy automatic row processing (DML) process
    form_items: list = []            # (page, item, column, region id raw, line, label)
    i, n = 0, len(toks)
    while i < n:
        t = toks[i]
        if t.kind == "id" and t.val == "g_varchar2_table" and i + 5 < n and toks[i + 1].val == "(" \
                and toks[i + 4].val == ":=" and toks[i + 5].kind == "str":     # g_varchar2_table(1) := 'HEX…'
            hexbuf.append(toks[i + 5].val)
            i += 6
            continue
        if t.kind == "id" and t.val == "empty_varchar2_table":
            hexbuf = []
            i += 1
            continue
        if not (t.kind == "id" and t.val.startswith("wwv_flow") and i + 3 < n and toks[i + 1].val == "."
                and toks[i + 2].kind == "id" and toks[i + 2].val.startswith("create_") and toks[i + 3].val == "("):
            i += 1
            continue
        fname = toks[i + 2].val
        page_scoped = toks[i].val.endswith("_page") or fname.startswith("create_page")
        params, i = _args(toks, i + 3)
        decoded = {k: _value(v) for k, v in params.items()}
        comp = fname[len("create_"):]
        if fname == "create_page":
            pid = decoded.get("p_id", (None, 0, ""))[2]
            page = pid or page
        if fname == "create_page_da_event":
            da_event = decoded.get("p_name", (None,))[0]
        name = next((decoded[p][0] for p in ("p_process_name", "p_plug_name", "p_name", "p_validation_name", "p_lov_name",
                                             "p_computation_item", "p_button_name", "p_column_alias", "p_db_column_name",
                                             "p_static_id", "p_display_name") if decoded.get(p, (None,))[0]), None)
        if fname == "create_page_da_action" and da_event:
            name = da_event
        pg = decoded.get("p_page_id", (None, 0, ""))[2] or decoded.get("p_flow_step_id", (None, 0, ""))[2] or (page if page_scoped else None)
        comp_ar = COMPONENT_AR.get(comp, comp)
        label = (f"صفحة {pg} › " if pg else "") + comp_ar + (f": {name}" if name else "")
        # implicit DML: a form region on a table, and page items whose source is one of its columns
        if fname == "create_page_plug" and decoded.get("p_query_table", (None,))[0]:
            region_tables[decoded.get("p_id", (None, 0, ""))[2]] = decoded["p_query_table"][0].upper().split(".")[-1]
        if fname in ("create_page_process", "create_page_process_dml") and any(
                x in decoded.get("p_process_type", (None, 0, ""))[2] for x in ("FORM_DML", "FORM_FETCH", "DML", "ROW")):
            tbl = decoded.get("p_attribute_02", (None,))[0] or decoded.get("p_attribute_01", (None,))[0]
            if tbl and re.fullmatch(r"[A-Za-z][\w$#.]*", tbl):
                form_tables[pg] = tbl.upper().split(".")[-1]
        if fname == "create_page_item":
            stype = decoded.get("p_source_type", (None, 0, ""))[2]
            col = decoded.get("p_source", (None,))[0]
            if col and ("REGION_SOURCE_COLUMN" in stype or "DB_COLUMN" in stype) and re.fullmatch(r"[A-Za-z][\w$#]*", col.strip()):
                form_items.append((pg, name, col.strip().upper(), decoded.get("p_item_source_plug_id", (None, 0, ""))[2],
                                   decoded.get("p_source", (None, 0))[1], label))
        # disabled output escaping
        for p, (val, ln, raw) in decoded.items():
            if (p, raw.strip()) in ESCAPE_OFF:
                findings.append(_finding("APX004", "medium", "Output escaping disabled", "تهريب المخرجات معطّل (XSS محتمل)",
                                         rel, ln, lines[ln - 1] if 0 < ln <= len(lines) else p,
                                         "أعد تفعيل Escape special characters، أو هرّب القيمة بـ apex_escape.html في الاستعلام.", "CWE-79", label))
        # static JavaScript files (plug-ins, application / workspace / theme files)
        if fname in STATIC_FILE_CALLS and hexbuf:
            fn_name = decoded.get("p_file_name", (None,))[0] or f"file_{len(files) + 1}"
            if fn_name.lower().endswith((".js", ".mjs")):
                try:
                    content = bytes.fromhex("".join(hexbuf)).decode("utf-8", "replace")
                    files.append((f"{rel}!{comp_ar}/{fn_name}", content))
                except ValueError:
                    pass
            hexbuf = []
        for p, (val, ln, raw) in decoded.items():
            if not val or len(val.strip()) < 2:
                continue
            kind = _classify(fname, p, val, decoded)
            if not kind:
                continue
            seq += 1
            unit = re.sub(r"\W", "_", f"apex_{'p' + str(pg) + '_' if pg else ''}{comp}_{seq}").lower()
            b = Block(kind, val, ln, label, unit)
            blocks.append(b)
            findings.extend(_subst_findings(b, rel))
    blocks.extend(_form_store_blocks(form_items, region_tables, form_tables))
    return blocks, findings, files


def _form_store_blocks(form_items, region_tables, form_tables) -> list[Block]:
    """Page items saved by a form region / automatic row processing -> stored_db_write__T__C(:ITEM) blocks."""
    out = []
    for k, (pg, item, col, plug, line, label) in enumerate(form_items):
        table = region_tables.get(plug) or form_tables.get(pg)
        if not table or not item:
            continue
        code = f"stored_db_write__{table}__{col}(:{item.upper()});"
        out.append(Block("plsql", code, line, f"{label} (يُحفظ في {table}.{col})",
                         re.sub(r"\W", "_", f"apex_form_{pg}_{item}_{k}").lower()))
    return out


def wrapped_plsql(block: Block) -> str:
    return _wrap(block.kind, block.unit, block.code)


def anchor_wrapper_sink(block: Block, units: list) -> None:
    """For function bodies the generated sink call (apex_dynamic_query / htp.p / apex_eval) sits after the code;
    point it at the last `return` so findings land on the line that builds the value."""
    if not block.kind.startswith("plsql_fn"):
        return
    import ast as _ast
    for u in units:
        for fn in u.body:
            if not isinstance(fn, _ast.FunctionDef) or not fn.body:
                continue
            inner = next((n for n in fn.body if isinstance(n, _ast.FunctionDef) and n.name == "body_"), None)
            if inner is None:
                continue
            rets = [n.lineno for n in _ast.walk(inner) if isinstance(n, _ast.Return)]
            if rets:
                for n in _ast.walk(fn.body[-1]):
                    if hasattr(n, "lineno"):
                        n.lineno = n.end_lineno = max(rets)


# =============================================================== readable YAML export (APEX 23.2+)
_YAML_HEADER = re.compile(r"^(\s*)(?:-\s*)?#\s*=+\s*([^:=]+?)\s*:\s*(.*?)\s*=*\s*$")
_YAML_KEY = re.compile(r"^(\s*)(-\s+)?([A-Za-z0-9_/().\-]+(?: [A-Za-z0-9_/().\-]+)*)\s*:(?:\s+(.*?))?\s*$")
YAML_HEADER_AR = {"page": "صفحة", "region": "منطقة", "process": "عملية", "page item": "عنصر", "item": "عنصر",
                  "dynamic action": "إجراء ديناميكي", "action": "إجراء ديناميكي", "validation": "تحقق", "computation": "حساب",
                  "column": "عمود", "branch": "تفرّع", "button": "زر", "plug-in": "إضافة", "plugin": "إضافة",
                  "list of values": "قائمة قيم", "authorization": "تفويض", "authentication": "مصادقة",
                  "application process": "عملية تطبيق", "application item": "عنصر تطبيق", "ai configuration": "إعداد الذكاء الاصطناعي",
                  "rest data source": "مصدر REST", "web source": "مصدر ويب", "rag source": "مصدر RAG"}
YAML_JS_KEYS = {"code", "javascript-code", "function-and-global-variable-declaration", "execute-when-page-loads",
                "javascript-expression", "javascript-initialization-code", "initialization-javascript-function", "javascript"}
YAML_HTML_KEYS = {"html-code", "html-expression", "text", "header", "footer", "pre-text", "post-text", "html", "link-text",
                  "column-formatting", "help-text", "inline-help-text", "html-header", "page-html-body-attribute"}


def is_apex_yaml(text: str, rel: str = "") -> bool:
    head = text[:200_000]
    if not re.search(r"^\s*-?\s*#\s*=+\s*(Page|Region|Process|Application|Plug-?in|List of Values|Page Item|Shared Component)", head, re.M | re.I):
        return False
    return "readable" in rel.replace("\\", "/").lower() or bool(re.search(r"^\s*identification\s*:", head, re.M))


def _yaml_scalar(v: str) -> str:
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] == "'":
        return v[1:-1].replace("''", "'")
    if len(v) >= 2 and v[0] == v[-1] == '"':
        return v[1:-1].encode("utf-8").decode("unicode_escape", "replace") if "\\" in v else v[1:-1]
    return v


def _yaml_classify(key: str, siblings: dict) -> str | None:
    k = key.lower()
    lang = (siblings.get("language", "") + " " + siblings.get("type", "")).lower()
    if "prompt" in k or "welcome-message" in k:
        return "ai"
    if "pl/sql" in k or "plsql" in k:
        if "returning" in k and "sql" in k.split("returning", 1)[1]:
            return "plsql_fn_sql"
        if "returning" in k and "clob" in k:
            return "plsql_fn_html"
        if "function-body" in k:
            if "returning sql" in lang:
                return "plsql_fn_sql"
            if "clob" in lang or "dynamic content" in lang:
                return "plsql_fn_html"
            return "plsql_fn"
        if "expression" in k:
            return "plsql_expr"
        return "plsql"
    if "sql-query" in k or k in ("sql", "sql-statement", "query", "list-of-values-query", "lov-query", "sql-query-returning-values"):
        return "sql"
    if "function-body" in k:
        return "plsql_fn"
    if k in YAML_JS_KEYS:
        if "pl/sql" in lang or "plsql" in lang:
            return "plsql"
        if lang.strip().startswith("sql") or " sql" in lang:
            return "sql"
        return "js"
    if "javascript" in k:
        return "js"
    if k in YAML_HTML_KEYS or "html" in k:
        return "html"
    return None


def extract_yaml(text: str, rel: str) -> tuple[list[Block], list[Finding], list[tuple[str, str]]]:
    """APEX readable export (YAML): code properties -> blocks at their real lines, labelled by component."""
    lines = text.split("\n")
    blocks: list[Block] = []
    findings: list[Finding] = []
    page_id = page_name = None
    comp = name = None
    da_name = None
    seq = 0
    # mapping scopes: indent -> {key: scalar}; reset when a line at a smaller indent starts
    scopes: list[tuple[int, dict]] = []
    region_tables: dict = {}
    form_items: list = []
    i, n = 0, len(lines)
    while i < n:
        raw = lines[i]
        h = _YAML_HEADER.match(raw)
        if h:
            kind, nm = h.group(2).strip().lower(), h.group(3).strip()
            if kind == "page":
                page_name, page_id = nm, None
            elif kind == "dynamic action":
                da_name = nm
            comp, name = kind, nm
            i += 1
            continue
        m = _YAML_KEY.match(raw)
        if not m or raw.lstrip().startswith("#"):
            i += 1
            continue
        indent = len(m.group(1)) + (len(m.group(2)) if m.group(2) else 0)
        if m.group(2):                       # a new list item starts a new mapping at this indent
            scopes = [(ind, d) for ind, d in scopes if ind < indent]
        scopes = [(ind, d) for ind, d in scopes if ind <= indent]
        if not scopes or scopes[-1][0] != indent:
            scopes.append((indent, {}))
        key, val = m.group(3), (m.group(4) or "")
        here = scopes[-1][1]
        if key == "id" and comp == "page" and page_id is None and indent == 0:
            page_id = _yaml_scalar(val)
        code, start = None, i + 1
        if val[:1] in ("|", ">"):             # block scalar
            j = i + 1
            body: list[str] = []
            base = None
            while j < n:
                ln = lines[j]
                if ln.strip() == "":
                    body.append("")
                    j += 1
                    continue
                ind = len(ln) - len(ln.lstrip(" "))
                if ind <= indent:
                    break
                if base is None:
                    base = ind
                body.append(ln[base:] if ind >= base else ln.lstrip())
                j += 1
            while body and body[-1] == "":
                body.pop()
            code, start = "\n".join(body), i + 2
            i = j
        else:
            here[key] = _yaml_scalar(val)
            if val and key not in ("id",):
                code, start = _yaml_scalar(val), i + 1
            i += 1
        # sibling scalars already seen in this mapping, plus the ones that follow it (look ahead)
        sib = dict(here)
        k2 = i
        while k2 < n and k2 < i + 40:
            m2 = _YAML_KEY.match(lines[k2])
            if m2:
                ind2 = len(m2.group(1)) + (len(m2.group(2)) if m2.group(2) else 0)
                if ind2 < indent or (m2.group(2) and ind2 <= indent):
                    break
                if ind2 == indent and m2.group(4) and m2.group(4)[:1] not in ("|", ">"):
                    sib.setdefault(m2.group(3), _yaml_scalar(m2.group(4)))
            k2 += 1
        if key == "table-name" and comp == "region" and here.get(key):
            region_tables[name] = here[key].upper().split(".")[-1]
        if key == "column" and comp in ("page item", "item") and here.get(key) and sib.get("form-region"):
            form_items.append((page_id, name, here[key].upper(), sib["form-region"], i, _yaml_label(page_id, page_name, comp, name, da_name)))
        if key == "escape-special-characters" and str(here.get(key, "")).lower() in ("false", "no", "n"):
            label = _yaml_label(page_id, page_name, comp, name, da_name)
            findings.append(_finding("APX004", "medium", "Output escaping disabled", "تهريب المخرجات معطّل (XSS محتمل)",
                                     rel, i, lines[i - 1], "أعد تفعيل Escape special characters، أو هرّب القيمة بـ apex_escape.html.",
                                     "CWE-79", label))
        if not code or len(code.strip()) < 2 or re.fullmatch(r"[A-Za-z0-9_$#,:. \-]*", code.strip()) and "&" not in code:
            continue
        kind = _yaml_classify(key, sib)
        if not kind:
            continue
        seq += 1
        label = _yaml_label(page_id, page_name, comp, name, da_name)
        unit = re.sub(r"\W", "_", f"apex_{'p' + str(page_id) + '_' if page_id else ''}{comp or 'component'}_{seq}").lower()
        b = Block(kind, code, start, label, unit)
        blocks.append(b)
        findings.extend(_subst_findings(b, rel))
    blocks.extend(_form_store_blocks(form_items, region_tables, {}))
    return blocks, findings, []


def _yaml_label(page_id, page_name, comp, name, da_name) -> str:
    comp_ar = YAML_HEADER_AR.get(comp or "", comp or "")
    if comp == "action" and da_name:
        name = da_name
    if comp == "page":
        return f"صفحة {page_id or page_name}"
    prefix = f"صفحة {page_id} › " if page_id else ""
    return prefix + comp_ar + (f": {name}" if name else "")


# ======================================================================= ORDS REST handlers
_ORDS_CALL = re.compile(r"^(?:\w+\.)?(?:ords|ords_services|ords_metadata\.ords_services)\.(define_handler|define_service|create_handler|create_service)$")
ORDS_POSITIONAL = {"define_handler": ["p_module_name", "p_pattern", "p_method", "p_source_type", "p_source"],
                   "define_service": ["p_module_name", "p_base_path", "p_pattern", "p_method", "p_source_type", "p_source"]}
ORDS_PLSQL_TYPES = ("PLSQL", "PLSQL/BLOCK", "SOURCE_TYPE_PLSQL")


def has_ords(text: str) -> bool:
    return bool(re.search(r"\bords(?:_services|_metadata)?\s*\.\s*(define_handler|define_service|create_handler|create_service)\b", text, re.I))


def extract_ords(text: str, rel: str, toks=None) -> list[Block]:
    """ORDS.DEFINE_HANDLER / DEFINE_SERVICE calls (in .sql, inside XML changelogs, anywhere PL/SQL appears):
    the handler source becomes a block — PL/SQL handlers as code, query handlers as SQL."""
    if not has_ords(text):
        return []
    toks = toks or tokenize(text)
    blocks: list[Block] = []
    i, n, seq = 0, len(toks), 0
    while i < n:
        t = toks[i]
        if t.kind != "id" or not t.val.startswith("ords"):
            i += 1
            continue
        j, name = i, t.val
        while j + 2 < n and toks[j + 1].val == "." and toks[j + 2].kind == "id":
            name += "." + toks[j + 2].val
            j += 2
        if j + 1 >= n or toks[j + 1].val != "(" or not _ORDS_CALL.match(name):
            i += 1
            continue
        fn = name.rsplit(".", 1)[-1]
        params, end = _args(toks, j + 1)
        if not params:                                  # positional call
            params = _positional(toks, j + 1, ORDS_POSITIONAL.get(fn, []))
        decoded = {k: _value(v) for k, v in params.items()}
        src, line, _ = decoded.get("p_source", (None, 0, ""))
        if src and src.strip():
            stype = decoded.get("p_source_type", (None, 0, ""))
            stype_text = ((stype[0] or "") + " " + stype[2]).upper().replace("ORDS.", "")
            kind = "plsql" if any(x in stype_text for x in ORDS_PLSQL_TYPES) or re.match(r"\s*(begin|declare)\b", src, re.I) else "sql"
            module = decoded.get("p_module_name", (None,))[0] or ""
            method = (decoded.get("p_method", (None,))[0] or "GET").upper()
            pattern = decoded.get("p_pattern", (None,))[0] or decoded.get("p_base_path", (None,))[0] or ""
            seq += 1
            label = f"ORDS › {module} {method} {pattern}".strip()
            blocks.append(Block(kind, src, line, label, re.sub(r"\W", "_", f"ords_{module}_{method}_{seq}").lower()))
        i = end
    return blocks


def _positional(toks, i, names) -> dict:
    """Arguments of a positional call -> {param name: tokens}."""
    out, depth, cur, k = {}, 0, [], 0
    j = i
    while j < len(toks):
        t = toks[j]
        if t.kind == "punct" and t.val == "(":
            depth += 1
            if depth == 1:
                j += 1
                continue
        elif t.kind == "punct" and t.val == ")":
            depth -= 1
            if depth == 0:
                break
        if depth == 1 and t.kind == "punct" and t.val == ",":
            if k < len(names):
                out[names[k]] = cur
            k, cur = k + 1, []
            j += 1
            continue
        cur.append(t)
        j += 1
    if cur and k < len(names):
        out[names[k]] = cur
    return out


# ============================================================ PL/SQL inside XML (Liquibase / SQLcl)
_XML_SCRIPT = re.compile(r"<!\[CDATA\[(.*?)\]\]>|<(?:\w+:)?(?:sql|source|createProcedure|sqlFile)\b[^>]*>(.*?)</(?:\w+:)?(?:sql|source|createProcedure)>", re.S | re.I)


def is_oracle_container(text: str, rel: str) -> bool:
    """A non-.sql file that carries Oracle code: APEX readable YAML, Liquibase/SQLcl XML with PL/SQL, ORDS JSON."""
    low = rel.lower()
    head = text[:2_000_000]
    if low.endswith((".yaml", ".yml")):
        return is_apex_yaml(text, rel)
    if low.endswith(".xml"):
        return bool(re.search(r"runOracleScript|<!\[CDATA\[\s*(begin|declare|create\s+or\s+replace)|ords\s*\.\s*define_", head, re.I))
    if low.endswith(".json"):
        keyed = bool(re.search(r'"(p_)?source"\s*:\s*"[^"]*(select|begin|declare)', head, re.I)) and bool(
            re.search(r'"(p_)?(source_?type|method|pattern|uri_template|module)"', head, re.I))
        return keyed or bool(_JSON_PLSQL_VALUE.search(head))
    return False


def xml_scripts(text: str) -> list[tuple[int, str]]:
    """PL/SQL / SQL scripts embedded in XML (CDATA or <sql>/<source> elements) -> [(first line, script)]."""
    out = []
    for m in _XML_SCRIPT.finditer(text):
        body = m.group(1) if m.group(1) is not None else m.group(2)
        if not body or not re.search(r"\b(begin|declare|create|select|ords\.)", body, re.I):
            continue
        start_off = m.start(1) if m.group(1) is not None else m.start(2)
        if m.group(1) is None and "<![CDATA[" in body:     # <source><![CDATA[ … ]]></source>: drop the wrapper, keep lines
            body = body.replace("<![CDATA[", " " * 9).replace("]]>", "   ")
        elif m.group(1) is None:
            body = re.sub(r"&lt;", "<", re.sub(r"&gt;", ">", re.sub(r"&quot;", '"', re.sub(r"&apos;", "'", body)))).replace("&amp;", "&")
        out.append((text.count("\n", 0, start_off) + 1, body))
    return out


# a JSON string holding a whole PL/SQL block: begin/declare … at least one statement ';' … end
_JSON_PLSQL_VALUE = re.compile(r'"\s*(?:declare|begin)(?:\\n|\s)(?:[^"\\]|\\.)*?;(?:[^"\\]|\\.)*?(?:\\n|[^A-Za-z0-9_])end\s*;?\s*(?:\\n)?\s*"', re.I)
_PLSQL_BLOCK = re.compile(r"^\s*(declare|begin)\s.*;.*[^\w]end\s*;?\s*$", re.I | re.S)


def extract_json_ords(text: str, rel: str) -> list[Block]:
    """REST definitions in JSON (ORDS module/handler objects): objects with a source and a source type / method."""
    import json
    try:
        data = json.loads(text)
    except ValueError:
        return []
    blocks: list[Block] = []
    seq = 0
    # flat exports of the ORDS metadata views (USER_ORDS_MODULES / _TEMPLATES / _HANDLERS, e.g. SQL Developer's
    # JSON export {"results":[{"items":[…]}]}) link handlers to templates and modules by id
    modules_by_id: dict = {}
    templates_by_id: dict = {}

    def index(o):
        if isinstance(o, dict):
            low = {k.lower(): v for k, v in o.items()}
            if "id" in low and "uri_prefix" in low and isinstance(low.get("name"), str):
                modules_by_id[str(low["id"])] = low["name"]
            if "id" in low and "uri_template" in low and ("module_id" in low or "handlers" not in low):
                templates_by_id[str(low["id"])] = (str(low.get("uri_template") or ""), str(low.get("module_id") or ""))
            for v in o.values():
                index(v)
        elif isinstance(o, list):
            for v in o:
                index(v)

    index(data)

    keyed_ids: set = set()

    def walk(o, module="", path="$"):
        nonlocal seq
        if isinstance(o, str):
            # any string that is a whole PL/SQL block is code, whatever its key is called
            if id(o) not in keyed_ids and _PLSQL_BLOCK.match(o):
                needle = json.dumps(o, ensure_ascii=False)[1:40]
                pos = text.find(needle) if needle else -1
                line = text.count("\n", 0, pos) + 1 if pos >= 0 else 1
                seq += 1
                blocks.append(Block("plsql", " ".join(re.sub(r"--[^\n]*", " ", o).split("\n")), line, f"JSON › {path}",
                                    re.sub(r"\W", "_", f"json_block_{seq}").lower()))
            return
        if isinstance(o, dict):
            low = {k.lower(): v for k, v in o.items()}
            module = low.get("name") if isinstance(low.get("name"), str) and ("handlers" in low or "templates" in low or "uri_prefix" in low) else module
            if "template_id" in low and str(low["template_id"]) in templates_by_id:
                tpl, mod_id = templates_by_id[str(low["template_id"])]
                low.setdefault("uri_template", tpl)
                module = modules_by_id.get(mod_id, module)
            elif "module_id" in low and str(low["module_id"]) in modules_by_id:
                module = modules_by_id[str(low["module_id"])]
            src = low.get("source") or low.get("p_source") or low.get("handler_source")
            if isinstance(src, str) and re.search(r"\b(select|begin|declare|with)\b", src, re.I):
                stype = str(low.get("source_type") or low.get("sourcetype") or low.get("p_source_type") or "").upper()
                kind = "plsql" if "PLSQL" in stype or re.match(r"\s*(begin|declare)\b", src, re.I) else "sql"
                method = str(low.get("method") or "GET").upper()
                pattern = str(low.get("uri_template") or low.get("pattern") or low.get("uritemplate") or "")
                needle = json.dumps(src, ensure_ascii=False)[1:40]
                pos = text.find(needle) if needle else -1
                line = text.count("\n", 0, pos) + 1 if pos >= 0 else 1
                seq += 1
                keyed_ids.add(id(src))
                # the whole source sits on one JSON line: keep it on one line so findings point there
                code = " ".join(re.sub(r"--[^\n]*", " ", src).split("\n"))
                blocks.append(Block(kind, code, line, f"ORDS › {module} {method} {pattern}".strip(),
                                    re.sub(r"\W", "_", f"ords_json_{module}_{method}_{seq}").lower()))
            for k, v in o.items():
                walk(v, module, f"{path}.{k}")
        elif isinstance(o, list):
            for i, v in enumerate(o):
                walk(v, module, f"{path}[{i}]")

    walk(data)
    return blocks
