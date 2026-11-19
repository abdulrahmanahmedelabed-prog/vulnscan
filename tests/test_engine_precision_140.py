"""1.4.0 engine precision: file-existence probes as path sinks, XXE decided by data flow, str facts through dict
slots / request field names / request-wrapper methods, and project classes built through a module path.
Every rule that marks something safe has a still-vulnerable twin."""

from __future__ import annotations

import textwrap

from vulnscan.scanner import scan_path
from vulnscan.taint import analyze

HEAD = """\
import os
import xml.dom.minidom
import xml.sax
import xml.sax.handler
import lxml.etree
from flask import Flask, request
app = Flask(__name__)
BASE = './files'
"""


def _lines(body: str, rule: str) -> set:
    code = HEAD + textwrap.dedent(body)
    first = len(HEAD.splitlines())
    return {f.line - first for f in analyze("app.py", code) if f.rule_id == rule}


def _marked(body: str, mark: str) -> set:
    return {i for i, line in enumerate(textwrap.dedent(body).splitlines(), 1) if line.rstrip().endswith(mark)}


def _check(body: str, rule: str) -> None:
    """Lines ending in `# VULN` must be reported for `rule`, lines ending in `# SAFE` must not."""
    got = _lines(body, rule)
    vuln, safe = _marked(body, "# VULN"), _marked(body, "# SAFE")
    assert vuln <= got, f"missed {sorted(vuln - got)}"
    assert not (safe & got), f"false positives {sorted(safe & got)}"


# ---------------------------------------------------------------- 1. existence / metadata probes are path sinks
def test_os_path_probes_are_path_sinks():
    _check("""
    @app.route('/a')
    def a():
        name = request.args.get('f')
        p = f'{BASE}/{name}'
        if os.path.exists(p):  # VULN
            return 'yes'
        return str(os.path.getsize(p)) + str(os.path.isfile(name)) + str(os.stat(p))  # VULN

    @app.route('/b')
    def b():
        name = request.args.get('f')
        if '..' in name:
            return 'no'
        p = f'{BASE}/{name}'
        return str(os.path.exists(p))  # SAFE

    @app.route('/c')
    def c():
        name = request.args.get('f')
        if '..' in name:
            return 'no'
        return str(os.path.exists(os.path.join(BASE, name)))  # VULN

    @app.route('/d')
    def d():
        name = request.args.get('f')
        p = os.path.realpath(os.path.join(BASE, name))
        if not p.startswith(os.path.realpath(BASE) + os.sep):
            return 'no'
        return str(os.path.isdir(p))  # SAFE

    @app.route('/e')
    def e():
        name = request.args.get('f')
        p = os.path.realpath(os.path.join(BASE, name))
        if not p.startswith(os.path.realpath(BASE)):
            return 'no'
        return str(os.path.isdir(p))  # VULN
    """, "DF011")


def test_dotdot_rejection_does_not_confine_a_path_join():
    _check("""
    import pathlib

    @app.route('/a')
    def a():
        name = request.args.get('f')
        if '..' in name:
            return 'no'
        return open(os.path.join(BASE, name)).read()  # VULN

    @app.route('/b')
    def b():
        name = request.args.get('f')
        if '..' in name:
            return 'no'
        p = os.path.join(BASE, name)
        return open(p).read()  # VULN

    @app.route('/c')
    def c():
        name = request.args.get('f')
        if '..' in name or os.path.isabs(name):
            return 'no'
        return open(os.path.join(BASE, name)).read()  # SAFE

    @app.route('/d')
    def d():
        name = request.args.get('f')
        if '..' in name:
            return 'no'
        return open(BASE + '/' + name).read()  # SAFE

    @app.route('/e')
    def e():
        name = request.args.get('f')
        if '..' in name:
            return 'no'
        return open(pathlib.Path(BASE) / name).read()  # VULN

    @app.route('/f')
    def f():
        name = request.args.get('f')
        if name not in ('a.txt', 'b.txt'):
            return 'no'
        return open(os.path.join(BASE, name)).read()  # SAFE
    """, "DF005")


# ---------------------------------------------------------------- 2. XXE: a parser with external entities on
def test_xxe_dataflow_needs_entities_turned_on_and_untrusted_xml():
    _check("""
    @app.route('/a', methods=['POST'])
    def a():
        doc = request.form.get('xml')
        parser = xml.sax.make_parser()
        parser.setFeature(xml.sax.handler.feature_external_ges, True)
        return xml.dom.minidom.parseString(doc, parser).toxml()  # VULN

    @app.route('/b', methods=['POST'])
    def b():
        doc = request.form.get('xml')
        parser = xml.sax.make_parser()
        return xml.dom.minidom.parseString(doc, parser).toxml()  # SAFE

    @app.route('/c', methods=['POST'])
    def c():
        doc = request.form.get('xml')
        m = {'a': '<r/>', 'b': doc}
        parser = xml.sax.make_parser()
        parser.setFeature(xml.sax.handler.feature_external_ges, True)
        return xml.dom.minidom.parseString(m['a'], parser).toxml()  # SAFE

    @app.route('/d', methods=['POST'])
    def d():
        doc = request.get_data()
        p = lxml.etree.XMLParser(resolve_entities=True, no_network=False)
        return lxml.etree.tostring(lxml.etree.fromstring(doc, p))  # VULN

    @app.route('/e', methods=['POST'])
    def e():
        doc = request.get_data()
        p = lxml.etree.XMLParser(resolve_entities=False)
        return lxml.etree.tostring(lxml.etree.fromstring(doc, p))  # SAFE

    @app.route('/f', methods=['POST'])
    def f():
        reader = xml.sax.make_parser()
        reader.setFeature(xml.sax.handler.feature_external_ges, True)
        reader.parse(request.files['doc'].stream)  # VULN
    """, "DF027")


XXE_APP = HEAD + textwrap.dedent("""
    @app.route('/const', methods=['POST'])
    def const():
        m = {'a': '<r/>', 'b': request.form.get('xml')}
        parser = xml.sax.make_parser()
        parser.setFeature(xml.sax.handler.feature_external_ges, True)
        return xml.dom.minidom.parseString(m['a'], parser).toxml()

    @app.route('/tainted', methods=['POST'])
    def tainted():
        parser = xml.sax.make_parser()
        parser.setFeature(xml.sax.handler.feature_external_ges, True)
        return xml.dom.minidom.parseString(request.form.get('xml'), parser).toxml()

    def wrapper(doc):
        parser = xml.sax.make_parser()
        parser.setFeature(xml.sax.handler.feature_external_ges, True)
        return xml.dom.minidom.parseString(doc, parser)

    def factory():
        parser = xml.sax.make_parser()
        parser.setFeature(xml.sax.handler.feature_external_ges, True)
        xml.dom.minidom.parseString('<r/>', parser)
        return parser

    def configure_only():
        p = lxml.etree.XMLParser(resolve_entities=True)
        CACHE.append(p)

    CACHE = []
    MODULE_PARSER = xml.sax.make_parser()
    MODULE_PARSER.setFeature(xml.sax.handler.feature_external_ges, True)
    """)


def _xxe001_functions(tmp_path, audit: bool) -> set:
    (tmp_path / "app.py").write_text(XXE_APP)
    findings = scan_path(tmp_path, [], set(), audit=audit)[0]
    lines = XXE_APP.splitlines()

    def owner(line):
        for i in range(line - 1, -1, -1):
            if lines[i].startswith("def "):
                return lines[i][4:].split("(")[0]
            if lines[i] and not lines[i].startswith((" ", "@")):
                return "<module>"
        return "<module>"
    return {(owner(f.line), bool(f.extra.get("audit"))) for f in findings if f.rule_id == "XXE001"}


def test_xxe_pattern_is_decided_by_dataflow_when_every_parse_is_traced(tmp_path):
    got = _xxe001_functions(tmp_path, audit=False)
    # constant XML: not reported by default
    assert not any(fn == "const" for fn, _ in got), got
    # untrusted XML, a parameter (the caller's data), a parser handed out, configured only, or at module level
    for fn in ("tainted", "wrapper", "factory", "configure_only", "<module>"):
        assert (fn, False) in got, (fn, got)


def test_xxe_pattern_on_constant_xml_stays_an_audit_lead(tmp_path):
    got = _xxe001_functions(tmp_path, audit=True)
    assert ("const", True) in got, got
    assert ("tainted", False) in got, got


# ---------------------------------------------------------------- 3. str facts: dict slots, field names, wrappers
def test_a_dict_slot_assigned_a_str_keeps_the_str_fact():
    _check("""
    @app.route('/a')
    def a():
        m = {}
        m['k'] = request.args.get('id')
        m['o'] = 'x'
        bar = m['k']
        root = lxml.etree.parse('e.xml')
        if "'" in bar:
            return 'no'
        return str(root.xpath(f"/E[@id='{bar}']"))  # SAFE

    @app.route('/b')
    def b():
        m = {}
        m['k'] = request.args.getlist('id')
        bar = m['k']
        root = lxml.etree.parse('e.xml')
        if "'" in bar:
            return 'no'
        return str(root.xpath(f"/E[@id='{bar}']"))  # VULN

    @app.route('/c')
    def c():
        m = {}
        m['k'] = request.args.get('id')
        m[request.args.get('key')] = request.get_json()
        bar = m['k']
        root = lxml.etree.parse('e.xml')
        if "'" in bar:
            return 'no'
        return str(root.xpath(f"/E[@id='{bar}']"))  # VULN

    @app.route('/d')
    def d():
        m = {}
        m['k'] = request.args.get('id')
        m.update(request.get_json())
        bar = m['k']
        root = lxml.etree.parse('e.xml')
        if "'" in bar:
            return 'no'
        return str(root.xpath(f"/E[@id='{bar}']"))  # VULN
    """, "DF015")


def test_request_field_names_are_str():
    _check("""
    @app.route('/a', methods=['POST'])
    def a():
        bar = ''
        for name in request.form.keys():
            bar = name
        root = lxml.etree.parse('e.xml')
        if "'" in bar:
            return 'no'
        return str(root.xpath(f"/E[@id='{bar}']"))  # SAFE

    @app.route('/b', methods=['POST'])
    def b():
        bar = ''
        for name in request.headers:
            bar = name
        root = lxml.etree.parse('e.xml')
        if "'" in bar:
            return 'no'
        return str(root.xpath(f"/E[@id='{bar}']"))  # VULN

    @app.route('/c', methods=['POST'])
    def c():
        bar = ''
        for name in request.form.values():
            bar = name
        root = lxml.etree.parse('e.xml')
        if "'" in bar:
            return 'no'
        return str(root.xpath(f"/E[@id='{bar}']"))  # VULN
    """, "DF015")


WRAPPERS = """
import flask
import lxml.etree
from flask import Flask, request
app = Flask(__name__)


class Wrapped:
    request: flask.Request

    def __init__(self, request: flask.Request):
        self.request = request

    def form(self, name: str):
        return self.request.form.get(name)

    def many(self, name: str):
        return self.request.form.getlist(name)


class Loose:
    def __init__(self, request):
        self.request = request

    def form(self, name: str):
        return self.request.form.get(name)


class Base:
    request: flask.Request

    def __init__(self, request: flask.Request):
        self.request = request

    def form(self, name: str):
        return self.request.form.get(name)


class Child(Base):
    def form(self, name: str):
        return self.request.get_json()[name]


def query(bar):
    root = lxml.etree.parse('e.xml')
    if "'" in bar:
        return 'no'
    return str(root.xpath(f"/E[@id='{bar}']"))


@app.route('/a')
def a():
    bar = Wrapped(request).form('id')
    root = lxml.etree.parse('e.xml')
    if "'" in bar:
        return 'no'
    return str(root.xpath(f"/E[@id='{bar}']"))  # SAFE


@app.route('/b')
def b():
    bar = Wrapped(request).many('id')
    root = lxml.etree.parse('e.xml')
    if "'" in bar:
        return 'no'
    return str(root.xpath(f"/E[@id='{bar}']"))  # VULN


@app.route('/c')
def c():
    bar = Loose(request).form('id')
    root = lxml.etree.parse('e.xml')
    if "'" in bar:
        return 'no'
    return str(root.xpath(f"/E[@id='{bar}']"))  # VULN


@app.route('/d')
def d():
    w = Base(request)
    bar = w.form('id')
    root = lxml.etree.parse('e.xml')
    if "'" in bar:
        return 'no'
    return str(root.xpath(f"/E[@id='{bar}']"))  # VULN
"""


def test_a_request_wrapper_method_returns_str_only_when_its_field_is_a_typed_request():
    got = {f.line for f in analyze("app.py", WRAPPERS) if f.rule_id == "DF015"}
    vuln, safe = _marked(WRAPPERS, "# VULN"), _marked(WRAPPERS, "# SAFE")
    assert vuln <= got, sorted(vuln - got)
    assert not (safe & got), sorted(safe & got)


# ---------------------------------------------------------------- 4. classes built through a module path
def test_a_project_class_built_through_its_module_path_is_resolved(tmp_path):
    (tmp_path / "helpers").mkdir()
    (tmp_path / "helpers" / "__init__.py").write_text("")
    (tmp_path / "helpers" / "box.py").write_text(
        "class holder:\n    def __init__(self, v):\n        self.v = v\n\n    def get(self):\n        return self.v\n")
    (tmp_path / "app.py").write_text(
        "import os\nfrom flask import Flask, request\napp = Flask(__name__)\n\n\n@app.route('/r')\ndef r():\n"
        "    import helpers.box\n    h = helpers.box.holder(request.args['c'])\n    os.system(h.get())\n"
        "    k = helpers.box.holder('ls')\n    os.system(k.get())\n")
    got = {(f.file, f.line) for f in scan_path(tmp_path, [], set())[0] if f.rule_id == "DF002"}
    assert ("app.py", 10) in got, got
    assert ("app.py", 12) not in got, got


# ---------------------------------------------------------------- 5. review round: XXE kept unless fully traced
XXE_PROBES = {
    # a parser whatever its variable name is a DF027 receiver (xml.sax reader, lxml feed parser)
    "sax1.py": ("import xml.sax\nfrom xml.sax.handler import feature_external_ges\nfrom flask import Flask, request\n"
                "app = Flask(__name__)\n\n@app.route('/upload', methods=['POST'])\ndef upload():\n"
                "    src = request.files['doc']\n    p = xml.sax.make_parser()\n    p.setFeature(feature_external_ges, True)\n"
                "    h = xml.sax.ContentHandler()\n    p.setContentHandler(h)\n    p.parse(src)\n    return 'ok'\n", True),
    "lx_feed.py": ("from lxml import etree\nfrom flask import Flask, request\napp = Flask(__name__)\n\n"
                   "@app.route('/feed', methods=['POST'])\ndef feed():\n    data = request.get_data()\n"
                   "    xp = etree.XMLParser(resolve_entities=True, load_dtd=True)\n    xp.feed(data)\n"
                   "    root = xp.close()\n    return root.tag\n", True),
    # lxml.objectify parses like lxml.etree
    "objectify1.py": ("from lxml import etree, objectify\nfrom flask import Flask, request\napp = Flask(__name__)\n\n"
                      "@app.route('/o', methods=['POST'])\ndef o():\n    body = request.data\n"
                      "    parser = etree.XMLParser(resolve_entities=True)\n    obj = objectify.fromstring(body, parser)\n"
                      "    return str(obj.name)\n", True),
    # the configured parser goes to a project helper the engine does not model as a parse
    "app.py": ("from flask import Flask, request\nfrom lxml import etree\nimport xmlutil\napp = Flask(__name__)\n\n"
               "@app.route('/h', methods=['POST'])\ndef h():\n    raw = request.data\n"
               "    parser = etree.XMLParser(resolve_entities=True)\n    doc = xmlutil.parse(raw, parser)\n"
               "    return doc.tag\n", False),
    "xmlutil.py": ("from lxml import etree\n\ndef parse(data, parser):\n    return etree.fromstring(data, parser)\n", None),
    # the parser is kept on the object; only a constant schema is parsed where it is configured
    "cls.py": ("import os\nfrom lxml import etree\n\nclass Importer:\n    def __init__(self):\n"
               "        self.parser = etree.XMLParser(resolve_entities=True, no_network=False)\n"
               "        xsd = os.path.join(os.path.dirname(__file__), 'schema.xsd')\n"
               "        self.schema = etree.XMLSchema(etree.parse(xsd))\n\n    def load(self, data):\n"
               "        doc = etree.fromstring(data, self.parser)\n        self.schema.assertValid(doc)\n        return doc\n",
               False),
    # returned inside a call / captured by a closure
    "ret_call.py": ("from lxml import etree\n\nclass Cfg:\n    def __init__(self, parser):\n        self.parser = parser\n\n"
                    "def build():\n    parser = etree.XMLParser(resolve_entities=True)\n"
                    "    etree.parse('schema.xsd', parser)\n    return Cfg(parser=parser)\n", False),
    "nested.py": ("from lxml import etree\n\ndef make_loader():\n    parser = etree.XMLParser(resolve_entities=True)\n"
                  "    etree.fromstring(b'<x/>', parser)\n    def load(data):\n        return etree.fromstring(data, parser)\n"
                  "    return load\n", False),
}


def test_xxe_pattern_stays_unless_every_use_of_the_parser_is_a_traced_parse(tmp_path):
    for name, (code, _) in XXE_PROBES.items():
        (tmp_path / name).write_text(code)
    findings = scan_path(tmp_path, [], set())[0]
    xxe = {f.file for f in findings if f.rule_id == "XXE001"}
    df = {f.file for f in findings if f.rule_id == "DF027"}
    for name, (_, dataflow) in XXE_PROBES.items():
        if dataflow is None:
            continue
        assert name in xxe, (name, sorted(xxe))
        if dataflow:
            assert name in df, (name, sorted(df))


def test_dict_slots_equal_keys_share_the_str_fact():
    _check("""
    @app.route('/a')
    def a():
        m = {}
        m[1] = request.args.get('id')
        m[True] = request.args.getlist('id')
        bar = m[1]
        root = lxml.etree.parse('e.xml')
        if "'" in bar:
            return 'no'
        return str(root.xpath(f"/E[@id='{bar}']"))  # VULN

    @app.route('/b')
    def b():
        m = {}
        m[1] = request.args.get('id')
        m[1.0] = request.args.getlist('id')
        bar = m[1]
        root = lxml.etree.parse('e.xml')
        if "'" in bar:
            return 'no'
        return str(root.xpath(f"/E[@id='{bar}']"))  # VULN

    @app.route('/c')
    def c():
        m = {}
        m[(1, 'a')] = request.args.get('id')
        m[(True, 'a')] = request.args.getlist('id')
        bar = m[(1, 'a')]
        root = lxml.etree.parse('e.xml')
        if "'" in bar:
            return 'no'
        return str(root.xpath(f"/E[@id='{bar}']"))  # VULN

    @app.route('/d')
    def d():
        m = {}
        m[1] = request.args.get('id')
        m[2] = request.args.getlist('id')
        bar = m[1]
        root = lxml.etree.parse('e.xml')
        if "'" in bar:
            return 'no'
        return str(root.xpath(f"/E[@id='{bar}']"))  # SAFE
    """, "DF015")
