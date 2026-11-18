"""1.2.0 engine precision: guards that end the request, configparser slots, response headers, string rebinding,
URL host allow-lists, confined paths and fixed Flask routes. Every safe case has a still-vulnerable twin."""

from __future__ import annotations

import textwrap

from vulnscan.taint import analyze

HEAD = """\
import configparser
import os
import pathlib
import urllib.parse
import elementpath
import lxml.etree
from flask import Flask, request, make_response, redirect, Blueprint
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


# ---------------------------------------------------------------- 1. guards that end the request
def test_dotdot_rejection_confines_a_path_under_a_fixed_directory():
    _check(r"""
    @app.route('/a')
    def a():
        name = request.args.get('f')
        file_name = None
        if '..' in name:
            return 'no'
        file_name = f'{BASE}/{name}'
        return open(file_name).read()  # SAFE

    @app.route('/a2')
    def a2():
        name = request.args.get('f')
        file_name = None
        if '../' in name or '..\\' in name:
            return 'no'
        file_name = f'{BASE}/{name}'
        return open(file_name).read()  # SAFE

    @app.route('/win')
    def win():
        name = request.args.get('f')
        file_name = None
        if '../' in name:
            return 'no'
        file_name = f'{BASE}/{name}'
        return open(file_name).read()  # VULN

    @app.route('/b')
    def b():
        name = request.args.get('f')
        if '..' in name:
            print('suspicious')
        file_name = None
        file_name = f'{BASE}/{name}'
        return open(file_name).read()  # VULN

    @app.route('/c')
    def c():
        name = request.args.get('f')
        if '../' in name:
            return 'no'
        name = request.args.get('g')
        file_name = None
        file_name = f'{BASE}/{name}'
        return open(file_name).read()  # VULN

    """, "DF005")


def test_dotdot_rejection_is_not_a_sanitizer_for_a_command():
    _check("""
    @app.route('/d')
    def d():
        name = request.args.get('f')
        if '../' in name:
            return 'no'
        os.system(f'cat {BASE}/{name}')  # VULN
    """, "DF002")


def test_dotdot_rejection_needs_a_directory_prefix_and_a_segment_start():
    _check("""
    @app.route('/a')
    def a():
        name = request.args.get('f')
        p = None
        if name.find('..') != -1:
            return 'no'
        p = BASE + '/' + name + '.txt'
        return open(p).read()  # SAFE

    @app.route('/b')
    def b():
        name = request.args.get('f')
        p = None
        if '../' in name:
            return 'no'
        p = f'{BASE}/{name}/x'
        return open(p).read()  # VULN

    @app.route('/c')
    def c():
        name = request.args.get('f')
        p = None
        if '..' in name:
            return 'no'
        p = f'{name}/{BASE}'
        return open(p).read()  # VULN
    """, "DF005")


def test_quote_rejection_protects_only_the_literal_it_delimits():
    _check("""
    @app.route('/a')
    def a():
        bar = request.args.get('id')
        root = lxml.etree.parse('e.xml')
        if "'" in bar:
            return 'no'
        root.xpath(f"/E[@id='{bar}']")  # SAFE
        root.xpath("/E[@id='" + bar + "']")  # SAFE
        root.xpath(f'/E[@id="{bar}"]')  # VULN
        root.xpath(f"/E[@id={bar}]")  # VULN

    @app.route('/b')
    def b():
        bar = request.args.get('id')
        root = lxml.etree.parse('e.xml')
        root.xpath("".join(["/E[@id='", bar.replace("'", "&apos;"), "']"]))  # SAFE
        root.xpath(f"/E[@id='{bar.replace('a', 'b')}']")  # VULN
        root.xpath(f'/E[@id="{bar.replace("'", "&apos;")}"]')  # VULN
        if '"' in bar:
            return 'no'
        root.xpath(f"/E[@id='{bar}']")  # VULN
    """, "DF015")


def test_quote_rejection_is_not_a_sanitizer_for_sql():
    got = _lines("""
    @app.route('/a')
    def a():
        bar = request.args.get('id')
        if "'" in bar:
            return 'no'
        cur = db.cursor()
        cur.execute(f"SELECT * FROM t WHERE id = '{bar}'")
    """, "DF004")
    assert got == {8}


def test_string_literal_shape_makes_eval_inert():
    _check("""
    @app.route('/a')
    def a():
        bar = request.args.get('x')
        if not bar.startswith("'") or not bar.endswith("'") or "'" in bar[1:-1]:
            return 'no'
        return str(eval(bar))  # SAFE

    @app.route('/b')
    def b():
        bar = request.args.get('x')
        if not bar.startswith("'") or not bar.endswith("'") or "'" in bar[1:-1]:
            return 'no'
        return str(eval(bar[1:-1]))  # VULN

    @app.route('/c')
    def c():
        bar = request.args.get('x')
        if not bar.startswith("'") or not bar.endswith("'"):
            return 'no'
        return str(eval(bar))  # VULN
    """, "DF001")


# ---------------------------------------------------------------- 2. configparser slots
def test_configparser_slots_are_kept_apart():
    _check("""
    @app.route('/a')
    def a():
        param = request.args.get('x')
        conf = configparser.ConfigParser()
        conf.add_section('s')
        conf.set('s', 'keyA', 'a_value')
        conf.set('s', 'keyB', param)
        eval(conf.get('s', 'keyA'))  # SAFE
        eval(conf.get('s', 'KEYB'))  # VULN
        eval(conf.get('s', request.args.get('k')))  # VULN

    @app.route('/s')
    def s():
        conf = configparser.ConfigParser()
        conf.add_section('s')
        conf.set('s', 'keyA', 'a_value')
        conf.set('s', 'keyB', request.args.get('x'))
        section = conf['s']
        eval(section['keyB'])  # VULN

    @app.route('/b')
    def b():
        param = request.args.get('x')
        conf = configparser.ConfigParser()
        conf.add_section('s')
        conf.set('s', 'keyA', '%(keyB)s')
        conf.set('s', 'keyB', param)
        eval(conf.get('s', 'keyA'))  # VULN

    @app.route('/c')
    def c():
        param = request.args.get('x')
        conf = configparser.ConfigParser()
        conf.add_section('s')
        conf.set('DEFAULT', 'keyA', param)
        eval(conf.get('s', 'keyA'))  # VULN
        eval(conf.get('s', 'other', fallback=param))  # VULN
    """, "DF001")


# ---------------------------------------------------------------- 3. response headers are not the page
def test_value_only_in_a_response_header_is_not_reflected_xss():
    _check("""
    @app.route('/a')
    def a():
        bar = request.args.get('x')
        resp = make_response(('static text', {'X-Value': bar}))  # SAFE
        return resp  # SAFE

    @app.route('/b')
    def b():
        bar = request.args.get('x')
        resp = make_response((bar, {'X-Value': 'v'}))  # VULN
        return resp  # VULN
    """, "DF013")


# ---------------------------------------------------------------- 4. str += rebinds, list += mutates
def test_augmented_string_assignment_does_not_write_through_an_alias():
    _check("""
    @app.route('/a')
    def a():
        s = ''
        copy = s
        s += request.args.get('x')
        copy += 'ok'
        return copy  # SAFE

    @app.route('/b')
    def b():
        s = []
        copy = s
        s += [request.args.get('x')]
        return str(copy)  # VULN
    """, "DF013")


# ---------------------------------------------------------------- 5. URL host allow-list
def test_parsed_url_host_allow_list_protects_the_redirect():
    _check("""
    @app.route('/a')
    def a():
        bar = request.args.get('next')
        url = urllib.parse.urlparse(bar)
        if url.netloc not in ['example.com'] or url.scheme != 'https':
            return 'no'
        return redirect(bar)  # SAFE

    @app.route('/b')
    def b():
        bar = request.args.get('next')
        url = urllib.parse.urlparse(bar)
        if url.scheme != 'https':
            return 'no'
        return redirect(bar)  # VULN

    @app.route('/c')
    def c():
        bar = request.args.get('next')
        url = urllib.parse.urlparse(bar)
        if url.netloc not in ['', 'example.com']:
            return 'no'
        return redirect(bar)  # VULN

    @app.route('/d')
    def d():
        bar = request.args.get('next')
        url = urllib.parse.urlparse(bar)
        bar = request.args.get('other')
        if url.netloc != 'example.com':
            return 'no'
        return redirect(bar)  # VULN
    """, "DF008")


# ---------------------------------------------------------------- 6. normalised path checked against a directory
def test_resolved_path_prefix_check_needs_the_separator():
    _check("""
    @app.route('/a')
    def a():
        base = pathlib.Path(BASE).resolve()
        p = (base / request.args.get('f')).resolve()
        if not str(p).startswith(str(base) + os.sep):
            return 'no'
        return p.read_text()  # SAFE

    @app.route('/b')
    def b():
        base = pathlib.Path(BASE).resolve()
        p = (base / request.args.get('f')).resolve()
        if not str(p).startswith(str(base)):
            return 'no'
        return p.read_text()  # VULN

    @app.route('/c')
    def c():
        p = os.path.join('/srv/files', request.args.get('f'))
        if not p.startswith('/srv/files/'):
            return 'no'
        return open(p).read()  # VULN

    @app.route('/d')
    def d():
        p = os.path.realpath(os.path.join('/srv/files', request.args.get('f')))
        if p.startswith('/srv/files/'):
            return open(p).read()  # SAFE
        return open(p).read()  # VULN
    """, "DF005")


# ---------------------------------------------------------------- 7. request.path is always input
# (a fixed-route exemption was tried for 1.2 and dropped: a variable route can reach any view by means a static
# analysis cannot see, e.g. add_url_rule(view_func=getattr(module, name)) or bp.url_prefix assigned later)
ROUTES = """
@app.route('/a/b', methods=['GET'])
def fixed_get():
    return fixed_post()  # VULN

@app.route('/a/b', methods=['POST'])
def fixed_post():
    return '<p>' + request.path + '</p>'  # VULN

@app.route('/v/<x>')
def variable():
    return '<p>' + request.path + '</p>'  # VULN

@app.route('/e')
def fixed_called():
    return redirect(request.path)
"""


def test_request_path_is_input_even_in_a_fixed_route():
    _check(ROUTES, "DF013")
    assert _lines(ROUTES, "DF008") == {16}


def test_request_path_with_routes_bound_dynamically():
    _check("""
    import sys

    @app.route('/a')
    def a(rest=None):
        return '<h1>' + request.path + '</h1>'  # VULN

    for _name in ('a',):
        app.add_url_rule('/legacy/' + _name + '/<path:rest>', view_func=getattr(sys.modules[__name__], _name))

    bp = Blueprint('bp', __name__)

    @bp.route('/b')
    def b(lang=None):
        return '<h1>' + request.path + '</h1>'  # VULN

    bp.url_prefix = '/<lang>'
    app.register_blueprint(bp)
    """, "DF013")


# ---------------------------------------------------------------- 8. elementpath: the XPath is the second argument
def test_elementpath_select_checks_the_path_argument():
    _check("""
    @app.route('/a')
    def a():
        root = lxml.etree.parse('e.xml')
        elementpath.select(root, "/E[@id='" + request.args.get('id') + "']")  # VULN
        elementpath.select(root, '/E')  # SAFE
    """, "DF015")


# ---------------------------------------------------------------- 9. bypasses found in review (still reported)
def test_substring_rejection_needs_a_str_value():
    _check("""
    @app.route('/a')
    def a():
        bar = request.get_json()['id']
        root = lxml.etree.parse('e.xml')
        if "'" in bar:
            return 'no'
        q = f"/E[@id='{bar}']"
        return str(root.xpath(q))  # VULN

    @app.route('/b')
    def b():
        bar = request.args.getlist('id')
        root = lxml.etree.parse('e.xml')
        if "'" in bar:
            return 'no'
        q = f"/E[@id='{bar}']"
        return str(root.xpath(q))  # VULN

    @app.route('/c')
    def c():
        bar = request.args.getlist('id')[0]
        root = lxml.etree.parse('e.xml')
        if "'" in bar:
            return 'no'
        q = f"/E[@id='{bar}']"
        return str(root.xpath(q))  # SAFE

    @app.route('/d')
    def d():
        bar = request.get_json()['id']
        root = lxml.etree.parse('e.xml')
        if not isinstance(bar, str) or "'" in bar:
            return 'no'
        q = f"/E[@id='{bar}']"
        return str(root.xpath(q))  # SAFE
    """, "DF015")


def test_hostname_allow_list_is_not_trusted():
    _check("""
    @app.route('/a')
    def a():
        target = request.args.get('next')
        u = urllib.parse.urlparse(target)
        if u.hostname not in ('good.example', 'www.good.example'):
            return 'bad host', 400
        return redirect(target)  # VULN
    """, "DF008")


def test_location_header_through_make_response_is_a_redirect():
    _check("""
    @app.route('/a')
    def a():
        nxt = request.args.get('next')
        return make_response(('', 302, {'Location': nxt}))  # VULN

    @app.route('/b')
    def b():
        nxt = request.args.get('next')
        return make_response('', 302, {'location': nxt})  # VULN

    @app.route('/c')
    def c():
        nxt = request.args.get('next')
        resp = make_response(('redirecting', {'Location': nxt, 'X': 'y'}))  # VULN
        resp.status_code = 302
        return resp

    @app.route('/d')
    def d():
        nxt = request.args.get('next')
        return make_response(('', 302, {'X-Next': nxt}))  # SAFE
    """, "DF008")
    # headers that are not a literal dict: the whole call stays one value, as in 1.1.1
    assert _lines("""
    @app.route('/e')
    def e():
        hdrs = {'X': request.args.get('x')}
        return make_response(('body', hdrs))
    """, "DF013") == {5}


def test_configparser_vars_and_optionxform_keep_the_taint():
    _check("""
    @app.route('/a')
    def a():
        conf = configparser.ConfigParser()
        conf.add_section('s')
        conf.set('s', 'safe', 'x')
        return eval(conf.get('s', 'safe', vars={'safe': request.args.get('x')}))  # VULN

    @app.route('/b')
    def b():
        conf = configparser.ConfigParser()
        conf.add_section('s')
        conf.optionxform = lambda o: o.replace('_', '')
        conf.set('s', 'sa_fe', request.args.get('x'))
        conf.set('s', 'safe', 'x')
        return eval(conf.get('s', 'safe'))  # VULN
    """, "DF001")


def test_directory_prefix_must_be_known_text():
    _check("""
    @app.route('/a')
    def a():
        p = os.path.abspath(request.args.get('f'))
        base = os.environ.get('UPLOAD_DIR', '')
        if not p.startswith(base + os.sep):
            return 'no'
        return open(p).read()  # VULN
    """, "DF005")


def test_module_constant_rebound_elsewhere_is_not_a_known_directory(tmp_path):
    from vulnscan.scanner import scan_path
    (tmp_path / "settings.py").write_text("UPLOAD_DIR = '/srv/uploads/'\n", encoding="utf-8")
    (tmp_path / "boot.py").write_text("import os\nimport settings\nsettings.UPLOAD_DIR = os.environ.get('D', '')\n",
                                      encoding="utf-8")
    (tmp_path / "app.py").write_text(
        "from flask import Flask, request\nimport settings\napp = Flask(__name__)\n\n"
        "@app.route('/p')\ndef p():\n    name = request.args.get('f')\n    if '..' in name:\n        return 'no'\n"
        "    p = settings.UPLOAD_DIR + name\n    return open(p).read()\n", encoding="utf-8")
    findings, _ = scan_path(tmp_path, jadx=False, notes=[])
    assert ("app.py", 11) in {(f.file, f.line) for f in findings if f.rule_id == "DF005"}


ROUTED_ELSEWHERE = """
@app.route('/a')
def a(rest=None):
    return '<h1>' + request.path + '</h1>'  # VULN

app.add_url_rule('/go/<path:rest>', endpoint='a')
"""


def test_request_path_stays_input_when_rules_are_bound_by_endpoint():
    _check(ROUTED_ELSEWHERE, "DF013")
    _check("""
    @app.route('/d')
    @app.endpoint('dyn')
    def d(p=None):
        return '<h1>' + request.path + '</h1>'  # VULN

    app.url_map.add(app.url_rule_class('/dyn/<path:p>', endpoint='dyn'))
    """, "DF013")
    _check("""
    @app.route('/v')
    def v():
        return '<h1>' + request.path + '</h1>'  # VULN

    app.view_functions['other'] = v
    """, "DF013")


def test_request_path_stays_input_in_an_error_handler():
    _check("""
    @app.route('/notfound')
    @app.errorhandler(404)
    def nf(e=None):
        return '<h1>' + request.path + ' not found</h1>', 404  # VULN

    @app.route('/gone')
    def gone(e=None):
        return '<h1>' + request.path + '</h1>'  # VULN

    app.register_error_handler(410, gone)
    """, "DF013")


# ---------------------------------------------------------------- 10. second review round (still reported)
def test_count_and_find_need_a_str_value():
    _check("""
    @app.route('/a')
    def a():
        bar = request.get_json()['id']
        root = lxml.etree.parse('e.xml')
        if bar.count("'") != 0:
            return 'no'
        return str(root.xpath(f"/E[@id='{bar}']"))  # VULN

    @app.route('/b')
    def b():
        bar = request.get_json()['id']
        root = lxml.etree.parse('e.xml')
        if bar.find("'") >= 0:
            return 'no'
        return str(root.xpath(f"/E[@id='{bar}']"))  # VULN

    @app.route('/c')
    def c():
        bar = request.args.get('id')
        root = lxml.etree.parse('e.xml')
        if bar.count("'") != 0:
            return 'no'
        return str(root.xpath(f"/E[@id='{bar}']"))  # SAFE
    """, "DF015")


def test_refresh_header_is_a_redirect_and_a_chosen_content_type_keeps_xss():
    _check("""
    @app.route('/a')
    def a():
        nxt = request.args.get('next')
        return make_response(('redirecting', 200, {'Refresh': f'0; url={nxt}'}))  # VULN

    @app.route('/b')
    def b():
        nxt = request.args.get('next')
        return make_response('redirecting', {'refresh': '0;url=' + nxt})  # VULN
    """, "DF008")
    _check("""
    @app.route('/c')
    def c():
        return make_response(('<b>hi</b>', {'Content-Type': request.args.get('t')}))  # VULN

    @app.route('/d')
    def d():
        return make_response(('<b>hi</b>', {'Content-Type': 'text/plain', 'X': request.args.get('t')}))  # SAFE
    """, "DF013")


def test_walrus_inside_an_augmented_assignment_rebinds_the_guarded_name():
    _check("""
    @app.route('/a')
    def a():
        log = ''
        name = request.args.get('f')
        if '..' in name:
            return 'no'
        log += (name := request.args.get('g'))
        p = f'{BASE}/{name}'
        return open(p).read()  # VULN

    @app.route('/b')
    def b():
        log = ''
        name = request.args.get('f')
        if '..' in name:
            return 'no'
        log += name
        p = f'{BASE}/{name}'
        return open(p).read()  # SAFE
    """, "DF005")


def test_decode_is_a_str_only_on_bytes():
    _check("""
    import base64
    import jwt

    @app.route('/a')
    def a():
        bar = jwt.decode(request.args.get('t'), 'k', algorithms=['HS256']).decode()
        root = lxml.etree.parse('e.xml')
        if "'" in bar:
            return 'no'
        return str(root.xpath(f"/E[@id='{bar}']"))  # VULN

    @app.route('/b')
    def b():
        bar = base64.b64decode(request.args.get('t')).decode('utf-8')
        root = lxml.etree.parse('e.xml')
        if "'" in bar:
            return 'no'
        return str(root.xpath(f"/E[@id='{bar}']"))  # SAFE
    """, "DF015")


def test_setattr_on_a_configparser_drops_slot_precision():
    _check("""
    @app.route('/a')
    def a():
        conf = configparser.ConfigParser()
        conf.add_section('s')
        setattr(conf, 'optionxform', lambda o: o.lower().replace('-', '_'))
        conf.set('s', 'a-b', request.args.get('x'))
        conf.set('s', 'safe', 'x')
        return eval(conf.get('s', 'a_b'))  # VULN
    """, "DF001")


def _scan_files(tmp_path, files: dict) -> set:
    from vulnscan.scanner import scan_path
    for rel, text in files.items():
        (tmp_path / rel).write_text(textwrap.dedent(text), encoding="utf-8")
    findings, _ = scan_path(tmp_path, jadx=False, notes=[])
    return {(f.file, f.line) for f in findings if f.rule_id == "DF005"}


GUARDED_OPEN = """\
    @app.route('/p')
    def p():
        name = request.args.get('f')
        if '..' in name:
            return 'no'
        p = {prefix} + name
        return open(p).read()
"""


def test_star_import_makes_a_module_constant_unknown(tmp_path):
    got = _scan_files(tmp_path, {
        "local_settings.py": "UPLOAD_DIR = ''\n",
        "settings.py": "UPLOAD_DIR = '/srv/uploads/'\ntry:\n    from local_settings import *\nexcept ImportError:\n    pass\n",
        "app.py": "from flask import Flask, request\nimport settings\napp = Flask(__name__)\n\n"
                  + textwrap.dedent(GUARDED_OPEN).format(prefix="settings.UPLOAD_DIR"),
    })
    assert ("app.py", 11) in got


def test_dynamic_globals_make_a_module_constant_unknown(tmp_path):
    body = textwrap.dedent(GUARDED_OPEN).format(prefix="DATA")
    got = _scan_files(tmp_path, {
        "app.py": "import json\nfrom flask import Flask, request\napp = Flask(__name__)\nDATA = '/srv/data/'\n"
                  "globals().update(json.load(open('overrides.json')))\n\n" + body,
        "safe.py": "from flask import Flask, request\napp = Flask(__name__)\nDATA = '/srv/data/'\n\n" + body,
    })
    assert ("app.py", 13) in got and ("safe.py", 11) not in got


# ---------------------------------------------------------------- 11. third review round (still reported)
def test_decoding_a_built_string_drops_its_protection():
    _check("""
    import html
    from urllib.parse import unquote

    @app.route('/a')
    def a():
        name = request.args.get('f')
        if '..' in name:
            return 'no'
        p = f'{BASE}/{name}'
        q = p
        open(q).read()  # SAFE
        open(unquote(p)).read()  # VULN
        p = unquote(p)
        return open(p).read()  # VULN

    @app.route('/b')
    def b():
        name = request.args.get('f')
        if '..' in name:
            return 'no'
        p = html.unescape(f'{BASE}/{name}')
        return open(p).read()  # VULN
    """, "DF005")
    _check("""
    import html
    from urllib.parse import unquote

    @app.route('/a')
    def a():
        bar = request.args.get('id')
        root = lxml.etree.parse('e.xml')
        if "'" in bar:
            return 'no'
        q = f"/E[@id='{bar}']"
        root.xpath(q)  # SAFE
        root.xpath(unquote(q))  # VULN
        q = html.unescape(q)
        return str(root.xpath(q))  # VULN
    """, "DF015")


def test_request_args_of_another_framework_is_not_known_str():
    code = textwrap.dedent("""\
        import lxml.etree
        from twisted.web import resource

        class Search(resource.Resource):
            def render_GET(self, request):
                bar = request.args.get(b'id')
                root = lxml.etree.parse('e.xml')
                if "'" in bar:
                    return b'no'
                q = f"/E[@id='{bar}']"
                return str(root.xpath(q)).encode()
        """)
    assert 11 in {f.line for f in analyze("res.py", code) if f.rule_id == "DF015"}   # twisted: lists of bytes


def test_encode_is_bytes_only_on_a_known_str():
    _check("""
    @app.route('/a')
    def a():
        bar = request.get_json()['id'].encode().decode()
        root = lxml.etree.parse('e.xml')
        if "'" in bar:
            return 'no'
        return str(root.xpath(f"/E[@id='{bar}']"))  # VULN

    @app.route('/b')
    def b():
        bar = request.args.get('id').encode('utf-8').decode('utf-8')
        root = lxml.etree.parse('e.xml')
        if "'" in bar:
            return 'no'
        return str(root.xpath(f"/E[@id='{bar}']"))  # SAFE
    """, "DF015")


def test_file_serving_headers_are_path_sinks():
    _check("""
    @app.route('/a')
    def a():
        return make_response(('', {'X-Accel-Redirect': '/protected/' + request.args.get('f')}))  # VULN

    @app.route('/b')
    def b():
        return make_response(('', 200, {'x-sendfile': request.args.get('f')}))  # VULN

    @app.route('/c')
    def c():
        return make_response('', 200, {'X-LiteSpeed-Location': request.args.get('f')})  # VULN
    """, "DF005")
    assert not _lines("""
    @app.route('/d')
    def d():
        return make_response(('static', {'X-Request-Id': request.args.get('f')}))
    """, "DF013")


def test_delattr_on_a_configparser_drops_slot_precision():
    # precision is given up after delattr: the untainted slot is reported, as for any untracked parser
    _check("""
    @app.route('/a')
    def a():
        conf = configparser.ConfigParser()
        conf.add_section('s')
        conf.set('s', 'keyB', request.args.get('x'))
        delattr(conf, 'optionxform')
        conf.set('s', 'keyA', 'x')
        return eval(conf.get('s', 'keyA'))  # VULN
    """, "DF001")


NAMESPACE_WRITES = ["locals().update(json.load(open('o.json')))", "builtins.exec(open('o.py').read())",
                    "sys._getframe().f_globals.update({})", "importlib.reload(sys.modules[__name__])"]


def test_dynamic_namespace_writes_make_module_constants_unknown(tmp_path):
    body = textwrap.dedent(GUARDED_OPEN).format(prefix="DATA")
    files = {}
    for i, stmt in enumerate(NAMESPACE_WRITES):
        files[f"app{i}.py"] = ("import builtins, importlib, json, sys\nfrom flask import Flask, request\napp = Flask(__name__)\n"
                               f"DATA = '/srv/data/'\n{stmt}\n\n" + body)
    got = _scan_files(tmp_path, files)
    assert {(f"app{i}.py", 13) for i in range(len(NAMESPACE_WRITES))} <= got
