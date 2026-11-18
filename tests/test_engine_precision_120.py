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
    _check("""
    @app.route('/a')
    def a():
        name = request.args.get('f')
        file_name = None
        if '../' in name:
            return 'no'
        file_name = f'{BASE}/{name}'
        return open(file_name).read()  # SAFE

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


# ---------------------------------------------------------------- 7. request.path of a fixed Flask route
FIXED_ROUTES = """
@app.route('/a/b', methods=['GET'])
def fixed_get():
    return fixed_post()  # SAFE

@app.route('/a/b', methods=['POST'])
def fixed_post():
    return '<p>' + request.path + '</p>'  # SAFE

@app.route('/v/<x>')
def variable():
    return '<p>' + request.path + '</p>'  # VULN

@app.route('/c/d')
def registered_again():
    return '<p>' + request.path + '</p>'  # VULN

app.add_url_rule('/z/<p>', view_func=registered_again)

@app.route('/e/<y>')
def caller():
    return fixed_called()

@app.route('/e')
def fixed_called():
    return redirect(request.path)
"""


def test_request_path_of_a_fixed_route_is_not_input():
    _check(FIXED_ROUTES, "DF013")
    assert _lines(FIXED_ROUTES, "DF008") == {26}     # fixed_called is also reached from a route with a variable


def test_blueprint_with_a_variable_prefix_keeps_request_path_tainted():
    body = FIXED_ROUTES + "\nbp = Blueprint('b', __name__, url_prefix='/<lang>')\n"
    assert _marked(FIXED_ROUTES, "# SAFE") <= _lines(body, "DF013")


# ---------------------------------------------------------------- 8. elementpath: the XPath is the second argument
def test_elementpath_select_checks_the_path_argument():
    _check("""
    @app.route('/a')
    def a():
        root = lxml.etree.parse('e.xml')
        elementpath.select(root, "/E[@id='" + request.args.get('id') + "']")  # VULN
        elementpath.select(root, '/E')  # SAFE
    """, "DF015")
