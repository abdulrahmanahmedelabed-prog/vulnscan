"""Java frontend semantics (operators, switch) and Java-specific checks."""

import ast

from vulnscan import cfamily_frontend
from vulnscan.scanner import scan_path
from vulnscan.semantic import check_java


def _py(src):
    return ast.unparse(cfamily_frontend.parse_cfamily(src, "T.java", "java"))


def test_arithmetic_operators_are_preserved():
    out = _py("class T { void f() { int a = 7 * 18 - 4 / 2 % 3; int b = a << 2 | 1 & 6 ^ 5; } }")
    assert "7.0 * 18.0" in out and " - " in out and " / " in out and " % " in out
    assert " << " in out and " | " in out and " & " in out and " ^ " in out


def test_switch_becomes_match_with_fallthrough():
    out = _py("class T { void f(String s) { String b; switch (s) {"
              " case \"a\": b = \"1\"; case \"b\": b = \"2\"; break; case \"c\": case \"d\": b = \"3\"; break;"
              " default: b = \"4\"; } } }")
    assert "match s:" in out and "case 'c' | 'd':" in out and "case _:" in out
    first = out.split("case 'a':")[1].split("case 'b':")[0]
    assert "b = '1'" in first and "b = '2'" in first                 # 'a' falls through into 'b'


def _scan(tmp_path, body, extra_files=None):
    (tmp_path / "T.java").write_text(
        "import javax.servlet.http.*;\npublic class T extends HttpServlet {\n"
        "  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {\n"
        + body + "\n  }\n}\n")
    for name, text in (extra_files or {}).items():
        (tmp_path / name).write_text(text)
    return {(f.rule_id, f.cwe) for f in scan_path(tmp_path, [], set())[0]}


def test_constant_switch_and_ternary_clear_taint(tmp_path):
    body = ('    String param = request.getParameter("p");\n    int num = 106;\n'
            '    String bar = (7 * 18) + num > 200 ? "safe" : param;\n'
            '    String guess = "ABC";\n    char t = guess.charAt(1);\n'
            '    switch (t) { case \'A\': bar = param; break; case \'B\': bar = "bob"; break; default: bar = param; }\n'
            '    Runtime.getRuntime().exec("ls " + bar);')
    assert not any(cwe == "CWE-78" for _, cwe in _scan(tmp_path, body))


def test_tainted_switch_case_is_reported(tmp_path):
    body = ('    String param = request.getParameter("p");\n    String guess = "ABC";\n    char t = guess.charAt(0);\n'
            '    String bar;\n    switch (t) { case \'A\': bar = param; break; default: bar = "x"; }\n'
            '    Runtime.getRuntime().exec("ls " + bar);')
    assert any(cwe == "CWE-78" for _, cwe in _scan(tmp_path, body))


def test_algorithms_resolved_from_properties():
    src = ('class T { public void f() throws Exception {\n'
           ' java.util.Properties p = new java.util.Properties();\n'
           ' String a = p.getProperty("hashAlg1", "SHA512");\n'
           ' java.security.MessageDigest.getInstance(a);\n'
           ' String c = p.getProperty("cryptoAlg2", "AES/ECB/PKCS5Padding");\n'
           ' javax.crypto.Cipher.getInstance(c);\n} }')
    ids = {f.rule_id for f in check_java("T.java", src, {"hashAlg1": "MD5", "cryptoAlg2": "AES/GCM/NoPadding"}, set())}
    assert ids == {"CRY102"}                      # MD5 via config; the ECB fallback is not used


def test_session_and_xpath_sinks(tmp_path):
    body = ('    String param = request.getParameter("p");\n'
            '    request.getSession().setAttribute("userid", param);\n'
            '    javax.xml.xpath.XPath xp = javax.xml.xpath.XPathFactory.newInstance().newXPath();\n'
            '    xp.evaluate("/a[@id=\'" + param + "\']", null);')
    cwes = {cwe for _, cwe in _scan(tmp_path, body)}
    assert "CWE-501" in cwes and "CWE-643" in cwes


def test_new_expression_keeps_its_call_chain_and_array_elements():
    out = _py("class T { void f() { String b = new Test().doSomething(r, p); String s = new StringBuilder().append(x).toString();"
              " String[] q = new String[]{param, \"x\"}; } }")
    assert "Test().doSomething(r, p)" in out and "StringBuilder().append(x).toString()" in out and "[param, 'x']" in out


def test_flow_through_inner_class_method(tmp_path):
    (tmp_path / "T.java").write_text(
        "import javax.servlet.http.*;\npublic class T extends HttpServlet {\n"
        "  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {\n"
        "    String param = request.getParameter(\"p\");\n    String bar = new Test().doSomething(request, param);\n"
        "    Runtime.getRuntime().exec(\"ls \" + bar);\n  }\n"
        "  private class Test {\n    public String doSomething(HttpServletRequest request, String param) {\n"
        "      String bar = param;\n      return bar;\n    }\n  }\n}\n")
    assert any(f.rule_id == "DF002" and f.line == 6 for f in scan_path(tmp_path, [], set())[0])


def test_java_collections_keep_their_layout(tmp_path):
    (tmp_path / "T.java").write_text(
        "import javax.servlet.http.*;\npublic class T extends HttpServlet {\n"
        "  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {\n"
        "    String param = request.getParameter(\"p\");\n"
        "    java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();\n"
        "    map.put(\"keyA\", \"a_Value\");\n    map.put(\"keyB\", param);\n"
        "    java.util.List<String> l = new java.util.ArrayList<String>();\n"
        "    l.add(\"safe\");\n    l.add(param);\n    l.add(\"moresafe\");\n    l.remove(0);\n"
        "    java.sql.Statement st = null;\n"
        "    st.execute(\"S \" + (String) map.get(\"keyA\"));\n"     # line 14: safe key
        "    st.execute(\"S \" + (String) map.get(\"keyB\"));\n"     # line 15: tainted key
        "    st.execute(\"S \" + l.get(1));\n"                       # line 16: 'moresafe'
        "    st.execute(\"S \" + l.get(0));\n  }\n}\n")              # line 17: param
    lines = {f.line for f in scan_path(tmp_path, [], set())[0] if f.rule_id == "DF004"}
    assert lines == {15, 17}
