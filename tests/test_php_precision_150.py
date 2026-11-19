"""1.5.0 PHP precision, measured on the NIST SARD PHP Vulnerability Test Suite (bench/score_php.py).

What a PHP escaper leaves of a value (php_semantics markers) is judged where the value lands: inside a quoted SQL /
shell / XPath / PHP literal or bare, and, for an echo, at its place in the page. Guards read the way PHP code writes
them (`preg_match(...) == 1`, if/else that validates or replaces), arithmetic and settype() make numbers, and a
shell command's output is a local source. Every rule that marks something safe has a still-vulnerable twin."""

from __future__ import annotations

import pickle
import textwrap

from vulnscan import php_semantics as php
from vulnscan.cfamily_frontend import parse_cfamily
from vulnscan.scanner import scan_path
from vulnscan.taint import analyze


def _lines(code: str, rules) -> set:
    return {f.line for f in analyze("app.php", code) if f.rule_id in rules}


def _marked(code: str, mark: str) -> set:
    return {i for i, line in enumerate(code.splitlines(), 1) if line.rstrip().endswith(mark)}


def _check(body: str, *rules: str) -> None:
    """Lines ending in `// VULN` must be reported for one of `rules`, lines ending in `// SAFE` must not."""
    code = textwrap.dedent(body).lstrip("\n")
    got = _lines(code, set(rules))
    vuln, safe = _marked(code, "// VULN"), _marked(code, "// SAFE")
    assert vuln <= got, f"missed {sorted(vuln - got)}"
    assert not (safe & got), f"false positives {sorted(safe & got)}"


# ------------------------------------------------------------------------------------- 1. SQL quoting context
def test_sql_escapers_protect_quoted_literals_not_numbers():
    _check("""
    <?php
    $t = $_GET['a'];
    mysql_query("SELECT * FROM x WHERE a='" . addslashes($t) . "'"); // SAFE
    mysql_query("SELECT * FROM x WHERE a=" . addslashes($t)); // VULN
    mysql_query("SELECT * FROM x WHERE a='" . mysql_real_escape_string($t) . "'"); // SAFE
    mysql_query("SELECT * FROM x WHERE a=" . mysql_real_escape_string($t)); // VULN
    $q = sprintf("SELECT * FROM x WHERE a='%s'", mysqli_real_escape_string($c, $t));
    mysqli_query($c, $q); // SAFE
    $q2 = sprintf("SELECT * FROM x WHERE a=%s", mysqli_real_escape_string($c, $t));
    mysqli_query($c, $q2); // VULN
    mysql_query(sprintf("SELECT * FROM x WHERE id=%d", $t)); // SAFE
    """, "DF004")


def test_quote_free_value_inside_a_quoted_literal():
    _check("""
    <?php
    $t = $_GET['a'];
    $h = htmlspecialchars($t, ENT_QUOTES);
    mysql_query("SELECT * FROM x WHERE a='" . $h . "'"); // SAFE
    mysql_query("SELECT * FROM x WHERE a=" . $h); // VULN
    $d = htmlspecialchars($t);
    mysql_query("SELECT * FROM x WHERE a='" . $d . "'"); // VULN
    mysql_query("SELECT * FROM x WHERE a='" . $h . "' AND b='" . $h . "'"); // VULN
    """, "DF004")


def test_xpath_has_no_backslash_escape():
    _check("""
    <?php
    $t = $_GET['a'];
    $xml = simplexml_load_file("users.xml");
    $xml->xpath("//user[@name='" . htmlspecialchars($t, ENT_QUOTES) . "']"); // SAFE
    $xml->xpath("//user[@name='" . addslashes($t) . "']"); // VULN
    """, "DF015")


# --------------------------------------------------------------------------------------------- 2. shell quoting
def test_escapeshellarg_only_unquoted_and_escapeshellcmd_is_no_sanitizer():
    _check("""
    <?php
    $t = $_GET['a'];
    system("ls " . escapeshellarg($t)); // SAFE
    system("ls '" . escapeshellarg($t) . "'"); // VULN
    system("ls " . escapeshellcmd($t)); // VULN
    system("ls '" . htmlspecialchars($t, ENT_QUOTES) . "'"); // SAFE
    system("ls '" . addslashes($t) . "'"); // VULN
    system("ls \\"" . htmlspecialchars($t, ENT_QUOTES) . "\\""); // VULN
    """, "DF002")


# ----------------------------------------------------------------------------------------- 3. HTML output context
def test_htmlspecialchars_by_place_in_the_page():
    _check("""
    <html><body>
    <?php
    $t = $_GET['a'];
    echo htmlspecialchars($t); // SAFE
    echo "<div id=\\"" . htmlspecialchars($t) . "\\">x</div>"; // SAFE
    echo "<div id='" . htmlspecialchars($t, ENT_QUOTES) . "'>x</div>"; // SAFE
    echo "<div id='" . htmlspecialchars($t) . "'>x</div>"; // VULN
    echo "<div id=" . htmlspecialchars($t, ENT_QUOTES) . ">x</div>"; // VULN
    echo "<div onclick=\\"x='" . htmlspecialchars($t, ENT_QUOTES) . "'\\">x</div>"; // VULN
    echo "<a href=\\"" . htmlspecialchars($t, ENT_QUOTES) . "\\">x</a>"; // VULN
    echo "<a href=\\"/page?q=" . htmlspecialchars($t, ENT_QUOTES) . "\\">x</a>"; // SAFE
    echo "<div id=\\"" . addslashes($t) . "\\">x</div>"; // VULN
    ?>
    </body></html>
    """, "DF013")


def test_script_block_context():
    _check("""
    <html><head><script>
    <?php
    $t = $_GET['a'];
    echo "var a = '" . htmlspecialchars($t, ENT_QUOTES) . "';"; // SAFE
    ?>
    </script><script>
    <?php
    echo htmlspecialchars($_GET['b'], ENT_QUOTES); // VULN
    ?>
    </script><script>
    <?php
    echo "setTimeout('" . htmlspecialchars($_GET['c'], ENT_QUOTES) . "');"; // VULN
    ?>
    </script></head></html>
    """, "DF013")


def test_comment_and_numeric_filters():
    _check("""
    <html><body><!--
    <?php
    echo htmlspecialchars($_GET['a']); // SAFE
    ?>
    --><style>
    <?php
    echo "body { color: " . filter_var($_GET['b'], FILTER_SANITIZE_NUMBER_INT) . "; }"; // SAFE
    echo "body { color: " . htmlspecialchars($_GET['c']) . "; }"; // VULN
    ?>
    </style></body></html>
    """, "DF013")


def test_html_state_survives_process_pools():
    tree = parse_cfamily("<script><?php echo $x; ?></script>", "a.php", "php")
    again = pickle.loads(pickle.dumps(tree))
    echo = next(n for n in again.body if hasattr(n, "value")).value
    assert echo.args[0].php_html.mode == "script"


# ----------------------------------------------------------------------------------------------- 4. filter_var
def test_filter_var_depends_on_the_filter():
    _check("""
    <?php
    $t = $_GET['a'];
    mysql_query("SELECT * FROM x WHERE a=" . filter_var($t, FILTER_VALIDATE_INT)); // SAFE
    mysql_query("SELECT * FROM x WHERE a=" . filter_var($t, FILTER_SANITIZE_NUMBER_INT)); // VULN
    mysql_query("SELECT * FROM x WHERE a='" . filter_var($t, FILTER_SANITIZE_NUMBER_INT) . "'"); // SAFE
    mysql_query("SELECT * FROM x WHERE a='" . filter_var($t, FILTER_SANITIZE_EMAIL) . "'"); // VULN
    mysql_query("SELECT * FROM x WHERE a='" . filter_var($t, FILTER_UNSAFE_RAW) . "'"); // VULN
    """, "DF004")
    _check("""
    <html><body>
    <?php
    echo filter_var($_GET['a'], FILTER_SANITIZE_FULL_SPECIAL_CHARS); // SAFE
    echo filter_var($_GET['b'], FILTER_VALIDATE_URL); // VULN
    echo filter_var($_GET['c'], FILTER_VALIDATE_EMAIL); // VULN
    ?>
    </body></html>
    """, "DF013")


# --------------------------------------------------------------------------------------------- 5. allow-lists
def test_preg_replace_allow_lists():
    _check("""
    <?php
    $t = $_GET['a'];
    system("ls " . preg_replace('/[^a-z0-9]/i', '', $t)); // SAFE
    system("ls " . preg_replace('/\\W/', '', $t)); // SAFE
    system("ls " . preg_replace('/[^a-z0-9 ;]/i', '', $t)); // VULN
    system("ls " . preg_replace('/[a-z]/', '', $t)); // VULN
    system("ls '" . preg_replace("/'/", '', $t) . "'"); // SAFE
    """, "DF002")


def test_ldap_metacharacters_removed():
    _check("""
    <?php
    $t = $_GET['a'];
    $c = ldap_connect("localhost");
    $f = str_replace(array('\\\\', '*', '(', ')', "\\0"), '', $t);
    ldap_search($c, "o=x", "(cn=" . $f . ")"); // SAFE
    $g = str_replace(array('*', '(', ')'), '', $t);
    ldap_search($c, "o=x", "(cn=" . $g . ")"); // VULN
    ldap_search($c, "o=x", "(cn=" . htmlspecialchars($t, ENT_QUOTES) . ")"); // VULN
    """, "DF014")


def test_preg_match_guards_read_the_pattern():
    _check("""
    <?php
    $t = $_GET['a'];
    $re = "/^[0-9]*$/";
    if (preg_match($re, $t) == 1) {
      $t = $t;
    } else {
      $t = "";
    }
    mysql_query("SELECT * FROM x WHERE a=" . $t); // SAFE
    $u = $_GET['b'];
    if (preg_match("/^.*$/", $u) == 1) {
      mysql_query("SELECT * FROM x WHERE a=" . $u); // VULN
    }
    $v = $_GET['c'];
    if (preg_match("/^[a-z ;']*$/", $v)) {
      mysql_query("SELECT * FROM x WHERE a=" . $v); // VULN
    }
    if (preg_match("/^[a-z]+$/m", $_GET['d'])) {
      mysql_query("SELECT * FROM x WHERE a=" . $_GET['d']); // VULN
    }
    """, "DF004")


def test_if_else_that_validates_or_replaces():
    _check("""
    <?php
    $t = $_GET['a'];
    $legal = array("safe1", "safe2");
    if (in_array($t, $legal, true)) {
      $t = $t;
    } else {
      $t = $legal[0];
    }
    $q = "SELECT * FROM x WHERE a='" . $t . "'";
    mysql_query($q); // SAFE
    $u = $_GET['b'];
    if (in_array($u, $legal, true)) {
      $u = $u;
    } else {
      $u = $_GET['c'];
    }
    mysql_query("SELECT * FROM x WHERE a='" . $u . "'"); // VULN
    $w = $_GET['d'];
    if (in_array($w, array(1, 2, 3))) {
      mysql_query("SELECT * FROM x WHERE a=" . $w); // VULN
    }
    if (in_array($w, array(1, 2, 3), true)) {
      mysql_query("SELECT * FROM x WHERE a=" . $w); // SAFE
    }
    """, "DF004")


def test_filter_var_guard():
    _check("""
    <?php
    $t = $_GET['a'];
    $s = filter_var($t, FILTER_SANITIZE_NUMBER_INT);
    if (filter_var($s, FILTER_VALIDATE_INT)) $t = $s; else $t = "";
    mysql_query("SELECT * FROM x WHERE a=" . $t); // SAFE
    $u = $_GET['b'];
    if (filter_var($u, FILTER_VALIDATE_EMAIL)) {
      mysql_query("SELECT * FROM x WHERE a='" . $u . "'"); // VULN
    }
    """, "DF004")


# ------------------------------------------------------------------------------------------------ 6. numbers
def test_arithmetic_and_settype_make_numbers():
    _check("""
    <?php
    $t = $_GET['a'];
    $n = $t + 0;
    mysql_query("SELECT ".$n); // SAFE
    $m = $t;
    $m += 0;
    mysql_query("SELECT ".$m); // SAFE
    $k = $t * 1;
    mysql_query("SELECT ".$k); // SAFE
    $s = $t . "0";
    mysql_query("SELECT ".$s); // VULN
    $p = $_GET['b'];
    $p .= "x";
    mysql_query("SELECT ".$p); // VULN
    $q = $_GET['c'];
    if (settype($q, "integer")) $q = $q;
    mysql_query("SELECT ".$q); // SAFE
    $r = $_GET['d'];
    settype($r, "string");
    mysql_query("SELECT ".$r); // VULN
    """, "DF004")


# ------------------------------------------------------------------------------------- 7. frontend corrections
def test_assignment_in_if_condition_runs_before_both_branches():
    _check("""
    <?php
    $h = fopen("/tmp/in.txt", "r");
    if (($t = fgets($h, 4096)) == false) {
      $x = 1;
    }
    mysql_query("SELECT * FROM x WHERE a='" . $t . "'"); // VULN
    """, "DF004")


def test_backticks_run_a_shell_and_command_output_is_a_local_source():
    _check("""
    <?php
    $a = `cat /tmp/x`;
    mysql_query("SELECT ".$a); // VULN
    exec("/usr/bin/report", $lines);
    mysql_query("SELECT ".$lines[0]); // VULN
    $b = system("ls", $rv);
    mysql_query("SELECT ".$b); // VULN
    echo $b; // SAFE
    """, "DF004", "DF013")
    _check("""
    <?php
    $d = `ls {$_GET['x']}`; // VULN
    $e = `ls -l`; // SAFE
    """, "DF002")


def test_php_string_escapes_are_decoded():
    tree = parse_cfamily('<?php $a = "x\\ty\\"z\\$w"; $b = \'p\\\'q\\\\r\\n\';', "a.php", "php")
    vals = [st.value.value for st in tree.body]
    assert vals == ['x\ty"z$w', "p'q\\r\\n"]


def test_wrapper_keeps_what_it_escaped():
    _check("""
    <?php
    class S { public function clean($i) { return mysql_real_escape_string($i); } }
    $o = new S();
    $t = $o->clean($_GET['a']);
    mysql_query("SELECT * FROM x WHERE a='" . $t . "'"); // SAFE
    mysql_query("SELECT * FROM x WHERE a=" . $t); // VULN
    """, "DF004")


def test_constant_command_is_not_an_audit_finding(tmp_path):
    (tmp_path / "a.php").write_text(textwrap.dedent("""\
        <?php
        $c = shell_exec("cat /tmp/x");
        system("ls", $status);
        system($_GET['a']);
        """), encoding="utf-8")
    findings, _ = scan_path(tmp_path)
    exe = {f.line for f in findings if f.rule_id == "EXE003"}
    assert 2 not in exe and 3 not in exe
    assert any(f.line == 4 and f.rule_id == "DF002" for f in findings)


# ------------------------------------------------------------------------------------------ 8. unit pieces
def test_semantics_units():
    assert php.call_kind(parse_cfamily("<?php f(htmlspecialchars($x, ENT_QUOTES));", "a.php", "php")
                         .body[0].value.args[0], "htmlspecialchars", None) >= php.no("<>\"'")
    assert php._preg_replace_kind("/[^a-z]/", "") == "all"
    assert php._preg_replace_kind("/[^a-z;]/", "") == php.only(set("abcdefghijklmnopqrstuvwxyz;"))
    assert php.sprintf_pieces("a='%s' b=%d %%", ["X", "Y"]) == [("lit", "a='"), ("val", "X"), ("lit", "' b="),
                                                                ("lit", "0"), ("lit", " "), ("lit", "%")]
    st = php.html_advance(php.TEXT, "<div title='")
    assert st.mode == "attr" and st.aq == "'" and php.html_required(st) == frozenset("'")
    assert php.quote_states([("lit", "a='"), ("val", 1), ("lit", "'")], lambda i: None) == [None, "'", "?"]
