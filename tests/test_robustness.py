"""Robustness: hostile, generated or broken input must never crash a scan or make it hang.

A scanner runs on code it does not trust. A single file that crashes a frontend would hide every other finding
in the repository (a denial of service against the scanner itself), so every frontend gets random bytes,
truncated syntax, pathological nesting and very long lines, and the whole scan must complete in bounded time.
"""

import pathlib
import random
import time
import zipfile

import pytest

from vulnscan.scanner import scan_path

EXTS = [".py", ".js", ".ts", ".java", ".kt", ".cs", ".go", ".php", ".c", ".cpp", ".rs", ".swift", ".rb", ".sql",
        ".pls", ".pkb", ".xml", ".yaml", ".yml", ".json", ".html", ".env", ".properties", ".tf", ".sh", ".dart"]
SNIPPETS = ["def f(x):\n", "class A {", "function g(a, b) {", "if (", "for x in y:", "BEGIN", "END;", "{{", "}}",
            "'''", '"""', "/*", "*/", "<?php", "?>", "<script>", "eval(", "os.system(", "request.args[", "SELECT * FROM t WHERE",
            "EXECUTE IMMEDIATE", "${", "#{", "\\", "\x00", "﻿", "‮", "λ", "؟", "🙂", "match x:", "case _:",
            "try:", "except:", "lambda: (", "[" * 3, "(" * 3, "-----BEGIN CERTIFICATE-----", "api_key = '", "@app.route('/')"]


def _junk(rng: random.Random, n: int) -> str:
    parts = []
    for _ in range(n):
        r = rng.random()
        if r < 0.5:
            parts.append(rng.choice(SNIPPETS))
        elif r < 0.8:
            parts.append("".join(rng.choice("abcxyz_ =+-*/()[]{}<>:;,.'\"\n\t0123456789") for _ in range(rng.randint(1, 40))))
        else:
            parts.append("".join(chr(rng.randint(1, 0x2FFF)) for _ in range(rng.randint(1, 10))))
    return "".join(parts)


def _pathological() -> dict[str, str]:
    deep = 400
    return {
        "deep_parens.py": "x = " + "(" * deep + "1" + ")" * deep + "\n",
        "deep_lists.js": "const a = " + "[" * deep + "]" * deep + ";\n",
        "deep_blocks.java": "class A { void f() { " + "if (x) { " * deep + "}" * deep + " } }\n",
        "deep_calls.go": "package m\nfunc f() { " + "g(" * deep + ")" * deep + " }\n",
        "long_line.py": "s = '" + "a" * 200_000 + "'\n",
        "many_lines.py": "x = 1\n" * 50_000,
        "chain.py": "y = a" + ".b" * 3000 + "\n",
        "concat.php": "<?php $q = " + " . ".join(["$x"] * 3000) + ";\n",
        "plsql.sql": "BEGIN\n" * 300 + "NULL;\n" + "END;\n" * 300,
        "unterminated.py": "def f(:\n    '''never closed\n",
        "unterminated.js": "function f( { `never closed ${\n",
        "nul.py": "x = 1\x00\x00\x00y = 2\n",
        "bom_rtl.py": "﻿import os\n# ‮evil\nos.system(input())\n",
        "binary.java": "".join(chr(b) for b in range(256)) * 20,
    }


def _scan_ok(root: pathlib.Path, budget: float) -> list:
    t = time.monotonic()
    findings, files = scan_path(root, [], set())
    took = time.monotonic() - t
    assert files > 0
    assert took < budget, f"scan took {took:.1f}s"
    return findings


@pytest.mark.parametrize("seed", range(6))
def test_random_garbage_never_crashes(tmp_path, seed):
    rng = random.Random(seed)
    for i, ext in enumerate(EXTS):
        (tmp_path / f"f{i}{ext}").write_text(_junk(rng, rng.randint(5, 400)), encoding="utf-8", errors="surrogatepass")
    (tmp_path / "raw.bin.py").write_bytes(bytes(rng.randrange(256) for _ in range(4000)))
    _scan_ok(tmp_path, budget=60)


def test_pathological_inputs_never_crash(tmp_path):
    for name, text in _pathological().items():
        (tmp_path / name).write_text(text, encoding="utf-8", errors="surrogatepass")
    # a real issue next to the hostile files must still be reported
    (tmp_path / "real.py").write_text("import os\nfrom flask import request\n@app.route('/x')\ndef x():\n"
                                      "    os.system(request.args['c'])\n")
    findings = _scan_ok(tmp_path, budget=120)
    assert any(f.file == "real.py" and f.rule_id.startswith("DF") for f in findings)


def test_hostile_archive(tmp_path):
    """Path traversal entries, absolute paths and a large compression ratio inside an archive."""
    z = tmp_path / "evil.zip"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("../../escape.py", "import os\nos.system(input())\n")
        zf.writestr("/abs/path.py", "x = 1\n")
        zf.writestr("ok/app.py", "import pickle\npickle.loads(data)\n")
        zf.writestr("big.txt", "0" * 5_000_000)
    findings, _ = scan_path(z, [], set(), jadx=False)
    assert not (tmp_path.parent / "escape.py").exists() and not pathlib.Path("/abs/path.py").exists()
    assert any("app.py" in f.file for f in findings)


def test_symlink_loop(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "x.py").write_text("x = 1\n")
    try:
        (tmp_path / "a" / "loop").symlink_to(tmp_path / "a", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported here")
    _scan_ok(tmp_path, budget=60)
