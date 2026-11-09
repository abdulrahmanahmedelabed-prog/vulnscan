"""Real vulnerabilities that an independent adversarial review showed the 0.7 precision work had hidden.

Each file under tests/data/regress is a small, realistic vulnerable program (loops with flags, aliasing,
try/except, deny-lists that are not validation, prefix checks, escaped + raw concatenation, Flask get_json, Java
switch/collections, ...). Every one must stay reported: precision work may never silence a real flaw."""

import json
import pathlib
import shutil

import pytest

from vulnscan.scanner import scan_path

DATA = pathlib.Path(__file__).parent / "data" / "regress"
EXPECTED = json.loads((DATA / "expected.json").read_text())


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_still_reported(tmp_path, name):
    shutil.copy(DATA / name, tmp_path / name)
    got = {f.rule_id for f in scan_path(tmp_path, [], set())[0]}
    assert set(EXPECTED[name]) <= got, (name, sorted(got))
