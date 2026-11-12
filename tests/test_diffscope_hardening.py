"""--diff-base / --diff-staged must not let a hostile .git/config run commands."""
import shutil
import subprocess

import pytest

from vulnscan import diffscope
from vulnscan.i18n import to_en

pytestmark = pytest.mark.skipif(not shutil.which("git"), reason="git not installed")


def _repo(tmp_path):
    def g(*a):
        subprocess.run(["git", *a], cwd=tmp_path, check=True, capture_output=True)
    g("init", "-q")
    g("config", "user.email", "t@example.invalid")
    g("config", "user.name", "t")
    (tmp_path / "a.py").write_text("x = 1\n")
    g("add", "a.py")
    g("commit", "-q", "-m", "init")
    return g


def test_fsmonitor_and_hooks_are_not_run(tmp_path):
    g = _repo(tmp_path)
    marker = tmp_path / "pwned"
    g("config", "core.fsmonitor", f"touch {marker}; false")
    (tmp_path / "a.py").write_text("x = 2\n")
    scope = diffscope.compute(str(tmp_path), base="HEAD")
    assert "a.py" in scope.changed
    assert not marker.exists()


def test_content_filter_repository_is_refused(tmp_path):
    g = _repo(tmp_path)
    marker = tmp_path / "pwned"
    g("config", "filter.evil.clean", f"touch {marker}; cat")
    (tmp_path / ".gitattributes").write_text("*.py filter=evil\n")
    (tmp_path / "a.py").write_text("x = 3\n")
    with pytest.raises(diffscope.DiffScopeError) as e:
        diffscope.compute(str(tmp_path), base="HEAD")
    assert not marker.exists()
    assert "content filter" in to_en(str(e.value))
