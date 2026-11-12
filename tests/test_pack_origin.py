"""`kashif rules install` / `verify` without --sha256: integrity is checked, origin is not, and the CLI says so.

1.x keeps installing without --sha256 (stability contract); the warning names the archive's real SHA-256 so it can be
compared with the publisher's, and --require-sha256 / KASHIF_REQUIRE_PACK_SHA256=1 make the hash mandatory.
"""

from __future__ import annotations

import pytest

from vulnscan import ruletest as rt


@pytest.fixture()
def archive(tmp_path, monkeypatch):
    monkeypatch.delenv("KASHIF_REQUIRE_PACK_SHA256", raising=False)
    monkeypatch.delenv("KASHIF_LANG", raising=False)
    src = tmp_path / "team-rules"
    rt.new_pack(src, None, "python")
    return rt.build_pack(src, tmp_path / "out")


def test_install_without_sha256_warns_with_the_actual_hash(archive, tmp_path, capsys):
    packs = tmp_path / "packs"
    assert rt.main(["install", str(archive.path), "--packs-dir", str(packs)]) == 0       # still installs (1.x)
    err = capsys.readouterr().err
    assert "origin not verified" in err and archive.sha256 in err and "--sha256" in err
    assert [p["name"] for p in rt.installed_packs(packs)] == ["team-rules"]


def test_install_without_sha256_warns_in_arabic(archive, tmp_path, capsys):
    assert rt.main(["--lang", "ar", "install", str(archive.path), "--packs-dir", str(tmp_path / "packs")]) == 0
    err = capsys.readouterr().err
    assert "المصدر غير مُتحقَّق منه" in err and archive.sha256 in err


def test_verify_without_sha256_warns_too(archive, capsys):
    assert rt.main(["verify", str(archive.path)]) == 0
    captured = capsys.readouterr()
    assert "origin not verified" in captured.err and archive.sha256 in captured.err


def test_no_warning_when_the_hash_was_given(archive, tmp_path, capsys):
    assert rt.main(["verify", str(archive.path), "--sha256", archive.sha256]) == 0
    assert rt.main(["install", str(archive.path), "--packs-dir", str(tmp_path / "packs"), "--sha256", archive.sha256]) == 0
    assert "origin not verified" not in capsys.readouterr().err


@pytest.mark.parametrize("how", ["flag", "env"])
def test_require_sha256_refuses_and_installs_nothing(archive, tmp_path, capsys, monkeypatch, how):
    packs = tmp_path / "packs"
    argv = ["install", str(archive.path), "--packs-dir", str(packs)]
    if how == "flag":
        argv.append("--require-sha256")
    else:
        monkeypatch.setenv("KASHIF_REQUIRE_PACK_SHA256", "1")
    assert rt.main(argv) == 2
    err = capsys.readouterr().err
    assert "--sha256 is required" in err and archive.sha256 in err
    assert not packs.exists() or rt.installed_packs(packs) == []
    assert rt.main([*argv, "--sha256", archive.sha256]) == 0       # with the hash it installs
    assert [p["name"] for p in rt.installed_packs(packs)] == ["team-rules"]


def test_require_sha256_still_reports_a_missing_archive(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("KASHIF_REQUIRE_PACK_SHA256", raising=False)
    assert rt.main(["install", str(tmp_path / "absent.kashifpack"), "--require-sha256"]) == 2
    assert "archive not found" in capsys.readouterr().err


def test_strings_exist_in_both_languages():
    for key in ("w_origin", "e_sha_required"):
        assert rt.STR["en"][key] and rt.STR["ar"][key] and rt.STR["en"][key] != rt.STR["ar"][key]
