"""The README (published as the site's docs page) must describe the current release: its "What's new" section in
both halves names the major.minor version in vulnscan.__version__, and the CHANGELOG has an entry for that version.
Added after 1.4.0, when the docs page still said «الجديد في 1.0»."""

from __future__ import annotations

import pathlib
import re

import vulnscan

ROOT = pathlib.Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8")
CHANGELOG = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
MAJOR_MINOR = ".".join(vulnscan.__version__.split(".")[:2])


def test_english_whats_new_names_the_current_minor_version():
    found = re.findall(r"^## What's new in (\d+\.\d+)\s*$", README, re.M)
    assert found == [MAJOR_MINOR], (found, vulnscan.__version__)


def test_arabic_whats_new_names_the_current_minor_version():
    found = re.findall(r"^### الجديد في (\d+\.\d+)\s*$", README, re.M)
    assert found == [MAJOR_MINOR], (found, vulnscan.__version__)


def test_changelog_has_the_current_version_first():
    first = re.search(r"^## v(\d+\.\d+\.\d+)\s*$", CHANGELOG, re.M)
    assert first and first.group(1) == vulnscan.__version__, (first and first.group(1), vulnscan.__version__)
