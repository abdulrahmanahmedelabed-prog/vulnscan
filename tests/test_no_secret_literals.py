"""No committed file may contain a literal that looks like a real credential.

Secret-detection tests need token-shaped strings, but storing them literally makes GitHub push protection reject
pushes and makes every secret scanner flag this repository for anyone who clones it. Build such strings at run time
instead (e.g. ``"hf_" + "x" * 34``). Well-known documentation examples (AWS's AKIAIOSFODNN7EXAMPLE) are allowed.
"""

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Formats that GitHub push protection and common scanners treat as live credentials.
TOKEN_SHAPES = [
    ("Hugging Face token", r"\bhf_[A-Za-z]{34}\b"),
    ("GitHub token", r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b"),
    ("GitHub fine-grained token", r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
    ("GitLab token", r"\bglpat-[A-Za-z0-9_-]{20}\b"),
    ("Slack token", r"\bxox[abprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9-]{20,}"),
    ("OpenAI key", r"\bsk-(?:proj-)?[A-Za-z0-9_-]{40,}\b"),
    ("Anthropic key", r"\bsk-ant-api03-[A-Za-z0-9_-]{80,}"),
    ("Stripe live key", r"\b[rs]k_live_[A-Za-z0-9]{24,}\b"),
    ("AWS access key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("Google API key", r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ("npm token", r"\bnpm_[A-Za-z0-9]{36}\b"),
    ("PyPI token", r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}"),
    ("SendGrid key", r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"),
    ("Private key block", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----\s*\n[A-Za-z0-9+/=\n]{200,}"),
]
ALLOWED = {"AKIAIOSFODNN7EXAMPLE"}          # AWS's documented example key
SKIP_DIRS = {".git", "node_modules", "__pycache__", "dist", "build", "dist-download", ".venv", "venv"}
TEXT_SUFFIXES = {".py", ".js", ".ts", ".java", ".kt", ".cs", ".go", ".php", ".rb", ".rs", ".swift", ".c", ".cpp", ".h",
                 ".txt", ".md", ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".env", ".properties", ".xml",
                 ".html", ".sh", ".tf", ".sql", ".vql", ".dockerfile", ""}


def _files():
    for p in ROOT.rglob("*"):
        if any(part in SKIP_DIRS for part in p.relative_to(ROOT).parts) or not p.is_file():
            continue
        if p.suffix.lower() in TEXT_SUFFIXES and p.stat().st_size < 2_000_000:
            yield p


def test_no_credential_shaped_literals():
    hits = []
    for p in _files():
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for label, rx in TOKEN_SHAPES:
            for m in re.finditer(rx, text):
                if m.group(0) not in ALLOWED:
                    line = text.count("\n", 0, m.start()) + 1
                    hits.append(f"{p.relative_to(ROOT)}:{line}: {label}")
    assert not hits, "credential-shaped literals (build them at run time instead):\n" + "\n".join(hits)
