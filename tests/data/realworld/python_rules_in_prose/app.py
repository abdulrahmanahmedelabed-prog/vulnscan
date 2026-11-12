import os
import re
import subprocess

import requests

FIXES = {
    "verify": "Remove verify=False so TLS certificate verification returns to its default (enabled).",
}
QUERY = """
where c.name matches "^acme\\.http\\." and c.kwargs contains "verify=False"
"""
LABELS = {
    "secret": "secret",
    "password": "Password",
}
_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")
_ACCOUNT_KEY = re.compile(r"(?i)AccountKey=([A-Za-z0-9+/]{20,}={0,2})")


def skip():
    return None          # `import os; os.system(...)`: a comment about the call, not the call


def fetch(url):
    return requests.get(url, verify=False)


def fetch_both(url):
    msg = "verify=False is unsafe"; return requests.get(url, verify=False)   # noqa: E702


def run(cmd):
    os.system(cmd)
    subprocess.run(cmd, shell=True)


def is_weak(q):
    return q in ("hashlib.md5", "hashlib.sha1")


def mode_bits(p):
    return p.stat().st_mode & 0o777


def weak_and_open(p, data):
    import hashlib
    os.chmod(p, 0o777)
    return hashlib.md5(data).hexdigest()
