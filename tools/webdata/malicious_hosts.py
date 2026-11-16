"""Write and validate ``vulnscan/data/web/malicious-hosts.json`` (WEB506 hosts, WEB507 signatures). Maintainers only.

    python tools/webdata/malicious_hosts.py                  # rewrite the file from the curated seed below
    python tools/webdata/malicious_hosts.py --check          # exit 1 when the bundled file differs from the seed
    python tools/webdata/malicious_hosts.py --zap PolyfillCdnScriptScanRule.java
                                                             # also merge the host list of a ZAP source file

The list is curated (no network access needed): the hosts of ZAP's ``PolyfillCdnScriptScanRule`` (10115, Apache-2.0;
the host names are facts) and exact miner / loader / defacement signatures in the spirit of the MIT nuclei templates
``crypto-mining-malware``, ``balada-injector-malware`` and ``defacement-detect``. Only exact, specific signatures are
allowed: never generic obfuscation such as ``eval(atob(``. The output is deterministic (sorted, fixed layout), so a
rerun without changes produces the same bytes; ``--date`` sets ``meta.date`` (default: keep the bundled date).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "vulnscan" / "data" / "web" / "malicious-hosts.json"
DEFAULT_DATE = "2026-11-13"

_POLYFILL = ("polyfill.io supply-chain compromise (June 2024): the CDN served injected redirects to scam sites; "
             "the same operator ran these domains")
# ZAP 10115 list (suffix match: the domain and every subdomain)
HOSTS = [
    ("polyfill.io", "suffix", _POLYFILL, "2024-06-25"),
    ("bootcss.com", "suffix", _POLYFILL, "2024-06-25"),
    ("bootcdn.net", "suffix", _POLYFILL, "2024-06-25"),
    ("staticfile.net", "suffix", _POLYFILL, "2024-06-25"),
    ("staticfile.org", "suffix", _POLYFILL, "2024-06-25"),
    ("unionadjs.com", "suffix", "malicious ad/redirect domain injected by the compromised polyfill.io CDN", "2024-06-25"),
    ("xhsbpza.com", "suffix", "malicious redirect domain injected by the compromised polyfill.io CDN", "2024-06-25"),
    ("union.macoms.la", "suffix", "malicious redirect domain injected by the compromised polyfill.io CDN", "2024-06-25"),
    ("newcrbpc.com", "suffix", "malicious redirect domain injected by the compromised polyfill.io CDN", "2024-06-25"),
]

# (id, kind, regex, flags). miner/loader patterns are searched in live inline scripts, script URLs and fetched script
# bodies; a defacement pattern must match both the page title and its visible text.
SIGNATURES = [
    ("coinhive-api", "miner", r"\bCoinHive\.(?:Anonymous|User|Token)\b", ""),
    ("coinhive-host", "miner", r"\b(?:coinhive\.com|coin-hive\.com|authedmine\.com)\b", "i"),
    ("coinhive-lib", "miner", r"\bcoinhive(?:\.min)?\.js\b", "i"),
    ("cryptoloot", "miner", r"\b(?:crypto-loot\.com|cryptoloot\.pro)\b|\bCRLT\.Anonymous\b", "i"),
    ("webminepool", "miner", r"\bwebminepool\.com\b", "i"),
    ("coinimp", "miner", r"\bcoinimp\.com\b", "i"),
    ("jsecoin", "miner", r"\bload\.jsecoin\.com\b", "i"),
    ("minero", "miner", r"\bminero\.cc\b", "i"),
    ("balada-stablelightway", "loader", r"\btrend\.stablelightway\.com\b", "i"),
    ("balada-scriptsplatform", "loader", r"\bstatistic\.scriptsplatform\.com\b", "i"),
    ("balada-specialtaskevents", "loader", r"\bcdn\.specialtaskevents\.com\b", "i"),
    ("balada-tracker-statistics", "loader", r"\bttt\.tracker-statistics\.com\b", "i"),
    ("defacement-hacked-by", "defacement", r"\b(?:hacked|h4ck3d|defaced)\s+by\b", "i"),
]

_ZAP_HOST = re.compile(r"((?:[a-z0-9-]+\\\\?\.)+[a-z]{2,})", re.I)


def zap_hosts(java_source: str) -> list[str]:
    """Host names from the regular expression in ZAP's PolyfillCdnScriptScanRule source (``polyfill\\.io`` …)."""
    out: list[str] = []
    for m in re.finditer(r'"([^"]*(?:polyfill|bootcss)[^"]*)"', java_source):
        for h in _ZAP_HOST.findall(m.group(1)):
            name = h.replace("\\\\", "").replace("\\", "").lower()
            if name not in out:
                out.append(name)
    return out


def build(date: str, extra_hosts: list[str] = ()) -> dict:
    hosts = {h: {"host": h, "match": m, "reason": r, "since": s} for h, m, r, s in HOSTS}
    for h in extra_hosts:
        hosts.setdefault(h, {"host": h, "match": "suffix", "reason": "listed by ZAP PolyfillCdnScriptScanRule (10115)"})
    sigs = [{"id": i, "kind": k, "pattern": p, **({"flags": f} if f else {})} for i, k, p, f in SIGNATURES]
    for s in sigs:
        re.compile(s["pattern"])          # fail early on a broken pattern
    return {
        "meta": {"schema_version": 1, "date": date, "generator": "tools/webdata/malicious_hosts.py",
                 "source": "Kashif curated list: ZAP pscanrules PolyfillCdnScriptScanRule (10115) host names; miner, "
                           "loader and defacement signatures after the nuclei templates crypto-mining-malware, "
                           "balada-injector-malware and defacement-detect",
                 "license": "Kashif project licence; host names from ZAP (Apache-2.0) and nuclei-templates (MIT) are "
                            "facts (see NOTICE)",
                 "notes": "WEB506 matches hosts (suffix = the domain and its subdomains); WEB507 uses only exact "
                          "signatures, never generic obfuscation patterns."},
        "hosts": [hosts[h] for h in sorted(hosts)],
        "signatures": sorted(sigs, key=lambda s: (s["kind"], s["id"])),
    }


def render(doc: dict) -> str:
    return json.dumps(doc, ensure_ascii=False, indent=1, sort_keys=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="compare with the bundled file instead of writing it")
    ap.add_argument("--zap", help="path of ZAP's PolyfillCdnScriptScanRule.java to merge its host list")
    ap.add_argument("--date", help="meta.date (YYYY-MM-DD); default: keep the bundled date")
    args = ap.parse_args(argv)
    date = args.date
    if date is None:
        try:
            date = json.loads(OUT.read_text(encoding="utf-8"))["meta"]["date"]
        except (OSError, ValueError, KeyError):
            date = DEFAULT_DATE
    extra = zap_hosts(Path(args.zap).read_text(encoding="utf-8")) if args.zap else []
    text = render(build(date, extra))
    sys.path.insert(0, str(ROOT))
    from vulnscan.webscan import data
    errors = data.validate_data(OUT.name, json.loads(text))
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    if args.check:
        current = OUT.read_text(encoding="utf-8") if OUT.is_file() else ""
        if current != text:
            print(f"{OUT} is not what the seed produces; run without --check", file=sys.stderr)
            return 1
        return 0
    OUT.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {OUT} ({len(text)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
