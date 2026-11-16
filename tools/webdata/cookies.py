"""Build the cookie classification table ``vulnscan/data/web/cookies.json`` (spec §3.3, §4.4; maintainers only).

    python tools/webdata/cookies.py                         # download the Open Cookie Database CSV (network)
    python tools/webdata/cookies.py --ocd open-cookie-database.csv   # use a local copy (offline / mirror)
    python tools/webdata/cookies.py --no-ocd                # Kashif's own seed table only
    python tools/webdata/cookies.py --check                 # exit 1 when the committed file differs from a rebuild

The table has two layers:

1. **Kashif's seed** (``SEED`` below, the source of truth for every class that changes a finding's severity): the §3.3
   table, ZAP's default session-token names, Observatory's examples and the vendor cookies whose names *look* like
   session cookies but are read by analytics JavaScript (``_hjSession_*``, ``intercom-session-*`` …), so the word
   heuristics of ``webscan/cookies.py`` never turn them into session findings.
2. **Open Cookie Database** (Apache-2.0, NOTICE): its *Analytics* and *Marketing* rows become ``analytics`` and rows of
   consent-management platforms become ``consent``. A row is **not** imported when its name would be classified as
   session/auth/csrf by the word heuristics (the database lists first-party login cookies of big platforms, e.g.
   Instagram's ``sessionid``, X's ``auth_token`` and Google's ``SID``: importing them would hide real session cookies of
   the scanned site), when it is too short or a plain English word (``uid``, ``token``, ``visitor``), when it collides
   with a seed name, or when its name is not a literal cookie name (``pagead/conv/%INTEGER%``).

The output is deterministic (sorted, no timestamps besides the ``--date``), so two runs give identical bytes.
Downloading the whole database leaks nothing about any scan target.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "vulnscan" / "data" / "web" / "cookies.json"
OCD_URL = "https://raw.githubusercontent.com/jkwakman/Open-Cookie-Database/master/open-cookie-database.csv"
OCD_SOURCE = "Open Cookie Database (jkwakman/Open-Cookie-Database), Apache-2.0"

# (pattern, class, source tag). A pattern with "*" or "?" is a case-insensitive glob; anything else is exact.
SEED: list[tuple[str, str, str]] = []


def _add(cls: str, source: str, *names: str) -> None:
    for n in names:
        SEED.append((n, cls, source))


# --- session (§3.3 table; ZAP's default session tokens: asp.net_sessionid, aspsessionid, siteserver, cfid, cftoken,
#     jsessionid, phpsessid, sessid, sid, zenid)
_add("session", "kashif",
     "PHPSESSID", "JSESSIONID", "JSESSIONIDSSO", "ASP.NET_SessionId", "ASPSESSIONID*", ".AspNetCore.Session",
     ".AspNetCore.Cookies", ".AspNetCore.Identity.Application", ".ASPXAUTH", "connect.sid",
     "laravel_session", "sessionid", "_session_id", "_*_session", "ci_session", "MoodleSession", "SESS*", "SSESS*",
     "wordpress_logged_in_*", "wordpress_sec_*", "wordpress_" + "?" * 32, "ORA_WWV_APP_*", "CFID", "CFTOKEN",
     "SITESERVER", "zenid", "sid", "sessid", "session", "frontend", "PrestaShop-*", "symfony", "rack.session",
     "_shibsession_*", "AWSELBAuthSessionCookie*", "KEYCLOAK_SESSION", "KEYCLOAK_SESSION_LEGACY", "AUTH_SESSION_ID",
     "AUTH_SESSION_ID_LEGACY", "PLAY_SESSION", "mod_auth_openidc_session", "phpbb3_*_sid", "xf_session",
     "vbulletin_sessionhash", "bb_sessionhash", "TWIKISID",
     # Matomo's own login session (core/Session.php SESSION_NAME): set only by a Matomo server, never by the tracker
     "MATOMO_SESSID", "PIWIK_SESSID")
# --- auth
_add("auth", "kashif",
     "access_token", "refresh_token", "id_token", "remember_*", "remember_user_token", "auth_token", "jwt",
     "KEYCLOAK_IDENTITY", "KEYCLOAK_IDENTITY_LEGACY", "_oauth2_proxy", "_oauth2_proxy_*",
     "ESTSAUTH", "ESTSAUTHPERSISTENT", "SimpleSAMLAuthToken", "SimpleSAMLSessionID")
# --- csrf
_add("csrf", "kashif",
     "csrftoken", "XSRF-TOKEN", "_csrf", "__RequestVerificationToken", "__RequestVerificationToken_*", "csrf_token",
     "CSRF-TOKEN", ".AspNetCore.Antiforgery.*", "csrf_cookie_name", "_xsrf", "csrf-token", "YII_CSRF_TOKEN",
     "_csrf_token")
# --- analytics (§3.3) and analytics cookies whose names contain session-like words
_add("analytics", "kashif",
     "_ga", "_ga_*", "_gid", "_gat*", "_gcl_*", "_fbp", "_fbc", "_hj*", "_clck", "_clsk", "_uetsid", "_uetvid", "mp_*",
     "ajs_*", "__utm*", "_pk_*", "_ym_*", "amplitude_*", "_hp2_*", "AMP_TOKEN", "AMP_*", "__insp_*", "sbjs_*", "ABTastySession", "ABTasty", "yabs-sid", "DotMetrics.*", "compass_sid", "_zdshared_*",
     "rl_session", "rl_auth_token", "rl_*", "QSI_*", "_rd_wa_first_session*", "_sp_wa_first_session*",
     "wisepops_session", "ab.storage.*", "mnet_session_depth", "sqzl_session_id", "taboola_session_id",
     "DotomiSession_*", "intercom-session-*", "intercom-id-*", "intercom-device-id-*", "_dc_gtm_*", "_gac_*",
     "__hstc", "__hssc", "__hssrc", "hubspotutk", "_vwo_*", "_vis_opt_*", "_mkto_trk", "_lfa", "_lfa_*", "_sp_id.*",
     "_sp_ses.*", "s_cc", "s_sq", "s_vi", "s_fid", "_parsely_session", "_parsely_visitor", "_derived_epik",
     "_pin_unauth", "_tt_enable_cookie", "_ttp", "_scid", "_sctr", "_rdt_uuid", "_ce.s", "_ce.clock_data",
     "_cs_*", "_dd_s", "_hjSession*", "_hjSessionUser*", "_hjAbsoluteSessionInProgress", "_hjIncludedInSessionSample*")
# --- load balancers
_add("lb", "kashif",
     "AWSALB", "AWSALBCORS", "AWSALBTG*", "AWSALBAPP-*", "AWSELB", "AWSELBCORS", "BIGipServer*", "ARRAffinity",
     "ARRAffinitySameSite", "ROUTEID", "SERVERID", "heroku-session-affinity", "GCLB", "INGRESSCOOKIE",
     "ApplicationGatewayAffinity", "ApplicationGatewayAffinityCORS", "NSC_*", "SERVERUSED", "BALANCEID", "JROUTE")
# --- CDN and bot management
_add("cdn_bot", "kashif",
     "__cf_bm", "cf_clearance", "__cflb", "_cfuvid", "__cfruid", "cf_chl_*", "incap_ses_*", "visid_incap_*", "nlbi_*",
     "datadome", "_px*", "ak_bmsc", "bm_sv", "bm_sz", "bm_mi", "_abck", "aws-waf-token", "__ddg*", "TS01*")
# --- consent
_add("consent", "kashif",
     "OptanonConsent", "OptanonAlertBoxClosed", "CookieConsent", "cookieyes-*", "cookielawinfo-*", "euconsent-v2",
     "euconsent", "cookieconsent_status", "CookieLawInfoConsent", "cky-consent", "cmplz_*", "complianz_*",
     "didomi_token", "usprivacy", "OTAdditionalConsentString", "borlabs-cookie", "__cmpconsent*", "cookiefirst-consent",
     "axeptio_*", "osano_consentmanager*", "viewed_cookie_policy", "cookie_notice_accepted", "CONSENT", "SOCS")
# --- preference
_add("preference", "kashif",
     "lang", "locale", "theme", "i18n_redirected", "timezone", "language", "tz", "NEXT_LOCALE", "django_language",
     "pll_language", "_icl_current_language", "wp-settings-*", "wp-settings-time-*", "wordpress_test_cookie",
     "sidebar_state", "currency", "dark_mode", "color_scheme", "font_size")

CLASSES = ("session", "auth", "csrf", "preference", "analytics", "lb", "cdn_bot", "consent")

# --- Open Cookie Database import filters
CMP_PLATFORMS = {"cookiebot", "onetrust", "cookie law info", "cookieyes", "complianz", "consentmanager.net", "osano",
                 "didomi", "iubenda", "axeptio", "borlabs", "cookie first", "termly", "cookieconsent.io", "usercentrics",
                 "trustarc", "quantcast", "hu-manity.co", "civic", "cookie script", "cookie information"}
GENERIC = {"token", "sessionid", "visitor", "viewer", "version", "callback", "audience", "audit", "europe", "locale",
           "hash", "user", "userid", "user_id", "uuid", "guid", "optout", "sync", "usersync", "lantern", "pluto",
           "khaos", "childinfo", "initref", "tearsheet", "session", "login", "auth", "csrf", "lang", "language",
           "theme", "consent", "cookie", "cookies", "test", "debug", "state", "tracking", "visit", "visits", "referrer",
           "source", "campaign", "country", "region", "device", "client", "clientid", "customer", "account"}
_NAME_OK = re.compile(r"^[A-Za-z0-9_.\-:]+\*?$")


def _words(name: str) -> list[str]:
    """The same word split as ``webscan.cookies.name_words`` (kept in sync by a test)."""
    s = re.sub(r"([a-z])([A-Z])", r"\1 \2", name)
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", s)
    return [w.lower() for w in re.split(r"[^A-Za-z]+", s) if w]


def heuristic_hit(name: str) -> bool:
    """True when the word heuristics of §3.3 would call ``name`` session, auth or csrf."""
    low = name.lower()
    if "csrf" in low or "xsrf" in low:
        return True
    for w in _words(name):
        if w.startswith("sess") or w in ("sid", "login", "auth", "token", "jwt", "remember"):
            return True
        if w.endswith(("session", "sessid", "sessionid")):
            return True
    return False


def ocd_entries(text: str, seed_names: set[str]) -> tuple[list[dict], dict[str, int]]:
    rows = list(csv.DictReader(io.StringIO(text)))
    if not rows or "Cookie / Data Key name" not in rows[0]:
        raise SystemExit("not an Open Cookie Database CSV (missing 'Cookie / Data Key name')")
    stats = {"rows": len(rows), "imported": 0, "heuristic": 0, "generic": 0, "collision": 0, "shape": 0, "category": 0}
    out: dict[str, dict] = {}
    for r in rows:
        name = (r.get("Cookie / Data Key name") or "").strip()
        cat = (r.get("Category") or "").strip().lower()
        platform = (r.get("Platform") or "").strip()
        wildcard = (r.get("Wildcard match") or "").strip() == "1"
        if cat in ("analytics", "marketing"):
            cls = "analytics"
        elif platform.lower() in CMP_PLATFORMS or "consent" in name.lower():
            cls = "consent"
        else:
            stats["category"] += 1
            continue
        if not name or not _NAME_OK.match(name):
            stats["shape"] += 1
            continue
        pattern = name if name.endswith("*") else (name + "*" if wildcard else name)
        literal = pattern.rstrip("*")
        core = literal.strip("_-.:")
        if len(core) < 4 or literal.lower() in GENERIC or core.lower() in GENERIC:
            stats["generic"] += 1
            continue
        if heuristic_hit(literal):
            stats["heuristic"] += 1
            continue
        key = pattern.lower()
        if key in seed_names or key in out:
            stats["collision"] += 1
            continue
        entry = {"name": pattern, "match": "glob" if "*" in pattern else "exact", "class": cls, "source": "ocd"}
        if platform:
            entry["vendor"] = platform[:80]
        out[key] = entry
        stats["imported"] += 1
    return list(out.values()), stats


def seed_entries() -> list[dict]:
    seen: dict[str, dict] = {}
    for name, cls, source in SEED:
        if cls not in CLASSES:
            raise SystemExit(f"seed: bad class {cls!r} for {name!r}")
        key = name.lower()
        if key in seen:
            if seen[key]["class"] != cls:
                raise SystemExit(f"seed: {name!r} listed as {seen[key]['class']} and {cls}")
            continue
        seen[key] = {"name": name, "match": "glob" if ("*" in name or "?" in name) else "exact", "class": cls,
                     "source": source}
    return list(seen.values())


def build(ocd_text: str | None, date: str) -> tuple[dict, dict]:
    entries = seed_entries()
    stats: dict[str, int] = {"seed": len(entries)}
    if ocd_text is not None:
        imported, s = ocd_entries(ocd_text, {e["name"].lower() for e in entries})
        entries += imported
        stats.update(s)
    entries.sort(key=lambda e: (CLASSES.index(e["class"]), e["source"] != "kashif", e["name"].lower(), e["name"]))
    source = "Kashif seed (spec §3.3: ZAP default session tokens, MDN Observatory heuristics, framework defaults)"
    license_ = "Kashif seed: project licence"
    if ocd_text is not None:
        source += " + " + OCD_SOURCE
        license_ += "; Open Cookie Database rows: Apache-2.0 (see NOTICE)"
    notes = ("Classes: session, auth, csrf, preference, analytics, lb, cdn_bot, consent. Open Cookie Database rows are "
             "imported only for Analytics/Marketing (as analytics) and consent platforms, and never when the name "
             "looks like a session, auth or CSRF cookie.")
    meta = {"schema_version": 1, "date": date, "source": source, "license": license_,
            "generator": "tools/webdata/cookies.py", "notes": notes}
    if ocd_text is not None:
        meta["upstream_version"] = "csv-sha256:" + hashlib.sha256(ocd_text.encode("utf-8")).hexdigest()[:16]
    return {"meta": meta, "entries": entries}, stats


def dump(obj: dict) -> bytes:
    """One entry per line: small diffs, deterministic bytes."""
    lines = ['{', '  "meta": ' + json.dumps(obj["meta"], ensure_ascii=False, sort_keys=True) + ',', '  "entries": [']
    for i, e in enumerate(obj["entries"]):
        lines.append("    " + json.dumps(e, ensure_ascii=False, sort_keys=True) + ("," if i + 1 < len(obj["entries"]) else ""))
    lines += ["  ]", "}", ""]
    return "\n".join(lines).encode("utf-8")


def fetch(url: str = OCD_URL, timeout: float = 60.0) -> str:
    sys.path.insert(0, str(ROOT))
    from vulnscan import __version__
    req = urllib.request.Request(url, headers={"User-Agent": f"Kashif/{__version__} webdata-refresh"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:   # nosec - fixed maintainer URL
        return resp.read(16 * 1024 * 1024).decode("utf-8")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--ocd", metavar="CSV", help="local copy of open-cookie-database.csv")
    src.add_argument("--no-ocd", action="store_true", help="seed table only")
    ap.add_argument("--date", default=datetime.now(timezone.utc).strftime("%Y-%m-%d"), help="snapshot date (YYYY-MM-DD)")
    ap.add_argument("--out", default=str(OUT))
    ap.add_argument("--check", action="store_true", help="compare with --out instead of writing (keeps its date)")
    args = ap.parse_args(argv)
    out = Path(args.out)
    date = args.date
    if args.check and out.is_file():
        date = json.loads(out.read_text(encoding="utf-8"))["meta"]["date"]
    if args.no_ocd:
        text = None
    elif args.ocd:
        text = Path(args.ocd).read_text(encoding="utf-8")
    else:
        text = fetch()
    obj, stats = build(text, date)  # nosec - maintainer tool
    sys.path.insert(0, str(ROOT))
    from vulnscan.webscan import data
    errs = data.validate_data("cookies.json", obj)
    if errs:
        raise SystemExit("schema errors:\n" + "\n".join(errs))
    raw = dump(obj)
    if args.check:
        same = out.is_file() and out.read_bytes() == raw
        print("cookies.json is up to date" if same else "cookies.json differs from a rebuild")
        return 0 if same else 1
    out.write_bytes(raw)
    print(f"wrote {out} ({len(raw)} bytes): {stats}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
