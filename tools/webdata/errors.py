"""Write and validate the information-disclosure data files of WP8 (spec §2.7). Maintainers only.

    python tools/webdata/errors.py                      # rewrite the three files from the curated tables below
    python tools/webdata/errors.py --check              # exit 1 when a bundled file differs from the tables
    python tools/webdata/errors.py --zap-xml application_errors.xml
                                                        # also merge the plain-string patterns of ZAP's list

Files written (``vulnscan/data/web/``):

* ``error-signatures.json`` — stack traces and detailed errors (WEB056), framework debug pages (WEB605), database errors
  (WEB606), server paths in error output (WEB607), version banners on error pages (WEB616) and default/parked pages
  (WEB617). The signatures are Kashif's own, written from the public error formats of each platform; ``--zap-xml``
  optionally merges the literal strings of ZAP's ``application_errors.xml`` (Apache-2.0, see NOTICE) as extra WEB056 /
  WEB606 ``contains`` signatures. Each signature uses the shared body-signature schema of ``webscan.data``
  (``all``/``any``/``none`` conditions of type regex, contains, magic or prefix, with ``min_count`` and ``within``).
* ``leak-headers.json`` — response headers that reveal backend software (WEB600) or debug/profiler output (WEB601). The
  list is re-derived by Kashif from vendor documentation; OSHP's CC BY-SA list was used only as a cross-check and is not
  copied. A name containing ``*`` is a case-insensitive glob (``X-Laravel-*-Debug``).
* ``secret-rules.json`` — the ids of Kashif's prefix-anchored SEC rules (``history.secret_rules()``) that are applied to
  client-side code, the web-only extra patterns (with an optional ``secret`` named group for the value) and the
  publishable-key prefixes that are never reported.

The output is deterministic (fixed order and layout): a rerun without changes produces the same bytes. No network access.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "vulnscan" / "data" / "web"
DEFAULT_DATE = "2026-11-13"
GENERATOR = "tools/webdata/errors.py"


def rx(pattern: str, flags: str = "", **kw) -> dict:
    d = {"type": "regex", "pattern": pattern}
    if flags:
        d["flags"] = flags
    d.update(kw)
    return d


def has(text: str, flags: str = "", **kw) -> dict:
    d = {"type": "contains", "pattern": text}
    if flags:
        d["flags"] = flags
    d.update(kw)
    return d


def sig(id_: str, rule: str, platform: str, *, all_=None, any_=None, none=None, status: str = "any",
        severity: str | None = None, confidence: str | None = None, debug_marker: bool = False,
        not_html: bool = False) -> dict:
    s: dict = {}
    if all_:
        s["all"] = all_
    if any_:
        s["any"] = any_
    if none:
        s["none"] = none
    if not_html:
        s["not_html"] = True
    out = {"id": id_, "rule": rule, "platform": platform, "signature": s, "status": status}
    if severity:
        out["severity"] = severity
    if confidence:
        out["confidence"] = confidence
    if debug_marker:
        out["debug_marker"] = True
    return out


# quoted file name in a Python traceback, raw or HTML-escaped (Werkzeug wraps it in <cite>)
_PYQ = r"""(?:"|&quot;|&#34;|&#x22;)"""
_ERRWORD = r"\b(?:[Ee]rror|ERROR|[Ee]xception|[Ww]arning|[Ff]atal|[Ff]ailed|Traceback|No such file|on line|[Ss]tack)\b"

SIGNATURES = [
    # ---------------------------------------------------------------- WEB605 framework debug mode (debug-page markers)
    # Debug pages are served with 4xx/5xx; on a 2xx page only markup markers count (a blog post or the framework's own
    # documentation quotes the page's prose — "Werkzeug Debugger", "You're seeing this error because …" — in text).
    sig("werkzeug-debugger", "WEB605", "Werkzeug", severity="critical", debug_marker=True,
        all_=[has("Werkzeug"), has("__debugger__")],
        any_=[has('class="debugger"'), rx(r"<title>[^<]{0,300}// Werkzeug Debugger\s*</title>")]),
    sig("werkzeug-debugger-error", "WEB605", "Werkzeug", status="error", severity="critical", debug_marker=True,
        all_=[has("Werkzeug")],
        any_=[has("__debugger__"), has("Werkzeug Debugger"), has('class="debugger"'),
              has("The debugger caught an exception")]),
    sig("django-debug", "WEB605", "Django", status="error", severity="high", debug_marker=True,
        all_=[rx(r"You(?:'|’|&#39;|&#x27;|&rsquo;)re seeing this error because you have\s*(?:<code>)?\s*DEBUG\s*=\s*True")],
        any_=[has("Django tried these URL patterns"), has("URLconf"), has("Exception Value:"), has("Request Method:"),
              has("Django Version:")]),
    sig("django-debug-toolbar", "WEB605", "Django", severity="high", debug_marker=True,
        all_=[rx(r"""<div[^>]{1,300}id=["']djDebug["']""")]),
    sig("laravel-ignition", "WEB605", "Laravel", severity="high", debug_marker=True,
        any_=[rx(r"\bwindow\.ignite\s*\("), rx(r"""<script[^>]{1,300}id=["']ignition""")]),
    sig("laravel-ignition-error", "WEB605", "Laravel", status="error", severity="high", debug_marker=True,
        all_=[rx(r"(?:facade|spatie)/(?:laravel-)?ignition\b")]),
    sig("php-whoops", "WEB605", "Whoops (PHP)", severity="high", debug_marker=True,
        all_=[has("Whoops")], any_=[has('class="Whoops container"'), has('id="plain-exception"')]),
    sig("php-whoops-error", "WEB605", "Whoops (PHP)", status="error", severity="high", debug_marker=True,
        all_=[has("Whoops\\Handler\\PrettyPageHandler")]),
    sig("symfony-toolbar", "WEB605", "Symfony", severity="high", debug_marker=True,
        any_=[rx(r"""<div[^>]{1,300}id=["']sfwdt"""), rx(r"""<div[^>]{1,300}class=["']sf-toolbar""")]),
    sig("symfony-debug", "WEB605", "Symfony", status="error", severity="high", debug_marker=True,
        all_=[has("symfony", "i")],
        any_=[has('class="exception-message-wrapper"'), has('class="trace-line'), has("Symfony\\Component\\ErrorHandler")]),
    sig("rails-web-console", "WEB605", "Ruby on Rails", severity="critical", debug_marker=True,
        all_=[has("__web_console")], any_=[has("Action Controller: Exception caught"), has("data-mount-point")]),
    sig("rails-debug", "WEB605", "Ruby on Rails", status="error", severity="high", debug_marker=True,
        all_=[has("Action Controller: Exception caught")]),
    sig("aspnet-ysod", "WEB605", "ASP.NET", status="error", severity="high", debug_marker=True,
        all_=[rx(r"Server Error in '[^'<]{0,200}' Application"), has("Stack Trace:")]),
    sig("spring-whitelabel-trace", "WEB605", "Spring Boot", status="error", severity="high", debug_marker=True,
        all_=[has("Whitelabel Error Page")],
        any_=[rx(r"\bat (?:org\.springframework|java\.|javax\.|jakarta\.)[\w.$]{1,300}\("),
              rx(r'"trace"\s*:\s*"[\w.$]{1,300}?(?:Exception|Error)')]),
    sig("spring-json-trace", "WEB605", "Spring Boot", severity="high", debug_marker=True,
        all_=[rx(r'"status"\s*:\s*[45]\d\d'), rx(r'"trace"\s*:\s*"(?:[\w$]{1,80}\.){1,15}[\w$]{0,80}(?:Exception|Error)\b')]),
    sig("bottle-debug", "WEB605", "Bottle", severity="high", debug_marker=True,
        all_=[has("<h2>Error: 500 Internal Server Error</h2>")], any_=[has("<h2>Traceback:</h2>"), has("<h2>Exception:</h2>")]),

    # ---------------------------------------------------------------- WEB056 stack traces / detailed errors
    sig("python-traceback", "WEB056", "Python",
        all_=[rx(r"Traceback\s*(?:<[^>]{1,40}>\s*)?\(most recent call last\)")],
        any_=[rx(r"\bFile\s+(?:<[^>]{1,60}>\s*)?" + _PYQ + r"[^\n<>]{1,300}?" + _PYQ
                 + r"(?:\s*</[a-z]+>)?,\s+line\s+(?:<[^>]{1,60}>\s*)?\d+")]),
    sig("java-stack", "WEB056", "Java",
        all_=[rx(r"\bat\s+(?:[\w$]{1,80}\.){1,15}[\w$<>]{1,80}\((?:[\w$]{1,80}\.(?:java|kt|scala|groovy):\d+|Native Method|"
                 r"Unknown Source)\)",
                 min_count=2)],
        any_=[rx(r"\b(?:[\w$]{1,80}\.){1,15}[\w$]{0,80}(?:Exception|Error)\b"), has("Exception")]),
    sig("dotnet-stack", "WEB056", ".NET",
        all_=[rx(r"(?m)^\s*at\s+(?:[\w`<>\[\]]{1,80}\.){0,15}[\w`<>\[\]]{1,80}\([^)\n]{0,300}\)", min_count=2)],
        any_=[has("--- End of stack trace"), rx(r":line \d+"), rx(r"\bSystem\.(?:\w{1,80}\.){0,10}\w{0,80}Exception\b")]),
    sig("php-error-html", "WEB056", "PHP",
        all_=[rx(r"<b>\s*(?:Warning|Fatal error|Parse error|Notice|Deprecated|Catchable fatal error|Recoverable fatal "
                 r"error)\s*</b>:\s+[^\n]{1,600}? on line\s+<b>\d+</b>")]),
    sig("php-error-text", "WEB056", "PHP",
        all_=[rx(r"\bPHP (?:Warning|Fatal error|Parse error|Notice|Deprecated):\s+[^\n]{1,600}? on line \d+")]),
    sig("node-stack", "WEB056", "Node.js",
        all_=[rx(r"(?m)^[ \t]*at[ \t]+(?:[\w$.<>\[\]]{1,200}(?: [\w$.<>\[\]]{1,200}){0,3}[ \t]+)?\(?(?:/|[A-Za-z]:\\|file://|node:internal)"
                 r"[^\s()]{0,500}:\d+:\d+\)?",
                 min_count=2)],
        any_=[rx(r"\b(?:Type|Reference|Syntax|Range|URI|Eval)?Error\b")]),
    sig("ruby-backtrace", "WEB056", "Ruby",
        all_=[rx(r"(?<![\w./-])[\w./-]{1,200}?\.rb:\d+:in [`'][^'`\n<]{1,120}'")],
        any_=[rx(r"\b(?:\w{1,80}::){0,8}\w{0,80}(?:Error|Exception)\b")]),
    sig("go-panic", "WEB056", "Go",
        all_=[rx(r"goroutine \d+ \[running\]:")], any_=[has("panic:"), rx(r"\.go:\d+")]),
    sig("perl-die", "WEB056", "Perl",
        all_=[rx(r"\bat (?:/[\w-]{1,80}){0,15}/[\w.-]{1,80}?\.p[lm] line \d+\.")]),
    sig("coldfusion-error", "WEB056", "ColdFusion",
        all_=[has("Error Occurred While Processing Request")],
        any_=[has("The error occurred in"), has("coldfusion."), has("ColdFusion")]),
    sig("jrun-error", "WEB056", "JRun", all_=[has("JRun Servlet Error")]),
    sig("servlet-exception", "WEB056", "Java Servlet",
        all_=[rx(r"\b(?:javax|jakarta)\.servlet\.(?:ServletException|jsp\.JspException|jsp\.JasperException)\b")]),
    sig("tomcat-exception-report", "WEB056", "Apache Tomcat", status="error",
        all_=[rx(r"HTTP Status 500")], any_=[has("Root Cause"), has("Exception Report"), has("<b>Exception</b>")]),
    sig("aspnet-error-details", "WEB056", "ASP.NET",
        all_=[has("Exception Details:")], any_=[has("Source Error:"), has("System.")]),

    # ---------------------------------------------------------------- WEB606 database errors
    # Class and function names (``PG::Connection``, ``java.sql.SQLException``, ``mysqli_query()``) are everyday words in
    # documentation and Q&A pages; they count only in the shape of an error message (``Name: message``, ``name():``).
    sig("sqlstate", "WEB606", "PDO / SQL", all_=[rx(r"SQLSTATE\[[0-9A-Z]{5}\]")]),
    sig("mysql-syntax", "WEB606", "MySQL",
        any_=[has("You have an error in your SQL syntax"),
              rx(r"\bmysqli?_(?:fetch_\w{1,40}|num_rows|query|connect|real_escape_string|select_db|result)\(\)(?::| expects)"),
              rx(r"\bcom\.mysql\.(?:cj\.)?jdbc\.exceptions\.[\w.]{1,120}Exception:"),
              rx(r"\bMySql(?:Client)?\.?Data\.MySqlClient\.MySqlException(?: \(0x[0-9A-Fa-f]{1,8}\))?:"),
              rx(r"Warning:\s+mysqli?_"), rx(r"\bmysqli_sql_exception:")]),
    sig("oracle-ora", "WEB606", "Oracle", all_=[rx(r"\bORA-\d{5}:")]),
    sig("postgres", "WEB606", "PostgreSQL",
        any_=[rx(r"\bPG::[A-Z]\w{1,80}: "), rx(r"\bpsycopg2?\.(?:errors\.)?[A-Z]\w{1,80}[:)]"),
              rx(r"\borg\.postgresql\.util\.PSQLException:"),
              rx(r"\bERROR:\s+syntax error at or near\b"), rx(r"\bpg_(?:query|exec)\(\): Query failed")]),
    sig("mssql", "WEB606", "Microsoft SQL Server",
        any_=[has("Microsoft OLE DB Provider for"), has("ODBC SQL Server Driver"),
              has("Unclosed quotation mark after the character string"),
              rx(r"\b(?:System|Microsoft)\.Data\.SqlClient\.SqlException(?: \(0x[0-9A-Fa-f]{1,8}\))?:"),
              rx(r"\[SqlException \(0x[0-9A-Fa-f]{1,8}\):"), rx(r"\[Microsoft\]\[ODBC [^\]]{1,60}\]")]),
    sig("sqlite", "WEB606", "SQLite",
        any_=[rx(r"\bSQLite3::\w{1,80}: "), rx(r"\bsqlite3\.(?:OperationalError|IntegrityError|ProgrammingError)[:)]"),
              rx(r"\bSQLITE_ERROR\b[:\]]"), rx(r"\bSQLiteException:")]),
    sig("jdbc-hibernate", "WEB606", "Java database",
        any_=[rx(r"\bjava\.sql\.SQL\w{0,80}Exception:"), rx(r"\borg\.hibernate\.exception\.\w{1,80}Exception:"),
              rx(r"\borg\.springframework\.jdbc\.BadSqlGrammarException:")]),
    sig("db2", "WEB606", "IBM Db2", any_=[has("DB2 SQL error"), rx(r"\bSQLCODE=-\d+")]),
    sig("sqlalchemy", "WEB606", "SQLAlchemy", all_=[rx(r"\bsqlalchemy\.exc\.\w{1,80}Error[:)]")]),

    # ---------------------------------------------------------------- WEB607 server paths in error output (4xx/5xx only)
    sig("unix-path", "WEB607", "Unix", status="error", confidence="tentative",
        all_=[rx(r"(?<![\w/.:\"'=%-])(?:/var/www|/home/[a-z_][\w.-]{0,31}|/srv|/usr/share/nginx|/usr/local/(?:lib|www|apache2?)"
                 r"|/opt)/[\w./-]{0,200}?\.[A-Za-z]{1,5}\b")],
        any_=[rx(_ERRWORD)]),
    sig("windows-path", "WEB607", "Windows", status="error", confidence="tentative",
        all_=[rx(r"(?<![\w\\])[A-Za-z]:\\(?:inetpub|Users|wwwroot|xampp|wamp\d*|Program Files(?: \(x86\))?)\\[^\s<>\"'|?*]{1,200}")],
        any_=[rx(_ERRWORD)]),

    # ---------------------------------------------------------------- WEB616 server version on error pages (ZAP 10009)
    sig("banner-apache", "WEB616", "Apache httpd", status="error", all_=[rx(r"\bApache/\d+\.\d+\.\d+")]),
    sig("banner-nginx", "WEB616", "nginx", status="error", all_=[rx(r"\bnginx/\d+\.\d+\.\d+")]),
    sig("banner-tomcat", "WEB616", "Apache Tomcat", status="error", all_=[rx(r"\bApache Tomcat/\d+\.\d+(?:\.\d+)?")]),
    sig("banner-jetty", "WEB616", "Jetty", status="error", all_=[rx(r"\bJetty://\s*\d+\.\d+")]),
    sig("banner-squid", "WEB616", "Squid", status="error", all_=[rx(r"\bsquid/\d+\.\d+")]),
    sig("banner-iis", "WEB616", "Microsoft IIS", status="error", all_=[rx(r"\bMicrosoft-IIS/\d+\.\d+")]),
    sig("banner-lighttpd", "WEB616", "lighttpd", status="error", all_=[rx(r"\blighttpd/\d+\.\d+\.\d+")]),
    sig("banner-openresty", "WEB616", "OpenResty", status="error", all_=[rx(r"\bopenresty/\d+\.\d+\.\d+")]),

    # ---------------------------------------------------------------- WEB617 default server pages (low) and parking (info)
    sig("iis-default", "WEB617", "Microsoft IIS", status="2xx", severity="low",
        any_=[rx(r"<title>\s*(?:IIS Windows(?: Server)?|IIS\d* Windows Server|Internet Information Services)\s*</title>", "i"),
              rx(r"""<img[^>]{1,300}src=["'](?:/)?iisstart\.png""", "i")]),
    sig("apache-ubuntu-debian-default", "WEB617", "Apache httpd", status="2xx", severity="low",
        all_=[rx(r"<title>\s*Apache2 (?:Ubuntu|Debian) Default Page", "i")]),
    sig("apache-it-works", "WEB617", "Apache httpd", status="2xx", severity="low",
        all_=[rx(r"\A\s*(?:<!DOCTYPE[^>]*>\s*)?<html>\s*<body>\s*<h1>\s*It works!\s*</h1>", "i")]),
    sig("httpd-test-page", "WEB617", "Apache httpd / nginx (RHEL family)", status="2xx", severity="low",
        any_=[rx(r"<title>\s*Test Page for the (?:Apache|HTTP Server|Nginx HTTP Server)[^<]{0,80}</title>", "i"),
              rx(r"<title>\s*HTTP Server Test Page powered by", "i")]),
    sig("nginx-default", "WEB617", "nginx", status="2xx", severity="low",
        all_=[rx(r"<title>\s*Welcome to nginx!\s*</title>", "i")],
        any_=[has("nginx web server is successfully installed"), has("nginx.org")]),
    sig("openresty-default", "WEB617", "OpenResty", status="2xx", severity="low",
        all_=[rx(r"<title>\s*Welcome to OpenResty!\s*</title>", "i")]),
    sig("tomcat-default", "WEB617", "Apache Tomcat", status="2xx", severity="low",
        all_=[rx(r"If you(?:'|&#39;|’)re seeing this, you(?:'|&#39;|’)ve successfully installed Tomcat")]),
    sig("caddy-default", "WEB617", "Caddy", status="2xx", severity="low",
        all_=[rx(r"<title>\s*Caddy works!\s*</title>", "i")]),
    sig("parking-sedo", "WEB617", "Sedo parking", status="2xx", severity="info",
        any_=[rx(r"\b(?:img\.)?sedoparking\.com\b", "i")]),
    sig("parking-godaddy", "WEB617", "GoDaddy parking", status="2xx", severity="info",
        any_=[rx(r"\bwsimg\.com/parking-lander\b", "i"), rx(r"\bparkingcrew\.net/.{0,40}godaddy", "i")]),
    sig("parking-bodis", "WEB617", "Bodis parking", status="2xx", severity="info",
        any_=[rx(r"\b(?:www\.)?bodis\.com\b", "i")], all_=[rx(r"park|for sale|domain", "i")]),
    sig("parking-parkingcrew", "WEB617", "ParkingCrew", status="2xx", severity="info",
        any_=[rx(r"\bparkingcrew\.net\b", "i")]),
]

# (name, match, rule, version_pattern, decode, severity, note)
_V = r"(?<!\d)\d{1,10}(?:\.\d{1,10})+"     # bounded and anchored: linear on a hostile 64 KB "000…" value
_VV = r"(?<!\d)\d{1,10}(?:\.\d{1,10})*"
LEAK_HEADERS = [
    # WEB600: backend software / version
    ("X-AspNet-Version", "exact", "WEB600", _V, "", "", "ASP.NET runtime version"),
    ("X-AspNetMvc-Version", "exact", "WEB600", _V, "", "", "ASP.NET MVC version"),
    ("X-Backend-Server", "exact", "WEB600", "", "", "", "backend host name"),
    ("X-Backend-Host", "exact", "WEB600", "", "", "", "backend host name"),
    ("X-BEServer", "exact", "WEB600", "", "", "", "Exchange/OWA back-end server name"),
    ("X-FEServer", "exact", "WEB600", "", "", "", "Exchange/OWA front-end server name"),
    ("X-OWA-Version", "exact", "WEB600", _V, "", "", "Outlook Web Access build"),
    ("X-Generator", "exact", "WEB600", _VV, "", "", "CMS / generator name and version"),
    ("X-Drupal-Cache", "exact", "WEB600", "", "", "info", "reveals Drupal"),
    ("X-Drupal-Dynamic-Cache", "exact", "WEB600", "", "", "info", "reveals Drupal 8+"),
    ("X-Php-Version", "exact", "WEB600", _V, "", "", "PHP version"),
    ("X-Joomla-Version", "exact", "WEB600", _V, "", "", "Joomla version"),
    ("X-Umbraco-Version", "exact", "WEB600", _V, "", "", "Umbraco version"),
    ("Liferay-Portal", "exact", "WEB600", _V, "", "", "Liferay edition and version"),
    ("MicrosoftSharePointTeamServices", "exact", "WEB600", _V, "", "", "SharePoint build"),
    ("X-Jenkins", "exact", "WEB600", _V, "", "", "Jenkins version"),
    ("X-Hudson", "exact", "WEB600", _V, "", "", "Hudson/Jenkins version"),
    ("X-Varnish-Backend", "exact", "WEB600", "", "", "", "Varnish backend name"),
    ("X-Varnish-Server", "exact", "WEB600", "", "", "", "Varnish server name"),
    ("X-Envoy-Upstream-Service-Time", "exact", "WEB600", "", "", "info", "Envoy proxy and upstream timing"),
    ("X-Kong-", "prefix", "WEB600", "", "", "info", "Kong API gateway"),
    ("X-Nextjs-", "prefix", "WEB600", "", "", "info", "Next.js"),
    ("X-Redirect-By", "exact", "WEB600", "", "", "info", "CMS that issued the redirect (e.g. WordPress)"),
    ("X-Powered-CMS", "exact", "WEB600", _VV, "", "", "CMS name"),
    ("X-Server-Powered-By", "exact", "WEB600", _VV, "", "", "backend software"),
    ("X-CF-Powered-By", "exact", "WEB600", _VV, "", "", "ColdFusion / CF platform"),
    ("X-Mod-Pagespeed", "exact", "WEB600", _V, "", "", "mod_pagespeed version"),
    ("X-Page-Speed", "exact", "WEB600", _V, "", "", "ngx_pagespeed version"),
    ("X-Turbo-Charged-By", "exact", "WEB600", _VV, "", "", "LiteSpeed"),
    ("X-Application-Context", "exact", "WEB600", "", "", "info", "Spring Boot application name, profile and port"),
    ("X-Runtime", "exact", "WEB600", "", "", "info", "server processing time (timing side channel)"),
    ("X-Request-Duration", "exact", "WEB600", "", "", "info", "server processing time (timing side channel)"),
    # WEB601: debug / profiler output
    ("X-Debug-Token", "exact", "WEB601", "", "", "", "Symfony profiler token"),
    ("X-Debug-Token-Link", "exact", "WEB601", "", "", "", "Symfony profiler link"),
    ("X-Debug-", "prefix", "WEB601", "", "", "", "debug output header"),
    ("X-ChromeLogger-Data", "exact", "WEB601", "", "base64", "", "ChromeLogger debug output (base64 JSON)"),
    ("X-ChromePhp-Data", "exact", "WEB601", "", "base64", "", "ChromePhp debug output (base64 JSON)"),
    ("X-SourceFiles", "exact", "WEB601", "", "", "", "IIS Express source path (development server)"),
    ("X-Clockwork-Id", "exact", "WEB601", "", "", "", "Clockwork PHP profiler"),
    ("X-Clockwork-Version", "exact", "WEB601", "", "", "", "Clockwork PHP profiler"),
    ("X-Laravel-*-Debug", "exact", "WEB601", "", "", "", "Laravel debug header (glob)"),
    ("phpdebugbar-id", "exact", "WEB601", "", "", "", "PHP Debug Bar (laravel-debugbar)"),
    ("X-Wf-", "prefix", "WEB601", "", "", "", "FirePHP (Wildfire protocol) debug output"),
    ("X-MiniProfiler-", "prefix", "WEB601", "", "", "", "MiniProfiler"),
    ("X-Xdebug-", "prefix", "WEB601", "", "", "", "Xdebug profiler"),
]

# Kashif's SEC rules applied to client-side code: prefix-anchored or structurally specific only. Excluded on purpose:
# SEC002 (an AWS key id alone is not a secret; the pair is an extra pattern), SEC004 (generic "password = …" assignments
# are noise in bundles), SEC005 (client-side JWTs are usually public tokens), SEC009 (marker without a value; its private
# key is found by SEC001), SEC011 (entropy-only), SEC019 (SAS URLs in pages are usually intended read links).
SEC_RULES = ["SEC001", "SEC003", "SEC006", "SEC007", "SEC008", "SEC010", "SEC012", "SEC013", "SEC014", "SEC015", "SEC016",
             "SEC017", "SEC018", "SEC020", "SEC021", "SEC022", "SEC023", "SEC024", "SEC025", "SEC026", "SEC027", "SEC028",
             "SEC029", "SEC030", "SEC031"]

# (id, pattern, severity, confidence, title_en, title_ar, min_entropy)
EXTRA_SECRETS = [
    ("google-api-key", r"(?<![\w-])AIza[0-9A-Za-z\-_]{35}(?![\w-])", "low", "tentative",
     "Google API key (often a browser key, public by design)", "مفتاح Google API (غالبًا مفتاح متصفح عام بطبيعته)", 3.0),
    ("aws-secret-pair",
     r"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])[\s\S]{1,300}?(?<![A-Za-z0-9/+=])(?P<secret>[A-Za-z0-9/+]{40})"
     r"(?![A-Za-z0-9/+=])", "high", "firm", "AWS access key id with its secret access key",
     "معرّف مفتاح AWS مع مفتاح الوصول السري", 4.0),
    ("aws-secret-assign", r"(?i)secret_?access_?key[\"']?\s*[:=]\s*[\"'](?P<secret>[A-Za-z0-9/+]{40})[\"']", "high", "firm",
     "AWS secret access key", "مفتاح الوصول السري لـ AWS", 4.0),
    ("braintree-token", r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}", "high", "firm",
     "Braintree production access token", "رمز وصول Braintree للإنتاج", 3.0),
    ("fcm-server-key", r"(?<![\w-])AAAA[A-Za-z0-9_-]{7}:APA91b[A-Za-z0-9_-]{134}(?![\w-])", "high", "firm",
     "Firebase Cloud Messaging server key", "مفتاح خادم Firebase Cloud Messaging", 3.5),
]

PUBLISHABLE = [r"pk_(?:live|test)_", r"rk_test_", r"sk_test_", r"pub_", r"SG\.EXAMPLE"]


def build_signatures(date: str, zap_xml: str | None = None) -> dict:
    sigs = [dict(s) for s in SIGNATURES]
    if zap_xml:
        sigs += zap_signatures(Path(zap_xml).read_text(encoding="utf-8"), {s["id"] for s in sigs})
    for s in sigs:                      # fail early on a broken pattern
        for part in ("all", "any", "none"):
            for c in s["signature"].get(part, []):
                if c["type"] == "regex":
                    re.compile(c["pattern"])
    meta = {"schema_version": 1, "date": date, "generator": GENERATOR,
            "source": "Kashif original signatures written from the public error formats of each platform"
                      + ("; plus literal strings of ZAP application_errors.xml" if zap_xml else ""),
            "license": "Kashif project licence" + ("; ZAP strings Apache-2.0 (see NOTICE)" if zap_xml else ""),
            "notes": "rule: WEB056 stack trace, WEB605 debug page (debug_marker), WEB606 database error, WEB607 path in "
                     "an error (4xx/5xx), WEB616 version banner on an error page, WEB617 default or parked page. status: "
                     "any | error (4xx/5xx) | 2xx."}
    return {"meta": meta, "signatures": sigs}


_DB_WORDS = re.compile(r"sql|odbc|ole db|ora-|jdbc|mysql|postgres|sqlite|db2|sybase|informix|ingres|database", re.I)


def zap_signatures(xml_text: str, taken: set[str]) -> list[dict]:
    """Plain-string patterns of ZAP's ``application_errors.xml`` (``<Pattern type="string">``) as ``contains``
    signatures: database words → WEB606, the rest → WEB056. Regex patterns are skipped (Java syntax)."""
    out: list[dict] = []
    root = ET.fromstring(xml_text)
    n = 0
    for el in root.iter():
        if not el.tag.lower().endswith("pattern") or (el.get("type") or "string").lower() != "string":
            continue
        text = (el.text or "").strip()
        if len(text) < 8:
            continue
        n += 1
        sid = f"zap-{n:03d}"
        if sid in taken:
            continue
        rule = "WEB606" if _DB_WORDS.search(text) else "WEB056"
        out.append(sig(sid, rule, "ZAP application_errors.xml", all_=[has(text)]))
    return out


def build_leak_headers(date: str) -> dict:
    headers = []
    for name, match, rule, vp, decode, sev, note in LEAK_HEADERS:
        h = {"name": name, "match": match, "rule": rule}
        if vp:
            re.compile(vp)
            h["version_pattern"] = vp
        if decode:
            h["decode"] = decode
        if sev:
            h["severity"] = sev
        if note:
            h["note"] = note
        headers.append(h)
    meta = {"schema_version": 1, "date": date, "generator": GENERATOR,
            "source": "Kashif's own list, re-derived from vendor documentation (OSHP's list used only as a cross-check)",
            "license": "Kashif project licence",
            "notes": "WEB600: low when version_pattern matches the value, else info (or the given severity); WEB601: "
                     "medium. match: exact | prefix; a name containing * is a case-insensitive glob. Server-Timing "
                     "entries are judged in code (disclosure.py)."}
    return {"meta": meta, "headers": headers}


def build_secret_rules(date: str) -> dict:
    extra = []
    for id_, pattern, sev, conf, t_en, t_ar, ent in EXTRA_SECRETS:
        re.compile(pattern)
        e = {"id": id_, "pattern": pattern, "severity": sev, "confidence": conf, "title_en": t_en, "title_ar": t_ar}
        if ent:
            e["min_entropy"] = ent
        extra.append(e)
    meta = {"schema_version": 1, "date": date, "generator": GENERATOR,
            "source": "Kashif: ids of history.secret_rules() applied to client-side code, plus web-only patterns",
            "license": "Kashif project licence",
            "notes": "extra patterns may name the secret with a (?P<secret>…) group; publishable entries are prefixes "
                     "(regular expressions anchored at the start of the value) that are never reported."}
    return {"meta": meta, "sec_rules": list(SEC_RULES), "extra": extra, "publishable": list(PUBLISHABLE)}


def _dump(obj: dict) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=1) + "\n"


def outputs(date: str, zap_xml: str | None = None) -> dict[str, str]:
    return {"error-signatures.json": _dump(build_signatures(date, zap_xml)),
            "leak-headers.json": _dump(build_leak_headers(date)),
            "secret-rules.json": _dump(build_secret_rules(date))}


def _bundled_date(path: Path) -> str | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))["meta"]["date"]
    except (OSError, ValueError, KeyError, TypeError):
        return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--check", action="store_true", help="compare with the bundled files instead of writing")
    ap.add_argument("--date", help="meta.date (default: keep the bundled date, else %s)" % DEFAULT_DATE)
    ap.add_argument("--zap-xml", help="path of a local copy of ZAP's application_errors.xml to merge")
    ap.add_argument("--out", default=str(OUT_DIR), help="output directory")
    args = ap.parse_args(argv)
    out_dir = Path(args.out)
    sys.path.insert(0, str(ROOT))
    from vulnscan.webscan import data as webdata
    status = 0
    for name in ("error-signatures.json", "leak-headers.json", "secret-rules.json"):
        path = out_dir / name
        date = args.date or _bundled_date(path) or DEFAULT_DATE
        text = outputs(date, args.zap_xml)[name]
        errs = webdata.validate_data(name, json.loads(text))
        if errs:
            print(f"{name}: schema errors:\n  " + "\n  ".join(errs[:20]), file=sys.stderr)
            return 2
        if args.check:
            try:
                same = path.read_text(encoding="utf-8") == text
            except OSError:
                same = False
            if not same:
                print(f"{name}: differs from {GENERATOR} output", file=sys.stderr)
                status = 1
            continue
        path.write_text(text, encoding="utf-8", newline="\n")
        print(f"wrote {path}")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
