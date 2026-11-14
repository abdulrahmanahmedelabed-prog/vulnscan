"""Remediation snippet library of the passive web scanner (spec §2.13, WP14).

Every remediation id a rule names (``RuleMeta.fix`` in :mod:`webscan.rules`) maps to a :class:`Snippet`: a title, a
one-line summary and a one-line caveat in English and Arabic, the recommended response headers (``headers``, used by the
self-check test that runs Kashif's own header/CSP/HSTS/cookie checks on them) and copy-paste blocks per platform.

Platforms: nginx, Apache httpd 2.4, IIS 10 (web.config), Caddy 2, Express (helmet 7+), Django (>= 4.2; CSP built in
from 6.0), Spring Security 6, ASP.NET Core 8+, Cloudflare, plus a few application stacks some snippets need (PHP,
Flask, Laravel, Rails, Symfony, Tomcat, classic ASP.NET, Node.js, F5 BIG-IP). A block of platform ``any`` is generic
(the header lines themselves, or steps that apply everywhere) and is always shown first.

The report shows the platforms detected for the site first and the rest collapsed: :func:`detect_platforms` reads the
technology inventory (``ctx.inventory["technologies"]``, WP9) and the ``Server`` / ``X-Powered-By`` headers, and
:func:`render` splits the blocks into ``detected`` and ``other``.

Placeholders: ``{host}`` (the scanned host), ``{domain}`` (its registrable domain), ``{names}`` (the server names of a
redirect block: the apex and www names when the host is one of them, else the host) and ``{expires}`` (security.txt
``Expires``: scan date + 6 months, RFC 9116 §2.5.5) are filled by :func:`fill`; without a scan they read
``example.com`` as in the spec. Only these three exact tokens are replaced, so braces in JavaScript, C# or Caddy code
are never touched; ``{RANDOM}`` / ``{nonce}`` in a CSP stay as documented placeholders for the user.

Pure module: no network, no import of a check module (it may import ``types``, ``psl`` and ``rules``).
"""

from __future__ import annotations

import calendar
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

from .rules import RULES

# ----------------------------------------------------------------------------------------------- vocabulary

# platform key → (English name, Arabic name); the order is the default display order
PLATFORMS: dict[str, tuple[str, str]] = {
    "any": ("All platforms", "كل المنصات"),
    "nginx": ("nginx", "nginx"),
    "apache": ("Apache httpd 2.4", "Apache httpd 2.4"),
    "iis": ("IIS 10 (web.config)", "IIS 10 (ملف web.config)"),
    "caddy": ("Caddy 2", "Caddy 2"),
    "express": ("Express (helmet 7+)", "Express (helmet 7+)"),
    "django": ("Django", "Django"),
    "spring": ("Spring Security 6 / Spring Boot", "Spring Security 6 / Spring Boot"),
    "aspnetcore": ("ASP.NET Core 8+", "ASP.NET Core 8+"),
    "cloudflare": ("Cloudflare", "Cloudflare"),
    "php": ("PHP", "PHP"),
    "flask": ("Flask / Werkzeug", "Flask / Werkzeug"),
    "laravel": ("Laravel", "Laravel"),
    "rails": ("Ruby on Rails", "Ruby on Rails"),
    "symfony": ("Symfony", "Symfony"),
    "tomcat": ("Apache Tomcat", "Apache Tomcat"),
    "aspnet": ("ASP.NET (.NET Framework)", "ASP.NET (.NET Framework)"),
    "node": ("Node.js", "Node.js"),
    "bigip": ("F5 BIG-IP", "F5 BIG-IP"),
}

# technology ids of data/web/tech.json (WP9) → platform keys whose snippets apply
TECH_PLATFORMS: dict[str, tuple[str, ...]] = {
    "nginx": ("nginx",), "openresty": ("nginx",), "tengine": ("nginx",),
    "apache-http-server": ("apache",), "litespeed": ("apache",),          # LiteSpeed reads Apache directives (.htaccess)
    "iis": ("iis",), "sharepoint": ("iis", "aspnet"), "outlook-web-app": ("iis", "aspnet"),
    "aspnet": ("aspnet", "iis"), "aspnet-mvc": ("aspnet", "iis"), "microsoft-asp.net": ("aspnet", "iis"),
    "kestrel": ("aspnetcore",), "umbraco": ("aspnetcore",),
    "caddy": ("caddy",),
    "express": ("express", "node"), "nodejs": ("node", "express"), "nextjs": ("node", "express"),
    "next.js": ("node", "express"), "nuxt": ("node",), "ghost": ("node", "express"),
    "django": ("django",), "werkzeug": ("flask",),
    "spring-boot": ("spring",), "tomcat": ("tomcat", "spring"), "jetty": ("spring",),   # Java alone says nothing
    "cloudflare": ("cloudflare",),
    "php": ("php",), "laravel": ("laravel", "php"), "symfony": ("symfony", "php"), "codeigniter": ("php",),
    "yii": ("php",), "nette-framework": ("php",),
    "ruby-on-rails": ("rails",),
    "f5-big-ip": ("bigip",),
}

# (header name, regular expression on its value, platform keys); first matches are the strongest evidence
HEADER_PLATFORMS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("server", r"apache-coyote|tomcat", ("tomcat", "spring")),
    ("server", r"\bnginx\b|openresty|\btengine\b", ("nginx",)),
    ("server", r"microsoft-iis", ("iis",)),
    ("server", r"\bkestrel\b", ("aspnetcore",)),
    ("server", r"\bcaddy\b", ("caddy",)),
    ("server", r"\bcloudflare\b", ("cloudflare",)),
    ("server", r"litespeed", ("apache",)),
    ("server", r"^apache\b|\bapache/\d|\bhttpd\b", ("apache",)),
    ("server", r"werkzeug", ("flask",)),
    ("server", r"jetty", ("spring",)),
    ("server", r"big-?ip", ("bigip",)),
    ("x-powered-by", r"\bexpress\b", ("express", "node")),
    ("x-powered-by", r"next\.js", ("node", "express")),
    ("x-powered-by", r"\bphp\b", ("php",)),
    ("x-powered-by", r"asp\.net", ("aspnet", "iis")),
    ("x-powered-by", r"servlet|jsp", ("spring", "tomcat")),
    ("x-aspnet-version", r".", ("aspnet", "iis")),
    ("x-aspnetmvc-version", r".", ("aspnet", "iis")),
    ("cf-ray", r".", ("cloudflare",)),
)

SNIPPET_LANGS = ("text", "nginx", "apache", "xml", "caddy", "js", "python", "java", "csharp", "ini", "properties",
                 "shell", "html", "php", "ruby", "yaml")

# labels the report uses around the snippets (en, ar)
STR: dict[str, tuple[str, str]] = {
    "detected": ("Detected on this site", "المكتشفة في هذا الموقع"),
    "other": ("Other platforms", "منصات أخرى"),
    "caution": ("Caution", "تنبيه"),
    "how_to_fix": ("How to fix", "طريقة الإصلاح"),
    "copy": ("Copy", "نسخ"),
    "placeholder": ("example.com stands for your site; replace it with your host name.",
                    "يرمز example.com إلى موقعك؛ استبدله باسم مضيفك."),
}

TOKENS = ("host", "domain", "domain_re", "names", "expires")
_TOKEN_RX = re.compile(r"\{(host|domain|domain_re|names|expires)\}")
_LABEL = r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?"
_HOST_OK = re.compile(rf"(?=.{{1,253}}$){_LABEL}(?:\.{_LABEL})*|[0-9a-f:.]{{2,45}}")
_ARABIC = re.compile(r"[؀-ۿ]")


# ----------------------------------------------------------------------------------------------- data model

@dataclass(frozen=True)
class Block:
    """One copy-paste block for one platform. ``code`` may be empty when the fix is a dashboard step (``note``).
    ``label_en`` / ``label_ar`` replace the platform name as the block's heading, to tell two blocks of one platform in
    a snippet apart."""
    platform: str
    code: str = ""
    lang: str = "text"
    note_en: str = ""
    note_ar: str = ""
    label_en: str = ""
    label_ar: str = ""

    def note(self, lang: str = "en") -> str:
        return self.note_ar if lang == "ar" else self.note_en

    def label(self, lang: str = "en") -> str:
        return self.label_ar if lang == "ar" else self.label_en


@dataclass(frozen=True)
class Header:
    """A recommended response header line. ``where`` is the kind of response it belongs on: ``any`` (every response),
    ``document`` (an HTML page), ``api`` (a JSON response), ``logout`` (the logout response) or ``sensitive`` (a
    personalised page or one that sets a session cookie)."""
    name: str
    value: str
    where: str = "document"


@dataclass(frozen=True)
class Snippet:
    id: str
    title_en: str
    title_ar: str
    summary_en: str
    summary_ar: str
    caveat_en: str
    caveat_ar: str
    blocks: tuple[Block, ...]
    headers: tuple[Header, ...] = ()
    prose: bool = False             # short prose without server configuration (S-HTML, S-SECRET, …)

    def title(self, lang: str = "en") -> str:
        return self.title_ar if lang == "ar" else self.title_en

    def summary(self, lang: str = "en") -> str:
        return self.summary_ar if lang == "ar" else self.summary_en

    def caveat(self, lang: str = "en") -> str:
        return self.caveat_ar if lang == "ar" else self.caveat_en

    @property
    def platforms(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(b.platform for b in self.blocks))


SNIPPETS: dict[str, Snippet] = {}


def _s(sid: str, title: tuple[str, str], summary: tuple[str, str], caveat: tuple[str, str], blocks: Iterable[Block],
       headers: Iterable[Header] = (), prose: bool = False) -> None:
    if sid in SNIPPETS:
        raise ValueError(f"duplicate snippet {sid}")
    SNIPPETS[sid] = Snippet(sid, title[0], title[1], summary[0], summary[1], caveat[0], caveat[1], tuple(blocks),
                            tuple(headers), prose)


def _b(platform: str, code: str = "", lang: str = "text", note: tuple[str, str] = ("", ""),
       label: tuple[str, str] = ("", "")) -> Block:
    return Block(platform, code.strip("\n"), lang, note[0], note[1], label[0], label[1])


# -- generic header-setting blocks (S-REF says: "same header-setting syntax for each platform") ---------------------

def _xml_attr(value: str) -> str:
    return value.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;")


def _cs_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def header_blocks(name: str, value: str, *, skip: Iterable[str] = ()) -> list[Block]:
    """nginx / Apache / IIS / Caddy / ASP.NET Core / Cloudflare blocks that set ``name: value`` on every response."""
    q = '"' not in value
    nginx_v = f'"{value}"' if q else f"'{value}'"
    caddy_v = f'"{value}"' if q else f"`{value}`"
    out = [
        _b("nginx", f"add_header {name} {nginx_v} always;", "nginx"),
        _b("apache", f"Header always set {name} {nginx_v}", "apache"),
        _b("iis", f'<add name="{name}" value="{_xml_attr(value)}" />', "xml",
          ("Inside <system.webServer><httpProtocol><customHeaders> of web.config.",
           "داخل <system.webServer><httpProtocol><customHeaders> في ملف web.config.")),
        _b("caddy", f"header {name} {caddy_v}", "caddy"),
        _b("aspnetcore", "app.Use(async (ctx, next) => {\n"
                        f"    ctx.Response.Headers[\"{name}\"] = {_cs_string(value)};\n"
                        "    await next(); });", "csharp"),
        _b("cloudflare", note=(f"Rules → Transform Rules → Modify Response Header → Set static: {name} = {value}",
                              f"في لوحة Cloudflare: ‏Rules → Transform Rules → Modify Response Header → Set static، ثم اضبط ‏{name} = {value}")),
    ]
    skip = set(skip)
    return [b for b in out if b.platform not in skip]


_CF_STATIC = ("Rules → Transform Rules → Modify Response Header → Set static header.",
              "Rules → Transform Rules → Modify Response Header → Set static (ترويسة ثابتة).")

# =============================================================================================== snippets (§2.13)

_s("S-HSTS",
   ("Strict-Transport-Security (HSTS)", "ترويسة Strict-Transport-Security ‏(HSTS)"),
   ("Tell browsers to use HTTPS only for this host (and its subdomains) for two years.",
    "اطلب من المتصفحات استخدام HTTPS فقط لهذا المضيف (ونطاقاته الفرعية) مدة سنتين."),
   ("includeSubDomains forces HTTPS on every subdomain: confirm they all serve HTTPS first. Add preload only after "
    "reading hstspreload.org, because removal from the preload list takes months.",
    "يفرض includeSubDomains استخدام HTTPS على كل النطاقات الفرعية، فتأكد أولًا من أنها كلها تعمل عبر HTTPS. ولا تضف "
    "preload إلا بعد قراءة شروط hstspreload.org، لأن الحذف من قائمة الإدراج المسبق يستغرق أشهرًا."),
   [
       _b("any", "Strict-Transport-Security: max-age=63072000; includeSubDomains"),
       _b("nginx", """
# nginx (server block on 443; "always" also covers error responses).
# Caution: add_header in a location{} replaces all server-level add_header lines; repeat them there.
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;""", "nginx"),
       _b("apache", """
# Apache httpd (mod_headers), inside <VirtualHost *:443>
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains\"""", "apache"),
       _b("iis", """
<!-- IIS 10 version 1709+: the site's native HSTS (applicationHost.config, or IIS Manager → site → HSTS) -->
<site name="Default Web Site">
  <hsts enabled="true" max-age="63072000" includeSubDomains="true" redirectHttpToHttps="true" />
</site>""", "xml",
         ("IIS sends the header on HTTPS responses only and redirects HTTP to HTTPS; use your site's name.",
          "يرسل IIS الترويسة في استجابات HTTPS فقط ويوجّه HTTP إلى HTTPS؛ استخدم اسم موقعك."),
         ("IIS 10 version 1709+ (native HSTS)", "IIS 10 الإصدار 1709 فأحدث (HSTS المدمجة)")),
       _b("iis", """
<system.webServer><httpProtocol><customHeaders>
  <add name="Strict-Transport-Security" value="max-age=63072000; includeSubDomains" />
</customHeaders></httpProtocol></system.webServer>""", "xml",
         ("Only for IIS older than 10 version 1709: customHeaders goes out on every binding, so put it only in the "
          "web.config of a site that is bound to HTTPS alone.",
          "لإصدارات IIS الأقدم من 10 (الإصدار 1709) فقط: تُرسَل customHeaders في كل ربط (binding)، فضعها فقط في ملف "
          "web.config لموقع مربوط بـ HTTPS وحده."),
         ("Older IIS (web.config custom header)", "IIS الأقدم (ترويسة مخصّصة في web.config)")),
       _b("caddy", """
{host} {
	header Strict-Transport-Security "max-age=63072000; includeSubDomains"
}""", "caddy"),
       _b("express", """
// Express + helmet
app.use(helmet.strictTransportSecurity({ maxAge: 63072000, includeSubDomains: true }));""", "js"),
       _b("django", """
# Django settings.py
SECURE_HSTS_SECONDS = 63072000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_SSL_REDIRECT = True""", "python"),
       _b("spring", """
// Spring Security 6
http.headers(h -> h.httpStrictTransportSecurity(s -> s.includeSubDomains(true).maxAgeInSeconds(63072000)));""", "java"),
       _b("aspnetcore", """
// ASP.NET Core
builder.Services.AddHsts(o => { o.MaxAge = TimeSpan.FromDays(730); o.IncludeSubDomains = true; });
app.UseHsts();""", "csharp"),
       _b("cloudflare", note=(
           "SSL/TLS → Edge Certificates → HTTP Strict Transport Security (HSTS) → Enable, Max Age 12 months; turn on "
           "Apply HSTS policy to subdomains only after confirming every subdomain serves HTTPS. Add preload only after "
           "reading hstspreload.org (removal takes months).",
           "SSL/TLS → Edge Certificates → HTTP Strict Transport Security (HSTS) → Enable، واختر Max Age بقيمة "
           "12 months، ولا تفعّل Apply HSTS policy to subdomains إلا بعد التأكد من أن كل النطاقات الفرعية تعمل عبر "
           "HTTPS. ولا تضف preload إلا بعد قراءة hstspreload.org (الحذف يستغرق أشهرًا).")),
   ],
   [Header("Strict-Transport-Security", "max-age=63072000; includeSubDomains", "any")])

_s("S-REDIR",
   ("Redirect HTTP to HTTPS (same host first, permanent)", "توجيه HTTP إلى HTTPS (نفس المضيف أولًا، توجيه دائم)"),
   ("Answer every plain-HTTP request with a 301/308 redirect to the same host on HTTPS; redirect to another host only "
    "after that.",
    "أجب عن كل طلب HTTP غير مشفّر بتوجيه 301 أو 308 إلى نفس المضيف عبر HTTPS، ثم وجّه إلى أي مضيف آخر بعد ذلك."),
   ("Behind a proxy or load balancer that terminates TLS, check the forwarded protocol header (X-Forwarded-Proto) or "
    "the redirect will loop. For APIs, do not redirect: close port 80 or answer 403.",
    "إذا كان TLS يُنهى عند وكيل أو موزّع أحمال فاعتمد على ترويسة البروتوكول المُمرَّرة (X-Forwarded-Proto) وإلا دار "
    "التوجيه في حلقة. أما واجهات API فلا توجّهها، بل أغلق المنفذ 80 أو أجب بـ 403."),
   [
       _b("nginx", """
server { listen 80; listen [::]:80; server_name {names}; return 301 https://$host$request_uri; }""",
         "nginx"),
       _b("apache", """
<VirtualHost *:80>
    ServerName {host}
    ServerAlias {names}
    RewriteEngine On
    RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]
</VirtualHost>""", "apache"),
       _b("iis", """
<!-- IIS: URL Rewrite module -->
<rewrite><rules><rule name="HTTPS" stopProcessing="true"><match url="(.*)" />
  <conditions><add input="{HTTPS}" pattern="off" /></conditions>
  <action type="Redirect" url="https://{HTTP_HOST}/{R:1}" redirectType="Permanent" />
</rule></rules></rewrite>""", "xml"),
       _b("caddy", note=("Automatic: Caddy redirects HTTP to HTTPS by default for site addresses.",
                        "تلقائي: يوجّه Caddy من HTTP إلى HTTPS افتراضيًا لعناوين المواقع.")),
       _b("express", """
app.set("trust proxy", 1);
app.use((q, s, n) => q.secure ? n() : s.redirect(301, "https://" + q.headers.host + q.originalUrl));""", "js",
         ("Better: terminate TLS at the proxy and redirect there.",
          "الأفضل: أنهِ TLS عند الوكيل العكسي ونفّذ التوجيه هناك.")),
       _b("django", """
SECURE_SSL_REDIRECT = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")   # only behind a proxy that sets it""", "python"),
       _b("spring", """
http.redirectToHttps(Customizer.withDefaults());   // Spring Security 6.5+
// older 6.x: http.requiresChannel(c -> c.anyRequest().requiresSecure());""", "java"),
       _b("aspnetcore", """
builder.Services.AddHttpsRedirection(o => o.RedirectStatusCode = 308);
app.UseHttpsRedirection();""", "csharp"),
       _b("cloudflare", note=("SSL/TLS → Edge Certificates → Always Use HTTPS = On.",
                             "في لوحة Cloudflare: ‏SSL/TLS → Edge Certificates → Always Use HTTPS = On.")),
       _b("any", note=("APIs (ASVS 5.0 4.1.2): do not redirect; close port 80 or return 403.",
                      "واجهات API (ASVS 5.0 4.1.2): لا توجّه، بل أغلق المنفذ 80 أو أعد 403.")),
   ])

_STRICT_CSP = ("script-src 'nonce-{RANDOM}' 'strict-dynamic' https: 'unsafe-inline'; object-src 'none'; base-uri 'none'; "
               "frame-ancestors 'none'; form-action 'self'; report-uri /csp-report; report-to csp")
_STATIC_CSP = "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
_API_CSP = "default-src 'none'; frame-ancestors 'none'"

_s("S-CSP",
   ("Content-Security-Policy (strict, nonce-based)", "سياسة أمان المحتوى CSP (صارمة قائمة على nonce)"),
   ("A strict CSP (nonce + 'strict-dynamic') for HTML pages and a locked-down CSP for APIs; the nonce is 16+ random "
    "bytes in base64, new for every response, also set as nonce=\"…\" on every <script>.",
    "سياسة CSP صارمة (nonce مع 'strict-dynamic') لصفحات HTML وسياسة مغلقة لواجهات API؛ والـ nonce قيمة عشوائية من 16 "
    "بايتًا أو أكثر بترميز base64، جديدة في كل استجابة، وتوضع أيضًا في nonce=\"…\" على كل وسم <script>."),
   ("A strict CSP blocks every script without the nonce, including inline event handlers (onclick=): deploy it as "
    "Content-Security-Policy-Report-Only first and switch once the reports are clean.",
    "تمنع سياسة CSP الصارمة كل سكربت لا يحمل الـ nonce، بما في ذلك معالجات الأحداث المضمّنة (onclick=)؛ فطبّقها أولًا "
    "بالترويسة Content-Security-Policy-Report-Only ثم انتقل إلى التطبيق الفعلي بعد خلو التقارير من المخالفات."),
   [
       _b("any", f"""
Content-Security-Policy: {_STRICT_CSP}
Reporting-Endpoints:     csp="https://{{host}}/csp-report"
API responses:          Content-Security-Policy: {_API_CSP}""", "text",
         ("'https:' and 'unsafe-inline' are ignored by CSP3 browsers when a nonce and 'strict-dynamic' are present; they "
          "only keep very old browsers working. Reporting-Endpoints defines the group that report-to names.",
          "تتجاهل متصفحات CSP3 كلًّا من 'https:' و'unsafe-inline' عند وجود nonce و'strict-dynamic'، وهما لإبقاء المتصفحات "
          "القديمة جدًا عاملة فقط. وتعرّف Reporting-Endpoints المجموعة التي يشير إليها report-to.")),
       _b("nginx", f"""
# nginx: per-request nonce requires a module (ngx_http_sub/njs) — prefer setting CSP in the application.
# Static sites without inline scripts can use a hash/allowlist policy:
add_header Content-Security-Policy "{_STATIC_CSP}" always;""", "nginx"),
       _b("apache", f"""
Header always set Content-Security-Policy "{_STATIC_CSP}"
# Per-request nonce: mod_unique_id + "Header set ... 'nonce-%{{UNIQUE_ID}}e'" is NOT random enough; generate the nonce in the app.""",
         "apache"),
       _b("iis", f'<add name="Content-Security-Policy" value="{_STATIC_CSP}" />', "xml"),
       _b("caddy", f'header Content-Security-Policy "{_STATIC_CSP}"', "caddy"),
       _b("express", """
// Express + helmet with a per-request nonce
const crypto = require("node:crypto");
app.use((req, res, next) => { res.locals.cspNonce = crypto.randomBytes(16).toString("base64"); next(); });
app.use(helmet.contentSecurityPolicy({ directives: {
  "script-src": [(req, res) => `'nonce-${res.locals.cspNonce}'`, "'strict-dynamic'"],
  "object-src": ["'none'"], "base-uri": ["'none'"], "frame-ancestors": ["'none'"], "form-action": ["'self'"] } }));
// templates: <script nonce="<%= cspNonce %>">""", "js"),
       _b("django", """
# Django >= 6.0 (built-in): MIDDLEWARE += ["django.middleware.csp.ContentSecurityPolicyMiddleware"]
from django.utils.csp import CSP
SECURE_CSP = {"script-src": [CSP.NONCE, CSP.STRICT_DYNAMIC], "object-src": [CSP.NONE],
              "base-uri": [CSP.NONE], "frame-ancestors": [CSP.NONE], "form-action": [CSP.SELF]}
# add "django.template.context_processors.csp" to TEMPLATES context_processors; templates: <script nonce="{{ csp_nonce }}">
# Django < 6.0: the django-csp package""", "python"),
       _b("spring", """
// Spring Security 6 (nonce: generate per request in a filter and expose it to templates)
http.headers(h -> h.contentSecurityPolicy(c -> c.policyDirectives(
    "script-src 'nonce-{nonce}' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")));""",
         "java"),
       _b("aspnetcore", """
// ASP.NET Core middleware
app.Use(async (ctx, next) => {
    var nonce = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));
    ctx.Items["csp-nonce"] = nonce;
    ctx.Response.Headers.ContentSecurityPolicy = $"script-src 'nonce-{nonce}' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";
    await next(); });""", "csharp"),
       _b("cloudflare", """
// Cloudflare Worker: a new nonce for every HTML response
export default {
  async fetch(req, env) {
    const res = await fetch(req);
    if (!(res.headers.get("content-type") || "").includes("text/html")) return res;
    const nonce = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
    const policy = `script-src 'nonce-${nonce}' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'`;
    const out = new HTMLRewriter().on("script[nonce]", {
      element(e) {   // only scripts your templates marked; any other nonce (e.g. an injected one) is removed
        if (e.getAttribute("nonce") === env.NONCE_MARK) e.setAttribute("nonce", nonce); else e.removeAttribute("nonce");
      },
    }).transform(res);
    const r = new Response(out.body, out);
    r.headers.set("Content-Security-Policy", policy);
    r.headers.set("Cache-Control", "private, no-store");   // a cached page would reuse the nonce
    return r;
  },
};""", "js",
         ("Your templates mark trusted scripts with nonce=\"<NONCE_MARK>\", a random value you also store as the Worker "
          "secret NONCE_MARK; the Worker replaces it with a fresh nonce. For a static policy (no nonce), use Rules → "
          "Transform Rules → Modify Response Header → Set static Content-Security-Policy instead.",
          "تضع قوالبك على السكربتات الموثوقة السمة nonce=\"<NONCE_MARK>\"، وهي قيمة عشوائية تحفظها أيضًا سرًّا للـ "
          "Worker باسم NONCE_MARK، فيستبدل بها الـ Worker قيمة nonce جديدة. أما السياسة الثابتة (بلا nonce) فاضبطها من "
          "Rules → Transform Rules → Modify Response Header → Set static للترويسة Content-Security-Policy.")),
   ],
   [Header("Content-Security-Policy", _STRICT_CSP), Header("Reporting-Endpoints", 'csp="https://{host}/csp-report"'),
    Header("Content-Security-Policy", _API_CSP, "api")])

_s("S-FRAME",
   ("Clickjacking protection (frame-ancestors / X-Frame-Options)", "الحماية من Clickjacking ‏(frame-ancestors / X-Frame-Options)"),
   ("Forbid other sites from framing your pages: CSP frame-ancestors for current browsers, X-Frame-Options for old ones.",
    "امنع المواقع الأخرى من تضمين صفحاتك في إطار: frame-ancestors في CSP للمتصفحات الحالية، وX-Frame-Options للقديمة."),
   ("'none' / DENY also stops your own site from framing the page; use 'self' / SAMEORIGIN if you embed your own pages.",
    "تمنع القيمة 'none' أو DENY موقعك أنت أيضًا من تضمين الصفحة؛ فاستخدم 'self' أو SAMEORIGIN إن كنت تضمّن صفحاتك."),
   [
       _b("any", """
Content-Security-Policy: <your policy>; frame-ancestors 'none'      (or 'self')
X-Frame-Options: DENY                                                (or SAMEORIGIN; for old browsers)""", "text",
         ("Add frame-ancestors to the policy you already send (S-CSP): a policy with only frame-ancestors restricts no "
          "scripts, and Kashif reports it as such (WEB042).",
          "أضف frame-ancestors إلى السياسة التي ترسلها أصلًا (S-CSP)، فالسياسة التي لا تحوي إلا frame-ancestors لا تقيّد "
          "أي سكربت، ويبلّغ عنها كاشِف بذلك (WEB042).")),
       *header_blocks("X-Frame-Options", "DENY"),
       _b("express", 'app.use(helmet.xFrameOptions({ action: "deny" }));', "js"),
       _b("django", 'X_FRAME_OPTIONS = "DENY"', "python",
         ("The default since Django 3.0 (XFrameOptionsMiddleware).",
          "هذه القيمة الافتراضية منذ Django 3.0 (عبر XFrameOptionsMiddleware).")),
       _b("spring", "http.headers(h -> h.frameOptions(f -> f.deny()));", "java",
         ("The default in Spring Security.", "هذه القيمة الافتراضية في Spring Security.")),
   ],
   [Header("X-Frame-Options", "DENY")])

_s("S-XCTO",
   ("nosniff and a correct Content-Type", "ترويسة nosniff ونوع محتوى صحيح"),
   ("Send X-Content-Type-Options: nosniff and a correct Content-Type with charset=utf-8 on every response.",
    "أرسل X-Content-Type-Options: nosniff ونوع محتوى صحيحًا مع charset=utf-8 في كل استجابة."),
   ("With nosniff, a script or stylesheet served with a wrong Content-Type is blocked: check your MIME types first.",
    "مع nosniff يُمنع أي سكربت أو ملف أنماط يُقدَّم بنوع محتوى خاطئ، فتحقّق من أنواع MIME أولًا."),
   [
       _b("any", "X-Content-Type-Options: nosniff\nContent-Type: text/html; charset=utf-8"),
       _b("nginx", 'add_header X-Content-Type-Options "nosniff" always;\ncharset utf-8;', "nginx",
         ("Also keep correct types{} / default_type.", "واحرص أيضًا على صحة types{} وdefault_type.")),
       _b("apache", 'Header always set X-Content-Type-Options "nosniff"\nAddDefaultCharset UTF-8', "apache"),
       *header_blocks("X-Content-Type-Options", "nosniff", skip=("nginx", "apache")),
       _b("express", "app.use(helmet.xContentTypeOptions());", "js",
         ("On by default in helmet.", "مفعّلة افتراضيًا في helmet.")),
       _b("django", "SECURE_CONTENT_TYPE_NOSNIFF = True", "python",
         ("The default.", "هذه القيمة الافتراضية.")),
       _b("spring", note=("On by default in Spring Security.", "مفعّلة افتراضيًا في Spring Security.")),
   ],
   [Header("X-Content-Type-Options", "nosniff", "any")])

_s("S-REF",
   ("Referrer-Policy", "ترويسة Referrer-Policy"),
   ("Send Referrer-Policy: strict-origin-when-cross-origin (or no-referrer) so full URLs are not sent to other sites.",
    "أرسل Referrer-Policy: strict-origin-when-cross-origin (أو no-referrer) حتى لا تُرسل الروابط الكاملة إلى مواقع أخرى."),
   ("no-referrer also removes the origin that some payment or analytics providers expect; strict-origin-when-cross-origin "
    "keeps it.",
    "تزيل no-referrer أيضًا المصدر الذي يتوقعه بعض مزودي الدفع أو التحليلات، أما strict-origin-when-cross-origin فتبقيه."),
   [
       _b("any", "Referrer-Policy: strict-origin-when-cross-origin"),
       *header_blocks("Referrer-Policy", "strict-origin-when-cross-origin"),
       _b("express", 'app.use(helmet.referrerPolicy({ policy: "strict-origin-when-cross-origin" }));', "js"),
       _b("django", 'SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"', "python"),
       _b("spring", "http.headers(h -> h.referrerPolicy(r -> r.policy("
                   "ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)));", "java"),
   ],
   [Header("Referrer-Policy", "strict-origin-when-cross-origin")])

_PP = ("camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), hid=(), display-capture=(), "
       "browsing-topics=()")
_s("S-PP",
   ("Permissions-Policy", "ترويسة Permissions-Policy"),
   ("Disable the browser features you do not use (structured-field syntax: feature=() means nobody).",
    "عطّل ميزات المتصفح التي لا تستخدمها (بصيغة الحقول المنظَّمة: feature=() تعني لا أحد)."),
   ("Remove a feature from the list (or allow it for self) if your pages use it, such as payment=(self) for a checkout "
    "or geolocation=(self) for a map.",
    "احذف الميزة من القائمة (أو اسمح بها لـ self) إن كانت صفحاتك تستخدمها، مثل payment=(self) لصفحة الدفع أو "
    "geolocation=(self) لخريطة."),
   [
       _b("any", f"Permissions-Policy: {_PP}"),
       *header_blocks("Permissions-Policy", _PP),
       _b("express", f'app.use((req, res, next) => {{ res.setHeader("Permissions-Policy", "{_PP}"); next(); }});', "js"),
       _b("django", note=("Add the header in a middleware (Django has no setting for it), or use django-permissions-policy.",
                         "أضف الترويسة عبر وسيط (middleware) لأن Django لا يوفر إعدادًا لها، أو استخدم الحزمة "
                         "django-permissions-policy.")),
       _b("spring", 'http.headers(h -> h.permissionsPolicyHeader(p -> p.policy("camera=(), microphone=(), geolocation=()")));',
         "java", ("Spring Security 6.4+.", "يتطلب Spring Security 6.4 أو أحدث.")),
   ],
   [Header("Permissions-Policy", _PP)])

_s("S-ISO",
   ("Cross-origin isolation (COOP, CORP, COEP)", "العزل بين المصادر (COOP وCORP وCOEP)"),
   ("Keep other sites' windows and pages away from yours: COOP same-origin, CORP same-origin, and COEP only if you "
    "need crossOriginIsolated.",
    "أبعد نوافذ المواقع الأخرى وصفحاتها عن موقعك: COOP بالقيمة same-origin وCORP بالقيمة same-origin، وCOEP فقط إن "
    "احتجت إلى crossOriginIsolated."),
   ("COOP same-origin breaks OAuth and payment pop-ups (use same-origin-allow-popups there); COEP require-corp blocks "
    "cross-origin resources that send no CORP/CORS headers, so test it first.",
    "تُعطّل COOP بالقيمة same-origin النوافذ المنبثقة لتسجيل الدخول OAuth والدفع (فاستخدم same-origin-allow-popups "
    "هناك)، وتمنع COEP بالقيمة require-corp الموارد الخارجية التي لا ترسل ترويسات CORP أو CORS، فجرّبها أولًا."),
   [
       _b("any", """
Cross-Origin-Opener-Policy: same-origin                 (same-origin-allow-popups if OAuth / payment popups are used)
Cross-Origin-Resource-Policy: same-origin               (same-site for assets shared with sibling subdomains)
Cross-Origin-Embedder-Policy: require-corp              (only if you need crossOriginIsolated; test first)"""),
       *header_blocks("Cross-Origin-Opener-Policy", "same-origin"),
       _b("express", 'app.use(helmet.crossOriginOpenerPolicy({ policy: "same-origin" }));\n'
                    'app.use(helmet.crossOriginResourcePolicy({ policy: "same-origin" }));', "js",
         ("COEP is off by default in helmet 7+; keep it that way unless needed.",
          "‏COEP معطّلة افتراضيًا في helmet 7 وما بعده، فأبقها كذلك ما لم تحتج إليها.")),
       _b("django", 'SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"', "python",
         ("The default.", "هذه القيمة الافتراضية.")),
       _b("spring", "http.headers(h -> h.crossOriginOpenerPolicy(c -> c.policy("
                   "CrossOriginOpenerPolicyHeaderWriter.CrossOriginOpenerPolicy.SAME_ORIGIN)));", "java"),
   ],
   [Header("Cross-Origin-Opener-Policy", "same-origin"), Header("Cross-Origin-Resource-Policy", "same-origin"),
    Header("Cross-Origin-Embedder-Policy", "require-corp")])

_s("S-COOKIE",
   ("Session cookie attributes", "سمات كوكي الجلسة"),
   ("Set session cookies with the __Host- prefix, Path=/, Secure, HttpOnly and SameSite=Lax.",
    "اضبط كوكي الجلسة بالبادئة __Host- مع Path=/ وSecure وHttpOnly وSameSite=Lax."),
   ("Renaming the session cookie (__Host-) logs every user out once, and SameSite=Strict would also drop the session on "
    "links from other sites; Lax is the safe default.",
    "تغيير اسم كوكي الجلسة (إلى __Host-) يُخرج كل المستخدمين مرة واحدة، والقيمة SameSite=Strict تُسقط الجلسة أيضًا عند "
    "القدوم من روابط مواقع أخرى؛ لذا فالقيمة Lax هي الخيار الآمن الافتراضي."),
   [
       _b("any", "Set-Cookie: __Host-sid=<random>; Path=/; Secure; HttpOnly; SameSite=Lax\nCache-Control: no-store",
         "text", ("A response that sets a session cookie must not be stored by shared caches: send Cache-Control: "
                  "no-store on it (S-CACHE).",
                  "يجب ألا تخزّن الذاكرات المؤقتة المشتركة أي استجابة تضبط كوكي جلسة، فأرسل معها Cache-Control: no-store "
                  "‏(S-CACHE).")),
       _b("nginx", """
proxy_cookie_flags sessionid secure httponly samesite=lax;   # each session cookie by name (the first match applies)
proxy_cookie_flags ~ secure samesite=lax;                     # every other cookie""", "nginx",
         ("nginx 1.19.3+ as a reverse proxy; prefer fixing the application. Name each session cookie on its own "
          "httponly line; never give HttpOnly to a CSRF cookie your JavaScript reads (such as XSRF-TOKEN or csrftoken).",
          "يتطلب nginx 1.19.3 أو أحدث كوكيل عكسي، والأفضل إصلاح التطبيق نفسه. اذكر كل كوكي جلسة باسمها في سطر httponly "
          "خاص بها، ولا تضف HttpOnly أبدًا إلى كوكي CSRF يقرؤها كود JavaScript (مثل XSRF-TOKEN أو csrftoken).")),
       _b("apache", r'Header always edit Set-Cookie "^((?!.*;\s*Secure).*)$" "$1; Secure"', "apache",
         ("Proxy, last resort; prefer the application setting.", "كحل أخير عند الوكيل فقط؛ والأفضل ضبطها في التطبيق.")),
       _b("iis", '<system.web><httpCookies requireSSL="true" httpOnlyCookies="true" sameSite="Lax" /></system.web>', "xml",
         ("IIS / ASP.NET web.config.", "ملف web.config في IIS أو ASP.NET.")),
       _b("php", "session.cookie_secure=1\nsession.cookie_httponly=1\nsession.cookie_samesite=Lax\n"
                "session.use_only_cookies=1\nsession.use_trans_sid=0", "ini", ("php.ini", "ملف php.ini")),
       _b("express", 'session({ name: "__Host-sid", cookie: { secure: true, httpOnly: true, sameSite: "lax", path: "/" } })',
         "js"),
       _b("django", 'SESSION_COOKIE_SECURE = True\nSESSION_COOKIE_HTTPONLY = True   # default\n'
                   'SESSION_COOKIE_SAMESITE = "Lax"   # default\nSESSION_COOKIE_NAME = "__Host-sessionid"\n'
                   'CSRF_COOKIE_SECURE = True', "python"),
       _b("spring", "server.servlet.session.cookie.secure=true\nserver.servlet.session.cookie.http-only=true\n"
                   "server.servlet.session.cookie.same-site=lax\n"
                   "# stops ;jsessionid= URLs\n"
                   "server.servlet.session.tracking-modes=cookie", "properties",
         ("Spring Boot application.properties.", "ملف application.properties في Spring Boot.")),
       _b("aspnetcore", 'builder.Services.ConfigureApplicationCookie(o => { o.Cookie.Name = "__Host-auth"; '
                       "o.Cookie.SecurePolicy = CookieSecurePolicy.Always; o.Cookie.HttpOnly = true; "
                       'o.Cookie.SameSite = SameSiteMode.Lax; o.Cookie.Path = "/"; });', "csharp"),
       _b("cloudflare", note=("Cookies are set by the origin; fix them there (a Worker can rewrite Set-Cookie as a stop-gap).",
                             "الكوكيز يضبطها الخادم الأصلي فأصلحها هناك (ويمكن لـ Worker إعادة كتابة Set-Cookie كحل مؤقت).")),
       _b("bigip", note=("WEB411: enable \"Cookie Encryption\" in the persistence profile.",
                        "للقاعدة WEB411: فعّل \"Cookie Encryption\" في ملف تعريف الاستمرارية (persistence profile).")),
   ],
   [Header("Set-Cookie", "__Host-sid=<random>; Path=/; Secure; HttpOnly; SameSite=Lax", "sensitive"),
    Header("Cache-Control", "no-store", "sensitive")])

_s("S-CORS",
   ("CORS: allowlist, never reflect", "CORS: قائمة سماح محددة وعدم عكس الأصل أبدًا"),
   ("Answer cross-origin requests only for the origins you trust, add Vary: Origin, and delete Flash/Silverlight "
    "policy files.",
    "أجب عن الطلبات القادمة من مصادر أخرى للمصادر الموثوقة فقط، وأضف Vary: Origin، واحذف ملفات سياسات Flash وSilverlight."),
   ("Removing a reflected or wildcard origin breaks any partner site that relied on it: list those origins explicitly "
    "before switching.",
    "حذف الأصل المعكوس أو الشامل (*) يعطّل أي موقع شريك كان يعتمد عليه، فأدرج تلك المصادر صراحةً قبل التغيير."),
   [
       _b("nginx", """
map $http_origin $cors_origin { default ""; "https://app.{domain}" $http_origin; }
add_header Access-Control-Allow-Origin $cors_origin always;     # nginx sends nothing when the value is empty
add_header Vary Origin always;""", "nginx"),
       _b("apache", r"""
SetEnvIf Origin "^(https://app\.{domain_re})$" CORS_OK=$1
Header always set Access-Control-Allow-Origin "%{CORS_OK}e" env=CORS_OK
Header always merge Vary Origin""", "apache"),
       _b("express", 'app.use(require("cors")({ origin: ["https://app.{domain}"], credentials: true }));', "js",
         ("helmet has no CORS; use the cors package.", "لا تتضمن helmet إعدادات CORS؛ استخدم الحزمة cors.")),
       _b("django", 'CORS_ALLOWED_ORIGINS = ["https://app.{domain}"]', "python",
         ("django-cors-headers; never CORS_ALLOW_ALL_ORIGINS with credentials.",
          "مع الحزمة django-cors-headers؛ ولا تستخدم CORS_ALLOW_ALL_ORIGINS أبدًا مع بيانات الاعتماد.")),
       _b("spring", 'config.setAllowedOrigins(List.of("https://app.{domain}"));', "java",
         ("Never a * pattern with setAllowCredentials(true).", "لا تستخدم النمط * أبدًا مع setAllowCredentials(true).")),
       _b("aspnetcore", 'builder.Services.AddCors(o => o.AddPolicy("app", p => p.WithOrigins("https://app.{domain}")'
                       '.AllowCredentials()));', "csharp"),
       _b("iis", '<cors enabled="true"><add origin="https://app.{domain}" allowCredentials="true" /></cors>', "xml",
         ("IIS CORS module.", "وحدة CORS في IIS.")),
       _b("cloudflare", note=("Set CORS at the origin or in a Worker.", "اضبط CORS في الخادم الأصلي أو في Worker.")),
       _b("any", note=("Delete crossdomain.xml and clientaccesspolicy.xml (WEB903); no current browser needs them.",
                      "احذف الملفين crossdomain.xml وclientaccesspolicy.xml ‏(WEB903)؛ لا يحتاجهما أي متصفح حالي.")),
   ],
   [Header("Vary", "Origin")])

_s("S-BANNER",
   ("Hide versions and stack headers", "إخفاء الإصدارات وترويسات التقنية"),
   ("Stop announcing server, framework and runtime versions in Server, X-Powered-By and similar headers.",
    "أوقف إعلان إصدارات الخادم وإطار العمل وبيئة التشغيل في ترويسات Server وX-Powered-By وما شابهها."),
   ("Hiding versions is defence in depth only: patch the software too (WEB800/WEB801).",
    "إخفاء الإصدارات دفاع إضافي فقط؛ فحدّث البرمجيات أيضًا (WEB800/WEB801)."),
   [
       _b("nginx", "server_tokens off;\nproxy_hide_header X-Powered-By;\nfastcgi_hide_header X-Powered-By;", "nginx"),
       _b("apache", "ServerTokens Prod\nServerSignature Off\nHeader always unset X-Powered-By\n"
                   "# WEB604: no inode in ETag\nFileETag MTime Size", "apache"),
       _b("php", "expose_php = Off", "ini", ("php.ini", "ملف php.ini")),
       _b("iis", """
<security><requestFiltering removeServerHeader="true" /></security>
<httpProtocol><customHeaders><remove name="X-Powered-By" /></customHeaders></httpProtocol>
<!-- X-AspNet-Version: <system.web><httpRuntime enableVersionHeader="false" /></system.web> -->""", "xml",
         ("ASP.NET MVC: MvcHandler.DisableMvcResponseHeader = true;",
          "في ASP.NET MVC أضف: MvcHandler.DisableMvcResponseHeader = true;")),
       _b("caddy", "header -Server\nheader -X-Powered-By", "caddy"),
       _b("express", 'app.disable("x-powered-by");', "js", ("helmet does it too.", "وتفعل helmet ذلك أيضًا.")),
       _b("spring", "server.server-header=", "properties",
         ("Empty value (Tomcat/Jetty).", "قيمة فارغة (Tomcat وJetty).")),
       _b("aspnetcore", "builder.WebHost.ConfigureKestrel(k => k.AddServerHeader = false);", "csharp"),
       _b("cloudflare", note=("Rules → Transform Rules → Managed Transforms → \"Remove X-Powered-By headers\".",
                             "في لوحة Cloudflare: ‏Rules → Transform Rules → Managed Transforms، ثم فعّل \"Remove X-Powered-By headers\".")),
   ])

_s("S-DIRLIST",
   ("Turn directory listing off", "تعطيل عرض فهارس المجلدات"),
   ("Make the web server answer 403/404 for folders without an index page instead of listing their files.",
    "اجعل خادم الويب يجيب بـ 403 أو 404 عن المجلدات التي لا تحتوي صفحة فهرس بدل عرض ملفاتها."),
   ("Folders meant for public downloads stop showing their file list; publish an index page for them if needed.",
    "المجلدات المخصصة للتنزيل العام لن تعرض قائمة ملفاتها بعد ذلك، فأنشئ لها صفحة فهرس إن احتجت."),
   [
       _b("nginx", "autoindex off;", "nginx"),
       _b("apache", "Options -Indexes", "apache"),
       _b("iis", '<directoryBrowse enabled="false" />', "xml"),
       _b("caddy", "file_server   # without the browse subdirective", "caddy"),
       _b("express", note=("Do not use serve-index.", "لا تستخدم الحزمة serve-index.")),
       _b("tomcat", "<init-param><param-name>listings</param-name><param-value>false</param-value></init-param>", "xml",
         ("web.xml, DefaultServlet.", "في ملف web.xml ضمن DefaultServlet.")),
       _b("any", note=("Python's http.server is not a production server.",
                      "الوحدة http.server في Python ليست خادمًا للإنتاج.")),
   ])

_s("S-DOTFILES",
   ("Block VCS folders, backups, env/config files and source maps", "منع الوصول إلى مجلدات التحكم بالإصدارات والنسخ الاحتياطية وملفات الإعداد وخرائط المصدر"),
   ("Deny hidden files and folders (except /.well-known/), backups, dumps, env files and source maps at the web server, "
    "and deploy build artifacts only.",
    "امنع من خادم الويب الملفات والمجلدات المخفية (عدا ‎/.well-known/‎) والنسخ الاحتياطية وملفات التفريغ وملفات البيئة "
    "وخرائط المصدر، وانشر مخرجات البناء فقط."),
   ("Keep /.well-known/ reachable (ACME certificate renewal and security.txt need it), and check that no needed file "
    "uses a blocked extension.",
    "أبقِ ‎/.well-known/‎ متاحًا (يحتاجه تجديد شهادات ACME وملف security.txt)، وتأكد من أن أي ملف تحتاجه لا يستخدم "
    "امتدادًا محظورًا."),
   [
       _b("nginx", r"""
location ~ /\.(?!well-known/) { return 404; }
location ~* \.(bak|old|orig|swp|sql|env|log|ini|map)$ { return 404; }""", "nginx"),
       _b("apache", r"""
RedirectMatch 404 "/\.(?!well-known/)"
<FilesMatch "\.(bak|old|orig|swp|sql|env|log|ini|map)$">
    Require all denied
</FilesMatch>""", "apache"),
       _b("iis", """
<security><requestFiltering>
  <hiddenSegments><add segment=".git" /><add segment=".svn" /><add segment=".env" /></hiddenSegments>
  <fileExtensions><add fileExtension=".bak" allowed="false" /><add fileExtension=".sql" allowed="false" /><add fileExtension=".map" allowed="false" /></fileExtensions>
</requestFiltering></security>""", "xml"),
       _b("caddy", """
@hidden path /.git/* /.svn/* /.env* *.bak *.sql *.map
respond @hidden 404""", "caddy"),
       _b("express", 'express.static(dir, { dotfiles: "deny" })', "js",
         ("And build with devtool: false (no production source maps).",
          "وابنِ المشروع مع devtool: false (بلا خرائط مصدر في الإنتاج).")),
       _b("spring", "management.endpoints.web.exposure.include=health", "properties",
         ("WEB062 actuator; and no WEB-INF outside the WAR.", "لمنافذ actuator ‏(WEB062)؛ ولا تضع WEB-INF خارج ملف WAR.")),
       _b("any", note=("Deploy build artifacts only (no .git, no backups) and keep secrets outside the web root.",
                      "انشر مخرجات البناء فقط (بلا .git وبلا نسخ احتياطية) واحفظ الأسرار خارج جذر الموقع.")),
   ])

_s("S-ERR",
   ("Production error handling", "معالجة الأخطاء في بيئة الإنتاج"),
   ("Turn debug mode off, log errors on the server and show users a generic error page.",
    "عطّل وضع التصحيح، وسجّل الأخطاء في الخادم، واعرض للمستخدمين صفحة خطأ عامة."),
   ("Make sure errors are still logged (log_errors, application logs) before hiding them, or failures become invisible.",
    "تأكد من استمرار تسجيل الأخطاء (log_errors وسجلات التطبيق) قبل إخفائها، وإلا صارت الأعطال غير مرئية."),
   [
       _b("php", "display_errors = Off\nlog_errors = On", "ini"),
       _b("django", "DEBUG = False", "python"),
       _b("flask", "app.run(debug=False)", "python",
         ("Never run the Werkzeug debugger in production.", "لا تشغّل مصحّح Werkzeug في الإنتاج أبدًا.")),
       _b("laravel", "APP_DEBUG=false", "ini", (".env", "ملف ‎.env")),
       _b("rails", "config.consider_all_requests_local = false", "ruby"),
       _b("spring", "server.error.include-stacktrace=never\nserver.error.include-message=never", "properties"),
       _b("aspnetcore", 'app.UseExceptionHandler("/error");', "csharp",
         ("Never UseDeveloperExceptionPage in production.", "لا تستخدم UseDeveloperExceptionPage في الإنتاج أبدًا.")),
       _b("aspnet", '<customErrors mode="RemoteOnly" defaultRedirect="/error" />\n<compilation debug="false" />', "xml"),
       _b("iis", '<httpErrors errorMode="DetailedLocalOnly" />', "xml",
         ("Inside <system.webServer> of web.config: detailed errors only on the server itself.",
          "داخل <system.webServer> في ملف web.config: الأخطاء التفصيلية على الخادم نفسه فقط.")),
       _b("express", "NODE_ENV=production", "shell",
         ("Set it in the service environment (systemd Environment=, docker run -e, your host's settings): Express then "
          "stops sending stack traces; log errors in your own error handler.",
          "اضبطه في بيئة الخدمة (Environment= في systemd أو docker run -e أو إعدادات الاستضافة)، فيتوقف Express عن إرسال "
          "أثر الاستثناء؛ وسجّل الأخطاء في معالج الأخطاء الخاص بك.")),
       _b("symfony", "APP_ENV=prod", "ini"),
       _b("nginx", "proxy_intercept_errors on;\nerror_page 500 502 503 504 /50x.html;", "nginx"),
       _b("apache", "ErrorDocument 500 /error.html", "apache"),
   ])

_TLS_CIPHERS = ("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:"
                "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305")
_s("S-TLS",
   ("TLS configuration (Mozilla intermediate 6.0)", "إعدادات TLS ‏(Mozilla intermediate 6.0)"),
   ("TLS 1.2 and 1.3 only with forward-secret AEAD suites, a trusted certificate with automatic renewal, and the full "
    "chain.",
    "TLS 1.2 و1.3 فقط مع مجموعات تشفير AEAD ذات سرية أمامية، وشهادة موثوقة تتجدد تلقائيًا، وإرسال السلسلة كاملة."),
   ("Disabling TLS 1.0/1.1 cuts off very old clients (Android 4.3 and older, old embedded devices); check your traffic "
    "first.",
    "تعطيل TLS 1.0 و1.1 يقطع العملاء القدامى جدًا (Android 4.3 وما قبله والأجهزة المدمجة القديمة)، فراجع حركة موقعك أولًا."),
   [
       _b("nginx", f"""
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers {_TLS_CIPHERS};
ssl_prefer_server_ciphers off;
ssl_ecdh_curve X25519:prime256v1:secp384r1;
# with OpenSSL >= 3.5, add the post-quantum hybrid group instead:
# ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1:secp384r1;
ssl_session_tickets off;
ssl_stapling on; ssl_stapling_verify on;                     # only if the certificate has an OCSP URL""", "nginx",
         ("Check the configuration with nginx -t before reloading (nginx -s reload).",
          "تحقّق من الإعداد بالأمر nginx -t قبل إعادة التحميل (nginx -s reload).")),
       _b("apache", f"""
SSLProtocol             -all +TLSv1.2 +TLSv1.3
SSLCipherSuite          {_TLS_CIPHERS}
SSLHonorCipherOrder     off
SSLSessionTickets       off
SSLCompression          off""", "apache"),
       _b("iis", note=(
           "Windows: disable SSL 2.0/3.0 and TLS 1.0/1.1 under HKLM\\SYSTEM\\CurrentControlSet\\Control\\"
           "SecurityProviders\\SCHANNEL\\Protocols (Enabled=0 for Server), order suites with Disable-TlsCipherSuite or "
           "Group Policy, then reboot.",
           "في Windows: عطّل SSL 2.0/3.0 وTLS 1.0/1.1 تحت المفتاح HKLM\\SYSTEM\\CurrentControlSet\\Control\\"
           "SecurityProviders\\SCHANNEL\\Protocols (القيمة Enabled=0 للخادم Server)، ورتّب مجموعات التشفير بالأمر "
           "Disable-TlsCipherSuite أو بنهج المجموعة (Group Policy)، ثم أعد التشغيل.")),
       _b("caddy", "tls {\n\tprotocols tls1.2 tls1.3\n}", "caddy",
         ("Defaults are already TLS 1.2+ with modern suites; this only pins them.",
          "الإعدادات الافتراضية أصلًا TLS 1.2 فما فوق بمجموعات حديثة، وهذا السطر يثبّتها فقط.")),
       _b("node", 'minVersion: "TLSv1.2"', "js", ("If Node terminates TLS (tls/https options).",
                                                  "إن كان Node هو من يُنهي TLS (خيارات tls أو https).")),
       _b("spring", "server.ssl.enabled-protocols=TLSv1.2,TLSv1.3", "properties"),
       _b("cloudflare", note=("SSL/TLS → Edge Certificates → Minimum TLS Version = 1.2, TLS 1.3 = On; SSL mode "
                             "\"Full (strict)\".",
                             "SSL/TLS → Edge Certificates → Minimum TLS Version = 1.2 وTLS 1.3 = On، واختر وضع "
                             "SSL ‏\"Full (strict)\".")),
       _b("any", note=("Certificates: ACME (Let's Encrypt or another CA) with automatic renewal; RSA 2048 or ECDSA P-256; "
                      "serve the full chain (fullchain.pem).",
                      "الشهادات: استخدم ACME ‏(Let's Encrypt أو جهة أخرى) مع التجديد التلقائي، ومفتاح RSA 2048 أو ECDSA "
                      "P-256، وأرسل السلسلة كاملة (fullchain.pem).")),
   ])

_s("S-MIXED",
   ("Remove mixed content", "إزالة المحتوى المختلط"),
   ("Change http:// subresource and form URLs to https:// (or a relative URL on your own origin), and add "
    "upgrade-insecure-requests as a safety net.",
    "غيّر روابط الموارد والنماذج من http://‎ إلى https://‎ (أو رابط نسبي على موقعك)، وأضف upgrade-insecure-requests "
    "كشبكة أمان."),
   ("upgrade-insecure-requests makes the browser fetch https:// instead; a host without HTTPS then fails to load, so "
    "check every third-party URL.",
    "يجعل upgrade-insecure-requests المتصفح يطلب https://‎ بدلًا من ذلك، فيفشل تحميل أي مضيف لا يدعم HTTPS، لذا تحقّق "
    "من كل رابط خارجي."),
   [
       _b("any", "Content-Security-Policy: <your policy>; upgrade-insecure-requests", "text",
         ("Add the directive to the policy you already send (S-CSP). Sent alone it restricts no scripts.",
          "أضف هذا التوجيه إلى السياسة التي ترسلها أصلًا (S-CSP)، فإرساله وحده لا يقيّد أي سكربت.")),
   ],
   [Header("Content-Security-Policy", "upgrade-insecure-requests")])

_s("S-SRI",
   ("Subresource Integrity for third-party code", "التحقق من سلامة الموارد الخارجية (SRI)"),
   ("Load third-party scripts and stylesheets from a pinned, versioned URL with an integrity hash and "
    "crossorigin=\"anonymous\"; restrict evergreen vendor scripts with CSP instead, or self-host them.",
    "حمّل السكربتات وملفات الأنماط الخارجية من رابط مثبّت بإصدار محدد مع بصمة integrity والسمة crossorigin=\"anonymous\"، "
    "وقيّد سكربتات المزودين المتغيرة باستمرار بسياسة CSP بدلًا من ذلك، أو استضفها على خادمك."),
   ("The browser blocks the file when its content changes, so pin a versioned URL; evergreen scripts (Google Tag "
    "Manager, Stripe.js) cannot use SRI.",
    "يمنع المتصفح الملف إذا تغيّر محتواه، لذا ثبّت رابطًا بإصدار محدد؛ أما السكربتات المتغيرة باستمرار (Google Tag Manager "
    "وStripe.js) فلا يمكن استخدام SRI معها."),
   [
       _b("any", """
<script src="https://cdn.example.net/lib/1.2.3/lib.min.js" integrity="sha384-<base64>" crossorigin="anonymous"></script>""",
         "html", label=("All platforms · HTML", "كل المنصات · HTML")),
       _b("any", "openssl dgst -sha384 -binary lib.min.js | openssl base64 -A", "shell",
         ("Compute the integrity value of the exact file you load.", "احسب قيمة integrity للملف نفسه الذي تحمّله."),
         ("All platforms · integrity value", "كل المنصات · قيمة integrity")),
   ])

_s("S-LIBS",
   ("Upgrade vulnerable components", "تحديث المكونات المصابة بثغرات"),
   ("Upgrade the library or platform to the fixed version, rebuild and redeploy; add Kashif's dependency scan (kashif "
    "<project-dir>) or npm audit to CI.",
    "حدّث المكتبة أو المنصة إلى الإصدار المُصلَح، ثم أعد البناء والنشر؛ وأضف فحص الاعتماديات في كاشِف (kashif <project-dir>) "
    "أو npm audit إلى خط التكامل المستمر."),
   ("A major-version upgrade can change APIs: run your tests and read the library's migration notes before deploying.",
    "قد يغيّر التحديث إلى إصدار رئيسي جديد واجهات البرمجة، فشغّل اختباراتك واقرأ ملاحظات الترحيل قبل النشر."),
   [
       _b("any", """
npm install <lib>@<fixed>     # or point the CDN URL at the fixed version
kashif <project-dir>          # in CI: catches the next vulnerable version before deployment""", "shell",
         ("Installed with npm: upgrade the package; loaded from a CDN: replace the URL with the fixed version. Run "
          "kashif in CI so the next vulnerable version is caught before deployment.",
          "إن ثبّتّ المكتبة عبر npm فحدّث الحزمة، وإن حمّلتها من CDN فاستبدل الرابط برابط الإصدار المُصلَح. وشغّل kashif "
          "في التكامل المستمر ليُكتشف أي إصدار مصاب لاحق قبل النشر.")),
   ])

_s("S-SECTXT",
   ("security.txt (RFC 9116)", "ملف security.txt ‏(RFC 9116)"),
   ("Publish /.well-known/security.txt as text/plain; charset=utf-8 so researchers know how to report a vulnerability.",
    "انشر الملف ‎/.well-known/security.txt‎ بنوع text/plain; charset=utf-8 ليعرف الباحثون كيف يبلّغون عن الثغرات."),
   ("Expires must be renewed before it passes (less than a year ahead is recommended); an expired file is treated as "
    "invalid.",
    "يجب تجديد قيمة Expires قبل حلول موعدها (يُنصح بأن تكون بعد أقل من سنة)، فالملف المنتهي يُعدّ غير صالح."),
   [
       _b("any", """
Contact: mailto:security@{domain}
Expires: {expires}
Preferred-Languages: ar, en
Canonical: https://{host}/.well-known/security.txt
Policy: https://{host}/security-policy""", "text",
         ("Expires is the scan date + 6 months (RFC 9116 §2.5.5 recommends less than a year).",
          "قيمة Expires هي تاريخ الفحص مضافًا إليه 6 أشهر (يوصي RFC 9116 ‏§2.5.5 بأقل من سنة).")),
   ])

_s("S-CACHE",
   ("Do not cache sensitive responses", "منع تخزين الاستجابات الحساسة مؤقتًا"),
   ("Send Cache-Control: no-store on personalised and authenticated responses, never public/s-maxage, and clear the "
    "browser's data on logout.",
    "أرسل Cache-Control: no-store في الاستجابات الشخصية والمحمية بالمصادقة، ولا تستخدم public أو s-maxage فيها أبدًا، "
    "وامسح بيانات المتصفح عند تسجيل الخروج."),
   ("Apply no-store only to sensitive paths: on static assets it slows the site down. Clear-Site-Data \"cookies\" logs "
    "the user out of every subdomain, so send it on the logout response only.",
    "طبّق no-store على المسارات الحساسة فقط، لأنها تُبطئ الموقع إن طُبّقت على الملفات الثابتة. وتُخرج القيمة "
    "Clear-Site-Data \"cookies\" المستخدم من كل النطاقات الفرعية، فأرسلها في استجابة تسجيل الخروج فقط."),
   [
       _b("any", 'Cache-Control: no-store\nClear-Site-Data: "cache", "cookies", "storage"      (logout response only)',
         "text", ("OWASP: Cache-Control: no-store, max-age=0.", "توصية OWASP: ‏Cache-Control: no-store, max-age=0.")),
       _b("nginx", 'add_header Cache-Control "no-store" always;', "nginx",
         ("In the sensitive location{}.", "داخل كتلة location{} الحساسة.")),
       _b("apache", '<LocationMatch "^/(account|admin)">\n    Header always set Cache-Control "no-store"\n</LocationMatch>',
         "apache"),
       _b("django", "from django.views.decorators.cache import never_cache\n\n@never_cache\ndef account(request): ...",
         "python"),
       _b("spring", note=("Default on secured responses (no-cache, no-store, max-age=0, must-revalidate).",
                         "افتراضي في الاستجابات المحمية (no-cache, no-store, max-age=0, must-revalidate).")),
       _b("aspnetcore", "[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]", "csharp"),
       _b("cloudflare", note=("Cache Rules → bypass cache for authenticated paths / when a session cookie is present.",
                             "في Cache Rules: تجاوز التخزين المؤقت للمسارات المحمية أو عند وجود كوكي جلسة.")),
   ],
   [Header("Cache-Control", "no-store", "sensitive"),
    Header("Clear-Site-Data", '"cache", "cookies", "storage"', "logout")])

_s("S-DEPR",
   ("Remove deprecated security headers", "إزالة ترويسات الأمان المتقادمة"),
   ("Remove Public-Key-Pins, Expect-CT and Feature-Policy (use Permissions-Policy); set X-XSS-Protection: 0 or remove "
    "it; set X-Permitted-Cross-Domain-Policies: none.",
    "احذف Public-Key-Pins وExpect-CT وFeature-Policy (واستخدم Permissions-Policy)، واضبط X-XSS-Protection: 0 أو احذفها، "
    "واضبط X-Permitted-Cross-Domain-Policies: none."),
   ("Move any feature rules from Feature-Policy into Permissions-Policy before removing it, or those features become "
    "allowed again.",
    "انقل قواعد الميزات من Feature-Policy إلى Permissions-Policy قبل حذفها، وإلا عادت تلك الميزات مسموحة."),
   [
       _b("any", "X-XSS-Protection: 0\nX-Permitted-Cross-Domain-Policies: none"),
       _b("nginx", 'add_header X-XSS-Protection "0" always;\nadd_header X-Permitted-Cross-Domain-Policies "none" always;\n'
                  "proxy_hide_header Public-Key-Pins;\nproxy_hide_header Expect-CT;\nproxy_hide_header Feature-Policy;",
         "nginx"),
       _b("apache", 'Header always set X-XSS-Protection "0"\nHeader always set X-Permitted-Cross-Domain-Policies "none"\n'
                   "Header always unset Public-Key-Pins\nHeader always unset Expect-CT\nHeader always unset Feature-Policy",
         "apache"),
       *header_blocks("X-Permitted-Cross-Domain-Policies", "none", skip=("nginx", "apache")),
   ],
   [Header("X-XSS-Protection", "0"), Header("X-Permitted-Cross-Domain-Policies", "none")])

_s("S-BREACH",
   ("BREACH: protect secrets in compressed responses", "BREACH: حماية الأسرار في الاستجابات المضغوطة"),
   ("Keep compression; mask CSRF tokens per response (Django, Rails and Laravel already do), avoid reflecting user "
    "input next to secrets, or disable compression on those pages only.",
    "أبقِ الضغط، وأخفِ رموز CSRF في كل استجابة (يفعل ذلك Django وRails وLaravel أصلًا)، وتجنب عكس مدخلات المستخدم بجوار "
    "الأسرار، أو عطّل الضغط في تلك الصفحات فقط."),
   ("Turning compression off site-wide makes pages slower and is not needed; limit it to pages that mix secrets with "
    "user input.",
    "تعطيل الضغط في الموقع كله يبطئ الصفحات ولا حاجة إليه؛ فاقصره على الصفحات التي تخلط الأسرار بمدخلات المستخدم."),
   [_b("nginx", "gzip off;   # only in the location{} of pages that mix secrets with user input", "nginx")])

_s("S-HTML",
   ("Fix the page markup or script", "إصلاح كود الصفحة أو السكربت"),
   ("Change the markup or script named in the evidence: add rel=\"noopener\" to target=_blank links, send forms with "
    "POST to your own HTTPS origin, keep secrets out of URLs and treat location/postMessage data as untrusted.",
    "عدّل الكود أو السكربت المذكور في الدليل: أضف rel=\"noopener\" إلى روابط target=_blank، وأرسل النماذج بطريقة POST "
    "إلى موقعك عبر HTTPS، وأبعد الأسرار عن الروابط، وتعامل مع بيانات location وpostMessage على أنها غير موثوقة."),
   ("Test the page after the change: forms, sign-in and links to partner sites can depend on the old behaviour.",
    "اختبر الصفحة بعد التعديل، فالنماذج وتسجيل الدخول والروابط إلى المواقع الشريكة قد تعتمد على السلوك القديم."),
   [_b("any", '<a href="https://partner.example.net/" target="_blank" rel="noopener noreferrer">…</a>', "html")],
   prose=True)

_s("S-SECRET",
   ("Revoke and rotate the exposed secret", "إبطال السرّ المكشوف واستبداله"),
   ("Revoke the secret at its provider and issue a new one first, then move it server-side so it never reaches the "
    "browser again, and check the provider's logs for misuse.",
    "أبطل السرّ لدى مزوده وأصدر سرًّا جديدًا أولًا، ثم انقله إلى الخادم حتى لا يصل إلى المتصفح مرة أخرى، وراجع سجلات "
    "المزود بحثًا عن أي استخدام مسيء."),
   ("Removing the secret from the page is not enough: it is already public and cached, so it must be revoked.",
    "حذف السرّ من الصفحة لا يكفي، فقد صار علنيًا ومخزّنًا في ذاكرات مؤقتة، ولا بد من إبطاله."),
   [_b("any", note=("Use the provider's key-management page to revoke the key; for payment card data, follow your PCI DSS "
                   "incident process.",
                   "استخدم صفحة إدارة المفاتيح لدى المزود لإبطال المفتاح؛ أما بيانات بطاقات الدفع فاتبع فيها إجراءات "
                   "الحوادث الخاصة بمعيار PCI DSS."))],
   prose=True)

_s("S-ADMIN",
   ("Restrict admin and login pages", "تقييد صفحات الإدارة والدخول"),
   ("Allow admin paths only from your network or VPN, or protect them with strong authentication, MFA and rate "
    "limiting.",
    "اسمح بمسارات الإدارة من شبكتك أو عبر VPN فقط، أو احمها بمصادقة قوية وتحقق متعدد العوامل وتحديد لعدد المحاولات."),
   ("Make sure you keep a way in (a VPN or an allowed address) before restricting the admin path, or you lock yourself "
    "out.",
    "تأكد من بقاء طريق للوصول (VPN أو عنوان مسموح) قبل تقييد مسار الإدارة، حتى لا تُغلق الباب على نفسك."),
   [
       _b("nginx", "location /admin/ { allow 203.0.113.0/24; deny all; }", "nginx"),
       _b("apache", '<Location "/admin/">\n    Require ip 203.0.113.0/24\n</Location>', "apache"),
   ],
   prose=True)

_s("S-TAKEOVER",
   ("Remove the dangling DNS record", "حذف سجل DNS المعلّق"),
   ("Delete the CNAME (or other record) that points to the unclaimed provider resource, or claim the resource again "
    "at the provider, today.",
    "احذف سجل CNAME (أو أي سجل آخر) الذي يشير إلى مورد غير مُطالَب به لدى المزود، أو استعد المورد لدى المزود، اليوم."),
   ("Check the subdomain's content and cookies after reclaiming it: someone may already have served pages from it.",
    "افحص محتوى النطاق الفرعي وكوكيزه بعد استعادته، فربما قدّم أحدهم صفحات منه بالفعل."),
   [_b("any", note=("Remove the record at your DNS provider, then confirm with your provider's DNS lookup tool.",
                   "احذف السجل لدى مزود DNS، ثم تحقّق بأداة الاستعلام لدى المزود."))],
   prose=True)

_s("S-INCIDENT",
   ("Incident response", "الاستجابة للحادث"),
   ("Treat the site as compromised: preserve a copy of the evidence, find and close the entry point, then remove the "
    "injected code (or restore a known-clean copy), rotate credentials and check the other pages.",
    "تعامل مع الموقع على أنه مخترق: احتفظ بنسخة من الأدلة، وابحث عن نقطة الاختراق وأغلقها، ثم أزل الكود المحقون (أو "
    "استعد نسخة نظيفة موثوقة)، وغيّر بيانات الاعتماد، وافحص بقية الصفحات."),
   ("Restoring a backup without closing the entry point lets the attacker return; patch first.",
    "استعادة نسخة احتياطية دون سد نقطة الدخول تسمح للمهاجم بالعودة، فأصلح الثغرة أولًا."),
   [_b("any", note=("Notify affected users and the authorities your law requires.",
                   "أبلغ المستخدمين المتأثرين والجهات التي يلزمك بها القانون."))],
   prose=True)


# =============================================================================================== API

def snippet(snippet_id: str) -> Snippet:
    return SNIPPETS[snippet_id]


def fix_ids_for(rule_ids: Iterable[str]) -> tuple[str, ...]:
    """The snippet ids of the given rules, in rule order, each once."""
    out: dict[str, None] = {}
    for rid in rule_ids:
        meta = RULES.get(rid)
        for sid in (meta.fix if meta else ()):
            out.setdefault(sid, None)
    return tuple(out)


def security_txt_expires(now: datetime | None = None) -> str:
    """``Expires`` for the S-SECTXT snippet: the scan date + 6 months, midnight UTC, RFC 3339 with milliseconds."""
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is not None:
        now = now.astimezone(timezone.utc)
    month = now.month + 6
    year = now.year + (month - 1) // 12
    month = (month - 1) % 12 + 1
    day = min(now.day, calendar.monthrange(year, month)[1])
    return f"{year:04d}-{month:02d}-{day:02d}T00:00:00.000Z"


def _registrable(host: str) -> str:
    try:
        from .psl import registrable_domain
        return registrable_domain(host) or host
    except Exception:   # a PSL problem must never break a report
        return host


def _host_of(host: Any) -> str:
    """The host name of a URL, a ``host:port`` or a bare host ("" when it cannot be parsed)."""
    h = host.strip() if isinstance(host, str) else ""
    if not h:
        return ""
    import urllib.parse
    try:
        if "://" in h:
            return urllib.parse.urlsplit(h).hostname or ""
        if h.count(":") > 1 and not h.startswith("["):      # a bare IPv6 literal
            return h
        return urllib.parse.urlsplit("//" + h).hostname or ""
    except ValueError:      # "http://[::1", "a]b": a malformed URL is no host name
        return ""


def placeholders(host: str | None = None, now: datetime | None = None) -> dict[str, str]:
    """Token values for :func:`fill`. ``host`` may be a URL, a ``host:port`` or a bare host name; without one (or for
    anything that is not a plain host name) the values read ``example.com``."""
    h = _host_of(host).strip("[]").rstrip(".").lower()
    if h and not h.isascii():
        try:
            h = h.encode("idna").decode("ascii")
        except UnicodeError:
            h = ""
    if not _HOST_OK.fullmatch(h):   # copy-paste config must never carry text from the target other than a host name
        h = "example.com"
    if ":" in h:   # IPv6 literal
        h = f"[{h}]"
    domain = h if h.startswith("[") else _registrable(h)
    is_ip = h.startswith("[") or bool(re.fullmatch(r"[0-9.]+", h))
    names = f"{domain} www.{domain}" if h in (domain, "www." + domain) and "." in domain and not is_ip else h
    return {"host": h, "domain": domain, "domain_re": re.escape(domain), "names": names,
            "expires": security_txt_expires(now)}


def fill(text: str, values: dict[str, str] | None = None) -> str:
    """Replace the exact tokens ``{host}``, ``{domain}``, ``{domain_re}`` (the domain escaped for a regular
    expression), ``{names}`` and ``{expires}``; nothing else is interpreted."""
    vals = values or placeholders()
    return _TOKEN_RX.sub(lambda m: vals.get(m.group(1), m.group(0)), text)


def header_lines(snippet_id: str, *, host: str | None = None, now: datetime | None = None,
                 where: str | None = None) -> list[tuple[str, str]]:
    """The recommended header lines of a snippet with placeholders filled (``where`` filters by response kind)."""
    vals = placeholders(host, now)
    return [(h.name, fill(h.value, vals)) for h in SNIPPETS[snippet_id].headers if where is None or h.where == where]


# -- platform detection and ordering --------------------------------------------------------------------------------

def _header_items(headers: Any) -> list[tuple[str, str]]:
    if headers is None or isinstance(headers, (str, bytes)):
        return []
    items = getattr(headers, "items", None)
    if isinstance(items, tuple):                      # types.HeaderList
        pairs: Iterable[Any] = items
    elif isinstance(headers, dict):
        pairs = headers.items()
    else:
        pairs = headers
    out = []
    for pair in pairs:
        if isinstance(pair, (tuple, list)) and len(pair) == 2 and isinstance(pair[0], str) and isinstance(pair[1], str):
            out.append((pair[0], pair[1]))
    return out


# inventory entries (tech.py) below this confidence are not "detected on this site" (exposure.py uses the same bar)
MIN_TECH_CONFIDENCE = 50


def _tech_ids(technologies: Any) -> list[str]:
    out = []
    if isinstance(technologies, str):
        technologies = (technologies,)
    for t in technologies or ():
        if isinstance(t, str):
            out.append(t)
        elif isinstance(t, dict):
            conf = t.get("confidence", 100)
            if isinstance(conf, (int, float)) and conf < MIN_TECH_CONFIDENCE:
                continue
            out.append(str(t.get("id") or t.get("product") or t.get("name") or ""))
        elif t is not None:
            conf = getattr(t, "confidence", 100)
            if isinstance(conf, (int, float)) and conf < MIN_TECH_CONFIDENCE:
                continue
            out.append(str(getattr(t, "id", "") or getattr(getattr(t, "tech", None), "id", "")))
    return [t.strip().lower() for t in out if t]


def detect_platforms(technologies: Any = (), headers: Any = None) -> tuple[str, ...]:
    """Snippet platforms detected for a site, strongest evidence first.

    ``technologies``: tech ids (``"nginx"``), the inventory dicts of ``ctx.inventory["technologies"]`` or
    ``tech.Detected`` objects. ``headers``: a ``HeaderList``, a dict or ``(name, value)`` pairs of the site's responses
    (``Server``, ``X-Powered-By``, ``X-AspNet-Version``, ``cf-ray``)."""
    found: dict[str, None] = {}
    for name, value in _header_items(headers):
        lname = name.strip().lower()
        for hname, rx, plats in HEADER_PLATFORMS:
            if lname == hname and re.search(rx, value or "", re.I):
                for p in plats:
                    found.setdefault(p, None)
                break
    for tid in _tech_ids(technologies):
        for p in TECH_PLATFORMS.get(tid, ()):
            found.setdefault(p, None)
    return tuple(found)


def platforms_from_context(ctx: Any) -> tuple[str, ...]:
    """:func:`detect_platforms` over a ``ScanContext``: the technology inventory and the headers of the entry chain."""
    techs = list((getattr(ctx, "inventory", None) or {}).get("technologies") or ())
    pairs: list[tuple[str, str]] = []
    entry = getattr(ctx, "entry", None)
    responses = []
    if entry is not None:
        hops = getattr(entry, "hops", None)
        responses = list(hops()) if callable(hops) else [entry]
    for p in getattr(ctx, "pages", ()) or ():
        responses.append(p.response)
    for r in responses:
        for name in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "cf-ray"):
            for v in r.headers.get_all(name):
                pairs.append((name, v))
    return detect_platforms(techs, pairs)


def ordered_blocks(snippet_id: str, detected: Iterable[str] = ()) -> tuple[list[Block], list[Block]]:
    """``(shown, collapsed)``: generic blocks and the detected platforms' blocks (in detection order), then the rest
    in the default platform order."""
    sn = SNIPPETS[snippet_id]
    det = [p for p in dict.fromkeys(detected) if p in PLATFORMS and p != "any"]
    rank = {p: i for i, p in enumerate(PLATFORMS)}
    shown = [b for b in sn.blocks if b.platform == "any"]
    for p in det:
        shown += [b for b in sn.blocks if b.platform == p]
    rest = sorted((b for b in sn.blocks if b.platform != "any" and b.platform not in det),
                  key=lambda b: rank.get(b.platform, len(rank)))
    return shown, rest


def _block_dict(b: Block, lang: str, vals: dict[str, str]) -> dict:
    name = PLATFORMS.get(b.platform, (b.platform, b.platform))
    label = b.label(lang) or (name[1] if lang == "ar" else name[0])
    return {"platform": b.platform, "name": label, "lang": b.lang, "code": fill(b.code, vals), "note": b.note(lang)}


def render(snippet_id: str, lang: str = "en", *, host: str | None = None, now: datetime | None = None,
           detected: Iterable[str] = (), values: dict[str, str] | None = None) -> dict:
    """A snippet ready for a report: title, summary, caveat, filled header lines and the blocks split into
    ``detected`` (shown) and ``other`` (collapsed). ``values`` overrides placeholder values (docs use it)."""
    lang = "ar" if lang == "ar" else "en"
    sn = SNIPPETS[snippet_id]
    vals = {**placeholders(host, now), **(values or {})}
    shown, rest = ordered_blocks(snippet_id, detected)
    return {"id": sn.id, "title": sn.title(lang), "summary": sn.summary(lang), "caveat": sn.caveat(lang),
            "caveat_label": STR["caution"][1 if lang == "ar" else 0], "prose": sn.prose,
            "headers": [f"{h.name}: {fill(h.value, vals)}" for h in sn.headers],
            "detected": [_block_dict(b, lang, vals) for b in shown],
            "other": [_block_dict(b, lang, vals) for b in rest]}


def for_rules(rule_ids: Iterable[str], lang: str = "en", *, host: str | None = None, now: datetime | None = None,
              detected: Iterable[str] = ()) -> list[dict]:
    """:func:`render` for every snippet the given rules name (each snippet once, in rule order)."""
    det = tuple(detected)
    return [render(sid, lang, host=host, now=now, detected=det) for sid in fix_ids_for(rule_ids) if sid in SNIPPETS]


def to_markdown(snippet_id: str, lang: str = "en", *, host: str | None = None, now: datetime | None = None,
                detected: Iterable[str] = (), heading: str = "###", values: dict[str, str] | None = None) -> str:
    """Markdown for one snippet (reports, docs): code fences per platform, generic blocks first."""
    detected = tuple(detected)
    d = render(snippet_id, lang, host=host, now=now, detected=detected, values=values)
    i = 1 if lang == "ar" else 0
    out = [f"{heading} {d['id']} · {d['title']}", "", d["summary"], "", f"**{d['caveat_label']}:** {d['caveat']}", ""]

    def emit(blocks: list[dict]) -> None:
        for b in blocks:
            out.append(f"**{b['name']}**")
            out.append("")
            if b["code"]:
                fence = "````" if "```" in b["code"] else "```"
                out.extend([fence + b["lang"], b["code"], fence, ""])
            if b["note"]:
                out.extend([b["note"], ""])

    emit(d["detected"])
    if d["other"]:
        if d["detected"] and detected:
            out += [f"*{STR['other'][i]}*", ""]
        emit(d["other"])
    return "\n".join(out).rstrip() + "\n"


# -- i18n -----------------------------------------------------------------------------------------------------------

def texts() -> list[tuple[str, str]]:
    """Every (English, Arabic) pair of this module (titles, summaries, caveats, notes, platform names, labels)."""
    pairs: list[tuple[str, str]] = []
    for sn in SNIPPETS.values():
        pairs += [(sn.title_en, sn.title_ar), (sn.summary_en, sn.summary_ar), (sn.caveat_en, sn.caveat_ar)]
        pairs += [(b.note_en, b.note_ar) for b in sn.blocks if b.note_en or b.note_ar]
        pairs += [(b.label_en, b.label_ar) for b in sn.blocks if b.label_en or b.label_ar]
    pairs += [(en, ar) for en, ar in PLATFORMS.values()]
    pairs += list(STR.values())
    return pairs


def i18n_catalog() -> tuple[dict[str, str], list[tuple[str, str]]]:
    """``(CATALOG, PATTERNS)`` for ``vulnscan/i18n/cat_web2.py``: Arabic → English for every text of this module."""
    catalog: dict[str, str] = {}
    for en, ar in texts():
        if _ARABIC.search(ar):
            catalog.setdefault(re.sub(r"\s+", " ", ar).strip(), en)
    return catalog, []


__all__ = ["PLATFORMS", "TECH_PLATFORMS", "HEADER_PLATFORMS", "STR", "TOKENS", "Block", "Header", "Snippet", "SNIPPETS",
           "snippet", "fix_ids_for", "security_txt_expires", "placeholders", "fill", "header_lines", "header_blocks",
           "detect_platforms", "platforms_from_context", "ordered_blocks", "render", "for_rules", "to_markdown", "texts",
           "i18n_catalog"]
