"""Build the bundled technology signatures (maintainers only; needs the network unless --from is given).

    python tools/webdata/tech.py                         # Kashif's own signatures + nuclei tech-detect (main)
    python tools/webdata/tech.py --from tech-detect.yaml # a local copy of http/technologies/tech-detect.yaml
    python tools/webdata/tech.py --own-only              # Kashif's own signatures only

Writes ``vulnscan/data/web/tech.json`` (spec §2.9 WEB080/WEB081, §2.10 platform deep paths). Two sources:

* ``OWN`` below: Kashif's original signatures (the seven 1.0.1 PLATFORMS entries — Moodle, Oracle APEX, WordPress,
  Joomla, Drupal, phpMyAdmin, Laravel — with their deep paths, plus CMSs, frameworks, servers, CDNs and libraries).
* nuclei-templates ``http/technologies/tech-detect.yaml`` (MIT; NOTICE carries the attribution), filtered to *scoped*
  matchers only (spec: never free page prose): body regexes that start with markup (``<``), ``Header: value`` and
  ``Set-Cookie: name=`` words, and Server-header words. Word matchers on page text and ``and``-combined matchers are
  dropped. Wappalyzer/WhatWeb data (GPL) is **not** used.

Signal semantics (read by ``webscan/tech.py``): ``header`` = regex on the values of the header ``name``; ``cookie`` =
regex on cookie names; ``meta`` = regex on the content of ``<meta name|property=name>``; ``script`` / ``link`` =
regex on absolute ``<script src>`` / ``<link href>`` URLs; ``html`` = regex on the raw HTML (markup-anchored patterns
only); ``url`` = regex on the page URL. ``confidence`` adds up per technology (capped at 100); ``version`` is a
``\\1``-style template. Deep paths: WEB082 (sensitive file, strong signature) / WEB083 (admin or login page, weak
signature + the soft-404 similarity test) for exposure.py (WP11); a path is in exactly one data file (paths already in
exposed-paths.json — ``/.env``, ``/telescope``, ``/storage/logs/laravel.log``, ``/wp-config.php.bak`` — are not repeated).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "vulnscan" / "data" / "web"
OUT_NAME = "tech.json"
RAW = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/{ref}/http/technologies/tech-detect.yaml"
SOURCE = "Kashif original signatures + projectdiscovery/nuclei-templates http/technologies/tech-detect.yaml (scoped matchers)"
LICENSE = "Kashif (project licence) + MIT (nuclei-templates)"
V = r"(\d+(?:\.\d+)+)"            # a dotted version
VO = r"(\d+(?:\.\d+)*)?"          # an optional version (major alone allowed)


def S(source: str, pattern: str, conf: int, *, name: str = "", version: str = "", flags: str = "") -> dict:
    sig: dict = {"source": source, "pattern": pattern, "confidence": conf}
    if name:
        sig["name"] = name
    if version:
        sig["version"] = version
    if flags:
        sig["flags"] = flags
    return sig


def gen(pattern: str, conf: int = 100, version: str = "\\1") -> dict:
    """A ``<meta name=generator>`` signal."""
    return S("meta", pattern, conf, name="generator", version=version if "(" in pattern else "", flags="i")


def T(tid: str, name: str, cats: list[str], signals: list[dict], *, cpe: str = "", implies: tuple = (),
      excludes: tuple = (), eol: str = "", website: str = "", deep: list[dict] | None = None) -> dict:
    t: dict = {"id": tid, "name": name, "categories": cats, "signals": signals}
    if website:
        t["website"] = website
    if cpe:
        t["cpe"] = cpe
    if implies:
        t["implies"] = list(implies)
    if excludes:
        t["excludes"] = list(excludes)
    if eol:
        t["eol_product"] = eol
    if deep:
        t["deep_paths"] = deep
    return t


def _sig(kind: str, pattern: str, **kw) -> dict:
    return {"type": kind, "pattern": pattern, **kw}


def admin(path: str, platform: str, markers: list[str], *, kinds=("document",)) -> dict:
    """A WEB083 deep path: a login/admin page (weak signature; exposure.py also wants a live password field or a
    marker and applies the soft-404 similarity test)."""
    return {"path": path, "rule": "WEB083", "severity": "info", "cwe": "CWE-284", "kinds": list(kinds),
            "signature": {"any": [_sig("regex", m, flags="i") for m in markers]}, "strength": "weak",
            "title_en": f"{platform} admin or login page reachable: {path}",
            "title_ar": f"صفحة إدارة أو دخول لـ {platform} متاحة: {path}",
            "advice_en": "Restrict the admin or login page (internal network, VPN, or strong authentication with rate "
                         "limiting and MFA).",
            "advice_ar": "قيّد الوصول إلى صفحة الإدارة أو الدخول (شبكة داخلية أو VPN أو مصادقة قوية مع تحديد عدد "
                         "المحاولات والتحقق متعدد العوامل)."}


def sensitive(path: str, platform: str, signature: dict, *, cwe: str = "CWE-538", strength: str = "strong",
              kinds=("text", "download", "other"), what_en: str = "", what_ar: str = "") -> dict:
    """A WEB082 deep path: a platform file that should not be public."""
    adv_en = "Block access to this file at the web server and remove it from the web root; rotate any secret it contained."
    adv_ar = "امنع الوصول إلى هذا الملف من خادم الويب واحذفه من جذر الموقع، وغيّر أي سرّ كان فيه."
    if what_en:
        adv_en = f"{what_en} {adv_en}"
        adv_ar = f"{what_ar} {adv_ar}"
    return {"path": path, "rule": "WEB082", "severity": "high", "cwe": cwe, "kinds": list(kinds), "signature": signature,
            "strength": strength, "title_en": f"{platform} sensitive file exposed: {path}",
            "title_ar": f"ملف حساس لـ {platform} مكشوف: {path}", "advice_en": adv_en, "advice_ar": adv_ar}


PASSWORD = r"<input[^>]+type=[\"']?password"

# ----------------------------------------------------------------------------------------------- own signatures
OWN: list[dict] = [
    # ---- the seven 1.0.1 platforms (deep paths kept, now signature-gated)
    T("moodle", "Moodle", ["lms"], [
        S("cookie", r"^MoodleSession", 80),
        S("link", r"/theme/(?:styles|yui_combo|image)\.php", 60),
        S("script", r"/lib/javascript\.php/|/theme/yui_combo\.php|/lib/requirejs\.php/", 60),
        S("html", r"<(?:img|link|a)\b[^>]+/pluginfile\.php/", 40),
        S("meta", r"^moodle\b", 50, name="keywords", flags="i"),
    ], cpe="cpe:2.3:a:moodle:moodle", implies=("php",), eol="moodle", website="https://moodle.org",
        deep=[admin("/login/index.php", "Moodle", [r"MoodleSession|moodle", PASSWORD]),
              admin("/admin/", "Moodle", [r"moodle", PASSWORD]),
              sensitive("/config-dist.php", "Moodle", {"all": [_sig("regex", r"\$CFG->(?:dbtype|dbhost|wwwroot)")]},
                        cwe="CWE-530", what_en="The Moodle configuration template is served as source code.",
                        what_ar="قالب إعدادات Moodle يُقدَّم كشيفرة مصدرية.")]),
    T("oracle-apex", "Oracle APEX", ["low-code"], [
        S("script", r"/i/(?:libraries/apex/|apex_)|/apex_[a-z_]+(?:\.min)?\.js", 60),
        S("script", r"/i/libraries/apex/[^?#]*\?v=" + V, 30, version="\\1"),
        S("html", r"<form\b[^>]+name=[\"']wwv_flow[\"']", 80),
        S("html", r"<input\b[^>]+name=[\"']p_flow_id[\"']", 80),
        S("url", r"/(?:ords|pls/apex)/[^?]*\bf\?p=", 30),
    ], cpe="cpe:2.3:a:oracle:application_express", website="https://apex.oracle.com",
        deep=[admin("/ords/", "Oracle APEX", [r"wwv_flow|apex", PASSWORD]),
              admin("/apex/", "Oracle APEX", [r"wwv_flow|apex", PASSWORD]),
              admin("/pls/apex/", "Oracle APEX", [r"wwv_flow|apex", PASSWORD]),
              admin("/i/", "Oracle APEX", [r"<title>Index of /i", r"apex_"], kinds=("document",))]),
    T("wordpress", "WordPress", ["cms", "blog"], [
        gen(r"^WordPress\s*" + VO),
        S("link", r"/wp-content/(?:themes|plugins|uploads)/", 60),
        S("script", r"/wp-(?:content|includes)/", 60),
        S("link", r"/wp-includes/[^?#]*\?ver=" + V, 25, version="\\1"),
        S("script", r"/wp-includes/[^?#]*\?ver=" + V, 25, version="\\1"),
        S("html", r"<link\b[^>]+rel=[\"']https://api\.w\.org/[\"']", 70),
        S("header", r"rel=\"?https://api\.w\.org/", 80, name="link"),
        S("header", r"/xmlrpc\.php", 40, name="x-pingback"),
        S("cookie", r"^wordpress_(?:logged_in_[0-9a-f]+|test_cookie|sec_[0-9a-f]+)$|^wp-settings-", 60),
    ], cpe="cpe:2.3:a:wordpress:wordpress", implies=("php", "mysql"), eol="wordpress", website="https://wordpress.org",
        deep=[admin("/wp-login.php", "WordPress", [r"wp-submit|user_login|wp-login\.php", PASSWORD]),
              admin("/wp-admin/", "WordPress", [r"wp-submit|user_login|wp-login\.php", PASSWORD]),
              admin("/xmlrpc.php", "WordPress", [r"XML-RPC server accepts POST requests only"],
                    kinds=("document", "text", "other")),
              sensitive("/wp-content/debug.log", "WordPress",
                        {"any": [_sig("regex", r"PHP (?:Warning|Fatal error|Notice|Parse error|Deprecated)")],
                         "not_html": True}, cwe="CWE-532",
                        what_en="The WordPress debug log can contain paths, queries and secrets.",
                        what_ar="سجل أخطاء WordPress قد يحوي مسارات واستعلامات وأسرارًا.")]),
    T("joomla", "Joomla!", ["cms"], [
        gen(r"^Joomla!?(?:\s*-\s*Open Source Content Management)?(?:\s*-\s*Version\s*" + V + r")?"),
        S("header", r"Joomla!?\s*" + VO, 100, name="x-content-encoded-by", version="\\1"),
        S("script", r"/media/(?:jui|system|vendor|templates/site)/js/", 50),
        S("link", r"/media/(?:jui|system|templates/site)/css/", 40),
        S("html", r"<script\b[^>]+class=[\"']joomla-script-options", 80),
        S("html", r"<a\b[^>]+href=[\"'][^\"']*[?&](?:amp;)?option=com_[a-z]", 40),
    ], cpe="cpe:2.3:a:joomla:joomla\\!", implies=("php",), eol="joomla", website="https://www.joomla.org",
        deep=[admin("/administrator/", "Joomla!", [r"joomla|com_login|mod-login-username", PASSWORD]),
              sensitive("/configuration.php-dist", "Joomla!", {"all": [_sig("regex", r"class\s+JConfig")]},
                        cwe="CWE-530", what_en="The Joomla configuration template is served as source code.",
                        what_ar="قالب إعدادات Joomla يُقدَّم كشيفرة مصدرية."),
              sensitive("/README.txt", "Joomla!", {"all": [_sig("regex", r"Joomla!?.{0,40}\d+\.\d+", within=4096)],
                                                   "not_html": True},
                        cwe="CWE-200", what_en="The file reveals the exact Joomla version.",
                        what_ar="الملف يكشف إصدار Joomla بدقة.")]),
    T("drupal", "Drupal", ["cms"], [
        gen(r"^Drupal\s*" + VO),
        S("header", r"Drupal\s*" + VO, 100, name="x-generator", version="\\1"),
        S("header", r".", 80, name="x-drupal-cache"),
        S("header", r".", 80, name="x-drupal-dynamic-cache"),
        S("script", r"/(?:core/)?misc/drupal\.js", 70),
        S("link", r"/sites/(?:default|all)/(?:files|modules|themes)/", 40),
        S("script", r"/sites/(?:default|all)/(?:files|modules|themes)/", 40),
        S("html", r"<script\b[^>]+data-drupal-selector=[\"']drupal-settings-json", 90),
        S("html", r"<[a-z]+\b[^>]+data-drupal-(?:selector|link-system-path)=", 60),
        S("cookie", r"^S?SESS[0-9a-f]{32}$", 40),
    ], cpe="cpe:2.3:a:drupal:drupal", implies=("php",), eol="drupal", website="https://www.drupal.org",
        deep=[admin("/user/login", "Drupal", [r"user-login|drupal", PASSWORD]),
              admin("/admin", "Drupal", [r"user-login|drupal", PASSWORD]),
              sensitive("/CHANGELOG.txt", "Drupal", {"all": [_sig("regex", r"^\s*Drupal \d", within=512)],
                                                     "not_html": True},
                        cwe="CWE-200", what_en="The changelog reveals the exact Drupal version.",
                        what_ar="سجل التغييرات يكشف إصدار Drupal بدقة."),
              sensitive("/core/CHANGELOG.txt", "Drupal", {"all": [_sig("regex", r"^\s*Drupal \d", within=512)],
                                                          "not_html": True},
                        cwe="CWE-200", what_en="The changelog reveals the exact Drupal version.",
                        what_ar="سجل التغييرات يكشف إصدار Drupal بدقة.")]),
    T("phpmyadmin", "phpMyAdmin", ["database-admin"], [
        S("cookie", r"^(?:pma_lang|pma_collation_connection|phpMyAdmin(?:_https)?|pmaUser-\d+|pmaAuth-\d+)$", 80),
        S("link", r"/themes/(?:pmahomme|original|metro|bootstrap)/(?:css|jquery)/", 50),
        S("html", r"<title>phpMyAdmin\s*</title>", 60),
        S("html", r"<(?:div|form)\b[^>]+(?:id|class)=[\"'](?:pma_navigation|pma_console_container|login_form)[\"']", 50),
        S("script", r"/js/(?:vendor/)?jquery/jquery\.min\.js\?v=" + V, 20, version="\\1"),
    ], cpe="cpe:2.3:a:phpmyadmin:phpmyadmin", implies=("php",), website="https://www.phpmyadmin.net",
        deep=[admin(p, "phpMyAdmin", [r"phpMyAdmin|pma_", PASSWORD]) for p in ("/phpmyadmin/", "/pma/", "/phpMyAdmin/")]),
    T("laravel", "Laravel", ["web-framework"], [
        S("cookie", r"^laravel_session$", 75),
        S("header", r"Laravel", 80, name="x-powered-by"),
        S("script", r"/vendor/laravel/", 50),
    ], cpe="cpe:2.3:a:laravel:laravel", implies=("php",), eol="laravel", website="https://laravel.com"),
    # ---- other CMS / commerce / collaboration platforms
    T("magento", "Magento / Adobe Commerce", ["ecommerce"], [
        S("html", r"<script\b[^>]+type=[\"']text/x-magento-init[\"']", 90),
        S("cookie", r"^(?:X-Magento-Vary|mage-cache-sessid|mage-cache-storage|mage-messages)$", 80),
        S("header", r".", 80, name="x-magento-cache-debug"),
        S("header", r".", 70, name="x-magento-tags"),
        S("script", r"/static/(?:version\d+/)?frontend/[^/]+/[^/]+/", 50),
        S("script", r"/skin/frontend/|/js/mage/", 50),
    ], cpe="cpe:2.3:a:magento:magento", implies=("php",), eol="magento"),
    T("typo3", "TYPO3", ["cms"], [
        gen(r"^TYPO3\s*(?:CMS)?\s*" + VO),
        S("link", r"/typo3(?:conf|temp)/", 60), S("script", r"/typo3(?:conf|temp)/", 60),
        S("cookie", r"^(?:fe_typo_user|be_typo_user)$", 80),
    ], cpe="cpe:2.3:a:typo3:typo3", implies=("php",), eol="typo3"),
    T("prestashop", "PrestaShop", ["ecommerce"], [
        gen(r"^PrestaShop"), S("cookie", r"^PrestaShop-[0-9a-f]{32}$", 80),
        S("html", r"<script\b[^>]*>\s*var prestashop\s*=", 70),
    ], cpe="cpe:2.3:a:prestashop:prestashop", implies=("php",)),
    T("opencart", "OpenCart", ["ecommerce"], [
        S("link", r"/catalog/view/(?:theme|javascript)/", 60), S("script", r"/catalog/view/javascript/", 60),
        S("cookie", r"^OCSESSID$", 70),
    ], cpe="cpe:2.3:a:opencart:opencart", implies=("php",)),
    T("woocommerce", "WooCommerce", ["ecommerce"], [
        gen(r"^WooCommerce\s*" + VO), S("script", r"/wp-content/plugins/woocommerce/", 90),
        S("link", r"/wp-content/plugins/woocommerce/", 90),
    ], cpe="cpe:2.3:a:woocommerce:woocommerce", implies=("wordpress",)),
    T("shopify", "Shopify", ["ecommerce", "hosting"], [
        S("script", r"//cdn\.shopify\.com/|\.myshopify\.com/", 70), S("header", r".", 80, name="x-shopid"),
        S("header", r".", 80, name="x-shopify-stage"), S("cookie", r"^_shopify_(?:y|s|sa_t|sa_p)$", 60),
    ]),
    T("wix", "Wix", ["cms", "hosting"], [
        gen(r"^Wix\.com Website Builder"), S("header", r".", 80, name="x-wix-request-id"),
        S("script", r"static\.parastorage\.com", 60),
    ]),
    T("squarespace", "Squarespace", ["cms", "hosting"], [
        S("html", r"<!-- This is Squarespace\. -->", 90),
        S("script", r"(?:static1|assets)\.squarespace\.com", 60), S("link", r"(?:static1|assets)\.squarespace\.com", 60),
    ]),
    T("ghost", "Ghost", ["cms", "blog"], [gen(r"^Ghost\s*" + VO), S("cookie", r"^ghost-admin-api-session$", 80)],
      cpe="cpe:2.3:a:ghost:ghost", implies=("nodejs",)),
    T("mediawiki", "MediaWiki", ["wiki"], [
        gen(r"^MediaWiki\s*" + VO), S("link", r"/load\.php\?[^\"']*modules=", 50),
        S("html", r"<link\b[^>]+rel=[\"']EditURI[\"'][^>]+api\.php", 40),
    ], cpe="cpe:2.3:a:mediawiki:mediawiki", implies=("php",), eol="mediawiki"),
    T("phpbb", "phpBB", ["forum"], [
        S("cookie", r"^phpbb\d*_[a-z0-9]+_(?:sid|u|k)$", 80), S("link", r"/styles/prosilver/", 60),
    ], cpe="cpe:2.3:a:phpbb:phpbb", implies=("php",), eol="phpbb"),
    T("discourse", "Discourse", ["forum"], [gen(r"^Discourse\s*" + VO)], implies=("ruby-on-rails",)),
    T("nextcloud", "Nextcloud", ["collaboration"], [
        S("html", r"<head\b[^>]+data-requesttoken=", 50), S("html", r"<title>[^<]*Nextcloud\s*</title>", 50),
        S("header", r".", 70, name="x-nextcloud-well-known"),
    ], cpe="cpe:2.3:a:nextcloud:nextcloud_server", implies=("php",), eol="nextcloud"),
    T("gitlab", "GitLab", ["devops"], [
        S("meta", r"^GitLab$", 90, name="og:site_name"), S("cookie", r"^_gitlab_session$", 90),
        S("header", r".", 60, name="x-gitlab-meta"),
    ], cpe="cpe:2.3:a:gitlab:gitlab", eol="gitlab", implies=("ruby-on-rails",)),
    T("jenkins", "Jenkins", ["ci"], [
        S("header", V, 100, name="x-jenkins", version="\\1"), S("header", r".", 80, name="x-hudson"),
    ], cpe="cpe:2.3:a:jenkins:jenkins", implies=("java",)),
    T("grafana", "Grafana", ["monitoring"], [
        S("cookie", r"^grafana_session", 90), S("html", r"<title>Grafana\s*</title>", 50),
    ], cpe="cpe:2.3:a:grafana:grafana"),
    T("kibana", "Kibana", ["monitoring"], [
        S("header", r".", 90, name="kbn-name"), S("header", V, 100, name="kbn-version", version="\\1"),
        S("html", r"<title>Kibana\s*</title>", 50),
    ], cpe="cpe:2.3:a:elastic:kibana"),
    T("confluence", "Atlassian Confluence", ["collaboration", "wiki"], [
        S("header", r".", 90, name="x-confluence-request-time"),
        S("meta", r"^" + V + r"$", 60, name="ajs-version-number", version="\\1"),
        S("meta", r".", 70, name="confluence-request-time"),
    ], cpe="cpe:2.3:a:atlassian:confluence_server", eol="confluence", implies=("java",)),
    T("jira", "Atlassian Jira", ["collaboration"], [
        S("meta", r"^JIRA$", 90, name="application-name", flags="i"),
        S("cookie", r"^atlassian\.xsrf\.token$", 40),
    ], cpe="cpe:2.3:a:atlassian:jira", eol="jira-software", implies=("java",)),
    T("sharepoint", "Microsoft SharePoint", ["collaboration", "cms"], [
        S("header", VO, 100, name="microsoftsharepointteamservices", version="\\1"),
        S("header", r".", 80, name="sprequestguid"),
    ], cpe="cpe:2.3:a:microsoft:sharepoint_server", implies=("aspnet", "iis")),
    T("aem", "Adobe Experience Manager", ["cms"], [
        S("script", r"/etc\.clientlibs/", 60), S("link", r"/etc\.clientlibs/", 60),
        S("html", r"<[a-z]+\b[^>]+(?:src|href)=[\"']/content/dam/", 30),
    ], cpe="cpe:2.3:a:adobe:experience_manager", implies=("java",)),
    T("sitecore", "Sitecore", ["cms"], [
        S("cookie", r"^SC_ANALYTICS_GLOBAL_COOKIE$", 80), S("html", r"<[a-z]+\b[^>]+(?:src|href)=[\"']/-/media/", 30),
    ], cpe="cpe:2.3:a:sitecore:experience_platform", implies=("aspnet",)),
    T("umbraco", "Umbraco", ["cms"], [
        S("header", VO, 100, name="x-umbraco-version", version="\\1"),
        S("script", r"/umbraco/", 40),
    ], cpe="cpe:2.3:a:umbraco:umbraco_cms", eol="umbraco", implies=("aspnet",)),
    T("craft-cms", "Craft CMS", ["cms"], [
        S("header", r"Craft CMS", 100, name="x-powered-by"), S("cookie", r"^CraftSessionId$", 90),
    ], cpe="cpe:2.3:a:craftcms:craft_cms", eol="craft-cms", implies=("php",)),
    T("liferay", "Liferay", ["cms", "portal"], [
        S("header", r"Liferay[^\d]*" + VO, 100, name="liferay-portal", version="\\1"),
        S("html", r"<script\b[^>]*>[^<]{0,200}Liferay\.(?:currentURL|ThemeDisplay|Portlet)", 60),
    ], cpe="cpe:2.3:a:liferay:liferay_portal", implies=("java",)),
    T("dotnetnuke", "DNN Platform", ["cms"], [
        S("cookie", r"^(?:dnn_IsMobile|\.DOTNETNUKE|DotNetNukeAnonymous)$", 80),
        S("html", r"<!--\*+\s*DNN Platform", 80),
    ], cpe="cpe:2.3:a:dnnsoftware:dotnetnuke", implies=("aspnet",)),
    T("roundcube", "Roundcube Webmail", ["webmail"], [
        S("cookie", r"^roundcube_sessid$", 90), S("html", r"<title>[^<]*Roundcube Webmail\s*</title>", 70),
    ], cpe="cpe:2.3:a:roundcube:webmail", implies=("php",)),
    T("outlook-web-app", "Outlook Web App", ["webmail"], [
        S("header", V, 100, name="x-owa-version", version="\\1"), S("url", r"/owa/(?:auth/)?", 40),
    ], cpe="cpe:2.3:a:microsoft:exchange_server", implies=("iis", "aspnet")),
    T("cpanel", "cPanel", ["admin-panel"], [S("cookie", r"^(?:cprelogin|cpsession|whostmgrrelogin)$", 90)]),
    T("plesk", "Plesk", ["admin-panel"], [S("header", r"^Plesk(?:Lin|Win)", 100, name="x-powered-by")]),
    T("webmin", "Webmin", ["admin-panel"], [S("header", r"^MiniServ/?" + VO, 100, name="server", version="\\1")]),
    # ---- frameworks
    T("django", "Django", ["web-framework"], [
        S("html", r"<input\b[^>]+name=[\"']csrfmiddlewaretoken[\"']", 80),
        S("cookie", r"^django_language$", 60), S("cookie", r"^csrftoken$", 30),
    ], cpe="cpe:2.3:a:djangoproject:django", implies=("python",), eol="django"),
    T("ruby-on-rails", "Ruby on Rails", ["web-framework"], [
        S("html", r"<meta\b[^>]+name=[\"']csrf-param[\"'][^>]+content=[\"']authenticity_token[\"']", 80),
        S("header", r"^\d+\.\d+$", 20, name="x-runtime"),
    ], cpe="cpe:2.3:a:rubyonrails:rails", implies=("ruby",), eol="ruby-on-rails"),
    T("symfony", "Symfony", ["web-framework"], [
        S("header", r".", 70, name="x-debug-token"), S("cookie", r"^symfony$", 60),
    ], cpe="cpe:2.3:a:sensiolabs:symfony", implies=("php",), eol="symfony"),
    T("spring-boot", "Spring Boot", ["web-framework"], [
        S("html", r"<h1>Whitelabel Error Page</h1>", 90), S("header", r".", 60, name="x-application-context"),
    ], cpe="cpe:2.3:a:vmware:spring_boot", implies=("java",), eol="spring-boot"),
    T("aspnet", "ASP.NET", ["web-framework"], [
        S("header", V, 100, name="x-aspnet-version", version="\\1"),
        S("header", r"^ASP\.NET$", 90, name="x-powered-by"),
        S("cookie", r"^(?:ASP\.NET_SessionId|\.ASPXAUTH|\.AspNetCore\.[A-Za-z.]+)$", 80),
        S("html", r"<input\b[^>]+name=[\"']__VIEWSTATE[\"']", 90),
    ], cpe="cpe:2.3:a:microsoft:asp.net"),
    T("aspnet-mvc", "ASP.NET MVC", ["web-framework"], [S("header", V, 100, name="x-aspnetmvc-version", version="\\1")],
      implies=("aspnet",)),
    T("express", "Express", ["web-framework"], [S("header", r"^Express$", 100, name="x-powered-by")],
      cpe="cpe:2.3:a:expressjs:express", implies=("nodejs",)),
    T("nextjs", "Next.js", ["web-framework"], [
        S("header", r"^Next\.js\s*" + VO, 100, name="x-powered-by", version="\\1"),
        S("script", r"/_next/static/", 80), S("html", r"<script\b[^>]+id=[\"']__NEXT_DATA__[\"']", 90),
    ], cpe="cpe:2.3:a:vercel:next.js", implies=("react", "nodejs"), eol="nextjs"),
    T("nuxt", "Nuxt", ["web-framework"], [
        S("script", r"/_nuxt/", 70), S("html", r"<div\b[^>]+id=[\"']__nuxt[\"']", 80),
        S("html", r"<script\b[^>]*>\s*window\.__NUXT__", 80),
    ], implies=("vue",)),
    T("gatsby", "Gatsby", ["static-site-generator"], [gen(r"^Gatsby\s*" + VO)], implies=("react",)),
    T("hugo", "Hugo", ["static-site-generator"], [gen(r"^Hugo\s*" + VO)]),
    T("jekyll", "Jekyll", ["static-site-generator"], [gen(r"^Jekyll\s*v?" + VO)]),
    T("elementor", "Elementor", ["page-builder"], [gen(r"^Elementor\s*" + VO)], implies=("wordpress",)),
    # ---- languages and runtimes (inventory; WEB800/WEB801 come from the banner parser)
    T("php", "PHP", ["language"], [
        S("header", r"\bPHP/?" + VO, 100, name="x-powered-by", version="\\1"),
        S("header", r"\bPHP/" + V, 100, name="server", version="\\1"),
        S("cookie", r"^PHPSESSID$", 60),
    ], cpe="cpe:2.3:a:php:php", eol="php"),
    T("python", "Python", ["language"], [S("header", r"\b(?:C?Python)/" + V, 100, name="server", version="\\1")],
      cpe="cpe:2.3:a:python:python", eol="python"),
    T("ruby", "Ruby", ["language"], [S("header", r"\bRuby/" + V, 100, name="server", version="\\1")]),
    T("java", "Java", ["language"], [S("cookie", r"^JSESSIONID$", 60)]),
    T("nodejs", "Node.js", ["language"], [S("header", r"^(?:NodeJS|Node\.js)", 80, name="server")], eol="nodejs"),
    T("mysql", "MySQL", ["database"], []),
    # ---- web servers, proxies, CDNs, WAFs (inventory)
    T("apache-http-server", "Apache HTTP Server", ["web-server"],
      [S("header", r"^Apache(?:/" + V + r")?(?![-\w])", 100, name="server", version="\\1")],
      cpe="cpe:2.3:a:apache:http_server", eol="apache-http-server"),
    T("nginx", "nginx", ["web-server"], [S("header", r"^nginx(?:/" + V + r")?", 100, name="server", version="\\1")],
      cpe="cpe:2.3:a:f5:nginx", eol="nginx"),
    T("iis", "Microsoft IIS", ["web-server"],
      [S("header", r"^Microsoft-IIS(?:/" + V + r")?", 100, name="server", version="\\1")],
      cpe="cpe:2.3:a:microsoft:internet_information_services", eol="iis"),
    T("litespeed", "LiteSpeed", ["web-server"], [S("header", r"^LiteSpeed", 100, name="server")]),
    T("openresty", "OpenResty", ["web-server"], [S("header", r"^openresty(?:/" + V + r")?", 100, name="server",
                                                        version="\\1")], implies=("nginx",)),
    T("caddy", "Caddy", ["web-server"], [S("header", r"^Caddy", 100, name="server")]),
    T("tomcat", "Apache Tomcat", ["web-server"], [
        S("header", r"^Apache-Coyote/", 60, name="server"),
        S("html", r"<h3>Apache Tomcat/" + V, 100, version="\\1"),
    ], cpe="cpe:2.3:a:apache:tomcat", eol="tomcat", implies=("java",)),
    T("jetty", "Eclipse Jetty", ["web-server"], [S("header", r"^Jetty\((\d+(?:\.\d+)+)", 100, name="server",
                                                      version="\\1")], eol="eclipse-jetty", implies=("java",)),
    T("gunicorn", "Gunicorn", ["web-server"], [S("header", r"^gunicorn(?:/" + V + r")?", 100, name="server",
                                                    version="\\1")], implies=("python",)),
    T("werkzeug", "Werkzeug", ["web-server"], [S("header", r"^Werkzeug(?:/" + V + r")?", 100, name="server",
                                                    version="\\1")], implies=("python",)),
    T("kestrel", "Kestrel", ["web-server"], [S("header", r"^Kestrel", 100, name="server")], implies=("aspnet",)),
    T("lighttpd", "lighttpd", ["web-server"], [S("header", r"^lighttpd(?:/" + V + r")?", 100, name="server",
                                                    version="\\1")], cpe="cpe:2.3:a:lighttpd:lighttpd"),
    T("envoy", "Envoy", ["proxy"], [S("header", r"^(?:istio-)?envoy", 100, name="server")]),
    T("varnish", "Varnish", ["cache"], [S("header", r".", 70, name="x-varnish"),
                                        S("header", r"\bvarnish\b", 70, name="via", flags="i")]),
    T("cloudflare", "Cloudflare", ["cdn", "waf"], [S("header", r"^cloudflare$", 100, name="server", flags="i"),
                                                  S("header", r".", 90, name="cf-ray")]),
    T("akamai", "Akamai", ["cdn"], [S("header", r"^AkamaiGHost", 100, name="server"),
                                    S("header", r".", 80, name="x-akamai-transformed")]),
    T("fastly", "Fastly", ["cdn"], [S("header", r".", 60, name="fastly-debug-digest"),
                                    S("header", r"^cache-[a-z0-9-]+", 60, name="x-served-by")]),
    T("amazon-cloudfront", "Amazon CloudFront", ["cdn"], [S("header", r".", 90, name="x-amz-cf-id"),
                                                          S("header", r"CloudFront", 80, name="via")]),
    T("sucuri", "Sucuri", ["waf"], [S("header", r".", 90, name="x-sucuri-id")]),
    T("imperva", "Imperva", ["waf"], [S("header", r".", 80, name="x-iinfo"), S("cookie", r"^incap_ses_", 80)]),
    T("f5-big-ip", "F5 BIG-IP", ["load-balancer"], [S("cookie", r"^BIGipServer", 90),
                                                   S("header", r"^BigIP", 80, name="server")]),
    # ---- front-end libraries and services (inventory; vulnerable versions are WEB054, retire.js)
    T("jquery", "jQuery", ["javascript-library"], [
        S("script", r"/jquery(?:[.-]" + V + r")?(?:\.slim)?(?:\.min)?\.js(?:$|[?#])", 80, version="\\1")]),
    T("react", "React", ["javascript-framework"], [S("html", r"<[a-z]+\b[^>]+data-reactroot", 80),
                                                    S("script", r"/react(?:-dom)?(?:\.production)?(?:\.min)?\.js", 70)]),
    T("vue", "Vue.js", ["javascript-framework"], [S("html", r"<[a-z]+\b[^>]+data-v-[0-9a-f]{8}", 70),
                                                   S("script", r"/vue(?:\.runtime)?(?:\.global)?(?:\.prod)?(?:\.min)?\.js", 70)]),
    T("angular", "Angular", ["javascript-framework"], [S("html", r"<[a-z-]+\b[^>]+ng-version=[\"']" + V, 100,
                                                          version="\\1")]),
    T("angularjs", "AngularJS", ["javascript-framework"], [S("html", r"<[a-z]+\b[^>]+\bng-app\b", 70),
                                                           S("script", r"/angular(?:\.min)?\.js", 70)]),
    T("bootstrap", "Bootstrap", ["ui-framework"], [S("link", r"/bootstrap(?:[.-]" + V + r")?(?:\.min)?\.css", 70,
                                                     version="\\1")]),
    T("google-analytics", "Google Analytics", ["analytics"], [
        S("script", r"google-analytics\.com/(?:ga|analytics)\.js|googletagmanager\.com/gtag/js", 90)]),
    T("google-tag-manager", "Google Tag Manager", ["tag-manager"], [
        S("script", r"googletagmanager\.com/gtm\.js", 90),
        S("html", r"<script\b[^>]*>[^<]{0,600}googletagmanager\.com/gtm\.js", 90),
        S("html", r"<iframe\b[^>]+googletagmanager\.com/ns\.html", 90)]),
    T("recaptcha", "reCAPTCHA", ["security"], [S("script", r"(?:google|recaptcha)\.(?:com|net)/recaptcha/", 90)]),
    T("font-awesome", "Font Awesome", ["font"], [S("link", r"font-?awesome", 70), S("script", r"kit\.fontawesome\.com", 80)]),
]

# platform categories: a technology in one of these is a "platform" and gets a WEB080 finding (tech.py reads this
# same list from the data via ``categories``; the rest goes to the inventory only)


# ----------------------------------------------------------------------------------------------- nuclei import

ALIASES = {"ms-iis": "iis", "nginx": "nginx", "php": "php", "node": "nodejs", "python": "python", "jenkins": "jenkins",
           "cloudflare": "cloudflare", "akamai": "akamai", "sucuri": "sucuri", "imperva": "imperva", "laravel": "laravel",
           "symfony": "symfony", "express": "express", "lighttpd": "lighttpd", "caddy": "caddy", "jetty": "jetty",
           "kibana": "kibana", "uvicorn": "uvicorn", "wordpress": "wordpress", "joomla": "joomla", "drupal": "drupal",
           "magento": "magento", "prestashop": "prestashop", "shopify": "shopify", "wix": "wix", "squarespace": "squarespace",
           "ghost": "ghost", "mediawiki": "mediawiki", "phpbb": "phpbb", "discourse": "discourse", "gitlab": "gitlab",
           "grafana": "grafana", "typo3": "typo3", "moodle": "moodle", "django": "django", "ruby-on-rails": "ruby-on-rails",
           "phpmyadmin": "phpmyadmin", "atlassian-jira": "jira", "atlassian-confluence": "confluence", "nextjs": "nextjs",
           "nuxtjs": "nuxt", "gatsby": "gatsby", "hugo": "hugo", "jekyll": "jekyll", "angular": "angular",
           "angularjs": "angularjs", "react": "react", "vue": "vue", "vuejs": "vue", "jquery": "jquery",
           "bootstrap": "bootstrap", "google-analytics": "google-analytics", "google-tag-manager": "google-tag-manager",
           "font-awesome": "font-awesome", "recaptcha": "recaptcha", "liferay": "liferay", "umbraco": "umbraco",
           "craft-cms": "craft-cms", "sitecore": "sitecore", "dotnetnuke": "dotnetnuke", "opencart": "opencart",
           "woocommerce": "woocommerce", "elementor": "elementor", "roundcube": "roundcube", "plesk": "plesk",
           "webmin": "webmin", "cpanel": "cpanel", "varnish": "varnish", "litespeed": "litespeed", "openresty": "openresty"}
_ID = re.compile(r"[^a-z0-9._+-]+")
_HEADER_WORD = re.compile(r"^([A-Za-z0-9-]+):\s*(.*)$")
_COOKIE_WORD = re.compile(r"^Set-Cookie:\s*([A-Za-z0-9_.$-]+)=$", re.I)


def fetch(ref: str = "main", timeout: float = 60.0) -> str:
    sys.path.insert(0, str(ROOT))
    from vulnscan import __version__
    req = urllib.request.Request(RAW.format(ref=ref), headers={"User-Agent": f"Kashif/{__version__} webdata-refresh"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:   # nosec - fixed maintainer URL
        return resp.read(8 * 1024 * 1024).decode("utf-8")


def _unquote(v: str) -> str:
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
        inner = v[1:-1]
        return inner.replace("''", "'") if v[0] == "'" else inner.replace('\\"', '"').replace("\\\\", "\\")
    return v


def parse_matchers(yaml_text: str) -> list[dict]:
    """``[{"type", "name", "part", "condition", "values"}]`` from the template's flat matcher list."""
    body = yaml_text.split("matchers:", 1)[-1]
    out = []
    for block in re.split(r"\n\s*-\s+type:\s*", body)[1:]:
        lines = block.split("\n")
        m: dict = {"type": lines[0].strip(), "name": "", "part": "body", "condition": "or", "values": [],
                   "nocase": False}
        key = ""
        for line in lines[1:]:
            s = line.strip()
            if not s:
                continue
            kv = re.match(r"^([a-z-]+):\s*(.*)$", s)
            if kv and not s.startswith("- "):
                key = kv.group(1)
                val = kv.group(2)
                if key == "name":
                    m["name"] = _unquote(val)
                elif key == "part":
                    m["part"] = val.strip()
                elif key == "condition":
                    m["condition"] = val.strip()
                elif key == "case-insensitive":
                    m["nocase"] = val.strip() == "true"
                continue
            if s.startswith("- ") and key in ("regex", "words"):
                m["values"].append(_unquote(s[2:]))
        if m["name"] and m["values"]:
            out.append(m)
    return out


def _compiles(p: str) -> bool:
    if "[[:" in p or "\\z" in p:
        return False
    try:
        re.compile(p)
        return True
    except re.error:
        return False


def nuclei_signals(m: dict) -> list[dict]:
    """Scoped signals for one nuclei matcher (empty when it is prose, combined with ``and`` or not portable)."""
    if m["condition"] == "and" and len(m["values"]) > 1:
        return []
    flags = "i" if m["nocase"] else ""
    out: list[dict] = []
    if m["type"] == "regex" and m["part"] in ("body", "response"):
        for p in m["values"]:
            if p.startswith("<") and _compiles(p):
                out.append(S("html", p, 50, flags=flags))
    elif m["type"] == "word" and m["part"] in ("header", "all_headers", "server", "response"):
        for w in m["values"]:
            ck = _COOKIE_WORD.match(w)
            hw = _HEADER_WORD.match(w)
            if ck:
                out.append(S("cookie", "^" + re.escape(ck.group(1)) + "$", 50))
            elif hw and hw.group(1).lower() != "set-cookie":
                value = hw.group(2).strip()
                pat = re.escape(value) if value else "."
                out.append(S("header", pat, 50, name=hw.group(1).lower(), flags=flags))
            elif m["part"] == "server" and w and ":" not in w:
                out.append(S("header", re.escape(w), 50, name="server", flags=flags or "i"))
    return out


def merge(own: list[dict], matchers: list[dict]) -> list[dict]:
    by_id = {t["id"]: t for t in own}
    out = list(own)
    for m in matchers:
        sigs = nuclei_signals(m)
        if not sigs:
            continue
        raw = m["name"].strip()
        tid = ALIASES.get(raw.lower(), _ID.sub("-", raw.lower()).strip("-.") or "unknown")
        tech = by_id.get(tid)
        if tech is None:
            tech = T(tid, raw, ["other"], [])
            by_id[tid] = tech
            out.append(tech)
        have = {(s["source"], s.get("name", ""), s["pattern"]) for s in tech["signals"]}
        for s in sigs:
            key = (s["source"], s.get("name", ""), s["pattern"])
            if key not in have:
                have.add(key)
                tech["signals"].append(s)
    return [t for t in out if t["signals"] or t["id"] in ("mysql",)]


def build(yaml_text: str | None, day: str, upstream: str = "", notes: str = "") -> dict:
    own = json.loads(json.dumps(OWN))
    techs = merge(own, parse_matchers(yaml_text)) if yaml_text else own
    for t in techs:
        for s in t["signals"]:
            re.compile(s["pattern"])
    meta = {"schema_version": 1, "date": day, "source": SOURCE if yaml_text else "Kashif original signatures",
            "license": LICENSE if yaml_text else "Kashif (project licence)", "generator": "tools/webdata/tech.py"}
    if upstream:
        meta["upstream_version"] = upstream
    if notes:
        meta["notes"] = notes
    return {"meta": meta, "technologies": techs}


def write(obj: dict, out_dir: Path = OUT_DIR) -> Path:
    sys.path.insert(0, str(ROOT))
    from vulnscan.webscan import data
    errors = data.validate_data(OUT_NAME, obj)
    if errors:
        raise SystemExit("schema errors: " + "; ".join(errors[:5]))
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / OUT_NAME
    items = ",\n".join(json.dumps(t, ensure_ascii=False, separators=(",", ":")) for t in obj["technologies"])
    path.write_text('{"meta":' + json.dumps(obj["meta"], ensure_ascii=False) + ',\n"technologies":[\n' + items + "\n]}\n",
                    encoding="utf-8", newline="\n")
    return path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--from", dest="src", help="a local tech-detect.yaml")
    ap.add_argument("--own-only", action="store_true", help="Kashif's own signatures only")
    ap.add_argument("--ref", default="main", help="nuclei-templates branch or commit (default: main)")
    ap.add_argument("--upstream-version", default="", help="upstream commit/version recorded in meta")
    ap.add_argument("--date", help="snapshot date YYYY-MM-DD (default: today, UTC)")
    ap.add_argument("--notes", default="", help="free-text provenance note stored in the header")
    ap.add_argument("--out", default=str(OUT_DIR), help="output directory (default: vulnscan/data/web)")
    args = ap.parse_args(argv)
    text = None
    if not args.own_only:
        text = Path(args.src).read_text(encoding="utf-8") if args.src else fetch(args.ref)
    day = args.date or datetime.now(timezone.utc).date().isoformat()
    obj = build(text, day, args.upstream_version or ("" if args.src or args.own_only else args.ref), args.notes)
    path = write(obj, Path(args.out))
    n_sig = sum(len(t["signals"]) for t in obj["technologies"])
    n_deep = sum(len(t.get("deep_paths", [])) for t in obj["technologies"])
    print(f"wrote {path} ({len(obj['technologies'])} technologies, {n_sig} signals, {n_deep} deep paths)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
