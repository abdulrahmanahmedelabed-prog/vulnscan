"""Write and validate ``vulnscan/data/web/takeover.json`` (WEB901 subdomain-takeover fingerprints). Maintainers only.

    python tools/webdata/takeover.py                       # rewrite the file from the curated table below
    python tools/webdata/takeover.py --check               # exit 1 when the bundled file differs from the table
    python tools/webdata/takeover.py --nuclei DIR          # cross-check the fingerprints against a nuclei-templates
                                                           # checkout (DIR/http/takeovers/*.yaml) and report drift

Sources. The body fingerprints are the ``word`` matchers of the MIT-licensed nuclei-templates ``http/takeovers`` set
(projectdiscovery; attribution in NOTICE). The CNAME suffixes, the expected status codes and the ``vulnerable`` flag are
facts about each provider (where an unclaimed custom domain points and what the provider answers) maintained by Kashif;
providers whose takeover is no longer possible (the provider verifies domain ownership or uses unguessable targets) stay
in the file with ``"vulnerable": false`` so the scanner can name them without ever reporting them.

Matching rules used by ``webscan/exposure.py`` (spec §2.10 WEB901): the scanned host's CNAME chain (canonical name and
aliases from ``gethostbyname_ex``) ends in one of ``cname`` **and** the response body contains one of ``fingerprints``
(case-sensitive, like nuclei's word matcher; for nuclei templates that require several words the most specific one is
kept) **and** the status equals ``status`` when it is not null. Nuclei templates that match only headers or a bare IP
(Ghost, Gemfury, GoDaddy parking, Worksites, UptimeRobot's one-line body, SurveyGizmo's generic marker) are not used.

No network access is needed; ``--nuclei`` reads a local checkout. The output is deterministic (sorted, fixed layout).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "vulnscan" / "data" / "web" / "takeover.json"
DEFAULT_DATE = "2026-11-13"

# (name, nuclei template id or "", CNAME suffixes, fingerprints, status or None, vulnerable, nxdomain)
PROVIDERS: list[tuple[str, str, tuple[str, ...], tuple[str, ...], int | None, bool, bool]] = [
    ("AfterShip", "aftership-takeover", ("aftership.com",),
     ("Oops.</h2><p class=\"text-muted text-tight\">The page you're looking for doesn't exist.",), None, True, False),
    ("Agile CRM", "agilecrm-takeover", ("agilecrm.com",), ("Sorry, this page is no longer available.",), None, True,
     False),
    ("Aha!", "aha-takeover", ("aha.io",), ("There is no portal here ... sending you back to Aha!",), None, True, False),
    ("Airee.ru", "airee-takeover", ("airee.ru",), ("Ошибка 402. Сервис Айри.рф не оплачен",), None, True, False),
    ("Anima", "anima-takeover", ("animaapp.io",),
     ("If this is your website and you've just created it, try refreshing in a minute",), None, True, False),
    ("AnnounceKit", "announcekit-takeover", ("announcekit.app",), ("Error 404 - AnnounceKit",), 404, True, False),
    ("AWS S3 bucket", "aws-bucket-takeover", ("s3.amazonaws.com", "amazonaws.com"),
     ("The specified bucket does not exist",), 404, True, False),
    ("Big Cartel", "bigcartel-takeover", ("bigcartel.com",), ("<h1>Oops! We couldn&#8217;t find that page.</h1>",), None,
     True, False),
    ("Bitbucket", "bitbucket-takeover", ("bitbucket.io",), ("Repository not found",), 404, True, False),
    ("Campaign Monitor", "campaignmonitor-takeover", ("createsend.com",), ("css.createsend1.com",), None, True, False),
    ("Canny", "canny-takeover", ("canny.io",), ("There is no such company. Did you enter the right URL?",), None, True,
     False),
    ("Cargo", "cargo-takeover", ("cargocollective.com",),
     ("If you're moving your domain away from Cargo you must make this configuration through your registrar's DNS "
      "control panel.",), None, True, False),
    ("Clever Cloud", "clever-takeover", ("clever-cloud.com", "cleverapps.io"),
     ("The application you're trying to access doesn't seem to exist",), None, True, False),
    ("Flexbe", "flexbe-takeover", ("flexbe.com",), ("Domain not configured",), 404, True, False),
    ("Framer", "framer-takeover", ("framer.app", "framer.website", "framercanvas.com"), ("Site Not Found | Framer",),
     None, True, False),
    ("Frontify", "frontify-takeover", ("frontify.com",), ("Oops… looks like you got lost",), None, True, False),
    ("GetResponse", "getresponse-takeover", ("gr8.com", "getresponse.com"),
     ("With GetResponse Landing Pages, lead generation has never been easier",), None, True, False),
    ("GitBook", "gitbook-takeover", ("gitbook.io", "gitbook.com"), ("If you need specifics, here's the error",), None,
     True, False),
    ("GitHub Pages", "github-takeover", ("github.io",),
     ("There isn't a GitHub Pages site here.",
      "For root URLs (like http://example.com/) you must provide an index.html file",
      "The site configured at this address does not contain the requested file.",
      "For root URLs (like <code>http://example.com/</code>)"), 404, True, False),
    ("GoHire", "gohire-takeover", ("gohire.io",),
     ("You may have followed an invalid link or the job you are looking for has been archived",), 404, True, False),
    ("GreatPages", "greatpages-takeover", ("greatpages.com.br",), ("Página não encontrada (Erro 404)",), None, True,
     False),
    ("Hatena Blog", "hatenablog-takeover", ("hatenablog.com", "hatena.ne.jp"), ("404 Blog is not found",), None, True,
     False),
    ("HelpDocs", "helpdocs-takeover", ("helpdocs.io",),
     ("You've tried to access an account/page that does not exist",), None, True, False),
    ("Helpjuice", "helpjuice-takeover", ("helpjuice.com",), ("We could not find what you're looking for.",), None, True,
     False),
    ("Helprace", "helprace-takeover", ("helprace.com",),
     ("Alias not configured!", "Admin of this Helprace account needs to set up domain alias"), None, True, False),
    ("Help Scout Docs", "helpscout-takeover", ("helpscoutdocs.com",), ("No settings were found for this company:",),
     None, True, False),
    ("HubSpot", "hubspot-takeover", ("hubspot.net", "hs-sites.com", "hubspotpagebuilder.com"),
     ("does not exist in our system",), 404, True, False),
    ("Intercom", "intercom-takeover", ("intercom.help", "custom.intercom.help"),
     ("This page is reserved for artistic dogs.",), None, True, False),
    ("JazzHR", "jazzhr-takeover", ("applytojob.com",), ("This account no longer active",), None, True, False),
    ("JetBrains YouTrack", "jetbrains-takeover", ("myjetbrains.com",), ("is not a registered InCloud YouTrack.",), None,
     True, False),
    ("Kinsta", "kinsta-takeover", ("kinsta.cloud",), ("No Site For Domain",), None, True, False),
    ("LaunchRock", "launchrock-takeover", ("launchrock.com",),
     ("It looks like you may have taken a wrong turn somewhere. Don't worry...it happens to all of us.",), None, True,
     False),
    ("Leadpages", "leadpages-takeover", ("lpages.co",),
     ("Double check that you have the right web address and give it another go!",), None, True, False),
    ("Mashery", "mashery-takeover", ("mashery.com",), ("Unrecognized domain <strong>",), None, True, False),
    ("Meteor", "meteor-takeover", ("meteor.com", "meteorapp.com"),
     ("404 Not Found: No applications registered for host '",), None, True, False),
    ("ngrok", "ngrok-takeover", ("ngrok.io", "ngrok.app", "ngrok-free.app"), ("ngrok.io not found",), None, True, False),
    ("Pagewiz", "pagewiz-takeover", ("pagewiz.com",), ("Start Your New Landing Page Now!",), None, True, False),
    ("Pantheon", "pantheon-takeover", ("pantheonsite.io",),
     ("The gods are wise, but do not know of the site which you seek.",), 404, True, False),
    ("Pingdom", "pingdom-takeover", ("pingdom.com",),
     ("This public report page has not been activated by the user", "Public Report Not Activated"), None, True, False),
    ("Proposify", "proposify-takeover", ("proposify.biz", "proposify.com"),
     ("If you need immediate assistance, please contact <a href=\"mailto:support@proposify.biz",), None, True, False),
    ("ReadMe", "readme-takeover", ("readme.io", "readmessl.com"), ("Project doesnt exist... yet!",), None, True, False),
    ("Read the Docs", "readthedocs-takeover", ("readthedocs.io",), ("unknown to Read the Docs",), None, True, False),
    ("redirect.pizza", "redirect-pizza-takeover", ("redirect.pizza",), ("Unable to redirect",), None, True, False),
    ("Short.io", "short-io", ("short.io", "short.gy"), ("This domain is not configured on Short.io",), None, True, False),
    ("Simplebooklet", "simplebooklet-takeover", ("simplebooklet.com",),
     ("We can't find this <a href=\"https://simplebooklet.com",), None, True, False),
    ("Smart Job Board", "smartjob-takeover", ("smartjobboard.com",),
     ("This job board website is either expired", "Job Board Is Unavailable"), None, True, False),
    ("SmugMug", "smugmug-takeover", ("smugmug.com",), ("{\"text\":\"Page Not Found\"",), None, True, False),
    ("Softr", "softr-takeover", ("softr.app", "softr.io"), ("The application you were looking for was built on Softr",),
     404, True, False),
    ("Sprintful", "sprintful-takeover", ("sprintful.com",),
     ("The user account associated with this calendar has been deactivated.",
      "This domain name does not have a default page configured."), 200, True, False),
    ("Squadcast", "squadcast-takeover", ("squadcast.com", "squadcast.fm"),
     ("There doesn’t seem to be an active status page associated with this URL.",), 404, True, False),
    ("Strikingly", "strikingly-takeover", ("strikinglydns.com", "s.strikinglydns.com"),
     ("But if you're looking to build your own website",), None, True, False),
    ("Surge.sh", "surge-takeover", ("surge.sh",), ("project not found",), 404, True, False),
    ("SurveySparrow", "surveysparrow-takeover", ("surveysparrow.com",), ("Account not found.",), None, True, False),
    ("Tave", "tave-takeover", ("tave.com",), ("<h1>Error 404: Page Not Found</h1>",), None, True, False),
    ("Teamwork", "teamwork-takeover", ("teamwork.com",), ("Oops - We didn't find your site.",), None, True, False),
    ("Tilda", "tilda-takeover", ("tilda.ws",),
     ("Please go to the site settings and put the domain name in the Domain tab.",), None, True, False),
    ("Uberflip", "uberflip-takeover", ("uberflip.com",),
     ("Non-hub domain, The URL you've accessed does not provide a hub.",), None, True, False),
    ("Better Stack status page", "uptime-takeover", ("betteruptime.com", "betterstack.com"),
     ("<html><body>You are being <a href=\"https://uptime.betterstack.com\">redirected</a>.</body></html>",), 302, True,
     False),
    ("UserVoice", "uservoice-takeover", ("uservoice.com",), ("This UserVoice subdomain is currently available!",), None,
     True, False),
    ("Vend", "vend-takeover", ("vendecommerce.com",), ("Looks like you've traveled too far into cyberspace.",), None,
     True, False),
    ("Wasabi bucket", "wasabi-bucket-takeover", ("wasabisys.com",), ("The specified bucket does not exist",), None, True,
     False),
    ("Wishpond", "wishpond-takeover", ("wishpond.com",),
     ("Oops! There isn’t a Wishpond Campaign published to this page.", "https://www.wishpond.com/404?campaign=true"),
     None, True, False),
    ("Wix", "wix-takeover", ("wixdns.net",), ("ConnectYourDomain Error | Wix.com",), 404, True, False),
    ("WordPress.com", "wordpress-takeover", ("wordpress.com",), (".wordpress.com</em> doesn&#8217;t&nbsp;exist",), None,
     True, False),
    ("Wufoo", "wufoo-takeover", ("wufoo.com",), ("Hmmm....something is not right.",), None, True, False),
    ("Zendesk", "zendesk-takeover", ("zendesk.com",), ("this help centre no longer exists", "Help Centre Closed"), None,
     True, False),
    # no longer exploitable by a CNAME alone: named, never reported
    ("Heroku", "", ("herokuapp.com", "herokudns.com", "herokussl.com"),
     ("No such app", "There's nothing here, yet."), 404, False, False),
    ("Shopify", "", ("myshopify.com",), ("Sorry, this shop is currently unavailable.",), None, False, False),
    ("Fastly", "", ("fastly.net",), ("Fastly error: unknown domain",), None, False, False),
    ("Netlify", "", ("netlify.app", "netlify.com", "netlifyglobalcdn.com"), ("Not Found - Request ID:",), 404, False,
     False),
    ("Tumblr", "", ("domains.tumblr.com",),
     ("Whatever you were looking for doesn't currently exist at this address.",), 404, False, False),
    ("Webflow", "", ("proxy-ssl.webflow.com", "proxy.webflow.com"),
     ("The page you are looking for doesn't exist or has been moved.",), 404, False, False),
    # dangling-name providers: the deleted resource no longer resolves, so the scan cannot see a body (spec §2.10
    # "Limitation"); kept for the explanation only
    ("Microsoft Azure", "", ("azurewebsites.net", "cloudapp.net", "cloudapp.azure.com", "trafficmanager.net",
                             "blob.core.windows.net", "azureedge.net", "azure-api.net", "azurefd.net"),
     ("404 Web Site not found",), 404, True, True),
]

_WORDS = re.compile(r"^\s+- (.*)$", re.M)


def nuclei_words(directory: Path) -> dict[str, list[str]]:
    """Template id → body ``word`` matcher strings of a local nuclei-templates ``http/takeovers`` directory."""
    out: dict[str, list[str]] = {}
    for f in sorted(directory.glob("*.yaml")):
        text = f.read_text(encoding="utf-8")
        body = text.split("matchers:", 1)[-1].split("extractors:", 1)[0]
        words: list[str] = []
        for block in re.split(r"\n\s+- type: ", body)[1:]:
            if not block.startswith("word") or "negative: true" in block or re.search(r"part: (?!body)", block):
                continue
            for item in _WORDS.findall(block.split("words:", 1)[-1]):
                item = item.strip()
                if len(item) >= 2 and item[0] == item[-1] and item[0] in "'\"":
                    item = item[1:-1]
                if item.startswith(("condition:", "part:", "negative:")):
                    continue
                words.append(item.replace("\\'", "'").replace("\\’", "’"))
        out[f.stem] = words
    return out


def drift(directory: Path) -> list[str]:
    """Fingerprints of the table that the nuclei checkout no longer has (and templates the table does not use)."""
    words = nuclei_words(directory)
    msgs = []
    used = set()
    for name, tid, _cn, fps, _st, _vul, _nx in PROVIDERS:
        if not tid:
            continue
        used.add(tid)
        if tid not in words:
            msgs.append(f"{name}: template {tid} is gone upstream")
            continue
        for fp in fps:
            if not any(fp in w or w in fp for w in words[tid]):
                msgs.append(f"{name}: fingerprint {fp!r} not in {tid}")
    for tid in sorted(set(words) - used):
        msgs.append(f"not used: {tid}")
    return msgs


def build(date: str) -> dict:
    providers = []
    for name, tid, cnames, fps, status, vulnerable, nxdomain in PROVIDERS:
        p = {"name": name, "cname": sorted(set(cnames)), "fingerprints": list(fps), "status": status,
             "vulnerable": vulnerable}
        if nxdomain:
            p["nxdomain"] = True
        if tid:
            p["reference"] = f"nuclei-templates http/takeovers/{tid}.yaml"
        providers.append(p)
    providers.sort(key=lambda p: p["name"].lower())
    return {
        "meta": {"schema_version": 1, "date": date, "generator": "tools/webdata/takeover.py",
                 "source": "Body fingerprints: nuclei-templates http/takeovers (projectdiscovery); CNAME suffixes, status "
                           "codes and the vulnerable flag: Kashif's provider facts",
                 "license": "nuclei-templates MIT (fingerprint strings, see NOTICE); provider facts Kashif project licence",
                 "notes": "WEB901 needs all three: a CNAME (canonical name or alias) ending in a listed suffix, a body "
                          "containing a fingerprint, and the listed status (null = any). vulnerable=false providers are "
                          "never reported; nxdomain providers usually leave a name that no longer resolves."},
        "providers": providers,
    }


def render(doc: dict) -> str:
    return json.dumps(doc, ensure_ascii=False, indent=1) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="compare with the bundled file instead of writing it")
    ap.add_argument("--nuclei", help="nuclei-templates checkout (or its http/takeovers directory) to cross-check")
    ap.add_argument("--date", help="meta.date (YYYY-MM-DD); default: keep the bundled date")
    args = ap.parse_args(argv)
    if args.nuclei:
        d = Path(args.nuclei)
        if (d / "http" / "takeovers").is_dir():
            d = d / "http" / "takeovers"
        for m in drift(d):
            print(m)
    date = args.date
    if date is None:
        try:
            date = json.loads(OUT.read_text(encoding="utf-8"))["meta"]["date"]
        except (OSError, ValueError, KeyError):
            date = DEFAULT_DATE
    text = render(build(date))
    sys.path.insert(0, str(ROOT))
    from vulnscan.webscan import data
    errors = data.validate_data(OUT.name, json.loads(text))
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    if args.check:
        current = OUT.read_text(encoding="utf-8") if OUT.is_file() else ""
        if current != text:
            print(f"{OUT} is not what the table produces; run without --check", file=sys.stderr)
            return 1
        return 0
    if args.nuclei:
        return 0
    OUT.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {OUT} ({len(text)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
