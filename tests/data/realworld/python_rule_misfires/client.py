import http.cookiejar
import requests


def fetch(url):
    return requests.get(url, verify=False)          # CRY002 is right; CFG007 ("JWT accepts none") is a misfire


def copy_jar(src):
    jar = http.cookiejar.CookieJar()
    for c in src:
        jar.set_cookie(c)                           # client-side cookie jar, not a Set-Cookie response: COOK001 misfire
    return jar


DIGEST_CHALLENGE = b'WWW-Authenticate: Digest nonce="6bf5d6e4da1ce66918800195d6b9130d"'   # protocol test data, not an IV


def check(user):
    assert user is not None, "user required"    # CFG005 on a null check, not authorization
