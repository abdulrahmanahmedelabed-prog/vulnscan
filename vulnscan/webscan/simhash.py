"""64-bit simhash, shingling and normalisation for soft-404 similarity (spec §3.2, WP2).

Charikar's simhash (Manku, Jain, Das Sarma, WWW 2007): every feature is hashed to 64 bits, each bit votes +w/−w, and
the sign of the sum gives the bit of the fingerprint. Near-duplicate documents differ in few bits; Kashif treats a
Hamming distance ≤ 3 as "similar" (§3.2) and group.py uses the same threshold for crawl near-duplicates (§3.5).

Features are stable across processes and platforms (BLAKE2b, never Python's salted ``hash``), so a simhash stored in
evidence or a snapshot can be compared with one from a later run.

Before shingling, the text is normalised so that the parts a soft-404 page typically echoes or varies (the requested
path and query values, dates, times, long numbers, long hex runs, UUIDs and random-looking tokens) do not change the
fingerprint. Everything here is pure and offline.
"""

from __future__ import annotations

import hashlib
import html
import re
import urllib.parse
from collections import Counter
from typing import Iterable, Sequence

MASK64 = 0xFFFFFFFFFFFFFFFF
SIMILAR_DISTANCE = 3              # §3.2 / §3.5: Hamming ≤ 3 means near-duplicate
WORD_SHINGLE = 3                  # words per shingle for visible text
BYTE_SHINGLE = 4                  # bytes per shingle for other bodies
SHINGLE_INPUT_CAP = 256 * 1024    # characters of HTML fed to the shingler (length and SHA-256 still cover the body)
BYTES_INPUT_CAP = 64 * 1024       # bytes of other bodies fed to the 4-byte shingler
SHORT_TEXT_WORDS = 40             # below this many words, tag-structure shingles are added (SPA shells, bare pages)
PLACEHOLDER = "#"


def _feature_digest(feature: str | bytes) -> bytes:
    data = feature.encode("utf-8", "surrogatepass") if isinstance(feature, str) else bytes(feature)
    return hashlib.blake2b(data, digest_size=8).digest()


def simhash64(features: Iterable[str | bytes]) -> int:
    """Unsigned 64-bit simhash of ``features`` (word shingles of visible text, or 4-byte shingles of other bodies).

    Repeated features count with their multiplicity. An empty feature set gives 0. The implementation tallies each of
    the 8 digest bytes per value first, so the cost is O(features + 8·256·8) instead of O(64·features)."""
    counts = Counter(_feature_digest(f) for f in features)
    if not counts:
        return 0
    total = sum(counts.values())
    # per byte position: weighted histogram of byte values
    hist: list[Counter] = [Counter() for _ in range(8)]
    for digest, weight in counts.items():
        for pos in range(8):
            hist[pos][digest[pos]] += weight
    result = 0
    for pos in range(8):
        ones = [0] * 8
        for value, weight in hist[pos].items():
            if not value:
                continue
            for bit in range(8):
                if value >> bit & 1:
                    ones[bit] += weight
        for bit in range(8):
            # bit votes +w when set and −w when clear: sum > 0  ⇔  2·ones > total
            if 2 * ones[bit] > total:
                # big-endian: digest byte 0 holds the most significant bits of the fingerprint
                result |= 1 << ((7 - pos) * 8 + bit)
    return result & MASK64


def hamming(a: int, b: int) -> int:
    """Number of differing bits between two 64-bit hashes."""
    return bin((a ^ b) & 0xFFFFFFFFFFFFFFFF).count("1")


def near_duplicate(a: int, b: int, distance: int = SIMILAR_DISTANCE) -> bool:
    """True when two simhashes are within ``distance`` bits (default 3, §3.2/§3.5)."""
    return hamming(a, b) <= distance


def to_hex(value: int) -> str:
    """The 16-hex-digit form used in evidence (``baseline.simhash``) and snapshots."""
    return f"{value & MASK64:016x}"


# ----------------------------------------------------------------------------------------------- normalisation

_MONTHS = (r"(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sep(?:t(?:ember)?)?"
           r"|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)")
_DAYS = r"(?:mon(?:day)?|tue(?:s(?:day)?)?|wed(?:nesday)?|thu(?:rs(?:day)?)?|fri(?:day)?|sat(?:urday)?|sun(?:day)?)"
_VOLATILE = re.compile(
    "|".join((
        # UUIDs
        r"(?<![0-9a-z])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![0-9a-z])",
        # ISO 8601 dates with optional time and zone
        r"\d{4}-\d{2}-\d{2}(?:[t ]\d{1,2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?(?:z|[+-]\d{2}:?\d{2})?)?",
        # numeric dates 12/11/2026, 12.11.26, 2026/11/12
        r"(?<!\d)\d{1,4}[/.]\d{1,2}[/.]\d{2,4}(?!\d)",
        # 12-Nov-2026, 12 Nov 2026, Nov 12, 2026
        rf"(?<![0-9a-z])\d{{1,2}}[ -]{_MONTHS}[ -,]+\d{{2,4}}(?![0-9])",
        rf"(?<![a-z]){_MONTHS}\.?\s+\d{{1,2}}(?:st|nd|rd|th)?,?\s+\d{{4}}(?![0-9])",
        # weekday names (HTTP dates, log lines)
        rf"(?<![a-z]){_DAYS}(?![a-z])",
        # times 10:00, 10:00:01.123, 10:00 AM, with an optional zone
        r"(?<!\d)\d{1,2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?(?:\s*[ap]\.?m\.?)?(?:\s*(?:gmt|utc|z)(?![a-z]))?",
        # hex runs of 16 or more (request ids, hashes, kashif-404-<16 hex>)
        r"(?<![0-9a-z])[0-9a-f]{16,}(?![0-9a-z])",
        # random-looking tokens: ≥ 20 characters mixing letters and digits (nonces, ray ids, base64 ids)
        r"(?<![0-9a-z_+/=-])(?=[0-9a-z_+/=-]*\d)(?=[0-9a-z_+/=-]*[a-z])[0-9a-z_+/=-]{20,}(?![0-9a-z_+/=-])",
        # numbers of 4 or more digits (after the date/time forms above)
        r"\d{4,}",
    )),
    re.I,
)
_WS = re.compile(r"\s+")


def _url_forms(url: str | None) -> list[str]:
    """Spellings of the requested URL a page may echo: full URL, without scheme, path(+query), decoded path."""
    if not url:
        return []
    forms: list[str] = [url]
    try:
        p = urllib.parse.urlsplit(url)
    except ValueError:
        return forms
    path = p.path or "/"
    pq = path + (("?" + p.query) if p.query else "")
    if p.netloc:
        forms.append(p.netloc + pq)
    forms += [pq, path]
    decoded = urllib.parse.unquote(path)
    if decoded != path:
        forms.append(decoded)
    base = path.rsplit("/", 1)[-1]
    # the file name alone, when it looks like one (a dot, dash, underscore or digit); plain words stay
    if len(base) >= 3 and re.search(r"[._\-0-9]", base):
        forms.append(base)
        dbase = urllib.parse.unquote(base)
        if dbase != base:
            forms.append(dbase)
    for _k, v in urllib.parse.parse_qsl(p.query, keep_blank_values=False):
        if len(v) >= 3:
            forms.append(v)
    # longest first so a full URL is removed before its path
    out: list[str] = []
    for f in sorted({f for f in forms if f and f != "/"}, key=len, reverse=True):
        out.append(f)
    return out


def normalise_text(text: str, url: str | None = None, *, extra: Sequence[str] = ()) -> str:
    """Lower-cased text with the requested URL/path/query values, dates, times, numbers ≥ 4 digits, hex ≥ 16, UUIDs
    and random-looking tokens replaced by ``#``, whitespace collapsed (§3.2)."""
    if not text:
        return ""
    out = text
    for form in [*_url_forms(url), *extra]:
        if form:
            out = out.replace(form, f" {PLACEHOLDER} ")
            esc = html.escape(form, quote=True)
            if esc != form:
                out = out.replace(esc, f" {PLACEHOLDER} ")
    out = _VOLATILE.sub(f" {PLACEHOLDER} ", out)
    return _WS.sub(" ", out).strip().lower()


# ----------------------------------------------------------------------------------------------- visible text

_DROP_BLOCKS = re.compile(r"<(script|style|template|svg|math)\b[^>]*>.*?</\1\s*>|<!--.*?(?:-->|$)", re.I | re.S)
_TAG = re.compile(r"<[^>]*>", re.S)
_START_TAG = re.compile(r"<([a-zA-Z][a-zA-Z0-9-]*)((?:[^>\"']|\"[^\"]*\"|'[^']*')*)>")
_ID_ATTR = re.compile(r"""\bid\s*=\s*["']?([^"'\s>]+)""", re.I)
_TITLE = re.compile(r"<title\b[^>]*>(.*?)</title\s*>", re.I | re.S)


def visible_text(markup: str) -> str:
    """Approximate rendered text of an HTML string: script, style, template, svg/math and comments removed, tags
    stripped, entities decoded, whitespace collapsed. Regex-based on purpose (fast on 2 MB pages; similarity only)."""
    if not markup:
        return ""
    text = _DROP_BLOCKS.sub(" ", markup)
    text = _TAG.sub(" ", text)
    return _WS.sub(" ", html.unescape(text)).strip()


def tag_features(markup: str, limit: int = 400) -> list[str]:
    """Shingles of the start-tag sequence (``tag#id``), used when a page has little text (§3.2 refinement)."""
    tags: list[str] = []
    for m in _START_TAG.finditer(markup):
        name = m.group(1).lower()
        idm = _ID_ATTR.search(m.group(2) or "")
        tags.append(f"{name}#{idm.group(1).lower()}" if idm else name)
        if len(tags) >= limit:
            break
    if len(tags) < WORD_SHINGLE:
        return [f"t:{t}" for t in tags]
    return ["t:" + " ".join(tags[i:i + WORD_SHINGLE]) for i in range(len(tags) - WORD_SHINGLE + 1)]


def word_shingles(text: str, k: int = WORD_SHINGLE) -> list[str]:
    """Overlapping ``k``-word shingles; the words themselves when the text is shorter than ``k`` words."""
    words = text.split()
    if len(words) < k:
        return words
    return [" ".join(words[i:i + k]) for i in range(len(words) - k + 1)]


def byte_shingles(data: bytes, k: int = BYTE_SHINGLE) -> list[bytes]:
    """Overlapping ``k``-byte shingles (the whole input when it is shorter than ``k``)."""
    if len(data) <= k:
        return [data] if data else []
    return [data[i:i + k] for i in range(len(data) - k + 1)]


def html_features(markup: str, url: str | None = None) -> list[str]:
    """Features of an HTML body: word shingles of the normalised visible text (title included); when the text is
    short (< ``SHORT_TEXT_WORDS`` words), also start-tag shingles so two different near-empty shells differ."""
    markup = markup[:SHINGLE_INPUT_CAP]
    text = normalise_text(visible_text(markup), url)
    feats = word_shingles(text)
    if len(text.split()) < SHORT_TEXT_WORDS:
        feats += tag_features(markup)
    return feats


def bytes_features(body: bytes, url: str | None = None) -> list[bytes]:
    """Features of a non-HTML body: 4-byte shingles of the body after the same normalisation (latin-1 round trip,
    so binary bytes survive unchanged)."""
    raw = body[:BYTES_INPUT_CAP].decode("latin-1")
    norm = normalise_text(raw, url)
    return byte_shingles(norm.encode("latin-1", "replace"))


def title_of(markup: str) -> str:
    m = _TITLE.search(markup[:65536])
    return _WS.sub(" ", html.unescape(_TAG.sub(" ", m.group(1)))).strip() if m else ""


__all__ = [
    "MASK64", "SIMILAR_DISTANCE", "WORD_SHINGLE", "BYTE_SHINGLE", "SHINGLE_INPUT_CAP", "BYTES_INPUT_CAP", "simhash64",
    "hamming", "near_duplicate", "to_hex", "normalise_text", "visible_text", "tag_features", "word_shingles", "byte_shingles",
    "html_features", "bytes_features", "title_of",
]
