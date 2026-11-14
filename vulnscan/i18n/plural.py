"""Arabic count phrases: the noun form that agrees with a number, as the web UI does (``tn()`` in ui/app.js).

Arabic has five forms (CLDR categories, by the last two digits): one (1, "ملف واحد"), two (2, the dual "ملفان"),
few (3-10, the plural "3 ملفات"), many (11-99, the accusative singular "11 ملفًا") and other (0 and 100, 101, 102 ...,
the singular "100 ملف"). A phrase table gives the five forms; ``{n}`` stands for the number.

A number with a fractional part (``0.5``, ``1.5``) takes the singular of the "other" form ("1.5 ثانية"), as in written
Modern Standard Arabic; the number is shown without a trailing ``.0``.
"""

from __future__ import annotations

FORMS = ("one", "two", "few", "many", "other")

FILES_SCANNED = ("ملف واحد مفحوص", "ملفان مفحوصان", "{n} ملفات مفحوصة", "{n} ملفًا مفحوصًا", "{n} ملف مفحوص")
FINDINGS = ("نتيجة واحدة", "نتيجتان", "{n} نتائج", "{n} نتيجةً", "{n} نتيجة")
PAGES_SCANNED = ("صفحة واحدة مفحوصة", "صفحتان مفحوصتان", "{n} صفحات مفحوصة", "{n} صفحةً مفحوصة", "{n} صفحة مفحوصة")
REQUESTS = ("طلب واحد", "طلبان", "{n} طلبات", "{n} طلبًا", "{n} طلب")
# accusative/genitive dual ("بعد ثانيتين", "مهلة ثانيتين"): durations are objects or complements in engine text
SECONDS = ("ثانية واحدة", "ثانيتين", "{n} ثوانٍ", "{n} ثانيةً", "{n} ثانية")


def parse_number(count):
    """``count`` as an int when it is integral (``3``, ``3.0``, ``"3"``), a float when it has a fraction, else None."""
    if isinstance(count, bool):
        return None
    if isinstance(count, int):
        return count
    try:
        x = float(count)
    except (TypeError, ValueError):
        return None
    if x != x or x in (float("inf"), float("-inf")):
        return None
    return int(x) if x.is_integer() else x


def number_text(count) -> str:
    """``count`` as shown next to a noun: ``3``, ``1.5`` (never ``3.0``); other values unchanged."""
    n = parse_number(count)
    if n is None:
        return str(count)
    return str(n) if isinstance(n, int) else f"{n:.3f}".rstrip("0").rstrip(".")


def ar_category(count) -> str:
    """The CLDR plural category of ``count`` in Arabic: one, two, few, many or other (fractions: other)."""
    n = parse_number(count)
    if not isinstance(n, int):
        return "other"
    n = abs(n)
    if n in (1, 2):
        return "one" if n == 1 else "two"
    r = n % 100
    return "few" if 3 <= r <= 10 else "many" if r >= 11 else "other"


def ar_count(count, forms: tuple[str, str, str, str, str]) -> str:
    """``count`` with the noun phrase that agrees with it, from ``forms`` (one, two, few, many, other)."""
    return forms[FORMS.index(ar_category(count))].replace("{n}", number_text(count))
