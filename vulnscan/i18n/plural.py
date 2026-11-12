"""Arabic count phrases: the noun form that agrees with a number, as the web UI does (``tn()`` in ui/app.js).

Arabic has five forms (CLDR categories, by the last two digits): one (1, "ملف واحد"), two (2, the dual "ملفان"),
few (3-10, the plural "3 ملفات"), many (11-99, the accusative singular "11 ملفًا") and other (0 and 100, 101, 102 ...,
the singular "100 ملف"). A phrase table gives the five forms; ``{n}`` stands for the number.
"""

from __future__ import annotations

FORMS = ("one", "two", "few", "many", "other")

FILES_SCANNED = ("ملف واحد مفحوص", "ملفان مفحوصان", "{n} ملفات مفحوصة", "{n} ملفًا مفحوصًا", "{n} ملف مفحوص")
FINDINGS = ("نتيجة واحدة", "نتيجتان", "{n} نتائج", "{n} نتيجةً", "{n} نتيجة")


def ar_category(count) -> str:
    """The CLDR plural category of ``count`` in Arabic: one, two, few, many or other."""
    try:
        n = abs(int(count))
    except (TypeError, ValueError):
        return "other"
    if n in (1, 2):
        return "one" if n == 1 else "two"
    r = n % 100
    return "few" if 3 <= r <= 10 else "many" if r >= 11 else "other"


def ar_count(count, forms: tuple[str, str, str, str, str]) -> str:
    """``count`` with the noun phrase that agrees with it, from ``forms`` (one, two, few, many, other)."""
    return forms[FORMS.index(ar_category(count))].replace("{n}", str(count))
