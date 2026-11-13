"""Bilingual command-line help shared by ``kashif`` and its sub-commands.

Three pieces, all standard library:

* :func:`pick` chooses a help text for a language: Arabic (``ar``), English (``en``) or both, the Arabic line
  first and the English line under it (``both``, the default of ``kashif`` when neither ``--lang``,
  ``VULNSCAN_LANG`` nor an Arabic system locale chooses one).
* :class:`HelpFormatter` / :class:`RawDescriptionHelpFormatter` keep those line breaks when argparse wraps the help
  of an option (argparse's own formatter joins every line into one paragraph).
* :func:`localized_argparse` translates argparse's own text: the ``usage:`` prefix, the "positional arguments" and
  "options" headings, "show this help message and exit" and the parser errors ("the following arguments are
  required: ...", "invalid choice: ..."). argparse looks these up through ``gettext`` when it builds a parser, prints
  help or reports an error, so the context manager supplies the translation for that time only and restores the
  previous lookup afterwards. A message without a translation stays in English.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import string
import textwrap

from .plural import FORMS, ar_category

HELP_LANGS = ("en", "ar", "both")

# argparse message id -> Arabic. Keys are argparse's exact gettext message ids (Python 3.10 to 3.13).
_AR = {
    "usage: ": "الاستخدام: ",
    "positional arguments": "المعاملات الموضعية",
    "options": "الخيارات",
    "optional arguments": "الخيارات",
    "subcommands": "الأوامر الفرعية",
    "show this help message and exit": "اعرض هذه المساعدة ثم اخرج",
    "show program's version number and exit": "اعرض رقم الإصدار ثم اخرج",
    "%(prog)s: error: %(message)s\n": "%(prog)s: خطأ: %(message)s\n",
    "%(prog)s: warning: %(message)s\n": "%(prog)s: تحذير: %(message)s\n",
    "the following arguments are required: %s": "معاملات مطلوبة لم تُحدَّد: %s",
    "invalid choice: %(value)r (choose from %(choices)s)": "قيمة غير صالحة: %(value)r (المتاح: %(choices)s)",
    "unrecognized arguments: %s": "معاملات غير معروفة: %s",
    "expected one argument": "يحتاج إلى قيمة واحدة",
    "expected at most one argument": "يقبل قيمة واحدة على الأكثر",
    "expected at least one argument": "يحتاج إلى قيمة واحدة على الأقل",
    "argument %(argument_name)s: %(message)s": "المعامل %(argument_name)s: %(message)s",
    "invalid %(type)s value: %(value)r": "قيمة %(type)s غير صالحة: %(value)r",
    "one of the arguments %s is required": "أحد المعاملات التالية مطلوب: %s",
    "not allowed with argument %s": "لا يجتمع مع المعامل %s",
    "ambiguous option: %(option)s could match %(matches)s": "خيار ملتبس: %(option)s قد يعني %(matches)s",
    "ignored explicit argument %r": "هذا الخيار لا يأخذ قيمة: %r",
    "unknown parser %(parser_name)r (choices: %(choices)s)": "أمر غير معروف %(parser_name)r (المتاح: %(choices)s)",
    "can't open '%(filename)s': %(error)s": "تعذّر فتح '%(filename)s': %(error)s",
}
# ngettext ids (singular, plural) -> Arabic, one form for every count
_AR_PLURAL = {
    ("expected %s argument", "expected %s arguments"): "عدد القيم المطلوب: %s",
}
# "both": headings and messages carry the Arabic and the English once each; a placeholder appears only once, so the
# English text keeps it and the Arabic is a label in front of it. "usage: " stays English (it starts the help).
_HEADINGS = ("positional arguments", "options", "optional arguments", "subcommands")
_HELP_ACTIONS = ("show this help message and exit", "show program's version number and exit")


def _both(msgid: str) -> str | None:
    ar = _AR.get(msgid)
    if ar is None or msgid == "usage: ":
        return None
    if msgid in _HEADINGS:
        return f"{ar} / {msgid}"
    if msgid in _HELP_ACTIONS:
        return f"{ar}\n{msgid}"
    if msgid == "%(prog)s: error: %(message)s\n":
        return "%(prog)s: خطأ / error: %(message)s\n"
    if msgid == "%(prog)s: warning: %(message)s\n":
        return "%(prog)s: تحذير / warning: %(message)s\n"
    if msgid in ("argument %(argument_name)s: %(message)s", "can't open '%(filename)s': %(error)s"):
        return None                         # a frame around another message: English, the message inside is bilingual
    if msgid == "invalid %(type)s value: %(value)r":
        return "قيمة غير صالحة / " + msgid
    label = ar.split(":")[0].split(" %")[0].strip()
    return f"{label} / {msgid}"


_BOTH = {k: v for k, v in ((k, _both(k)) for k in _AR) if v is not None}


def pick(lang: str, ar: str, en: str) -> str:
    """The help text for ``lang``: ``ar``, ``en``, or both (Arabic line, then English line)."""
    if lang == "ar":
        return ar
    if lang == "both":
        return f"{ar}\n{en}" if ar != en else ar
    return en


def help_lang(argv, default: str = "en", choices=HELP_LANGS) -> str:
    """The language named by ``--lang X`` / ``--lang=X`` in ``argv`` (looked up before the parser exists, so that
    ``--help`` itself is localized), else ``default``."""
    value = None
    argv = list(argv or [])
    for i, a in enumerate(argv):
        if a == "--":
            break
        if a == "--lang" and i + 1 < len(argv):
            value = argv[i + 1]
        elif a.startswith("--lang="):
            value = a[7:]
    return value if value in choices else default


LANG_VARS = ("VULNSCAN_LANG", "KASHIF_LANG")     # both name the language of every command; the first set one wins


def env_lang(default: str = "en", environ=None) -> str:
    """``VULNSCAN_LANG`` (or ``KASHIF_LANG``) when it names a language, else ``default``."""
    env = os.environ if environ is None else environ
    for var in LANG_VARS:
        value = (env.get(var) or "").strip().lower()
        if value in HELP_LANGS:
            return value
    return default


def lang_from_env(environ=None) -> str:
    """The language named by ``VULNSCAN_LANG`` or ``KASHIF_LANG`` (the first one set): "ar" (also "ar_EG.UTF-8"),
    "en", "both", or "" when neither names one. Every command honours both variables, in this order."""
    env = os.environ if environ is None else environ
    for var in LANG_VARS:
        value = (env.get(var) or "").strip().lower()
        if value.startswith(("ar", "en")) or value == "both":
            return value[:2] if value != "both" else value
    return ""


def usage_prefix(lang: str) -> str:
    return _AR["usage: "] if lang == "ar" else "usage: "


class HelpFormatter(argparse.HelpFormatter):
    """argparse's formatter, keeping the line breaks of a bilingual help text: each line is wrapped on its own."""

    def _split_lines(self, text, width):
        out: list[str] = []
        for part in text.split("\n"):
            part = " ".join(part.split())
            out += textwrap.wrap(part, width, break_on_hyphens=False) or [""]     # never split "--list-formats"
        return out

    def _fill_text(self, text, width, indent):
        return "\n".join(textwrap.fill(" ".join(part.split()), width, initial_indent=indent, subsequent_indent=indent,
                                        break_on_hyphens=False) if part.strip() else ""
                         for part in text.split("\n"))


class RawDescriptionHelpFormatter(HelpFormatter):
    """Like :class:`HelpFormatter`, with the description and epilog printed as written (aligned tables)."""

    def _fill_text(self, text, width, indent):
        return "".join(indent + line for line in text.splitlines(keepends=True))


@contextlib.contextmanager
def localized_argparse(lang: str):
    """Within the block, argparse's own text (headings, usage prefix, errors) is in ``lang`` ("ar", "both"; any other
    value leaves English). Build the parser, parse and print help inside the block: argparse reads the headings
    when the parser is created and the rest when it prints."""
    table = _AR if lang == "ar" else _BOTH if lang == "both" else None
    orig, orig_n = getattr(argparse, "_", None), getattr(argparse, "ngettext", None)
    if table is None or not callable(orig):
        yield
        return

    def gettext(message):
        hit = table.get(message)
        return hit if hit is not None else orig(message)

    def ngettext(singular, plural, n):
        ar = _AR_PLURAL.get((singular, plural))
        en = orig_n(singular, plural, n) if callable(orig_n) else (singular if n == 1 else plural)
        if ar is None:
            return en
        return ar if lang == "ar" else f"{ar.split(':')[0]} / {en}"

    argparse._ = gettext
    if callable(orig_n):
        argparse.ngettext = ngettext
    try:
        yield
    finally:
        argparse._ = orig
        if callable(orig_n):
            argparse.ngettext = orig_n


# ------------------------------------------------------------------------------------------------ count phrases
# A number and the noun that agrees with it, for the messages of the command line: "{n:findings}" in a message
# template prints "نتيجة واحدة" / "نتيجتان" / "3 نتائج" / "11 نتيجةً" / "100 نتيجة" in Arabic and "1 finding" /
# "3 findings" in English (Arabic forms by vulnscan/i18n/plural.py). Each entry: the five Arabic forms (one, two,
# few, many, other), then the English singular and plural; "{n}" is the number. An "_obl" entry is the same noun
# after a preposition or as an object, where only the dual changes (يومين, not يومان).
NOUNS: dict[str, tuple[tuple[str, str, str, str, str], str, str]] = {
    "findings": (("نتيجة واحدة", "نتيجتان", "{n} نتائج", "{n} نتيجةً", "{n} نتيجة"), "{n} finding", "{n} findings"),
    "findings_obl": (("نتيجة واحدة", "نتيجتين", "{n} نتائج", "{n} نتيجةً", "{n} نتيجة"), "{n} finding", "{n} findings"),
    "triaged": (("نتيجة مفروزة واحدة", "نتيجتان مفروزتان", "{n} نتائج مفروزة", "{n} نتيجةً مفروزةً",
                 "{n} نتيجة مفروزة"), "{n} triaged finding", "{n} triaged findings"),
    "fixed_obl": (("نتيجة مُصلَحة واحدة", "نتيجتين مُصلَحتين", "{n} نتائج مُصلَحة", "{n} نتيجةً مُصلَحةً",
                   "{n} نتيجة مُصلَحة"), "{n} fixed finding", "{n} fixed findings"),
    "more_findings": (("نتيجة إضافية واحدة", "نتيجتان إضافيتان", "{n} نتائج إضافية", "{n} نتيجةً إضافيةً",
                       "{n} نتيجة إضافية"), "{n} more finding", "{n} more findings"),
    "new_findings": (("نتيجة جديدة واحدة", "نتيجتان جديدتان", "{n} نتائج جديدة", "{n} نتيجةً جديدةً",
                      "{n} نتيجة جديدة"), "{n} new finding", "{n} new findings"),
    "open_findings": (("نتيجة مفتوحة واحدة", "نتيجتان مفتوحتان", "{n} نتائج مفتوحة", "{n} نتيجةً مفتوحةً",
                       "{n} نتيجة مفتوحة"), "{n} open finding", "{n} open findings"),
    "days": (("يوم واحد", "يومان", "{n} أيام", "{n} يومًا", "{n} يوم"), "{n} day", "{n} days"),
    "days_obl": (("يوم واحد", "يومين", "{n} أيام", "{n} يومًا", "{n} يوم"), "{n} day", "{n} days"),
    "seconds_obl": (("ثانية واحدة", "ثانيتين", "{n} ثوانٍ", "{n} ثانيةً", "{n} ثانية"), "{n} second", "{n} seconds"),
    "files": (("ملف واحد", "ملفان", "{n} ملفات", "{n} ملفًا", "{n} ملف"), "{n} file", "{n} files"),
    "files_obl": (("ملف واحد", "ملفين", "{n} ملفات", "{n} ملفًا", "{n} ملف"), "{n} file", "{n} files"),
    "fixture_files": (("ملف اختبار واحد", "ملفا اختبار", "{n} ملفات اختبار", "{n} ملفَّ اختبار", "{n} ملف اختبار"),
                      "{n} fixture file", "{n} fixture files"),
    "source_files": (("ملف مصدري واحد", "ملفان مصدريان", "{n} ملفات مصدرية", "{n} ملفًا مصدريًا", "{n} ملف مصدري"),
                     "{n} source file", "{n} source files"),
    "python_files_obl": (("ملف بايثون واحد", "ملفَّي بايثون", "{n} ملفات بايثون", "{n} ملفَّ بايثون",
                          "{n} ملف بايثون"), "{n} Python file", "{n} Python files"),
    "warnings": (("تحذير واحد", "تحذيران", "{n} تحذيرات", "{n} تحذيرًا", "{n} تحذير"), "{n} warning", "{n} warnings"),
    "errors": (("خطأ واحد", "خطآن", "{n} أخطاء", "{n} خطأً", "{n} خطأ"), "{n} error", "{n} errors"),
    "rules": (("قاعدة واحدة", "قاعدتان", "{n} قواعد", "{n} قاعدةً", "{n} قاعدة"), "{n} rule", "{n} rules"),
    "builtin_rules": (("قاعدة مدمجة واحدة", "قاعدتان مدمجتان", "{n} قواعد مدمجة", "{n} قاعدةً مدمجةً", "{n} قاعدة مدمجة"),
                      "{n} built-in rule", "{n} built-in rules"),
    "dataflow_rules": (("قاعدة واحدة لتدفق البيانات وAPEX", "قاعدتان لتدفق البيانات وAPEX",
                        "{n} قواعد لتدفق البيانات وAPEX", "{n} قاعدةً لتدفق البيانات وAPEX",
                        "{n} قاعدة لتدفق البيانات وAPEX"), "{n} data-flow and APEX rule", "{n} data-flow and APEX rules"),
    "vql_queries": (("استعلام مدمج واحد بلغة VQL", "استعلامان مدمجان بلغة VQL", "{n} استعلامات مدمجة بلغة VQL",
                     "{n} استعلامًا مدمجًا بلغة VQL", "{n} استعلام مدمج بلغة VQL"),
                    "{n} built-in VQL query", "{n} built-in VQL queries"),
    "fingerprints": (("بصمة واحدة", "بصمتان", "{n} بصمات", "{n} بصمةً", "{n} بصمة"), "{n} fingerprint", "{n} fingerprints"),
    "secrets": (("سرّ واحد", "سرّان", "{n} أسرار", "{n} سرًّا", "{n} سرّ"), "{n} secret", "{n} secrets"),
    "conflicts": (("تعارض واحد", "تعارضان", "{n} تعارضات", "{n} تعارضًا", "{n} تعارض"),
                  "{n} conflicting edit", "{n} conflicting edits"),
    "expectations": (("توقّع واحد", "توقّعان", "{n} توقّعات", "{n} توقّعًا", "{n} توقّع"),
                     "{n} expectation", "{n} expectations"),
    "known_gaps": (("فجوة معروفة واحدة", "فجوتان معروفتان", "{n} فجوات معروفة", "{n} فجوةً معروفةً",
                    "{n} فجوة معروفة"), "{n} known gap", "{n} known gaps"),
    "mid_steps": (("خطوة وسيطة واحدة", "خطوتان وسيطتان", "{n} خطوات وسيطة", "{n} خطوةً وسيطةً", "{n} خطوة وسيطة"),
                  "{n} intermediate step", "{n} intermediate steps"),
    "fingerprints_obl": (("بصمة واحدة", "بصمتين", "{n} بصمات", "{n} بصمةً", "{n} بصمة"),
                         "{n} fingerprint", "{n} fingerprints"),
    "characters_obl": (("محرف واحد", "محرفين", "{n} محارف", "{n} محرفًا", "{n} محرف"),
                       "{n} character", "{n} characters"),
    "chars": (("حرف واحد", "حرفان", "{n} أحرف", "{n} حرفًا", "{n} حرف"), "{n} character", "{n} characters"),
    "chars_obl": (("حرف واحد", "حرفين", "{n} أحرف", "{n} حرفًا", "{n} حرف"), "{n} character", "{n} characters"),
    "changed_lines": (("سطر متغيّر واحد", "سطران متغيّران", "{n} أسطر متغيّرة", "{n} سطرًا متغيّرًا", "{n} سطر متغيّر"),
                      "{n} changed line", "{n} changed lines"),
    "levels_obl": (("مستوى واحد", "مستويين", "{n} مستويات", "{n} مستوىً", "{n} مستوى"), "{n} level", "{n} levels"),
    "values_obl": (("قيمة واحدة", "قيمتين", "{n} قيم", "{n} قيمةً", "{n} قيمة"), "{n} value", "{n} values"),
    "entries_obl": (("عنصر واحد", "عنصرين", "{n} عناصر", "{n} عنصرًا", "{n} عنصر"), "{n} entry", "{n} entries"),
    "entry_points": (("نقطة دخول واحدة", "نقطتا دخول", "{n} نقاط دخول", "{n} نقطةَ دخول", "{n} نقطة دخول"),
                     "{n} entry point", "{n} entry points"),
    "entry_points_obl": (("نقطة دخول واحدة", "نقطتي دخول", "{n} نقاط دخول", "{n} نقطةَ دخول", "{n} نقطة دخول"),
                         "{n} entry point", "{n} entry points"),
    "untrusted_params": (("مدخل واحد غير موثوق", "مدخلان غير موثوقين", "{n} مدخلات غير موثوقة",
                          "{n} مدخلًا غير موثوق", "{n} مدخل غير موثوق"),
                         "{n} untrusted parameter", "{n} untrusted parameters"),
    "conditions": (("شرط بوابة واحد", "شرطا بوابة", "{n} شروط بوابة", "{n} شرطَ بوابة", "{n} شرط بوابة"),
                   "{n} gate condition", "{n} gate conditions"),
    "scopes": (("نطاق واحد", "نطاقان", "{n} نطاقات", "{n} نطاقًا", "{n} نطاق"), "{n} scope", "{n} scopes"),
    "ignores": (("استثناء واحد", "استثناءان", "{n} استثناءات", "{n} استثناءً", "{n} استثناء"), "{n} ignore", "{n} ignores"),
    "decision_changes": (("تغيير واحد", "تغييران", "{n} تغييرات", "{n} تغييرًا", "{n} تغيير"),
                         "{n} decision change", "{n} decision changes"),
    "suppress_comments": (("تعليق كتم واحد", "تعليقا كتم", "{n} تعليقات كتم", "{n} تعليقَ كتم", "{n} تعليق كتم"),
                          "{n} inline suppression comment", "{n} inline suppression comments"),
}


def _whole(n) -> bool:
    """True for a whole number (int, integral float or a string of digits): only those take a singular or dual."""
    if isinstance(n, bool):
        return False
    if isinstance(n, int):
        return True
    if isinstance(n, float):
        return n.is_integer()
    return isinstance(n, str) and n.strip().lstrip("-").isdigit()


def count(n, noun: str, lang: str = "en", nouns=None) -> str:
    """``n`` with ``noun`` (a key of ``NOUNS`` or of ``nouns``) in the form that agrees with it, in ``lang``."""
    ar, one, many = (nouns or {}).get(noun) or NOUNS[noun]
    num = str(int(n)) if isinstance(n, float) and n.is_integer() else str(n)
    if lang == "ar":
        form = ar[FORMS.index(ar_category(n))] if _whole(n) else ar[-1]
        return form.replace("{n}", num)
    single = _whole(n) and abs(int(float(n))) == 1
    return (one if single else many).replace("{n}", num)


class _Counts(string.Formatter):
    def __init__(self, lang: str, nouns):
        super().__init__()
        self.lang, self.nouns = lang, nouns

    def format_field(self, value, format_spec):
        if format_spec in self.nouns or format_spec in NOUNS:
            return count(value, format_spec, self.lang, self.nouns)
        return super().format_field(value, format_spec)


def fmt(text: str, lang: str = "en", nouns=None, /, **kw) -> str:
    """``text.format(**kw)``, where a field written ``{n:noun}`` becomes the count phrase of ``noun`` (see NOUNS)."""
    return _Counts("ar" if lang == "ar" else "en", nouns or {}).format(text, **kw)
