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
import textwrap

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


def env_lang(default: str = "en") -> str:
    """``VULNSCAN_LANG`` (or ``KASHIF_LANG``) when it names a language, else ``default``."""
    for var in ("VULNSCAN_LANG", "KASHIF_LANG"):
        value = (os.environ.get(var) or "").strip().lower()
        if value in HELP_LANGS:
            return value
    return default


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
