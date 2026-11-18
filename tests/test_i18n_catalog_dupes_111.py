"""No Arabic string is given two different English translations across the catalog modules (the first one loaded
would silently win)."""
from vulnscan.i18n import _MODULES


def test_no_conflicting_translations_across_catalogs():
    seen: dict[str, tuple[str, str]] = {}
    conflicts = []
    for m in _MODULES:
        for ar, en in m.CATALOG.items():
            if ar in seen and seen[ar][1] != en:
                conflicts.append((ar, seen[ar][0], m.__name__))
            seen.setdefault(ar, (m.__name__, en))
    assert conflicts == []
