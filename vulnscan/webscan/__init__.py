"""Kashif passive web scanner (1.1.0): ``scan(target, options) -> WebScanResult``.

The package is imported lazily: ``vulnscan.i18n`` imports ``webscan.rules`` (through ``cat_web2``) to build its
catalogue, so importing this package must not pull in the engine, the fetcher or any check module. ``scan`` loads
the engine on first use. See spec §4 for the module map and the frozen interfaces in ``webscan.types``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:   # pragma: no cover
    from .types import ScanOptions, WebScanResult


def scan(target: str, options: "ScanOptions | None" = None) -> "WebScanResult":
    """Run a passive scan of ``target`` (an http(s) URL the user is authorized to scan) and return the result."""
    from .engine import scan as _scan   # WP15a
    return _scan(target, options)


__all__ = ["scan"]
