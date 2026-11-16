"""TLS and certificates (spec §2.8, WP10).

* :func:`collect` — pipeline step 4 (§4.3, engine only): handshakes and raw ClientHello probes for every https host the
  entry or counterpart chain reached, through the scan's Fetcher (SSRF guard, DNS pin, proxy tunnel, ≤ 5
  handshakes/s/IP). Fills ``ctx.tls`` (shape documented in :mod:`.probe`).
* :func:`run` with :data:`CHECKS` — the stage-2 check module (§4.2 ``CheckModule``): a pure function of ``ctx.tls``.
* :func:`ssllabs_grade` — the SSL Labs-compatible grade for grade.py (§3.4 c).

Sub-modules: :mod:`.raw` (ClientHello builder and plaintext reply parser), :mod:`.x509` (DER reader, SCT list, OCSP,
weak-key tests), :mod:`.probe` (orchestration), :mod:`.assess` (rules, grade, Mozilla conformance).
"""

from __future__ import annotations

from .assess import CHECKS, ssllabs_grade
from .assess import run as run
from .probe import collect, scan_host

__all__ = ["CHECKS", "run", "collect", "scan_host", "ssllabs_grade"]
