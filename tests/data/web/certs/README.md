# TLS test fixtures (WP10)

Test-only material for `tests/web/test_tls_*.py`, `tests/web/tls_stub.py` and the corpus (`bench/web`). Every private
key here is a throw-away test key; none is used anywhere else.

| File | What it is | Origin |
|---|---|---|
| `root.pem`, `int.pem` | "Kashif Test Root" / "Kashif Test Intermediate" (RSA 2048, 2026-11 .. 2046) | `make_fixtures.py` |
| `leaf.pem`, `leaf.key` | leaf for `localhost` + `127.0.0.1`, AIA (OCSP, caIssuers), CRL DP, DV policy | `make_fixtures.py` |
| `muststaple.pem` | same key, TLS feature status_request (OCSP must-staple) | `make_fixtures.py` |
| `ecleaf.pem` | ECDSA P-256 leaf, signed sha384WithRSA | `make_fixtures.py` |
| `sha1leaf.pem`, `rsa1024leaf.pem` | SHA-1 signature; RSA-1024 key | `make_fixtures.py` |
| `cnonly.pem`, `noaki.pem` | no subjectAltName (CN only); no Authority Key Identifier (D19) | `make_fixtures.py` |
| `wildcard.pem`, `manysan.pem` | `*.kashif.test`; 105 SAN entries | `make_fixtures.py` |
| `clientauth.pem` | EKU clientAuth only (verify code 26) | `make_fixtures.py` |
| `selfsigned.pem` | self-signed leaf | `make_fixtures.py` |
| `roca-leaf.pem`, `roca-leaf.key` | self-signed RSA-2048 whose primes have the Infineon RSALib structure p = k·M + 65537^a mod M (ROCA fingerprint); served by the corpus case `tls-roca` | `make_fixtures.py` |
| `fermat-leaf.pem` | RSA key with close primes (Fermat-factorable, CVE-2022-26320); the key was discarded | `make_fixtures.py` |
| `ocsp-good.der`, `ocsp-revoked.der` | OCSP responses for `leaf.pem`, signed by the intermediate | `make_fixtures.py` |
| `roca-sample-positive.pem`, `roca-sample-negative.pem` | `cert04.pem` / `cert01.pem` of the ROCA authors' test data | crocs-muni/roca, MIT licence, © 2017 CRoCS, EnigmaBridge Ltd. |
| `sctleaf.pem` | lab certificate with two embedded SCTs (fabricated log ids 00..1f, 20..3f) | Kashif research lab |
| `tls-flights.json` | server replies (raw bytes) to Kashif ClientHellos, recorded from OpenSSL 3.0.13 `s_server` and a Python 3.13 / OpenSSL 3.5.9 server | Kashif research lab |

Regenerate the `make_fixtures.py` files with `python tests/data/web/certs/make_fixtures.py` (needs the openssl CLI).
