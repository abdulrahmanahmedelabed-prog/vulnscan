"""Regenerate the static TLS test fixtures in this directory (WP10; maintainers only, needs the openssl CLI).

    python tests/data/web/certs/make_fixtures.py

Every key is a throw-away test key. Validity is long (2026-11-01 .. 2046) so that tests that run a real TLS server keep
working for years; tests that judge dates use fixed clocks. Not regenerated here (kept as they are): the two ROCA
reference certificates (crocs-muni/roca test data, MIT), the lab certificate with embedded SCTs and tls-flights.json.
"""
import base64
import os
import random
import shutil
import subprocess
import sys
import tempfile

OUT = os.path.dirname(os.path.abspath(__file__))
START, END = "20261101000000Z", "20461101000000Z"
rng = random.SystemRandom()


def run(args, cwd, inp=None):
    r = subprocess.run(["openssl", *args], cwd=cwd, capture_output=True, input=inp)
    if r.returncode:
        raise SystemExit(f"openssl {' '.join(args)}: {r.stderr.decode()}")
    return r.stdout


def write(wd, name, text):
    with open(os.path.join(wd, name), "w", encoding="ascii", newline="\n") as fh:
        fh.write(text)


CA_CNF = """[ req ]
distinguished_name = dn
prompt = no
[ dn ]
CN = {cn}
[ v3_ca ]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
"""


def ca_db(wd):
    write(wd, "index.txt", "")
    write(wd, "serial", "1000\n")
    write(wd, "ca.cnf", """[ ca ]
default_ca = CA
[ CA ]
dir = .
database = index.txt
serial = serial
default_md = sha256
new_certs_dir = .
policy = any
unique_subject = no
copy_extensions = none
[ any ]
commonName = supplied
""")


def sign(wd, issuer, name, key, cn, ext, md="sha256", start=START, end=END, selfsign=False):
    write(wd, f"{name}.ext", "[ v3 ]\n" + ext + "\n")
    write(wd, f"{name}.req.cnf", f"[ req ]\ndistinguished_name = dn\nprompt = no\n[ dn ]\nCN = {cn}\n")
    run(["req", "-new", "-key", key, "-config", f"{name}.req.cnf", "-out", f"{name}.csr"], wd)
    if selfsign:
        run(["x509", "-req", "-in", f"{name}.csr", "-signkey", key, "-out", f"{name}.pem", f"-{md}", "-days", "7300",
             "-extfile", f"{name}.ext", "-extensions", "v3", "-set_serial", str(rng.getrandbits(120))], wd)
        return
    run(["ca", "-batch", "-config", "ca.cnf", "-cert", f"{issuer}.pem", "-keyfile", f"{issuer}.key", "-in", f"{name}.csr",
         "-out", f"{name}.pem", "-md", md, "-startdate", start, "-enddate", end, "-extfile", f"{name}.ext",
         "-extensions", "v3", "-notext"], wd)


LEAF_EXT = """basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
"""


# ------------------------------------------------------------------ RSA keys with chosen primes
def is_probable_prime(n, rounds=40):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = rng.randrange(2, n - 2)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def der_int(v):
    b = v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big")
    return b"\x02" + der_len(len(b)) + b


def der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def rsa_pem(p, q, e=65537):
    n = p * q
    lam = (p - 1) * (q - 1)
    d = pow(e, -1, lam)
    body = b"".join(der_int(x) for x in (0, n, e, d, p, q, d % (p - 1), d % (q - 1), pow(q, -1, p)))
    der = b"\x30" + der_len(len(body)) + body
    b64 = base64.b64encode(der).decode()
    return "-----BEGIN RSA PRIVATE KEY-----\n" + "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64)) + \
        "\n-----END RSA PRIVATE KEY-----\n"


def primes_upto(n):
    out = []
    for c in range(2, n + 1):
        if all(c % p for p in out if p * p <= c):
            out.append(c)
    return out


def roca_prime(bits, M):
    """p = k*M + (65537^a mod M): the structure of Infineon RSALib primes (CVE-2017-15361)."""
    while True:
        a = rng.getrandbits(60)
        r = pow(65537, a, M)
        lo = (1 << (bits - 1)) // M + 1
        hi = ((1 << bits) - 1) // M
        for _ in range(200):
            k = rng.randrange(lo, hi)
            p = k * M + r
            if p.bit_length() == bits and is_probable_prime(p):
                return p


def roca_key():
    M = 1
    for p in primes_upto(701)[:126]:       # the primorial RSALib used for 2048-bit keys
        M *= p
    while True:
        p, q = roca_prime(1024, M), roca_prime(1024, M)
        if (p * q).bit_length() == 2048 and p != q:
            return p, q


def fermat_key():
    while True:
        base = rng.getrandbits(1024) | (1 << 1023) | 1
        p = base
        while not is_probable_prime(p):
            p += 2
        q = p + 2 + 2 * rng.getrandbits(20)
        while not is_probable_prime(q):
            q += 2
        if ((p - 1) * (q - 1)) % 65537:
            return p, q


def main():
    wd = tempfile.mkdtemp(prefix="kashif-wp10-certs-")
    try:
        ca_db(wd)
        run(["genrsa", "-out", "root.key", "2048"], wd)
        write(wd, "root.cnf", CA_CNF.format(cn="Kashif Test Root"))
        run(["req", "-x509", "-new", "-key", "root.key", "-config", "root.cnf", "-extensions", "v3_ca", "-days", "7300",
             "-set_serial", "4096", "-out", "root.pem"], wd)
        run(["genrsa", "-out", "int.key", "2048"], wd)
        sign(wd, "root", "int", "int.key", "Kashif Test Intermediate",
             "basicConstraints = critical,CA:TRUE,pathlen:0\nkeyUsage = critical,keyCertSign,cRLSign\n"
             "subjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid\n")
        aia = ("authorityInfoAccess = OCSP;URI:http://ocsp.kashif.test,caIssuers;URI:http://ca.kashif.test/int.der\n"
               "crlDistributionPoints = URI:http://crl.kashif.test/int.crl\n"
               "certificatePolicies = 2.23.140.1.2.1\n")
        san = "subjectAltName = DNS:localhost,IP:127.0.0.1\n"
        run(["genrsa", "-out", "leaf.key", "2048"], wd)
        sign(wd, "int", "leaf", "leaf.key", "localhost", LEAF_EXT + san + aia)
        sign(wd, "int", "muststaple", "leaf.key", "localhost",
             LEAF_EXT + san + aia + "1.3.6.1.5.5.7.1.24 = DER:30:03:02:01:05\n")
        run(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "ec.key"], wd)
        sign(wd, "int", "ecleaf", "ec.key", "localhost", LEAF_EXT.replace(",keyEncipherment", "") + san, md="sha384")
        sign(wd, "int", "sha1leaf", "leaf.key", "localhost", LEAF_EXT + san, md="sha1")
        run(["genrsa", "-out", "k1024.key", "1024"], wd)
        sign(wd, "int", "rsa1024leaf", "k1024.key", "localhost", LEAF_EXT + san)
        sign(wd, "int", "cnonly", "leaf.key", "localhost", LEAF_EXT)
        sign(wd, "int", "noaki", "leaf.key", "localhost", LEAF_EXT.replace("authorityKeyIdentifier = keyid\n",
                                                                            "authorityKeyIdentifier = none\n") + san)
        sign(wd, "int", "wildcard", "leaf.key", "*.kashif.test",
             LEAF_EXT + "subjectAltName = DNS:*.kashif.test,DNS:kashif.test\n")
        many = ",".join(f"DNS:h{i}.kashif.test" for i in range(105))
        sign(wd, "int", "manysan", "leaf.key", "h0.kashif.test", LEAF_EXT + f"subjectAltName = {many}\n")
        sign(wd, "int", "clientauth", "leaf.key", "localhost",
             LEAF_EXT.replace("serverAuth", "clientAuth") + san)
        sign(wd, None, "selfsigned", "leaf.key", "localhost", LEAF_EXT.replace("authorityKeyIdentifier = keyid\n", "")
             + san, selfsign=True)
        # ROCA-structured key (self-signed; key shipped for the corpus server, WP16 tls-roca)
        p, q = roca_key()
        write(wd, "roca-leaf.key", rsa_pem(p, q))
        sign(wd, None, "roca-leaf", "roca-leaf.key", "tls-roca.tls.kashif.test",
             LEAF_EXT.replace("authorityKeyIdentifier = keyid\n", "")
             + "subjectAltName = DNS:tls-roca.tls.kashif.test,DNS:localhost,IP:127.0.0.1\n", selfsign=True)
        # Fermat-factorable key (close primes, CVE-2022-26320): certificate only, the key is discarded
        p, q = fermat_key()
        write(wd, "fermat.key", rsa_pem(p, q))
        sign(wd, None, "fermat-leaf", "fermat.key", "localhost", LEAF_EXT.replace("authorityKeyIdentifier = keyid\n", "")
             + san, selfsign=True)
        # OCSP responses for the leaf, signed by the intermediate: good, then revoked
        serial = run(["x509", "-in", "leaf.pem", "-noout", "-serial"], wd).decode().strip().split("=", 1)[1]
        run(["ocsp", "-issuer", "int.pem", "-cert", "leaf.pem", "-reqout", "req.der", "-no_nonce"], wd)
        run(["ocsp", "-index", "index.txt", "-rsigner", "int.pem", "-rkey", "int.key", "-CA", "int.pem",
             "-reqin", "req.der", "-respout", "ocsp-good.der", "-ndays", "7"], wd)
        run(["ca", "-config", "ca.cnf", "-revoke", "leaf.pem", "-keyfile", "int.key", "-cert", "int.pem"], wd)
        run(["ocsp", "-index", "index.txt", "-rsigner", "int.pem", "-rkey", "int.key", "-CA", "int.pem",
             "-reqin", "req.der", "-respout", "ocsp-revoked.der", "-ndays", "7"], wd)
        os.makedirs(OUT, exist_ok=True)
        for f in ("root.pem", "int.pem", "leaf.pem", "leaf.key", "muststaple.pem", "ecleaf.pem", "sha1leaf.pem",
                  "rsa1024leaf.pem", "cnonly.pem", "noaki.pem", "wildcard.pem", "manysan.pem", "clientauth.pem",
                  "selfsigned.pem", "roca-leaf.pem", "roca-leaf.key", "fermat-leaf.pem", "ocsp-good.der",
                  "ocsp-revoked.der"):
            shutil.copy(os.path.join(wd, f), os.path.join(OUT, f))
        print("leaf serial", serial)
    finally:
        shutil.rmtree(wd, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
