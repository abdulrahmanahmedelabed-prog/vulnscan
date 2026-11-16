"""Small local corpus for the 1.1.0 accuracy round (engine end to end, offline).

Every case runs the real engine against a server on 127.0.0.1 started by the test: plain HTTP pages for the CSP and diff
cases, TLS servers with deliberately old configurations (TLS 1.0 only, NULL suites only, 1024-bit DHE only, a SHA-1
intermediate) for the TLS cases. Names resolve through the test-only resolver hook (``KASHIF_TEST_RESOLVE``); the test PKI
is generated per session with the ``openssl`` CLI and its root is the hook's CA (``KASHIF_TEST_CAFILE``). Nothing leaves
the machine; a case whose requirement the local OpenSSL lacks is skipped, never passed.
"""

from __future__ import annotations

import json
import pathlib
import shutil
import socket
import ssl
import subprocess
import threading
import warnings

HOST = "site.kashif.test"
PAGE = b"<!doctype html><html><head><title>Corpus</title></head><body><p>static page</p></body></html>"

# RFC 2409 Oakley group 2: the classic shared 1024-bit MODP prime (Logjam precomputation target)
OAKLEY2 = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD"
              "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
              "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16)


# ----------------------------------------------------------------------------------------------- PKI

def openssl() -> str | None:
    return shutil.which("openssl")


def _run(args: list[str], cwd: pathlib.Path) -> None:
    subprocess.run([openssl()] + args, cwd=cwd, check=True, capture_output=True, timeout=60)


def build_pki(wd: pathlib.Path) -> dict[str, pathlib.Path]:
    """Root (SHA-256), a SHA-256 and a SHA-1 intermediate, and a leaf under each for HOST, localhost and 127.0.0.1."""
    wd.mkdir(parents=True, exist_ok=True)
    (wd / "ca.ext").write_text("basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n"
                               "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n", encoding="ascii")
    (wd / "leaf.ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                                 "extendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n"
                                 f"subjectAltName=DNS:{HOST},DNS:localhost,IP:127.0.0.1\n", encoding="ascii")
    _run(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "root.key", "-out", "root.pem", "-days", "3650",
          "-sha256", "-subj", "/CN=Kashif Accuracy Corpus Root", "-addext", "basicConstraints=critical,CA:TRUE",
          "-addext", "keyUsage=critical,keyCertSign,cRLSign"], wd)
    out = {"root": wd / "root.pem"}
    for name, md in (("int", "sha256"), ("int-sha1", "sha1")):
        _run(["req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{name}.key", "-out", f"{name}.csr", "-subj",
              f"/CN=Kashif Accuracy Corpus Intermediate {md}"], wd)
        _run(["x509", "-req", "-in", f"{name}.csr", "-CA", "root.pem", "-CAkey", "root.key", "-CAcreateserial",
              "-out", f"{name}.pem", "-days", "1000", f"-{md}", "-extfile", "ca.ext"], wd)
        leaf = f"leaf-{name}"
        _run(["req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{leaf}.key", "-out", f"{leaf}.csr", "-subj",
              f"/CN={HOST}"], wd)
        _run(["x509", "-req", "-in", f"{leaf}.csr", "-CA", f"{name}.pem", "-CAkey", f"{name}.key", "-CAcreateserial",
              "-out", f"{leaf}.pem", "-days", "90", "-sha256", "-extfile", "leaf.ext"], wd)
        chain = wd / f"{leaf}-chain.pem"
        chain.write_bytes((wd / f"{leaf}.pem").read_bytes() + (wd / f"{name}.pem").read_bytes())
        out[name] = chain
        out[f"{name}-key"] = wd / f"{leaf}.key"
    out["dh1024"] = wd / "dh1024.pem"
    out["dh1024"].write_text(dh_params_pem(OAKLEY2, 2), encoding="ascii")
    return out


def _der_int(n: int) -> bytes:
    b = n.to_bytes((n.bit_length() + 8) // 8, "big")
    return b"\x02" + _der_len(len(b)) + b


def _der_len(n: int) -> bytes:
    if n < 128:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def dh_params_pem(p: int, g: int) -> str:
    """PKCS#3 DHParameter (``-----BEGIN DH PARAMETERS-----``) for a fixed prime: no slow parameter generation."""
    import base64
    body = _der_int(p) + _der_int(g)
    der = b"\x30" + _der_len(len(body)) + body
    b64 = base64.b64encode(der).decode("ascii")
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return "-----BEGIN DH PARAMETERS-----\n" + "\n".join(lines) + "\n-----END DH PARAMETERS-----\n"


# ----------------------------------------------------------------------------------------------- servers

def server_context(pki: dict, profile: str) -> ssl.SSLContext:
    """A server SSLContext for one corpus profile; raises ssl.SSLError/ValueError when this OpenSSL refuses it."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    chain, key = pki["int"], pki["int-key"]
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        if profile == "tls10":
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1
        elif profile == "null":
            ctx.set_ciphers("eNULL:@SECLEVEL=0")
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        elif profile == "dhe1024":
            ctx.set_ciphers("DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:@SECLEVEL=0")
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_dh_params(str(pki["dh1024"]))
        elif profile == "sha1int":
            chain, key = pki["int-sha1"], pki["int-sha1-key"]
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        elif profile != "good":
            raise ValueError(profile)
    ctx.load_cert_chain(str(chain), str(key))
    return ctx


def http_reply(status: str = "200 OK", headers=(), body: bytes = PAGE) -> bytes:
    lines = [f"HTTP/1.1 {status}"] + [f"{k}: {v}" for k, v in headers]
    lines += [f"Content-Length: {len(body)}", "Connection: close"]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body


class TLSServer:
    """HTTPS on 127.0.0.1 with a given SSLContext; every request gets ``reply``. Raw probes that never finish a
    handshake are simply dropped."""

    def __init__(self, ctx: ssl.SSLContext, reply: bytes):
        self.ctx, self.reply = ctx, reply
        self.requests: list[bytes] = []
        self.handshakes = 0
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(64)
        self._sock.settimeout(0.2)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def url(self, path: str = "/") -> str:
        return f"https://{HOST}:{self.port}{path}"

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(5)
        try:
            with self.ctx.wrap_socket(conn, server_side=True) as tls:
                self.handshakes += 1
                data = b""
                while b"\r\n\r\n" not in data and len(data) < 65536:
                    chunk = tls.recv(4096)
                    if not chunk:
                        return
                    data += chunk
                self.requests.append(data)
                tls.sendall(self.reply)
        except (OSError, ssl.SSLError, ValueError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def close(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=2)


def resolver_map(path: pathlib.Path) -> pathlib.Path:
    rmap = {"version": 1, "hosts": {HOST: {"status": "ok", "addresses": ["127.0.0.1"], "public": True}},
            "default": {"status": "ok", "addresses": ["127.0.0.1"], "public": True}}
    path.write_text(json.dumps(rmap), encoding="utf-8")
    return path
