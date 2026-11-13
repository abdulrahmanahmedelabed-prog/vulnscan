"""TLS material and server contexts for the Kashif passive web corpus (spec §5.2).

Certificates are generated at run time with the ``openssl`` command-line tool (OpenSSL 1.1.1+, 3.x or LibreSSL), so the
"good" certificates are always short-lived and fresh and nothing in the repository ages. Every key is a throw-away test key
created in a temporary directory; nothing is written into the repository. When the tool is missing, :func:`build` raises
:class:`TLSUnavailable` and the corpus marks every https case ``skipped`` (never passed).

Layout of the test PKI::

    Kashif Corpus Test Root (self-signed CA)          <- the only file given to Kashif's test-only CA hook
      Kashif Corpus Test Intermediate
        shared leaf: *.<group>.kashif.test, *.kashif-third.test, *.s3.amazonaws.com, kashif-corpus.dev, IP 127.0.0.1
        one leaf per certificate profile below (expired, not yet valid, wrong host, SHA-1, RSA-1024, …)

Profiles that need different protocol settings (TLS 1.0 accepted, modern-only cipher list) get their own listener; profiles
that only differ in the certificate or the chain share one https listener and are selected by SNI.
"""

from __future__ import annotations

import datetime as _dt
import importlib.util
import os
import pathlib
import shutil
import socket
import ssl
import subprocess
import tempfile
import warnings
from dataclasses import dataclass, field

ROOT = pathlib.Path(__file__).resolve().parents[2]
STUB_PATH = ROOT / "tests" / "web" / "tls_stub.py"       # WP10's raw-probe stub (recorded server flights)


class TLSUnavailable(RuntimeError):
    """The local machine cannot produce the TLS material (no openssl CLI or it failed)."""


@dataclass(frozen=True)
class Profile:
    """How one TLS case is served."""
    cert: str = "shared"                 # certificate kind, see CERT_KINDS
    chain: str = "leaf+int"              # leaf | leaf+int | leaf+root+int | leaf+int+root
    own_port: bool = False               # needs its own listener (protocol/cipher settings differ)
    min_version: str | None = None       # "TLSv1", "TLSv1_2", ...
    max_version: str | None = None
    ciphers: str | None = None
    weak: bool = False                   # load with @SECLEVEL=0 (SHA-1, RSA-1024, TLS 1.0)
    stub: str | None = None              # raw-probe stub flight profile (tests/web/tls_stub.py), passthrough to the real server
    second_ip: bool = False              # also listen on 127.0.0.2 with a different configuration (WEB715)


# Certificate kinds: validity relative to now (days), extra properties.
CERT_KINDS: dict[str, dict] = {
    "shared": {"start": -1, "end": 44},
    "good": {"start": -1, "end": 44},
    "expired": {"start": -100, "end": -10},
    "notyet": {"start_abs": "20900101000000Z", "end_abs": "20900301000000Z"},
    "selfsigned": {"start": -1, "end": 44, "self": True},
    "wronghost": {"start": -1, "end": 44, "sans": ["DNS:somewhere-else.kashif.test"]},
    "sha1": {"start": -1, "end": 44, "md": "sha1"},
    "rsa1024": {"start": -1, "end": 44, "bits": 1024},
    "noaki": {"start": -1, "end": 44, "aki": False},
    "muststaple": {"start": -1, "end": 44, "ext": ["1.3.6.1.5.5.7.1.24 = DER:30:03:02:01:05"]},
    "cnonly": {"start": -1, "end": 44, "sans": []},
    "days400": {"start": -1, "end": 399},
    "days90left25": {"start": -65, "end": 25},
    "days90left5": {"start": -85, "end": 5},
    "wrongeku": {"start": -1, "end": 44, "eku": "clientAuth"},
}

PROFILES: dict[str, Profile] = {
    "good": Profile("good"),
    "expired": Profile("expired"),
    "notyet": Profile("notyet"),
    "selfsigned": Profile("selfsigned", chain="leaf"),
    "wronghost": Profile("wronghost"),
    "leafonly": Profile("good", chain="leaf"),
    "wrongorder": Profile("good", chain="leaf+root+int"),
    "withroot": Profile("good", chain="leaf+int+root"),
    "sha1": Profile("sha1", weak=True, own_port=True),
    "rsa1024": Profile("rsa1024", weak=True, own_port=True),
    "noaki": Profile("noaki"),
    "muststaple": Profile("muststaple"),
    "cnonly": Profile("cnonly"),
    "days400": Profile("days400"),
    "days90left25": Profile("days90left25"),
    "days90left5": Profile("days90left5"),
    "wrongeku": Profile("wrongeku"),
    "tls12only": Profile("good", own_port=True, max_version="TLSv1_2"),
    "tls10": Profile("good", own_port=True, min_version="TLSv1", max_version="TLSv1_2", weak=True),
    "modern": Profile("good", own_port=True, min_version="TLSv1_2",
                      ciphers="ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!eNULL"),
    "twoips": Profile("good", own_port=True, second_ip=True),
    "stub-sslv3": Profile("good", own_port=True, stub="sslv3"),
    "stub-rc4": Profile("good", own_port=True, stub="rc4"),
    "stub-compression": Profile("good", own_port=True, stub="compression"),
    "stub-noreneg": Profile("good", own_port=True, stub="no_renegotiation_info"),
    "stub-timeout": Profile("good", own_port=True, stub="timeout"),
    "stub-dhe1024": Profile("good", own_port=True, stub="dhe1024_pt"),
    "stub-higher": Profile("good", own_port=True, stub="higher_pt"),
    "stub-nopq": Profile("good", own_port=True, stub="nopq_pt"),
    "stub-pq": Profile("good", own_port=True, stub="pq_pt"),
    "roca": Profile("roca", own_port=True, weak=True),      # needs a fixture from WP10 (tests/data/web/certs/roca*.pem)
}


def _utc(days: float) -> str:
    t = _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=days)
    return t.strftime("%Y%m%d%H%M%SZ")


@dataclass
class Material:
    """Paths of the generated PKI. ``chains[(kind, layout)]`` and ``keys[kind]`` point at PEM files."""
    workdir: pathlib.Path
    root: pathlib.Path
    intermediate: pathlib.Path
    keys: dict[str, pathlib.Path] = field(default_factory=dict)
    leaves: dict[str, pathlib.Path] = field(default_factory=dict)

    def chain_file(self, kind: str, layout: str) -> pathlib.Path:
        out = self.workdir / f"chain-{kind}-{layout.replace('+', '_')}.pem"
        if not out.exists():
            parts = {"leaf": self.leaves[kind], "int": self.intermediate, "root": self.root}
            text = "".join(parts[p].read_text(encoding="ascii") for p in layout.split("+"))
            out.write_text(text, encoding="ascii", newline="\n")
        return out


def openssl_path() -> str | None:
    return shutil.which("openssl")


def _run(args: list[str], cwd: pathlib.Path) -> None:
    exe = openssl_path()
    if not exe:
        raise TLSUnavailable("openssl CLI not found on PATH")
    try:
        proc = subprocess.run([exe, *args], cwd=cwd, capture_output=True, text=True, timeout=120, check=False)
    except (OSError, subprocess.SubprocessError) as e:
        raise TLSUnavailable(f"openssl failed to run: {e}") from None
    if proc.returncode != 0:
        raise TLSUnavailable(f"openssl {' '.join(args[:2])} failed: {proc.stderr.strip()[:400]}")


_REQ_CNF = "[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN={cn}\nO=Kashif corpus (test only)\n"
_CA_CNF = """[ca]
default_ca=CA_default
[CA_default]
dir=.
database=./{name}-index.txt
new_certs_dir=./newcerts
serial=./{name}-serial.txt
policy=policy_any
copy_extensions=none
unique_subject=no
default_md=sha256
email_in_dn=no
[policy_any]
commonName=supplied
organizationName=optional
"""


def _ca_setup(wd: pathlib.Path, name: str) -> pathlib.Path:
    (wd / "newcerts").mkdir(exist_ok=True)
    (wd / f"{name}-index.txt").write_text("", encoding="ascii")
    (wd / f"{name}-serial.txt").write_text("1000\n", encoding="ascii")
    cnf = wd / f"{name}-ca.cnf"
    cnf.write_text(_CA_CNF.format(name=name), encoding="ascii", newline="\n")
    return cnf


def _sign(wd: pathlib.Path, ca: str, cn: str, out: str, key: str, *, start: str, end: str, ext_lines: list[str],
          md: str = "sha256") -> pathlib.Path:
    (wd / f"{out}.req.cnf").write_text(_REQ_CNF.format(cn=cn), encoding="utf-8", newline="\n")
    _run(["req", "-new", "-key", key, "-config", f"{out}.req.cnf", "-out", f"{out}.csr"], wd)
    (wd / f"{out}.ext.cnf").write_text("[v3]\n" + "\n".join(ext_lines) + "\n", encoding="ascii", newline="\n")
    _run(["ca", "-batch", "-config", f"{ca}-ca.cnf", "-cert", f"{ca}.pem", "-keyfile", f"{ca}.key", "-in", f"{out}.csr",
          "-out", f"{out}.pem", "-startdate", start, "-enddate", end, "-md", md, "-notext",
          "-extfile", f"{out}.ext.cnf", "-extensions", "v3"], wd)
    return wd / f"{out}.pem"


def _key(wd: pathlib.Path, name: str, bits: int = 2048) -> str:
    _run(["genrsa", "-out", f"{name}.key", str(bits)], wd)
    return f"{name}.key"


def build(workdir: pathlib.Path, shared_sans: list[str], case_hosts: dict[str, list[str]]) -> Material:
    """Create the test PKI in ``workdir``.

    ``shared_sans`` are the SAN entries (``DNS:*.csp.kashif.test``, ``IP:127.0.0.1``) of the shared leaf; ``case_hosts`` maps a
    certificate kind to the host names of the cases that use it (they get their own leaf)."""
    if not openssl_path():
        raise TLSUnavailable("openssl CLI not found on PATH")
    wd = pathlib.Path(workdir)
    wd.mkdir(parents=True, exist_ok=True)
    root_cnf = wd / "root.cnf"
    root_cnf.write_text(_REQ_CNF.format(cn="Kashif Corpus Test Root") +
                        "[v3_ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n"
                        "subjectKeyIdentifier=hash\n", encoding="ascii", newline="\n")
    _key(wd, "root")
    _run(["req", "-x509", "-new", "-key", "root.key", "-config", "root.cnf", "-extensions", "v3_ca", "-days", "3650",
          "-sha256", "-out", "root.pem"], wd)
    _ca_setup(wd, "root")
    _key(wd, "int")
    _sign(wd, "root", "Kashif Corpus Test Intermediate", "int", "int.key", start=_utc(-30), end=_utc(3000),
          ext_lines=["basicConstraints=critical,CA:TRUE,pathlen:0", "keyUsage=critical,keyCertSign,cRLSign",
                     "subjectKeyIdentifier=hash", "authorityKeyIdentifier=keyid"])
    _ca_setup(wd, "int")
    mat = Material(wd, wd / "root.pem", wd / "int.pem")
    leaf_ext = ["basicConstraints=critical,CA:FALSE", "keyUsage=critical,digitalSignature,keyEncipherment",
                "extendedKeyUsage=serverAuth", "subjectKeyIdentifier=hash"]
    wanted = {"shared": shared_sans}
    for kind, hosts in case_hosts.items():
        if kind not in CERT_KINDS or kind == "shared":
            continue
        wanted[kind] = [f"DNS:{h}" for h in hosts] + ["IP:127.0.0.1"]
    for kind, sans in wanted.items():
        spec = CERT_KINDS[kind]
        sans = spec.get("sans", sans)
        cn = (case_hosts.get(kind) or ["kashif-corpus.kashif.test"])[0]
        key = _key(wd, f"leaf-{kind}", spec.get("bits", 2048))
        start = spec.get("start_abs") or _utc(spec["start"])
        end = spec.get("end_abs") or _utc(spec["end"])
        ext = [e.replace("serverAuth", spec["eku"]) for e in leaf_ext] if spec.get("eku") else list(leaf_ext)
        if spec.get("aki", True):
            ext.append("authorityKeyIdentifier=keyid")
        else:
            ext.append("authorityKeyIdentifier=none")      # OpenSSL 3 adds an AKI by default; 1.1.1 retries without
        if sans:
            ext.append("subjectAltName=" + ",".join(sans))
        ext += spec.get("ext", [])
        if spec.get("self"):
            (wd / f"leaf-{kind}.req.cnf").write_text(_REQ_CNF.format(cn=cn) + "[v3]\n" + "\n".join(
                e for e in ext if not e.startswith("authorityKeyIdentifier")) + "\n", encoding="ascii", newline="\n")
            _run(["req", "-x509", "-new", "-key", key, "-config", f"leaf-{kind}.req.cnf", "-extensions", "v3", "-days", "44",
                  "-sha256", "-out", f"leaf-{kind}.pem"], wd)
            leaf = wd / f"leaf-{kind}.pem"
        else:
            try:
                leaf = _sign(wd, "int", cn, f"leaf-{kind}", key, start=start, end=end, ext_lines=ext,
                             md=spec.get("md", "sha256"))
            except TLSUnavailable:
                if "authorityKeyIdentifier=none" not in ext:
                    raise
                ext.remove("authorityKeyIdentifier=none")
                leaf = _sign(wd, "int", cn, f"leaf-{kind}", key, start=start, end=end, ext_lines=ext,
                             md=spec.get("md", "sha256"))
        mat.keys[kind] = wd / key
        mat.leaves[kind] = leaf
    return mat


_VERSIONS = {"TLSv1": ssl.TLSVersion.TLSv1, "TLSv1_1": ssl.TLSVersion.TLSv1_1, "TLSv1_2": ssl.TLSVersion.TLSv1_2,
             "TLSv1_3": ssl.TLSVersion.TLSv1_3}


def server_context(mat: Material, profile: Profile) -> ssl.SSLContext:
    """An SSLContext serving ``profile``. Raises ssl.SSLError / ValueError when the local OpenSSL refuses the settings."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if profile.weak:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    if profile.ciphers:
        ctx.set_ciphers(profile.ciphers)
    with warnings.catch_warnings():              # TLS 1.0 is deprecated in ssl: serving it is the point of the case
        warnings.simplefilter("ignore", DeprecationWarning)
        if profile.min_version:
            ctx.minimum_version = _VERSIONS[profile.min_version]
        if profile.max_version:
            ctx.maximum_version = _VERSIONS[profile.max_version]
    kind = profile.cert
    if kind not in mat.leaves:
        raise ValueError(f"no certificate of kind {kind!r}")
    ctx.load_cert_chain(str(mat.chain_file(kind, profile.chain)), str(mat.keys[kind]))
    return ctx


def client_accepts_tls10() -> bool:
    """Whether this Python/OpenSSL can complete a TLS 1.0 handshake at all (needed to verify the TLS 1.0 server works)."""
    try:
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        c.set_ciphers("DEFAULT:@SECLEVEL=0")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            c.minimum_version = ssl.TLSVersion.TLSv1
            c.maximum_version = ssl.TLSVersion.TLSv1
        return True
    except (ValueError, ssl.SSLError):
        return False


def probe_version(host: str, port: int, version: str, server_name: str, timeout: float = 5.0) -> bool:
    """Handshake once with exactly ``version`` (used to check that a profile really serves what it claims)."""
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE           # test-only check of the protocol version of our own local server
    try:
        c.set_ciphers("DEFAULT:@SECLEVEL=0")
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            c.minimum_version = c.maximum_version = _VERSIONS[version]
    except (ValueError, ssl.SSLError):
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout) as s, c.wrap_socket(s, server_hostname=server_name):
            return True
    except (OSError, ssl.SSLError):
        return False


def load_stub():
    """WP10's raw-probe stub module, or None. Expected API: ``start_stub(flight, upstream=(host, port)) -> (port, stop)``."""
    if not STUB_PATH.is_file():
        return None
    spec = importlib.util.spec_from_file_location("kashif_corpus_tls_stub", STUB_PATH)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception:                       # noqa: BLE001 - a broken stub only skips the stub cases
        return None
    return mod if hasattr(mod, "start_stub") else None


def roca_fixture() -> tuple[pathlib.Path, pathlib.Path] | None:
    """A ROCA-vulnerable certificate and key from WP10's fixtures (licence-checked by WP10), if present."""
    d = ROOT / "tests" / "data" / "web" / "certs"
    cert, key = d / "roca-leaf.pem", d / "roca-leaf.key"
    return (cert, key) if cert.is_file() and key.is_file() else None


def can_bind(ip: str) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((ip, 0))
        return True
    except OSError:
        return False


class TempPKI:
    """Context manager: build the PKI in a temporary directory and remove it afterwards."""

    def __init__(self, shared_sans: list[str], case_hosts: dict[str, list[str]], keep: str | None = None):
        self.shared_sans, self.case_hosts, self.keep = shared_sans, case_hosts, keep
        self._tmp: tempfile.TemporaryDirectory | None = None
        self.material: Material | None = None
        self.error: str | None = None

    def __enter__(self) -> TempPKI:
        if self.keep:
            wd = pathlib.Path(self.keep)
        else:
            self._tmp = tempfile.TemporaryDirectory(prefix="kashif-corpus-pki-")
            wd = pathlib.Path(self._tmp.name)
        try:
            self.material = build(wd, self.shared_sans, self.case_hosts)
        except TLSUnavailable as e:
            self.error = str(e)
        return self

    def __exit__(self, *exc) -> None:
        if self._tmp is not None:
            self._tmp.cleanup()



def describe() -> str:
    exe = openssl_path()
    if not exe:
        return "openssl: not found"
    try:
        out = subprocess.run([exe, "version"], capture_output=True, text=True, timeout=10, check=False).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        out = "?"
    return f"openssl CLI: {out} ({exe}); Python ssl: {ssl.OPENSSL_VERSION}; platform: {os.name}"
