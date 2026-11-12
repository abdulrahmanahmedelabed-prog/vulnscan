"""Software composition analysis: dependency manifests/lockfiles -> packages, and reachability of a package.

Two halves, both standard library only and fully offline:

* ``collect(root)`` reads every supported manifest and lockfile and returns exact (ecosystem, name, version)
  triples, marked direct or transitive. Lockfiles win over the manifest next to them (exact resolved versions).
* ``ImportIndex(root)`` scans the project's source once and answers, for a package, whether the code imports it
  (``imported`` / ``not_imported`` / ``unknown``) and whether named vulnerable functions are called
  (``vulnerable_function_called``). vulnscan/deps.py combines this with OSV.dev advisories.
"""

from __future__ import annotations

import ast
import json
import os
import pathlib
import re
from dataclasses import dataclass, field

SKIP_DIRS = frozenset({"node_modules", ".git", ".venv", "venv", "build", ".tox", "__pycache__", "site-packages"})
# third-party code checked into the tree must not count as "the project imports it"
SOURCE_SKIP_DIRS = SKIP_DIRS | {"vendor", "target", "dist", "bower_components", "Pods", ".gradle", ".idea", "third_party"}
MAX_MANIFEST_BYTES = 30_000_000
MAX_SOURCE_BYTES = 1_000_000
MAX_SOURCE_FILES = 20_000

IMPORTED, NOT_IMPORTED, UNKNOWN, CALLED = "imported", "not_imported", "unknown", "vulnerable_function_called"


@dataclass
class Package:
    ecosystem: str            # OSV ecosystem name: PyPI, npm, Maven, Go, Packagist, RubyGems, crates.io, NuGet, Pub
    name: str
    version: str
    manifest: str             # path relative to the scanned root
    direct: bool | None = None   # True direct, False transitive, None unknown
    dev: bool = False
    namespaces: tuple = ()    # PHP autoload namespaces (composer.lock)
    aliases: tuple = ()       # names the code imports it by, when not its registry name (npm "x": "npm:real@1")
    also_in: list = field(default_factory=list)

    @property
    def relation(self) -> str:
        return "unknown" if self.direct is None else "direct" if self.direct else "transitive"


# ------------------------------------------------------------------ small readers

def _read(path: pathlib.Path) -> str:
    if path.stat().st_size > MAX_MANIFEST_BYTES:
        raise ValueError("manifest too large")
    return path.read_text(encoding="utf-8", errors="replace")


def _json(path: pathlib.Path) -> dict:
    data = json.loads(_read(path))
    return data if isinstance(data, dict) else {}


def pypi_name(name: str) -> str:
    """PEP 503 normalized distribution name."""
    return re.sub(r"[-_.]+", "-", name).lower()


# no two \s* runs may touch (directly or across an optional group): that backtracks quadratically on long blank runs
_REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9_.\-]*)\s*(?:\[[^\]]*\]\s*)?===?\s*([A-Za-z0-9][A-Za-z0-9_.\-+!]*)\s*(?:(?:;.*|\\)\s*)?$")
_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9_.\-]*)")


def _req(req: str) -> tuple[str, str] | None:
    """``name==version`` (extras, markers and hashes allowed) -> (normalized name, version); None when not pinned."""
    req = req.split(" --hash")[0]
    m = _REQ.match(req)
    if not m or "*" in m.group(2):
        return None
    return pypi_name(m.group(1)), m.group(2)


def _toml_sections(text: str) -> dict[str, list[str]]:
    """Section name -> its lines. Enough TOML for dependency tables; works on every supported Python."""
    out: dict[str, list[str]] = {"": []}
    cur = ""
    for line in text.splitlines():
        # linear-time header match: a lazy group between two \s* runs backtracked cubically on "[" + spaces
        m = re.match(r"^\s*\[\[?([^\]]*)\]\]?\s*(?:#.*)?$", line)
        if m and m.group(1).strip() and "=" not in line.split("]")[0]:
            cur = m.group(1).strip().replace('"', "").replace("'", "")
            out.setdefault(cur, [])
        else:
            out[cur].append(line)
    return out


def _toml_keys(lines: list[str]) -> dict[str, str]:
    """``key = value`` pairs of one table (value kept raw)."""
    out = {}
    for line in lines:
        m = re.match(r"^\s*[\"']?([A-Za-z0-9_.\-]+)[\"']?\s*=\s*(.+?)\s*$", line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def _lock_blocks(text: str) -> list[str]:
    """The ``[[package]]`` blocks of poetry.lock / uv.lock / Cargo.lock."""
    return re.split(r"(?m)^\[\[package\]\]\s*$", text)[1:]


def _block_str(block: str, key: str) -> str:
    m = re.search(rf'(?m)^{key}\s*=\s*"([^"]*)"', block)
    return m.group(1) if m else ""


_EXACT = re.compile(r"\d[A-Za-z0-9_.\-+!]*")


# ------------------------------------------------------------------ direct-dependency names (from the manifest)

def _npm_direct(d: pathlib.Path) -> tuple[set, set] | None:
    try:
        data = _json(d / "package.json")
    except (OSError, ValueError):
        return None
    prod, dev = set(), set()
    for sec in ("dependencies", "optionalDependencies", "peerDependencies"):
        prod |= set(data.get(sec) or {})
    dev |= set(data.get("devDependencies") or {})
    return prod | dev, dev - prod


def _pyproject_names(text: str) -> set:
    names = set()
    secs = _toml_sections(text)
    for sec, lines in secs.items():
        if sec in ("project", "project.optional-dependencies", "dependency-groups", "tool.uv", "build-system"):
            for s in re.findall(r"[\"']([^\"']+)[\"']", "\n".join(lines)):
                m = _REQ_NAME.match(s)
                if m and re.match(r"^\s*[A-Za-z0-9_.\-]+\s*(\[|[<>=!~;@]|$)", s):
                    names.add(pypi_name(m.group(1)))
        elif re.fullmatch(r"tool\.poetry\.(dependencies|dev-dependencies|group\.[^.]+\.dependencies)", sec):
            names |= {pypi_name(k) for k in _toml_keys(lines)}
    names.discard("python")
    return names


def _py_direct(d: pathlib.Path) -> set | None:
    names, found = set(), False
    try:
        names |= _pyproject_names(_read(d / "pyproject.toml"))
        found = True
    except (OSError, ValueError):
        pass
    try:
        secs = _toml_sections(_read(d / "Pipfile"))
        for sec in ("packages", "dev-packages"):
            names |= {pypi_name(k) for k in _toml_keys(secs.get(sec, []))}
        found = True
    except (OSError, ValueError):
        pass
    return names if found else None


def _composer_direct(d: pathlib.Path) -> set | None:
    try:
        data = _json(d / "composer.json")
    except (OSError, ValueError):
        return None
    return {k.lower() for sec in ("require", "require-dev") for k in (data.get(sec) or {})}


def _cargo_direct(d: pathlib.Path) -> set | None:
    try:
        secs = _toml_sections(_read(d / "Cargo.toml"))
    except (OSError, ValueError):
        return None
    names = set()
    for sec, lines in secs.items():
        if re.search(r"(^|\.)(dev-|build-)?dependencies$", sec):
            for k, v in _toml_keys(lines).items():
                m = re.search(r'package\s*=\s*"([^"]+)"', v)
                names.add(m.group(1) if m else k)
        m = re.search(r"(?:^|\.)(?:dev-|build-)?dependencies\.([A-Za-z0-9_\-]+)$", sec)
        if m:
            names.add(m.group(1))
    return names


def _gradle_coords(text: str) -> list[tuple[str, str, str]]:
    """(group, artifact, version or '') for simple coordinates in a Gradle build script (Groovy or Kotlin)."""
    text = re.sub(r"(?m)//.*$", "", text)
    variables = dict(re.findall(r"(?m)^[ \t]*(?:(?:def|val|var)[ \t]+|ext\.)?(\w+)[ \t]*=[ \t]*[\"'](\d[\w.\-]*)[\"']", text))

    def subst(v: str) -> str:
        return re.sub(r"\$\{?(?:project\.|rootProject\.|ext\.)?(\w+)\}?", lambda m: variables.get(m.group(1), m.group(0)), v)

    out = []
    conf = r"(?:\b[a-z]\w*)"
    for m in re.finditer(conf + r"\s*(?:\(\s*)?(?:platform\s*\(\s*)?[\"']([\w.\-]+):([\w.\-]+)(?::([^\"':@]+))?(?:[:@][\w.\-]+)?[\"']", text):
        out.append((m.group(1), m.group(2), subst(m.group(3) or "")))
    for m in re.finditer(r"group\s*[:=]\s*[\"']([\w.\-]+)[\"']\s*,\s*name\s*[:=]\s*[\"']([\w.\-]+)[\"']"
                         r"(?:\s*,\s*version\s*[:=]\s*[\"']([^\"']+)[\"'])?", text):
        out.append((m.group(1), m.group(2), subst(m.group(3) or "")))
    return out


# ------------------------------------------------------------------ parsers: one per file kind

def _p_requirements(path, rel, d):
    text = re.sub(r"\\\r?\n", " ", _read(path))
    lines = text.splitlines()
    compiled = any(re.match(r"\s*#\s+via\b", ln) or "# via " in ln for ln in lines)
    out = []
    for i, line in enumerate(lines):
        r = _req(line.split("#")[0])
        if not r:
            continue
        direct = True
        if compiled:      # pip-compile / uv pip compile output: "# via x" names who pulled the package in
            via = line.split("#", 1)[1] if "#" in line else ""
            for nxt in lines[i + 1:]:
                if not nxt.lstrip().startswith("#"):
                    break
                via += " " + nxt
            direct = "via" not in via or bool(re.search(r"-r |-c |\.in\b|pyproject\.toml|setup\.(py|cfg)|\(.*\)", via))
        out.append(Package("PyPI", r[0], r[1], rel, direct))
    return out


def _p_pyproject(path, rel, d):
    text = _read(path)
    out = []
    secs = _toml_sections(text)
    for sec, lines in secs.items():
        if sec in ("project", "project.optional-dependencies", "dependency-groups"):
            for s in re.findall(r"[\"']([^\"']+)[\"']", "\n".join(lines)):
                r = _req(s)
                if r:
                    out.append(Package("PyPI", r[0], r[1], rel, True, dev=sec == "dependency-groups"))
        elif re.fullmatch(r"tool\.poetry\.(dependencies|dev-dependencies|group\.[^.]+\.dependencies)", sec):
            for k, v in _toml_keys(lines).items():
                m = re.search(r'version\s*=\s*"([^"]+)"', v) if v.startswith("{") else re.match(r'"([^"]+)"', v)
                ver = re.sub(r"^==\s*", "", m.group(1).strip()) if m else ""
                if k.lower() != "python" and _EXACT.fullmatch(ver):
                    out.append(Package("PyPI", pypi_name(k), ver, rel, True, dev=not sec.endswith("poetry.dependencies")))
    return out


def _p_pipfile_lock(path, rel, d):
    data = _json(path)
    direct = _py_direct(d)
    out = []
    for sec in ("default", "develop"):
        for name, meta in (data.get(sec) or {}).items():
            ver = str((meta or {}).get("version", "")) if isinstance(meta, dict) else ""
            if ver.startswith("=="):
                n = pypi_name(name)
                out.append(Package("PyPI", n, ver[2:], rel, None if direct is None else n in direct, dev=sec == "develop"))
    return out


def _p_poetry_lock(path, rel, d):
    direct = _py_direct(d)
    out = []
    for b in _lock_blocks(_read(path)):
        name, ver = pypi_name(_block_str(b, "name")), _block_str(b, "version")
        if name and ver:
            out.append(Package("PyPI", name, ver, rel, None if direct is None else name in direct,
                               dev=_block_str(b, "category") == "dev"))
    return out


def _p_uv_lock(path, rel, d):
    blocks = _lock_blocks(_read(path))
    direct: set | None = None
    for b in blocks:
        if re.search(r"(?m)^source\s*=\s*\{\s*(virtual|editable)\b", b):      # the project itself / workspace members
            direct = (direct or set()) | {pypi_name(n) for n in re.findall(r'\{\s*name\s*=\s*"([^"]+)"', b)}
    if direct is None:
        direct = _py_direct(d)
    out = []
    for b in blocks:
        name, ver = pypi_name(_block_str(b, "name")), _block_str(b, "version")
        if name and ver and not re.search(r"(?m)^source\s*=\s*\{\s*(virtual|editable|directory)\b", b):
            out.append(Package("PyPI", name, ver, rel, None if direct is None else name in direct))
    return out


def _p_package_json(path, rel, d):
    data = _json(path)
    out = []
    for sec in ("dependencies", "devDependencies", "optionalDependencies"):
        for dep, ver in (data.get(sec) or {}).items():
            if re.fullmatch(r"=?\s*\d+\.\d+\.\d+(?:-[\w.]+)?", str(ver)):
                out.append(Package("npm", dep, str(ver).lstrip("= "), rel, True, dev=sec == "devDependencies"))
    return out


def _p_package_lock(path, rel, d):
    data = _json(path)
    out = []
    packages = data.get("packages")
    if isinstance(packages, dict) and packages:                     # lockfileVersion 2 and 3
        root = packages.get("") or {}
        direct = {n for sec in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
                  for n in (root.get(sec) or {})}
        known = bool(direct) or "" in packages
        if not known:
            nd = _npm_direct(d)
            direct, known = (nd[0], True) if nd else (set(), False)
        for key, meta in packages.items():
            if not key or not isinstance(meta, dict) or meta.get("link") or not meta.get("version"):
                continue
            if "node_modules/" not in key:
                continue                                            # a workspace member, not a registry package
            name = key.rsplit("node_modules/", 1)[1]
            top = key == "node_modules/" + name
            real = str(meta.get("name") or name)
            out.append(Package("npm", real, str(meta["version"]), rel, (top and name in direct) if known else None,
                               dev=bool(meta.get("dev")), aliases=(name,) if real != name else ()))
        return out
    nd = _npm_direct(d)

    def walk(deps: dict, top: bool) -> None:                        # lockfileVersion 1: nested "dependencies"
        for name, meta in (deps or {}).items():
            if not isinstance(meta, dict):
                continue
            ver = str(meta.get("version") or "")
            real, alias = name, _npm_alias(ver)
            if alias:                                               # "lodash4": {"version": "npm:lodash@4.17.21"}
                real, ver = alias
            if ver and _EXACT.fullmatch(ver):
                out.append(Package("npm", real, ver, rel, None if nd is None else (top and name in nd[0]),
                                   dev=bool(meta.get("dev")), aliases=(name,) if real != name else ()))
            walk(meta.get("dependencies") or {}, False)

    walk(data.get("dependencies") or {}, True)
    return out


def _npm_alias(spec: str) -> tuple[str, str] | None:
    """``npm:real-name@1.2.3`` (an npm alias) -> (real name, version or range); None when not an alias."""
    if not spec.startswith("npm:"):
        return None
    rest = spec[4:]
    at = rest.find("@", 1)
    return (rest[:at], rest[at + 1:]) if at > 0 else (rest, "")


def _p_yarn_lock(path, rel, d):
    nd = _npm_direct(d)
    out = []
    header = None
    for line in _read(path).splitlines():
        if line and not line[0].isspace() and not line.startswith("#") and line.rstrip().endswith(":"):
            header = line.rstrip()[:-1]
            continue
        m = re.match(r'^\s+version:?\s+"?([^"\s]+)"?\s*$', line)
        if m and header and header != "__metadata":
            spec = header.split(",")[0].strip().strip('"\'')
            at = spec.find("@", 1)
            name = spec[:at] if at > 0 else spec
            alias = _npm_alias(spec[at + 1:]) if at > 0 else None
            real = alias[0] if alias and alias[0][:1] not in "^~<>=*0123456789" else name   # "x@npm:^1" is no alias
            if "@workspace:" not in header and "@patch:" not in spec and "@portal:" not in header and "@link:" not in header:
                out.append(Package("npm", real, m.group(1), rel, None if nd is None else name in nd[0],
                                   dev=bool(nd and name in nd[1]), aliases=(name,) if real != name else ()))
            header = None
    return out


def _p_pnpm_lock(path, rel, d):
    lines = _read(path).splitlines()
    direct: set = set()
    section, sub = "", ""
    entries = []
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        body = line.strip()
        if indent == 0:
            section, sub = body.rstrip(":"), ""
            continue
        if section in ("dependencies", "devDependencies", "optionalDependencies") and indent == 2:
            direct.add(body.split(":")[0].strip("'\""))
        elif section == "importers":
            if indent == 4:
                sub = body.rstrip(":")
            elif indent == 6 and sub in ("dependencies", "devDependencies", "optionalDependencies"):
                direct.add(body.rsplit(":", 1)[0].strip("'\""))
        elif section in ("packages", "snapshots") and indent == 2 and body.endswith(":"):
            key = body[:-1].strip("'\"").lstrip("/")
            # v6/v9: foo@1.0.0(react@18.2.0) and @scope/foo@1.0.0; v5: foo/1.0.0_react@17.0.2
            m = re.match(r"^(@[^/@]+/[^/@]+|[^/@]+)@(\d[^_(]*)", key) or re.match(r"^(@[^/]+/[^/]+|[^/@]+)/(\d[^_(]*)", key)
            if m:
                entries.append((m.group(1), m.group(2)))
    nd = _npm_direct(d)
    known = bool(direct) or nd is not None
    if nd:
        direct |= nd[0]
    return [Package("npm", n, v, rel, (n in direct) if known else None, dev=bool(nd and n in nd[1])) for n, v in entries]


def _p_pom(path, rel, d):
    import xml.etree.ElementTree as ET
    text = _read(path)
    if "<!ENTITY" in text or "<!DOCTYPE" in text:                    # never expand entities from an untrusted POM
        return []
    root = ET.fromstring(re.sub(r"\sxmlns(:\w+)?=\"[^\"]*\"", "", text, count=0))

    def child(node, tag):
        el = node.find(tag) if node is not None else None
        return (el.text or "").strip() if el is not None else ""

    parent = root.find("parent")
    props = {"project.version": child(root, "version") or child(parent, "version"),
             "project.groupId": child(root, "groupId") or child(parent, "groupId"),
             "project.parent.version": child(parent, "version")}
    props["version"], props["pom.version"] = props["project.version"], props["project.version"]
    for p in root.findall("properties/*"):
        props[p.tag] = (p.text or "").strip()

    def resolve(v: str) -> str:
        for _ in range(8):
            new = re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), v)
            if new == v:
                break
            v = new
        return v

    managed = {}
    for dep in root.findall("dependencyManagement/dependencies/dependency"):
        managed[(resolve(child(dep, "groupId")), resolve(child(dep, "artifactId")))] = resolve(child(dep, "version"))
    out = []
    for dep in root.findall("dependencies/dependency") + root.findall("profiles/profile/dependencies/dependency"):
        g, a = resolve(child(dep, "groupId")), resolve(child(dep, "artifactId"))
        ver = resolve(child(dep, "version")) or managed.get((g, a), "")
        if g and a and _EXACT.fullmatch(ver):
            out.append(Package("Maven", f"{g}:{a}", ver, rel, True, dev=child(dep, "scope") == "test"))
    return out


def _p_gradle(path, rel, d):
    out = []
    for g, a, v in _gradle_coords(_read(path)):
        if _EXACT.fullmatch(v) and "+" not in v:
            out.append(Package("Maven", f"{g}:{a}", v, rel, True))
    return out


def _p_gradle_lock(path, rel, d):
    direct: set | None = None
    for name in ("build.gradle", "build.gradle.kts"):
        try:
            direct = (direct or set()) | {f"{g}:{a}" for g, a, _ in _gradle_coords(_read(d / name))}
        except (OSError, ValueError):
            pass
    out = []
    for line in _read(path).splitlines():
        m = re.match(r"^([\w.\-]+):([\w.\-]+):([^=\s]+)=(.*)$", line.strip())
        if m:
            name = f"{m.group(1)}:{m.group(2)}"
            confs = m.group(4).lower()
            out.append(Package("Maven", name, m.group(3), rel, None if direct is None else name in direct,
                               dev=bool(confs) and all("test" in c for c in confs.split(","))))
    return out


def _p_go_mod(path, rel, d):
    out = []
    block = ""
    for line in _read(path).splitlines():
        s = line.strip()
        m = re.match(r"^(require|replace|exclude|retract)\s*\($", s)
        if m:
            block = m.group(1)
            continue
        if s == ")":
            block = ""
            continue
        if s.startswith("require "):
            s, kind = s[8:].strip(), "require"
        else:
            kind = block
        if kind != "require":
            continue
        m = re.match(r"^([\w./\-~]+)\s+v([\w.\-+]+)\s*(//.*)?$", s)
        if m:
            out.append(Package("Go", m.group(1), m.group(2), rel, "indirect" not in (m.group(3) or "")))
    return out


def _p_go_sum(path, rel, d):
    seen, out = set(), []
    for line in _read(path).splitlines():
        m = re.match(r"^([\w./\-~]+)\s+v([\w.\-+]+?)(?:/go\.mod)?\s+h1:", line)
        if m and m.groups() not in seen:
            seen.add(m.groups())
            out.append(Package("Go", m.group(1), m.group(2), rel, None))
    return out


def _p_composer_lock(path, rel, d):
    data = _json(path)
    direct = _composer_direct(d)
    out = []
    for sec in ("packages", "packages-dev"):
        for p in data.get(sec) or []:
            name, ver = str(p.get("name", "")), str(p.get("version", "")).lstrip("vV")
            if not name or not _EXACT.fullmatch(ver):
                continue
            auto = p.get("autoload") or {}
            ns = [k for kind in ("psr-4", "psr-0") for k in (auto.get(kind) or {}) if k] if isinstance(auto, dict) else []
            out.append(Package("Packagist", name, ver, rel, None if direct is None else name.lower() in direct,
                               dev=sec == "packages-dev", namespaces=tuple(ns)))
    return out


def _p_gemfile_lock(path, rel, d):
    text = _read(path)
    direct, section = set(), ""
    specs = []
    for line in text.splitlines():
        if line and not line[0].isspace():
            section = line.strip()
            continue
        if section == "DEPENDENCIES":
            m = re.match(r"^  ([\w.\-]+)", line)
            if m:
                direct.add(m.group(1))
        elif section in ("GEM", "GIT", "PATH"):
            m = re.match(r"^    ([\w.\-]+) \((\d[\w.]*)(?:-[\w.\-]+)?\)", line)
            if m and section == "GEM":
                specs.append(m.groups())
    known = "DEPENDENCIES" in text
    return [Package("RubyGems", n, v, rel, (n in direct) if known else None) for n, v in specs]


def _p_cargo_lock(path, rel, d):
    direct = _cargo_direct(d)
    out = []
    for b in _lock_blocks(_read(path)):
        name, ver = _block_str(b, "name"), _block_str(b, "version")
        if name and ver and _block_str(b, "source"):                 # no source = a crate of this workspace
            out.append(Package("crates.io", name, ver, rel, None if direct is None else name in direct))
    return out


def _p_nuget_lock(path, rel, d):
    out = []
    for deps in (_json(path).get("dependencies") or {}).values():
        for name, meta in (deps or {}).items():
            if isinstance(meta, dict) and meta.get("resolved") and meta.get("type") != "Project":
                kind = str(meta.get("type", ""))
                out.append(Package("NuGet", name, str(meta["resolved"]), rel,
                                   True if kind == "Direct" else False if kind.startswith("Transitive") else None))
    return out


def _strip_xml_comments(text: str) -> str:
    """``<!-- ... -->`` removed in one pass; an unclosed comment runs to the end of the text."""
    out, pos = [], 0
    while True:
        start = text.find("<!--", pos)
        if start < 0:
            out.append(text[pos:])
            return "".join(out)
        out.append(text[pos:start])
        end = text.find("-->", start + 4)
        if end < 0:
            return "".join(out)
        pos = end + 3


def _p_csproj(path, rel, d):
    out = []
    text = _strip_xml_comments(_read(path))
    # opening tags by a bounded regex, bodies by str.find up to the next tag: lazy or unbounded groups rescanned the
    # rest of the file from every unclosed tag (quadratic on a crafted project file)
    for m in re.finditer(r"<(PackageReference|PackageVersion)\b([^>]{0,4000})>", text):
        attrs = dict(re.findall(r"(\w+)\s*=\s*\"([^\"]*)\"", m.group(2)))
        name = attrs.get("Include") or attrs.get("Update")
        ver = attrs.get("Version") or attrs.get("VersionOverride") or ""
        if not ver and not m.group(2).endswith("/"):
            nxt = text.find("<" + m.group(1), m.end())
            nxt = len(text) if nxt < 0 else nxt
            end = text.find(f"</{m.group(1)}>", m.end(), nxt)
            body = text[m.end():end] if end >= 0 else ""
            mv = re.search(r"<Version>\s*([^<\s]+)\s*</Version>", body)
            ver = mv.group(1) if mv else ""
        ver = ver.strip("[]")
        if name and _EXACT.fullmatch(ver):
            out.append(Package("NuGet", name, ver, rel, True))
    return out


def _p_pubspec_lock(path, rel, d):
    out = []
    for m in re.finditer(r"(?m)^  ([a-z0-9_]+):\n((?:    .*\n)*)", _read(path) + "\n"):
        mv = re.search(r'(?m)^    version: "([^"]+)"', m.group(2))
        if mv:
            md = re.search(r'(?m)^    dependency: "?([^"\n]+)"?', m.group(2))
            kind = md.group(1) if md else ""
            out.append(Package("Pub", m.group(1), mv.group(1), rel, None if not kind else kind.startswith("direct"),
                               dev="dev" in kind))
    return out


# file name -> (parser, ecosystem, is a lockfile). Lockfiles are read first and silence the manifest of the
# same ecosystem in the same directory (it only says which packages are direct).
_BY_NAME = {
    "Pipfile.lock": (_p_pipfile_lock, "PyPI", True), "poetry.lock": (_p_poetry_lock, "PyPI", True),
    "uv.lock": (_p_uv_lock, "PyPI", True), "pyproject.toml": (_p_pyproject, "PyPI", False),
    "package-lock.json": (_p_package_lock, "npm", True), "npm-shrinkwrap.json": (_p_package_lock, "npm", True),
    "yarn.lock": (_p_yarn_lock, "npm", True), "pnpm-lock.yaml": (_p_pnpm_lock, "npm", True),
    "package.json": (_p_package_json, "npm", False),
    "pom.xml": (_p_pom, "Maven", None), "gradle.lockfile": (_p_gradle_lock, "Maven", True),
    "build.gradle": (_p_gradle, "Maven", False), "build.gradle.kts": (_p_gradle, "Maven", False),
    "go.mod": (_p_go_mod, "Go", True), "go.sum": (_p_go_sum, "Go", False),
    "composer.lock": (_p_composer_lock, "Packagist", True), "Gemfile.lock": (_p_gemfile_lock, "RubyGems", True),
    "Cargo.lock": (_p_cargo_lock, "crates.io", True), "packages.lock.json": (_p_nuget_lock, "NuGet", True),
    "Directory.Packages.props": (_p_csproj, "NuGet", False), "pubspec.lock": (_p_pubspec_lock, "Pub", True),
}
SUPPORTED = tuple(sorted(_BY_NAME)) + ("requirements*.txt", "*.csproj")


def _parser_for(name: str, parent: str):
    hit = _BY_NAME.get(name)
    if hit:
        return hit
    if name.endswith(".txt") and (name.startswith(("requirements", "constraints")) or parent == "requirements"):
        return _p_requirements, "PyPI", None
    if name.endswith((".csproj", ".fsproj", ".vbproj")):
        return _p_csproj, "NuGet", False
    return None


def collect(root: pathlib.Path) -> list[Package]:
    """Every pinned dependency under ``root``, one entry per (ecosystem, name, version); the first manifest that
    names it is kept (lockfiles first), the others are listed in ``also_in``."""
    root = pathlib.Path(root)
    if not root.is_dir():
        return []
    found: dict[tuple, Package] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(x for x in dirnames if x not in SKIP_DIRS)
        d = pathlib.Path(dirpath)
        jobs = []
        for name in sorted(filenames):
            hit = _parser_for(name, d.name)
            if hit:
                jobs.append((0 if hit[2] else 1, name, hit))
        locked = {eco for _, _, (_, eco, lock) in jobs if lock}
        for _, name, (parser, eco, lock) in sorted(jobs, key=lambda j: j[:2]):
            if lock is False and eco in locked:
                continue
            path = d / name
            try:
                pkgs = parser(path, path.relative_to(root).as_posix(), d)
            except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError, SyntaxError):
                continue                                              # a malformed manifest never stops the scan
            for p in pkgs:
                key = (p.ecosystem, p.name, p.version)
                old = found.get(key)
                if old is None:
                    found[key] = p
                    continue
                if p.manifest != old.manifest and p.manifest not in old.also_in:
                    old.also_in.append(p.manifest)
                if p.direct and not old.direct:                       # direct anywhere = direct
                    old.direct = True
                elif old.direct is None and p.direct is not None:
                    old.direct = p.direct
                old.dev = old.dev and p.dev
                if p.aliases:
                    old.aliases = tuple(dict.fromkeys(old.aliases + p.aliases))
    return list(found.values())


# ------------------------------------------------------------------ reachability

# distribution name (PEP 503) -> top-level import names, for distributions whose import name differs
PY_IMPORT_NAMES = {
    "pyyaml": ["yaml"], "pillow": ["PIL"], "beautifulsoup4": ["bs4"], "scikit-learn": ["sklearn"],
    "scikit-image": ["skimage"], "opencv-python": ["cv2"], "opencv-python-headless": ["cv2"],
    "opencv-contrib-python": ["cv2"], "python-dateutil": ["dateutil"], "pyjwt": ["jwt"], "python-jose": ["jose"],
    "attrs": ["attr", "attrs"], "setuptools": ["setuptools", "pkg_resources"], "protobuf": ["google.protobuf"],
    "pycryptodome": ["Crypto"], "pycryptodomex": ["Cryptodome"], "pycrypto": ["Crypto"], "mysqlclient": ["MySQLdb"],
    "mysql-connector-python": ["mysql.connector"], "psycopg2-binary": ["psycopg2"], "psycopg-binary": ["psycopg"],
    "python-dotenv": ["dotenv"], "msgpack-python": ["msgpack"], "pyopenssl": ["OpenSSL"],
    "djangorestframework": ["rest_framework"], "djangorestframework-simplejwt": ["rest_framework_simplejwt"],
    "django-cors-headers": ["corsheaders"], "django-filter": ["django_filters"], "django-environ": ["environ"],
    "python-multipart": ["multipart", "python_multipart"], "python-magic": ["magic"], "python-ldap": ["ldap"],
    "python-memcached": ["memcache"], "pymemcache": ["pymemcache"], "pyserial": ["serial"], "pyzmq": ["zmq"],
    "ruamel-yaml": ["ruamel.yaml", "ruamel"], "typing-extensions": ["typing_extensions"], "markupsafe": ["markupsafe"],
    "flask-sqlalchemy": ["flask_sqlalchemy"], "flask-cors": ["flask_cors"], "flask-login": ["flask_login"],
    "flask-jwt-extended": ["flask_jwt_extended"], "flask-wtf": ["flask_wtf"], "wtforms": ["wtforms"],
    "google-api-python-client": ["googleapiclient"], "google-auth": ["google.auth", "google.oauth2"],
    "google-cloud-storage": ["google.cloud.storage"], "grpcio": ["grpc"], "grpcio-tools": ["grpc_tools"],
    "faiss-cpu": ["faiss"], "tensorflow-gpu": ["tensorflow"], "tensorflow-cpu": ["tensorflow"], "torch": ["torch"],
    "pytorch-lightning": ["pytorch_lightning", "lightning"], "py-bcrypt": ["bcrypt"], "pynacl": ["nacl"],
    "pyasn1-modules": ["pyasn1_modules"], "ipython": ["IPython"], "jupyter-core": ["jupyter_core"],
    "pymongo": ["pymongo", "bson", "gridfs"], "pymysql": ["pymysql"], "pysaml2": ["saml2"],
    "python3-saml": ["onelogin"], "python-keycloak": ["keycloak"], "python-gnupg": ["gnupg"],
    "python-socketio": ["socketio"], "python-engineio": ["engineio"], "websocket-client": ["websocket"],
    "ldap3": ["ldap3"], "lxml": ["lxml"], "defusedxml": ["defusedxml"], "xmltodict": ["xmltodict"],
    "apache-airflow": ["airflow"], "elasticsearch-dsl": ["elasticsearch_dsl"], "redis-py-cluster": ["rediscluster"],
    "dnspython": ["dns"], "pyhamcrest": ["hamcrest"], "pypdf2": ["PyPDF2"], "pymupdf": ["fitz", "pymupdf"],
    "python-docx": ["docx"], "python-pptx": ["pptx"], "openpyxl": ["openpyxl"], "pyqt5": ["PyQt5"],
    "pygithub": ["github"], "gitpython": ["git"], "pywin32": ["win32api", "win32con", "win32com", "pywintypes"],
    "antlr4-python3-runtime": ["antlr4"], "importlib-metadata": ["importlib_metadata"], "zope-interface": ["zope.interface"],
    "starlette": ["starlette"], "uvicorn": ["uvicorn"], "jinja2": ["jinja2"], "werkzeug": ["werkzeug"],
    "sqlalchemy": ["sqlalchemy"], "paramiko": ["paramiko"], "cryptography": ["cryptography"], "httpx": ["httpx"],
    "aiohttp": ["aiohttp"], "tornado": ["tornado"], "twisted": ["twisted"], "celery": ["celery"],
    "langchain-core": ["langchain_core"], "langchain-community": ["langchain_community"],
    "azure-storage-blob": ["azure.storage.blob"], "azure-identity": ["azure.identity"], "boto": ["boto"],
    "pyarrow": ["pyarrow"], "pandas": ["pandas"], "numpy": ["numpy"], "scipy": ["scipy"], "mako": ["mako"],
    "markdown2": ["markdown2"], "pygments": ["pygments"], "babel": ["babel"], "nltk": ["nltk"],
    "discord-py": ["discord"], "pysnmp": ["pysnmp"], "pexpect": ["pexpect"], "docker": ["docker"],
    "kubernetes": ["kubernetes"], "ansible-core": ["ansible"], "pyspark": ["pyspark"], "mlflow": ["mlflow"],
    "sentry-sdk": ["sentry_sdk"], "simple-salesforce": ["simple_salesforce"], "oauthlib": ["oauthlib"],
    "requests-oauthlib": ["requests_oauthlib"], "authlib": ["authlib"], "itsdangerous": ["itsdangerous"],
    "pysocks": ["socks", "sockshandler"], "pymdown-extensions": ["pymdownx"], "markdown-it-py": ["markdown_it"],
    "googleapis-common-protos": ["google.api", "google.rpc", "google.type", "google.longrunning", "google.logging"],
    "opentelemetry-api": ["opentelemetry"], "opentelemetry-sdk": ["opentelemetry.sdk"], "pyyaml-include": ["yamlinclude"],
    "pycairo": ["cairo"], "pygobject": ["gi"], "pyusb": ["usb"], "pyxdg": ["xdg"], "pywavelets": ["pywt"],
    "pysmb": ["smb", "nmb"], "pyhcl": ["hcl"], "llama-index": ["llama_index"], "python-levenshtein": ["Levenshtein"],
    "beautifulsoup": ["BeautifulSoup"], "pycryptodome-test-vectors": ["pycryptodome_test_vectors"],
    "msal-extensions": ["msal_extensions"], "google-cloud-core": ["google.cloud"], "uwsgi": ["uwsgi", "uwsgidecorators"],
}

# Maven "group:artifact" (or just group) -> Java package prefixes, where the group id is not the package prefix
JAVA_PACKAGES = {
    "com.google.guava:guava": ["com.google.common"], "com.google.code.gson:gson": ["com.google.gson"],
    "com.google.protobuf": ["com.google.protobuf"], "com.fasterxml.jackson.core:jackson-databind": ["com.fasterxml.jackson.databind"],
    "com.fasterxml.jackson.core:jackson-core": ["com.fasterxml.jackson.core"],
    "com.fasterxml.jackson.core:jackson-annotations": ["com.fasterxml.jackson.annotation"],
    "com.fasterxml.jackson.dataformat:jackson-dataformat-xml": ["com.fasterxml.jackson.dataformat.xml"],
    "com.fasterxml.jackson.dataformat:jackson-dataformat-yaml": ["com.fasterxml.jackson.dataformat.yaml"],
    "org.apache.logging.log4j:log4j-core": ["org.apache.logging.log4j.core", "org.apache.logging.log4j"],
    "org.apache.logging.log4j:log4j-api": ["org.apache.logging.log4j"], "log4j:log4j": ["org.apache.log4j"],
    "ch.qos.logback": ["ch.qos.logback"], "org.slf4j": ["org.slf4j"],
    "commons-collections:commons-collections": ["org.apache.commons.collections"],
    "org.apache.commons:commons-collections4": ["org.apache.commons.collections4"],
    "commons-io:commons-io": ["org.apache.commons.io"], "commons-codec:commons-codec": ["org.apache.commons.codec"],
    "commons-fileupload:commons-fileupload": ["org.apache.commons.fileupload"],
    "commons-beanutils:commons-beanutils": ["org.apache.commons.beanutils"],
    "commons-lang:commons-lang": ["org.apache.commons.lang"], "org.apache.commons:commons-lang3": ["org.apache.commons.lang3"],
    "org.apache.commons:commons-text": ["org.apache.commons.text"], "org.apache.commons:commons-compress": ["org.apache.commons.compress"],
    "org.apache.commons:commons-configuration2": ["org.apache.commons.configuration2"],
    "commons-httpclient:commons-httpclient": ["org.apache.commons.httpclient"], "commons-net:commons-net": ["org.apache.commons.net"],
    "commons-cli:commons-cli": ["org.apache.commons.cli"], "commons-dbcp:commons-dbcp": ["org.apache.commons.dbcp"],
    "org.apache.httpcomponents:httpclient": ["org.apache.http"], "org.apache.httpcomponents:httpcore": ["org.apache.http"],
    "org.apache.httpcomponents.client5:httpclient5": ["org.apache.hc.client5"],
    "org.apache.struts:struts2-core": ["org.apache.struts2", "com.opensymphony.xwork2"],
    "org.apache.tomcat.embed:tomcat-embed-core": ["org.apache.catalina", "org.apache.tomcat", "org.apache.coyote"],
    "org.apache.xmlgraphics": ["org.apache.batik", "org.apache.fop", "org.apache.xmlgraphics"],
    "org.apache.poi": ["org.apache.poi"], "org.apache.shiro": ["org.apache.shiro"], "org.apache.velocity": ["org.apache.velocity"],
    "org.apache.santuario:xmlsec": ["org.apache.xml.security"], "org.apache.tika": ["org.apache.tika"],
    "org.yaml:snakeyaml": ["org.yaml.snakeyaml"], "com.thoughtworks.xstream:xstream": ["com.thoughtworks.xstream"],
    "org.springframework:spring-web": ["org.springframework.web", "org.springframework.http"],
    "org.springframework:spring-webmvc": ["org.springframework.web.servlet"],
    "org.springframework:spring-core": ["org.springframework.core", "org.springframework.util"],
    "org.springframework:spring-beans": ["org.springframework.beans"],
    "org.springframework:spring-context": ["org.springframework.context", "org.springframework.stereotype"],
    "org.springframework:spring-expression": ["org.springframework.expression"],
    "org.springframework:spring-jdbc": ["org.springframework.jdbc"], "org.springframework.security": ["org.springframework.security"],
    "org.springframework.boot": ["org.springframework.boot"], "org.springframework.data": ["org.springframework.data"],
    "org.hibernate:hibernate-core": ["org.hibernate"], "org.hibernate.validator:hibernate-validator": ["org.hibernate.validator"],
    "com.alibaba:fastjson": ["com.alibaba.fastjson"], "com.alibaba.fastjson2:fastjson2": ["com.alibaba.fastjson2"],
    "org.codehaus.groovy": ["groovy", "org.codehaus.groovy"], "org.apache.groovy": ["groovy", "org.apache.groovy"],
    "org.bouncycastle": ["org.bouncycastle"], "io.jsonwebtoken": ["io.jsonwebtoken"], "com.auth0:java-jwt": ["com.auth0.jwt"],
    "com.nimbusds:nimbus-jose-jwt": ["com.nimbusds.jose", "com.nimbusds.jwt"], "org.jsoup:jsoup": ["org.jsoup"],
    "org.dom4j:dom4j": ["org.dom4j"], "dom4j:dom4j": ["org.dom4j"], "org.jdom:jdom2": ["org.jdom2"],
    "xerces:xercesImpl": ["org.apache.xerces"], "xalan:xalan": ["org.apache.xalan", "org.apache.xpath"],
    "org.json:json": ["org.json"], "com.squareup.okhttp3:okhttp": ["okhttp3"], "com.squareup.okio:okio": ["okio"],
    "com.squareup.retrofit2:retrofit": ["retrofit2"], "io.netty": ["io.netty"], "org.eclipse.jetty": ["org.eclipse.jetty"],
    "org.jboss.resteasy": ["org.jboss.resteasy"], "org.freemarker:freemarker": ["freemarker"], "org.thymeleaf": ["org.thymeleaf"],
    "org.mybatis:mybatis": ["org.apache.ibatis"], "com.h2database:h2": ["org.h2"], "org.postgresql:postgresql": ["org.postgresql"],
    "mysql:mysql-connector-java": ["com.mysql"], "com.mysql:mysql-connector-j": ["com.mysql"],
    "org.mongodb": ["com.mongodb", "org.bson"], "redis.clients:jedis": ["redis.clients.jedis"],
    "org.apache.kafka": ["org.apache.kafka"], "org.apache.zookeeper": ["org.apache.zookeeper"],
    "org.apache.activemq": ["org.apache.activemq"], "com.rabbitmq:amqp-client": ["com.rabbitmq"],
    "org.quartz-scheduler:quartz": ["org.quartz"], "junit:junit": ["org.junit", "junit"], "org.junit.jupiter": ["org.junit.jupiter"],
    "org.mockito": ["org.mockito"], "org.jetbrains.kotlin": ["kotlin"], "org.jetbrains.kotlinx": ["kotlinx"],
    "org.scala-lang": ["scala"], "com.typesafe.akka": ["akka"], "org.apache.spark": ["org.apache.spark"],
    "org.apache.hadoop": ["org.apache.hadoop"], "com.amazonaws": ["com.amazonaws"], "software.amazon.awssdk": ["software.amazon.awssdk"],
    "org.elasticsearch": ["org.elasticsearch"], "org.apache.solr": ["org.apache.solr"], "org.apache.lucene": ["org.apache.lucene"],
    "org.owasp.esapi:esapi": ["org.owasp.esapi"], "org.apache.pdfbox": ["org.apache.pdfbox"], "com.itextpdf": ["com.itextpdf"],
    "net.minidev:json-smart": ["net.minidev.json"], "com.jayway.jsonpath:json-path": ["com.jayway.jsonpath"],
    "org.codehaus.jackson": ["org.codehaus.jackson"], "com.unboundid:unboundid-ldapsdk": ["com.unboundid"],
    "org.keycloak": ["org.keycloak"], "org.opensaml": ["org.opensaml"], "javax.servlet": ["javax.servlet"],
    "jakarta.servlet": ["jakarta.servlet"], "org.glassfish.jersey.core": ["org.glassfish.jersey"],
}
# packages loaded by name at run time (JDBC drivers, logging back ends): no import does not mean unused
_JAVA_RUNTIME_LOADED = ("mysql:", "com.mysql:", "org.postgresql:", "com.h2database:", "org.xerial:", "com.oracle.",
                        "com.microsoft.sqlserver:", "org.mariadb.jdbc:", "ch.qos.logback", "org.apache.logging.log4j:log4j-slf4j",
                        # embedded servlet containers: started by the framework, never imported by the application
                        "org.apache.tomcat.embed:", "io.undertow:", "org.eclipse.jetty:jetty-server")
# used by Spring itself (JSON binding, application.yml, validation, logging, reactive server) when the code only
# imports Spring: not importing them does not mean they are unused
_SPRING_IMPLICIT = ("com.fasterxml.jackson.", "org.yaml:snakeyaml", "org.hibernate.validator:", "jakarta.validation:",
                    "javax.validation:", "org.apache.logging.log4j:", "io.netty:", "io.projectreactor", "org.apache.tomcat:")
# files whose words name command-line tools run by the project (gunicorn, uvicorn, celery, pm2, ...)
_COMMAND_FILES = re.compile(r"(?i)^(procfile|dockerfile.*|containerfile|.*\.dockerfile|(docker-)?compose.*\.ya?ml|makefile|"
                            r"justfile|.*\.sh|tox\.ini|setup\.cfg|pytest\.ini|uwsgi\.ini|supervisord\.conf|.*\.service|"
                            r"mkdocs\.ya?ml|app\.ya?ml|fly\.toml|netlify\.toml|vercel\.json|nixpacks\.toml)$")
# JSON / RC configuration that names npm packages as plugins, presets or loaders
_JS_CONFIG_FILES = re.compile(r"(?i)^(\.babelrc(\.json)?|\.eslintrc(\.json)?|\.swcrc|\.postcssrc(\.json)?|\.prettierrc(\.json)?|"
                              r"\.stylelintrc(\.json)?|\.mocharc(\.json)?|tsconfig.*\.json|jsconfig\.json|angular\.json|"
                              r"\.browserslistrc|nx\.json|turbo\.json)$")

RUBY_REQUIRE_NAMES = {
    "activesupport": ["active_support"], "activerecord": ["active_record"], "actionpack": ["action_controller", "action_dispatch"],
    "actionview": ["action_view"], "activemodel": ["active_model"], "activejob": ["active_job"], "actionmailer": ["action_mailer"],
    "activestorage": ["active_storage"], "railties": ["rails"], "ruby-saml": ["onelogin/ruby-saml"], "rack-cors": ["rack/cors"],
    "jwt": ["jwt"], "rest-client": ["rest-client", "rest_client", "restclient"], "aws-sdk-s3": ["aws-sdk-s3"],
    "mini_magick": ["mini_magick"], "rubyzip": ["zip"], "ruby-openid": ["openid"], "net-ldap": ["net/ldap"],
    "httparty": ["httparty"], "bcrypt-ruby": ["bcrypt"], "redcarpet": ["redcarpet"], "rmagick": ["rmagick", "RMagick"],
}

_LANG = {".py": "py", ".pyi": "py", ".js": "js", ".jsx": "js", ".mjs": "js", ".cjs": "js", ".ts": "js", ".tsx": "js",
         ".mts": "js", ".cts": "js", ".vue": "js", ".svelte": "js", ".java": "java", ".kt": "java", ".kts": "java",
         ".scala": "java", ".groovy": "java", ".go": "go", ".php": "php", ".phtml": "php", ".rb": "rb", ".rake": "rb",
         ".ru": "rb", ".rs": "rs", ".cs": "cs", ".dart": "dart"}
_ECO_LANG = {"PyPI": "py", "npm": "js", "Maven": "java", "Go": "go", "Packagist": "php", "RubyGems": "rb",
             "crates.io": "rs", "NuGet": "cs", "Pub": "dart"}

_JS_IMPORT = re.compile(r"""(?:\brequire(?:\.resolve)?|\bimport)\s*\(\s*(?:['"]([^'"\n]+)['"]|`([^`$\n]+)`)"""
                        r"""|\bfrom\s+['"]([^'"\n]+)['"]|\bimport\s+['"]([^'"\n]+)['"]""")
# a string literal that is exactly a package name ('babel-loader', "@babel/preset-env"): plugins and loaders
_JS_PKG_STRING = re.compile(r"""['"](@[a-z0-9][\w.\-]*/[a-z0-9][\w.\-]*|[a-z0-9][\w.\-]*)(?:/[\w.\-/]*)?['"]""")
_NODE_MODULES_REF = re.compile(r"node_modules/(@[\w.\-]+/[\w.\-]+|[\w.\-]+)")
# a fully qualified Java / Kotlin type used without an import: new org.yaml.snakeyaml.Yaml()
_JAVA_FQN = re.compile(r"\b((?:[a-z_][a-z0-9_]*\.){2,})[A-Z]\w*")
_JAVA_IMPORT = re.compile(r"(?m)^\s*import\s+(?:static\s+)?([A-Za-z_][\w.]*)")
_GO_IMPORT = re.compile(r'(?m)^\s*import\s+(?:([\w.]+)\s+)?"([^"\n]+)"')
_GO_BLOCK_START = re.compile(r"\bimport\s*\(")
_GO_LINE = re.compile(r'(?m)^\s*(?:([\w.]+)\s+)?"([^"\n]+)"')
_PHP_USE = re.compile(r"(?m)^\s*use\s+(?:function\s+|const\s+)?\\?([A-Za-z_][\w\\]*)")
_PHP_FQN = re.compile(r"\\?\b([A-Z]\w*(?:\\\w+)+)")
_RB_REQUIRE = re.compile(r"""(?m)^\s*(?:require|gem)\s*\(?\s*['"]([^'"\n]+)['"]""")
_RS_PATH = re.compile(r"\b([a-z_][a-z0-9_]*)::|\bextern\s+crate\s+(\w+)|\buse\s+(?:::)?([a-z_][a-z0-9_]*)")
_CS_USING = re.compile(r"(?m)^\s*(?:global\s+)?using\s+(?:static\s+)?(?:\w+\s*=\s*)?([A-Za-z_][\w.]*)\s*;")
_DART_IMPORT = re.compile(r"""\bimport\s+['"]package:(\w+)/""")
_PY_IMPORT_LINE = re.compile(r"(?m)^[ \t]*(?:from[ \t]+([A-Za-z_][\w.]*)|import[ \t]+([A-Za-z_][\w., \t]*))")
_PY_DYNAMIC = re.compile(r"\b(?:import_module|__import__|import_string)\s*\(\s*[^'\")\s]")
_PY_IMPORTERS = frozenset({"import_module", "__import__", "import_string", "find_spec", "load_module"})
_PACKAGE_JSON_NON_CONFIG = frozenset({"name", "version", "description", "keywords", "homepage", "bugs", "license",
                                      "author", "contributors", "funding", "files", "main", "module", "types",
                                      "dependencies", "devDependencies", "peerDependencies", "optionalDependencies",
                                      "bundleDependencies", "bundledDependencies", "overrides", "resolutions",
                                      "repository", "scripts", "engines", "os", "cpu", "workspaces", "publishConfig"})
_MODULE_STRING = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*")


def _go_import_blocks(text: str) -> list[str]:
    """The bodies of ``import ( ... )`` blocks. A plain loop, not a lazy regex: an unclosed ``import (`` repeated
    through a large file made a lazy ``import (...)`` regex rescan to the end of the file from every occurrence."""
    out, pos = [], 0
    while True:
        m = _GO_BLOCK_START.search(text, pos)
        if not m:
            return out
        end = text.find(")", m.end())
        if end < 0:
            return out
        out.append(text[m.end():end])
        pos = end + 1


def _notebook_code(text: str) -> str:
    """The code cells of a Jupyter notebook as one Python text (IPython magics and shell lines dropped)."""
    try:
        cells = json.loads(text).get("cells") or []
    except (ValueError, AttributeError, RecursionError):
        return ""
    out = []
    for cell in cells if isinstance(cells, list) else ():
        if isinstance(cell, dict) and cell.get("cell_type") == "code":
            src = cell.get("source") or ""
            src = "".join(x for x in src if isinstance(x, str)) if isinstance(src, list) else str(src)
            out += [ln for ln in src.splitlines() if not ln.lstrip().startswith(("%", "!"))]
    return "\n".join(out)


def _js_package(spec: str) -> str | None:
    if not spec or spec[0] in "./~#" or spec.startswith(("node:", "http:", "https:")):
        return None
    parts = spec.split("/")
    return "/".join(parts[:2]) if spec[0] == "@" and len(parts) > 1 else parts[0]


class ImportIndex:
    """What the scanned project imports and calls, per language. Built once per scan, text never executed."""

    def __init__(self, root: pathlib.Path):
        self.root = pathlib.Path(root)
        self.langs: set[str] = set()
        self.py_modules: set[str] = set()       # every imported dotted module and its prefixes
        self.py_refs: set[str] = set()          # dotted names referenced, import aliases resolved (yaml.load)
        self.py_called_attrs: set[str] = set()  # method / function names that are called
        self.py_strings: set[str] = set()       # module-like string constants (INSTALLED_APPS, importlib)
        self.users: dict[tuple[str, str], list] = {}   # (lang, import key) -> [(file, alias)]
        self.php_uses: set[str] = set()
        self.rb_bundler_require = False
        self.npm_script_words: set[str] = set()
        self.command_words: set[str] = set()     # words of Procfile / Dockerfile / shell scripts / CI-like config
        self.js_strings: set[str] = set()        # package names in JS / JSON build configuration and HTML
        self.py_dynamic_import = False           # importlib.import_module(<not a literal>) somewhere
        self.rs_renames: dict[str, set] = {}     # crate -> names it is renamed to in Cargo.toml (package = "...")
        self.truncated = False
        self._scan()

    # -- building
    def _scan(self) -> None:
        n = 0
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = sorted(x for x in dirnames if x not in SOURCE_SKIP_DIRS)
            for name in sorted(filenames):
                path = pathlib.Path(dirpath) / name
                if name == "package.json":
                    self._npm_scripts(path)
                elif name == "Cargo.toml":
                    self._cargo_renames(path)
                elif _COMMAND_FILES.match(name):
                    self._words(path, self.command_words)
                elif _JS_CONFIG_FILES.match(name):
                    self._words(path, self.js_strings, _JS_PKG_STRING)
                elif path.suffix.lower() in (".html", ".htm"):
                    self._html(path)
                lang = _LANG.get(path.suffix.lower())
                if path.suffix.lower() == ".ipynb":
                    lang = "py"
                if not lang:
                    continue
                if n >= MAX_SOURCE_FILES:
                    self.truncated = True
                    return
                try:
                    if path.stat().st_size > MAX_SOURCE_BYTES:
                        self.truncated = True
                        continue
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                n += 1
                self.langs.add(lang)
                if path.suffix.lower() == ".ipynb":
                    text = _notebook_code(text)
                try:
                    getattr(self, "_scan_" + lang)(path, text)
                except (RecursionError, ValueError, MemoryError):
                    self.truncated = True

    def _use(self, lang: str, key: str, path: pathlib.Path, alias: str = "") -> None:
        self.users.setdefault((lang, key), []).append((path, alias))

    def _npm_scripts(self, path: pathlib.Path) -> None:
        try:
            data = _json(path)
        except (OSError, ValueError, RecursionError):
            return
        scripts = data.get("scripts") or {}
        for cmd in scripts.values() if isinstance(scripts, dict) else ():
            self.npm_script_words |= set(re.findall(r"[@\w][\w./\-]*", str(cmd)))
        # inline tool configuration ("babel": {"presets": [...]}, "eslintConfig", "jest", "prettier", ...)
        for key, value in data.items():
            if key not in _PACKAGE_JSON_NON_CONFIG and isinstance(value, (dict, list)):
                self.js_strings |= {m.group(1) for m in _JS_PKG_STRING.finditer(json.dumps(value))}

    def _small_text(self, path: pathlib.Path) -> str:
        try:
            if path.stat().st_size > MAX_SOURCE_BYTES:
                return ""
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def _words(self, path: pathlib.Path, into: set, rx=None) -> None:
        text = self._small_text(path)
        if rx:
            into |= {m.group(1) for m in rx.finditer(text)}
            return
        words = set(re.findall(r"[@\w][\w./\-]*", text))
        into |= words | {w.split(".")[0] for w in words if "." in w}        # pymdownx.superfences -> pymdownx

    def _html(self, path: pathlib.Path) -> None:
        """<script src="node_modules/x/..."> and inline <script type="module"> imports: npm packages used by a page."""
        text = self._small_text(path)
        self.js_strings |= {m.group(1) for m in _NODE_MODULES_REF.finditer(text)}
        for m in _JS_IMPORT.finditer(text):
            pkg = _js_package(next((g for g in m.groups() if g), ""))
            if pkg:
                self.js_strings.add(pkg)

    def _cargo_renames(self, path: pathlib.Path) -> None:
        try:
            secs = _toml_sections(self._small_text(path))
        except (ValueError, RecursionError):
            return
        for sec, lines in secs.items():
            if re.search(r"(^|\.)(dev-|build-)?dependencies$", sec):
                for key, value in _toml_keys(lines).items():
                    m = re.search(r'package\s*=\s*"([^"]+)"', value)
                    if m:
                        self.rs_renames.setdefault(m.group(1), set()).add(key)
            m = re.search(r"(?:^|\.)(?:dev-|build-)?dependencies\.([A-Za-z0-9_\-]+)$", sec)
            if m:
                real = _toml_keys(lines).get("package", "").strip('"\'')
                if real:
                    self.rs_renames.setdefault(real, set()).add(m.group(1))

    def _py_module(self, mod: str) -> None:
        parts = mod.split(".")
        for i in range(1, len(parts) + 1):
            self.py_modules.add(".".join(parts[:i]))

    def _scan_py(self, path: pathlib.Path, text: str) -> None:
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError):
            for m in _PY_IMPORT_LINE.finditer(text):                 # Python 2 or broken file: imports by regex
                for mod in (m.group(2) or m.group(1)).split(","):
                    mod = mod.split(" as ")[0].strip()
                    if _MODULE_STRING.fullmatch(mod):
                        self._py_module(mod)
            if _PY_DYNAMIC.search(text):
                self.py_dynamic_import = True
            return
        alias: dict[str, str] = {}
        nodes = list(ast.walk(tree))
        for node in nodes:
            if isinstance(node, ast.Import):
                for a in node.names:
                    self._py_module(a.name)
                    alias[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                self._py_module(node.module)
                for a in node.names:
                    alias[a.asname or a.name] = f"{node.module}.{a.name}"
                    self._py_module(f"{node.module}.{a.name}")       # may be a submodule (from google.cloud import storage)
                    self.py_refs.add(f"{node.module}.{a.name}")
        for node in nodes:
            if isinstance(node, ast.Call):
                f = node.func
                if isinstance(f, ast.Attribute):
                    self.py_called_attrs.add(f.attr)
                elif isinstance(f, ast.Name):
                    self.py_called_attrs.add(alias.get(f.id, f.id).rsplit(".", 1)[-1])
                fname = f.attr if isinstance(f, ast.Attribute) else alias.get(f.id, f.id) if isinstance(f, ast.Name) else ""
                if fname.rsplit(".", 1)[-1] in _PY_IMPORTERS and node.args and not (
                        isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
                    self.py_dynamic_import = True                       # the module name is computed at run time
            if isinstance(node, (ast.Attribute, ast.Name)):
                chain, cur = [], node
                while isinstance(cur, ast.Attribute):
                    chain.append(cur.attr)
                    cur = cur.value
                if isinstance(cur, ast.Name) and cur.id in alias:
                    self.py_refs.add(".".join([alias[cur.id]] + chain[::-1]))
            elif isinstance(node, ast.Constant) and isinstance(node.value, str) and len(node.value) <= 80 \
                    and _MODULE_STRING.fullmatch(node.value):
                self.py_strings.add(node.value)
                self.py_strings.add(node.value.split(".")[0])

    def _scan_js(self, path: pathlib.Path, text: str) -> None:
        seen = set()
        for m in _JS_IMPORT.finditer(text):
            pkg = _js_package(next((g for g in m.groups() if g), ""))
            if pkg and pkg not in seen:
                seen.add(pkg)
                self._use("js", pkg, path)
        name = path.name.lower()
        if "config" in name or name.startswith((".", "gulpfile", "gruntfile")):   # webpack loaders, babel presets
            self.js_strings |= {m.group(1) for m in _JS_PKG_STRING.finditer(text)}

    def _scan_java(self, path: pathlib.Path, text: str) -> None:
        names = {m.group(1).rstrip(".") for m in _JAVA_IMPORT.finditer(text)}
        names |= {m.group(1).rstrip(".") for m in _JAVA_FQN.finditer(text)}     # used fully qualified, no import
        for name in names:
            self._use("java", name, path)

    def _scan_go(self, path: pathlib.Path, text: str) -> None:
        found = [(m.group(1) or "", m.group(2)) for m in _GO_IMPORT.finditer(text)]
        for block in _go_import_blocks(text):
            found += [(m.group(1) or "", m.group(2)) for m in _GO_LINE.finditer(block)]
        for alias, imp in set(found):
            self._use("go", imp, path, alias)

    def _scan_php(self, path: pathlib.Path, text: str) -> None:
        for rx in (_PHP_USE, _PHP_FQN):
            self.php_uses |= {m.group(1).lower() for m in rx.finditer(text)}

    def _scan_rb(self, path: pathlib.Path, text: str) -> None:
        for m in _RB_REQUIRE.finditer(text):
            self._use("rb", m.group(1), path)
        if "Bundler.require" in text:
            self.rb_bundler_require = True

    def _scan_rs(self, path: pathlib.Path, text: str) -> None:
        for name in {g for m in _RS_PATH.finditer(text) for g in m.groups() if g}:
            self._use("rs", name, path)

    def _scan_cs(self, path: pathlib.Path, text: str) -> None:
        for name in {m.group(1).lower() for m in _CS_USING.finditer(text)}:
            self._use("cs", name, path)

    def _scan_dart(self, path: pathlib.Path, text: str) -> None:
        for name in {m.group(1) for m in _DART_IMPORT.finditer(text)}:
            self._use("dart", name, path)

    # -- questions
    def _keys(self, lang: str):
        return [k for (lg, k) in self.users if lg == lang]

    def _files(self, lang: str, keys) -> list:
        out, seen = [], set()
        for k in keys:
            for item in self.users.get((lang, k), ()):
                if item not in seen:
                    seen.add(item)
                    out.append(item)
        return out

    @staticmethod
    def python_import_names(dist: str) -> list[str]:
        n = pypi_name(dist)
        names = list(PY_IMPORT_NAMES.get(n, ()))
        names += [n.replace("-", "_"), n.replace("-", ".")]
        for prefix in ("python-", "py-"):
            if n.startswith(prefix):
                names.append(n[len(prefix):].replace("-", "_"))
        if n.endswith("-python"):
            names.append(n[:-7].replace("-", "_"))
        return list(dict.fromkeys(names))

    @staticmethod
    def java_prefixes(coord: str) -> tuple[list[str], bool]:
        """(package prefixes, certain). ``certain`` = the prefixes are known to be this artifact's packages."""
        group, _, artifact = coord.partition(":")
        mapped = JAVA_PACKAGES.get(coord) or JAVA_PACKAGES.get(group)
        if mapped:
            return list(mapped), True
        if "." not in group:
            return [], False
        return [group], False

    def _matching(self, pkg: Package) -> tuple[str, list]:
        """(status, matching import keys) for a package."""
        eco, name = pkg.ecosystem.split(":")[0], pkg.name
        lang = _ECO_LANG.get(eco)
        if not lang or lang not in self.langs:
            return UNKNOWN, []
        miss = UNKNOWN if self.truncated else NOT_IMPORTED
        if eco == "PyPI":
            names = self.python_import_names(name)
            lower = {m.lower() for m in self.py_modules}
            hit = [n for n in names if n in self.py_modules or n.lower() in lower]
            if hit or any(n in self.py_strings for n in names):
                return IMPORTED, hit or names[:1]
            if any(n in self.command_words for n in [pypi_name(name)] + names):    # gunicorn app:app, celery -A
                return IMPORTED, names[:1]
            return (UNKNOWN if self.py_dynamic_import else miss), []
        if eco == "npm":
            for n in (name,) + tuple(pkg.aliases):
                if (lang, n) in self.users:
                    return IMPORTED, [n]
                words = self.npm_script_words | self.command_words
                if n in words or n.split("/")[-1] in words or n in self.js_strings:
                    return IMPORTED, [n]
            return (UNKNOWN if name.startswith("@types/") else miss), []
        if eco == "Maven":
            prefixes, certain = self.java_prefixes(name)
            keys = [k for k in self._keys("java") if any(k == p or k.startswith(p + ".") for p in prefixes)]
            if keys:
                return IMPORTED, keys
            if not prefixes or name.startswith(_JAVA_RUNTIME_LOADED):
                return UNKNOWN, []
            if name.startswith(_SPRING_IMPLICIT) and any(k.startswith("org.springframework") for k in self._keys("java")):
                return UNKNOWN, []
            if not certain:      # the group id is only a guess at the package name: same vendor imported = unsure
                seg = prefixes[0].split(".")
                vendor = ".".join(seg[:3] if seg[0] in ("org", "com", "io", "net") and len(seg) > 3 else seg[:2])
                if any(k.startswith(vendor + ".") for k in self._keys("java")):
                    return UNKNOWN, []
            return miss, []
        if eco == "Go":
            keys = [k for k in self._keys("go") if k == name or k.startswith(name + "/")]
            return (IMPORTED, keys) if keys else (miss, [])
        if eco == "Packagist":
            ns = [n.strip("\\").lower() for n in pkg.namespaces if n.strip("\\")]
            guess = [re.sub(r"[-_.]", "", name.lower()).replace("/", "\\")]
            vendor, _, short = guess[0].partition("\\")
            if vendor == short:
                guess.append(vendor)                                  # monolog/monolog -> Monolog\
            if any(u == n or u.startswith(n + "\\") for n in ns + guess for u in self.php_uses):
                return IMPORTED, ns or guess
            return (miss if ns else UNKNOWN), []
        if eco == "RubyGems":
            cands = RUBY_REQUIRE_NAMES.get(name, []) + [name, name.replace("-", "/"), name.replace("-", "_")]
            keys = [k for k in self._keys("rb") if any(k == c or k.startswith(c + "/") for c in cands)]
            if keys:
                return IMPORTED, keys
            return (UNKNOWN if self.rb_bundler_require else miss), []     # Bundler.require loads the whole Gemfile
        if eco == "crates.io":
            keys = [k.replace("-", "_") for k in [name, *sorted(self.rs_renames.get(name, ()))]]
            keys = [k for k in keys if ("rs", k) in self.users]
            return (IMPORTED, keys) if keys else (miss, [])
        if eco == "NuGet":
            n = name.lower()
            keys = [k for k in self._keys("cs") if k == n or k.startswith(n + ".") or n.startswith(k + ".")]
            return (IMPORTED, keys) if keys else (UNKNOWN, [])           # package id is not always the namespace
        if eco == "Pub":
            return (IMPORTED, [name]) if ("dart", name) in self.users else (miss, [])
        return UNKNOWN, []

    def _text_calls(self, files, symbol: str, go_alias: str | None = None) -> bool:
        last = re.split(r"::|[.#]", symbol)[-1]
        if not re.fullmatch(r"\w+", last or ""):
            return False
        for path, alias in files:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if go_alias is not None:
                a = alias or go_alias
                if a == "_":
                    continue
                if "." in symbol:                                      # Type.Method: a method call in a file using the package
                    rx = rf"\.{re.escape(last)}\s*\("
                elif a == ".":
                    rx = rf"(?<![\w.]){re.escape(last)}\b"
                else:
                    rx = rf"\b{re.escape(a)}\.{re.escape(last)}\b"
            else:
                rx = rf"\b{re.escape(last)}\s*[(<]"
            if re.search(rx, text):
                return True
        return False

    def _py_calls(self, fn: str, names: list[str]) -> bool:
        fn = fn.replace("::", ".").replace(":", ".").strip("()")
        if fn in self.py_refs:
            return True
        parts = fn.split(".")
        if len(parts) < 2:
            return False
        # Class.method: the class is referenced through its import and the method name is called somewhere
        if len(parts) >= 3 and parts[-1] in self.py_called_attrs and ".".join(parts[:-1]) in self.py_refs:
            return True
        return False

    def reach(self, pkg: Package, symbols: list[tuple[str, str]] | None = None) -> tuple[str, list[str]]:
        """Reachability of ``pkg``. ``symbols`` are the advisory's vulnerable functions as (import path or '',
        symbol). Returns (status, vulnerable symbols the code calls)."""
        status, keys = self._matching(pkg)
        if status != IMPORTED or not symbols:
            return status, []
        eco = pkg.ecosystem.split(":")[0]
        called = []
        for imp_path, sym in symbols:
            if eco == "PyPI":
                ok = self._py_calls(sym, keys)
            elif eco == "Go":
                target = imp_path or pkg.name
                files = self._files("go", [target])
                seg = [s for s in target.split("/") if not re.fullmatch(r"v\d+", s)]
                default = re.sub(r"^go-|[.\-]go$", "", seg[-1]).replace("-", "_") if seg else ""
                ok = bool(files) and self._text_calls(files, sym, default)
            else:
                lang = _ECO_LANG.get(eco, "")
                files = self._files(lang, keys)
                if eco == "Maven" and "." in sym:                        # com.x.Class.method: the class must be imported
                    owner = re.split(r"[#(]", sym)[0].rsplit(".", 1)[0]
                    narrowed = [k for k in keys if k == owner or owner.startswith(k + ".") or k.startswith(owner + ".")]
                    files = self._files(lang, narrowed) if narrowed else files
                    sym = re.split(r"[(]", sym)[0]
                ok = self._text_calls(files, sym)
            if ok:
                called.append(sym if not imp_path or eco != "Go" else f"{imp_path}.{sym}")
        return (CALLED, called) if called else (IMPORTED, [])
