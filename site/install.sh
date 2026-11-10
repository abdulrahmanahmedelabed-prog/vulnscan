#!/bin/sh
# Kashif (vulnscan) installer for macOS and Linux.
#
#   curl -fsSL https://abdulrahmanahmedelabed-prog.github.io/vulnscan/install.sh | sh   # vulnscan: ignore
#
# Downloads the latest release binary for this machine, verifies its SHA-256 against the release's SHA256SUMS.txt,
# and installs it as "vulnscan" (plus a "kashif" alias) into $KASHIF_INSTALL_DIR (default: ~/.local/bin).
# curl sets no quarantine attribute, so macOS Gatekeeper does not block the un-notarized binary.
# Options (environment): KASHIF_VERSION=v0.8.0 to pin a release; KASHIF_INSTALL_DIR=/path to choose the folder.
set -eu

REPO="abdulrahmanahmedelabed-prog/vulnscan"
DIR="${KASHIF_INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${KASHIF_VERSION:-latest}"

say() { printf '%s\n' "kashif: $*"; }
die() { printf '%s\n' "kashif: error: $*" >&2; exit 1; }

case "$(uname -s)" in
  Darwin)
    arch="$(uname -m)"
    # an Intel shell under Rosetta on Apple Silicon still gets the native arm64 build
    if [ "$arch" = "x86_64" ] && [ "$(sysctl -in sysctl.proc_translated 2>/dev/null || echo 0)" = "1" ]; then arch=arm64; fi
    case "$arch" in
      arm64) ASSET="vulnscan-macos-arm64" ;;
      x86_64) ASSET="vulnscan-macos-x86_64" ;;
      *) die "unsupported macOS CPU: $arch" ;;
    esac ;;
  Linux)
    case "$(uname -m)" in
      x86_64|amd64) ASSET="vulnscan-linux" ;;
      *) die "no prebuilt binary for $(uname -m); install with: pip install vulnscan" ;;
    esac ;;
  *) die "unsupported system $(uname -s); on Windows use install.ps1 or download vulnscan-windows.exe" ;;
esac

case "$VERSION" in
  latest) BASE="https://github.com/$REPO/releases/latest/download" ;;
  v[0-9]*.[0-9]*.[0-9]*) BASE="https://github.com/$REPO/releases/download/$VERSION" ;;
  *) die "KASHIF_VERSION must look like v1.2.3" ;;
esac

if command -v sha256sum >/dev/null 2>&1; then SHA="sha256sum"
elif command -v shasum >/dev/null 2>&1; then SHA="shasum -a 256"
else die "need sha256sum or shasum to verify the download"; fi
command -v curl >/dev/null 2>&1 || die "curl is required"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT TERM

say "downloading $ASSET ($VERSION)"
curl -fsSL --proto '=https' --tlsv1.2 -o "$TMP/$ASSET" "$BASE/$ASSET"
curl -fsSL --proto '=https' --tlsv1.2 -o "$TMP/SHA256SUMS.txt" "$BASE/SHA256SUMS.txt"

expected="$(awk -v f="$ASSET" '$2 == f || $2 == "*" f { print $1 }' "$TMP/SHA256SUMS.txt")"
[ -n "$expected" ] || die "SHA256SUMS.txt has no entry for $ASSET"
actual="$($SHA "$TMP/$ASSET" | awk '{print $1}')"
[ "$expected" = "$actual" ] || die "checksum mismatch for $ASSET (expected $expected, got $actual); nothing was installed"
say "checksum verified"

chmod 0755 "$TMP/$ASSET"
"$TMP/$ASSET" --version >/dev/null 2>&1 || die "the downloaded binary does not run on this machine"

mkdir -p "$DIR"
mv -f "$TMP/$ASSET" "$DIR/vulnscan"
ln -sf "$DIR/vulnscan" "$DIR/kashif"
say "installed $("$DIR/vulnscan" --version) to $DIR/vulnscan"

case ":$PATH:" in
  *":$DIR:"*) ;;
  *) say "add $DIR to your PATH, e.g.: echo 'export PATH=\"$DIR:\$PATH\"' >> ~/.profile" ;;
esac
say "run 'vulnscan ui' for the web interface, or 'vulnscan ./project' to scan from the terminal"
