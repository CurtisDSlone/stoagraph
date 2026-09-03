#!/bin/sh
# StoaGraph installer.
#
#   curl -sSL https://raw.githubusercontent.com/CurtisDSlone/stoagraph/v0.3.1/install.sh | sh
#
# ---------------------------------------------------------------------------------------------------
# About piping this into your shell.
#
# You are installing a product whose entire argument is "do not trust — verify". It would be rude of us
# to then ask you to execute an unread script from the internet. So:
#
#   * This script is IN the repo, at the tag it installs. What you read is what runs.
#   * It downloads a released binary and VERIFIES its SHA-256 against the published checksums before
#     executing anything. If the checksum does not match, it stops.
#   * The checksums file is signed (cosign, keyless). Verifying that signature is one command, printed
#     at the end, and we would rather you ran it.
#   * Nothing is installed with sudo unless you point it at a directory that needs it.
#
# If you would rather read first (you should; we would):
#
#   curl -sSLO https://raw.githubusercontent.com/CurtisDSlone/stoagraph/v0.3.1/install.sh
#   less install.sh && sh install.sh
# ---------------------------------------------------------------------------------------------------
set -eu

REPO="CurtisDSlone/stoagraph"
VERSION="${STOAGRAPH_VERSION:-v0.3.1}"
BINDIR="${STOAGRAPH_BINDIR:-$HOME/.local/bin}"

say()  { printf '  %s\n' "$*"; }
die()  { printf '\n  error: %s\n' "$*" >&2; exit 1; }

printf '\nStoaGraph %s — verifiable control for AI agents\n\n' "$VERSION"

# ---- what are we running on ----
os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) die "unsupported architecture: $arch" ;;
esac
case "$os" in
  linux|darwin) ;;
  *) die "unsupported OS: $os (on Windows, download the .exe from the releases page)" ;;
esac
bin="stoagraph-$os-$arch"

command -v docker >/dev/null 2>&1 || die "docker is required — https://docs.docker.com/get-docker/"

base="https://github.com/$REPO/releases/download/$VERSION"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# ---- download ----
say "downloading $bin"
curl -sSfL "$base/$bin"        -o "$tmp/$bin"        || die "could not download $bin ($VERSION)"
curl -sSfL "$base/checksums.txt" -o "$tmp/checksums.txt" || die "could not download checksums.txt"

# ---- VERIFY before we execute anything ----
# This is the whole reason the script is safe to pipe. If the bytes are not the bytes we published,
# nothing runs.
say "verifying sha256"
want=$(grep " $bin\$" "$tmp/checksums.txt" | awk '{print $1}')
[ -n "$want" ] || die "no checksum published for $bin"

if command -v sha256sum >/dev/null 2>&1; then
  got=$(sha256sum "$tmp/$bin" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  got=$(shasum -a 256 "$tmp/$bin" | awk '{print $1}')
else
  die "need sha256sum or shasum to verify the download; refusing to install unverified"
fi

[ "$want" = "$got" ] || die "CHECKSUM MISMATCH — expected $want, got $got. Not installing."
say "sha256 ok"

# ---- install ----
mkdir -p "$BINDIR"
install -m 0755 "$tmp/$bin" "$BINDIR/stoagraph" 2>/dev/null || {
  cp "$tmp/$bin" "$BINDIR/stoagraph" && chmod 0755 "$BINDIR/stoagraph"; }
say "installed $BINDIR/stoagraph"

case ":$PATH:" in
  *":$BINDIR:"*) ;;
  *) printf '\n  note: %s is not on your PATH. Add it, or run the full path below.\n' "$BINDIR" ;;
esac

cat <<EOF

  Next:

    stoagraph up      mint your control-plane role secrets, pull the signed images, start

  Then open the console at http://localhost:3000 (the login link is printed by 'up') and wire your
  first tool from the empty state, or start from examples/custom-tool.

  Verify what you just installed (we would):

    cosign verify-blob --signature checksums.txt.sig --certificate checksums.txt.pem \\
      --certificate-identity-regexp 'https://github.com/$REPO/.*' \\
      --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt

    cosign verify ghcr.io/$REPO/stag-serve:$VERSION \\
      --certificate-identity-regexp 'https://github.com/$REPO/.*' \\
      --certificate-oidc-issuer https://token.actions.githubusercontent.com

EOF
