#!/usr/bin/env sh
# Install a pinned uv release after verifying the installer's SHA-256.
#
# `curl https://astral.sh/uv/install.sh | sh` executes whatever the CDN serves at
# that moment. Here the installer is downloaded to a file, its digest compared to
# the one pinned below (taken from the GitHub release assets), and only then run.
# The pinned installer in turn carries the SHA-256 of every uv artifact it may
# download, so the whole chain is anchored in this repository.
#
# Bumping uv: change UV_VERSION and UV_INSTALLER_SHA256 together. The digest is
#   sha256sum of https://github.com/astral-sh/uv/releases/download/<ver>/uv-installer.sh
# Both may also be overridden through the environment.
#
# The installer honours UV_INSTALL_DIR and UV_NO_MODIFY_PATH=1.
set -eu

UV_VERSION="${UV_VERSION:-0.12.17}"
UV_INSTALLER_SHA256="${UV_INSTALLER_SHA256:-37b82230b28617c6c24fa52364fa28aa37f2aa40c114809a623f6b064a9730e5}"
url="https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/uv-installer.sh"

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d' ' -f1
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$1" | sed 's/^.*= //'
    else
        echo "install-uv: need sha256sum, shasum or openssl to verify the installer" >&2
        exit 1
    fi
}

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT INT TERM

echo "[*] Downloading uv ${UV_VERSION} installer"
curl -LsSf --proto '=https' --tlsv1.2 "$url" -o "$tmp"

actual="$(sha256_of "$tmp" | tr 'A-F' 'a-f')"
if [ "$actual" != "$UV_INSTALLER_SHA256" ]; then
    echo "[!] uv installer checksum mismatch - refusing to run it" >&2
    echo "    expected: ${UV_INSTALLER_SHA256}" >&2
    echo "    actual:   ${actual}" >&2
    exit 1
fi

echo "[*] Checksum OK, installing uv ${UV_VERSION}"
sh "$tmp"
