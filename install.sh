#!/bin/sh
set -eu
release=https://github.com/NahaNCode/nahan-subscription-gateway/releases/download/v0.1.5
manifest_sha=__MANIFEST_SHA256__
installer_sha=__INSTALLER_SHA256__
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 10 --max-time 60 "$release/install.py" -o "$work/install.py"
printf '%s  %s\n' "$installer_sha" "$work/install.py" | sha256sum -c - >/dev/null
python3 "$work/install.py" --release-url "$release" --manifest-sha256 "$manifest_sha" --install-dir /opt/nahan-edge --install-timer "$@"
