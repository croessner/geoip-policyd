#!/bin/sh
# Download the IPinfo Lite MMDB database and replace the target file atomically.
#
# Usage: IPINFO_TOKEN=... contrib/update-ipinfo-lite.sh [target-path]
#
# Environment:
#   IPINFO_TOKEN     Required. Free token from https://ipinfo.io/lite
#   IPINFO_URL       Optional download URL. Default: https://ipinfo.io/data/ipinfo_lite.mmdb
#   IPINFO_MIN_SIZE  Optional minimum accepted file size in bytes. Default: 1048576
#
# Downloads time out after 10 minutes and are retried up to three times. The
# file must be at least IPINFO_MIN_SIZE bytes and contain the MMDB metadata
# marker. It is downloaded next to the target and moved into place with mv, so
# geoip-policyd never opens a partially written database. geoip-policyd picks
# up the new file on its next auto-reload tick or on GET /reload.
#
# IPinfo Lite data is licensed under CC BY-SA 4.0 and requires attribution:
# "IP address data powered by IPinfo" (https://ipinfo.io).

set -eu

target="${1:-/usr/share/GeoIP/ipinfo_lite.mmdb}"
url="${IPINFO_URL:-https://ipinfo.io/data/ipinfo_lite.mmdb}"
min_size="${IPINFO_MIN_SIZE:-1048576}"

if [ -z "${IPINFO_TOKEN:-}" ]; then
    echo "IPINFO_TOKEN is not set" >&2
    exit 1
fi

target_dir=$(dirname "$target")
tmp=$(mktemp "${target_dir}/.ipinfo_lite.XXXXXX")
trap 'rm -f "$tmp"' EXIT HUP INT TERM

# The token is passed via a curl config on stdin so it does not appear in the process list.
printf 'url = "%s?token=%s"\n' "$url" "$IPINFO_TOKEN" |
    curl --fail --silent --show-error --location \
        --connect-timeout 30 --max-time 600 --retry 3 --retry-delay 10 \
        --config - --output "$tmp"

size=$(wc -c < "$tmp" | tr -d ' ')
if [ "$size" -lt "$min_size" ]; then
    echo "downloaded file is only ${size} bytes, expected at least ${min_size}" >&2
    exit 1
fi

# Every MMDB file carries this marker in its metadata section; it rejects HTML error pages and other payloads.
if ! LC_ALL=C grep -q 'MaxMind.com' "$tmp"; then
    echo "downloaded file is not an MMDB database" >&2
    exit 1
fi

chmod 0644 "$tmp"
mv -f "$tmp" "$target"
trap - EXIT HUP INT TERM

echo "updated ${target} (${size} bytes)"
