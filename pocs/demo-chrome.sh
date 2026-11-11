#!/usr/bin/env bash
set -euo pipefail

DOMAIN=${1:?usage: $0 <domain> [proxy port] [path]}
PORT=${2:-1234}
URL_PATH=${3:-/cat.html}

CHROME=${CHROME:-"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}
[ -x "$CHROME" ] || CHROME=$(command -v google-chrome || command -v chromium) || { echo "Chrome not found, set CHROME=" >&2; exit 1; }

PROFILE=$(mktemp -d "${TMPDIR:-/tmp}/opossum-chrome.XXXXXX")
trap 'rm -rf "$PROFILE"' EXIT

# CHROME_FLAGS: optional extra flags, e.g. CHROME_FLAGS="--incognito"
# shellcheck disable=SC2086
"$CHROME" --user-data-dir="$PROFILE" \
    --host-resolver-rules="MAP $DOMAIN 127.0.0.1:$PORT" \
    --no-first-run --no-default-browser-check \
    ${CHROME_FLAGS:-} \
    "https://$DOMAIN$URL_PATH"
