#!/usr/bin/env bash
# =============================================================================
# guide-pdf.sh — print the device setup guide to a PDF for the website.
#
#   website/guide-pdf.sh OUT.pdf [BASE_URL]
#
# The guide's one source is web/ui/guide/device-setup.html, the same page the
# console's Enroll > "Setup guide" fills in with a live code. Here the code is
# left blank (a box to write it in) and the commands show BASE_URL — by default
# CONSOLE_URL from the git-ignored local/website.env. The address is written
# into a staged copy, never into the repo (ci/check-public.mjs).
#
# Needs Google Chrome or Chromium (headless print). Set CHROME=/path/to/chrome
# if it isn't found.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."

die() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

OUT="${1:-}"
[[ -n "$OUT" ]] || die "usage: website/guide-pdf.sh OUT.pdf [BASE_URL]"
BASE="${2:-}"
if [[ -z "$BASE" ]]; then
  [[ -f local/website.env ]] || die "no BASE_URL given and local/website.env is missing"
  BASE="$(sed -n 's/^CONSOLE_URL=//p' local/website.env | tr -d '"'"'" | head -1)"
fi
BASE="${BASE%/}"
# The public URL allow-list from docs/specs/CLIENT_PROTOCOL.md §1, https only.
[[ "$BASE" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$ ]] \
  || die "BASE_URL '$BASE' is not a plain https:// server address"

CHROME="${CHROME:-}"
if [[ -z "$CHROME" ]]; then
  for c in "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
           "/Applications/Chromium.app/Contents/MacOS/Chromium" \
           "$(command -v google-chrome || true)" "$(command -v chromium || true)" "$(command -v chromium-browser || true)"; do
    [[ -n "$c" && -x "$c" ]] && { CHROME="$c"; break; }
  done
fi
[[ -n "$CHROME" && -x "$CHROME" ]] || die "Chrome or Chromium not found; set CHROME=/path/to/chrome"

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/guide" "$STAGE/brand"
cp web/ui/tokens.css "$STAGE/tokens.css"
cp web/ui/brand/mark.svg "$STAGE/brand/mark.svg"
cp web/ui/guide/guide.css "$STAGE/guide/guide.css"

# Write the address in (literally, HTML-escaped) and drop the script: modules
# don't run from file://, and the blank guide needs none.
BASE="$BASE" python3 -I - web/ui/guide/device-setup.html "$STAGE/guide/device-setup.html" <<'PY'
import html, os, re, sys
src, dst = sys.argv[1], sys.argv[2]
text = open(src, encoding="utf-8").read()
if "https://your-server" not in text:
    sys.exit("device-setup.html no longer has the https://your-server placeholder")
text = text.replace("https://your-server", html.escape(os.environ["BASE"], quote=True))
text, n = re.subn(r'\s*<script type="module" src="guide\.js"></script>', "", text)
if n != 1:
    sys.exit("device-setup.html: expected exactly one guide.js script tag")
open(dst, "w", encoding="utf-8").write(text)
PY

mkdir -p "$(dirname "$OUT")"
"$CHROME" --headless=new --disable-gpu --no-first-run --no-default-browser-check \
  --user-data-dir="$STAGE/chrome" --no-pdf-header-footer \
  --print-to-pdf="$OUT" "file://$STAGE/guide/device-setup.html" >/dev/null 2>&1 \
  || die "Chrome could not print the guide"
[[ "$(head -c 4 "$OUT" 2>/dev/null)" == "%PDF" ]] || die "$OUT is not a PDF"
printf '  \033[1;32m✓\033[0m %s (%s KB)\n' "$OUT" "$(( $(wc -c <"$OUT") / 1024 ))"
