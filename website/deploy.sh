#!/usr/bin/env bash
# =============================================================================
# deploy.sh — publish the RemoteHound project website.
#
#   website/deploy.sh             # render, sync, verify
#   website/deploy.sh --dry-run   # render and show what would change
#
# website/index.html is a template: the public URLs of a particular install
# ({{CONSOLE_URL}}, {{MESH_URL}}, …) are placeholders, because this repo is
# meant to be public and keeps owner data out (ci/check-public.mjs). The real
# values come from the git-ignored local/website.env:
#
#   SITE_HOST=…            the site's own host name (used for the check at the end)
#   CONSOLE_URL=https://…  the RemoteHound console (no trailing slash)
#   MESH_URL=https://…     the MeshCentral server the "Why we built it" part links to
#   SIGN_IN_NOTE=…         one sentence above the links, e.g. who can sign in
#   DEPLOY_SSH=…           ssh destination of the web server (a Host alias works)
#   DEPLOY_DIR=…           folder the web server serves this site from
#
# The web server's site block (TLS, headers, CSP) lives with the server's own
# configuration, not here. The page has no scripts and loads nothing from
# elsewhere, so a strict CSP fits: default-src 'none'; img-src 'self';
# style-src 'unsafe-inline'.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."

c()   { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
ok()  { printf '\033[1;32m  ✓\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

DRY=""
[[ "${1:-}" == "--dry-run" ]] && DRY="--dry-run"

ENVF="local/website.env"
[[ -f "$ENVF" ]] || die "$ENVF is missing — see the header of this script for what it holds"
# shellcheck disable=SC1090
set -a; . "$ENVF"; set +a
for v in SITE_HOST CONSOLE_URL MESH_URL SIGN_IN_NOTE DEPLOY_SSH DEPLOY_DIR; do
  [[ -n "${!v:-}" ]] || die "$v is not set in $ENVF"
done
CONSOLE_URL="${CONSOLE_URL%/}"; MESH_URL="${MESH_URL%/}"
CONSOLE_HOST="${CONSOLE_URL#*://}"; MESH_HOST="${MESH_URL#*://}"

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/img"
cp website/img/* "$STAGE/img/"
# Browsers (Safari especially) also ask for these at the root, without reading the page's <link> tags.
cp website/img/favicon.ico "$STAGE/favicon.ico"
cp website/img/apple-touch-icon.png "$STAGE/apple-touch-icon.png"

# Render the template. Values are substituted literally (no shell or sed
# expansion of their contents) and HTML-escaped.
CONSOLE_URL="$CONSOLE_URL" CONSOLE_HOST="$CONSOLE_HOST" MESH_URL="$MESH_URL" MESH_HOST="$MESH_HOST" \
SIGN_IN_NOTE="$SIGN_IN_NOTE" python3 -I - website/index.html "$STAGE/index.html" <<'PY'
import html, os, re, sys
src, dst = sys.argv[1], sys.argv[2]
keys = ["CONSOLE_URL", "CONSOLE_HOST", "MESH_URL", "MESH_HOST", "SIGN_IN_NOTE"]
text = open(src, encoding="utf-8").read()
for k in keys:
    text = text.replace("{{" + k + "}}", html.escape(os.environ[k], quote=True))
left = sorted(set(re.findall(r"\{\{[A-Z_]+\}\}", text)))
if left:
    sys.exit("unfilled placeholders: " + ", ".join(left))
open(dst, "w", encoding="utf-8").write(text)
PY
# every image the page names must be staged
for f in $(grep -oE 'img/[A-Za-z0-9._-]+' "$STAGE/index.html" | sort -u); do
  [[ -f "$STAGE/$f" ]] || die "index.html uses $f, which isn't in website/img"
done
ok "rendered index.html and $(find "$STAGE/img" -type f | wc -l | tr -d ' ') images"

c "Syncing to $DEPLOY_SSH:$DEPLOY_DIR${DRY:+ (dry run)}"
ssh -o BatchMode=yes -o ConnectTimeout=20 "$DEPLOY_SSH" "sudo mkdir -p '$DEPLOY_DIR'" \
  || die "cannot reach $DEPLOY_SSH"
# --checksum: the rendered files are new every run, so compare content, not
# mtimes; --itemize-changes so a dry run says out loud whether anything differs.
rsync -rlz --checksum --delete --itemize-changes $DRY --rsync-path="sudo rsync" \
  -e "ssh -o BatchMode=yes" "$STAGE/" "$DEPLOY_SSH:$DEPLOY_DIR/"
[[ -n "$DRY" ]] && { echo "  dry run: nothing copied"; exit 0; }
# The web server must be able to read everything; nobody else may write it.
ssh -o BatchMode=yes "$DEPLOY_SSH" "sudo chown -R root:root '$DEPLOY_DIR' && sudo chmod -R a+rX,go-w '$DEPLOY_DIR'"
ok "synced"

c "Verifying https://$SITE_HOST/"
# (curl prints 000 itself when it cannot connect; a new name may not resolve here yet.)
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "https://$SITE_HOST/")" || true
[[ "$code" == 200 ]] || die "https://$SITE_HOST/ answered ${code:-000} — if the name is new, local DNS may not have it yet: curl --resolve $SITE_HOST:443:<server IP> https://$SITE_HOST/"
curl -s --max-time 20 "https://$SITE_HOST/" | grep -q '{{' && die "the live page still has placeholders"
ok "https://$SITE_HOST/ -> 200, fully rendered"
