#!/bin/sh
# TEST ONLY: writes deploy/test/e2e.env for the e2e overlay with fresh, throwaway
# random keys. Never reuse this file for a real deployment. Prints no key.
#   sh deploy/test/make-env.sh            # keeps an existing file
#   sh deploy/test/make-env.sh --force    # replaces it (the bundle's volumes must be reset too)
set -eu
out="$(dirname "$0")/e2e.env"
if [ -f "$out" ] && [ "${1:-}" != "--force" ]; then
  echo "kept existing $out"
  exit 0
fi
umask 077
{
  echo RH_DOMAIN=localhost
  echo RH_PUBLIC_URL=https://localhost:8443
  echo RH_AUTH_MODE=proxy
  echo RH_SSH_PUBLISH=127.0.0.1:2222
  echo "RH_SECRET_KEY=$(openssl rand -hex 32)"
  echo "RH_GUAC_JSON_SECRET=$(openssl rand -hex 16)"
} > "$out"
echo "wrote $out"
