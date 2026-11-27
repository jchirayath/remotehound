#!/bin/sh
# Architecture guards (SHR-2): each shared concern has ONE module, and these
# checks fail the build when code goes around it. Allow-lists are empty by
# design — keep them empty. Complements the semgrep rules in .semgrep/standard/.
set -eu
cd "$(dirname "$0")/.."
fail=0
check() { # name, pattern, paths, allowed-path-regex
  hits=$(grep -rnE "$2" $3 2>/dev/null | grep -vE "$4" | grep -v '_test.go' || true)
  if [ -n "$hits" ]; then echo "✗ $1"; echo "$hits" | sed 's/^/    /'; fail=1; else echo "✓ $1"; fi
}
GO="--include=*.go internal cmd client docs web"
check "CORE-1 env only in config"        'os\.(Getenv|LookupEnv|Environ)\('    "$GO" '^internal/core/config/'
check "CORE-3 no fmt/log printing"        '(fmt\.Print|log\.Print|log\.Fatal|println\()' "$GO" '^cmd/'
check "CORE-6 outbound HTTP only in httpx" '(http\.(Get|Post|Head)\(|http\.DefaultClient|&http\.Client\{|http\.Client\{)' "$GO" '^internal/core/httpx/|^internal/app/app\.go:.*nosemgrep|^internal/control/(docker|run)\.go:.*nosemgrep'
check "CORE-8 state written only by store" 'os\.WriteFile\(.*state' "$GO" '^internal/core/store/'
check "SEC-21 no math/rand for secrets"   '"math/rand"' "$GO" '^$'
check "SEC-2 no shell exec"               'exec\.Command\("(sh|bash|cmd|powershell)"' "$GO" '^$'
check "CORE-12 fetch only in lib/api.js"  'fetch\(' "--include=*.js web/ui" '^web/ui/lib/api\.js:|^web/ui/tests/'
check "CORE-13 no raw colors in UI"       '#[0-9a-fA-F]{3,8}\b|rgba?\(' "--include=*.css --include=*.js web/ui" '^web/ui/tokens\.css:|^web/ui/tests/|^web/ui/lib/icons\.js:'
check "THEME-5 no inline SVG outside icons" '<svg|createElementNS' "--include=*.js web/ui/screens web/ui/app.js" '^$'
# Dependencies: exactly one external module (ADR-0002).
deps=$(go list -m -f '{{if not .Main}}{{if not .Indirect}}{{.Path}}{{end}}{{end}}' all 2>/dev/null | sort -u | tr -d ' ')
if [ "$deps" != "golang.org/x/crypto" ]; then echo "✗ go.mod must require only golang.org/x/crypto, found: $deps"; fail=1; else echo "✓ one external Go module"; fi
exit $fail
