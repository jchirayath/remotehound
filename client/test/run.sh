#!/bin/sh
# RemoteHound client test harness  (@feature:enroll)
#
#   sh client/test/run.sh            run everything with every shell found
#   RH_SHELLS="sh dash" sh client/test/run.sh
#
# (a) syntax: sh -n / dash -n / bash -n / zsh-as-sh -n on bootstrap.sh and the
#     tunnel.sh / uninstall.sh it writes (extracted from their heredocs)
# (b) PowerShell: parses bootstrap.ps1 and its embedded tunnel.ps1 / uninstall.ps1
#     with the real parser (pwsh), and checks the file is pure ASCII (PS 5.1 safe)
# (c) functional: bootstrap.sh in RH_TEST_MODE against fake_server.py: files,
#     permissions, the JSON it sent, hostile hostname, hostile server answers,
#     refused code, re-enrollment, uninstall dry run
# (d) watchdog: tunnel.sh with a stub `ssh`: revoked handling, state file,
#     backoff sequence, SIGTERM, log rotation, bad config
# Every result line is "PASS @feature:enroll <name>" or "FAIL @feature:enroll <name>".
set -u
LC_ALL=C; export LC_ALL
HERE=$(cd "$(dirname "$0")" && pwd)
CLIENT=$(dirname "$HERE")
BS="$CLIENT/bootstrap.sh"
PS="$CLIENT/bootstrap.ps1"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/rh test.XXXXXX")     # the space is deliberate
WORK=$(cd "$WORK" && pwd)                              # canonical, as the scripts see it
SERVER_PID=""
PASSES=0; FAILS=0

cleanup() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
  [ -n "${KEEP:-}" ] || rm -rf "$WORK"; [ -n "${KEEP:-}" ] && echo "kept $WORK"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

pass() { PASSES=$((PASSES + 1)); echo "PASS @feature:enroll $*"; }
fail() { FAILS=$((FAILS + 1)); echo "FAIL @feature:enroll $*"; }
check() { name=$1; shift; if "$@"; then pass "$name"; else fail "$name"; fi; }
has()    { grep -F -q -- "$2" "$1" 2>/dev/null; }      # has FILE STRING
hasnt()  { ! grep -F -q -- "$2" "$1" 2>/dev/null; }
perm()   { [ "$(ls -ld "$1" | cut -c1-10)" = "$2" ]; }
shcmd()  { case $1 in zsh-sh) echo "zsh --emulate sh" ;; *) echo "$1" ;; esac; }
extract() { sed -n "/<<'$2'/,/^$2\$/p" "$1" | sed '1d;$d'; }

# wait_pid PID TENTHS: wait for a background job with a timeout; returns its status
wait_pid() {
  wp=0
  while kill -0 "$1" 2>/dev/null; do
    wp=$((wp + 1))
    if [ "$wp" -gt "$2" ]; then kill -9 "$1" 2>/dev/null; wait "$1" 2>/dev/null; return 124; fi
    sleep 0.1
  done
  wait "$1"
}

if [ -n "${RH_SHELLS:-}" ]; then SHELLS=$RH_SHELLS
else
  SHELLS=sh
  for s in dash bash; do command -v "$s" >/dev/null 2>&1 && SHELLS="$SHELLS $s"; done
  command -v zsh >/dev/null 2>&1 && SHELLS="$SHELLS zsh-sh"
fi
echo "shells: $SHELLS"

# ---------------------------------------------------------------------------
# (a) syntax
# ---------------------------------------------------------------------------
extract "$BS" RH_TUNNEL_EOF >"$WORK/tunnel.sh"
extract "$BS" RH_UNINSTALL_EOF >"$WORK/uninstall.sh"
check "syntax: tunnel.sh heredoc extracted" test -s "$WORK/tunnel.sh"
check "syntax: uninstall.sh heredoc extracted" test -s "$WORK/uninstall.sh"
for s in $SHELLS; do
  for f in "$BS" "$WORK/tunnel.sh" "$WORK/uninstall.sh"; do
    check "syntax: $s -n $(basename "$f")" $(shcmd "$s") -n "$f"
  done
done
check "placeholders: bootstrap.sh has each placeholder exactly once" \
  test "$(grep -c '__RH_BASE_URL__' "$BS")" = 1 -a "$(grep -c '__RH_CODE__' "$BS")" = 1
check "safety: bootstrap.sh never uses eval" sh -c "! grep -En '(^|[;&|[:space:]])eval[[:space:]]' '$BS'"
if command -v shellcheck >/dev/null 2>&1; then
  check "shellcheck: bootstrap.sh" shellcheck -s sh -S warning "$BS"
  check "shellcheck: tunnel.sh" shellcheck -s sh -S warning "$WORK/tunnel.sh"
fi

# ---------------------------------------------------------------------------
# (b) PowerShell parse
# ---------------------------------------------------------------------------
PWSH=$(command -v pwsh 2>/dev/null || echo /usr/local/bin/pwsh)
if [ -f "$PS" ]; then
  check "ps1: bootstrap.ps1 is pure ASCII (safe for PS 5.1 and irm|iex)" \
    sh -c "! LC_ALL=C grep -n '[^ -~	]' '$PS' | grep -q ."
  check "placeholders: bootstrap.ps1 has each placeholder exactly once" \
    test "$(grep -c '__RH_BASE_URL__' "$PS")" = 1 -a "$(grep -c '__RH_CODE__' "$PS")" = 1
  if [ -x "$PWSH" ]; then
    "$PWSH" -NoProfile -NonInteractive -File "$HERE/parse_ps1.ps1" "$PS" >"$WORK/ps.out" 2>&1
    ps_rc=$?
    while IFS= read -r l; do
      case $l in OK*) pass "ps1 parse: ${l#OK }" ;; SKIP*) echo "SKIP @feature:enroll ps1 parse: ${l#SKIP }" ;; *) fail "ps1 parse: $l" ;; esac
    done <"$WORK/ps.out"
    check "ps1 parse: parser exit status 0" test "$ps_rc" = 0
  else
    echo "SKIP ps1 parse (pwsh not found)"
  fi
else
  fail "ps1: client/bootstrap.ps1 missing"
fi

# ---------------------------------------------------------------------------
# (c) functional: bootstrap.sh against the fake server
# ---------------------------------------------------------------------------
python3 -I "$HERE/fake_server.py" --port-file "$WORK/port" --record "$WORK/requests.jsonl" &
SERVER_PID=$!
i=0; while [ ! -s "$WORK/port" ] && [ "$i" -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
PORT=$(cat "$WORK/port" 2>/dev/null)
check "fake server started" test -n "$PORT"
BASE="http://127.0.0.1:$PORT"

mkbs() { sed -e "s#__RH_BASE_URL__#$BASE#" -e "s#__RH_CODE__#$1#" "$BS" >"$WORK/bs-$1.sh"; }
# runbs SHELL CODE TESTDIR OUT [hostname]: sets RC
runbs() {
  mkbs "$2"
  if [ $# -ge 5 ]; then
    RH_TEST_MODE=1 RH_TEST_DIR="$3" RH_TEST_SERVICES="ssh:22 vnc:5900" RH_TEST_HOSTNAME="$5" \
      $(shcmd "$1") "$WORK/bs-$2.sh" >"$4" 2>&1
  else
    RH_TEST_MODE=1 RH_TEST_DIR="$3" RH_TEST_SERVICES="ssh:22 vnc:5900" \
      $(shcmd "$1") "$WORK/bs-$2.sh" >"$4" 2>&1
  fi
  RC=$?
}
# json_ok CODE EXPECTED_HOSTNAME PUBFILE: the last POST for CODE was valid JSON with these values
json_ok() {
  python3 -I - "$WORK/requests.jsonl" "$1" "$2" "$3" <<'PY'
import json, sys
rec, code, host, pubf = sys.argv[1:]
posts = [json.loads(l) for l in open(rec) if '"POST"' in l]
mine = [p for p in posts if json.loads(p["raw"]).get("code") == code]
assert mine, "no request for code"
p = mine[-1]
assert p["content_type"] == "application/json", p["content_type"]
assert not p["errors"], p["errors"]
b = json.loads(p["raw"])
assert b["hostname"] == host, (b["hostname"], host)
assert b["public_key"] == open(pubf).read().strip(), "public key differs from id_ed25519.pub"
assert b["services"] == [{"kind": "ssh", "remote_port": 22}, {"kind": "vnc", "remote_port": 5900}], b["services"]
assert b["client_version"] == "1" and b["os"] in ("macos", "linux")
# Tests run unprivileged: a per-user install, reported with this account's name.
import getpass
assert b["install_scope"] == "user" and b["install_user"] == getpass.getuser(), (b["install_scope"], b["install_user"])
PY
}
fp_of() { ssh-keygen -l -f "$1" | awk '{print $2}'; }
no_secret() {   # no_secret KEYFILE FILE...: no private key material in any FILE
  k=$1; shift
  body=$(sed -n '2p' "$k")
  for f in "$@"; do hasnt "$f" "PRIVATE KEY" && hasnt "$f" "$body" || return 1; done
}

STUB="$WORK/stub"; mkdir -p "$STUB"
cat >"$STUB/ssh" <<'STUB_EOF'
#!/bin/sh
# Stub ssh for the watchdog tests. STUB_MODE: revoke | fail | hang
printf '%s\n' "$@" >"$STUB_OUT/args"
cat >"$STUB_OUT/stdin"
case ${STUB_MODE:-revoke} in
  revoke) echo "ok ${STUB_DEV:-dev_stub}"; echo ping; printf 'revoked\n'; exit 0 ;;
  fail)   echo "ssh: connect to host rh.test.invalid port 2222: Connection refused" >&2; exit 255 ;;
  hang)   echo "ok ${STUB_DEV:-dev_stub}"; echo "$$" >"$STUB_OUT/pid"; exec sleep 30 ;;
  # real OpenSSH resolves the options without connecting (-G): proves they parse
  config) "$REAL_SSH" -G "$@" >"$STUB_OUT/config" 2>&1; echo revoked; exit 0 ;;
esac
STUB_EOF
chmod 755 "$STUB/ssh"
REAL_SSH=$(command -v ssh); export REAL_SSH

for s in $SHELLS; do
  T="$WORK/$s home"; D="$T/remotehound"; O="$WORK/$s.out"
  # -- happy path, with a hostile hostname --------------------------------
  EVIL=$(printf 'evil"host\\name$(id)`x`;\nline2\033[31m')
  runbs "$s" k7q2mx "$T" "$O" "$EVIL"
  check "[$s] enroll: exit 0" test "$RC" = 0
  check "[$s] enroll: prints Connected as <name>" has "$O" 'Connected as Test ? "evilhostnameidxline231m"'
  check "[$s] enroll: all six steps shown" sh -c "grep -c '^\[[1-6]/6\]' '$O' | grep -qx 6"
  check "[$s] enroll: request JSON well-formed, hostname sanitised" \
    json_ok k7q2mx evilhostnameidxline231m "$D/id_ed25519.pub"
  DEV=$(sed -n 's/^RH_DEVICE_ID=//p' "$D/device.conf" 2>/dev/null)
  check "[$s] files: device.conf contents" sh -c "
    grep -qx 'RH_BASE_URL=$BASE' '$D/device.conf' &&
    grep -Eqx 'RH_DEVICE_ID=dev_[a-f0-9]{12}' '$D/device.conf' &&
    grep -qx 'RH_SSH_HOST=rh.test.invalid' '$D/device.conf' &&
    grep -qx 'RH_SSH_PORT=2222' '$D/device.conf' &&
    grep -qx 'RH_FORWARDS=22:localhost:22 5900:localhost:5900' '$D/device.conf' &&
    grep -qx 'RH_CLIENT_VERSION=1' '$D/device.conf'"
  check "[$s] files: known_hosts holds the pinned line" \
    sh -c "grep -Eqx '\[rh\.test\.invalid\]:2222 ssh-ed25519 AAAA[A-Za-z0-9+/]+' '$D/known_hosts' && test \$(wc -l <'$D/known_hosts') -eq 1"
  check "[$s] files: private key mode 600" perm "$D/id_ed25519" "-rw-------"
  check "[$s] files: folder mode 700" perm "$D" "drwx------"
  check "[$s] files: device.conf mode 600" perm "$D/device.conf" "-rw-------"
  check "[$s] files: no leftover .new key" sh -c "! ls '$D' | grep -q '\.new'"
  check "[$s] files: tunnel.sh syntax" $(shcmd "$s") -n "$D/tunnel.sh"
  check "[$s] files: uninstall.sh syntax" $(shcmd "$s") -n "$D/uninstall.sh"
  check "[$s] files: tunnel.sh identical to the heredoc" cmp -s "$D/tunnel.sh" "$WORK/tunnel.sh"
  check "[$s] files: tunnel.log has the enroll line" has "$D/tunnel.log" "INFO enrolled as $DEV"
  check "[$s] security: private key never printed" no_secret "$D/id_ed25519" "$O" "$D/tunnel.log" "$WORK/requests.jsonl"
  check "[$s] status poll sent the URL-encoded local fingerprint" python3 -I -c "
import json,sys
gets=[json.loads(l) for l in open(sys.argv[1]) if '\"GET\"' in l]
q=[g['query'] for g in gets if g['query'].get('device_id')==sys.argv[2]]
assert q and q[-1]['fingerprint']==sys.argv[3], q" "$WORK/requests.jsonl" "$DEV" "$(fp_of "$D/id_ed25519.pub")"

  # -- re-enrollment with a new code: same folder, new key, new device ----------
  FP1=$(fp_of "$D/id_ed25519.pub")
  runbs "$s" k7q2my "$T" "$O.2"
  FP2=$(fp_of "$D/id_ed25519.pub")
  DEV2=$(sed -n 's/^RH_DEVICE_ID=//p' "$D/device.conf")
  check "[$s] re-enroll: exit 0" test "$RC" = 0
  check "[$s] re-enroll: key regenerated" test -n "$FP2" -a "$FP1" != "$FP2"
  check "[$s] re-enroll: device.conf replaced" test -n "$DEV2" -a "$DEV" != "$DEV2"
  check "[$s] re-enroll: key still mode 600" perm "$D/id_ed25519" "-rw-------"

  # -- failures must leave the working enrollment untouched ----------------------
  cp "$D/device.conf" "$WORK/conf.before"; cp "$D/id_ed25519" "$WORK/key.before"
  runbs "$s" usedzz "$T" "$O.used"
  check "[$s] used code: exit 1" test "$RC" = 1
  check "[$s] used code: server detail shown" has "$O.used" "This code has already been used. (ENROLL_CODE_USED). Ask whoever"
  for bad in badzzz badfwd badhst; do
    runbs "$s" "$bad" "$T" "$O.$bad"
    check "[$s] hostile answer $bad: refused (exit 1)" test "$RC" = 1
    check "[$s] hostile answer $bad: says invalid" has "$O.$bad" "The server sent an invalid"
  done
  check "[$s] failures: device.conf untouched" cmp -s "$D/device.conf" "$WORK/conf.before"
  check "[$s] failures: key untouched" cmp -s "$D/id_ed25519" "$WORK/key.before"
  check "[$s] failures: no leftover .new key" sh -c "! ls '$D' | grep -q '\.new'"
  check "[$s] failures: nothing injected" test ! -e /tmp/rh-pwned

  # -- not substituted / not served by the server ------------------------------
  RH_TEST_MODE=1 RH_TEST_DIR="$WORK/raw" $(shcmd "$s") "$BS" >"$O.raw" 2>&1; RC=$?
  check "[$s] raw script refuses to run" test "$RC" = 1
  check "[$s] raw script explains why" has "$O.raw" "has to be downloaded from your RemoteHound server"

  # -- wget instead of curl (also keeps the problem+json body of a 410) -----------
  if [ "$s" = sh ] && command -v wget >/dev/null 2>&1; then
    RH_TEST_NO_CURL=1; export RH_TEST_NO_CURL
    runbs "$s" k7q2mz "$WORK/wget home" "$O.wget" wget-host.1
    check "[$s] wget: enroll exit 0" test "$RC" = 0
    check "[$s] wget: connected" has "$O.wget" "Connected as"
    check "[$s] wget: request JSON well-formed" json_ok k7q2mz wget-host.1 "$WORK/wget home/remotehound/id_ed25519.pub"
    runbs "$s" usedzz "$WORK/wget home" "$O.wget2"
    check "[$s] wget: used code detail shown" has "$O.wget2" "This code has already been used."
    unset RH_TEST_NO_CURL
  fi

  # -- uninstall dry run ---------------------------------------------------------
  RH_TEST_MODE=1 $(shcmd "$s") "$D/uninstall.sh" >"$O.un" 2>&1; RC=$?
  check "[$s] uninstall: dry run exit 0" test "$RC" = 0
  check "[$s] uninstall: would remove the folder" has "$O.un" "would run: rm -rf $D"
  check "[$s] uninstall: dry run kept the folder" test -f "$D/device.conf"

  # ---------------------------------------------------------------------------
  # (d) watchdog
  # ---------------------------------------------------------------------------
  W="$WORK/$s wd/remotehound"; mkdir -p "$(dirname "$W")"; cp -R "$D" "$W"
  SO="$WORK/$s stub"; mkdir -p "$SO"
  wd() {  # wd MODE [extra env...]: run the watchdog in the background, sets WPID
    md=$1; shift
    env PATH="$STUB:$PATH" RH_TEST_MODE=1 RH_TEST_FAST=1 STUB_OUT="$SO" STUB_MODE="$md" STUB_DEV="$DEV2" "$@" \
      $(shcmd "$s") "$W/tunnel.sh" 2>>"$SO/watchdog.stderr" &
    WPID=$!
  }
  # revoked: control lines logged, state written, exit 0
  wd revoke; wait_pid "$WPID" 100; RC=$?
  check "[$s] watchdog revoked: exits 0" test "$RC" = 0
  check "[$s] watchdog revoked: state=revoked" sh -c "test \"\$(cat '$W/state')\" = revoked"
  check "[$s] watchdog revoked: control lines in log" sh -c "
    grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z INFO server: ok $DEV2\$' '$W/tunnel.log' &&
    grep -q 'INFO server: ping\$' '$W/tunnel.log' && grep -q 'INFO server: revoked\$' '$W/tunnel.log' &&
    grep -q 'INFO ssh exited rc=0\$' '$W/tunnel.log'"
  check "[$s] watchdog: ssh arguments per protocol" sh -c "
    a='$SO/args'
    grep -qx -- '-T' \"\$a\" && grep -qx 'StrictHostKeyChecking=yes' \"\$a\" && grep -qx 'BatchMode=yes' \"\$a\" &&
    grep -qx 'IdentitiesOnly=yes' \"\$a\" && grep -qx 'ExitOnForwardFailure=yes' \"\$a\" &&
    grep -qx 'ServerAliveInterval=15' \"\$a\" && grep -qx 'ServerAliveCountMax=3' \"\$a\" &&
    grep -qx 'ConnectTimeout=15' \"\$a\" && grep -qx '2222' \"\$a\" &&
    grep -qxF 'UserKnownHostsFile=\"$W/known_hosts\"' \"\$a\" && grep -qxF '$W/id_ed25519' \"\$a\" &&
    grep -qx '22:localhost:22' \"\$a\" && grep -qx '5900:localhost:5900' \"\$a\" &&
    grep -qx '$DEV2@rh.test.invalid' \"\$a\" && grep -qx 'agent' \"\$a\" && grep -qx 'v1' \"\$a\" &&
    grep -Eqx 'os=(macos|linux)' \"\$a\" && grep -qx 'ver=1' \"\$a\" && grep -Eqx 'host=[A-Za-z0-9._-]+' \"\$a\" &&
    grep -qx 'services=ssh:22,vnc:5900' \"\$a\""
  check "[$s] watchdog: stdin carried the log tail" has "$SO/stdin" "INFO connecting to rh.test.invalid:2222 as $DEV2"
  check "[$s] watchdog: no private key in log or upload" no_secret "$W/id_ed25519" "$W/tunnel.log" "$SO/stdin"
  rm -f "$W/state"
  wd config; wait_pid "$WPID" 100
  check "[$s] watchdog: real ssh -G accepts the options (paths with spaces)" sh -c "
    c='$SO/config'
    grep -qixF 'userknownhostsfile $W/known_hosts' \"\$c\" && grep -qixF 'identityfile $W/id_ed25519' \"\$c\" &&
    grep -qix 'stricthostkeychecking true' \"\$c\" && grep -qix 'exitonforwardfailure yes' \"\$c\" &&
    grep -qix 'batchmode yes' \"\$c\" && grep -qix 'port 2222' \"\$c\" && grep -qix 'user $DEV2' \"\$c\" &&
    grep -qix 'serveraliveinterval 15' \"\$c\" && grep -Eqi '^remoteforward 22 \\[?localhost\\]?:22\$' \"\$c\""
  # stays down once revoked
  rm -f "$SO/args"
  wd revoke; wait_pid "$WPID" 100; RC=$?
  check "[$s] watchdog revoked: re-start exits 0 without connecting" sh -c "test $RC = 0 && test ! -e '$SO/args'"
  check "[$s] watchdog revoked: says so in the log" has "$W/tunnel.log" "device is revoked; not connecting"
  # backoff: 255 every time -> 4 8 16 ... 300 300, jitter within 0..b/2
  rm -f "$W/state"; : >"$W/tunnel.log"
  wd fail RH_TEST_MAX_LOOPS=9; wait_pid "$WPID" 200; RC=$?
  SEQ=$(sed -n 's/.* retrying in \([0-9]*\)s (+[0-9]*s jitter)$/\1/p' "$W/tunnel.log" | tr '\n' ' ')
  check "[$s] watchdog backoff: sequence 4 8 16 32 64 128 256 300 300 (got: $SEQ)" \
    test "$SEQ" = "4 8 16 32 64 128 256 300 300 "
  check "[$s] watchdog backoff: jitter within 0..backoff/2" sh -c "
    sed -n 's/.* retrying in \([0-9]*\)s (+\([0-9]*\)s jitter)\$/\1 \2/p' '$W/tunnel.log' |
    awk '{ if (\$2 < 0 || \$2 > int(\$1 / 2)) bad = 1; n++ } END { exit (bad || n != 9) }'"
  check "[$s] watchdog backoff: rc and ssh error logged" sh -c "
    grep -q 'INFO ssh exited rc=255\$' '$W/tunnel.log' && grep -q 'WARN ssh: ssh: connect to host' '$W/tunnel.log'"
  # SIGTERM while connected: ssh is stopped, watchdog leaves cleanly
  rm -f "$SO/pid"
  wd hang; i=0; while [ ! -s "$SO/pid" ] && [ "$i" -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
  SPID=$(cat "$SO/pid" 2>/dev/null); sleep 0.3
  kill -TERM "$WPID" 2>/dev/null; wait_pid "$WPID" 50; RC=$?
  check "[$s] watchdog SIGTERM: exits promptly (rc=$RC)" test "$RC" != 124
  check "[$s] watchdog SIGTERM: ssh child stopped" sh -c "test -n '$SPID' && ! kill -0 '$SPID' 2>/dev/null"
  check "[$s] watchdog SIGTERM: logged and cleaned up" sh -c "
    grep -q 'INFO stopping (SIGTERM)\$' '$W/tunnel.log' && test ! -e '$W/.control' && test ! -e '$W/tunnel.pid'"
  [ -n "$SPID" ] && kill "$SPID" 2>/dev/null
  # log rotation at 1 MB, keep 1; upload is at most 50 lines
  awk 'BEGIN { for (i = 0; i < 12000; i++) printf "2026-01-01T00:00:00Z INFO filler %06d xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n", i }' >"$W/tunnel.log"
  rm -f "$W/state" "$W/tunnel.log.1"
  wd revoke; wait_pid "$WPID" 100
  check "[$s] watchdog log rotation: tunnel.log.1 kept, tunnel.log fresh" sh -c "
    test \$(wc -c <'$W/tunnel.log.1') -gt 1048576 && test \$(wc -c <'$W/tunnel.log') -lt 4096 &&
    grep -q 'server: revoked' '$W/tunnel.log'"
  check "[$s] watchdog: uploads at most 50 log lines" test "$(wc -l <"$SO/stdin")" -le 50
  # invalid device.conf: refuses to connect
  rm -f "$W/state" "$SO/args"
  sed 's/^RH_DEVICE_ID=.*/RH_DEVICE_ID=dev_X;rm/' "$W/device.conf" >"$W/device.conf.x" && mv "$W/device.conf.x" "$W/device.conf"
  wd revoke; wait_pid "$WPID" 100; RC=$?
  check "[$s] watchdog bad config: exit 1, no ssh, error logged" sh -c "
    test $RC = 1 && test ! -e '$SO/args' && grep -q 'ERROR device.conf' '$W/tunnel.log'"
done

echo
echo "passed: $PASSES  failed: $FAILS"
[ "$FAILS" -eq 0 ]
