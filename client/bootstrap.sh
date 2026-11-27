#!/bin/sh
# =============================================================================
#  RemoteHound device bootstrap for Linux and macOS            (Apache-2.0)
#  Client protocol v1 - see docs/specs/CLIENT_PROTOCOL.md in the RemoteHound repo
# =============================================================================
#
#  You were probably asked to run:    curl -sL https://<server>/e/<code> | sh
#  To read this script first, run:    curl -sL https://<server>/e/<code>
#  (Downloading it does not use up the code. Only step 3 below does.)
#
#  WHAT IT DOES
#   1. Checks this computer: OS, whether you are root, and which remote-access
#      services already listen on localhost (SSH 22, RDP 3389, VNC 5900).
#   2. Makes a new SSH key pair for this device (ed25519). The private key
#      never leaves this computer and is never printed or logged.
#   3. Sends the PUBLIC key, the one-time code, the hostname, the OS and the
#      service list to your RemoteHound server. The server answers with this
#      device's id and the server's host key, which is pinned.
#   4. Turns on built-in services where it can (root only): Remote Login/sshd;
#      on macOS it opens the Sharing settings so you can switch on Screen
#      Sharing; on Linux with GNOME (as your user) GNOME Remote Desktop.
#      It never installs packages and never opens a firewall port: all access
#      goes through the outbound tunnel below.
#   5. Writes a small watchdog script (tunnel.sh) and a service entry that
#      keeps ONE outbound `ssh -R` connection to the server running, and
#      starts it. The server can then reach only the forwarded local ports.
#   6. Waits until the server sees the tunnel and prints "Connected".
#
#  WHAT IT WRITES (nothing else on the system is changed)
#   Linux, root   /etc/remotehound/
#                 /etc/systemd/system/remotehound-tunnel.service
#   Linux, user   ~/.config/remotehound/
#                 ~/.config/systemd/user/remotehound-tunnel.service
#   macOS, root   /Library/Application Support/RemoteHound/
#                 /Library/LaunchDaemons/net.remotehound.tunnel.plist
#   macOS, user   ~/Library/Application Support/RemoteHound/
#                 ~/Library/LaunchAgents/net.remotehound.tunnel.plist
#   The folder holds: id_ed25519 (+ .pub), known_hosts, device.conf,
#   tunnel.sh, tunnel.log, state and uninstall.sh.
#
#  HOW TO UNDO
#   sh "<folder>/uninstall.sh"      (prefix with sudo if you installed with sudo)
#   It stops the tunnel, removes the service entry and deletes the folder.
#   It leaves sshd / Remote Login / Screen Sharing as they are, because you
#   may rely on them; turn those off yourself if you want.
#
#  Running it again with a new code is safe: the folder is reused, a fresh key
#  is made and the service entry is replaced. If enrollment fails, an existing
#  working connection is left untouched.
#
#  Exit status: 0 connected, 1 error, 2 enrolled but not online within 60 s
#  (the watchdog keeps retrying in the background).
# =============================================================================

# Everything lives in functions and runs from the last line, so a download
# that is cut short cannot run half a script.

set -eu
umask 077                      # every file and folder we create is private
LC_ALL=C; export LC_ALL        # predictable tr/sed/awk/grep behavior

# ---- filled in by the server when it hands out this script -----------------
RH_BASE_URL='__RH_BASE_URL__'
RH_CODE='__RH_CODE__'
# -----------------------------------------------------------------------------
RH_CLIENT_VERSION=1
RH_LABEL=net.remotehound.tunnel          # launchd label
RH_UNIT=remotehound-tunnel.service       # systemd unit name
RH_TEST=${RH_TEST_MODE:-0}               # 1 only under client/test/run.sh
RH_TMP=""; RH_NEWKEY=""; RH_ENABLE=""; RH_NOTES=""; RH_SERVICES=""

# ---- output -----------------------------------------------------------------
step() { printf '\n[%s/6] %s\n' "$1" "$2"; }
ok()   { printf '  \342\234\223 %s\n' "$*"; }          # ✓
warn() { printf '  ! %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
die()  { printf '  \342\234\227 %s\n' "$*" >&2; exit 1; }   # ✗
note() { RH_NOTES="$RH_NOTES$*
"; }                                                     # shown in step 4

# ---- small helpers ----------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

# rh_match REGEX VALUE: VALUE is one line and matches the extended regex.
rh_match() {
  case $2 in *'
'*) return 1 ;; esac
  printf '%s\n' "$2" | grep -Eq "$1"
}

# rh_clean VALUE ALLOWED_CHARS MAXLEN: drop every character not in the set.
rh_clean() { printf '%s' "$1" | tr -cd "$2" | cut -c "1-$3"; }

# rh_json_str VALUE: a JSON string literal (control chars dropped, \ and " escaped).
rh_json_str() {
  printf '"%s"' "$(printf '%s' "$1" | tr -d '\000-\037\177' | sed 's/\\/\\\\/g; s/"/\\"/g')"
}

# rh_json_flatten < json > kv: turns a JSON document into "path=value" lines,
# e.g. data.device_id=dev_x and data.forwards.0=22:localhost:22. A small
# recursive-descent parser in POSIX awk: no eval, no python (on macOS python3
# may only be an installer stub). Control characters are removed from values.
rh_json_flatten() {
  awk '
  function ws() { while (pos <= n && index(" \t\r\n", substr(s, pos, 1)) > 0) pos++ }
  function str(   c, out) {
    out = ""; pos++
    while (pos <= n) {
      c = substr(s, pos, 1)
      if (c == "\"") { pos++; return out }
      if (c == "\\") {
        pos++; c = substr(s, pos, 1)
        if (c == "u") { c = "?"; pos += 4 }
        else if (c == "n" || c == "r" || c == "t" || c == "b" || c == "f") c = " "
      }
      out = out c; pos++
    }
    bad = 1; return out
  }
  function val(path,   c, cl, d, k, i, start) {
    if (bad || depth > 20) { bad = 1; return }
    ws(); c = substr(s, pos, 1)
    if (c == "{" || c == "[") {
      cl = (c == "{") ? "}" : "]"
      depth++; pos++; ws(); i = 0
      if (substr(s, pos, 1) == cl) { pos++; depth--; return }
      while (!bad) {
        ws()
        if (c == "{") {
          if (substr(s, pos, 1) != "\"") { bad = 1; return }
          k = str(); ws()
          if (substr(s, pos, 1) != ":") { bad = 1; return }
          pos++
          val((path == "") ? k : (path "." k))
        } else {
          val((path == "") ? i : (path "." i)); i++
        }
        ws(); d = substr(s, pos, 1); pos++
        if (d == cl) { depth--; return }
        if (d != ",") { bad = 1; return }
      }
      return
    }
    if (c == "\"") { print path "=" str(); return }
    start = pos
    while (pos <= n && index("+-.0123456789abcdefghijklmnopqrstuvwxyzE", substr(s, pos, 1)) > 0) pos++
    if (pos == start) { bad = 1; return }
    print path "=" substr(s, start, pos - start)
  }
  { s = s $0 "\n" }
  END { n = length(s); pos = 1; depth = 0; bad = 0; val(""); if (bad) exit 2 }
  ' | tr -d '\000-\011\013-\037\177'
}

# rh_jget KEY: value of KEY from the last flattened response ($RH_KV).
rh_jget() { awk -v k="$1" 'index($0, k "=") == 1 { print substr($0, length(k) + 2); exit }' "$RH_KV"; }

# rh_http METHOD URL BODYFILE-or-"" OUTFILE: sets RH_STATUS ("000" = no answer).
rh_http() {
  : >"$4"
  if [ "$RH_HTTP" = curl ]; then
    if [ -n "$3" ]; then
      RH_STATUS=$(curl -sS --connect-timeout 15 --max-time 30 -o "$4" -w '%{http_code}' \
        -A "RemoteHound-bootstrap/$RH_CLIENT_VERSION" -H 'Accept: application/json' \
        -H 'Content-Type: application/json' -X "$1" --data-binary "@$3" "$2") || RH_STATUS=000
    else
      RH_STATUS=$(curl -sS --connect-timeout 15 --max-time 30 -o "$4" -w '%{http_code}' \
        -A "RemoteHound-bootstrap/$RH_CLIENT_VERSION" -H 'Accept: application/json' \
        -X "$1" "$2") || RH_STATUS=000
    fi
  else
    # wget: -S prints the response headers on stderr; --content-on-error keeps
    # the problem+json body of 4xx answers (GNU wget >= 1.14).
    if [ -n "$3" ]; then
      wget -q -S -T 30 -O "$4" --content-on-error --header='Content-Type: application/json' \
        --post-file="$3" "$2" 2>"$RH_TMP/wget.hdr" || :
    else
      wget -q -S -T 30 -O "$4" --content-on-error "$2" 2>"$RH_TMP/wget.hdr" || :
    fi
    RH_STATUS=$(awk '$1 ~ /^HTTP\// { c = $2 } END { print (c == "" ? "000" : c) }' "$RH_TMP/wget.hdr")
  fi
  case $RH_STATUS in [0-9][0-9][0-9]) ;; *) RH_STATUS=000 ;; esac
}

# rh_port_open PORT: 0 = something listens on 127.0.0.1:PORT, 1 = nothing,
# 2 = cannot tell. POSIX sh has no sockets, so: `nc -z` if present (BSD, OpenBSD,
# ncat and busybox nc all accept -z -w), else bash's /dev/tcp if bash exists,
# else 2 and the caller falls back to "is the matching daemon enabled?".
rh_port_open() {
  if have nc; then
    nc -z -w 1 127.0.0.1 "$1" </dev/null >/dev/null 2>&1 && return 0
    return 1
  fi
  if have bash; then
    bash -c 'exec 3<>"/dev/tcp/127.0.0.1/$1"' rh "$1" </dev/null >/dev/null 2>&1 && return 0
    return 1
  fi
  return 2
}

# Fallback for rh_port_open = 2: assume the service is there if its daemon runs.
rh_sd_active() { have systemctl && systemctl is-active --quiet "$1" 2>/dev/null; }
rh_daemon_enabled() {
  case $RH_OS:$1 in
    linux:ssh) rh_sd_active ssh || rh_sd_active sshd ;;
    linux:rdp) rh_sd_active xrdp || rh_sd_active gnome-remote-desktop ;;
    macos:ssh) launchctl print system/com.openssh.sshd >/dev/null 2>&1 ;;
    macos:vnc) launchctl print system/com.apple.screensharing >/dev/null 2>&1 ;;
    *) return 1 ;;
  esac
}

rh_add_service() {
  case " $RH_SERVICES " in *" $1 "*) ;; *) RH_SERVICES="${RH_SERVICES:+$RH_SERVICES }$1" ;; esac
}

# Stops a watchdog started without a service manager (nohup fallback).
rh_kill_pidfile() {
  rh_pid=$(cat "$1" 2>/dev/null || :)
  case $rh_pid in ''|*[!0-9]*) return 0 ;; esac
  if ps -p "$rh_pid" -o args= 2>/dev/null | grep -q 'tunnel\.sh'; then kill "$rh_pid" 2>/dev/null || :; fi
}

rh_cleanup() {
  if [ -n "$RH_NEWKEY" ]; then rm -f "$RH_NEWKEY" "$RH_NEWKEY.pub"; fi   # enrollment did not finish
  if [ -n "$RH_TMP" ]; then rm -rf "$RH_TMP"; fi
}

# =============================================================================
#  Stage 1: what is this computer?
# =============================================================================
stage1() {
  step 1 "Checking this computer"
  case $(uname -s) in
    Linux)  RH_OS=linux ;;
    Darwin) RH_OS=macos ;;
    *) die "This script is for Linux and macOS. On Windows use the PowerShell command instead." ;;
  esac
  for rh_tool in ssh ssh-keygen; do
    have "$rh_tool" || die "'$rh_tool' was not found. Install the OpenSSH client (e.g. 'sudo apt install openssh-client' or 'sudo dnf install openssh-clients') and run the command again."
  done
  if have curl && [ "${RH_TEST_NO_CURL:-0}" != 1 ]; then RH_HTTP=curl     # (the override is for tests)
  elif have wget; then RH_HTTP=wget
  else die "Neither curl nor wget was found. Install curl and run the command again."; fi
  if [ "$(id -u)" -eq 0 ]; then RH_ROOT=1; else RH_ROOT=0; fi

  # Hostname: only [A-Za-z0-9._-], at most 64 characters.
  if [ "$RH_TEST" = 1 ] && [ -n "${RH_TEST_HOSTNAME+x}" ]; then rh_h=$RH_TEST_HOSTNAME
  elif [ "$RH_OS" = macos ]; then rh_h=$(scutil --get LocalHostName 2>/dev/null || hostname 2>/dev/null || uname -n)
  else rh_h=$(hostname 2>/dev/null || uname -n); fi
  RH_HOSTNAME=$(rh_clean "$rh_h" 'A-Za-z0-9._-' 64)
  [ -n "$RH_HOSTNAME" ] || RH_HOSTNAME=device

  if [ "$RH_OS" = macos ]; then
    rh_v=$(sw_vers -productVersion 2>/dev/null || :); rh_pretty="macOS $rh_v"
  else
    rh_v=$(awk -F= '$1 == "ID" { id = $2 } $1 == "VERSION_ID" { v = $2 }
      END { gsub(/"/, "", id); gsub(/"/, "", v); print id " " v }' /etc/os-release 2>/dev/null || :)
    rh_pretty="Linux $rh_v"
  fi
  RH_OS_VERSION=$(rh_clean "$rh_v" 'A-Za-z0-9._ -' 128)
  ok "$rh_pretty, hostname $RH_HOSTNAME"

  # Where to install, and which service manager keeps the tunnel running.
  if [ "$RH_TEST" = 1 ]; then
    [ -n "${RH_TEST_DIR:-}" ] || die "RH_TEST_DIR must be set in test mode"
    RH_DIR="$RH_TEST_DIR/remotehound"; RH_SUP="test"
  elif [ "$RH_OS" = linux ]; then
    if [ "$RH_ROOT" = 1 ]; then
      RH_DIR=/etc/remotehound
      if [ -d /run/systemd/system ] && have systemctl; then RH_SUP=systemd-system; else RH_SUP="nohup"; fi
    else
      RH_DIR="${HOME:?}/.config/remotehound"
      if have systemctl && systemctl --user show-environment >/dev/null 2>&1; then RH_SUP=systemd-user; else RH_SUP="nohup"; fi
    fi
  else
    if [ "$RH_ROOT" = 1 ]; then RH_DIR="/Library/Application Support/RemoteHound"; RH_SUP=launchd-daemon
    else RH_DIR="${HOME:?}/Library/Application Support/RemoteHound"; RH_SUP=launchd-agent; fi
  fi
  if [ "$RH_ROOT" = 1 ]; then
    ok "Running as root: installing system-wide (the tunnel starts at boot)"
  else
    warn "Not running as root: installing for your user only. For a system-wide"
    info "install that also runs before anyone logs in, use '| sudo sh' instead."
  fi

  # Which services are listening already? (localhost only, 1 s timeout)
  if [ "$RH_TEST" = 1 ] && [ -n "${RH_TEST_SERVICES:-}" ]; then
    for rh_s in $RH_TEST_SERVICES; do
      rh_match '^(ssh|rdp|vnc):[0-9]{1,5}$' "$rh_s" || die "bad RH_TEST_SERVICES entry"
      rh_add_service "$rh_s"
    done
    ok "Services (test override): $RH_SERVICES"
    return 0
  fi
  for rh_s in ssh:22 rdp:3389 vnc:5900; do
    rh_kind=${rh_s%%:*}; rh_port=${rh_s#*:}; rh_rc=0
    rh_port_open "$rh_port" || rh_rc=$?
    if [ "$rh_rc" -eq 0 ]; then
      ok "$(echo "$rh_kind" | tr a-z A-Z) is listening on port $rh_port"; rh_add_service "$rh_s"
    elif [ "$rh_rc" -eq 2 ] && rh_daemon_enabled "$rh_kind"; then
      ok "$(echo "$rh_kind" | tr a-z A-Z) service is enabled (no nc/bash to test the port)"; rh_add_service "$rh_s"
    fi
  done

  # Plan stage 4 now, so that services it will turn on are part of the
  # registration in stage 3 (the protocol includes them even if not yet up).
  case " $RH_SERVICES " in *" ssh:22 "*) ;; *)
    if [ "$RH_OS" = linux ] && [ "$RH_ROOT" = 1 ]; then
      rh_unit=""
      for rh_u in ssh sshd; do
        if have systemctl && systemctl cat "$rh_u.service" >/dev/null 2>&1; then rh_unit=$rh_u; break; fi
      done
      if [ -n "$rh_unit" ]; then RH_ENABLE="$RH_ENABLE sshd:$rh_unit"; rh_add_service ssh:22
      else note "No SSH server is installed (package openssh-server). This script never installs packages."; fi
    elif [ "$RH_OS" = linux ]; then
      note "The SSH server is off. Turning it on needs root: sudo systemctl enable --now ssh"
    elif [ "$RH_ROOT" = 1 ]; then
      RH_ENABLE="$RH_ENABLE mac-ssh"; rh_add_service ssh:22
    else
      note "Remote Login (SSH) is off. Turning it on needs an admin: System Settings > General >"
      note "  Sharing > Remote Login, or run the command again with '| sudo sh'."
    fi ;;
  esac
  if [ "$RH_OS" = linux ]; then
    case " $RH_SERVICES " in *" rdp:3389 "*) ;; *)
      if have grdctl && [ "$RH_ROOT" = 0 ]; then
        RH_ENABLE="$RH_ENABLE grd"; rh_add_service rdp:3389
      elif have grdctl; then
        note "GNOME Remote Desktop is set up per user. As your desktop user run:"
        note "  grdctl rdp enable && grdctl rdp set-credentials <user> <password>"
      elif have krdpserver || [ "${XDG_CURRENT_DESKTOP:-}" = KDE ]; then
        note "KDE: turn on remote desktop in System Settings > Remote Desktop (krdp)."
      fi ;;
    esac
  else
    case " $RH_SERVICES " in *" vnc:5900 "*) ;; *)
      if [ -z "${SSH_CONNECTION:-}" ]; then RH_ENABLE="$RH_ENABLE mac-screen"; rh_add_service vnc:5900
      else note "Screen Sharing is off. Turn it on at the Mac: System Settings > General > Sharing > Screen Sharing."; fi ;;
    esac
  fi
  if [ -z "$RH_SERVICES" ]; then
    rh_add_service ssh:22
    warn "No remote-access service found; registering SSH (22) so the operator can add more later"
  fi
}

# =============================================================================
#  Stage 2: a fresh key pair. It is written as id_ed25519.new and only
#  replaces the current key after the server accepted it (stage 5).
# =============================================================================
stage2() {
  step 2 "Creating this device's key"
  mkdir -p "$RH_DIR" && chmod 700 "$RH_DIR" || die "Could not create $RH_DIR"
  RH_NEWKEY="$RH_DIR/id_ed25519.new"
  rm -f "$RH_NEWKEY" "$RH_NEWKEY.pub"
  ssh-keygen -q -t ed25519 -N '' -C remotehound -f "$RH_NEWKEY" </dev/null >/dev/null 2>&1 \
    || die "ssh-keygen could not create a key in $RH_DIR"
  RH_PUBKEY=$(cat "$RH_NEWKEY.pub")
  rh_match '^ssh-ed25519 [A-Za-z0-9+/]+=*( [A-Za-z0-9@._-]*)?$' "$RH_PUBKEY" || die "ssh-keygen wrote an unexpected public key"
  RH_FPR=$(ssh-keygen -l -f "$RH_NEWKEY.pub" 2>/dev/null | awk '{ print $2 }')
  rh_match '^SHA256:[A-Za-z0-9+/]+=*$' "$RH_FPR" || die "Could not read the key fingerprint (OpenSSH 6.8 or newer is needed)"
  ok "New ed25519 key $RH_FPR (the private key stays on this computer)"
}

# =============================================================================
#  Stage 3: redeem the code. The response is validated field by field before
#  anything from it is written to a file or used in a command.
# =============================================================================
stage3() {
  step 3 "Registering with $RH_BASE_URL"
  rh_sj=""
  for rh_s in $RH_SERVICES; do   # entries are validated kind:digits
    rh_sj="${rh_sj:+$rh_sj,}{\"kind\":\"${rh_s%%:*}\",\"remote_port\":${rh_s#*:}}"
  done
  # How this run installs, so the console can show it: "system" (root) or
  # "user" (this account's logins only).
  if [ "$RH_ROOT" = 1 ]; then rh_scope=system; rh_iuser=""
  else rh_scope=user; rh_iuser=$(rh_clean "$(id -un 2>/dev/null || :)" 'A-Za-z0-9._-' 64); fi
  printf '{"code":%s,"public_key":%s,"hostname":%s,"os":%s,"os_version":%s,"services":[%s],"client_version":%s,"install_scope":%s,"install_user":%s}\n' \
    "$(rh_json_str "$RH_CODE")" "$(rh_json_str "$RH_PUBKEY")" "$(rh_json_str "$RH_HOSTNAME")" \
    "$(rh_json_str "$RH_OS")" "$(rh_json_str "$RH_OS_VERSION")" "$rh_sj" \
    "$(rh_json_str "$RH_CLIENT_VERSION")" "$(rh_json_str "$rh_scope")" "$(rh_json_str "$rh_iuser")" >"$RH_TMP/request.json"

  rh_http POST "$RH_BASE_URL/api/v1/enroll" "$RH_TMP/request.json" "$RH_TMP/response.json"
  RH_KV="$RH_TMP/response.kv"
  rh_json_flatten <"$RH_TMP/response.json" >"$RH_KV" 2>/dev/null || :
  case $RH_STATUS in
    201) ;;
    000) die "Could not reach $RH_BASE_URL (network, proxy or TLS problem). Check the connection and run the command again." ;;
    *)
      rh_detail=$(rh_jget detail | cut -c1-300)
      [ -n "$rh_detail" ] || rh_detail=$(rh_jget title | cut -c1-300)
      [ -n "$rh_detail" ] || rh_detail="HTTP $RH_STATUS"
      rh_ecode=$(rh_clean "$(rh_jget code)" 'A-Z_' 40)
      case $rh_ecode in
        ENROLL_CODE_*) rh_hint=" Ask whoever gave you the command for a new code." ;;
        RATE_LIMITED)  rh_hint=" Wait a minute, then try again." ;;
        *)             rh_hint="" ;;
      esac
      die "The server refused the enrollment: $rh_detail${rh_ecode:+ ($rh_ecode)}.$rh_hint" ;;
  esac

  RH_DEVICE_ID=$(rh_jget data.device_id)
  rh_match '^dev_[a-z0-9]{6,40}$' "$RH_DEVICE_ID" || die "The server sent an invalid device id; stopping."
  RH_SSH_HOST=$(rh_jget data.ssh_host)
  rh_match '^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$' "$RH_SSH_HOST" || die "The server sent an invalid tunnel host; stopping."
  RH_SSH_PORT=$(rh_jget data.ssh_port)
  rh_match '^[0-9]{1,5}$' "$RH_SSH_PORT" && [ "$RH_SSH_PORT" -ge 1 ] && [ "$RH_SSH_PORT" -le 65535 ] \
    || die "The server sent an invalid tunnel port; stopping."
  RH_FORWARDS=""; rh_i=0
  while [ "$rh_i" -lt 16 ]; do
    rh_f=$(rh_jget "data.forwards.$rh_i"); [ -n "$rh_f" ] || break
    rh_match '^[0-9]{1,5}:localhost:[0-9]{1,5}$' "$rh_f" || die "The server sent an invalid port forward; stopping."
    RH_FORWARDS="${RH_FORWARDS:+$RH_FORWARDS }$rh_f"; rh_i=$((rh_i + 1))
  done
  [ -n "$RH_FORWARDS" ] || warn "The server allowed no port forwards yet; the operator can add services later"
  RH_KNOWN_HOSTS=$(rh_jget data.known_hosts_line)
  rh_match '^(\[[A-Za-z0-9.-]+\]:[0-9]{1,5}|[A-Za-z0-9.-]+) (ssh-ed25519|ecdsa-sha2-nistp(256|384|521)|rsa-sha2-(256|512)|ssh-rsa) [A-Za-z0-9+/]+=*$' \
    "$RH_KNOWN_HOSTS" || die "The server sent an invalid host key line; stopping."
  if [ "$RH_SSH_PORT" = 22 ]; then rh_kh=$RH_SSH_HOST; else rh_kh="[$RH_SSH_HOST]:$RH_SSH_PORT"; fi
  case $RH_KNOWN_HOSTS in "$rh_kh "*) ;; *) warn "The pinned host key is not for $rh_kh; the tunnel may fail to connect" ;; esac
  rh_sfpr=$(rh_jget data.fingerprint)
  if [ -n "$rh_sfpr" ] && [ "${rh_sfpr%%=*}" != "${RH_FPR%%=*}" ]; then
    warn "The server reports a different key fingerprint than this device's key"
  fi
  RH_DEVICE_NAME=$(rh_jget data.device_name | cut -c1-64)
  [ -n "$RH_DEVICE_NAME" ] || RH_DEVICE_NAME=$RH_HOSTNAME
  ok "Registered as $RH_DEVICE_NAME ($RH_DEVICE_ID)"
  ok "Tunnel endpoint $RH_SSH_HOST:$RH_SSH_PORT, forwarding ${RH_FORWARDS:-nothing yet}"
}

# =============================================================================
#  Stage 4: built-in services (planned in stage 1). Never installs packages
#  and never touches the firewall.
# =============================================================================
stage4() {
  step 4 "Turning on remote access services"
  if [ "$RH_TEST" = 1 ]; then info "(test mode) would run:${RH_ENABLE:- nothing}"; RH_ENABLE=""; fi
  for rh_e in $RH_ENABLE; do
    case $rh_e in
      sshd:*)
        if systemctl enable --now "${rh_e#sshd:}.service" >/dev/null 2>&1; then ok "SSH server (${rh_e#sshd:}) enabled and started"
        else warn "Could not start ${rh_e#sshd:}.service; see: systemctl status ${rh_e#sshd:}"; fi ;;
      grd)
        if grdctl rdp enable </dev/null >/dev/null 2>&1; then
          ok "GNOME Remote Desktop (RDP) enabled for $(id -un)"
          info "Set the login it asks for:  grdctl rdp set-credentials <user> <password>"
          info "and keep it running:        systemctl --user enable --now gnome-remote-desktop"
        else warn "grdctl rdp enable failed; turn on Remote Desktop in GNOME Settings > Sharing"; fi ;;
      mac-ssh)
        rh_out=$(systemsetup -setremotelogin on </dev/null 2>&1 || :)
        if rh_port_open 22 || systemsetup -getremotelogin 2>/dev/null | grep -q 'On'; then
          ok "Remote Login (SSH) turned on"
        else
          case $rh_out in *"Full Disk Access"*)
            warn "macOS needs Full Disk Access for your terminal app to change Remote Login:"
            info "System Settings > Privacy & Security > Full Disk Access > turn on Terminal,"
            info "or simply switch on System Settings > General > Sharing > Remote Login." ;;
          *) warn "Could not turn on Remote Login; switch it on in System Settings > General > Sharing." ;;
          esac
        fi ;;
      mac-screen)
        rh_pane='x-apple.systempreferences:com.apple.Sharing-Settings.extension'
        if [ -n "${SUDO_USER:-}" ]; then sudo -u "$SUDO_USER" open "$rh_pane" >/dev/null 2>&1 || :
        else open "$rh_pane" >/dev/null 2>&1 || :; fi
        warn "Screen Sharing cannot be switched on by a script. In the Sharing window that"
        info "just opened, turn on \"Screen Sharing\". The operator signs in with this Mac's"
        info "user name and password." ;;
    esac
  done
  if [ -n "$RH_NOTES" ]; then printf '%s' "$RH_NOTES" | while IFS= read -r rh_l; do warn "$rh_l"; done; fi
  if [ -z "$RH_ENABLE" ] && [ -z "$RH_NOTES" ]; then ok "Nothing to change"; fi
}

# =============================================================================
#  Stage 5: write the files and the service entry, then start the tunnel.
# =============================================================================
stage5() {
  step 5 "Installing the tunnel"
  rh_stop_existing
  rh_retire_user_install
  mv -f "$RH_NEWKEY" "$RH_DIR/id_ed25519"
  mv -f "$RH_NEWKEY.pub" "$RH_DIR/id_ed25519.pub"
  RH_NEWKEY=""
  chmod 600 "$RH_DIR/id_ed25519"; chmod 644 "$RH_DIR/id_ed25519.pub"
  printf '%s\n' "$RH_KNOWN_HOSTS" >"$RH_DIR/known_hosts"
  # Every value was validated in stage 1/3; the watchdog validates them again.
  {
    printf 'RH_BASE_URL=%s\n' "$RH_BASE_URL"
    printf 'RH_DEVICE_ID=%s\n' "$RH_DEVICE_ID"
    printf 'RH_SSH_HOST=%s\n' "$RH_SSH_HOST"
    printf 'RH_SSH_PORT=%s\n' "$RH_SSH_PORT"
    printf 'RH_FORWARDS=%s\n' "$RH_FORWARDS"
    printf 'RH_CLIENT_VERSION=%s\n' "$RH_CLIENT_VERSION"
    printf 'RH_OS=%s\n' "$RH_OS"
    printf 'RH_SERVICES=%s\n' "$RH_SERVICES"
  } >"$RH_DIR/device.conf.tmp"
  mv -f "$RH_DIR/device.conf.tmp" "$RH_DIR/device.conf"
  rh_write_tunnel >"$RH_DIR/tunnel.sh.tmp"; chmod 700 "$RH_DIR/tunnel.sh.tmp"; mv -f "$RH_DIR/tunnel.sh.tmp" "$RH_DIR/tunnel.sh"
  rh_write_uninstall >"$RH_DIR/uninstall.sh.tmp"; chmod 700 "$RH_DIR/uninstall.sh.tmp"; mv -f "$RH_DIR/uninstall.sh.tmp" "$RH_DIR/uninstall.sh"
  rm -f "$RH_DIR/state"                               # clears an old "revoked"
  printf '%s INFO enrolled as %s (%s)\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$RH_DEVICE_ID" "$RH_FPR" >>"$RH_DIR/tunnel.log"
  ok "Wrote key, known_hosts, device.conf, tunnel.sh, uninstall.sh to $RH_DIR"

  rh_tunnel="$RH_DIR/tunnel.sh"
  case $RH_SUP in
    test)
      info "(test mode) would install a $RH_SUP-style service entry running: /bin/sh '$rh_tunnel'" ;;
    systemd-system|systemd-user)
      if [ "$RH_SUP" = systemd-system ]; then
        rh_unitdir=/etc/systemd/system; rh_sc="systemctl"; rh_want=multi-user.target
      else
        rh_unitdir="$HOME/.config/systemd/user"; rh_sc="systemctl --user"; rh_want=default.target
      fi
      mkdir -p "$rh_unitdir"
      rh_exec=$(printf '%s' "$rh_tunnel" | sed 's/%/%%/g; s/\$/$$/g')
      {
        printf '%s\n' '[Unit]' 'Description=RemoteHound tunnel (outbound SSH to the RemoteHound server)' \
          'Wants=network-online.target' 'After=network-online.target' 'StartLimitIntervalSec=0' '' \
          '[Service]' 'Type=simple'
        printf 'ExecStart=/bin/sh "%s"\n' "$rh_exec"
        printf '%s\n' 'Restart=always' 'RestartSec=5' \
          '# The watchdog exits 0 only when the server revoked this device: stay down.' \
          'RestartPreventExitStatus=0' '' '[Install]' "WantedBy=$rh_want"
      } >"$rh_unitdir/$RH_UNIT.tmp"
      chmod 644 "$rh_unitdir/$RH_UNIT.tmp"; mv -f "$rh_unitdir/$RH_UNIT.tmp" "$rh_unitdir/$RH_UNIT"
      # $rh_sc is deliberately unquoted: "systemctl" or "systemctl --user".
      if $rh_sc daemon-reload && $rh_sc enable "$RH_UNIT" >/dev/null 2>&1 && $rh_sc restart "$RH_UNIT"; then
        ok "Started $RH_UNIT ($RH_SUP)"
      else
        die "Could not start $RH_UNIT; see: $rh_sc status $RH_UNIT"
      fi
      if [ "$RH_SUP" = systemd-user ] && ! loginctl show-user "$(id -un)" -p Linger 2>/dev/null | grep -q 'yes'; then
        warn "A user service stops when you log out. To keep the tunnel up after logout and"
        info "reboot, ask an admin to run:  sudo loginctl enable-linger $(id -un)"
      fi ;;
    launchd-daemon|launchd-agent)
      if [ "$RH_SUP" = launchd-daemon ]; then
        rh_plist="/Library/LaunchDaemons/$RH_LABEL.plist"; rh_domain=system
      else
        rh_plist="$HOME/Library/LaunchAgents/$RH_LABEL.plist"; rh_domain="gui/$(id -u)"
        mkdir -p "$HOME/Library/LaunchAgents"
      fi
      rh_write_plist "$rh_tunnel" >"$rh_plist.tmp"
      chmod 644 "$rh_plist.tmp"; mv -f "$rh_plist.tmp" "$rh_plist"
      launchctl enable "$rh_domain/$RH_LABEL" >/dev/null 2>&1 || :
      rh_try=0; rh_started=0
      while [ "$rh_try" -lt 3 ]; do       # bootstrap can fail briefly right after bootout
        if launchctl bootstrap "$rh_domain" "$rh_plist" >/dev/null 2>&1; then rh_started=1; break; fi
        rh_try=$((rh_try + 1)); sleep 1
      done
      if [ "$rh_started" = 0 ] && launchctl load -w "$rh_plist" >/dev/null 2>&1; then rh_started=1; fi
      if [ "$rh_started" = 1 ]; then ok "Started $RH_LABEL ($RH_SUP)"
      else die "launchctl could not load $rh_plist"; fi ;;
    nohup)
      nohup /bin/sh "$rh_tunnel" </dev/null >/dev/null 2>&1 &
      ok "Started the tunnel in the background (pid $!)"
      warn "No service manager found, so it will not start again after a reboot. To fix,"
      info "add this line with 'crontab -e':  @reboot /bin/sh '$rh_tunnel'" ;;
  esac
}

# Stop a running tunnel before its key and config are replaced (re-enrollment).
# A system-wide install (sudo) replaces a per-user install made earlier by the
# same person: otherwise both tunnels keep running, as two devices. Runs that
# install's own uninstall.sh as its owner. Only reached after this enrollment
# succeeded, so a failed upgrade never removes the working per-user tunnel.
rh_retire_user_install() {
  if [ "$RH_TEST" = 1 ] || [ "$RH_ROOT" != 1 ]; then return 0; fi
  rh_u=${SUDO_USER:-}
  case $rh_u in ''|root) return 0 ;; esac
  rh_match '^[A-Za-z_][A-Za-z0-9_.-]{0,31}$' "$rh_u" || return 0
  case $RH_OS in
    macos) rh_h=$(dscl . -read "/Users/$rh_u" NFSHomeDirectory 2>/dev/null | sed -n 's/^NFSHomeDirectory: //p')
           rh_ud="$rh_h/Library/Application Support/RemoteHound" ;;
    *)     rh_h=$(getent passwd "$rh_u" 2>/dev/null | cut -d: -f6)
           rh_ud="$rh_h/.config/remotehound" ;;
  esac
  case $rh_h in /*) ;; *) return 0 ;; esac
  [ -f "$rh_ud/uninstall.sh" ] || return 0
  rh_uid=$(id -u "$rh_u" 2>/dev/null) || return 0
  if sudo -u "$rh_u" -H env XDG_RUNTIME_DIR="/run/user/$rh_uid" sh "$rh_ud/uninstall.sh" >/dev/null 2>&1; then
    ok "Removed the earlier install for $rh_u only: this system-wide one replaces it"
    info "Its old entry in RemoteHound shows 'Check identity' (enrolled twice): delete it there."
  else
    warn "An earlier install for $rh_u is still in $rh_ud. Remove it with:"
    info "  sh '$rh_ud/uninstall.sh'   (as $rh_u, without sudo)"
  fi
}

rh_stop_existing() {
  if [ "$RH_TEST" = 1 ]; then return 0; fi
  case $RH_SUP in
    systemd-system) systemctl stop "$RH_UNIT" >/dev/null 2>&1 || : ;;
    systemd-user)   systemctl --user stop "$RH_UNIT" >/dev/null 2>&1 || : ;;
    launchd-daemon) launchctl bootout "system/$RH_LABEL" >/dev/null 2>&1 || : ;;
    launchd-agent)  launchctl bootout "gui/$(id -u)/$RH_LABEL" >/dev/null 2>&1 \
                      || launchctl unload "$HOME/Library/LaunchAgents/$RH_LABEL.plist" >/dev/null 2>&1 || : ;;
  esac
  rh_kill_pidfile "$RH_DIR/tunnel.pid"
}

# launchd job: start at load, restart unless it exited 0 (0 = revoked).
rh_write_plist() {
  rh_x=$(printf '%s' "$1" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
  cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- RemoteHound tunnel. Remove with uninstall.sh next to tunnel.sh. -->
<plist version="1.0">
<dict>
  <key>Label</key><string>$RH_LABEL</string>
  <key>ProgramArguments</key>
  <array><string>/bin/sh</string><string>$rh_x</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>StandardOutPath</key><string>/dev/null</string>
  <key>StandardErrorPath</key><string>/dev/null</string>
</dict>
</plist>
EOF
}

# -----------------------------------------------------------------------------
#  tunnel.sh - the watchdog (protocol sections 4 and 5). Written verbatim.
# -----------------------------------------------------------------------------
rh_write_tunnel() {
  cat <<'RH_TUNNEL_EOF'
#!/bin/sh
# RemoteHound tunnel watchdog (written by the RemoteHound bootstrap; protocol v1).
#
# Keeps ONE outbound SSH connection to the RemoteHound server open. It carries
# reverse port forwards (-R) so the server can reach the local services listed
# in device.conf (e.g. SSH on 22, Screen Sharing on 5900). No inbound firewall
# port is opened on this computer and nothing else is reachable.
#
#  - systemd / launchd start it and restart it if it dies.
#  - On connect it sends the last 50 lines of tunnel.log on stdin, so the
#    operator can see why a device is struggling (heartbeat "ping" lines are
#    skipped so they do not crowd out real events). The private key is never
#    logged.
#  - Control lines from the server (ok / ping / reconnect / revoked) are
#    appended to tunnel.log as "server: <line>".
#  - "revoked": writes "revoked" to ./state and exits 0, which the service
#    manager treats as "stay down". Re-running the enroll command resets it.
#  - Reconnects with exponential backoff, 2 s doubling to 5 min, plus random
#    jitter of up to half the delay; a session that lasted over 60 s resets it.
#  - SIGTERM/SIGINT/SIGHUP: stops ssh, logs, and exits by the same signal.
#  - tunnel.log is rotated at 1 MB; one old copy (tunnel.log.1) is kept.
set -u
umask 077
LC_ALL=C; export LC_ALL

DIR=${RH_DIR:-$(cd "$(dirname "$0")" && pwd)}
CONF="$DIR/device.conf"; LOG="$DIR/tunnel.log"; STATE="$DIR/state"; PIDF="$DIR/tunnel.pid"
FIFO="$DIR/.control"; LAST="$DIR/.last_control"; TAILF="$DIR/.log_tail"; ERRF="$DIR/.ssh_err"
SSH_PID=""; READER_PID=""; NAP_PID=""
TEST=${RH_TEST_MODE:-0}

# log LEVEL MESSAGE...: "<RFC3339 UTC> <LEVEL> <message>", with rotation.
log() {
  size=$(wc -c <"$LOG" 2>/dev/null | tr -d ' ')
  if [ "${size:-0}" -gt 1048576 ] 2>/dev/null; then mv -f "$LOG" "$LOG.1"; fi
  lvl=$1; shift
  printf '%s %s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$lvl" "$*" >>"$LOG"
}

# printable, length-limited copy of untrusted text
clean() { printf '%s' "$1" | tr -d '\000-\037\177' | cut -c "1-$2"; }

valid() { printf '%s\n' "$2" | grep -Eq "$1"; }

# Sleep in the background so a signal interrupts it (traps wait for
# foreground commands). RH_TEST_FAST=1 (tests only) skips the delay.
nap() {
  if [ "$TEST" = 1 ] && [ "${RH_TEST_FAST:-0}" = 1 ]; then return 0; fi
  sleep "$1" & NAP_PID=$!
  wait "$NAP_PID"; NAP_PID=""
}

load_conf() {
  DEVICE_ID=""; SSH_HOST=""; SSH_PORT=""; FORWARDS=""; CLIENT_VERSION=1; OS=""; SERVICES=""
  [ -r "$CONF" ] || return 1
  while IFS='=' read -r k v || [ -n "$k" ]; do      # parsed, never sourced
    case $k in
      RH_DEVICE_ID) DEVICE_ID=$v ;;      RH_SSH_HOST) SSH_HOST=$v ;;
      RH_SSH_PORT) SSH_PORT=$v ;;        RH_FORWARDS) FORWARDS=$v ;;
      RH_CLIENT_VERSION) CLIENT_VERSION=$v ;;
      RH_OS) OS=$v ;;                    RH_SERVICES) SERVICES=$v ;;
    esac
  done <"$CONF"
  valid '^dev_[a-z0-9]{6,40}$' "$DEVICE_ID" || return 1
  valid '^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$' "$SSH_HOST" || return 1
  valid '^[0-9]{1,5}$' "$SSH_PORT" || return 1
  for f in $FORWARDS; do valid '^[0-9]{1,5}:localhost:[0-9]{1,5}$' "$f" || return 1; done
  for s in $SERVICES; do valid '^(ssh|rdp|vnc):[0-9]{1,5}$' "$s" || return 1; done
  valid '^[A-Za-z0-9._-]{1,32}$' "$CLIENT_VERSION" || CLIENT_VERSION=1
  case $OS in linux|macos) ;; *) case $(uname -s) in Darwin) OS=macos ;; *) OS=linux ;; esac ;; esac
  [ -r "$DIR/id_ed25519" ] && [ -r "$DIR/known_hosts" ]
}

host_fact() {
  if [ "$OS" = macos ]; then h=$(scutil --get LocalHostName 2>/dev/null || hostname 2>/dev/null || uname -n)
  else h=$(hostname 2>/dev/null || uname -n); fi
  h=$(printf '%s' "$h" | tr -cd 'A-Za-z0-9._-' | cut -c1-64)
  printf '%s' "${h:-device}"
}

# Reads ssh's stdout (the server's control lines) as they arrive.
reader() {
  while IFS= read -r line || [ -n "$line" ]; do
    line=$(clean "$line" 200)
    [ -n "$line" ] || continue
    printf '%s\n' "$line" >"$LAST"
    log INFO "server: $line"
  done
}

# One SSH session (blocking). Returns ssh's exit code.
run_session() {
  grep -v ' server: ping$' "$LOG" 2>/dev/null | tail -n 50 >"$TAILF"
  : >"$LAST"; : >"$ERRF"
  rm -f "$FIFO"
  mkfifo "$FIFO" || { log ERROR "cannot create $FIFO"; return 1; }
  reader <"$FIFO" &
  READER_PID=$!
  set -f                                   # forwards are expanded unquoted below
  set -- -T -F /dev/null -i "$DIR/id_ed25519" \
    -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes \
    -o "UserKnownHostsFile=\"$DIR/known_hosts\"" -o GlobalKnownHostsFile=/dev/null \
    -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
    -o ConnectTimeout=15 -o LogLevel=ERROR -p "$SSH_PORT"
  for f in $FORWARDS; do set -- "$@" -R "$f"; done
  set -- "$@" "$DEVICE_ID@$SSH_HOST" agent v1 "os=$OS" "ver=$CLIENT_VERSION" \
    "host=$(host_fact)" "services=$(printf '%s' "$SERVICES" | tr ' ' ',')"
  set +f
  ssh "$@" <"$TAILF" >"$FIFO" 2>"$ERRF" &
  SSH_PID=$!
  wait "$SSH_PID"; rc=$?
  SSH_PID=""
  wait "$READER_PID" 2>/dev/null; READER_PID=""
  rm -f "$FIFO" "$TAILF"
  while IFS= read -r e || [ -n "$e" ]; do          # ssh's own messages
    e=$(clean "$e" 300); [ -n "$e" ] && log WARN "ssh: $e"
  done <"$ERRF"
  rm -f "$ERRF"
  return "$rc"
}

on_signal() {
  trap - TERM INT HUP
  for p in $SSH_PID $READER_PID $NAP_PID; do kill "$p" 2>/dev/null; done
  rm -f "$FIFO" "$TAILF" "$ERRF" "$PIDF"
  log INFO "stopping (SIG$1)"
  kill -s "$1" "$$"                        # die by the signal: a clean stop for systemd
  exit 143
}

main() {
  [ -d "$DIR" ] || exit 1
  trap 'on_signal TERM' TERM; trap 'on_signal INT' INT; trap 'on_signal HUP' HUP
  echo "$$" >"$PIDF"
  if ! load_conf; then
    log ERROR "device.conf, id_ed25519 or known_hosts is missing or invalid; run the enroll command again"
    nap 60; rm -f "$PIDF"; exit 1
  fi
  backoff=2; loops=0
  while :; do
    if [ "$(cat "$STATE" 2>/dev/null)" = revoked ]; then
      log INFO "device is revoked; not connecting (run the enroll command again to reconnect)"
      rm -f "$PIDF"; exit 0
    fi
    start=$(date +%s)
    log INFO "connecting to $SSH_HOST:$SSH_PORT as $DEVICE_ID (forwards: ${FORWARDS:-none})"
    run_session; rc=$?
    log INFO "ssh exited rc=$rc"
    if [ "$(cat "$LAST" 2>/dev/null)" = revoked ]; then
      printf 'revoked\n' >"$STATE"
      log WARN "the server revoked this device; stopping for good"
      rm -f "$PIDF" "$LAST"; exit 0
    fi
    if [ $(($(date +%s) - start)) -gt 60 ]; then backoff=2
    else backoff=$((backoff * 2)); [ "$backoff" -gt 300 ] && backoff=300; fi
    jitter=$(awk -v b="$backoff" -v seed="$(($$ + loops * 7919 + $(date +%s)))" \
      'BEGIN { srand(seed); print int(rand() * (int(b / 2) + 1)) }')
    log INFO "retrying in ${backoff}s (+${jitter}s jitter)"
    loops=$((loops + 1))
    if [ "$TEST" = 1 ] && [ "$loops" -ge "${RH_TEST_MAX_LOOPS:-1000000}" ]; then
      log INFO "test: stopping after $loops attempts"; rm -f "$PIDF"; exit 0
    fi
    nap $((backoff + jitter))
  done
}

main "$@"
RH_TUNNEL_EOF
}

# -----------------------------------------------------------------------------
#  uninstall.sh - written verbatim. Works out what to remove from where it is.
# -----------------------------------------------------------------------------
rh_write_uninstall() {
  cat <<'RH_UNINSTALL_EOF'
#!/bin/sh
# RemoteHound uninstaller: stops the tunnel, removes its service entry and
# deletes this folder (key, config, logs). It does NOT turn off sshd, Remote
# Login, Screen Sharing or GNOME Remote Desktop: you may rely on them.
# Run with sudo if RemoteHound was installed with sudo.
set -u
DIR=$(cd "$(dirname "$0")" && pwd)
LABEL=net.remotehound.tunnel
UNIT=remotehound-tunnel.service

run() {   # runs a command quietly; RH_TEST_MODE=1 (tests only) prints it instead
  if [ "${RH_TEST_MODE:-0}" = 1 ]; then echo "  (test mode) would run: $*"; return 0; fi
  "$@" >/dev/null 2>&1
}
need_root() {
  [ "$(id -u)" -eq 0 ] || { echo "Run this with sudo:  sudo sh '$DIR/uninstall.sh'"; exit 1; }
}

main() {
  case $DIR in */remotehound|*/RemoteHound) ;; *) echo "Refusing to run from $DIR"; exit 1 ;; esac
  case $(uname -s) in
    Linux)
      if [ "$DIR" = /etc/remotehound ]; then
        need_root
        run systemctl disable --now "$UNIT"
        run rm -f "/etc/systemd/system/$UNIT"
        run systemctl daemon-reload
      elif [ -f "$HOME/.config/systemd/user/$UNIT" ]; then
        run systemctl --user disable --now "$UNIT"
        run rm -f "$HOME/.config/systemd/user/$UNIT"
        run systemctl --user daemon-reload
      fi ;;
    Darwin)
      if [ "$DIR" = "/Library/Application Support/RemoteHound" ]; then
        need_root
        run launchctl bootout "system/$LABEL"
        run rm -f "/Library/LaunchDaemons/$LABEL.plist"
      else
        run launchctl bootout "gui/$(id -u)/$LABEL" \
          || run launchctl unload "$HOME/Library/LaunchAgents/$LABEL.plist"
        run rm -f "$HOME/Library/LaunchAgents/$LABEL.plist"
      fi ;;
  esac
  # A watchdog started without a service manager (or still shutting down).
  pid=$(cat "$DIR/tunnel.pid" 2>/dev/null || :)
  case $pid in ''|*[!0-9]*) ;; *)
    if ps -p "$pid" -o args= 2>/dev/null | grep -q 'tunnel\.sh'; then run kill "$pid"; fi ;;
  esac
  run rm -rf "$DIR"
  echo "RemoteHound has been removed from this computer."
  echo "SSH / Remote Login / Screen Sharing were left as they are; turn them off in"
  echo "your system settings if you no longer need them."
}

main "$@"
RH_UNINSTALL_EOF
}

# =============================================================================
#  Stage 6: wait for the server to see the tunnel (every 2 s, up to 60 s).
# =============================================================================
stage6() {
  step 6 "Waiting for the tunnel to come up"
  rh_fq=$(printf '%s' "$RH_FPR" | sed 's/%/%25/g; s/+/%2B/g; s/\//%2F/g; s/=/%3D/g; s/:/%3A/g')
  RH_KV="$RH_TMP/status.kv"
  rh_i=0
  if [ "$RH_SUP" = launchd-daemon ] || [ "$RH_SUP" = systemd-system ]; then rh_sudo="sudo "; else rh_sudo=""; fi
  while [ "$rh_i" -lt 30 ]; do
    rh_http GET "$RH_BASE_URL/api/v1/enroll/status?device_id=$RH_DEVICE_ID&fingerprint=$rh_fq" "" "$RH_TMP/status.json"
    if [ "$RH_STATUS" = 200 ] && rh_json_flatten <"$RH_TMP/status.json" >"$RH_KV" 2>/dev/null \
       && [ "$(rh_jget data.online)" = true ]; then
      printf '\n  Connected as %s \342\234\223\n\n' "$RH_DEVICE_NAME"
      info "Log file:   $RH_DIR/tunnel.log"
      info "To remove:  ${rh_sudo}sh '$RH_DIR/uninstall.sh'"
      return 0
    fi
    sleep 2; rh_i=$((rh_i + 1))
  done
  warn "The server has not seen the tunnel yet. It keeps retrying in the background."
  info "Last lines of $RH_DIR/tunnel.log:"
  tail -n 10 "$RH_DIR/tunnel.log" 2>/dev/null | while IFS= read -r rh_l; do info "  $rh_l"; done
  info "To remove:  ${rh_sudo}sh '$RH_DIR/uninstall.sh'"
  exit 2
}

main() {
  printf 'RemoteHound: connecting this computer for remote support\n'
  case $RH_BASE_URL$RH_CODE in *__RH_*)
    die "This script has to be downloaded from your RemoteHound server (its settings are not filled in)." ;;
  esac
  RH_BASE_URL=${RH_BASE_URL%/}
  rh_match '^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$' "$RH_BASE_URL" || die "The server address in this script looks wrong."
  rh_match '^[a-hjkmnp-z2-9]{6}$' "$RH_CODE" || die "The enrollment code in this script looks wrong."
  RH_TMP=$(mktemp -d 2>/dev/null || mktemp -d -t remotehound) || die "Could not create a temporary folder"
  trap rh_cleanup EXIT
  trap 'exit 130' INT TERM HUP
  stage1
  stage2
  stage3
  stage4
  stage5
  stage6
}

main "$@"
