#!/usr/bin/env bash
# Unattended end-to-end test of RemoteHound on real machines in Azure: the
# bundle (this checkout's HEAD) plus Windows Server 2019 and Ubuntu 22.04 / 18.04
# clients enrolled with the script-free ssh commands (ADR-0005), checked through
# the API, Guacamole and a browser. Creates ONE resource group and always deletes
# it at the end (RH_E2E_KEEP=1 keeps it for debugging). See e2e/azure/README.md.
#
#   e2e/azure/run.sh            # needs: az (logged in), ssh, python3, git; Chrome + e2e deps for the browser stage
#
# Options (environment):
#   RH_E2E_LOCATION   Azure region (default westus2)
#   RH_E2E_CALLER_IP  your public IP for the firewall rules (default: looked up)
#   RH_E2E_PORT       local tunnel port for the UI (default 9443; 9444 is used for the operator view)
#   RH_E2E_BROWSER    0 skips the browser stage
#   RH_E2E_KEEP       1 keeps the resource group (delete it yourself: az group delete -n <name>)
#   RH_E2E_OUT        where results and screenshots go (default e2e/azure/out/<run id>)
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
RUN_ID="rh-e2e-$(date -u +%Y%m%d-%H%M%S)"
RG="$RUN_ID"
LOCATION="${RH_E2E_LOCATION:-westus2}"
PORT="${RH_E2E_PORT:-9443}"
OPORT=$((PORT + 1))
URL="https://localhost:$PORT"
OUT="${RH_E2E_OUT:-$HERE/out/$RUN_ID}"
WORK=$(mktemp -d)                      # keys and passwords: never printed, deleted at exit
SERVER_IP=10.42.0.10                   # fixed private address the devices dial
OSSH77_URL=https://github.com/PowerShell/Win32-OpenSSH/releases/download/v7.7.2.0p1-Beta/OpenSSH-Win64.zip
OSSH77_SHA256=8631f00013116388362cb06f3e6fd2c44c8e57d8f857033111f98feb34fa5bce
PYWINRM=pywinrm==0.5.0
mkdir -p "$OUT"
FAILS=0
TUNNEL_PID=""

log() { printf '\n== %s\n' "$*"; }
rh() { python3 -I "$HERE/rh_e2e.py" "$URL" "$@"; }
# t <cmd…>: run a check, keep its PASS/FAIL lines, count failures, never abort.
t() { if "$@" 2>&1 | tee -a "$OUT/results.txt"; then :; else FAILS=$((FAILS + 1)); fi; }
tfail() { echo "FAIL $*" | tee -a "$OUT/results.txt"; FAILS=$((FAILS + 1)); }
tpass() { echo "PASS $*" | tee -a "$OUT/results.txt"; }

cleanup() {
  local rc=$?
  [ -n "$TUNNEL_PID" ] && kill "$TUNNEL_PID" 2>/dev/null || true
  if [ "${RH_E2E_KEEP:-0}" = 1 ]; then
    echo "RH_E2E_KEEP=1: resource group $RG kept. Delete it with: az group delete -n $RG --yes"
  elif az group exists -n "$RG" 2>/dev/null | grep -q true; then
    echo "Deleting resource group $RG (in the background)…"
    az group delete -n "$RG" --yes --no-wait || echo "WARNING: could not delete $RG — delete it by hand"
  fi
  rm -rf "$WORK"
  exit "$rc"
}
trap cleanup EXIT INT TERM

for tool in az ssh scp python3 git curl; do command -v "$tool" >/dev/null || { echo "missing: $tool"; exit 2; }; done
az account show >/dev/null || { echo "az is not logged in (az login)"; exit 2; }
CALLER_IP="${RH_E2E_CALLER_IP:-$(curl -fsS https://api.ipify.org)}"
echo "$CALLER_IP" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' || { echo "could not determine your public IPv4 (set RH_E2E_CALLER_IP)"; exit 2; }

# ---- infrastructure ---------------------------------------------------------------
log "Resource group $RG in $LOCATION (tests run from $CALLER_IP)"
umask 077
ssh-keygen -q -t ed25519 -N '' -C rh-e2e -f "$WORK/key"
printf 'Rh%s!9' "$(openssl rand -hex 10)" > "$WORK/winpass"
openssl rand -hex 10 > "$WORK/linpass"
az group create -n "$RG" -l "$LOCATION" --tags purpose=remotehound-e2e created-by=e2e/azure/run.sh -o none
az network vnet create -g "$RG" -n vnet --address-prefix 10.42.0.0/16 --subnet-name default --subnet-prefix 10.42.0.0/24 -o none
az network nsg create -g "$RG" -n nsg-server -o none
az network nsg create -g "$RG" -n nsg-clients -o none   # no inbound rules at all
az network nsg rule create -g "$RG" --nsg-name nsg-server -n admin-ssh --priority 100 --access Allow --protocol Tcp \
  --direction Inbound --source-address-prefixes "$CALLER_IP" --destination-port-ranges 22 -o none
az network nsg rule create -g "$RG" --nsg-name nsg-server -n rh-tunnel --priority 110 --access Allow --protocol Tcp \
  --direction Inbound --source-address-prefixes 10.42.0.0/16 --destination-port-ranges 2222 -o none

vm() { # vm <name> <image> <size> <nsg> [extra…]
  local n=$1 img=$2 size=$3 nsg=$4; shift 4
  az vm create -g "$RG" -n "$n" --image "$img" --size "$size" --admin-username rhadmin --vnet-name vnet --subnet default \
    --nsg "$nsg" --public-ip-sku Standard --no-wait -o none --only-show-errors "$@"
}
log "Creating VMs (server, Windows Server 2019, Ubuntu 22.04, Ubuntu 18.04)"
vm rh-server Canonical:ubuntu-24_04-lts:server:latest Standard_B2ms nsg-server --ssh-key-values "$WORK/key.pub" --private-ip-address "$SERVER_IP"
vm rh-win2019 MicrosoftWindowsServer:WindowsServer:2019-datacenter-gensecond:latest Standard_B2s nsg-clients \
  --computer-name RHWIN2019 --admin-password "$(cat "$WORK/winpass")"
vm rh-u2204 Canonical:0001-com-ubuntu-server-jammy:22_04-lts-gen2:latest Standard_B2s nsg-clients --ssh-key-values "$WORK/key.pub"
vm rh-u1804 Canonical:UbuntuServer:18.04-LTS:latest Standard_B2s nsg-clients --ssh-key-values "$WORK/key.pub"
for n in rh-server rh-win2019 rh-u2204 rh-u1804; do az vm wait -g "$RG" -n "$n" --created --timeout 1200; done
WIN_IP=$(az vm show -g "$RG" -n rh-win2019 -d --query privateIps -o tsv)
SRV_PUB=$(az vm show -g "$RG" -n rh-server -d --query publicIps -o tsv)
cat > "$WORK/ssh_config" <<EOF
Host rhs
  HostName $SRV_PUB
  User rhadmin
  IdentityFile $WORK/key
  IdentitiesOnly yes
  UserKnownHostsFile $WORK/known_hosts
  StrictHostKeyChecking accept-new
  ServerAliveInterval 30
EOF
srv() { ssh -F "$WORK/ssh_config" rhs "$@"; }
until srv true 2>/dev/null; do sleep 5; done

# ---- the bundle on the server ------------------------------------------------------
log "Deploying the bundle from $(git -C "$REPO" rev-parse --short HEAD)"
git -C "$REPO" archive --format=tar.gz -o "$WORK/src.tgz" HEAD
scp -q -F "$WORK/ssh_config" "$WORK/src.tgz" "$WORK/winpass" "$HERE/winrm_hold.py" rhs:/home/rhadmin/
srv "set -e; chmod 600 ~/winpass; mkdir -p ~/rh && tar -xzf ~/src.tgz -C ~/rh
  sudo apt-get -qq update >/dev/null
  sudo DEBIAN_FRONTEND=noninteractive apt-get -qq install -y docker.io docker-compose-v2 python3-venv >/dev/null
  python3 -m venv ~/wr && ~/wr/bin/pip -q install '$PYWINRM'
  cd ~/rh/deploy; umask 077
  printf 'RH_DOMAIN=localhost\nRH_PUBLIC_URL=$URL\nRH_AUTH_MODE=proxy\nRH_SECRET_KEY=%s\nRH_GUAC_JSON_SECRET=%s\n' \"\$(openssl rand -hex 32)\" \"\$(openssl rand -hex 16)\" > test/e2e.env
  GID=\$(getent group docker | cut -d: -f3)
  printf 'services:\n  remotehound:\n    environment:\n      RH_PUBLIC_URL: $URL\n  rh-control:\n    user: \"65532:%s\"\n' \"\$GID\" > test/azure.override.yml
  sudo docker compose -f compose.yml -f test/compose.e2e.yml -f test/azure.override.yml --env-file test/e2e.env up -d --build >/tmp/compose.log 2>&1 || { tail -40 /tmp/compose.log; exit 1; }
  until sudo docker logs remotehound-guacamole-1 2>&1 | grep -q 'Server startup in'; do sleep 3; done"
ssh -F "$WORK/ssh_config" -N -o ExitOnForwardFailure=yes -L "$PORT:127.0.0.1:8443" -L "$OPORT:127.0.0.1:8444" rhs &
TUNNEL_PID=$!
until curl -sk -o /dev/null -w '%{http_code}' "$URL/healthz" | grep -q 200; do sleep 2; done

log "Bundle checks"
t rh setup "$SERVER_IP"
t rh integration

# ---- Linux clients (run-command runs as root; the commands run as rhadmin) ---------
linux_cmd() { python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1]))["ssh"]["unix"])' "$1"; }
# lin_run <vm> <command_file> <out_file>: run one typed command as rhadmin, detached, like a terminal left open.
lin_run() {
  { echo "pkill -u rhadmin -f 'hello v1'; sleep 1"
    echo "id rhdemo >/dev/null 2>&1 || { useradd -m -s /bin/bash rhdemo; echo 'rhdemo:$(cat "$WORK/linpass")' | chpasswd; }"
    echo "printf 'PasswordAuthentication yes\n' > /etc/ssh/sshd_config.d/10-rhdemo.conf; rm -f /etc/ssh/sshd_config.d/60-cloudimg-settings.conf; systemctl reload ssh || systemctl reload sshd"
    echo "cat > /tmp/rh-case.sh <<'RH_E2E_INNER'"; cat "$2"; echo "RH_E2E_INNER"
    echo 'echo "client: $(ssh -V 2>&1)"'
    echo 'sudo -u rhadmin -H setsid nohup bash /tmp/rh-case.sh </dev/null >/tmp/rh-case.log 2>&1 &'
    echo 'sleep 10; cat /tmp/rh-case.log'; } > "$WORK/lin.sh"
  az vm run-command invoke -g "$RG" -n "$1" --command-id RunShellScript --scripts @"$WORK/lin.sh" --query "value[0].message" -o tsv > "$3"
}
lin_stop() { printf "pkill -u rhadmin -f 'hello v1'; true\n" > "$WORK/stop.sh"; az vm run-command invoke -g "$RG" -n "$1" --command-id RunShellScript --scripts @"$WORK/stop.sh" -o none; }
reconnect_line() { grep -A1 'To reconnect later' "$1" | tail -1 | sed 's/^ *//'; }

# lin_persistent <vm> <label> <client substring> → sets DEV
lin_persistent() {
  local vmn=$1 label=$2 client=$3
  log "$label: install code, typed ssh with a key, then reconnect"
  t rh code persistent "$label" linux "$OUT/$vmn-per.json"
  linux_cmd "$OUT/$vmn-per.json" > "$WORK/cmd"
  lin_run "$vmn" "$WORK/cmd" "$OUT/$vmn-per.out"
  local enr; enr=$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1]))["id"])' "$OUT/$vmn-per.json")
  DEV=$(rh wait-used "$enr" 90) || { tfail "$label: device not enrolled"; cat "$OUT/$vmn-per.out"; return; }
  t rh device "$DEV" --transport ssh-manual --os linux --online true --client-contains "$client" --code-shown "$OUT/$vmn-per.out"
  reconnect_line "$OUT/$vmn-per.out" > "$WORK/recon"
  [ -s "$WORK/recon" ] && tpass "$label: reconnect command printed" || tfail "$label: no reconnect command"
  lin_stop "$vmn"; t rh wait-online "$DEV" false 60
  lin_run "$vmn" "$WORK/recon" "$OUT/$vmn-recon.out"
  t rh wait-online "$DEV" true 60
  t rh device "$DEV" --transport ssh-manual --online true --code-shown "$OUT/$vmn-recon.out"
}

lin_persistent rh-u2204 "Ubuntu 22.04" "OpenSSH_8"
LIVE_SSH=$DEV
t rh svc "$LIVE_SSH" ssh 22 rhdemo "$WORK/linpass"
t rh probe "$LIVE_SSH" ssh ok
t rh guac "$LIVE_SSH" ssh

lin_persistent rh-u1804 "Ubuntu 18.04" "OpenSSH_7.6"

log "Ubuntu 18.04: one-time code, end it, and a second session on the same machine"
t rh code attended "Ubuntu 18.04 one-time" linux "$OUT/u1804-att.json"
linux_cmd "$OUT/u1804-att.json" > "$WORK/cmd"
lin_run rh-u1804 "$WORK/cmd" "$OUT/u1804-att.out"
ENR=$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1]))["id"])' "$OUT/u1804-att.json")
ENDED=$(rh wait-used "$ENR" 90) || tfail "one-time Ubuntu device not enrolled"
t rh device "$ENDED" --transport ssh-attended --os linux --online true --code-shown "$OUT/u1804-att.out"
lin_stop rh-u1804; t rh wait-online "$ENDED" false 60
t rh enr-state "$ENR" used
t rh code attended "Ubuntu 18.04 one-time" linux "$OUT/u1804-att2.json"
linux_cmd "$OUT/u1804-att2.json" > "$WORK/cmd"
lin_run rh-u1804 "$WORK/cmd" "$OUT/u1804-att2.out"
ENR2=$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1]))["id"])' "$OUT/u1804-att2.json")
SECOND=$(rh wait-used "$ENR2" 90) || tfail "second one-time session not enrolled"
t rh no-dup-with "$SECOND" "$ENDED"
lin_stop rh-u1804

# ---- Windows Server 2019 (cmd.exe as the real user, over WinRM from the server) ----
log "Windows: WinRM for the session holder, portable OpenSSH 7.7 (checksum pinned)"
cat > "$WORK/win-setup.ps1" <<EOF
Enable-PSRemoting -Force -SkipNetworkProfileCheck | Out-Null
New-Item -ItemType Directory -Force C:\\rh | Out-Null
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -UseBasicParsing -Uri '$OSSH77_URL' -OutFile C:\\rh\\ossh77.zip
if ((Get-FileHash C:\\rh\\ossh77.zip -Algorithm SHA256).Hash -ne '$OSSH77_SHA256') { 'CHECKSUM MISMATCH'; exit 1 }
Expand-Archive -Force C:\\rh\\ossh77.zip C:\\rh\\ossh77
icacls.exe C:\\rh /grant 'Users:(OI)(CI)RX' /T | Out-Null
'builtin: ' + (cmd /c 'C:\\Windows\\System32\\OpenSSH\\ssh.exe -V 2>&1')
'portable: ' + (cmd /c 'C:\\rh\\ossh77\\OpenSSH-Win64\\ssh.exe -V 2>&1')
EOF
az vm run-command invoke -g "$RG" -n rh-win2019 --command-id RunPowerShellScript --scripts @"$WORK/win-setup.ps1" --query "value[0].message" -o tsv | tee "$OUT/win-setup.out"
grep -q 'CHECKSUM MISMATCH' "$OUT/win-setup.out" && tfail "portable OpenSSH checksum" || tpass "portable OpenSSH 7.7 checksum matches"

win_cmd() { python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1]))["ssh"]["windows"])' "$1"; }
win_place() { # win_place <command_file>: put one line in C:\rh\test.cmd
  { echo "Set-Content -Path C:\\rh\\test.cmd -Encoding Ascii -Value @'"; cat "$1"; echo "'@"; } > "$WORK/place.ps1"
  az vm run-command invoke -g "$RG" -n rh-win2019 --command-id RunPowerShellScript --scripts @"$WORK/place.ps1" -o none
}
win_start() { srv "rm -f ~/win-out.txt; (setsid nohup ~/wr/bin/python ~/winrm_hold.py $WIN_IP rhadmin ~/winpass ~/win-out.txt /tmp/rh-stop > ~/hold.log 2>&1 < /dev/null &)"; }
win_stop() { srv "touch /tmp/rh-stop"; }
win_wait_out() { # win_wait_out <pattern> <out_file>
  local i; for i in $(seq 1 40); do srv "cat ~/win-out.txt 2>/dev/null" > "$2" || true; grep -q "$1" "$2" && return 0; sleep 3; done; return 1
}
PATH77='set "PATH=C:\rh\ossh77\OpenSSH-Win64;%PATH%" & '

# win_case <label> <mode> <prefix> <client substring> → sets DEV
win_case() {
  local label=$1 mode=$2 prefix=$3 client=$4 tag; tag=$(echo "$label" | tr -c 'A-Za-z0-9\n' '-')
  log "$label"
  t rh code "$mode" "$label" windows "$OUT/$tag.json"
  { printf '%s' "$prefix"; win_cmd "$OUT/$tag.json"; } > "$WORK/cmd"
  win_place "$WORK/cmd"; win_start
  local enr; enr=$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1]))["id"])' "$OUT/$tag.json")
  DEV=$(rh wait-used "$enr" 120) || { tfail "$label: device not enrolled"; srv "cat ~/win-out.txt ~/hold.log" || true; return; }
  win_wait_out 'Keep this window open' "$OUT/$tag.out" || tfail "$label: no status lines in the window"
  t rh device "$DEV" --transport "ssh-$([ "$mode" = attended ] && echo attended || echo manual)" --os windows --online true \
    --client-contains "$client" --hostname RHWIN2019 --code-shown "$OUT/$tag.out"
  if [ "$mode" = persistent ]; then
    { printf '%s' "$prefix"; reconnect_line "$OUT/$tag.out"; } > "$WORK/recon"
    win_stop; t rh wait-online "$DEV" false 60
    win_place "$WORK/recon"; win_start
    t rh wait-online "$DEV" true 90
    win_wait_out 'Keep this window open' "$OUT/$tag-recon.out" || true
    t rh device "$DEV" --online true --code-shown "$OUT/$tag-recon.out"
  fi
}

win_case "Windows 2019 OpenSSH 9.5 install" persistent "" "for_Windows_9"; win_stop
win_case "Windows 2019 OpenSSH 7.7 install" persistent "$PATH77" "for_Windows_7.7"; win_stop
win_case "Windows 2019 OpenSSH 7.7 one-time" attended "$PATH77" "for_Windows_7.7"; win_stop

log "Windows: a code for another OS is refused and not used up"
t rh code attended "wrong machine" linux "$OUT/wrong-os.json"
win_cmd "$OUT/wrong-os.json" > "$WORK/cmd"; win_place "$WORK/cmd"; win_start
win_wait_out 'could not connect' "$OUT/wrong-os.out" && tpass "wrong OS refused in the person's window" || tfail "wrong OS: no refusal shown"
win_stop
t rh enr-state "$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1]))["id"])' "$OUT/wrong-os.json")" open
t rh audit-has enrollment.redeem failure

log "Windows: the cmd line pasted into PowerShell runs nothing"
{ echo "Set-Content -Path C:\\rh\\pasted.ps1 -Encoding Ascii -Value @'"; win_cmd "$OUT/wrong-os.json"; echo "'@"
  echo "powershell.exe -NoProfile -File C:\\rh\\pasted.ps1 2>&1 | Out-String"; } > "$WORK/ps.ps1"
az vm run-command invoke -g "$RG" -n rh-win2019 --command-id RunPowerShellScript --scripts @"$WORK/ps.ps1" --query "value[].message" -o tsv > "$OUT/powershell.out" 2>&1 || true
grep -q 'ampersand (&) character is not allowed' "$OUT/powershell.out" && tpass "PowerShell refuses the cmd line (documented message)" || tfail "PowerShell message changed: see $OUT/powershell.out"

win_case "Windows 2019 OpenSSH 9.5 one-time" attended "" "for_Windows_9"   # left running for the browser stage
LIVE_RDP=$DEV
t rh svc "$LIVE_RDP" rdp 3389 rhadmin "$WORK/winpass"
t rh probe "$LIVE_RDP" rdp ok
t rh guac "$LIVE_RDP" rdp
t rh audit-has enrollment.redeem success

# ---- browser ----------------------------------------------------------------------
if [ "${RH_E2E_BROWSER:-1}" != 0 ] && [ -d "$REPO/e2e/node_modules/@playwright" ]; then
  log "Browser: device pages, probe, Connect RDP/SSH through Guacamole, ended session"
  t node "$REPO/e2e/azure/browser.mjs" "$URL" "$OUT" "$LIVE_RDP" "$LIVE_SSH" "$ENDED"
  log "Browser: the walkthrough suite (every screen, light + dark, axe, desktop + phone)"
  ( cd "$REPO/e2e" && RH_E2E_URL="$URL" RH_E2E_OPERATOR_URL="https://localhost:$OPORT" \
      npx playwright test walk/ --output "$OUT/walk" > "$OUT/walk.log" 2>&1 ) \
    && tpass "walkthrough suite: $(grep -Eo '[0-9]+ passed' "$OUT/walk.log" | tail -1)" \
    || tfail "walkthrough suite: see $OUT/walk.log"
else
  echo "Browser stage skipped (RH_E2E_BROWSER=0, or run: cd e2e && npm ci)"
fi
win_stop

# ---- summary ----------------------------------------------------------------------
log "Summary ($OUT/results.txt)"
P=$(grep -c '^PASS' "$OUT/results.txt" || true); F=$(grep -c '^FAIL' "$OUT/results.txt" || true)
echo "$P passed, $F failed"
grep '^FAIL' "$OUT/results.txt" || true
[ "$FAILS" -eq 0 ] && [ "$F" -eq 0 ]
