# =============================================================================
#  RemoteHound device bootstrap for Windows                    (Apache-2.0)
#  Client protocol v1 - see docs/specs/CLIENT_PROTOCOL.md in the RemoteHound repo
#  Works in Windows PowerShell 5.1 and PowerShell 7.
# =============================================================================
#
#  You were probably asked to run (in PowerShell):
#      irm https://<server>/e/<code> | iex
#  To read this script first:
#      irm https://<server>/e/<code>.ps1
#  (Downloading it does not use up the code. Only step 3 below does.)
#  Run PowerShell "as Administrator" for a full install that starts at boot;
#  without admin rights it installs for your user only and runs while you are
#  logged in.
#
#  WHAT IT DOES
#   1. Checks this computer: Windows edition, admin rights, and which
#      remote-access services listen on localhost (SSH 22, RDP 3389, VNC 5900).
#   2. Makes a new SSH key pair for this device (ed25519) with the built-in
#      OpenSSH client. The private key never leaves this computer, is never
#      printed or logged, and only SYSTEM + Administrators (or, without admin,
#      you + SYSTEM) can read it.
#   3. Sends the PUBLIC key, the one-time code, hostname, OS and service list
#      to your RemoteHound server, which returns this device's id and the
#      server's host key (pinned).
#   4. Admin only: turns on Remote Desktop (registry setting only; Windows Home
#      has no RDP server and is skipped) and, if you agree, the optional
#      OpenSSH Server. It does NOT open the Remote Desktop firewall rule: the
#      tunnel connects to localhost, so RDP stays closed to your network.
#   5. Writes a watchdog script (tunnel.ps1) and a Scheduled Task
#      "RemoteHound Tunnel" that keeps ONE outbound `ssh -R` connection to the
#      server running, and starts it.
#   6. Waits until the server sees the tunnel and prints "Connected".
#
#  WHAT IT WRITES (nothing else is changed)
#   Admin:     %ProgramData%\RemoteHound\  + Scheduled Task "RemoteHound Tunnel"
#              (runs as SYSTEM at startup and every 5 minutes; one instance)
#   Not admin: %LOCALAPPDATA%\RemoteHound\ + Scheduled Task "RemoteHound Tunnel"
#              for your user at logon (and every 5 minutes; one instance)
#   The folder holds: id_ed25519 (+ .pub), known_hosts, ssh_config (empty, so
#   your own ssh settings cannot interfere), device.conf, tunnel.ps1,
#   tunnel.log, state, uninstall.ps1.
#
#  HOW TO UNDO
#   powershell -ExecutionPolicy Bypass -File "<folder>\uninstall.ps1"
#   (from an Administrator PowerShell if you installed as Administrator). It
#   removes the task and the folder. Remote Desktop / OpenSSH Server are left
#   as they are, because you may rely on them.
#
#  Running it again with a new code is safe: the folder is reused, a fresh key
#  is made and the task is replaced. If enrolment fails, an existing working
#  connection is left untouched.
#
#  This file is pure ASCII on purpose (Windows PowerShell 5.1 reads scripts
#  without a byte-order mark as ANSI). It never uses `exit`, so running it
#  through `| iex` cannot close your PowerShell window.
# =============================================================================

function Invoke-RemoteHoundEnrol {
    $ErrorActionPreference = 'Stop'

    # ---- filled in by the server when it hands out this script --------------
    $BaseUrl = '__RH_BASE_URL__'
    $Code = '__RH_CODE__'
    # -------------------------------------------------------------------------
    $ClientVersion = '1'
    $TaskName = 'RemoteHound Tunnel'

    # ---- output (the check/cross marks only where the console can show them)
    $utf8 = $false
    try { $utf8 = ([Console]::OutputEncoding.CodePage -eq 65001) } catch { }
    if ($utf8) { $markOk = [string][char]0x2713; $markBad = [string][char]0x2717 } else { $markOk = '+'; $markBad = 'x' }
    function Step([int]$n, [string]$text) { Write-Host ''; Write-Host ("[{0}/6] {1}" -f $n, $text) }
    function Ok([string]$text) { Write-Host ("  {0} {1}" -f $markOk, $text) -ForegroundColor Green }
    function Warn([string]$text) { Write-Host ("  ! {0}" -f $text) -ForegroundColor Yellow }
    function Info([string]$text) { Write-Host ("    {0}" -f $text) }
    # Fail: throw a message the top-level catch prints nicely (no `exit` under iex).
    function Fail([string]$text) { throw (New-Object System.Exception ('RH:' + $text)) }

    # ---- helpers ---------------------------------------------------------------
    # Full-string regex match. .NET's `$` also matches before a trailing newline,
    # so patterns end in \z instead.
    function Test-Value([string]$pattern, $value) { return ($value -is [string]) -and ($value -cmatch $pattern) }

    # Run a native program with an exact command line. ProcessStartInfo.Arguments
    # is passed verbatim in PS 5.1 and 7, which side-steps the empty-argument
    # quirks (ssh-keygen -N "" would otherwise need '""' in 5.1 but '' in 7.3+).
    function Invoke-Native([string]$file, [string]$arguments) {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $file
        $psi.Arguments = $arguments
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true
        $p = [System.Diagnostics.Process]::Start($psi)
        $errTask = $p.StandardError.ReadToEndAsync()
        $out = $p.StandardOutput.ReadToEnd()
        $p.WaitForExit()
        return New-Object psobject -Property @{ Code = $p.ExitCode; Out = $out; Err = $errTask.Result }
    }

    # UTF-8 without BOM (a BOM would break known_hosts for ssh). An existing
    # file is deleted first and the new one is created with CreateNew, so it
    # only ever carries the protected ACL inherited from our folder: a file
    # that is overwritten in place keeps its old (possibly hostile) ACL.
    function Write-TextFile([string]$path, [string]$text) {
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
        $bytes = (New-Object System.Text.UTF8Encoding $false).GetBytes($text)
        $fs = New-Object System.IO.FileStream($path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        try { $fs.Write($bytes, 0, $bytes.Length) } finally { $fs.Close() }
    }

    # ---- folder and file ACLs ----------------------------------------------------
    # Why this matters: the SYSTEM task runs tunnel.ps1 from this folder and
    # reads the private key there. Any account that can write to the folder (or
    # owns it, since an owner can always rewrite the ACL) could run code as
    # SYSTEM or steal the key. %ProgramData% lets ordinary users create
    # folders, so an attacker could have created RemoteHound before us.
    $SidSystem = 'S-1-5-18'; $SidAdmins = 'S-1-5-32-544'
    # write/modify/full-control style rights: WriteData, AppendData, WriteEA,
    # DeleteChild, WriteAttributes, Delete, WRITE_DAC, WRITE_OWNER, GENERIC_ALL, GENERIC_WRITE
    $WriteMask = 0x500D0156

    # Test-RhTrustedDirectory: $true only if the folder and everything in it is
    # owned by one of $OwnerSids, no Allow entry gives write-type rights to any
    # SID outside $WriterSids, and nothing is a junction/symlink. With -Strict,
    # any Allow entry for another SID fails, and the folder must not inherit
    # entries from its parent. Any error (e.g. access denied) counts as untrusted.
    function Test-RhTrustedDirectory([string]$Path, [string[]]$OwnerSids, [string[]]$WriterSids, [switch]$Strict) {
        try {
            $root = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
            if (-not $root.PSIsContainer) { return $false }
            $queue = New-Object System.Collections.Queue
            $queue.Enqueue($root)
            while ($queue.Count -gt 0) {
                $item = $queue.Dequeue()
                if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { return $false }
                $acl = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
                $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
                if ($OwnerSids -notcontains $owner) { return $false }
                if ($Strict -and ($item.FullName -eq $root.FullName) -and -not $acl.AreAccessRulesProtected) { return $false }
                foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
                    if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
                    if ($WriterSids -contains $rule.IdentityReference.Value) { continue }
                    if ($Strict) { return $false }
                    if (([int]$rule.FileSystemRights -band $WriteMask) -ne 0) { return $false }
                }
                if ($item.PSIsContainer) {
                    foreach ($child in @(Get-ChildItem -LiteralPath $item.FullName -Force -ErrorAction Stop)) { $queue.Enqueue($child) }
                }
            }
            return $true
        } catch { return $false }
    }

    # A security descriptor whose DACL is exactly "full control for $Sids",
    # protected from inheritance (folder entries are inherited by its files).
    function New-RhProtectedSecurity([bool]$IsDirectory, [string[]]$Sids) {
        if ($IsDirectory) {
            $sec = New-Object System.Security.AccessControl.DirectorySecurity
            $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
        } else {
            $sec = New-Object System.Security.AccessControl.FileSecurity
            $inherit = [System.Security.AccessControl.InheritanceFlags]::None
        }
        $sec.SetAccessRuleProtection($true, $false)
        foreach ($sid in $Sids) {
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                (New-Object System.Security.Principal.SecurityIdentifier $sid),
                [System.Security.AccessControl.FileSystemRights]::FullControl, $inherit,
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow)
            $sec.AddAccessRule($rule)
        }
        return $sec
    }

    # Replace the whole DACL of a file or folder (Set-Acl writes only the
    # DACL here, because only the DACL of the new object was set).
    function Set-RhProtectedAcl([string]$Path, [string[]]$Sids) {
        $isDir = (Get-Item -LiteralPath $Path -Force).PSIsContainer
        Set-Acl -LiteralPath $Path -AclObject (New-RhProtectedSecurity $isDir $Sids)
    }

    # Create the folder with the protected DACL in one step where .NET allows
    # it (no moment with inherited %ProgramData% permissions). If the folder
    # appeared in the meantime nothing is applied; the caller verifies.
    function New-RhSecureDirectory([string]$Path, [string[]]$Sids) {
        # A function's return value arrives wrapped in a PSObject; reflection's
        # Invoke passes the wrapper through and .NET refuses it ("PSObject cannot
        # be converted to DirectorySecurity", seen on Windows 11 2026-11-21).
        # Unwrap to the real DirectorySecurity before calling .NET directly.
        $sec = [System.Security.AccessControl.DirectorySecurity](New-RhProtectedSecurity $true $Sids).PSObject.BaseObject
        $m = [System.IO.Directory].GetMethod('CreateDirectory', [type[]]@([string], [System.Security.AccessControl.DirectorySecurity]))
        if ($m) { [void]$m.Invoke($null, [object[]]@($Path, $sec)); return }          # .NET Framework (PS 5.1)
        $ext = 'System.IO.FileSystemAclExtensions' -as [type]
        if ($ext) { [void]$ext::Create((New-Object System.IO.DirectoryInfo $Path), $sec); return }   # .NET 5+ (PS 7)
        New-Item -ItemType Directory -Path $Path | Out-Null                           # last resort; verified after
        Set-Acl -LiteralPath $Path -AclObject $sec
    }

    # Make $Path a folder that only $Sids can use. An existing folder that
    # fails Test-RhTrustedDirectory is renamed aside, never reused.
    function Initialize-RhDirectory([string]$Path, [string[]]$Sids, [string[]]$OwnerSids, [string]$SetOwnerSid) {
        if (Test-Path -LiteralPath $Path) {
            # Reuse it only if it already looks exactly like what we create:
            # trusted owners, a protected DACL with no other SID, no links.
            # That also rules out every ACE that grants another SID write access.
            if (-not (Test-RhTrustedDirectory $Path $OwnerSids $Sids -Strict)) {
                Stop-OldTunnel $Path
                $aside = '{0}.untrusted-{1}' -f $Path, [DateTime]::UtcNow.ToString('yyyyMMddHHmmss', [Globalization.CultureInfo]::InvariantCulture)
                try { [IO.Directory]::Move($Path, $aside) }
                catch { Fail ("{0} is owned by or writable for another account and could not be moved aside ({1}). Delete it as Administrator and run the command again." -f $Path, (Clean $_.Exception.Message 200)) }
                Warn ("{0} was owned by or writable for another account, so it was not" -f $Path)
                Info ("trusted. It was moved to {0} (inspect or delete it); starting fresh." -f $aside)
            }
        }
        if (Test-Path -LiteralPath $Path) { Set-RhProtectedAcl $Path $Sids }      # trusted: reset the DACL anyway
        else { New-RhSecureDirectory $Path $Sids }
        if ($SetOwnerSid) {
            $r = Invoke-Native 'icacls.exe' ('"{0}" /setowner *{1} /C /Q' -f $Path, $SetOwnerSid)
            if ($r.Code -ne 0) { Fail ("Could not set the owner of {0}: {1}" -f $Path, (Clean $r.Err 200)) }
        }
        # Fail closed: read the ACL back; only $Sids may appear at all.
        if (-not (Test-RhTrustedDirectory $Path $OwnerSids $Sids -Strict)) {
            Fail ("Could not make {0} private (unexpected owner or permissions). Nothing was installed." -f $Path)
        }
    }

    function Test-Port([int]$port) {
        $c = New-Object System.Net.Sockets.TcpClient
        try {
            $iar = $c.BeginConnect('127.0.0.1', $port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(1000) -and $c.Connected) { $c.EndConnect($iar); return $true }
            return $false
        } catch { return $false } finally { $c.Close() }
    }

    # Read the body of a failed Invoke-RestMethod in both PS 5.1 and PS 7.
    function Get-ErrorBody($err) {
        if ($err.ErrorDetails -and $err.ErrorDetails.Message) { return $err.ErrorDetails.Message }
        try {
            $resp = $err.Exception.Response
            if ($resp -and ($resp -is [System.Net.WebResponse])) {
                $reader = New-Object System.IO.StreamReader ($resp.GetResponseStream())
                return $reader.ReadToEnd()
            }
        } catch { }
        return ''
    }

    function Get-StatusCode($err) {
        try { if ($err.Exception.Response) { return [int]$err.Exception.Response.StatusCode } } catch { }
        return 0
    }

    function Clean([string]$text, [int]$max) {
        if ($null -eq $text) { return '' }
        $t = $text -replace '[\x00-\x1f\x7f]', ''
        if ($t.Length -gt $max) { $t = $t.Substring(0, $max) }
        return $t
    }

    function Stop-OldTunnel([string]$dir) {
        try { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue } catch { }
        $key = Join-Path $dir 'id_ed25519'
        $script = Join-Path $dir 'tunnel.ps1'
        try {
            Get-CimInstance Win32_Process -Filter "Name='ssh.exe' OR Name='powershell.exe' OR Name='pwsh.exe'" -ErrorAction SilentlyContinue |
                Where-Object { $_.CommandLine -and ($_.CommandLine.Contains($key) -or $_.CommandLine.Contains($script)) } |
                ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        } catch { }
    }

    try {
        Write-Host 'RemoteHound: connecting this computer for remote support'
        if (($BaseUrl + $Code).Contains('__RH_')) { Fail 'This script has to be downloaded from your RemoteHound server (its settings are not filled in).' }
        $BaseUrl = $BaseUrl.TrimEnd('/')
        if (-not (Test-Value '^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?\z' $BaseUrl)) { Fail 'The server address in this script looks wrong.' }
        if (-not (Test-Value '^[a-hjkmnp-z2-9]{6}\z' $Code)) { Fail 'The enrolment code in this script looks wrong.' }
        # Windows PowerShell 5.1 on older .NET does not offer TLS 1.2 by default.
        try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }

        # =====================================================================
        #  Stage 1: what is this computer?
        # =====================================================================
        Step 1 'Checking this computer'
        $sshDir = Join-Path $env:WINDIR 'System32\OpenSSH'
        if (-not (Test-Path (Join-Path $sshDir 'ssh.exe')) -and (Test-Path (Join-Path $env:WINDIR 'Sysnative\OpenSSH\ssh.exe'))) {
            $sshDir = Join-Path $env:WINDIR 'Sysnative\OpenSSH'     # 32-bit PowerShell on 64-bit Windows
        }
        $ssh = Join-Path $sshDir 'ssh.exe'
        $keygen = Join-Path $sshDir 'ssh-keygen.exe'
        if (-not (Test-Path $ssh) -or -not (Test-Path $keygen)) {
            Fail ("The built-in OpenSSH Client is not installed. Add it in Settings > System > Optional features > " +
                "Add a feature > 'OpenSSH Client' (or, as Administrator: Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0), " +
                "then run the command again.")
        }

        $osInfo = Get-CimInstance Win32_OperatingSystem
        $edition = ''
        try { $edition = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name EditionID).EditionID } catch { }
        # Home editions ("Core*") have no Remote Desktop server.
        $isHome = ($edition -like 'Core*') -or ($osInfo.Caption -match 'Home')
        $osVersion = Clean ([string]$osInfo.Version) 128
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $isAdmin = (New-Object System.Security.Principal.WindowsPrincipal $identity).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
        $userSid = $identity.User.Value
        $hostname = ($env:COMPUTERNAME -replace '[^A-Za-z0-9._-]', '')
        if ($hostname.Length -gt 64) { $hostname = $hostname.Substring(0, 64) }
        if (-not $hostname) { $hostname = 'device' }
        Ok ("{0} (build {1}), hostname {2}" -f (Clean ([string]$osInfo.Caption) 80), $osVersion, $hostname)

        if ($isAdmin) {
            $dir = Join-Path $env:ProgramData 'RemoteHound'
            Ok 'Running as Administrator: installing system-wide (the tunnel starts at boot)'
        } else {
            $dir = Join-Path $env:LOCALAPPDATA 'RemoteHound'
            Warn 'Not running as Administrator: installing for your user only (runs while you are'
            Info 'logged in; Remote Desktop cannot be turned on). For a full install, open PowerShell'
            Info 'with "Run as administrator" and run the command again.'
        }

        $services = New-Object System.Collections.ArrayList
        $enableRdp = $false; $installSshd = $false; $rdpNote = $null
        if (Test-Port 22) { Ok 'SSH is listening on port 22'; [void]$services.Add(@{ kind = 'ssh'; port = 22 }) }
        if (Test-Port 3389) { Ok 'Remote Desktop is listening on port 3389'; [void]$services.Add(@{ kind = 'rdp'; port = 3389 }) }
        elseif ($isHome) { $rdpNote = 'This is Windows Home, which has no Remote Desktop server; RDP is skipped. (Windows Pro or Enterprise is needed for RDP.)' }
        elseif ($isAdmin) { $enableRdp = $true; [void]$services.Add(@{ kind = 'rdp'; port = 3389 }) }
        else { $rdpNote = 'Remote Desktop is off. Turning it on needs Administrator rights (Settings > System > Remote Desktop).' }
        if (Test-Port 5900) { Ok 'VNC is listening on port 5900'; [void]$services.Add(@{ kind = 'vnc'; port = 5900 }) }

        # Optional OpenSSH Server: ask (default No), or set $env:RH_SSHD = '1' / '0'.
        if ($isAdmin -and -not ($services | Where-Object { $_.kind -eq 'ssh' })) {
            $answer = $env:RH_SSHD
            if (-not $answer -and [Environment]::UserInteractive) {
                try { $answer = Read-Host '  ? Also turn on the OpenSSH Server, for terminal access? [y/N]' } catch { $answer = '' }
            }
            if ($answer -match '^(1|y|yes)\z') { $installSshd = $true; [void]$services.Add(@{ kind = 'ssh'; port = 22 }) }
        }
        if ($services.Count -eq 0) {
            [void]$services.Add(@{ kind = 'ssh'; port = 22 })
            Warn 'No remote-access service found; registering SSH (22) so the operator can add more later'
        }

        # =====================================================================
        #  Stage 2: a fresh key, written as id_ed25519.new until the server
        #  has accepted it.
        # =====================================================================
        Step 2 "Creating this device's key"
        # Folder: protected DACL, no inherited entries. Admin: SYSTEM +
        # Administrators, owner Administrators. User: you + SYSTEM, owner you
        # (Administrators may also own it). SIDs, so it works in every language.
        if ($isAdmin) {
            $dirSids = @($SidSystem, $SidAdmins); $ownerSids = @($SidSystem, $SidAdmins); $setOwner = $SidAdmins
        } else {
            $dirSids = @($userSid, $SidSystem); $ownerSids = @($userSid, $SidSystem, $SidAdmins); $setOwner = $null
        }
        Initialize-RhDirectory $dir $dirSids $ownerSids $setOwner

        $newKey = Join-Path $dir 'id_ed25519.new'
        Remove-Item -LiteralPath $newKey, "$newKey.pub" -Force -ErrorAction SilentlyContinue
        $r = Invoke-Native $keygen ('-q -t ed25519 -N "" -C remotehound -f "{0}"' -f $newKey)
        if ($r.Code -ne 0 -or -not (Test-Path $newKey)) { Fail ("ssh-keygen could not create a key: {0}" -f (Clean $r.Err 200)) }
        $pubKey = ([IO.File]::ReadAllText("$newKey.pub")).Trim()
        if (-not (Test-Value '^ssh-ed25519 [A-Za-z0-9+/]+=*( [A-Za-z0-9@._-]*)?\z' $pubKey)) { Fail 'ssh-keygen wrote an unexpected public key' }
        $r = Invoke-Native $keygen ('-l -f "{0}.pub"' -f $newKey)
        $fpr = (($r.Out -split '\s+') | Where-Object { $_ -like 'SHA256:*' } | Select-Object -First 1)
        if (-not (Test-Value '^SHA256:[A-Za-z0-9+/]+=*\z' $fpr)) { Fail 'Could not read the key fingerprint' }
        Ok "New ed25519 key $fpr (the private key stays on this computer)"

        # =====================================================================
        #  Stage 3: redeem the code; validate every field of the answer.
        # =====================================================================
        Step 3 "Registering with $BaseUrl"
        $svcList = @()
        foreach ($s in $services) { $svcList += [ordered]@{ kind = $s.kind; remote_port = [int]$s.port } }
        $body = [ordered]@{
            code = $Code; public_key = $pubKey; hostname = $hostname; os = 'windows'
            os_version = $osVersion; services = $svcList; client_version = $ClientVersion
            install_scope = $(if ($isAdmin) { 'system' } else { 'user' })
            install_user = $(if ($isAdmin) { '' } else { Clean (($identity.Name -split '\\')[-1] -replace '[^A-Za-z0-9._ -]', '') 64 })
        }
        $json = ConvertTo-Json -InputObject $body -Depth 4 -Compress
        try {
            $resp = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/v1/enroll" -ContentType 'application/json' `
                -Body ([Text.Encoding]::UTF8.GetBytes($json)) -UseBasicParsing -TimeoutSec 30 `
                -Headers @{ Accept = 'application/json' }
        } catch {
            $status = Get-StatusCode $_
            if ($status -eq 0) { Fail ("Could not reach {0} (network, proxy or TLS problem): {1}" -f $BaseUrl, (Clean $_.Exception.Message 200)) }
            $detail = "HTTP $status"; $ecode = ''
            try {
                $p = (Get-ErrorBody $_) | ConvertFrom-Json
                if ($p.detail) { $detail = Clean ([string]$p.detail) 300 } elseif ($p.title) { $detail = Clean ([string]$p.title) 300 }
                if ($p.code) { $ecode = ([string]$p.code) -replace '[^A-Z_]', '' }
            } catch { }
            $hint = ''
            if ($ecode -like 'ENROLL_CODE_*') { $hint = ' Ask whoever gave you the command for a new code.' }
            elseif ($ecode -eq 'RATE_LIMITED') { $hint = ' Wait a minute, then try again.' }
            if ($ecode) { $detail = "$detail ($ecode)" }
            Fail ("The server refused the enrolment: {0}.{1}" -f $detail, $hint)
        }
        $d = $resp.data
        if (-not $d) { Fail 'The server sent an unexpected answer; stopping.' }
        $deviceId = [string]$d.device_id
        if (-not (Test-Value '^dev_[a-z0-9]{6,40}\z' $deviceId)) { Fail 'The server sent an invalid device id; stopping.' }
        $sshHost = [string]$d.ssh_host
        if (-not (Test-Value '^[A-Za-z0-9][A-Za-z0-9.-]{0,252}\z' $sshHost)) { Fail 'The server sent an invalid tunnel host; stopping.' }
        $sshPort = [string]$d.ssh_port
        if (-not (Test-Value '^[0-9]{1,5}\z' $sshPort) -or [int]$sshPort -lt 1 -or [int]$sshPort -gt 65535) { Fail 'The server sent an invalid tunnel port; stopping.' }
        $forwards = @()
        foreach ($f in @($d.forwards)) {
            if ($null -eq $f) { continue }
            if (-not (Test-Value '^[0-9]{1,5}:localhost:[0-9]{1,5}\z' ([string]$f))) { Fail 'The server sent an invalid port forward; stopping.' }
            $forwards += [string]$f
        }
        if ($forwards.Count -gt 16) { Fail 'The server sent too many port forwards; stopping.' }
        if ($forwards.Count -eq 0) { Warn 'The server allowed no port forwards yet; the operator can add services later' }
        $knownHosts = [string]$d.known_hosts_line
        if (-not (Test-Value '^(\[[A-Za-z0-9.-]+\]:[0-9]{1,5}|[A-Za-z0-9.-]+) (ssh-ed25519|ecdsa-sha2-nistp(256|384|521)|rsa-sha2-(256|512)|ssh-rsa) [A-Za-z0-9+/]+=*\z' $knownHosts)) {
            Fail 'The server sent an invalid host key line; stopping.'
        }
        if ($sshPort -eq '22') { $khHost = $sshHost } else { $khHost = "[$sshHost]:$sshPort" }
        if (-not $knownHosts.StartsWith("$khHost ")) { Warn "The pinned host key is not for $khHost; the tunnel may fail to connect" }
        if ($d.fingerprint -and (([string]$d.fingerprint).TrimEnd('=') -ne $fpr.TrimEnd('='))) {
            Warn "The server reports a different key fingerprint than this device's key"
        }
        $deviceName = Clean ([string]$d.device_name) 64
        if (-not $deviceName) { $deviceName = $hostname }
        Ok "Registered as $deviceName ($deviceId)"
        Ok ("Tunnel endpoint {0}:{1}, forwarding {2}" -f $sshHost, $sshPort, ($(if ($forwards) { $forwards -join ' ' } else { 'nothing yet' })))

        # =====================================================================
        #  Stage 4: built-in services. Never touches the firewall for RDP.
        # =====================================================================
        Step 4 'Turning on remote access services'
        $changed = $false
        if ($enableRdp) {
            try {
                Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0
                Ok 'Remote Desktop turned on (reachable only through the tunnel; no firewall rule was opened)'
                Info 'The operator signs in with a Windows account on this PC.'
            } catch { Warn ("Could not turn on Remote Desktop: {0}" -f (Clean $_.Exception.Message 200)) }
            $changed = $true
        }
        if ($rdpNote) { Warn $rdpNote; $changed = $true }
        if ($installSshd) {
            Info 'Adding the OpenSSH Server feature (this can take a few minutes)...'
            try {
                Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' | Out-Null
                Set-Service -Name sshd -StartupType Automatic
                Start-Service -Name sshd
                # The feature opens port 22 to the network; the tunnel does not need that.
                try { Disable-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction Stop } catch { }
                Ok 'OpenSSH Server installed and started (port 22 kept closed to the network)'
            } catch { Warn ("Could not add the OpenSSH Server: {0}" -f (Clean $_.Exception.Message 200)) }
            $changed = $true
        }
        if (-not $changed) { Ok 'Nothing to change' }

        # =====================================================================
        #  Stage 5: files, Scheduled Task, start.
        # =====================================================================
        Step 5 'Installing the tunnel'
        Stop-OldTunnel $dir
        $key = Join-Path $dir 'id_ed25519'
        # Delete-then-create for every file (see Write-TextFile); old logs go too.
        foreach ($old in @($key, "$key.pub", 'tunnel.log', 'tunnel.log.1', 'state')) {
            $oldPath = $old; if (-not [IO.Path]::IsPathRooted($old)) { $oldPath = Join-Path $dir $old }
            if (Test-Path -LiteralPath $oldPath) { Remove-Item -LiteralPath $oldPath -Force }
        }
        Move-Item -LiteralPath $newKey -Destination $key
        Move-Item -LiteralPath "$newKey.pub" -Destination "$key.pub"
        $newKey = $null
        Write-TextFile (Join-Path $dir 'known_hosts') ($knownHosts + "`n")
        Write-TextFile (Join-Path $dir 'ssh_config') ''
        $conf = @(
            "RH_BASE_URL=$BaseUrl", "RH_DEVICE_ID=$deviceId", "RH_SSH_HOST=$sshHost", "RH_SSH_PORT=$sshPort",
            ("RH_FORWARDS=" + ($forwards -join ' ')), "RH_CLIENT_VERSION=$ClientVersion", 'RH_OS=windows',
            ("RH_SERVICES=" + (($svcList | ForEach-Object { '{0}:{1}' -f $_.kind, $_.remote_port }) -join ' '))
        ) -join "`n"
        Write-TextFile (Join-Path $dir 'device.conf') ($conf + "`n")
        Write-TextFile (Join-Path $dir 'tunnel.ps1') $tunnelPs1
        Write-TextFile (Join-Path $dir 'uninstall.ps1') $uninstallPs1
        $stamp = [DateTime]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture)
        Write-TextFile (Join-Path $dir 'tunnel.log') "$stamp INFO enrolled as $deviceId ($fpr)`n"

        # Private key ACL. OpenSSH for Windows refuses a key that anyone but its
        # owner, SYSTEM or Administrators can read, and the owner must be one of
        # those for the account that runs ssh. The SYSTEM task therefore gets an
        # Administrators-owned folder; the per-user task a folder owned by you.
        # ssh-keygen sets its own ACL on the key; replace it wholesale (a
        # protected DACL with exactly the folder's SIDs).
        try { Set-RhProtectedAcl $key $dirSids; Set-RhProtectedAcl "$key.pub" $dirSids }
        catch { Fail ("Could not restrict access to the private key: {0}" -f (Clean $_.Exception.Message 200)) }
        if ($isAdmin) {
            $r = Invoke-Native 'icacls.exe' ('"{0}" /setowner *{1} /T /C /Q' -f $dir, $SidAdmins)
            if ($r.Code -ne 0) { Fail ("Could not set the owner of {0}: {1}" -f $dir, (Clean $r.Err 200)) }
        }
        # Fail closed before the task is registered: every file must be owned
        # by a trusted account and carry no entry for any other SID.
        if (-not (Test-RhTrustedDirectory $dir $ownerSids $dirSids -Strict)) {
            Fail ("The files in {0} did not end up private; the task was not registered." -f $dir)
        }
        Ok "Wrote key, known_hosts, device.conf, tunnel.ps1, uninstall.ps1 to $dir"

        $psExe = Join-Path $PSHOME 'powershell.exe'
        if (-not (Test-Path $psExe)) { $psExe = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe' }
        $action = New-ScheduledTaskAction -Execute $psExe -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}"' -f (Join-Path $dir 'tunnel.ps1'))
        # Repeat every 5 minutes: a dead watchdog is restarted; IgnoreNew keeps it to one.
        $repeat = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(1)) -RepetitionInterval (New-TimeSpan -Minutes 5)
        $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable `
            -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) `
            -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
        if ($isAdmin) {
            $triggers = @((New-ScheduledTaskTrigger -AtStartup), $repeat)
            $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        } else {
            $me = "$env:USERDOMAIN\$env:USERNAME"
            $triggers = @((New-ScheduledTaskTrigger -AtLogOn -User $me), $repeat)
            $principal = New-ScheduledTaskPrincipal -UserId $me -LogonType Interactive -RunLevel Limited
        }
        $registered = $false
        try {
            Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $triggers -Settings $settings -Principal $principal `
                -Description 'RemoteHound: keeps the outbound tunnel to the RemoteHound server running. Remove with uninstall.ps1 in the RemoteHound folder.' `
                -Force | Out-Null
            Start-ScheduledTask -TaskName $TaskName
            $registered = $true
            Ok "Scheduled Task '$TaskName' registered and started"
        } catch {
            Warn ("Could not register the Scheduled Task: {0}" -f (Clean $_.Exception.Message 200))
        }
        if (-not $registered) {
            Start-Process -FilePath $psExe -WindowStyle Hidden -ArgumentList @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f (Join-Path $dir 'tunnel.ps1')))
            Warn 'The tunnel is running now but will not start again after you log off or restart.'
            Info 'Run the command again from an Administrator PowerShell for a permanent install.'
        }

        # =====================================================================
        #  Stage 6: wait for the server to see the tunnel (2 s x 30).
        # =====================================================================
        Step 6 'Waiting for the tunnel to come up'
        $statusUrl = "$BaseUrl/api/v1/enroll/status?device_id=$deviceId&fingerprint=" + [Uri]::EscapeDataString($fpr)
        $uninstallCmd = 'powershell -ExecutionPolicy Bypass -File "{0}"' -f (Join-Path $dir 'uninstall.ps1')
        for ($i = 0; $i -lt 30; $i++) {
            try {
                $st = Invoke-RestMethod -Method Get -Uri $statusUrl -UseBasicParsing -TimeoutSec 10
                if ($st.data.online -eq $true) {
                    Write-Host ''
                    Write-Host ("  Connected as {0} {1}" -f $deviceName, $markOk) -ForegroundColor Green
                    Write-Host ''
                    Info ("Log file:   {0}" -f (Join-Path $dir 'tunnel.log'))
                    Info ("To remove:  {0}" -f $uninstallCmd)
                    return
                }
            } catch { }
            Start-Sleep -Seconds 2
        }
        Warn 'The server has not seen the tunnel yet. It keeps retrying in the background.'
        Info ("Last lines of {0}:" -f (Join-Path $dir 'tunnel.log'))
        Get-Content -LiteralPath (Join-Path $dir 'tunnel.log') -Tail 10 -ErrorAction SilentlyContinue | ForEach-Object { Info ("  " + $_) }
        Info ("To remove:  {0}" -f $uninstallCmd)
    } catch {
        $msg = $_.Exception.Message
        if ($msg.StartsWith('RH:')) { $msg = $msg.Substring(3) } else { $msg = 'Unexpected error: ' + $msg }
        Write-Host ("  {0} {1}" -f $markBad, $msg) -ForegroundColor Red
        if ($newKey) { Remove-Item -LiteralPath $newKey, "$newKey.pub" -Force -ErrorAction SilentlyContinue }
        # No `exit`: under `irm | iex` it would close the person's PowerShell
        # window. A failed run still reports failure to automation (run-command,
        # RMM tools) through the last exit code.
        $global:LASTEXITCODE = 1
    }
}

# -----------------------------------------------------------------------------
#  tunnel.ps1 - the watchdog (protocol sections 4 and 5). Written verbatim.
# -----------------------------------------------------------------------------
$tunnelPs1 = @'
# RemoteHound tunnel watchdog for Windows (written by the RemoteHound bootstrap; protocol v1).
#
# Keeps ONE outbound SSH connection to the RemoteHound server open. It carries
# reverse port forwards (-R) so the server can reach the local services listed
# in device.conf (e.g. Remote Desktop on 3389). No inbound firewall port is
# opened on this computer.
#
#  - The Scheduled Task "RemoteHound Tunnel" starts it at startup/logon and
#    every 5 minutes; a named mutex keeps it to one instance.
#  - On connect it sends the last 50 lines of tunnel.log on stdin (heartbeat
#    "ping" lines skipped). The private key is never logged.
#  - Control lines from the server (ok / ping / reconnect / revoked) are
#    appended to tunnel.log as "server: <line>".
#  - "revoked": writes "revoked" to .\state, disables the task and exits 0.
#    Re-running the enrol command resets it.
#  - Reconnects with exponential backoff, 2 s doubling to 5 min, plus random
#    jitter of up to half the delay; a session that lasted over 60 s resets it.
#  - tunnel.log is rotated at 1 MB; one old copy (tunnel.log.1) is kept.
$ErrorActionPreference = 'Continue'
$Dir = $PSScriptRoot
$Conf = Join-Path $Dir 'device.conf'
$Log = Join-Path $Dir 'tunnel.log'
$State = Join-Path $Dir 'state'
$Key = Join-Path $Dir 'id_ed25519'
$KnownHosts = Join-Path $Dir 'known_hosts'
$SshConfig = Join-Path $Dir 'ssh_config'
$TaskName = 'RemoteHound Tunnel'
$Utf8 = New-Object System.Text.UTF8Encoding $false

function Write-Log([string]$Level, [string]$Message) {
    try {
        if ((Test-Path -LiteralPath $Log) -and ((Get-Item -LiteralPath $Log).Length -gt 1MB)) {
            Move-Item -LiteralPath $Log -Destination "$Log.1" -Force
        }
        $stamp = [DateTime]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture)
        [IO.File]::AppendAllText($Log, ('{0} {1} {2}' -f $stamp, $Level, $Message) + "`n", $Utf8)
    } catch { }
}

function Clean([string]$Text, [int]$Max) {
    $t = $Text -replace '[\x00-\x1f\x7f]', ''
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max) }
    return $t
}

function Test-Value([string]$Pattern, [string]$Value) { return $Value -cmatch $Pattern }

# Windows command-line quoting for one argument (CommandLineToArgvW rules).
function Quote([string]$s) {
    if ($s -notmatch '[\s"]') { return $s }
    $s = $s -replace '(\\*)"', '$1$1\"'
    $s = $s -replace '(\\+)$', '$1$1'
    return '"' + $s + '"'
}

function Read-Conf {
    $c = @{}
    if (-not (Test-Path -LiteralPath $Conf)) { return $null }
    foreach ($line in [IO.File]::ReadAllLines($Conf)) {
        $i = $line.IndexOf('=')
        if ($i -gt 0) { $c[$line.Substring(0, $i)] = $line.Substring($i + 1) }
    }
    if (-not (Test-Value '^dev_[a-z0-9]{6,40}\z' $c['RH_DEVICE_ID'])) { return $null }
    if (-not (Test-Value '^[A-Za-z0-9][A-Za-z0-9.-]{0,252}\z' $c['RH_SSH_HOST'])) { return $null }
    if (-not (Test-Value '^[0-9]{1,5}\z' $c['RH_SSH_PORT'])) { return $null }
    $c['Forwards'] = @()
    foreach ($f in ([string]$c['RH_FORWARDS'] -split ' ')) {
        if (-not $f) { continue }
        if (-not (Test-Value '^[0-9]{1,5}:localhost:[0-9]{1,5}\z' $f)) { return $null }
        $c['Forwards'] += $f
    }
    $svc = @()
    foreach ($s in ([string]$c['RH_SERVICES'] -split ' ')) {
        if (-not $s) { continue }
        if (-not (Test-Value '^(ssh|rdp|vnc):[0-9]{1,5}\z' $s)) { return $null }
        $svc += $s
    }
    $c['ServicesCsv'] = $svc -join ','
    if (-not (Test-Value '^[A-Za-z0-9._-]{1,32}\z' $c['RH_CLIENT_VERSION'])) { $c['RH_CLIENT_VERSION'] = '1' }
    if (-not (Test-Path -LiteralPath $Key) -or -not (Test-Path -LiteralPath $KnownHosts)) { return $null }
    return $c
}

function Find-Ssh {
    $p = Join-Path $env:WINDIR 'System32\OpenSSH\ssh.exe'
    if (-not (Test-Path $p)) { $p = Join-Path $env:WINDIR 'Sysnative\OpenSSH\ssh.exe' }
    return $p
}

# One SSH session (blocking). Returns @{ Rc = exit code; Last = last control line }.
function Invoke-Session($c) {
    $hostFact = ($env:COMPUTERNAME -replace '[^A-Za-z0-9._-]', '')
    $known = $KnownHosts.Replace('\', '/')
    $a = @('-T', '-F', (Quote $SshConfig), '-i', (Quote $Key),
        '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
        '-o', (Quote ('UserKnownHostsFile="' + $known + '"')),
        '-o', 'ExitOnForwardFailure=yes', '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3',
        '-o', 'ConnectTimeout=15', '-o', 'LogLevel=ERROR', '-p', $c['RH_SSH_PORT'])
    foreach ($f in $c['Forwards']) { $a += @('-R', $f) }
    $a += @(('{0}@{1}' -f $c['RH_DEVICE_ID'], $c['RH_SSH_HOST']), 'agent', 'v1', 'os=windows',
        ('ver=' + $c['RH_CLIENT_VERSION']), ('host=' + $hostFact), ('services=' + $c['ServicesCsv']))

    $tail = @()
    if (Test-Path -LiteralPath $Log) {
        $tail = @(Get-Content -LiteralPath $Log -Tail 400 | Where-Object { $_ -notmatch ' server: ping$' } | Select-Object -Last 50)
    }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = Find-Ssh
    $psi.Arguments = $a -join ' '
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $script:SshProc = $p
    $errTask = $p.StandardError.ReadToEndAsync()
    try {
        foreach ($l in $tail) { $p.StandardInput.WriteLine((Clean $l 500)) }
        $p.StandardInput.Close()
    } catch { }
    $last = ''
    while ($null -ne ($line = $p.StandardOutput.ReadLine())) {
        $line = Clean $line 200
        if ($line) { $last = $line; Write-Log 'INFO' "server: $line" }
    }
    $p.WaitForExit()
    $script:SshProc = $null
    foreach ($e in ($errTask.Result -split "`r?`n")) {
        $e = Clean $e 300
        if ($e) { Write-Log 'WARN' "ssh: $e" }
    }
    return @{ Rc = $p.ExitCode; Last = $last }
}

$script:SshProc = $null
# One watchdog at a time. Global\ spans sessions; fall back to Local\ if a
# mutex of the same name belongs to another account.
try { $mutex = New-Object System.Threading.Mutex($false, 'Global\RemoteHoundTunnel') }
catch { $mutex = New-Object System.Threading.Mutex($false, 'Local\RemoteHoundTunnel') }
$owned = $false
try { $owned = $mutex.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $owned = $true }
if (-not $owned) { exit 0 }    # another watchdog is already running

try {
    $c = Read-Conf
    if (-not $c) {
        Write-Log 'ERROR' 'device.conf, id_ed25519 or known_hosts is missing or invalid; run the enrol command again'
        Start-Sleep -Seconds 60
        exit 1
    }
    # An ssh left over from a watchdog that was killed would hold the forwards.
    try {
        Get-CimInstance Win32_Process -Filter "Name='ssh.exe'" -ErrorAction SilentlyContinue |
            Where-Object { $_.CommandLine -and $_.CommandLine.Contains($Key) } |
            ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    } catch { }
    $backoff = 2
    while ($true) {
        if ((Test-Path -LiteralPath $State) -and (([IO.File]::ReadAllText($State)).Trim() -eq 'revoked')) {
            Write-Log 'INFO' 'device is revoked; not connecting (run the enrol command again to reconnect)'
            exit 0
        }
        $start = Get-Date
        Write-Log 'INFO' ('connecting to {0}:{1} as {2} (forwards: {3})' -f $c['RH_SSH_HOST'], $c['RH_SSH_PORT'], $c['RH_DEVICE_ID'], ($c['Forwards'] -join ' '))
        $r = Invoke-Session $c
        Write-Log 'INFO' ('ssh exited rc={0}' -f $r.Rc)
        if ($r.Last -eq 'revoked') {
            [IO.File]::WriteAllText($State, "revoked`n", $Utf8)
            Write-Log 'WARN' 'the server revoked this device; stopping for good'
            try { Disable-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue | Out-Null } catch { }
            exit 0
        }
        if (((Get-Date) - $start).TotalSeconds -gt 60) { $backoff = 2 } else { $backoff = [Math]::Min($backoff * 2, 300) }
        $jitter = Get-Random -Minimum 0 -Maximum ([int][Math]::Floor($backoff / 2) + 1)
        Write-Log 'INFO' ('retrying in {0}s (+{1}s jitter)' -f $backoff, $jitter)
        Start-Sleep -Seconds ($backoff + $jitter)
    }
} finally {
    if ($script:SshProc -and -not $script:SshProc.HasExited) { try { $script:SshProc.Kill() } catch { } }
    if ($owned) { try { $mutex.ReleaseMutex() } catch { } }
}
'@

# -----------------------------------------------------------------------------
#  uninstall.ps1 - written verbatim.
# -----------------------------------------------------------------------------
$uninstallPs1 = @'
# RemoteHound uninstaller for Windows: stops the tunnel, removes the Scheduled
# Task "RemoteHound Tunnel" and deletes this folder (key, config, logs).
# It does NOT turn off Remote Desktop or the OpenSSH Server: you may rely on them.
# Run from an Administrator PowerShell if RemoteHound was installed as Administrator:
#   powershell -ExecutionPolicy Bypass -File "<this folder>\uninstall.ps1"
$Dir = $PSScriptRoot
if ((Split-Path -Leaf $Dir) -ne 'RemoteHound') { Write-Host "Refusing to run from $Dir"; exit 1 }
$isAdmin = (New-Object System.Security.Principal.WindowsPrincipal ([System.Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
if ($Dir.StartsWith($env:ProgramData, [StringComparison]::OrdinalIgnoreCase) -and -not $isAdmin) {
    Write-Host 'Run this from an Administrator PowerShell (right-click PowerShell > Run as administrator).'
    exit 1
}
try { Stop-ScheduledTask -TaskName 'RemoteHound Tunnel' -ErrorAction SilentlyContinue } catch { }
try { Unregister-ScheduledTask -TaskName 'RemoteHound Tunnel' -Confirm:$false -ErrorAction SilentlyContinue } catch { }
$key = Join-Path $Dir 'id_ed25519'
$script = Join-Path $Dir 'tunnel.ps1'
try {
    Get-CimInstance Win32_Process -Filter "Name='ssh.exe' OR Name='powershell.exe' OR Name='pwsh.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.ProcessId -ne $PID -and $_.CommandLine -and ($_.CommandLine.Contains($key) -or $_.CommandLine.Contains($script)) } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
} catch { }
Start-Sleep -Seconds 1
Set-Location $env:TEMP
Remove-Item -LiteralPath $Dir -Recurse -Force -ErrorAction SilentlyContinue
if (Test-Path -LiteralPath $Dir) { Write-Host "Some files in $Dir could not be removed; delete the folder by hand." }
Write-Host 'RemoteHound has been removed from this computer.'
Write-Host 'Remote Desktop / OpenSSH Server were left as they are; turn them off in Settings if you no longer need them.'
'@

Invoke-RemoteHoundEnrol
# Leave nothing behind in the PowerShell session that ran `| iex`.
Remove-Variable -Name tunnelPs1, uninstallPs1 -ErrorAction SilentlyContinue
Remove-Item -Path Function:\Invoke-RemoteHoundEnrol -ErrorAction SilentlyContinue
