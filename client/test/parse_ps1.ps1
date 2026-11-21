# Parses a PowerShell file and every single-quoted here-string inside it (the embedded
# tunnel.ps1 / uninstall.ps1) with the real PowerShell parser. Prints one line per
# script checked: "OK <name>" or "ERR <name>: <line>:<col> <message>". Exit 1 on any error.
# Usage: pwsh -NoProfile -File parse_ps1.ps1 <file.ps1>
$path = $args[0]
$text = [IO.File]::ReadAllText($path)
$bad = 0

function Test-Script([string]$Name, [string]$Source) {
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($Source, [ref]$tokens, [ref]$errors)
    if ($errors.Count -gt 0) {
        foreach ($e in $errors) {
            Write-Output ("ERR {0}: {1}:{2} {3}" -f $Name, $e.Extent.StartLineNumber, $e.Extent.StartColumnNumber, $e.Message)
        }
        return $null
    }
    Write-Output "OK $Name"
    return $ast
}

$ast = $null
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) {
    foreach ($e in $errors) { Write-Output ("ERR {0}: {1}:{2} {3}" -f (Split-Path -Leaf $path), $e.Extent.StartLineNumber, $e.Extent.StartColumnNumber, $e.Message) }
    exit 1
}
Write-Output ("OK " + (Split-Path -Leaf $path))

# The bootstrap runs under `irm | iex`: no `exit` (it would close the user's shell),
# no script param() block and no $PSScriptRoot (both are meaningless under iex).
# Here-string contents are strings, so the embedded watchdog may use them.
$exits = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.ExitStatementAst] }, $true)
if ($exits.Count -gt 0) { Write-Output ("ERR bootstrap uses exit at line {0}" -f $exits[0].Extent.StartLineNumber); $bad = 1 }
else { Write-Output 'OK iex-safe: no exit statement' }
$roots = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] -and $n.VariablePath.UserPath -eq 'PSScriptRoot' }, $true)
if ($ast.ParamBlock -or $roots.Count -gt 0) { Write-Output 'ERR bootstrap relies on param() or $PSScriptRoot'; $bad = 1 }
else { Write-Output 'OK iex-safe: no param() block or $PSScriptRoot' }

# Security hardening of the install folder (local privilege escalation fix):
# the functions must exist, and the bootstrap must use them instead of plain writes.
$fnNames = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object { $_.Name })
foreach ($fn in 'Test-RhTrustedDirectory', 'Initialize-RhDirectory', 'New-RhSecureDirectory', 'New-RhProtectedSecurity', 'Set-RhProtectedAcl', 'Write-TextFile') {
    if ($fnNames -contains $fn) { Write-Output "OK acl-hardening: function $fn defined" } else { Write-Output "ERR acl-hardening: function $fn missing"; $bad = 1 }
}
$calls = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() })
foreach ($c in 'Initialize-RhDirectory', 'Test-RhTrustedDirectory', 'Set-RhProtectedAcl') {
    if ($calls -contains $c) { Write-Output "OK acl-hardening: $c is called" } else { Write-Output "ERR acl-hardening: $c is never called"; $bad = 1 }
}
# Outside Write-TextFile nothing may write files in place (that keeps an existing file's ACL).
$inPlace = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
        $n.Member.Extent.Text -match '^(WriteAllText|AppendAllText|WriteAllBytes|WriteAllLines)$' }, $true)
if ($inPlace.Count -eq 0) { Write-Output 'OK acl-hardening: no in-place [IO.File]::Write*/Append* in the bootstrap' }
else { Write-Output ("ERR acl-hardening: in-place file write at line {0}" -f $inPlace[0].Extent.StartLineNumber); $bad = 1 }
$newItemDir = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'New-Item' -and
        $n.Extent.Text -match 'Directory' }, $true) | Where-Object {
    $p = $_.Parent; while ($p -and $p -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) { $p = $p.Parent }; -not $p -or $p.Name -ne 'New-RhSecureDirectory' }
if (@($newItemDir).Count -eq 0) { Write-Output 'OK acl-hardening: folders are only created by New-RhSecureDirectory' }
else { Write-Output 'ERR acl-hardening: New-Item -ItemType Directory outside New-RhSecureDirectory'; $bad = 1 }
# Behaviour of the ACL helpers that can run on any OS: the descriptor is protected and has only the given SIDs.
$helper = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'New-RhProtectedSecurity' }, $true)
if ($helper) {
    try {
        . ([scriptblock]::Create($helper[0].Extent.Text))
        $sd = New-RhProtectedSecurity $true @('S-1-5-18', 'S-1-5-32-544')
        $sids = @($sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | ForEach-Object { $_.IdentityReference.Value }) | Sort-Object
        if ($sd.AreAccessRulesProtected -and (($sids -join ',') -eq 'S-1-5-18,S-1-5-32-544')) { Write-Output 'OK acl-hardening: New-RhProtectedSecurity builds a protected DACL with only the given SIDs' }
        else { Write-Output ("ERR acl-hardening: descriptor protected={0} sids={1}" -f $sd.AreAccessRulesProtected, ($sids -join ',')); $bad = 1 }
    } catch { Write-Output ("SKIP acl-hardening: descriptor check needs Windows ACL types ({0})" -f $_.Exception.Message) }
}

# Embedded scripts: $<name>Ps1 = @' ... '@
$assigns = $ast.FindAll({ param($n)
        $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $n.Left.Extent.Text -match '^\$\w+Ps1$' }, $true)
if ($assigns.Count -eq 0) { Write-Output "ERR no embedded *Ps1 here-strings found"; exit 1 }
foreach ($a in $assigns) {
    $rhs = $a.Right.Expression
    if ($rhs -isnot [System.Management.Automation.Language.StringConstantExpressionAst] -or
        $rhs.StringConstantType -ne 'SingleQuotedHereString') {
        Write-Output ("ERR {0} is not a single-quoted here-string" -f $a.Left.Extent.Text); $bad = 1; continue
    }
    $r = Test-Script $a.Left.Extent.Text $rhs.Value
    if (-not ($r | Where-Object { $_ -is [string] -and $_.StartsWith('OK ') })) { $bad = 1 }
    $r | Where-Object { $_ -is [string] }
    # Unit-check the Windows argument quoting used for ssh.exe's command line.
    $quote = $r | Where-Object { $_ -isnot [string] } | ForEach-Object {
        $_.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Quote' }, $true) }
    if ($quote) {
        . ([scriptblock]::Create($quote[0].Extent.Text))
        $cases = @(
            @('plain', 'plain'),
            @('C:\Users\John Smith\id', '"C:\Users\John Smith\id"'),
            @('UserKnownHostsFile="C:/x y/known_hosts"', '"UserKnownHostsFile=\"C:/x y/known_hosts\""'),
            @('C:\dir with space\', '"C:\dir with space\\"'))
        $qok = $true
        foreach ($c in $cases) { if ((Quote $c[0]) -cne $c[1]) { $qok = $false; Write-Output ("ERR Quote({0}) = {1}, want {2}" -f $c[0], (Quote $c[0]), $c[1]) } }
        if ($qok) { Write-Output 'OK tunnel.ps1 Quote() follows CommandLineToArgvW rules' } else { $bad = 1 }
    }
}

# The enrol request body: a one-element services list must stay a JSON array.
$svcList = @(); $svcList += [ordered]@{ kind = 'ssh'; remote_port = 22 }
$json = ConvertTo-Json -InputObject ([ordered]@{ code = 'k7q2mx'; services = $svcList }) -Depth 4 -Compress
if ($json -ceq '{"code":"k7q2mx","services":[{"kind":"ssh","remote_port":22}]}') { Write-Output 'OK request JSON keeps services as an array' }
else { Write-Output "ERR request JSON: $json"; $bad = 1 }
exit $bad
