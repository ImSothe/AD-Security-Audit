# Security tests: injection, tampered input, path traversal, secrets, read-only guarantees, privacy.
if (-not (Get-Command Invoke-MockCollect -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'AdMock.ps1') }

$labSnap = Get-Content (Join-Path $root 'lab\lab-sample.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$payload = '"><img src=x onerror=alert(1)><script>alert(2)</script>'''

function Get-ReportFor { param($Snapshot)
    $r = New-ADAuditResult -Snapshot $Snapshot -Findings @(Invoke-ADAuditChecks -Snapshot $Snapshot) -InactiveDays 90 -MaxDomainAdmins 5
    ConvertTo-ADAuditHtml -Results ($r | ConvertTo-Json -Depth 8 | ConvertFrom-Json)
}
# Real attributes only: quoted attribute values are removed first, so encoded text such as
# id="&quot;&gt;&lt;img onerror=..." (harmless, inside quotes) is not mistaken for a handler.
function Test-HasEventHandler { param([string]$Html)
    foreach ($tag in [regex]::Matches($Html, '<[A-Za-z][^>]*>')) {
        if (($tag.Value -replace '"[^"]*"', '""') -match '\son[a-z]+\s*=') { return $true }
    }
    return $false
}
function Assert-NoInjectedMarkup { param([string]$Html)
    Assert-True ($Html -notmatch '<img') 'raw <img> tag rendered'
    Assert-True ($Html -notmatch '<script>alert') 'raw <script> rendered'
    Assert-Equal 1 ([regex]::Matches($Html, '<script')).Count 'number of script tags'
    Assert-True (-not (Test-HasEventHandler $Html)) 'event handler attribute present'
}
# Command names actually invoked in a script, from the PowerShell parser (strings and comments ignored).
function Get-InvokedCommands { param([string]$Path)
    $ast = [Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
    @($ast.FindAll({ param($n) $n -is [Management.Automation.Language.CommandAst] }, $true) |
        ForEach-Object { $_.GetCommandName() } | Where-Object { $_ } | Select-Object -Unique)
}
# Source files that ship (tests excluded, they contain the patterns they look for).
$shipped = @(Get-ChildItem $root -Recurse -Include '*.ps1' | Where-Object { $_.FullName -notlike '*\tests\*' })

# ---------------------------------------------------------------- injection into the report
Test-Case 'XSS: payload in every directory string field is encoded' {
    $s = Copy-Deep $labSnap; $i = 0
    foreach ($u in $s.Users) { $i++
        $u.DisplayName = "$payload$i"; $u.SamAccountName = "$payload-u$i"; $u.MemberOf = @("$payload-g")
        if (@($u.ServicePrincipalNames).Count) { $u.ServicePrincipalNames = @("$payload/spn") }
        if (@($u.DelegatesTo).Count) { $u.DelegatesTo = @("$payload/svc") } }
    foreach ($c in $s.Computers) { $c.Name = "$payload-c"; $c.OperatingSystem = "Windows 7 $payload"; $c.OperatingSystemVersion = $payload
        if (@($c.DelegatesTo).Count) { $c.DelegatesTo = @("$payload/svc") } }
    foreach ($g in $s.Gpos) { $g.DisplayName = "$payload-gpo" }
    foreach ($g in $s.PrivilegedGroups) { $g.Name = "$payload-grp"; foreach ($m in $g.Members) { $m.SamAccountName = "$payload-m" } }
    $s.Domain.DnsRoot = $payload; $s.Domain.NetBIOSName = $payload; $s.Domain.DomainMode = $payload; $s.Domain.ForestMode = $payload
    $s.SysvolOrphans = @($payload); $s.Errors = @($payload)
    $h = Get-ReportFor $s
    Assert-NoInjectedMarkup $h
    Assert-True ($h -match '&lt;img src=x onerror=alert\(1\)&gt;') 'payload should be visible as text'
    Assert-True ($h -match '<title>AD security audit - &quot;&gt;&lt;img') 'title encoded'
}
Test-Case 'XSS: GPO read error message is encoded' {
    $s = Copy-Deep $labSnap; $s.GpoError = $payload
    Assert-NoInjectedMarkup (Get-ReportFor $s)
}
Test-Case 'tampered results JSON cannot inject through severity, counts, totals or columns' {
    $r = New-ADAuditResult -Snapshot $labSnap -Findings @(Invoke-ADAuditChecks -Snapshot $labSnap) -InactiveDays 90 -MaxDomainAdmins 5 |
        ConvertTo-Json -Depth 8 | ConvertFrom-Json
    $f = $r.Findings[0]
    $f.Severity = 'Red"><script>alert(1)</script>'; $f.Count = '1<img src=x onerror=alert(1)>'; $f.Id = $payload
    $f.Columns = @($payload); $f.Title = $payload; $f.Recommendation = $payload; $f.Category = $payload
    $r.Score = '50"><script>'; $r.Totals.Red = '<img src=x>'; $r.Stats.Users = '<img src=x>'
    $r.Parameters.InactiveDays = '<img src=x>'; $r.ToolVersion = $payload; $r.CollectionErrors = @($payload)
    $h = ConvertTo-ADAuditHtml -Results $r
    Assert-NoInjectedMarkup $h
    Assert-True ($h -match '<details id="&quot;&gt;&lt;img[^"]*" class="NotRun"') 'unknown severity must fall back to NotRun'
}
Test-Case 'tampered score is clamped to 0..100' {
    $r = $labSnap | ForEach-Object { New-ADAuditResult -Snapshot $_ -Findings @(Invoke-ADAuditChecks -Snapshot $_) -InactiveDays 90 -MaxDomainAdmins 5 }
    $r.Score = 9999; Assert-True ((ConvertTo-ADAuditHtml -Results $r) -match '>100</text>') 'clamped high'
    $r.Score = -5; Assert-True ((ConvertTo-ADAuditHtml -Results $r) -match '>0</text>') 'clamped low'
}

# ---------------------------------------------------------------- report hardening
$labHtml = Get-ReportFor $labSnap
Test-Case 'CSP: default-src none, no remote anything, script pinned by hash' {
    $m = [regex]::Match($labHtml, '<meta http-equiv="Content-Security-Policy" content="([^"]+)">')
    Assert-True $m.Success 'CSP meta missing'
    $csp = $m.Groups[1].Value
    foreach ($d in "default-src 'none'", "base-uri 'none'", "form-action 'none'", "img-src data:") { Assert-True ($csp.Contains($d)) "CSP lacks $d" }
    Assert-True ($csp -notmatch "unsafe-eval|'unsafe-inline'[^;]*script|https?:|\*") "CSP too permissive: $csp"
    $script = [regex]::Match($labHtml, '<script>(.*?)</script>', 'Singleline').Groups[1].Value
    $hash = [Convert]::ToBase64String([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($script)))
    Assert-True ($csp.Contains("script-src 'sha256-$hash'")) 'script hash does not match the inline script'
}
Test-Case 'CSP meta comes before any style or script' {
    $cspAt = $labHtml.IndexOf('Content-Security-Policy'); $styleAt = $labHtml.IndexOf('<style>'); $scriptAt = $labHtml.IndexOf('<script>')
    Assert-True ($cspAt -gt 0 -and $cspAt -lt $styleAt -and $cspAt -lt $scriptAt) 'CSP must be first in <head>'
}
Test-Case 'report has no external resources, inline handlers or javascript: URLs' {
    Assert-True ($labHtml -notmatch '(src|href)\s*=\s*"(https?:)?//') 'external src/href'
    Assert-True ($labHtml -notmatch '@import|url\(') 'CSS import/url'
    Assert-True ($labHtml -notmatch '<[^>]+\son[a-z]+\s*=') 'inline event handler'
    Assert-True ($labHtml -notmatch 'javascript:') 'javascript: URL'
    Assert-True ($labHtml -match '<meta name="referrer" content="no-referrer">') 'referrer policy'
}

# ---------------------------------------------------------------- input validation
Test-Case 'unsupported snapshot schema is rejected' {
    $bad = Copy-Deep $labSnap; $bad.SchemaVersion = 2
    $p = Join-Path $TempRoot 'bad-schema.json'; $bad | ConvertTo-Json -Depth 8 | Set-Content $p -Encoding UTF8
    Assert-Throws { & (Join-Path $root 'Invoke-ADSecurityAudit.ps1') -SnapshotPath $p -OutputDirectory $TempRoot 6>$null } -Like '*schema*' -What 'schema 2'
}
Test-Case 'converter rejects files that are not audit results' {
    $p = Join-Path $TempRoot 'not-results.json'; '{"hello":"world"}' | Set-Content $p -Encoding UTF8
    Assert-Throws { & (Join-Path $root 'ConvertTo-ADAuditReport.ps1') -InputPath $p } -Like '*not an AD-Security-Audit results file*' -What 'random json'
    $p2 = Join-Path $TempRoot 'snapshot-not-results.json'; $labSnap | ConvertTo-Json -Depth 8 | Set-Content $p2 -Encoding UTF8
    Assert-Throws { & (Join-Path $root 'ConvertTo-ADAuditReport.ps1') -InputPath $p2 } -Like '*not an AD-Security-Audit results file*' -What 'snapshot passed as results'
}
Test-Case 'path traversal: NetBIOS name from a snapshot cannot escape the output folder' {
    foreach ($evil in '..\..\pwned', '../../pwned', 'C:\Windows\x', '\\server\share\x', 'a:b*c?d"e<f>g|h') {
        $safe = Get-SafeFileNamePart $evil
        Assert-True ($safe -match '^[A-Za-z0-9_-]+$') "unsafe part '$safe' from '$evil'"
    }
    Assert-Equal 'DOMAIN' (Get-SafeFileNamePart '') 'empty'
    Assert-Equal 'DOMAIN' (Get-SafeFileNamePart '....') 'only dots'
    Assert-Equal 40 (Get-SafeFileNamePart ('A' * 300)).Length 'length cap'

    $s = Copy-Deep $labSnap; $s.Domain.NetBIOSName = '..\..\..\pwned'
    $p = Join-Path $TempRoot 'evil.json'; $s | ConvertTo-Json -Depth 8 | Set-Content $p -Encoding UTF8
    $out = Join-Path $TempRoot 'out-evil'
    & (Join-Path $root 'Invoke-ADSecurityAudit.ps1') -SnapshotPath $p -OutputDirectory $out 6>$null | Out-Null
    $written = @(Get-ChildItem $out -File)
    Assert-Equal 2 $written.Count 'files in output folder'
    Assert-True (-not (Test-Path (Join-Path $TempRoot 'pwned*'))) 'file written outside the output folder'
}

# ---------------------------------------------------------------- read-only and secrets
Test-Case 'collector only invokes read cmdlets against AD (parsed, not grepped)' {
    $cmds = Get-InvokedCommands (Join-Path $root 'src\Collect.ps1')
    $ad = @($cmds | Where-Object { $_ -match '-AD' })
    Assert-True ($ad.Count -ge 9) "expected the AD read cmdlets, found: $($ad -join ', ')"
    $writes = @($ad | Where-Object { $_ -notlike 'Get-*' })
    Assert-Equal 0 $writes.Count "non-read AD cmdlets: $($writes -join ', ')"
}
Test-Case 'checks, report and helpers never invoke AD cmdlets' {
    foreach ($f in 'Checks', 'Report', 'Common', 'Lab') {
        $ad = @(Get-InvokedCommands (Join-Path $root "src\$f.ps1") | Where-Object { $_ -match '-AD' })
        Assert-Equal 0 $ad.Count "$f.ps1 invokes $($ad -join ', ')"
    }
}
Test-Case 'shipped code has no dynamic execution, remoting, downloads or outbound network calls' {
    $bannedCmds = 'Invoke-Expression', 'iex', 'Invoke-WebRequest', 'iwr', 'Invoke-RestMethod', 'irm', 'Start-BitsTransfer', 'Send-MailMessage',
        'Add-Type', 'Start-Process', 'Invoke-Command', 'New-PSSession', 'Enter-PSSession', 'Set-ExecutionPolicy', 'Invoke-Item', 'New-Object'
    $bannedText = 'DownloadString', 'DownloadFile', 'Net\.WebClient', 'Net\.Http', 'Net\.Sockets', 'FromBase64String', 'EncodedCommand', '\[ScriptBlock\]::Create'
    foreach ($file in $shipped) {
        $cmds = Get-InvokedCommands $file.FullName
        foreach ($b in $bannedCmds) {
            # New-Object is only allowed for in-memory types (lists, encodings, random, byte arrays).
            if ($b -eq 'New-Object') { continue }
            Assert-True ($cmds -notcontains $b) "$($file.Name) invokes $b"
        }
        $code = Get-Content $file.FullName -Raw
        foreach ($t in $bannedText) { Assert-True ($code -notmatch $t) "$($file.Name) uses $t" }
        $objects = [regex]::Matches($code, 'New-Object\s+([\w.\[\]]+)') | ForEach-Object { $_.Groups[1].Value }
        foreach ($o in $objects) {
            Assert-True ($o -match '^(System\.Collections\.Generic\.List\[\w+\]|System\.Random|byte\[\]|Text\.UTF8Encoding|System\.Text\.StringBuilder|pscredential)$') "$($file.Name) creates $o"
        }
    }
}
Test-Case 'shipped code only writes files through the expected commands' {
    $allowed = @{ 'Invoke-ADSecurityAudit.ps1' = 'Set-Content', 'New-Item'; 'New-LabSample.ps1' = 'Set-Content', 'Copy-Item' }
    foreach ($file in $shipped) {
        $writers = @(Get-InvokedCommands $file.FullName | Where-Object {
            $_ -in 'Set-Content', 'Add-Content', 'Out-File', 'New-Item', 'Copy-Item', 'Move-Item', 'Remove-Item', 'Rename-Item', 'Clear-Content', 'Export-Csv', 'Export-Clixml' })
        $ok = if ($allowed[$file.Name]) { $allowed[$file.Name] } else { @() }
        $extra = @($writers | Where-Object { $_ -notin $ok })
        Assert-Equal 0 $extra.Count "$($file.Name) uses $($extra -join ', ')"
    }
}
Test-Case 'collector never requests secret attributes' {
    $code = Get-Content (Join-Path $root 'src\Collect.ps1') -Raw
    foreach ($attr in 'unicodePwd', 'ms-Mcs-AdmPwd', 'msLAPS-Password', 'msLAPS-EncryptedPassword', 'ntPwdHistory', 'lmPwdHistory',
            'supplementalCredentials', 'msDS-ManagedPassword', 'msFVE-RecoveryPassword', 'dBCSPwd', 'Properties \*', "Properties '\*'") {
        Assert-True ($code -notmatch [regex]::Escape($attr).Replace('\\\*', '\*')) "collector mentions $attr"
    }
}
Test-Case 'secrets returned by AD never reach the snapshot, and the credential is not stored' {
    $cred = New-Object pscredential 'MOCK\auditor-x9', (ConvertTo-SecureString 'Sup3r-Secret-Pw!' -AsPlainText -Force)
    $snapJson = Invoke-MockCollect @{ Credential = $cred } | ConvertTo-Json -Depth 8
    foreach ($secret in 'LAPS-SECRET', 'HASH-SECRET', 'auditor-x9', 'Sup3r-Secret-Pw', 'ms-Mcs-AdmPwd', 'unicodePwd') {
        Assert-True (-not $snapJson.Contains($secret)) "snapshot contains $secret"
    }
}

# ---------------------------------------------------------------- repository hygiene
$tracked = @()
if (Get-Command git -ErrorAction SilentlyContinue) {
    $tracked = @(git -C $root ls-files 2>$null | Where-Object { $_ -notmatch '\.png$' } | ForEach-Object { Join-Path $root $_ })
}
Test-Case 'repository: no personal e-mail addresses, user paths or key material in tracked files' {
    if (-not $tracked.Count) { return }
    foreach ($file in $tracked) {
        if (-not (Test-Path $file) -or $file -like '*\tests\Security.Tests.ps1') { continue }
        $text = [IO.File]::ReadAllText($file)
        $mails = [regex]::Matches($text, '[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}') |
            ForEach-Object Value | Where-Object { $_ -notmatch '@users\.noreply\.github\.com$|@example\.(com|org|local)$|\.lab$' }
        Assert-Equal 0 @($mails).Count "$file contains e-mail $(@($mails) -join ', ')"
        Assert-True ($text -notmatch '[A-Za-z]:\\Users\\[A-Za-z]') "$file contains a user profile path"
        Assert-True ($text -notmatch '-----BEGIN [A-Z ]*PRIVATE KEY-----') "$file contains a private key"
        Assert-True ($text -notmatch '(?i)(api[_-]?key|secret|token)\s*[:=]\s*["''][A-Za-z0-9/+_-]{16,}') "$file contains a secret-looking value"
    }
}
Test-Case 'repository: real audit output is git-ignored' {
    if (-not $tracked.Count) { return }
    foreach ($p in 'reports/ad-audit-CORP-20260101-0000-report.html', 'C:/x/ad-audit-CORP-20260101-0000-snapshot.json'.Replace('C:/x/', 'anywhere/')) {
        git -C $root check-ignore -q $p 2>$null
        Assert-Equal 0 $LASTEXITCODE "$p is not ignored"
    }
}
