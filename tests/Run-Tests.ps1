#Requires -Version 5.1
# Dependency-free test runner (works on Windows PowerShell 5.1 and PowerShell 7, with or without Pester).
# Exit code = number of failed tests.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
foreach ($file in 'Common', 'Collect', 'Lab', 'Checks', 'Report') { . (Join-Path $root "src\$file.ps1") }

$script:passed = 0; $script:failed = 0
function Test-Case {
    param([string]$Name, [scriptblock]$Body)
    try { & $Body; $script:passed++; Write-Host "  [PASS] $Name" -ForegroundColor Green }
    catch { $script:failed++; Write-Host "  [FAIL] $Name`n         $($_.Exception.Message)" -ForegroundColor Red }
}
function Assert-Equal { param($Expected, $Actual, [string]$What = 'value')
    if ($Expected -ne $Actual) { throw "$What : expected '$Expected', got '$Actual'" } }
function Assert-True { param([bool]$Condition, [string]$Message) if (-not $Condition) { throw $Message } }

$ref = [datetime]'2026-11-20T09:00:00Z'
$lab = Get-Content (Join-Path $root 'lab\lab-sample.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$findings = @(Invoke-ADAuditChecks -Snapshot $lab)
$byId = @{}; foreach ($f in $findings) { $byId[$f.Id] = $f }

Write-Host 'Lab sample'
Test-Case 'committed lab-sample.json matches the generator' {
    $fresh = New-ADAuditLabSnapshot | ConvertTo-Json -Depth 8 | ConvertFrom-Json | ConvertTo-Json -Depth 8 -Compress
    $file = $lab | ConvertTo-Json -Depth 8 -Compress
    Assert-True ($fresh -eq $file) 'lab\lab-sample.json is stale: run tools\New-LabSample.ps1'
}
Test-Case 'all 29 checks run without engine errors' {
    Assert-Equal 29 $findings.Count 'finding count'
    Assert-Equal 0 @($findings | Where-Object Severity -eq 'NotRun').Count 'NotRun findings'
}
Test-Case 'finding ids are unique' {
    Assert-Equal $findings.Count @($findings.Id | Select-Object -Unique).Count 'unique ids'
}
$expected = [ordered]@{
    'ACC-01' = 'Amber', 5;  'ACC-02' = 'Amber', 3;  'ACC-03' = 'Red', 3;    'ACC-04' = 'Red', 9
    'ACC-05' = 'Red', 1;    'ACC-06' = 'Amber', 10; 'ACC-07' = 'Amber', 2;  'ACC-08' = 'Green', 0
    'ACC-09' = 'Red', 1;    'ACC-10' = 'Red', 2;    'ACC-11' = 'Green', 0;  'PRV-01' = 'Amber', 18
    'PRV-02' = 'Amber', 4;  'PRV-03' = 'Red', 7;    'PRV-04' = 'Red', 1;    'PRV-05' = 'Amber', 1
    'PRV-06' = 'Amber', 1;  'DEL-01' = 'Red', 1;    'DEL-02' = 'Amber', 2;  'DEL-03' = 'Amber', 1
    'CMP-01' = 'Red', 14;   'CMP-02' = 'Amber', 6;  'GPO-01' = 'Amber', 4;  'GPO-02' = 'Amber', 2
    'GPO-03' = 'Amber', 1;  'GPO-04' = 'Red', 2;    'DOM-01' = 'Red', 2;    'DOM-02' = 'Amber', 0
    'DOM-03' = 'Amber', 0
}
foreach ($id in $expected.Keys) {
    $sev, $count = $expected[$id]
    Test-Case "$id is $sev with $count items" {
        Assert-Equal $sev $byId[$id].Severity "$id severity"
        Assert-Equal $count $byId[$id].Count "$id count"
    }
}
Test-Case 'planted accounts are found by name' {
    Assert-True (@($byId['ACC-02'].Items.Account) -contains 'supplier.erp') 'ghost supplier.erp missing'
    Assert-True (@($byId['ACC-03'].Items.Account) -contains 'old.admin') 'leaver old.admin missing'
    Assert-True (@($byId['ACC-09'].Items.Account) -contains 'svc_legacy') 'AS-REP svc_legacy missing'
    Assert-True (@($byId['DEL-01'].Items.Object) -contains 'SRV-ERP01') 'unconstrained SRV-ERP01 missing'
    Assert-True (-not (@($byId['DEL-01'].Items.Object) -contains 'DC01')) 'domain controllers must be excluded from DEL-01'
    Assert-True (-not (@($byId['CMP-01'].Items.Computer) -contains 'PC-OLDXP')) 'disabled computers must be excluded'
}
Test-Case 'nested Domain Admins members appear in the inventory' {
    $da = @($byId['PRV-01'].Items | Where-Object Group -eq 'Domain Admins').Account
    Assert-True ($da -contains 'hd.paula') 'nested member hd.paula missing'
}

Write-Host 'Rules'
Test-Case 'OS lifecycle classification' {
    Assert-Equal 'Unsupported' (Get-OsSupportStatus 'Windows 7 Professional' $ref).Status 'Win7'
    Assert-Equal 'Unsupported' (Get-OsSupportStatus 'Windows 8.1 Pro' $ref).Status 'Win8.1'
    Assert-Equal 'Unsupported' (Get-OsSupportStatus 'Windows 10 Pro' $ref).Status 'Win10'
    Assert-Equal 'Supported'   (Get-OsSupportStatus 'Windows 11 Enterprise' $ref).Status 'Win11'
    Assert-Equal 'Unsupported' (Get-OsSupportStatus 'Windows Server 2012 R2 Standard' $ref).Status '2012 R2'
    Assert-Equal 'EndingSoon'  (Get-OsSupportStatus 'Windows Server 2016 Datacenter' $ref).Status '2016'
    Assert-Equal 'Supported'   (Get-OsSupportStatus 'Windows Server 2022 Standard' $ref).Status '2022'
    Assert-Equal 'Unknown'     (Get-OsSupportStatus 'Ubuntu 24.04' $ref).Status 'non-Windows'
    Assert-Equal 'Supported'   (Get-OsSupportStatus 'Windows 10 Pro' ([datetime]'2024-01-01')).Status 'Win10 before EOS'
}
Test-Case 'score: all green 100, all red 0, NotRun ignored' {
    $mk = { param($s) [pscustomobject]@{ Severity = $s } }
    Assert-Equal 100 (Get-AuditScore @((& $mk Green), (& $mk Green), (& $mk NotRun))) 'all green'
    Assert-Equal 0 (Get-AuditScore @((& $mk Red), (& $mk Red))) 'all red'
    Assert-Equal 50 (Get-AuditScore @((& $mk Amber), (& $mk Amber))) 'all amber'
}
Test-Case 'thresholds are configurable' {
    $strict = @(Invoke-ADAuditChecks -Snapshot $lab -InactiveDays 30 -MaxDomainAdmins 20)
    $acc01 = $strict | Where-Object Id -eq 'ACC-01'
    Assert-True ($acc01.Count -gt $byId['ACC-01'].Count) '30-day threshold should find more inactive users'
    Assert-Equal 'Green' ($strict | Where-Object Id -eq 'PRV-01').Severity 'PRV-01 with 20 allowed admins'
}
Test-Case 'a healthy domain is all green' {
    $clean = New-ADAuditLabSnapshot | ConvertTo-Json -Depth 8 | ConvertFrom-Json
    $clean.Users = @($clean.Users | Where-Object { $_.Sid -match '-(500|501|502)$' -or $_.SamAccountName -in 'adm.jmartin', 'lgarcia' })
    foreach ($u in $clean.Users) {
        $u.PasswordNeverExpires = $false; $u.ServicePrincipalNames = @(); $u.AdminCount = 0
        $u.PasswordLastSet = $ref.AddDays(-30).ToString('o')
    }
    ($clean.Users | Where-Object SamAccountName -eq 'adm.jmartin').AccountNotDelegated = $true
    ($clean.Users | Where-Object SamAccountName -eq 'Administrator').LastLogonDate = $ref.AddDays(-30).ToString('o')
    ($clean.Users | Where-Object SamAccountName -eq 'Administrator').AccountNotDelegated = $true
    $sids = @{}; foreach ($u in $clean.Users) { $sids[$u.SamAccountName] = $u.Sid }
    foreach ($g in $clean.PrivilegedGroups) {
        $keep = switch ($g.Key) { 'DomainAdmins' { 'Administrator', 'adm.jmartin' } 'Administrators' { 'Administrator', 'adm.jmartin' } default { @() } }
        $g.Members = @($g.Members | Where-Object SamAccountName -in $keep)
    }
    $clean.Computers = @($clean.Computers | Where-Object { $_.Name -in 'DC01', 'SRV-FILE01', 'PC-001' })
    $clean.Gpos = @($clean.Gpos | Where-Object { $_.DisplayName -like 'Default*' }); $clean.SysvolOrphans = @()
    $clean.Domain.DomainMode = 'Windows2016Domain'; $clean.Domain.RecycleBinEnabled = $true
    $clean.Domain.PasswordPolicy.MinPasswordLength = 14; $clean.Domain.PasswordPolicy.LockoutThreshold = 10
    $notGreen = @(Invoke-ADAuditChecks -Snapshot $clean | Where-Object Severity -ne 'Green')
    Assert-Equal 0 $notGreen.Count "non-green findings ($(($notGreen | ForEach-Object { "$($_.Id)=$($_.Severity)" }) -join ', '))"
}
Test-Case 'missing GPO data marks GPO checks NotRun instead of green' {
    $copy = $lab | ConvertTo-Json -Depth 8 | ConvertFrom-Json
    $copy.GpoError = 'access denied'
    $gpo = @(Invoke-ADAuditChecks -Snapshot $copy | Where-Object Category -eq 'Group Policy')
    Assert-Equal 4 @($gpo | Where-Object Severity -eq 'NotRun').Count 'NotRun GPO checks'
}

Write-Host 'Report'
$results = New-ADAuditResult -Snapshot $lab -Findings $findings -InactiveDays 90 -MaxDomainAdmins 5
$json = $results | ConvertTo-Json -Depth 8
$html = ConvertTo-ADAuditHtml -Results ($json | ConvertFrom-Json)
Test-Case 'results JSON round-trips with totals' {
    $back = $json | ConvertFrom-Json
    Assert-Equal 29 @($back.Findings).Count 'findings after round trip'
    Assert-Equal 11 $back.Totals.Red 'red total'
}
Test-Case 'HTML is self-contained (no external resources)' {
    Assert-True ($html -notmatch '(src|href)\s*=\s*"https?:') 'external src/href found'
    Assert-True ($html -notmatch '@import|url\(') 'external CSS import found'
}
Test-Case 'HTML shows the lab badge and a recommended action for every red/amber finding' {
    Assert-True ($html -match 'LAB DATA') 'lab badge missing'
    $actionRows = ([regex]::Matches($html, '<td class="action">')).Count
    Assert-Equal ($results.Totals.Red + $results.Totals.Amber) $actionRows 'action plan rows'
}
Test-Case 'HTML encodes directory data' {
    $evil = $lab | ConvertTo-Json -Depth 8 | ConvertFrom-Json
    ($evil.Users | Where-Object SamAccountName -eq 'test.user').DisplayName = '<script>alert(1)</script>'
    $r = New-ADAuditResult -Snapshot $evil -Findings @(Invoke-ADAuditChecks -Snapshot $evil) -InactiveDays 90 -MaxDomainAdmins 5
    $h = ConvertTo-ADAuditHtml -Results $r
    Assert-True ($h -notmatch '<script>alert') 'raw script tag rendered'
    Assert-True ($h -match '&lt;script&gt;alert') 'encoded value missing'
}

Write-Host 'Safety'
Test-Case 'collector only uses read cmdlets' {
    $code = Get-Content (Join-Path $root 'src\Collect.ps1') -Raw
    $writes = [regex]::Matches($code, '\b(Set|New|Remove|Add|Enable|Disable|Move|Rename|Clear|Reset|Unlock|Restore)-AD\w+') | ForEach-Object Value
    Assert-Equal 0 @($writes).Count "write cmdlets in collector: $($writes -join ', ')"
}
Test-Case 'DN parsing handles escaped commas' {
    Assert-Equal 'Garcia, Ana' (Get-CnFromDn 'CN=Garcia\, Ana,OU=Users,DC=x,DC=lab') 'escaped CN'
    Assert-Equal 'Domain Admins' (Get-CnFromDn 'CN=Domain Admins,CN=Users,DC=x,DC=lab') 'plain CN'
}

Write-Host ''
Write-Host "$script:passed passed, $script:failed failed" -ForegroundColor $(if ($script:failed) { 'Red' } else { 'Green' })
exit $script:failed
