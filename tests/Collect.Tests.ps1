# Collector tests against the fake ActiveDirectory module in AdMock.ps1.
if (-not (Get-Command Invoke-MockCollect -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'AdMock.ps1') }

$snap = Invoke-MockCollect
$jdoe = $snap.Users | Where-Object SamAccountName -eq 'jdoe'

Test-Case 'collector: only Get-* cmdlets were called' {
    Assert-True ($script:AdCalls.Count -gt 10) "only $($script:AdCalls.Count) AD calls recorded"
    $bad = @($script:AdCalls | Where-Object { $_.Name -notlike 'Get-*' })
    Assert-Equal 0 $bad.Count "non-read calls: $($bad.Name -join ', ')"
}
Test-Case 'collector: users mapped with ISO dates and plain values' {
    Assert-Equal 'Doe, John' $jdoe.DisplayName 'display name'
    Assert-Equal "$script:MockSid-1105" $jdoe.Sid 'SID as string'
    Assert-True ($jdoe.LastLogonDate -is [string] -and $jdoe.LastLogonDate -match 'Z$') "LastLogonDate '$($jdoe.LastLogonDate)' not ISO UTC"
    Assert-Equal 0 $jdoe.AdminCount 'null adminCount becomes 0'
    Assert-Equal 'HTTP/app.mock.lab' (@($jdoe.ServicePrincipalNames)[0]) 'SPN'
    Assert-Equal $null $jdoe.AccountExpires 'no expiry'
}
Test-Case 'collector: memberOf DNs become group names, escaped commas kept' {
    Assert-Equal 'Ventas, Madrid' $jdoe.MemberOf[0] 'escaped CN'
    Assert-Equal 'Admins. del dominio' $jdoe.MemberOf[1] 'localized group'
}
Test-Case 'collector: domain controllers detected by primary group (DC and RODC), RBCD detected' {
    Assert-True ($snap.Computers | Where-Object Name -eq 'DC1').IsDomainController 'DC1'
    Assert-True ($snap.Computers | Where-Object Name -eq 'RODC1').IsDomainController 'RODC1'
    Assert-True (-not ($snap.Computers | Where-Object Name -eq 'WS1').IsDomainController) 'WS1 is not a DC'
    Assert-True ($snap.Computers | Where-Object Name -eq 'WS1').HasRbcd 'WS1 RBCD'
    Assert-True (-not ($snap.Computers | Where-Object Name -eq 'DC1').HasRbcd) 'DC1 no RBCD'
}
Test-Case 'collector: domain, policy and recycle bin' {
    Assert-Equal 'MOCK' $snap.Domain.NetBIOSName 'NetBIOS'
    Assert-Equal 42 $snap.Domain.PasswordPolicy.MaxPasswordAgeDays 'max age days'
    Assert-True $snap.Domain.RecycleBinEnabled 'recycle bin'
    Assert-Equal 1 $snap.SchemaVersion 'schema'
}
Test-Case 'collector: privileged groups looked up by SID, localized names kept' {
    $da = $snap.PrivilegedGroups | Where-Object Key -eq 'DomainAdmins'
    Assert-Equal "$script:MockSid-512" $da.Sid 'DA SID'
    Assert-Equal 'Admins. del dominio' $da.Name 'localized name'
    Assert-Equal 2 @($da.Members).Count 'members (user + computer)'
    $calls = @($script:AdCalls | Where-Object Name -eq 'Get-ADGroupMember')
    Assert-True (@($calls | Where-Object { -not $_.Params.Recursive }).Count -eq 0) 'every member query is recursive'
    Assert-True (@($script:AdCalls | Where-Object { $_.Name -eq 'Get-ADGroup' -and $_.Params.Identity -notmatch '^S-1-' }).Count -eq 0) 'groups queried by name'
}
Test-Case 'collector: a missing group is recorded, not fatal' {
    $ka = $snap.PrivilegedGroups | Where-Object Key -eq 'KeyAdmins'
    Assert-True ([bool]$ka.Error) 'KeyAdmins error recorded'
    Assert-Equal 11 @($snap.PrivilegedGroups).Count 'all groups present'
}
Test-Case 'collector: a failing member query only affects that group' {
    $script:FailGroupMember = @('512')
    try { $s2 = Invoke-MockCollect } finally { $script:FailGroupMember = @() }
    Assert-True ([bool]($s2.PrivilegedGroups | Where-Object Key -eq 'DomainAdmins').Error) 'DA error'
    $f = Invoke-ADAuditChecks -Snapshot $s2 | Where-Object Id -eq 'PRV-01'
    Assert-Equal 'NotRun' $f.Severity 'PRV-01 must be NotRun, not green'
}
Test-Case 'collector: GPO links parsed (enabled, disabled, case-insensitive) and versions decoded' {
    $linked = $snap.Gpos | Where-Object Id -eq $gpoLinked
    Assert-Equal 2 $linked.EnabledLinks 'enabled links (upper + lower case)'
    Assert-Equal 3 $linked.UserVersion 'user version'; Assert-Equal 7 $linked.ComputerVersion 'computer version'
    Assert-True $linked.SysvolPresent 'SYSVOL folder present'
    $nf = $snap.Gpos | Where-Object Id -eq $gpoNoFolder
    Assert-Equal 0 $nf.EnabledLinks 'no enabled link'; Assert-Equal 1 $nf.DisabledLinks 'disabled link'
    Assert-True (-not $nf.SysvolPresent) 'missing folder detected'
    Assert-Equal 3 $nf.Flags 'flags'
}
Test-Case 'collector: SYSVOL folders without an AD object are orphans; PolicyDefinitions ignored' {
    Assert-Equal 1 @($snap.SysvolOrphans).Count 'orphans'
    Assert-Equal $gpoOrphanFolder $snap.SysvolOrphans[0] 'orphan id'
}
Test-Case 'collector: unreadable site links do not stop GPO collection; readable ones count' {
    Assert-Equal $null $snap.GpoError 'GpoError'
    $script:FailSites = $false
    try { $s3 = Invoke-MockCollect } finally { $script:FailSites = $true }
    Assert-Equal 3 ($s3.Gpos | Where-Object Id -eq $gpoLinked).EnabledLinks 'site link counted'
}
Test-Case 'collector: -Server and -Credential reach every AD call' {
    $cred = New-Object pscredential 'MOCK\auditor', (ConvertTo-SecureString 'Not-A-Real-Pass-1!' -AsPlainText -Force)
    $null = Invoke-MockCollect @{ Server = 'dc9.mock.lab'; Credential = $cred }
    $missing = @($script:AdCalls | Where-Object { -not $_.Params.Server -or -not $_.Params.Credential })
    Assert-Equal 0 $missing.Count "calls without server/credential: $(($missing.Name | Select-Object -Unique) -join ', ')"
}
Test-Case 'collector: Enterprise/Schema Admins are read from the forest root domain' {
    $script:MockRoot = 'root.lab'
    try { $s4 = Invoke-MockCollect } finally { $script:MockRoot = 'mock.lab' }
    Assert-Equal "$script:MockRootSid-519" ($s4.PrivilegedGroups | Where-Object Key -eq 'EnterpriseAdmins').Sid 'EA SID'
    Assert-Equal "$script:MockRootSid-518" ($s4.PrivilegedGroups | Where-Object Key -eq 'SchemaAdmins').Sid 'SA SID'
    Assert-Equal "$script:MockSid-512" ($s4.PrivilegedGroups | Where-Object Key -eq 'DomainAdmins').Sid 'DA stays in the domain'
    $eaCall = $script:AdCalls | Where-Object { $_.Name -eq 'Get-ADGroupMember' -and $_.Params.Identity -eq "$script:MockRootSid-519" }
    Assert-Equal 'root.lab' $eaCall.Params.Server 'EA queried on the root domain'
}
Test-Case 'collector: snapshot survives a JSON round trip and feeds the checks' {
    $back = $snap | ConvertTo-Json -Depth 8 | ConvertFrom-Json
    $f = @(Invoke-ADAuditChecks -Snapshot $back)
    Assert-Equal 29 $f.Count 'findings'
    Assert-Equal 0 @($f | Where-Object Category -eq 'Engine').Count 'engine errors'
    Assert-Equal 'Red' ($f | Where-Object Id -eq 'GPO-04').Severity 'orphaned GPO found'
}
Test-Case 'collector: without the AD module it fails with a clear message' {
    if (Get-Module -ListAvailable -Name ActiveDirectory) { return }   # cannot simulate on a machine with RSAT
    $saved = Get-Item function:Get-ADUser
    Remove-Item function:Get-ADUser
    try { Assert-Throws { Get-ADAuditSnapshot } -Like '*RSAT*' -What 'collect without RSAT' }
    finally { Set-Item function:script:Get-ADUser -Value $saved.ScriptBlock }
}
