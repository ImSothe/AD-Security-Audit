#Requires -Version 5.1
<#
.SYNOPSIS
    Dependency-free test runner (Windows PowerShell 5.1 and PowerShell 7, no Pester needed).
.DESCRIPTION
    Loads the source files once, then dot-sources every tests\*.Tests.ps1 in this scope so the
    test files share the helpers below. Exit code = number of failed tests.
.EXAMPLE
    .\tests\Run-Tests.ps1                 # everything
    .\tests\Run-Tests.ps1 -Filter Security
#>
param([string]$Filter = '*')

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
foreach ($file in 'Common', 'Collect', 'Lab', 'Checks', 'Report') { . (Join-Path $root "src\$file.ps1") }

# ------------------------------------------------------------------ harness
$script:passed = 0; $script:failed = 0; $script:failures = New-Object System.Collections.Generic.List[string]
function Test-Case {
    param([string]$Name, [scriptblock]$Body)
    try { & $Body; $script:passed++; Write-Host "  [PASS] $Name" -ForegroundColor Green }
    catch {
        $script:failed++; $script:failures.Add("$script:currentFile :: $Name")
        Write-Host "  [FAIL] $Name`n         $($_.Exception.Message)" -ForegroundColor Red
    }
}
function Assert-Equal { param($Expected, $Actual, [string]$What = 'value')
    if ($Expected -ne $Actual) { throw "$What : expected '$Expected', got '$Actual'" } }
function Assert-True { param([bool]$Condition, [string]$Message) if (-not $Condition) { throw $Message } }
function Assert-Throws {
    param([scriptblock]$Body, [string]$Like = '*', [string]$What = 'call')
    try { & $Body } catch {
        if ($_.Exception.Message -notlike $Like) { throw "$What threw '$($_.Exception.Message)', expected like '$Like'" }
        return
    }
    throw "$What did not throw"
}

# ------------------------------------------------------------------ fixtures
$ref = [datetime]::SpecifyKind([datetime]'2026-11-20T09:00:00', 'Utc')
$TestDomainSid = 'S-1-5-21-9-8-7'
$script:nextRid = 2000
$TempRoot = Join-Path ([IO.Path]::GetTempPath()) ("adsa-tests-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $TempRoot | Out-Null

function Ago { param($Days) if ($null -eq $Days) { return $null } $ref.AddDays(-[double]$Days).ToString('o') }

function New-TestUser {
    param([string]$Sam, [hashtable]$Set = @{})
    $script:nextRid++
    $o = [ordered]@{
        SamAccountName = $Sam; DisplayName = $Sam; Enabled = $true; Sid = "$TestDomainSid-$script:nextRid"
        LastLogonDate = Ago 1; WhenCreated = Ago 400; PasswordLastSet = Ago 10
        PasswordNeverExpires = $false; PasswordNotRequired = $false; DoesNotRequirePreAuth = $false
        ReversibleEncryption = $false; TrustedForDelegation = $false; TrustedToAuthForDelegation = $false
        DelegatesTo = @(); AccountNotDelegated = $false; ServicePrincipalNames = @(); AdminCount = 0
        LockedOut = $false; AccountExpires = $null; MemberOf = @(); DistinguishedName = "CN=$Sam,DC=test,DC=lab"
    }
    foreach ($k in $Set.Keys) { $o[$k] = $Set[$k] }
    [pscustomobject]$o
}

function New-TestComputer {
    param([string]$Name, [hashtable]$Set = @{})
    $o = [ordered]@{
        Name = $Name; Enabled = $true; OperatingSystem = 'Windows Server 2022 Standard'; OperatingSystemVersion = '10.0 (20348)'
        LastLogonDate = Ago 1; WhenCreated = Ago 400; IsDomainController = $false
        TrustedForDelegation = $false; TrustedToAuthForDelegation = $false; DelegatesTo = @(); HasRbcd = $false
        DistinguishedName = "CN=$Name,DC=test,DC=lab"
    }
    foreach ($k in $Set.Keys) { $o[$k] = $Set[$k] }
    [pscustomobject]$o
}

function New-TestGpo {
    param([string]$Name, [hashtable]$Set = @{})
    $o = [ordered]@{ Id = '{' + [guid]::NewGuid().ToString().ToUpperInvariant() + '}'; DisplayName = $Name; Flags = 0
        UserVersion = 1; ComputerVersion = 1; EnabledLinks = 1; DisabledLinks = 0; WhenChanged = Ago 30; SysvolPresent = $true }
    foreach ($k in $Set.Keys) { $o[$k] = $Set[$k] }
    [pscustomobject]$o
}

# A domain with no findings. Tests add exactly the weakness they want to see.
function New-TestSnapshot {
    param([object[]]$Users = @(), [object[]]$Computers = @(), [object[]]$Gpos = $null, [hashtable]$Members = @{})
    $admin = New-TestUser 'Administrator' @{ Sid = "$TestDomainSid-500"; AccountNotDelegated = $true; AdminCount = 1 }
    $guest = New-TestUser 'Guest' @{ Sid = "$TestDomainSid-501"; Enabled = $false; LastLogonDate = $null }
    $krbtgt = New-TestUser 'krbtgt' @{ Sid = "$TestDomainSid-502"; Enabled = $false; LastLogonDate = $null; AdminCount = 1 }
    $allUsers = @($admin, $guest, $krbtgt) + @($Users)
    $bySam = @{}; foreach ($u in $allUsers) { $bySam[$u.SamAccountName] = $u }
    $defs = [ordered]@{ DomainAdmins = 512; EnterpriseAdmins = 519; SchemaAdmins = 518; Administrators = 'S-1-5-32-544'
        AccountOperators = 'S-1-5-32-548'; ServerOperators = 'S-1-5-32-549'; PrintOperators = 'S-1-5-32-550'
        BackupOperators = 'S-1-5-32-551'; GroupPolicyCreatorOwners = 520; KeyAdmins = 526; EnterpriseKeyAdmins = 527 }
    $groups = foreach ($key in $defs.Keys) {
        $names = if ($Members.ContainsKey($key)) { $Members[$key] }
                 elseif ($key -in 'DomainAdmins', 'Administrators') { @('Administrator') } else { @() }
        $sid = if ($defs[$key] -is [int]) { "$TestDomainSid-$($defs[$key])" } else { $defs[$key] }
        [pscustomobject]@{ Key = $key; Name = $key; Sid = $sid; Error = $null
            Members = @($names | ForEach-Object { [pscustomobject]@{ SamAccountName = $_; ObjectClass = 'user'; Sid = $bySam[$_].Sid } }) }
    }
    if ($null -eq $Gpos) { $Gpos = @(New-TestGpo 'Default Domain Policy') }
    $dc = New-TestComputer 'DC01' @{ IsDomainController = $true; TrustedForDelegation = $true }
    [pscustomobject]@{
        SchemaVersion = 1; Source = 'Test'; CollectedAt = $ref.ToString('o')
        Domain = [pscustomobject]@{ DnsRoot = 'test.lab'; NetBIOSName = 'TEST'; DomainSid = $TestDomainSid
            DomainMode = 'Windows2016Domain'; ForestMode = 'Windows2016Forest'; ForestRoot = 'test.lab'; RecycleBinEnabled = $true
            PasswordPolicy = [pscustomobject]@{ MinPasswordLength = 14; MaxPasswordAgeDays = 365; LockoutThreshold = 10
                ComplexityEnabled = $true; PasswordHistoryCount = 24; ReversibleEncryptionEnabled = $false } }
        Users = $allUsers; Computers = @($dc) + @($Computers); PrivilegedGroups = @($groups)
        Gpos = @($Gpos); SysvolOrphans = @(); GpoError = $null; Errors = @()
    }
}

# Runs one check against a snapshot with explicit thresholds.
function Invoke-Check {
    param([string]$Name, $Snapshot, [int]$InactiveDays = 90, [int]$MaxDomainAdmins = 5)
    $ctx = New-AuditContext -Snapshot $Snapshot -InactiveDays $InactiveDays -MaxDomainAdmins $MaxDomainAdmins -ReferenceDate $ref
    & $Name $ctx
}

function Copy-Deep { param($Object) $Object | ConvertTo-Json -Depth 10 | ConvertFrom-Json }

# ------------------------------------------------------------------ run
$testFiles = Get-ChildItem -Path $PSScriptRoot -Filter '*.Tests.ps1' | Where-Object { $_.BaseName -like "$Filter*" } | Sort-Object Name
try {
    foreach ($tf in $testFiles) {
        $script:currentFile = $tf.BaseName
        Write-Host ''
        Write-Host $tf.BaseName -ForegroundColor Cyan
        . $tf.FullName
    }
} finally {
    Remove-Item -LiteralPath $TempRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ''
if ($script:failed) { Write-Host 'Failed:' -ForegroundColor Red; $script:failures | ForEach-Object { Write-Host "  $_" -ForegroundColor Red } }
Write-Host "$script:passed passed, $script:failed failed" -ForegroundColor $(if ($script:failed) { 'Red' } else { 'Green' })
exit $script:failed
