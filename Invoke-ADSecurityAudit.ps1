<#
.SYNOPSIS
    Read-only security and hygiene audit of an Active Directory domain, with an executive HTML report.

.DESCRIPTION
    Three stages, each one replaceable:
      1. Collect  - reads users, computers, privileged groups, GPOs and domain policy (Get-* cmdlets only),
                    or loads the fictional lab domain (-Lab), or a snapshot saved earlier (-SnapshotPath).
      2. Analyse  - runs every check against that snapshot and writes the findings to a results JSON.
      3. Report   - ConvertTo-ADAuditReport.ps1 turns the results JSON into one self-contained HTML file.

    Nothing in this script writes to Active Directory, SYSVOL or any computer.

.PARAMETER Lab
    Use the fictional "Demo Corp" domain in lab\lab-sample.json instead of a real domain. No AD needed.

.PARAMETER SnapshotPath
    Analyse a snapshot JSON saved earlier with -ExportSnapshot (for example collected on a DC, analysed on a laptop).

.PARAMETER Server
    Domain controller or domain to query. Default: the domain of the current computer.

.PARAMETER Credential
    Account used to read AD. Any authenticated domain user can read almost everything audited here.

.PARAMETER InactiveDays
    Days without logon before a user or computer counts as inactive. Default 90.

.PARAMETER MaxDomainAdmins
    Domain Admins members considered acceptable. Above it the check turns amber, above twice it red. Default 5.

.PARAMETER OutputDirectory
    Folder for the results JSON and the HTML report. Default: .\reports

.PARAMETER ExportSnapshot
    Also save the raw snapshot JSON. It contains account names and group memberships: treat it as confidential.

.PARAMETER PassThru
    Also return the results object to the pipeline.

.EXAMPLE
    .\Invoke-ADSecurityAudit.ps1 -Lab
    Builds the sample report from the fictional domain.

.EXAMPLE
    .\Invoke-ADSecurityAudit.ps1 -InactiveDays 60 -OutputDirectory C:\Audits
    Audits the current domain with a 60-day inactivity threshold.
#>
#Requires -Version 5.1
[CmdletBinding(DefaultParameterSetName = 'Live')]
param(
    [Parameter(ParameterSetName = 'Lab', Mandatory)][switch]$Lab,
    [Parameter(ParameterSetName = 'Snapshot', Mandatory)][string]$SnapshotPath,
    [Parameter(ParameterSetName = 'Live')][string]$Server,
    [Parameter(ParameterSetName = 'Live')][pscredential]$Credential,
    [Parameter(ParameterSetName = 'Live')][switch]$ExportSnapshot,
    [ValidateRange(1, 3650)][int]$InactiveDays = 90,
    [ValidateRange(1, 100)][int]$MaxDomainAdmins = 5,
    [string]$OutputDirectory = (Join-Path (Get-Location) 'reports'),
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'
$ToolVersion = '1.0.0'
foreach ($file in 'Common', 'Collect', 'Lab', 'Checks', 'Report') { . (Join-Path $PSScriptRoot "src\$file.ps1") }

# 1. Collect
switch ($PSCmdlet.ParameterSetName) {
    'Lab' {
        $SnapshotPath = Join-Path $PSScriptRoot 'lab\lab-sample.json'
        Write-Host 'Lab mode: fictional domain demo-corp.lab, no Active Directory needed.' -ForegroundColor Yellow
        $snapshot = Get-Content -LiteralPath $SnapshotPath -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    'Snapshot' {
        $snapshot = Get-Content -LiteralPath $SnapshotPath -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    'Live' {
        $params = @{}
        if ($Server) { $params.Server = $Server }
        if ($Credential) { $params.Credential = $Credential }
        Write-Host 'Reading Active Directory (read-only)...' -ForegroundColor Cyan
        $snapshot = Get-ADAuditSnapshot @params
    }
}
if ($snapshot.SchemaVersion -ne 1) { throw "Unsupported snapshot schema version: $($snapshot.SchemaVersion)" }

if (-not (Test-Path -LiteralPath $OutputDirectory)) { New-Item -ItemType Directory -Path $OutputDirectory | Out-Null }
$stamp = (ConvertFrom-AuditDateString $snapshot.CollectedAt).ToLocalTime().ToString('yyyyMMdd-HHmm')
$base = Join-Path $OutputDirectory "ad-audit-$(Get-SafeFileNamePart $snapshot.Domain.NetBIOSName)-$stamp"

if ($ExportSnapshot) {
    $snapshot | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath "$base-snapshot.json" -Encoding UTF8
    Write-Host "Snapshot saved:  $base-snapshot.json (confidential)"
}

# 2. Analyse
$findings = @(Invoke-ADAuditChecks -Snapshot $snapshot -InactiveDays $InactiveDays -MaxDomainAdmins $MaxDomainAdmins)
$results = New-ADAuditResult -Snapshot $snapshot -Findings $findings -InactiveDays $InactiveDays `
    -MaxDomainAdmins $MaxDomainAdmins -ToolVersion $ToolVersion
$jsonPath = "$base-results.json"
$results | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

# 3. Report
$htmlPath = "$base-report.html"
& (Join-Path $PSScriptRoot 'ConvertTo-ADAuditReport.ps1') -InputPath $jsonPath -OutputPath $htmlPath

$t = $results.Totals
Write-Host ''
Write-Host "Domain $($results.Domain.DnsRoot): score $($results.Score)/100" -ForegroundColor Cyan
Write-Host ("  Red {0}   Amber {1}   Green {2}{3}" -f $t.Red, $t.Amber, $t.Green, $(if ($t.NotRun) { "   Not run $($t.NotRun)" } else { '' }))
Write-Host "  Results JSON: $jsonPath"
Write-Host "  HTML report:  $htmlPath"
if ($PassThru) { $results }
