<#
.SYNOPSIS
    Converts an audit results JSON into a single self-contained HTML report.

.DESCRIPTION
    Presentation only: reads the JSON produced by Invoke-ADSecurityAudit.ps1 and writes HTML.
    It never touches Active Directory, so it runs on any machine.

.PARAMETER InputPath
    Results JSON written by Invoke-ADSecurityAudit.ps1 (the *-results.json file).

.PARAMETER OutputPath
    HTML file to write. Default: next to the input, with -results.json replaced by -report.html.

.EXAMPLE
    .\ConvertTo-ADAuditReport.ps1 -InputPath .\reports\ad-audit-DEMOCORP-20261120-1000-results.json
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$InputPath,
    [string]$OutputPath = ([IO.Path]::ChangeExtension($InputPath, $null).TrimEnd('.') -replace '-results$', '') + '-report.html'
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'src\Common.ps1')
. (Join-Path $PSScriptRoot 'src\Report.ps1')

$results = Get-Content -LiteralPath $InputPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($results.SchemaVersion -ne 1 -or -not $results.Findings) { throw "$InputPath is not an AD-Security-Audit results file." }
$html = ConvertTo-ADAuditHtml -Results $results
[IO.File]::WriteAllText([IO.Path]::GetFullPath($OutputPath), $html, (New-Object Text.UTF8Encoding $false))
Write-Verbose "Report written to $OutputPath"
