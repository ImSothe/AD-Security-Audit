#Requires -Version 5.1
# Regenerates lab\lab-sample.json (the fictional Demo Corp domain) and the sample report in docs\.
# Run it after changing src\Lab.ps1 or the report layout.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
foreach ($file in 'Common', 'Lab') { . (Join-Path $root "src\$file.ps1") }

$snapshot = New-ADAuditLabSnapshot
$snapshot | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $root 'lab\lab-sample.json') -Encoding UTF8

$out = Join-Path $env:TEMP 'ad-audit-lab'
& (Join-Path $root 'Invoke-ADSecurityAudit.ps1') -Lab -OutputDirectory $out | Out-Null
$report = Get-ChildItem $out -Filter '*-report.html' | Sort-Object LastWriteTime | Select-Object -Last 1
Copy-Item $report.FullName (Join-Path $root 'docs\sample-report.html') -Force
Write-Host 'Updated lab\lab-sample.json and docs\sample-report.html'
