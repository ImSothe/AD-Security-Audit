# End-to-end tests of the command-line scripts.
$audit = Join-Path $root 'Invoke-ADSecurityAudit.ps1'

Test-Case 'CLI: -Lab writes results JSON and HTML, and -PassThru returns the results' {
    $out = Join-Path $TempRoot 'cli-lab'
    $r = & $audit -Lab -OutputDirectory $out -PassThru 6>$null
    $files = @(Get-ChildItem $out -File | Sort-Object Name)
    Assert-Equal 2 $files.Count 'files'
    Assert-True ($files[0].Name -eq 'ad-audit-DEMOCORP-20261120-1000-report.html' -or $files[0].Name -like 'ad-audit-DEMOCORP-*-report.html') "name $($files[0].Name)"
    Assert-True ($files[1].Name -like 'ad-audit-DEMOCORP-*-results.json') "name $($files[1].Name)"
    Assert-Equal 34 $r.Score 'score'
    Assert-Equal 'Lab' $r.Source 'source'
}
Test-Case 'CLI: output folder is created when missing' {
    $out = Join-Path $TempRoot 'cli-new\nested\folder'
    & $audit -Lab -OutputDirectory $out 6>$null | Out-Null
    Assert-True (Test-Path $out) 'folder created'
}
Test-Case 'CLI: thresholds are passed through to the results' {
    $r = & $audit -Lab -OutputDirectory (Join-Path $TempRoot 'cli-th') -InactiveDays 30 -MaxDomainAdmins 20 -PassThru 6>$null
    Assert-Equal 30 $r.Parameters.InactiveDays 'InactiveDays'
    Assert-Equal 'Green' ($r.Findings | Where-Object Id -eq 'PRV-01').Severity 'PRV-01 with 20 allowed'
    Assert-True (($r.Findings | Where-Object Id -eq 'ACC-01').Count -gt 5) 'more inactive users at 30 days'
}
Test-Case 'CLI: invalid thresholds are rejected' {
    Assert-Throws { & $audit -Lab -InactiveDays 0 -OutputDirectory $TempRoot 6>$null } -What 'InactiveDays 0'
    Assert-Throws { & $audit -Lab -MaxDomainAdmins 500 -OutputDirectory $TempRoot 6>$null } -What 'MaxDomainAdmins 500'
}
Test-Case 'CLI: -Lab and -SnapshotPath cannot be combined; snapshot mode needs an existing file' {
    Assert-Throws { & $audit -Lab -SnapshotPath 'x.json' 6>$null } -What 'both modes'
    Assert-Throws { & $audit -SnapshotPath (Join-Path $TempRoot 'missing.json') -OutputDirectory $TempRoot 6>$null } -What 'missing file'
}
Test-Case 'CLI: -SnapshotPath gives the same findings as -Lab for the same data' {
    $a = & $audit -Lab -OutputDirectory (Join-Path $TempRoot 'cli-a') -PassThru 6>$null
    $b = & $audit -SnapshotPath (Join-Path $root 'lab\lab-sample.json') -OutputDirectory (Join-Path $TempRoot 'cli-b') -PassThru 6>$null
    Assert-True (($a.Findings | ConvertTo-Json -Depth 6 -Compress) -eq ($b.Findings | ConvertTo-Json -Depth 6 -Compress)) 'findings differ'
}
Test-Case 'CLI: help is complete for both scripts' {
    $h = Get-Help $audit -Full
    Assert-True ([bool]$h.Synopsis -and $h.Synopsis -notlike '*Invoke-ADSecurityAudit.ps1*') 'synopsis'
    foreach ($p in 'Lab', 'SnapshotPath', 'Server', 'Credential', 'InactiveDays', 'MaxDomainAdmins', 'OutputDirectory', 'ExportSnapshot', 'PassThru') {
        $param = $h.parameters.parameter | Where-Object name -eq $p
        Assert-True ([bool]($param.description | Out-String).Trim()) "no help for -$p"
    }
    Assert-True (@($h.examples.example).Count -ge 2) 'examples'
    $c = Get-Help (Join-Path $root 'ConvertTo-ADAuditReport.ps1') -Full
    Assert-True ($c.Synopsis -notlike '*ConvertTo-ADAuditReport.ps1*') 'converter synopsis'
    foreach ($p in 'InputPath', 'OutputPath') {
        Assert-True ([bool](($c.parameters.parameter | Where-Object name -eq $p).description | Out-String).Trim()) "no help for -$p"
    }
}
Test-Case 'CLI: scripts parse cleanly' {
    foreach ($f in Get-ChildItem $root -Recurse -Include '*.ps1') {
        $errs = $null
        [void][Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$errs)
        Assert-Equal 0 @($errs).Count "$($f.Name) parse errors"
    }
}
Test-Case 'CLI: source files are ASCII so Windows PowerShell 5.1 reads them correctly' {
    foreach ($f in Get-ChildItem (Join-Path $root 'src'), (Join-Path $root 'tests'), (Join-Path $root 'tools'), $root -Filter '*.ps1') {
        $bad = [regex]::Matches([IO.File]::ReadAllText($f.FullName), '[^\x00-\x7F]')
        Assert-Equal 0 $bad.Count "$($f.Name) has non-ASCII characters"
    }
}
