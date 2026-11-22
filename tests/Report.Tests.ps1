# HTML report structure and content.
$labSnap = Get-Content (Join-Path $root 'lab\lab-sample.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$labRes = New-ADAuditResult -Snapshot $labSnap -Findings @(Invoke-ADAuditChecks -Snapshot $labSnap) -InactiveDays 90 -MaxDomainAdmins 5
$labJson = $labRes | ConvertTo-Json -Depth 8
$html = ConvertTo-ADAuditHtml -Results ($labJson | ConvertFrom-Json)

Test-Case 'results JSON round-trips without truncation' {
    $back = $labJson | ConvertFrom-Json
    Assert-Equal 29 @($back.Findings).Count 'findings'
    Assert-Equal 11 $back.Totals.Red 'red total'
    Assert-True ($labJson -notmatch 'System\.Collections|System\.Object\[\]|"@\{') 'ConvertTo-Json depth truncation detected'
    Assert-Equal 18 @(($back.Findings | Where-Object Id -eq 'PRV-01').Items).Count 'items preserved'
}
Test-Case 'every finding has a section with its id as anchor' {
    foreach ($f in $labRes.Findings) { Assert-True ($html -match "<details id=""$($f.Id)""") "section $($f.Id)" }
    Assert-Equal 29 ([regex]::Matches($html, '<details ')).Count 'details count'
}
Test-Case 'action plan lists red before amber and links to each section' {
    $plan = $html.Substring(0, $html.IndexOf('<h2>All checks'))
    $rows = [regex]::Matches($plan, '<td class="sev (Red|Amber)">') | ForEach-Object { $_.Groups[1].Value }
    Assert-Equal 27 @($rows).Count 'rows'
    $firstAmber = [array]::IndexOf(@($rows), 'Amber')
    Assert-True (@($rows)[$firstAmber..(@($rows).Count - 1)] -notcontains 'Red') 'red after amber'
    Assert-True ($plan -match 'href="#ACC-03"') 'anchor link'
}
Test-Case 'red sections are open by default, others closed' {
    Assert-Equal 11 ([regex]::Matches($html, '<details id="[^"]+" class="Red" open>')).Count 'open red'
    Assert-Equal 0 ([regex]::Matches($html, '<details id="[^"]+" class="(Amber|Green)" open>')).Count 'open others'
}
Test-Case 'green checks show no recommended-action box' {
    $acc08 = [regex]::Match($html, '<details id="ACC-08".*?</details>', 'Singleline').Value
    Assert-True ($acc08 -notmatch 'Recommended action') 'green ACC-08 has a recommendation box'
}
Test-Case 'tags are balanced' {
    foreach ($tag in 'details', 'table', 'tr', 'div', 'summary', 'script', 'svg') {
        $open = ([regex]::Matches($html, "<$tag[\s>]")).Count; $close = ([regex]::Matches($html, "</$tag>")).Count
        Assert-Equal $open $close "<$tag> open/close"
    }
}
Test-Case 'header shows domain, lab badge, score and counts' {
    Assert-True ($html -match 'demo-corp\.lab \(DEMOCORP\)') 'domain'
    Assert-True ($html -match 'LAB DATA') 'lab badge'
    Assert-True ($html -match '>34</text>') 'score'
    Assert-True ($html -match '<div class="n">11</div><div class="l">Red') 'red card'
}
Test-Case 'live results show the live badge instead of the lab one' {
    $live = $labJson | ConvertFrom-Json; $live.Source = 'ActiveDirectory'
    $h = ConvertTo-ADAuditHtml -Results $live
    Assert-True ($h -match 'LIVE DOMAIN' -and $h -notmatch 'LAB DATA') 'badge'
}
Test-Case 'long tables are truncated with a note' {
    $h = ConvertTo-ADAuditHtml -Results ($labJson | ConvertFrom-Json) -MaxRowsPerFinding 2
    Assert-True ($h -match 'Showing 2 of 18 rows') 'truncation note'
}
Test-Case 'NotRun card and collection warnings appear only when needed' {
    Assert-True ($html -notmatch 'Collection warnings') 'no warnings section for the lab'
    $snap = Copy-Deep $labSnap; $snap.GpoError = 'access denied'
    $r = New-ADAuditResult -Snapshot $snap -Findings @(Invoke-ADAuditChecks -Snapshot $snap) -InactiveDays 90 -MaxDomainAdmins 5
    $h = ConvertTo-ADAuditHtml -Results $r
    Assert-True ($h -match 'Collection warnings' -and $h -match 'access denied') 'warnings section'
    Assert-True ($h -match '<div class="n">4</div><div class="l">Not run') 'NotRun card'
}
Test-Case 'report supports dark mode and print' {
    Assert-True ($html -match 'prefers-color-scheme:dark') 'dark mode'
    Assert-True ($html -match '@media print') 'print styles'
    Assert-True ($html -match 'beforeprint') 'expand on print'
}
Test-Case 'converter script writes UTF-8 without BOM next to the JSON' {
    $json = Join-Path $TempRoot 'ad-audit-X-20260101-0000-results.json'
    $labJson | Set-Content -LiteralPath $json -Encoding UTF8
    & (Join-Path $root 'ConvertTo-ADAuditReport.ps1') -InputPath $json
    $out = Join-Path $TempRoot 'ad-audit-X-20260101-0000-report.html'
    Assert-True (Test-Path $out) 'default output path'
    $bytes = [IO.File]::ReadAllBytes($out)
    Assert-True (-not ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB)) 'BOM present'
    Assert-True ([Text.Encoding]::UTF8.GetString($bytes) -match '<meta charset="utf-8">') 'charset meta'
}
Test-Case 'non-ASCII directory data survives to the HTML' {
    $snap = Copy-Deep $labSnap
    $n = [char]0x00F1   # n with tilde; built from its code so this file stays ASCII for Windows PowerShell 5.1
    $name = "Mu${n}oz Pe${n}a, Bego${n}a"
    ($snap.Users | Where-Object SamAccountName -eq 'test.user').DisplayName = $name
    $r = New-ADAuditResult -Snapshot $snap -Findings @(Invoke-ADAuditChecks -Snapshot $snap) -InactiveDays 90 -MaxDomainAdmins 5
    $json = Join-Path $TempRoot 'utf8-results.json'
    $r | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $json -Encoding UTF8
    $out = Join-Path $TempRoot 'utf8-report.html'
    & (Join-Path $root 'ConvertTo-ADAuditReport.ps1') -InputPath $json -OutputPath $out
    $text = [IO.File]::ReadAllText($out, [Text.Encoding]::UTF8)
    Assert-True ($text.Contains($name) -or $text.Contains('Mu&#241;oz Pe&#241;a, Bego&#241;a')) 'accented name lost'
}
