#Requires -Version 5.1
# Turns an audit results object (the JSON written by Invoke-ADSecurityAudit.ps1) into one
# self-contained HTML file: inline CSS, no external fonts, scripts or images, so it can be
# emailed or opened offline. This file never reads Active Directory.

$script:ReportCss = @'
:root{--bg:#f5f6f8;--card:#fff;--text:#1c2430;--muted:#5d6878;--line:#e2e6ec;--red:#c62828;--red-bg:#fdecec;
--amber:#b26a00;--amber-bg:#fff4df;--green:#2e7d32;--green-bg:#e8f5e9;--grey:#6b7280;--grey-bg:#eef0f3;--accent:#1f4e8c}
@media (prefers-color-scheme:dark){:root{--bg:#12161c;--card:#1b2129;--text:#e6e9ee;--muted:#9aa4b2;--line:#2c3440;
--red:#ff6b6b;--red-bg:#3a1f22;--amber:#ffb547;--amber-bg:#3a2e17;--green:#5fd37a;--green-bg:#183324;--grey:#9aa4b2;--grey-bg:#262d37;--accent:#7fb0ff}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 "Segoe UI",system-ui,-apple-system,sans-serif}
.wrap{max-width:1180px;margin:0 auto;padding:32px 20px 48px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;margin:36px 0 12px}
.muted{color:var(--muted)}.small{font-size:13px}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:600;letter-spacing:.03em}
.badge.lab{background:var(--amber-bg);color:var(--amber);border:1px solid var(--amber)}
.badge.live{background:var(--green-bg);color:var(--green);border:1px solid var(--green)}
.head{display:flex;justify-content:space-between;gap:24px;flex-wrap:wrap;align-items:flex-start}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:24px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px}
.card .n{font-size:30px;font-weight:700;line-height:1.1}.card .l{color:var(--muted);font-size:13px}
.card.red .n{color:var(--red)}.card.amber .n{color:var(--amber)}.card.green .n{color:var(--green)}.card.grey .n{color:var(--grey)}
.score{display:flex;align-items:center;gap:16px}
.score svg{width:96px;height:96px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);background:var(--grey-bg)}
tr:last-child td{border-bottom:0}
.dot{display:inline-block;width:12px;height:12px;border-radius:50%;margin-right:8px;vertical-align:-1px}
.dot.Red{background:var(--red)}.dot.Amber{background:var(--amber)}.dot.Green{background:var(--green)}.dot.NotRun{background:var(--grey)}
.sev{font-weight:600;white-space:nowrap}.sev.Red{color:var(--red)}.sev.Amber{color:var(--amber)}.sev.Green{color:var(--green)}.sev.NotRun{color:var(--grey)}
.id{font-family:Consolas,monospace;font-size:13px;color:var(--muted);white-space:nowrap}
a{color:var(--accent)}
h3{font-size:15px;margin:22px 0 6px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
.action{max-width:520px}
details{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--grey);border-radius:10px;margin:10px 0}
details.Red{border-left-color:var(--red)}details.Amber{border-left-color:var(--amber)}details.Green{border-left-color:var(--green)}
summary{cursor:pointer;padding:12px 16px;display:flex;gap:10px;align-items:center;list-style:none}
summary::-webkit-details-marker{display:none}
summary .t{flex:1;font-weight:600}summary .c{color:var(--muted);font-size:13px;white-space:nowrap}
.body{padding:0 16px 16px}
.rec{background:var(--grey-bg);border-radius:8px;padding:10px 12px;margin:10px 0}
.body table{font-size:13px;margin-top:10px}
.scroll{overflow-x:auto}
button{font:inherit;font-size:13px;padding:6px 12px;border-radius:8px;border:1px solid var(--line);background:var(--card);color:var(--text);cursor:pointer}
footer{margin-top:40px;color:var(--muted);font-size:13px;border-top:1px solid var(--line);padding-top:16px}
@media print{body{background:#fff}.noprint{display:none}details{break-inside:avoid}.wrap{padding:0}}
'@

# The report's only script. Its SHA-256 goes into the CSP, so any change here is picked up automatically.
$script:ReportScript = 'function toggleAll(o){document.querySelectorAll("details").forEach(function(d){d.open=o})}' +
    'document.querySelectorAll("[data-toggle]").forEach(function(b){b.addEventListener("click",function(){toggleAll(b.getAttribute("data-toggle")==="open")})});' +
    'window.addEventListener("beforeprint",function(){toggleAll(true)});'

function ConvertTo-ADAuditHtml {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Results, [int]$MaxRowsPerFinding = 500)

    $e = { param($v) ConvertTo-HtmlText $v }
    $int = { param($v) $n = 0; if ([int]::TryParse([string]$v, [ref]$n)) { $n } else { 0 } }
    $sevLabel = @{ Red = 'Red'; Amber = 'Amber'; Green = 'Green'; NotRun = 'Not run' }
    # The results JSON is treated as untrusted input: severities are whitelisted (they end up in
    # class attributes), numbers are re-parsed as integers and every string is HTML-encoded below.
    $findings = @(@($Results.Findings) | ForEach-Object {
        [pscustomobject]@{
            Id = [string]$_.Id; Category = [string]$_.Category; Title = [string]$_.Title
            Severity = if ([string]$_.Severity -cin 'Red', 'Amber', 'Green', 'NotRun') { [string]$_.Severity } else { 'NotRun' }
            Summary = [string]$_.Summary; Recommendation = [string]$_.Recommendation
            Count = & $int $_.Count; Items = @($_.Items); Columns = @($_.Columns | ForEach-Object { [string]$_ })
        }
    })
    $sb = New-Object System.Text.StringBuilder
    $w = { param($s) [void]$sb.Append($s) }

    $isLab = $Results.Source -eq 'Lab'
    $domainName = & $e $Results.Domain.DnsRoot
    $collected = (ConvertFrom-AuditDateString $Results.CollectedAt).ToLocalTime().ToString('yyyy-MM-dd HH:mm')
    $score = [math]::Max(0, [math]::Min(100, (& $int $Results.Score)))
    $scoreColor = if ($score -ge 80) { 'var(--green)' } elseif ($score -ge 50) { 'var(--amber)' } else { 'var(--red)' }
    $circ = 2 * [math]::PI * 42
    $dash = [math]::Round($circ * $score / 100, 1)

    # Content Security Policy: nothing may load from anywhere, and the only script allowed is
    # the one below, pinned by its SHA-256 hash. Injected markup could not run code.
    $sha = [Security.Cryptography.SHA256]::Create()
    $scriptHash = [Convert]::ToBase64String($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($script:ReportScript)))
    $csp = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; script-src 'sha256-$scriptHash'; base-uri 'none'; form-action 'none'"

    & $w "<!doctype html><html lang=""en""><head><meta charset=""utf-8"">"
    & $w "<meta http-equiv=""Content-Security-Policy"" content=""$csp""><meta name=""referrer"" content=""no-referrer"">"
    & $w "<meta name=""viewport"" content=""width=device-width,initial-scale=1"">"
    & $w "<title>AD security audit - $domainName</title><style>$script:ReportCss</style></head><body><div class=""wrap"">"

    # Header and executive summary
    $badge = if ($isLab) { '<span class="badge lab">LAB DATA - FICTIONAL DOMAIN</span>' } else { '<span class="badge live">LIVE DOMAIN</span>' }
    & $w "<div class=""head""><div><h1>Active Directory security audit</h1>"
    & $w "<div class=""muted"">$domainName ($(& $e $Results.Domain.NetBIOSName)) &middot; collected $collected &middot; $badge</div>"
    & $w "<div class=""muted small"">Read-only audit. Thresholds: inactivity $(& $int $Results.Parameters.InactiveDays) days, Domain Admins target $(& $int $Results.Parameters.MaxDomainAdmins).</div></div>"
    & $w "<div class=""score""><svg viewBox=""0 0 100 100"" role=""img"" aria-label=""Score $score of 100"">"
    & $w "<circle cx=""50"" cy=""50"" r=""42"" fill=""none"" stroke=""var(--line)"" stroke-width=""10""/>"
    & $w "<circle cx=""50"" cy=""50"" r=""42"" fill=""none"" stroke=""$scoreColor"" stroke-width=""10"" stroke-linecap=""round"" stroke-dasharray=""$dash $circ"" transform=""rotate(-90 50 50)""/>"
    & $w "<text x=""50"" y=""57"" text-anchor=""middle"" font-size=""24"" font-weight=""700"" fill=""$scoreColor"">$score</text></svg>"
    & $w "<div><div style=""font-weight:600"">Hygiene score</div><div class=""muted small"">share of checks passed;<br>red counts double</div></div></div></div>"

    # Totals are recounted from the (sanitised) findings rather than trusted from the file.
    $t = @{}; foreach ($k in 'Red', 'Amber', 'Green', 'NotRun') { $t[$k] = @($findings | Where-Object Severity -eq $k).Count }
    $s = @{}; foreach ($k in 'Users', 'EnabledUsers', 'Computers', 'EnabledComputers', 'Gpos') { $s[$k] = & $int $Results.Stats.$k }
    & $w '<div class="cards">'
    & $w "<div class=""card red""><div class=""n"">$($t.Red)</div><div class=""l"">Red: act now</div></div>"
    & $w "<div class=""card amber""><div class=""n"">$($t.Amber)</div><div class=""l"">Amber: plan a fix</div></div>"
    & $w "<div class=""card green""><div class=""n"">$($t.Green)</div><div class=""l"">Green: no issue found</div></div>"
    if ($t.NotRun) { & $w "<div class=""card grey""><div class=""n"">$($t.NotRun)</div><div class=""l"">Not run</div></div>" }
    & $w "<div class=""card""><div class=""n"">$($s.EnabledUsers)</div><div class=""l"">enabled users of $($s.Users)</div></div>"
    & $w "<div class=""card""><div class=""n"">$($s.EnabledComputers)</div><div class=""l"">enabled computers of $($s.Computers)</div></div>"
    & $w "<div class=""card""><div class=""n"">$($s.Gpos)</div><div class=""l"">group policy objects</div></div>"
    & $w '</div>'

    # Action plan: every red and amber finding with its recommended action
    $order = @{ Red = 0; Amber = 1; NotRun = 2; Green = 3 }
    $actionable = @($findings | Where-Object { $_.Severity -in 'Red', 'Amber' } | Sort-Object { $order[$_.Severity] }, Id)
    & $w '<h2>Action plan</h2>'
    if ($actionable.Count -eq 0) {
        & $w '<p class="muted">No red or amber findings.</p>'
    } else {
        & $w '<div class="scroll"><table><thead><tr><th>Status</th><th>Check</th><th>Finding</th><th>Affected</th><th>Recommended action</th></tr></thead><tbody>'
        foreach ($f in $actionable) {
            & $w "<tr><td class=""sev $($f.Severity)""><span class=""dot $($f.Severity)""></span>$($sevLabel[$f.Severity])</td>"
            & $w "<td class=""id""><a href=""#$(& $e $f.Id)"">$(& $e $f.Id)</a></td><td>$(& $e $f.Title)</td><td>$($f.Count)</td>"
            & $w "<td class=""action"">$(& $e $f.Recommendation)</td></tr>"
        }
        & $w '</tbody></table></div>'
    }

    # Details per category
    & $w '<h2>All checks</h2><p class="noprint"><button type="button" data-toggle="open">Expand all</button> <button type="button" data-toggle="close">Collapse all</button></p>'
    foreach ($cat in ($findings | Select-Object -ExpandProperty Category -Unique)) {
        & $w "<h3>$(& $e $cat)</h3>"
        foreach ($f in @($findings | Where-Object Category -eq $cat)) {
            $open = if ($f.Severity -eq 'Red') { ' open' } else { '' }
            & $w "<details id=""$(& $e $f.Id)"" class=""$($f.Severity)""$open><summary><span class=""dot $($f.Severity)""></span>"
            & $w "<span class=""id"">$(& $e $f.Id)</span><span class=""t"">$(& $e $f.Title)</span><span class=""c"">$($f.Count) affected</span></summary>"
            & $w "<div class=""body""><p>$(& $e $f.Summary)</p>"
            if ($f.Recommendation -and $f.Severity -ne 'Green') { & $w "<div class=""rec""><strong>Recommended action:</strong> $(& $e $f.Recommendation)</div>" }
            $items = @($f.Items); $cols = @($f.Columns)
            if ($items.Count -and $cols.Count) {
                & $w '<div class="scroll"><table><thead><tr>'
                foreach ($c in $cols) { & $w "<th>$(& $e $c)</th>" }
                & $w '</tr></thead><tbody>'
                foreach ($item in ($items | Select-Object -First $MaxRowsPerFinding)) {
                    & $w '<tr>'
                    foreach ($c in $cols) { & $w "<td>$(& $e $item.$c)</td>" }
                    & $w '</tr>'
                }
                & $w '</tbody></table></div>'
                if ($items.Count -gt $MaxRowsPerFinding) {
                    & $w "<p class=""muted small"">Showing $MaxRowsPerFinding of $($items.Count) rows. The full list is in the results JSON.</p>"
                }
            }
            & $w '</div></details>'
        }
    }

    if (@($Results.CollectionErrors).Count) {
        & $w '<h2>Collection warnings</h2><ul>'
        foreach ($err in $Results.CollectionErrors) { & $w "<li>$(& $e $err)</li>" }
        & $w '</ul>'
    }

    $generated = (ConvertFrom-AuditDateString $Results.GeneratedAt).ToLocalTime().ToString('yyyy-MM-dd HH:mm')
    & $w "<footer>Generated $generated by AD-Security-Audit $(& $e $Results.ToolVersion). The tool only reads directory data; it changed nothing in the domain. "
    & $w 'Severity is a guide for prioritising work, not a compliance verdict.</footer></div>'
    & $w "<script>$script:ReportScript</script></body></html>"
    return $sb.ToString()
}
