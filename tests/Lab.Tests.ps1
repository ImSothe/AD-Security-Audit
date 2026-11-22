# Golden tests: the fictional lab domain must produce exactly these findings.
$lab = Get-Content (Join-Path $root 'lab\lab-sample.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$labFindings = @(Invoke-ADAuditChecks -Snapshot $lab)
$byId = @{}; foreach ($f in $labFindings) { $byId[$f.Id] = $f }

Test-Case 'committed lab-sample.json matches the generator' {
    $fresh = New-ADAuditLabSnapshot | ConvertTo-Json -Depth 8 | ConvertFrom-Json | ConvertTo-Json -Depth 8 -Compress
    $file = Get-Content (Join-Path $root 'lab\lab-sample.json') -Raw -Encoding UTF8 | ConvertFrom-Json | ConvertTo-Json -Depth 8 -Compress
    Assert-True ($fresh -eq $file) 'lab\lab-sample.json is stale: run tools\New-LabSample.ps1'
}
Test-Case 'the generator is deterministic' {
    $a = New-ADAuditLabSnapshot | ConvertTo-Json -Depth 8 -Compress
    $b = New-ADAuditLabSnapshot | ConvertTo-Json -Depth 8 -Compress
    Assert-True ($a -eq $b) 'two runs produced different snapshots'
}
Test-Case 'all 29 checks run without engine errors' {
    Assert-Equal 29 $labFindings.Count 'finding count'
    Assert-Equal 0 @($labFindings | Where-Object { $_.Severity -eq 'NotRun' -or $_.Category -eq 'Engine' }).Count 'NotRun/engine findings'
}
Test-Case 'finding ids are unique and well formed' {
    Assert-Equal $labFindings.Count @($labFindings.Id | Select-Object -Unique).Count 'unique ids'
    foreach ($f in $labFindings) { Assert-True ($f.Id -match '^(ACC|PRV|DEL|CMP|GPO|DOM)-\d{2}$') "bad id $($f.Id)" }
}
Test-Case 'every finding has title, summary, recommendation and columns for its items' {
    foreach ($f in $labFindings) {
        Assert-True ([bool]$f.Title -and [bool]$f.Summary -and [bool]$f.Recommendation) "$($f.Id) missing text"
        if ($f.Count) {
            Assert-True ($f.Columns.Count -gt 0) "$($f.Id) has items but no columns"
            foreach ($c in $f.Columns) { Assert-True ($null -ne $f.Items[0].PSObject.Properties[$c]) "$($f.Id) column $c not on items" }
        }
    }
}

$expected = [ordered]@{
    'ACC-01' = 'Amber', 5;  'ACC-02' = 'Amber', 3;  'ACC-03' = 'Red', 3;    'ACC-04' = 'Red', 9
    'ACC-05' = 'Red', 1;    'ACC-06' = 'Amber', 10; 'ACC-07' = 'Amber', 2;  'ACC-08' = 'Green', 0
    'ACC-09' = 'Red', 1;    'ACC-10' = 'Red', 2;    'ACC-11' = 'Green', 0;  'PRV-01' = 'Amber', 18
    'PRV-02' = 'Amber', 4;  'PRV-03' = 'Red', 7;    'PRV-04' = 'Red', 1;    'PRV-05' = 'Amber', 1
    'PRV-06' = 'Amber', 1;  'DEL-01' = 'Red', 1;    'DEL-02' = 'Amber', 2;  'DEL-03' = 'Amber', 1
    'CMP-01' = 'Red', 16;   'CMP-02' = 'Amber', 6;  'GPO-01' = 'Amber', 4;  'GPO-02' = 'Amber', 2
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

Test-Case 'planted weaknesses are found by name' {
    Assert-True (@($byId['ACC-01'].Items.Account) -contains 'mprieto') 'inactive mprieto'
    Assert-True (@($byId['ACC-02'].Items.Account) -contains 'supplier.erp') 'ghost supplier.erp'
    Assert-True (@($byId['ACC-03'].Items.Account) -contains 'old.admin') 'leaver old.admin'
    Assert-True (@($byId['ACC-05'].Items.Account) -contains 'reception') 'empty password reception'
    Assert-True (@($byId['ACC-07'].Items.Account) -contains 'contractor.site') 'expired contractor.site'
    Assert-True (@($byId['ACC-09'].Items.Account) -contains 'svc_legacy') 'AS-REP svc_legacy'
    Assert-True (@($byId['PRV-06'].Items.Account) -contains 'jruiz') 'stale adminCount jruiz'
    Assert-True (@($byId['DEL-01'].Items.Object) -contains 'SRV-ERP01') 'unconstrained SRV-ERP01'
    Assert-True (@($byId['DEL-03'].Items.Computer) -contains 'SRV-APP02') 'RBCD SRV-APP02'
    Assert-True (@($byId['GPO-01'].Items.GPO) -contains 'GPO test') 'unlinked GPO test'
}
Test-Case 'things that must not be flagged are not' {
    Assert-True (-not (@($byId['DEL-01'].Items.Object) -contains 'DC01')) 'domain controllers excluded from DEL-01'
    Assert-True (-not (@($byId['CMP-01'].Items.Computer) -contains 'PC-OLDXP')) 'disabled computer excluded from CMP-01'
    Assert-True (-not (@($byId['CMP-01'].Items.Computer) -contains 'KIOSK-01')) 'Windows 10 LTSC 2019 is still supported'
    Assert-True (-not (@($byId['CMP-01'].Items.Computer) -contains 'PC-001')) 'Windows 11 25H2 is supported'
    Assert-True (-not (@($byId['ACC-01'].Items.Account) -contains 'agil')) 'disabled users excluded from ACC-01'
    Assert-True (-not (@($byId['ACC-10'].Items.Account) -contains 'krbtgt')) 'krbtgt excluded from Kerberoasting'
}
Test-Case 'nested Domain Admins members appear in the inventory' {
    $da = @($byId['PRV-01'].Items | Where-Object Group -eq 'Domain Admins').Account
    Assert-True ($da -contains 'hd.paula') 'nested member hd.paula missing'
    Assert-Equal 8 $da.Count 'Domain Admins members'
}
Test-Case 'lab score and totals' {
    $r = New-ADAuditResult -Snapshot $lab -Findings $labFindings -InactiveDays 90 -MaxDomainAdmins 5
    Assert-Equal 11 $r.Totals.Red 'red'; Assert-Equal 16 $r.Totals.Amber 'amber'; Assert-Equal 2 $r.Totals.Green 'green'
    Assert-Equal 34 $r.Score 'score'
    Assert-Equal 64 $r.Stats.Users 'users'; Assert-Equal 44 $r.Stats.Computers 'computers'; Assert-Equal 13 $r.Stats.Gpos 'gpos'
}
Test-Case 'lab data only uses fictional .lab names' {
    Assert-True ($lab.Domain.DnsRoot -like '*.lab') 'domain is not .lab'
    foreach ($u in $lab.Users) {
        Assert-True ($u.DistinguishedName -like '*DC=demo-corp,DC=lab') "user DN $($u.DistinguishedName)"
        foreach ($spn in @($u.ServicePrincipalNames)) { Assert-True ($spn -like '*.demo-corp.lab*') "SPN $spn" }
    }
}
