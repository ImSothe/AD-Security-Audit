# Unit tests for each check: thresholds, boundaries and exclusions, on small hand-built snapshots.

function Get-Sev { param($Finding) $Finding.Severity }

Test-Case 'a healthy domain is green on every check' {
    $notGreen = @(Invoke-ADAuditChecks -Snapshot (New-TestSnapshot) | Where-Object Severity -ne 'Green')
    Assert-Equal 0 $notGreen.Count "non-green: $(($notGreen | ForEach-Object { "$($_.Id)=$($_.Severity)" }) -join ', ')"
}
Test-Case 'checks do not modify the snapshot' {
    $snap = New-TestSnapshot -Users @(New-TestUser 'u1' @{ TrustedToAuthForDelegation = $true }) `
        -Computers @(New-TestComputer 'S1' @{ TrustedToAuthForDelegation = $true })
    $before = $snap | ConvertTo-Json -Depth 10 -Compress
    Invoke-ADAuditChecks -Snapshot $snap | Out-Null
    Assert-True ($before -eq ($snap | ConvertTo-Json -Depth 10 -Compress)) 'snapshot changed during checks'
}
Test-Case 'checks are deterministic' {
    $lab2 = Get-Content (Join-Path $root 'lab\lab-sample.json') -Raw | ConvertFrom-Json
    $a = Invoke-ADAuditChecks -Snapshot $lab2 | ConvertTo-Json -Depth 8 -Compress
    $b = Invoke-ADAuditChecks -Snapshot $lab2 | ConvertTo-Json -Depth 8 -Compress
    Assert-True ($a -eq $b) 'two runs differ'
}
Test-Case 'reference date defaults to the snapshot collection date, not today' {
    $snap = New-TestSnapshot -Users @(New-TestUser 'u1' @{ LastLogonDate = Ago 50 })
    $snap.CollectedAt = $ref.AddDays(100).ToString('o')
    $f = Invoke-ADAuditChecks -Snapshot $snap | Where-Object Id -eq 'ACC-01'
    $u1 = $f.Items | Where-Object Account -eq 'u1'
    Assert-True ($null -ne $u1) 'u1 should be inactive at collection time'
    Assert-Equal 150 $u1.DaysInactive 'days counted to the collection date'
}
Test-Case 'a check that throws becomes a NotRun finding and the other checks still run' {
    function Test-RecycleBin { param($Ctx) throw 'simulated failure' }
    $all = @(Invoke-ADAuditChecks -Snapshot (New-TestSnapshot))
    Assert-Equal 29 $all.Count 'all checks still produced a finding'
    $broken = $all | Where-Object Id -eq 'Test-RecycleBin'
    Assert-Equal 'NotRun' $broken.Severity 'broken check severity'
    Assert-True ($broken.Summary -like '*simulated failure*') 'error message kept'
}

# ---------------------------------------------------------------- ACC-01 inactive users
Test-Case 'ACC-01: 90 days is active, 91 is inactive' {
    $snap = New-TestSnapshot -Users @((New-TestUser 'd90' @{ LastLogonDate = Ago 90 }), (New-TestUser 'd91' @{ LastLogonDate = Ago 91 }))
    $f = Invoke-Check Test-InactiveUsers $snap
    Assert-Equal 1 $f.Count 'count'; Assert-Equal 'd91' $f.Items[0].Account 'account'; Assert-Equal 91 $f.Items[0].DaysInactive 'days'
}
Test-Case 'ACC-01: 10% of users is amber, more than 10% is red' {
    $users = @(1..8 | ForEach-Object { New-TestUser "u$_" }) + @(New-TestUser 'old1' @{ LastLogonDate = Ago 200 })
    Assert-Equal 'Amber' (Get-Sev (Invoke-Check Test-InactiveUsers (New-TestSnapshot -Users $users))) '1 of 10'
    $users += New-TestUser 'old2' @{ LastLogonDate = Ago 200 }
    Assert-Equal 'Red' (Get-Sev (Invoke-Check Test-InactiveUsers (New-TestSnapshot -Users $users))) '2 of 11'
}
Test-Case 'ACC-01: ignores disabled and never-logged-on accounts' {
    $snap = New-TestSnapshot -Users @((New-TestUser 'dis' @{ Enabled = $false; LastLogonDate = Ago 500 }), (New-TestUser 'never' @{ LastLogonDate = $null }))
    Assert-Equal 0 (Invoke-Check Test-InactiveUsers $snap).Count 'count'
}
Test-Case 'ACC-01: threshold follows -InactiveDays' {
    $snap = New-TestSnapshot -Users @(New-TestUser 'd45' @{ LastLogonDate = Ago 45 })
    Assert-Equal 0 (Invoke-Check Test-InactiveUsers $snap -InactiveDays 60).Count '60 days'
    Assert-Equal 1 (Invoke-Check Test-InactiveUsers $snap -InactiveDays 30).Count '30 days'
}
# ---------------------------------------------------------------- ACC-02 ghosts
Test-Case 'ACC-02: never logged on, 30 days old is fine, 31 is a ghost' {
    $snap = New-TestSnapshot -Users @((New-TestUser 'new' @{ LastLogonDate = $null; WhenCreated = Ago 30 }),
        (New-TestUser 'ghost' @{ LastLogonDate = $null; WhenCreated = Ago 31 }),
        (New-TestUser 'nodate' @{ LastLogonDate = $null; WhenCreated = $null }))
    $f = Invoke-Check Test-GhostAccounts $snap
    Assert-Equal 'Amber' $f.Severity 'severity'; Assert-Equal 1 $f.Count 'count'; Assert-Equal 'ghost' $f.Items[0].Account 'account'
}
# ---------------------------------------------------------------- ACC-03 leavers in groups
Test-Case 'ACC-03: disabled user with groups is amber' {
    $snap = New-TestSnapshot -Users @((New-TestUser 'left' @{ Enabled = $false; MemberOf = @('GG_Sales', 'VPN') }), (New-TestUser 'clean' @{ Enabled = $false }))
    $f = Invoke-Check Test-DisabledWithGroups $snap
    Assert-Equal 'Amber' $f.Severity 'severity'; Assert-Equal 1 $f.Count 'count'; Assert-Equal 2 $f.Items[0].GroupCount 'groups'
}
Test-Case 'ACC-03: disabled user still in a privileged group is red' {
    $snap = New-TestSnapshot -Users @(New-TestUser 'oldadm' @{ Enabled = $false; MemberOf = @('Domain Admins') }) -Members @{ DomainAdmins = 'Administrator', 'oldadm' }
    Assert-Equal 'Red' (Invoke-Check Test-DisabledWithGroups $snap).Severity 'severity'
}
Test-Case 'ACC-03: krbtgt is never reported' {
    $snap = New-TestSnapshot
    ($snap.Users | Where-Object SamAccountName -eq 'krbtgt').MemberOf = @('Denied RODC Password Replication Group')
    Assert-Equal 0 (Invoke-Check Test-DisabledWithGroups $snap).Count 'count'
}
# ---------------------------------------------------------------- ACC-04 never expires
Test-Case 'ACC-04: amber for normal users, red when a privileged account has it, disabled ignored' {
    $snap = New-TestSnapshot -Users @((New-TestUser 'svc' @{ PasswordNeverExpires = $true }), (New-TestUser 'off' @{ PasswordNeverExpires = $true; Enabled = $false }))
    $f = Invoke-Check Test-PasswordNeverExpires $snap
    Assert-Equal 'Amber' $f.Severity 'severity'; Assert-Equal 1 $f.Count 'count'
    $snap2 = New-TestSnapshot -Users @(New-TestUser 'adm' @{ PasswordNeverExpires = $true }) -Members @{ DomainAdmins = 'Administrator', 'adm' }
    $f2 = Invoke-Check Test-PasswordNeverExpires $snap2
    Assert-Equal 'Red' $f2.Severity 'privileged'; Assert-Equal 'Yes' $f2.Items[0].Privileged 'privileged column'
}
# ---------------------------------------------------------------- ACC-05..ACC-11
Test-Case 'ACC-05: PasswordNotRequired is red, disabled ignored' {
    $snap = New-TestSnapshot -Users @((New-TestUser 'np' @{ PasswordNotRequired = $true }), (New-TestUser 'np2' @{ PasswordNotRequired = $true; Enabled = $false }))
    $f = Invoke-Check Test-PasswordNotRequired $snap
    Assert-Equal 'Red' $f.Severity 'severity'; Assert-Equal 1 $f.Count 'count'
}
Test-Case 'ACC-06: password 365 days is fine, 366 is old; never-set ignored' {
    $snap = New-TestSnapshot -Users @((New-TestUser 'p365' @{ PasswordLastSet = Ago 365 }), (New-TestUser 'p366' @{ PasswordLastSet = Ago 366 }),
        (New-TestUser 'pnull' @{ PasswordLastSet = $null }))
    $f = Invoke-Check Test-OldPasswords $snap
    Assert-Equal 1 $f.Count 'count'; Assert-Equal 'p366' $f.Items[0].Account 'account'
}
Test-Case 'ACC-07: locked out and expired are flagged, future expiry is not' {
    $snap = New-TestSnapshot -Users @((New-TestUser 'locked' @{ LockedOut = $true }), (New-TestUser 'expired' @{ AccountExpires = Ago 1 }),
        (New-TestUser 'today' @{ AccountExpires = Ago 0 }), (New-TestUser 'future' @{ AccountExpires = Ago -10 }))
    $f = Invoke-Check Test-LockedOrExpired $snap
    Assert-Equal 3 $f.Count 'count'
    Assert-True (-not (@($f.Items.Account) -contains 'future')) 'future expiry flagged'
    Assert-Equal 'expired 1 days ago' ($f.Items | Where-Object Account -eq 'expired').State 'state text'
}
Test-Case 'ACC-08: reversible encryption on a user, or only in the domain policy, is red' {
    $f = Invoke-Check Test-ReversibleEncryption (New-TestSnapshot -Users @(New-TestUser 'rev' @{ ReversibleEncryption = $true }))
    Assert-Equal 'Red' $f.Severity 'user flag'
    $snap = New-TestSnapshot; $snap.Domain.PasswordPolicy.ReversibleEncryptionEnabled = $true
    $f2 = Invoke-Check Test-ReversibleEncryption $snap
    Assert-Equal 'Red' $f2.Severity 'policy flag'; Assert-Equal 0 $f2.Count 'no users'
}
Test-Case 'ACC-09: no pre-authentication is red' {
    Assert-Equal 'Red' (Invoke-Check Test-AsRepRoastable (New-TestSnapshot -Users @(New-TestUser 'asrep' @{ DoesNotRequirePreAuth = $true }))).Severity 'severity'
}
Test-Case 'ACC-10: SPN on a user is amber, on an admin red' {
    $spn = @('HTTP/app.test.lab')
    Assert-Equal 'Amber' (Invoke-Check Test-Kerberoastable (New-TestSnapshot -Users @(New-TestUser 'svc' @{ ServicePrincipalNames = $spn }))).Severity 'user'
    $snap = New-TestSnapshot -Users @(New-TestUser 'svcadm' @{ ServicePrincipalNames = $spn }) -Members @{ DomainAdmins = 'Administrator', 'svcadm' }
    Assert-Equal 'Red' (Invoke-Check Test-Kerberoastable $snap).Severity 'admin'
}
Test-Case 'ACC-11: Guest enabled is red, matched by RID not by name' {
    $snap = New-TestSnapshot
    $g = $snap.Users | Where-Object SamAccountName -eq 'Guest'; $g.Enabled = $true; $g.SamAccountName = 'Invitado'
    $f = Invoke-Check Test-GuestEnabled $snap
    Assert-Equal 'Red' $f.Severity 'severity'; Assert-Equal 'Invitado' $f.Items[0].Account 'renamed guest'
}

# ---------------------------------------------------------------- PRV
Test-Case 'PRV-01: Domain Admins 5 green, 6 amber, 10 amber, 11 red (target 5)' {
    foreach ($case in @(@(5, 'Green'), @(6, 'Amber'), @(10, 'Amber'), @(11, 'Red'))) {
        $n = $case[0]
        $users = @(1..($n - 1) | ForEach-Object { New-TestUser "adm$_" @{ AccountNotDelegated = $true } })
        $snap = New-TestSnapshot -Users $users -Members @{ DomainAdmins = @('Administrator') + @($users.SamAccountName) }
        Assert-Equal $case[1] (Invoke-Check Test-DomainAdminCount $snap).Severity "$n admins"
    }
}
Test-Case 'PRV-01: target follows -MaxDomainAdmins and only users are counted' {
    $users = @(1..3 | ForEach-Object { New-TestUser "adm$_" })
    $snap = New-TestSnapshot -Users $users -Members @{ DomainAdmins = @('Administrator') + @($users.SamAccountName) }
    ($snap.PrivilegedGroups | Where-Object Key -eq 'DomainAdmins').Members += [pscustomobject]@{ SamAccountName = 'IT-Group'; ObjectClass = 'group'; Sid = 'S-1-5-21-x' }
    Assert-Equal 'Amber' (Invoke-Check Test-DomainAdminCount $snap -MaxDomainAdmins 2).Severity 'target 2'
    Assert-Equal 'Green' (Invoke-Check Test-DomainAdminCount $snap -MaxDomainAdmins 4).Severity 'target 4'
}
Test-Case 'PRV-01: inventory lists Enterprise Admins and Administrators too' {
    $snap = New-TestSnapshot -Members @{ EnterpriseAdmins = @('Administrator') }
    $f = Invoke-Check Test-DomainAdminCount $snap
    Assert-Equal 3 $f.Count 'rows'
    Assert-True (@($f.Items.Group) -contains 'EnterpriseAdmins') 'EA row'
}
Test-Case 'PRV-01: unreadable Domain Admins is NotRun' {
    $snap = New-TestSnapshot; ($snap.PrivilegedGroups | Where-Object Key -eq 'DomainAdmins').Error = 'access denied'
    Assert-Equal 'NotRun' (Invoke-Check Test-DomainAdminCount $snap).Severity 'severity'
}
Test-Case 'PRV-02: any member of Enterprise/Schema Admins or Operators groups is amber' {
    foreach ($key in 'EnterpriseAdmins', 'SchemaAdmins', 'AccountOperators', 'ServerOperators', 'PrintOperators', 'BackupOperators') {
        Assert-Equal 'Amber' (Invoke-Check Test-GroupsThatShouldBeEmpty (New-TestSnapshot -Members @{ $key = @('Administrator') })).Severity $key
    }
}
Test-Case 'PRV-03: dormant admin is red; weak but active admin is amber' {
    $dormant = New-TestSnapshot -Users @(New-TestUser 'zz' @{ LastLogonDate = Ago 91; AccountNotDelegated = $true }) -Members @{ DomainAdmins = 'Administrator', 'zz' }
    Assert-Equal 'Red' (Invoke-Check Test-PrivilegedAccountHygiene $dormant).Severity 'dormant'
    $weak = New-TestSnapshot -Users @(New-TestUser 'ww' @{ PasswordNeverExpires = $true; AccountNotDelegated = $true }) -Members @{ DomainAdmins = 'Administrator', 'ww' }
    $f = Invoke-Check Test-PrivilegedAccountHygiene $weak
    Assert-Equal 'Amber' $f.Severity 'weak'; Assert-True ($f.Items[0].Issues -like '*never expires*') 'issue text'
}
Test-Case 'PRV-03: delegable admin, old admin password and disabled member are each reported' {
    $snap = New-TestSnapshot -Users @((New-TestUser 'deleg'), (New-TestUser 'oldpw' @{ PasswordLastSet = Ago 400; AccountNotDelegated = $true }),
        (New-TestUser 'gone' @{ Enabled = $false })) -Members @{ DomainAdmins = 'Administrator', 'deleg', 'oldpw', 'gone' }
    $f = Invoke-Check Test-PrivilegedAccountHygiene $snap
    Assert-Equal 3 $f.Count 'count'
    Assert-True (($f.Items | Where-Object Account -eq 'deleg').Issues -like '*cannot be delegated*') 'delegation issue'
    Assert-True (($f.Items | Where-Object Account -eq 'oldpw').Issues -like '*400 days*') 'password age issue'
    Assert-True (($f.Items | Where-Object Account -eq 'gone').Issues -like '*disabled*') 'disabled issue'
}
Test-Case 'PRV-04: krbtgt 180 green, 181 amber, 365 amber, 366 red, unknown red, missing NotRun' {
    foreach ($case in @(@(180, 'Green'), @(181, 'Amber'), @(365, 'Amber'), @(366, 'Red'), @($null, 'Red'))) {
        $snap = New-TestSnapshot; ($snap.Users | Where-Object SamAccountName -eq 'krbtgt').PasswordLastSet = Ago $case[0]
        Assert-Equal $case[1] (Invoke-Check Test-KrbtgtPasswordAge $snap).Severity "age $($case[0])"
    }
    $snap = New-TestSnapshot; $snap.Users = @($snap.Users | Where-Object SamAccountName -ne 'krbtgt')
    Assert-Equal 'NotRun' (Invoke-Check Test-KrbtgtPasswordAge $snap).Severity 'missing'
}
Test-Case 'PRV-05: RID 500 password 365 green, 366 amber, disabled green, found by RID' {
    foreach ($case in @(@(365, $true, 'Green'), @(366, $true, 'Amber'), @(900, $false, 'Green'))) {
        $snap = New-TestSnapshot; $a = $snap.Users | Where-Object { $_.Sid -like '*-500' }
        $a.PasswordLastSet = Ago $case[0]; $a.Enabled = $case[1]; $a.SamAccountName = 'Administrador'
        Assert-Equal $case[2] (Invoke-Check Test-BuiltinAdministrator $snap).Severity "age $($case[0]) enabled $($case[1])"
    }
}
Test-Case 'PRV-06: adminCount=1 outside privileged groups is amber; current admins and krbtgt are not' {
    $snap = New-TestSnapshot -Users @((New-TestUser 'former' @{ AdminCount = 1 }), (New-TestUser 'current' @{ AdminCount = 1; AccountNotDelegated = $true })) `
        -Members @{ DomainAdmins = 'Administrator', 'current' }
    $f = Invoke-Check Test-StaleAdminCount $snap
    Assert-Equal 1 $f.Count 'count'; Assert-Equal 'former' $f.Items[0].Account 'account'
}

# ---------------------------------------------------------------- DEL
Test-Case 'DEL-01: unconstrained delegation on servers and users is red, DCs and disabled excluded' {
    $snap = New-TestSnapshot -Users @(New-TestUser 'svcu' @{ TrustedForDelegation = $true }) `
        -Computers @((New-TestComputer 'APP' @{ TrustedForDelegation = $true }), (New-TestComputer 'OFF' @{ TrustedForDelegation = $true; Enabled = $false }))
    $f = Invoke-Check Test-UnconstrainedDelegation $snap
    Assert-Equal 'Red' $f.Severity 'severity'; Assert-Equal 2 $f.Count 'count'
    Assert-True (-not (@($f.Items.Object) -contains 'DC01')) 'DC flagged'
}
Test-Case 'DEL-02: protocol transition on users and computers is amber with targets listed' {
    $snap = New-TestSnapshot -Users @(New-TestUser 'svcw' @{ TrustedToAuthForDelegation = $true; DelegatesTo = @('HTTP/a', 'HTTP/b') }) `
        -Computers @(New-TestComputer 'WEB' @{ TrustedToAuthForDelegation = $true; DelegatesTo = @('CIFS/f') })
    $f = Invoke-Check Test-ProtocolTransition $snap
    Assert-Equal 2 $f.Count 'count'; Assert-Equal 'HTTP/a, HTTP/b' ($f.Items | Where-Object Object -eq 'svcw').DelegatesTo 'targets'
}
Test-Case 'DEL-03: resource-based delegation is amber' {
    Assert-Equal 'Amber' (Invoke-Check Test-ResourceBasedDelegation (New-TestSnapshot -Computers @(New-TestComputer 'R' @{ HasRbcd = $true }))).Severity 'severity'
}

# ---------------------------------------------------------------- CMP
Test-Case 'OS lifecycle by name' {
    $cases = @(
        @('Windows XP Professional', '', 'Unsupported'), @('Windows Vista Business', '', 'Unsupported'),
        @('Windows 7 Professional', '', 'Unsupported'), @('Windows 8 Pro', '', 'Unsupported'), @('Windows 8.1 Pro', '', 'Unsupported'),
        @('Windows 10 Pro', '10.0 (19045)', 'Unsupported'), @('Windows 10 Enterprise', '10.0 (19045)', 'Unsupported'),
        @('Windows Server 2003', '', 'Unsupported'), @('Windows Server 2008 R2 Standard', '', 'Unsupported'),
        @('Windows Server 2012 R2 Datacenter', '', 'Unsupported'), @('Windows Server 2016 Standard', '', 'EndingSoon'),
        @('Windows Server 2019 Standard', '', 'Supported'), @('Windows Server 2022 Datacenter', '', 'Supported'),
        @('Windows Server 2025 Standard', '', 'Supported'), @('Ubuntu 24.04', '', 'Unknown'), @('', '', 'Unknown')
    )
    foreach ($c in $cases) { Assert-Equal $c[2] (Get-OsSupportStatus $c[0] $ref $c[1]).Status "$($c[0]) $($c[1])" }
}
Test-Case 'OS lifecycle: Windows 11 by build and edition' {
    $cases = @(
        @('Windows 11 Pro', '10.0 (22000)', 'Unsupported'), @('Windows 11 Pro', '10.0 (22621)', 'Unsupported'),
        @('Windows 11 Pro', '10.0 (22631)', 'Unsupported'), @('Windows 11 Enterprise', '10.0 (22631)', 'Unsupported'),
        @('Windows 11 Pro', '10.0 (26100)', 'Unsupported'), @('Windows 11 Enterprise', '10.0 (26100)', 'Supported'),
        @('Windows 11 Education', '10.0 (26100)', 'Supported'), @('Windows 11 Pro', '10.0 (26200)', 'Supported'),
        @('Windows 11 Pro', '10.0 (27000)', 'Supported'), @('Windows 11 Pro', '', 'Supported')
    )
    foreach ($c in $cases) { Assert-Equal $c[2] (Get-OsSupportStatus $c[0] $ref $c[1]).Status "$($c[0]) $($c[1])" }
}
Test-Case 'OS lifecycle: LTSC/LTSB editions use the build, IoT gets its longer date' {
    $cases = @(
        @('Windows 10 Enterprise LTSC', '10.0 (17763)', 'Supported', '2029-01-09'),
        @('Windows 10 Enterprise LTSC', '10.0 (19044)', 'EndingSoon', '2027-01-12'),
        @('Windows 10 IoT Enterprise LTSC', '10.0 (19044)', 'Supported', '2032-01-13'),
        @('Windows 10 Enterprise 2016 LTSB', '10.0 (14393)', 'Unsupported', '2026-10-13'),
        @('Windows 11 Enterprise LTSC', '10.0 (26100)', 'Supported', '2029-10-09'),
        @('Windows 10 Enterprise LTSC', '10.0 (99999)', 'Unsupported', '2025-10-14')
    )
    foreach ($c in $cases) {
        $s = Get-OsSupportStatus $c[0] $ref $c[1]
        Assert-Equal $c[2] $s.Status "$($c[0]) $($c[1]) status"; Assert-Equal $c[3] $s.End "$($c[0]) $($c[1]) end"
    }
}
Test-Case 'OS lifecycle: day boundaries around end of support' {
    $eos = [datetime]'2027-01-12'   # Server 2016
    Assert-Equal 'EndingSoon' (Get-OsSupportStatus 'Windows Server 2016' $eos).Status 'on the last day'
    Assert-Equal 'Unsupported' (Get-OsSupportStatus 'Windows Server 2016' $eos.AddDays(1)).Status 'day after'
    Assert-Equal 'EndingSoon' (Get-OsSupportStatus 'Windows Server 2016' $eos.AddDays(-365)).Status '365 days before'
    Assert-Equal 'Supported' (Get-OsSupportStatus 'Windows Server 2016' $eos.AddDays(-366)).Status '366 days before'
    Assert-Equal 'Supported' (Get-OsSupportStatus 'Windows 10 Pro' ([datetime]'2024-01-01')).Status 'Win10 in 2024 (more than a year left)'
}
Test-Case 'CMP-01: red when unsupported, amber when only ending soon; disabled and blank OS ignored' {
    $amber = New-TestSnapshot -Computers @(New-TestComputer 'S16' @{ OperatingSystem = 'Windows Server 2016 Standard' })
    Assert-Equal 'Amber' (Invoke-Check Test-ObsoleteOperatingSystems $amber).Severity 'ending soon'
    $red = New-TestSnapshot -Computers @((New-TestComputer 'W7' @{ OperatingSystem = 'Windows 7 Professional' }),
        (New-TestComputer 'OFF' @{ OperatingSystem = 'Windows XP'; Enabled = $false }), (New-TestComputer 'NAS' @{ OperatingSystem = $null }))
    $f = Invoke-Check Test-ObsoleteOperatingSystems $red
    Assert-Equal 'Red' $f.Severity 'unsupported'; Assert-Equal 1 $f.Count 'count'
}
Test-Case 'CMP-02: computer inactivity uses creation date when it never logged on' {
    $snap = New-TestSnapshot -Computers @((New-TestComputer 'OLD' @{ LastLogonDate = Ago 91 }), (New-TestComputer 'NEVER' @{ LastLogonDate = $null; WhenCreated = Ago 200 }),
        (New-TestComputer 'FRESH' @{ LastLogonDate = $null; WhenCreated = Ago 5 }), (New-TestComputer 'D90' @{ LastLogonDate = Ago 90 }))
    $f = Invoke-Check Test-InactiveComputers $snap
    Assert-Equal 2 $f.Count 'count'; Assert-Equal 'Amber' $f.Severity 'severity'
}

# ---------------------------------------------------------------- GPO
Test-Case 'GPO-01: no enabled link is unlinked, even with disabled links' {
    $snap = New-TestSnapshot -Gpos @((New-TestGpo 'linked'), (New-TestGpo 'none' @{ EnabledLinks = 0 }), (New-TestGpo 'offlink' @{ EnabledLinks = 0; DisabledLinks = 2 }))
    $f = Invoke-Check Test-UnlinkedGpos $snap
    Assert-Equal 2 $f.Count 'count'
}
Test-Case 'GPO-02: only flags=3 (all settings disabled) is reported' {
    $snap = New-TestSnapshot -Gpos @((New-TestGpo 'f0'), (New-TestGpo 'f1' @{ Flags = 1 }), (New-TestGpo 'f2' @{ Flags = 2 }), (New-TestGpo 'f3' @{ Flags = 3 }))
    $f = Invoke-Check Test-DisabledGpos $snap
    Assert-Equal 1 $f.Count 'count'; Assert-Equal 'f3' $f.Items[0].GPO 'gpo'
}
Test-Case 'GPO-03: empty means both user and computer versions are 0' {
    $snap = New-TestSnapshot -Gpos @((New-TestGpo 'u' @{ UserVersion = 0 }), (New-TestGpo 'c' @{ ComputerVersion = 0 }), (New-TestGpo 'e' @{ UserVersion = 0; ComputerVersion = 0 }))
    Assert-Equal 1 (Invoke-Check Test-EmptyGpos $snap).Count 'count'
}
Test-Case 'GPO-04: missing SYSVOL folder and leftover SYSVOL folder are both red' {
    $snap = New-TestSnapshot -Gpos @(New-TestGpo 'nofolder' @{ SysvolPresent = $false }); $snap.SysvolOrphans = @('{11111111-2222-3333-4444-555555555555}')
    $f = Invoke-Check Test-OrphanedGpos $snap
    Assert-Equal 'Red' $f.Severity 'severity'; Assert-Equal 2 $f.Count 'count'
}
Test-Case 'GPO checks are NotRun when GPO data could not be read' {
    $snap = New-TestSnapshot; $snap.GpoError = 'access denied'
    foreach ($c in 'Test-UnlinkedGpos', 'Test-DisabledGpos', 'Test-EmptyGpos', 'Test-OrphanedGpos') {
        Assert-Equal 'NotRun' (Invoke-Check $c $snap).Severity $c
    }
}

# ---------------------------------------------------------------- DOM
Test-Case 'DOM-01: each password policy rule' {
    $cases = @(
        @{ Set = @{ MinPasswordLength = 7 }; Sev = 'Red' }, @{ Set = @{ MinPasswordLength = 8 }; Sev = 'Amber' },
        @{ Set = @{ MinPasswordLength = 11 }; Sev = 'Amber' }, @{ Set = @{ MinPasswordLength = 12 }; Sev = 'Green' },
        @{ Set = @{ ComplexityEnabled = $false }; Sev = 'Amber' }, @{ Set = @{ LockoutThreshold = 0 }; Sev = 'Amber' },
        @{ Set = @{ PasswordHistoryCount = 9 }; Sev = 'Amber' }, @{ Set = @{ PasswordHistoryCount = 10 }; Sev = 'Green' },
        @{ Set = @{ ReversibleEncryptionEnabled = $true }; Sev = 'Red' }
    )
    foreach ($c in $cases) {
        $snap = New-TestSnapshot
        foreach ($k in $c.Set.Keys) { $snap.Domain.PasswordPolicy.$k = $c.Set[$k] }
        Assert-Equal $c.Sev (Invoke-Check Test-PasswordPolicy $snap).Severity (($c.Set.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ',')
    }
}
Test-Case 'DOM-02: functional level parsing' {
    foreach ($c in @(@('Windows2025Domain', 'Green'), @('Windows2016Domain', 'Green'), @('Windows2012R2Domain', 'Amber'),
            @('Windows2008Domain', 'Amber'), @('', 'Amber'), @('UnknownDomain', 'Amber'))) {
        $snap = New-TestSnapshot; $snap.Domain.DomainMode = $c[0]
        Assert-Equal $c[1] (Invoke-Check Test-FunctionalLevel $snap).Severity $c[0]
    }
}
Test-Case 'DOM-03: Recycle Bin' {
    $snap = New-TestSnapshot; $snap.Domain.RecycleBinEnabled = $false
    Assert-Equal 'Amber' (Invoke-Check Test-RecycleBin $snap).Severity 'disabled'
}

# ---------------------------------------------------------------- scoring and helpers
Test-Case 'score: all green 100, all red 0, all amber 50, NotRun ignored, nothing evaluated 0' {
    $mk = { param($s) [pscustomobject]@{ Severity = $s } }
    Assert-Equal 100 (Get-AuditScore @((& $mk Green), (& $mk Green), (& $mk NotRun))) 'all green'
    Assert-Equal 0 (Get-AuditScore @((& $mk Red), (& $mk Red))) 'all red'
    Assert-Equal 50 (Get-AuditScore @((& $mk Amber), (& $mk Amber))) 'all amber'
    Assert-Equal 50 (Get-AuditScore @((& $mk Red), (& $mk Green))) 'one red one green'
    Assert-Equal 0 (Get-AuditScore @((& $mk NotRun))) 'nothing evaluated'
}
Test-Case 'date helpers: ISO round trip, age in days, empty values' {
    $iso = ConvertTo-AuditDateString ([datetime]::SpecifyKind([datetime]'2026-01-01T10:00:00', 'Utc'))
    Assert-Equal '2026-01-01T10:00:00.0000000Z' $iso 'ISO string'
    Assert-Equal 10 (Get-AuditAgeDays (Ago 10) $ref) 'age'
    Assert-Equal $null (Get-AuditAgeDays $null $ref) 'null age'
    Assert-Equal $null (ConvertTo-AuditDateString '') 'empty string'
    Assert-Equal 'Never' (Format-AuditDate $null) 'never'
    $local = ConvertFrom-AuditDateString '2026-03-01T00:30:00+02:00'
    Assert-Equal '2026-02-28T22:30:00' $local.ToUniversalTime().ToString('s') 'offset honoured'
}
Test-Case 'results document has totals that match the findings' {
    $snap = New-TestSnapshot -Users @(New-TestUser 'np' @{ PasswordNotRequired = $true })
    $f = @(Invoke-ADAuditChecks -Snapshot $snap)
    $r = New-ADAuditResult -Snapshot $snap -Findings $f -InactiveDays 90 -MaxDomainAdmins 5 -ToolVersion '9.9.9'
    Assert-Equal 1 $r.Totals.Red 'red'; Assert-Equal 28 $r.Totals.Green 'green'; Assert-Equal '9.9.9' $r.ToolVersion 'version'
    Assert-Equal 4 $r.Stats.Users 'users'; Assert-Equal 2 $r.Stats.EnabledUsers 'enabled users'
}
Test-Case 'GPO read failure is carried into the collection warnings' {
    $snap = New-TestSnapshot; $snap.GpoError = 'access denied'; $snap.Errors = @('Recycle Bin state: nope')
    $r = New-ADAuditResult -Snapshot $snap -Findings @(Invoke-ADAuditChecks -Snapshot $snap) -InactiveDays 90 -MaxDomainAdmins 5
    Assert-Equal 2 @($r.CollectionErrors).Count 'warnings'
    Assert-Equal 4 $r.Totals.NotRun 'NotRun total'
}
