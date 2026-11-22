#Requires -Version 5.1
# Every check is a pure function: snapshot in, finding out. Nothing here talks to AD,
# which is what makes the checks testable against the lab snapshot.

# End of extended support. Order matters: more specific patterns first.
$script:OsLifecycle = @(
    @{ Pattern = 'Windows XP';                  End = '2014-04-08' }
    @{ Pattern = 'Windows Vista';               End = '2017-04-11' }
    @{ Pattern = 'Windows 7\b';                 End = '2020-01-14' }
    @{ Pattern = 'Windows 8\.1';                End = '2023-01-10' }
    @{ Pattern = 'Windows 8\b';                 End = '2016-01-12' }
    @{ Pattern = 'Windows 10\b';                End = '2025-10-14' }
    @{ Pattern = 'Windows 11\b';                End = $null }
    @{ Pattern = 'Windows Server 2003';         End = '2015-07-14' }
    @{ Pattern = 'Windows Server 2008';         End = '2020-01-14' }
    @{ Pattern = 'Windows Server 2012';         End = '2023-10-10' }
    @{ Pattern = 'Windows Server 2016';         End = '2027-01-12' }
    @{ Pattern = 'Windows Server 2019';         End = '2029-01-09' }
    @{ Pattern = 'Windows Server 2022';         End = '2031-10-14' }
    @{ Pattern = 'Windows Server 2025';         End = '2034-10-10' }
)

$script:EmptyGroupKeys = 'EnterpriseAdmins', 'SchemaAdmins', 'AccountOperators', 'ServerOperators', 'PrintOperators', 'BackupOperators'
$script:PrivilegedGroupKeys = 'DomainAdmins', 'EnterpriseAdmins', 'SchemaAdmins', 'Administrators',
    'AccountOperators', 'ServerOperators', 'PrintOperators', 'BackupOperators'

function Format-AuditDate {
    param($Value)
    $d = ConvertFrom-AuditDateString $Value
    if ($null -eq $d) { return 'Never' }
    return $d.ToString('yyyy-MM-dd')
}

function Get-WorstSeverity {
    param([string[]]$Severities)
    foreach ($s in 'Red', 'Amber', 'Green') { if ($Severities -contains $s) { return $s } }
    return 'Green'
}

# Windows 11 feature updates each have their own end of servicing: Home/Pro first, Enterprise/Education a year later.
$script:Win11Builds = @{
    22000 = '2023-10-10', '2024-10-08'   # 21H2
    22621 = '2024-10-08', '2025-10-14'   # 22H2
    22631 = '2025-11-11', '2026-11-10'   # 23H2
    26100 = '2026-10-13', '2027-10-12'   # 24H2
    26200 = '2027-10-12', '2028-10-10'   # 25H2
}
# Long-term servicing editions report the same name for every release, so the build decides. Second value: IoT.
$script:LtscBuilds = @{
    14393 = '2026-10-13', '2026-10-13'   # Windows 10 LTSB 2016
    17763 = '2029-01-09', '2029-01-09'   # Windows 10 LTSC 2019
    19044 = '2027-01-12', '2032-01-13'   # Windows 10 LTSC 2021
    26100 = '2029-10-09', '2034-10-10'   # Windows 11 LTSC 2024
}

function Get-OsSupportStatus {
    param([string]$OperatingSystem, [datetime]$ReferenceDate, [string]$Version)
    $build = if ($Version -match '\((\d+)\)') { [int]$Matches[1] } else { 0 }
    $end = $null; $matched = $false
    # The current Windows 11 release is always less than a year from its end of servicing and moves on
    # through Windows Update, so for those builds only "already unsupported" is worth reporting.
    $warnEarly = $true

    if ($OperatingSystem -match 'LTS[BC]' -and $script:LtscBuilds.ContainsKey($build)) {
        $end = $script:LtscBuilds[$build][[int]($OperatingSystem -match 'IoT')]; $matched = $true
    } elseif ($OperatingSystem -match 'Windows 11\b' -and $script:Win11Builds.ContainsKey($build)) {
        $end = $script:Win11Builds[$build][[int]($OperatingSystem -match 'Enterprise|Education')]; $matched = $true; $warnEarly = $false
    } else {
        foreach ($entry in $script:OsLifecycle) {
            if ($OperatingSystem -match $entry.Pattern) { $end = $entry.End; $matched = $true; break }
        }
    }
    if (-not $matched) { return [pscustomobject]@{ Status = 'Unknown'; End = $null } }
    if (-not $end) { return [pscustomobject]@{ Status = 'Supported'; End = $null } }
    $endDate = [datetime]::ParseExact($end, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
    $daysLeft = ($endDate - $ReferenceDate.Date).TotalDays
    $status = if ($daysLeft -lt 0) { 'Unsupported' } elseif ($warnEarly -and $daysLeft -le 365) { 'EndingSoon' } else { 'Supported' }
    return [pscustomobject]@{ Status = $status; End = $end }
}

function New-AuditContext {
    param($Snapshot, [int]$InactiveDays, [int]$MaxDomainAdmins, [datetime]$ReferenceDate)
    $privileged = @{}
    foreach ($g in @($Snapshot.PrivilegedGroups)) {
        if ($g.Key -notin $script:PrivilegedGroupKeys) { continue }
        foreach ($m in @($g.Members)) {
            if ($m.ObjectClass -eq 'user' -and $m.Sid) {
                if (-not $privileged[$m.Sid]) { $privileged[$m.Sid] = New-Object System.Collections.Generic.List[string] }
                $privileged[$m.Sid].Add($g.Name)
            }
        }
    }
    [pscustomobject]@{
        Snapshot        = $Snapshot
        Ref             = $ReferenceDate
        InactiveDays    = $InactiveDays
        MaxDomainAdmins = $MaxDomainAdmins
        Privileged      = $privileged
        EnabledUsers    = @($Snapshot.Users | Where-Object Enabled)
        EnabledPcs      = @($Snapshot.Computers | Where-Object Enabled)
    }
}

function Test-IsPrivileged { param($Ctx, $User) return [bool]$Ctx.Privileged[$User.Sid] }

function Get-InactiveDays {
    # Days since last logon; accounts that never logged on count from their creation date.
    param($Ctx, $Object)
    $age = Get-AuditAgeDays $Object.LastLogonDate $Ctx.Ref
    if ($null -eq $age) { $age = Get-AuditAgeDays $Object.WhenCreated $Ctx.Ref }
    return $age
}

# ---------------------------------------------------------------- Accounts

function Test-InactiveUsers {
    param($Ctx)
    $items = @($Ctx.EnabledUsers | Where-Object LastLogonDate | ForEach-Object {
        $days = Get-AuditAgeDays $_.LastLogonDate $Ctx.Ref
        if ($days -gt $Ctx.InactiveDays) {
            [pscustomobject]@{ Account = $_.SamAccountName; Name = $_.DisplayName
                LastLogon = Format-AuditDate $_.LastLogonDate; DaysInactive = $days }
        }
    } | Sort-Object DaysInactive -Descending)
    $total = [math]::Max(1, $Ctx.EnabledUsers.Count)
    $pct = [math]::Round(100 * $items.Count / $total)
    $sev = if ($items.Count -eq 0) { 'Green' } elseif ($pct -gt 10) { 'Red' } else { 'Amber' }
    New-AuditFinding -Id 'ACC-01' -Category 'Accounts' -Title "Enabled users inactive for more than $($Ctx.InactiveDays) days" `
        -Severity $sev -Items $items -Columns Account, Name, LastLogon, DaysInactive `
        -Summary "$($items.Count) of $($Ctx.EnabledUsers.Count) enabled users ($pct%) have not logged on in $($Ctx.InactiveDays) days." `
        -Recommendation 'Check with HR or the account owner, then disable the account and move it to a leavers OU (for example OU=Leavers). Delete it after the retention period. LastLogonDate replicates with up to 14 days of lag, so values close to the threshold need a second look.'
}

function Test-GhostAccounts {
    # Created more than 30 days ago and never used: forgotten test, supplier or pre-created accounts.
    param($Ctx)
    $grace = 30
    $items = @($Ctx.EnabledUsers | Where-Object { -not $_.LastLogonDate } | ForEach-Object {
        $age = Get-AuditAgeDays $_.WhenCreated $Ctx.Ref
        if ($null -ne $age -and $age -gt $grace) {
            [pscustomobject]@{ Account = $_.SamAccountName; Name = $_.DisplayName
                Created = Format-AuditDate $_.WhenCreated; AgeDays = $age }
        }
    } | Sort-Object AgeDays -Descending)
    $sev = if ($items.Count) { 'Amber' } else { 'Green' }
    New-AuditFinding -Id 'ACC-02' -Category 'Accounts' -Title 'Ghost accounts (enabled, never logged on)' -Severity $sev `
        -Items $items -Columns Account, Name, Created, AgeDays `
        -Summary "$($items.Count) enabled users were created more than $grace days ago and have never logged on." `
        -Recommendation 'Find out who requested each one. Disable the ones without an owner; a never-used account with a known initial password is an easy way in.'
}

function Test-DisabledWithGroups {
    param($Ctx)
    $items = @($Ctx.Snapshot.Users | Where-Object { -not $_.Enabled -and $_.SamAccountName -ne 'krbtgt' -and @($_.MemberOf).Count -gt 0 } |
        ForEach-Object {
            [pscustomobject]@{ Account = $_.SamAccountName; Name = $_.DisplayName; GroupCount = @($_.MemberOf).Count
                Groups = (@($_.MemberOf) | Select-Object -First 5) -join ', ' }
        } | Sort-Object GroupCount -Descending)
    $privCount = @($Ctx.Snapshot.Users | Where-Object { -not $_.Enabled -and $_.SamAccountName -ne 'krbtgt' -and (Test-IsPrivileged $Ctx $_) }).Count
    $sev = if ($privCount) { 'Red' } elseif ($items.Count) { 'Amber' } else { 'Green' }
    New-AuditFinding -Id 'ACC-03' -Category 'Accounts' -Title 'Disabled accounts still in security groups (incomplete offboarding)' -Severity $sev `
        -Items $items -Columns Account, Name, GroupCount, Groups `
        -Summary "$($items.Count) disabled users still belong to groups ($privCount of them to privileged groups). Re-enabling one by mistake restores all its access." `
        -Recommendation 'Add a step to the leaver procedure: record the groups in the description, then remove every membership except Domain Users. Folder permissions granted directly to the user must be reviewed on each file server.'
}

function Test-PasswordNeverExpires {
    param($Ctx)
    $items = @($Ctx.EnabledUsers | Where-Object PasswordNeverExpires | ForEach-Object {
        [pscustomobject]@{ Account = $_.SamAccountName; Name = $_.DisplayName
            Privileged = if (Test-IsPrivileged $Ctx $_) { 'Yes' } else { 'No' }
            PasswordAgeDays = Get-AuditAgeDays $_.PasswordLastSet $Ctx.Ref }
    } | Sort-Object Privileged, PasswordAgeDays -Descending)
    $privCount = @($items | Where-Object Privileged -eq 'Yes').Count
    $sev = if ($items.Count -eq 0) { 'Green' } elseif ($privCount -gt 0) { 'Red' } else { 'Amber' }
    New-AuditFinding -Id 'ACC-04' -Category 'Accounts' -Title 'Passwords set to never expire' -Severity $sev `
        -Items $items -Columns Account, Name, Privileged, PasswordAgeDays `
        -Summary "$($items.Count) enabled users have PasswordNeverExpires ($privCount of them privileged)." `
        -Recommendation 'Remove the flag from people accounts. Move service accounts to group Managed Service Accounts (gMSA), which rotate their own password.'
}

function Test-PasswordNotRequired {
    param($Ctx)
    $items = @($Ctx.EnabledUsers | Where-Object PasswordNotRequired | ForEach-Object {
        [pscustomobject]@{ Account = $_.SamAccountName; Name = $_.DisplayName; LastLogon = Format-AuditDate $_.LastLogonDate }
    })
    $sev = if ($items.Count) { 'Red' } else { 'Green' }
    New-AuditFinding -Id 'ACC-05' -Category 'Accounts' -Title 'Accounts allowed to have an empty password' -Severity $sev `
        -Items $items -Columns Account, Name, LastLogon `
        -Summary "$($items.Count) enabled users have the PASSWD_NOTREQD flag." `
        -Recommendation 'Clear the flag (Set-ADUser -PasswordNotRequired $false) and make sure each account has a real password.'
}

function Test-OldPasswords {
    param($Ctx)
    $items = @($Ctx.EnabledUsers | Where-Object { $_.SamAccountName -ne 'krbtgt' } | ForEach-Object {
        $age = Get-AuditAgeDays $_.PasswordLastSet $Ctx.Ref
        if ($null -ne $age -and $age -gt 365) {
            [pscustomobject]@{ Account = $_.SamAccountName; Name = $_.DisplayName; PasswordAgeDays = $age
                NeverExpires = if ($_.PasswordNeverExpires) { 'Yes' } else { 'No' } }
        }
    } | Sort-Object PasswordAgeDays -Descending)
    $sev = if ($items.Count) { 'Amber' } else { 'Green' }
    New-AuditFinding -Id 'ACC-06' -Category 'Accounts' -Title 'Passwords older than one year' -Severity $sev `
        -Items $items -Columns Account, Name, PasswordAgeDays, NeverExpires `
        -Summary "$($items.Count) enabled users have not changed their password in more than 365 days." `
        -Recommendation 'Force a change at next logon for people accounts. For service accounts, rotate the password in a maintenance window or move them to gMSA.'
}

function Test-LockedOrExpired {
    param($Ctx)
    $items = @($Ctx.EnabledUsers | ForEach-Object {
        $expiredDays = Get-AuditAgeDays $_.AccountExpires $Ctx.Ref
        $state = @()
        if ($_.LockedOut) { $state += 'locked out' }
        if ($null -ne $expiredDays -and $expiredDays -ge 0) { $state += "expired $expiredDays days ago" }
        if ($state) {
            [pscustomobject]@{ Account = $_.SamAccountName; Name = $_.DisplayName; State = $state -join ', '
                LastLogon = Format-AuditDate $_.LastLogonDate }
        }
    })
    $sev = if ($items.Count) { 'Amber' } else { 'Green' }
    New-AuditFinding -Id 'ACC-07' -Category 'Accounts' -Title 'Locked-out or expired accounts still enabled' -Severity $sev `
        -Items $items -Columns Account, Name, State, LastLogon `
        -Summary "$($items.Count) enabled users are locked out right now or past their account expiry date (typically ended contracts)." `
        -Recommendation 'Expired: confirm the contract ended and disable the account. Locked out: if nobody asked for an unlock, someone may be guessing the password; check event 4740 on the PDC emulator.'
}

function Test-ReversibleEncryption {
    param($Ctx)
    $items = @($Ctx.EnabledUsers | Where-Object ReversibleEncryption | ForEach-Object {
        [pscustomobject]@{ Account = $_.SamAccountName; Name = $_.DisplayName }
    })
    $policyOn = [bool]$Ctx.Snapshot.Domain.PasswordPolicy.ReversibleEncryptionEnabled
    $sev = if ($items.Count -or $policyOn) { 'Red' } else { 'Green' }
    $note = if ($policyOn) { ' The default domain policy also enables it for everyone.' } else { '' }
    New-AuditFinding -Id 'ACC-08' -Category 'Accounts' -Title 'Passwords stored with reversible encryption' -Severity $sev `
        -Items $items -Columns Account, Name `
        -Summary "$($items.Count) enabled users store their password in a reversible form.$note" `
        -Recommendation 'Disable reversible encryption and force a password change so the reversible copy is discarded.'
}

function Test-AsRepRoastable {
    param($Ctx)
    $items = @($Ctx.EnabledUsers | Where-Object DoesNotRequirePreAuth | ForEach-Object {
        [pscustomobject]@{ Account = $_.SamAccountName; Name = $_.DisplayName
            Privileged = if (Test-IsPrivileged $Ctx $_) { 'Yes' } else { 'No' } }
    })
    $sev = if ($items.Count) { 'Red' } else { 'Green' }
    New-AuditFinding -Id 'ACC-09' -Category 'Accounts' -Title 'Kerberos pre-authentication disabled (AS-REP roasting)' -Severity $sev `
        -Items $items -Columns Account, Name, Privileged `
        -Summary "$($items.Count) enabled users do not require Kerberos pre-authentication; anyone can request material to crack their password offline." `
        -Recommendation 'Re-enable pre-authentication (Set-ADAccountControl -DoesNotRequirePreAuth $false). Legacy systems that need it are rare today.'
}

function Test-Kerberoastable {
    param($Ctx)
    $items = @($Ctx.EnabledUsers | Where-Object { @($_.ServicePrincipalNames).Count -gt 0 -and $_.SamAccountName -ne 'krbtgt' } | ForEach-Object {
        [pscustomobject]@{ Account = $_.SamAccountName
            Privileged = if (Test-IsPrivileged $Ctx $_) { 'Yes' } else { 'No' }
            PasswordAgeDays = Get-AuditAgeDays $_.PasswordLastSet $Ctx.Ref
            SPN = (@($_.ServicePrincipalNames) | Select-Object -First 2) -join ', ' }
    } | Sort-Object Privileged, PasswordAgeDays -Descending)
    $privCount = @($items | Where-Object Privileged -eq 'Yes').Count
    $sev = if ($items.Count -eq 0) { 'Green' } elseif ($privCount) { 'Red' } else { 'Amber' }
    New-AuditFinding -Id 'ACC-10' -Category 'Accounts' -Title 'User accounts with SPNs (Kerberoasting)' -Severity $sev `
        -Items $items -Columns Account, Privileged, PasswordAgeDays, SPN `
        -Summary "$($items.Count) enabled users have a service principal name ($privCount privileged). Their tickets can be cracked offline if the password is weak." `
        -Recommendation 'Move services to gMSA. Otherwise use 25+ character random passwords, remove privileged rights from service accounts and enforce AES-only encryption.'
}

function Test-GuestEnabled {
    param($Ctx)
    $items = @($Ctx.EnabledUsers | Where-Object { $_.Sid -like '*-501' } | ForEach-Object {
        [pscustomobject]@{ Account = $_.SamAccountName; LastLogon = Format-AuditDate $_.LastLogonDate }
    })
    $sev = if ($items.Count) { 'Red' } else { 'Green' }
    New-AuditFinding -Id 'ACC-11' -Category 'Accounts' -Title 'Built-in Guest account enabled' -Severity $sev `
        -Items $items -Columns Account, LastLogon `
        -Summary $(if ($items.Count) { 'The built-in Guest account is enabled.' } else { 'The built-in Guest account is disabled.' }) `
        -Recommendation 'Disable the Guest account.'
}

# ---------------------------------------------------------------- Privileged access

function Get-PrivilegedGroup { param($Ctx, [string]$Key) @($Ctx.Snapshot.PrivilegedGroups) | Where-Object Key -eq $Key | Select-Object -First 1 }

function Test-DomainAdminCount {
    # Full inventory of the three top groups (nested members included); severity driven by the Domain Admins count.
    param($Ctx)
    $da = Get-PrivilegedGroup $Ctx 'DomainAdmins'
    if (-not $da -or $da.Error) {
        return New-AuditFinding -Id 'PRV-01' -Category 'Privileged access' -Title 'Administrator inventory' -Severity NotRun `
            -Summary "Domain Admins could not be read. $($da.Error)"
    }
    $bySid = @{}; foreach ($u in $Ctx.Snapshot.Users) { $bySid[$u.Sid] = $u }
    $items = @(foreach ($key in 'DomainAdmins', 'EnterpriseAdmins', 'Administrators') {
        $g = Get-PrivilegedGroup $Ctx $key
        if (-not $g -or $g.Error) { continue }
        foreach ($m in @($g.Members | Where-Object ObjectClass -eq 'user')) {
            $u = $bySid[$m.Sid]
            [pscustomobject]@{ Group = $g.Name; Account = $m.SamAccountName
                Name = if ($u) { $u.DisplayName } else { '' }
                Enabled = if ($u -and $u.Enabled) { 'Yes' } else { 'No' }
                LastLogon = if ($u) { Format-AuditDate $u.LastLogonDate } else { '?' }
                PasswordAgeDays = if ($u) { Get-AuditAgeDays $u.PasswordLastSet $Ctx.Ref } else { $null } }
        }
    })
    $daCount = @($items | Where-Object Group -eq $da.Name).Count
    $max = $Ctx.MaxDomainAdmins
    $sev = if ($daCount -le $max) { 'Green' } elseif ($daCount -le 2 * $max) { 'Amber' } else { 'Red' }
    New-AuditFinding -Id 'PRV-01' -Category 'Privileged access' -Title 'Administrator inventory (Domain Admins, Enterprise Admins, Administrators)' -Severity $sev `
        -Items $items -Columns Group, Account, Name, Enabled, LastLogon, PasswordAgeDays `
        -Summary "$daCount user accounts are effective members of $($da.Name) (nested groups included); target $max or fewer. $($items.Count) memberships across the three groups." `
        -Recommendation 'Go through the list with IT management: remove former staff and external suppliers, give each admin a separate admin account (not the daily one) and delegate day-to-day tasks with scoped groups.'
}

function Test-GroupsThatShouldBeEmpty {
    param($Ctx)
    $items = @(foreach ($key in $script:EmptyGroupKeys) {
        $g = Get-PrivilegedGroup $Ctx $key
        if ($g -and -not $g.Error) {
            foreach ($m in @($g.Members)) { [pscustomobject]@{ Group = $g.Name; Member = $m.SamAccountName; Type = $m.ObjectClass } }
        }
    })
    $sev = if ($items.Count) { 'Amber' } else { 'Green' }
    New-AuditFinding -Id 'PRV-02' -Category 'Privileged access' -Title 'Privileged groups that should normally be empty' -Severity $sev `
        -Items $items -Columns Group, Member, Type `
        -Summary "$($items.Count) memberships found in Enterprise Admins, Schema Admins and the built-in Operators groups." `
        -Recommendation 'Add members only for the duration of a specific change, then remove them. The Operators groups carry hidden rights on domain controllers.'
}

function Test-PrivilegedAccountHygiene {
    param($Ctx)
    $red = $false
    $items = @(foreach ($u in $Ctx.Snapshot.Users) {
        if (-not (Test-IsPrivileged $Ctx $u) -or $u.SamAccountName -eq 'krbtgt') { continue }
        $issues = New-Object System.Collections.Generic.List[string]
        $inactive = Get-InactiveDays $Ctx $u
        $pwdAge = Get-AuditAgeDays $u.PasswordLastSet $Ctx.Ref
        if (-not $u.Enabled) { $issues.Add('disabled but still in a privileged group') }
        elseif ($null -ne $inactive -and $inactive -gt $Ctx.InactiveDays) { $issues.Add("inactive $inactive days"); $red = $true }
        if ($u.Enabled -and $u.PasswordNeverExpires) { $issues.Add('password never expires') }
        if ($u.Enabled -and $null -ne $pwdAge -and $pwdAge -gt 365) { $issues.Add("password $pwdAge days old") }
        if ($u.Enabled -and -not $u.AccountNotDelegated) { $issues.Add('not marked "sensitive and cannot be delegated"') }
        if ($issues.Count) {
            [pscustomobject]@{ Account = $u.SamAccountName; Groups = ($Ctx.Privileged[$u.Sid] | Select-Object -Unique) -join ', '
                Issues = $issues -join '; ' }
        }
    })
    $sev = if ($items.Count -eq 0) { 'Green' } elseif ($red) { 'Red' } else { 'Amber' }
    New-AuditFinding -Id 'PRV-03' -Category 'Privileged access' -Title 'Hygiene of privileged accounts' -Severity $sev `
        -Items $items -Columns Account, Groups, Issues `
        -Summary "$($items.Count) privileged accounts have at least one weakness." `
        -Recommendation 'Remove dormant admins, rotate their passwords yearly, set "Account is sensitive and cannot be delegated" and add them to the Protected Users group.'
}

function Test-KrbtgtPasswordAge {
    param($Ctx)
    $k = @($Ctx.Snapshot.Users) | Where-Object SamAccountName -eq 'krbtgt' | Select-Object -First 1
    if (-not $k) {
        return New-AuditFinding -Id 'PRV-04' -Category 'Privileged access' -Title 'krbtgt password age' -Severity NotRun -Summary 'krbtgt account not found in the snapshot.'
    }
    $age = Get-AuditAgeDays $k.PasswordLastSet $Ctx.Ref
    $sev = if ($null -eq $age -or $age -gt 365) { 'Red' } elseif ($age -gt 180) { 'Amber' } else { 'Green' }
    New-AuditFinding -Id 'PRV-04' -Category 'Privileged access' -Title 'krbtgt password age' -Severity $sev `
        -Items @([pscustomobject]@{ Account = 'krbtgt'; PasswordLastSet = Format-AuditDate $k.PasswordLastSet; AgeDays = $age }) `
        -Columns Account, PasswordLastSet, AgeDays `
        -Summary "The krbtgt password is $age days old. It signs every Kerberos ticket; an old one keeps stolen golden tickets valid." `
        -Recommendation 'Reset the krbtgt password twice, waiting for full replication between resets (Microsoft New-KrbtgtKeys.ps1). Repeat every 180 days.'
}

function Test-BuiltinAdministrator {
    param($Ctx)
    $a = @($Ctx.Snapshot.Users) | Where-Object { $_.Sid -like '*-500' } | Select-Object -First 1
    if (-not $a) {
        return New-AuditFinding -Id 'PRV-05' -Category 'Privileged access' -Title 'Built-in Administrator account' -Severity NotRun -Summary 'RID 500 account not found in the snapshot.'
    }
    $age = Get-AuditAgeDays $a.PasswordLastSet $Ctx.Ref
    $lastUse = Get-AuditAgeDays $a.LastLogonDate $Ctx.Ref
    $sev = if ($a.Enabled -and ($null -eq $age -or $age -gt 365)) { 'Amber' } else { 'Green' }
    New-AuditFinding -Id 'PRV-05' -Category 'Privileged access' -Title 'Built-in Administrator account (RID 500)' -Severity $sev `
        -Items @([pscustomobject]@{ Account = $a.SamAccountName; Enabled = if ($a.Enabled) { 'Yes' } else { 'No' }
            PasswordAgeDays = $age; LastLogon = Format-AuditDate $a.LastLogonDate }) `
        -Columns Account, Enabled, PasswordAgeDays, LastLogon `
        -Summary "Built-in Administrator: password $age days old, last logon $(if ($null -ne $lastUse) { "$lastUse days ago" } else { 'never' })." `
        -Recommendation 'Use it only as a break-glass account: long random password stored offline, rotated yearly, logons monitored.'
}

function Test-StaleAdminCount {
    param($Ctx)
    $items = @($Ctx.Snapshot.Users | Where-Object {
        $_.AdminCount -eq 1 -and $_.SamAccountName -ne 'krbtgt' -and -not (Test-IsPrivileged $Ctx $_)
    } | ForEach-Object { [pscustomobject]@{ Account = $_.SamAccountName; Enabled = if ($_.Enabled) { 'Yes' } else { 'No' } } })
    $sev = if ($items.Count) { 'Amber' } else { 'Green' }
    New-AuditFinding -Id 'PRV-06' -Category 'Privileged access' -Title 'Former admins still flagged adminCount=1' -Severity $sev `
        -Items $items -Columns Account, Enabled `
        -Summary "$($items.Count) accounts were once privileged and still carry adminCount=1, so they keep a frozen, non-inherited ACL." `
        -Recommendation 'Clear adminCount and re-enable permission inheritance on these accounts, or disable them if they are no longer used.'
}

# ---------------------------------------------------------------- Delegation

function Test-UnconstrainedDelegation {
    param($Ctx)
    $pcs = @($Ctx.EnabledPcs | Where-Object { $_.TrustedForDelegation -and -not $_.IsDomainController } |
        ForEach-Object { [pscustomobject]@{ Object = $_.Name; Type = 'Computer'; Detail = $_.OperatingSystem } })
    $users = @($Ctx.EnabledUsers | Where-Object TrustedForDelegation |
        ForEach-Object { [pscustomobject]@{ Object = $_.SamAccountName; Type = 'User'; Detail = $_.DisplayName } })
    $items = @($pcs) + @($users)
    $sev = if ($items.Count) { 'Red' } else { 'Green' }
    New-AuditFinding -Id 'DEL-01' -Category 'Delegation' -Title 'Unconstrained Kerberos delegation (non-DC)' -Severity $sev `
        -Items $items -Columns Object, Type, Detail `
        -Summary "$($items.Count) objects other than domain controllers can impersonate any user to any service. Compromising one of them can expose a domain admin ticket." `
        -Recommendation 'Replace with constrained or resource-based delegation to the specific services needed, then clear "Trust this computer for delegation to any service".'
}

function Test-ProtocolTransition {
    param($Ctx)
    $row = { param($name, $type, $obj) [pscustomobject]@{ Object = $name; Type = $type
        DelegatesTo = (@($obj.DelegatesTo) | Select-Object -First 3) -join ', ' } }
    $items = @(@($Ctx.EnabledPcs | Where-Object TrustedToAuthForDelegation | ForEach-Object { & $row $_.Name 'Computer' $_ }) +
        @($Ctx.EnabledUsers | Where-Object TrustedToAuthForDelegation | ForEach-Object { & $row $_.SamAccountName 'User' $_ }))
    $sev = if ($items.Count) { 'Amber' } else { 'Green' }
    New-AuditFinding -Id 'DEL-02' -Category 'Delegation' -Title 'Constrained delegation with protocol transition' -Severity $sev `
        -Items $items -Columns Object, Type, DelegatesTo `
        -Summary "$($items.Count) objects can obtain tickets for any user to their target services without that user authenticating." `
        -Recommendation 'Confirm each one is required and that its target services are as narrow as possible. Prefer "Kerberos only" when the application allows it.'
}

function Test-ResourceBasedDelegation {
    param($Ctx)
    $items = @($Ctx.EnabledPcs | Where-Object HasRbcd | ForEach-Object {
        [pscustomobject]@{ Computer = $_.Name; OperatingSystem = $_.OperatingSystem }
    })
    $sev = if ($items.Count) { 'Amber' } else { 'Green' }
    New-AuditFinding -Id 'DEL-03' -Category 'Delegation' -Title 'Resource-based constrained delegation configured' -Severity $sev `
        -Items $items -Columns Computer, OperatingSystem `
        -Summary "$($items.Count) computers accept delegated tickets from other accounts (msDS-AllowedToActOnBehalfOfOtherIdentity). Attackers also set this attribute to take over machines." `
        -Recommendation 'Review who is allowed on each computer. Any entry nobody recognises should be treated as a possible compromise.'
}

# ---------------------------------------------------------------- Computers

function Test-ObsoleteOperatingSystems {
    param($Ctx)
    $items = @($Ctx.EnabledPcs | Where-Object OperatingSystem | ForEach-Object {
        $support = Get-OsSupportStatus $_.OperatingSystem $Ctx.Ref $_.OperatingSystemVersion
        if ($support.Status -in 'Unsupported', 'EndingSoon') {
            [pscustomobject]@{ Computer = $_.Name; OperatingSystem = $_.OperatingSystem; Build = $_.OperatingSystemVersion
                EndOfSupport = $support.End; Status = $support.Status; LastLogon = Format-AuditDate $_.LastLogonDate }
        }
    } | Sort-Object EndOfSupport, Computer)
    $unsupported = @($items | Where-Object Status -eq 'Unsupported').Count
    $sev = if ($unsupported) { 'Red' } elseif ($items.Count) { 'Amber' } else { 'Green' }
    New-AuditFinding -Id 'CMP-01' -Category 'Computers' -Title 'Operating systems out of support' -Severity $sev `
        -Items $items -Columns Computer, OperatingSystem, Build, EndOfSupport, Status, LastLogon `
        -Summary "$unsupported enabled computers run an operating system past its end of support; $($items.Count - $unsupported) more reach it within 12 months." `
        -Recommendation 'Upgrade or retire them. If one must stay, isolate it on its own network segment and cover it with paid Extended Security Updates where available.'
}

function Test-InactiveComputers {
    param($Ctx)
    $items = @($Ctx.EnabledPcs | ForEach-Object {
        $days = Get-InactiveDays $Ctx $_
        if ($null -ne $days -and $days -gt $Ctx.InactiveDays) {
            [pscustomobject]@{ Computer = $_.Name; OperatingSystem = $_.OperatingSystem
                LastLogon = Format-AuditDate $_.LastLogonDate; DaysInactive = $days }
        }
    } | Sort-Object DaysInactive -Descending)
    $sev = if ($items.Count) { 'Amber' } else { 'Green' }
    New-AuditFinding -Id 'CMP-02' -Category 'Computers' -Title "Computers inactive for more than $($Ctx.InactiveDays) days" -Severity $sev `
        -Items $items -Columns Computer, OperatingSystem, LastLogon, DaysInactive `
        -Summary "$($items.Count) of $($Ctx.EnabledPcs.Count) enabled computer accounts have not authenticated in $($Ctx.InactiveDays) days." `
        -Recommendation 'Disable them and move them to a quarantine OU; delete after confirming the hardware is gone.'
}

# ---------------------------------------------------------------- Group Policy

function Get-GpoNotRun {
    param($Ctx, [string]$Id, [string]$Title)
    New-AuditFinding -Id $Id -Category 'Group Policy' -Title $Title -Severity NotRun -Summary "GPO data could not be read: $($Ctx.Snapshot.GpoError)"
}

function Test-UnlinkedGpos {
    param($Ctx)
    $title = 'GPOs not linked anywhere'
    if ($Ctx.Snapshot.GpoError) { return Get-GpoNotRun $Ctx 'GPO-01' $title }
    $items = @($Ctx.Snapshot.Gpos | Where-Object { $_.EnabledLinks -eq 0 } | ForEach-Object {
        [pscustomobject]@{ GPO = $_.DisplayName; DisabledLinks = $_.DisabledLinks; LastChanged = Format-AuditDate $_.WhenChanged }
    } | Sort-Object GPO)
    $sev = if ($items.Count) { 'Amber' } else { 'Green' }
    New-AuditFinding -Id 'GPO-01' -Category 'Group Policy' -Title $title -Severity $sev -Items $items -Columns GPO, DisabledLinks, LastChanged `
        -Summary "$($items.Count) of $(@($Ctx.Snapshot.Gpos).Count) GPOs have no enabled link, so they apply to nobody." `
        -Recommendation 'Back them up (Backup-GPO) and delete the ones nobody claims. Fewer GPOs means faster logons and easier troubleshooting.'
}

function Test-DisabledGpos {
    param($Ctx)
    $title = 'GPOs with all settings disabled'
    if ($Ctx.Snapshot.GpoError) { return Get-GpoNotRun $Ctx 'GPO-02' $title }
    $items = @($Ctx.Snapshot.Gpos | Where-Object { $_.Flags -eq 3 } | ForEach-Object {
        [pscustomobject]@{ GPO = $_.DisplayName; Links = $_.EnabledLinks; LastChanged = Format-AuditDate $_.WhenChanged }
    } | Sort-Object GPO)
    $sev = if ($items.Count) { 'Amber' } else { 'Green' }
    New-AuditFinding -Id 'GPO-02' -Category 'Group Policy' -Title $title -Severity $sev -Items $items -Columns GPO, Links, LastChanged `
        -Summary "$($items.Count) GPOs are fully disabled but still exist." `
        -Recommendation 'Decide whether each one is still needed; delete it or re-enable it with a documented purpose.'
}

function Test-EmptyGpos {
    param($Ctx)
    $title = 'Empty GPOs (never edited)'
    if ($Ctx.Snapshot.GpoError) { return Get-GpoNotRun $Ctx 'GPO-03' $title }
    $items = @($Ctx.Snapshot.Gpos | Where-Object { $_.UserVersion -eq 0 -and $_.ComputerVersion -eq 0 } | ForEach-Object {
        [pscustomobject]@{ GPO = $_.DisplayName; Links = $_.EnabledLinks; LastChanged = Format-AuditDate $_.WhenChanged }
    } | Sort-Object GPO)
    $sev = if ($items.Count) { 'Amber' } else { 'Green' }
    New-AuditFinding -Id 'GPO-03' -Category 'Group Policy' -Title $title -Severity $sev -Items $items -Columns GPO, Links, LastChanged `
        -Summary "$($items.Count) GPOs have never had a setting saved (version 0)." `
        -Recommendation 'Delete them; an empty GPO still has to be processed at every logon if it is linked.'
}

function Test-OrphanedGpos {
    param($Ctx)
    $title = 'Orphaned GPOs (AD and SYSVOL out of sync)'
    if ($Ctx.Snapshot.GpoError) { return Get-GpoNotRun $Ctx 'GPO-04' $title }
    $items = @(@($Ctx.Snapshot.Gpos | Where-Object { -not $_.SysvolPresent } | ForEach-Object {
            [pscustomobject]@{ GPO = $_.DisplayName; Id = $_.Id; Problem = 'AD object without SYSVOL folder' } }) +
        @(@($Ctx.Snapshot.SysvolOrphans) | ForEach-Object {
            [pscustomobject]@{ GPO = '(none)'; Id = $_; Problem = 'SYSVOL folder without AD object' } }))
    $sev = if ($items.Count) { 'Red' } else { 'Green' }
    New-AuditFinding -Id 'GPO-04' -Category 'Group Policy' -Title $title -Severity $sev -Items $items -Columns GPO, Id, Problem `
        -Summary "$($items.Count) GPOs exist only in AD or only in SYSVOL. Clients fail to apply them and replication may be broken." `
        -Recommendation 'Check SYSVOL replication (DFSR) health first. Then restore the missing half from backup or remove the leftover.'
}

# ---------------------------------------------------------------- Domain

function Test-PasswordPolicy {
    param($Ctx)
    $p = $Ctx.Snapshot.Domain.PasswordPolicy
    $items = New-Object System.Collections.Generic.List[object]
    $add = { param($s, $setting, $value, $target) $items.Add([pscustomobject]@{ Setting = $setting; Value = $value; Target = $target; Severity = $s }) }
    if ($p.MinPasswordLength -lt 8) { & $add 'Red' 'Minimum length' $p.MinPasswordLength '12 or more' }
    elseif ($p.MinPasswordLength -lt 12) { & $add 'Amber' 'Minimum length' $p.MinPasswordLength '12 or more' }
    if (-not $p.ComplexityEnabled) { & $add 'Amber' 'Complexity' 'Disabled' 'Enabled (or 15+ length)' }
    if ($p.LockoutThreshold -eq 0) { & $add 'Amber' 'Lockout threshold' '0 (never)' '5-10 attempts' }
    if ($p.PasswordHistoryCount -lt 10) { & $add 'Amber' 'Password history' $p.PasswordHistoryCount '24' }
    if ($p.ReversibleEncryptionEnabled) { & $add 'Red' 'Reversible encryption' 'Enabled' 'Disabled' }
    $sev = Get-WorstSeverity @($items | ForEach-Object Severity)
    New-AuditFinding -Id 'DOM-01' -Category 'Domain' -Title 'Default domain password policy' -Severity $sev `
        -Items $items.ToArray() -Columns Setting, Value, Target `
        -Summary "Minimum length $($p.MinPasswordLength), complexity $(if ($p.ComplexityEnabled) { 'on' } else { 'off' }), lockout after $($p.LockoutThreshold) attempts, history $($p.PasswordHistoryCount). $($items.Count) settings below target." `
        -Recommendation 'Raise the minimum length to at least 12 (14 for admins via a Fine-Grained Password Policy), enable lockout and block known-breached passwords.'
}

function Test-FunctionalLevel {
    param($Ctx)
    $mode = [string]$Ctx.Snapshot.Domain.DomainMode
    $year = if ($mode -match '(\d{4})') { [int]$Matches[1] } else { 0 }
    $sev = if ($year -ge 2016) { 'Green' } else { 'Amber' }
    New-AuditFinding -Id 'DOM-02' -Category 'Domain' -Title 'Domain functional level' -Severity $sev `
        -Summary "Domain functional level: $mode. Forest functional level: $($Ctx.Snapshot.Domain.ForestMode)." `
        -Recommendation 'Raise to Windows Server 2016 or later once every domain controller supports it, to unlock Protected Users protections, AES-only Kerberos and PAM features.'
}

function Test-RecycleBin {
    param($Ctx)
    $on = [bool]$Ctx.Snapshot.Domain.RecycleBinEnabled
    New-AuditFinding -Id 'DOM-03' -Category 'Domain' -Title 'Active Directory Recycle Bin' -Severity $(if ($on) { 'Green' } else { 'Amber' }) `
        -Summary $(if ($on) { 'The AD Recycle Bin is enabled.' } else { 'The AD Recycle Bin is disabled: an accidentally deleted user or OU needs an authoritative restore from backup.' }) `
        -Recommendation 'Enable it (Enable-ADOptionalFeature "Recycle Bin Feature"). It is irreversible and needs forest level 2008 R2 or later.'
}

# ---------------------------------------------------------------- Runner

function Invoke-ADAuditChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Snapshot,
        [int]$InactiveDays = 90,
        [int]$MaxDomainAdmins = 5,
        [datetime]$ReferenceDate
    )
    if (-not $PSBoundParameters.ContainsKey('ReferenceDate')) { $ReferenceDate = ConvertFrom-AuditDateString $Snapshot.CollectedAt }
    $ctx = New-AuditContext -Snapshot $Snapshot -InactiveDays $InactiveDays -MaxDomainAdmins $MaxDomainAdmins -ReferenceDate $ReferenceDate

    $checks = 'Test-InactiveUsers', 'Test-GhostAccounts', 'Test-DisabledWithGroups', 'Test-PasswordNeverExpires',
        'Test-PasswordNotRequired', 'Test-OldPasswords', 'Test-LockedOrExpired', 'Test-ReversibleEncryption',
        'Test-AsRepRoastable', 'Test-Kerberoastable', 'Test-GuestEnabled',
        'Test-DomainAdminCount', 'Test-GroupsThatShouldBeEmpty', 'Test-PrivilegedAccountHygiene', 'Test-KrbtgtPasswordAge',
        'Test-BuiltinAdministrator', 'Test-StaleAdminCount',
        'Test-UnconstrainedDelegation', 'Test-ProtocolTransition', 'Test-ResourceBasedDelegation',
        'Test-ObsoleteOperatingSystems', 'Test-InactiveComputers',
        'Test-UnlinkedGpos', 'Test-DisabledGpos', 'Test-EmptyGpos', 'Test-OrphanedGpos',
        'Test-PasswordPolicy', 'Test-FunctionalLevel', 'Test-RecycleBin'

    foreach ($check in $checks) {
        try { & $check $ctx }
        catch {
            New-AuditFinding -Id $check -Category 'Engine' -Title "$check failed" -Severity NotRun -Summary $_.Exception.Message
        }
    }
}

# Share of evaluated checks that pass, with red weighing twice as much as amber.
# All green = 100, all red = 0. A number for the cover page, not a benchmark.
function Get-AuditScore {
    param([object[]]$Findings)
    $red = @($Findings | Where-Object Severity -eq 'Red').Count
    $amber = @($Findings | Where-Object Severity -eq 'Amber').Count
    $evaluated = @($Findings | Where-Object Severity -ne 'NotRun').Count
    if ($evaluated -eq 0) { return 0 }
    return [int][math]::Round(100 * (1 - (2 * $red + $amber) / (2 * $evaluated)))
}

# The results document: everything the HTML report needs, nothing it has to recompute.
function New-ADAuditResult {
    param([Parameter(Mandatory)]$Snapshot, [Parameter(Mandatory)][object[]]$Findings,
        [int]$InactiveDays, [int]$MaxDomainAdmins, [string]$ToolVersion = '1.0.0')
    $count = { param($s) @($Findings | Where-Object Severity -eq $s).Count }
    [pscustomobject]@{
        SchemaVersion    = 1
        ToolVersion      = $ToolVersion
        Source           = $Snapshot.Source
        CollectedAt      = $Snapshot.CollectedAt
        GeneratedAt      = ConvertTo-AuditDateString (Get-Date)
        Domain           = [pscustomobject]@{
            DnsRoot = $Snapshot.Domain.DnsRoot; NetBIOSName = $Snapshot.Domain.NetBIOSName
            DomainMode = $Snapshot.Domain.DomainMode; ForestMode = $Snapshot.Domain.ForestMode
        }
        Parameters       = [pscustomobject]@{ InactiveDays = $InactiveDays; MaxDomainAdmins = $MaxDomainAdmins }
        Stats            = [pscustomobject]@{
            Users = @($Snapshot.Users).Count; EnabledUsers = @($Snapshot.Users | Where-Object Enabled).Count
            Computers = @($Snapshot.Computers).Count; EnabledComputers = @($Snapshot.Computers | Where-Object Enabled).Count
            Gpos = @($Snapshot.Gpos).Count
        }
        Score            = Get-AuditScore $Findings
        Totals           = [pscustomobject]@{ Red = & $count 'Red'; Amber = & $count 'Amber'; Green = & $count 'Green'; NotRun = & $count 'NotRun' }
        Findings         = @($Findings)
        CollectionErrors = @(@($Snapshot.Errors) + @($(if ($Snapshot.GpoError) { "GPO data: $($Snapshot.GpoError)" })) | Where-Object { $_ })
    }
}
