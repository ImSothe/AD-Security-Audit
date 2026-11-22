#Requires -Version 5.1
# Builds the fictional "Demo Corp" domain used by -Lab, the tests and the sample report.
# Deterministic: the same reference date always produces the same snapshot.
# Every weakness below is planted on purpose so each check has something to find
# (and a few checks stay green, so the report shows all three colours).

function New-ADAuditLabSnapshot {
    [CmdletBinding()]
    param([datetime]$ReferenceDate = '2026-11-20T09:00:00Z')

    $ref = $ReferenceDate.ToUniversalTime()
    $rng = New-Object System.Random 2026
    $ago = { param($days) if ($null -eq $days) { return $null } $ref.AddDays(-[double]$days).ToString('o') }
    $domainSid = 'S-1-5-21-1111111111-2222222222-3333333333'
    $dn = 'DC=demo-corp,DC=lab'
    $script:labRid = 1100
    $newGuid = {
        $bytes = New-Object byte[] 16; $rng.NextBytes($bytes)
        '{' + ([guid]::new($bytes)).ToString().ToUpperInvariant() + '}'
    }

    $users = New-Object System.Collections.Generic.List[object]
    $addUser = {
        param([hashtable]$p)
        $rid = if ($p.Rid) { $p.Rid } else { $script:labRid++; $script:labRid }
        $o = [ordered]@{
            SamAccountName = $p.Sam; DisplayName = $p.Name; Enabled = $true; Sid = "$domainSid-$rid"
            LastLogonDate = & $ago $p.Logon; WhenCreated = & $ago $p.Created; PasswordLastSet = & $ago $p.Pwd
            PasswordNeverExpires = $false; PasswordNotRequired = $false; DoesNotRequirePreAuth = $false
            ReversibleEncryption = $false; TrustedForDelegation = $false; TrustedToAuthForDelegation = $false
            DelegatesTo = @(); AccountNotDelegated = $false; ServicePrincipalNames = @(); AdminCount = 0
            LockedOut = $false; AccountExpires = $null; MemberOf = @()
            DistinguishedName = "CN=$($p.Name),OU=Users,OU=DemoCorp,$dn"
        }
        foreach ($k in @($p.Keys)) { if ($o.Contains($k)) { $o[$k] = $p[$k] } }
        if ($p.ContainsKey('Expires')) { $o.AccountExpires = & $ago $p.Expires }
        $users.Add([pscustomobject]$o)
    }

    # Built-in accounts
    & $addUser @{ Sam = 'Administrator'; Name = 'Administrator'; Rid = 500; Logon = 3; Created = 2900; Pwd = 910; AdminCount = 1; PasswordNeverExpires = $true }
    & $addUser @{ Sam = 'Guest'; Name = 'Guest'; Rid = 501; Logon = $null; Created = 2900; Pwd = $null; Enabled = $false }
    & $addUser @{ Sam = 'krbtgt'; Name = 'krbtgt'; Rid = 502; Logon = $null; Created = 2900; Pwd = 1460; Enabled = $false; AdminCount = 1 }

    # Ordinary staff: healthy accounts spread across departments
    $first = 'Lucia', 'Javier', 'Marta', 'Carlos', 'Elena', 'David', 'Sara', 'Pablo', 'Laura', 'Diego', 'Ana', 'Sergio',
        'Paula', 'Alberto', 'Irene', 'Raul', 'Nuria', 'Ivan', 'Cristina', 'Hugo', 'Beatriz', 'Adrian', 'Rocio', 'Mario',
        'Teresa', 'Oscar', 'Silvia', 'Ruben', 'Alicia', 'Victor', 'Noelia', 'Jorge', 'Patricia', 'Andres', 'Lorena', 'Fernando'
    $last = 'Garcia', 'Fernandez', 'Lopez', 'Martinez', 'Sanchez', 'Perez', 'Gomez', 'Diaz', 'Moreno', 'Alvarez', 'Romero', 'Navarro'
    $depts = 'Finance', 'Sales', 'Warehouse', 'HR', 'Legal', 'Operations'
    for ($i = 0; $i -lt $first.Count; $i++) {
        $f = $first[$i]; $l = $last[$i % $last.Count]; $dept = $depts[$i % $depts.Count]
        & $addUser @{ Sam = ($f.Substring(0, 1) + $l).ToLowerInvariant(); Name = "$f $l"
            Logon = $rng.Next(0, 21); Created = $rng.Next(200, 2400); Pwd = $rng.Next(1, 85)
            MemberOf = @("GG_$dept", "Share_$dept") }
    }

    # ACC-01 inactive (left without anyone telling IT)
    & $addUser @{ Sam = 'mprieto'; Name = 'Manuel Prieto'; Logon = 412; Created = 1900; Pwd = 450; MemberOf = @('GG_Sales', 'Share_Sales') }
    & $addUser @{ Sam = 'cvidal'; Name = 'Carmen Vidal'; Logon = 188; Created = 1500; Pwd = 230; MemberOf = @('GG_Finance', 'Share_Finance', 'VPN_Users') }
    & $addUser @{ Sam = 'ttorres'; Name = 'Tomas Torres'; Logon = 133; Created = 700; Pwd = 170; MemberOf = @('GG_Warehouse') }
    & $addUser @{ Sam = 'pruiz'; Name = 'Pilar Ruiz'; Logon = 97; Created = 1100; Pwd = 120; MemberOf = @('GG_Legal', 'Share_Legal') }
    # ACC-02 ghost accounts
    & $addUser @{ Sam = 'test.user'; Name = 'Test User'; Logon = $null; Created = 640; Pwd = 640; PasswordNeverExpires = $true }
    & $addUser @{ Sam = 'intern2025'; Name = 'Intern 2025'; Logon = $null; Created = 310; Pwd = 310 }
    & $addUser @{ Sam = 'supplier.erp'; Name = 'ERP Supplier'; Logon = $null; Created = 95; Pwd = 95; MemberOf = @('VPN_Users') }
    # ACC-03 leavers disabled but still in groups
    & $addUser @{ Sam = 'agil'; Name = 'Antonio Gil'; Enabled = $false; Logon = 260; Created = 2100; Pwd = 300; MemberOf = @('GG_Finance', 'Share_Finance', 'VPN_Users', 'ERP_Approvers') }
    & $addUser @{ Sam = 'esantos'; Name = 'Eva Santos'; Enabled = $false; Logon = 150; Created = 900; Pwd = 160; MemberOf = @('GG_HR', 'Share_HR', 'Payroll_RW') }
    & $addUser @{ Sam = 'old.admin'; Name = 'Old Admin'; Enabled = $false; Logon = 700; Created = 2600; Pwd = 800; AdminCount = 1; MemberOf = @('Domain Admins') }
    & $addUser @{ Sam = 'rcastro'; Name = 'Ramon Castro'; Enabled = $false; Logon = 400; Created = 1300; Pwd = 420 }
    # ACC-05 empty password allowed, ACC-07 locked out / expired contract
    & $addUser @{ Sam = 'reception'; Name = 'Reception Desk'; Logon = 1; Created = 1800; Pwd = 1700; PasswordNotRequired = $true; PasswordNeverExpires = $true }
    & $addUser @{ Sam = 'mlopez2'; Name = 'Miguel Lopez'; Logon = 2; Created = 600; Pwd = 40; LockedOut = $true; MemberOf = @('GG_Sales') }
    & $addUser @{ Sam = 'contractor.site'; Name = 'Site Contractor'; Logon = 50; Created = 200; Pwd = 200; Expires = 41; MemberOf = @('VPN_Users') }
    # Service accounts: never-expiring, old, with SPNs, one without pre-auth
    & $addUser @{ Sam = 'svc_sql'; Name = 'SQL Service'; Logon = 0; Created = 2000; Pwd = 1650; PasswordNeverExpires = $true
        ServicePrincipalNames = @('MSSQLSvc/srv-sql01.demo-corp.lab:1433', 'MSSQLSvc/srv-sql01.demo-corp.lab') }
    & $addUser @{ Sam = 'svc_backup'; Name = 'Backup Service'; Logon = 0; Created = 2300; Pwd = 1200; PasswordNeverExpires = $true; AdminCount = 1
        ServicePrincipalNames = @('backup/srv-file01.demo-corp.lab') }
    & $addUser @{ Sam = 'svc_scan'; Name = 'Scanner SMTP'; Logon = 0; Created = 1400; Pwd = 1390; PasswordNeverExpires = $true }
    & $addUser @{ Sam = 'svc_legacy'; Name = 'Legacy App'; Logon = 5; Created = 2500; Pwd = 2400; PasswordNeverExpires = $true; DoesNotRequirePreAuth = $true }
    & $addUser @{ Sam = 'svc_web'; Name = 'Intranet Service'; Logon = 0; Created = 500; Pwd = 30; TrustedToAuthForDelegation = $true
        DelegatesTo = @('HTTP/srv-erp01.demo-corp.lab') }
    # IT staff and admins
    & $addUser @{ Sam = 'it.admin'; Name = 'IT Admin'; Logon = 1; Created = 2700; Pwd = 600; PasswordNeverExpires = $true; AdminCount = 1 }
    & $addUser @{ Sam = 'adm.jmartin'; Name = 'Jose Martin (admin)'; Logon = 4; Created = 400; Pwd = 60; AdminCount = 1; AccountNotDelegated = $true }
    & $addUser @{ Sam = 'ext.itsupport'; Name = 'External IT Support'; Logon = 214; Created = 1600; Pwd = 1500; AdminCount = 1; PasswordNeverExpires = $true }
    & $addUser @{ Sam = 'hd.paula'; Name = 'Paula Helpdesk'; Logon = 0; Created = 350; Pwd = 20; AdminCount = 1; MemberOf = @('IT-Helpdesk') }
    & $addUser @{ Sam = 'hd.carlos'; Name = 'Carlos Helpdesk'; Logon = 1; Created = 800; Pwd = 75; AdminCount = 1; MemberOf = @('IT-Helpdesk') }
    # PRV-06 former admin still flagged
    & $addUser @{ Sam = 'jruiz'; Name = 'Jaime Ruiz'; Logon = 6; Created = 1700; Pwd = 30; AdminCount = 1; MemberOf = @('GG_Operations') }

    $bySam = @{}; foreach ($u in $users) { $bySam[$u.SamAccountName] = $u }
    $member = { param($sam) [pscustomobject]@{ SamAccountName = $sam; ObjectClass = 'user'; Sid = $bySam[$sam].Sid } }
    $daMembers = 'Administrator', 'it.admin', 'adm.jmartin', 'svc_backup', 'ext.itsupport', 'old.admin', 'hd.paula', 'hd.carlos'
    $groupRows = @(
        @{ Key = 'DomainAdmins'; Name = 'Domain Admins'; Rid = 512; Members = $daMembers }
        @{ Key = 'EnterpriseAdmins'; Name = 'Enterprise Admins'; Rid = 519; Members = 'Administrator', 'it.admin' }
        @{ Key = 'SchemaAdmins'; Name = 'Schema Admins'; Rid = 518; Members = @('Administrator') }
        @{ Key = 'Administrators'; Name = 'Administrators'; Sid = 'S-1-5-32-544'; Members = $daMembers }
        @{ Key = 'AccountOperators'; Name = 'Account Operators'; Sid = 'S-1-5-32-548'; Members = @() }
        @{ Key = 'ServerOperators'; Name = 'Server Operators'; Sid = 'S-1-5-32-549'; Members = @() }
        @{ Key = 'PrintOperators'; Name = 'Print Operators'; Sid = 'S-1-5-32-550'; Members = @() }
        @{ Key = 'BackupOperators'; Name = 'Backup Operators'; Sid = 'S-1-5-32-551'; Members = @('svc_backup') }
        @{ Key = 'GroupPolicyCreatorOwners'; Name = 'Group Policy Creator Owners'; Rid = 520; Members = @('Administrator') }
        @{ Key = 'KeyAdmins'; Name = 'Key Admins'; Rid = 526; Members = @() }
        @{ Key = 'EnterpriseKeyAdmins'; Name = 'Enterprise Key Admins'; Rid = 527; Members = @() }
    )
    $groups = foreach ($g in $groupRows) {
        [pscustomobject]@{
            Key = $g.Key; Name = $g.Name
            Sid = if ($g.Sid) { $g.Sid } else { "$domainSid-$($g.Rid)" }
            Members = @($g.Members | ForEach-Object { & $member $_ }); Error = $null
        }
    }

    $computers = New-Object System.Collections.Generic.List[object]
    $addPc = {
        param([hashtable]$p)
        $o = [ordered]@{
            Name = $p.Name; Enabled = $true; OperatingSystem = $p.Os; OperatingSystemVersion = $p.Ver
            LastLogonDate = & $ago $p.Logon; WhenCreated = & $ago $p.Created; IsDomainController = $false
            TrustedForDelegation = $false; TrustedToAuthForDelegation = $false; DelegatesTo = @(); HasRbcd = $false
            DistinguishedName = "CN=$($p.Name),OU=Computers,OU=DemoCorp,$dn"
        }
        foreach ($k in @($p.Keys)) { if ($o.Contains($k)) { $o[$k] = $p[$k] } }
        $computers.Add([pscustomobject]$o)
    }
    & $addPc @{ Name = 'DC01'; Os = 'Windows Server 2019 Standard'; Ver = '10.0 (17763)'; Logon = 0; Created = 2900; IsDomainController = $true; TrustedForDelegation = $true }
    & $addPc @{ Name = 'DC02'; Os = 'Windows Server 2016 Standard'; Ver = '10.0 (14393)'; Logon = 0; Created = 2500; IsDomainController = $true; TrustedForDelegation = $true }
    & $addPc @{ Name = 'SRV-FILE01'; Os = 'Windows Server 2019 Standard'; Ver = '10.0 (17763)'; Logon = 1; Created = 2100 }
    & $addPc @{ Name = 'SRV-SQL01'; Os = 'Windows Server 2016 Standard'; Ver = '10.0 (14393)'; Logon = 1; Created = 2000 }
    & $addPc @{ Name = 'SRV-ERP01'; Os = 'Windows Server 2012 R2 Standard'; Ver = '6.3 (9600)'; Logon = 2; Created = 2600; TrustedForDelegation = $true }
    & $addPc @{ Name = 'SRV-PRINT'; Os = 'Windows Server 2008 R2 Standard'; Ver = '6.1 (7601)'; Logon = 301; Created = 3000 }
    & $addPc @{ Name = 'SRV-WEB01'; Os = 'Windows Server 2022 Standard'; Ver = '10.0 (20348)'; Logon = 0; Created = 600; TrustedToAuthForDelegation = $true; DelegatesTo = @('HTTP/srv-erp01.demo-corp.lab') }
    & $addPc @{ Name = 'SRV-APP02'; Os = 'Windows Server 2022 Standard'; Ver = '10.0 (20348)'; Logon = 0; Created = 300; HasRbcd = $true }
    for ($i = 1; $i -le 34; $i++) {
        $name = 'PC-{0:D3}' -f $i
        if ($i -le 22) { $os = 'Windows 11 Pro'; $ver = '10.0 (26100)' }
        elseif ($i -le 30) { $os = 'Windows 10 Pro'; $ver = '10.0 (19045)' }
        elseif ($i -le 32) { $os = 'Windows 7 Professional'; $ver = '6.1 (7601)' }
        else { $os = 'Windows 11 Pro'; $ver = '10.0 (22631)' }
        $logon = if ($i -in 9, 17, 26, 31, 34) { $rng.Next(100, 600) } else { $rng.Next(0, 10) }
        & $addPc @{ Name = $name; Os = $os; Ver = $ver; Logon = $logon; Created = $rng.Next(150, 2500) }
    }
    & $addPc @{ Name = 'PC-OLDXP'; Os = 'Windows XP Professional'; Ver = '5.1 (2600)'; Logon = 2200; Created = 3500; Enabled = $false }

    $gpo = {
        param($name, $id, $flags, $user, $computer, $links, $disabledLinks, $changed, $sysvol)
        [pscustomobject]@{ Id = $id; DisplayName = $name; Flags = $flags; UserVersion = $user; ComputerVersion = $computer
            EnabledLinks = $links; DisabledLinks = $disabledLinks; WhenChanged = & $ago $changed; SysvolPresent = $sysvol }
    }
    $gpos = @(
        & $gpo 'Default Domain Policy' '{31B2F340-016D-11D2-945F-00C04FB984F9}' 0 0 12 1 0 400 $true
        & $gpo 'Default Domain Controllers Policy' '{6AC1786C-016F-11D2-945F-00C04FB984F9}' 0 0 8 1 0 400 $true
        & $gpo 'Drive mappings' (& $newGuid) 1 14 0 3 0 60 $true
        & $gpo 'Desktop wallpaper' (& $newGuid) 1 3 0 1 0 900 $true
        & $gpo 'Browser hardening' (& $newGuid) 2 0 9 1 0 120 $true
        & $gpo 'WSUS settings' (& $newGuid) 2 0 6 1 0 700 $true
        & $gpo 'BitLocker workstations' (& $newGuid) 2 0 4 1 0 200 $true
        & $gpo 'Firewall baseline' (& $newGuid) 0 0 11 2 0 90 $true
        & $gpo 'GPO test' (& $newGuid) 0 0 0 0 0 1300 $true
        & $gpo 'Old - Printers 2015' (& $newGuid) 3 7 0 0 0 3100 $true
        & $gpo 'Copy of WSUS settings' (& $newGuid) 2 0 6 0 0 1000 $true
        & $gpo 'Kiosk test' (& $newGuid) 3 2 5 0 1 800 $true
        & $gpo 'Legacy logon script' (& $newGuid) 1 4 0 1 0 2000 $false
    )

    [pscustomobject]@{
        SchemaVersion    = 1
        Source           = 'Lab'
        CollectedAt      = $ref.ToString('o')
        Domain           = [pscustomobject]@{
            DnsRoot = 'demo-corp.lab'; NetBIOSName = 'DEMOCORP'; DomainSid = $domainSid
            DomainMode = 'Windows2012R2Domain'; ForestMode = 'Windows2012R2Forest'; ForestRoot = 'demo-corp.lab'
            RecycleBinEnabled = $false
            PasswordPolicy = [pscustomobject]@{ MinPasswordLength = 7; MaxPasswordAgeDays = 90; LockoutThreshold = 0
                ComplexityEnabled = $true; PasswordHistoryCount = 12; ReversibleEncryptionEnabled = $false }
        }
        Users            = $users.ToArray()
        Computers        = $computers.ToArray()
        PrivilegedGroups = @($groups)
        Gpos             = $gpos
        SysvolOrphans    = @(& $newGuid)
        GpoError         = $null
        Errors           = @()
    }
}
