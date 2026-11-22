#Requires -Version 5.1
# Read-only collection from a real domain. Only Get-* cmdlets and Test-Path are used:
# nothing in this file can change Active Directory, SYSVOL or any computer.

# Privileged groups are looked up by well-known SID / RID, never by name, so the audit
# works on localized domains (for example "Admins. del dominio" in Spanish).
$script:PrivilegedGroupDefinitions = @(
    @{ Key = 'DomainAdmins';             Rid = 512;  Scope = 'Domain' }
    @{ Key = 'EnterpriseAdmins';         Rid = 519;  Scope = 'ForestRoot' }
    @{ Key = 'SchemaAdmins';             Rid = 518;  Scope = 'ForestRoot' }
    @{ Key = 'Administrators';           Sid = 'S-1-5-32-544' }
    @{ Key = 'AccountOperators';         Sid = 'S-1-5-32-548' }
    @{ Key = 'ServerOperators';          Sid = 'S-1-5-32-549' }
    @{ Key = 'PrintOperators';           Sid = 'S-1-5-32-550' }
    @{ Key = 'BackupOperators';          Sid = 'S-1-5-32-551' }
    @{ Key = 'GroupPolicyCreatorOwners'; Rid = 520;  Scope = 'Domain' }
    @{ Key = 'KeyAdmins';                Rid = 526;  Scope = 'Domain' }
    @{ Key = 'EnterpriseKeyAdmins';      Rid = 527;  Scope = 'ForestRoot' }
)

function Get-CnFromDn {
    param([string]$DistinguishedName)
    if ($DistinguishedName -match '^CN=((?:\\.|[^,])+)') { return $Matches[1] -replace '\\(.)', '$1' }
    return $DistinguishedName
}

function Get-ADAuditSnapshot {
    [CmdletBinding()]
    param(
        [string]$Server,
        [pscredential]$Credential
    )

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw 'The ActiveDirectory module (RSAT) is not installed. Install RSAT, run on a domain controller, or use -Lab.'
    }
    Import-Module ActiveDirectory -ErrorAction Stop -Verbose:$false

    $ad = @{}
    if ($Server)     { $ad.Server = $Server }
    if ($Credential) { $ad.Credential = $Credential }
    $errors = New-Object System.Collections.Generic.List[string]

    Write-Verbose 'Reading domain and forest'
    $domain = Get-ADDomain @ad
    $forest = Get-ADForest @ad
    $policy = Get-ADDefaultDomainPasswordPolicy @ad

    $recycleBin = $false
    try {
        $feature = Get-ADOptionalFeature @ad -Filter "Name -eq 'Recycle Bin Feature'"
        $recycleBin = @($feature.EnabledScopes).Count -gt 0
    } catch { $errors.Add("Recycle Bin state: $($_.Exception.Message)") }

    Write-Verbose 'Reading users'
    $userProps = 'DisplayName', 'LastLogonDate', 'whenCreated', 'PasswordLastSet', 'PasswordNeverExpires',
        'PasswordNotRequired', 'DoesNotRequirePreAuth', 'AllowReversiblePasswordEncryption',
        'TrustedForDelegation', 'TrustedToAuthForDelegation', 'AccountNotDelegated',
        'servicePrincipalName', 'adminCount', 'msDS-AllowedToDelegateTo', 'LockedOut', 'AccountExpirationDate', 'MemberOf'
    $users = foreach ($u in Get-ADUser @ad -Filter * -Properties $userProps) {
        [pscustomobject]@{
            SamAccountName             = $u.SamAccountName
            DisplayName                = $u.DisplayName
            Enabled                    = [bool]$u.Enabled
            Sid                        = [string]$u.SID
            LastLogonDate              = ConvertTo-AuditDateString $u.LastLogonDate
            WhenCreated                = ConvertTo-AuditDateString $u.whenCreated
            PasswordLastSet            = ConvertTo-AuditDateString $u.PasswordLastSet
            PasswordNeverExpires       = [bool]$u.PasswordNeverExpires
            PasswordNotRequired        = [bool]$u.PasswordNotRequired
            DoesNotRequirePreAuth      = [bool]$u.DoesNotRequirePreAuth
            ReversibleEncryption       = [bool]$u.AllowReversiblePasswordEncryption
            TrustedForDelegation       = [bool]$u.TrustedForDelegation
            TrustedToAuthForDelegation = [bool]$u.TrustedToAuthForDelegation
            DelegatesTo                = @($u.'msDS-AllowedToDelegateTo')
            AccountNotDelegated        = [bool]$u.AccountNotDelegated
            ServicePrincipalNames      = @($u.servicePrincipalName)
            AdminCount                 = [int]$u.adminCount
            LockedOut                  = [bool]$u.LockedOut
            AccountExpires             = ConvertTo-AuditDateString $u.AccountExpirationDate
            MemberOf                   = @($u.MemberOf | ForEach-Object { Get-CnFromDn $_ })
            DistinguishedName          = $u.DistinguishedName
        }
    }

    Write-Verbose 'Reading computers'
    $computerProps = 'OperatingSystem', 'OperatingSystemVersion', 'LastLogonDate', 'whenCreated', 'PrimaryGroupID',
        'TrustedForDelegation', 'TrustedToAuthForDelegation', 'msDS-AllowedToDelegateTo',
        'msDS-AllowedToActOnBehalfOfOtherIdentity'
    $computers = foreach ($c in Get-ADComputer @ad -Filter * -Properties $computerProps) {
        [pscustomobject]@{
            Name                       = $c.Name
            Enabled                    = [bool]$c.Enabled
            OperatingSystem            = $c.OperatingSystem
            OperatingSystemVersion     = $c.OperatingSystemVersion
            LastLogonDate              = ConvertTo-AuditDateString $c.LastLogonDate
            WhenCreated                = ConvertTo-AuditDateString $c.whenCreated
            IsDomainController         = $c.PrimaryGroupID -in 516, 521
            TrustedForDelegation       = [bool]$c.TrustedForDelegation
            TrustedToAuthForDelegation = [bool]$c.TrustedToAuthForDelegation
            DelegatesTo                = @($c.'msDS-AllowedToDelegateTo')
            HasRbcd                    = $null -ne $c.'msDS-AllowedToActOnBehalfOfOtherIdentity'
            DistinguishedName          = $c.DistinguishedName
        }
    }

    Write-Verbose 'Reading privileged groups'
    $rootSid = $domain.DomainSID.Value
    $rootAd = $ad.Clone()
    if ($forest.RootDomain -ne $domain.DNSRoot) {
        try {
            $rootAd.Server = $forest.RootDomain
            $rootSid = (Get-ADDomain @rootAd -Identity $forest.RootDomain).DomainSID.Value
        } catch { $errors.Add("Forest root domain: $($_.Exception.Message)") }
    }
    $groups = foreach ($def in $script:PrivilegedGroupDefinitions) {
        $params = $ad
        if ($def.Sid) { $sid = $def.Sid }
        elseif ($def.Scope -eq 'ForestRoot') { $sid = "$rootSid-$($def.Rid)"; $params = $rootAd }
        else { $sid = "$($domain.DomainSID.Value)-$($def.Rid)" }

        $entry = [ordered]@{ Key = $def.Key; Name = $def.Key; Sid = $sid; Members = @(); Error = $null }
        try {
            $entry.Name = (Get-ADGroup @params -Identity $sid).Name
            $entry.Members = @(Get-ADGroupMember @params -Identity $sid -Recursive | ForEach-Object {
                [pscustomobject]@{ SamAccountName = $_.SamAccountName; ObjectClass = $_.objectClass; Sid = [string]$_.SID }
            })
        } catch {
            # Missing groups (for example Key Admins before 2016 schema) are not an error worth failing for.
            $entry.Error = $_.Exception.Message
        }
        [pscustomobject]$entry
    }

    Write-Verbose 'Reading group policy objects'
    $gpos = @(); $sysvolOrphans = @(); $gpoError = $null
    try {
        $gpoInfo = Get-ADAuditGpoData -Ad $ad -DomainDN $domain.DistinguishedName -DnsRoot $domain.DNSRoot `
            -ConfigurationNC $forest.PartitionsContainer.Replace('CN=Partitions,', '')
        $gpos = $gpoInfo.Gpos
        $sysvolOrphans = $gpoInfo.SysvolOrphans
    } catch { $gpoError = $_.Exception.Message }

    [pscustomobject]@{
        SchemaVersion    = 1
        Source           = 'ActiveDirectory'
        CollectedAt      = ConvertTo-AuditDateString (Get-Date)
        Domain           = [pscustomobject]@{
            DnsRoot           = $domain.DNSRoot
            NetBIOSName       = $domain.NetBIOSName
            DomainSid         = $domain.DomainSID.Value
            DomainMode        = [string]$domain.DomainMode
            ForestMode        = [string]$forest.ForestMode
            ForestRoot        = $forest.RootDomain
            RecycleBinEnabled = $recycleBin
            PasswordPolicy    = [pscustomobject]@{
                MinPasswordLength           = [int]$policy.MinPasswordLength
                MaxPasswordAgeDays          = [int]$policy.MaxPasswordAge.TotalDays
                LockoutThreshold            = [int]$policy.LockoutThreshold
                ComplexityEnabled           = [bool]$policy.ComplexityEnabled
                PasswordHistoryCount        = [int]$policy.PasswordHistoryCount
                ReversibleEncryptionEnabled = [bool]$policy.ReversibleEncryptionEnabled
            }
        }
        Users            = @($users)
        Computers        = @($computers)
        PrivilegedGroups = @($groups)
        Gpos             = @($gpos)
        SysvolOrphans    = @($sysvolOrphans)
        GpoError         = $gpoError
        Errors           = $errors.ToArray()
    }
}

# GPOs are read straight from their AD containers (no GroupPolicy module needed).
# gPLink format: [LDAP://cn={GUID},cn=policies,cn=system,DC=x;FLAG] where FLAG 1 = link disabled.
function Get-ADAuditGpoData {
    param([hashtable]$Ad, [string]$DomainDN, [string]$DnsRoot, [string]$ConfigurationNC)

    $enabledLinks = @{}; $disabledLinks = @{}
    $linkHolders = @(Get-ADObject @Ad -SearchBase $DomainDN -LDAPFilter '(gPLink=*)' -Properties gPLink)
    try {
        $linkHolders += @(Get-ADObject @Ad -SearchBase "CN=Sites,$ConfigurationNC" -LDAPFilter '(gPLink=*)' -Properties gPLink)
    } catch { Write-Verbose "Site links not read: $($_.Exception.Message)" }
    foreach ($holder in $linkHolders) {
        foreach ($m in [regex]::Matches([string]$holder.gPLink, '\[LDAP://cn=(\{[0-9a-fA-F-]{36}\})[^;]*;(\d+)\]')) {
            $guid = $m.Groups[1].Value.ToUpperInvariant()
            $table = if (([int]$m.Groups[2].Value -band 1) -eq 1) { $disabledLinks } else { $enabledLinks }
            $table[$guid] = 1 + [int]$table[$guid]
        }
    }

    $containers = Get-ADObject @Ad -SearchBase "CN=Policies,CN=System,$DomainDN" -SearchScope OneLevel `
        -LDAPFilter '(objectClass=groupPolicyContainer)' -Properties displayName, flags, versionNumber, gPCFileSysPath, whenChanged
    $gpos = foreach ($g in $containers) {
        $guid = $g.Name.ToUpperInvariant()
        $version = [int]$g.versionNumber
        [pscustomobject]@{
            Id              = $guid
            DisplayName     = $g.displayName
            Flags           = [int]$g.flags
            UserVersion     = $version -shr 16
            ComputerVersion = $version -band 0xFFFF
            EnabledLinks    = [int]$enabledLinks[$guid]
            DisabledLinks   = [int]$disabledLinks[$guid]
            WhenChanged     = ConvertTo-AuditDateString $g.whenChanged
            SysvolPresent   = [bool]($g.gPCFileSysPath -and (Test-Path -LiteralPath $g.gPCFileSysPath))
        }
    }

    $known = @($gpos | ForEach-Object Id)
    $policiesPath = "\\$DnsRoot\SYSVOL\$DnsRoot\Policies"
    $orphans = @()
    if (Test-Path -LiteralPath $policiesPath) {
        $orphans = @(Get-ChildItem -LiteralPath $policiesPath -Directory |
            Where-Object { $_.Name -match '^\{[0-9a-fA-F-]{36}\}$' -and $_.Name.ToUpperInvariant() -notin $known } |
            ForEach-Object { $_.Name.ToUpperInvariant() })
    }
    [pscustomobject]@{ Gpos = @($gpos); SysvolOrphans = $orphans }
}
