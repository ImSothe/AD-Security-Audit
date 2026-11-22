# Fake ActiveDirectory module for the collector and security tests. Every fake cmdlet records its name and
# parameters, so the tests can prove at run time that the collector only reads.
# The fakes are plain functions in the runner's scope; Get-ADAuditSnapshot finds them before the
# real module (which is not needed, and not installed on most dev machines or CI runners).

$script:AdCalls = New-Object System.Collections.Generic.List[object]
$script:MockRoot = 'mock.lab'
$script:FailGroupMember = @()
$script:FailSites = $true
$script:MockSid = 'S-1-5-21-100-200-300'
$script:MockRootSid = 'S-1-5-21-900-800-700'
$sysvol = Join-Path $TempRoot 'sysvol-policies'
$gpoLinked = '{AAAAAAAA-0000-0000-0000-000000000001}'
$gpoNoFolder = '{AAAAAAAA-0000-0000-0000-000000000002}'
$gpoOrphanFolder = '{BBBBBBBB-0000-0000-0000-000000000009}'
New-Item -ItemType Directory -Force -Path (Join-Path $sysvol $gpoLinked), (Join-Path $sysvol $gpoOrphanFolder), (Join-Path $sysvol 'PolicyDefinitions') | Out-Null

function Write-AdCall { param([string]$Name, [hashtable]$Bound)
    $script:AdCalls.Add([pscustomobject]@{ Name = $Name; Params = @{} + $Bound }) }
function Get-MockDate { param([int]$Days) [datetime]::UtcNow.AddDays(-$Days) }

function Get-ADDomain { [CmdletBinding()] param($Server, $Credential, $Identity)
    Write-AdCall 'Get-ADDomain' $PSBoundParameters
    if ($Identity -and $Identity -ne 'mock.lab') {
        return [pscustomobject]@{ DNSRoot = $Identity; DomainSID = [Security.Principal.SecurityIdentifier]$script:MockRootSid }
    }
    [pscustomobject]@{ DNSRoot = 'mock.lab'; NetBIOSName = 'MOCK'; DomainSID = [Security.Principal.SecurityIdentifier]$script:MockSid
        DomainMode = 'Windows2016Domain'; DistinguishedName = 'DC=mock,DC=lab' }
}
function Get-ADForest { [CmdletBinding()] param($Server, $Credential)
    Write-AdCall 'Get-ADForest' $PSBoundParameters
    [pscustomobject]@{ RootDomain = $script:MockRoot; ForestMode = 'Windows2016Forest'; PartitionsContainer = 'CN=Partitions,CN=Configuration,DC=mock,DC=lab' }
}
function Get-ADDefaultDomainPasswordPolicy { [CmdletBinding()] param($Server, $Credential)
    Write-AdCall 'Get-ADDefaultDomainPasswordPolicy' $PSBoundParameters
    [pscustomobject]@{ MinPasswordLength = 12; MaxPasswordAge = [timespan]::FromDays(42); LockoutThreshold = 5
        ComplexityEnabled = $true; PasswordHistoryCount = 24; ReversibleEncryptionEnabled = $false }
}
function Get-ADOptionalFeature { [CmdletBinding()] param($Server, $Credential, $Filter)
    Write-AdCall 'Get-ADOptionalFeature' $PSBoundParameters
    [pscustomobject]@{ Name = 'Recycle Bin Feature'; EnabledScopes = @('CN=Partitions,CN=Configuration,DC=mock,DC=lab') }
}
function Get-ADUser { [CmdletBinding()] param($Server, $Credential, $Filter, $Properties)
    Write-AdCall 'Get-ADUser' $PSBoundParameters
    [pscustomobject]@{ SamAccountName = 'jdoe'; DisplayName = 'Doe, John'; Enabled = $true; SID = [Security.Principal.SecurityIdentifier]"$script:MockSid-1105"
        LastLogonDate = Get-MockDate 3; whenCreated = Get-MockDate 400; PasswordLastSet = Get-MockDate 20; PasswordNeverExpires = $false
        PasswordNotRequired = $false; DoesNotRequirePreAuth = $false; AllowReversiblePasswordEncryption = $false
        TrustedForDelegation = $false; TrustedToAuthForDelegation = $false; AccountNotDelegated = $false
        servicePrincipalName = @('HTTP/app.mock.lab'); adminCount = $null; 'msDS-AllowedToDelegateTo' = @()
        LockedOut = $false; AccountExpirationDate = $null
        MemberOf = @('CN=Ventas\, Madrid,OU=Groups,DC=mock,DC=lab', 'CN=Admins. del dominio,CN=Users,DC=mock,DC=lab')
        DistinguishedName = 'CN=Doe\, John,OU=Users,DC=mock,DC=lab'
        # Secrets a careless collector could leak; they must never reach the snapshot.
        'ms-Mcs-AdmPwd' = 'LAPS-SECRET-123'; unicodePwd = 'HASH-SECRET-456' }
    [pscustomobject]@{ SamAccountName = 'krbtgt'; DisplayName = $null; Enabled = $false; SID = [Security.Principal.SecurityIdentifier]"$script:MockSid-502"
        LastLogonDate = $null; whenCreated = Get-MockDate 900; PasswordLastSet = Get-MockDate 100; PasswordNeverExpires = $false
        PasswordNotRequired = $false; DoesNotRequirePreAuth = $false; AllowReversiblePasswordEncryption = $false
        TrustedForDelegation = $false; TrustedToAuthForDelegation = $false; AccountNotDelegated = $false
        servicePrincipalName = @('kadmin/changepw'); adminCount = 1; 'msDS-AllowedToDelegateTo' = $null
        LockedOut = $false; AccountExpirationDate = $null; MemberOf = @(); DistinguishedName = 'CN=krbtgt,CN=Users,DC=mock,DC=lab' }
}
function Get-ADComputer { [CmdletBinding()] param($Server, $Credential, $Filter, $Properties)
    Write-AdCall 'Get-ADComputer' $PSBoundParameters
    $mk = { param($name, $pgid, $rbcd, $os)
        [pscustomobject]@{ Name = $name; Enabled = $true; OperatingSystem = $os; OperatingSystemVersion = '10.0 (20348)'
            LastLogonDate = Get-MockDate 1; whenCreated = Get-MockDate 300; PrimaryGroupID = $pgid
            TrustedForDelegation = ($pgid -ne 515); TrustedToAuthForDelegation = $false; 'msDS-AllowedToDelegateTo' = $null
            'msDS-AllowedToActOnBehalfOfOtherIdentity' = $rbcd; DistinguishedName = "CN=$name,DC=mock,DC=lab"
            'ms-Mcs-AdmPwd' = 'LAPS-SECRET-789' } }
    & $mk 'DC1' 516 $null 'Windows Server 2022 Standard'
    & $mk 'RODC1' 521 $null 'Windows Server 2022 Standard'
    & $mk 'WS1' 515 ([byte[]](1, 2, 3)) 'Windows 11 Pro'
}
function Get-ADGroup { [CmdletBinding()] param($Server, $Credential, $Identity)
    Write-AdCall 'Get-ADGroup' $PSBoundParameters
    if ($Identity -like '*-526' -or $Identity -like '*-527') { throw "Cannot find an object with identity: '$Identity'" }
    $names = @{ '512' = 'Admins. del dominio'; '519' = 'Administradores de empresas'; '518' = 'Administradores de esquema'; '544' = 'Administradores' }
    $rid = ($Identity -split '-')[-1]
    [pscustomobject]@{ Name = if ($names[$rid]) { $names[$rid] } else { "Group-$rid" } }
}
function Get-ADGroupMember { [CmdletBinding()] param($Server, $Credential, $Identity, [switch]$Recursive)
    Write-AdCall 'Get-ADGroupMember' $PSBoundParameters
    foreach ($bad in $script:FailGroupMember) { if ($Identity -like "*-$bad") { throw 'The server was unable to process the request' } }
    if ($Identity -like '*-512' -or $Identity -eq 'S-1-5-32-544') {
        [pscustomobject]@{ SamAccountName = 'jdoe'; objectClass = 'user'; SID = [Security.Principal.SecurityIdentifier]"$script:MockSid-1105" }
        [pscustomobject]@{ SamAccountName = 'SRV-SVC$'; objectClass = 'computer'; SID = [Security.Principal.SecurityIdentifier]"$script:MockSid-1200" }
    }
}
function Get-ADObject { [CmdletBinding()] param($Server, $Credential, $SearchBase, $SearchScope, $LDAPFilter, $Properties)
    Write-AdCall 'Get-ADObject' $PSBoundParameters
    if ($SearchBase -like 'CN=Sites,*') {
        if ($script:FailSites) { throw 'Access to the sites container is denied' }
        return [pscustomobject]@{ gPLink = "[LDAP://cn=$gpoLinked,cn=policies,cn=system,DC=mock,DC=lab;0]" }
    }
    if ($SearchBase -like 'CN=Policies,*') {
        $v = { param($user, $computer) ($user -shl 16) + $computer }
        return @(
            [pscustomobject]@{ Name = $gpoLinked.ToLowerInvariant(); displayName = 'Linked'; flags = 0; versionNumber = (& $v 3 7)
                gPCFileSysPath = (Join-Path $sysvol $gpoLinked); whenChanged = Get-MockDate 10 }
            [pscustomobject]@{ Name = $gpoNoFolder; displayName = 'No folder'; flags = 3; versionNumber = 0
                gPCFileSysPath = (Join-Path $sysvol $gpoNoFolder); whenChanged = Get-MockDate 10 }
        )
    }
    # gPLink holders in the domain: a domain head link (enabled + enforced), an OU link in lower case
    # (enabled) and a disabled link to the same GPO.
    [pscustomobject]@{ gPLink = "[LDAP://cn=$gpoLinked,cn=policies,cn=system,DC=mock,DC=lab;2]" }
    [pscustomobject]@{ gPLink = "[LDAP://CN=$($gpoLinked.ToLowerInvariant()),CN=Policies,CN=System,DC=mock,DC=lab;0][LDAP://cn=$gpoNoFolder,cn=policies,cn=system,DC=mock,DC=lab;1]" }
}

function Invoke-MockCollect { param([hashtable]$Extra = @{})
    $script:AdCalls.Clear()
    Get-ADAuditSnapshot -PoliciesPath $sysvol @Extra
}
