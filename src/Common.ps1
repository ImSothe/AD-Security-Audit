#Requires -Version 5.1
# Shared helpers. Every date in a snapshot is an ISO 8601 string so that a
# snapshot survives a JSON round trip unchanged on PowerShell 5.1 and 7.

function ConvertTo-AuditDateString {
    param($Value)
    if ($null -eq $Value -or $Value -eq '') { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('o') }
    return [string]$Value
}

function ConvertFrom-AuditDateString {
    param($Value)
    if ($null -eq $Value -or $Value -eq '') { return $null }
    if ($Value -is [datetime]) { return $Value }
    return [datetime]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind)
}

# Whole days between a snapshot date string and the reference date. $null when unknown.
function Get-AuditAgeDays {
    param($Value, [datetime]$ReferenceDate)
    $date = ConvertFrom-AuditDateString $Value
    if ($null -eq $date) { return $null }
    return [int][math]::Floor(($ReferenceDate.ToUniversalTime() - $date.ToUniversalTime()).TotalDays)
}

# Severity: Red (act now), Amber (plan a fix), Green (fine), NotRun (data unavailable).
function New-AuditFinding {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][ValidateSet('Red', 'Amber', 'Green', 'NotRun')][string]$Severity,
        [Parameter(Mandatory)][string]$Summary,
        [string]$Recommendation = '',
        [object[]]$Items = @(),
        [string[]]$Columns = @()
    )
    [pscustomobject]@{
        Id             = $Id
        Category       = $Category
        Title          = $Title
        Severity       = $Severity
        Summary        = $Summary
        Recommendation = $Recommendation
        Count          = @($Items).Count
        Items          = @($Items)
        Columns        = @($Columns)
    }
}

# Output file names include the NetBIOS name read from the snapshot: never let it carry a path.
function Get-SafeFileNamePart {
    param([string]$Value)
    $safe = ([string]$Value -replace '[^A-Za-z0-9_-]', '_').Trim('_')
    if (-not $safe) { return 'DOMAIN' }
    return $safe.Substring(0, [math]::Min(40, $safe.Length))
}

function ConvertTo-HtmlText {
    param($Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}
