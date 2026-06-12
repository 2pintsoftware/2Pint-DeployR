<#
.SYNOPSIS
Looks up an AD computer object and returns DeployR task sequence variables.

.DESCRIPTION
This server-side script accepts a computer name, queries Active Directory,
and returns name/value objects that DeployR can inject as task sequence variables.

.NOTES
Date Created: 2026-06-12
Created By: Gary Blok
#>

param(
    [string]$ComputerName,

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ExtraArgs
)

$ErrorActionPreference = 'Stop'

# Helper to return DeployR-compatible task sequence variable objects.
function New-DeployRVariable {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [AllowNull()]
        [object]$Value
    )

    [PSCustomObject]@{
        name  = $Name
        value = if ($null -eq $Value) { '' } else { [string]$Value }
    }
}

# Parse extra task sequence arguments into a key/value hashtable.
function ConvertTo-ExtraParams {
    param(
        [string[]]$Arguments
    )

    $paramsTable = @{}
    if (-not $Arguments -or $Arguments.Count -eq 0) {
        return $paramsTable
    }

    for ($i = 0; $i -lt $Arguments.Count; $i += 2) {
        $key = $Arguments[$i].TrimStart('-')
        $value = ''

        if (($i + 1) -lt $Arguments.Count) {
            $value = $Arguments[$i + 1]
        }

        $paramsTable[$key] = $value
    }

    return $paramsTable
}

function Escape-LdapFilterValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    $escaped = $Value
    $escaped = $escaped.Replace('\', '\5c')
    $escaped = $escaped.Replace('*', '\2a')
    $escaped = $escaped.Replace('(', '\28')
    $escaped = $escaped.Replace(')', '\29')
    $escaped = $escaped.Replace([string][char]0, '\00')
    return $escaped
}

function Get-LdapSingleValue {
    param(
        [Parameter(Mandatory = $true)]
        [System.DirectoryServices.SearchResult]$SearchResult,
        [Parameter(Mandatory = $true)]
        [string]$PropertyName
    )

    if (-not $SearchResult.Properties.Contains($PropertyName)) {
        return $null
    }

    $values = $SearchResult.Properties[$PropertyName]
    if (-not $values -or $values.Count -eq 0) {
        return $null
    }

    return $values[0]
}

function Convert-FileTimeToDateTime {
    param(
        [object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }

    try {
        $fileTime = [int64]$Value
        if ($fileTime -le 0) {
            return $null
        }

        return [DateTime]::FromFileTimeUtc($fileTime).ToLocalTime()
    }
    catch {
        return $null
    }
}

$extraParams = ConvertTo-ExtraParams -Arguments $ExtraArgs

if ([string]::IsNullOrWhiteSpace($ComputerName)) {
    $candidateKeys = @('ComputerName', 'OSDComputerName', '_SMSTSMachineName', 'MachineName')
    foreach ($key in $candidateKeys) {
        if ($extraParams.ContainsKey($key) -and -not [string]::IsNullOrWhiteSpace($extraParams[$key])) {
            $ComputerName = $extraParams[$key]
            break
        }
    }
}

if ([string]::IsNullOrWhiteSpace($ComputerName)) {
    Write-Warning 'No ComputerName provided. Set parameter ComputerName or pass one via task sequence variables.'

    New-DeployRVariable -Name 'ADComputerExists' -Value 'False'
    New-DeployRVariable -Name 'ADLookupError' -Value 'ComputerName was not provided.'
    return
}

$ComputerName = $ComputerName.Trim()
Write-Information "Received ComputerName: $ComputerName" -InformationAction Continue

$shortName = $ComputerName
if ($shortName -like '*.*') {
    $shortName = $shortName.Split('.')[0]
}

try {
    # Resolve LDAP search base with fallback for local-account contexts.
    $resolvedDomainFqdn = ''
    $defaultNamingContext = ''

    $rootDse = [ADSI]'LDAP://RootDSE'
    $defaultNamingContext = [string]$rootDse.defaultNamingContext

    if ([string]::IsNullOrWhiteSpace($defaultNamingContext)) {
        if ($extraParams.ContainsKey('ADDomainFqdn') -and -not [string]::IsNullOrWhiteSpace($extraParams['ADDomainFqdn'])) {
            $resolvedDomainFqdn = [string]$extraParams['ADDomainFqdn']
        }
        else {
            try {
                $resolvedDomainFqdn = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Name
            }
            catch {
                $resolvedDomainFqdn = ''
            }
        }

        if (-not [string]::IsNullOrWhiteSpace($resolvedDomainFqdn)) {
            $rootDse = [ADSI]("LDAP://$resolvedDomainFqdn/RootDSE")
            $defaultNamingContext = [string]$rootDse.defaultNamingContext
        }
    }

    if ([string]::IsNullOrWhiteSpace($defaultNamingContext)) {
        throw 'Unable to resolve AD default naming context. If running under a local account, pass ADDomainFqdn as an extra parameter.'
    }

    $searchBase = if ([string]::IsNullOrWhiteSpace($resolvedDomainFqdn)) {
        "LDAP://$defaultNamingContext"
    }
    else {
        "LDAP://$resolvedDomainFqdn/$defaultNamingContext"
    }

    $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry($searchBase)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)
    $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
    $searcher.PageSize = 1000

    $escapedComputerName = Escape-LdapFilterValue -Value $shortName
    $searcher.Filter = "(&(objectCategory=computer)(|(name=$escapedComputerName)(sAMAccountName=$escapedComputerName`$)))"

    $propertiesToLoad = @(
        'name',
        'samaccountname',
        'distinguishedname',
        'dnshostname',
        'description',
        'managedby',
        'whencreated',
        'lastlogontimestamp',
        'operatingsystem',
        'operatingsystemversion',
        'canonicalname',
        'useraccountcontrol'
    )

    foreach ($prop in $propertiesToLoad) {
        [void]$searcher.PropertiesToLoad.Add($prop)
    }

    $result = $searcher.FindOne()

    if ($null -eq $result) {
        Write-Warning "Computer '$shortName' was not found in Active Directory."

        New-DeployRVariable -Name 'ADComputerQueryName' -Value $ComputerName
        New-DeployRVariable -Name 'ADComputerExists' -Value 'False'
        New-DeployRVariable -Name 'ADLookupError' -Value 'Computer object not found in AD.'
        return
    }

    $adName = Get-LdapSingleValue -SearchResult $result -PropertyName 'name'
    $samAccountName = Get-LdapSingleValue -SearchResult $result -PropertyName 'samaccountname'
    $distinguishedName = Get-LdapSingleValue -SearchResult $result -PropertyName 'distinguishedname'
    $dnsHostName = Get-LdapSingleValue -SearchResult $result -PropertyName 'dnshostname'
    $description = Get-LdapSingleValue -SearchResult $result -PropertyName 'description'
    $managedByDn = Get-LdapSingleValue -SearchResult $result -PropertyName 'managedby'
    $whenCreated = Get-LdapSingleValue -SearchResult $result -PropertyName 'whencreated'
    $lastLogonTimestampRaw = Get-LdapSingleValue -SearchResult $result -PropertyName 'lastlogontimestamp'
    $operatingSystem = Get-LdapSingleValue -SearchResult $result -PropertyName 'operatingsystem'
    $operatingSystemVersion = Get-LdapSingleValue -SearchResult $result -PropertyName 'operatingsystemversion'
    $canonicalName = Get-LdapSingleValue -SearchResult $result -PropertyName 'canonicalname'
    $userAccountControl = Get-LdapSingleValue -SearchResult $result -PropertyName 'useraccountcontrol'

    $parentDn = ''
    $ouPath = ''
    if ($distinguishedName -and $distinguishedName -match '^CN=[^,]+,(.+)$') {
        $parentDn = $matches[1]
        $ouSegments = @($parentDn.Split(',') | Where-Object { $_ -like 'OU=*' } | ForEach-Object { $_.Substring(3) })
        if ($ouSegments.Count -gt 0) {
            $ouPath = ($ouSegments -join '/')
        }
    }

    $managedBy = ''
    if (-not [string]::IsNullOrWhiteSpace($managedByDn)) {
        try {
            $managedByPath = if ([string]::IsNullOrWhiteSpace($resolvedDomainFqdn)) { "LDAP://$managedByDn" } else { "LDAP://$resolvedDomainFqdn/$managedByDn" }
            $managedByEntry = New-Object System.DirectoryServices.DirectoryEntry($managedByPath)
            $managedBy = [string]$managedByEntry.Properties['displayName'].Value
            if ([string]::IsNullOrWhiteSpace($managedBy)) {
                $managedBy = [string]$managedByEntry.Properties['name'].Value
            }
            if ([string]::IsNullOrWhiteSpace($managedBy)) {
                $managedBy = $managedByDn
            }
        }
        catch {
            $managedBy = $managedByDn
            Write-Warning "ManagedBy object lookup failed for '$managedByDn'."
        }
    }

    $objectOwner = ''
    try {
        $computerPath = if ([string]::IsNullOrWhiteSpace($resolvedDomainFqdn)) { "LDAP://$distinguishedName" } else { "LDAP://$resolvedDomainFqdn/$distinguishedName" }
        $computerEntry = New-Object System.DirectoryServices.DirectoryEntry($computerPath)
        $objectOwner = $computerEntry.ObjectSecurity.GetOwner([System.Security.Principal.NTAccount]).Value
    }
    catch {
        Write-Warning "Unable to read AD object owner for '$distinguishedName'."
    }

    $enabled = $true
    if ($null -ne $userAccountControl) {
        $enabled = (([int]$userAccountControl -band 2) -eq 0)
    }

    $lastLogonDate = Convert-FileTimeToDateTime -Value $lastLogonTimestampRaw

    Write-Information "Computer '$shortName' found in AD. Returning variables to DeployR." -InformationAction Continue

    New-DeployRVariable -Name 'ADComputerQueryName' -Value $ComputerName
    New-DeployRVariable -Name 'ADComputerExists' -Value 'TRUE'
    New-DeployRVariable -Name 'ADDomainUsed' -Value $resolvedDomainFqdn
    New-DeployRVariable -Name 'ADComputerName' -Value $adName
    New-DeployRVariable -Name 'ADComputerSamAccountName' -Value $samAccountName
    New-DeployRVariable -Name 'ADComputerEnabled' -Value $enabled
    New-DeployRVariable -Name 'ADComputerDistinguishedName' -Value $distinguishedName
    New-DeployRVariable -Name 'ADComputerParentDN' -Value $parentDn
    New-DeployRVariable -Name 'ADComputerOU' -Value $ouPath
    New-DeployRVariable -Name 'ADComputerCanonicalName' -Value $canonicalName
    New-DeployRVariable -Name 'ADComputerDNSHostName' -Value $dnsHostName
    New-DeployRVariable -Name 'ADComputerDescription' -Value $description
    New-DeployRVariable -Name 'ADComputerManagedByDN' -Value $managedByDn
    New-DeployRVariable -Name 'ADComputerManagedBy' -Value $managedBy
    New-DeployRVariable -Name 'ADComputerObjectOwner' -Value $objectOwner
    New-DeployRVariable -Name 'ADComputerOperatingSystem' -Value $operatingSystem
    New-DeployRVariable -Name 'ADComputerOperatingSystemVersion' -Value $operatingSystemVersion
    New-DeployRVariable -Name 'ADComputerWhenCreated' -Value $whenCreated
    New-DeployRVariable -Name 'ADComputerLastLogonTimestamp' -Value $lastLogonDate
    New-DeployRVariable -Name 'ADLookupError' -Value ''
}
catch {
    Write-Warning "Active Directory lookup failed: $($_.Exception.Message)"

    New-DeployRVariable -Name 'ADComputerQueryName' -Value $ComputerName
    New-DeployRVariable -Name 'ADComputerExists' -Value 'FALSE'
    New-DeployRVariable -Name 'ADLookupError' -Value $_.Exception.Message
}


