<#
.SYNOPSIS
    Updates an AD computer description using values passed from DeployR.
.DESCRIPTION
    Replaces the existing description with:
    DeployR OSD: <TimeStamp> | Make: <MakeAlias> | Model: <ModelAlias> | Serial: <SerialNumber>
    Generates TimeStamp at execution using server local time in yyyy-MM-dd HH:mm:ss format.
    MakeAlias, ModelAlias and SerialNumber must be supplied.
    Make and Model accept raw DeployR values separately to prevent abbreviated-parameter collisions.
    The executing account needs permission to write description.
    Throws an error if the computer cannot be found or the update fails.
.EXAMPLE
    .\Update-ComputerDescription.ps1 -ComputerName 'PC001' -MakeAlias 'HP' -ModelAlias 'EliteBook 840' -SerialNumber 'ABC123'
#>
param(
    [string]$ComputerName,

    [string]$OU,

    [string]$Make,

    [string]$MakeAlias,

    [string]$Model,

    [string]$ModelAlias,

    [string]$SerialNumber,

    [string]$ADDomainFqdn,

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ExtraArgs
)

$ErrorActionPreference = 'Stop'

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

function ConvertTo-LdapFilterValue {
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
    throw 'No ComputerName provided. Set parameter ComputerName or pass one via task sequence variables.'
}

$descriptionValues = [ordered]@{
    MakeAlias = $MakeAlias
    ModelAlias = $ModelAlias
    SerialNumber = $SerialNumber
}

foreach ($key in @($descriptionValues.Keys)) {
    if ([string]::IsNullOrWhiteSpace($descriptionValues[$key]) -and $extraParams.ContainsKey($key)) {
        $descriptionValues[$key] = $extraParams[$key]
    }
}

$missingValues = @($descriptionValues.Keys | Where-Object { [string]::IsNullOrWhiteSpace($descriptionValues[$_]) })
if ($missingValues.Count -gt 0) {
    throw "Missing description values: $($missingValues -join ', '). AD description was not changed."
}

$TimeStamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$newDescription = "DeployR OSD: $TimeStamp | Make: $($descriptionValues['MakeAlias']) | Model: $($descriptionValues['ModelAlias']) | Serial: $($descriptionValues['SerialNumber'])"

$ComputerName = $ComputerName.Trim()
$shortName = $ComputerName
if ($shortName -like '*.*') {
    $shortName = $shortName.Split('.')[0]
}

if ([string]::IsNullOrWhiteSpace($ADDomainFqdn) -and $extraParams.ContainsKey('ADDomainFqdn')) {
    $ADDomainFqdn = $extraParams['ADDomainFqdn']
}

$ldapPrefix = if ([string]::IsNullOrWhiteSpace($ADDomainFqdn)) { 'LDAP:/' } else { "LDAP://$($ADDomainFqdn.Trim())" }
$rootDse = $null
$directoryEntry = $null
$searcher = $null
$computerEntry = $null

try {
    $rootDse = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList "$ldapPrefix/RootDSE"
    $defaultNamingContext = [string]$rootDse.Properties['defaultNamingContext'].Value
    if ([string]::IsNullOrWhiteSpace($defaultNamingContext)) {
        throw 'Unable to resolve AD default naming context. Pass ADDomainFqdn to specify the domain.'
    }

    $searchBaseDn = if ([string]::IsNullOrWhiteSpace($OU)) { $defaultNamingContext } else { $OU.Trim() }
    $directoryEntry = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList "$ldapPrefix/$searchBaseDn"
    $searcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList $directoryEntry
    $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
    $escapedComputerName = ConvertTo-LdapFilterValue -Value $shortName
    $searcher.Filter = "(&(objectCategory=computer)(|(name=$escapedComputerName)(sAMAccountName=$escapedComputerName`$)))"
    [void]$searcher.PropertiesToLoad.Add('distinguishedname')

    $result = $searcher.FindOne()
    if ($null -eq $result) {
        throw "Computer '$shortName' was not found in Active Directory."
    }

    $computerEntry = $result.GetDirectoryEntry()
    $computerEntry.Properties['description'].Value = $newDescription
    $computerEntry.CommitChanges()
    Write-Information "Updated AD description for '$shortName': $newDescription" -InformationAction Continue
}
finally {
    foreach ($entry in @($computerEntry, $searcher, $directoryEntry, $rootDse)) {
        if ($null -ne $entry) {
            $entry.Dispose()
        }
    }
}

