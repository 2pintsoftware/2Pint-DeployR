<#Tests

USE POWERSHELL 7.  This doesn't work properly from PowerShell 5 Terminal.

- Check if all required applications are installed
- Validate server configuration settings
- Ensure firewall rules are correctly set
- Checks Connectivity for DeployR / StifleR URLs & Ports based on Registry Entries
- Check if BranchCache is enabled
- Check if IIS components are installed
- Check if IIS Virtual Web Directory is Setup
- Check if IIS MIME types added
- Check StifleR Dashboard URLs in Registry & Server Config File
- Check for Certificate set in StifleR & DeployR is same and that the thumbprint exists
- Check if all required services are running
- Check for SQL String Connection based on DeployR Registry
- Check for SQL Permissions of NT AUTHORITY\SYSTEM for sysadmin and dbcreator roles
- Check for SQL Permissions of NT AUTHORITY\SYSTEM for db_owner on all databases
- Check for SQL String Connection based on iPXE WS Registry



Remediation at end will prompt to remediate:
- Missing IIS MIME types
- Missing IIS Virtual Directories
- Missing Windows Components

Change Log
- 2025.10.22 - Updated .NET version to 8.0.21
- 2025.10.29 - Updated PowerShell version to 7.4.13
- 2025.10.29 - Added SQL Permissions checks for NT AUTHORITY\SYSTEM
- 2026.01.26 - Updated script to handle when it finds multiple installed versions of .net Software in registry
- 2026.01.27 - Updated C++ Name to Microsoft Visual C++ v14 Redistributable (x64) to match MS new naming
- 2026.01.27 - Add DeployR Registry Log File
- 2026.02.02 - Added ADK Version Check.
- 2026.02.16 - Updated MIME Type Section to remove errors on duplicates
- 2026.02.17 - Added BackConnectionHostNames registry check
- 2026.02.17 - Added Freespace check on the Volume the DeployR Content is located
- 2026.02.17 - Added check for .net 4.8 on 2019 ServerOS
- 2026.02.24 - Added iPXE & 2PXE Apps to list, noted as OPTIONAL
- 2026.02.24 - Added check for matching certificate thumbprints between iPXE WS and 2PXE if both are installed
- 2026.04.01 - Added Notes around IIS & MIME Type, reminders that it's optional
- 2026.04.16 - Added check for SQL String Connection based on iPXE WS Registry
- 2026.06.26 - Added check for 2Pint API URL https://api.service.2pintsoftware.com
- 2026.06.26 - Updated Min version for PS and .Net to 7.6.3 and 10.0.3 respectively for DeployR 1.3 Pre-Reqs
- 2026.07.02 - Updated to do better match on the ADK
- 2026.07.06 - Updated to disable remediation prompt for MIME Types and IIS Virtual Directories, as they are optional for DeployR.
- 2026.07.28 - Added More info about Certs being used in 2PXE and confirms the CustomCAThumbprint if used
- 2026.07.28 - Modified process to detect if DeployR is Approved in Infra Services
- 2026.07.28 - Added Check for Latest versions of DeployR & StifleR installed based on releases.2pintsoftware.com
- 2026.07.29 - Updated to support iPXE 4.0 Apps (new names & registry locations)
- 2026.07.29 - Updated the check for Infra Services API to provide better feedback if auth is the issue.

To DO
- Add if Statements for SQL Permissions checks and remediation, first check connection string to get instance name
#>

#Ensure Several things are installed, as well as configurations are done to help troubleshoot DeployR installations

#Keep this updated as needed 
$DotNetMinVersion = '10.0.3'
$PowerShellMinVersion = '7.6.3'
$ADKVersion = '10.1.26100.2454'

# Check for Administrator role
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

#PowerShell Table of Pre-Req Applications:
$PreReqApps = @(
[PSCustomObject]@{Title = 'Microsoft .NET Runtime'; Installed = $false ; MinVersion = $DotNetMinVersion; URL = 'https://dotnet.microsoft.com/en-us/download/dotnet/8.0'}
[PSCustomObject]@{Title = 'Microsoft Windows Desktop Runtime'; Installed = $false ; MinVersion = $DotNetMinVersion; URL = 'https://dotnet.microsoft.com/en-us/download/dotnet/8.0'}
[PSCustomObject]@{Title = 'Microsoft ASP.NET Core'; Installed = $false ; MinVersion = $DotNetMinVersion; URL = 'https://dotnet.microsoft.com/en-us/download/dotnet/8.0'}
[PSCustomObject]@{Title = 'Windows Assessment and Deployment Kit'; Installed = $false; MinVersion = $ADKVersion; ExactMatch = $true; URL = 'https://learn.microsoft.com/en-us/windows-hardware/get-started/adk-install'}
[PSCustomObject]@{Title = 'Windows Assessment and Deployment Kit Windows Preinstallation Environment Add-ons'; Installed = $false; MinVersion = $ADKVersion; ExactMatch = $true; URL = 'https://learn.microsoft.com/en-us/windows-hardware/get-started/adk-install'}
[PSCustomObject]@{Title = 'PowerShell 7-x64'; Installed = $false; MinVersion = $PowerShellMinVersion; URL = 'https://aka.ms/powershell-release?tag=lts'}
[PSCustomObject]@{Title = 'Microsoft SQL Server'; Installed = $false; URL = 'https://www.microsoft.com/en-us/download/details.aspx?id=104781'}
[PSCustomObject]@{Title = 'SQL Server Management Studio'; Installed = $false; URL = 'https://learn.microsoft.com/en-us/ssms/install/install'}
[PSCustomObject]@{Title = 'Microsoft Visual C++ v14 Redistributable (x64)'; Installed = $false; URL = 'https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist?view=msvc-170'}
)

$2PintSoftware = @(
[PSCustomObject]@{Title = '2Pint Software DeployR'; Installed = $false; Notes = 'Required for DeployR Servers'; URL = 'https://documentation.2pintsoftware.com/deployr'}
[PSCustomObject]@{Title = '2Pint Software StifleR Server'; Installed = $false; Notes = 'Required for DeployR Servers'; URL = 'https://documentation.2pintsoftware.com/stifler'}
[PSCustomObject]@{Title = '2Pint Software StifleR Dashboards'; Installed = $false; Notes = 'Required for DeployR Servers'; URL = 'https://documentation.2pintsoftware.com/stifler'}
[PSCustomObject]@{Title = '2Pint Software StifleR WmiAgent'; Installed = $false; Notes = 'OPTIONAL for DeployR Servers'; URL = 'https://documentation.2pintsoftware.com/stifler'}
[PSCustomObject]@{Title = '2Pint Software StifleR ActionHub'; Installed = $false; Notes = 'OPTIONAL for DeployR Servers'; URL = 'https://documentation.2pintsoftware.com/stifler'}
[PSCustomObject]@{Title = '2Pint Software iPXE Anywhere WebService'; MatchPatterns = @('2Pint Software iPXE Anywhere WebService','2Pint Software iPXE Anywhere Web Service'); Installed = $false; Notes = 'OPTIONAL for DeployR Servers'; URL = 'https://documentation.2pintsoftware.com/ipxe-ws'}
[PSCustomObject]@{Title = '2Pint Software PXE Server'; MatchPatterns = @('2Pint Software PXE Server','2Pint Software iPXE Anywhere 2PXE Service'); Installed = $false; Notes = 'OPTIONAL for DeployR Servers'; URL = 'https://documentation.2pintsoftware.com/2pxe-server'}
)

#Merge Software Lists
$AllPreReqApps = $PreReqApps + $2PintSoftware

$FirewallRules = @(
[PSCustomObject]@{DisplayName = '2Pint DeployR HTTPS 7281'; Port = 7281; Protocol = 'TCP'}
[PSCustomObject]@{DisplayName = '2Pint DeployR HTTP 7282'; Port = 7282; Protocol = 'TCP'}
[PSCustomObject]@{DisplayName = '2Pint Software StifleR API 9000'; Port = 9000; Protocol = 'TCP'}
[PSCustomObject]@{DisplayName = '2Pint Software StifleR SignalR 1414 TCP'; Port = 1414; Protocol = 'TCP'}
[PSCustomObject]@{DisplayName = '2Pint Software StifleR SignalR 1414 UDP'; Port = 1414; Protocol = 'UDP'}
[PSCustomObject]@{DisplayName = '2Pint iPXE WebService 8051'; Port = 8051; Protocol = 'TCP'}
[PSCustomObject]@{DisplayName = '2Pint iPXE WebService 8052'; Port = 8052; Protocol = 'TCP'}
[PSCustomObject]@{DisplayName = '2Pint 2PXE 8050'; Port = 8050; Protocol = 'TCP'}
)

#region Functions
function Get-UpdatedVersions
{
    $releaseDefinitions = @(
        [pscustomobject]@{
            DisplayName    = 'DeployR'
            Uri            = 'https://releases.2pintsoftware.com/deployr/release.json'
            Pattern        = '(?i)DeployR(?!\s*Community)'
            ExcludePreview  = $false
        },
        [pscustomobject]@{
            DisplayName    = 'DeployR Community'
            Uri            = 'https://releases.2pintsoftware.com/deployrcommunity/release.json'
            Pattern        = '(?i)DeployR\s*Community|DeployRCommunity'
            ExcludePreview  = $false
        },
        [pscustomobject]@{
            DisplayName    = 'StifleR Server'
            Uri            = 'https://releases.2pintsoftware.com/stifler/release.json'
            Pattern        = '(?i)StifleR Server'
            ExcludePreview  = $true
        }
    )

    $installedApps = Get-InstalledApps

    foreach ($definition in $releaseDefinitions) {
        $releaseInfo = Get-ReleaseInfo -Uri $definition.Uri -DisplayName $definition.DisplayName -ExcludePreview:($definition.ExcludePreview)
        $releaseInfoAny = Get-ReleaseInfo -Uri $definition.Uri -DisplayName $definition.DisplayName
        $releasePreview = Get-ReleaseInfo -Uri $definition.Uri -DisplayName $definition.DisplayName -PreviewOnly
        $installedInfo = Get-LatestInstalledApp -InstalledApps $installedApps -Pattern $definition.Pattern -DisplayName $definition.DisplayName

        $latestVersionObject = ConvertTo-VersionObject $releaseInfo.LatestVersion
        $latestAnyVersionObject = ConvertTo-VersionObject $releaseInfoAny.LatestVersion
        $installedVersionObject = $installedInfo.InstalledVersionObject
        $installedChannel = Get-VersionChannel -Version $installedInfo.InstalledVersion
        $latestStableChannel = Get-VersionChannel -Version $releaseInfo.LatestVersion
        $latestAnyChannel = Get-VersionChannel -Version $releaseInfoAny.LatestVersion

        $updateAvailable = $false
        $upgradeAvailable = $false

        if ($installedInfo.Found -and $installedVersionObject -and $latestVersionObject) {
            if ($installedChannel -eq $latestStableChannel) {
                $updateAvailable = $installedVersionObject -lt $latestVersionObject
            }
            elseif ($installedVersionObject -lt $latestVersionObject) {
                $upgradeAvailable = $true
            }
        }

        if ($installedInfo.Found -and $installedVersionObject -and $latestAnyVersionObject) {
            if ($installedVersionObject -lt $latestAnyVersionObject) {
                if ($installedChannel -eq $latestAnyChannel) {
                    $updateAvailable = $true
                }
                else {
                    $upgradeAvailable = $true
                }
            }
        }

        $stableStatus = if (-not $installedInfo.Found) {
            'Not Installed'
        }
        elseif ($installedInfo.Found -and $installedVersionObject -and $latestVersionObject -and $installedVersionObject -lt $latestVersionObject) {
            if ($installedChannel -eq $latestStableChannel) {
                'Update Available'
            }
            else {
                'Upgrade Available'
            }
        }
        else {
            'Up To Date'
        }

        $overallStatus = if (-not $installedInfo.Found) {
            'Not Installed'
        }
        elseif ($updateAvailable -and $upgradeAvailable) {
            'Update and Upgrade Available'
        }
        elseif ($upgradeAvailable) {
            'Upgrade Available'
        }
        elseif ($updateAvailable) {
            'Update Available'
        }
        else {
            'Up To Date'
        }

        [pscustomobject]@{
            Product             = $definition.DisplayName
            Installed           = $installedInfo.Found
            InstalledVersion    = $installedInfo.InstalledVersion
            CurrentChannel      = $installedChannel
            LatestVersion       = $releaseInfo.LatestVersion
            LatestChannel       = $releaseInfo.LatestChannel
            LatestTimestamp     = $releaseInfo.LatestTimestamp
            LatestAvailableVersion = $releaseInfoAny.LatestVersion
            LatestAvailableChannel = $releaseInfoAny.LatestChannel
            LatestAvailableIsPreview = $releaseInfoAny.IsPreview
            PreviewVersion      = $releasePreview.LatestVersion
            PreviewChannel      = $releasePreview.LatestChannel
            UpdateAvailable     = $updateAvailable
            UpgradeAvailable    = $upgradeAvailable
            StableStatus        = $stableStatus
            Status              = $overallStatus
            DownloadUrl         = $releaseInfo.DownloadUrl
            ReleaseArtifact     = $releaseInfo.ArtifactName
            LatestAvailableDownloadUrl = $releaseInfoAny.DownloadUrl
            SourceUrl           = $releaseInfo.SourceUrl
            InstalledDisplayName = $installedInfo.InstalledName
            InstalledInstallDate = $installedInfo.InstallDate
        }
    }
}

function ConvertTo-VersionObject
{
    param(
        [Parameter(Mandatory = $false)]
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $null
    }

    $versionText = [regex]::Match($Value, '\d+(?:\.\d+){1,3}').Value
    if ([string]::IsNullOrWhiteSpace($versionText)) {
        $versionText = $Value.Trim()
    }

    try {
        return [version]$versionText
    }
    catch {
        return $null
    }
}

function Get-VersionChannel
{
    param(
        [Parameter(Mandatory = $false)]
        [string]$Version
    )

    $parsedVersion = ConvertTo-VersionObject -Value $Version
    if (-not $parsedVersion) {
        return $null
    }

    return '{0}.{1}' -f $parsedVersion.Major, $parsedVersion.Minor
}

function Get-ReleaseInfo
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $true)]
        [string]$DisplayName,

        [Parameter(Mandatory = $false)]
        [switch]$ExcludePreview,

        [Parameter(Mandatory = $false)]
        [switch]$PreviewOnly
    )

    $release = Invoke-RestMethod -Uri $Uri -Method Get -ErrorAction Stop
    $channels = foreach ($channel in $release.channels.PSObject.Properties) {
        [pscustomobject]@{
            Channel      = $channel.Name
            Version      = $channel.Value.version
            Timestamp    = $channel.Value.timestamp
            BuildId      = $channel.Value.build_id
            Commit       = $channel.Value.commit
            IsPreview    = ($channel.Name -match 'preview')
            ArtifactName = ($channel.Value.artifacts.PSObject.Properties | Select-Object -First 1).Name
            ArtifactPath = ($channel.Value.artifacts.PSObject.Properties | Select-Object -First 1).Value
            Checksums    = $channel.Value.checksums
        }
    }

    if ($ExcludePreview) {
        $channels = $channels | Where-Object { $_.Channel -notmatch 'preview' }
    }

    if ($PreviewOnly) {
        $channels = $channels | Where-Object { $_.Channel -match 'preview' }
    }

    if (-not $channels) {
        return [pscustomobject]@{
            ProductName     = $DisplayName
            ProductId       = $release.product
            SourceUrl       = $Uri
            LatestVersion   = $null
            LatestChannel   = $null
            LatestTimestamp = $null
            BuildId         = $null
            Commit          = $null
            IsPreview       = $false
            ArtifactName    = $null
            ArtifactPath    = $null
            DownloadUrl     = $null
            Checksums       = $null
        }
    }

    $latestChannel = $channels |
        Where-Object { ConvertTo-VersionObject $_.Version } |
        Sort-Object -Property @{ Expression = { ConvertTo-VersionObject $_.Version } }, @{ Expression = { $_.Timestamp } } -Descending |
        Select-Object -First 1

    if (-not $latestChannel) {
        $latestChannel = $channels | Sort-Object Channel -Descending | Select-Object -First 1
    }

    [pscustomobject]@{
        ProductName     = $DisplayName
        ProductId       = $release.product
        SourceUrl       = $Uri
        LatestVersion   = $latestChannel.Version
        LatestChannel   = $latestChannel.Channel
        LatestTimestamp = $latestChannel.Timestamp
        BuildId         = $latestChannel.BuildId
        Commit          = $latestChannel.Commit
        IsPreview       = $latestChannel.IsPreview
        ArtifactName    = $latestChannel.ArtifactName
        ArtifactPath    = $latestChannel.ArtifactPath
        DownloadUrl     = if ($latestChannel.ArtifactPath) { 'https://releases.2pintsoftware.com/' + $latestChannel.ArtifactPath } else { $null }
        Checksums       = $latestChannel.Checksums
    }
}

function Get-LatestInstalledApp
{
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$InstalledApps,

        [Parameter(Mandatory = $true)]
        [string]$Pattern,

        [Parameter(Mandatory = $true)]
        [string]$DisplayName
    )

    $matches = $InstalledApps | Where-Object { $_.DisplayName -match $Pattern }
    if (-not $matches) {
        return [pscustomobject]@{
            Found                 = $false
            DisplayName           = $DisplayName
            InstalledName         = $null
            InstalledVersion      = $null
            InstalledVersionObject = $null
            InstallDate           = $null
        }
    }

    $candidates = foreach ($match in $matches) {
        [pscustomobject]@{
            DisplayName    = $match.DisplayName
            DisplayVersion = $match.DisplayVersion
            VersionObject  = ConvertTo-VersionObject $match.DisplayVersion
            InstallDate    = $match.InstallDate
            Publisher      = $match.Publisher
            InstallLocation = $match.InstallLocation
        }
    }

    $installed = $candidates |
        Sort-Object -Property @{ Expression = { if ($_.VersionObject) { $_.VersionObject } else { [version]'0.0.0.0' } } }, @{ Expression = { $_.InstallDate } } -Descending |
        Select-Object -First 1

    return [pscustomobject]@{
        Found                 = $true
        DisplayName           = $DisplayName
        InstalledName         = $installed.DisplayName
        InstalledVersion      = $installed.DisplayVersion
        InstalledVersionObject = $installed.VersionObject
        InstallDate           = $installed.InstallDate
    }
}
function Test-CertificateChain {
    <#
    .SYNOPSIS
    Builds and validates the certificate chain for a given certificate (by thumbprint)
    and returns detailed results as a structured object.
    
    .PARAMETER Thumbprint
    The thumbprint of the certificate in the Local Machine\Personal store (without spaces).
    
    .PARAMETER RevocationMode
    How to check revocation (Online, Offline, NoCheck). Default: Online.
    
    .EXAMPLE
    Test-CertificateChain -Thumbprint "a1b2c3d4e5f67890..." | Format-List
    
    .EXAMPLE
    $result = Test-CertificateChain -Thumbprint "..." -RevocationMode Offline
    $result.ChainValid
    $result.ChainElements
    $result.ChainErrors
    #>
    
    [CmdletBinding()]
    param (
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{40}$')]
    [string]$Thumbprint,
    
    [ValidateSet('Online', 'Offline', 'NoCheck')]
    [string]$RevocationMode = 'Online',
    
    [System.Security.Cryptography.X509Certificates.X509VerificationFlags]$VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
    )
    
    # Normalize thumbprint (remove any spaces just in case)
    $Thumbprint = $Thumbprint -replace '\s', ''
    
    # Try to get the certificate
    $certPath = "Cert:\LocalMachine\My\$Thumbprint"
    $cert = Get-Item $certPath -ErrorAction SilentlyContinue
    
    if (-not $cert) {
        return [PSCustomObject]@{
            Thumbprint     = $Thumbprint
            Found          = $false
            ErrorMessage   = "Certificate with thumbprint $Thumbprint not found in LocalMachine\My"
            ChainValid     = $false
            ChainElements  = @()
            ChainErrors    = @()
            RawChain       = $null
        }
    }
    
    # Build the chain
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    
    # Set revocation checking
    switch ($RevocationMode) {
        'Online'  { $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online }
        'Offline' { $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Offline }
        'NoCheck' { $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck }
    }
    
    $chain.ChainPolicy.VerificationFlags = $VerificationFlags
    
    $buildSuccess = $chain.Build($cert)
    
    # Collect chain elements
    $elements = @()
    foreach ($element in $chain.ChainElements) {
        $elements += [PSCustomObject]@{
            Subject    = $element.Certificate.Subject
            Issuer     = $element.Certificate.Issuer
            Thumbprint = $element.Certificate.Thumbprint
            NotAfter   = $element.Certificate.NotAfter
            IsRoot     = $element.Certificate.Subject -eq $element.Certificate.Issuer
            HasPrivateKey = $element.Certificate.HasPrivateKey
        }
    }
    
    # Collect any chain status errors
    $errors = @()
    foreach ($status in $chain.ChainStatus) {
        $errors += [PSCustomObject]@{
            Status           = $status.Status.ToString()
            StatusInformation = $status.StatusInformation
        }
    }
    
    # Final result object
    $result = [PSCustomObject]@{
        Thumbprint       = $cert.Thumbprint
        Subject          = $cert.Subject
        Issuer           = $cert.Issuer
        NotAfter         = $cert.NotAfter
        Found            = $true
        ChainValid       = $buildSuccess
        RevocationMode   = $RevocationMode
        ChainElements    = $elements
        ChainErrors      = $errors
        ChainElementCount = $elements.Count
        RawChain         = $chain
    }
    
    return $result
}
function Get-SqlInstances {
    <#
    .SYNOPSIS
    Finds SQL Server instances installed on the local server.
    
    .DESCRIPTION
    Queries the registry and services to discover SQL Server instances on the local machine.
    Returns information about each instance including name, version, edition, and running status.
    
    .EXAMPLE
    $instances = Get-SqlInstances
    $instances | Format-Table -AutoSize
    
    .OUTPUTS
    PSCustomObject with properties: InstanceName, ServiceName, IsRunning, Version, Edition, InstancePath
    #>
    [CmdletBinding()]
    param()
    
    $instances = @()
    
    try {
        # Check for SQL Server instances in registry
        $regPath = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server'
        
        if (Test-Path $regPath) {
            # Get installed instances
            $installedInstances = Get-ItemProperty -Path "$regPath" -Name InstalledInstances -ErrorAction SilentlyContinue
            
            if ($installedInstances.InstalledInstances) {
                foreach ($instanceName in $installedInstances.InstalledInstances) {
                    # Determine service name
                    if ($instanceName -eq 'MSSQLSERVER') {
                        $serviceName = 'MSSQLSERVER'
                        $displayName = '(Default Instance)'
                        $connectionName = '.'
                    }
                    else {
                        $serviceName = "MSSQL`$$instanceName"
                        $displayName = $instanceName
                        $connectionName = ".\$instanceName"
                    }
                    
                    # Get service status
                    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                    $isRunning = $service.Status -eq 'Running'
                    
                    # Try to get instance details from registry
                    $instanceRegPath = "$regPath\Instance Names\SQL"
                    $instanceKey = Get-ItemProperty -Path $instanceRegPath -Name $instanceName -ErrorAction SilentlyContinue
                    
                    $version = 'Unknown'
                    $edition = 'Unknown'
                    $instancePath = 'Unknown'
                    
                    if ($instanceKey) {
                        $instanceId = $instanceKey.$instanceName
                        $setupPath = "$regPath\$instanceId\Setup"
                        
                        if (Test-Path $setupPath) {
                            $setupInfo = Get-ItemProperty -Path $setupPath -ErrorAction SilentlyContinue
                            $version = $setupInfo.Version
                            $edition = $setupInfo.Edition
                            $instancePath = $setupInfo.SQLPath
                        }
                    }
                    
                    $instances += [PSCustomObject]@{
                        InstanceName = $displayName
                        ConnectionString = $connectionName
                        ServiceName = $serviceName
                        IsRunning = $isRunning
                        Status = if ($service) { $service.Status } else { 'Not Found' }
                        Version = $version
                        Edition = $edition
                        InstancePath = $instancePath
                    }
                }
            }
        }
        
        # If no instances found in registry, check for running SQL services
        if ($instances.Count -eq 0) {
            $sqlServices = Get-Service -Name "MSSQL*" -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^MSSQL\$' -or $_.Name -eq 'MSSQLSERVER' }
            
            foreach ($service in $sqlServices) {
                if ($service.Name -eq 'MSSQLSERVER') {
                    $instanceName = '(Default Instance)'
                    $connectionName = '.'
                }
                else {
                    $instanceName = $service.Name -replace '^MSSQL\$', ''
                    $connectionName = ".\$instanceName"
                }
                
                $instances += [PSCustomObject]@{
                    InstanceName = $instanceName
                    ConnectionString = $connectionName
                    ServiceName = $service.Name
                    IsRunning = $service.Status -eq 'Running'
                    Status = $service.Status
                    Version = 'Unknown'
                    Edition = 'Unknown'
                    InstancePath = 'Unknown'
                }
            }
        }
    }
    catch {
        Write-Error "Failed to enumerate SQL instances $_"
    }
    
    if ($instances.Count -eq 0) {
        Write-Warning "No SQL Server instances found on this server."
    }
    
    return $instances
}

function Get-InstalledApps
{
    if (![Environment]::Is64BitProcess) {
        $regpath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    }
    else {
        $regpath = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
        'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
    }
    
    # Get all installed apps, filter out those without InstallDate, and keep only the latest version of each
    $allApps = Get-ItemProperty $regpath | .{process{if($_.DisplayName -and $_.UninstallString) { $_ } }} | 
    Select DisplayName, Publisher, InstallDate, DisplayVersion, UninstallString, InstallLocation
    
    # Filter out apps without InstallDate and group by DisplayName to keep only the latest
    $filteredApps = $allApps | Where-Object { $_.InstallDate -and $_.InstallDate -ne '' } | 
    Group-Object -Property DisplayName | 
    ForEach-Object {
        $_.Group | Sort-Object -Property InstallDate -Descending | Select-Object -First 1
    }
    
    return $allApps | Sort-Object DisplayName
}

function Set-SqlServerPermissions {
    <#
    .SYNOPSIS
    Configures the permissions and firewall rules for Microsoft SQL Server.
    
    .DESCRIPTION
    This function grants permissions to NT AUTHORITY\SYSTEM (sysadmin and dbcreator roles) 
    and configures the firewall rules for SQL Server default instance and Browser service.
    
    .PARAMETER InstanceName
    The name of the SQL Server instance. Use 'MSSQLSERVER' for the default instance.
    Default is 'SQLEXPRESS'.
    
    .PARAMETER SkipFirewall
    If specified, skips creating firewall rules.
    
    .EXAMPLE
    Set-SqlServerPermissionsAndFirewall -InstanceName 'SQLEXPRESS'
    
    .EXAMPLE
    Set-SqlServerPermissionsAndFirewall -InstanceName 'MSSQLSERVER' -SkipFirewall
    
    .NOTES
    Author: Mike Terrill/2Pint Software
    Date: August 4, 2025
    Version: 25.08.04
    Requires: Administrative privileges, 64-bit Windows, sqlcmd installed
    #>
    [CmdletBinding()]
    param(
    [Parameter()]
    [string]$InstanceName = 'SQLEXPRESS'
    
    )
    
    # Ensure the script runs with elevated privileges
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "This function requires administrative privileges. Please run PowerShell as Administrator."
        return $false
    }
    
    # Determine server instance connection string
    if ($InstanceName -eq 'MSSQLSERVER') {
        $ServerInstance = '.'
    }
    else {
        $ServerInstance = ".\$InstanceName"
    }
    
    # Find sqlcmd.exe
    $SqlCmdPath = $null
    $possiblePaths = @(
    "C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\sqlcmd.exe",
    "C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\180\Tools\Binn\sqlcmd.exe",
    "C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\190\Tools\Binn\sqlcmd.exe",
    "C:\Program Files\Microsoft SQL Server\160\Tools\Binn\sqlcmd.exe",
    "C:\Program Files\Microsoft SQL Server\150\Tools\Binn\sqlcmd.exe",
    "C:\Program Files\Microsoft SQL Server\140\Tools\Binn\sqlcmd.exe"
    )
    
    foreach ($path in $possiblePaths) {
        if (Test-Path $path) {
            $SqlCmdPath = $path
            break
        }
    }
    
    if (-not $SqlCmdPath) {
        Write-Error "sqlcmd.exe not found. Please ensure SQL Server client tools are installed."
        return $false
    }
    
    Write-Host "Using sqlcmd at: $SqlCmdPath" -ForegroundColor Cyan
    
    # Grant NT AUTHORITY\SYSTEM sysadmin and dbcreator rights
    Write-Host "Granting permissions to NT AUTHORITY\SYSTEM on $ServerInstance..." -ForegroundColor Cyan
    
    $TsqlQuery = "IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = 'NT AUTHORITY\SYSTEM') CREATE LOGIN [NT AUTHORITY\SYSTEM] FROM WINDOWS; EXEC sp_addsrvrolemember @loginame = 'NT AUTHORITY\SYSTEM', @rolename = 'sysadmin'; EXEC sp_addsrvrolemember @loginame = 'NT AUTHORITY\SYSTEM', @rolename = 'dbcreator';"
    
    try {
        $Process = Start-Process -FilePath $SqlCmdPath -ArgumentList "-S `"$ServerInstance`" -Q `"$TsqlQuery`"" -NoNewWindow -PassThru -Wait -ErrorAction Stop
        if ($Process.ExitCode -eq 0) {
            Write-Host "Successfully granted sysadmin and dbcreator roles to NT AUTHORITY\SYSTEM on $ServerInstance." -ForegroundColor Green
        }
        else {
            Write-Error "sqlcmd failed with exit code $($Process.ExitCode)."
            return $false
        }
    }
    catch {
        Write-Error "Failed to execute sqlcmd. Error: $($_.Exception.Message)"
        Write-Host "Ensure sqlcmd is installed and the SQL Server instance ($ServerInstance) is running." -ForegroundColor Yellow
        return $false
    }
    
    return $true
}
function Test-Url {
    param (
    [string]$Url
    )
    
    try {
        $request = [System.Net.WebRequest]::Create($Url)
        $request.Method = "HEAD"  # Uses HEAD to check status without downloading content
        $request.Timeout = 5000   # 5 second timeout
        
        $response = $request.GetResponse()
        $status = [int]$response.StatusCode
        
        if ($status -eq 200) {
            #Write-Output "URL is active: $Url"
            return $true
        }
        else {
            #Write-Output "URL responded with status code $status $Url"
            return $false
        }
        $response.Close()
    }
    catch {
        Write-Output "URL is not accessible: $Url - Error: $_"
    }
}
function Test-SQLConnection {
    param(
    [Parameter(Mandatory=$true)]
    [string]$ConnectionString
    )
    
    try {
        $connection = New-Object System.Data.SqlClient.SqlConnection($ConnectionString)
        $connection.Open()
        Write-Host " Connection successful!" -ForegroundColor Green
        $connection.Close()
    }
    catch {
        Write-Host "Connection failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}
function Test-SystemSqlPermissions {
    [CmdletBinding()]
    param(
    [string]
    $Instance = 'localhost\SQLEXPRESS',
    
    [switch]
    $UseInvokeSqlCmd
    )
    
    $result = [PSCustomObject]@{
        Instance    = $Instance
        LoginExists = $false
        IsSysadmin  = $false
        IsDbCreator = $false
        Error       = $null
    }
    
    try {
        # T-SQL to check if NT AUTHORITY\\SYSTEM exists as a login and check role membership
        # Try matching by SID first; if SID is NULL (unlikely), fall back to name search for principals containing 'system'
        $tsql = @"
SET NOCOUNT ON;
DECLARE @loginname sysname = N'NT AUTHORITY\\SYSTEM';
DECLARE @sid varbinary(85) = SUSER_SID(@loginname);
        
;WITH principals AS (
    SELECT principal_id, name, sid
    FROM sys.server_principals
    WHERE (sid IS NOT NULL AND sid = @sid)
    OR ( @sid IS NULL AND LOWER(name) LIKE '%system%')
    OR (LOWER(name) LIKE '%nt authority%system%')
)
SELECT
    CASE WHEN EXISTS(SELECT 1 FROM principals) THEN 1 ELSE 0 END AS LoginExists,
    CASE WHEN EXISTS(
        SELECT 1 FROM principals p
        JOIN sys.server_role_members srm ON p.principal_id = srm.member_principal_id
        JOIN sys.server_principals r ON srm.role_principal_id = r.principal_id
        WHERE r.name = 'sysadmin') THEN 1 ELSE 0 END AS IsSysadmin,
    CASE WHEN EXISTS(
        SELECT 1 FROM principals p
        JOIN sys.server_role_members srm ON p.principal_id = srm.member_principal_id
        JOIN sys.server_principals r ON srm.role_principal_id = r.principal_id
        WHERE r.name = 'dbcreator') THEN 1 ELSE 0 END AS IsDbCreator;
"@
        
        if ($UseInvokeSqlCmd) {
            if (-not (Get-Module -ListAvailable -Name SqlServer)) {
                throw "SqlServer module is not available; install it or run without -UseInvokeSqlCmd."
            }
            $rows = Invoke-Sqlcmd -ServerInstance $Instance -Query $tsql -ErrorAction Stop
            if ($rows) {
                $result.LoginExists = [bool]$rows.LoginExists
                $result.IsSysadmin  = [bool]$rows.IsSysadmin
                $result.IsDbCreator = [bool]$rows.IsDbCreator
            }
        }
        else {
            # Use System.Data.SqlClient to run the query
            $connString = "Server=$Instance;Integrated Security=True;Connection Timeout=5;"
            $conn = New-Object System.Data.SqlClient.SqlConnection $connString
            $cmd = $conn.CreateCommand()
            $cmd.CommandText = $tsql
            $conn.Open()
            $reader = $cmd.ExecuteReader()
            if ($reader.Read()) {
                $loginExists = $reader['LoginExists'] -as [int]
                $isSys = $reader['IsSysadmin'] -as [int]
                $isDb  = $reader['IsDbCreator'] -as [int]
                $result.LoginExists = ($loginExists -eq 1)
                $result.IsSysadmin  = ($isSys -eq 1)
                $result.IsDbCreator = ($isDb -eq 1)
            }
            $reader.Close()
            $conn.Close()
        }
        
    }
    catch {
        $result.Error = $_.Exception.Message
    }
    
    return $result
}
function Test-SqlDatabases {
    [CmdletBinding()]
    param(
    [string]
    $Instance = 'localhost\SQLEXPRESS',
    
    [switch]
    $UseInvokeSqlCmd
    )
    
    $result = [PSCustomObject]@{
        Instance  = $Instance
        Databases = @()
        Error     = $null
    }
    
    try {
        # Get all databases from the instance (excluding system databases)
        $tsql = @"
SET NOCOUNT ON;
SELECT 
    d.name AS DatabaseName,
    d.database_id AS DatabaseId,
    d.create_date AS CreateDate,
    d.state_desc AS State,
    d.recovery_model_desc AS RecoveryModel
FROM sys.databases d
WHERE d.name NOT IN ('master', 'tempdb', 'model', 'msdb')
ORDER BY d.name;
"@
        
        if ($UseInvokeSqlCmd) {
            if (-not (Get-Module -ListAvailable -Name SqlServer)) {
                throw "SqlServer module is not available; install it or run without -UseInvokeSqlCmd."
            }
            $rows = Invoke-Sqlcmd -ServerInstance $Instance -Query $tsql -ErrorAction Stop
            foreach ($row in $rows) {
                $result.Databases += [PSCustomObject]@{
                    Name          = $row.DatabaseName
                    DatabaseId    = $row.DatabaseId
                    CreateDate    = $row.CreateDate
                    State         = $row.State
                    RecoveryModel = $row.RecoveryModel
                }
            }
        }
        else {
            # Use System.Data.SqlClient to run the query
            $connString = "Server=$Instance;Integrated Security=True;Connection Timeout=5;"
            $conn = New-Object System.Data.SqlClient.SqlConnection $connString
            $cmd = $conn.CreateCommand()
            $cmd.CommandText = $tsql
            $conn.Open()
            $reader = $cmd.ExecuteReader()
            while ($reader.Read()) {
                $result.Databases += [PSCustomObject]@{
                    Name          = $reader['DatabaseName'] -as [string]
                    DatabaseId    = $reader['DatabaseId'] -as [int]
                    CreateDate    = $reader['CreateDate'] -as [DateTime]
                    State         = $reader['State'] -as [string]
                    RecoveryModel = $reader['RecoveryModel'] -as [string]
                }
            }
            $reader.Close()
            $conn.Close()
        }
        
    }
    catch {
        $result.Error = $_.Exception.Message
    }
    
    return $result
}
function Test-SystemDatabaseOwnership {
    [CmdletBinding()]
    param(
    [string]
    $Instance = 'localhost\SQLEXPRESS',
    
    [string[]]
    $DatabaseNames = @('DeployR', 'iPXEAnywhere35'),
    
    [switch]
    $UseInvokeSqlCmd
    )
    
    $result = [PSCustomObject]@{
        Instance            = $Instance
        DatabasePermissions = @()
        Error               = $null
    }
    
    try {
        # For each database, check if SYSTEM has db_owner role
        foreach ($dbName in $DatabaseNames) {
            $tsql = @"
SET NOCOUNT ON;
DECLARE @dbName sysname = (SELECT TOP 1 name FROM sys.databases WHERE name = '$dbName');
DECLARE @sql nvarchar(max);
DECLARE @hasDbOwner bit = 0;
DECLARE @loginSid varbinary(85) = SUSER_SID(N'NT AUTHORITY\SYSTEM');
            
IF @dbName IS NOT NULL
BEGIN
    -- Check if the login's SID is mapped to a user in the database and if that user is in db_owner role
    -- This handles cases where the login is mapped as 'dbo' or another username
    SET @sql = N'USE [' + @dbName + N'];
    SELECT @hasDbOwner = CASE 
        WHEN EXISTS(
            SELECT 1 FROM sys.database_principals dp
            JOIN sys.database_role_members drm ON dp.principal_id = drm.member_principal_id
            JOIN sys.database_principals r ON drm.role_principal_id = r.principal_id
            WHERE dp.sid = @loginSid AND r.name = ''db_owner''
        ) THEN 1
        WHEN EXISTS(
            SELECT 1 FROM sys.database_principals dp
            WHERE dp.sid = @loginSid AND dp.name = ''dbo''
        ) THEN 1
        ELSE 0
    END;';
    EXEC sp_executesql @sql, N'@loginSid varbinary(85), @hasDbOwner bit OUTPUT', @loginSid = @loginSid, @hasDbOwner = @hasDbOwner OUTPUT;
END
            
SELECT @dbName AS ActualDbName, CASE WHEN @dbName IS NULL THEN 0 ELSE 1 END AS DbExists, @hasDbOwner AS HasDbOwner;
"@
            
            if ($UseInvokeSqlCmd) {
                if (-not (Get-Module -ListAvailable -Name SqlServer)) {
                    throw "SqlServer module is not available; install it or run without -UseInvokeSqlCmd."
                }
                $row = Invoke-Sqlcmd -ServerInstance $Instance -Query $tsql -ErrorAction Stop
                $result.DatabasePermissions += [PSCustomObject]@{
                    SearchName   = $dbName
                    ActualDbName = $row.ActualDbName
                    DbExists     = [bool]$row.DbExists
                    HasDbOwner   = [bool]$row.HasDbOwner
                }
            }
            else {
                # Use System.Data.SqlClient to run the query
                $connString = "Server=$Instance;Integrated Security=True;Connection Timeout=5;"
                $conn = New-Object System.Data.SqlClient.SqlConnection $connString
                $cmd = $conn.CreateCommand()
                $cmd.CommandText = $tsql
                $conn.Open()
                $reader = $cmd.ExecuteReader()
                if ($reader.Read()) {
                    $result.DatabasePermissions += [PSCustomObject]@{
                        SearchName   = $dbName
                        ActualDbName = if ($reader['ActualDbName'] -isnot [DBNull]) { $reader['ActualDbName'] -as [string] } else { $null }
                        DbExists     = (($reader['DbExists'] -as [int]) -eq 1)
                        HasDbOwner   = (($reader['HasDbOwner'] -as [int]) -eq 1)
                    }
                }
                $reader.Close()
                $conn.Close()
            }
        }
        
    }
    catch {
        $result.Error = $_.Exception.Message
    }
    
    return $result
}

function Set-IISMIMETypes {
    # Set the MIME Types for the iPXE boot files, fonts, etc.
    # v2.0 - accounts for duplicates (e.g. BIN, TTF, WIM)
    
    $mimeTypeList = @(
    @(".",     "application/octet-stream"), # BCD file (with no extension)
    @(".bcd",  "application/octet-stream"), # boot.bcd boot configuration files
    @(".bin",  "application/octet-stream"), # wimboot.bin file
    @(".com",  "application/octet-stream"), # BIOS boot loaders
    @(".efi",  "application/octet-stream"), # EFI loader files
    @(".img",  "application/octet-stream"), # .img file type
    @(".ipxe", "text/plain"),               # .ipxe file
    @(".iso",  "application/octet-stream"), # .iso file type
    @(".kpxe", "application/octet-stream"), # For the UNDIonly version of iPXE
    @(".n12",  "application/octet-stream"), # BIOS loaders without F12 key press
    @(".pxe",  "application/octet-stream"), # For the iPXE BIOS loader files
    @(".sdi",  "application/octet-stream"), # For the boot.sdi file
    @(".ttf",  "application/octet-stream"), # For the boot fonts
    @(".wim",  "application/octet-stream")  # For the winpe images itself
    )
    
    foreach($mimeType in $mimeTypeList)
    {
        #$mimeType[0] - extension; $mimeType[1] - mimeType
        if((Get-WebConfigurationProperty -Filter "system.webServer/staticContent" -Name "Collection").Where({$_.fileExtension -eq $mimeType[0]}).Count)
        {
            # Update the existing setting without destroying everything else :)
            Set-WebConfigurationProperty -Filter "system.webServer/staticContent/mimeMap[@fileExtension='$($mimeType[0])']" -Name "mimeType" -Value $mimeType[1]
        } 
        else 
        {
            # Add a new setting
            Add-WebConfigurationProperty //staticContent -name collection -value @{fileExtension=$mimeType[0];mimeType=$mimeType[1]}
        }
    }
}

function Get-BackConnectionHostNames {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
    $propertyName = "BackConnectionHostNames"
    $RegItem = Get-Item -path $regPath -ErrorAction SilentlyContinue 
    $BackConnectionHostNamesValue = $RegItem.GetValue($propertyName, $null)
    if ($BackConnectionHostNamesValue) {
        return $BackConnectionHostNamesValue
    }
    else {
        return @()
    }
}
function Set-BackConnectionHostNames {
    [CmdletBinding()]
    param(
    [string[]]$HostNames
    )
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
    $propertyName = "BackConnectionHostNames"
    $multiStringData = $HostNames
    Set-ItemProperty -Path $regPath -Name $propertyName -Value $multiStringData -Type MultiString
}
function Get-FQDNFromDashboardConfig {
    $regPath = 'HKLM:\SOFTWARE\2Pint Software\StifleR\Dashboard'
    $propertyName = 'ServiceUrl'
    $RegItem = Get-Item -path $regPath -ErrorAction SilentlyContinue
    if ($RegItem) {
        $serviceUrl = $RegItem.GetValue($propertyName, $null)
        if ($serviceUrl) {
            try {
                $uri = [Uri]$serviceUrl
                return $uri.Host
            }
            catch {
                Write-Warning "ServiceUrl value is not a valid URI: $serviceUrl"
                return $null
            }
        }
        else {
            Write-Warning "ServiceUrl property not found in registry at $regPath"
            return $null
        }
    }
    else {
        Write-Warning "Registry key not found: $regPath"
        return $null
    }
}
#Function to get freespace in GB of Drive the path is pointing to..
#AKA Get-FreeSpaceAvailable -Path d:\DeployR would get the free space for the D volume
function Get-FreeSpaceAvailable {
    param(
    [Parameter(Mandatory=$true)]
    [string]$Path
    )
    
    try {
        $drive = Get-PSDrive -Name (Split-Path -Qualifier $Path).TrimEnd(':') -ErrorAction Stop
        $freeSpaceGB = [math]::Round($drive.Free / 1GB, 2)
        return $freeSpaceGB
    }
    catch {
        Write-Error "Failed to get free space for path '$Path'. Error: $_"
        return $null
    }
}




#endregion
$TempFolder = "$env:USERPROFILE\Downloads\DeployR_TroubleShootingLogs"
if (!(Test-Path -Path $TempFolder)){New-Item -Path $TempFolder -ItemType Directory -Force | Out-Null}
$TranscriptFilePath = "$TempFolder\Check-DeployR_TroubleShooting.log"
$InstalledAppsFilePath = "$TempFolder\InstalledApps.log"
if (Test-Path -Path $TranscriptFilePath) {
    Remove-Item -Path $TranscriptFilePath -Force
}
if (Test-Path -Path $InstalledAppsFilePath) {
    Remove-Item -Path $InstalledAppsFilePath -Force
}    
Start-Transcript -Path $TranscriptFilePath -Force

# Executing Script
Write-Host "=========================================================================" -ForegroundColor DarkGray

#Generate Log of Installed Apps
$LogApps = Get-InstalledApps
$LogApps | ForEach-Object { $_; "----------------------------------------------------" }| Out-File -FilePath $InstalledAppsFilePath -Force -Encoding UTF8

#Get Latest Versions of 2Pint Software
try {
    $LatestVersions = Get-UpdatedVersions
}
catch {
    #Write-Warning "Failed to retrieve latest versions of 2Pint Software. Error: $_"
    #$LatestVersions = @()
}


#Test if Applications are installed
$installedApps = Get-InstalledApps | Where-Object {$_.DisplayName -notmatch " - Shared framework"}
$installedApps = $installedApps | Where-Object {$_.DisplayName -notmatch "SDK"}
$installedApps = $installedApps | Where-Object {$_.DisplayName -notmatch "AppHost"}

#Testing Specific Applications
#$installedApps = Get-InstalledApps | Where-Object {$_.DisplayName -match "PowerShell 7"}

Write-Host "Checking for Pre-Requisite Applications..." -ForegroundColor Cyan
$PreReqAppsStatus = @()
foreach ($app in $AllPreReqApps) {
    $matchPatterns = if ($app.PSObject.Properties.Name -contains 'MatchPatterns' -and $app.MatchPatterns) {
        @($app.MatchPatterns)
    }
    else {
        @($app.Title)
    }

    $found = $installedApps | Where-Object { 
        $isMatch = $false
        foreach ($matchPattern in $matchPatterns) {
            if ($app.ExactMatch) {
                if ($_.DisplayName -eq $matchPattern) {
                    $isMatch = $true
                    break
                }
            }
            else {
                if ($_.DisplayName -match [regex]::Escape($matchPattern) -or $_.DisplayName -like "*$matchPattern*") {
                    $isMatch = $true
                    break
                }
            }
        }
        $isMatch
    }
    
    if ($found) {
        
        if (($found | Select-Object -Unique DisplayName | Measure-Object).Count -gt 1) {
            #Write-Host "Multiple versions of $($app.Title) found:" -ForegroundColor Yellow
            #$found | Select-Object -Unique DisplayName | ForEach-Object { Write-Host " - $($_.DisplayName) Version: $($_.DisplayVersion)" -ForegroundColor Yellow }
            foreach ($appitem in $found) {
                $Version = $appitem.DisplayVersion
                if ($app.Url -match "dotnet"){
                    #Write-Host "Testing $($appitem.DisplayName)"
                    if ($appitem.DisplayName -match "\d+\.\d+\.\d+") {
                        $Version = $matches[0]
                        #Write-Host "   Found .NET version: $Version" -ForegroundColor DarkGray
                    }
                }
                
                $PreReqAppsStatus += [PSCustomObject]@{
                    Title       = $app.Title
                    Installed   = $true
                    URL         = $app.URL
                    Notes       = $app.Notes
                    InstallDate = $appitem.InstallDate
                    Version     = $Version
                    DisplayName = $appitem.DisplayName
                    MinVersion  = $app.MinVersion
                }
            }
        }
        else{
            $found = $found | Select-Object -First 1
            $Version = $found.DisplayVersion
            if ($app.Url -match "dotnet"){
                #Write-Host "Testing $($found.DisplayName)"
                if ($found.DisplayName -match "\d+\.\d+\.\d+") {
                    $Version = $matches[0]
                    #Write-Host "   Found .NET version: $Version" -ForegroundColor DarkGray
                }
            }
            $PreReqAppsStatus += [PSCustomObject]@{
                Title       = $app.Title
                Installed   = $true
                URL         = $app.URL
                Notes       = $app.Notes
                InstallDate = $found.InstallDate
                Version     = $Version
                DisplayName = $found.DisplayName
                MinVersion  = $app.MinVersion
            }
        }
        
        
        New-Variable -Name "Installed_$($app.Title.Replace(' ', '_'))" -Value $true -Scope Global -Force
        
    }
    
    else {
        New-Variable -Name "Installed_$($app.Title.Replace(' ', '_'))" -Value $false -Scope Global -Force
        $PreReqAppsStatus += [PSCustomObject]@{
            Title    = $app.Title
            Installed = $false
            URL      = $app.URL
            Notes    = $app.Notes
        }
    }
}
#Display App Status, Green Arrow next to Installed Apps and Red X next to Missing Apps

# Deduplicate by title, prefer entries with InstallDate and the latest date
$PreReqAppsStatus = $PreReqAppsStatus |
Group-Object -Property Title |
ForEach-Object {
    $withDate = $_.Group | Where-Object { $_.InstallDate }
    if ($withDate) {
        $withDate | Sort-Object {[int]$_.InstallDate} -Descending | Select-Object -First 1
    }
    else {
        $_.Group | Select-Object -First 1
    }
}

foreach ($app in $PreReqAppsStatus) {
    
    if ($app.Installed) {
        if ($app.Title -match "2Pint Software StifleR Server"){
            $2PintStifleRServerInstallDetails = $app
        }
        if ($app.Title -match "2Pint Software DeployR"){
            $2PintDeployRInstallDetails = $app
        }
        if ($app.MinVersion -and $app.Version -and ([version]$app.Version -lt [version]$app.MinVersion)) {
            Write-Host " ✗  $($app.Title)  " -ForegroundColor Red
            Write-Host "   Installed Version: $($app.Version)" -ForegroundColor DarkGray
            Write-Host "   Minimum Required Version: $($app.MinVersion)" -ForegroundColor DarkGray
            if ($app.Notes) {
                Write-Host "   $($app.Notes)" -ForegroundColor DarkGray
            }
        }
        else {
            Write-Host " ✓  $($app.Title)  " -ForegroundColor Green
            Write-Host "   Installed Version: $($app.Version)" -ForegroundColor DarkGray
            Write-Host "   Display Name: $($app.DisplayName)" -ForegroundColor DarkGray
            if ($app.Notes) {
                Write-Host "   $($app.Notes)" -ForegroundColor DarkGray
            }
        }
    }
    else {
        Write-Host " ✗  $($app.Title)" -ForegroundColor Red
        if ($app.Notes) {
            Write-Host " $($app.Notes)" -ForegroundColor Red
        }
    }
}

#Double Check PowerShell is NOT 7.5 or above    
$PowerShellVersionInstalled = $PSVersionTable.PSVersion.ToString()
if ([version]$PowerShellVersionInstalled -le [version]'7.6') {
    Write-Host "=========================================================================" -ForegroundColor Red
    #Write-Host "✗ PowerShell 7.5.X is NOT supported." -ForegroundColor Red
    Write-Host "   Installed Version: $PowerShellVersionInstalled" -ForegroundColor DarkGray
    Write-Host "   Required  Version: $PowerShellMinVersion" -ForegroundColor DarkGray
    Write-Host "=========================================================================" -ForegroundColor Red
}
#Double Check PowerShell is NOT 7.5 or above    
$PowerShellVersionInstalled = $installedApps | Where-Object { $_.DisplayName -match "PowerShell 7" } | Select-Object -First 1 | ForEach-Object {
    if ($_.DisplayVersion -match "\d+\.\d+\.\d+") {
        if ($matches[0] -le [version]'7.6') {
            Write-Host "=========================================================================" -ForegroundColor Red
            #Write-Host "✗ PowerShell 7.5.X is NOT supported." -ForegroundColor Red
            Write-Host "   Installed Version: $PowerShellVersionInstalled" -ForegroundColor DarkGray
            Write-Host "   Required  Version: $PowerShellMinVersion" -ForegroundColor DarkGray
            Write-Host "=========================================================================" -ForegroundColor Red
        }
    }
}
#Double Check DotNET 4.8 on Server 2019
$ServerOSVersion = (Get-CimInstance -Class Win32_OperatingSystem).Version
if ($ServerOSVersion -like "10.0.17763*") {
    # Check .NET Framework versions (4.5 and later) from Registry
    Write-Host "Confirm .NET 4.8 on Server 2019"
    $netfxKey = "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"
    if (Test-Path $netfxKey) {
        $release = (Get-ItemProperty -Path $netfxKey -Name Release -ErrorAction SilentlyContinue).Release
        if ($release) {
            switch ($release) {
                { $_ -ge 533325 } { $version = "4.8.1"; break }
                { $_ -ge 528040 } { $version = "4.8"; break }
                { $_ -ge 461808 } { $version = "4.7.2"; break }
                { $_ -ge 461308 } { $version = "4.7.1"; break }
                { $_ -ge 460798 } { $version = "4.7"; break }
                { $_ -ge 394802 } { $version = "4.6.2"; break }
                { $_ -ge 394254 } { $version = "4.6.1"; break }
                { $_ -ge 393295 } { $version = "4.6"; break }
                { $_ -ge 379893 } { $version = "4.5.2"; break }
                { $_ -ge 378675 } { $version = "4.5.1"; break }
                { $_ -ge 378389 } { $version = "4.5"; break }
                default { $version = "Unknown" }
            }
            Write-Host ".NET Framework Version: $version (Release: $release)"
            if ($release -ge 528040) {
                Write-Host ".NET Framework 4.8 or later is installed." -ForegroundColor Green
            }   
        } else {
            Write-Host ".NET Framework 4.5+ not found." -ForegroundColor Red
        }
    } else {
        Write-Host ".NET Framework registry key not found." -ForegroundColor Red
    }
}
#Double Check ADK = $ADKVersion is installed
$PreReqAppsStatus | Where-Object { $_.Title -match "Windows Assessment and Deployment Kit Windows Preinstallation Environment" } | ForEach-Object {
    if ($_.Installed) {
        if ($_.Version -ne $ADKVersion) {
            Write-Host "=========================================================================" -ForegroundColor Red
            Write-Host "✗ Windows ADK version is different than the required version." -ForegroundColor Red
            Write-Host "   Installed Version: $($_.Version)" -ForegroundColor DarkGray
            Write-Host "   Required  Version: $ADKVersion" -ForegroundColor DarkGray
            Write-Host "   NOTE: $($_.Notes)" -ForegroundColor Yellow
            Write-Host "=========================================================================" -ForegroundColor Red
        }
    }
}


$MissingApps = $PreReqAppsStatus | Where-Object { $_.Installed -eq $false }
if ($MissingApps) {
    Write-Host "=========================================================================" -ForegroundColor DarkGray
    Write-Host "The following Pre-Requisite Applications are NOT installed:" -ForegroundColor Red
    foreach ($app in $MissingApps) {
        $appName = $app.Title -replace 'Installed_', '' -replace '_', ' '
        
        Write-Host " - $appName" -ForegroundColor Yellow
        if ($app.URL) {
            Write-Host "   Download URL: $($app.URL)" -ForegroundColor DarkGray
        }
        if ($app.Notes) {
            Write-Host "   $($app.Notes)" -ForegroundColor Red
        }
        
    }
    Write-Host "Please install the missing applications and re-run this script." -ForegroundColor Yellow
    Write-Host "=========================================================================" -ForegroundColor DarkGray
    #return
}

if ($Installed_2Pint_Software_StifleR_Server){
    #Write The Current Installed Version of StifleR Server 
    Write-Host "StifleR Server Installed Version: $($2PintStifleRServerInstallDetails.Version)" -ForegroundColor Cyan
    if ($LatestVersions){
        $LatestStifleRVersion = $LatestVersions | Where-Object { $_.Product -match "StifleR Server" } | Select-Object -First 1
        if ($LatestStifleRVersion) {
            Write-Host " Latest StifleR Server Version: $($LatestStifleRVersion.LatestAvailableVersion)" -ForegroundColor Cyan
            Write-Host "  Status: $($LatestStifleRVersion.Status)" -ForegroundColor DarkGray
        }
    }
}
if ($Installed_2Pint_Software_DeployR){
    Write-Host "DeployR Installed Version: $($2PintDeployRInstallDetails.Version)" -ForegroundColor Cyan
    if ($LatestVersions){
        $LatestDeployRVersion = $LatestVersions | Where-Object { $_.Product -eq "DeployR" } | Select-Object -First 1
        if ($LatestDeployRVersion) {
            Write-Host " Latest DeployR Version: $($LatestDeployRVersion.LatestAvailableVersion)" -ForegroundColor Cyan
            Write-Host "  Status: $($LatestDeployRVersion.Status)" -ForegroundColor DarkGray
        }
    }
}

Write-Host "=========================================================================" -ForegroundColor DarkGray
Write-Host "Confirming Windows Features for DeployR" -ForegroundColor Cyan
#Confirm Windows Components
$RequiredWindowsComponents = @(
"BranchCache",
"Web-Server",
"Web-Http-Errors",
"Web-Static-Content",
"Web-Digest-Auth",
"Web-Windows-Auth",
"Web-Mgmt-Console"
)

foreach ($Component in $RequiredWindowsComponents) {
    if (Get-WindowsFeature -Name $Component -ErrorAction SilentlyContinue) {
        Write-Host "✓ $Component is installed." -ForegroundColor Green
    } else {
        Write-Host "✗ $Component is NOT installed." -ForegroundColor Red
        $MissingComponents += $Component
    }
}
if ($MissingComponents) {
    Write-Host "The following required components are missing:" -ForegroundColor Red
    Write-Host "Remediation: Run following Command"
    write-host -ForegroundColor darkgray "Add-WindowsFeature Web-Server, Web-Http-Errors, Web-Static-Content, Web-Digest-Auth, Web-Windows-Auth, Web-Mgmt-Console, BranchCache"
    
}

if (Get-WindowsFeature -Name 'Web-Server' -ErrorAction SilentlyContinue) {
    Write-Host "=========================================================================" -ForegroundColor DarkGray
    Write-Host "Confirm IIS MIME Types" -ForegroundColor Cyan
    Write-Host " IIS is OPTIONAL, but if you plan to use IIS to serve the iPXE boot files, then most of these will be needed." -ForegroundColor Yellow
    try {
        Import-Module WebAdministration -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    }
    catch {
        write-host "Catch block executed"
    }
    
    $vdirForMimeCheck = $null
    if (Get-Module -Name WebAdministration) {
        $vdirForMimeCheck = Get-WebVirtualDirectory -Site "Default Web Site" -Name "StifleRDashboard" -ErrorAction SilentlyContinue
    }
    
    if ($vdirForMimeCheck) {
        # Table of required MIME types for iPXE and related boot files
        $RequiredMimeTypes = @(
        [PSCustomObject]@{ Extension = ".bin";  MimeType = "application/octet-stream"; Description = "wimboot.bin file" },
        [PSCustomObject]@{ Extension = ".efi";  MimeType = "application/octet-stream"; Description = "EFI loader files" },
        [PSCustomObject]@{ Extension = ".com";  MimeType = "application/octet-stream"; Description = "BIOS boot loaders" },
        [PSCustomObject]@{ Extension = ".n12";  MimeType = "application/octet-stream"; Description = "BIOS loaders without F12 key press" },
        [PSCustomObject]@{ Extension = ".sdi";  MimeType = "application/octet-stream"; Description = "boot.sdi file" },
        [PSCustomObject]@{ Extension = ".bcd";  MimeType = "application/octet-stream"; Description = "boot.bcd boot configuration files" },
        [PSCustomObject]@{ Extension = ".";     MimeType = "application/octet-stream"; Description = "BCD file (with no extension)" },
        [PSCustomObject]@{ Extension = ".wim";  MimeType = "application/octet-stream"; Description = "winpe images (optional)" },
        [PSCustomObject]@{ Extension = ".pxe";  MimeType = "application/octet-stream"; Description = "iPXE BIOS loader files" },
        [PSCustomObject]@{ Extension = ".kpxe"; MimeType = "application/octet-stream"; Description = "UNDIonly version of iPXE" },
        [PSCustomObject]@{ Extension = ".ttf";  MimeType = "application/octet-stream"; Description = "boot fonts" },
        [PSCustomObject]@{ Extension = ".iso";  MimeType = "application/octet-stream"; Description = ".iso file type" },
        [PSCustomObject]@{ Extension = ".img";  MimeType = "application/octet-stream"; Description = ".img file type" },
        [PSCustomObject]@{ Extension = ".ipxe"; MimeType = "text/plain";                Description = ".ipxe file" }
        )
        
        if (Get-Module -name WebAdministration) {
            $IISMimeTypes = Get-WebConfigurationProperty -Filter /system.webServer/staticContent/mimeMap -Name "fileExtension" -PSPath "IIS:\Sites\Default Web Site"
            # Loop through required MIME types and check if present in IIS
            foreach ($mime in $RequiredMimeTypes) {
                if ($IISMimeTypes.value -contains $mime.Extension) {
                    Write-Host ("✓ IIS MIME type for {0} ({1}) is configured." -f $mime.Extension, $mime.Description) -ForegroundColor Green
                } else {
                    Write-Host ("✗ IIS MIME type for {0} ({1}) is NOT configured." -f $mime.Extension, $mime.Description) -ForegroundColor Red
                    Write-Host "Remediation: Run following Command" -ForegroundColor Yellow
                    Write-Host ("New-WebMimeType -FileExtension '{0}' -MimeType '{1}' -PSPath 'IIS:\Sites\Default Web Site'" -f $mime.Extension, $mime.MimeType) -ForegroundColor DarkGray
                    $IISMimeTypeUpdateRequired = $true
                }
            }
            if ($IISMimeTypeUpdateRequired) {
                write-host -ForegroundColor Magenta "See this Page for details: https://documentation.2pintsoftware.com/2pxe-server/configuration/iis-and-branchcache-setup-and-config"
            }
        }
    }
    else {
        Write-Host "Skipping IIS MIME type checks because StifleRDashboard virtual directory is not present." -ForegroundColor DarkGray
    }
}
#Region Services
Write-Host "=========================================================================" -ForegroundColor DarkGray
Write-Host "Checking for Services..." -ForegroundColor Cyan
#Test Services if App Installed
#Test SQL Express
$SQLInstances = Get-SqlInstances
if ($SQLInstances.Count -eq 0) {
    Write-Host "No SQL Server instances found on this server." -ForegroundColor Red
    $Global:Installed_Microsoft_SQL_Server = $false
} else {
    $SQLServiceName = $SQLInstances.ServiceName
}

if (($Installed_Microsoft_SQL_Server) -and ($SQLServiceName)){
    $SQLService = Get-Service -Name $SQLServiceName
    if ($SQLService.Status -eq 'Running') {
        Write-Host "Microsoft SQL Server service is running." -ForegroundColor Green
        Write-Host "  Display Name: $($SQLService.DisplayName)" -ForegroundColor DarkGray
        Write-Host "  Service Name: $($SQLService.Name)" -ForegroundColor DarkGray
        Write-Host "  Start Type:   $($SQLService.StartType)" -ForegroundColor DarkGray
        $Global:SQLServiceRunning = $true
    }
    else {
        Write-Host "Microsoft SQL Server service is NOT running." -ForegroundColor Red
        Write-Host " Attempting to start service..." -ForegroundColor Yellow
        Start-Service -Name $SQLServiceName -ErrorAction SilentlyContinue
        if ($?) {
            Write-Host "Service started successfully." -ForegroundColor Green
        }
        else {
            Write-Host "Failed to start service." -ForegroundColor Red
        }
        $Global:SQLServiceRunning = $false
    }
}
#Test StifleR Service
if ($Installed_2Pint_Software_StifleR_Server){
    $StifleRService = Get-Service -Name '2Pint Software StifleR Server'
    if ($StifleRService.Status -eq 'Running') {
        Write-Host "2Pint StifleR Server service is running." -ForegroundColor Green
        Write-Host "  Display Name: $($StifleRService.DisplayName)" -ForegroundColor DarkGray
        Write-Host "  Service Name: $($StifleRService.Name)" -ForegroundColor DarkGray
        Write-Host "  Start Type:   $($StifleRService.StartType)" -ForegroundColor DarkGray
        $Global:StifleRServiceRunning = $true
    }
    else {
        Write-Host "WARNING: 2Pint StifleR Server service is NOT running." -ForegroundColor Red
        Write-Host " Attempting to start service..." -ForegroundColor Yellow
        Start-Service -Name '2Pint Software StifleR Server' -ErrorAction SilentlyContinue
        if ($?) {
            Write-Host "Service started successfully." -ForegroundColor Green
            Write-Host " Waiting for service to start additional processes..." -ForegroundColor Yellow
            Start-Sleep -Seconds 5
        }
        else {
            Write-Host "Failed to start service." -ForegroundColor Red
        }
        $Global:StifleRServiceRunning = $false
    }
}
#Test DeployR Service
if ($Installed_2Pint_Software_DeployR){
    
    $DeployRService = Get-Service -Name '2Pint Software DeployR Service'
    if ($DeployRService.Status -eq 'Running') {
        Write-Host "2Pint DeployR service is running." -ForegroundColor Green
        Write-Host "  Display Name: $($DeployRService.DisplayName)" -ForegroundColor DarkGray
        Write-Host "  Service Name: $($DeployRService.Name)" -ForegroundColor DarkGray
        Write-Host "  Start Type:   $($DeployRService.StartType)" -ForegroundColor DarkGray
        $Global:DeployRServiceRunning = $true
    }
    else {
        Write-Host "2Pint DeployR service is NOT running." -ForegroundColor Red
        Write-Host " Attempting to start service..." -ForegroundColor Yellow
        Start-Service -Name '2Pint Software DeployR Service' -ErrorAction SilentlyContinue
        if ($?) {
            Write-Host "Service started successfully." -ForegroundColor Green
        }
        else {
            Write-Host "Failed to start service." -ForegroundColor Red
        }
        $Global:DeployRServiceRunning = $false
    }
}

#endRegion Services

#Confirm StifleR Registry Settings
if ($Installed_2Pint_Software_StifleR_Server){
    Write-Host "=========================================================================" -ForegroundColor DarkGray
    Write-Host "Testing StifleR Registry Settings..." -ForegroundColor Cyan
    $StifleRRegPath = "HKLM:\SOFTWARE\2Pint Software\StifleR\Server\GeneralSettings"
    $StifleRRegData = Get-ItemProperty -Path $StifleRRegPath -ErrorAction SilentlyContinue
    
    #Note, this is no longer used in newer releases
    if ($StifleRRegData -and $StifleRRegData.DeployRUrl) {
        Write-Host "DeployR API URL: $($StifleRRegData.DeployRUrl)" -ForegroundColor Green
    }
    else {
        #Write-Host "DeployR API URL is NOT configured." -ForegroundColor Red
    }
    $StifleRCertThumbprint = $StifleRRegData.WSCertificateThumbprint
    Write-Host "StifleR Using Certificate with Thumbprint: $($StifleRCertThumbprint)" -ForegroundColor Cyan
    #Get Certificate from Local Machine Store that matches
    $AllLocalCerts = Get-ChildItem -Path Cert:\LocalMachine\My
    $CertThumbprint = $AllLocalCerts  | Where-Object { $_.Thumbprint -match $StifleRCertThumbprint }
    if ($CertThumbprint) {
        Write-Host "Found certificate in local store: $($CertThumbprint.Thumbprint)" -ForegroundColor Green
        write-host " DNSNameList:    $($CertThumbprint.DNSNameList -join ', ')" -ForegroundColor DarkGray
        write-host " Subject:        $($CertThumbprint.Subject)" -ForegroundColor DarkGray
        write-host " Issuer:         $($CertThumbprint.Issuer)" -ForegroundColor DarkGray
    }
    else {
        Write-Host "Certificate NOT found." -ForegroundColor Red
    }
    
    #Test the 2Pint Heartbeat URL 'https://api.service.2pintsoftware.com'
    Write-Host "=========================================================================" -ForegroundColor DarkGray
    write-Host "Testing 2Pint Heartbeat URL: https://api.service.2pintsoftware.com" -ForegroundColor Cyan
    write-host "This is used to confirm the StifleR Server can reach the 2Pint Heartbeat service." -ForegroundColor DarkGray
    write-host "This is also used for DeployR Driverpack page and any steps that pull cloud content" -ForegroundColor DarkGray
    try {
        $HeartbeatResponse = Invoke-WebRequest -Uri "https://api.service.2pintsoftware.com" -UseBasicParsing -ErrorAction Stop
        if ($HeartbeatResponse.StatusCode -eq 200) {
            Write-Host "✓ Successfully connected to 2Pint Heartbeat URL." -ForegroundColor Green
            
            # LicenseKeys may be a JSON array string or an array-like value, so normalize it first.
            $licenseKeys = $StifleRRegData.LicenseKeys
            if ($licenseKeys -is [string]) {
                $trimmedLicenseKeys = $licenseKeys.Trim()
                if ($trimmedLicenseKeys.StartsWith('[') -and $trimmedLicenseKeys.EndsWith(']')) {
                    $licenseKeys = $trimmedLicenseKeys | ConvertFrom-Json
                }
                else {
                    $licenseKeys = @($trimmedLicenseKeys)
                }
            }
            elseif ($licenseKeys -isnot [System.Collections.IEnumerable] -or $licenseKeys -is [string]) {
                $licenseKeys = @($licenseKeys)
            }
            
            $prod = $null
            foreach ($licenseKey in @($licenseKeys | Where-Object { $_ })) {
                Write-Host "Testing 2Pint Heartbeat with a license key..." -ForegroundColor DarkGray
                $headers = @{ 
                    "X-API-Key" = [System.Convert]::ToBase64String([System.Security.Cryptography.SHA512]::HashData([System.Text.Encoding]::UTF8.GetBytes($licenseKey)))
                }
                
                try {
                    $prod = Invoke-RestMethod -Uri "https://api.service.2pintsoftware.com/location/ip" -Method Get -Headers $headers -ErrorAction Stop
                    if ($prod) {
                        Write-Host "License key validated successfully." -ForegroundColor Green
                        #$prod
                        break
                    }
                }
                catch {
                    Write-Host "License key failed, trying next one if available..." -ForegroundColor Yellow
                }
            }
            
            if (-not $prod) {
                Write-Host "No valid license key was accepted by the 2Pint Heartbeat service." -ForegroundColor Red
            }
        }
        else {
            Write-Host "✗ Failed to connect to 2Pint Heartbeat URL. Status Code: $($HeartbeatResponse.StatusCode)" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "✗ Error connecting to 2Pint Heartbeat URL: $_" -ForegroundColor Red
    }
    
    
    
    Write-Host "=========================================================================" -ForegroundColor DarkGray
    Write-Host "Checking for StifleRDashboard Web Virtual Directory..." -ForegroundColor Cyan
    
    try {
        $vdir = Get-WebVirtualDirectory -Site "Default Web Site" -Name "StifleRDashboard"
    } catch {
        Write-Host "Error checking for StifleRDashboard Web Virtual Directory: $_" -ForegroundColor Red
    }
    if ($vdir) {
        Write-Host "✓ StifleRDashboard Web Virtual Directory exists in Default Web Site." -ForegroundColor Green
        Write-Host "  Physical Path: $($vdir.PhysicalPath)" -ForegroundColor DarkGray
    } else {
        Write-Host "✗ StifleRDashboard Web Virtual Directory is NOT present in Default Web Site." -ForegroundColor Red
        Write-Host "Remediation: Run the following command:" -ForegroundColor Yellow
        Write-Host "New-WebVirtualDirectory -Site 'Default Web Site' -Name 'StifleRDashboard' -PhysicalPath 'C:\Program Files\2Pint Software\StifleR Dashboards\Dashboard Files'" -ForegroundColor DarkGray
        $IISVirtualDirMissing = $true
    }
    Write-Host ""
    Write-Host "Confirm BackConnectionHostNames for Dashboard access... (prevent authentication loop)" -ForegroundColor Cyan
    $BackConnectionHostNames = Get-BackConnectionHostNames
    if ($BackConnectionHostNames.Count -gt 0) {
        Write-Host "Current BackConnectionHostNames:" -ForegroundColor Green
        foreach ($item in $BackConnectionHostNames) {
            Write-Host " - $item" -ForegroundColor DarkGray
        }
    }
    else {
        Write-Host "No BackConnectionHostNames configured." -ForegroundColor Red
        Write-Host "Remediation: Add the Dashboard URL hostname to the BackConnectionHostNames registry value." -ForegroundColor Yellow
        Write-Host "Example: If Dashboard URL is https://dashboard.contoso.com, add 'dashboard.contoso.com' to BackConnectionHostNames." -ForegroundColor DarkGray
        
        #Offer to do it for them:
        $FQDN = Get-FQDNFromDashboardConfig
        if ($FQDN) {
            write-host "I detected the Dashboard Service URL is configured with hostname: '$FQDN'." -ForegroundColor Green
            Write-Host "I can add '$FQDN' to the BackConnectionHostNames for you." -ForegroundColor Yellow
            $response = Read-Host "Do you want me to add '$FQDN' to BackConnectionHostNames? (Y/N)"
            if ($response -match '^[Yy]') {
                $UpdatedHostNames = $BackConnectionHostNames + $FQDN
                Set-BackConnectionHostNames -HostNames $UpdatedHostNames
                Write-Host "Added '$FQDN' to BackConnectionHostNames." -ForegroundColor Green
            }
            else {
                Write-Host "Please remember to add '$FQDN' to BackConnectionHostNames to prevent authentication issues." -ForegroundColor Yellow
            }
        }
    }
    
    Write-Host "=========================================================================" -ForegroundColor DarkGray
    
    Write-Host "Testing Dashboard Registry Settings for URLs" -ForegroundColor Cyan
    $DashReg = "HKLM:\SOFTWARE\2Pint Software\StifleR\Dashboard"
    $DashRegData = Get-ItemProperty -Path $DashReg -ErrorAction SilentlyContinue
    
    if ($DashRegData -and $DashRegData.HubUrl) {
        if ($($DashRegData.HubUrl) -match "localhost") {
            Write-Host " Hub URL is configured to use localhost." -ForegroundColor Red
        }
        else{
            Write-Host " Hub URL: $($DashRegData.HubUrl)" -ForegroundColor Green
        }
    }
    else {
        Write-Host " Hub URL is NOT configured." -ForegroundColor Red
    }
    
    if ($DashRegData -and $DashRegData.ServiceUrl) {
        if ($($DashRegData.ServiceUrl) -match "localhost") {
            Write-Host " Service URL is configured to use localhost." -ForegroundColor Red
        }
        else{
            Write-Host " Service URL: $($DashRegData.ServiceUrl)" -ForegroundColor Green
        }
    }
    else {
        Write-Host " Service URL is NOT configured." -ForegroundColor Red
    }
    Write-Host "Testing Dashboard Config Settings for URLs" -ForegroundColor Cyan
    if (Test-Path -Path "C:\Program Files\2Pint Software\StifleR Dashboards\Dashboard Files\assets\config\server.json") {
        Write-Host "  Server configuration file exists." -ForegroundColor Green
        $ServerConfigJSON = Get-Content -Path "C:\Program Files\2Pint Software\StifleR Dashboards\Dashboard Files\assets\config\server.json" -Raw | ConvertFrom-Json
        if ($ServerConfigJSON -and $ServerConfigJSON.server.hub) {
            if ($($ServerConfigJSON.server.hub) -match "localhost") {
                Write-Host "Hub URL is configured to use localhost." -ForegroundColor Red
            }
            else{
                Write-Host " Hub URL: $($ServerConfigJSON.server.hub)" -ForegroundColor Green
            }
        }
        else {
            Write-Host " Hub URL is NOT configured." -ForegroundColor Red
        }
        
        if ($ServerConfigJSON -and $ServerConfigJSON.server.controller) {
            if ($($ServerConfigJSON.server.controller) -match "localhost") {
                Write-Host " Service URL is configured to use localhost." -ForegroundColor Red
            }
            else{
                Write-Host " Service URL: $($ServerConfigJSON.server.controller)" -ForegroundColor Green
            }
        }
        else {
            Write-Host " Service URL is NOT configured." -ForegroundColor Red
        }
    }
    else {
        Write-Host " Server configuration file is missing." -ForegroundColor Red
    }
    #Check to ensure Registry Values match Config Values
    if ($DashRegData -and $ServerConfigJSON) {
        if ($DashRegData.HubUrl -ne $ServerConfigJSON.server.hub) {
            Write-Host " Hub URL in Registry does not match Config file." -ForegroundColor Red
        }
        else {
            Write-Host " Hub URL in Registry matches Config file." -ForegroundColor Green
        }
        if ($DashRegData.ServiceUrl -ne $ServerConfigJSON.server.controller) {
            Write-Host " Service URL in Registry does not match Config file." -ForegroundColor Red
        }
        else {
            Write-Host " Service URL in Registry matches Config file." -ForegroundColor Green
        }
    }
}
Start-Sleep -Seconds 2

#Confirm DeployR Registry Settings
if ($Installed_2Pint_Software_DeployR){
    Write-Host "=========================================================================" -ForegroundColor DarkGray
    
    $RegPath = "HKLM:\SOFTWARE\2Pint Software\DeployR\GeneralSettings"
    $DeployRRegData = Get-ItemProperty -Path $RegPath -ErrorAction SilentlyContinue
    write-host "DeployR Information from Registry:" -ForegroundColor Cyan
    if ($DeployRRegData){
        #Export to file for logging
        $DeployRRegData | Out-File -FilePath "$TempFolder\DeployR_Registry_Info.log" -Force -Encoding UTF8
        $DeployRCon
    }
    #Test ServiceURL against Dashboard
    if ($DeployRRegData -and $DeployRRegData.StifleRServerApiUrl) {
        Write-Host " DeployR StifleRServerApiUrl: $($DeployRRegData.StifleRServerApiUrl)" -ForegroundColor Green
        if (($DeployRRegData.StifleRServerApiUrl) -and ($DeployRRegData.StifleRServerApiUrl)){
            if (($DeployRRegData.StifleRServerApiUrl) -match ($DeployRRegData.StifleRServerApiUrl)){
                Write-Host " StifleR API URI matches in both Dashboard Registry & DeployR Registry" -foregroundColor Green
                
                #Check if Infrasturcture Service is registered
                $InfrastructureServiceUri = "$($DeployRRegData.StifleRServerApiUrl)/api/infrastructureService"
                $Result = $null
                $AuthPromptDetected = $false

                try {
                    $Result = Invoke-RestMethod $InfrastructureServiceUri -UseDefaultCredentials -ErrorAction Stop
                }
                catch {
                    $errorMessage = $_.Exception.Message
                    if ($errorMessage -match '401|403|Unauthorized|Forbidden') {
                        Write-Host "  StifleR API authentication failed for infrastructure service endpoint." -ForegroundColor Red
                        Write-Host "  The current user/computer credentials were not accepted by the API." -ForegroundColor Yellow
                    }
                    else {
                        Write-Host "  Failed to query StifleR infrastructure service endpoint." -ForegroundColor Red
                        Write-Host "  Error: $errorMessage" -ForegroundColor DarkGray
                    }
                }

                if ($Result -is [string]) {
                    # Detect interactive sign-in HTML that indicates auth/SSO challenge instead of API JSON.
                    if ($Result -match '(?is)<!DOCTYPE\s+html|<html\b|Sign in to your account|aadcdn\.msftauth\.net|login\.microsoftonline\.com') {
                        $AuthPromptDetected = $true
                        Write-Host "  StifleR API returned an HTML sign-in/authentication page instead of API data." -ForegroundColor Yellow
                        Write-Host "  This usually means integrated authentication is not working for this request context." -ForegroundColor Yellow
                    }
                }

                if ($AuthPromptDetected) {
                    # Auth prompt already reported above.
                }
                elseif ($null -eq $Result) {
                    Write-Host "  DeployR Infrastructure Service is NOT registered with StifleR API, or Unable to reach StifleR API." -ForegroundColor Red
                }
                else {
                    $DeployRresult = $result | Where-Object { $_.Type -eq 11 } #Type 11 is DeployR Infrastructure Service
                    if ($DeployRresult.status -eq '50') {
                        Write-Host "   DeployR Infrastructure Service is Approved with StifleR API." -ForegroundColor Green
                        write-Host "    DeployR Version: $($DeployRresult.version)" -ForegroundColor DarkGray
                        Write-Host "    DeployR Infrastructure Service registration Date: $($DeployRresult.registrationDate)" -ForegroundColor DarkGray
                        Write-Host "    DeployR Infrastructure Service heartbeat Date: $($DeployRresult.heartbeatDate)" -ForegroundColor DarkGray
                    }
                    else {
                        Write-Host "  DeployR Infrastructure Service is NOT Approved with StifleR API." -ForegroundColor Red
                    }
                }
            }
            else{
                Write-Host " StifleR API URI does NOT match between Dashboard Registry and DeployR Registry" -ForegroundColor Red
                Write-Host "  Dashboard Registry URI: $($DashRegData.ServiceUrl)" -ForegroundColor DarkGray
                Write-Host "  DeployR Registry URI: $($DeployRRegData.StifleRServerApiUrl)" -ForegroundColor DarkGray
            }
        }
        write-host "-------------------------------------------------"  -ForegroundColor DarkGray
    }
    
    
    if ($DeployRRegData -and $DeployRRegData.ContentLocation) {
        Write-Host " DeployR ContentLocation: $($DeployRRegData.ContentLocation)" -ForegroundColor Green
        $DeployRContentPath = $DeployRRegData.ContentLocation
    }
    else {
        if (Test-Path "$env:ProgramData\2Pint Software\DeployR\Content") {
            Write-Host " DeployR ContentLocation (Default): $env:ProgramData\2Pint Software\DeployR" -ForegroundColor Yellow
            $DeployRContentPath = "$env:ProgramData\2Pint Software\DeployR\Content"
        }
        else {
            Write-Host " DeployR ContentLocation is NOT found in Registry and not in Default Location." -ForegroundColor Red
        }
    }
    #Get Free Space for where the DeployR Content is then return free space in GB (REg if 100GB or larger, Yellow if 50-100GB, Red if under 50GB)
    if ($DeployRContentPath) {
        $FreeSpaceGB = Get-FreeSpaceAvailable -Path $DeployRContentPath
        if ($FreeSpaceGB -ne $null) {
            if ($FreeSpaceGB -ge 100) {
                Write-Host " Free space available at DeployR Content Location: $FreeSpaceGB GB" -ForegroundColor Green
            }
            elseif ($FreeSpaceGB -ge 50 -and $FreeSpaceGB -lt 100) {
                Write-Host " Free space available at DeployR Content Location: $FreeSpaceGB GB" -ForegroundColor Yellow
            }
            else {
                Write-Host " Free space available at DeployR Content Location: $FreeSpaceGB GB" -ForegroundColor Red
            }
        }
        write-host "-------------------------------------------------"  -ForegroundColor DarkGray
    }
    if ($DeployRRegData -and $DeployRRegData.ConnectionString) {
        $DeployRegDataSQLServerInstanceString = (($DeployRRegData.ConnectionString).Split(';') | Where-Object { $_ -match '^Server=' }).Split('\')[1]
        if ($DeployRegDataSQLServerInstanceString -eq $SQLInstances.InstanceName) {
            Write-Host " DeployR SQL Server Instance in Registry matches detected SQL Instance: $($SQLInstances.InstanceName)" -ForegroundColor Green
        }
        else {
            Write-Host "!!!!!=============================================================================!!!!!" -ForegroundColor Red
            Write-Host "     DeployR SQL Server Instance in Registry does NOT match detected SQL Instance." -ForegroundColor Red
            Write-Host "      Registry Instance: $($DeployRegDataSQLServerInstanceString)" -ForegroundColor DarkGray
            Write-Host "      Detected Instance: $($SQLInstances.InstanceName)" -ForegroundColor DarkGray
            Write-Host "!!!!!=============================================================================!!!!!" -ForegroundColor Red
        }
        Write-Host " Testing DeployR SQL Connection string from Registry... " -ForegroundColor Cyan
        write-host "  $($DeployRRegData.ConnectionString)"
        Test-SQLConnection -ConnectionString $DeployRRegData.ConnectionString
    }
    #Check SQL Principal Rights for NT AUTHORITY\SYSTEM
    Write-Host "=========================================================================" -ForegroundColor DarkGray
    Write-Host "Testing NT AUTHORITY\SYSTEM permissions on local SQL Express..." -ForegroundColor Cyan
    $out = Test-SystemSqlPermissions -Instance $SQLInstances.ConnectionString
    if ($out.Error) {
        Write-Host "Error: $($out.Error)" -ForegroundColor Red
        Write-Host "Please Manually Check Permissions on Database Instances" -ForegroundColor Cyan
        Write-Host "Would you like to try to automatically add SYSTEM to the Instance $($SQLInstances.InstanceName)  (Y/N): " -ForegroundColor Yellow -NoNewline
        $response = Read-Host
        if ($response -eq 'Y' -or $response -eq 'y') {
            try {
                $SetSQLPerm = Set-SqlServerPermissions -InstanceName $($SQLInstances.InstanceName)
            }
            catch {
                Write-Host "Failed to set permissions: $_" -ForegroundColor Red
            }
        }
    }
    else {
        Write-Host "Instance: $($out.Instance)" -ForegroundColor Green
        Write-Host "  LoginExists: $($out.LoginExists)" -ForegroundColor ($(if ($out.LoginExists) {'Green'} else {'Red'}))
        Write-Host "  IsSysadmin : $($out.IsSysadmin)" -ForegroundColor ($(if ($out.IsSysadmin) {'Green'} else {'Yellow'}))
        Write-Host "  IsDbCreator: $($out.IsDbCreator)" -ForegroundColor ($(if ($out.IsDbCreator) {'Green'} else {'Yellow'}))
    }
    Write-Host "=========================================================================" -ForegroundColor DarkGray
    Write-Host "Checking NT AUTHORITY\SYSTEM db_owner permissions for all databases..." -ForegroundColor Cyan
    $dbOut = Test-SqlDatabases -Instance $SQLInstances.ConnectionString
    if ($dbOut.Error) {
        Write-Host "Error: Cannot check permissions - failed to get database list" -ForegroundColor Red
    }
    elseif ($dbOut.Databases.Count -eq 0) {
        Write-Host "No user databases found to check" -ForegroundColor Yellow
    }
    else {
        # Extract database names and check permissions
        $dbNames = $dbOut.Databases | ForEach-Object { $_.Name }
        $dbOwnerOut = Test-SystemDatabaseOwnership -Instance $SQLInstances.ConnectionString -DatabaseNames $dbNames
        
        if ($dbOwnerOut.Error) {
            Write-Host "Error: $($dbOwnerOut.Error)" -ForegroundColor Red
        }
        else {
            Write-Host "Instance: $($dbOwnerOut.Instance)" -ForegroundColor Green
            foreach ($dbPerm in $dbOwnerOut.DatabasePermissions) {
                if (-not $dbPerm.DbExists) {
                    Write-Host "  Database '$($dbPerm.SearchName)': DATABASE NOT FOUND" -ForegroundColor Red
                }
                else {
                    $color = if ($dbPerm.HasDbOwner) {'Green'} else {'Red'}
                    $status = if ($dbPerm.HasDbOwner) {'HAS db_owner'} else {'MISSING db_owner'}
                    Write-Host "  Database '$($dbPerm.ActualDbName)': $status" -ForegroundColor $color
                }
            }
        }
    }
    
    Write-Host "=========================================================================" -ForegroundColor DarkGray
    Write-Host "Testing DeployR Certificate..." -ForegroundColor Cyan
    #Test Certificate
    $CertThumbprintRegValue = $DeployRRegData.CertificateThumbprint
    Write-Host "DeployR Using Certificate with Thumbprint: $($CertThumbprintRegValue)" -ForegroundColor Cyan
    #Get Certificate from Local Machine Store that matches
    $CertThumbprint = Get-ChildItem -Path Cert:\LocalMachine\My  | Where-Object { $_.Thumbprint -match $CertThumbprintRegValue }
    if ($CertThumbprint) {
        Write-Host "  Found certificate in local store: $($CertThumbprint.Thumbprint)" -ForegroundColor Green
        Write-Host "  DNSNameList:   $($CertThumbprint.DNSNameList -join ', ')" -ForegroundColor DarkGray
        Write-Host "  Subject:       $($CertThumbprint.Subject)" -ForegroundColor DarkGray
        Write-Host "  Issuer:        $($CertThumbprint.Issuer)" -ForegroundColor DarkGray
    }
    else {
        Write-Host "  Certificate NOT found." -ForegroundColor Red
    }
    Write-Host "=========================================================================" -ForegroundColor DarkGray
    #Test StifleR Server URL
    Write-Host "Testing Network Connections..." -ForegroundColor Cyan
    #StifleR Server URL = $DeployRRegData.StifleRServerApiUrl without Port Number
    $StifleRServerURL = $DeployRRegData.StifleRServerApiUrl
    $StifleRServerURL = $StifleRServerURL.Split(':')[0..1] -join ':'
    $StifleRServerName = $StifleRServerURL.Split('/')[2]
    $DeployRURL = $DeployRRegData.ClientURL
    $DeployRURL = $DeployRURL.Split(':')[0..1] -join ':'
    $DeployRServerName = $DeployRURL.Split('/')[2]
    
    
    
    Write-Host " Testing StifleR Server URL... $($StifleRServerURL)" -ForegroundColor Green
    $StifleRTest = Test-Url -Url $StifleRServerURL
    if ($StifleRTest) {
        Write-Host "  StifleR Server URL is accessible." -ForegroundColor DarkGray
        $Test443 = Test-NetConnection -ComputerName $StifleRServerName -Port 443
        if ($Test443) {
            Write-Host "  StifleR Server Port 443 is accessible." -ForegroundColor DarkGray
        }
        $Test9000 = Test-NetConnection -ComputerName $StifleRServerName -Port 9000
        if ($Test9000) {
            Write-Host "  StifleR Server Port 9000 is accessible." -ForegroundColor DarkGray
        }
    }
    else {
        Write-Host "StifleR Server URL is NOT accessible." -ForegroundColor Red
    }
    Write-Host " Testing DeployR Server URL... $($DeployRURL)" -ForegroundColor Green
    $DeployRTest = Test-Url -Url $DeployRURL
    if ($DeployRTest) {
        
        
        
        $Test7281 = Test-NetConnection -ComputerName $DeployRServerName -Port 7281
        if ($Test7281) {
            Write-Host "  DeployR Server Port 7281 is accessible." -ForegroundColor DarkGray
        }
        $Test7282 = Test-NetConnection -ComputerName $DeployRServerName -Port 7282
        if ($Test7282) {
            Write-Host "  DeployR Server Port 7282 is accessible." -ForegroundColor DarkGray
        }
    }
    else {
        Write-Host "  DeployR Server URL is NOT accessible." -ForegroundColor Red
    }
    
}
Write-Host "=========================================================================" -ForegroundColor DarkGray
Write-Host "Checking Certificate... on Ports 443 & 9000 & 8051 & 8050" -ForegroundColor Cyan
# Get the certificate hash from the HTTP.SYS binding for port 443
$certHash = $Null
$certHash = netsh http show sslcert ipport=0.0.0.0:443 | Select-String "Certificate Hash" | ForEach-Object { ($_ -split ": ")[1].Trim() }

if ($certHash) {
    Write-Host "Certificate Thumbprint for HTTPS (port 443): $certHash" -ForegroundColor Cyan
    if ($certHash -eq $CertThumbprintRegValue) {
        Write-Host "  The certificate hash matches the DeployR configuration." -ForegroundColor Green
    }
    else {
        Write-Host "  The certificate hash does NOT match the DeployR configuration." -ForegroundColor Red
    }
} else {
    Write-Host "No SSL binding found for port 443. Trying all IPs..." -ForegroundColor Yellow
    # Fallback: Scan common IPs (adjust as needed)
    $ips = @("0.0.0.0", "*")  # Add specific IPs if known, e.g., "192.168.1.100"
    $found = $false
    foreach ($ip in $ips) {
        $hash = netsh http show sslcert ipport="$ip`:443" | Select-String "Certificate Hash" | ForEach-Object { ($_ -split ": ")[1].Trim() }
        if ($hash) {
            Write-Host "Certificate Thumbprint for HTTPS (port 443) on $ip`: $hash" -ForegroundColor Yellow
            $found = $true
            break
        }
    }
    if (-not $found) { Write-Host "No binding found." -ForegroundColor Red }
}
$certHash = $Null
$certHash = netsh http show sslcert ipport=0.0.0.0:9000 | Select-String "Certificate Hash" | ForEach-Object { ($_ -split ": ")[1].Trim() }

if ($certHash) {
    Write-Host "Certificate Thumbprint for HTTPS (port 9000 - StifleR): $certHash" -ForegroundColor Cyan
    if ($certHash -eq $CertThumbprintRegValue) {
        Write-Host "  The certificate hash matches the DeployR configuration." -ForegroundColor Green
        $CertThumbprint = $AllLocalCerts  | Where-Object { $_.Thumbprint -match $certHash }
        if ($CertThumbprint) {
            Write-Host "  Found certificate in local store: $($CertThumbprint.Thumbprint)" -ForegroundColor Green
            Write-Host "  DNSNameList:   $($CertThumbprint.DNSNameList -join ', ')" -ForegroundColor DarkGray
            Write-Host "  Subject:       $($CertThumbprint.Subject)" -ForegroundColor DarkGray
            Write-Host "  Issuer:        $($CertThumbprint.Issuer)" -ForegroundColor DarkGray
        }
        else {
            Write-Host "  Certificate NOT found." -ForegroundColor Red
        }
    }
    else {
        Write-Host "  The certificate hash does NOT match the DeployR configuration." -ForegroundColor Red
        $CertThumbprint = $AllLocalCerts  | Where-Object { $_.Thumbprint -match $certHash }
        if ($CertThumbprint) {
            Write-Host "  Found certificate in local store: $($CertThumbprint.Thumbprint)" -ForegroundColor Green
            Write-Host "  DNSNameList:   $($CertThumbprint.DNSNameList -join ', ')" -ForegroundColor DarkGray
            Write-Host "  Subject:       $($CertThumbprint.Subject)" -ForegroundColor DarkGray
            Write-Host "  Issuer:        $($CertThumbprint.Issuer)" -ForegroundColor DarkGray
        }
        else {
            Write-Host "  Certificate NOT found." -ForegroundColor Red
        }
    }
} else {
    Write-Host "No SSL binding found for port 9000. Trying all IPs..." -ForegroundColor Yellow
    # Fallback: Scan common IPs (adjust as needed)
    $ips = @("0.0.0.0", "*")  # Add specific IPs if known, e.g., "192.168.1.100"
    $found = $false
    foreach ($ip in $ips) {
        $hash = netsh http show sslcert ipport="$ip`:9000" | Select-String "Certificate Hash" | ForEach-Object { ($_ -split ": ")[1].Trim() }
        if ($hash) {
            Write-Host "Certificate Thumbprint for HTTPS (port 9000) on $ip`: $hash" -ForegroundColor Yellow
            $found = $true
            break
        }
    }
    if (-not $found) { Write-Host "No binding found." -ForegroundColor Red }
}

if ($Installed_2Pint_Software_iPXE_Anywhere_WebService -eq $true) {
    $iPXEWSConnectionInfo = @(
        [PSCustomObject]@{ Path = 'HKLM:\SOFTWARE\2Pint Software\iPXE Anywhere Web Service'; ValueName = 'ConnectionString' }
        [PSCustomObject]@{ Path = 'HKLM:\SOFTWARE\2Pint Software\iPXE Anywhere Web Service\GeneralSettings'; ValueName = 'ConnectionString' }
        [PSCustomObject]@{ Path = 'HKLM:\SOFTWARE\2Pint Software\iPXE Anywhere Web Service\GeneralSettings'; ValueName = 'AdvancedConnectionString' }
    )

    $iPXEWSConnectionStringFound = $false
    $testediPXEWSConnectionStrings = @()
    foreach ($regItem in $iPXEWSConnectionInfo) {
        if (Test-Path -Path $regItem.Path) {
            $iPXEWSRegData = Get-ItemProperty -Path $regItem.Path -ErrorAction SilentlyContinue
            if ($iPXEWSRegData -and -not [string]::IsNullOrWhiteSpace($iPXEWSRegData.($regItem.ValueName))) {
                $candidateConnectionString = $iPXEWSRegData.($regItem.ValueName)
                if ($testediPXEWSConnectionStrings -notcontains $candidateConnectionString) {
                    $testediPXEWSConnectionStrings += $candidateConnectionString
                    $iPXEWSConnectionStringFound = $true
                    Write-Host "iPXE WS SQL Connection String from Registry ($($regItem.Path)::$($regItem.ValueName)): $candidateConnectionString" -ForegroundColor Cyan
                    Test-SQLConnection -ConnectionString $candidateConnectionString
                }
            }
        }
    }

    if (-not $iPXEWSConnectionStringFound) {
        Write-Host "iPXE WS SQL Connection String is NOT configured in either legacy or current registry locations." -ForegroundColor Red
    }
    $iPXEcertHash = netsh http show sslcert ipport=0.0.0.0:8051 | Select-String "Certificate Hash" | ForEach-Object { ($_ -split ": ")[1].Trim() }
    if ($iPXEcertHash) {
        Write-Host "Certificate Thumbprint for HTTPS (port 8051 - iPXE WS): $iPXEcertHash" -ForegroundColor Cyan
        
        $CertThumbprint = $AllLocalCerts  | Where-Object { $_.Thumbprint -match $iPXEcertHash }
        if ($CertThumbprint) {
            Write-Host "  Found certificate in local store: $($CertThumbprint.Thumbprint)" -ForegroundColor Green
            Write-Host "  DNSNameList:   $($CertThumbprint.DNSNameList -join ', ')" -ForegroundColor DarkGray
            Write-Host "  Subject:       $($CertThumbprint.Subject)" -ForegroundColor DarkGray
            Write-Host "  Issuer:        $($CertThumbprint.Issuer)" -ForegroundColor DarkGray
        }
        else {
            Write-Host "  Certificate NOT found." -ForegroundColor Red
        }
    }
    
} else {
    Write-Host "No SSL binding found for port 8051. Trying all IPs..." -ForegroundColor Yellow
    # Fallback: Scan common IPs (adjust as needed)
    $ips = @("0.0.0.0", "*")  # Add specific IPs if known, e.g., "192.168.1.100"
    $found = $false
    foreach ($ip in $ips) {
        $hash = netsh http show sslcert ipport="$ip`:8051" | Select-String "Certificate Hash" | ForEach-Object { ($_ -split ": ")[1].Trim() }
        if ($hash) {
            Write-Host "Certificate Thumbprint for HTTPS (port 8051) on $ip`: $hash" -ForegroundColor Yellow
            $found = $true
            break
        }
    }
    if (-not $found) { Write-Host "No binding found." -ForegroundColor Red }
    
}

if ($Installed_2Pint_Software_PXE_Server -eq $true){
    $2PXEcertHash = netsh http show sslcert ipport=0.0.0.0:8050 | Select-String "Certificate Hash" | ForEach-Object { ($_ -split ": ")[1].Trim() }
    $2PXEConfigFilePath = "C:\Program Files\2Pint Software\2PXE\2Pint.2PXE.Service.exe.config"
    
    if ($2PXEcertHash) {
        Write-Host "Certificate Thumbprint for HTTPS (port 8050 - 2PXE): $2PXEcertHash" -ForegroundColor Cyan
        
        $CertThumbprint = $AllLocalCerts  | Where-Object { $_.Thumbprint -match $2PXEcertHash }
        if ($CertThumbprint) {
            Write-Host "  Found certificate in local store: $($CertThumbprint.Thumbprint)" -ForegroundColor Green
            Write-Host "  DNSNameList:   $($CertThumbprint.DNSNameList -join ', ')" -ForegroundColor DarkGray
            Write-Host "  Subject:       $($CertThumbprint.Subject)" -ForegroundColor DarkGray
            Write-Host "  Issuer:        $($CertThumbprint.Issuer)" -ForegroundColor DarkGray
        }
        else {
            Write-Host "  Certificate NOT found." -ForegroundColor Red
        }
    } else {
        Write-Host "No SSL binding found for port 8050. Trying all IPs..." -ForegroundColor Yellow
        # Fallback: Scan common IPs (adjust as needed)
        $ips = @("0.0.0.0", "*")  # Add specific IPs if known, e.g., "192.168.1.100"
        $found = $false
        foreach ($ip in $ips) {
            $hash = netsh http show sslcert ipport="$ip`:8050" | Select-String "Certificate Hash" | ForEach-Object { ($_ -split ": ")[1].Trim() }
            if ($hash) {
                Write-Host "Certificate Thumbprint for HTTPS (port 8050) on $ip`: $hash" -ForegroundColor Yellow
                $found = $true
                break
            }
        }
        if (-not $found) { Write-Host "No binding found." -ForegroundColor Red }
    }
}
if (($Installed_2Pint_Software_PXE_Server -eq $true) -and ($Installed_2Pint_Software_iPXE_Anywhere_WebService -eq $true)){
    
    if ($2PXEcertHash -eq $iPXEcertHash) {
        Write-Host "The certificate hash matches (2PXE & iPXE WS)." -ForegroundColor Green
    }
    else {
        Write-Host "The certificate hashes are different between 2PXE & iPXE WS." -ForegroundColor Red
    }
    if (Test-Path -Path $2PXEConfigFilePath) {
        Write-Host "------------------------------------" -ForegroundColor DarkGray
        Write-Host "Checking Settings in 2PXE config file: $2PXEConfigFilePath" -ForegroundColor Cyan
        $2PXEConfig = [xml](Get-Content -Path $2PXEConfigFilePath)
        $2PXEConfigiPXEAnywhereWebServiceURI = $2PXEConfig.configuration.appSettings.add | Where-Object { $_.key -eq "iPXEAnywhereWebServiceURI" } | Select-Object -ExpandProperty value
        
        if ($2PXEConfigiPXEAnywhereWebServiceURI) {
            if ($DeployRURL){
                if ($2PXEConfigiPXEAnywhereWebServiceURI -match $DeployRURL) {
                    Write-Host "iPXEAnywhereWebServiceURI in 2PXE config matches DeployR Server URL." -ForegroundColor Green
                    Write-Host "  iPXEAnywhereWebServiceURI: $2PXEConfigiPXEAnywhereWebServiceURI" -ForegroundColor DarkGray
                }
                else {
                    Write-Host "iPXEAnywhereWebServiceURI in 2PXE config does NOT match DeployR Server URL." -ForegroundColor Red
                    Write-Host "  iPXEAnywhereWebServiceURI: $2PXEConfigiPXEAnywhereWebServiceURI" -ForegroundColor DarkGray
                    Write-Host "  DeployR Server URL: $DeployRURL" -ForegroundColor DarkGray
                }
            }
        }
        else{
            Write-Host "  2PXE Config Missing Value for iPXEAnywhereWebServiceURI" -ForegroundColor Red
        }
        
    }
    
}
if ($Installed_2Pint_Software_PXE_Server -eq $true){
    if (Test-Path -Path $2PXEConfigFilePath) {
        $2PXEConfig = [xml](Get-Content -Path $2PXEConfigFilePath)
        $2PXEConfigExternalFQDNOverride = $2PXEConfig.configuration.appSettings.add | Where-Object { $_.key -eq "ExternalFQDNOverride" } | Select-Object -ExpandProperty value
        Write-Host "Additional Config Settings (2PXE):" -ForegroundColor Cyan
        if (-not [string]::IsNullOrWhiteSpace($2PXEConfigExternalFQDNOverride)) {
            Write-Host "  ExternalFQDNOverride: $2PXEConfigExternalFQDNOverride" -ForegroundColor DarkGray
        }
        $2PXEConfigCustomCAThumbprint = $2PXEConfig.configuration.appSettings.add | Where-Object { $_.key -eq "CustomCAThumbprint" } | Select-Object -ExpandProperty value
        if ($2PXEConfigCustomCAThumbprint) {
            Write-Host "  CustomCAThumbprint: $2PXEConfigCustomCAThumbprint" -ForegroundColor DarkGray
            #Get the certificate from the local store that matches the thumbprint in the Trusted Root Certification Authorities store
            $CertThumbprint = Get-ChildItem -Path Cert:\LocalMachine\Root  | Where-Object { $_.Thumbprint -match $2PXEConfigCustomCAThumbprint }
            if ($CertThumbprint) {
                Write-Host "  Found Custom CA certificate in local Trusted Root store: $($CertThumbprint.Thumbprint)" -ForegroundColor Green
                Write-Host "    DNSNameList: $($CertThumbprint.DNSNameList -join ', ')" -ForegroundColor DarkGray
                Write-Host "    Subject:     $($CertThumbprint.Subject)" -ForegroundColor DarkGray
                Write-Host "    Issuer:      $($CertThumbprint.Issuer)" -ForegroundColor DarkGray
            }
            else {
                Write-Host "  Custom CA certificate NOT found in Trusted Root Certification Authorities store." -ForegroundColor Red
            }
        }
        else{
            #Write-Host "2PXE Config Missing Value for CustomCAThumbprint" -ForegroundColor Red
        }
    }
}
#Testing Firewall Rules:

Write-Host "=========================================================================" -ForegroundColor DarkGray
Write-Host "Checking Firewall Rules to ensure Ports are Open" -ForegroundColor Cyan
$Ports = Get-NetFirewallPortFilter
$InboundRules = Get-NetFirewallRule -Direction Inbound
foreach ($FirewallRule in $FirewallRules){
    Write-Host "Checking Firewall Rule: $($FirewallRule.DisplayName)" -ForegroundColor DarkCyan
    $RulePorts = $Ports | Where-Object { $_.LocalPort -eq $FirewallRule.Port -and $_.Protocol -eq $FirewallRule.Protocol } | Select-Object -first 1
    if ($RulePorts){
        foreach ($Port in $RulePorts){
            $NetFirewallRule = $InboundRules | Where-Object { $_.InstanceID -eq $Port.InstanceID }
            Write-Host " Found Firewall Rule: $($NetFirewallRule.DisplayName)" -ForegroundColor Green
            Write-Host "  Enabled: $($NetFirewallRule.Enabled) | Action:  $($NetFirewallRule.Action) | Profile: $($NetFirewallRule.Profile)" -ForegroundColor DarkGray
            Write-Host "  Port: $($Port.LocalPort) | Protocol: $($Port.Protocol)" -ForegroundColor DarkGray
        }
    }
    else {
        Write-Host "No matching ports found for Firewall Rule: $($FirewallRule.DisplayName)" -ForegroundColor Red
    }
}
#Check StifleR Infrastructure Approval for DeployR if StifleR Wmi Agent is installed
<#
if ($Installed_2Pint_Software_StifleR_WmiAgent) {
Write-Host "=========================================================================" -ForegroundColor DarkGray
Write-Host "Checking for StifleR Infrastructure Approval for DeployR" -ForegroundColor Cyan
$InfraServices = Get-CimInstance -ClassName "InfrastructureServices" -Namespace root\stifler -ErrorAction SilentlyContinue
if ($InfraServices) {
Write-Host "StifleR Infrastructure Services found." -ForegroundColor Green
} else {
Write-Host "No StifleR Infrastructure Services found." -ForegroundColor Red
}
if (!$InfraServices) {

Write-Host "Sometimes if the service just started, this can take a bit"
write-host "Waiting for a minute and going to try again..."
Start-Sleep -seconds 10
$InfraServices = Get-CimInstance -ClassName "InfrastructureServices" -Namespace root\stifler -ErrorAction SilentlyContinue
write-host " 50..."
Start-Sleep -seconds 10
$InfraServices = Get-CimInstance -ClassName "InfrastructureServices" -Namespace root\stifler -ErrorAction SilentlyContinue
write-Host " 40..."
Start-Sleep -seconds 10
$InfraServices = Get-CimInstance -ClassName "InfrastructureServices" -Namespace root\stifler -ErrorAction SilentlyContinue
write-host " 30..."
Start-Sleep -seconds 10
$InfraServices = Get-CimInstance -ClassName "InfrastructureServices" -Namespace root\stifler -ErrorAction SilentlyContinue
write-host " 20..."
Start-Sleep -seconds 10
$InfraServices = Get-CimInstance -ClassName "InfrastructureServices" -Namespace root\stifler -ErrorAction SilentlyContinue
write-host " 10..."
Start-Sleep -seconds 10
$InfraServices = Get-CimInstance -ClassName "InfrastructureServices" -Namespace root\stifler -ErrorAction SilentlyContinue
}
if ($InfraServices) {
$DeployR = $InfraServices | Where-Object {$_.Type -eq "DeployR"}
if ($DeployR){
Write-Host "StifleR Infrastructure for DeployR found." -ForegroundColor Green
if ($DeployR.Status -eq "IsApproved") {
Write-Host "DeployR Status: Approved" -ForegroundColor Green
} else {
Write-Host "DeployR Status: NOT Approved" -ForegroundColor Red
}
}
else{
Write-Host "No StifleR Infrastructure for DeployR found." -ForegroundColor Red
}
} else {
Write-Host "StifleR Infrastructure Services are NOT available." -ForegroundColor Red
}
}
#>


#Remediation 
#prompt user to do installs
Write-Host "=========================================================================" -ForegroundColor DarkGray
if ($MissingComponents) {
    Write-Host "Based on what you're doing, some Windows Features are required, and some are optional" -ForegroundColor Yellow
    Write-Host "Since I don't know what you plan to do, this script offers you the option of installing them all automatically" -ForegroundColor Yellow
    Write-Host "Would you like to install the missing Windows Features now? (Y/N): " -ForegroundColor Yellow -NoNewline
    $response = Read-Host
    if ($response -eq 'Y' -or $response -eq 'y') {
        Write-Host "Remediation: Run the following command to install missing Windows Features:" -ForegroundColor Yellow
        Write-Host "Add-WindowsFeature $($MissingComponents -join ', ')" -ForegroundColor DarkGray
    }
}
if (Get-WindowsFeature -Name 'Web-Server' -ErrorAction SilentlyContinue) {
    if ($IISVirtualDirMissing) {
        Write-Host "=========================================================================" -ForegroundColor DarkGray
        Write-Host "Running Remediation for StifleRDashboard virtual directory"
        if (Test-Path -path "C:\Program Files\2Pint Software\StifleR Dashboards\Dashboard Files"){
            Write-Host "✓ StifleRDashboard directory exists." -ForegroundColor Green
        } else {
            Write-Host "✗ StifleRDashboard directory is missing." -ForegroundColor Red
        }
        <#
        Write-Host "Would you like to create the StifleRDashboard virtual directory now? (Y/N): " -ForegroundColor Yellow -NoNewline
        $response = Read-Host
        if ($response -eq 'Y' -or $response -eq 'y') {
        try {
        New-WebVirtualDirectory -Site 'Default Web Site' -Name 'StifleRDashboard' -PhysicalPath 'C:\Program Files\2Pint Software\StifleR Dashboards\Dashboard Files' -ErrorAction Stop
        Write-Host "✓ StifleRDashboard virtual directory created successfully." -ForegroundColor Green
        } catch {
        Write-Host "✗ Failed to create virtual directory: $_" -ForegroundColor Red
        Write-Host "Please run the command manually with elevated permissions." -ForegroundColor Yellow
        }
        } else {
        Write-Host "Skipping virtual directory creation." -ForegroundColor DarkGray
        }
        #>
        Write-Host "Skipping virtual directory remediation prompt (temporarily disabled)." -ForegroundColor DarkGray
    }
}
if ($IISMimeTypeUpdateRequired) {
    Write-Host "=========================================================================" -ForegroundColor DarkGray
    Write-Host "Based on what you're doing, IIS is optional, and some MIME types are optional" -ForegroundColor Yellow
    Write-Host "Since I don't know what you plan to do, this script offers you the option of enabling them all automatically" -ForegroundColor Yellow
    <#
    Write-Host "Would you like to add the missing IIS MIME types now? (Y/N): " -ForegroundColor Yellow -NoNewline
    $response = Read-Host
    if ($response -eq 'Y' -or $response -eq 'y') {
    Set-IISMIMETypes
    Write-Host "✓ Missing IIS MIME types added successfully." -ForegroundColor Green
    }
    #>
    Write-Host "Skipping IIS MIME type remediation prompt (temporarily disabled)." -ForegroundColor DarkGray
}

Stop-Transcript
Write-Host ""
Write-Host "Transcript Recorded to $TranscriptFilePath" -ForegroundColor Green
Write-Host "=========================================================================" -ForegroundColor DarkGray
