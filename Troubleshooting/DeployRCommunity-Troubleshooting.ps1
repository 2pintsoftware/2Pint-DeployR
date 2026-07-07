<#Tests

USE POWERSHELL 7.  This doesn't work properly from PowerShell 5 Terminal.

- Check if all required applications are installed
- Ensure firewall rules are correctly set
- Checks Connectivity for DeployR / StifleR URLs & Ports based on Registry Entries
- Check if BranchCache is enabled
- Check StifleR Dashboard URLs in Registry & Server Config File
- Check for Certificate set in StifleR & DeployR is same and that the thumbprint exists
- Check if all required services are running
- Check Certificates on Ports 9000 & 8050



Change Log
- 26.07.26 - Started with DeployR Troubleshooting Script and modified for Community

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
[PSCustomObject]@{Title = '2Pint Software DeployR'; Installed = $false; Notes = 'Required for DeployR Servers'; ExactMatch = $true; URL = 'https://documentation.2pintsoftware.com/deployr'}
[PSCustomObject]@{Title = '2Pint Software DeployR Community (bundle)'; Installed = $false; Notes = 'Required for DeployR Community Servers'; ExactMatch = $true; URL = 'https://documentation.2pintsoftware.com/deployr'}
[PSCustomObject]@{Title = '2Pint Software StifleR Server'; Installed = $false; Notes = 'Required for DeployR Servers'; URL = 'https://documentation.2pintsoftware.com/stifler'}
[PSCustomObject]@{Title = '2Pint Software StifleR Dashboards'; Installed = $false; Notes = 'Required for DeployR Servers'; URL = 'https://documentation.2pintsoftware.com/stifler'}
[PSCustomObject]@{Title = '2Pint Software iPXE Anywhere 2PXE Service'; Installed = $false; Notes = 'OPTIONAL for DeployR Servers'; URL = 'https://documentation.2pintsoftware.com/2pxe-server'}

)
$FirewallRules = @(
[PSCustomObject]@{DisplayName = '2Pint DeployR HTTPS 7281'; Port = 7281; Protocol = 'TCP'}
[PSCustomObject]@{DisplayName = '2Pint DeployR HTTP 7282'; Port = 7282; Protocol = 'TCP'}
[PSCustomObject]@{DisplayName = '2Pint Software StifleR API 9000'; Port = 9000; Protocol = 'TCP'}
[PSCustomObject]@{DisplayName = '2Pint Software StifleR SignalR 1414 TCP'; Port = 1414; Protocol = 'TCP'}
[PSCustomObject]@{DisplayName = '2Pint Software StifleR SignalR 1414 UDP'; Port = 1414; Protocol = 'UDP'}
[PSCustomObject]@{DisplayName = '2Pint 2PXE 8050'; Port = 8050; Protocol = 'TCP'}
[PSCustomObject]@{DisplayName = '2Pint 2PXE 4011'; Port = 4011; Protocol = 'UDP'}
)

#region Functions

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
$TranscriptFilePath = "$TempFolder\Check-DeployRCommunity_TroubleShooting.log"
$InstalledAppsFilePath = "$TempFolder\DeployRCommunity_InstalledApps.log"
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

#Test if Applications are installed
$installedApps = Get-InstalledApps | Where-Object {$_.DisplayName -notmatch " - Shared framework"}
$installedApps = $installedApps | Where-Object {$_.DisplayName -notmatch "SDK"}
$installedApps = $installedApps | Where-Object {$_.DisplayName -notmatch "AppHost"}

#Testing Specific Applications
#$installedApps = Get-InstalledApps | Where-Object {$_.DisplayName -match "PowerShell 7"}

Write-Host "Checking for Pre-Requisite Applications..." -ForegroundColor Cyan
$PreReqAppsStatus = @()
foreach ($app in $PreReqApps) {
    $found = $installedApps | Where-Object { 
        if ($app.ExactMatch) {
            $_.DisplayName -eq $app.Title
        } else {
            $_.DisplayName -match [regex]::Escape($app.Title) -or
            $_.DisplayName -like "*$($app.Title)*"
        }
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


Write-Host "=========================================================================" -ForegroundColor DarkGray
Write-Host "Confirming Windows Features for DeployR" -ForegroundColor Cyan
#Confirm Windows Components
$RequiredWindowsComponents = @(
"BranchCache"
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
    write-host -ForegroundColor darkgray "Add-WindowsFeature BranchCache"
    
}
#Region Services
Write-Host "=========================================================================" -ForegroundColor DarkGray
Write-Host "Checking for Services..." -ForegroundColor Cyan
#Test Services if App Installed
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
        Write-Host "2Pint StifleR Server service is NOT running." -ForegroundColor Red
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
    Write-Host "=========================================================================" -ForegroundColor DarkGray
    Write-Host "Testing DeployR Certificate..." -ForegroundColor Cyan
    #Test Certificate
    $CertThumbprintRegValue = $DeployRRegData.CertificateThumbprint
    Write-Host "DeployR Using Certificate with Thumbprint: $($CertThumbprintRegValue)" -ForegroundColor Cyan
    #Get Certificate from Local Machine Store that matches
    $CertThumbprint = Get-ChildItem -Path Cert:\LocalMachine\My  | Where-Object { $_.Thumbprint -match $CertThumbprintRegValue }
    if ($CertThumbprint) {
        Write-Host "Found certificate in local store: $($CertThumbprint.Thumbprint)" -ForegroundColor Green
    }
    else {
        Write-Host "Certificate NOT found." -ForegroundColor Red
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
    
    
    
    Write-Host "Testing StifleR Server URL... $($StifleRServerURL)" -ForegroundColor Cyan
    $StifleRTest = Test-Url -Url $StifleRServerURL
    if ($StifleRTest) {
        Write-Host "StifleR Server URL is accessible." -ForegroundColor Green
        $Test9000 = Test-NetConnection -ComputerName $StifleRServerName -Port 9000
        if ($Test9000) {
            Write-Host "StifleR Server Port 9000 is accessible." -ForegroundColor Green
        }
    }
    else {
        Write-Host "StifleR Server URL is NOT accessible." -ForegroundColor Red
    }
    Write-Host "Testing DeployR Server URL... $($DeployRURL)" -ForegroundColor Cyan
    $DeployRTest = Test-Url -Url $DeployRURL
    if ($DeployRTest) {
        
        
        
        $Test7281 = Test-NetConnection -ComputerName $DeployRServerName -Port 7281
        if ($Test7281) {
            Write-Host "DeployR Server Port 7281 is accessible." -ForegroundColor Green
        }
        $Test7282 = Test-NetConnection -ComputerName $DeployRServerName -Port 7282
        if ($Test7282) {
            Write-Host "DeployR Server Port 7282 is accessible." -ForegroundColor Green
        }
    }
    else {
        Write-Host "DeployR Server URL is NOT accessible." -ForegroundColor Red
    }
    
}
Write-Host "=========================================================================" -ForegroundColor DarkGray
write-host "Checking Certificate... on Ports 9000 & 8050" -ForegroundColor Magenta
$certHash = $Null
$certHash = netsh http show sslcert ipport=0.0.0.0:9000 | Select-String "Certificate Hash" | ForEach-Object { ($_ -split ": ")[1].Trim() }

if ($certHash) {
    Write-Host  "Certificate Thumbprint for HTTPS (port 9000 StifleR): $certHash" -ForegroundColor Cyan
    if ($certHash -eq $CertThumbprintRegValue) {
        Write-Host "The certificate hash matches the DeployR configuration." -ForegroundColor Green
        $CertThumbprint = $AllLocalCerts  | Where-Object { $_.Thumbprint -match $certHash }
        if ($CertThumbprint) {
            Write-Host "Found certificate in local store: $($CertThumbprint.Thumbprint)" -ForegroundColor Green
            write-host " DNSNameList:    $($CertThumbprint.DNSNameList -join ', ')" -ForegroundColor DarkGray
            write-host " Subject:        $($CertThumbprint.Subject)" -ForegroundColor DarkGray
            write-host " Issuer:         $($CertThumbprint.Issuer)" -ForegroundColor DarkGray
        }
        else {
            Write-Host "Certificate NOT found." -ForegroundColor Red
        }
    }
    else {
        Write-Host "The certificate hash does NOT match the DeployR configuration." -ForegroundColor Red
        $CertThumbprint = $AllLocalCerts  | Where-Object { $_.Thumbprint -match $certHash }
        if ($CertThumbprint) {
            Write-Host "Found certificate in local store: $($CertThumbprint.Thumbprint)" -ForegroundColor Green
            write-host " DNSNameList:    $($CertThumbprint.DNSNameList -join ', ')" -ForegroundColor DarkGray
            write-host " Subject:        $($CertThumbprint.Subject)" -ForegroundColor DarkGray
            write-host " Issuer:         $($CertThumbprint.Issuer)" -ForegroundColor DarkGray
        }
        else {
            Write-Host "Certificate NOT found." -ForegroundColor Red
        }
    }
} else {
    Write-Host  "No SSL binding found for port 443. Trying all IPs..." -ForegroundColor Yellow
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

if ($Installed_2Pint_Software_PXE_Server -eq $true){
    $2PXEcertHash = netsh http show sslcert ipport=0.0.0.0:8050 | Select-String "Certificate Hash" | ForEach-Object { ($_ -split ": ")[1].Trim() }
    $2PXEConfigFilePath = "C:\Program Files\2Pint Software\2PXE\2Pint.2PXE.Service.exe.config"
    
    if ($2PXEcertHash) {
        Write-Host  "Certificate Thumbprint for HTTPS (port 8050 - 2PXE): $2PXEcertHash" -ForegroundColor Cyan
        
        $CertThumbprint = $AllLocalCerts  | Where-Object { $_.Thumbprint -match $2PXEcertHash }
        if ($CertThumbprint) {
            Write-Host "Found certificate in local store: $($CertThumbprint.Thumbprint)" -ForegroundColor Green
            write-host " DNSNameList:    $($CertThumbprint.DNSNameList -join ', ')" -ForegroundColor DarkGray
            write-host " Subject:        $($CertThumbprint.Subject)" -ForegroundColor DarkGray
            write-host " Issuer:         $($CertThumbprint.Issuer)" -ForegroundColor DarkGray
        }
        else {
            Write-Host "Certificate NOT found." -ForegroundColor Red
        }
    } else {
        Write-Host  "No SSL binding found for port 8050. Trying all IPs..." -ForegroundColor Yellow
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
if ($Installed_2Pint_Software_PXE_Server -eq $true){
    if (Test-Path -Path $2PXEConfigFilePath) {
        $2PXEConfig = [xml](Get-Content -Path $2PXEConfigFilePath)
        $2PXEConfigExternalFQDNOverride = $2PXEConfig.configuration.appSettings.add | Where-Object { $_.key -eq "ExternalFQDNOverride" } | Select-Object -ExpandProperty value
        Write-Host "Additional Config Settings:" -ForegroundColor Cyan
        if ($2PXEConfigExternalFQDNOverride -ne $null -and $2PXEConfigExternalFQDNOverride -ne "") {
            Write-Host " ExternalFQDNOverride in 2PXE config: $2PXEConfigExternalFQDNOverride" -ForegroundColor DarkGray
        }
    }
}
#Testing Firewall Rules:

Write-Host "=========================================================================" -ForegroundColor DarkGray
write-host "Checking Firewall Rules to ensure Ports are Open" -ForegroundColor Cyan
$Ports = Get-NetFirewallPortFilter
$InboundRules = Get-NetFirewallRule -Direction Inbound
foreach ($FirewallRule in $FirewallRules){
    Write-Host "Checking Firewall Rule: $($FirewallRule.DisplayName)" -ForegroundColor Yellow
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
Stop-Transcript
Write-Host ""
Write-Host "Transcript Recorded to $TranscriptFilePath" -ForegroundColor Green
Write-Host "=========================================================================" -ForegroundColor DarkGray
