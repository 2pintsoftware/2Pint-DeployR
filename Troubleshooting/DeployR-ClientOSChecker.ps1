#This Script is designed to test a Windows Client you're looking to start a Task Sequence from
$DeployRServerFQDN = 'dr.2pintlabs.com'


$DotNetMinVersion = '8.0.21'
$PowerShellMinVersion = '7.4.13'
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
[PSCustomObject]@{Title = 'PowerShell 7-x64'; Installed = $false; MinVersion = $PowerShellMinVersion; URL = 'https://aka.ms/powershell-release?tag=lts'}
)

#region Functions

function Get-InstalledApps {
    if (![Environment]::Is64BitProcess) {
        $regpath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    }
    else {
        $regpath = @(
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
            'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
    }
    $allApps = Get-ItemProperty $regpath | .{process{if($_.DisplayName -and $_.UninstallString) { $_ } }} |
        Select-Object DisplayName, Publisher, InstallDate, DisplayVersion, UninstallString, InstallLocation
    return $allApps | Sort-Object DisplayName
}

#endregion Functions

#region Check Pre-Req Applications
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

Write-Host "=========================================================================" -ForegroundColor DarkGray
if ($DeployRServerFQDN -eq "dr.2pintlabs.com") {
    Write-Host "WARNING: DeployR Server FQDN is set to the default value of 'dr.2pintlabs.com'." -ForegroundColor Yellow
    Write-Host 'Please update the $DeployRServerFQDN variable in the script to point to your actual DeployR Server.' -ForegroundColor Yellow
    stop-transcript
    exit 1
}
else {
    Write-Host "DeployR Server FQDN: $DeployRServerFQDN" -ForegroundColor Green
}

Write-Host "Checking for Pre-Requisite Applications..." -ForegroundColor Cyan

$installedApps = Get-InstalledApps
$installedApps = $installedApps | Where-Object {$_.DisplayName -notmatch "AppHost"}

$PreReqAppsStatus = @()
foreach ($app in $PreReqApps) {
    $found = $installedApps | Where-Object {
        $_.DisplayName -match [regex]::Escape($app.Title) -or
        $_.DisplayName -like "*$($app.Title)*"
    }

    if ($found) {
        if (($found | Select-Object -Unique DisplayName | Measure-Object).Count -gt 1) {
            foreach ($appitem in $found) {
                $Version = $appitem.DisplayVersion
                if ($app.Url -match "dotnet") {
                    if ($appitem.DisplayName -match "\d+\.\d+\.\d+") {
                        $Version = $matches[0]
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
        else {
            $found = $found | Select-Object -First 1
            $Version = $found.DisplayVersion
            if ($app.Url -match "dotnet") {
                if ($found.DisplayName -match "\d+\.\d+\.\d+") {
                    $Version = $matches[0]
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
    }
    else {
        $PreReqAppsStatus += [PSCustomObject]@{
            Title     = $app.Title
            Installed = $false
            URL       = $app.URL
            Notes     = $app.Notes
        }
    }
}

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

# Display results
foreach ($app in $PreReqAppsStatus) {
    if ($app.Installed) {
        if ($app.MinVersion -and $app.Version -and ([version]$app.Version -lt [version]$app.MinVersion)) {
            Write-Host " ✗  $($app.Title)  " -ForegroundColor Red
            Write-Host "   Installed Version: $($app.Version)" -ForegroundColor DarkGray
            Write-Host "   Minimum Required Version: $($app.MinVersion)" -ForegroundColor DarkGray
            if ($app.Notes) { Write-Host "   $($app.Notes)" -ForegroundColor DarkGray }
        }
        else {
            Write-Host " ✓  $($app.Title)  " -ForegroundColor Green
            Write-Host "   Installed Version: $($app.Version)" -ForegroundColor DarkGray
            Write-Host "   Display Name: $($app.DisplayName)" -ForegroundColor DarkGray
            if ($app.Notes) { Write-Host "   $($app.Notes)" -ForegroundColor DarkGray }
        }
    }
    else {
        Write-Host " ✗  $($app.Title)" -ForegroundColor Red
        Write-Host "   Download: $($app.URL)" -ForegroundColor DarkGray
        if ($app.Notes) { Write-Host "   $($app.Notes)" -ForegroundColor Red }
    }
}

#endregion Check Pre-Req Applications

#region All .NET Installations

Write-Host ""
Write-Host "=========================================================================" -ForegroundColor DarkGray
Write-Host "All .NET Installations Found..." -ForegroundColor Cyan

# .NET Framework (legacy) from registry
$ndpKey = 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full'
if (Test-Path $ndpKey) {
    $ndpRelease = (Get-ItemProperty $ndpKey -Name Release -ErrorAction SilentlyContinue).Release
    $ndpVersion = (Get-ItemProperty $ndpKey -Name Version -ErrorAction SilentlyContinue).Version
    Write-Host " .NET Framework 4.x" -ForegroundColor Yellow
    Write-Host "   Version: $ndpVersion (Release: $ndpRelease)" -ForegroundColor DarkGray
}

# .NET Core / .NET 5+ runtimes via dotnet --list-runtimes
$dotnetExe = Get-Command dotnet -ErrorAction SilentlyContinue
if ($dotnetExe) {
    Write-Host ""
    Write-Host " .NET Runtimes (dotnet --list-runtimes):" -ForegroundColor Yellow
    $runtimes = & dotnet --list-runtimes 2>&1
    foreach ($line in $runtimes) {
        Write-Host "   $line" -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host " .NET SDKs (dotnet --list-sdks):" -ForegroundColor Yellow
    $sdks = & dotnet --list-sdks 2>&1
    if ($sdks) {
        foreach ($line in $sdks) {
            Write-Host "   $line" -ForegroundColor DarkGray
        }
    }
    else {
        Write-Host "   No SDKs installed" -ForegroundColor DarkGray
    }
}
else {
    Write-Host " dotnet CLI not found on PATH — no .NET Core/5+ runtimes detected via CLI" -ForegroundColor Yellow
}

# Any .NET-related entries in Add/Remove Programs
Write-Host ""
Write-Host " All .NET entries in Add/Remove Programs:" -ForegroundColor Yellow
$dotnetApps = $installedApps | Where-Object { $_.DisplayName -match '\.NET|dotnet' } | Sort-Object DisplayName
if ($dotnetApps) {
    foreach ($app in $dotnetApps) {
        Write-Host "   $($app.DisplayName)  —  $($app.DisplayVersion)" -ForegroundColor DarkGray
    }
}
else {
    Write-Host "   None found" -ForegroundColor DarkGray
}

Write-Host "=========================================================================" -ForegroundColor DarkGray

#endregion All .NET Installations

#region DeployR Server Connectivity

Write-Host ""
Write-Host "=========================================================================" -ForegroundColor DarkGray
Write-Host "DeployR Server Connectivity Check..." -ForegroundColor Cyan
Write-Host "   Server: $DeployRServerFQDN  Port: 7281" -ForegroundColor DarkGray

try {
    $tcpTest = Test-NetConnection -ComputerName $DeployRServerFQDN -Port 7281 -WarningAction SilentlyContinue
    if ($tcpTest.TcpTestSucceeded) {
        Write-Host " ✓  TCP connection to ${DeployRServerFQDN}:7281 succeeded" -ForegroundColor Green
        Write-Host "   Remote Address: $($tcpTest.RemoteAddress)" -ForegroundColor DarkGray
    }
    else {
        Write-Host " ✗  TCP connection to ${DeployRServerFQDN}:7281 FAILED" -ForegroundColor Red
        Write-Host "   Verify the server is running and port 7281 is open in the firewall" -ForegroundColor DarkGray
    }
}
catch {
    Write-Host " ✗  Unable to test connection to ${DeployRServerFQDN}:7281" -ForegroundColor Red
    Write-Host "   Error: $_" -ForegroundColor DarkGray
}

# Download test via Bootstrap endpoint
Write-Host ""
Write-Host " Testing Bootstrap download..." -ForegroundColor Cyan
try {
    $DownloadTest = Invoke-RestMethod "https://${DeployRServerFQDN}:7281/v1/Service/Bootstrap" -ErrorAction Stop
    if ($DownloadTest) {
        Write-Host " ✓  Bootstrap download succeeded" -ForegroundColor Green
        Write-Host "   Response length: $($DownloadTest.Length) characters" -ForegroundColor DarkGray
    }
    else {
        Write-Host " ✗  Bootstrap download returned empty response" -ForegroundColor Red
    }
}
catch {
    Write-Host " ✗  Bootstrap download FAILED" -ForegroundColor Red
    Write-Host "   URL: https://${DeployRServerFQDN}:7281/v1/Service/Bootstrap" -ForegroundColor DarkGray
    Write-Host "   Error: $_" -ForegroundColor DarkGray

    # Check for 2PintSoftware CA certificate in Trusted Root CA store
    Write-Host ""
    Write-Host " Checking for 2PintSoftware CA certificate in Trusted Root CA..." -ForegroundColor Cyan
    Write-Host " This will ONLY matter if you are using the 2PintSoftware Self-Signed Cert on the DeployR Server" -ForegroundColor Yellow
    $caCerts = Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object { $_.Subject -match '2Pint' -or $_.Issuer -match '2Pint' }
    if ($caCerts) {
        foreach ($cert in $caCerts) {
            Write-Host " ✓  Found: $($cert.Subject)" -ForegroundColor Green
            Write-Host "   Thumbprint: $($cert.Thumbprint)" -ForegroundColor DarkGray
            Write-Host "   Expires: $($cert.NotAfter)" -ForegroundColor DarkGray
            if ($cert.NotAfter -lt (Get-Date)) {
                Write-Host "   ✗ Certificate is EXPIRED" -ForegroundColor Red
            }
        }
    }
    else {
        Write-Host " ✗  2PintSoftware CA certificate NOT found in Trusted Root Certification Authorities" -ForegroundColor Red
        Write-Host "   The certificate may need to be imported for HTTPS connections to succeed" -ForegroundColor DarkGray
    }
}

Write-Host "=========================================================================" -ForegroundColor DarkGray
Stop-Transcript
Write-Host ""
Write-Host "Transcript Recorded to $TranscriptFilePath" -ForegroundColor Green
Write-Host "=========================================================================" -ForegroundColor DarkGray

#endregion DeployR Server Connectivity