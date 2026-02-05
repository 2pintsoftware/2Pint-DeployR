<#
.SYNOPSIS
    Downloads and installs the Microsoft Visual C++ Redistributable (x64) for Windows.
.DESCRIPTION
    This script automates the download and silent installation of the Visual C++ 2015-2022 Redistributable (x64).
    It verifies the installation, logs the process, and handles common errors.
.NOTES
    Author: Mike Terrill/2Pint Software
    Date: January 27, 2026
    Version: 26.01.27
    Requires: Administrative privileges, 64-bit Windows, internet access
    Use for a fresh install - Needs work on testing/verifying installation

    Version history:
    26.01.27: Updated to the new download link
    25.07.17: Initial release
#>

# Configuration
# Configuration
#$DownloadUrl = "https://aka.ms/vs/17/release/vc_redist.x64.exe"  # Official Microsoft URL for Visual C++ 2015-2022 x64
$DownloadUrl = "https://aka.ms/vc14/vc_redist.x64.exe"  # Official Microsoft URL for Visual C++ 14 x64
$InstallerPath = "$env:TEMP\vc_redist.x64.exe"  # Temporary location for the installer
$LogFile = "$env:TEMP\VC_Redist_Install_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Function to write to log file
function Write-Log {
    param ([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp - $Message" | Out-File -FilePath $LogFile -Append
}

# Function to check if the script is running as administrator
function Test-Admin {
    $CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object Security.Principal.WindowsPrincipal($CurrentUser)
    return $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to verify installation
function Test-VCRedistInstalled {
    $RegPath = "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64"
    if (Test-Path $RegPath) {
        $Version = (Get-ItemProperty -Path $RegPath -Name "Version" -ErrorAction SilentlyContinue).Version
        # Remove 'v' prefix if present
        $CleanVersion = if ($Version -match '^v(.*)') { $Matches[1] } else { $Version }
        if ([Version]$CleanVersion -like [Version]$ExpectedVersion) {
            Write-Log "Visual C++ Redistributable (x64) version $CleanVersion is installed."
            return $true
        } else {
            Write-Log "Found Visual C++ Redistributable, but version ($CleanVersion) does not match expected ($ExpectedVersion)."
            return $false
        }
    } else {
        Write-Log "Visual C++ Redistributable (x64) is not installed."
        return $false
    }
}

function Get-SoftwareVersion {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$InstallerPath,
        [Parameter(Mandatory = $true)]
        [string]$LogFile
    )

    Write-Log "Attempting to retrieve version from $InstallerPath" -LogFile $LogFile

    try {
        # Get file version info
        $FileVersionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($InstallerPath)
        $Version = $FileVersionInfo.FileVersion

        if ($Version) {
            Write-Log "Successfully retrieved version: $Version" -LogFile $LogFile
            Write-Output $Version
        } else {
            Write-Log "ERROR: Could not retrieve version information from $InstallerPath" -LogFile $LogFile
            Write-Error "Could not retrieve version information from $InstallerPath"
            return $null
        }
    } catch {
        Write-Log "ERROR: Failed to retrieve version. Error: $($_.Exception.Message)" -LogFile $LogFile
        Write-Error "Failed to retrieve version from $InstallerPath. Error: $($_.Exception.Message)"
        return $null
    }
}

# Start logging
Write-Log "Starting Visual C++ Redistributable (x64) installation script."

# Check for administrative privileges
if (-not (Test-Admin)) {
    Write-Log "ERROR: Script must be run as an administrator."
    Write-Error "This script requires administrative privileges. Please run PowerShell as an administrator."
    exit 1
}

# Download the installer
Write-Log "Downloading Visual C++ Redistributable from $DownloadUrl..."
try {
    $ProgressPreference = 'SilentlyContinue'  # Suppress progress bar for faster download
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $InstallerPath -ErrorAction Stop
    Write-Log "Download successful: $InstallerPath"
} catch {
    Write-Log "ERROR: Failed to download installer. Error: $($_.Exception.Message)"
    Write-Error "Failed to download Visual C++ Redistributable. Error: $($_.Exception.Message)"
    exit 1
}

# Verify the downloaded file exists
if (-not (Test-Path $InstallerPath)) {
    Write-Log "ERROR: Installer file not found at $InstallerPath."
    Write-Error "Installer file not found at $InstallerPath."
    exit 1
}

# Get the version of the downloaded installer
Write-Log "Checking the version of the downloaded Visual C++ Redistributable..."
$ExpectedVersion = Get-SoftwareVersion -InstallerPath $InstallerPath -LogFile $LogFile

# Check if already installed
#if (Test-VCRedistInstalled) {
#    Write-Host "Visual C++ Redistributable (x64) is already installed. Exiting."
#    Write-Log "Script terminated: Visual C++ Redistributable is already installed."
#    exit 0
#}

# Install the redistributable silently
Write-Log "Installing Visual C++ Redistributable (x64)..."
try {
    $Process = Start-Process -FilePath $InstallerPath -ArgumentList "/quiet /norestart" -Wait -PassThru -ErrorAction Stop
    Write-Log "Installation exit code: $($Process.ExitCode)"
    
    if ($Process.ExitCode -eq 0) {
        Write-Log "Installation completed successfully."
    } elseif ($Process.ExitCode -eq 3010) {
        Write-Log "Installation completed successfully, but a reboot is required."
        Write-Host "Installation completed successfully, but a reboot is required."
    } else {
        Write-Log "ERROR: Installation failed with exit code $($Process.ExitCode)."
        Write-Error "Installation failed with exit code $($Process.ExitCode)."
        exit $Process.ExitCode
    }
} catch {
    Write-Log "ERROR: Installation process failed. Error: $($_.Exception.Message)"
    Write-Error "Installation process failed. Error: $($_.Exception.Message)"
    exit 1
}

# Verify installation
#if (Test-VCRedistInstalled) {
#    Write-Host "Visual C++ Redistributable (x64) installed successfully."
#    Write-Log "Verification: Visual C++ Redistributable (x64) installed successfully."
#} else {
#    Write-Log "ERROR: Verification failed. Visual C++ Redistributable (x64) not detected after installation."
#    Write-Error "Verification failed. Visual C++ Redistributable (x64) not detected."
#    exit 1
#}

Write-Log "Script completed successfully."
Write-Host "Script completed. Log file: $LogFile"