<#
.SYNOPSIS
    Downloads and installs Microsoft SQL Server Management Studio (SSMS) 22.x for Windows.
.DESCRIPTION
    This script automates the download, silent installation, and verification of SSMS 22.x using the Visual Studio Installer.
    It logs the process and handles common errors, suitable for managing SQL Server instances.
.NOTES
    Author: Mike Terrill/2Pint Software
    Date: February 4, 2026
    Version: 26.02.04
    Requires: Administrative privileges, 64-bit Windows (10/11, Server 2016+), internet access
    Use for a fresh install - Needs work on testing/verifying installation
#>

# Configuration
$DownloadUrl = "https://aka.ms/ssms/22/release/vs_SSMS.exe"  # Official Microsoft URL for SSMS 22.x bootstrapper
$InstallerPath = "$env:TEMP\vs_SSMS.exe"  # Temporary location for the bootstrapper
$LogFile = "$env:TEMP\SSMS_Install_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Function to write to log file
function Write-Log {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $true)]
        [string]$LogFile
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp - $Message" | Out-File -FilePath $LogFile -Append
}

# Function to check if the script is running as administrator
function Test-Admin {
    $CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object Security.Principal.WindowsPrincipal($CurrentUser)
    return $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to verify SSMS installation via registry
function Test-SSMSInstalled {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$LogFile
    )

    Write-Log -Message "Checking if SQL Server Management Studio 22 is installed via registry..." -LogFile $LogFile

    try {
        # Check 64-bit and 32-bit uninstall registry keys
        $UninstallPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )

        $SSMSFound = $false
        $Version = $null

        foreach ($Path in $UninstallPaths) {
            $SSMSItems = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue | 
                Where-Object { $_.DisplayName -like "Microsoft SQL Server Management Studio*" -and $_.DisplayVersion -like "22.*" }
            
            if ($SSMSItems) {
                $SSMSFound = $true
                $Version = $SSMSItems | Sort-Object DisplayVersion -Descending | Select-Object -First 1 -ExpandProperty DisplayVersion
                Write-Log -Message "SSMS 22 found in registry at $Path. Version: $Version" -LogFile $LogFile
                break
            }
        }

        if ($SSMSFound) {
            Write-Log -Message "SQL Server Management Studio 22 is installed. Version: $Version" -LogFile $LogFile
            return $true
        } else {
            Write-Log -Message "SQL Server Management Studio 22 is not installed." -LogFile $LogFile
            return $false
        }
    } catch {
        Write-Log -Message "ERROR: Failed to verify SSMS installation via registry. Error: $($_.Exception.Message)" -LogFile $LogFile
        Write-Error "Failed to verify SSMS installation. Error: $($_.Exception.Message)"
        return $false
    }
}

# Start logging
Write-Log -Message "Starting SQL Server Management Studio (SSMS) 22.x installation script." -LogFile $LogFile

# Check for administrative privileges
if (-not (Test-Admin)) {
    Write-Log -Message "ERROR: Script must be run as an administrator." -LogFile $LogFile
    Write-Error "This script requires administrative privileges. Please run PowerShell as an administrator."
    exit 1
}

# Check if SSMS is already installed
#if (Test-SSMSInstalled -LogFile $LogFile) {
#    Write-Host "SQL Server Management Studio 22 is already installed. Exiting."
#    Write-Log -Message "Script terminated: SSMS 22 is already installed." -LogFile $LogFile
#    exit 0
#}

# Download the SSMS bootstrapper
Write-Log -Message "Downloading SSMS 22 bootstrapper from $DownloadUrl..." -LogFile $LogFile
try {
    $ProgressPreference = 'SilentlyContinue'  # Suppress progress bar for faster download
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $InstallerPath -ErrorAction Stop
    Write-Log -Message "Download successful: $InstallerPath" -LogFile $LogFile
} catch {
    Write-Log -Message "ERROR: Failed to download SSMS bootstrapper. Error: $($_.Exception.Message)" -LogFile $LogFile
    Write-Error "Failed to download SSMS bootstrapper. Error: $($_.Exception.Message)"
    exit 1
}

# Verify the downloaded file exists
if (-not (Test-Path $InstallerPath)) {
    Write-Log -Message "ERROR: Bootstrapper file not found at $InstallerPath." -LogFile $LogFile
    Write-Error "Bootstrapper file not found at $InstallerPath."
    exit 1
}

# Install SSMS silently using Visual Studio Installer
Write-Log -Message "Installing SQL Server Management Studio 22..." -LogFile $LogFile
try {
    $Arguments = "--quiet --norestart --installPath `"C:\Program Files (x86)\Microsoft SQL Server Management Studio 22`" --add Microsoft.VisualStudio.Workload.Sql"
    $Process = Start-Process -FilePath $InstallerPath -ArgumentList $Arguments -Wait -PassThru -ErrorAction Stop
    Write-Log -Message "Installation exit code: $($Process.ExitCode)" -LogFile $LogFile
    
    if ($Process.ExitCode -eq 0) {
        Write-Log -Message "Installation completed successfully." -LogFile $LogFile
    } elseif ($Process.ExitCode -eq 3010) {
        Write-Log -Message "Installation completed successfully, but a reboot is required." -LogFile $LogFile
        Write-Host "Installation completed successfully, but a reboot is required."
    } else {
        Write-Log -Message "ERROR: Installation failed with exit code $($Process.ExitCode). Check logs in %APPDATA%\Microsoft\VisualStudio\Setup" -LogFile $LogFile
        Write-Error "Installation failed with exit code $($Process.ExitCode). Check logs in %APPDATA%\Microsoft\VisualStudio\Setup"
        exit $Process.ExitCode
    }
} catch {
    Write-Log -Message "ERROR: Installation process failed. Error: $($_.Exception.Message)" -LogFile $LogFile
    Write-Error "Installation process failed. Error: $($_.Exception.Message)"
    exit 1
}

# Verify installation
#if (Test-SSMSInstalled -LogFile $LogFile) {
#    Write-Host "SQL Server Management Studio 22 installed successfully."
#    Write-Log -Message "Verification: SSMS 22 installed successfully." -LogFile $LogFile
#} else {
#    Write-Log -Message "ERROR: Verification failed. SSMS 22 not detected after installation." -LogFile $LogFile
#    Write-Error "Verification failed. SSMS 22 not detected after installation."
#    exit 1
#}

Write-Log -Message "Script completed successfully." -LogFile $LogFile
Write-Host "SQL Server Management Studio 22 installed. Log file: $LogFile"