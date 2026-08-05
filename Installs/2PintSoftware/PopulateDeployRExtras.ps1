<# This script populates the DeployR extras with the necessary information

1 - DeployR Sources WinPE Dell Driver Pack
2 - App Content Sources

RUN from PS7 Terminal with Admin Privleges on the DeployR Client Machine after running Setup-DeployR.ps1 to ensure DeployR.Utility module is available for use. This script can be re-run as needed to update the Driver Packs or App Content in DeployR.

#>

$useDDrive = $false
    
try {
    $vol = Get-Volume -DriveLetter D -ErrorAction SilentlyContinue
    if ($vol) {
        # Check drive type - ensure it's a local fixed disk (DriveType 3)
        # DriveType: 2 = Removable, 3 = Local Disk, 5 = CD-ROM
        $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='D:'" -ErrorAction SilentlyContinue
        
        # Only use D: if it's a local fixed disk with NTFS
        if ($disk -and $disk.DriveType -eq 3 -and $vol.FileSystem -eq 'NTFS') {
            $useDDrive = $true
        }
    }
}
catch {
    # Silently fall back to C: if any error occurs
    $useDDrive = $false
}

# Determine target location
if ($useDDrive) {
    $driveLetter = 'D:'
}
else {
    $driveLetter = 'C:'
}
$RootPath = "$driveLetter\SourceRepo"
write-host "RootPath is set to $RootPath"
# Ensure the script runs with elevated privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script requires administrative privileges. Please run PowerShell as Administrator."
    exit 1
}

if (Test-Path 'C:\Program Files\2Pint Software\DeployR\Client\PSModules\DeployR.Utility') {
    Write-Host "DeployR.Utility module found."
    Import-Module 'C:\Program Files\2Pint Software\DeployR\Client\PSModules\DeployR.Utility'
    #Set-DeployRHost "http://localhost:7282"
    $Passcode = (Get-Item -path 'HKLM:\SOFTWARE\2Pint Software\DeployR\GeneralSettings').GetValue("ClientPasscode")
    Connect-DeployR -Passcode $Passcode -ErrorAction Stop

} else {
    Write-Host "DeployR.Utility module not found. Please ensure DeployR Client is installed."
}

#region Functions
<#
.SYNOPSIS
    Get Dell WinPE 11 Driver Pack information and optionally download/extract it.

.DESCRIPTION
    This function retrieves information about the Dell WinPE 11 Driver Pack from the 
    mkaptano/tools GitHub repository, extracts the CAB download URL, and optionally
    downloads and/or extracts the driver pack using BITS transfer.

.PARAMETER Download
    Download the WinPE 11 driver pack CAB file using BITS transfer.

.PARAMETER Extract
    Extract the downloaded CAB file to the specified destination.
    Requires -Download or an existing CAB file at -DownloadPath.

.PARAMETER DownloadPath
    Destination path for the downloaded CAB file. 
    Default: $env:TEMP\DellWinPE11DriverPack.cab

.PARAMETER ExtractPath
    Destination folder for extracted driver pack contents.
    Default: $env:TEMP\DellWinPE11Drivers

.EXAMPLE
    Get-DellWinPE11DriverPack
    Returns information about the WinPE 11 driver pack including CAB download URL.

.EXAMPLE
    Get-DellWinPE11DriverPack -Download
    Downloads the WinPE 11 driver pack CAB file using BITS.

.EXAMPLE
    Get-DellWinPE11DriverPack -Download -Extract
    Downloads and extracts the driver pack.

.EXAMPLE
    Get-DellWinPE11DriverPack -Download -Extract -ExtractPath "C:\Drivers\WinPE11"
    Downloads and extracts to a specific location.

.NOTES
    Source: https://github.com/mkaptano/tools
    Maintained by: Mesut Kaptanoğlu (Dell Product Manager)
#>

<#
.SYNOPSIS
    Get Dell WinPE 11 Driver Pack information and optionally download/extract it.

.DESCRIPTION
    This function retrieves information about the Dell WinPE 11 Driver Pack from the 
    mkaptano/tools GitHub repository, extracts the CAB download URL, and optionally
    downloads and/or extracts the driver pack using BITS transfer.

.PARAMETER Download
    Download the WinPE 11 driver pack CAB file using BITS transfer.

.PARAMETER Extract
    Extract the downloaded CAB file to the specified destination.
    Requires -Download or an existing CAB file at -DownloadPath.

.PARAMETER DownloadPath
    Destination path for the downloaded CAB file. 
    Default: $env:TEMP\DellWinPE11DriverPack.cab

.PARAMETER ExtractPath
    Destination folder for extracted driver pack contents.
    Default: $env:TEMP\DellWinPE11Drivers

.EXAMPLE
    Get-DellWinPE11DriverPack
    Returns information about the WinPE 11 driver pack including CAB download URL.

.EXAMPLE
    Get-DellWinPE11DriverPack -Download
    Downloads the WinPE 11 driver pack CAB file using BITS.

.EXAMPLE
    Get-DellWinPE11DriverPack -Download -Extract
    Downloads and extracts the driver pack.

.EXAMPLE
    Get-DellWinPE11DriverPack -Download -Extract -ExtractPath "C:\Drivers\WinPE11"
    Downloads and extracts to a specific location.

.NOTES
    Source: https://github.com/mkaptano/tools
    Maintained by: Mesut Kaptanoğlu (Dell Product Manager)
#>

function Get-DellWinPE11DriverPack {
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$Download,
        
        [Parameter()]
        [switch]$Extract,
        
        [Parameter()]
        [string]$DownloadPath = "$env:TEMP\DellWinPE11DriverPack.cab",
        
        [Parameter()]
        [string]$ExtractPath = "$env:TEMP\DellWinPE11Drivers"
    )

    $gitHubUrl = "https://raw.githubusercontent.com/mkaptano/tools/refs/heads/main/README.md"
    
    try {
        Write-Host "Fetching Dell WinPE 11 Driver Pack information..." -ForegroundColor Cyan
        
        # Get the markdown content
        $content = Invoke-RestMethod -Uri $gitHubUrl -UseBasicParsing -ErrorAction Stop
        
        # Find the WinPE 11 Driver Pack row
        $lines = $content -split "`n"
        $winpe11Line = $null
        
        foreach ($line in $lines) {
            if ($line -match 'WinPE 11 Driver Pack' -and $line -match '\|') {
                $winpe11Line = $line
                break
            }
        }
        
        if (-not $winpe11Line) {
            throw "Could not find WinPE 11 Driver Pack in the tools list"
        }
        
        # Parse the table row
        $columns = $winpe11Line -split '\|' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
        
        $toolName = $columns[0] -replace '\*\*\*', '' -replace '\*\*', ''
        $driverID = $columns[1].Trim()
        $version = $columns[2].Trim()
        $releaseDate = $columns[3].Trim()
        
        # Extract Dell support page URL
        $linkText = $columns[5].Trim()
        $supportPageUrl = if ($linkText -match 'https://[^\s<>)]+') {
            $matches[0]
        } else {
            throw "Could not extract support page URL"
        }
        
        Write-Host "  Tool: $toolName" -ForegroundColor White
        Write-Host "  Driver ID: $driverID" -ForegroundColor Gray
        Write-Host "  Version: $version" -ForegroundColor Gray
        Write-Host "  Release Date: $releaseDate" -ForegroundColor Gray
        Write-Host "  Support Page: $supportPageUrl" -ForegroundColor Gray
        
        # Fetch the CAB download URL from the Dell support page
        Write-Host "`nFetching CAB download URL from Dell support page..." -ForegroundColor Cyan
        $cabUrl = Get-DellCABDownloadUrl -Url $supportPageUrl
        
        if (-not $cabUrl) {
            throw "Could not extract CAB download URL from Dell support page"
        }
        
        # Extract filename from URL
        $cabFileName = Split-Path $cabUrl -Leaf
        
        Write-Host "  CAB URL: $cabUrl" -ForegroundColor Green
        Write-Host "  File Name: $cabFileName" -ForegroundColor Gray
        
        # Create result object
        $result = [PSCustomObject]@{
            ToolName = $toolName
            DriverID = $driverID
            Version = $version
            ReleaseDate = $releaseDate
            SupportPageUrl = $supportPageUrl
            CABDownloadUrl = $cabUrl
            CABFileName = $cabFileName
            Downloaded = $false
            DownloadPath = $null
            Extracted = $false
            ExtractPath = $null
        }
        
        # Download if requested
        if ($Download) {
            Write-Host "`nDownloading CAB file..." -ForegroundColor Cyan
            
            # Ensure download directory exists
            $downloadDir = Split-Path $DownloadPath -Parent
            if (-not (Test-Path $downloadDir)) {
                New-Item -ItemType Directory -Path $downloadDir -Force | Out-Null
            }
            
            $downloadSuccess = $false
            
            # Try Request-DeployRCustomContent first (if available)
            try {
                Write-Host "  Attempting download using DeployR..." -ForegroundColor Gray
                Request-DeployRCustomContent -ContentName $cabFileName -ContentFriendlyName "Dell WinPE 11 Driver Pack CAB" -URL $cabUrl -DestinationPath $DownloadPath -ErrorAction Stop
                
                if (Test-Path $DownloadPath) {
                    $downloadSuccess = $true
                    Write-Host "  Downloaded via DeployR" -ForegroundColor Green
                }
            }
            catch {
                Write-Warning "DeployR download failed: $($_.Exception.Message)"
                Write-Host "  Falling back to BITS transfer..." -ForegroundColor Yellow
            }
            
            # Fall back to BITS if DeployR method failed
            if (-not $downloadSuccess) {
                try {
                    Write-Host "  Attempting download using BITS..." -ForegroundColor Gray
                    Start-BitsTransfer -Source $cabUrl -Destination $DownloadPath -DisplayName "Dell WinPE 11 Driver Pack" -Description "Downloading $cabFileName" -ErrorAction Stop -RetryInterval 60  -CustomHeaders "User-Agent:Bob"
                    
                    if (Test-Path $DownloadPath) {
                        $downloadSuccess = $true
                        Write-Host "  Downloaded via BITS" -ForegroundColor Green
                    }
                }
                catch {
                    Write-Error "BITS download also failed: $_"
                    throw "Both DeployR and BITS download methods failed"
                }
            }
            
            # Verify download and report results
            if ($downloadSuccess -and (Test-Path $DownloadPath)) {
                $fileInfo = Get-Item $DownloadPath
                $fileSizeMB = [math]::Round($fileInfo.Length / 1MB, 2)
                
                Write-Host "  Download complete!" -ForegroundColor Green
                Write-Host "  Location: $DownloadPath" -ForegroundColor White
                Write-Host "  Size: $fileSizeMB MB" -ForegroundColor Gray
                
                $result.Downloaded = $true
                $result.DownloadPath = $DownloadPath
            }
            else {
                throw "Download completed but file not found at expected location"
            }
        }
        
        # Extract if requested
        if ($Extract) {
            if (-not $result.Downloaded -and -not (Test-Path $DownloadPath)) {
                throw "Cannot extract: CAB file not found. Use -Download to download first, or specify existing file with -DownloadPath"
            }
            
            $cabPath = if ($result.Downloaded) { $result.DownloadPath } else { $DownloadPath }
            
            Write-Host "`nExtracting CAB file..." -ForegroundColor Cyan
            Write-Host "  Source: $cabPath" -ForegroundColor Gray
            Write-Host "  Destination: $ExtractPath" -ForegroundColor Gray
            
            # Ensure extract directory exists
            if (-not (Test-Path $ExtractPath)) {
                New-Item -ItemType Directory -Path $ExtractPath -Force | Out-Null
            }
            
            try {
                # Use expand.exe to extract CAB file
                $expandArgs = @(
                    $cabPath,
                    "-F:*",
                    $ExtractPath
                )
                
                $expandResult = Start-Process -FilePath "expand.exe" -ArgumentList $expandArgs -Wait -NoNewWindow -PassThru -RedirectStandardOutput "$env:TEMP\expand_output.txt" -RedirectStandardError "$env:TEMP\expand_error.txt"
                
                if ($expandResult.ExitCode -eq 0) {
                    $extractedFiles = Get-ChildItem -Path $ExtractPath -Recurse -File
                    
                    Write-Host "  Extraction complete!" -ForegroundColor Green
                    Write-Host "  Files extracted: $($extractedFiles.Count)" -ForegroundColor Gray
                    Write-Host "  Location: $ExtractPath" -ForegroundColor White
                    
                    $result.Extracted = $true
                    $result.ExtractPath = $ExtractPath
                } else {
                    throw "expand.exe returned exit code $($expandResult.ExitCode)"
                }
            }
            catch {
                Write-Error "CAB extraction failed: $_"
                throw
            }
        }
        
        return $result
    }
    catch {
        Write-Error "Failed to process Dell WinPE 11 Driver Pack: $_"
        return $null
    }
}

function Get-DellCABDownloadUrl {
    <#
    .SYNOPSIS
        Extract the CAB download URL from a Dell driver support page.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Url
    )
    
    try {
        Write-Verbose "Fetching Dell support page: $Url"
        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
        
        $downloadUrl = $null
        
        # Pattern 1: Look for .cab files in downloads.dell.com
        if ($response.Content -match '(https://downloads\.dell\.com/[^"<>\s]+\.cab)') {
            $downloadUrl = $matches[1]
        }
        
        # Pattern 2: Look for .cab files in dl.dell.com
        if (-not $downloadUrl -and $response.Content -match '(https://dl\.dell\.com/[^"<>\s]+\.cab)') {
            $downloadUrl = $matches[1]
        }
        
        # Pattern 3: Look for any .cab href
        if (-not $downloadUrl -and $response.Content -match 'href="(https://[^"]+\.cab)"') {
            $downloadUrl = $matches[1]
        }
        
        # Pattern 4: Look for data-download-url with .cab
        if (-not $downloadUrl -and $response.Content -match 'data-download-url="([^"]+\.cab)"') {
            $downloadUrl = $matches[1]
        }
        
        if ($downloadUrl) {
            # Clean up URL (remove HTML entities)
            $downloadUrl = $downloadUrl -replace '&amp;', '&'
            Write-Verbose "Found CAB URL: $downloadUrl"
            return $downloadUrl
        }
        
        return $null
    }
    catch {
        Write-Verbose "Failed to parse Dell support page: $_"
        return $null
    }
}
function Import-DellWinPEDriverPackBasic {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$FullSourcePath,
        [Parameter(Mandatory=$true)]
        [string]$CabUrl
    )

    if (-not (Test-Path -Path $FullSourcePath)) {
        New-Item -Path $FullSourcePath -ItemType Directory -Force | Out-Null
    }

    $cabFileName = Split-Path -Path $CabUrl -Leaf
    $cabPath = Join-Path -Path $FullSourcePath -ChildPath $cabFileName
    $extractPath = Join-Path -Path $FullSourcePath -ChildPath 'Extracted'

    Write-Host "Downloading Dell CAB to $cabPath"
    if (-not (Test-Path -Path $cabPath)) {
        Start-BitsTransfer -Source $CabUrl -Destination $cabPath -RetryInterval 60 -RetryTimeout 3600 -CustomHeaders "User-Agent:Bob" -ErrorAction Stop
    }
    else {
        Write-Host "  CAB already exists, skipping download."
    }

    if (-not (Test-Path -Path $cabPath)) {
        throw "CAB download failed. File not found at $cabPath"
    }

    Write-Host "Extracting CAB to $extractPath"
    if (Test-Path -Path $extractPath) {
        Remove-Item -Path $extractPath -Recurse -Force -ErrorAction Stop
    }
    New-Item -Path $extractPath -ItemType Directory -Force | Out-Null
    Expand -R $cabPath -F:* $extractPath | Out-Null

    $contentName = 'Driver Pack - Dell - WinPE11 - Win11'
    $contentItem = Get-DeployRContentItem | Where-Object { $_.Name -eq $contentName } | Select-Object -First 1

    if (-not $contentItem) {
        Write-Host "Creating DeployR DriverPack content item: $contentName"
        $contentItem = New-DeployRContentItem -Name $contentName -Type Folder -Purpose DriverPack -Description "File: $cabFileName"
    }
    else {
        Write-Host "Using existing DeployR content item: $contentName"
    }

    $newVersion = New-DeployRContentItemVersion -ContentItemId $contentItem.id -Description "Source: $FullSourcePath" -DriverManufacturer 'Dell' -DriverModel 'WinPE11' -SourceFolder $extractPath

    Write-Host "Uploading extracted content to DeployR (ContentId: $($contentItem.id), Version: $($newVersion.versionNo))"
    $ciVersion = Update-DeployRContentItemContent -ContentId $contentItem.id -ContentVersion $newVersion.versionNo -SourceFolder $extractPath

    Write-Host "Driver Pack upload complete." -ForegroundColor Green
    Write-Host "  CI ID: $($ciVersion.contentItemId), Version: $($ciVersion.versionNo), Size: $([math]::Round($ciVersion.contentSize / 1MB, 2)) MB" -ForegroundColor DarkGray
}


# Export the main function
#Export-ModuleMember -Function Get-DellWinPE11DriverPack

#endregion
$DellWinPE = Get-DellWinPE11DriverPack
$FullSourcePath = "$RootPath\DriverPacks\X64\WinPE\Dell"

if (Test-Path -path $FullSourcePath){
    Write-Host "Dell Driver Pack already exists at $FullSourcePath"
} else {
    New-Item -Path $FullSourcePath -ItemType Directory -Force | Out-Null
    Write-Host "Created directory for Dell Driver Pack at $FullSourcePath"
}

if ($DellWinPE) {
    Import-DellWinPEDriverPackBasic -FullSourcePath $FullSourcePath -CabUrl $DellWinPE.CABDownloadUrl
} else {
    Write-Warning "Could not find Dell WinPE Driver Pack URL."
}

