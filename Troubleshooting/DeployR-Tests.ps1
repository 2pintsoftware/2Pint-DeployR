#Goal here is to connect to the DeployR Server API and do some checks on content items.

# Check for Administrator role
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}
#region Function
function Connect-ToDeployR {
    try {
        if (Test-Path 'C:\Program Files\2Pint Software\DeployR\Client\PSModules\DeployR.Utility') {
            Import-Module 'C:\Program Files\2Pint Software\DeployR\Client\PSModules\DeployR.Utility' -ErrorAction Stop
        }
        elseif (Get-Module -ListAvailable -Name DeployR.Utility) {
            Import-Module DeployR.Utility -ErrorAction Stop
        }
        else {
            throw "DeployR.Utility module not found. Please ensure DeployR Client is installed."
        }
        
        Write-Host "Connecting to DeployR..." -ForegroundColor Cyan
        Import-Module 'C:\Program Files\2Pint Software\DeployR\Client\PSModules\DeployR.Utility'
        
        if (Test-Path "HKLM:\software\2Pint Software\DeployR\GeneralSettings") {
            $DeployRReg = Get-Item -Path "HKLM:\SOFTWARE\2Pint Software\DeployR\GeneralSettings"
            $ClientPasscode = $DeployRReg.GetValue("ClientPasscode")
            Connect-DeployR -Passcode $ClientPasscode -ErrorAction Stop
        }
        elseif (Test-Path "D:\DeployRPasscode.txt") {
            $ClientPasscode = (Get-Content "D:\DeployRPasscode.txt" -Raw)
            Connect-DeployR -Passcode $ClientPasscode -ErrorAction Stop
        }
        else {
            throw "Cannot find DeployR Client Passcode in registry or D:\DeployRPasscode.txt"
            Connect-DeployR
        }
        
        Write-Host "Connected to DeployR" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to connect to DeployR: $_"
        return $false
    }
}

function Get-DeployRContentPath {
    $RegPath = "HKLM:\SOFTWARE\2Pint Software\DeployR\GeneralSettings"
    $DeployRRegData = Get-ItemProperty -Path $RegPath -ErrorAction SilentlyContinue
    if ($DeployRRegData -and $DeployRRegData.ContentLocation) {
        $DeployRContentPath = $DeployRRegData.ContentLocation
    }
    else {
        if (Test-Path "$env:ProgramData\2Pint Software\DeployR\Content") {
            $DeployRContentPath = "$env:ProgramData\2Pint Software\DeployR\Content"
        }
        else {
            Write-Warning "Unable to determine DeployR Content Location from registry or default path."
            $DeployRContentPath = $null
        }
    }
    return $DeployRContentPath
}

#endregion
$TempFolder = "$env:USERPROFILE\Downloads\DeployR_TroubleShootingLogs"
if (!(Test-Path -Path $TempFolder)){New-Item -Path $TempFolder -ItemType Directory -Force | Out-Null}
$TranscriptFilePath = "$TempFolder\Check-DeployR_TroubleShooting_ContentItems.log"
if (Test-Path -Path $TranscriptFilePath) {
    Remove-Item -Path $TranscriptFilePath -Force
} 
Start-Transcript -Path $TranscriptFilePath -Force

#Execution Area - Running Tests
Connect-ToDeployR

$Bootimages = Get-DeployRMetadata -Type BootImage
$Winx64Bootimage = $Bootimages | Where-Object { $_.architecture -eq "x64" -and $_.platform -eq "Windows" }
if ($Winx64Bootimage.Count -gt 0) {
    Write-Host "Found $($Winx64Bootimage.Count) Windows x64 BootImage(s):" -ForegroundColor Green
    if ($Winx64Bootimage.status -ne 'Generated') {
        Write-Host "" -ForegroundColor Red
        Write-Host "WARNING: BootImage is not in 'Generated' status. Current status: $($Winx64Bootimage.status)" -ForegroundColor Red
        Write-Host "This may indicate an issue with the BootImage generation process." -ForegroundColor Red
        Write-Host "Please check the DeployR server logs for any errors during BootImage generation." -ForegroundColor Red
        Write-Host "" -ForegroundColor Red
    }
    $BootImagePath = "$(Get-DeployRContentPath)\Content\Boot\winpe_amd64.wim"
    if (Test-Path $BootImagePath) {
        $BootImageSizeMB = [Math]::Round((Get-Item $BootImagePath).Length / 1MB, 2)
        $WinImageInfo = Get-WindowsImage -ImagePath $BootImagePath -Index 1
        Write-Host " Boot Image Path: $BootImagePath" -ForegroundColor Cyan
        Write-Host " Boot Image Size: $BootImageSizeMB MB" -ForegroundColor Cyan
        Write-Host " Boot Image Version: $($WinImageInfo.Version)" -ForegroundColor Cyan
        Write-Host " Boot Image Edition: $($WinImageInfo.EditionID)" -ForegroundColor Cyan
        Write-Host " Boot Image Architecture: $($WinImageInfo.Architecture)" -ForegroundColor Cyan
        Write-Host " Boot Image Languages: $($WinImageInfo.Languages -join ', ')" -ForegroundColor Cyan
        Write-Host " Boot Image Last Modified: $($WinImageInfo.ModifiedTime)" -ForegroundColor Cyan
    }
    else {
        Write-Warning "Boot image file not found at expected path: $BootImagePath"
    }
    if ($Winx64Bootimage.driversContentItem -eq $null) {
        Write-Host "No driver pack assigned to Windows x64 BootImage." -ForegroundColor Yellow
    }
    else{
        $AssignedDrivePackCIID = $Winx64Bootimage.driversContentItem -split(':') | Select-Object -First 1
        $AssignedDrivePackCIVersion =  $Winx64Bootimage.driversContentItem -split(':') | Select-Object -Last 1
        $AssignedDriverPackCI = Get-DeployRContentItem -Id $AssignedDrivePackCIID
        $AssignedDriverPackVer = Get-DeployRContentItemVersion -ContentItemId $AssignedDrivePackCIID -Version $AssignedDrivePackCIVersion
        Write-Host "Assigned Driver Pack for Windows x64 BootImage:" -ForegroundColor Green -NoNewline
        Write-Host " $($AssignedDriverPackCI.Name) (Version: $($AssignedDriverPackVer.versionNo))" -ForegroundColor Magenta
        Write-Host " Driver Pack CI Type: $($AssignedDriverPackCI.contentItemType)" -ForegroundColor Cyan
        Write-Host " Driver Pack CI Created: $([DateTime]::UnixEpoch.AddSeconds($AssignedDriverPackVer.createdDate).ToString("yyyy-MM-dd-HHmmss"))" -ForegroundColor Cyan
        Write-Host " Driver Pack CI Last Modified: $([DateTime]::UnixEpoch.AddSeconds($AssignedDriverPackVer.lastModifiedDate).ToString("yyyy-MM-dd-HHmmss"))" -ForegroundColor Cyan
        Write-Host " Driver Pack WIM Size: $([Math]::Round($AssignedDriverPackVer.contentSize / 1MB, 2)) MB" -ForegroundColor Cyan
    }
    if ($Winx64Bootimage.certificateContentItem -ne $null) {
        $AssignedCertificateCIID = $Winx64Bootimage.certificateContentItem -split(':') | Select-Object -First 1
        $AssignedCertificateCIVersion =  $Winx64Bootimage.certificateContentItem -split(':') | Select-Object -Last 1
        $AssignedCertificateCI = Get-DeployRContentItem -Id $AssignedCertificateCIID
        $AssignedCertificateVer = Get-DeployRContentItemVersion -ContentItemId $AssignedCertificateCIID -Version $AssignedCertificateCIVersion
        Write-Host "Assigned Certificate for Windows x64 BootImage:" -ForegroundColor Green -NoNewline
        Write-Host " $($AssignedCertificateCI.Name) (Version: $($AssignedCertificateVer.versionNo))" -ForegroundColor Magenta
        Write-Host " Certificate CI Type: $($AssignedCertificateCI.contentItemType)" -ForegroundColor Cyan
        Write-Host " Certificate CI Created: $([DateTime]::UnixEpoch.AddSeconds($AssignedCertificateVer.createdDate).ToString("yyyy-MM-dd-HHmmss"))" -ForegroundColor Cyan
        Write-Host " Certificate CI Last Modified: $([DateTime]::UnixEpoch.AddSeconds($AssignedCertificateVer.lastModifiedDate).ToString("yyyy-MM-dd-HHmmss"))" -ForegroundColor Cyan
    }
    else {
        Write-Host "No certificate assigned to Windows x64 BootImage." -ForegroundColor Red
    }
    if ($Winx64Bootimage.stifleRClientContentItem -ne $null) {
        $AssignedStifleRCIID = $Winx64Bootimage.stifleRClientContentItem -split(':') | Select-Object -First 1
        $AssignedStifleRCIVersion =  $Winx64Bootimage.stifleRClientContentItem -split(':') | Select-Object -Last 1
        $AssignedStifleRCICI = Get-DeployRContentItem -Id $AssignedStifleRCIID
        $AssignedStifleRCIVer = Get-DeployRContentItemVersion -ContentItemId $AssignedStifleRCIID -Version $AssignedStifleRCIVersion
        Write-Host "Assigned StifleR Client for Windows x64 BootImage:" -ForegroundColor Green -NoNewline
        Write-Host " $($AssignedStifleRCICI.Name) (Version: $($AssignedStifleRCIVer.versionNo))" -ForegroundColor Magenta
        Write-Host " StifleR Client CI Type: $($AssignedStifleRCICI.contentItemType)" -ForegroundColor Cyan
        Write-Host " StifleR Client CI Created: $([DateTime]::UnixEpoch.AddSeconds($AssignedStifleRCIVer.createdDate).ToString("yyyy-MM-dd-HHmmss"))" -ForegroundColor Cyan
        Write-Host " StifleR Client CI Last Modified: $([DateTime]::UnixEpoch.AddSeconds($AssignedStifleRCIVer.lastModifiedDate).ToString("yyyy-MM-dd-HHmmss"))" -ForegroundColor Cyan
    }
    else {
        Write-Host "No StifleR Client assigned to Windows x64 BootImage. (OPTIONAL)" -ForegroundColor Yellow
    }
    if ($Winx64Bootimage.winREContentItem -ne $null) {
        $AssignedWinRECIID = $Winx64Bootimage.winREContentItem -split(':') | Select-Object -First 1
        $AssignedWinRECIVersion =  $Winx64Bootimage.winREContentItem -split(':') | Select-Object -Last 1
        $AssignedWinRECI = Get-DeployRContentItem -Id $AssignedWinRECIID
        $AssignedWinRECIVer = Get-DeployRContentItemVersion -ContentItemId $AssignedWinRECIID -Version $AssignedWinRECIVersion
        Write-Host "Assigned WinRE for Windows x64 BootImage:" -ForegroundColor Green -NoNewline
        Write-Host " $($AssignedWinRECI.Name) (Version: $($AssignedWinRECIVer.versionNo))" -ForegroundColor Magenta
        Write-Host " WinRE CI Type: $($AssignedWinRECI.contentItemType)" -ForegroundColor Cyan
        Write-Host " WinRE CI Created: $([DateTime]::UnixEpoch.AddSeconds($AssignedWinRECIVer.createdDate).ToString("yyyy-MM-dd-HHmmss"))" -ForegroundColor Cyan
        Write-Host " WinRE CI Last Modified: $([DateTime]::UnixEpoch.AddSeconds($AssignedWinRECIVer.lastModifiedDate).ToString("yyyy-MM-dd-HHmmss"))" -ForegroundColor Cyan
    }
    else {
        Write-Host "No WinRE assigned to Windows x64 BootImage. (OPTIONAL)" -ForegroundColor Yellow
    }
    if ($Winx64Bootimage.extraFilesContentItem -ne $null) {
        $AssignedExtraFilesCIID = $Winx64Bootimage.extraFilesContentItem -split(':') | Select-Object -First 1
        $AssignedExtraFilesCIVersion =  $Winx64Bootimage.extraFilesContentItem -split(':') | Select-Object -Last 1
        $AssignedExtraFilesCI = Get-DeployRContentItem -Id $AssignedExtraFilesCIID
        $AssignedExtraFilesCIVer = Get-DeployRContentItemVersion -ContentItemId $AssignedExtraFilesCIID -Version $AssignedExtraFilesCIVersion
        Write-Host "Assigned Extra Files for Windows x64 BootImage:" -ForegroundColor Green -NoNewline
        Write-Host " $($AssignedExtraFilesCI.Name) (Version: $($AssignedExtraFilesCIVer.versionNo))" -ForegroundColor Magenta
        Write-Host " Extra Files CI Type: $($AssignedExtraFilesCI.contentItemType)" -ForegroundColor Cyan
        Write-Host " Extra Files CI Created: $([DateTime]::UnixEpoch.AddSeconds($AssignedExtraFilesCIVer.createdDate).ToString("yyyy-MM-dd-HHmmss"))" -ForegroundColor Cyan
        Write-Host " Extra Files CI Last Modified: $([DateTime]::UnixEpoch.AddSeconds($AssignedExtraFilesCIVer.lastModifiedDate).ToString("yyyy-MM-dd-HHmmss"))" -ForegroundColor Cyan
    }
    else {
        Write-Host "No Extra Files assigned to Windows x64 BootImage. (OPTIONAL)" -ForegroundColor Yellow
    }
}
else {
    Write-Warning "No Windows x64 BootImages found."
}

Stop-Transcript
Write-Host ""
Write-Host "Transcript Recorded to $TranscriptFilePath" -ForegroundColor Green
Write-Host "=========================================================================" -ForegroundColor DarkGray