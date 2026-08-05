# Configure root download path

$RootPath = "D:\SourceRepo\DriverPacks\X64\WinPE"
$ProxmoxSourcePath = Join-Path -Path $RootPath -ChildPath 'Proxmox'
$ProxmoxIsoUrl = 'https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/latest-virtio/virtio-win.iso'
$ProxmoxContentName = 'Driver Pack - Proxmox - VirtIO'

function Import-ProxmoxVirtIODriverPack {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SourcePath,

        [Parameter(Mandatory)]
        [string]$IsoUrl,

        [Parameter(Mandatory)]
        [string]$ContentName
    )

    if (-not (Test-Path -Path $SourcePath -PathType Container)) {
        New-Item -Path $SourcePath -ItemType Directory -Force | Out-Null
    }

    $isoFileName = Split-Path -Path $IsoUrl -Leaf
    $isoPath = Join-Path -Path $SourcePath -ChildPath $isoFileName
    $extractPath = Join-Path -Path $SourcePath -ChildPath 'Extracted'

    Write-Host "Downloading Proxmox VirtIO ISO to $isoPath" -ForegroundColor Cyan
    if (-not (Test-Path -Path $isoPath -PathType Leaf)) {
        try {
            Start-BitsTransfer -Source $IsoUrl -Destination $isoPath -RetryInterval 60 -RetryTimeout 3600 -CustomHeaders 'User-Agent:Bob' -ErrorAction Stop
        }
        catch {
            Write-Warning "BITS download failed or was redirected: $($_.Exception.Message)"
            Write-Host "  Falling back to Invoke-WebRequest..." -ForegroundColor Yellow
            Invoke-WebRequest -Uri $IsoUrl -OutFile $isoPath -Headers @{ 'User-Agent' = 'Bob' } -MaximumRedirection 10 -AllowInsecureRedirect -ErrorAction Stop
        }
    }
    else {
        Write-Host "  ISO already exists, skipping download." -ForegroundColor DarkGray
    }

    if (-not (Test-Path -Path $isoPath -PathType Leaf)) {
        throw "ISO download failed. File not found at $isoPath"
    }

    Write-Host "Extracting ISO contents to $extractPath" -ForegroundColor Cyan
    if (Test-Path -Path $extractPath) {
        Remove-Item -Path $extractPath -Recurse -Force -ErrorAction Stop
    }
    New-Item -Path $extractPath -ItemType Directory -Force | Out-Null

    $mountedImage = $null
    try {
        $mountedImage = Mount-DiskImage -ImagePath $isoPath -PassThru -ErrorAction Stop
        $mountedVolume = $mountedImage | Get-Volume -ErrorAction Stop

        if (-not $mountedVolume.DriveLetter) {
            throw "Mounted ISO did not expose a drive letter."
        }

        $mountedDriveRoot = "$($mountedVolume.DriveLetter):\"
        Copy-Item -Path "$mountedDriveRoot*" -Destination $extractPath -Recurse -Force -ErrorAction Stop
    }
    finally {
        if ($mountedImage) {
            try {
                Dismount-DiskImage -ImagePath $isoPath -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Warning "Failed to dismount ISO $($isoPath): $($_.Exception.Message)"
            }
        }
    }

    $contentItem = Get-DeployRContentItem | Where-Object { $_.Name -eq $ContentName } | Select-Object -First 1
    if (-not $contentItem) {
        Write-Host "Creating DeployR content item: $ContentName" -ForegroundColor Cyan
        $contentItem = New-DeployRContentItem -Name $ContentName -Type Folder -Purpose DriverPack -Description "Source: $isoFileName"
    }
    else {
        Write-Host "Using existing DeployR content item: $ContentName" -ForegroundColor Yellow
    }

    $newVersion = New-DeployRContentItemVersion -ContentItemId $contentItem.id -Description "Source: $SourcePath" -DriverManufacturer 'Proxmox' -DriverModel 'VirtIO' -SourceFolder $extractPath
    $ciVersion = Update-DeployRContentItemContent -ContentId $contentItem.id -ContentVersion $newVersion.versionNo -SourceFolder $extractPath

    Write-Host "Driver Pack upload complete." -ForegroundColor Green
    Write-Host "  CI ID: $($ciVersion.contentItemId), Version: $($ciVersion.versionNo), Size: $([math]::Round($ciVersion.contentSize / 1MB, 2)) MB" -ForegroundColor DarkGray
}

if (-not (Test-Path -Path $RootPath -PathType Container)) {
    Write-Error "Root path does not exist: $RootPath. Update the `$RootPath value near the top of this script to point to an existing folder, then run the script again."
    exit 1
}

# Check for Administrator role
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}
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


#region Execution Area
# =============================================================================
# EXECUTION AREA - Download Proxmox VirtIO Driver Pack
# =============================================================================
if (Test-Path 'C:\Program Files\2Pint Software\DeployR\Client\PSModules\DeployR.Utility') {
    Write-Host "DeployR.Utility module found."
    Import-Module 'C:\Program Files\2Pint Software\DeployR\Client\PSModules\DeployR.Utility'
    if (Connect-ToDeployR) {
        Import-ProxmoxVirtIODriverPack -SourcePath $ProxmoxSourcePath -IsoUrl $ProxmoxIsoUrl -ContentName $ProxmoxContentName
    }
    
} else {
    Write-Host "DeployR.Utility module not found. Please Where DeployR Server is installed to and update paths."
}

