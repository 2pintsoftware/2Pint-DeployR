<#
Builds a standard source folder structure used to stage DeployR-related content.

What this script does:
1. Detects all fixed local disks except C:.
2. Selects the disk with the largest total capacity.
3. Sets the source root to <SelectedDrive>:\SourceRepo (falls back to C:\SourceRepo if no other fixed disk exists).
4. Creates the predefined folder tree for WinPE content, applications, OS packages, and driver packs.
5. Copies CMTrace into WinPE content (or downloads it if missing locally).
6. Copies the 2PXE certificate into WinPEContent\Certificates when present.

Purpose:
This is for organizing and maintaining source content used during deployment workflows.
It is not a required DeployR component, but provides a consistent working structure for editing and re-uploading content.
#>

$candidateDrives = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType = 3" |
    Where-Object { $_.DeviceID -ne 'C:' }

if ($candidateDrives) {
    $selectedDrive = $candidateDrives | Sort-Object -Property Size -Descending | Select-Object -First 1
    $DeployRSourcePath = "$($selectedDrive.DeviceID)\SourceRepo"
    Write-Host "Selected source drive: $($selectedDrive.DeviceID) (size: $([math]::Round($selectedDrive.Size / 1GB, 2)) GB)" -ForegroundColor Cyan
}
else {
    $DeployRSourcePath = "C:\SourceRepo"
    Write-Host "No fixed drive besides C: was found. Falling back to $DeployRSourcePath" -ForegroundColor Yellow
}

$DeployRSourcesPath = $DeployRSourcePath
    
    Write-Host "Creating source directory structure in $DeployRSourcesPath..." -ForegroundColor Cyan
    
    # Define the folder structure
    $folderStructure = @(
    
    # Applications folders
    "Applications\2PintSoftware\StifleRClient",
    "Applications\7zip",
    "Applications\NotepadPP",
    "Applications\VSCode",
    
    # OSPackages folders
    "OperatingSystems\ClientOS\Win1123H2",
    "OperatingSystems\ClientOS\Win1124H2",
    "OperatingSystems\ClientOS\Win1125H2",
    "OperatingSystems\ServerOS\Server2019",
    "OperatingSystems\ServerOS\Server2022",
    "OperatingSystems\ServerOS\Server2025",
    
    # DriverPacks folders
    # Full OS Driver Packs
    "DriverPacks\X64\Win11\Dell",
    "DriverPacks\X64\Win11\HP",
    "DriverPacks\X64\Win11\Lenovo",
    "DriverPacks\X64\Win11\Panasonic",
    "DriverPacks\ARM64\Win11\Dell",
    "DriverPacks\ARM64\Win11\HP",
    "DriverPacks\ARM64\Win11\Lenovo",
    "DriverPacks\ARM64\Win11\Panasonic"

    # WinPE Driver Packs folders
    "DriverPacks\X64\WinPE\Dell",
    "DriverPacks\X64\WinPE\HP",
    "DriverPacks\X64\WinPE\Lenovo",
    "DriverPacks\X64\WinPE\Panasonic",
    "DriverPacks\ARM64\WinPE\Dell",
    "DriverPacks\ARM64\WinPE\HP",
    "DriverPacks\ARM64\WinPE\Lenovo",
    "DriverPacks\ARM64\WinPE\Panasonic"

    #Other Content Items folders
    # WinPEContent folders
    "Other\Certificates",
    "Other\ExtraFiles",
    "Other\ExtraFiles\Windows",
    "Other\ExtraFiles\Windows\System32",
    "Other\WinRE",
    "Other\CustomStepDefScripts",
    "Other\CustomOrganizationScripts",
    "Other\BrandingAssets"
    )
    
    # Create each folder in the structure
    foreach ($folder in $folderStructure) {
        $fullPath = Join-Path -Path $DeployRSourcesPath -ChildPath $folder
        try {
            if (-not (Test-Path -Path $fullPath)) {
                New-Item -Path $fullPath -ItemType Directory -Force | Out-Null
                Write-Host "  Created: $folder" -ForegroundColor Green
            }
            else {
                Write-Host "  Exists: $folder" -ForegroundColor DarkGray
            }
        }
        catch {
            Write-Warning "  Failed to create: $folder - $_"
        }
    }
    
    Write-Host "Source directory structure creation completed." -ForegroundColor Cyan
    
    #Copy CM Trace to WinPE
    $sourceCMTracePath = "C:\Windows\System32\cmtrace.exe"
    $destCMTracePath = Join-Path -Path $DeployRSourcesPath -ChildPath "WinPEContent\ExtraFiles\Windows\System32\cmtrace.exe"
    if (Test-Path -path $sourceCMTracePath) {
        Copy-Item -Path $sourceCMTracePath -Destination $destCMTracePath -Force -ErrorAction Stop
        Write-Host "Copied CM Trace to $destCMTracePath" -ForegroundColor Green
    } else {
        Write-Host "CM Trace not found at $sourceCMTracePath - Downloading instead" -ForegroundColor Yellow
        Invoke-WebRequest -Uri "https://patchmypc.com/cmtrace" -OutFile $destCMTracePath -ErrorAction Stop
        Write-Host "Downloaded CM Trace to $destCMTracePath" -ForegroundColor Green
    }
    # Copy 2PXE certificate to WinPEContent\Certificates if it exists
    $sourceCertPath = "C:\Program Files\2Pint Software\2PXE\x64\ca.crt"
    $destCertFolder = Join-Path -Path $DeployRSourcesPath -ChildPath "WinPEContent\Certificates"
    
    if (Test-Path -Path $sourceCertPath) {
        try {
            $destCertPath = Join-Path -Path $destCertFolder -ChildPath "ca.crt"
            Copy-Item -Path $sourceCertPath -Destination $destCertPath -Force -ErrorAction Stop
            Write-Host "Copied 2PXE certificate to $destCertPath" -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to copy 2PXE certificate: $_"
        }
    }
    else {
        Write-Host "2PXE certificate not found at $sourceCertPath - skipping copy" -ForegroundColor Yellow
    }