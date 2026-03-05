<#This will generate a folder structure for the DeployR sources, which can be used to organize the files needed for deployment. 
It will also copy the CM Trace executable and the 2PXE certificate (if it exists) to the appropriate locations within the WinPEContent folder.

Remember, DeployR has no tie back to this, it's just nice to keep track of sources for the ability to easily reference them or make edits and re-upload to DeployR when needed.

UPDATE Variable: $DeployRSourcesPath to the desired location for the source files.
#>
$DeployRSourcesPath = "E:\DeployRSources"
    
    Write-Host "Creating source directory structure in $DeployRSourcesPath..." -ForegroundColor Cyan
    
    # Define the folder structure
    $folderStructure = @(
    # WinPEContent folders
    "WinPEContent\Certificates",
    "WinPEContent\Drivers",
    "WinPEContent\ExtraFiles",
    "WinPEContent\ExtraFiles\Windows",
    "WinPEContent\ExtraFiles\Windows\System32",
    "WinPEContent\WinRE",
    
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
    "DriverPacks\Dell",
    "DriverPacks\HP",
    "DriverPacks\Lenovo",
    "DriverPacks\Panasonic"
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