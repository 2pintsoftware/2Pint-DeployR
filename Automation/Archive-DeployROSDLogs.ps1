<#
.NOTES
Change Log
- 2026.10.13 - Added age-based archiving for ImportOEMDriverPack*.log and ImportCloudOS*.log files into separate archive folders.

.SYNOPSIS
Archives older DeployR OSD zip logs and ImportOEMDriverPack/ImportCloudOS logs from the Logs folder.

.DESCRIPTION
This script finds the DeployR Content root, targets its child Logs folder, and moves
date-prefixed OSD backup zip files older than a configured number of days into
Logs\OSDLogsArchive. ImportOEMDriverPack*.log and ImportCloudOS*.log files older
than the same threshold are moved into their respective archive folders.

The script only processes zip files that match this naming style:
YYYYMMDD_HHMMSS_<anything>.zip

Examples:
20260319_140415_OSD4C4C45440035.zip
20260319_165328_OSDEE8DF6A9664A.zip

Non-zip files and zip files that do not match the date-prefixed pattern are ignored.

.NOTES
How log location is discovered:
1. Reads registry key HKLM:\SOFTWARE\2Pint Software\DeployR\GeneralSettings
2. Uses property ContentLocation when present and path exists
3. Falls back to $env:ProgramData\2Pint Software\DeployR\Content
4. Uses Logs as a subfolder of Content: <ContentLocation>\Logs

How to set archive age:
- Use parameter -ArchiveAfterDays
- Default is 14 days

How to clean up OSDLogsArchive:
- Use switch -CleanupArchive to enable cleanup
- Use -ArchiveCleanupAfterDays to control retention in archive
- Default retention is 90 days (about 3 months)

Logging:
- Uses CMTrace-compatible log entries
- Writes to <ContentLocation>\Logs\OSDLogsArchive\Archive-DeployROSDLogs.log (append-only)

Examples:
Dry run (no changes):
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Archive-DeployROSDLogs.ps1 -WhatIf

Archive files older than 30 days:
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Archive-DeployROSDLogs.ps1 -ArchiveAfterDays 30

Archive files and also remove archived zip files older than 90 days:
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Archive-DeployROSDLogs.ps1 -CleanupArchive

Archive files and remove archived zip files older than 120 days:
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Archive-DeployROSDLogs.ps1 -CleanupArchive -ArchiveCleanupAfterDays 120
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateRange(1, 3650)]
    [int]$ArchiveAfterDays = 14,

    [switch]$CleanupArchive,

    [ValidateRange(1, 3650)]
    [int]$ArchiveCleanupAfterDays = 90
)

$ErrorActionPreference = 'Stop'

function Get-DeployRContentPath {
    [CmdletBinding()]
    param()

    $registryPath = 'HKLM:\SOFTWARE\2Pint Software\DeployR\GeneralSettings'
    $defaultPath = Join-Path -Path $env:ProgramData -ChildPath '2Pint Software\DeployR\Content'

    $regData = Get-ItemProperty -Path $registryPath -ErrorAction SilentlyContinue
    if ($regData -and $regData.ContentLocation) {
        $regPath = $regData.ContentLocation
        if (Test-Path -LiteralPath $regPath) {
            Write-Host "DeployR ContentLocation (Registry): $regPath" -ForegroundColor Green
            return $regPath
        }
        else {
            Write-Warning "DeployR ContentLocation from registry does not exist: $regPath"
        }
    }

    if (Test-Path -LiteralPath $defaultPath) {
        Write-Host "DeployR ContentLocation (Default): $defaultPath" -ForegroundColor Yellow
        return $defaultPath
    }

    throw "DeployR Content location was not found in registry or default path: $defaultPath"
}

function Get-UniqueDestinationPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ArchiveFolder,

        [Parameter(Mandatory = $true)]
        [string]$FileName
    )

    $destination = Join-Path -Path $ArchiveFolder -ChildPath $FileName
    if (-not (Test-Path -LiteralPath $destination)) {
        return $destination
    }

    $name = [System.IO.Path]::GetFileNameWithoutExtension($FileName)
    $ext = [System.IO.Path]::GetExtension($FileName)
    $suffix = Get-Date -Format 'yyyyMMdd_HHmmss'

    return (Join-Path -Path $ArchiveFolder -ChildPath ("{0}_{1}{2}" -f $name, $suffix, $ext))
}

function Start-CMTraceLog {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $indexOfLastSlash = $Path.LastIndexOf('\')
    $directory = $Path.Substring(0, $indexOfLastSlash)

    if (-not (Test-Path -Path $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
}

function Write-CMTraceLog {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [string]$LogPath = $($Global:LogFilePath),

        [Parameter()]
        [ValidateSet(1, 2, 3)]
        [int]$LogLevel = 1,

        [Parameter()]
        [string]$Component = 'Archive-DeployROSDLogs',

        [Parameter()]
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Type
    )

    switch ($Type) {
        Info { $LogLevel = 1 }
        Warning { $LogLevel = 2 }
        Error { $LogLevel = 3 }
    }

    $timeGenerated = "$(Get-Date -Format HH:mm:ss).$((Get-Date).Millisecond)+000"
    $line = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="" type="{4}" thread="" file="">'
    $lineFormat = $Message, $timeGenerated, (Get-Date -Format MM-dd-yyyy), $Component, $LogLevel
    $line = $line -f $lineFormat

    try {
        if (-not $LogPath) {
            return
        }

        $indexOfLastSlash = $LogPath.LastIndexOf('\')
        $directory = $LogPath.Substring(0, $indexOfLastSlash)
        if (-not (Test-Path -Path $directory)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }

        Add-Content -Value $line -Path $LogPath
    }
    catch {
        # Avoid interrupting maintenance operations due to logging issues.
    }
}

$contentPath = Get-DeployRContentPath
$logsPath = Join-Path -Path $contentPath -ChildPath 'Logs'

if (-not (Test-Path -LiteralPath $logsPath)) {
    Write-Warning "Logs folder was not found: $logsPath"
    return
}

$archivePath = Join-Path -Path $logsPath -ChildPath 'OSDLogsArchive'
if (-not (Test-Path -LiteralPath $archivePath)) {
    if ($PSCmdlet.ShouldProcess($archivePath, 'Create archive folder')) {
        New-Item -Path $archivePath -ItemType Directory -Force | Out-Null
        Write-Host "Created archive folder: $archivePath" -ForegroundColor Cyan
    }
}

$Global:LogFilePath = Join-Path -Path $archivePath -ChildPath 'Archive-DeployROSDLogs.log'
Start-CMTraceLog -Path $Global:LogFilePath
$runId = [guid]::NewGuid().ToString()
Write-CMTraceLog -Message "Run heartbeat. RunId=$runId Script=Archive-DeployROSDLogs" -Type Info -Component 'Heartbeat'
Write-CMTraceLog -Message "Started archive maintenance run. ArchiveAfterDays=$ArchiveAfterDays CleanupArchive=$CleanupArchive ArchiveCleanupAfterDays=$ArchiveCleanupAfterDays" -Type Info -Component 'Init'

$cutoffDate = (Get-Date).AddDays(-$ArchiveAfterDays)
$datePrefixedZipPattern = '^\d{8}_\d{6}_.+\.zip$'

$filesToArchive = Get-ChildItem -Path $logsPath -File -Filter '*.zip' | Where-Object {
    $_.Name -match $datePrefixedZipPattern -and $_.LastWriteTime -lt $cutoffDate
}

if (-not $filesToArchive) {
    Write-Host "No matching OSD zip files older than $ArchiveAfterDays days found in $logsPath" -ForegroundColor Green
    Write-CMTraceLog -Message "No matching OSD zip files older than $ArchiveAfterDays days found in $logsPath" -Type Info -Component 'Archive'
}

$movedCount = 0
if ($filesToArchive) {
    foreach ($file in $filesToArchive) {
        $destinationPath = Get-UniqueDestinationPath -ArchiveFolder $archivePath -FileName $file.Name

        if ($PSCmdlet.ShouldProcess($file.FullName, "Move to $destinationPath")) {
            Move-Item -LiteralPath $file.FullName -Destination $destinationPath -ErrorAction Stop
            $movedCount++
            Write-Host "Archived: $($file.Name)" -ForegroundColor DarkGray
            Write-CMTraceLog -Message "Archived zip file '$($file.FullName)' to '$destinationPath'" -Type Info -Component 'Archive'
        }
    }
}

Write-Host "Archived $movedCount file(s) to $archivePath" -ForegroundColor Green
Write-CMTraceLog -Message "Archived $movedCount file(s) to $archivePath" -Type Info -Component 'Archive'

foreach ($logArchive in @(
    @{ NamePattern = 'ImportOEMDriverPack*.log'; ArchiveFolder = 'ImportOEMDriverPackArchive' },
    @{ NamePattern = 'ImportCloudOS*.log'; ArchiveFolder = 'ImportCloudOSArchive' }
)) {
    $logArchivePath = Join-Path -Path $logsPath -ChildPath $logArchive.ArchiveFolder
    if (-not (Test-Path -LiteralPath $logArchivePath)) {
        if ($PSCmdlet.ShouldProcess($logArchivePath, 'Create log archive folder')) {
            New-Item -Path $logArchivePath -ItemType Directory -Force | Out-Null
            Write-Host "Created archive folder: $logArchivePath" -ForegroundColor Cyan
        }
    }

    $logFilesToArchive = Get-ChildItem -Path $logsPath -File -Filter $logArchive.NamePattern | Where-Object {
        $_.LastWriteTime -lt $cutoffDate
    }

    if (-not $logFilesToArchive) {
        Write-Host "No $($logArchive.NamePattern) files older than $ArchiveAfterDays days found in $logsPath" -ForegroundColor Green
        Write-CMTraceLog -Message "No $($logArchive.NamePattern) files older than $ArchiveAfterDays days found in $logsPath" -Type Info -Component $logArchive.ArchiveFolder
        continue
    }

    $logMovedCount = 0
    foreach ($logFile in $logFilesToArchive) {
        $destinationPath = Get-UniqueDestinationPath -ArchiveFolder $logArchivePath -FileName $logFile.Name

        if ($PSCmdlet.ShouldProcess($logFile.FullName, "Move to $destinationPath")) {
            Move-Item -LiteralPath $logFile.FullName -Destination $destinationPath -ErrorAction Stop
            $logMovedCount++
            Write-Host "Archived: $($logFile.Name)" -ForegroundColor DarkGray
            Write-CMTraceLog -Message "Archived log '$($logFile.FullName)' to '$destinationPath'" -Type Info -Component $logArchive.ArchiveFolder
        }
    }

    Write-Host "Archived $logMovedCount $($logArchive.NamePattern) file(s) to $logArchivePath" -ForegroundColor Green
    Write-CMTraceLog -Message "Archived $logMovedCount $($logArchive.NamePattern) file(s) to $logArchivePath" -Type Info -Component $logArchive.ArchiveFolder
}

if ($CleanupArchive) {
    $archiveCutoffDate = (Get-Date).AddDays(-$ArchiveCleanupAfterDays)
    $archiveZipFilesToDelete = Get-ChildItem -Path $archivePath -File -Filter '*.zip' | Where-Object {
        $_.LastWriteTime -lt $archiveCutoffDate
    }

    if (-not $archiveZipFilesToDelete) {
        Write-Host "No archived zip files older than $ArchiveCleanupAfterDays days found in $archivePath" -ForegroundColor Green
        Write-CMTraceLog -Message "No archived zip files older than $ArchiveCleanupAfterDays days found in $archivePath" -Type Info -Component 'Cleanup'
    }
    else {
        $deletedCount = 0
        foreach ($archiveZip in $archiveZipFilesToDelete) {
            if ($PSCmdlet.ShouldProcess($archiveZip.FullName, 'Delete archived zip file')) {
                Remove-Item -LiteralPath $archiveZip.FullName -Force -ErrorAction Stop
                $deletedCount++
                Write-Host "Deleted archived zip: $($archiveZip.Name)" -ForegroundColor DarkGray
                Write-CMTraceLog -Message "Deleted archived zip file '$($archiveZip.FullName)'" -Type Info -Component 'Cleanup'
            }
        }

        Write-Host "Deleted $deletedCount archived zip file(s) older than $ArchiveCleanupAfterDays days from $archivePath" -ForegroundColor Yellow
        Write-CMTraceLog -Message "Deleted $deletedCount archived zip file(s) older than $ArchiveCleanupAfterDays days from $archivePath" -Type Warning -Component 'Cleanup'
    }
}
