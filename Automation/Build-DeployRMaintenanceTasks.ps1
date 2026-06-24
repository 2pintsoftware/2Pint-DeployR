<#
.SYNOPSIS
Creates DeployR maintenance assets for archiving OSD log zip files.

.DESCRIPTION
This script does two things:
1. Creates C:\ProgramData\2Pint Software\Maintenance\Archive-DeployROSDLogs.ps1
    by generating script content on the fly.
2. Creates or updates a scheduled task that runs as SYSTEM and executes
   the archive script daily.

.NOTES
Run this script elevated (as Administrator).
#>

[CmdletBinding()]
param(
    [string]$TaskName = 'Archive DeployR OSD Logs',
    [string]$TaskPath = '\2Pint Software',
    [datetime]$TaskTime = [datetime]'2:00 AM',

    [ValidateRange(1, 3650)]
    [int]$ArchiveAfterDays = 14,

    [switch]$CleanupArchive = $true,

    [ValidateRange(1, 3650)]
    [int]$ArchiveCleanupAfterDays = 85
)

$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function New-ScheduledTaskFolder {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FolderPath
    )

    $trimmedPath = $FolderPath.Trim('\')
    if ([string]::IsNullOrWhiteSpace($trimmedPath)) {
        return
    }

    $taskService = New-Object -ComObject Schedule.Service
    $taskService.Connect()

    try {
        $null = $taskService.GetFolder("\$trimmedPath")
    }
    catch {
        $rootFolder = $taskService.GetFolder("\")
        $null = $rootFolder.CreateFolder($trimmedPath)
    }
}

if (-not (Test-IsAdministrator)) {
    Write-Warning 'This script must be run as Administrator.'
    exit 1
}

$maintenanceFolder = Join-Path -Path $env:ProgramData -ChildPath '2Pint Software\Maintenance'
$targetArchiveScriptPath = Join-Path -Path $maintenanceFolder -ChildPath 'Archive-DeployROSDLogs.ps1'

if (-not (Test-Path -LiteralPath $maintenanceFolder)) {
    New-Item -Path $maintenanceFolder -ItemType Directory -Force | Out-Null
    Write-Host "Created maintenance folder: $maintenanceFolder" -ForegroundColor Cyan
}

$archiveScriptContent = @'
<#
.SYNOPSIS
Archives older DeployR OSD zip logs from the Logs folder into OSDLogsArchive.

.DESCRIPTION
This script finds the DeployR Content root, targets its child Logs folder, and moves
date-prefixed OSD backup zip files older than a configured number of days into
Logs\OSDLogsArchive.

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
'@

$archiveScriptContent | Out-File -FilePath $targetArchiveScriptPath -Force -Encoding UTF8
Write-Host "Created archive script: $targetArchiveScriptPath" -ForegroundColor Green

New-ScheduledTaskFolder -FolderPath $TaskPath

$taskArguments = @(
    '-NoProfile'
    '-ExecutionPolicy Bypass'
    "-File `"$targetArchiveScriptPath`""
    "-ArchiveAfterDays $ArchiveAfterDays"
)

if ($CleanupArchive) {
    $taskArguments += '-CleanupArchive'
    $taskArguments += "-ArchiveCleanupAfterDays $ArchiveCleanupAfterDays"
}

$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ($taskArguments -join ' ')
$trigger = New-ScheduledTaskTrigger -Daily -At $TaskTime
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest

$normalizedTaskPath = if ($TaskPath.EndsWith('\')) { $TaskPath } else { "$TaskPath\" }

$existingTask = Get-ScheduledTask -TaskName $TaskName -TaskPath $normalizedTaskPath -ErrorAction SilentlyContinue
if ($existingTask) {
    Unregister-ScheduledTask -TaskName $TaskName -TaskPath $normalizedTaskPath -Confirm:$false
    Write-Host "Removed existing task: $normalizedTaskPath$TaskName" -ForegroundColor Yellow
}

Register-ScheduledTask -TaskName $TaskName -TaskPath $normalizedTaskPath -Action $action -Trigger $trigger -Principal $principal -Description 'DeployR OSD log archive maintenance task' -Force | Out-Null

Write-Host "Scheduled task created: $normalizedTaskPath$TaskName" -ForegroundColor Green
Write-Host "Runs daily at: $($TaskTime.ToString('hh:mm tt')) as SYSTEM" -ForegroundColor Green
Write-Host "Task command: powershell.exe $($taskArguments -join ' ')" -ForegroundColor DarkGray
