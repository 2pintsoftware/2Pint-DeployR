[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateRange(1, 3650)]
    [int]$ArchiveAfterDays = 14
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

$cutoffDate = (Get-Date).AddDays(-$ArchiveAfterDays)
$datePrefixedZipPattern = '^\d{8}_\d{6}_.+\.zip$'

$filesToArchive = Get-ChildItem -Path $logsPath -File -Filter '*.zip' | Where-Object {
    $_.Name -match $datePrefixedZipPattern -and $_.LastWriteTime -lt $cutoffDate
}

if (-not $filesToArchive) {
    Write-Host "No matching OSD zip files older than $ArchiveAfterDays days found in $logsPath" -ForegroundColor Green
    return
}

$movedCount = 0
foreach ($file in $filesToArchive) {
    $destinationPath = Get-UniqueDestinationPath -ArchiveFolder $archivePath -FileName $file.Name

    if ($PSCmdlet.ShouldProcess($file.FullName, "Move to $destinationPath")) {
        Move-Item -LiteralPath $file.FullName -Destination $destinationPath -ErrorAction Stop
        $movedCount++
        Write-Host "Archived: $($file.Name)" -ForegroundColor DarkGray
    }
}

Write-Host "Archived $movedCount file(s) to $archivePath" -ForegroundColor Green
