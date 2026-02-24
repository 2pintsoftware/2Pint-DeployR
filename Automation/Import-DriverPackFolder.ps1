function Import-DriverPack {
    param (
    [parameter(Mandatory=$true)]
    [string]$MakeAlias,
    [parameter(Mandatory=$true)]
    [string]$ModelAlias,
    [parameter(Mandatory=$true)]
    [string]$InputSourceFolder, #Downloaded Extracted Driver Pack Source Folder
    [string]$DeployRModulePath ='C:\Program Files\2Pint Software\DeployR\Client\PSModules\DeployR.Utility'
    )
    
    if (-not $InputSourceFolder) {
        Write-Error "InputSourceFolder is a required parameter. Exiting."
        Write-Host "Please provide a local InputSourceFolder path where the driver pack is already extracted." -ForegroundColor Yellow
        return
    }
    
    #Ensure Source Folder exists
    if (-not (Test-Path $InputSourceFolder)) {
        Write-Error "Source Folder $InputSourceFolder does not exist. Exiting."
        return
    }
    Import-Module $DeployRModulePath

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] Starting Driver Pack Import for $MakeAlias - $ModelAlias" -ForegroundColor Cyan
    Write-Host "  $(Get-Date -Format "HH:mm:ss") | " -NoNewline -ForegroundColor DarkGray
    Write-Host "Source Path: $InputSourceFolder" -ForegroundColor DarkGray
    if (Get-DeployRContentItem | Where-Object {$_.Name -eq "Driver Pack - $MakeAlias - $ModelAlias"}){
        Write-Host "  $(Get-Date -Format "HH:mm:ss") | " -NoNewline -ForegroundColor DarkGray
        Write-Host "Driver Pack Content Item already exists for $MakeAlias - $ModelAlias" -ForegroundColor Yellow
    }
    else {
        Write-Host "  $(Get-Date -Format "HH:mm:ss") | " -NoNewline -ForegroundColor DarkGray
        Write-Host "Driver Pack Content Item does not exist for $MakeAlias - $ModelAlias. Creating new one..." -ForegroundColor Cyan
        #Download the Driver Pack
        if ($InputSourceFolder -and (Test-Path $InputSourceFolder)) {
            Write-Host "  $(Get-Date -Format "HH:mm:ss") | " -NoNewline -ForegroundColor DarkGray
            Write-Host "Using provided Input Source Folder: $InputSourceFolder" -ForegroundColor DarkGray
        }
        
        #Create DeployR Content Item for the Driver Pack
        $StartDPCreationTime = Get-Date
        $NewCI = New-DeployRContentItem -Name "Driver Pack - $MakeAlias - $ModelAlias" -Type Folder -Purpose DriverPack -Description "Generated for $MakeAlias - $ModelAlias"
        $ContentId = $NewCI.id
        $NewVersion = New-DeployRContentItemVersion -ContentItemId $ContentId -Description "Source: $InputSourceFolder" -DriverManufacturer $MakeAlias -DriverModel $ModelAlias # -SourceFolder "$InputSourceFolder"
        $ContentVersion = $NewVersion.versionNo
        Write-Host "  $(Get-Date -Format "HH:mm:ss") | " -NoNewline -ForegroundColor DarkGray
        Write-Host "Created DeployR Content Item for Driver Pack: $($NewCI.name), ID $ContentId, Version $ContentVersion" -ForegroundColor Green
        #Upload the extracted driver pack to the DeployR Content Item

        Write-Host "  $(Get-Date -Format "HH:mm:ss") | " -NoNewline -ForegroundColor DarkGray
        Write-Host "Uploading extracted Driver Pack to newly created DeployR Content Item..." -ForegroundColor Cyan
        write-Output "This can take a little while or long while, depending on the size of the driver pack and your network speed to DeployR. Please be patient..."

        try {
            $ciVersion = update-DeployRContentItemContent -ContentId $ContentId -ContentVersion $ContentVersion -SourceFolder "$InputSourceFolder"
            $StopDPCreationTime = Get-Date
            #Time the creation of the DeployR Content Item and upload of the driver pack content in Minutes and Seconds format MM:SS
            $DPCreationDuration = $StopDPCreationTime - $StartDPCreationTime
            $DPCreationDurationFormatted = "{0:D2}:{1:D2}" -f $DPCreationDuration.Minutes, $DPCreationDuration.Seconds
            Write-Host "  $(Get-Date -Format "HH:mm:ss") | " -NoNewline -ForegroundColor DarkGray
            Write-Host "Time taken to create DeployR Content Item and Version: $DPCreationDurationFormatted" -foregroundColor Green
            write-Host "  Successfully uploaded Driver Pack content to DeployR!  Content Item Info:" -ForegroundColor Green
            write-Host "    CI driverManufacturer:   $($ciVersion.driverManufacturer)" -ForegroundColor DarkGray
            write-Host "    CI driverModel:          $($ciVersion.driverModel)" -ForegroundColor DarkGray
            write-Host "    CI ID:                   $($ciVersion.contentItemId), Version: $($ciVersion.versionNo)" -ForegroundColor DarkGray
            write-Host "    CI path:                 $($ciVersion.relativePath)" -ForegroundColor DarkGray
            write-Host "    CI Status:               $($ciVersion.status)" -ForegroundColor DarkGray
            write-Host "    CI Size:                 $([math]::round($ciVersion.contentSize / 1MB, 2)) MB" -ForegroundColor DarkGray
        }
        catch {
            Write-Error "  Failed to upload Driver Pack content to DeployR Content Item for $MakeAlias - $ModelAlias. Error: $_"
        }
    }
}