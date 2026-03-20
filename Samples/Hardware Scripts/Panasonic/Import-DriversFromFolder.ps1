




function Import-DriverPack {
    param (
    [parameter(Mandatory=$true)]
    [string]$MakeAlias,
    [parameter(Mandatory=$true)]
    [switch]$ImportByName,
    [string]$ModelAlias,
    [string]$FriendlyModel, # e.g., 'Latitude 5580' vs '07A8' ModelAlias
    [string]$OSVer,  # e.g., 'Win10' or 'Win11'
    [string]$URL,  # URL to download the driver pack
    [string]$CabPath, #If you already downloaded the CAB file and use that instead of the URL
    [string]$InputSourceFolder, #Downloaded Extracted Driver Pack Source Folder
    [string]$DriverPackFileName = "", # If not provided, will be derived from URL
    [string]$ArchiveSourceFolder = "D:\DeployRContentItems\Source\DriverPacks",
    [string]$DeployRModulePath ='C:\Program Files\2Pint Software\DeployR\Client\PSModules\DeployR.Utility',
    [bool]$SkipArchive
    )
    
    
    if (-not $URL -and -not $InputSourceFolder -and -not $CabPath) {
        Write-Error "Either URL, CabPath, or InputSourceFolder are required parameters. Exiting."
        Write-Host "Please provide either a URL to download the driver pack, a local CabPath to the CAB file, or a local InputSourceFolder path where the driver pack is already extracted." -ForegroundColor Yellow
        return
    }
    
    
    #Ensure Source Folder exists
    if (-not (Test-Path $ArchiveSourceFolder)) {
        Write-Error "Source Folder $ArchiveSourceFolder does not exist. Exiting."
        return
    }
    Import-Module $DeployRModulePath
    #Get the latest version number of the Content Item
    if ($InputSourceFolder -and (Test-Path $InputSourceFolder)) {
        #Write-Host "  Using provided Input Source Folder: $InputSourceFolder"
        $DriverPackFileName = (Get-Item $InputSourceFolder).Name
        #Copy-Item -Path $InputSourceFolder -Destination "$DriverPackSourcePath\$DriverPackFileName" -Force
    }
    else {
        if (-not $DriverPackFileName) {
            if ($CabPath) {
                $DriverPackFileName = (Get-Item $CabPath).Name
            }
            else {
                $DriverPackFileName = $URL.Split("/")[-1]
            }
            $DriverPackFileFullName = $DriverPackFileName
            #Get Extension
            $DriverPackFileNameExt = $DriverPackFileName.Split(".")[-1]
            
            #Drop Extension
            $DriverPackFileName = [System.IO.Path]::GetFileNameWithoutExtension($DriverPackFileName)
            
        }
    }
    
    if (-not $FriendlyModel) {
        $FriendlyModel = $ModelAlias
        $FolderModelAlias = $ModelAlias
    }
    else {
        $FolderModelAlias = "$FriendlyModel - $ModelAlias"
    }
    $DriverPackSourcePath = "$ArchiveSourceFolder\$MakeAlias\$FolderModelAlias\$OSVer"
    Write-Host "  File Name: $DriverPackFileFullName"
    Write-Host "  Source Path: $DriverPackSourcePath"
    #if (Get-DeployRContentItem | Where-Object {$_.Name -eq "Driver Pack - $MakeAlias - $ModelAlias - $OSVer" -and $_.description -match "$DriverPackFileName"}){
    if (Get-DeployRContentItem | Where-Object {$_.Name -eq "Driver Pack - $MakeAlias - $FolderModelAlias - $OSVer"}){
        Write-Host "  Driver Pack Content Item already exists for $MakeAlias - $FolderModelAlias - $OSVer" -ForegroundColor Yellow
    }
    else {
        Write-Host "  Driver Pack Content Item does not exist for $MakeAlias - $FolderModelAlias - $OSVer. Creating new one."
        #Create Source Folder Structure
        New-Item -Path "$DriverPackSourcePath\Extracted" -ItemType Directory -Force | Out-Null
        #Download the Driver Pack
        if ($InputSourceFolder -and (Test-Path $InputSourceFolder)) {
            Write-Host "  Using provided Input Source Folder: $InputSourceFolder"
            $DriverPackFileName = (Get-Item $InputSourceFolder).Name
            Copy-Item -Path $InputSourceFolder -Destination "$DriverPackSourcePath\Extracted" -Force
        }
        if ($CabPath -and (Test-Path $CabPath)) {
            Write-Host "  Using provided CAB Path: $CabPath" -ForegroundColor Green
            write-HOst "  Copying CAB to Source Folder: $DriverPackSourcePath\$DriverPackFileFullName"
            Copy-Item -Path $CabPath -Destination "$DriverPackSourcePath\$DriverPackFileFullName" -Force
        }
        if (Test-Path "$DriverPackSourcePath\$DriverPackFileFullName") {
            Write-Host "  Driver Pack already downloaded: $DriverPackFileFullName"
        }
        else {
            write-Host "  Downloading Driver Pack to $DriverPackSourcePath\$DriverPackFileFullName"
            Start-BitsTransfer -Source $URL -Destination "$DriverPackSourcePath\$DriverPackFileFullName" -RetryInterval 60 -RetryTimeout 3600   -CustomHeaders "User-Agent:Bob" -ErrorAction Stop
        }
        if (Test-Path "$DriverPackSourcePath\$DriverPackFileFullName") {
            
            if ($DriverPackFileNameExt -eq "zip"){
                write-Host "  Extracting Zip Driver Pack to $DriverPackSourcePath\Extracted"
                Expand-Archive -Path "$DriverPackSourcePath\$DriverPackFileFullName" -DestinationPath "$DriverPackSourcePath\Extracted" -Force
            }
            if ($DriverPackFileNameExt -eq "cab"){
                
                Write-Host -Verbose "Expanding CAB Driver Pack to $DriverPackSourcePath\Extracted"
                Expand -R "$DriverPackSourcePath\$DriverPackFileFullName" -F:* "$DriverPackSourcePath\Extracted" | Out-Null
            }
            if ($DriverPackFileNameExt -eq "exe") {
                Write-Host "  Starting Extraction of EXE Driver Pack...."
                $DriverPack = Get-Item -Path "$DriverPackSourcePath\$DriverPackFileFullName"
                if ($DriverPack) {
                    #Some EXE driver packs support silent extraction, others may not. This may need to be customized per manufacturer.
                    try {
                        if ($MakeAlias -eq "Dell"){
                            Write-Host "  Executing DELL EXE Driver Pack to extract contents to $DriverPackSourcePath\Extracted"
                            Start-Process -FilePath $DriverPack.FullName -ArgumentList "/s /e=`"$DriverPackSourcePath\Extracted`"" -Wait
                        }
                        elseif ($MakeAlias -eq "HP"){
                            Write-Host "  Executing HP EXE Driver Pack to extract contents to $DriverPackSourcePath\Extracted"
                            Start-Process -FilePath $DriverPack.FullName -ArgumentList "/s /e /f `"$DriverPackSourcePath\Extracted`"" -Wait
                        }
                        else{
                            Write-Host "This is not Dell or HP EXE file"
                        }
                    } catch {
                        Write-Error "Failed to extract driver pack: $DriverPack"
                        write-host "Failed to extract driver pack: $DriverPack" -ForegroundColor Red
                        return
                    }
                }
            }
        }
        else {
            Write-Error "Failed to Download"
            exit 1
        }
        #Extract the Driver Pack
        
        #Create DeployR Content Item for the Driver Pack
        
        $NewCI = New-DeployRContentItem -Name "Driver Pack - $MakeAlias - $FolderModelAlias - $OSVer" -Type Folder -Purpose DriverPack -Description "File: $DriverPackFileName"
        $ContentId = $NewCI.id
        if ($ImportByName){
            $NewVersion = New-DeployRContentItemVersion -ContentItemId $ContentId -Description "Source: $DriverPackSourcePath" -DriverManufacturer $MakeAlias -DriverModel $FriendlyModel -SourceFolder "$DriverPackSourcePath\Extracted"
        }
        else {
            $NewVersion = New-DeployRContentItemVersion -ContentItemId $ContentId -Description "Source: $DriverPackSourcePath" -DriverManufacturer $MakeAlias -DriverModel $ModelAlias -SourceFolder "$DriverPackSourcePath\Extracted"    
        }
        
        $ContentVersion = $NewVersion.versionNo
        #Upload the extracted driver pack to the DeployR Content Item
        write-Host "  Uploading extracted Driver Pack to DeployR Content Item"
        try {
            $ciVersion = update-DeployRContentItemContent -ContentId $ContentId -ContentVersion $ContentVersion -SourceFolder "$DriverPackSourcePath\Extracted"
            write-Host "  Successfully uploaded Driver Pack content to DeployR!  Content Item Info:" -ForegroundColor Green
            write-Host "    CI driverManufacturer:   $($ciVersion.driverManufacturer)" -ForegroundColor DarkGray
            write-Host "    CI driverModel:          $($ciVersion.driverModel)" -ForegroundColor DarkGray
            write-Host "    CI ID:                   $($ciVersion.contentItemId), Version: $($ciVersion.versionNo)" -ForegroundColor DarkGray
            write-Host "    CI path:                 $($ciVersion.relativePath)" -ForegroundColor DarkGray
            write-Host "    CI Status:               $($ciVersion.status)" -ForegroundColor DarkGray
            write-Host "    CI Size:                 $([math]::round($ciVersion.contentSize / 1MB, 2)) MB" -ForegroundColor DarkGray
        }
        catch {
            Write-Error "  Failed to upload Driver Pack content to DeployR Content Item for $ManufacturerAlias - $FriendlyModel - $OSVer. Error: $_"
        }
    }
}


#region Panasonic Driver Packs Import
function Import-PanasonicDriverPacks {
    param (
    [string]$SourceFolder = "D:\DeployRContentItems\Source\DriverPacks",
    [string]$DeployRModulePath ='C:\Program Files\2Pint Software\DeployR\Client\PSModules\DeployR.Utility',
    [string]$CabPath,
    [string]$ModelAlias
    )
    Write-Host "Importing Panasonic Driver Packs" -ForegroundColor Green
    #Ensure Source Folder exists
    if (-not (Test-Path $SourceFolder)) {
        New-Item -Path $SourceFolder -ItemType Directory -Force | Out-Null
    }
    $MakeAlias = "Panasonic Corporation"
    if ($CabPath -and (Test-Path $CabPath)) {
        if (-not $ModelAlias) {
            Write-Error "ModelAlias parameter is required when using CabPath. Exiting."
            return
        }
        Write-Host "  Using provided CAB Path: $CabPath"
        #Assumes the CAB contains the extracted driver packs in the correct folder structure
        #Copy the CAB to the source folder and extract it
        $DriverPackFileName = (Get-Item $CabPath).Name
        $OSVer = if ($DriverPackFileName -match "Win11") {'Win11'} else {'Win10'}
        Write-Host "  Processing Windows $OSVer $URL" -foregroundColor Green
        Import-DriverPack -MakeAlias $MakeAlias -ModelAlias $ModelAlias -OSVer $OSVer -CabPath $CabPath -ArchiveSourceFolder $SourceFolder -DeployRModulePath $DeployRModulePath -ImportByName:$false
    }
    else{
        #Get the Panasonic Driver Pack Catalog JSON
        Import-Module $DeployRModulePath
        $PanasonicCatalogURL = "https://pna-b2b-storage-mkt.s3.amazonaws.com/computer/software/apps/Panasonic.json"
        $JSONCatalog = Invoke-RestMethod -Uri $PanasonicCatalogURL
        $PanasonicDriverPacks = $JSONCatalog.PanasonicModels
        

        $TotalModels = (($PanasonicDriverPacks.PSObject.Properties).Count).Count
        Write-Host "Total Panasonic Models to process: $TotalModels" -ForegroundColor Magenta
        $CurrentCount = 0
        foreach ($modelKey in $PanasonicDriverPacks.PSObject.Properties.Name) {
            $CurrentCount++
            Write-Host "Processing model $CurrentCount of $TotalModels" -ForegroundColor Cyan
            $model = $PanasonicDriverPacks.$modelKey
            $ModelAlias = $modelKey
            Write-Host " Processing $MakeAlias - $ModelAlias" -ForegroundColor Cyan
            if ($Model.URL10) {
                $OSVer = 'Win10'
                $URL = $model.URL10
                Write-Host "  Processing Windows $OSVer $URL" -foregroundColor Green
                Import-DriverPack -MakeAlias $MakeAlias -ModelAlias $ModelAlias -OSVer $OSVer -URL $URL -ArchiveSourceFolder $SourceFolder -DeployRModulePath $DeployRModulePath -ImportByName:$false
            }
            if ($Model.URL11) {
                $OSVer = 'Win11'
                $URL = $model.URL11
                Write-Host "  Processing Windows $OSVer $URL" -foregroundColor Green
                Import-DriverPack -MakeAlias $MakeAlias -ModelAlias $ModelAlias -OSVer $OSVer -URL $URL -ArchiveSourceFolder $SourceFolder -DeployRModulePath $DeployRModulePath -ImportByName:$false
            }
        }
    }
}

#endregion Panasonic Driver Packs Import
