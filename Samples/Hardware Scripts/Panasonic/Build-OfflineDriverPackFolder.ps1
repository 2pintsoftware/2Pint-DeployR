#This script will read the JSON Catalog from Panasonic and download the latest driver packs for offline use with MDT or other deployment tools. 
#It will also create a folder structure for the driver packs based on the models and operating systems.


$BuildFolderPath = "C:\PanasonicDriverPacks" #Change this to your desired folder path for storing the driver packs



$PanasonicCatalogURL = "https://pna-b2b-storage-mkt.s3.amazonaws.com/computer/software/apps/Panasonic.json"
$JSONCatalog = Invoke-RestMethod -Uri $PanasonicCatalogURL

#Prompt User to select which models to download drivers for
$SelectedModels = $JSONCatalog.Models | Out-GridView -Title "Select Panasonic Models to Download Drivers For" -PassThru

#Prompt User to select Windows 10 or 11
$SelectedOS = @("Win10","Win11") | Out-GridView -Title "Select Windows Version to Download Drivers For" -PassThru

foreach ($Model in $SelectedModels) {
    foreach ($OS in $SelectedOS) {
        $DriverPack = $Model.DriverPacks | Where-Object { $_.OSVer -eq $OS }
        if ($DriverPack) {
            $DownloadURL = $DriverPack.URL
            $FileName = $DownloadURL.Split("/")[-1]
            $Hash = $DriverPack.Hash
            $DestinationPath = Join-Path -Path $BuildFolderPath -ChildPath "$($Model.Alias)\$OS"
            $FilePath = Join-Path -Path $DestinationPath -ChildPath $FileName
            if (Test-Path -Path $FilePath) {
                $FileHash = (Get-FileHash -Path $FilePath -Algorithm MD5).Hash
                if ($FileHash -eq $Hash) {
                    Write-Output "Driver Pack for $($Model.Alias) $OS already exists with correct hash, skipping download."
                    continue
                }
                else {
                    Write-Output "Driver Pack for $($Model.Alias) $OS exists but hash mismatch, re-downloading..."
                }
            }
            else {
                Write-Output "Downloading Driver Pack for $($Model.Alias) $OS..."
            }
            #Use Start-BitsTransfer for reliable downloading
            New-Item -Path $DestinationPath -ItemType Directory -Force | Out-Null    
            Start-BitsTransfer -Source $DownloadURL -Destination $FilePath

        }
        else {
            Write-Output "No Driver Pack found for $($Model.Alias) $OS."
        }
    }
}