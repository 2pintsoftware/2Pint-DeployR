<#
Grab the DeployR information along with some general system information for troubleshooting.
Grab several logs and package them into a zip file for troubleshooting
Ideally run the DeployR-Troubleshooting.ps1 script first to pull additional logs that will be included in the output of the zip file this script creates.


Change Log
- 2026.02.17 - Added Grabbing info of the DeployR Content Downloads Folder to a log
- 2026.03.12 - Added Grabbing info of all StifleR, 2PXE, and iPXE related Event Logs to a dedicated EventLogs folder in the output
- 2026.04.03 - Added check for default Content location.
#>


$TempFolder = "$env:USERPROFILE\Downloads\DeployR_TroubleShootingLogs"
if (!(Test-Path -Path $TempFolder)){New-Item -Path $TempFolder -ItemType Directory -Force | Out-Null}
$EventLogsFolder = "$TempFolder\EventLogs"
if (!(Test-Path -Path $EventLogsFolder)){New-Item -Path $EventLogsFolder -ItemType Directory -Force | Out-Null}

Function Find-EventLogs {
    <#
    .SYNOPSIS
    Finds StifleR-related event logs on the system.
    
    .DESCRIPTION
    By default, lists all StifleR event log providers and their associated logs.
    Optionally exports the logs to a specified directory.
    
    .PARAMETER Export
    If specified, exports the found event logs to the OutputDirectory.
    
    .PARAMETER OutputDirectory
    Directory where event logs will be exported (only used with -Export).
    Default: $env:USERPROFILE\Downloads\DeployR_TroubleShootingLogs
    
    .PARAMETER LogNameFilter
    Filter for log provider names. Default: *StifleR*
    
    .EXAMPLE
    Find-EventLogs
    Lists all StifleR event logs found on the system.
    
    .EXAMPLE
    Find-EventLogs -Export
    Finds and exports all StifleR event logs to the default directory.
    
    .EXAMPLE
    Find-EventLogs -Export -OutputDirectory "C:\Logs"
    Finds and exports event logs to C:\Logs.
    #>
    [CmdletBinding()]
    param (
    [Parameter()]
    [switch]$Export,
    
    [Parameter()]
    [switch]$PassThru,
    
    [Parameter()]
    [string]$OutputDirectory = "$env:USERPROFILE\Downloads\DeployR_TroubleShootingLogs",
    
    [Parameter()]
    [string]$LogNameFilter = "*DeployR*"
    )
    
    Write-Host "Searching for event logs matching: $LogNameFilter" -ForegroundColor Cyan
    
    $foundLogs = @()
    $logNamesToExport = @()
    
    # --- Search by Provider Name ---
    $Providers = Get-WinEvent -ListProvider $LogNameFilter -ErrorAction SilentlyContinue
    if ($Providers) {
        foreach ($provider in $Providers) {
            $providerName = $provider.ProviderName
            $events = (Get-WinEvent -ListProvider $providerName -ErrorAction SilentlyContinue).Events
            
            if ($events) {
                $logLinks = $provider.LogLinks.LogName
                foreach ($logLink in $logLinks) {
                    if ($logNamesToExport -notcontains $logLink) {
                        $logNamesToExport += $logLink
                        $foundLogs += [PSCustomObject]@{
                            Source      = 'Provider'
                            ProviderName = $providerName
                            LogName     = $logLink
                            EventCount  = $events.Count
                        }
                    }
                }
            }
        }
    }
    
    # --- Search by Log Name (Channel) ---
    # This catches logs visible in Event Viewer whose provider name doesn't match the filter
    $LogChannels = Get-WinEvent -ListLog $LogNameFilter -ErrorAction SilentlyContinue
    if ($LogChannels) {
        foreach ($logChannel in $LogChannels) {
            if ($logNamesToExport -notcontains $logChannel.LogName) {
                $logNamesToExport += $logChannel.LogName
                $foundLogs += [PSCustomObject]@{
                    Source       = 'LogName'
                    ProviderName = ($logChannel.ProviderNames -join ', ')
                    LogName      = $logChannel.LogName
                    EventCount   = $logChannel.RecordCount
                }
            }
        }
    }
    
    # Display found logs
    if ($foundLogs.Count -gt 0) {
        Write-Host "`nFound $($foundLogs.Count) event log(s):" -ForegroundColor Green
        $foundLogs | Format-Table -AutoSize
    }
    else {
        Write-Warning "No event logs found matching '$LogNameFilter'"
        return
    }
    
    # Export if requested
    if ($Export) {
        Write-Host "`nExporting event logs..." -ForegroundColor Cyan
        
        # Ensure the output directory exists
        if (-not (Test-Path -Path $OutputDirectory)) {
            New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
            Write-Host "Created output directory: $OutputDirectory" -ForegroundColor Gray
        }
        
        $exportCount = 0
        
        # Export each unique log channel as .evtx
        foreach ($logName in $logNamesToExport) {
            $safeLogName = $logName.Replace('/', '_')
            $evtxFilePath = Join-Path -Path $OutputDirectory -ChildPath "$safeLogName.evtx"
            
            try {
                Start-Process wevtutil.exe -ArgumentList "export-log `"$logName`" `"$evtxFilePath`"" -NoNewWindow -Wait -ErrorAction Stop
                Write-Host "  Exported: $safeLogName.evtx" -ForegroundColor Gray
                $exportCount++
            }
            catch {
                Write-Warning "  Failed to export: $logName - $_"
            }
        }
        
        Write-Host "`nExport complete! $exportCount log file(s) exported to: $OutputDirectory" -ForegroundColor Green
    }
    
    if ($PassThru) {
        return $foundLogs
    }
}


#Get DeployR Log Files
$DeployRRegPath = "HKLM:\SOFTWARE\2Pint Software\DeployR\GeneralSettings"
$ContentLocation = (Get-ItemProperty -Path $DeployRRegPath).ContentLocation
if ($ContentLocation -eq $null -or $ContentLocation -eq ""){
    $ContentLocation = "$Env:Programdata\2Pint Software\DeployR"
}
if (Test-Path -Path $ContentLocation){
    Write-Host "DeployR Content Location found at: $ContentLocation" -ForegroundColor Green
    $LogFiles = Get-ChildItem -Path "$ContentLocation" -Filter "*.log" -Recurse
    if ($LogFiles.Count -eq 0){
        Write-Output "No log files found in $ContentLocation" | Out-File -FilePath "$TempFolder\DeployR_LogFiles.txt" -Force
    }
    else{
        foreach ($LogFile in $LogFiles){
            $LogFiles.FullName | Out-File -FilePath "$TempFolder\DeployR_LogFiles.txt" -Append -Force
            Copy-Item -Path $LogFile.FullName -Destination $TempFolder -Force
        }
    }
    
    
    #Get Detailed List of all downloads in the $ContentLocation\Download Folder
    $DownloadFiles = Get-ChildItem -Path "$ContentLocation\Downloads" | Select-Object *
    #Write to Dedicated Log File with a ---------------- in between each entry:
    $DownloadFiles | ForEach-Object { $_ | Out-File -FilePath "$TempFolder\DeployR_Download_Files.txt" -Append -Force; "----------------" | Out-File -FilePath "$TempFolder\DeployR_Download_Files.txt" -Append -Force }    
    
    #Grab the last 10 .zip files from the \Logs Folder
    $ZipFiles = Get-ChildItem -Path "$ContentLocation\Logs" -Filter "*.zip" | Sort-Object LastWriteTime -Descending | Select-Object -First 10
    foreach ($ZipFile in $ZipFiles){
        $ZipFile.FullName | Out-File -FilePath "$TempFolder\DeployR_ZipFiles.txt" -Append -Force
        Copy-Item -Path $ZipFile.FullName -Destination $TempFolder -Force
    }   

}
else{
    Write-Warning "DeployR Content Location not found at expected path: $ContentLocation. No logs will be gathered."
}
#Get DeployR (and other 2Pint Software) Configuration
$2PintRegPath = "HKLM:\SOFTWARE\2Pint Software"
Get-ChildItem -Path $2PintRegPath -Recurse | Out-File -FilePath "$TempFolder\2Pint_Software_Registry_Settings.txt" -Force

#Get Hardware Information
#systeminfo | Out-File -FilePath "$TempFolder\System_Hardware_Information.txt" -Force
#Get CPU & Number of Cores
#Get-CimInstance -ClassName Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors | Out-File -FilePath "$TempFolder\CPU_Information.txt" -Force

#Get Computer Info (Replaces the 2 above)
$ComputerInfo = Get-ComputerInfo
$ComputerInfo | Out-File -FilePath "$TempFolder\Computer_Information.txt" -Force

#Get DeployR Event Logs
Find-EventLogs -Export -OutputDirectory "$TempFolder\EventLogs" -LogNameFilter "*DeployR*"

#Get 2PXE | iPXE Event Logs
Find-EventLogs -Export -OutputDirectory "$TempFolder\EventLogs" -LogNameFilter "*2PXE*"
Find-EventLogs -Export -OutputDirectory "$TempFolder\EventLogs" -LogNameFilter "*iPXE*"

#Get iPXE DebugLog if exist
$iPXEWSRegPath = 'HKLM:\SOFTWARE\2Pint Software\iPXE Anywhere Web Service'
if (Test-Path -Path $iPXEWSRegPath) {
    $iPXEWSRegData = Get-ItemProperty -Path $iPXEWSRegPath
    if ($iPXEWSRegData.DebugLogPath) {
        #Write-Host "iPXE WS Debug Log Path from Registry: $($iPXEWSRegData.DebugLogPath)" -ForegroundColor Cyan
        Copy-Item -Path $iPXEWSRegData.DebugLogPath -Destination $TempFolder -Force -ErrorAction SilentlyContinue
    }
    else {
        #Write-Host "iPXE WS Debug Log Path is NOT configured in Registry." -ForegroundColor Red
    }
}

#Get StifleR Event Logs (in case there are some that don't have DeployR in the name)
Find-EventLogs -Export -OutputDirectory "$TempFolder\EventLogs" -LogNameFilter "*StifleR*"
Write-Host "Event log export complete!" -ForegroundColor Green

#Compress the logs into a zip file (with time stamp)
$TimeStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$ZipFilePath = "$env:USERPROFILE\Downloads\DeployR_TroubleShootingLogs_$TimeStamp.zip"
if (Test-Path -Path $ZipFilePath){
    Remove-Item -Path $ZipFilePath -Force
}
Write-Host "`nCompressing logs into zip file: $ZipFilePath" -ForegroundColor Cyan
Compress-Archive -Path "$TempFolder\*" -DestinationPath $ZipFilePath -Force 
Write-Host "Compression complete! Logs saved to: $ZipFilePath" -ForegroundColor Green
Write-Host "!!! Please send to support@2pintsoftware.com !!!" -ForegroundColor Magenta

