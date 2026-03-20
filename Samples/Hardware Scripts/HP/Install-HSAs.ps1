<# Gary Blok - 2Pint Software
For HP Hardware that has extra UWP / HSA apps, this script will find the latest version of the HSAs and run the InstallAllApps.cmd file to install them. This is used in the HP Image Creation process to ensure the latest HSAs are included in the image.
Based on: https://developers.hp.com/hp-client-management/blog/hp-uwp-application-pack-deployment-microsoft-endpoint-configuration-manager-os-deployment-task
and: https://garytown.com/apply-hps-uwp-apps-during-osd


What it does...
After DeployR has downloaded your HP Driver pack, it gets extracted to _2P\Content\DriverPacks, HP includes additional UWP apps in a folder name HSAs.
This script will search for that folder, if found, will look for the HP supplied InstallAllApps.cmd file and run it to install the apps. 
If running in WinPE, it will pass the S:\ parameter to the InstallAllApps.cmd file to ensure it installs to the correct drive.

#>
if ($env:SystemDrive -eq "X:"){
    $WinPE = $true
    $ContentPath = "S:\_2P\content"
}
else {
    $ContentPath = "C:\_2P\content"
}
    
$HSAsPath = Get-ChildItem -Path "$ContentPath\DriverPacks" -Recurse | Where-Object {$_.Name -like "HSAs" -and $_.Attributes -eq "Directory"} | Sort-Object -Descending | Select-Object -First 1
If ($HSAsPath) {
    Test-Path -Path "$($HSAsPath.FullName)\InstallAllApps.cmd" -ErrorAction SilentlyContinue
    Write-Output "Installing HSAs from $($HSAsPath.FullName)"
    if ($WinPE) {
        Start-Process cmd.exe -ArgumentList "/c `"$($HSAsPath.FullName)\InstallAllApps.cmd`" S:\" -Wait -PassThru -NoNewWindow
    }
    else {
        Start-Process cmd.exe -ArgumentList "/c `"$($HSAsPath.FullName)\InstallAllApps.cmd`""  -Wait -PassThru -NoNewWindow
    }

}
else {
    Write-Output "No HSAs found in $ContentPath\DriverPacks"
}

