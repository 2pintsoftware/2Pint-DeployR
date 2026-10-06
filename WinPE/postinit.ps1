<# This Script will automatically be called during the WinPE post-initialization phase

More more details how this all works:
https://documentation.2pintsoftware.com/deployr/getting-started/generate-windows-pe-boot-images/preinit-postinit-postauth-ps1



Some samples of scripts for preinit and postinit are in this WinPE folder, this script demonstrates how to load and use the Test-DeployRConnection script.
To use this script, uncomment the line below to load the Test-DeployRConnection script.
#>


# Load the Test-DeployRConnection script
if (Test-path "$PSScriptRoot\Test-DeployRConnection.ps1") {
    write-host "Loading Test-DeployRConnection.ps1"
    . "$PSScriptRoot\Test-DeployRConnection.ps1"
}
