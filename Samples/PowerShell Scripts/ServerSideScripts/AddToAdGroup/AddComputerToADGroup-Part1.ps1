<#
DeployR Server Side Script - Add Computer to AD Group
Place in the DeployR Content  \ Scripts folder and call from the Task Sequence with the ComputerName parameter.
https://documentation.2pintsoftware.com/deployr/reference/step-definitions/run-server-side-script

In this Example, I have my DeployR Content in D:\DeployRCIs, so the script is at D:\DeployRCIs\Scripts\AddComputerToADGroup-Part2.ps1

We are kicking off a sub-process to call PowerShell 5 to allow us to use the ActiveDirectory module, and to run with a different execution policy. 
The main script is just a wrapper to call the actual logic in a separate PS5 process.
#>
param(
    [string]$ComputerName
)
$DeployRContentPath = "D:\DeployRCIs"
Write-Information "Received ComputerName: $ComputerName"
Write-Information "Starting AddComputerToADGroup-Part2.ps1 with ComputerName: $ComputerName"
Write-Information "Check Log for details: $DeployRContentPath\Logs\AddComputerToADGroup-Part2.log"

$arg = "-NoProfile -ExecutionPolicy Bypass -File $DeployRContentPath\Scripts\AddComputerToADGroup-Part2.ps1 -ComputerName $ComputerName"
$proc = Start-Process -FilePath "powershell.exe" -ArgumentList $arg -NoNewWindow -PassThru -Wait
Write-Information "PS Script Exit Code: $($proc.ExitCode)"
exit 0
