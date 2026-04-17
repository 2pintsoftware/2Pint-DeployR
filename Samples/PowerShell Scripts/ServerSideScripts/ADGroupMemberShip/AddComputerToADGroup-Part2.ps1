<#
DeployR Server Side Script - Add Computer to AD Group Part 2
Place in the DeployR Content  \ Scripts folder and call from the Task Sequence with the ComputerName parameter.
https://documentation.2pintsoftware.com/deployr/reference/step-definitions/run-server-side-script

In this Example:
- I have my DeployR Content in D:\DeployRCIs, so the script is at D:\DeployRCIs\Scripts\AddComputerToADGroup-Part2.ps1
- the AD Group Name is : ADComputerGroupExample
    - The DeployR Server must have permissions to read the computer account and modify the group membership. This is often the cause of hangs when running under SYSTEM.
- A log is created at D:\DeployRCIs\Logs\AddComputerToADGroup-Part2.log with details of the execution, including any errors.
    - I recommend you update this path to where you want the log to go, it is setup to overwrite previous logs, so if you want to keep previous logs, you should implement a log rotation or unique naming strategy.
#>
param(
    [string]$ComputerName
)
$DeployRContentPath = "D:\DeployRCIs"
$LogFileName = "$DeployRContentPath\Logs\AddComputerToADGroup-Part2.log"
if (Test-Path $LogFileName) { Remove-Item $LogFileName -ErrorAction SilentlyContinue }

Start-Transcript -Path $LogFileName -NoClobber

Write-Output "=== Add to AD Group Started ==="
Write-Output "Running as: $(whoami)"
Write-Output "ComputerName: $ComputerName"

Import-Module ActiveDirectory -ErrorAction Stop

$groupname = "ADComputerGroupExample"

try {
    $computer = Get-ADComputer $ComputerName -ErrorAction Stop
    Write-Output "Computer found - SamAccountName: $($computer.SamAccountName)"
    Write-Output "DistinguishedName: $($computer.DistinguishedName)"

    # Check if already a member (this is often the culprit for hangs)
    Write-Output "Checking current membership..."
    $members = Get-ADGroupMember -Identity $groupname -ErrorAction Stop
    
    if ($members.SamAccountName -contains $computer.SamAccountName) {
        Write-Output "INFO: Computer is ALREADY a member of $groupname. Skipping add."
    }
    else {
        Write-Warning "Adding computer '$ComputerName' ($($computer.SamAccountName)) to group '$groupname'"

        # Use the pipe method + -Verbose for more detail
        # Low-level ADSI method - often works when cmdlets hang under SYSTEM
        $group = [ADSI]"LDAP://$((Get-ADGroup $groupname).DistinguishedName)"
        $computerDN = (Get-ADComputer $ComputerName).DistinguishedName
        $group.PutEx(3, "member", @($computerDN))   # 3 = ADS_PROPERTY_APPEND
        $group.SetInfo()
        Write-Output "SUCCESS: Added using ADSI"
        Write-Output "SUCCESS: Added $ComputerName to $groupname"
    }
}
catch {
    Write-Error "ERROR occurred: $($_.Exception.Message)"
    Write-Error "Exception Type: $($_.Exception.GetType().FullName)"
    if ($_.Exception.InnerException) {
        Write-Error "Inner Exception: $($_.Exception.InnerException.Message)"
    }
}
finally {
    Stop-Transcript
    Write-Output "=== Script Finished - Transcript saved ==="
}