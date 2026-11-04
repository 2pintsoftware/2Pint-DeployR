<#
Idea was to circumvent the default security in DeployR for the Offline Domain Join step.
If you read the docs, ODJ via DeployR will NOT overwrite an existing computer account, UNLESS it was orginally created by DeployR via DeployR OSD
If it was joined by any other process, you'd have to MANUALLY change the owner of the computer account to the DeployR Server's computer account or 
delete the object and let DeployR create it during the ODJ step.


NOTE, this SCRIPT does NOT work with the default delegation of permissions in AD, 
you must give the DeployR Server's computer account permissions to modify the computer account in AD, 
otherwise it will fail with an access denied error. 
This is because the script needs to change the owner of the computer account to the DeployR Server's computer account, 
and if it doesn't have permissions to do that, it will fail.

2PINT SOFTWARE DOES NOT SUPPORT THIS!  

#>


param(
    [string]$ComputerName,
    [string]$NewOwner,
    [string]$OU,
    [string]$DryRun
)
$ouPath = $OU

#Convert $DryRun to boolean
if ($DryRun) {
    $DryRun = [System.Convert]::ToBoolean($DryRun)
} else {
    $DryRun = $false
}

$InformationPreference = 'Continue'
Write-Information "Received ComputerName: $ComputerName, NewOwner: $NewOwner, OU: $OU, DryRun: $DryRun"
Write-Information "Executing on '$env:COMPUTERNAME' as '$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)'."


if ($computerName -and $ouPath) {
    try {
        # Get the computer object
        $computerDN = "CN=$computerName,$ouPath"
        Write-Information "Binding to target computer object '$computerDN'."
        $computer = [ADSI]"LDAP://$computerDN"
        if ($null -eq $computer) {
            throw "Could not bind to computer object '$computerDN'"
        }
        try {
            $computer.PSBase.RefreshCache(@('distinguishedName'))
        } catch {
            if ($_.Exception.GetBaseException().HResult -eq -2147016656) {
                Write-Information "SKIPPED: Computer object '$computerDN' does not exist yet. No ownership change is needed; ODJ can create the account."
                return
            }
            throw
        }

        # Get the new owner's SID
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.Filter = "(&(objectClass=computer)(sAMAccountName=$newOwner))"
        Write-Information "Looking up owner computer account '$newOwner'."
        $ownerObject = $searcher.FindOne()

        if ($ownerObject) {
            $ownerSID = New-Object System.Security.Principal.SecurityIdentifier($ownerObject.Properties["objectsid"][0], 0)
            if ($null -eq $ownerSID) {
                throw "Could not read the SID for machine account '$newOwner'"
            }
            Write-Information "Resolved owner '$newOwner' to SID '$($ownerSID.Value)'."

            # Get current ACL
            Write-Information "Reading security descriptor for '$computerDN'."
            $acl = $computer.PSBase.ObjectSecurity
            if ($null -eq $acl) {
                throw "Could not read the security descriptor for '$computerDN'"
            }
            $currentOwnerSID = $acl.GetOwner([System.Security.Principal.SecurityIdentifier])
            Write-Information "Read security descriptor; current owner SID is '$($currentOwnerSID.Value)'."

            if ($DryRun -eq $true) {
                Write-Information 'DRY RUN: No changes were made.'
                Write-Information "Target: $computerDN"
                Write-Information "Current owner SID: $($currentOwnerSID.Value)"
                Write-Information "Proposed owner: $newOwner"
                Write-Information "Proposed owner SID: $($ownerSID.Value)"
                Write-Information 'ACL read succeeded; no changes were committed to AD.'
            } else {
                # Set new owner
                Write-Information "Setting owner of '$computerDN' to '$newOwner' (SID '$($ownerSID.Value)')."
                $acl.SetOwner($ownerSID)
                $computer.PSBase.ObjectSecurity = $acl
                $computer.PSBase.CommitChanges()
                Write-Information "SUCCESS: Changed owner of $computerDN to $newOwner (SID $($ownerSID.Value))."
            }
        } else {
            Write-Warning "Could not find machine account $newOwner"
        }
    } catch {
        $errorRecord = $_
        Write-Error "Failed to process ownership at script line $($errorRecord.InvocationInfo.ScriptLineNumber) - $($errorRecord.Exception.Message)`n$($errorRecord.InvocationInfo.PositionMessage)`n$($errorRecord.ScriptStackTrace)"
    }
} else {
    Write-Warning "Missing COMPUTERNAME or OU variable, skipping ownership change"
} 
