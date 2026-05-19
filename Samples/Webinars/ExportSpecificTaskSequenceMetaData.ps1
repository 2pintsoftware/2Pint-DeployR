#region Import and connect
if (Test-Path -Path 'C:\Program Files\2Pint Software\DeployR\Client\PSModules\DeployR.Utility') {
	Import-Module 'C:\Program Files\2Pint Software\DeployR\Client\PSModules\DeployR.Utility' -ErrorAction Stop
}
elseif (Get-Module -ListAvailable -Name DeployR.Utility) {
	Import-Module DeployR.Utility -ErrorAction Stop
}
else {
	throw 'DeployR.Utility module not found. Install the DeployR client or update -DeployRModulePath.'
}

if (Test-Path 'HKLM:\SOFTWARE\2Pint Software\DeployR\GeneralSettings') {
	$DeployRReg = Get-Item -Path 'HKLM:\SOFTWARE\2Pint Software\DeployR\GeneralSettings'
	$ClientPasscode = $DeployRReg.GetValue('ClientPasscode')
	if ($ClientPasscode) {
		Connect-DeployR -Passcode $ClientPasscode -ErrorAction Stop
	}
	else {
		Connect-DeployR -ErrorAction Stop
	}
}
else {
	Connect-DeployR -ErrorAction Stop
}
#endregion

#region Gather DeployR Content Location
#Grab DeployR Content Location from registry for use in content item creation and task sequence cloning examples below.
$DeployRRegPath = 'HKLM:\SOFTWARE\2Pint Software\DeployR\GeneralSettings'
if (Test-Path -Path $DeployRRegPath) {
    $DeployRReg = Get-Item -Path $DeployRRegPath
    $DeployRCILocation = $DeployRReg.GetValue('ContentLocation')
    if (-not $DeployRCILocation) {
        throw 'ContentLocation value not found in registry. Update the registry or set $DeployRCILocation manually.'
    }
}
else {
    throw 'DeployR general settings registry key not found. Update the registry or set $DeployRCILocation manually.'
}
$TempLocation = "$DeployRCILocation\Temp"
if (-not (Test-Path -Path $TempLocation)) {
    Write-Host "Temp Location $TempLocation does not exist. exiting..."
    exit
}

#endregion

#Clone a DeployR Task Sequnce 
$TSID = '102d275b-fee3-477b-aa07-a8f63ca2140c'

#Export the task sequence to a temporary location, then import it back as a clone. 
Export-DeployRTaskSequence -Id $TSID -DestinationFolder $TempLocation
#The exported file is filtered by the original TS ID to ensure we get the correct one if there are multiple exports in the temp folder.
$ExportedTSFile = Get-ChildItem -Path $TempLocation -Filter '*.json' | Where-Object {$_.Name -match $TSID}
Write-Host "Exported Task Sequence file located at: $($ExportedTSFile.FullName)"
