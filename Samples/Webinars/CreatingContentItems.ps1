<#
.SYNOPSIS
Starter examples for creating DeployR content items with PowerShell.

.DESCRIPTION
This script provides one basic section for each common item type.

The goal is to show the smallest possible working examples using the
2Pint DeployR module:
- Root certificates
- WinPE x64 driver pack
- Boot image wiring (TBD)
- Model-specific driver pack (BYO and catalog)
- Windows 11 OS image
- Application

Update names, paths, and command lines to match your environment.
#>

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

#region 1 - Root certificates
# Notes:
# - Use Purpose Other for certificate payloads.
# - The source folder should contain the certificate files you want to publish.

$RootCertificateFolder = 'D:\DeployRSources\WinPEContent\Certificate'
$RootCertificateCI = New-DeployRContentItem -Type Folder -Name '01 DEMO - Root Certificates - Enterprise' -Description 'Root and intermediate certificate content' -Purpose Other
$RootCertificateVersion = New-DeployRContentItemVersion -ContentItemId $RootCertificateCI.id -SourceFolder $RootCertificateFolder -Description 'Initial certificate payload'
#endregion

#region 2 - WinPE x64 driver pack
# Notes:
# - This is the basic shape for a WinPE driver pack.
# - Adjust DriverManufacturer and DriverModel to match your naming convention.

$WinPEDriverFolder = 'D:\DeployRSources\WinPEContent\Drivers\x64'
$WinPEDriverPackCI = New-DeployRContentItem -Type Folder -Name '01 DEMO - Driver Pack - WinPE x64' -Description 'Generic WinPE x64 driver pack' -Purpose DriverPack
$WinPEDriverVersion = New-DeployRContentItemVersion -ContentItemId $WinPEDriverPackCI.id -SourceFolder $WinPEDriverFolder -DriverManufacturer 'Generic' -DriverModel 'WinPE x64' -Description 'Initial WinPE x64 driver pack'
#endregion

#region 3 - Boot image TBD
# Notes:
# - Boot image creation / regeneration is environment-specific in DeployR.
# - This section shows the metadata wiring you would typically update after a boot image exists.

$Winx64BootImage = Get-DeployRMetadata -Type BootImage | Where-Object { $_.platform -eq 'Windows' -and $_.architecture -eq 'x64' } | Select-Object -First 1
if ($Winx64BootImage) {
	# Link the boot image to the x64 driver pack and certificate content items.
	# Replace these example references with the actual content item id + version number values you want to assign.
	$Winx64BootImage.driversContentItem = '<DriverPackContentItemId>:<VersionNo>'
	$Winx64BootImage.certificateContentItem = '<CertificateContentItemId>:<VersionNo>'
	$Winx64BootImage | Set-DeployRMetadata -Type BootImage | Out-Null
	Write-Host 'Boot image metadata updated. Regeneration command TBD for your environment.' -ForegroundColor Yellow
}
else {
	Write-Warning 'No Windows x64 BootImage metadata found in DeployR yet.'
}
#endregion

#region 4a - Model specific driver pack (BYO)
# Notes:
# - Use this when you already have the extracted driver pack folder.
# - Replace the manufacturer/model values with your own target model.

$ModelDriverFolder = 'D:\DeployRSources\Drivers\Dell\Latitude-7450\Win11'
$ModelDriverPackCI = New-DeployRContentItem -Type Folder -Name '01 DEMO - Driver Pack - Dell - Latitude 7450 - Win11' -Description 'BYO model driver pack for Dell Latitude 7450' -Purpose DriverPack
$ModelDriverPackVersion = New-DeployRContentItemVersion -ContentItemId $ModelDriverPackCI.id -SourceFolder $ModelDriverFolder -DriverManufacturer 'Dell' -DriverModel 'Latitude 7450' -Description "Source: $ModelDriverFolder"
#endregion

#region 4b - Model specific driver pack (catalog example)
# Notes:
# - This example uses the OEM catalog lookup flow from DeployR.
# - First narrow the supported models, then choose the OS-specific pack, then import it.

$MakeAlias = 'Dell'
$ModelAlias = 'Latitude 7450'
$OSImage = 'Windows 11'
$OSImageRelease = '24H2'

$SupportedModels = Get-DeployROEMDriverPack -Manufacturer $MakeAlias
$MatchedModel = $SupportedModels | Where-Object { $_ -match $ModelAlias } | Select-Object -Last 1

if (-not $MatchedModel) {
	Write-Warning "No OEM catalog model match found for '$MakeAlias - $ModelAlias'."
}
else {
	$DriverPacks = Get-DeployROEMDriverPack -Manufacturer $MakeAlias -Model $MatchedModel
	$SpecificDriverPack = $DriverPacks | Where-Object { $_.OS -match $OSImage -and $_.OSReleaseID -match $OSImageRelease } | Select-Object -Last 1

	if (-not $SpecificDriverPack) {
		# Fallback to any pack for the selected OS, then take the newest one returned.
		$SpecificDriverPack = $DriverPacks | Where-Object { $_.OS -match $OSImage } | Select-Object -Last 1
	}

	if ($SpecificDriverPack) {
		$SpecificDriverPack | Import-DeployROEMDriverPack
	}
	else {
		Write-Warning "No OEM catalog pack found for '$MakeAlias - $MatchedModel' and OS '$OSImage'."
	}
}
#endregion

#region 5 - Windows 11 OS image
# Notes:
# - Purpose OperatingSystem is the key piece for OS content items.
# - The source folder should contain the OS media or prepared payload you want to publish.

$Windows11SourceFolder = 'D:\DeployRSources\OS\Windows11-24H2'
$Windows11OSCI = New-DeployRContentItem -Type Folder -Name '01 DEMO - Windows 11 24H2 x64 Enterprise' -Description 'Windows 11 OS package source' -Purpose OperatingSystem
$Windows11OSVersion = New-DeployRContentItemVersion -ContentItemId $Windows11OSCI.id -SourceFolder $Windows11SourceFolder -Description 'Initial Windows 11 24H2 OS image'
#endregion

#region 6 - Application
# Notes:
# - Application items need an installation command line in addition to the source folder.
# - This example uses 7-Zip, but any silent installer works.

$ApplicationSourceFolder = 'D:\DeployRSources\Applications\7zip'
$ApplicationInstallCommandLine = '7z2409-x64.exe /S'
$ApplicationCI = New-DeployRContentItem -Type Folder -Name '01 DEMO - 7-Zip (x64)' -Description 'Sample app content item' -Purpose Application
$ApplicationVersion = New-DeployRContentItemVersion -ContentItemId $ApplicationCI.id -SourceFolder $ApplicationSourceFolder -InstallationCommandLine $ApplicationInstallCommandLine -Description '24.09'
#endregion


