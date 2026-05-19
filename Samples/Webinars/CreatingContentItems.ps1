<#
.NOTES
    IMPORTANT: These commands must be run elevated (as Administrator).
    Several operations use DISM, which requires administrative privileges.

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
$RootCertificateCI = New-DeployRContentItem -Type Folder -Purpose Other -Name '01 DEMO - Root Certificates' -Description 'Root certificate content'
$RootCertificateVersion = New-DeployRContentItemVersion -ContentItemId $RootCertificateCI.id -SourceFolder $RootCertificateFolder -Description 'Required Certs'
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
# - Tags can help with filtering/targeting content items later.

$ModelDriverFolder = 'D:\DeployRSources\DriverPacks\Dell\Latitude 5430\Win11\Extracted'
$ModelDriverTags = @('Windows11', 'x64')
$ModelDriverPackCI = New-DeployRContentItem -Type Folder -Name '01 DEMO - Driver Pack - Dell - Latitude 5430 - Win11' -Description 'BYO model driver pack for Dell Latitude 5430' -Purpose DriverPack -Tags $ModelDriverTags
$ModelDriverPackVersion = New-DeployRContentItemVersion -ContentItemId $ModelDriverPackCI.id -SourceFolder $ModelDriverFolder -DriverManufacturer 'Dell' -DriverModel 'Latitude 5430' -Description "Source: $ModelDriverFolder"


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
	# Grab all driver packs for the make/model, then filter down to the best match for the target OS.
	$DriverPacks = Get-DeployROEMDriverPack -Manufacturer $MakeAlias -Model $MatchedModel.Name
	
	# With a model match, find the most specific driver pack for the target OS and import it.
	$SpecificDriverPack = $DriverPacks | Where-Object { $_.OS -match $OSImage -and $_.OSReleaseID -match $OSImageRelease } | Select-Object -Last 1
	
	# If we don't find a pack matching both the OS and release, try just matching the OS.
	if (-not $SpecificDriverPack) {
		# Fallback to any pack for the selected OS, then take the newest one returned.
		$SpecificDriverPack = $DriverPacks | Where-Object { $_.OS -match $OSImage } | Select-Object -Last 1
	}
	
	# If we found a specific pack for the target OS, import it. Otherwise, warn that no pack was found for the make/model/OS combination.
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

#Simple Example
$Windows11SourceFolder = 'D:\DeployRSources\OSPackages\ClientOS\26100.8246'
$Windows11OSCI = New-DeployRContentItem -Type Folder -Name '01 DEMO - Windows 11 24H2 x64' -Description 'Windows 11 OS package source' -Purpose OperatingSystem
$Windows11OSVersion = New-DeployRContentItemVersion -ContentItemId $Windows11OSCI.id -SourceFolder "$Windows11SourceFolder\install.wim" -Description 'Initial Windows 11 24H2 OS image'



#Advanced Example
# - This example shows how to select a specific edition from the source media, export it to a new folder, and use that as the source for the content item version.
$DesiredIndex = 'Windows 11 Pro' # Adjust this to match the edition you want to publish from the source media.
$Windows11SourceFolder = 'D:\DeployRSources\OSPackages\ClientOS\26100.8246'
$Indexes = Get-WindowsImage -ImagePath "$Windows11SourceFolder\install.wim"
$SelectedIndex = $Indexes | Where-Object { $_.ImageName -match $DesiredIndex } | Select-Object -First 1
if (-not $SelectedIndex) {
	Write-Warning "No matching Windows image index found for '$DesiredIndex' in source folder '$Windows11SourceFolder'."
}
else {
	#Create SubFolder for the selected index and export it there, then use that as the source folder for the content item version.
	$IndexNumber = $SelectedIndex.ImageIndex
	$IndexDetails = Get-WindowsImage -ImagePath "$Windows11SourceFolder\install.wim" -Index $IndexNumber
	$ExportFolder = Join-Path -Path $Windows11SourceFolder -ChildPath ($DesiredIndex -replace '\s+', '_')
	if (-not (Test-Path -Path $ExportFolder)) {	
		New-Item -Path $ExportFolder -ItemType Directory | Out-Null
	}
	if (-not (Test-Path -Path "$ExportFolder\$DesiredIndex.wim")) {	
		Write-Host "Exporting selected Windows image index '$DesiredIndex' to '$ExportFolder'..." -ForegroundColor Yellow
		Export-WindowsImage -SourceImagePath "$Windows11SourceFolder\install.wim" -SourceIndex $SelectedIndex.ImageIndex -DestinationImagePath "$ExportFolder\$DesiredIndex.wim" -CheckIntegrity
	}
	else {
		Write-Host "Export already exists. Skipping export." -ForegroundColor Yellow
	}
	
	# Extract version from the folder path (e.g., "26100.8246")
	$OSVersion = $SelectedIndex.ImageVersion
	
	# Build comprehensive tags with WIM metadata
	$OSImageTags = @(
		"Windows11",
		"$($IndexDetails.EditionId)",		  # e.g., "Professional"
		"$($IndexDetails.Languages -join '-')", # e.g., "en-US"
		"$($IndexDetails.Version)"
	)
}

$Windows11OSCI = New-DeployRContentItem -Type SingleFile -Name "01 DEMO - Windows 11 24H2 x64 $($IndexDetails.EditionId)" -Description 'Windows 11 OS package source' -Purpose OperatingSystem -Tags $OSImageTags
$Windows11OSVersion = New-DeployRContentItemVersion -ContentItemId $Windows11OSCI.id -SourceFolder "$ExportFolder\$DesiredIndex.wim" -Description "Initial Windows 11 24H2 OS image - Edition: $DesiredIndex, Build: $OSVersion, Index: $($SelectedIndex.IndexNumber)"
#endregion

#region 6 - Application
# Notes:
# - Application items need an installation command line in addition to the source folder.
# - This example uses 7-Zip, but any silent installer works.
# - Tags can be set during creation and updated later via metadata.

$ApplicationSourceFolder = 'D:\DeployRSources\Applications\7-Zip\26.00'
$AppFileName = Get-ChildItem -Path $ApplicationSourceFolder -Filter '*.msi' | Select-Object -First 1
$ApplicationInstallCommandLine = "msiexec.exe /i `"$($AppFileName.Name)`" /quiet /norestart"
$ApplicationCI = New-DeployRContentItem -Type Folder -Name '01 DEMO - 7-Zip (x64)' -Description 'Sample app content item' -Purpose Application
$ApplicationVersion = New-DeployRContentItemVersion -ContentItemId $ApplicationCI.id -SourceFolder $ApplicationSourceFolder -InstallationCommandLine $ApplicationInstallCommandLine -Description '24.09'

# Optional: update tags after creation (same pattern used in Generate-AppContentItems.ps1).
$ApplicationTags = @('FrontEnd', '2PintLabs')
$ApplicationMeta = Get-DeployRMetadata -Type ContentItem | Where-Object { $_.id -eq $ApplicationCI.id } | Select-Object -First 1
if ($ApplicationMeta) {
	$ApplicationMeta.tags = $ApplicationTags
	$ApplicationMeta | Set-DeployRMetadata -Type ContentItem | Out-Null
}

#endregion


