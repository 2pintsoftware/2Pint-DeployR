#Requires -RunAsAdministrator

[CmdletBinding()]
param()

$PrerequisiteBaseUrl = 'https://raw.githubusercontent.com/2pintsoftware/2Pint-DeployR/refs/heads/main/Installs/Pre-Reqs'

function Get-InstalledApps {
	$RegistryPaths = @(
		'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
		'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
	)
	Get-ItemProperty -Path $RegistryPaths -ErrorAction SilentlyContinue |
		Where-Object { $_.DisplayName } |
		Select-Object DisplayName, Publisher, InstallDate, DisplayVersion, UninstallString, InstallLocation |
		Sort-Object DisplayName
}

function Test-InstalledApp {
	param(
		[object[]]$InstalledApps,
		[string]$NamePattern,
		[string]$VersionPattern
	)

	return @($InstalledApps | Where-Object {
		$_.DisplayName -like $NamePattern -and $_.DisplayVersion -like $VersionPattern
	}).Count -gt 0
}

function Test-PrerequisiteInstalled {
	param([string]$ScriptName)

	$InstalledApps = @(Get-InstalledApps)
	switch ($ScriptName) {
		'Install-PowerShell76X.ps1' {
			return Test-InstalledApp $InstalledApps 'PowerShell 7.6* (x64)' '7.6.*'
		}
		'Install-DotNetRuntimes100X.ps1' {
			foreach ($NamePattern in @('Microsoft .NET Runtime* (x64)', 'Microsoft ASP.NET Core* (x64)', 'Microsoft Windows Desktop Runtime* (x64)')) {
				if (-not (Test-InstalledApp $InstalledApps $NamePattern '10.0.*')) {
					return $false
				}
			}
			return $true
		}
		{ $_ -in 'Install-WinFeatures-BranchCache-Required.ps1', 'Install-WinFeatures-IIS-Optional.ps1' } {
			try {
				$ProductType = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).ProductType
				if ($ProductType -eq 1) {
					if ($ScriptName -eq 'Install-WinFeatures-BranchCache-Required.ps1') {
						return [bool](Get-BCStatus -ErrorAction Stop).BranchCacheIsEnabled
					}
					foreach ($FeatureName in @('IIS-WebServerRole', 'IIS-WindowsAuthentication')) {
						if ((Get-WindowsOptionalFeature -Online -FeatureName $FeatureName -ErrorAction Stop).State -ne 'Enabled') {
							return $false
						}
					}
					return $true
				}
				Import-Module ServerManager -ErrorAction Stop
				$FeatureNames = @('BranchCache')
				if ($ScriptName -eq 'Install-WinFeatures-IIS-Optional.ps1') {
					$FeatureNames = @('Web-Server', 'Web-Windows-Auth')
				}
				foreach ($FeatureName in $FeatureNames) {
					if (-not (Get-WindowsFeature -Name $FeatureName -ErrorAction Stop).Installed) {
						return $false
					}
				}
				return $true
			} catch {
				Write-Warning "Could not confirm Windows feature state: $($_.Exception.Message). Running the prerequisite script."
				return $false
			}
		}
		'Install-SQLExpress2025.ps1' {
			$InstanceId = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL' -ErrorAction SilentlyContinue).SQLEXPRESS
			if (-not $InstanceId) { return $false }
			$Setup = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$InstanceId\Setup" -ErrorAction SilentlyContinue
			return (Test-InstalledApp $InstalledApps '*SQL Server 2025*' '*') -and $Setup.Edition -like '*Express*' -and $Setup.Version -like '17.*'
		}
		'Install-WindowsADK.ps1' {
			$KitsRoot = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Kits\Installed Roots' -ErrorAction SilentlyContinue).KitsRoot10
			return (Test-InstalledApp $InstalledApps 'Windows Assessment and Deployment Kit' '10.1.26100.*') -and
				(Test-Path "$KitsRoot\Assessment and Deployment Kit\Deployment Tools\amd64\DISM\dism.exe") -and
				(Test-Path "$KitsRoot\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe")
		}
		'Install-WindowsADKWinPE.ps1' {
			return Test-InstalledApp $InstalledApps 'Windows Assessment and Deployment Kit Windows Preinstallation Environment Add-ons*' '10.1.26100.*'
		}
		'Install-VCRedist-x64.ps1' {
			return Test-InstalledApp $InstalledApps 'Microsoft Visual C++*Redistributable* (x64)*' '14.*'
		}
		'Install-SMSS22.ps1' {
			return Test-InstalledApp $InstalledApps 'Microsoft SQL Server Management Studio*' '22.*'
		}
		default { return $false }
	}
}

function Read-YesNo {
	param([string]$Prompt)

	do {
		$Answer = (Read-Host "$Prompt [y/N]").Trim()
	} until ($Answer -match '^(?i:y|yes|n|no)?$')

	return $Answer -match '^(?i:y|yes)$'
}

function Invoke-PrerequisiteScript {
	param([string]$ScriptName)

	if (Test-PrerequisiteInstalled -ScriptName $ScriptName) {
		Write-Host "Skipping $ScriptName - prerequisite is already installed."
		return
	}

	Write-Host "Running $ScriptName..."
	$Command = "`$ErrorActionPreference = 'Stop'; iex (irm '$PrerequisiteBaseUrl/$ScriptName' -ErrorAction Stop)"
	& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -Command $Command
	if ($LASTEXITCODE -notin 0, 3010) {
		throw "$ScriptName failed with exit code $LASTEXITCODE. Resolve the error before continuing."
	}
}

Write-Host 'DeployR prerequisite installation. Run in an elevated PowerShell console.'
Write-Host 'These scripts use the POC defaults documented in the prerequisite README.'

$EnableIIS = Read-YesNo -Prompt 'Enable IIS for hosting additional files?'
$UseSQLExpress = Read-YesNo -Prompt 'Use SQL Express (required for iPXE Web Service; otherwise DeployR can use SQLite)?'

Invoke-PrerequisiteScript -ScriptName 'Install-PowerShell76X.ps1'
Invoke-PrerequisiteScript -ScriptName 'Install-DotNetRuntimes100X.ps1'
Invoke-PrerequisiteScript -ScriptName 'Install-WinFeatures-BranchCache-Required.ps1'

if ($EnableIIS) {
	Invoke-PrerequisiteScript -ScriptName 'Install-WinFeatures-IIS-Optional.ps1'
}
if ($UseSQLExpress) {
	Invoke-PrerequisiteScript -ScriptName 'Install-SQLExpress2025.ps1'
	Invoke-PrerequisiteScript -ScriptName 'Install-SQL2025CU.ps1'
}

Invoke-PrerequisiteScript -ScriptName 'Install-WindowsADK.ps1'
Invoke-PrerequisiteScript -ScriptName 'Install-WindowsADKWinPE.ps1'
Invoke-PrerequisiteScript -ScriptName 'Install-VCRedist-x64.ps1'

if ($UseSQLExpress) {
	Invoke-PrerequisiteScript -ScriptName 'Configure-SQLExpress.ps1'
	Invoke-PrerequisiteScript -ScriptName 'Install-SMSS22.ps1'
}

Write-Host 'DeployR prerequisite installation complete. Some components may require a restart to take effect.'
