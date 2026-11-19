<#
.SYNOPSIS
Assigns the No-Throttle template to all StifleR network groups.

.DESCRIPTION
WARNING: Do not run this script if you use StifleR to manage network bandwidth.
It is intended for DeployR customers who do not use StifleR for network management
but integrate StifleR for OSD monitoring.

Queries the StifleR WMI provider for the No-Throttle template and all network groups,
then assigns the template to groups that are not already using it. Requires access to
the StifleR WMI namespace on the computer where the script runs.

.EXAMPLE
.\Set-StifleRNoThrottleAllNGroups.ps1 -WhatIf

.EXAMPLE
.\Set-StifleRNoThrottleAllNGroups.ps1

.NOTES
Author: Not specified
Created: 2026-11-19
Change History:
2026-11-19 - Initial version.
2026-11-19 - Added a warning for StifleR bandwidth-management customers.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param()

Write-Warning 'Do not run this script if you use StifleR to manage network bandwidth. It is intended for DeployR customers who integrate StifleR for OSD monitoring only.'

$namespace = 'root\StifleR'
$templateId = '00000000-0000-0000-0000-000000000011' # No-Throttle template ID

# Load templates once so group assignments can be reported by name and ID.
$templates = @(Get-CimInstance -Namespace $namespace -ClassName NetworkGroupTemplates -ErrorAction Stop)
$template = $templates | Where-Object { $_.Id -eq $templateId } | Select-Object -First 1
if (-not $template) {
	throw "StifleR template '$templateId' was not found in namespace '$namespace'."
}
$templateNamesById = @{}
foreach ($networkTemplate in $templates) {
	$templateNamesById[[string]$networkTemplate.Id] = $networkTemplate.Name
}

$networkGroups = @(Get-CimInstance -Namespace $namespace -ClassName NetworkGroups -ErrorAction Stop)
if ($networkGroups.Count -eq 0) {
	Write-Warning 'No StifleR network groups were found.'
	return
}

$failures = [System.Collections.Generic.List[string]]::new()
foreach ($networkGroup in $networkGroups) {
	$groupName = if ([string]::IsNullOrWhiteSpace($networkGroup.Name)) { $networkGroup.Id } else { $networkGroup.Name }
	$currentTemplateId = [string]$networkGroup.Template
	$currentTemplateName = if ($templateNamesById.ContainsKey($currentTemplateId)) {
		$templateNamesById[$currentTemplateId]
	}
	else {
		'Unknown template'
	}
	Write-Host "Checking network group '$groupName' ($($networkGroup.Id)) | Assigned template: $currentTemplateName ($currentTemplateId)"

	if ($currentTemplateId -eq $templateId) {
		Write-Host '  No change needed; the No-Throttle template is already assigned.'
		continue
	}

	if ($PSCmdlet.ShouldProcess("$groupName ($($networkGroup.Id))", "Assign No-Throttle template $templateId")) {
		try {
			$result = Invoke-CimMethod -InputObject $networkGroup -MethodName SetTemplate `
				-Arguments @{ TemplateId = $templateId } -ErrorAction Stop
			$returnValue = $result.ReturnValue
			$methodSucceeded = if ($returnValue -is [bool]) { $returnValue } else { $returnValue -eq 0 }
			if (-not $methodSucceeded) {
				throw "SetTemplate returned code $($result.ReturnValue)."
			}
			Write-Host "  Assigned template: $($template.Name) ($templateId)" -ForegroundColor Green
		}
		catch {
			$failures.Add("$groupName ($($networkGroup.Id)): $($_.Exception.Message)")
			Write-Error -Message "Failed to assign the No-Throttle template to network group '$groupName': $($_.Exception.Message)" -ErrorAction Continue
		}
	}
}

if ($failures.Count -gt 0) {
	throw "Failed to assign the No-Throttle template to $($failures.Count) network group(s): $($failures -join '; ')"
}
