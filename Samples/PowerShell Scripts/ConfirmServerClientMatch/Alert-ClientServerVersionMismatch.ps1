# Alert and decision gate for DeployR version mismatch in task sequences.
#
# Behavior:
# - Reads DEPLOYRCLIENTVERSION and DEPLOYRSERVERVERSION from the TSEnv drive.
# - If versions match, exits 0 (continue).
# - If versions differ (or are missing), shows a simple dialog with two options:
#   Continue Task Sequence (exit 0) or Fail Task Sequence (exit 124).

$ErrorActionPreference = 'Stop'

function Get-DeployRTSVariable {
	param(
		[Parameter(Mandatory = $true)]
		[string]$Name
	)

	try {
		$value = (Get-Item -Path ("TSEnv:{0}" -f $Name) -ErrorAction Stop).Value
		if (-not [string]::IsNullOrWhiteSpace($value)) {
			return $value.Trim()
		}
	}
	catch {
	}

	try {
		$value = [Environment]::GetEnvironmentVariable($Name)
		if (-not [string]::IsNullOrWhiteSpace($value)) {
			return $value.Trim()
		}
	}
	catch {
	}

	return ''
}

function Show-VersionDecisionDialog {
	param(
		[Parameter(Mandatory = $true)]
		[string]$ClientVersion,

		[Parameter(Mandatory = $true)]
		[string]$ServerVersion
	)

	Add-Type -AssemblyName System.Windows.Forms
	Add-Type -AssemblyName System.Drawing

	$form = New-Object System.Windows.Forms.Form
	$form.Text = 'DeployR Version Mismatch'
	$form.StartPosition = 'CenterScreen'
	$form.FormBorderStyle = 'FixedDialog'
	$form.MaximizeBox = $false
	$form.MinimizeBox = $false
	$form.TopMost = $true
	$form.ClientSize = New-Object System.Drawing.Size(580, 230)

	$message = New-Object System.Windows.Forms.Label
	$message.Location = New-Object System.Drawing.Point(16, 16)
	$message.Size = New-Object System.Drawing.Size(548, 124)
	$message.Font = New-Object System.Drawing.Font('Segoe UI', 10)
	$message.Text = @"
DeployR client and server versions do not match.

Client version: $ClientVersion
Server version: $ServerVersion

Choose Continue Task Sequence to proceed anyway, or Fail Task Sequence to stop.
This prompt will auto-continue in 30 seconds.
"@
	$form.Controls.Add($message)

	$continueButton = New-Object System.Windows.Forms.Button
	$continueButton.Text = 'Continue Task Sequence'
	$continueButton.Size = New-Object System.Drawing.Size(190, 34)
	$continueButton.Location = New-Object System.Drawing.Point(160, 166)
	$continueButton.DialogResult = [System.Windows.Forms.DialogResult]::Yes
	$continueButton.Add_Click({
		$form.DialogResult = [System.Windows.Forms.DialogResult]::Yes
		$form.Close()
	})
	$form.Controls.Add($continueButton)

	$failButton = New-Object System.Windows.Forms.Button
	$failButton.Text = 'Fail Task Sequence'
	$failButton.Size = New-Object System.Drawing.Size(160, 34)
	$failButton.Location = New-Object System.Drawing.Point(364, 166)
	$failButton.DialogResult = [System.Windows.Forms.DialogResult]::No
	$failButton.Add_Click({
		$form.DialogResult = [System.Windows.Forms.DialogResult]::No
		$form.Close()
	})
	$form.Controls.Add($failButton)

	$form.AcceptButton = $continueButton
	$form.CancelButton = $failButton

	$timeoutSeconds = 30
	$defaultContinueText = 'Continue Task Sequence'
	$continueButton.Text = "$defaultContinueText ($timeoutSeconds)"

	$form.Show()
	$form.Activate()

	$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
	while (-not $form.IsDisposed -and $form.Visible) {
		$remainingSeconds = [int][Math]::Ceiling($timeoutSeconds - $stopwatch.Elapsed.TotalSeconds)
		if ($remainingSeconds -lt 0) { $remainingSeconds = 0 }
		$continueButton.Text = "$defaultContinueText ($remainingSeconds)"

		if ($stopwatch.Elapsed.TotalSeconds -ge $timeoutSeconds) {
			$form.DialogResult = [System.Windows.Forms.DialogResult]::Yes
			$form.Close()
			break
		}

		[System.Windows.Forms.Application]::DoEvents()
		[System.Threading.Thread]::Sleep(200)
	}

	$stopwatch.Stop()
	$result = $form.DialogResult
	$form.Dispose()

	return $result
}

$clientVersion = Get-DeployRTSVariable -Name 'DEPLOYRCLIENTVERSION'
$serverVersion = Get-DeployRTSVariable -Name 'DEPLOYRSERVERVERSION'

if ([string]::IsNullOrWhiteSpace($clientVersion)) { $clientVersion = '<not set>' }
if ([string]::IsNullOrWhiteSpace($serverVersion)) { $serverVersion = '<not set>' }

Write-Host "DeployR client version: $clientVersion"
Write-Host "DeployR server version: $serverVersion"

if ($clientVersion -eq $serverVersion -and $clientVersion -ne '<not set>') {
	Write-Host 'DeployR versions match. Continuing task sequence.' -ForegroundColor Green
	exit 0
}

try {
	$choice = Show-VersionDecisionDialog -ClientVersion $clientVersion -ServerVersion $serverVersion
	if ($choice -eq [System.Windows.Forms.DialogResult]::Yes) {
		Write-Host 'User selected Continue Task Sequence.' -ForegroundColor Yellow
		exit 0
	}

	Write-Host 'User selected Fail Task Sequence.' -ForegroundColor Red
	exit 124
}
catch {
	Write-Host "Unable to show version mismatch dialog: $($_.Exception.Message)" -ForegroundColor Red
	Write-Host 'Continuing task sequence by default due to mismatch prompt fallback behavior.' -ForegroundColor Yellow
	exit 0
}
