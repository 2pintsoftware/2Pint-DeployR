# Alert and decision gate for DeployR version mismatch in task sequences.
#
# Behavior:
# - Reads DEPLOYRCLIENTVERSION and DEPLOYRSERVERVERSION from the TSEnv drive.
# - If versions match, exits 0 (continue).
# - If versions differ (or are missing), shows a simple dialog with two options:
#   Continue Task Sequence (exit 0) or Fail Task Sequence (exit 124).
# - Use -DialogPosition to choose where the dialog appears on the primary screen.

param(
	[ValidateSet('Center', 'TopLeft', 'TopCenter', 'TopRight', 'BottomLeft', 'BottomCenter', 'BottomRight')]
	[string]$DialogPosition = 'BottomCenter'
)

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
		[string]$ServerVersion,

		[string]$Position = 'Center'
	)

	Add-Type -AssemblyName System.Windows.Forms
	Add-Type -AssemblyName System.Drawing

	if (-not ('DeployRDialogNative' -as [type])) {
		Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class DeployRDialogNative {
	[DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);
	[DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
}
'@
	}
	$hwndTopMost = [IntPtr]::new(-1)
	$swpNoMoveNoSizeNoActivate = 0x0013
	$form = New-Object System.Windows.Forms.Form
	$form.Text = 'DeployR Version Mismatch'
	$form.StartPosition = 'Manual'
	$form.FormBorderStyle = 'FixedDialog'
	$form.MaximizeBox = $false
	$form.MinimizeBox = $false
	$form.TopMost = $true
	$form.ClientSize = New-Object System.Drawing.Size(580, 230)

	$workArea = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
	$margin = 20
	$left = $workArea.Left + $margin
	$centerX = $workArea.Left + [int](($workArea.Width - $form.Width) / 2)
	$right = $workArea.Right - $form.Width - $margin
	$top = $workArea.Top + $margin
	$centerY = $workArea.Top + [int](($workArea.Height - $form.Height) / 2)
	$bottom = $workArea.Bottom - $form.Height - $margin
	$x, $y = switch ($Position) {
		'TopLeft' { $left, $top }
		'TopCenter' { $centerX, $top }
		'TopRight' { $right, $top }
		'BottomLeft' { $left, $bottom }
		'BottomCenter' { $centerX, $bottom }
		'BottomRight' { $right, $bottom }
		default { $centerX, $centerY }
	}
	$form.Location = New-Object System.Drawing.Point($x, $y)

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
	[void][DeployRDialogNative]::SetWindowPos($form.Handle, $hwndTopMost, 0, 0, 0, 0, $swpNoMoveNoSizeNoActivate)
	[void][DeployRDialogNative]::SetForegroundWindow($form.Handle)

	$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
	$lastTopMostAssert = 0
	while (-not $form.IsDisposed -and $form.Visible) {
		# Another topmost window can take the top spot, so re-assert every 2 seconds.
		if (($stopwatch.Elapsed.TotalSeconds - $lastTopMostAssert) -ge 2) {
			[void][DeployRDialogNative]::SetWindowPos($form.Handle, $hwndTopMost, 0, 0, 0, 0, $swpNoMoveNoSizeNoActivate)
			$lastTopMostAssert = $stopwatch.Elapsed.TotalSeconds
		}
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
	$choice = Show-VersionDecisionDialog -ClientVersion $clientVersion -ServerVersion $serverVersion -Position $DialogPosition
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
