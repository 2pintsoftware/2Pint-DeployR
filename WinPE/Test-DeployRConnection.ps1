<#
.SYNOPSIS
    Tests the connection to the DeployR Server.
.DESCRIPTION
    This script tests the network connectivity to the DeployR Server.
    It will first check for a valid network configuration, and then attempt to connect to the DeployR Server on port 7281.
    Add this to the PostInit.ps1 script in WinPE/WinRE:
    . "$PSScriptRoot\Test-DeployRConnection.ps1"

.NOTES
    Author: Mike Terrill/2Pint Software
    Date: September 17, 2026
    Version: 26.09.17
        
    Version history:
    26.09.17: Initial release
    26.09.17: Updated to use raw TCP socket for connectivity test in WinPE/WinRE
    26.09.17: Added transcript logging for debugging purposes
 
#>

if (Get-PSProvider TSENV -ErrorAction SilentlyContinue){
    $DeployRServer = ([System.Uri]$TSENV:DEPLOYRHOST).Host
}
else {
    $DeployRServer = "deployr.2pintdemo.net"
}


$MaxWaitSeconds = 120
$IntervalSeconds = 10

$LogFolder = Join-Path $env:SystemDrive "_2P\Logs"
if (-not (Test-Path -Path $LogFolder)){
    $LogFolder = $env:TEMP
}

Start-Transcript -Path (Join-Path $LogFolder "TestDeployRConnect.txt") -Force | Out-Null

function Get-NetworkInfo {

    # Get-NetIPConfiguration/Get-NetIPAddress aren't available in WinPE, so use CIM/WMI instead
    $WmiAdapter = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object {
        $_.IPEnabled -and
        $_.DefaultIPGateway -and
        ($_.IPAddress | Where-Object { $_ -notlike '*:*' -and $_ -notlike '169.254*' })
    } | Select-Object -First 1

    if (-not $WmiAdapter) {
        return $null
    }

    $IPAddress = $WmiAdapter.IPAddress | Where-Object { $_ -notlike '*:*' -and $_ -notlike '169.254*' } | Select-Object -First 1
    $SubnetMask = $WmiAdapter.IPSubnet | Where-Object { $_ -and $_ -notlike '*:*' } | Select-Object -First 1

    [PSCustomObject]@{
        Adapter    = $WmiAdapter.Description
        IPAddress  = $IPAddress
        SubnetMask = $SubnetMask
        Gateway    = ($WmiAdapter.DefaultIPGateway | Where-Object { $_ -notlike '*:*' } | Select-Object -First 1)
        DHCPServer = $WmiAdapter.DHCPServer
        DNSServers = ($WmiAdapter.DNSServerSearchOrder -join ', ')
    }
}

try {

#
# Phase 1 - Wait for network configuration
#
$Elapsed = 0
$NetworkInfo = $null

while ($Elapsed -lt $MaxWaitSeconds) {

    $NetworkInfo = Get-NetworkInfo

    if ($NetworkInfo) {
        Write-Host "Network configuration detected." -ForegroundColor Green
        $NetworkInfo | Format-List
        break
    }

    Write-Host "Waiting for network configuration... ($Elapsed/$MaxWaitSeconds seconds)"
    Start-Sleep -Seconds $IntervalSeconds
    $Elapsed += $IntervalSeconds
}

if (-not $NetworkInfo) {
    Write-Warning "No network configuration detected after $MaxWaitSeconds seconds."
    exit 1
}

#
# Phase 2 - Wait for DeployR connectivity
#
Write-Host ""
Write-Host "Testing connectivity to $DeployRServer on port 7281..." -ForegroundColor Cyan

$Elapsed = 0
$Connected = $false

while ($Elapsed -lt $MaxWaitSeconds) {

    try {
        # Test-NetConnection isn't available in WinPE, so use a raw TCP socket instead
        $TcpClient = [System.Net.Sockets.TcpClient]::new()
        $ConnectTask = $TcpClient.ConnectAsync($DeployRServer, 7281)
        $Test = $ConnectTask.Wait(5000) -and $TcpClient.Connected
        $TcpClient.Close()

        if ($Test) {
            Write-Host "Successfully connected to $DeployRServer on port 7281." -ForegroundColor Green
            $Connected = $true
            break
        }
    }
    catch {
        # Ignore and retry
    }

    Write-Host "Unable to connect to $DeployRServer:7281. Retrying... ($Elapsed/$MaxWaitSeconds seconds)"
    Start-Sleep -Seconds $IntervalSeconds
    $Elapsed += $IntervalSeconds
}

if (-not $Connected) {
    Write-Warning "Failed to connect to $DeployRServer on port 7281 after $MaxWaitSeconds seconds."
    exit 2
}

exit 0

}
finally {
    Stop-Transcript | Out-Null
}
