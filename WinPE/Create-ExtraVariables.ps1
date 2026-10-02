
$LogFolder = Join-Path $env:SystemDrive "_2P\Logs"
if (-not (Test-Path -Path $LogFolder)){
    $LogFolder = $env:TEMP
}

Start-Transcript -Path (Join-Path $LogFolder "Create-ExtraVariables.log") -Force | Out-Null

try {
    if (-not (Get-PSDrive -Name TSENV -ErrorAction SilentlyContinue)) {
        throw 'DeployR TSENV drive is not available; no variables were created.'
    }

    $Variables = @{
        PA_HOSTNAME = $env:COMPUTERNAME
        PA_NETWORKADAPTER = 'NA'
        PA_NETWORKMACADDRESS = 'NA'
        PA_NETWORKIPADDRESS = 'NA'
        PA_NETWORKSUBNETMASK = 'NA'
        PA_NETWORKGATEWAY = 'NA'
        PA_NETWORKDHCP = 'NA'
        PA_NETWORKDNSSERVERS = 'NA'
        PA_DISKCOUNT = 'NA'
        PA_DISKMODEL = 'NA'
        PA_DISKSIZEGB = 'NA'
        PA_DISKTYPE = 'NA'
        PA_TPMVERSION = 'NA'
        PA_SECUREBOOTSTATUS = 'NA'
        PA_STIFLERVERSION = 'NA'
    }

    try {
        $Adapter = Get-CimInstance Win32_NetworkAdapterConfiguration -ErrorAction Stop | Where-Object {
            $_.IPEnabled -and ($_.IPAddress | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' -and $_ -notlike '169.254*' })
        } | Sort-Object -Property @{ Expression = { [int](-not $_.DefaultIPGateway) } } | Select-Object -First 1
        if ($Adapter) {
            $Variables.PA_NETWORKADAPTER = $Adapter.Description
            $Variables.PA_NETWORKMACADDRESS = $Adapter.MACAddress
            $Variables.PA_NETWORKIPADDRESS = @($Adapter.IPAddress | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' -and $_ -notlike '169.254*' })[0]
            $Variables.PA_NETWORKSUBNETMASK = @($Adapter.IPSubnet | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' })[0]
            $Variables.PA_NETWORKGATEWAY = @($Adapter.DefaultIPGateway | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' })[0]
            if ($null -ne $Adapter.DHCPEnabled) {
                $Variables.PA_NETWORKDHCP = if ($Adapter.DHCPEnabled) { 'True' } else { 'False' }
            }
            $Variables.PA_NETWORKDNSSERVERS = @($Adapter.DNSServerSearchOrder) -join ', '
        }
    } catch {
        Write-Warning "Network inventory failed: $_"
    }

    try {
        $Disks = @(Get-CimInstance Win32_DiskDrive -ErrorAction Stop | Sort-Object Index)
        $Variables.PA_DISKCOUNT = [string]$Disks.Count
        $PreferredDiskIndex = ${TSEnv:DiskIndex}
        $Disk = $Disks | Where-Object { $null -ne $PreferredDiskIndex -and $_.Index -eq $PreferredDiskIndex } | Select-Object -First 1
        if (-not $Disk) {
            $Disk = $Disks | Where-Object { $_.InterfaceType -ne 'USB' } | Select-Object -First 1
        }
        if (-not $Disk) { $Disk = $Disks | Select-Object -First 1 }
        if ($Disk) {
            $Variables.PA_DISKMODEL = $Disk.Model
            if ($null -ne $Disk.Size -and [double]$Disk.Size -gt 0) {
                $Variables.PA_DISKSIZEGB = [string][math]::Round([double]$Disk.Size / 1GB, 1)
            }
            $Variables.PA_DISKTYPE = if ($Disk.PNPDeviceID -match 'NVME') { 'NVMe' } else { $Disk.InterfaceType }
            try {
                $StorageDisk = Get-CimInstance -Namespace 'root\microsoft\windows\storage' -ClassName MSFT_Disk -Filter "Number = $($Disk.Index)" -ErrorAction Stop | Select-Object -First 1
                if ($StorageDisk) {
                    $Variables.PA_DISKTYPE = switch ([string]$StorageDisk.BusType) {
                        '17' { 'NVMe' }
                        '11' { 'SATA' }
                        '10' { 'SAS' }
                        '7' { 'USB' }
                        '8' { 'RAID' }
                        default { [string]$StorageDisk.BusType }
                    }
                }
            } catch {
                Write-Warning "Disk bus type unavailable, using Win32_DiskDrive: $_"
            }
        }
    } catch {
        Write-Warning "Disk inventory failed: $_"
    }

    try {
        $Tpm = Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction Stop
        if ($Tpm.SpecVersion) {
            $Variables.PA_TPMVERSION = ($Tpm.SpecVersion -split ',')[0].Trim()
        }
    } catch {
        Write-Warning "TPM inventory unavailable: $_"
    }

    if (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) {
        try {
            $Variables.PA_SECUREBOOTSTATUS = if (Confirm-SecureBootUEFI -ErrorAction Stop) { 'Enabled' } else { 'Disabled' }
        } catch {
            $Variables.PA_SECUREBOOTSTATUS = 'NA'
            Write-Warning "Secure Boot status unavailable: $_"
        }
    }

    $StifleRPath = Join-Path $env:SystemDrive 'Program Files\2Pint Software\StifleR Client\StifleR.ClientApp.exe'
    try {
        if (Test-Path -LiteralPath $StifleRPath -PathType Leaf) {
            $Variables.PA_STIFLERVERSION = (Get-Item -LiteralPath $StifleRPath -ErrorAction Stop).VersionInfo.FileVersion
        }
    } catch {
        Write-Warning "StifleR version unavailable: $_"
    }

    foreach ($Name in @($Variables.Keys)) {
        if ([string]::IsNullOrWhiteSpace([string]$Variables[$Name])) {
            $Variables[$Name] = 'NA'
        }
        Set-Item -Path "TSENV:$Name" -Value ([string]$Variables[$Name]) -ErrorAction Stop
        Write-Host "$Name = $($Variables[$Name])"
    }
} finally {
    Stop-Transcript | Out-Null
}
