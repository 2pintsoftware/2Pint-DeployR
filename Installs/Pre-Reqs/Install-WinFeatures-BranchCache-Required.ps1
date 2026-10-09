# BranchCache is required. Client operating systems use Distributed Cache mode;
# Windows Server installs the BranchCache feature and management tools.

$ErrorActionPreference = 'Stop'

try {
    $os = Get-CimInstance Win32_OperatingSystem
    $productType = [int]$os.ProductType

    Write-Host "Detected OS: $($os.Caption)"
    Write-Host "ProductType: $productType"

    if ($productType -eq 1) {
        if (-not (Get-Command Enable-BCDistributed -ErrorAction SilentlyContinue)) {
            throw 'BranchCache PowerShell cmdlets are not available on this device.'
        }

        $bcStatus = Get-BCStatus -ErrorAction SilentlyContinue
        if ($bcStatus -and $bcStatus.BranchCacheIsEnabled) {
            Write-Host 'BranchCache is already enabled.'
        }
        else {
            Write-Host 'Enabling BranchCache in Distributed Cache mode...'
            Enable-BCDistributed -Force
        }

        $bcStatus = Get-BCStatus
        Write-Host "BranchCache enabled: $($bcStatus.BranchCacheIsEnabled)"
        Write-Host "BranchCache client mode: $($bcStatus.ClientConfiguration.CurrentClientMode)"
    }
    elseif ($productType -in 2, 3) {
        Import-Module ServerManager -ErrorAction Stop

        $result = Install-WindowsFeature -Name BranchCache -IncludeManagementTools
        if (-not $result.Success) {
            throw 'Install-WindowsFeature reported failure for BranchCache.'
        }

        if ($result.RestartNeeded -ne 'No') {
            Write-Host "BranchCache installed. Restart required: $($result.RestartNeeded)"
        }
    }
    else {
        throw "Unknown ProductType value: $productType"
    }

    Write-Host 'Required BranchCache configuration completed successfully.'
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}