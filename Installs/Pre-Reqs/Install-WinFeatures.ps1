$ErrorActionPreference = 'Stop'

try {
    $os = Get-CimInstance Win32_OperatingSystem
    $productType = [int]$os.ProductType

    Write-Host "Detected OS: $($os.Caption)"
    Write-Host "ProductType: $productType"

    if ($productType -eq 1) {
        Write-Host "Windows client OS detected. Using DISM for IIS features and BranchCache cmdlets for BranchCache."

        $clientFeatures = @(
            'IIS-WebServerRole',
            'IIS-WindowsAuthentication'
        )

        foreach ($feature in $clientFeatures) {
            $state = Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction SilentlyContinue

            if ($state -and $state.State -eq 'Enabled') {
                Write-Host "Feature already enabled: $feature"
                continue
            }

            Write-Host "Enabling feature: $feature"
            $process = Start-Process -FilePath dism.exe `
                -ArgumentList "/online /enable-feature /featurename:$feature /all /norestart" `
                -Wait `
                -NoNewWindow `
                -PassThru

            if ($process.ExitCode -notin 0, 3010) {
                throw "Failed to enable feature $feature. DISM exit code: $($process.ExitCode)"
            }

            if ($process.ExitCode -eq 3010) {
                Write-Host "Feature enabled and reboot required: $feature"
            }
        }

        if (-not (Get-Command Enable-BCDistributed -ErrorAction SilentlyContinue)) {
            throw "BranchCache PowerShell cmdlets are not available on this device."
        }

        $bcStatus = Get-BCStatus -ErrorAction SilentlyContinue

        if ($bcStatus -and $bcStatus.BranchCacheIsEnabled) {
            Write-Host "BranchCache is already enabled."
        }
        else {
            Write-Host "Enabling BranchCache in Distributed Cache mode..."
            Enable-BCDistributed -Force
        }

        $bcStatus = Get-BCStatus
        Write-Host "BranchCache enabled: $($bcStatus.BranchCacheIsEnabled)"
        Write-Host "BranchCache client mode: $($bcStatus.ClientConfiguration.CurrentClientMode)"
    }
    elseif ($productType -in 2,3) {
        Write-Host "Windows Server OS detected. Using ServerManager."

        Import-Module ServerManager -ErrorAction Stop

        $result = Install-WindowsFeature `
            -Name Web-Server, Web-Windows-Auth, BranchCache `
            -IncludeManagementTools

        if (-not $result.Success) {
            throw "Install-WindowsFeature reported failure."
        }

        if ($result.RestartNeeded -ne 'No') {
            Write-Host "One or more features installed. Restart required: $($result.RestartNeeded)"
        }
    }
    else {
        throw "Unknown ProductType value: $productType"
    }

    Write-Host "Configuration completed successfully."
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
