$ErrorActionPreference = 'Stop'

$UILanguage = [string]${tsenv:UILANGUAGE}
if ([string]::IsNullOrWhiteSpace($UILanguage)) {
    Write-Host 'UILANGUAGE is not set. Skipping language installation.'
    return
}

try {
    Write-Host "Checking installed languages for $UILanguage..."
    $installedLanguages = @(Get-InstalledLanguage -ErrorAction Stop)
    $installedLanguageIds = @($installedLanguages | ForEach-Object { $_.LanguageId })
    if ($installedLanguageIds.Count -gt 0) {
        Write-Host "Currently installed language(s): $($installedLanguageIds -join ', ')"
    }
    else {
        Write-Host 'No installed language packs were reported.'
    }

    if ($installedLanguageIds -contains $UILanguage) {
        Write-Host "Language $UILanguage is already installed. No installation is needed."
        return
    }

    Write-Host "Starting language installation for $UILanguage. This can take several minutes..."
    $installStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $installJob = Install-Language -Language $UILanguage -AsJob -Verbose -ErrorAction Stop
    if ($null -eq $installJob) {
        throw 'Install-Language did not return a background job.'
    }

    Write-Host "Language installation job started (ID: $($installJob.Id), state: $($installJob.State)). Waiting for Windows servicing..."
    while ($installJob.State -in @('NotStarted', 'Running')) {
        $completedJob = Wait-Job -Job $installJob -Timeout 30
        if ($completedJob) {
            break
        }

        Write-Host "Still installing $UILanguage. Elapsed: $($installStopwatch.Elapsed.ToString('hh\:mm\:ss')); job state: $($installJob.State)."
    }

    if ($installJob.State -ne 'Completed') {
        $jobFailure = @($installJob.ChildJobs | ForEach-Object { $_.JobStateInfo.Reason } | Where-Object { $_ }) -join '; '
        if ([string]::IsNullOrWhiteSpace($jobFailure)) {
            $jobFailure = "Job ended in state '$($installJob.State)'"
        }
        throw "Language installation job failed: $jobFailure"
    }

    Write-Host "Language installation job completed in $($installStopwatch.Elapsed.ToString('hh\:mm\:ss')). Retrieving verbose output..."
    $null = Receive-Job -Job $installJob -ErrorAction Stop -Verbose
    Remove-Job -Job $installJob -Force -ErrorAction SilentlyContinue
    $installStopwatch.Stop()

    Write-Host 'Verifying installed language...'
    $installedLanguages = @(Get-InstalledLanguage -ErrorAction Stop)
    if ($installedLanguages.LanguageId -notcontains $UILanguage) {
        throw "Install-Language completed, but $UILanguage is not reported as installed."
    }

    Write-Host "Language $UILanguage installed successfully in $($installStopwatch.Elapsed.ToString('hh\:mm\:ss')). Unattend.xml remains responsible for locale settings."
}
catch {
    Write-Error "Failed to install language ${UILanguage}: $($_.Exception.Message)"
    exit 1
}
finally {
    if ($null -ne $installJob) {
        Remove-Job -Job $installJob -Force -ErrorAction SilentlyContinue
    }
}