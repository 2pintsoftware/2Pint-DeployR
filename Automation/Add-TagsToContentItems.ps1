<#
.SYNOPSIS
Automatically adds manufacturer tags to driverpack content items in DeployR.

.DESCRIPTION
This script searches for all driverpack content items in DeployR and automatically adds
tags based on the manufacturer name found in the driverpack name.

Supported manufacturers:
- HP
- Dell
- Lenovo
- Panasonic
- Microsoft

.EXAMPLE
.\Add-TagsToContentItems.ps1

.NOTES
Author: Gary Blok
Date: 2026-07-14
#>

# Check for Administrator role
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

#region Functions

function Connect-ToDeployR {
    try {
        if (Test-Path 'C:\Program Files\2Pint Software\DeployR\Client\PSModules\DeployR.Utility') {
            Import-Module 'C:\Program Files\2Pint Software\DeployR\Client\PSModules\DeployR.Utility' -ErrorAction Stop
        }
        elseif (Get-Module -ListAvailable -Name DeployR.Utility) {
            Import-Module DeployR.Utility -ErrorAction Stop
        }
        else {
            throw "DeployR.Utility module not found. Please ensure DeployR Client is installed."
        }
        
        Write-Host "Connecting to DeployR..." -ForegroundColor Cyan
        
        if (Test-Path "HKLM:\software\2Pint Software\DeployR\GeneralSettings") {
            $DeployRReg = Get-Item -Path "HKLM:\SOFTWARE\2Pint Software\DeployR\GeneralSettings"
            $ClientPasscode = $DeployRReg.GetValue("ClientPasscode")
            Connect-DeployR -Passcode $ClientPasscode -ErrorAction Stop
        }
        elseif (Test-Path "D:\DeployRPasscode.txt") {
            $ClientPasscode = (Get-Content "D:\DeployRPasscode.txt" -Raw)
            Connect-DeployR -Passcode $ClientPasscode -ErrorAction Stop
        }
        else {
            throw "Cannot find DeployR Client Passcode in registry or D:\DeployRPasscode.txt"
        }
        
        Write-Host "Connected to DeployR" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to connect to DeployR: $_"
        return $false
    }
}

function Get-ManufacturerFromName {
    <#
    .SYNOPSIS
    Extracts manufacturer name from a driverpack name.
    
    .PARAMETER Name
    The name of the driverpack to analyze.
    
    .OUTPUTS
    String containing the manufacturer name if found, otherwise $null
    #>
    param(
        [string]$Name
    )
    
    $manufacturers = @('HP', 'Dell', 'Lenovo', 'Panasonic', 'Microsoft')
    
    foreach ($manufacturer in $manufacturers) {
        if ($Name -match [regex]::Escape($manufacturer)) {
            return $manufacturer
        }
    }
    
    return $null
}

function Add-TagToContentItem {
    <#
    .SYNOPSIS
    Adds a tag to a DeployR content item.
    
    .PARAMETER ContentItemId
    The ID of the content item to tag.
    
    .PARAMETER ContentItemName
    The name of the content item (for logging).
    
    .PARAMETER Tag
    The tag to add to the content item.
    #>
    param(
        [string]$ContentItemId,
        [string]$ContentItemName,
        [string]$Tag
    )
    
    try {
        $contentItem = Get-DeployRMetaData -Type ContentItem | Where-Object { $_.id -eq $ContentItemId }
        
        if ($null -eq $contentItem) {
            Write-Warning "Content item with ID $ContentItemId not found"
            return $false
        }
        
        $currentTags = $contentItem.tags
        
        if ($null -eq $currentTags) {
            $currentTags = @()
        }
        
        if ($Tag -notin $currentTags) {
            $contentItem.tags += $Tag
            $null = Set-DeployRMetadata -Type ContentItem -Object $contentItem
            Write-Host "  ✓ Added tag '$Tag' to: $ContentItemName" -ForegroundColor Green
            return $true
        }
        else {
            Write-Host "  ○ Tag '$Tag' already exists on: $ContentItemName" -ForegroundColor Cyan
            return $false
        }
    }
    catch {
        Write-Error "  ✗ Failed to add tag to $ContentItemName : $_"
        return $false
    }
}

#endregion

#region Execution Area

Write-Host "`n=== DeployR Driverpack Auto-Tagger ===" -ForegroundColor Magenta
Write-Host "This script will add manufacturer tags to driverpack content items" -ForegroundColor Gray

# Connect to DeployR
if (-not (Connect-ToDeployR)) {
    exit 1
}

# Get all content items (specifically looking for driverpacks)
Write-Host "`nRetrieving driverpack content items..." -ForegroundColor Cyan

try {
    $contentItems = Get-DeployRMetaData -Type ContentItem
    
    if ($null -eq $contentItems -or $contentItems.Count -eq 0) {
        Write-Warning "No content items found in DeployR"
        exit 1
    }
    
    # Filter for driverpacks (items with 'driver' in the name, case-insensitive)
    $driverpacks = $contentItems | Where-Object { $_.contentItemPurpose -eq 'DriverPack' } | Sort-Object -Property Name
    
    if ($null -eq $driverpacks) {
        Write-Warning "No driverpacks found in DeployR"
        exit 0
    }
    
    Write-Host "Found $($driverpacks.Count) driverpack(s)" -ForegroundColor Green
    
    # Process each driverpack
    $tagsAdded = 0
    $tagsSkipped = 0
    
    Write-Host "`n--- Processing Driverpacks ---" -ForegroundColor Yellow
    
    foreach ($driverpack in $driverpacks) {
        $manufacturer = Get-ManufacturerFromName -Name $driverpack.name
        
        if ($null -ne $manufacturer) {
            Write-Host "`n$($driverpack.name)" -ForegroundColor Cyan
            if (Add-TagToContentItem -ContentItemId $driverpack.id -ContentItemName $driverpack.name -Tag $manufacturer) {
                $tagsAdded++
            }
            else {
                $tagsSkipped++
            }
        }
        else {
            Write-Host "`n$($driverpack.name)" -ForegroundColor Gray
            Write-Host "  ⊘ No recognized manufacturer in name (HP, Dell, Lenovo, Panasonic, Microsoft)" -ForegroundColor Gray
        }
    }
    
    # Summary
    Write-Host "`n=== Summary ===" -ForegroundColor Magenta
    Write-Host "Total driverpacks processed: $($driverpacks.Count)" -ForegroundColor Cyan
    Write-Host "Tags added: $tagsAdded" -ForegroundColor Green
    Write-Host "Tags skipped (already exist): $tagsSkipped" -ForegroundColor Yellow
}
catch {
    Write-Error "Failed to retrieve or process driverpacks: $_"
    exit 1
}

Write-Host "`nScript completed successfully!" -ForegroundColor Green

#endregion
