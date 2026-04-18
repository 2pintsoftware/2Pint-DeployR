<#This script will run server side, but be triggered in a TS

Purpose is to have it automatically generate a Driver Pack for the model of the machine it is running on in the DeployR Server

how you ask?  
The TS will pass back to the script the Make & Model & OS of the system being deployed
Then this script will take that info and trigger the creation of a Driver Pack for that Make & Model & OS in the DeployR Server
This is available in Version 1.1+


#>

<#
.SYNOPSIS
    Server-side script to create a Driver Pack for the current model.
    Properly handles DeployR's argument passing.
#>

# Capture ALL arguments DeployR sends (this is the recommended pattern)
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ExtraArgs
)



#Region Functions
function Connect-ToDeployR {
    [cmdletbinding()]
    param(
        [string]$DeployRModulePath ='C:\Program Files\2Pint Software\DeployR\Client\PSModules\DeployR.Utility',
        [string]$PasscodeString = $null
    )

    
    # Check if module is available
    if (Test-Path $DeployRModulePath) {
        Import-Module $DeployRModulePath -ErrorAction Stop
    }
    elseif (Get-Module -ListAvailable -Name DeployR.Utility) {
        Import-Module DeployR.Utility -ErrorAction Stop
    }
    else {
        throw "DeployR.Utility module not found. Please ensure DeployR Client is installed."
    }
    if (get-command -Module DeployR.Utility -Name "Get-DeployROemDriverPack" -ErrorAction SilentlyContinue) {
        Write-Information "DeployR.Utility module loaded successfully." -ForegroundColor Green
    }
    else {
        throw "Get-DeployROemDriverPack command not found in DeployR.Utility module."
    }
    
    try {
        Connect-DeployR -erroraction stop
        Write-Information "Successfull connection to DeployR" -ForegroundColor Green
    }
    catch{
        Write-Warning "Initial connection to DeployR failed, attempting to retrieve passcode..." -ForegroundColor Yellow
    }    
    try {    
        #Write-Information "Connecting to DeployR..." -ForegroundColor Cyan
        Import-Module $DeployRModulePath
        #Set-DeployRHost "http://localhost:7282"
        
        if (Test-Path "HKLM:\software\2Pint Software\DeployR\GeneralSettings") {
            $DeployRReg = Get-Item -Path "HKLM:\SOFTWARE\2Pint Software\DeployR\GeneralSettings"
            $ClientPasscode = $DeployRReg.GetValue("ClientPasscode")
            Connect-DeployR -Passcode $ClientPasscode -ErrorAction Stop
        }
        elseif ($PasscodeString) {
            Connect-DeployR -Passcode $PasscodeString -ErrorAction Stop
        }
        elseif (Test-Path "D:\DeployRPasscode.txt") {
            $ClientPasscode = (Get-Content "D:\DeployRPasscode.txt" -Raw)
            Connect-DeployR -Passcode $ClientPasscode -ErrorAction Stop
        }
        else {
            throw "Cannot find DeployR Client Passcode in registry or D:\DeployRPasscode.txt"
            Connect-DeployR
        }
        
        Write-Information "Connected to DeployR" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to connect to DeployR: $_"
        return $false
    }
}
#endregion


# Convert the flat argument list into a nice hashtable
$TSVars = @{}
for ($i = 0; $i -lt $ExtraArgs.Count; $i += 2) {
    if ($i + 1 -lt $ExtraArgs.Count) {
        $key = $ExtraArgs[$i].TrimStart('-')
        $value = $ExtraArgs[$i + 1]
        $TSVars[$key] = $value
    }
}

# Now pull the values you actually need
$MakeAlias             = $TSVars['MakeAlias']
$ModelAlias            = $TSVars['ModelAlias']
$SystemAlias           = $TSVars['SystemAlias']
$OSIMAGE               = $TSVars['OSIMAGE']
$OSIMAGERELEASE        = $TSVars['OSIMAGERELEASE']
$OSIMAGEARCHITECTURE   = $TSVars['OSIMAGEARCHITECTURE']

# Logging (visible in DeployR Logger)
Write-Information "MakeAlias          : $MakeAlias"
Write-Information "ModelAlias         : $ModelAlias"
Write-Information "SystemAlias        : $SystemAlias"
Write-Information "OSIMAGE            : $OSIMAGE"
Write-Information "OSIMAGERELEASE     : $OSIMAGERELEASE"
Write-Information "OSIMAGEARCHITECTURE: $OSIMAGEARCHITECTURE"

# ←←← PUT YOUR ACTUAL DRIVER PACK CREATION CODE HERE ↓↓↓
# Example placeholder:
# Write-Information "Creating Driver Pack for $MakeAlias - $ModelAlias ($OSIMAGE)..."
# ... your logic ...
Connect-ToDeployR


<#
Ok, this isn't gonna be as simple as I thought, because the Get-DeployROEMDriverPack lets you feed it the Make & Model, however..
often times the Model (ModelAlias) doesn't match the feed from the Get-DeployROEMDriverPack function.
I think for Lenovo as example, we'll had to do something like:
$Models = Get-DeployROEMDriverPack -Make "Lenovo"
$Specific = $Models | where-object { $_ -match $ModelAlias }
if ($Specific.count -lt 1){
    #Try SystemAlias
    $Specific = $Models | where-object { $_ -match $SystemAlias }
}

Then compare the ModelAlias to the list of Models to find the correct match, then feed that back into the Get-DeployROEMDriverPack function to get the correct Driver Pack created.
I have a lot of matching to do now to figure out if this idea is viable.
#>

$SupportedModels = Get-DeployROEMDriverPack -Make $MakeAlias
$MatchedModel = $SupportedModels | Where-Object { $_ -match $ModelAlias }
if ($MatchedModel.Count -eq 0) {
    Write-Warning "No exact match found for ModelAlias '$ModelAlias'. Attempting to match with SystemAlias variable..."
    $MatchedModel = $SupportedModels | Where-Object { $_ -match $SystemAlias }
    if ($MatchedModel.Count -eq 0) {
        Write-Error "No match found for either ModelAlias '$ModelAlias' or SystemAlias '$SystemAlias'. Cannot create Driver Pack."
    }
    else {
        Write-Information "Match found using SystemAlias: $($MatchedModel -join ', ')"
        # Proceed with creating Driver Pack using $MatchedModel
    }
}

else {
    $DriverPacks = $SupportedModels = Get-DeployROEMDriverPack -Make $MakeAlias -Model $MatchedModel
    if ($DriverPacks.Count -eq 0) {
        Write-Error "No Driver Packs found for Make '$MakeAlias' and Model '$MatchedModel'."
    }
    else {
        foreach ($Pack in $DriverPacks) {
            Write-Information "Found Driver Pack $($Pack.name)"
            # Here you would call the function to create the Driver Pack, e.g.:
            # New-DeployROEMDriverPack -Make $MakeAlias -Model $MatchedModel -OS $OSIMAGE
        }
    }
    if ($DriverPacks.Count -ge 1) {
        $SpecificDriverPack = $DriverPacks | Where-Object { $_.OS -match $OSIMAGE -and $_.OSReleaseID -match $OSIMAGERELEASE}
        if ($SpecificDriverPack.Count -eq 0) {
            Write-Warning "No exact match found for OS '$OSIMAGE' and Release '$OSIMAGERELEASE'. Attempting to match with just OS '$OSIMAGE'..."
            $SpecificDriverPack = $DriverPacks | Where-Object { $_.OS -match $OSIMAGE }
            if ($SpecificDriverPack.Count -eq 0) {
                Write-Warning "No match found for OS '$OSIMAGE'"
                $SpecificDriverPack = $DriverPacks | Select-Object -Last 1
            }
            else {
                Write-Information "Match found using OS Architecture: $($SpecificDriverPack -join ', ')"
                $SpecificDriverPack = $SpecificDriverPack | Select-Object -Last 1
                # Proceed with creating Driver Pack using $SpecificDriverPack
            }
        }
        else {
            Write-Information "Exact match found for OS and Release: $($SpecificDriverPack -join ', ')"
            $SpecificDriverPack = $SpecificDriverPack | Select-Object -Last 1
        }
    }
}
if ($SpecificDriverPack) {
    Write-Information "Creating Driver Pack for $MakeAlias - $MatchedModel with OS $($SpecificDriverPack.OS) Release $($SpecificDriverPack.OSReleaseID)..."
    $SpecificDriverPack | Import-DeployROEMDriverPack
}
Write-Information "Script completed successfully."