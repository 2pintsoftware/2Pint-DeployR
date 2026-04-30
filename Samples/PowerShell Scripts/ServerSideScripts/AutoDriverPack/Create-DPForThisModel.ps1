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
    if (get-command -Module DeployR.Utility -Name "Get-DeployROemDriverPack" -ErrorAction SilentlyContinue) {
        Write-Information "Line # 38 | DeployR.Utility module loaded successfully."
    }
    else {
        if (Test-Path $DeployRModulePath) {
            Import-Module $DeployRModulePath -ErrorAction Stop
        }
        elseif (Get-Module -ListAvailable -Name DeployR.Utility) {
            Import-Module DeployR.Utility -ErrorAction Stop
        }
        else {
            throw "DeployR.Utility module not found. Please ensure DeployR Client is installed."
        }
    }
    
    
    try {
        Connect-DeployR -erroraction stop
        Write-Information "Line # 55 | Successfull connection to DeployR" 
    }
    catch{
        Write-Warning "Line # 58 | Initial connection to DeployR failed, attempting to retrieve passcode..."
    }    
    try {    
        #Write-Information "Connecting to DeployR..."
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
        
        Write-Information "Line # 82 | Connected to DeployR"
        return $true
    }
    catch {
        Write-Error "Line # 86 | Failed to connect to DeployR: $_"
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

<# Logging (visible in DeployR Logger)
Write-Information "Line # 112 | MakeAlias          : $MakeAlias"
Write-Information "Line # 113 | ModelAlias         : $ModelAlias"
Write-Information "Line # 114 | SystemAlias        : $SystemAlias"
Write-Information "Line # 115 | OSIMAGE            : $OSIMAGE"
Write-Information "Line # 116 | OSIMAGERELEASE     : $OSIMAGERELEASE"
Write-Information "Line # 117 | OSIMAGEARCHITECTURE: $OSIMAGEARCHITECTURE"
#>
Write-Information "Line # 119 | Make: $MakeAlias, Model: $ModelAlias, System: $SystemAlias, OS: $OSIMAGE, Release: $OSIMAGERELEASE, Architecture: $OSIMAGEARCHITECTURE"


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

if ($ModelAlias -match "Virtual Machine" -and $MakeAlias -match "Microsoft") {
    Write-Information "Line # 145 | Detected Hyper-V VM. Skipping Driver Pack creation."
    #For Testing, we're going to change this to a VMWare VM
    $MakeAlias = "HP"
    $ModelAlias = "HP ZBook Studio 16 inch G10 Mobile Workstation PC"
    $SystemAlias = "8B8F"
    Write-Information "Line # 150 | Changed MakeAlias to '$MakeAlias' and ModelAlias to '$ModelAlias' for testing purposes."
}

$SupportedModels = Get-DeployROEMDriverPack -Manufacturer $MakeAlias
$MatchedModel = $SupportedModels | Where-Object { $_ -match $ModelAlias }
if ($MatchedModel.Count -eq 0) {
    Write-Warning "Line # 156 | No exact match found for ModelAlias '$ModelAlias'. Attempting to match with SystemAlias variable..."
    $MatchedModel = $SupportedModels | Where-Object { $_ -match $SystemAlias }
    if ($MatchedModel.Count -eq 0) {
        Write-Error "Line # 159 | No match found for either ModelAlias '$ModelAlias' or SystemAlias '$SystemAlias'. Cannot create Driver Pack."
    }
    else {
        Write-Information "Line # 162 | Match found using SystemAlias: $($MatchedModel -join ', ')"
        # Proceed with creating Driver Pack using $MatchedModel
    }
}

else {
    $MatchedModel = ($MatchedModel | Select-Object -Last 1).Name
    $DriverPacks = Get-DeployROEMDriverPack -Manufacturer $MakeAlias -Model $MatchedModel
    if ($DriverPacks.Count -eq 0) {
        Write-Error "Line # 170 | No Driver Packs found for Make '$MakeAlias' and Model '$MatchedModel'."
    }
    else {
        foreach ($Pack in $DriverPacks) {
            Write-Information "Line # 174 | Found Driver Pack $($Pack.name)"
            # Here you would call the function to create the Driver Pack, e.g.:
            # New-DeployROEMDriverPack -Manufacturer $MakeAlias -Model $MatchedModel -OS $OSIMAGE
        }
    }
    if ($DriverPacks.Count -ge 1) {
        $SpecificDriverPack = $DriverPacks | Where-Object { $_.OS -match $OSIMAGE -and $_.OSReleaseID -match $OSIMAGERELEASE}
        if ($SpecificDriverPack.Count -eq 0) {
            Write-Warning "Line # 182 | No exact match found for OS '$OSIMAGE' and Release '$OSIMAGERELEASE'. Attempting to match with just OS '$OSIMAGE'..."
            $SpecificDriverPack = $DriverPacks | Where-Object { $_.OS -match $OSIMAGE }
            if ($SpecificDriverPack.Count -eq 0) {
                Write-Warning "Line # 185 | No match found for OS '$OSIMAGE'"
                $SpecificDriverPack = $DriverPacks | Select-Object -Last 1
            }
            else {
                Write-Information "Line # 189 | Match found using OS Architecture: $($SpecificDriverPack -join ', ')"
                $SpecificDriverPack = $SpecificDriverPack | Select-Object -Last 1
                # Proceed with creating Driver Pack using $SpecificDriverPack
            }
        }
        else {
            Write-Information "Line # 195 | Exact match found for OS and Release: $($SpecificDriverPack -join ', ')"
            $SpecificDriverPack = $SpecificDriverPack | Select-Object -Last 1
        }
    }
}
if ($SpecificDriverPack) {
    Write-Information "Line # 201 | Creating Driver Pack for $MakeAlias - $MatchedModel with OS $($SpecificDriverPack.OS) Release $($SpecificDriverPack.OSReleaseID)..."
    $SpecificDriverPack | Import-DeployROEMDriverPack
}
Write-Information "Line # 204 | Script completed successfully."