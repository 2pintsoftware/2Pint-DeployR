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
$OSIMAGE               = $TSVars['OSIMAGE']
$OSIMAGERELEASE        = $TSVars['OSIMAGERELEASE']
$OSIMAGEARCHITECTURE   = $TSVars['OSIMAGEARCHITECTURE']

# Optional: also grab MODEL if you need it
$Model                 = $TSVars['MODEL']

# Logging (visible in DeployR Logger)
Write-Information "MakeAlias          : $MakeAlias"
Write-Information "ModelAlias         : $ModelAlias"
Write-Information "MODEL (TS var)     : $Model"
Write-Information "OSIMAGE            : $OSIMAGE"
Write-Information "OSIMAGERELEASE     : $OSIMAGERELEASE"
Write-Information "OSIMAGEARCHITECTURE: $OSIMAGEARCHITECTURE"

# ←←← PUT YOUR ACTUAL DRIVER PACK CREATION CODE HERE ↓↓↓
# Example placeholder:
# Write-Information "Creating Driver Pack for $MakeAlias - $ModelAlias ($OSIMAGE)..."
# ... your logic ...

Write-Information "Script completed successfully."