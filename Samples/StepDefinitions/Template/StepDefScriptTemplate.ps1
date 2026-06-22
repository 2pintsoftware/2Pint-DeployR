<#
This script is just a template for how to use the provided variables in a DeployR Task Sequence, gather host values, and make decisions based on those values. 
It also includes examples of how to set new variables that can be used in later steps of the Task Sequence. 
This script is meant to be modified and expanded upon based on the specific requirements of your Task Sequence.

I'd recommend looking at the real samples for additional inspiration on how to use the provided variables and gather host values to make decisions in your Task Sequence.


#>


#Pull Vars from TS:
try {
    Import-Module DeployR.Utility -ErrorAction SilentlyContinue
}
catch {}



# Get the provided variables from the DeployR Task Sequence Environment Variables, if the module is available. If not, use default values for testing purposes.
if (Get-Module -name "DeployR.Utility"){
    $VarExample1 = ${TSEnv:VarExample1}
    $VarExample2 = ${TSEnv:VarExample2}
    $VarExample3 = ${TSEnv:VarExample3}
    $VarExample4 = ${TSEnv:VarExample4}
    $VarExample5 = ${TSEnv:VarExample5}
    $VarExample6 = ${TSEnv:VarExample6}

}
#setting defaults for testing the script outside of a Task Sequence environment. These values can be modified for testing different scenarios.
else{
    $VarExample1 = "4"
    $VarExample2 = "20"
    $VarExample3 = "Client"
    $VarExample4 = "19045"
    $VarExample5 = "true"
    $VarExample6 = "true"
}

#Check if running in WinPE, as some checks may not apply in that environment. This is just an example of how to handle environment-specific logic in your script.
if ($env:SystemDrive -eq "X:"){
    $IsWinPE = $true
    Write-Host "Running in WinPE environment, Several Checks do not apply"
}
else {$IsWinPE = $false}


#Report Step Variables
Write-Host "================================================================"
Write-Host "Reporting Step Variables"

#Report these variables, but note that some of them may not apply in WinPE, so we will conditionally report them based on the environment. This is just an example of how to handle variables that may not be applicable in certain environments.
if ($IsWinPE){
    Write-Host "VarExample1         | Does not apply in WinPE" = $VarExample1
    Write-Host "VarExample2         | Does not apply in WinPE" = $VarExample2
    Write-Host "VarExample3         | Does not apply in WinPE" = $VarExample3
}
else{
    Write-Host "VarExample1 = $VarExample1"
    Write-Host "VarExample2 = $VarExample2"
    Write-Host "VarExample3 = $VarExample3"

}
Write-Host "VarExample4 = $VarExample4"
Write-Host "VarExample5 = $VarExample5"
Write-Host "VarExample6 = $VarExample6"
Write-Host "================================================================"

#Sample of gathering Host Values that aren't in TS Vars, such as Free Storage Space, Memory, TPM 2.0, etc. These can be used for comparisons later in the script to make decisions based on the environment the script is running in.
write-host "Gathering System Information"
#Get Host Values That aren't in TS Vars
#Free Space in GB
$HostValueFreeStorage = [math]::Round((Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'" | Select-Object -ExpandProperty FreeSpace) / 1GB, 2)
#Current OS Build
$HostValueCurrentBuild = (Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty Version).split(".") | Select-Object -Last 1
#Host Value Memory
$HostValueMemory = [math]::Round((Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty TotalPhysicalMemory) / 1GB, 2)

#TPM 2
$TPMRAW = (Get-CimInstance -Namespace "ROOT\cimv2\Security\MicrosoftTpm" -ClassName Win32_TPM).SpecVersion
if ($null -ne $TPMRAW) {
    if ($TPMRAW -like "2.*") {
        $HostValueTPM2 = $true
    }
    else {
        $HostValueTPM2 = $false
    }
}
else {
    $HostValueTPM2 = $false
}




# Start the Compares
Write-host "Starting Requirement Checks"
$Compliant = $true


#Check if $VarExample1 is set
if ($null -ne $VarExample1 -and $VarExample1 -ne ""){
    #Do something with $VarExample1, such as compare it to a Host Value or just report that it's set.
} 

#Check if $VarExample2 is set
if ($null -ne $VarExample2 -and $VarExample2 -ne ""){
    #Pretending we updated Var2, and based on that we're going to set a new TS Variable to be used in later steps of the Task Sequence. This is just an example of how you can use the provided variables to make decisions and set new variables for later use in the Task Sequence.
    ${TSEnv:VarExample2Updated} = $VarExample2 + 10
} 

#Sample of starting a process passing a variable
if ($null -ne $VarExample3 -and $VarExample3 -ne ""){
    $Setup = start-process -FilePath "Setup.exe" -ArgumentList "/Mode:$VarExample3" -Wait -passThru
    if ($Setup.ExitCode -ne 0){
        Write-Host "Setup.exe did not complete successfully, failing requirement" -ForegroundColor Red
        $Compliant = $false
    }
}

