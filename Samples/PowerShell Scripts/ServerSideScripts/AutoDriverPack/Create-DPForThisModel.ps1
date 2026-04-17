<#This script will run server side, but be triggered in a TS

Purpose is to have it automatically generate a Driver Pack for the model of the machine it is running on in the DeployR Server

how you ask?  
The TS will pass back to the script the Make & Model & OS of the system being deployed
Then this script will take that info and trigger the creation of a Driver Pack for that Make & Model & OS in the DeployR Server
This is available in Version 1.1+


#>

param(
    [string]$MakeAlias,
    [string]$ModelAlias,
    [string]$OSIMAGE,
    [string]$OSIMAGERELEASE,
    [string]$OSIMAGEARCHITECTURE
)

Write-Information "Make: $MakeAlias"
Write-Information "Model: $ModelAlias"
Write-Information "OS Image: $OSIMAGE"
Write-Information "OS Image Release: $OSIMAGERELEASE"
Write-Information "OS Image Architecture: $OSIMAGEARCHITECTURE"
