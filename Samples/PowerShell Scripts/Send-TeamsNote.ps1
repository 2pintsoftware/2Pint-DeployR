<# 
This script will grab TS Vars and send them to a Teams channel via a webhook.
https://documentation.2pintsoftware.com/deployr/reference/step-definitions/send-message-to-teams

What it does is grab the VARS, then creates a header based on the TS Name and UUID, then creates a message body with all the other variables and values. 
It then sends this to the Teams channel via the webhook URL.
I clean up some Vars that I don't want to send to Teams (like the progress and token variables) but you can adjust this as needed.

I have the step definition script pasted below for reference, it is not needed, just was nice to know what was happening so I could do manual tests.

HOW TO USE:
Add a "Run PowerShell Step" to your task sequence, paste in the script below at the point you want to send the message to Teams
This will set the TEAMSMESSAGE variable with the message body
Add a "Send message to Teams" step directly after the PowerShell step and set the WebHook Bot URL, and you can set the "Message to send" to %TEAMSMESSAGE%

#>


<#  Send to Teams Step Def Script Here for Reference
Write-Host "SendToTeams"

Import-Module DeployR.Utility

# Send the message
$WebHookBotURL = ${tsenv:WEBHOOKBOTURL}
$Message = Resolve-DeployRVariables -Value ${tsenv:TEAMSMESSAGE}
$parameters = @{ text = $Message }
Write-Host "Sending message: $Message"
Invoke-RestMethod -Uri $WebHookBotURL -Method POST -Body ($parameters | ConvertTo-Json) -ContentType "application/json"
#>




#Get all TS Vars
$Vars = Get-ChildItem -path tsenv: 

#Grab the progress variable to get the TS Name and UUID for the header of the message, then remove it from the Vars list so it doesn't get sent to Teams.
$TSProgressJSON = ($Vars | Where-Object {$_.Name -eq 'DEPLOYRPROGRESS'}).value | ConvertFrom-Json
$TSName = $TSProgressJSON.Name
$TSUUID = $TSProgressJSON.UUID

#Select only the Vars we want to send to Teams, and format them as a string with line breaks for the message body.
$subVars = $Vars | Where-Object { 
    $_.Name -notlike 'DEPLOYRPROGRESS*' -and
    $_.Name -notlike 'DEPLOYRTASKSEQUENCERUN*' -and
    $_.Name -notlike '_SEQUENCESTATE*' -and
    $_.Name -notlike 'DEPLOYRCLIENTPASSCODE*' -and
    $_.Name -notlike 'DEPLOYRTOKEN*' -and
    $_.Name -notlike '_CI_*' -and
    $_.Name -notlike '_CIV_*' -and
    $_.Name -notlike 'SCRIPT*'
}
$stringResult = [string]::Join(' <br> ', $subVars)

#Create the Intro Line with the TS Name and UUID, then combine it with the Vars string to create the full message body. Set this to the TEAMSMESSAGE variable that will be sent to Teams.
$IntroString = "Task Sequence: $TSName running on UUID: $TSUUID <br><br>"
${TSEnv:TEAMSMESSAGE} = $IntroString + $stringResult

#Set the Intro line as a separate variable if you want to use it in the Teams message title or elsewhere.
${TSEnv:TEAMSMESSAGEIntro} = $IntroString