if ($env:SystemDrive -eq "X:"){
    Write-Host "Running in WinPE, this step requires a full Windows environment to run properly."
    exit 0
}
#Pull Vars from TS:
try {
    Import-Module DeployR.Utility
}
catch {}


#region functions

function Write-CMTraceLog {
    [CmdletBinding()]
    Param (
    [Parameter(Mandatory=$false)]
    $Message,
    
    [Parameter(Mandatory=$false)]
    $ErrorMessage,
    
    [Parameter(Mandatory=$false)]
    $Component = "M365",
    
    [Parameter(Mandatory=$false)]
    [int]$Type,
    
    [Parameter(Mandatory=$false)]
    $LogFile = "C:\windows\temp\M365_Install.log"
    )
    <#
    Type: 1 = Normal, 2 = Warning (yellow), 3 = Error (red)
    #>
    $Time = Get-Date -Format "HH:mm:ss.ffffff"
    $Date = Get-Date -Format "MM-dd-yyyy"
    
    $LogFileFolderPath = Split-Path -Path $LogFile -Parent
    if (!(Test-Path -Path $LogFileFolderPath)) {
        New-Item -ItemType Directory -Path $LogFileFolderPath -Force | Out-Null
    }
    
    if ($ErrorMessage -ne $null) {$Type = 3}
    if ($Component -eq $null) {$Component = " "}
    if ($Type -eq $null) {$Type = 1}
    
    $LogMessage = "<![LOG[$Message $ErrorMessage" + "]LOG]!><time=`"$Time`" date=`"$Date`" component=`"$Component`" context=`"`" type=`"$Type`" thread=`"`" file=`"`">"
    $LogMessage | Out-File -Append -Encoding UTF8 -FilePath $LogFile
}

#Used to set Exit Code in way that CM registers
function ExitWithCode
{
    param
    (
    $exitcode
    )
    
    $host.SetShouldExit($exitcode)
    exit
}
#endregion functions



# Get the provided variables
if (Get-Module -name "DeployR.Utility"){
    
    $Project = ${TSEnv:M365Project}
    $Visio = ${TSEnv:M365Visio}
    $Access = ${TSEnv:M365Access}
    $AccessRuntime = ${TSEnv:M365AccessRuntime}
    $IncludePublisher = ${TSEnv:M365Publisher}
    $IncludeOneNote = ${TSEnv:M365OneNote}
    $IncludeSkype = ${TSEnv:M365Skype}
    $IncludeOutlookClassic = ${TSEnv:M365OutlookClassic}
    $IncludeOutlookNew = ${TSEnv:M365OutlookNew}
    $IncludePowerPoint = ${TSEnv:M365PowerPoint}
    #$IncludeBing = ${TSEnv:M365Bing}
    $SharedComputerLicensing = ${TSEnv:M365SharedComputerLicensing}
    $AUTOACTIVATE = ${TSEnv:M365AUTOACTIVATE}
    $PinIconsToTaskbar = ${TSEnv:M365PinIconsToTaskbar}
    $DeviceBasedLicensing = ${TSEnv:M365DeviceBasedLicensing}
    $Channel = ${TSEnv:M365Channel}
    $Language = ${TSEnv:M365Language}
    $SetLanguageDefault = ${TSEnv:M365SetLanguageDefault}
    $CompanyValue = ${TSEnv:M365CompanyValue}
    $OfficeDeployToolKitURL = ${TSEnv:M365OfficeDeployToolKitURL}

}
else{
    $Access = "false"
    $Project = "ProjectStd2021Volume"
    $Visio = "VisioPro2024Volume"
    $AccessRuntime = "false"
    $IncludePublisher = "false"
    $IncludeOneNote = "true"
    $IncludeSkype = "false"
    $IncludeOutlookClassic = "false"
    $IncludeOutlookNew = "true"
    $IncludePowerPoint = "true"
    #$IncludeBing = "true"
    $SharedComputerLicensing = "false"
    $AUTOACTIVATE = "true"
    $PinIconsToTaskbar = "true"
    $DeviceBasedLicensing = "false"
    $Channel = "Current"
    $Language = "MatchOS"
    $SetLanguageDefault = "false"
    $CompanyValue = "2PintLabs"
    $OfficeDeployToolKitURL = "https://download.microsoft.com/download/6c1eeb25-cf8b-41d9-8d0d-cc1dbc032140/officedeploymenttool_19029-20136.exe"
}

$SourceDir = Get-Location
$M365Cache = "C:\windows\Temp\M365_Cache" #Sets Registry Location used for Toast Notification
$ScriptVer = "25.08.28.01"


    




Write-CMTraceLog -Message "=====================================================" -Type 1 -Component "o365script"
Write-CMTraceLog -Message "Starting Script version $ScriptVer..." -Type 1 -Component "o365script"
Write-CMTraceLog -Message "=====================================================" -Type 1 -Component "o365script"

#Report Variables
Write-Host "====================================================="
Write-Host "Starting M365 Install Script Version: $ScriptVer..."
Write-Host "====================================================="
Write-Host ""
Write-Host "Reporting Variables"
Write-Host "Project = $Project"
Write-Host "Visio = $Visio"
Write-Host "Access = $Access"
Write-Host "AccessRuntime = $AccessRuntime"
Write-Host "IncludePublisher = $IncludePublisher"
Write-Host "IncludeOneNote = $IncludeOneNote"
Write-Host "IncludeSkype = $IncludeSkype"
Write-Host "IncludeOutlook = $IncludeOutlook"
Write-Host "IncludePowerPoint = $IncludePowerPoint"
#"IncludeBing" = $IncludeBing
Write-Host "SharedComputerLicensing = $SharedComputerLicensing"
Write-Host "AUTOACTIVATE = $AUTOACTIVATE"
Write-Host "PinIconsToTaskbar = $PinIconsToTaskbar"
Write-Host "DeviceBasedLicensing = $DeviceBasedLicensing"
Write-Host "Channel = $Channel"
Write-Host "Language = $Language"
Write-Host "SetLanguageDefault = $SetLanguageDefault"
Write-Host "CompanyValue = $CompanyValue"
Write-Host "OfficeDeployToolKitURL = $OfficeDeployToolKitURL"


#Download Office Deployment ToolKit & Extract
$tempDownloadPath = $M365Cache
if (!(Test-Path $M365Cache)) {
    New-Item -ItemType Directory -Path $M365Cache -Force | Out-Null
}

Write-Host "Downloading Office Deployment ToolKit from $OfficeDeployToolKitURL to $tempDownloadPath"
Write-CMTraceLog -Message "Downloading Office Deployment ToolKit from $OfficeDeployToolKitURL to $tempDownloadPath" -Type 1 -Component "o365script"
try {
    $destFile = Request-DeployRCustomContent -ContentName "M365" -ContentFriendlyName "Office Deployment ToolKit" -URL $URL -DestinationPath $tempDownloadPath -ErrorAction SilentlyContinue
    $GetItemOutFile = Get-Item $destFile
    $ToolKitFile = $GetItemOutFile.FullName
    
} catch {
    $ToolKitFile = "$tempDownloadPath\officedeploymenttool.exe"
    Invoke-WebRequest -Uri $OfficeDeployToolKitURL -OutFile $ToolKitFile -ErrorAction SilentlyContinue
}
Write-Host "Extracting Office Deployment ToolKit to $M365Cache"
Write-CMTraceLog -Message "Extracting Office Deployment ToolKit to $M365Cache" -Type 1 -Component "o365script"
Start-Process -FilePath $ToolKitFile -ArgumentList "/quiet /extract:$M365Cache" -Wait -NoNewWindow

#Create XML (Configuration.XML) if Install Mode (Not PreCache Mode)

[XML]$XML = @"
<Configuration Host="cm">
    <Info Description="Customized Office 365" />
    <Add OfficeClientEdition="64" Channel="SemiAnnual" OfficeMgmtCOM="TRUE" ForceUpgrade="TRUE">
    <Product ID="O365ProPlusRetail">
    <Language ID="MatchOS" />
    <ExcludeApp ID="Groove" />
    <ExcludeApp ID="OneDrive" />
    </Product>
    </Add>
    <Property Name="SharedComputerLicensing" Value="0" />
    <Property Name="PinIconsToTaskbar" Value="FALSE" />
    <Property Name="SCLCacheOverride" Value="0" />
    <Property Name="AUTOACTIVATE" Value="1" />
    <Property Name="FORCEAPPSHUTDOWN" Value="TRUE" />
    <Property Name="DeviceBasedLicensing" Value="0" />
    <RemoveMSI />
    <AppSettings>
    <Setup Name="Company" Value="Your Company Here" />
    <User Key="software\microsoft\office\16.0\excel\options" Name="defaultformat" Value="51" Type="REG_DWORD" App="excel16" Id="L_SaveExcelfilesas" />
    <User Key="software\microsoft\office\16.0\powerpoint\options" Name="defaultformat" Value="27" Type="REG_DWORD" App="ppt16" Id="L_SavePowerPointfilesas" />
    <User Key="software\microsoft\office\16.0\word\options" Name="defaultformat" Value="" Type="REG_SZ" App="word16" Id="L_SaveWordfilesas" />
    </AppSettings>
    <Display Level="Basic" AcceptEULA="TRUE" />
</Configuration>
"@




#Change Channel
$xml.Configuration.Add.SetAttribute("Channel","$Channel")
Write-CMTraceLog -Message "Setting Office Channel to $Channel" -Type 1 -Component "o365script"

$XML.Configuration.AppSettings.Setup.SetAttribute("Value", "$CompanyValue")
Write-CMTraceLog -Message "Setting Setup Company name to $CompanyValue" -Type 1 -Component "o365script"

if ($SharedComputerLicensing -eq "true")
{
    #Change SharedComputerLicensing to 1
    ($xml.Configuration.Property | Where-Object {$_.Name -eq "SharedComputerLicensing"}).SetAttribute("Value","1")
}

if ($AUTOACTIVATE -eq "true")
{
    #Change AUTOACTIVATE to 1
    ($xml.Configuration.Property | Where-Object {$_.Name -eq "AUTOACTIVATE"}).SetAttribute("Value","1")
}

if ($PinIconsToTaskbar -eq "true")
{
    #Change PinIconsToTaskbar to TRUE
    ($xml.Configuration.Property | Where-Object {$_.Name -eq "PinIconsToTaskbar"}).SetAttribute("Value","TRUE")
}

if ($DeviceBasedLicensing -eq "true")
{
    #Change DeviceBasedLicensing to 1
    ($xml.Configuration.Property | Where-Object {$_.Name -eq "DeviceBasedLicensing"}).SetAttribute("Value","1")
}


if ($Project -ne "none")
{
    if ($Project -eq 'ProjectPro2024Volume'){
        $PIDKEY = 'FQQ23-N4YCY-73HQ3-FM9WC-76HF4'
    }
    elseif ($Project -eq 'ProjectStd2024Volume') {
        $PIDKEY = 'PD3TT-NTHQQ-VC7CY-MFXK3-G87F8'
    }
    elseif ($Project -eq 'ProjectPro2021Volume') {
        $PIDKEY = 'FTNWT-C6WBT-8HMGF-K9PRX-QV9H8'
    }
    elseif ($Project -eq 'ProjectStd2021Volume') {
        $PIDKEY = 'J2JDC-NJCYY-9RGQ4-YXWMH-T3D4T'
    }
    $newProductElement = $xml.CreateElement("Product")
    $newProductApp = $xml.Configuration.Add.AppendChild($newProductElement)
    $newProductApp.SetAttribute("ID","$Project")
    $newProductApp.SetAttribute("PIDKEY","$PIDKEY")
    $newXmlNameElement = $newProductElement.AppendChild($xml.CreateElement("Language"))
    $newXmlNameElement.SetAttribute("ID","en-us")
    $newXmlNameElement = $newProductElement.AppendChild($xml.CreateElement("ExcludeApp"))
    $newXmlNameElement.SetAttribute("ID","Groove")
    $newXmlNameElement = $newProductElement.AppendChild($xml.CreateElement("ExcludeApp"))
    $newXmlNameElement.SetAttribute("ID","OneDrive")    
    Write-CMTraceLog -Message "Adding $Project to Install XML" -Type 1 -Component "o365script"
}  


if ($Visio -ne "none")
{
    if ($Visio -eq 'VisioPro2024Volume'){
        $PIDKEY = 'B7TN8-FJ8V3-7QYCP-HQPMV-YY89G'
    }
    elseif ($Visio -eq 'VisioStd2024Volume') {
        $PIDKEY = 'JMMVY-XFNQC-KK4HK-9H7R3-WQQTV'
    }
    elseif ($Visio -eq 'VisioPro2021Volume') {
        $PIDKEY = 'KNH8D-FGHT4-T8RK3-CTDYJ-K2HT4'
    }
    elseif ($Visio -eq 'VisioStd2021Volume') {
        $PIDKEY = 'MJVNY-BYWPY-CWV6J-2RKRT-4M8QG'
    }

    $newProductElement = $xml.CreateElement("Product")
    $newProductApp = $xml.Configuration.Add.AppendChild($newProductElement)
    $newProductApp.SetAttribute("ID","$Visio")
    $newProductApp.SetAttribute("PIDKEY","$PIDKEY")
    $newXmlNameElement = $newProductElement.AppendChild($xml.CreateElement("Language"))
    $newXmlNameElement.SetAttribute("ID","en-us")
    $newXmlNameElement = $newProductElement.AppendChild($xml.CreateElement("ExcludeApp"))
    $newXmlNameElement.SetAttribute("ID","Groove")
    $newXmlNameElement = $newProductElement.AppendChild($xml.CreateElement("ExcludeApp"))
    $newXmlNameElement.SetAttribute("ID","OneDrive")     
    Write-CMTraceLog -Message "Adding Visio Pro to Install XML" -Type 1 -Component "o365script"
}



if ($AccessRuntime -eq "true")
{
    $newProductElement = $xml.CreateElement("Product")
    $newProductApp = $xml.Configuration.Add.AppendChild($newProductElement)
    $newProductApp.SetAttribute("ID","AccessRuntimeRetail")
    $newXmlNameElement = $newProductElement.AppendChild($xml.CreateElement("Language"))
    $newXmlNameElement.SetAttribute("ID","en-us")
    $newXmlNameElement = $newProductElement.AppendChild($xml.CreateElement("ExcludeApp"))
    $newXmlNameElement.SetAttribute("ID","Groove")
    $newXmlNameElement = $newProductElement.AppendChild($xml.CreateElement("ExcludeApp"))
    $newXmlNameElement.SetAttribute("ID","OneDrive")    
    Write-CMTraceLog -Message "Adding Access Runtime to Install XML" -Type 1 -Component "o365script"
}  

#Don't Remove Access from XML if Previously Installed or Called from Param
if ($Access -eq "false")
{
    $newProductAttributes = $xml.Configuration.Add.Product
    foreach ($newproduct in $newProductAttributes)
    {
        $newXmlNameElement = $newproduct.AppendChild($xml.CreateElement("ExcludeApp"))
        $newXmlNameElement.SetAttribute("ID","Access")
    }
    Write-CMTraceLog -Message "Removing Access from Install XML" -Type 1 -Component "o365script"
}
else{Write-CMTraceLog -Message "Adding Access To Install XML" -Type 1 -Component "o365script"}

#If Include OneNote
if ($IncludeOneNote -eq "false")
{
    $newProductAttributes = $xml.Configuration.Add.Product
    foreach ($newproduct in $newProductAttributes)
    {
        $newXmlNameElement = $newproduct.AppendChild($xml.CreateElement("ExcludeApp"))
        $newXmlNameElement.SetAttribute("ID","OneNote")
    }
    Write-CMTraceLog -Message "Removing OneNote from Install XML" -Type 1 -Component "o365script"
}

#If Include Skype
if ($IncludeSkype -eq "false")
{
    $newProductAttributes = $xml.Configuration.Add.Product
    foreach ($newproduct in $newProductAttributes)
    {
        $newXmlNameElement = $newproduct.AppendChild($xml.CreateElement("ExcludeApp"))
        $newXmlNameElement.SetAttribute("ID","lync")
    }
    Write-CMTraceLog -Message "Removing Skype from Install XML" -Type 1 -Component "o365script"
}
#If Include Publisher
if ($IncludePublisher -eq "false")
{
    $newProductAttributes = $xml.Configuration.Add.Product
    foreach ($newproduct in $newProductAttributes)
    {
        $newXmlNameElement = $newproduct.AppendChild($xml.CreateElement("ExcludeApp"))
        $newXmlNameElement.SetAttribute("ID","Publisher")
    }
    Write-CMTraceLog -Message "Removing Publisher from Install XML" -Type 1 -Component "o365script"
}

#If Include Outlook Classic
if ($IncludeOutlookClassic -eq "false")
{
    $newProductAttributes = $xml.Configuration.Add.Product
    foreach ($newproduct in $newProductAttributes)
    {
        $newXmlNameElement = $newproduct.AppendChild($xml.CreateElement("ExcludeApp"))
        $newXmlNameElement.SetAttribute("ID","Outlook")
    }
    Write-CMTraceLog -Message "Removing Outlook from Install XML" -Type 1 -Component "o365script"
}
#If Include Outlook New
if ($IncludeOutlookNew -eq "false")
{
    $newProductAttributes = $xml.Configuration.Add.Product
    foreach ($newproduct in $newProductAttributes)
    {
        $newXmlNameElement = $newproduct.AppendChild($xml.CreateElement("ExcludeApp"))
        $newXmlNameElement.SetAttribute("ID","OutlookForWindows")
    }
    Write-CMTraceLog -Message "Removing Outlook from Install XML" -Type 1 -Component "o365script"
}
#If Include PowerPoint
if ($IncludePowerPoint -eq "false")
{
    $newProductAttributes = $xml.Configuration.Add.Product
    foreach ($newproduct in $newProductAttributes)
    {
        $newXmlNameElement = $newproduct.AppendChild($xml.CreateElement("ExcludeApp"))
        $newXmlNameElement.SetAttribute("ID","PowerPoint")
    }
    Write-CMTraceLog -Message "Removing PowerPoint from Install XML" -Type 1 -Component "o365script"
}
<#If Exclude Bing
if ($ExcludeBing -eq "true")
{
    $newProductAttributes = $xml.Configuration.Add.Product
    foreach ($newproduct in $newProductAttributes)
    {
        $newXmlNameElement = $newproduct.AppendChild($xml.CreateElement("ExcludeApp"))
        $newXmlNameElement.SetAttribute("ID","Bing")
    }
    Write-CMTraceLog -Message "Removing BBing from Install XML" -Type 1 -Component "o365script"
}
#>

<#add additional languages to download
In the install command, if you leave out -Language, it will default to en-us
If you pick a different language like fr-fr, it will set that as default, but still include en-us
#>
if ($Language)
{
    Write-CMTraceLog -Message "Language Param detected, added $Language to XML" -Type 1 -Component "o365script"
    if ($SetLanguageDefault)#Set Default language to the Language Specified
    {
        Write-CMTraceLog -Message " LanguageDefault Param detected, set $Language to Default" -Type 1 -Component "o365script"
        $CurrentProductAttributeLang = $xml.Configuration.Add.Product
        foreach ($currentproduct in $CurrentProductAttributeLang)
        {
            $newXmlNameElement = $currentproduct.Language
            $newXmlNameElement.SetAttribute("ID","$Language")
        }
        #Include English in the install if you picked a different language as your default
        if (!($Language -eq "en-us"))
        {
            Write-CMTraceLog -Message " LanguageDefault Param detected, appending en-us to XML" -Type 1 -Component "o365script"
            $newProductAttributeLang = $xml.Configuration.Add.Product
            foreach ($newproduct in $newProductAttributeLang)
            {
                $newXmlNameElement = $newproduct.AppendChild($xml.CreateElement("Language"))
                $newXmlNameElement.SetAttribute("ID","en-us")
            }
        }
    }
    else #Append Language, leaving English as Default
    {
        Write-CMTraceLog -Message " LanguageDefault Param NOT detected, appending $Language to XML" -Type 1 -Component "o365script"
        $newProductAttributeLang = $xml.Configuration.Add.Product
        foreach ($newproduct in $newProductAttributeLang)
        {
            $newXmlNameElement = $newproduct.AppendChild($xml.CreateElement("Language"))
            $newXmlNameElement.SetAttribute("ID","$Language")
        }
    }
}



Write-CMTraceLog -Message "Creating XML file: $("$M365Cache\configuration.xml")" -Type 1 -Component "o365script"
$xml.Save("$M365Cache\configuration.xml")


Write-CMTraceLog -Message "Starting Office 365 Install" -Type 1 -Component "o365script"
Write-Host "Starting Office 365 Install, this may take a while..."
$InstallOffice = Start-Process -FilePath $M365Cache\setup.exe -ArgumentList "/configure $M365Cache\configuration.xml" -PassThru -WindowStyle Hidden
$OfficeInstallCode = $InstallOffice.ExitCode

Start-Sleep -Seconds 60
#Look for the sub process called setup that Office triggers, and monitor that until it finishes
$setupProcess = Get-Process -Name "setup" -ErrorAction SilentlyContinue
if ($setupProcess) {
    Write-Host "Monitoring Office setup process..."
    $setupProcess | Wait-Process
}

Write-Host "Finished Office 365 Install with code: $OfficeInstallCode"
Write-CMTraceLog -Message "Finished Office Install with code: $OfficeInstallCode" -Type 1 -Component "o365script"
Start-Sleep -Seconds 5
Write-CMTraceLog -Message "Stopping OfficeC2RClient process" -Type 1 -Component "o365script"
Write-Host "Stopping OfficeC2RClient process"
Get-Process -name OfficeC2RClient | Stop-Process -Force



