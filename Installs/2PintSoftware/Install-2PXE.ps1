<#
.SYNOPSIS
Installs 2Pint 2PXE and imports the 2PXE root certificate.

.DESCRIPTION
This script locates a 2PXE MSI in the script directory, builds/install parameters,
installs the 2PXE service silently, and imports the 2PXE CA certificate into the
Local Machine Trusted Root Certification Authorities store.
Can be used in DeployR task sequences or run standalone.

If the DeployR.Utility module is available, task sequence environment variables are
used for FQDN/input values; otherwise, fallback test values are used.

.NOTES
Author          : Phil Wilcock, Mike Terrill
Maintainer      : 2Pint Software
Repository      : 2Pint-DeployR
Script          : Install-2PXE.ps1
Requires        : PowerShell 5.1+ (Windows), Administrative privileges
Last Updated    : 2026-03-03

.EXAMPLE
.\Install-2PXE.ps1
Runs the script in standalone mode and installs using the first matching *2PXE*.msi
in the same folder.

.EXAMPLE
Run as part of a task sequence where DeployR.Utility is available.
Uses TSEnv values for FormFQDN and FormInstall2PXE.


NOTE, FQDN is super important to ensure certificates work properly, so if not running in DeployR or if the domain suffix cannot be determined, the script will prompt for a domain name to use for the FQDN.
ASSUME you've downloaded the DeployR Suite, extracted the 2Pint Software zips to $env:USERPROFILE\Downloads\DeployRSuite\Extracted, and placed the Install-2PXE.ps1 script in the same folder as the 2PXE MSI file before running this script.
#>

$sourceFolder = "$env:USERPROFILE\Downloads\DeployRSuite\Extracted"

#region functions
Function Get-ActiveNetworkDomainSuffix {
    [CmdletBinding()]
    param()

    try {
        # Prefer an interface that has an IPv4 address and a default gateway (likely the active network)
        $ipConfig = Get-NetIPConfiguration -ErrorAction SilentlyContinue | Where-Object {
            ($_.IPv4Address -ne $null) -and ($_.IPv4DefaultGateway -ne $null)
        } | Select-Object -First 1

        if ($ipConfig -and $ipConfig.DnsSuffix -and $ipConfig.DnsSuffix.Trim() -ne '') {
            return $ipConfig.DnsSuffix
        }

        # Fall back to connection-specific suffix from Get-DnsClient
        $suffix = Get-DnsClient -ErrorAction SilentlyContinue | Where-Object { $_.ConnectionSpecificSuffix -and $_.ConnectionSpecificSuffix.Trim() -ne '' } | Select-Object -ExpandProperty ConnectionSpecificSuffix -First 1
        if ($suffix) { return $suffix }

        # Last-resort: try WMI/CIM property
        $wmiSuffix = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled = 1" -ErrorAction SilentlyContinue | Where-Object { $_.DNSSuffix -and $_.DNSSuffix.Trim() -ne '' } | Select-Object -ExpandProperty DNSSuffix -First 1
        return $wmiSuffix
    }
    catch {
        return $null
    }
}

Function Install-2PXE {
    [CmdletBinding()]
    param (
    [string]$domain,
    [string]$fqdn,
    #This one is required - path to the 2PXE MSI file
    [Parameter(Mandatory=$true)]
    [string]$msifile
    )
    <#
    .Synopsis
    Install the 2PXE service and sets all the optional parameters
    
    .Description
    Use this to automate the install.
    
    .Notes
    Author          : Phil Wilcock <senior@2PintSoftware.com>
    Last Updated By : Mike Terrill
    Web             : https://2pintsoftware.com
    Date            : 20/07/2025
    Version         : 1.1
    
    IMPORTANT Requires PS -Version 3.0
    
    This script must be run from the same folder as the  2PXE Installer .MSI
    Tested with version 3.7
    
    Example: Run from the Powershell console - .\install_2pxe.ps1
    
    This script contains ALL config parameters. The Mandatory ones are enabled, and all others are commented out, 
    so simply choose the ones that you want to configure and uncomment them + insert the correct config parameter.
    NOTE: Parameters in "quotes" need to be escaped - don't delete the escape ```` chars in there!
    
    Problems? Check the Full Documentation for descriptions of the install paramters etc.
    Still stuck? - Email support@2pintsoftware.com      
    
    #>
    
    # Set path to MSI file
    #$msifile = "$PSScriptRoot\2Pint Software 2PXE Service (x64).msi"
    if (-not $msifile) {
    Write-Error "Please provide the path to the StifleR Dashboard MSI file."
    exit 1
}
if (!(Test-Path $msifile)) {
    Write-Error "MSI file not found at $msifile. Please provide the correct path to the StifleR Dashboard MSI."
    exit 1
}

    # This will use the connection specific suffix for the fqdn - useful when system is not domain joined
    if (!$domain) {
        $domain = Get-ActiveNetworkDomainSuffix
    }
    if ($($domain.Trim()) -eq ""){
        Write-Host "No domain suffix found. Please provide a domain name."
        #prompt user for domain name
        $domain = Read-Host "Enter the domain name to use for FQDN (e.g., example.com)"
    }
    Write-Host "Using Domain: $domain"
    if (!$fqdn) {
        $fqdn = "$($env:COMPUTERNAME.Trim()).$($domain.Trim())"
    }
    Write-Host "Using FQDN: $fqdn"
    $iPXEWSURL = "https://$($fqdn):8051"
    # Grabs the IPv4 address - used for teh BINDTOIP property
    $IPv4 = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled = 1" | % { $_.IPAddress | ? { -not $_.Contains(":") } }
    
    $arguments = @(
    #Mandatory msiexec Arguments
    
    "/i"
    
    "`"$msiFile`""
    
    #Mandatory 2Pint Arguments
    
    "INSTALLTYPE=`"1`""                  # <- 1 is PowerShell integration (NO CONFIGMGR), 2 is with MS ConfigMgr integration.
    "SERVICE_USERNAME=`"LocalSystem`""   # or "domain\username" if you want to use a domain account
    # "SERVICE_PASSWORD=`"Password`""        # (Can be skipped if SERVICE_USERNAME is LocalSystem)
    "BINDTOIP=`"$IPv4`""                 # Enter the server NIC IP address to which to bind the service
    
    #Non Mandatory 2Pint Arguments - Uncomment+change the settings that you need - otherwise the default will be used.
    
    ### MS CONFIGMGR SQL SETTINGS ##### 
    
    #"CONFIGMGRSQL=`"1`"" #  1 to enable a SQL connection to the  ConfigMgr DB, 0 to use HTTP via the Management Point (no menu)
    
    ### If CONFIGMGRSQL is set to 1 the following paramemeters MUST be set###
    
    # "RUNTIME_DATABASE_LOGON_TYPE=`"WinAuthCurrentUser`""     # "SqlAuth" if using SQL Accounts. "WinAuthCurrentUser" uses Integrated Security
    # "ODBC_SERVER=`"server.domain.local`""                   # FQDN of the ConfigMgr Database Server
    # "RUNTIME_DATABASE_NAME=`"CONFIGMGR_CEN`""               # Database Name, typically CONFIGMGR_<SITECODE>
    
    #####If CREATE_DATABASE_LOGON_TYPE is set to "SqlAuth" the follow parameters MUST be set
    
    # "CREATE_DATABASE_USERNAME=`"myusername`""              #<SQL Auth Username>
    # "CREATE_DATABASE_PASSWORD=`"mypassword`""              #<SQL Auth password>
    
    #Other Non-Mandatory 2Pint Settings
    
    # "REMOTEINSTALL_PATH=`"C:\myremoteinstallpath`""          # Set an alternate remoteinstall path - 
    # "DEBUGLOG_PATH=`"C:\MyLogfiles\2PXE.log`""               # Path to the logfile 
    # "DEBUGLOG=`"1`""                                         # 1 to enable and 0 to disable verbose logging
    # "RUN_ON_DHCP_PORT=`"1`""                                 # By default, 2PXE answers on both the DHCP (67) port and PXE (4011) port
    # "RUN_ON_PXE_PORT=`"1`""                                  # You can control this by setting the values to "0" for off or "1" for on
    # "RUN_TFTP_SERVER=`"1`""                                  # 2PXE has a built-in TFTP server 1 for ON 0 for OFF
    # "RUN_HTTP_SERVER=`"1`""                                  # 2PXE WebService for iPXE integration 1 for ON 0 for OFF
    "EMBEDDEDSDI=`"0`""                                      # Use an embedded boot.sdi image. See full documentation for more info
    "EXTERNALFQDNOVERRIDE=`"$fqdn`""                       # Use this FQDN for iPXE Anywhere Web Service calls instead of the local system FQDN
    # "TFTPROOTPATH=`"C:\MyTFTPRoot`""
    # "F12TIMEOUT=`"10000`""                                   # F12 prompt timout for iPXE loaders for non mandatory deployements in milliseconds.
    # "IPXELOADERS=`"1`""                                      # Use iPXE Boot Loaders 1 to enable and 0 to disable. If 0 2PXE will use Windows boot loaders
    # "UNKNOWNSUPPORT=`"1`""                                   # 1 for enable (default) 0 to disable - enables Unknown Machine support in ConfigMgr
    # "PORTNUMBER=`"8050`""                                    # 2PXE Http Service Port -  8050 by default
    # "POWERSHELLSCRIPTALLOWBOOTH_PATH=`"c:\myscripts`""       # Set only if using custom path location for .ps1 scripts
    # "POWERSHELLSCRIPTIMAGES_PATH=`"c:\myscripts`""           # Set only if using custom path location for .ps1 scripts
    # "INSTALLFOLDER=`"C:\MyInstallPath`""                     # Default is C:\Program Files\2pint Software 
    # "ENABLESCCMMENUCOUNTDOWN=`"10000`""                      # Countdown for menu timeout if nothing is selcted (in Millisecs)
    # "ENABLESCCMMANDATORYCOUNTDOWN=`"30000`""                 # Countdown for Mandatory deployments - the deployment will be executed  after this expires (in Millisecs)
    # "SCCMREPORTSTATE=`"1`""                                  # Instructs 2PXE to send SCCM state messages for mandatory deployments. 1 to send, 0 to not send.
    # "WIMBOOTPARAMS=`"gui`""                                  # command line for wimboot, possible paramteres are: gui, pause, pause=quiet, rawbcd, index=x For details see: http://ipxe.org/appnote/wimboot_architecture
    "ENABLEIPXEANYWHEREWEBSERVICE=`"573`""                   # Specifies to use iPXE Anywhere Web Service. 0 to disable and various BIT values for various Reporting options 
    "IPXEANYWHEREWEBSERVICEURI=`"$iPXEWSURL`""               # "http://url:Port" Specifies the address and Port for the iPXE Anywhere Web Service 
    # "NETWORKACCESS_USERNAME="[%USERDOMAIN]\[%USERNAME]"      # User name to access IIS paths 
    # "NETWORKACCESS_PASSWORD=“A123456!"                       # Password for above account
    # "FWTFTP=`"1`""                                           # Allow the installer to create the Port 69 UDP Firewall exception
    # "FWDHCP=`"1`""                                           # Allow the installer to create the Port 67 UDP Firewall exception
    # "FWPROXYDHCP=`"1`""                                      # Allow the installer to create the Port 4011 UDP Firewall exception
    # "FWHTTP=`"1`""                                           # Allow the installer to create the Port 8050 TCP Firewall exception
    # "USEHYPERTHREAD=`"1`""                                   # Enabel Hyperthread
    
    #Other MSIEXEC params
    "/qn" #Quiet - with basic interface - for NO interface use /qn instead
    
    "/norestart"
    
    "/l*v $env:TEMP\2PXEInstall.log"    #Optional logging for the install
    
    )
    
    write-host "Using the following install commands: $arguments" #uncomment this line to see the command line
    
    #Install the 2PXE Service
    start-process "msiexec.exe" -arg $arguments -Wait
}
Function Create-FQDN2PXECert {
    param(
    [string]$domain = $null,
    [string]$fqdn = $null
    )
    
    <#
.SYNOPSIS
    PowerShell script to reset certificates and a create a FQDN self-signed certificate
.DESCRIPTION
    This script will check the 2PXE self-signed certificates for the FQDN name of the system and will delete them
    It will then stop the 2PXE service, remove the 2PXE self-signed certificate files from ProgramData, edit the 2PXE config file,
    and then start the 2PXE service to generate a new FQDN self-signed certificate
    It verifies the import, and handles common errors.
.NOTES
    Author: Mike Terrill/2Pint Software
    Date: July 20, 2025
    Version: 25.07.20
    Requires: Administrative privileges, 64-bit Windows
    #>
    
    # Specify the new ExternalFQDNOverride value (e.g., dynamically constructed or static)
    # Example: Construct FQDN dynamically using computer name and domain suffix - useful when system is not domain joined

    if ($fqdn) {
        Write-Host "Using FQDN : $fqdn"
        $domain = ($fqdn.Split(".") | Select-Object -Skip 1) -Join "."   
    } else {
        Write-Host "No FQDN found"
    }
    
    
    if (!$domain) {
        $domain = [string](Get-DnsClient | Select-Object -ExpandProperty ConnectionSpecificSuffix)
    }
    if ($($domain.Trim()) -eq ""){
        Write-Host "No domain suffix found. Please provide a domain name."
        if (-not $domain) {
            Write-Host "Domain name could not be determined from 2PXE config. Please provide a domain name."
            $domain = Read-Host "Enter the domain name to use for FQDN (e.g., example.com)"
        }
    }
    Write-Host "Using Domain: $domain"
    if (!$fqdn) {
        $fqdn = "$($env:COMPUTERNAME.Trim()).$($domain.Trim())"
    }
    Write-Host "Using FQDN: $fqdn"
    
    $newExternalFQDN = $fqdn  # Or set a static value, e.g., "2PINT.corp.viamonstra.com"
    $match = $false
    $delete = $true
    
    # Ensure the script runs with elevated privileges
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "This script requires administrative privileges. Please run PowerShell as Administrator."
        exit 1
    }
    
    try {
        # Open the Local Machine's Personal certificate store
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
        [System.Security.Cryptography.X509Certificates.StoreName]::My,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
        )
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
        
        # Find certificates where the issuer contains "2PintSoftware.com"
        $certificates = $store.Certificates | Where-Object { $_.Issuer -like "*2PintSoftware.com*" }
        
        if (-not $certificates) {
            Write-Host "No certificates found issued by 2PintSoftware.com in the Local Machine Personal store."
            $store.Close()
            exit 0
        }
        
        # Iterate through matching certificates
        foreach ($cert in $certificates) {
            Write-Host "---------------------------------------------"
            Write-Host "Certificate Found:"
            Write-Host "Subject: $($cert.Subject)"
            Write-Host "Issuer: $($cert.Issuer)"
            Write-Host "Thumbprint: $($cert.Thumbprint)"
            Write-Host "Valid From: $($cert.NotBefore)"
            Write-Host "Valid Until: $($cert.NotAfter)"
            
            # Check for Subject Alternative Name extension
            $sanExtension = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" }
            
            if ($sanExtension) {
                Write-Host "Subject Alternative Names (SANs):"
                # Parse the SAN extension
                $sanRawData = $sanExtension.Format($true)
                # Split the SAN data into lines and look for DNS names
                $sanEntries = $sanRawData -split "`n" | Where-Object { $_ -match "DNS Name=" }
                
                if ($sanEntries) {
                    foreach ($entry in $sanEntries) {
                        # Extract the FQDN from the DNS Name entry
                        $SANfqdn = $entry -replace "DNS Name=", "" -replace "\s", ""
                        Write-Host "  - FQDN: $SANfqdn"
                        if ($SANfqdn -eq $fqdn) {$match = $true}
                    }
                } else {
                    Write-Host "  No DNS Names found in SAN."
                }
            } else {
                Write-Host "No Subject Alternative Name extension found."
            }
            Write-Host "---------------------------------------------"
        }
        
        # Close the store
        $store.Close()
    }
    catch {
        Write-Error "An error occurred: $_"
        if ($store) { $store.Close() }
        exit 1
    }
    
    Write-Host "SAN FQDN equals system FQDN: $match"
    
    if ($match -eq $false) {
        
        try {
            # Open the Local Machine's Personal certificate store
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
            [System.Security.Cryptography.X509Certificates.StoreName]::My,
            [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
            )
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            
            # Find certificates where the issuer contains "2PintSoftware.com"
            $certificates = $store.Certificates | Where-Object { $_.Issuer -like "*2PintSoftware.com*" }
            
            if (-not $certificates) {
                Write-Host "No certificates found issued by 2PintSoftware.com in the Local Machine Personal store."
                $store.Close()
                exit 0
            }
            
            # Iterate through matching certificates
            $deletedCount = 0
            foreach ($cert in $certificates) {
                Write-Host "---------------------------------------------"
                Write-Host "Certificate Found:"
                Write-Host "Subject: $($cert.Subject)"
                Write-Host "Issuer: $($cert.Issuer)"
                Write-Host "Thumbprint: $($cert.Thumbprint)"
                Write-Host "Valid From: $($cert.NotBefore)"
                Write-Host "Valid Until: $($cert.NotAfter)"
                
                # Delete certificate if $delete is set to $true
                if ($delete -eq $true) {
                    try {
                        # Remove the certificate from the store
                        $store.Remove($cert)
                        Write-Host "Certificate with thumbprint $($cert.Thumbprint) deleted successfully."
                        $deletedCount++
                    }
                    catch {
                        Write-Error "Failed to delete certificate with thumbprint $($cert.Thumbprint): $_"
                    }
                } else {
                    Write-Host "Delete is set to false."
                    Write-Host "Skipping deletion of certificate with thumbprint $($cert.Thumbprint)."
                }
                Write-Host "---------------------------------------------"
            }
            
            # Report summary
            Write-Host "Script completed. $deletedCount certificate(s) deleted."
            
            # Close the store
            $store.Close()
        }
        catch {
            Write-Error "An error occurred: $_"
            if ($store) { $store.Close() }
            exit 1
        }
    }
    
    # Verify no certificates remain
    try {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
        [System.Security.Cryptography.X509Certificates.StoreName]::My,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
        )
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
        $remainingCerts = $store.Certificates | Where-Object { $_.Issuer -like "*2PintSoftware.com*" }
        $store.Close()
        
        if (-not $remainingCerts) {
            Write-Host "Verification: No certificates issued by 2PintSoftware.com remain in the Personal store."
        } else {
            Write-Warning "Verification: $($remainingCerts.Count) certificate(s) issued by 2PintSoftware.com still remain in the Personal store."
        }
    }
    catch {
        Write-Error "Verification failed: $_"
    }
    
    # Clean up old 2PXE certificate files and generate a FQDL self-signed certificate
    if ($match -eq $false) {
        
        #Stop the 2PXE Service
        try {
            # Check if the 2PXE service exists
            $service = Get-Service -Name "2PXE" -ErrorAction SilentlyContinue
            if (-not $service) {
                Write-Host "The 2PXE service was not found on this computer."
                exit 0
            }
            
            # Check the current status of the service
            Write-Host "Current status of 2PXE service: $($service.Status)"
            
            # Stop the service if it is running
            if ($service.Status -eq 'Running') {
                Write-Host "Stopping the 2PXE service..."
                Stop-Service -Name "2PXE" -Force -ErrorAction Stop
                Write-Host "Service stop command issued. Waiting for service to stop..."
                
                # Wait for the service to stop (up to 30 seconds)
                $service.WaitForStatus('Stopped', '00:00:30')
                
                # Verify the service status
                $service.Refresh()
                if ($service.Status -eq 'Stopped') {
                    Write-Host "Verification: 2PXE service is now stopped."
                } else {
                    Write-Warning "Verification: 2PXE service is still in state: $($service.Status)"
                }
            } else {
                Write-Host "The 2PXE service is already stopped or in state: $($service.Status)"
            }
        }
        catch {
            Write-Error "An error occurred while attempting to stop the 2PXE service: $_"
            exit 1
        }
        
        # Clean up the 2PXE ProgramData certificates
        $targetDir = "C:\ProgramData\2Pint Software\2PXE\Certificates"
        
        try {
            # Check if the directory exists
            if (-not (Test-Path -Path $targetDir)) {
                Write-Host "Directory not found: $targetDir"
                exit 0
            }
            
            # Get the directory contents
            $items = Get-ChildItem -Path $targetDir -Force
            if (-not $items) {
                Write-Host "No files or subdirectories found in: $targetDir"
                exit 0
            }
            
            # Display items to be deleted for confirmation
            Write-Host "The following items will be deleted from: $targetDir"
            foreach ($item in $items) {
                Write-Host "  - $($item.FullName)"
            }
            
            # Delete all contents
            Write-Host "Deleting contents of: $targetDir"
            foreach ($item in $items) {
                try {
                    if ($item.PSIsContainer) {
                        # Remove directory and its contents recursively
                        Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction Stop
                        Write-Host "Deleted directory: $($item.FullName)"
                    } else {
                        # Remove file
                        Remove-Item -Path $item.FullName -Force -ErrorAction Stop
                        Write-Host "Deleted file: $($item.FullName)"
                    }
                }
                catch {
                    Write-Warning "Failed to delete item: $($item.FullName). Error: $_"
                }
            }
            
            # Verify deletion
            $remainingItems = Get-ChildItem -Path $targetDir -Force
            if (-not $remainingItems) {
                Write-Host "Verification: All contents in $targetDir have been deleted."
            } else {
                Write-Warning "Verification: Some items remain in $targetDir."
                foreach ($item in $remainingItems) {
                    Write-Warning "  - $($item.FullName)"
                }
            }
        }
        catch {
            Write-Error "An error occurred while attempting to delete contents of $targetDir : $_"
            exit 1
        }
        
        # Default path to the 2PXE configuration file
        $configFilePath = "C:\Program Files\2Pint Software\2PXE\2Pint.2PXE.Service.exe.config"  # Update with the actual file path
        
        # Function to create a backup of the configuration file
        function Backup-ConfigFile {
            param (
            [string]$FilePath
            )
            try {
                $backupPath = "$FilePath.bak_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
                Copy-Item -Path $FilePath -Destination $backupPath -Force
                Write-Host "Backup created at: $backupPath"
            }
            catch {
                Write-Error "Failed to create backup: $_"
                exit 1
            }
        }
        
        try {
            # Check if the configuration file exists
            if (-not (Test-Path -Path $configFilePath)) {
                Write-Error "Configuration file not found at: $configFilePath"
                exit 1
            }
            
            # Create a backup of the configuration file
            Backup-ConfigFile -FilePath $configFilePath
            
            # Load the XML configuration file
            [xml]$xml = Get-Content -Path $configFilePath -Raw
            
            # Locate the ExternalFQDNOverride key in appSettings
            $appSettings = $xml.configuration.appSettings
            $fqdnSetting = $appSettings.add | Where-Object { $_.key -eq "ExternalFQDNOverride" }
            
            if (-not $fqdnSetting) {
                Write-Error "ExternalFQDNOverride key not found in appSettings section."
                exit 1
            }
            
            # Update the value
            $oldValue = $fqdnSetting.value
            $fqdnSetting.value = $newExternalFQDN
            Write-Host "Updated ExternalFQDNOverride from '$oldValue' to '$newExternalFQDN'"
            
            # Save the modified XML back to the file
            $xml.Save($configFilePath)
            Write-Host "Configuration file updated successfully: $configFilePath"
            
            # Verify the change
            [xml]$updatedXml = Get-Content -Path $configFilePath -Raw
            $updatedValue = ($updatedXml.configuration.appSettings.add | Where-Object { $_.key -eq "ExternalFQDNOverride" }).value
            if ($updatedValue -eq $newExternalFQDN) {
                Write-Host "Verification: ExternalFQDNOverride is correctly set to '$updatedValue'"
            } else {
                Write-Warning "Verification: ExternalFQDNOverride is set to '$updatedValue', which does not match the intended value '$newExternalFQDN'"
            }
        }
        catch {
            Write-Error "An error occurred: $_"
            exit 1
        }
        
        # Start the 2PXE Service
        try {
            # Check if the 2PXE service exists
            $service = Get-Service -Name "2PXE" -ErrorAction SilentlyContinue
            if (-not $service) {
                Write-Host "The 2PXE service was not found on this computer."
                exit 0
            }
            
            # Check the current status of the service
            Write-Host "Current status of 2PXE service: $($service.Status)"
            
            # Start the service if it is not running
            if ($service.Status -ne 'Running') {
                Write-Host "Starting the 2PXE service..."
                Start-Service -Name "2PXE" -ErrorAction Stop
                Write-Host "Service start command issued. Waiting for service to start..."
                
                # Wait for the service to start (up to 30 seconds)
                $service.WaitForStatus('Running', '00:00:30')
                
                # Verify the service status
                $service.Refresh()
                if ($service.Status -eq 'Running') {
                    Write-Host "Verification: 2PXE service is now running."
                } else {
                    Write-Warning "Verification: 2PXE service is still in state: $($service.Status)"
                }
            } else {
                Write-Host "The 2PXE service is already running."
            }
        }
        catch {
            Write-Error "An error occurred while attempting to start the 2PXE service: $_"
            exit 1
        }
        
    }
    
    Write-Host "Create-FQDN2PXECert Function completed."
}
Function Import-2PXERootCA {
    <#
.SYNOPSIS
    PowerShell script to import the 2Pint 2PXE root certificate into the Trusted Root Certification Authorities store
.DESCRIPTION
    This script automates importing of the 2Pint 2PXE root certificate
    It verifies the import, and handles common errors.
.NOTES
    Author: Mike Terrill/2Pint Software
    Date: July 20, 2025
    Version: 25.07.22
    Requires: Administrative privileges, 64-bit Windows
    #>
    
    # Default 2Pint 2PXE path to the certificate file
    $certFilePath = "C:\Program Files\2Pint Software\2PXE\x64\ca.crt"
    
    # Check if the certificate file exists
    if (-not (Test-Path -Path $certFilePath)) {
        Write-Error "Certificate file not found at: $certFilePath"
        exit 1
    }
    
    try {
        # Load the certificate
        $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certFilePath)
        
        # Display certificate details for verification
        Write-Host "Importing certificate: $($certificate.Subject)"
        Write-Host "Issuer: $($certificate.Issuer)"
        Write-Host "Thumbprint: $($certificate.Thumbprint)"
        
        # Open the Trusted Root Certification Authorities store for the Local Machine
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
        [System.Security.Cryptography.X509Certificates.StoreName]::Root,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
        )
        
        # Open the store with read/write access
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        
        # Check if the certificate already exists in the store
        $existingCert = $store.Certificates | Where-Object { $_.Thumbprint -eq $certificate.Thumbprint }
        if ($existingCert) {
            Write-Warning "Certificate with thumbprint $($certificate.Thumbprint) already exists in the Trusted Root store."
        } else {
            # Add the certificate to the store
            $store.Add($certificate)
            Write-Host "Certificate successfully imported to Trusted Root Certification Authorities store."
        }
        
        # Close the store
        $store.Close()
    }
    catch {
        Write-Error "Failed to import certificate: $_"
        $store.Close()
        exit 1
    }
    
    # Verify the certificate was added
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
    [System.Security.Cryptography.X509Certificates.StoreName]::Root,
    [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
    )
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    $certInStore = $store.Certificates | Where-Object { $_.Thumbprint -eq $certificate.Thumbprint }
    $store.Close()
    
    if ($certInStore) {
        Write-Host "Verification: Certificate with thumbprint $($certificate.Thumbprint) is present in the Trusted Root store."
    } else {
        Write-Warning "Verification: Certificate with thumbprint $($certificate.Thumbprint) was not found in the Trusted Root store."
    }
}
#endregion

try {
    Import-Module DeployR.Utility -ErrorAction SilentlyContinue
}
catch {
    Write-Warning "DeployR.Utility module not found. Environment variables will be set in the standard environment."
}

if (Get-Module -name "DeployR.Utility"){
    write-Host "Using DeployR.Utility Module to get FQDN and Install2PXE values" -ForegroundColor Green
    $FQDN = ${TSEnv:FormFQDN}
    $Install2PXE = ${TSEnv:FormInstall2PXE}
    write-Host "FQDN = $(${TSEnv:FormFQDN})" -ForegroundColor Green
    write-Host "Install2PXE = $Install2PXE" -ForegroundColor Green
}
else{
    Write-Host "Using Test Values for FQDN and Install2PXE" -ForegroundColor Yellow
    $Hostname = $env:COMPUTERNAME
    $DomainSuffix = Get-ActiveNetworkDomainSuffix
    if (!$DomainSuffix) {
        Write-Host "No domain suffix found. Please provide a domain name."
        #prompt user for domain name
        $DomainSuffix = Read-Host "Enter the domain name to use for FQDN (e.g., example.com)"
    }
    $FQDN = "$Hostname.$DomainSuffix"
    $Install2PXE = $true
    write-Host "FQDN = $FQDN" -ForegroundColor Yellow
    write-Host "Install2PXE = $Install2PXE" -ForegroundColor Yellow
}

$WorkingDir = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
if ($WorkingDir){
    if (!(Test-Path -Path $WorkingDir)) {
        Write-Host "Script directory not found: $WorkingDir"
    }
    $MSIFiles = Get-ChildItem -Path $WorkingDir -Filter *.msi
}


if (!$MSIFiles) {
    Write-Host "No MSI files found in script directory: $WorkingDir"
    write-Host "Falling back to target folder: $sourceFolder if it exists." -ForegroundColor Yellow
    if (Test-Path -Path $sourceFolder) {
        $MSIFiles = Get-ChildItem -Path $sourceFolder -Filter *.msi
        if (!$MSIFiles) {
            Write-Host "No MSI files found in target folder: $sourceFolder"
            exit 1
        } else {
            Write-Host "Found MSI files in target folder: $sourceFolder" -ForegroundColor Green
        }
    } else {
        Write-Host "Target folder not found: $sourceFolder"
        exit 1
    }
}

$2PXE = $MSIFiles | Where-Object { $_.Name -like "*2PXE*.msi" } | Select-Object -First 1
if (!$2PXE) {
    Write-Host "No MSI file matching *2PXE*.msi found in script directory or target folder."
    exit 1
} else {
    Write-Host "Found 2PXE MSI: $($2PXE.FullName)" -ForegroundColor Green
}
Install-2PXE -msifile $2PXE.FullName -fqdn $FQDN
Import-2PXERootCA
Create-FQDN2PXECert -fqdn $FQDN