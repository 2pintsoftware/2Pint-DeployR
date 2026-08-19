<#
    .SYNOPSIS
    Stages the Proxmox VirtIO driver ISO, breaks the drivers apart per detected operating system, and publishes one DeployR driver pack content item per operating system.

    .DESCRIPTION
    This script does not install or apply drivers to the currently running operating system. It only stages driver source files and uploads them into DeployR content items.

    Workflow:
    1. Validate administrative rights and the local source root.
    2. Import the local DeployR.Utility module and connect to DeployR using the client passcode (registry first, passcode file second).
    3. Locate the latest ISO within the Proxmox source folder regardless of its file name, or download the ISO when none exists.
    4. Mount the ISO and copy all contents to an Extracted folder (rebuilt on every run).
    5. Detect the operating system folder names from the extracted driver layout (driver\os\architecture) and filter them with the OSInclusionExpression and OSExclusionExpression regular expressions.
    6. For each included operating system, stage the matching driver folders into a per operating system driver pack folder and publish it into its own DeployR content item. Newly created content items always receive their initial version, while existing content items only receive a new version when the AddNewVersions parameter is specified.

    Local content layout created/used (relative to the source root):
        Proxmox\<AnyName>.iso
        Proxmox\Extracted\*
        Proxmox\DriverPacks\<OSName>\*

    DeployR content items used (one per included operating system):
        Name: <ContentNamePrefix> - <OSName> (for example "Driver Pack - Proxmox - VirtIO - w11")
        Type: Folder
        Purpose: DriverPack
        Version behavior: newly created content items receive their initial version automatically, and existing content items only receive a new version when the AddNewVersions parameter is specified.

    .PARAMETER RootDirectory
    The existing local source root directory. The "Proxmox" source folder structure is created beneath this directory.

    .PARAMETER DownloadURL
    The URL where the VirtIO driver ISO is located. The download only occurs when no ISO already exists within the Proxmox source folder (any ISO file name is accepted and the latest one is used).

    .PARAMETER OSInclusionExpression
    A regular expression that determines which detected operating system folder names are included. The default expression includes every detected operating system.

    .PARAMETER OSExclusionExpression
    A regular expression that determines which detected operating system folder names are excluded. The default expression excludes nothing.

    .PARAMETER ArchitectureInclusionExpression
    A regular expression that determines which processor architecture folder names are included within each driver pack.

    .PARAMETER ContentNamePrefix
    The DeployR content item name prefix. The detected operating system folder name is appended to form the full content item name.

    .PARAMETER DriverManufacturer
    The driver manufacturer (make) recorded on each published content item version.

    .PARAMETER DriverModel
    The driver model recorded on each published content item version.

    .PARAMETER AddNewVersions
    Publish a new content item version for content items that already exist. Without this switch, existing content items are left untouched and only newly created content items receive their initial version.

    .PARAMETER PasscodePath
    The path to a text file containing the DeployR client passcode. Empty by default and dynamically detected: the passcode is read from the registry first, then from "DeployRPasscode.txt" at the root of the drive containing the source root directory. Explicitly supplying this parameter overrides the dynamic detection.

    .EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -NoProfile -NoLogo -File ".\Import-ProxMoxDriverPack.ps1"

    .EXAMPLE
    pwsh.exe -ExecutionPolicy Bypass -NoProfile -NoLogo -File ".\Import-ProxMoxDriverPack.ps1" -OSInclusionExpression '.*(w11|2k25).*' -OSExclusionExpression '.*(w7|xp).*' -AddNewVersions

    .EXAMPLE
    .\Import-ProxMoxDriverPack.ps1 -RootDirectory 'D:\SourceRepo\DriverPacks\X64\WinPE' -ContentNamePrefix 'Driver Pack - Proxmox - VirtIO'

    .NOTES
    The operating system folder names within the VirtIO ISO follow the vendor naming convention, such as w10, w11, 2k16, 2k19, 2k22, and 2k25.

    Requires administrator rights and an installed DeployR client (DeployR.Utility module).

    .LINK
    https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/
#>

[CmdletBinding()]
  Param
    (
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [Alias('Root', 'RD')]
        [System.IO.DirectoryInfo]$RootDirectory = 'D:\SourceRepo\DriverPacks\X64\WinPE',

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [Alias('URI', 'URL', 'DURL')]
        [System.URI]$DownloadURL = 'https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/latest-virtio/virtio-win.iso',

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [Alias('OSIE')]
        [Regex]$OSInclusionExpression = '.*(win11|).*',

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [Alias('OSEE')]
        [Regex]$OSExclusionExpression = '.*(Exclude1|Exclude2).*',

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [Alias('AIE')]
        [Regex]$ArchitectureInclusionExpression = '.*(amd64).*',

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [Alias('CNP')]
        [String]$ContentNamePrefix = 'Driver Pack - Proxmox - VirtIO',

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [Alias('Make', 'Manufacturer')]
        [String]$DriverManufacturer = 'Proxmox',

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [Alias('Model')]
        [String]$DriverModel = 'Virtual Machine',

        [Parameter(Mandatory=$False)]
        [Alias('ANV')]
        [Switch]$AddNewVersions,

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [Alias('PP')]
        [System.IO.FileInfo]$PasscodePath
    )

Try
  {
      #region Define Default Action Preferences
        $ErrorActionPreference = 'Stop'
        $ProgressPreference = 'Continue'
      #endregion

      #region Set the default exit code for the script
        [System.Environment]::ExitCode = 0
      #endregion

      #region Validate administrative rights
        $Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $Principal = New-Object -TypeName 'System.Security.Principal.WindowsPrincipal' -ArgumentList ($Identity)
        $IsElevated = $Principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

        Switch ($IsElevated)
          {
              {($_ -eq $False)}
                {
                    Throw "This script must be run as an administrator."
                }
          }
      #endregion

      #region Validate the source root and define the directory structure
        Switch ([System.IO.Directory]::Exists($RootDirectory.FullName))
          {
              {($_ -eq $False)}
                {
                    Throw "The root directory `"$($RootDirectory.FullName)`" does not exist. Update the RootDirectory parameter to point to an existing folder and run the script again."
                }
          }

        $DriverSourceDirectory = [System.IO.DirectoryInfo][System.IO.Path]::Combine($RootDirectory.FullName, 'Proxmox')
        $ExtractedDirectory = [System.IO.DirectoryInfo][System.IO.Path]::Combine($DriverSourceDirectory.FullName, 'Extracted')
        $DriverPacksDirectory = [System.IO.DirectoryInfo][System.IO.Path]::Combine($DriverSourceDirectory.FullName, 'DriverPacks')

        Switch ([System.IO.Directory]::Exists($DriverSourceDirectory.FullName))
          {
              {($_ -eq $False)}
                {
                    $Null = [System.IO.Directory]::CreateDirectory($DriverSourceDirectory.FullName)
                }
          }
      #endregion

      #region Import the DeployR.Utility module
        $DeployRModulePathList = New-Object -TypeName 'System.Collections.Generic.List[System.String]'
          $DeployRModulePathList.Add("$($Env:ProgramFiles)\2Pint Software\DeployR\Client\PSModules\DeployR.Utility")
          $DeployRModulePathList.Add('DeployR.Utility')

        $DeployRModuleImported = $False

        For ($DeployRModulePathListIndex = 0; $DeployRModulePathListIndex -lt $DeployRModulePathList.Count; $DeployRModulePathListIndex++)
          {
              $DeployRModulePath = $DeployRModulePathList[$DeployRModulePathListIndex]

              $DeployRModuleAvailable = ([System.IO.Directory]::Exists($DeployRModulePath) -eq $True) -or ($Null -ine (Get-Module -ListAvailable -Name ($DeployRModulePath) -ErrorAction SilentlyContinue))

              Switch (($DeployRModuleAvailable -eq $True) -and ($DeployRModuleImported -eq $False))
                {
                    {($_ -eq $True)}
                      {
                          Write-Verbose -Message "Attempting to import the DeployR.Utility module. Please Wait... [Path: $($DeployRModulePath)]" -Verbose

                          $ImportModuleParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                            $ImportModuleParameters.Name = $DeployRModulePath
                            $ImportModuleParameters.Force = $True
                            $ImportModuleParameters.DisableNameChecking = $True
                            $ImportModuleParameters.Verbose = $False

                          $Null = Import-Module @ImportModuleParameters

                          $DeployRModuleImported = $True
                      }
                }
          }

        Switch ($DeployRModuleImported)
          {
              {($_ -eq $False)}
                {
                    Throw "The DeployR.Utility module could not be found. Please ensure that the DeployR client is installed."
                }
          }
      #endregion

      #region Connect to DeployR using the client passcode (Registry first, passcode file second)
        [System.IO.FileInfo]$DeployRSettingsRegistryPath = "$($Env:SystemDrive)"

        $DeployRGeneralSettingsPath = 'HKLM:\SOFTWARE\2Pint Software\DeployR\GeneralSettings'

        #Determine the passcode file path dynamically when one was not explicitly supplied (The root of the drive containing the source root directory)
          [Boolean]$PasscodePathSupplied = $PSBoundParameters.ContainsKey('PasscodePath')

          Switch ($PasscodePathSupplied)
            {
                {($_ -eq $False)}
                  {
                      $PasscodePath = [System.IO.FileInfo][System.IO.Path]::Combine($RootDirectory.Root.FullName, 'DeployRPasscode.txt')
                  }
            }

        $ClientPasscode = $Null

        Switch ($True)
          {
              {($PasscodePathSupplied -eq $True) -and ([System.IO.File]::Exists($PasscodePath.FullName))}
                {
                    Write-Verbose -Message "Attempting to read the DeployR client passcode from the explicitly supplied passcode file. Please Wait... [Path: $($PasscodePath.FullName)]" -Verbose

                    $ClientPasscode = [System.IO.File]::ReadAllText($PasscodePath.FullName).Trim()

                    Break
                }

              {(Test-Path -Path ($DeployRGeneralSettingsPath))}
                {
                    Write-Verbose -Message "Attempting to read the DeployR client passcode from the registry. Please Wait... [Path: $($DeployRGeneralSettingsPath)]" -Verbose

                    $ClientPasscode = (Get-Item -Path ($DeployRGeneralSettingsPath)).GetValue('ClientPasscode')

                    Break
                }

              {([System.IO.File]::Exists($PasscodePath.FullName))}
                {
                    Write-Verbose -Message "Attempting to read the DeployR client passcode from the dynamically detected passcode file. Please Wait... [Path: $($PasscodePath.FullName)]" -Verbose

                    $ClientPasscode = [System.IO.File]::ReadAllText($PasscodePath.FullName).Trim()

                    Break
                }

              Default
                {
                    Throw "The DeployR client passcode could not be found within the registry or within `"$($PasscodePath.FullName)`"."
                }
          }

        Write-Verbose -Message "Attempting to connect to DeployR. Please Wait..." -Verbose

        $ConnectDeployRParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
          $ConnectDeployRParameters.Passcode = $ClientPasscode
          $ConnectDeployRParameters.ErrorAction = [System.Management.Automation.ActionPreference]::Stop

        $Null = Connect-DeployR @ConnectDeployRParameters

        Write-Verbose -Message "Successfully connected to DeployR." -Verbose
      #endregion

      #region Stage the ISO (Any existing ISO within the source folder is used as-is regardless of its file name, otherwise the ISO is downloaded)
        $ExistingISOList = Get-ChildItem -Path ($DriverSourceDirectory.FullName) -Filter '*.iso' -Force -ErrorAction SilentlyContinue | Where-Object {($_ -is [System.IO.FileInfo])}

        $ExistingISOListCount = ($ExistingISOList | Measure-Object).Count

        Switch ($ExistingISOListCount -gt 0)
          {
              {($_ -eq $True)}
                {
                    $ISOPath = $ExistingISOList | Sort-Object -Property @('LastWriteTime') -Descending | Select-Object -First 1

                    Write-Verbose -Message "Found $($ExistingISOListCount) existing ISO image(s) within `"$($DriverSourceDirectory.FullName)`". The download will be skipped. [Latest Existing ISO Image: $($ISOPath.FullName)]" -Verbose
                }

              Default
                {
                    $ISOPath = [System.IO.FileInfo][System.IO.Path]::Combine($DriverSourceDirectory.FullName, [System.IO.Path]::GetFileName($DownloadURL.OriginalString))

                    Write-Verbose -Message "Attempting to download `"$($DownloadURL.OriginalString)`" to `"$($ISOPath.FullName)`". Please Wait..." -Verbose

                    $WebClient = New-Object -TypeName 'System.Net.WebClient'
                      $WebClient.UseDefaultCredentials = $True

                    Try
                      {
                          $Null = $WebClient.DownloadFile($DownloadURL.OriginalString, $ISOPath.FullName)
                      }
                    Finally
                      {
                          Try {$Null = $WebClient.Dispose()} Catch {}
                      }

                    $ISOPath = Get-Item -Path ($ISOPath.FullName) -Force

                    Write-Verbose -Message "The download completed successfully. [Size: $([System.Math]::Round($ISOPath.Length / 1MB, 2)) MB]" -Verbose
                }
          }
      #endregion

      #region Extract the ISO contents (Rebuilt on every run so that the driver packs reflect the current ISO contents)
        Write-Verbose -Message "Attempting to extract the ISO contents to `"$($ExtractedDirectory.FullName)`". Please Wait..." -Verbose

        Switch ([System.IO.Directory]::Exists($ExtractedDirectory.FullName))
          {
              {($_ -eq $True)}
                {
                    $Null = Remove-Item -Path ($ExtractedDirectory.FullName) -Recurse -Force -Confirm:$False
                }
          }

        $Null = [System.IO.Directory]::CreateDirectory($ExtractedDirectory.FullName)

        Try
          {
              $ISOImageInfo = Mount-DiskImage -ImagePath ($ISOPath.FullName) -StorageType ISO -Access ReadOnly -PassThru

              $ISOImageVolume = $ISOImageInfo | Get-Volume

              Switch (([String]::IsNullOrEmpty($ISOImageVolume.DriveLetter) -eq $True) -or ([String]::IsNullOrWhiteSpace($ISOImageVolume.DriveLetter) -eq $True))
                {
                    {($_ -eq $True)}
                      {
                          Throw "The mounted ISO image did not expose a drive letter."
                      }
                }

              $Null = Copy-Item -Path "$($ISOImageVolume.DriveLetter):\*" -Destination "$($ExtractedDirectory.FullName)\" -Recurse -Force
          }
        Finally
          {
              $ISOImageInfo = Get-DiskImage -ImagePath ($ISOPath.FullName) -StorageType ISO

              Switch ($ISOImageInfo.Attached)
                {
                    {($_ -eq $True)}
                      {
                          Write-Verbose -Message "Attempting to dismount the previously mounted ISO image. Please Wait... [ISO Image Path: $($ISOPath.FullName)]" -Verbose

                          $Null = Try {Dismount-DiskImage -ImagePath ($ISOPath.FullName) -StorageType ISO} Catch {}
                      }
                }
          }
      #endregion

      #region Detect the operating system folder names from the extracted driver layout (driver\os\architecture)
        Write-Verbose -Message "Attempting to detect the operating system folder names within `"$($ExtractedDirectory.FullName)`". Please Wait..." -Verbose

        $ArchitectureDirectoryList = Get-ChildItem -Path ($ExtractedDirectory.FullName) -Directory -Recurse -Force | Where-Object {($_.Name -imatch $ArchitectureInclusionExpression.ToString()) -and ($Null -ine $_.Parent) -and ($_.Parent.FullName -ine $ExtractedDirectory.FullName)}

        $DetectedOSNameList = $ArchitectureDirectoryList | ForEach-Object {$_.Parent.Name} | Sort-Object -Unique

        $DetectedOSNameListCount = ($DetectedOSNameList | Measure-Object).Count

        Write-Verbose -Message "Detected $($DetectedOSNameListCount) operating system folder name(s): $($DetectedOSNameList -Join ', ')" -Verbose

        $IncludedOSNameList = New-Object -TypeName 'System.Collections.Generic.List[System.String]'

        ForEach ($DetectedOSName In $DetectedOSNameList)
          {
              Switch (($DetectedOSName -imatch $OSInclusionExpression.ToString()) -and ($DetectedOSName -inotmatch $OSExclusionExpression.ToString()))
                {
                    {($_ -eq $True)}
                      {
                          $IncludedOSNameList.Add($DetectedOSName)
                      }

                    Default
                      {
                          Write-Verbose -Message "Skipping operating system `"$($DetectedOSName)`". [Reason: The name did not match the inclusion expression or matched the exclusion expression.]" -Verbose
                      }
                }
          }

        Write-Verbose -Message "$($IncludedOSNameList.Count) operating system(s) will be processed: $($IncludedOSNameList -Join ', ')" -Verbose

        Switch ($IncludedOSNameList.Count -gt 0)
          {
              {($_ -eq $False)}
                {
                    Throw "No operating system folder names matched the specified inclusion and exclusion expressions. [Inclusion: $($OSInclusionExpression.ToString())] [Exclusion: $($OSExclusionExpression.ToString())]"
                }
          }
      #endregion

      #region Retrieve the existing DeployR content item list one time before processing
        $ExistingContentItemList = Get-DeployRContentItem
      #endregion

      #region Create one driver pack per included operating system and publish each as its own DeployR content item version
        $IncludedOSNameListCounter = 1

        For ($IncludedOSNameListIndex = 0; $IncludedOSNameListIndex -lt $IncludedOSNameList.Count; $IncludedOSNameListIndex++)
          {
              Try
                {
                    $OSName = $IncludedOSNameList[$IncludedOSNameListIndex]

                    $ProgressPercentage = [System.Math]::Round((($IncludedOSNameListCounter / $IncludedOSNameList.Count) * 100), 2)

                    $WriteProgressParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                      $WriteProgressParameters.Activity = "Processing driver pack $($IncludedOSNameListCounter) of $($IncludedOSNameList.Count). Please Wait... [Operating System: $($OSName)]"
                      $WriteProgressParameters.Status = "Progress Percentage: $($ProgressPercentage)%"
                      $WriteProgressParameters.PercentComplete = $ProgressPercentage
                      $WriteProgressParameters.CurrentOperation = $OSName

                    Write-Progress @WriteProgressParameters

                    Write-Verbose -Message "Attempting to process driver pack $($IncludedOSNameListCounter) of $($IncludedOSNameList.Count). Please Wait... [Operating System: $($OSName)]" -Verbose

                    #region Stage the matching driver folders into the per operating system driver pack folder
                      $DriverPackDirectory = [System.IO.DirectoryInfo][System.IO.Path]::Combine($DriverPacksDirectory.FullName, $OSName)

                      Switch ([System.IO.Directory]::Exists($DriverPackDirectory.FullName))
                        {
                            {($_ -eq $True)}
                              {
                                  $Null = Remove-Item -Path ($DriverPackDirectory.FullName) -Recurse -Force -Confirm:$False
                              }
                        }

                      $Null = [System.IO.Directory]::CreateDirectory($DriverPackDirectory.FullName)

                      $OSArchitectureDirectoryList = @($ArchitectureDirectoryList | Where-Object {($_.Parent.Name -ieq $OSName)})

                      For ($OSArchitectureDirectoryListIndex = 0; $OSArchitectureDirectoryListIndex -lt $OSArchitectureDirectoryList.Count; $OSArchitectureDirectoryListIndex++)
                        {
                            $OSArchitectureDirectory = $OSArchitectureDirectoryList[$OSArchitectureDirectoryListIndex]

                            #Preserve the full path below the extracted directory (For example, pvpanic\w11\amd64)
                              [String]$RelativeDirectoryPath = $OSArchitectureDirectory.FullName.Substring($ExtractedDirectory.FullName.Length).TrimStart([System.IO.Path]::DirectorySeparatorChar)

                              $DestinationDirectory = [System.IO.DirectoryInfo][System.IO.Path]::Combine($DriverPackDirectory.FullName, $RelativeDirectoryPath)

                              $Null = [System.IO.Directory]::CreateDirectory($DestinationDirectory.FullName)

                              $Null = Copy-Item -Path "$($OSArchitectureDirectory.FullName)\*" -Destination "$($DestinationDirectory.FullName)\" -Recurse -Force
                        }

                      Write-Verbose -Message "Staged $($OSArchitectureDirectoryList.Count) driver folder(s) into `"$($DriverPackDirectory.FullName)`"." -Verbose
                    #endregion

                    #region Create or reuse the DeployR content item for this operating system
                      [String]$ContentName = "$($ContentNamePrefix) - $($OSName)"

                      $ContentItem = $ExistingContentItemList | Where-Object {($_.Name -ieq $ContentName)} | Select-Object -First 1

                      [Boolean]$ContentItemIsNew = $False

                      Switch ($Null -ine $ContentItem)
                        {
                            {($_ -eq $True)}
                              {
                                  Write-Verbose -Message "Using the existing DeployR content item. [Name: $($ContentName)]" -Verbose
                              }

                            Default
                              {
                                  Write-Verbose -Message "Attempting to create the DeployR content item. Please Wait... [Name: $($ContentName)]" -Verbose

                                  $NewDeployRContentItemParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                    $NewDeployRContentItemParameters.Name = $ContentName
                                    $NewDeployRContentItemParameters.Type = 'Folder'
                                    $NewDeployRContentItemParameters.Purpose = 'DriverPack'
                                    $NewDeployRContentItemParameters.Description = "Source: $($ISOPath.Name) [$($OSName)]"

                                  $ContentItem = New-DeployRContentItem @NewDeployRContentItemParameters

                                  [Boolean]$ContentItemIsNew = $True
                              }
                        }
                    #endregion

                    #region Publish the driver pack content as a new content item version (Existing content items only receive a new version when the AddNewVersions parameter is specified)
                      Switch (($ContentItemIsNew -eq $True) -or ($AddNewVersions.IsPresent -eq $True))
                        {
                            {($_ -eq $True)}
                              {
                                  Write-Verbose -Message "Attempting to publish the driver pack content as a new content item version. Please Wait... [Name: $($ContentName)]" -Verbose

                                  $NewDeployRContentItemVersionParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                    $NewDeployRContentItemVersionParameters.ContentItemId = $ContentItem.id
                                    $NewDeployRContentItemVersionParameters.Description = "Source: $($ISOPath.Name) [$($OSName)]"
                                    $NewDeployRContentItemVersionParameters.DriverManufacturer = $DriverManufacturer
                                    $NewDeployRContentItemVersionParameters.DriverModel = $DriverModel
                                    $NewDeployRContentItemVersionParameters.SourceFolder = $DriverPackDirectory.FullName

                                  $NewContentItemVersion = New-DeployRContentItemVersion @NewDeployRContentItemVersionParameters

                                  $UpdateDeployRContentItemContentParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                    $UpdateDeployRContentItemContentParameters.ContentId = $ContentItem.id
                                    $UpdateDeployRContentItemContentParameters.ContentVersion = $NewContentItemVersion.versionNo
                                    $UpdateDeployRContentItemContentParameters.SourceFolder = $DriverPackDirectory.FullName

                                  $ContentItemVersion = Update-DeployRContentItemContent @UpdateDeployRContentItemContentParameters

                                  Write-Verbose -Message "The driver pack upload completed successfully. [Name: $($ContentName)] [CI ID: $($ContentItemVersion.contentItemId)] [Version: $($ContentItemVersion.versionNo)] [Size: $([System.Math]::Round($ContentItemVersion.contentSize / 1MB, 2)) MB]" -Verbose
                              }

                            Default
                              {
                                  Write-Verbose -Message "The content item already exists and the `"-AddNewVersions`" parameter was not specified. The version publish will be skipped. [Name: $($ContentName)]" -Verbose
                              }
                        }
                    #endregion
                }
              Catch
                {
                    Write-Warning -Message "The driver pack for operating system `"$($OSName)`" could not be processed. [Error: $($_.Exception.Message)]"
                }
              Finally
                {
                    $IncludedOSNameListCounter++
                }
          }

        $WriteProgressParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
          $WriteProgressParameters.Activity = "Processing driver packs"
          $WriteProgressParameters.Completed = $True

        Write-Progress @WriteProgressParameters
      #endregion
  }
Catch
  {
      Switch (([System.Environment]::ExitCode -eq 0))
        {
            {($_ -eq $True)}
              {
                  [System.Environment]::ExitCode = 1
              }
        }

      Write-Warning -Message "Message: $($_.Exception.Message)"
      Write-Warning -Message "Script: $([System.IO.Path]::GetFileName($_.InvocationInfo.ScriptName))"
      Write-Warning -Message "Line Number: $($_.InvocationInfo.ScriptLineNumber)"
      Write-Warning -Message "Line Position: $($_.InvocationInfo.OffsetInLine)"
      Write-Warning -Message "Code: $($_.InvocationInfo.Line)"

      Throw
  }
Finally
  {
      Write-Verbose -Message "Exiting script with exit code $([System.Environment]::ExitCode)." -Verbose
  }
