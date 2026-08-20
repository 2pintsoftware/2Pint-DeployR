<#
    .SYNOPSIS
    Stages the Proxmox VirtIO driver ISO, breaks the drivers apart per detected operating system, and publishes one DeployR driver pack content item per operating system.

    .DESCRIPTION
    This script does not install or apply drivers to the currently running operating system. It only stages driver source files and uploads them into DeployR content items.

    Workflow:
    1. Validate administrative rights and determine the local source root (dynamically selected when not supplied: the largest fixed and ready drive with a drive letter, using "2Pint\DeployR\Source" beneath its root), creating it when it does not exist.
    2. Import the local DeployR.Utility module and connect to DeployR using the client passcode (registry first, passcode file second).
    3. Locate the latest ISO within the ISO folder regardless of its file name, or download the ISO when none exists.
    4. Mount the ISO and copy all contents to an Extracted folder (rebuilt on every run).
    5. Detect the operating system folder names from the extracted driver layout (driver\os\architecture) and filter them with the OSInclusionExpression and OSExclusionExpression regular expressions.
    6. Define one driver pack per included operating system, plus a generic Windows PE driver pack that is intended for boot image driver injection.
    7. For each driver pack, stage the matching driver folders into its own driver pack folder and publish it into its own DeployR content item. Newly created content items always receive their initial version, while existing content items only receive a new version when the AddNewVersions parameter is specified.
    8. Apply the tag list to each content item and all of its versions.
    9. Set every content item version to the desired status (Active by default) so that the published driver packs are immediately usable. The tags and the status are applied within a single update per version.

    Local content layout created/used (relative to the source root):
        Proxmox\VirtIO\ISO\<AnyName>.iso
        Proxmox\VirtIO\Extracted\*
        Proxmox\VirtIO\DriverPacks\<OSName>\<driver>\<operatingsystem>\<architecture>\*
        Proxmox\VirtIO\DriverPacks\<WinPEDisplayName>\<DriverManufacturer>\<driver>\<architecture>\*

    DeployR content items used (one per included operating system, plus one for Windows PE):
        Name: <ContentNamePrefix> - <OSDisplayName> - <ArchitectureDisplayName> (for example "Driver Pack - Proxmox - VirtIO - Windows 11 - X64" or "Driver Pack - Proxmox - VirtIO - Windows Server 2022 - X64")
        Naming: the operating system and processor architecture folder names are mapped to friendly display names through mapping tables (for example "2k22" becomes "Windows Server 2022" and "amd64" becomes "X64"), and unmapped folder names fall through to the folder name as-is.
        Description: <OSDisplayName> [<OSName>] (for example "Windows Server 2022 [2k22]")
        Type: Folder
        Purpose: DriverPack
        Version behavior: newly created content items receive their initial version automatically, and existing content items only receive a new version when the AddNewVersions parameter is specified.
        Tags: Drivers, VirtIO, <DriverManufacturer>, <DriverModel>, <OSDisplayName>, and the included architecture display name(s) (for example X64) are applied to the content item and all of its versions.

    Generic Windows PE driver pack:
        A single additional driver pack is created for boot image driver injection. Its drivers are sourced from the operating system folder(s) matching the WinPESourceOSExpression parameter (the Windows 11 folder by default, because those drivers are the most current), however it carries no operating system identity whatsoever:
            Name: <ContentNamePrefix> - <WinPEDisplayName> - <ArchitectureDisplayName> (for example "Driver Pack - Proxmox - VirtIO - WindowsPE - X64")
            Description: a generic description that makes no reference to an operating system.
            Tags: Drivers, VirtIO, <DriverManufacturer>, <DriverModel>, <WinPEDisplayName>, "Boot Image", and the included architecture display name(s). No operating system tag is applied.
            Staged structure: the operating system folder segment is dropped and the drivers are placed beneath a driver manufacturer folder, so the staged layout is <DriverManufacturer>\<driver>\<architecture> (for example "WindowsPE\Proxmox\NetKVM\amd64").
        The driver manufacturer folder exists so that drivers from additional vendors (network, storage, and so on) can be added alongside the VirtIO drivers within the same boot image content item without colliding and without the content item implying a single operating system or a single vendor. Specify the SkipWinPEDriverPack parameter to skip its creation.

    Successful output resembles the following:

        VERBOSE: The source root was dynamically determined. [Drive: D:\] [Total Size: 512 GB] [Path: D:\2Pint\DeployR\Source]
        VERBOSE: Attempting to connect to DeployR. Please Wait...
        Passcode authentication was successful, token valid until 08/20/2026 05:08:38
        VERBOSE: Successfully connected to DeployR.
        VERBOSE: Found 1 existing ISO image(s) within "D:\2Pint\DeployR\Source\Proxmox\VirtIO\ISO". The download will be skipped. [Latest Existing ISO Image: D:\2Pint\DeployR\Source\Proxmox\VirtIO\ISO\virtio-win.iso]
        VERBOSE: Attempting to extract the ISO contents to "D:\2Pint\DeployR\Source\Proxmox\VirtIO\Extracted". Please Wait...
        VERBOSE: Detected 15 operating system folder name(s): 2k12, 2k12R2, 2k16, 2k19, 2k22, 2k25, 2k3, 2k8, 2k8R2, w10, w11, w7, w8, w8.1, xp
        VERBOSE: Skipping operating system "2k12". [Reason: The name did not match the inclusion expression or matched the exclusion expression.]
        VERBOSE: 6 operating system(s) will be processed: 2k16, 2k19, 2k22, 2k25, w10, w11
        VERBOSE: The generic WindowsPE driver pack will be created from 17 driver folder(s). [Source Expression: .*(w11).*] [Architecture: X64]
        VERBOSE: 7 driver pack(s) will be processed: 2k16, 2k19, 2k22, 2k25, w10, w11, WindowsPE
        VERBOSE: Attempting to process driver pack 3 of 7. Please Wait... [Driver Pack: Windows Server 2022 (2k22)] [Architecture: X64]
        VERBOSE: Staged 17 driver folder(s) into "D:\2Pint\DeployR\Source\Proxmox\VirtIO\DriverPacks\2k22".
        VERBOSE: Attempting to create the DeployR content item. Please Wait... [Name: Driver Pack - Proxmox - VirtIO - Windows Server 2022 - X64]
        VERBOSE: The DeployR content item was created successfully. [Name: Driver Pack - Proxmox - VirtIO - Windows Server 2022 - X64] [CI ID: 00000000-0000-0000-0001-000000000011]
        VERBOSE: Attempting to publish the driver pack content as a new content item version. Please Wait... [Name: Driver Pack - Proxmox - VirtIO - Windows Server 2022 - X64]
        VERBOSE: The driver pack upload completed successfully. [Name: Driver Pack - Proxmox - VirtIO - Windows Server 2022 - X64] [CI ID: 00000000-0000-0000-0001-000000000011] [Version: 1] [Size: 12.32 MB]
        VERBOSE: Attempting to apply 6 tag(s) and the "Active" version status to the content item and all of its versions. Please Wait... [Name: Driver Pack - Proxmox - VirtIO - Windows Server 2022 - X64] [Tags: Drivers, VirtIO, Proxmox, Virtual Machine, Windows Server 2022, X64]
        VERBOSE: Added 6 tag(s) to the content item. [Name: Driver Pack - Proxmox - VirtIO - Windows Server 2022 - X64] [Added Tags: Drivers, VirtIO, Proxmox, Virtual Machine, Windows Server 2022, X64]
        VERBOSE: Updated content item version 1. [Name: Driver Pack - Proxmox - VirtIO - Windows Server 2022 - X64] [Added Tags: Drivers, VirtIO, Proxmox, Virtual Machine, Windows Server 2022, X64] [Status: New -> Active]
        VERBOSE: Attempting to process driver pack 7 of 7. Please Wait... [Driver Pack: WindowsPE (WindowsPE)] [Architecture: X64]
        VERBOSE: Staged 17 driver folder(s) into "D:\2Pint\DeployR\Source\Proxmox\VirtIO\DriverPacks\WindowsPE".
        VERBOSE: The DeployR content item was created successfully. [Name: Driver Pack - Proxmox - VirtIO - WindowsPE - X64] [CI ID: 00000000-0000-0000-0001-000000000017]
        VERBOSE: Updated content item version 1. [Name: Driver Pack - Proxmox - VirtIO - WindowsPE - X64] [Added Tags: Drivers, VirtIO, Proxmox, Virtual Machine, WindowsPE, Boot Image, X64] [Status: New -> Active]
        VERBOSE: Exiting script with exit code 0.

    .PARAMETER RootDirectory
    The local source root directory. The "Proxmox" source folder structure is created beneath this directory.
    Empty by default and dynamically determined: the largest fixed and ready drive with a drive letter is selected, and "2Pint\DeployR\Source" beneath its root is used. The directory is created when it does not exist.

    .PARAMETER DownloadURL
    The URL where the VirtIO driver ISO is located. The download only occurs when no ISO already exists within the ISO folder (any ISO file name is accepted and the latest one is used).

    .PARAMETER OSInclusionExpression
    A regular expression that determines which detected operating system folder names are included. The default expression includes Windows 10, Windows 11, and Windows Server 2016 through Windows Server 2025 (w10, w11, 2k16, 2k19, 2k22, 2k25). Every other detected operating system is skipped by default without requiring an exclusion.

    .PARAMETER OSExclusionExpression
    A regular expression that determines which detected operating system folder names are excluded. The default expression excludes nothing.

    .PARAMETER ArchitectureInclusionExpression
    A regular expression that determines which processor architecture folder names are included within each driver pack. The architecture folder names are mapped to friendly display names (for example "amd64" becomes "X64") for use within the content item name and the tag list.

    .PARAMETER ContentNamePrefix
    The DeployR content item name prefix. The operating system display name and the processor architecture display name are appended to form the full content item name (for example "Driver Pack - Proxmox - VirtIO - Windows Server 2022 - X64").

    .PARAMETER DriverManufacturer
    The driver manufacturer (make) recorded on each published content item version.

    .PARAMETER DriverModel
    The driver model recorded on each published content item version.

    .PARAMETER WinPESourceOSExpression
    A regular expression that determines which operating system folder name(s) supply the drivers for the generic Windows PE driver pack. The default expression sources the drivers from the Windows 11 folder (w11) because those drivers are current, however no operating system identity is carried into the resulting driver pack.

    .PARAMETER WinPEDisplayName
    The display name used for the generic Windows PE driver pack within the content item name, the tag list, and the staged driver pack folder name. The default value is "WindowsPE".

    .PARAMETER SkipWinPEDriverPack
    Skip the creation of the generic Windows PE driver pack. Without this switch, the Windows PE driver pack is always created.

    .PARAMETER ContentItemVersionStatus
    The status applied to every content item version. The default value is "Active" so that the published driver packs are immediately usable. The status is only written when it differs from the current status, and it is applied within the same update as the tags.

    .PARAMETER AddNewVersions
    Publish a new content item version for content items that already exist. Without this switch, existing content items are left untouched and only newly created content items receive their initial version.

    .PARAMETER PasscodePath
    The path to a text file containing the DeployR client passcode. Empty by default and dynamically detected: the passcode is read from the registry first, then from "DeployRPasscode.txt" at the root of the drive containing the source root directory. Explicitly supplying this parameter overrides the dynamic detection.

    .EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -NoProfile -NoLogo -File ".\Import-ProxMoxDriverPack.ps1"

    .EXAMPLE
    pwsh.exe -ExecutionPolicy Bypass -NoProfile -NoLogo -File ".\Import-ProxMoxDriverPack.ps1" -OSInclusionExpression '.*(w11|2k25).*' -OSExclusionExpression '.*(w7|xp).*' -AddNewVersions

    .EXAMPLE
    .\Import-ProxMoxDriverPack.ps1 -RootDirectory 'D:\2Pint\DeployR\Source' -ContentNamePrefix 'Driver Pack - Proxmox - VirtIO'

    .NOTES
    The operating system folder names within the VirtIO ISO follow the vendor naming convention, such as w10, w11, 2k16, 2k19, 2k22, and 2k25. The processor architecture folder names follow the vendor naming convention as well, such as amd64, x86, and ARM64.

    Both the operating system and the processor architecture folder names are translated through mapping tables so that the content item names remain readable. A folder name that is not present within a mapping table is used as-is, so a newly introduced folder name never breaks a run.

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
        [System.IO.DirectoryInfo]$RootDirectory,

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [Alias('URI', 'URL', 'DURL')]
        [System.URI]$DownloadURL = 'https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/latest-virtio/virtio-win.iso',

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [Alias('OSIE')]
        [Regex]$OSInclusionExpression = '.*(w10|w11|2k16|2k19|2k22|2k25).*',

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
        [ValidateNotNullOrEmpty()]
        [Alias('WinPEOSE', 'PEOSE')]
        [Regex]$WinPESourceOSExpression = '.*(w11).*',

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [Alias('WinPEDN', 'PEDN')]
        [String]$WinPEDisplayName = 'WindowsPE',

        [Parameter(Mandatory=$False)]
        [Alias('SkipWinPE', 'SWPE')]
        [Switch]$SkipWinPEDriverPack,

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [Alias('Status', 'CIVS')]
        [String]$ContentItemVersionStatus = 'Active',

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

      #region Determine, validate, and create the source root and define the directory structure
        #Determine the source root dynamically when one was not explicitly supplied (The largest fixed and ready drive with a drive letter)
          Switch ($PSBoundParameters.ContainsKey('RootDirectory'))
            {
                {($_ -eq $False)}
                  {
                      $FixedDriveList = [System.IO.DriveInfo]::GetDrives() | Where-Object {($_.DriveType -ieq 'Fixed') -and ($_.IsReady -eq $True) -and ([String]::IsNullOrEmpty($_.Name) -eq $False) -and ([String]::IsNullOrWhiteSpace($_.Name) -eq $False)}

                      $LargestFixedDrive = $FixedDriveList | Sort-Object -Property @('TotalSize') -Descending | Select-Object -First 1

                      Switch ($Null -ieq $LargestFixedDrive)
                        {
                            {($_ -eq $True)}
                              {
                                  Throw "Unable to locate a fixed and ready drive with a drive letter for the dynamically determined source root."
                              }
                        }

                      $RootDirectory = [System.IO.DirectoryInfo][System.IO.Path]::Combine($LargestFixedDrive.RootDirectory.FullName, '2Pint', 'DeployR', 'Source')

                      Write-Verbose -Message "The source root was dynamically determined. [Drive: $($LargestFixedDrive.Name)] [Total Size: $([System.Math]::Round($LargestFixedDrive.TotalSize / 1GB, 2)) GB] [Path: $($RootDirectory.FullName)]" -Verbose
                  }
            }

        #Create the source root when it does not exist
          Switch ([System.IO.Directory]::Exists($RootDirectory.FullName))
            {
                {($_ -eq $False)}
                  {
                      Write-Verbose -Message "Attempting to create the source root directory. Please Wait... [Path: $($RootDirectory.FullName)]" -Verbose

                      $Null = [System.IO.Directory]::CreateDirectory($RootDirectory.FullName)
                  }
            }

        $DriverSourceDirectory = [System.IO.DirectoryInfo][System.IO.Path]::Combine($RootDirectory.FullName, 'Proxmox', 'VirtIO')
        $ISODirectory = [System.IO.DirectoryInfo][System.IO.Path]::Combine($DriverSourceDirectory.FullName, 'ISO')
        $ExtractedDirectory = [System.IO.DirectoryInfo][System.IO.Path]::Combine($DriverSourceDirectory.FullName, 'Extracted')
        $DriverPacksDirectory = [System.IO.DirectoryInfo][System.IO.Path]::Combine($DriverSourceDirectory.FullName, 'DriverPacks')

        Switch ([System.IO.Directory]::Exists($ISODirectory.FullName))
          {
              {($_ -eq $False)}
                {
                    $Null = [System.IO.Directory]::CreateDirectory($ISODirectory.FullName)
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

      #region Stage the ISO (Any existing ISO within the ISO folder is used as-is regardless of its file name, otherwise the ISO is downloaded)
        $ExistingISOList = Get-ChildItem -Path ($ISODirectory.FullName) -Filter '*.iso' -Force -ErrorAction SilentlyContinue | Where-Object {($_ -is [System.IO.FileInfo])}

        $ExistingISOListCount = ($ExistingISOList | Measure-Object).Count

        Switch ($ExistingISOListCount -gt 0)
          {
              {($_ -eq $True)}
                {
                    $ISOPath = $ExistingISOList | Sort-Object -Property @('LastWriteTime') -Descending | Select-Object -First 1

                    Write-Verbose -Message "Found $($ExistingISOListCount) existing ISO image(s) within `"$($ISODirectory.FullName)`". The download will be skipped. [Latest Existing ISO Image: $($ISOPath.FullName)]" -Verbose
                }

              Default
                {
                    $ISOPath = [System.IO.FileInfo][System.IO.Path]::Combine($ISODirectory.FullName, [System.IO.Path]::GetFileName($DownloadURL.OriginalString))

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

      #region Define the operating system display name mapping table (Unmapped folder names fall through to the folder name as-is)
        $OSDisplayNameTable = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
          $OSDisplayNameTable['xp'] = 'Windows XP'
          $OSDisplayNameTable['w7'] = 'Windows 7'
          $OSDisplayNameTable['w8'] = 'Windows 8'
          $OSDisplayNameTable['w8.1'] = 'Windows 8.1'
          $OSDisplayNameTable['w10'] = 'Windows 10'
          $OSDisplayNameTable['w11'] = 'Windows 11'
          $OSDisplayNameTable['2k3'] = 'Windows Server 2003'
          $OSDisplayNameTable['2k8'] = 'Windows Server 2008'
          $OSDisplayNameTable['2k8R2'] = 'Windows Server 2008 R2'
          $OSDisplayNameTable['2k12'] = 'Windows Server 2012'
          $OSDisplayNameTable['2k12R2'] = 'Windows Server 2012 R2'
          $OSDisplayNameTable['2k16'] = 'Windows Server 2016'
          $OSDisplayNameTable['2k19'] = 'Windows Server 2019'
          $OSDisplayNameTable['2k22'] = 'Windows Server 2022'
          $OSDisplayNameTable['2k25'] = 'Windows Server 2025'
      #endregion

      #region Define the processor architecture display name mapping table (Unmapped folder names fall through to the folder name as-is)
        $ArchitectureDisplayNameTable = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
          $ArchitectureDisplayNameTable['amd64'] = 'X64'
          $ArchitectureDisplayNameTable['x64'] = 'X64'
          $ArchitectureDisplayNameTable['x86'] = 'X86'
          $ArchitectureDisplayNameTable['i386'] = 'X86'
          $ArchitectureDisplayNameTable['ARM64'] = 'ARM64'
          $ArchitectureDisplayNameTable['ARM'] = 'ARM'
      #endregion

      #region Retrieve the existing DeployR content item list one time before processing
        $ExistingContentItemList = Get-DeployRContentItem
      #endregion

      #region Build the driver pack definition list (One definition per included operating system, plus the generic Windows PE driver pack)
        $DriverPackList = New-Object -TypeName 'System.Collections.Generic.List[PSObject]'

        #region Define one driver pack per included operating system
          ForEach ($OSName In $IncludedOSNameList)
            {
                #Determine the operating system display name (Unmapped folder names fall through to the folder name as-is)
                  Switch ($OSDisplayNameTable.Contains($OSName))
                    {
                        {($_ -eq $True)}
                          {
                              [String]$OSDisplayName = $OSDisplayNameTable[$OSName]
                          }

                        Default
                          {
                              [String]$OSDisplayName = $OSName
                          }
                    }

                $OSArchitectureDirectoryList = @($ArchitectureDirectoryList | Where-Object {($_.Parent.Name -ieq $OSName)})

                $OSArchitectureDisplayNameList = New-Object -TypeName 'System.Collections.Generic.List[System.String]'

                ForEach ($OSArchitectureName In @($OSArchitectureDirectoryList | ForEach-Object {$_.Name} | Sort-Object -Unique))
                  {
                      Switch ($ArchitectureDisplayNameTable.Contains($OSArchitectureName))
                        {
                            {($_ -eq $True)}
                              {
                                  [String]$OSArchitectureDisplayName = $ArchitectureDisplayNameTable[$OSArchitectureName]
                              }

                            Default
                              {
                                  [String]$OSArchitectureDisplayName = $OSArchitectureName
                              }
                        }

                      Switch ($OSArchitectureDisplayNameList -icontains $OSArchitectureDisplayName)
                        {
                            {($_ -eq $False)}
                              {
                                  $OSArchitectureDisplayNameList.Add($OSArchitectureDisplayName)
                              }
                        }
                  }

                [String]$ArchitectureDisplayName = $OSArchitectureDisplayNameList -Join ' - '

                $DriverPackTagList = New-Object -TypeName 'System.Collections.Generic.List[System.String]'
                  $DriverPackTagList.Add('Drivers')
                  $DriverPackTagList.Add('VirtIO')
                  $DriverPackTagList.Add($DriverManufacturer)
                  $DriverPackTagList.Add($DriverModel)
                  $DriverPackTagList.Add($OSDisplayName)
                  $DriverPackTagList.AddRange($OSArchitectureDisplayNameList)

                $DriverPackProperties = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                  $DriverPackProperties.PackName = $OSName
                  $DriverPackProperties.DisplayName = $OSDisplayName
                  $DriverPackProperties.ContentName = "$($ContentNamePrefix) - $($OSDisplayName) - $($ArchitectureDisplayName)"
                  $DriverPackProperties.Description = "$($OSDisplayName) [$($OSName)]"
                  $DriverPackProperties.ArchitectureDisplayName = $ArchitectureDisplayName
                  $DriverPackProperties.ArchitectureDirectoryList = $OSArchitectureDirectoryList
                  $DriverPackProperties.PreserveOperatingSystemSegment = $True
                  $DriverPackProperties.StagingPathPrefix = ''
                  $DriverPackProperties.TagList = $DriverPackTagList

                $DriverPackList.Add((New-Object -TypeName 'System.Management.Automation.PSObject' -Property ($DriverPackProperties)))
            }
        #endregion

        #region Define the generic Windows PE driver pack (The drivers are sourced from the matching operating system folder(s) but no operating system identity is carried into the name, the description, the tags, or the staged folder structure)
          Switch ($SkipWinPEDriverPack.IsPresent)
            {
                {($_ -eq $False)}
                  {
                      $WinPEArchitectureDirectoryList = @($ArchitectureDirectoryList | Where-Object {($_.Parent.Name -imatch $WinPESourceOSExpression.ToString())})

                      Switch ($WinPEArchitectureDirectoryList.Count -gt 0)
                        {
                            {($_ -eq $True)}
                              {
                                  $WinPEArchitectureDisplayNameList = New-Object -TypeName 'System.Collections.Generic.List[System.String]'

                                  ForEach ($WinPEArchitectureName In @($WinPEArchitectureDirectoryList | ForEach-Object {$_.Name} | Sort-Object -Unique))
                                    {
                                        Switch ($ArchitectureDisplayNameTable.Contains($WinPEArchitectureName))
                                          {
                                              {($_ -eq $True)}
                                                {
                                                    [String]$WinPEArchitectureDisplayName = $ArchitectureDisplayNameTable[$WinPEArchitectureName]
                                                }

                                              Default
                                                {
                                                    [String]$WinPEArchitectureDisplayName = $WinPEArchitectureName
                                                }
                                          }

                                        Switch ($WinPEArchitectureDisplayNameList -icontains $WinPEArchitectureDisplayName)
                                          {
                                              {($_ -eq $False)}
                                                {
                                                    $WinPEArchitectureDisplayNameList.Add($WinPEArchitectureDisplayName)
                                                }
                                          }
                                    }

                                  [String]$WinPEArchitectureDisplayNameJoined = $WinPEArchitectureDisplayNameList -Join ' - '

                                  $WinPETagList = New-Object -TypeName 'System.Collections.Generic.List[System.String]'
                                    $WinPETagList.Add('Drivers')
                                    $WinPETagList.Add('VirtIO')
                                    $WinPETagList.Add($DriverManufacturer)
                                    $WinPETagList.Add($DriverModel)
                                    $WinPETagList.Add($WinPEDisplayName)
                                    $WinPETagList.Add('Boot Image')
                                    $WinPETagList.AddRange($WinPEArchitectureDisplayNameList)

                                  $WinPEDriverPackProperties = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                    $WinPEDriverPackProperties.PackName = $WinPEDisplayName
                                    $WinPEDriverPackProperties.DisplayName = $WinPEDisplayName
                                    $WinPEDriverPackProperties.ContentName = "$($ContentNamePrefix) - $($WinPEDisplayName) - $($WinPEArchitectureDisplayNameJoined)"
                                    $WinPEDriverPackProperties.Description = "Generic boot image drivers. Additional drivers may be added to this content item."
                                    $WinPEDriverPackProperties.ArchitectureDisplayName = $WinPEArchitectureDisplayNameJoined
                                    $WinPEDriverPackProperties.ArchitectureDirectoryList = $WinPEArchitectureDirectoryList
                                    $WinPEDriverPackProperties.PreserveOperatingSystemSegment = $False
                                    $WinPEDriverPackProperties.StagingPathPrefix = $DriverManufacturer
                                    $WinPEDriverPackProperties.TagList = $WinPETagList

                                  $DriverPackList.Add((New-Object -TypeName 'System.Management.Automation.PSObject' -Property ($WinPEDriverPackProperties)))

                                  Write-Verbose -Message "The generic $($WinPEDisplayName) driver pack will be created from $($WinPEArchitectureDirectoryList.Count) driver folder(s). [Source Expression: $($WinPESourceOSExpression.ToString())] [Architecture: $($WinPEArchitectureDisplayNameJoined)]" -Verbose
                              }

                            Default
                              {
                                  Write-Warning -Message "No driver folders matched the `"$($WinPESourceOSExpression.ToString())`" source expression, therefore the generic $($WinPEDisplayName) driver pack will be skipped."
                              }
                        }
                  }

                Default
                  {
                      Write-Verbose -Message "The generic $($WinPEDisplayName) driver pack will be skipped because the `"-SkipWinPEDriverPack`" parameter was specified." -Verbose
                  }
            }
        #endregion

        Write-Verbose -Message "$($DriverPackList.Count) driver pack(s) will be processed: $(($DriverPackList | ForEach-Object {$_.PackName}) -Join ', ')" -Verbose
      #endregion

      #region Create each driver pack and publish it as its own DeployR content item version
        $DriverPackListCounter = 1

        For ($DriverPackListIndex = 0; $DriverPackListIndex -lt $DriverPackList.Count; $DriverPackListIndex++)
          {
              Try
                {
                    $DriverPack = $DriverPackList[$DriverPackListIndex]

                    $OSArchitectureDirectoryList = @($DriverPack.ArchitectureDirectoryList)

                    $ProgressPercentage = [System.Math]::Round((($DriverPackListCounter / $DriverPackList.Count) * 100), 2)

                    $WriteProgressParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                      $WriteProgressParameters.Id = 1
                      $WriteProgressParameters.Activity = "Processing driver pack $($DriverPackListCounter) of $($DriverPackList.Count). Please Wait... [Driver Pack: $($DriverPack.PackName)]"
                      $WriteProgressParameters.Status = "Progress Percentage: $($ProgressPercentage)%"
                      $WriteProgressParameters.PercentComplete = $ProgressPercentage
                      $WriteProgressParameters.CurrentOperation = $DriverPack.PackName

                    Write-Progress @WriteProgressParameters

                    Write-Verbose -Message "Attempting to process driver pack $($DriverPackListCounter) of $($DriverPackList.Count). Please Wait... [Driver Pack: $($DriverPack.DisplayName) ($($DriverPack.PackName))] [Architecture: $($DriverPack.ArchitectureDisplayName)]" -Verbose

                    #region Stage the matching driver folders into the driver pack folder
                      $DriverPackDirectory = [System.IO.DirectoryInfo][System.IO.Path]::Combine($DriverPacksDirectory.FullName, "$($DriverPack.PackName)")

                      Switch ([System.IO.Directory]::Exists($DriverPackDirectory.FullName))
                        {
                            {($_ -eq $True)}
                              {
                                  $Null = Remove-Item -Path ($DriverPackDirectory.FullName) -Recurse -Force -Confirm:$False
                              }
                        }

                      $Null = [System.IO.Directory]::CreateDirectory($DriverPackDirectory.FullName)

                      $StagedRelativeDirectoryPathList = New-Object -TypeName 'System.Collections.Generic.List[System.String]'

                      For ($OSArchitectureDirectoryListIndex = 0; $OSArchitectureDirectoryListIndex -lt $OSArchitectureDirectoryList.Count; $OSArchitectureDirectoryListIndex++)
                        {
                            $OSArchitectureDirectory = $OSArchitectureDirectoryList[$OSArchitectureDirectoryListIndex]

                            #Determine the relative path beneath the driver pack folder
                              Switch ($DriverPack.PreserveOperatingSystemSegment)
                                {
                                    {($_ -eq $True)}
                                      {
                                          #Preserve the full path below the extracted directory (For example, pvpanic\w11\amd64)
                                            [String]$RelativeDirectoryPath = $OSArchitectureDirectory.FullName.Substring($ExtractedDirectory.FullName.Length).TrimStart([System.IO.Path]::DirectorySeparatorChar)
                                      }

                                    Default
                                      {
                                          #Drop the operating system segment so that the staged structure carries no operating system identity (For example, pvpanic\amd64)
                                            [String]$RelativeDirectoryPath = [System.IO.Path]::Combine("$($OSArchitectureDirectory.Parent.Parent.Name)", "$($OSArchitectureDirectory.Name)")
                                      }
                                }

                            #Place the drivers beneath the staging path prefix so that additional vendors can be added alongside them later (For example, Proxmox\pvpanic\amd64)
                              Switch ([String]::IsNullOrEmpty("$($DriverPack.StagingPathPrefix)"))
                                {
                                    {($_ -eq $False)}
                                      {
                                          [String]$RelativeDirectoryPath = [System.IO.Path]::Combine("$($DriverPack.StagingPathPrefix)", $RelativeDirectoryPath)
                                      }
                                }

                            #Skip a relative path that has already been staged so that overlapping source folders remain deterministic
                              Switch ($StagedRelativeDirectoryPathList -icontains $RelativeDirectoryPath)
                                {
                                    {($_ -eq $True)}
                                      {
                                          Write-Verbose -Message "Skipping `"$($OSArchitectureDirectory.FullName)`" because `"$($RelativeDirectoryPath)`" has already been staged." -Verbose

                                          Continue
                                      }
                                }

                              $StagedRelativeDirectoryPathList.Add($RelativeDirectoryPath)

                              $StagingProgressPercentage = [System.Math]::Round(((($OSArchitectureDirectoryListIndex + 1) / $OSArchitectureDirectoryList.Count) * 100), 2)

                              $WriteProgressParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                $WriteProgressParameters.Id = 2
                                $WriteProgressParameters.ParentId = 1
                                $WriteProgressParameters.Activity = "Staging driver folder $($OSArchitectureDirectoryListIndex + 1) of $($OSArchitectureDirectoryList.Count). Please Wait... [Driver Pack: $($DriverPack.PackName)]"
                                $WriteProgressParameters.Status = "Progress Percentage: $($StagingProgressPercentage)%"
                                $WriteProgressParameters.PercentComplete = $StagingProgressPercentage
                                $WriteProgressParameters.CurrentOperation = $RelativeDirectoryPath

                              Write-Progress @WriteProgressParameters

                              $DestinationDirectory = [System.IO.DirectoryInfo][System.IO.Path]::Combine($DriverPackDirectory.FullName, $RelativeDirectoryPath)

                              $Null = [System.IO.Directory]::CreateDirectory($DestinationDirectory.FullName)

                              $Null = Copy-Item -Path "$($OSArchitectureDirectory.FullName)\*" -Destination "$($DestinationDirectory.FullName)\" -Recurse -Force
                        }

                      $WriteProgressParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                        $WriteProgressParameters.Id = 2
                        $WriteProgressParameters.ParentId = 1
                        $WriteProgressParameters.Activity = "Staging driver folders"
                        $WriteProgressParameters.Completed = $True

                      Write-Progress @WriteProgressParameters

                      Write-Verbose -Message "Staged $($StagedRelativeDirectoryPathList.Count) driver folder(s) into `"$($DriverPackDirectory.FullName)`"." -Verbose
                    #endregion

                    #region Create or reuse the DeployR content item for this driver pack
                      [String]$ContentName = "$($DriverPack.ContentName)"

                      [String]$ContentDescription = "$($DriverPack.Description)"

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
                                    $NewDeployRContentItemParameters.Description = $ContentDescription

                                  $Null = New-DeployRContentItem @NewDeployRContentItemParameters

                                  #Re-retrieve the newly created content item so that it is shaped identically to a content item retrieved from DeployR, otherwise the initial version can be published without its content attached
                                    $ContentItem = Get-DeployRContentItem | Where-Object {($_.Name -ieq $ContentName)} | Select-Object -First 1

                                    Switch ($Null -ieq $ContentItem)
                                      {
                                          {($_ -eq $True)}
                                            {
                                                Throw "The DeployR content item was created but could not be retrieved. [Name: $($ContentName)]"
                                            }
                                      }

                                  Write-Verbose -Message "The DeployR content item was created successfully. [Name: $($ContentName)] [CI ID: $($ContentItem.id)]" -Verbose

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
                                    $NewDeployRContentItemVersionParameters.Description = $ContentDescription
                                    $NewDeployRContentItemVersionParameters.DriverManufacturer = $DriverManufacturer
                                    $NewDeployRContentItemVersionParameters.DriverModel = $DriverModel
                                    $NewDeployRContentItemVersionParameters.SourceFolder = $DriverPackDirectory.FullName

                                  $NewContentItemVersion = New-DeployRContentItemVersion @NewDeployRContentItemVersionParameters

                                  #The version number is required in order to attach the content to the correct version
                                    Switch ([String]::IsNullOrEmpty("$($NewContentItemVersion.versionNo)"))
                                      {
                                          {($_ -eq $True)}
                                            {
                                                Throw "The DeployR content item version was created but no version number was returned, therefore the content cannot be attached. [Name: $($ContentName)]"
                                            }
                                      }

                                  $UpdateDeployRContentItemContentParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
                                    $UpdateDeployRContentItemContentParameters.ContentId = $ContentItem.id
                                    $UpdateDeployRContentItemContentParameters.ContentVersion = $NewContentItemVersion.versionNo
                                    $UpdateDeployRContentItemContentParameters.SourceFolder = $DriverPackDirectory.FullName

                                  $ContentItemVersion = Update-DeployRContentItemContent @UpdateDeployRContentItemContentParameters

                                  #Confirm that the content was actually attached to the version so that an empty version is never reported as a success
                                    Switch ([Int64]$ContentItemVersion.contentSize -gt 0)
                                      {
                                          {($_ -eq $True)}
                                            {
                                                Write-Verbose -Message "The driver pack upload completed successfully. [Name: $($ContentName)] [CI ID: $($ContentItemVersion.contentItemId)] [Version: $($ContentItemVersion.versionNo)] [Size: $([System.Math]::Round($ContentItemVersion.contentSize / 1MB, 2)) MB]" -Verbose
                                            }

                                          Default
                                            {
                                                Throw "The DeployR content item version was published but no content is attached to it. [Name: $($ContentName)] [CI ID: $($ContentItem.id)] [Version: $($NewContentItemVersion.versionNo)]"
                                            }
                                      }
                              }

                            Default
                              {
                                  Write-Verbose -Message "The content item already exists and the `"-AddNewVersions`" parameter was not specified. The version publish will be skipped. [Name: $($ContentName)]" -Verbose
                              }
                        }
                    #endregion

                    #region Apply the tag list to the content item and apply the tag list and the desired status to all of its versions
                      $ContentItemTagList = $DriverPack.TagList

                      Write-Verbose -Message "Attempting to apply $($ContentItemTagList.Count) tag(s) and the `"$($ContentItemVersionStatus)`" version status to the content item and all of its versions. Please Wait... [Name: $($ContentName)] [Tags: $($ContentItemTagList -Join ', ')]" -Verbose

                      $ContentItemMetadata = Get-DeployRMetaData -Type ContentItem | Where-Object {($_.id -eq $ContentItem.id)} | Select-Object -First 1

                      Switch ($Null -ine $ContentItemMetadata)
                        {
                            {($_ -eq $True)}
                              {
                                  #region Apply the missing tags to the content item
                                    $MissingContentItemTagList = New-Object -TypeName 'System.Collections.Generic.List[System.String]'

                                    ForEach ($ContentItemTag In $ContentItemTagList)
                                      {
                                          Switch ($ContentItemMetadata.tags -icontains $ContentItemTag)
                                            {
                                                {($_ -eq $False)}
                                                  {
                                                      $MissingContentItemTagList.Add($ContentItemTag)
                                                  }
                                            }
                                      }

                                    Switch ($MissingContentItemTagList.Count -gt 0)
                                      {
                                          {($_ -eq $True)}
                                            {
                                                $UpdatedContentItemTagList = New-Object -TypeName 'System.Collections.Generic.List[System.String]'

                                                ForEach ($ExistingContentItemTag In $ContentItemMetadata.tags)
                                                  {
                                                      Switch ([String]::IsNullOrEmpty($ExistingContentItemTag))
                                                        {
                                                            {($_ -eq $False)}
                                                              {
                                                                  $UpdatedContentItemTagList.Add($ExistingContentItemTag)
                                                              }
                                                        }
                                                  }

                                                $UpdatedContentItemTagList.AddRange($MissingContentItemTagList)

                                                $ContentItemMetadata.tags = $UpdatedContentItemTagList.ToArray()

                                                $Null = Set-DeployRMetadata -Type ContentItem -Object $ContentItemMetadata

                                                Write-Verbose -Message "Added $($MissingContentItemTagList.Count) tag(s) to the content item. [Name: $($ContentName)] [Added Tags: $($MissingContentItemTagList -Join ', ')]" -Verbose
                                            }

                                          Default
                                            {
                                                Write-Verbose -Message "All tags already exist on the content item. [Name: $($ContentName)]" -Verbose
                                            }
                                      }
                                  #endregion

                                  #region Apply the missing tags and the desired status to each content item version (Both changes are applied within a single update per version)
                                    $ContentItemVersionList = New-Object -TypeName 'System.Collections.Generic.List[PSObject]'

                                    ForEach ($ContentItemVersionEntry In $ContentItemMetadata.versions)
                                      {
                                          Switch ($Null -ine $ContentItemVersionEntry)
                                            {
                                                {($_ -eq $True)}
                                                  {
                                                      $ContentItemVersionList.Add($ContentItemVersionEntry)
                                                  }
                                            }
                                      }

                                    For ($ContentItemVersionListIndex = 0; $ContentItemVersionListIndex -lt $ContentItemVersionList.Count; $ContentItemVersionListIndex++)
                                      {
                                          $ContentItemVersionMetadata = $ContentItemVersionList[$ContentItemVersionListIndex]

                                          $ContentItemVersionChangeList = New-Object -TypeName 'System.Collections.Generic.List[System.String]'

                                          #region Determine the missing tags
                                            $MissingContentItemVersionTagList = New-Object -TypeName 'System.Collections.Generic.List[System.String]'

                                            ForEach ($ContentItemTag In $ContentItemTagList)
                                              {
                                                  Switch ($ContentItemVersionMetadata.tags -icontains $ContentItemTag)
                                                    {
                                                        {($_ -eq $False)}
                                                          {
                                                              $MissingContentItemVersionTagList.Add($ContentItemTag)
                                                          }
                                                    }
                                              }

                                            Switch ($MissingContentItemVersionTagList.Count -gt 0)
                                              {
                                                  {($_ -eq $True)}
                                                    {
                                                        $UpdatedContentItemVersionTagList = New-Object -TypeName 'System.Collections.Generic.List[System.String]'

                                                        ForEach ($ExistingContentItemVersionTag In $ContentItemVersionMetadata.tags)
                                                          {
                                                              Switch ([String]::IsNullOrEmpty($ExistingContentItemVersionTag))
                                                                {
                                                                    {($_ -eq $False)}
                                                                      {
                                                                          $UpdatedContentItemVersionTagList.Add($ExistingContentItemVersionTag)
                                                                      }
                                                                }
                                                          }

                                                        $UpdatedContentItemVersionTagList.AddRange($MissingContentItemVersionTagList)

                                                        $ContentItemVersionMetadata.tags = $UpdatedContentItemVersionTagList.ToArray()

                                                        $ContentItemVersionChangeList.Add("Added Tags: $($MissingContentItemVersionTagList -Join ', ')")
                                                    }
                                              }
                                          #endregion

                                          #region Determine whether the version status requires an update
                                            [String]$CurrentContentItemVersionStatus = "$($ContentItemVersionMetadata.status)"

                                            Switch ($CurrentContentItemVersionStatus -ine $ContentItemVersionStatus)
                                              {
                                                  {($_ -eq $True)}
                                                    {
                                                        $ContentItemVersionMetadata.status = $ContentItemVersionStatus

                                                        $ContentItemVersionChangeList.Add("Status: $($CurrentContentItemVersionStatus) -> $($ContentItemVersionStatus)")
                                                    }
                                              }
                                          #endregion

                                          #region Apply every pending change within a single update
                                            Switch ($ContentItemVersionChangeList.Count -gt 0)
                                              {
                                                  {($_ -eq $True)}
                                                    {
                                                        $Null = Set-DeployRMetadata -Type ContentItemVersion -Object $ContentItemVersionMetadata

                                                        Write-Verbose -Message "Updated content item version $($ContentItemVersionMetadata.versionNo). [Name: $($ContentName)] [$($ContentItemVersionChangeList -Join '] [')]" -Verbose
                                                    }

                                                  Default
                                                    {
                                                        Write-Verbose -Message "Content item version $($ContentItemVersionMetadata.versionNo) is already tagged and already has the `"$($ContentItemVersionStatus)`" status. [Name: $($ContentName)]" -Verbose
                                                    }
                                              }
                                          #endregion
                                      }
                                  #endregion
                              }

                            Default
                              {
                                  Write-Warning -Message "The content item metadata could not be retrieved, therefore the tags and the version status could not be applied. [Name: $($ContentName)]"
                              }
                        }
                    #endregion
                }
              Catch
                {
                    Write-Warning -Message "The `"$($DriverPack.PackName)`" driver pack could not be processed. [Error: $($_.Exception.Message)]"
                }
              Finally
                {
                    $DriverPackListCounter++
                }
          }

        $WriteProgressParameters = New-Object -TypeName 'System.Collections.Specialized.OrderedDictionary'
          $WriteProgressParameters.Id = 1
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
