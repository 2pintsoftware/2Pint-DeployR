# 2Pint Software Install Scripts

This section will cover installing the 2Pint software in a simple automated method designed for DeployR Integration (Non ConfigMgr)

It will leverage using 2PintSoftware self signed certs, which is great for a POC, then you can break it later with your own certs if you like.  The FQDN of your sever will be derived from the hostname + DNS Suffix.  If you do not have a DNS Suffix, you'll want to update the Install-2PXE.ps1 script to create your own FQDN.

Once you've done your pre-reqs... come here...

## Assumptions

- You downloaded the DeployR Suite files to your Downloads folder in a subfolder called "DeployRSuite"
- It will contain the 4 zip files from 2Pint Software
  - 2Pint.2PXE.Installer64.VERSION.zip
  - iPXEAnywhere.Installer64.Version.zip
  - StifleR-30.VERSION.zip
    - This contains several more zip files
  - DeployR-VERSION.zip
  
If you've done, that, run the Extract-2PintZips.ps1 which will expand all of those zip files into a subfolder called "Extracted" which is where rest of the scripts will look to find the installer files.

> [!NOTE]
> All of the MSI files should be located here: "$env:USERPROFILE\Downloads\DeployRSuite\Extracted"  If you extract them manually, that's fine, just get extract them to that path, then continue with the install scripts.

Order of Install:
- 2PXE
- iPXE WS
- StifleR Server
- StifleR Dashboard
- DeployR
- StifleR WMIAgent | OPTIONAL
- StifleR ActionHub | OPTIONAL

## Scripts for Automated Install

You can download the scripts and run them, or run the iex (irm) commands directly assuming you don't block GitHub.  Run from the Elevated PS7 Console.

- Install-2PXE.ps1
```
iex (irm https://raw.githubusercontent.com/2pintsoftware/2Pint-DeployR/refs/heads/main/Installs/2PintSoftware/Install-2PXE.ps1)
```

- Install-iPXEWS.ps1
```
iex (irm https://raw.githubusercontent.com/2pintsoftware/2Pint-DeployR/refs/heads/main/Installs/2PintSoftware/Install-iPXEWS.ps1)
```

- Create-IIS443Binding.ps1 (If using IIS as your Dashboard)
```
iex (irm https://raw.githubusercontent.com/2pintsoftware/2Pint-DeployR/refs/heads/main/Installs/2PintSoftware/Create-IIS443Binding.ps1)
```

- Install-StifleRComponents.ps1
```
iex (irm https://raw.githubusercontent.com/2pintsoftware/2Pint-DeployR/refs/heads/main/Installs/2PintSoftware/Install-StifleRComponents.ps1)
```

- Setup-DeployR.ps1
```
iex (irm https://raw.githubusercontent.com/2pintsoftware/2Pint-DeployR/refs/heads/main/Installs/2PintSoftware/Setup-DeployR.ps1)
```


- PopulateDeployRExtras.ps1 - NOTE: Run on Server from Elevated PS7 Terminal.
```
iex (irm https://raw.githubusercontent.com/2pintsoftware/2Pint-DeployR/refs/heads/main/Installs/2PintSoftware/PopulateDeployRExtras.ps1)
```
