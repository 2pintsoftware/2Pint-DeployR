# DeployR Pre-Req Install Scripts

This folder will contain scripts to automate the installation of Pre-reqs
You can open the script and paste them into your environment, or run the powershell command listed under the script directly in Elevated PowerShell console: iex (irm URL to script)


## Order

- Install-PowerShell74X.ps1
  - iex (irm <https://raw.githubusercontent.com/2pintsoftware/2Pint-DeployR/refs/heads/main/Pre-ReqInstalls/Install-PowerShell74X.ps1>)
- Install-DotNetRuntimes80X.ps1
  - iex (irm <https://raw.githubusercontent.com/2pintsoftware/2Pint-DeployR/refs/heads/main/Pre-ReqInstalls/Install-DotNetRuntimes80X.ps1>)
- Install-WinFeatures.ps1
  - iex (irm <https://raw.githubusercontent.com/2pintsoftware/2Pint-DeployR/refs/heads/main/Pre-ReqInstalls/Install-WinFeatures.ps1>)
- Install-SQLExpress2025.ps1
  - iex (irm <https://raw.githubusercontent.com/2pintsoftware/2Pint-DeployR/refs/heads/main/Pre-ReqInstalls/Install-SQLExpress2025.ps1>)
- Install-SQL2025CU.ps1
  - iex (irm <https://raw.githubusercontent.com/2pintsoftware/2Pint-DeployR/refs/heads/main/Pre-ReqInstalls/Install-SQL2025CU.ps1>)
  - Reboot
- Install-WindowsADK.ps1
  - iex (irm <https://raw.githubusercontent.com/2pintsoftware/2Pint-DeployR/refs/heads/main/Pre-ReqInstalls/Install-WindowsADK.ps1>)
- Install-WindowsADKWinPE.ps1
  - iex (irm <https://raw.githubusercontent.com/2pintsoftware/2Pint-DeployR/refs/heads/main/Pre-ReqInstalls/Install-WindowsADKWinPE.ps1>)
- Install-VCRedist-x64.ps1
  - iex (irm <https://raw.githubusercontent.com/2pintsoftware/2Pint-DeployR/refs/heads/main/Pre-ReqInstalls/Install-VCRedist-x64.ps1>)
- Configure-SQLExpress.ps1
  - iex (irm <https://raw.githubusercontent.com/2pintsoftware/2Pint-DeployR/refs/heads/main/Pre-ReqInstalls/Configure-SQLExpress.ps1>)
- Install-SSMS22.ps1
  - iex (irm <https://raw.githubusercontent.com/2pintsoftware/2Pint-DeployR/refs/heads/main/Pre-ReqInstalls/Install-SMSS22.ps1>)
  
## 2Pint Software Installs

- 2PXE
- iPXE WS
- StifleR Server
- StifleR Dashboard
- DeployR
- StifleR WMIAgent | OPTIONAL
- StifleR ActionHub | OPTIONAL


## In Action

Here are a couple captures from running in the elevated PS Console:

![WinFeatures](./media/WinFeatures.png)

![SQL2025CU](./media/SQL2025CU.png)

After, you should have all your pre-reqs

![Programs](./media/Programs.png)