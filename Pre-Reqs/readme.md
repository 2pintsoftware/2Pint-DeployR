# DeployR Pre-Req Install Scripts

This folder will contain scripts to automate the installation of Pre-reqs
You can open the script and paste them into your environment, or run the powershell command listed under the script directly in Elevated PowerShell console: iex (irm URL to script)

## Order

- Install-PowerShell74X.ps1
  - iex (irm <https://raw.githubusercontent.com/2pintsoftware/2Pint-DeployR/refs/heads/main/Pre-Req/Install-PowerShell74X.ps1>)
- Install-DotNetRuntimes80X.ps1
  - iex (irm <https://raw.githubusercontent.com/2pintsoftware/2Pint-DeployR/refs/heads/main/Pre-Req/Install-DotNetRuntimes80X.ps1>)
- Install-WinFeatures.ps1
  - iex (irm <https://raw.githubusercontent.com/2pintsoftware/2Pint-DeployR/refs/heads/main/Pre-Req/Install-WinFeatures.ps1>)
- Install-SQLExpress2025.ps1
  - iex (irm <https://raw.githubusercontent.com/2pintsoftware/2Pint-DeployR/refs/heads/main/Pre-Req/Install-SQLExpress2025.ps1>)
- Install-SQL2025CU.ps1
  - iex (irm <https://raw.githubusercontent.com/2pintsoftware/2Pint-DeployR/refs/heads/main/Pre-Req/Install-SQL2025CU.ps1>)
  - Reboot
- Install-WindowsADK.ps1
  - iex (irm <https://raw.githubusercontent.com/2pintsoftware/2Pint-DeployR/refs/heads/main/Pre-Req/Install-WindowsADK.ps1>)
- Install-WindowsADKWinPE.ps1
  - iex (irm <https://raw.githubusercontent.com/2pintsoftware/2Pint-DeployR/refs/heads/main/Pre-Req/Install-WindowsADKWinPE.ps1>)
- Install-VCRedist-x64.ps1
  - iex (irm <https://raw.githubusercontent.com/2pintsoftware/2Pint-DeployR/refs/heads/main/Pre-Req/Install-VCRedist-x64.ps1>)
- Configure-SQLExpress.ps1
  - iex (irm <https://raw.githubusercontent.com/2pintsoftware/2Pint-DeployR/refs/heads/main/Pre-Req/Configure-SQLExpress.ps1>)
- Install-SSMS22.ps1
  - iex (irm <https://raw.githubusercontent.com/2pintsoftware/2Pint-DeployR/refs/heads/main/Pre-Req/Install-SMSS22.ps1>)
  
## 2Pint Software Installs

This software is available to 2Pint Software DeployR Customers, if you don't have access to the downloads, reach out to your sales representative, or send an email to <support@2pintsoftware.com>.

For a DeployR Server, this would be the install order of 2Pint Software components:

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
