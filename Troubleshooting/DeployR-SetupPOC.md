# Guide for Testing Task Sequences

This is for once you've got DeployR setup, and you just want to kick the tires to ensure all is working. 

## Pre-reqs for the Test Cases

- DeployR server setup and configured, able to access all the areas of DeployR in the dashboard, and successfully generated boot media.. 
  - WinPE Boot Media Generated: [Generate Windows PE Boot Images](https://documentation.2pintsoftware.com/deployr/generate-windows-pe-boot-images)
- Everything else can be created later along the way, but things to consider building ahead of time:
  - Content Item -> Operating System -> Import the install.wim from Windows 11
  - Content Item ->

## Start Simple

Using the built in "Windows bare metal from cloud" template, create a task sequence.  This template will have enough pre-created for you to Test OSD.  Boot a VM using the generated ISO file, then select the "Windows bare metal from cloud" task sequence and watch it run.

Now, once you've run that successfully, start adding things one, or two at a time, and re-run.  You can also during this time, upload your own Windows install.wim file to an Operating System content item, then test the Windows bare metal task sequence using your own content.

## Test Cases starting on Hyper-V
Using Hyper-V, create a VM for testing, follow this guidance: [Bare Metal with Hyper-V](https://documentation.2pintsoftware.com/deployr/bare-metal-with-hyper-v)

- Create new Task Sequence from Template -> "Windows bare metal from cloud" - Run from VM
  - Test Success / Fail
- Test Enabling Admin and Setting Password, Add Steps 
  - [Enable Administrator Account](https://documentation.2pintsoftware.com/deployr/reference/step-definitions/enable-administrator-account) at the end of the Task Sequence
  - [Set variable](https://documentation.2pintsoftware.com/deployr/reference/step-definitions/set-variable) just BEFORE the Enable Administrator account step
    - Variable Name: AdminPassword
    - Variable value: P@ssw0rd (or whatever you want it to be)
  - Run test again, confirm you can now login with the administartor account using the password
    - Test Success / Fail
- Create an Application Content Type, start with someone simple like 7zip
  - Download: https://github.com/ip7z/7zip/releases/download/26.00/7z2600-x64.msi to Downloads
  - Content Items -> Add -> Name: 7zip | Purpose: Application | Type: Folder  | Open after creation -> Save -> New version:
    - Install command line: msiexec.exe /i "7z2600-x64.msi" /quiet /norestart
    - Choose file -> Choose the 7zip MSI from the download's folder
  - In task sequence, add application an pick 7Zip, and re-run confirming it installs.
  - Run OSD again, confirm the application installed
    - Test Success / Fail 
- Test running PowerShell Script in Task Sequence
  - In the task sequence editor, we're going to use a script example from the docs to set the computer name.  This will need to be done before the Apply OS step, so in the task sequence editor, add a powershell step to your task sequence and move it before the Apply Operating System step.  Then go here [Simple Prompt for Computer Name](https://documentation.2pintsoftware.com/deployr/powershell-modules/simple-prompt-for-computer-name) and copy the script and paste it in to the script area of the PowerShell Step.
  - Run OSD again, enter the desired name at the prompt, then confirm the name is set at the end
    - Test Success / Fail
  

## Continue Testing on Physical Device

At this point we've confirmed everything is working on a virtual machine, so we'll take what we've build, change nothing and test on a physical.  You can either use iPXE or Flash Drive to boot the physical device to DeployR.  The task sequence template "Windows baremetal from cloud" includes the step "Inject drivers from Cloud", which will automatically detect and download the required drivers.  