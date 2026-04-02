# Guide for Testing Task Sequences

This is for once you've got DeployR setup, and you just want to kick the tires to ensure all is working. 

## Start Simple

Using the built in "Windows bare metal from cloud" template, create a task sequence.  This template will have enough pre-created for you to Test OSD.  Boot a VM using the generated ISO file, then select the "Windows bare metal from cloud" task sequence and watch it run.

Now, once you've run that successfully, start adding things one, or two at a time, and re-run.  You can also during this time, upload your own Windows install.wim file to an Operating System content item, then test the Windows bare metal task sequence using your own content.

## Check List

- Create new Task Sequence from Template -> "Windows bare metal from cloud" - Run from VM
  - Test Success / Fail
- Add Steps 
  - [Enable Administrator Account](https://documentation.2pintsoftware.com/deployr/reference/step-definitions/enable-administrator-account) at the end of the Task Sequence
  - [Set variable](https://documentation.2pintsoftware.com/deployr/reference/step-definitions/set-variable) just BEFORE the Enable Administrator account step
    - Variable Name: AdminPassword
    - Variable value: P@ssw0rd (or whatever you want it to be)
- Run test again, confirm you can now login with the administartor account using the password
  - Test Success / Fail
  - 