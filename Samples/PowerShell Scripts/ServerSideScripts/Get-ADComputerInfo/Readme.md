# Grabbing Info for AD Computer

This came about so I could find if a computer was already in AD and find specific attributes about the device.
When run, it will grab the following information and then create corripsonding DeployR variables in the task sequence.

You can then use this information to help automate other processes.

| Variable | Value |
|---|---|
| ADComputerCanonicalName | 2P.garytown.com/2PintTown/Workstations/VM-2CM-800G6-02 |
| ADComputerDescription |  |
| ADComputerDistinguishedName | CN=VM-2CM-800G6-02,OU=Workstations,OU=2PintTown,DC=2P,DC=garytown,DC=com |
| ADComputerDNSHostName | VM-2CM-800G6-02.2P.garytown.com |
| ADComputerEnabled | True |
| ADComputerExists | True |
| ADComputerLastLogonTimestamp | 11/18/2025 01:04:02 |
| ADComputerManagedBy |  |
| ADComputerManagedByDN |  |
| ADComputerName | VM-2CM-800G6-02 |
| ADComputerObjectOwner | 2P\CM_DJ |
| ADComputerOperatingSystem | Windows 11 Enterprise |
| ADComputerOperatingSystemVersion | 10.0 (22631) |
| ADComputerOU | Workstations/2PintTown |
| ADComputerParentDN | OU=Workstations,OU=2PintTown,DC=2P,DC=garytown,DC=com |
| ADComputerQueryName | VM-2CM-800G6-02 |
| ADComputerSamAccountName | VM-2CM-800G6-02$ |
| ADComputerWhenCreated | 08/26/2024 20:53:03 |
| ADDomainUsed | 2P.garytown.com |
| ADLookupError |  |

## Example

Using this data to grab the OU to feed into the Offline Domain Join step:

First run the script that pulls back the information
![GetInfo01](media\GetInfo01.png)

Second run a PowerShell step that will set the OU based on the condition that the computer existed.
```PowerShell
$TSENV:OU = $TSENV:ADCOMPUTERPARENTDN
```
![GetInfo02](media\GetInfo02.png)
Condition: Query | ADComputerExists | Equals | TRUE
![GetInfo03](media\GetInfo03.png)


## Demo

This machine is currently in the RetailPOS OU, we'll start a reimage of the device.

First you can see the computer already exists in the RetailPOS OU, and that was created at 11:04:36AM and the last time I reimaged was at 12:33:19PM on the same day, hence the Modified date.
![GetInfo04](media\GetInfo04.png)

Next during the OSD Process, it ran the server side script and pushed back all these variables to make available to the Task Sequence
![GetInfo05](media\GetInfo05.png)

Then based on the condition we set, it was evaluated true and set the OU variable to the one it grabbed from AD.
![GetInfo06](media\GetInfo06.png)

Next the ODJ step runs using the variables we created and returns successful join
![GetInfo07](media\GetInfo07.png)

Then going back into AD and refreshing, the object is still in the same OU, but with updated Modifed date to when I just ran OSD again and had the latest ODJ run.
![GetInfo08](media\GetInfo08.png)

Hope that helps someone!  Hit us up on Reddit if you need any more assistance. https://www.reddit.com/r/DeployR