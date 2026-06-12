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

