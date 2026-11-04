# Change AD Computer Object Owner

[Change-ADComputerObjectOwner.ps1](Change-ADComputerObjectOwner.ps1) changes the owner of an existing Active Directory computer object to a specified computer account, typically the DeployR server's account. Run it as a DeployR server-side script before the Offline Domain Join (ODJ) step.

**This workaround is not supported by 2Pint Software.** It changes AD security ownership. Test in a lab and obtain approval for the required AD permissions before using it in production. Changing ownership does not guarantee that all DeployR or Windows domain-join reuse requirements will be satisfied.

## What It Does

1. Logs the parameters, execution server, and Windows identity.
2. Builds the target distinguished name as `CN=<ComputerName>,<OU>` and forces an LDAP read to check whether the object exists.
3. If LDAP reports that the object does not exist, logs `SKIPPED` and returns without changing AD. The later ODJ step can create the account using its normal permissions.
4. For an existing object, resolves the proposed owner computer account to its SID and reads the current owner from the security descriptor.
5. With `DryRun=True`, logs the current and proposed owners without writing changes. Otherwise, sets the owner and commits the change to AD.

The script does not create, delete, move, or rename computer accounts. It uses ADSI/System.DirectoryServices rather than the ActiveDirectory PowerShell module. Missing `ComputerName` or `OU`, or an unresolved owner account, produces a warning rather than an ownership change. Other LDAP and ownership failures are reported as errors.

## Prerequisites

- The DeployR server must have domain connectivity and working AD DNS resolution.
- The execution identity needs permission to find the accounts, read the target security descriptor, and assign the specified owner. Default ODJ delegation is not sufficient for changing ownership; ordinary write-property permissions do not necessarily allow it either.
- `NewOwner` must identify an existing computer account by its `sAMAccountName`, including the trailing `$`.
- The target account must have the expected CN directly inside the supplied OU. This script does not search other OUs for the target.

The client initiates the server-side action during OSD, but the AD operation runs on the **DeployR server**, not in the client's WinPE session. Check the `Executing on ... as ...` log entry for the actual identity. When the service runs as `NT AUTHORITY\SYSTEM`, domain access normally uses the DeployR server's computer account, such as `CONTOSO\DEPLOYR$`. Do not assume the interactive administrator's permissions apply.

## Placement and Task Sequence

1. Place the script in the DeployR server's configured server-side Scripts directory. In the environment used for this sample, the deployed path is:

   ```text
   D:\DeployRContentLib\Scripts\Change-ADComputerObjectOwner.ps1
   ```

   Use your installation's configured location; the drive and content-library root may differ. Keeping the script only in this GitHub sample folder or on the OSD client does not make it available to the server-side action.

2. Before calling the script, add a **Set variable** task sequence step named **Set NewOwner Value**. Set **Variable Name** to `newOwner` and **Variable value** to the DeployR server's computer name followed by `$`. For example, a server named `DeployR` uses `DeployR$`. This identifies the server's AD computer account, not the client being deployed.
3. Immediately after that variable step, add a **Run server-side PowerShell script** step. Set **Script name** to `Change-ADComputerObjectOwner.ps1`. This step requests execution on the DeployR server; it is not a client-side PowerShell script step. Place it after the target computer name and OU are known and **before the Offline domain join step**.
4. Ensure the task sequence provides the following values to the server-side script, including the `newOwner` variable set in the preceding step:

   | Parameter | Example | Meaning |
   | --- | --- | --- |
   | `ComputerName` | `PC-001` | Target computer CN, without a trailing `$`. |
  | `NewOwner` | `DeployR$` | Supplied by the preceding `newOwner` task sequence variable; DeployR server name plus `$`. |
  | `OU` | `OU=Workstations,DC=contoso,DC=com` | Supplied by the `OU` task sequence variable; target parent OU distinguished name, not an LDAP URL. |
   | `DryRun` | `True` | String `True` or `False`; omitted or empty defaults to `False`. |

5. Start with `DryRun=True` and inspect the server logs. For an existing account, expect the current and proposed owner SIDs and `ACL read succeeded; no changes were committed to AD.` For a missing account, expect `SKIPPED` before any owner lookup.
6. Only set `DryRun=False` after reviewing the target, owner, and permissions. A successful write logs `SUCCESS: Changed owner ...`. A dry run proves read access, not permission to assign ownership.

The script pulls `OU` from a task sequence variable, typically populated early in the task sequence by a database lookup or a frontend. An OU configured only on the later **Offline domain join** step is not automatically available to this script. If the `OU` variable has not already been set, add another **Set variable** step before the server-side script, with **Variable Name** set to `OU` and **Variable value** set to the correct distinguished name, such as `OU=Workstations,DC=contoso,DC=com`. Keep this value consistent with the OU used for ODJ.

Alternatively, hardcode the desired OU in the deployed script by replacing `$ouPath = $OU` with `$ouPath = 'OU=Workstations,DC=contoso,DC=com'`. This makes that copy specific to one OU; prefer the task sequence variable when deploying to multiple OUs.

The relevant task sequence order is:

```text
Set OU Value                        (Set variable: OU = target OU DN, if not already set)
Set NewOwner Value                  (Set variable: newOwner = DeployR$)
Change-ADComputerObjectOwner.ps1     (Run server-side PowerShell script)
Offline domain join
```

For an interactive read-only test on the server:

```powershell
& 'D:\DeployRContentLib\Scripts\Change-ADComputerObjectOwner.ps1' `
    -ComputerName 'PC-001' `
    -NewOwner 'DEPLOYR$' `
    -OU 'OU=Workstations,DC=contoso,DC=com' `
    -DryRun 'True'
```

This test runs as your interactive user. Repeat validation through DeployR to exercise the service's permissions.

## Logs and Troubleshooting

On the **DeployR server**, open Event Viewer and navigate to:

```text
Applications and Services Logs
  TwoPintSoftware
    DeployR
      Logger
        Operational
```

The channel name for PowerShell queries is `TwoPintSoftware-DeployR-Logger/Operational`. Look for messages containing `Server-side script Change-ADComputerObjectOwner.ps1`. Information messages use event ID `11003`; script failure messages use `11005` in this environment.

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'TwoPintSoftware-DeployR-Logger/Operational'
    StartTime = (Get-Date).AddHours(-1)
} -MaxEvents 1000 |
    Where-Object { $_.Message -like '*Change-ADComputerObjectOwner.ps1*' } |
    Select-Object TimeCreated, Id, Message |
    Format-List
```

The query searches the most recent 1,000 channel events within the last hour; increase the limit or adjust the time window if necessary. Read the information events immediately before a failure to identify the parameters, execution identity, and last completed operation.

| Symptom | What to Check |
| --- | --- |
| `SKIPPED: Computer object ... does not exist yet` | Expected for a new machine. Also verify the supplied CN and OU: a wrong path can look like a missing account. The result reflects the contacted domain controller's view, so replication timing can matter. |
| `Could not read the security descriptor` | Verify the object path, execution identity, and security-descriptor read permissions. Confirm the deployed copy uses `PSBase.ObjectSecurity` and `RefreshCache()` for the existence check. Merely constructing an ADSI object or reading `NativeObject` is not a reliable existence test. |
| Access denied while reading or committing | Check permissions for the service's domain identity on the target object and any inherited restrictions. Being able to read an ACL or perform ODJ does not prove permission to assign the requested owner. |
| `Could not find machine account` | Check `NewOwner`, its trailing `$`, and whether the account exists in the searched domain. No ownership change occurs in this case. |
| `Missing COMPUTERNAME or OU variable` | Check the task sequence variables available before the server-side action. If the OU is configured only on the ODJ step, add a preceding Set variable step for `OU`, or hardcode `$ouPath` in the deployed script. |
| LDAP server or binding error | Check AD DNS, domain-controller connectivity, the distinguished name, and the service identity. Errors other than LDAP no-such-object are not treated as a normal missing-account skip. |
| Changes to this sample do not affect OSD | Update the copy in the server's configured Scripts directory, then check the next run's events. |

After a non-dry-run success, verify the object's owner in Active Directory Users and Computers with Advanced Features enabled, under the computer object's **Security > Advanced > Owner** settings. For a skipped account, verify the subsequent ODJ result separately; this script does not perform the join.