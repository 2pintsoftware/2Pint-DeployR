# DeployR WinPE Hook Samples

DeployR can run custom PowerShell scripts at points in the WinPE startup flow. These hooks let you extend the standard flow, for example by configuring networking, checking connectivity, collecting inventory, or launching a custom interface.

For the official setup instructions and behavior, see [Preinit, Postinit, Postauth ps1 | DeployR | Product Documentation](https://documentation.2pintsoftware.com/deployr/customization/preinit-postinit-postauth-ps1). Add the hook scripts to the DeployR **Extra Files** content item so they are included on the boot media.

## Hook order

DeployR runs the hooks in this order:

1. `preinit.ps1` runs before networking is initialized.
2. `postinit.ps1` runs after networking is initialized.
3. `postauth.ps1` runs after authentication completes.

This folder contains samples for `postinit.ps1` and `postauth.ps1`; it does not include a `preinit.ps1` sample. DeployR invokes the hook files at their corresponding stages. Supporting scripts used by a hook should be placed beside it in the root of the Extra Files content item, because the samples load them from `$PSScriptRoot`.

## Samples

### `postinit.ps1`

Runs after WinPE networking is initialized. The sample checks whether `Test-DeployRConnection.ps1` is present beside it and dot-sources that script.

### `Test-DeployRConnection.ps1`

Checks for a usable IPv4 network configuration, then tests TCP connectivity to the DeployR server on port `7281`. It retries for up to two minutes and writes a transcript to `_2P\Logs` (or `$env:TEMP` if that log folder is unavailable). It reads the server host from `TSENV:DEPLOYRHOST` when the TSENV provider is available; otherwise it uses the sample fallback `deployr.company.com`, which should be changed for your environment if needed. It exits with code `1` when no network configuration is found, `2` when it cannot connect, and `0` on success.

### `postauth.ps1`

Runs after authentication completes. The sample checks for `Create-ExtraVariables.ps1` beside it and dot-sources that script.

### `Create-ExtraVariables.ps1`

Collects WinPE device inventory and writes it to the DeployR `TSENV` drive as `PA_` variables. The values cover hostname, network adapter and addressing, disk count/model/size/type, TPM version, Secure Boot state, and StifleR Client version. Values that are unavailable are set to `NA`. It writes a transcript to `_2P\Logs` (or `$env:TEMP` if that folder is unavailable).

Place both `postauth.ps1` and `Create-ExtraVariables.ps1` in the root of the Extra Files content item to enable this sample. The created `PA_` variables can then be used by later customization, including URL substitutions that need WinPE inventory.

## Using these samples

1. Copy the hook you want and its supporting script(s) into the root of the DeployR Extra Files content item.
2. Review the sample values and behavior, especially the DeployR server fallback in `Test-DeployRConnection.ps1`.
3. Generate or update the boot media so the Extra Files content is included.
4. Test the hook flow in a lab and review the transcripts under `_2P\Logs` or `$env:TEMP` if troubleshooting is needed.
