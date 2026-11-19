


$ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
$ModelAlias = $ComputerSystem.Model
$MakeAlias = $ComputerSystem.Manufacturer

if ($MakeAlias -match "NewLine") {
    ${TSEnv:ModelAlias} = (Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Model).Trim()   # "OPS"
    ${TSEnv:MakeAlias} = "NewLine"

    # Model portion of the serial-style SKU, e.g. DS7C120F501303 -> DS7C120
    $sku = (Get-CimInstance -ClassName MS_SystemInformation -Namespace root\wmi).SystemSku.Trim()
    ${TSEnv:SystemAlias} = $sku.Substring(0, 7)
}






