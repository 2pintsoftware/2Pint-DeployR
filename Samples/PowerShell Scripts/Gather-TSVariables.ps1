# WindowsGather
# 
# Based on the PSDGather module LocalOnly logic, see https://github.com/FriendsOfMDT/PSD/blob/master/Scripts/PSDGather.psm1.  
# Due to differences in how DeployR handles things, this was converted to a standalone script.

#Build a hashtable for local info
$LocalInfo = @{}

$LocalInfo['IsServerCoreOS'] = "False"
$LocalInfo['IsServerOS'] = "False"

# Look up OS details
Get-CimInstance -ClassName Win32_OperatingSystem -Property Version, BuildNumber, OperatingSystemSKU | ForEach-Object { $LocalInfo['OSCurrentVersion'] = $_.Version; $LocalInfo['OSCurrentBuild'] = $_.BuildNumber; $sku = $_.OperatingSystemSKU }
if (Test-Path HKLM:System\CurrentControlSet\Control\MiniNT) {
	$LocalInfo['OSVersion'] = "WinPE"
}
else {
	$LocalInfo['OSVersion'] = "Other"
	if (!(Test-Path -Path "$env:WINDIR\Explorer.exe")) {
		$LocalInfo['IsServerCoreOS'] = "True"
	}
	if (Test-Path -Path HKLM:\System\CurrentControlSet\Control\ProductOptions) {
		$productType = (Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Control\ProductOptions).ProductType
		if ($productType -eq "ServerNT" -or $productType -eq "LanmanNT") {
			$LocalInfo['IsServerOS'] = "True"
		}
	}
}

# Look up network details
$ipList = @()
$macList = @()
$gwList = @()
Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled = 1" | ForEach-Object {
	$_.IPAddress | ForEach-Object { $ipList += $_ }
	$_.MacAddress | ForEach-Object { $macList += $_ }
	if ($_.DefaultIPGateway) {
		$_.DefaultIPGateway | ForEach-Object { $gwList += $_ }
	}
}
$LocalInfo['IPAddress'] = $ipList
$LocalInfo['MacAddress'] = $macList
$LocalInfo['DefaultGateway'] = $gwList

# Look up asset information
$LocalInfo['IsDesktop'] = "False"
$LocalInfo['IsLaptop'] = "False"
$LocalInfo['IsServer'] = "False"
$LocalInfo['IsSFF'] = "False"
$LocalInfo['IsTablet'] = "False"
Get-CimInstance -ClassName Win32_SystemEnclosure | ForEach-Object {
	$LocalInfo['AssetTag'] = "$($_.SMBIOSAssetTag)".Trim()
	if ($_.ChassisTypes[0] -in "8", "9", "10", "11", "12", "14", "18", "21") { $LocalInfo['IsLaptop'] = "True"; $LocalInfo['Chassis'] = "Laptop"}
	if ($_.ChassisTypes[0] -in "3", "4", "5", "6", "7", "15", "16") { $LocalInfo['IsDesktop'] = "True"; $LocalInfo['Chassis'] = "Desktop"}
	if ($_.ChassisTypes[0] -in "23") { $LocalInfo['IsServer'] = "True"; $LocalInfo['Chassis'] = "Server"}
	if ($_.ChassisTypes[0] -in "34", "35", "36") { $LocalInfo['IsSFF'] = "True"; $LocalInfo['Chassis'] = "Small Form Factor"}
	if ($_.ChassisTypes[0] -in "13", "31", "32", "30") {$LocalInfo['IsTablet'] = "True"; $LocalInfo['Chassis'] = "Tablet"}
}

Get-CimInstance -ClassName Win32_BIOS | ForEach-Object {
	$LocalInfo['SerialNumber'] =  "$($_.SerialNumber)".Trim()
}

if ($env:PROCESSOR_ARCHITEW6432) {
	if ($env:PROCESSOR_ARCHITEW6432 -eq "AMD64") {
		$LocalInfo['Architecture'] = "x64"
	}
	else {
		$LocalInfo['Architecture'] = $env:PROCESSOR_ARCHITEW6432.ToUpper()
	}
}
else {
	if ($env:PROCESSOR_ARCHITECTURE -eq "AMD64") {
		$LocalInfo['Architecture'] = "x64"
	}
	else {
		$LocalInfo['Architecture'] = $env:PROCESSOR_ARCHITECTURE.ToUpper()
	}
}

Get-CimInstance -ClassName Win32_Processor -Property MaxClockSpeed,SecondLevelAddressTranslationExtensions | ForEach-Object {
	$LocalInfo['ProcessorSpeed'] = $_.MaxClockSpeed
	$LocalInfo['SupportsSLAT'] = $_.SecondLevelAddressTranslationExtensions
}

# TODO: Capable architecture

Get-CimInstance -ClassName Win32_ComputerSystem | ForEach-Object {
	$LocalInfo['Manufacturer'] = "$($_.Manufacturer)".Trim()
	$LocalInfo['Make'] = "$($_.Manufacturer)".Trim()
	$LocalInfo['Model'] = "$($_.Model)".Trim()
	$LocalInfo['Memory'] = [int] ($_.TotalPhysicalMemory / 1024 / 1024)
}

if ($LocalInfo['Make'] -eq "") {
	$Make = "$(Get-CimInstance -ClassName Win32_BaseBoard | Select-Object -ExpandProperty Manufacturer)".Trim()
	$LocalInfo['Make'] = $Make
	$LocalInfo['Manufacturer'] = $Make
}

if ($LocalInfo['Model'] -eq "") {
	$LocalInfo['Model'] = "$(Get-CimInstance -ClassName Win32_BaseBoard | Select-Object -ExpandProperty Product)".Trim()
}

Get-CimInstance -ClassName Win32_ComputerSystemProduct | ForEach-Object {
	$LocalInfo['UUID'] = "$($_.UUID)".Trim()
	$LocalInfo['CSPVersion'] = "$($_.Version)".Trim()
}

Get-CimInstance -ClassName MS_SystemInformation -NameSpace root\WMI | ForEach-Object {
	$LocalInfo['BaseBoardProduct'] = "$($_.BaseBoardProduct)".Trim()
	$LocalInfo['SystemSku'] = "$($_.SystemSku)".Trim()
}

Get-CimInstance -ClassName Win32_BaseBoard | ForEach-Object {
	$LocalInfo['Product'] = "$($_.Product)".Trim()
}

# UEFI
try {
	Get-SecureBootUEFI -Name SetupMode | Out-Null
	$LocalInfo['IsUEFI'] = "True"
	$LocalInfo['SetupMode'] = "UEFI"
}
catch {
	$LocalInfo['IsUEFI'] = "False"
	$LocalInfo['SetupMode'] = "BIOS"
}

# TEST: Battery
$bFoundAC = $false
$bOnBattery = $false
$bFoundBattery = $false
foreach ($Battery in (Get-CimInstance -ClassName Win32_Battery)) {
	$bFoundBattery = $true
	if ($Battery.BatteryStatus -eq "2") {
		$bFoundAC = $true
	}
}
If ($bFoundBattery -and !$bFoundAC) {
	$LocalInfo['IsOnBattery'] = $true
}

#https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getproductinfo
switch ($sku)
{
	0       {$LocalInfo['OSSku']="Undefined";break}
	1       {$LocalInfo['OSSku']="Ultimate Edition";break}
	2       {$LocalInfo['OSSku']="Home Basic Edition";break}
	3       {$LocalInfo['OSSku']="Home Basic Premium Edition";break}
	4       {$LocalInfo['OSSku']="Enterprise Edition";break}
	5       {$LocalInfo['OSSku']="Home Basic N Edition";break}
	6       {$LocalInfo['OSSku']="Business Edition";break}
	7       {$LocalInfo['OSSku']="Standard Server Edition";break}
	8       {$LocalInfo['OSSku']="Datacenter Server Edition";break}
	9       {$LocalInfo['OSSku']="Small Business Server Edition";break}
	10      {$LocalInfo['OSSku']="Enterprise Server Edition";break}
	11      {$LocalInfo['OSSku']="Web Server";break}
	12      {$LocalInfo['OSSku']="Datacenter Server Core Edition";break}
	13      {$LocalInfo['OSSku']="Standard Server Core Edition";break}
	14      {$LocalInfo['OSSku']="Enterprise Server Core Edition";break}
	15      {$LocalInfo['OSSku']="Storage Server Standard";break}
	16      {$LocalInfo['OSSku']="Storage Server Workgroup";break}
	17      {$LocalInfo['OSSku']="Storage Server Enterprise";break}
	18      {$LocalInfo['OSSku']="Windows Essential Server Solutions";break}
	19      {$LocalInfo['OSSku']="Small Business Server Premium";break}
	20      {$LocalInfo['OSSku']="Storage Express Server Edition";break}
	21      {$LocalInfo['OSSku']="Server Foundation";break}
	22      {$LocalInfo['OSSku']="Storage Workgroup Server Edition";break}
	23      {$LocalInfo['OSSku']="Windows Essential Server Solutions";break}
	24      {$LocalInfo['OSSku']="Server For Small Business Edition";break}
	25      {$LocalInfo['OSSku']="Small Business Server Premium Edition";break}
	30      {$LocalInfo['OSSku']="Pro Edition";break}
	40      {$LocalInfo['OSSku']="Server Hyper Core V";break}
	48		{$LocalInfo['OSSku']="Enterprise Edition";break}
	50      {$LocalInfo['OSSku']="Datacenter Server Edition";break}
	54      {$LocalInfo['OSSku']="Enterpise N Edition";break}
	62      {$LocalInfo['OSSku']="Home N Edition";break}
	65      {$LocalInfo['OSSku']="Home Edition";break}
	68      {$LocalInfo['OSSku']="Mobile Edition";break}
	79		{$LocalInfo['OSSku']="Education Edition";break}
	81		{$LocalInfo['OSSku']="Enterprise 2015 LTSB";break}
	82		{$LocalInfo['OSSku']="Enterprise 2015 N LTSB";break}
	85		{$LocalInfo['OSSku']="Mobile Enterprise";break}
	default {$LocalInfo['OSSku']="Not Supported";break}
}

# TODO: GetCurrentOSInfo

# TODO: BitLocker

# Generate ModelAlias, MakeAlias and SystemAlias
$LocalInfo['IsVM'] = "False"
Switch -Wildcard ($LocalInfo['Make']) {
	"*Microsoft*" {
		$LocalInfo['MakeAlias'] = "Microsoft"
		$LocalInfo['ModelAlias'] = "$(Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Model)".Trim()
		$LocalInfo['SystemAlias'] = Get-CimInstance -ClassName MS_SystemInformation -Namespace root\wmi | Select-Object -ExpandProperty SystemSKU
		# Logic for Hyper-V Testing
		If ($LocalInfo['ModelAlias'] -eq "Virtual Machine") {
			$LocalInfo['SystemAlias'] = Get-CimInstance -ClassName MS_SystemInformation -Namespace root\wmi | Select-Object -ExpandProperty SystemVersion
			if ([string]::IsNullOrEmpty($LocalInfo['SystemAlias']))
			{
				$LocalInfo['SystemAlias'] = $LocalInfo['ModelAlias']
			}
			$LocalInfo['IsVM'] = "True"
		}
	}
	"*HP*" {
		$LocalInfo['MakeAlias'] = "HP"
		$LocalInfo['ModelAlias'] = "$(Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Model)".Trim()
		$LocalInfo['SystemAlias'] = "$((Get-CimInstance -ClassName MS_SystemInformation -NameSpace root\wmi).BaseBoardProduct)".Trim()
	}
	"*VMWare*" {
		$LocalInfo['MakeAlias'] = "VMWare"
		# $LocalInfo['ModelAlias'] = "$(Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Model)".Trim() # Default, sets alias to same as model
		# $LocalInfo['ModelAlias'] = ("$(Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Model)".Trim()).replace(",","_") # Remove the "," and replace with "_"
		$LocalInfo['ModelAlias'] = ("$(Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Model)".Trim()).replace(" ","_").replace(",","_") # Remove the "," and replace with "_", Remove the " " and replace with "_"

		# DeployR: The MS_SystemInformation value is 0000000000000001, which isn't useful.  Just hard-code the value.
		#$LocalInfo['SystemAlias'] = Get-CimInstance -ClassName MS_SystemInformation -Namespace root\wmi | Select-Object -ExpandProperty SystemSKU
		$LocalInfo['SystemAlias'] = "VMWare"
		$LocalInfo['IsVM'] = "True"
	}
	"*QEMU*" {
		$LocalInfo['MakeAlias'] = "QEMU"
		$LocalInfo['ModelAlias'] = "$(Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Model)".Trim()
		$LocalInfo['SystemAlias'] = Get-CimInstance -ClassName MS_SystemInformation -Namespace root\wmi | Select-Object -ExpandProperty SystemSKU
		$LocalInfo['IsVM'] = "True"
	}
	"*Innotek*" {
		$LocalInfo['MakeAlias'] = "Innotek"
		$LocalInfo['ModelAlias'] = "$(Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Model)".Trim()
		$LocalInfo['SystemAlias'] = Get-CimInstance -ClassName MS_SystemInformation -Namespace root\wmi | Select-Object -ExpandProperty SystemSKU
		$LocalInfo['IsVM'] = "True"
	}
	"*Hewlett-Packard*" {
		$LocalInfo['MakeAlias'] = "HP"
		$LocalInfo['ModelAlias'] = "$(Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Model)".Trim()
		$LocalInfo['SystemAlias'] = "$((Get-CimInstance -ClassName MS_SystemInformation -NameSpace root\wmi).BaseBoardProduct)".Trim()
	}
	"*Dell*" {
		$LocalInfo['MakeAlias'] = "Dell"
		$LocalInfo['ModelAlias'] = "$(Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Model)".Trim()
		$LocalInfo['SystemAlias'] = "$((Get-CimInstance -ClassName MS_SystemInformation -NameSpace root\wmi ).SystemSku)".Trim()
	}
	"*Lenovo*" {
		$LocalInfo['MakeAlias'] = "Lenovo"
		$LocalInfo['ModelAlias'] = "$(Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object -ExpandProperty Version)".Trim()
		$LocalInfo['SystemAlias'] = "$((Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Model).SubString(0, 4))".Trim()
	}
	"*Intel(R) Client Systems*" {
		$LocalInfo['MakeAlias'] = "Intel(R) Client Systems"
		$LocalInfo['ModelAlias'] = "$(Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object -ExpandProperty Version)".Trim()
		$LocalInfo['SystemAlias'] = ("$(Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Model)".Trim())
		$LocalInfo['SystemAlias'] = "$($LocalInfo['SystemAlias'].SubString(0, $LocalInfo['SystemAlias'].IndexOf("i")))".Trim()
	}
	"*Panasonic*" {
		$LocalInfo['MakeAlias'] = "Panasonic Corporation"
		$LocalInfo['ModelAlias'] = "$(Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Model)".Trim()
		$LocalInfo['SystemAlias'] = "$((Get-CimInstance -ClassName MS_SystemInformation -NameSpace root\wmi ).BaseBoardProduct)".Trim()
	}
	"*Viglen*" {
		$LocalInfo['MakeAlias'] = "Viglen"
		$LocalInfo['ModelAlias'] = "$(Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Model)".Trim()
		$LocalInfo['SystemAlias'] = "$(Get-CimInstance -ClassName Win32_BaseBoard | Select-Object -ExpandProperty SKU)".Trim()
	}
	"*AZW*" {
		$LocalInfo['MakeAlias'] = "AZW"
		$LocalInfo['ModelAlias'] = "$(Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Model)".Trim()
		$LocalInfo['SystemAlias'] = "$((Get-CimInstance -ClassName MS_SystemInformation -NameSpace root\wmi ).BaseBoardProduct)".Trim()
	}
	"*Fujitsu*" {
		$LocalInfo['MakeAlias'] = "Fujitsu"
		$LocalInfo['ModelAlias'] = "$(Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Model)".Trim()
		$LocalInfo['SystemAlias'] = "$(Get-CimInstance -ClassName Win32_BaseBoard | Select-Object -ExpandProperty SKU)".Trim()
	}
	"*Acer*" {
		$LocalInfo['MakeAlias'] = "Acer"
		$LocalInfo['ModelAlias'] = "$(Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Model)".Trim()
		$LocalInfo['SystemAlias'] = $LocalInfo['ModelAlias']
	}
	Default {
		$LocalInfo['MakeAlias'] = "NA"
		$LocalInfo['ModelAlias'] = "NA"
		$LocalInfo['SystemAlias'] = "NA"
	}
	# Closing for switch block
}

# Dump all items in hastable as TS VARs
foreach ($i in $LocalInfo.GetEnumerator())
{
	# If value is null, skip and continue to next
	If([string]::IsNullOrEmpty($i.Value)){
		Continue
	}

	# Detemine is value is an array
	# If it is add to $tenvlist instead
	if ($i.Value -is [array])
	{
		Write-Host "Value for $($i.Name) is an array, adding to tsenvlist instead of tsenv"
		#Set-Item -Path tsenvlist:$($i.name) -Value $i.Value
	} else {
		Write-Host "Setting TS Variable for $($i.Name) with value $($i.Value)"
		#Set-Item -Path tsenv:$($i.name) -Value $i.Value
	}
}
