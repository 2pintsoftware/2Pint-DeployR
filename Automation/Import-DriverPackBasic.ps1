$MakeAlias = 'HP'
$ModelAlias = '83B2'
$NewCI = New-DeployRContentItem -Name "Driver Pack - $MakeAlias - $ModelAlias" -Type Folder -Purpose DriverPack -Description "Generated for $MakeAlias - $ModelAlias"

$ContentId = $NewCI.id
$InputSourceFolder =  "D:\DeployRSources\DriverPacks\HP\HP EliteBook 840 G5 Notebook PC - 83B2\Win10\Extracted"
$NewVersion = New-DeployRContentItemVersion -ContentItemId $ContentId -Description "Source: $InputSourceFolder" -DriverManufacturer $MakeAlias -DriverModel $ModelAlias -SourceFolder "$InputSourceFolder"