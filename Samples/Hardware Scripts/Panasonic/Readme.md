# Panasonic Offline Driver Sync

This process was created for the ability to easily go onto any machine, build a repository of Panasonic driver packs, then copy that folder via Flash Drive / Network Share, and place it somewhere the DeployR Server has access too.

## Build-OfflineDriverPackFolder.ps1

This script will use the Panasonic Online Catalog information to prompt you for the models you want to support, then if you want Win10 or Win11.  Once you have made your selections, it will go ahead and download them to the path you specify.

Make sure you set $BuildFolderPath to where you want the content downloaded

![Offline02]](media/Offline02.png)
![Offline03]](media/Offline03.png)
![Offline01]](media/Offline01.png)