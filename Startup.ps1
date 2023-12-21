param (
    [Parameter(Mandatory=$false)]
    [string[]]$Arguments
)

# Petrel Startup Script
#
#	In sync with \\statoil.net\dfs\common\Prog\Global\Petrel\MyPetrel\
#
# Created by Leif Erik Betten, 30.11.2023
# Last modified by: <Name>, <Date>

# 0. Init

$WrapperScript = "MyPetrel.ps1"
$WrapperINI = "MyPetrel.ini"

$NetworkFolder = "G:\Prog\Global\Petrel\Program\MyPetrel\"
$LocalFolder = "C:\Appl\Schlumberger\"
$LocalScript = Join-Path $LocalFolder $WrapperScript

$objFSO = New-Object -ComObject Scripting.FileSystemObject

# 1. Keep local Startup Script & Ini file in sync

$SyncStartupScript = "Robocopy $NetworkFolder $LocalFolder $WrapperScript /R:1 /W:1" 
Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $SyncStartupScript -WindowStyle Hidden

$SyncIniFile = "Robocopy $NetworkFolder $LocalFolder $WrapperINI /R:1 /W:1" 
Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $SyncIniFile -WindowStyle Hidden

# 2. Run Startup Script (if present)

if ($objFSO.FileExists($LocalScript)) {
    $RunLocalScript = "PowerShell -NoLogo -NoProfile -File `"$LocalScript`" $($Arguments -join ' ')"
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $RunLocalScript -WindowStyle Hidden
}
else {
    Write-Error "The Petrel startup script is missing. Please make sure you are connected to the Equinor network. Then, restart Petrel."
}