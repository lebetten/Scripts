# This script checks if the logged on user has write access to all files and folders under a folder.

# Function to check if the current user has write access to a path (file or directory)
function Test-WriteAccess {
    param (
        [string]$Path
    )
    $accessAllowed = $false
    $acl = Get-Acl -Path $Path
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $currentIdentity = New-Object System.Security.Principal.NTAccount($currentUser)

    foreach ($accessRule in $acl.Access) {
        if ($accessRule.IdentityReference -eq $currentIdentity -or $accessRule.IdentityReference.Value -eq "BUILTIN\Administrators") {
            if ($accessRule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Write -eq [System.Security.AccessControl.FileSystemRights]::Write) {
                $accessAllowed = $true
                break
            }
        }
    }
    return $accessAllowed
}

# Function to check write access for a root path and all subfolders and files
function Test-WriteAccessRecursive {
    param (
        [string]$RootPath
    )
    $items = Get-ChildItem -Path $RootPath -Recurse -depth 2 -ErrorAction SilentlyContinue
    $items | ForEach-Object {
        $hasWriteAccess = Test-WriteAccess -Path $_.FullName
        [PSCustomObject]@{
            Path          = $_.FullName
            Type          = if ($_.PSIsContainer) { "Directory" } else { "File" }
            HasWriteAccess = $hasWriteAccess
        }
    }
}

# Specify the root folder path
$rootFolderPath = "G:\Sub_Appl_Data\Techlog\BE_Cased_Hole_Group\Oseberg South\30-9-K-12 H TTL"

# Check write access for the root folder and all subfolders and files
$result = Test-WriteAccessRecursive -RootPath $rootFolderPath

# Display the results
#$result | Format-Table -AutoSize

# Optionally, you can filter to show only items without write access
$noWriteAccess = $result | Where-Object { -not $_.HasWriteAccess }
if($null -eq $noWriteAccess){
    Write-Output "You have write access to all files"
} else {
    Write-Output $noWriteAccess | Format-Table -AutoSize
    $noWriteAccess | Select-Object -ExpandProperty CategoryInfo | Export-Csv -NoTypeInformation -Path C:\Temp\NoWriteAccess.csv
}
