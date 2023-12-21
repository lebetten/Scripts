<#
 # Report orphaned Petrel Project objects
 # Created by LEEB, 20.11.2023
 # Updated by , 20.11.2023
#>

$objFSO = New-Object -ComObject Scripting.FileSystemObject

$StartTime = (Get-Date -Format "yyyy-MM-dd_HH-mm")
$CSVFile = "\\statoil.net\dfs\common\P\PetrelSystem\Cleanup\LockReport\CSV\LockReport-$($Env:ComputerName)-$StartTime.csv"
$LogDetailedFile = "C:\Windows\temp\LockReport-$($Env:ComputerName)-$StartTime.log"
$LogExportPath = "\\statoil.net\dfs\common\P\PetrelSystem\Cleanup\LockReport\Log"

Function Get-NewestLogFiles {
    param(
        [string]$RootFolderName
    )

    
    $LogFiles = @()
    $LogFiles = dir "$($RootFolderName)\Scan*.log" | ?{$_.LastWriteTime -gt (Get-Date).AddDays(-14)} | Sort LastWriteTime -Descending

    Return $LogFiles
}

Function Get-LockFileInfo {
    [cmdletbinding()] 
    param (
        [string]$LogFile
    )
    
    $PresentLockFile = @()
    $LockLogText = "\.Lock"
    

    $LockFiles = Select-String -Path $LogFile $LockLogText

    $LockFiles | %{
        $LockFile = $_.ToString()
        $LockOwner = $LockFile.ToString().split(':')[5]
        $LockOwner = $LockOwner.split("")[1]
        if ($LockFile -match $LockLogText) {
            $LockFile = $LockFile -replace " Type.*$"
            }
        $LockFile = $LockFile.ToString().split(':')[2].Replace("\\statoil.net\dfs","\\?\UNC\statoil.net\dfs")
        If (Test-Path $LockFile) {
            $LockSize = dir $LockFile | Measure -Property Length -Sum
            $LockLastUpdateTime = (dir $LockFile).LastWriteTime.ToString()
            $LockFileInfo = New-Object psobject -Property @{
                Name = $LockFile
                Size = $($LockSize).Sum
                LastUpdateTime = $LockLastUpdateTime
                LogFile = $LogFile
                Type = "Lock"
                Server = $Env:ComputerName
                Owner = $LockOwner

                
            }
            Write-Log "Got LockFile Size: $($LockFileInfo.Name) Size: $($LockFileInfo.Size)"
            $PresentLockFile += $LockFileInfo
        }
        Else {
            Write-Log "  Could not find Lock file from log file: $LockFile"
        }
    }

    Return $PresentLockFile
}

Function Report-PetrelProjectFiles {
    [cmdletbinding()] 
    param(
        $InputObject
    )

    $InputObject | %{
        $ReportObject = $_.Name
        Write-Log "Logging object: $($ReportObject) Size: $($_.Size) LogFile: $($_.LogFile) Owner: $($_.Owner)"
               
        If (Test-Path $ReportObject) {
            Write-Log "Object exist on disk"
            Write-Log "Writing object to report $($ReportObject)"
            Write-Csv $_
        }
        Else {
            Write-Log "  Could not find object on disk anymore: $($ReportObject)"
        }
    }
}

Function Write-Log {
    [cmdletbinding()] 
    param (
        [string]$LogText
    )

    $VerbosePreference = "Continue"

    $Now = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")

    Write-Verbose "$Now -> $LogText"
    Add-Content $LogDetailedFile -Value "$($Now) -> $LogText"
    Start-Sleep -Seconds 1
}

Function Write-Csv {
    [cmdletbinding()] 
    param(
        $InputObject
    )

    $InputObject | Export-Csv -NoTypeInformation $CSVFile -Append
}

$ReportObjects = @()

    #Get info about orphaned objects from previous log file
    $TrackerLogFiles = Get-NewestLogFiles -RootFolderName "\\statoil.net\dfs\common\P\PetrelSystem\Tracker\Log\$($Env:ComputerName)\" | Out-GridView -Title "Select logfiles" -PassThru
    $TrackerLogFiles | %{
        Write-Log "Checking logfile: $($_)"
    
        $LockFiles = $Nothing
    
        Write-Host "Getting LockFiles in $($_)"
        $LockFiles = Get-LockFileInfo $_ -Verbose
        If ($LockFiles) {
            $ReportObjects += $LockFiles
        }
        #Report-PetrelProjectFiles $LockFiles
       
        
    }
    
    
    
    #Display objects found and let user select objects to be deleted
    $Selection = $ReportObjects | Sort-Object Name -Unique | Out-GridView -Title "Select Petrel projects to report" -PassThru 
    
    
    #If objects are found in the selection, write them to the CSV
    If ($Selection) {
    
        Report-PetrelProjectFiles $Selection
    }
    Copy-Item $LogDetailedFile -Destination $LogExportPath