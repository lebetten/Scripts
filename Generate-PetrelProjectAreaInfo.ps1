#
# Purpose: Scan Tracker logfiles and collect info about other files in the Petrel projects folder structure 
#          Generate CSV file that can be used in the PetrelInfo portal
#
# Created by Sigmund Nessa, 15.11.2023
# Last modified by: Leif Erik Betten, 15.12.2023
#
# Version 0.5
#
#

#Folders
$ProgramFolder = "C:\Temp\PetrelProjectAreaInfo"
$LogFolder = "$ProgramFolder\Log\"
$CSVFolder = "$ProgramFolder\CSV"


#Input/output files
$StartTime = (Get-Date -Format "yyyy-MM-dd_HH-mm")
$InstallStart = Get-Date -UFormat %Y%m%d%H%M%S
$LogFileDetailed = "$LogFolder\Generate_PetrelProjectAreaInfo-$InstallStart.log"
$TrackerServersFile = "$ProgramFolder\Input\TrackerServers.txt"


Function Write-Log {
    param (
        $LogText
    )
    
    $Now = Get-Date -uformat %Y%m%d%H%M%S
    Add-Content $LogFileDetailed -Value "$($Now):$($LogText)"
}

Function Write-Csv {
    [cmdletbinding()] 
    param(
        $InputObject,
        $CSVFile
    )

    $InputObject | Export-Csv -NoTypeInformation $CSVFile -Append -Delimiter ";"
}

Function Get-NewestLogFiles {
    param(
        [string]$RootFolderName
    )

    
    $LogFiles = @()
    $LogFiles = Get-ChildItem -Path $RootFolderName\* -Include "Scan*.log", "PetrelScan*.log" | Where-Object { $_.Length / 1MB -ge 10 } | Sort-Object -Descending | Select-Object -ExpandProperty FullName -First 1
    Write-Log "Using logfile $LogFiles"

    Return $LogFiles
}

Function Convert-Date {
    [cmdletbinding()]
    param (
        [string]$StringDate,
        [string]$DateFormat
    )

    $Date = $null

    try {
        # use the [DateTime]::ParseExact method to convert the string to a DateTime object
        $Date = [DateTime]::ParseExact($StringDate, $DateFormat, $null)
    }
    catch {
        Write-Warning "Error converting date string '$StringDate' using format '$DateFormat': $_"
    }

    if ($Date -ne $null) {
        # format the DateTime object as "yyyy.MM.dd"
        $FormattedDate = $Date.ToString("yyyy.MM.dd")
        return $FormattedDate
    }
    else {
        return $null
    }
}


Function Get-NonPetrelFileInfo {
    [cmdletbinding()] 
    param (
        [string]$LogFileUsed,
        [string]$LogServerUsed
    )
    
    $PresentNonPetrelFiles = @()
    $NonPetrelExtensions = @("Type: ZGY", "Type: segy", "Type: sgy")
    $exclude1 = "\\ref\\index\\"
    $exclude2 = "Access to the path"

    # read the date format from the TrackerServers.txt file
    #$DateFormat = Get-Content "$ProgramFolder\Input\TrackerServers.txt" | Where-Object { $_ -like "$LogServerUsed DateFormat:*" } | ForEach-Object { $_ -replace "^.*: " }
    $DateFormat = Get-Content $TrackerServersFile | Where-Object { $_ -like "$LogServer*" -and $_ -like "*DateFormat:*" } | ForEach-Object { $_ -replace "^.*DateFormat:\s*" }
            
    $NonPetrelFiles = Get-Content -Path $LogFileUsed | Select-String -Pattern $NonPetrelExtensions
        #Select-String -Pattern "($exclude1)|($exclude2)" -NotMatch

    $TotalNonPetrelFiles = $NonPetrelFiles.Count
    $FileCounter = 1

    Write-Log "Process $($NonPetrelFiles.Count) Non-Petrel Files and map the info for each file"
    $NonPetrelFiles |  ForEach-Object{
       Write-Progress -Activity "Non-PetrelFilesMapping" -Status "LogFile Progress:" -PercentComplete ($FileCounter/$TotalNonPetrelFiles*100)
        $NonPetrelFile = $_.ToString()
        $NonPetrelFileName = $NonPetrelFile -replace " Type.*$"
        $NonPetrelFileName = $NonPetrelFileName.Replace("\\?\UNC\statoil.net\dfs\common","G:")
        $NonPetrelFileSplit1 = $NonPetrelFile.Split(":") 
            $NonPetrelSize = $NonPetrelFileSplit1[2].trim().split(" ")[0]
            $NonPetrelSize = if (($NonPetrelSize)){$NonPetrelSize} else {"0"}
            $NonPetrelCreateDateTmp = $NonPetrelFileSplit1[4].trim()
            $NonPetrelCreateDate = Convert-Date -StringDate $NonPetrelCreateDateTmp -DateFormat $DateFormat  # use the Convert-Date function to convert the date string to a DateTime object
            $NonPetrelCreateDate = if (($NonPetrelCreateDate)){$NonPetrelCreateDate} else {"2001.01.01"}
            $NonPetrelType = $NonPetrelFileSplit1[1].trim().split(" ")[0]
            $NonPetrelType = if (($NonPetrelType)){$NonPetrelType} else {"NotSet"}
            $NonPetrelOwner = $NonPetrelFileSplit1[3].trim().split(" ")[0]            
            $NonPetrelOwner = if (($NonPetrelOwner)){$NonPetrelOwner} else {"NotSet"}            
            $NonPetrelFileInfo = New-Object psobject -Property @{
                Name = $NonPetrelFileName
                Size = $NonPetrelSize
                LastUpdateTime = $NonPetrelCreateDate
                LogFile = $LogFileUsed
                Type = $NonPetrelType
                Server = $LogServerUsed
                Owner = $NonPetrelOwner
                
            }
            #Write-Log "Got NonPetrelFile $($NonPetrelFileInfo.Name) Size: $($NonPetrelFileInfo.Size)"
            $PresentNonPetrelFiles += $NonPetrelFileInfo
            $FileCounter += 1
    }
    Write-Progress -Activity "Non-PetrelFilesMapping" -Completed
    Return $PresentNonPetrelFiles
}

Function Report-NonPetrelProjectFiles {
    [cmdletbinding()] 
    param(
        $InputObject,
        $CSVFile
    )

    if ($InputObject) {
        $TotalInputObject = $InputObject.Count
        Write-Log "Writing $TotalInputObject objects to report"
        $InputObject | %{
            $ReportObject = $_.Name
            Write-Csv $_ $CSVFile
        }
    }
    else {
        Write-Log "No files matching the criteria were found."
    }
}



#
# Main
#

$ReportObjects = @()
$TrackerLogservers = Get-Content $TrackerServersFile | Where-Object { $_ -notlike "#*" } | ForEach-Object { $_.Split(",")[0].Trim() }

$TrackerLogservers | ForEach-Object {
    $LogServer = $_
    #$DateFormat = Get-Content $TrackerServersFile | Where-Object { $_ -like "$LogServer*" -and $_ -like "*DateFormat:*" } | ForEach-Object { $_ -replace "^.*DateFormat:\s*" }
    $RootFolderName = Get-Content $TrackerServersFile | Where-Object { $_ -like "ServerName:*" } | Select-String -Pattern $LogServer | ForEach-Object { $_.ToString().Split(" ")[1].Trim() }
#$RootFolderName = Get-Content $TrackerServersFile | Where-Object { $_ -like "$LogServer RootFolderName:*" } | ForEach-Object { $_ -replace "^.*: " }

    # Get info about the file objects from the log files
    $TrackerLogFiles = Get-NewestLogFiles -RootFolderName "\\statoil.net\dfs\common\P\PetrelSystem\Tracker\Log\$RootFolderName"
    $TrackerLogFiles | ForEach-Object {
        $LogFile = $_
        $NonPetrelFiles = Get-NonPetrelFileInfo $_ $RootFolderName -Verbose
        $CSVFile = "$CSVFolder\NonPetrelFileReport-$RootFolderName-$StartTime.csv"
        Report-NonPetrelProjectFiles $NonPetrelFiles $CSVFile

    }
}

move $CSVFolder\* \\statoil.net\dfs\common\P\PetrelSystem\Cleanup\NonPetrelFileReport\CSV\