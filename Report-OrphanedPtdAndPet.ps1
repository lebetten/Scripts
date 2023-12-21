<#
 # Report orphaned Petrel Project objects
 # Created by SIGN, 03.11.2023
 # Updated by LEEB, 28.11.2023
#>

$objFSO = New-Object -ComObject Scripting.FileSystemObject

$StartTime = (Get-Date -Format "yyyy-MM-dd_HH-mm")
$CSVFile = "\\statoil.net\dfs\common\P\PetrelSystem\Cleanup\PtdPetReport\CSV\PetPtdReport-$($Env:ComputerName)-$StartTime.csv"
$LogDetailedFile = "C:\Windows\temp\PetPtdReport-$($Env:ComputerName)-$StartTime.log"
$LogExportPath = "\\statoil.net\dfs\common\P\PetrelSystem\Cleanup\PtdPetReport\Log\$($Env:ComputerName)"
$ImportLogPath = "\\statoil.net\dfs\common\P\PetrelSystem\Tracker\Log\$Env:ComputerName"
$LatestLogFile = Get-ChildItem -Path $ImportLogPath -Filter "PetrelScan*.log" | Where-Object { $_.Length / 1MB -ge 100 } | Sort-Object -Descending | Select-Object -First 1

if (Test-Path $LogExportPath) {
    Write-Host "Folder exists"
} else {
    New-Item -ItemType Directory -Path $LogExportPath
}

if ($LatestLogFile) {
    $AbsolutePath = $LatestLogFile.FullName
    Write-Log "$AbsolutePath"
}
else {
    Write-Log "Could not find latest log file."
}



Function Get-PetFileInfo {
    [cmdletbinding()] 
    param (
        [string]$LogFile
    )
    
    $ReportPetFile = @()
    $PetLogText = "ERROR: No Petrel project folder for project"

    $PetFiles = Select-String -Path $LogFile $PetLogText

    $PetFiles | ForEach-Object{
        $PetFile = $_.ToString().Substring($_.ToString().IndexOf($PetLogText)+45)
        $PetFile = $PetFile.Replace("\\statoil.net\dfs","\\?\UNC\statoil.net\dfs")
        If (Test-Path $PetFile) {
            $PetSize = dir $PetFile | Measure -Property Length -Sum
            $PetLastUpdateTime = (dir $PetFile).LastWriteTime.ToString("yyyy.MM.dd HH:mm")
            $PetScanDate = (dir $LogFile).CreationTime.Date.ToString("yyyy.MM.dd")
            $PetFileOwner = (dir $PetFile).GetAccessControl().Owner.ToString()
            $PetFileOwner = if (($PetFileOwner)){$PetFileOwner} else {"NotSet"}
            $PetFile = $PetFile.Replace("\\?\UNC\statoil.net\dfs\common","G:")
            $PetFileInfo = New-Object psobject -Property @{
                Name = $PetFile
                Size = $($PetSize).Sum
                LastUpdateTime = $PetLastUpdateTime
                Scandate = $PetScanDate
                Type = "Pet"
                Server = $Env:ComputerName
                Owner = $PetFileOwner
            }
            Write-Log "Got PetFile $($PetFileInfo.Name) Size: $($PetFileInfo.Size)"
            $ReportPetFile += $PetFileInfo
        }
        Else {
            Write-Log "  Could not find PET file from log file: $PetFile"
        }
    }

    Return $ReportPetFile
}

Function Get-PetTmpFileInfo {
    [cmdletbinding()] 
    param (
        [string]$LogFile
    )
    
    $PresentPetTmpFile = @()
    $PetTmpLogText = "\.pet_tmp"
    

    $PetTmpFiles = Select-String -Path $LogFile $PetTmpLogText

    $PetTmpFiles | ForEach-Object{
        $PetTmpFile = $_.ToString()
        $PetTmpFileName = $PetTmpFile -replace " Type.*$"
        $PetTmpFileName = $PetTmpFileName.split(':')[2]
        If (Test-Path $PetTmpFileName) {
            $PetTmpSize = dir $PetTmpFileName | Measure -Property Length -Sum
            $PetTmpLastUpdateTime = (dir $PetTmpFileName).LastWriteTime.ToString("yyyy.MM.dd HH:mm")
            $PetTmpOwner = (dir $PetTmpFileName).GetAccessControl().Owner.ToString()
            $PetTmpOwner = if (($PetTmpOwner)){$PetTmpOwner} else {"NotSet"}
            $PetTmpScanDate = (dir $LogFile).CreationTime.Date.ToString("yyyy.MM.dd")
            $PetTmpFileName = $PetTmpFileName.Replace("\\?\UNC\statoil.net\dfs\common","G:")
            $PetTmpFileInfo = New-Object psobject -Property @{
                Name = $PetTmpFileName
                Size = $($PetTmpSize).Sum
                LastUpdateTime = $PetTmpLastUpdateTime
                Scandate = $PetTmpScanDate
                Type = "Pet_tmp"
                Server = $Env:ComputerName
                Owner = $PetTmpOwner
                
            }
            Write-Log "Got PetTmpFile $($PetTmpFileInfo.Name) Size: $($PetTmpFileInfo.Size)"
            $PresentPetTmpFile += $PetTmpFileInfo
        }
        Else {
            Write-Log "  Could not find PET_tmp file from log file: $PetTmpFileName"
        }
    }

    Return $PresentPetTmpFile
}

Function Get-PtdFolderInfo {
    [cmdletbinding()] 
    param (
        [string]$LogFile
    )
    
    $ReportPtdFolder = @()
    $PtdLogText = "ERROR: Petrel project folder does not have a .pet file: "
    
    $PtdFolders = Select-String -Path $LogFile $PtdLogText
    

    $PtdFolders | ForEach-Object{
        $PtdFolder = $_.ToString().SubString($_.ToString().IndexOf($PtdLogText)+56)
        $PtdFolder = $PtdFolder.Replace("\\statoil.net\dfs","\\?\UNC\statoil.net\dfs")
        $CheckReferenceProject = $PtdFolder.TrimEnd("ptd") + "petR"
        $CheckManagedProject = $PtdFolder.TrimEnd("ptd") + "petM"
        $PtdSize = $Nothing


        If (Test-Path $CheckReferenceProject) {
            Write-Log "Found reference project file $CheckReferenceProject - skip processing $PtdFolder"
        }
        ElseIf (Test-Path $CheckManagedProject) {
            Write-Log "Found managed project file $CheckReferenceProject - skip processing $PtdFolder"
        }
        ElseIf (Test-Path $PtdFolder) {
            $PtdSize = $objFSO.GetFolder($PtdFolder).Size
            $PtdLastUpdateTime = (dir $PtdFolder).LastWriteTime.ToString("yyyy.MM.dd HH:mm")
            $PtdScanDate = (dir $LogFile).CreationTime.Date.ToString("yyyy.MM.dd")
            $PtdOwner = (dir $PtdFolder).GetAccessControl().Owner.ToString()
            $PtdOwner = if (($PtdOwner)){$PtdOwner} else {"NotSet"}
            $PtdFolder = $PtdFolder.Replace("\\?\UNC\statoil.net\dfs\common","G:")
            $PtdFolderInfo = New-Object psobject -Property @{
                Name = $PtdFolder
                Size = $PtdSize
                LastUpdateTime = $PtdLastUpdateTime
                Scandate = $PtdScanDate
                Type = "Ptd"
                Server = $Env:ComputerName
                Owner = $PtdOwner
            }
            Write-Log "Got PtdFolder $($PtdFolderInfo.Name) Size: $($PtdFolderInfo.Size)"

            $ReportPtdFolder += $PtdFolderInfo
        }
        Else {
            Write-Log "  Could not find PTD folder from log file: $PtdFolder"
        }
        
    }

    Return $ReportPtdFolder

}

Function Report-PetrelProjectFiles {
    [cmdletbinding()] 
    param (
        $InputObject
    )

    Begin
    {
        $Header = "Name;Owner;Server;Type;LastUpdateTime;Size;Scandate"
        Write-Output $Header | Out-File -FilePath $CSVFile -Encoding utf8 -Force
    }
    
    Process
    {
        $InputObject | ForEach-Object {
            $ReportObject = $_.Name
            #$ReportObject
            $OutString = "{0};{1};{2};{3};{4};{5};{6}" -f $ReportObject,$_.Owner, $_.Server,$_.Type,$_.LastUpdateTime,$_.Size, $_.Scandate
            Write-Verbose "Exporting object to CSV: $($OutString)"
            $OutString | Out-File -FilePath $CSVFile -Encoding utf8 -append -NoClobber
        }
    }
    
    End {}
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
    }

Function Write-Csv {
    [cmdletbinding()] 
    param(
        $InputObject
    )

    $InputObject | Export-Csv -NoTypeInformation $CSVFile -Append
}


#
# Main
#

$ReportObjects = @()

#Get info about orphaned objects from previous log file
$LatestLogFile | %{
    Write-Log "Checking logfile: $($_)"

    $PetFiles = $Nothing
    $PetTmpFiles = $Nothing
    $PtdFolders = $Nothing

    Write-Host "Getting PetTmpFiles in $($AbsolutePath)"
    $PetTmpFiles = Get-PetTmpFileInfo $AbsolutePath
    If ($PetTmpFiles) {
        $ReportObjects += $PetTmpFiles
    }
    #Report-PetrelProjectFiles $PetTmpFiles

    Write-Host "Getting PetFiles in $($AbsolutePath)"
    $PetFiles = Get-PetFileInfo $AbsolutePath
    If ($PetFiles) {
        $ReportObjects += $PetFiles
    }
    #Report-PetrelProjectFiles $PetFiles

    Write-Host "Getting PtdFolders in $($AbsolutePath)"
    $PtdFolders = Get-PtdFolderInfo $AbsolutePath
    If ($PtdFolders) {
        $ReportObjects += $PtdFolders
    }
    #Report-PetrelProjectFiles $PtdFolders

    
}



Report-PetrelProjectFiles -InputObject $ReportObjects
Write-Verbose "CSV report successfully exported to: $ExportCsvPath"
Copy-Item $LogDetailedFile -Destination $LogExportPath