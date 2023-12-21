lo# Set the starttime for the script
$StartTime = (Get-Date -Format "yyyy.MM.dd_HH.mm")

# Set the output directory
$outputDir = 'F:\Config\LockFiles'

# Set export paths
$CsvExport = "\\statoil.net\dfs\common\P\PetrelSystem\Cleanup\LockReport\csv"
$LogExport = "\\statoil.net\dfs\common\P\PetrelSystem\Cleanup\LockReport\Log"

# Check if the output directory exists, create it if it doesn't
if (!(Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

# Set the paths to the CSV, input, and log directories
$csvDir = Join-Path $outputDir 'CSV'
$inputDir = Join-Path $outputDir 'input'
$logDir = Join-Path $outputDir 'Log'

# Check if the CSV directory exists, create it if it doesn't
if (!(Test-Path $csvDir)) {
    New-Item -ItemType Directory -Path $csvDir -Force | Out-Null
}

# Check if the input directory exists, create it if it doesn't
if (!(Test-Path $inputDir)) {
    New-Item -ItemType Directory -Path $inputDir -Force | Out-Null
}

# Check if the log directory exists, create it if it doesn't
if (!(Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

# Create the output directory if it doesn't exist
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

# Set the paths to scan from the paths.txt file
$pathsFile = "$inputDir\paths.txt"
$FolderPath = Get-Content $pathsFile

# Set the output CSV file path
$outputFile = "$csvDir\LockFiles-$($Env:ComputerName)-$StartTime.csv"

# Set the log file path
$logFile = "$logDir\LockFiles-$($Env:ComputerName)-$StartTime.log"

# Output the header to the CSV file
"FilePath;Name;Owner;Date" | Out-File -FilePath $outputFile -Encoding utf8

# Initialize the log file
Add-Content -Path $logFile -Value "$(Get-Date) - Starting file scan"

# Define a function to get file attributes and output them to CSV and log
function Get-FileAttributes {
    param (
        [string]$filePath
    )

    # Wait until the file is available
    while (Test-Path $outputFile) {
        $locked = $false
        try {
            $null = Get-Content $outputFile -ErrorAction Stop
        } catch {
            $locked = $true
        }
        if (!$locked) {
            break
        }
        Start-Sleep -Milliseconds 100
    }

    # Get the file attributes
    $file = Get-Item $filePath
    $name = $file.Name
    $owner = (Get-Acl $filePath).Owner
    $date = $file.LastWriteTime
    #$diskSpace = $file.Length

    # Output the file attributes to CSV
    $output = "$filePath;$name;$owner;$($date.ToString('yyyy.MM.dd'))"
    Add-Content -Path $outputFile -Value $output
    #Add-Content -Path $logFile -Value "$(Get-Date) - $output"
}

# Iterate over the files in the first path
foreach($path in $FolderPath) {
Add-Content -Path $logFile -Value "$(Get-Date) - Checking path: $path"
Get-ChildItem -Path $path -Recurse | ForEach-Object {
    # Check if the file is a .lock file
    if ($_.Extension -eq '.lock') {
        # Get the file attributes and output them to CSV
        Get-FileAttributes $_.FullName
    }
}

}
# Log the end of the file scan
Add-Content -Path $logFile -Value "$(Get-Date) - Finished file scan"

move $logFile $LogExport
move $outputFile $CsvExport