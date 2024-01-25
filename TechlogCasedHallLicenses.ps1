<#  
.DESCRIPTION
    This script gives checks the usage of CasedHole licenses on vlic05 and vlic14
.NOTES  
    File Name  : TechlogCasedHallLicenses.ps1  
    Version    : 1.0
    Author     : Leif Erik Beten - leeb@equinor.com
    Modifier   : -
    Updated    : 16.01.24
#>

# Define the list of computers to check for license usage
$computerList = "st-vlic05.st.statoil.no", "st-vlic14.st.statoil.no"

# Define the list of license features to check for usage
$licenseFeatures = "tlbase","tlWellIntegrity","O4TL_SLB_WIAP","O4TL_SLB_WIRP","tlAdvancedPlotting","tlTechdataPlus","tlPulsedNeutron","tlPython","O4TL_SLB_PLUGIN_PNX"

# Define a hashtable to map the feature names to their full names for display purposes
$featureNames = @{
    "tlbase" = "Techlog Base"
    "tlWellIntegrity" = "Techlog Wellbore Integrity"
    "O4TL_SLB_WIAP" = "Techlog Wellbore Integrity Suite"
    "O4TL_SLB_WIRP" = "Techlog R+"
    "tlAdvancedPlotting" = "Advanced Plotting"
    "tlTechdataPlus" = "TechData Plus"
    "tlPulsedNeutron" = "Cased Hole"
    "tlPython" = "Python"
    "O4TL_SLB_PLUGIN_PNX" = "Pulsar Processing"
}

# Set the current directory to a folder with lmutil.exe file
Set-Location "C:\Program Files\Schlumberger\Techlog 2022.2.1 (r6462801)\tools"

# Loop through each computer in the list and check license usage for each feature
foreach ($computer in $computerList) {
    Write-Output "Checking license usage on $computer..."

    foreach ($feature in $licenseFeatures) {
        # Get the feature's full name from the hashtable
        $displayName = $featureNames.Get_Item($feature)
        # If the full name is not found, use the feature name as the display name
        if ($displayName -eq $null) {
            $displayName = $feature
        }
        # Run the lmutil command to get the license usage report for the feature on the current server
        $licenseReport = .\lmutil lmstat -a -c 7321@$computer -f $feature
        # Use Select-String to extract the usage summary and usage info from the license report
        $usageSummary = $licenseReport | Select-String -Pattern "Users of $feature*" -AllMatches
        $usageInfo = $licenseReport | Select-String -Pattern ', start' -AllMatches
        # If the usage summary is not null, output the license usage for the feature
        if ($usageSummary -ne $null) {
            Write-Output "License usage for ${displayName}:"
            Write-Output $usageSummary
            Write-Output $usageInfo `n
        }
    }
}

# Wait for user input before exiting the script
Read-Host -Prompt "Press Enter to exit"