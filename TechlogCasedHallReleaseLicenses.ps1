<#  
.DESCRIPTION
    This script releases all the Techlog licenses hold by the username entered when starting the script on st-vlic05 and st-vlic14
.NOTES  
    File Name  : TechlogReleaseLicenses.ps1  
    Version    : 1.0
    Author     : Leif Erik Beten - leeb@equinor.com
    Modifier   : -
    Updated    : 16.01.24
#>

# Define the list of license servers to check for license usage
$licenseServers = @("st-vlic05.st.statoil.no", "st-vlic14.st.statoil.no")

# Define the list of license features to check for usage
$licenseFeatures = @("O4TL_SLB_WIAP", "04TL_SLB_WIRP", "tl3DPetrophysics", "tl3DVue", "tlAcoustics", "tlAdvancedPlotting", "tlBase", "tlDataAPIC", "tlDataRecallConnector", "tlDLIS", "tlFieldMap", "tlFPress", "tlGeophy", "tlIpsom", "tlKmod", "tlMessageDataAPI", "tlOpenSpirit", "tlPulsedNeutron", "tlPython", "tlQuanti", "tlQuantiMin", "tlRecall", "tlSHM", "tlSlbToolLock", "tlTechcore", "tlTechdataPlus", "tlTechstat", "tlTransferDataAPI", "tlViewer", "tlWBI", "tlWellIntegrity")

# Set the current directory to a folder with lmutil.exe file
Set-Location "C:\Program Files\Schlumberger\Techlog 2022.2.1 (r6462801)\tools"

# Define a hashtable to map the feature names to their full names for display purposes
$featureNames = @{
    "O4TL_SLB_WIAP" = "Techlog Wellbore Integrity Suite"
    "O4TL_SLB_WIRP" = "Techlog R+"
}

# Prompt the user to enter their username
$username = Read-Host "Enter the username"

# Loop through each license server in the list and release any licenses held by the specified user
foreach ($server in $licenseServers) {
    
    foreach ($feature in $licenseFeatures) {
        # Get the licenses held by the specified user for the current feature on the current server
        $licenses = .\lmutil lmstat -a -c 7321@$server -f $feature | select-string -Pattern "$username"
        # If the user does not hold any licenses for the current feature on the current server, do nothing
        if ($licenses -eq $null) {
        }
        # If the user holds licenses for the current feature on the current server, release them
        else {
            # Extract the session ID from the license information
            $licenses = $licenses.ToString().split(' ')
            $SessionID = $licenses[9].split(')')[0]
            # Use lmremove to release the licenses held by the user for the current feature on the current server
            .\lmutil.exe lmremove -c 7321@$server -h $feature $server 7321 $SessionID
            # Get the feature's full name from the hashtable
            $displayName = $featureNames.Get_Item($feature)
            # If the full name is not found, use the feature name as the display name
            if ($displayName -eq $null) {
                $displayName = $feature
            }
            # Output a message indicating that the feature has been released for the user
            Write-Output "Released feature $displayName for user $username"
        }
    }
}
