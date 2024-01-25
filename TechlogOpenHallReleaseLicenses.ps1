<#  
.DESCRIPTION
    This script releases all the Techlog licenses hold by the username entered when starting the script on st-vlic04 and hou-vlic01
.NOTES  
    File Name  : TechlogReleaseLicenses.ps1  
    Version    : 1.0
    Author     : Leif Erik Beten - leeb@equinor.com
    Modifier   : -
    Updated    : 23.01.24
#>

# Define the list of license servers to check for license usage
$licenseServers = @("st-vlic04.st.statoil.no","hou-vlic01.hou.statoil.no")

# Define the list of license features to check for usage
$licenseFeatures = @("O4TL_SLB_LITH_LOADER","O4TL_SLB_LITH_MANAGER","O4TL_SLB_PETROGRAPHIC_VIEWER","O4TL_SLB_QGEO_PRO_INV","tlDataRecallConnector","tlRecall","tlTransferDataAPI","tlMessageDataAPI","O4TL_SLB_DEPTH_SHIFT","tlOpenSpirit","tl3DPetrophysics","tlAcoustics","tlQuantiMin","O4TL_SLB_CoreImageCropping","tlQuanti","O4TL_SLB_NMR_SUITE","tlNMR","tlFPress","tlDLIS","tlBase","tlSlbToolLock","tlSlbToolLock","tlSHM")

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
