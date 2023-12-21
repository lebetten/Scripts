$computerList = "st-vlic05.st.statoil.no", "st-vlic14.st.statoil.no"
$licenseFeatures = "tlbase","tlWellIntegrity","O4TL_SLB_WIAP","O4TL_SLB_WIRP"
$featureNames = @{
    "tlbase" = "Techlog Base"
    "tlWellIntegrity" = "Techlog Wellbore Integrity"
    "O4TL_SLB_WIAP" = "Techlog Wellbore Integrity Suite"
    "O4TL_SLB_WIRP" = "Techlog R+"
}
Set-Location "C:\Program Files\Schlumberger\Techlog 2022.2.1 (r6462801)\tools"

foreach ($computer in $computerList) {
    Write-Output "Checking license usage on $computer..."

    foreach ($feature in $licenseFeatures) {
        $displayName = $featureNames.Get_Item($feature)     # get the feature's full name from the hashtable
        if ($displayName -eq $null) {
            $displayName = $feature                          # if not found, use the feature name
        }
        $licenseReport = .\lmutil lmstat -a -c 7321@$computer -f $feature
        $usageSummary = $licenseReport | Select-String -Pattern "Users of $feature*" -AllMatches
        $usageInfo = $licenseReport | Select-String -Pattern ', start' -AllMatches
        Write-Output "License usage for ${displayName}:"
        Write-Output $usageSummary
        Write-Output $usageInfo `n
    }
}

Read-Host -Prompt "Press Enter to exit"