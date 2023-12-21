
<#  
.SYNOPSIS  
    MyPetrel - Role Based Provisiong of Petrel versions & licenses
.DESCRIPTION
    This script gives access to Petrel versions based on roles. 
    Petrel + all setup are synced from network, and software 
    requirements + best practice setups are checked/fixed.
.NOTES  
    File Name  : MyPetrel.ps1  
    Version    : 1.5.5
    Author     : Marius Gjerde Naalsund - mngj@equinor.com
    Modifier   : Sigmund Nessa
    Updated    : 20230421
#>
 param (
        [string]$Mode="Production",
        [ValidateSet('GG','GG_RE','RE','SIP','Admin','Test','VPN','Offline','DataRoom','Production','Geoteric')][string]$ForceMode,
        [string]$Version,
        [ValidateSet('Continue','SilentlyContinue')][string]$Verbose = "SilentlyContinue",
        [string]$MOTDFolder = $Nothing
    ) 

$WrapperRelease = "1.5.5"
$WrapperAuthor = "rnor@equinor.com"

# -----------------------------------------------------------------------------------------
# Environment
# -----------------------------------------------------------------------------------------

$ScriptBaseFolder = Split-Path -Parent $MyInvocation.MyCommand.Definition

#Set Verbose Preference
$VerbosePreference = $Verbose

#Define DNS domains used for ADSI queries
$ComputerDNSDomain = (Get-WMIObject Win32_ComputerSystem).Domain
$UserDNSDomain = $Env:USERDNSDOMAIN

# Make sure default robocopy.exe/nltest.exe is used
$Env:Path = "${Env:SystemRoot}\System32;${Env:Path}"

# Run specified version straight away (if available)
If($Version) {
    
    $SpecificVersion = $Version

} #End If Run Straight


# -----------------------------------------------------------------------------------------
# Functions
# -----------------------------------------------------------------------------------------

Function Start-LoadProgressGUI {
    <#  
    .Description  
        Initiates a Windows Forms GUI show loading progress 
    .Outputs  
        System.Windows.Forms.Form object
    .Parameter WindowTitleText
        Text in title (header) of the window
    .Parameter WindowLabelText
        Text in label object of the window
    .Example  
        Start-LoadProgressGUI
    .Example  
        $Variable = Start-LoadProgressGUI
    #>
    param(
        $WindowsTitleText,
        $WindowsLabelText
    )

    # Load .Net GUI assemblies
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    #Sizing variables
    $WindowHeight = 100
    $WindowWidth = 400
    $ObjectHeight = 15
    $MarginX = 20
    $MarginY = 12

    #Initiate Windows Forms window   
    $LoadProgressGUI = New-Object System.Windows.Forms.Form 
    $LoadProgressGUI.Text = $WindowsTitleText          
    $LoadProgressGUI.FormBorderStyle = "FixedDialog"				
    $LoadProgressGUI.MinimizeBox = $False
    $LoadProgressGUI.MaximizeBox = $False
    $LoadProgressGUI.ShowInTaskbar = $False
    $LoadProgressGUI.BackColor = "LightGray"
    $LoadProgressGUI.ForeColor = "Black"
    $LoadProgressGUI.Size = "$WindowWidth, $WindowHeight"
    $LoadProgressGUI.StartPosition = "CenterScreen"
    
    #Initate label 
    $LoadProgressLabel = New-Object 'System.Windows.Forms.Label'
    $LoadProgressLabel.ForeColor = "Maroon"
    $LoadProgressLabel.Name = "LoadProgressText"
    $LoadProgressLabel.Location = "$MarginX, $MarginY"
    $LoadProgressLabel.Size = "$($WindowWidth - 3*$MarginX), $ObjectHeight"
    $LoadProgressLabel.Text = $WindowsLabelText
        
    $LoadProgressGUI.Controls.Add($LoadProgressLabel)

    #Initiate progress Bar
    $LoadProgressProgressBar = New-Object System.Windows.Forms.ProgressBar
    $LoadProgressProgressBar.Name = 'LoadProgressBar'
    $LoadProgressProgressBar.Value = 1
    $LoadProgressProgressBar.Style="Continuous"
    $LoadProgressProgressBar.Size = "$($WindowWidth - 3*$MarginX), $ObjectHeight"
    $LoadProgressProgressBar.Location = "$MarginX, $(2*$ObjectHeight+5)"
    
    $LoadProgressGUI.Controls.Add($LoadProgressProgressBar)

    #Show GUI and continue processing
    $LoadProgressGUI.Show()

    #Return Windows Forms object to caller
    Return $LoadProgressGUI
} #End Function Start-LoadProgressGUI

Function Update-LoadProgressGUI {
    <#  
    .Description  
        Updates a Windows Forms GUI with progress bar and label with new text and increments percentage for the progress bar.
        Known issue: will be one update behind the call!
    .Input  
        System.Windows.Forms.Form object
    .Parameter WindowsFormsObject
        An object to an already existing Windows Forms UI
    .Parameter UpdateText
        New text to be shown in the label object 
    .Parameter UpdatePercent
        A percentage (0..100) on where the progress bar to be updated to
    .Example  
        Update-LoadProgressGUI -WindowsFormsObject $WindowsFormsObject -IncrementProgressPercent 50 -NewLabelText "Checking disk free space"
    #>
    param(
        $WindowsFormsObject,
        $NewLabelText,
        $IncrementProgressPercent
    )

    #Find the sub-objects in the Windows Forms object
    $ProgressBar =  $WindowsFormsObject.Controls | ?{$_.Name -eq "LoadProgressBar"}
    $ProgressText =  $WindowsFormsObject.Controls | ?{$_.Name -eq "LoadProgressText"}
    
    #Update the objects with new information
    If ($NewLabelText) {
        $ProgressText.Text = $NewLabelText
    }
    If ($IncrementProgressPercent) {
        $ProgressBar.Increment($IncrementProgressPercent)
    }

    #Force fresh of GUI to avoid lag in update
    $WindowsFormsObject.Refresh() 

} #End Function Update-LoadProgressGUI

Function Close-LoadProgressGUI {
    <#  
    .Description  
        Closes a Windows Forms GUI
    .Input  
        System.Windows.Forms.Form object
    .Parameter WindowsFormsObject
        An object to an already existing Windows Forms UI
    .Example  
        Close-LoadProgressGUI -WindowsFormsObject $WindowsFormsObject
    #>
    param(
        $WindowsFormsObject
    )

    #Find the progress bar and set it to 100 percent
    $ProgressBar =  $WindowsFormsObject.Controls | ?{$_.Name -eq "LoadProgressBar"}
    $ProgressBar.Value = 100

    #Close Windows Forms GUI
    $WindowsFormsObject.Close()
} #End Function LoadProgressGUI


Function Start-MyPetrel {
    <#   
    .DESCRIPTION 
        Setting MyPetrel environment and starting the GUI
    .EXAMPLE
        Start-MyPetrel
    #>
    
    #Update load progress GUI
    Update-LoadProgressGUI -WindowsFormsObject $InitiateMyPetrelGUI -IncrementProgressPercent 20

    # Read the .INI file
    $Script:NetworkIniFile = "$ScriptBaseFolder\MyPetrel.ini"
    
    # Temporary hack due to both vbs and ini update:
    IF(!(Test-Path $NetworkIniFile)) {
        & robocopy "G:\Prog\Global\Petrel\Program\MyPetrel" $ScriptBaseFolder "MyPetrel.ini" /R:1 /W:1
    }
    
    $Script:IniSettings = Get-IniContent "$($NetworkIniFile)"

    # Petrel versions
    $Script:VersionsGG = $IniSettings["DEFAULT_VERSIONS"]["GG"].split(",") | % {$_.trim()} | Sort-Object
    $Script:VersionsRE = $IniSettings["DEFAULT_VERSIONS"]["RE"].split(",") | % {$_.trim()} | Sort-Object
    $Script:VersionsSIP = $IniSettings["DEFAULT_VERSIONS"]["SIP"].split(",") | % {$_.trim()} | Sort-Object
    $Script:VersionsTest = $IniSettings["DEFAULT_VERSIONS"]["TEST"].split(",") | % {$_.trim()} | Sort-Object
    $Script:VersionsGeoteric = $IniSettings["DEFAULT_VERSIONS"]["Geoteric"].split(",") | % {$_.trim()} | Sort-Object
  
    # User AD Groups
    $Script:GroupGG = $IniSettings["DEFAULT_USERGROUPS"]["GG"]
    $Script:GroupRE = $IniSettings["DEFAULT_USERGROUPS"]["RE"]
    $Script:GroupTest = $IniSettings["DEFAULT_USERGROUPS"]["TEST"]
    $Script:GroupAdmin = $IniSettings["DEFAULT_USERGROUPS"]["ADMIN"]
    $Script:GroupGeoteric = $IniSettings["DEFAULT_USERGROUPS"]["Geoteric"]
    
    # Computer AD Groups
    $Script:GroupRGS = $IniSettings["DEFAULT_COMPUTERGROUPS"]["RGS"]
    $Script:GroupSIP = $IniSettings["DEFAULT_COMPUTERGROUPS"]["SIP"]
    
    # Petrel Paths
    $Script:NetworkPetrelBase = $IniSettings["DEFAULT_ENVIRONMENT"]["NetworkPetrelBase"]
    $Script:NetworkDataBase = $IniSettings["DEFAULT_ENVIRONMENT"]["NetworkDataBase"]
    $Script:NetworkLogBase = $IniSettings["DEFAULT_ENVIRONMENT"]["NetworkLogBase"]
    $Script:NetworkLogBase = "$($Script:NetworkLogBase)\$(Get-Date -Format "yyyy")"
    $Script:LocalPetrelBase = $IniSettings["DEFAULT_ENVIRONMENT"]["LocalPetrelBase"]

    $Script:LocalPetrelBinFolder = "$LocalPetrelBase\Bin"
    $Script:LocalPetrelConfigFolder = "$LocalPetrelBase\Config"

    #ADInfo
    $Script:ADSiteName = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("System\CurrentControlSet\Services\NetLogon\Parameters").GetValue("DynamicSiteName").Split([Char]0)[0]

    #Global variables
    $Script:SyncNewVersion = $False         #Used to keep track of if new Petrel version is being loaded

    #Kick off async jobs
    $Script:JobStartCleanupTaskCheck = Start-Job -Name CleanupTaskCheck -ScriptBlock {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;Invoke-WebRequest $args[0] -UseDefaultCredentials | ConvertFrom-Json} -ArgumentList "$($IniSettings["PETREL_PORTAL"]["CleanupPortalURL"])/JSon/$($Env:UserName).json"
    $Script:JobStartLicenseCheck = Start-Job -Name LicenseCheck -ScriptBlock {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;Invoke-WebRequest $args[0] -UseDefaultCredentials | ConvertFrom-Json} -ArgumentList "$($IniSettings["PETREL_PORTAL"]["LicensePortalURL"])/JSon/$($Env:UserName).json"
    $Script:RunspaceLicenseServerCheck = Test-TCPPortUsingRunspace -HostName $IniSettings["LICENSESERVER"]["Verify"].Split("@")[1] -Port $IniSettings["LICENSESERVER"]["Verify"].Split("@")[0] -TimeOut $IniSettings["LICENSESERVER"]["Timeout"]

    #Update load progress GUI
    Update-LoadProgressGUI -WindowsFormsObject $InitiateMyPetrelGUI -IncrementProgressPercent 20

    # Available disk space
    $Script:FreeSpace = (Get-WmiObject Win32_LogicalDisk | Where-Object {$_.DeviceID -eq $Env:SystemDrive}).FreeSpace
    $Script:RequiredFreeSpace = 5GB
    If ($FreeSpace -lt $RequiredFreeSpace) {
        $Script:DiskFreeSpaceCheck = $False
    }
    Else {
        $Script:DiskFreeSpaceCheck = $True
    }

    #Update load progress GUI
    Update-LoadProgressGUI -WindowsFormsObject $InitiateMyPetrelGUI -IncrementProgressPercent 20

    # Customized message of the day based on date/location
    If (!($MOTDFolder)) {
        $MOTDFolder = "G:\appl\UBA\Petrel\MOTD"
    }
    $MOTD_Date = (Get-Date -Format "yyyy-MM-dd")
    If (Test-Path "$MOTDFolder\MOTD_$($MOTD_Date)_$($ADSiteName).html") {
        Write-DebugLog "Setting MOTD file to $MOTDFolder\MOTD_$($MOTD_Date)_$($ADSiteName).html"
        $Script:NetworkMotdFile = "$MOTDFolder\MOTD_$($MOTD_Date)_$($ADSiteName).html"        
    }
    ElseIf (Test-Path "$MOTDFolder\MOTD_$($MOTD_Date).html") {
        Write-DebugLog "Setting MOTD file to $MOTDFolder\MOTD_$($MOTD_Date).html"
        $Script:NetworkMotdFile = "$MOTDFolder\MOTD_$($MOTD_Date).html"
    }
    Else {
        Write-DebugLog "Setting MOTD file to default file $NetworkPetrelBase\motd.html"
        $Script:NetworkMotdFile = "$NetworkPetrelBase\motd.html"
    }

    # Shortcut path
    $Script:ShortcutFolder = ${Env:Appdata} + "\Microsoft\Windows\Start Menu\Programs\Schlumberger"
    $Script:ScriptPath = $LocalPetrelBase + "\startup.vbs"

    # Dongle environment
    $Script:NetworkDongleFolder = "$NetworkPetrelBase\Config\Dongle"
    $Script:LocalDongleFolder = "$LocalPetrelBase\Dongle"
    $Script:CodemeterCmuExeFile = ${ENV:ProgramFiles(x86)} + "\CodeMeter\Runtime\bin\cmu32.exe"
    $Script:LmgrdFolder = $LocalDongleFolder
    $Script:LmgrdExeFile = "$LmgrdFolder\lmgrd.exe"

    # Oracle -> Studio
    # $ENV:TNS_ADMIN = $IniSettings["DEFAULT_ENVIRONMENT"]["TNS_ADMIN"]
    # $ENV:LNS_lang= ""
    
    #OS version
    $Script:OSVersion = [System.Version](Get-WmiObject Win32_OperatingSystem).Version
    If ($OSVersion.Major -eq 6 -And $OSVersion.Minor -eq 1) {
        $Script:OS = "WIN7"
    }
    ElseIf ($OSVersion.Major -eq 6 -And $OSVersion.Minor -ge 2) {
        $Script:OS = "WIN8"
    }
    ElseIf ($OSVersion.Major -ge 10) {
        $Script:OS = "WIN10"
    }
    Else {
        $Script:OS = "UNKNOWN"
    }

    #Check if there is a previous cleanup that has failed
    $BackupPetrelBinFolder = "$($LocalPetrelBinFolder)_bck"
    If (Test-Path $BackupPetrelBinFolder) {
        Write-DebugLog "Found folder $BackupPetrelBinFolder from previous cleanup, start cleanup job as a new background task"
        Start-Job -Scriptblock { Remove-Item $args[0] -Recurse -Force } -ArgumentList $BackupPetrelBinFolder
    }

    #Install the User Environment Variables defined in the INI file
    Update-Userenvvariables
    
    # Start the GUI
    Show-MyPetrel
    
} #End Function Start-MyPetrel



Function Get-IniContent {  
    <#  
    .Synopsis  
        Gets the content of an INI file       
    .Description  
        Gets the content of an INI file and returns it as a hashtable  
    .Inputs  
        System.String  
    .Outputs  
        System.Collections.Hashtable  
    .Parameter FilePath  
        Specifies the path to the input file.  
    .Example  
        $FileContent = Get-IniContent "C:\myinifile.ini"  
        -----------  
        Description  
        Saves the content of the c:\myinifile.ini in a hashtable called $FileContent  
    .Example  
        $inifilepath | $FileContent = Get-IniContent  
        -----------  
        Description  
        Gets the content of the ini file passed through the pipe into a hashtable called $FileContent  
    .Example  
        C:\PS>$FileContent = Get-IniContent "c:\settings.ini"  
        C:\PS>$FileContent["Section"]["Key"]  
        -----------  
        Description  
        Returns the key "Key" of the section "Section" from the C:\settings.ini file   
    #>    
    [CmdletBinding()]  
    Param(  
        [ValidateNotNullOrEmpty()]  
        [ValidateScript({(Test-Path $_) -and ((Get-Item $_).Extension -eq ".ini")})]  
        [Parameter(ValueFromPipeline=$True,Mandatory=$True)]  
        [string]$FilePath  
    )  
        
    $ini = @{}  
    switch -regex -file $FilePath {  
        "^\[(.+)\]$" # Section  
            {  
                $section = $matches[1]  
                $ini[$section] = @{}  
                $CommentCount = 0  
            }  
        "^(;.*)$" # Comment  
            {  
		        Continue
            }   
        "(.+?)\s*=\s*(.*)" # Key  
            {  
                if (!($section))  
                {  
                    $section = "No-Section"  
                    $ini[$section] = @{}  
                }  
                $name,$value = $matches[1..2]  
                $ini[$section][$name] = $value  
            }  
        }  

        Return $ini  
 
} #end function get-inicontent


Function Get-MyADGroups {
    <#   
    .DESCRIPTION 
        Get my AD groups
    .EXAMPLE
        Get-MyADGroups
    #>
    If (!($Script:GlobalMyADGroups)) {
        $Script:GlobalMyADGroups = ((New-Object ADSISearcher([ADSI]"LDAP://$UserDNSDomain","(samaccountname=$Env:UserName)")).FindOne().Properties.memberof -replace '^CN=([^,]+).+$','$1') | % { $_.ToLower() } 
    }
    Return $Script:GlobalMyADGroups
        
} #end Function Get-MyADGroups


Function Get-MyADUserProperty {
    <#   
    .DESCRIPTION 
        Get one or all AD properties from current user
    .PARAMETER Property
        AD user property to search for 
    .EXAMPLE
        Get-MyADUserProperty GivenName
    #>
    param (
        [string] $Property
        )

    If (!($Script:GlobalMyADUserProperties)) {
        $Script:GlobalMyADUserProperties = (New-Object ADSISearcher([ADSI]"LDAP://$UserDNSDomain","(samaccountname=$Env:UserName)")).FindOne().Properties 
    }

    If($Property) {
        $Script:GlobalMyADUserProperties.$($Property)
    } Else {
        $Script:GlobalMyADUserProperties
    } # end if property specified
    
} #end Function Get-MyADGroups


Function Write-Log {
    <#   
    .DESCRIPTION 
        Append to Petrel log file
    .PARAMETER Text
        Text to be appended
    .PARAMETER LogFile
        Logfile to be appended to 
    .EXAMPLE
        Write-Log "Hello World!" "C:\Temp\Temp.log"
    #>
    param (
            [string]$LogText,
            [string]$LogFile
        )
    
    $Now = Get-Date -uFormat %Y%m%d%H%M%S
    #$UserName = ($Env:Username).ToLower()
    #$ComputerName = ($Env:Computername).ToLower()
   
    [string]$LogString = "$Now;$(($Env:Username).ToLower());$(($Env:ComputerName).ToLower());$OSVersion;$ADSiteName;$PetrelVersion;$Latency;$Bandwidth;$($LogText.Trim())"
    
    # Writing to network log files can take time -> run as background job
    If($Logfile.StartsWith("G")) {
    
        Start-Job -ScriptBlock { Add-Content $args[0] -Value $args[1] } -Argumentlist $LogFile,$LogString | Out-Null
    
    } Else { 
    
        Add-Content "$LogFile" -Value "$LogString" 
    }

} #End Function Write-Log


Function Write-UpgradeLog {
    <#   
    .DESCRIPTION 
        Log Petrel upgrades
    .PARAMETER Text
        Text to be appended
    .EXAMPLE
        Write-UpgradeLog "Hello World!" 
    #>
    param (
            [string] $Text
            )

    $LogFile = "$NetworkLogBase\PetrelUpgrade.log"
    Write-Log "$Text" "$LogFile"
        
} # end Function Write-UpgradeLog


Function Write-ErrorLog {
    <#   
    .DESCRIPTION 
        Log Petrel errors
    .PARAMETER Text
        Text to be appended
    .EXAMPLE
        Write-ErrorLog "Hello World!" 
    #>
    param (
            [string] $Text
            )

    $LogFile = "$NetworkLogBase\PetrelError.log"
    Write-Log "$Text" "$LogFile"
        
} # end Function Write-ErrorLog


Function Write-PrerequisiteLog {
    <#   
    .DESCRIPTION 
        Log Petrel prerequisite autofix/missing
    .PARAMETER Text
        Text to be appended
    .EXAMPLE
        Write-PrerequisiteLog ".Net 4.5" 
    #>
    param (
            [string] $Text
            )

    $LogFile = "$NetworkLogBase\PetrelPrerequisites.log"
    Write-Log "$Text" "$LogFile"
        
} # end Function Write-PrerequisiteLog


Function Write-UsageLog {
    <#   
    .DESCRIPTION 
        Log all Petrel startups to a global usage file
    .PARAMETER Text
        Text to be appended
    .EXAMPLE
        Write-UsageLog "Test Mode, 27009@petrel-lic-no.statoil.net"
    #>
    param (
        [string]$Text
    )

    $LogFile = "$NetworkLogBase\PetrelUsage.log"
    Write-Log "$Text" "$LogFile"
        
} # end Function Write-UsageLog

Function Write-DongleLog {
    <#   
    .DESCRIPTION 
        Log all dongle license downloads to a global dongle file
    .PARAMETER Text
        Dongle ID
    .EXAMPLE
        Write-DongleLog "2-222141"
    #>
    param (
            [string] $Text
            )

    $LogFile = "$NetworkLogBase\PetrelDongle.log"
    Write-Log "$Text" "$LogFile"
        
} # end Function Write-DongleLog

Function Write-DebugLog {
    <#   
    .DESCRIPTION 
        Write to Petrel debug log  
    .PARAMETER Text
        Text to be appended
    .EXAMPLE
        Write-DebugLog "Starting Petrel 2015.3" 
    #>
    param (
            [string] $Text
            )

    $LogFile = "$($Env:Temp)\MyPetrel-$(Get-Date -Format "yyyy").log"
    Write-Log "$Text" "$LogFile"
    Write-Verbose "$(Get-Date -Format G) $Text"
        
} # end Function Write-DebugLog


Function Get-VPN {
    <#   
    .DESCRIPTION 
        Check if machine is running VPN
    .EXAMPLE
        Get-VPN
        Return count of connected VPN network adapters (ie. that have IpAddress)
    #>
    
    #Get number of connected Cisco AnyConnect adapters from WMI
	@(Get-WmiObject -class "Win32_NetworkAdapterConfiguration" | ? {$_.Description -like "*Cisco AnyConnect*" -and $_.IpAddress -ne $Null}).Count


} #End Function Get-VPN


Function Get-NetworkStatus {
    <#   
    .DESCRIPTION 
        Check if machine is connected to the Equinor network
    .EXAMPLE
        Get-NetworkStatus
        Return Online or Offline
    #>

    $PingEquinor = Test-Connection statoil.net -count 1
    
    $IPv4 = $PingEquinor.IPv4Address
    $IPv6 = $PingEquinor.IPv6Address
    
    If($IPv4) {
    
        # IPv4 address is only given while connected to Equinor network 
        Write-DebugLog "The machine is online" 
        "Online"
    
    } ElseIf($IPv6 -and !($IPv4)) {
    
        # Offline Equinor machine - only an IPv6 address is given
        Write-DebugLog "The machine is 95% offline" 
        "Offline"
        
    } Else {
    
        # No IP address given - totally offline or no Equinor machine
        Write-DebugLog "The machine is 100% offline"
        "Offline"
    }

} #End Function Get-NetworkStatus


Function Get-Latency {
    <#   
    .DESCRIPTION 
        Get latency in ms towards logon server
    .EXAMPLE
        Get-Latency
    #>
    
    $LogonServer = $Env:LogonServer.Replace("\\","")  
    $Response = @()
    
    # 3 ping tests. No delay.  
    1..3 | % { $Response += Test-Connection $LogonServer -count 1 }
    $Latency = ($Response | Measure-Object ResponseTime -Minimum).Minimum
    
    Write-DebugLog "Latency measured to $Latency ms towards LogonServer $LogonServer"
    $Latency

} #End Function Get-Latency


Function Get-BandWidth {
    <#   
    .DESCRIPTION 
        Get bandwidth/troughput in Mbps from G:\Prog to client by reading network files
        in two steps (one tiny (<100kb) and one medium (~5MB))
    .EXAMPLE
        Get-BandWidth
    #>
    
    $TargetDir = $Env:Temp
     
    $SourceDir = "$($NetworkDataBase)\BandWidthCheck"
    
    # Step 1: Read a tiny file
    
    $TinyFile = "$SourceDir\TinyFile.test"    
    $TinySize = (Get-ChildItem $TinyFile).Length
    
    $ReadTiny = Measure-Command { Copy-Item $TinyFile $TargetDir }   
    $TinyMbps = [Math]::Round((($TinySize * 8) / $ReadTiny.TotalSeconds) / 1MB)
    
    # Step 2: If above 3G-level,- Read a medium file
    If($TinyMbps -lt 2) {
    
        $TinyKbps = [Math]::Round((($TinySize * 8) / $ReadTiny.TotalSeconds) / 1KB)
        Write-DebugLog "Low bandwidth - measured to $TinyMbps Mbps ($TinyKbps Kbps)."
    
        Return $TinyMbps
    
    } Else {
                
        $MediumFile = "$SourceDir\MediumFile.test"
        $MediumSize = (Get-ChildItem $MediumFile).Length
        
        $ReadMedium = Measure-Command { Copy-Item $MediumFile $TargetDir }
        $MediumMbps = [Math]::Round((($MediumSize * 8) / $ReadMedium.TotalSeconds) / 1MB)
        
               
        If ($MediumMbps -lt 50) {

            Write-DebugLog "Medium bandwidth - measured to $MediumMbps Mbps"
            Return $MediumMbps

        }
        # Step 3: Good connectivity, read a large file
        Else {
            $LargeFile = "$SourceDir\LargeFile.test"
            $LargeSize = (Get-ChildItem $LargeFile).Length

            $ReadLarge = Measure-Command { Copy-Item $LargeFile $TargetDir }
            $LargeMbps = [Math]::Round((($LargeSize * 8) / $ReadLarge.TotalSeconds) / 1MB)

            Write-DebugLog "High bandwidth - measured to $LargeMbps Mbps"
            Return $LargeMbps
        }

        
    
    } # End If on a slow network
    
} #End Function Get-BandWidth


Function Get-MyMode {
    <#   
    .DESCRIPTION 
        Get mode based on who and where I am, and what I want
    .EXAMPLE
        Get-MyMode
        Return my production mode 
    .EXAMPLE
        Get-MyMode -Mode Test
        Return test mode
    #>
    param(
        [string] $Mode
    )

    If ($ForceMode) {
        Write-DebugLog "Force Petrel Mode selected - setting MyMode to $ForceMode"
        Return $ForceMode
    }

    $MyGroups = Get-MyADGroups 
    If($GroupSIP) {
        $OmegaMachine = Get-ADComputerGroup $GroupSIP
    }
    $RunningVPN = Get-VPN
    $NetworkStatus = Get-NetworkStatus 

    If ($RunningVPN -ge 1) {
        
        # Running through VPN
        # - no 'clear petrel settings'
        # - no user check
        Write-DebugLog "Putting on the Petrel VPN hat" 
        Write-DebugLog "Only preinstalled version available" 
        Return "VPN" 
        
    } ElseIf ($NetworkStatus -eq "Offline") {
    
        # Exception for Data Rooms 
        If($($env:USERNAME).ToLower().StartsWith("guest_")) {
        
            # Data Room mode, no contact with statoil.net
            Write-DebugLog "Putting on the Petrel DataRoom hat"
            Return "DataRoom"

        } Else {
            
            # Offline mode, no contact with statoil.net
            Write-DebugLog "Putting on the Petrel Offline hat"
            Return "Offline"        
        
        }
    
    } ElseIf (($Mode -eq "Test") -and ($MyGroups -contains $GroupTest)) {
          
        # In test mode 
        Write-DebugLog "Putting on the Petrel Test hat"  
        Return "Test"
        
    #} ElseIf (($Mode -eq "Admin") -and ($MyGroups -contains $GroupAdmin)) {
    } ElseIf ($Mode -eq "Admin") {
    
        # In test mode  
        Write-DebugLog "Putting on the Petrel Admin hat" 
        Return "Admin"
    
    } Else {
    
        If ($OmegaMachine) {
    
            # Prod mode, access to SIP
            # - On SIP Machine 
            # - no user check
            Write-DebugLog "Putting on the Petrel SIP hat" 
            Return "SIP" 

        } Else {
        
            If ($MyGroups -contains "$GroupGeoteric") {
            
            # Prod mode, only access to Geoteric
            Write-DebugLog "Putting on the Petrel Geoteric hat"
            Return "Geoteric"
            
            } ElseIf (($MyGroups -match "^$GroupGG") -and ($MyGroups -contains "$GroupRE")) {
            
                # Prod mode, access to both GG and RE
                Write-DebugLog "Putting on both the Petrel GG and RE hat"
                Return "GG_RE" 
            
            } ElseIf ($MyGroups -match "^$GroupGG")  {
            
                # Prod mode, only access to GG
                Write-DebugLog "Putting on the Petrel GG hat"
                Return "GG"
            
            } ElseIf ($MyGroups -contains "$GroupRE") {
            
                # Prod mode, only access to RE
                Write-DebugLog "Putting on the Petrel RE hat"
                Return "RE"
                        
            } ElseIf (!$MyGroups) {
                
                # Offline mode, no contact with AD
                Write-DebugLog "Putting on the Petrel Offline hat"
                Return "Offline" 
            
            } #end if GG or RE
        } #end if on omega machine or not
   } #end if test/admin/prod mode 
} #end function Get-MyMode


Function Get-MyPetrelVersions {
    <#   
    .DESCRIPTION 
        Get available Petrel versions based on mode
    .EXAMPLE
        Get-MyPetrelVersions GG
        Get all Petrel GG production versions 
    .EXAMPLE
        Get-MyPetrelVersions -Mode Test
        Get all Petrel test versions 
    #>
    param ( [string] $Mode )

    Switch -WildCard ($Mode) {
    
        "Test" {
                Return $VersionsTest
                Break
        }
        "Admin" {
                #[array] $Versions = ls "$($NetworkPetrelBase)\Bin" | ? {$_.name -like "20*" } | Select Name
                $VersionsAdmin = @()
                Get-ChildItem "$($NetworkPetrelBase)\Bin" | ? {$_.name -like "20*" } | Select Name | % { $VersionsAdmin += $_.Name }
                Return ($VersionsAdmin | Sort-Object)
                Break
        }
        "SIP" {
                Return $VersionsSIP
                Break
        }
        "GG_RE" {
                Return ($VersionsGG,$VersionsRE | % {$_.trim()} | Sort-Object | Get-Unique)
                Break
        }
        "GG" {
                Return $VersionsGG
                Break
        }
        "RE" {
                Return $VersionsRE
                Break
        }
        "Geoteric" {
                Return $VersionsGeoteric
                Break
        }
        "VPN" {
                $VersionsVPN = @()
                Get-ChildItem "$($LocalPetrelBase)\Bin\*\Petrel.exe" | ? {$_.DirectoryName -like "$($LocalPetrelBase)\Bin\20*" } | Select DirectoryName | %{$VersionsVPN += $_.DirectoryName.Substring($_.DirectoryName.LastIndexOf("\")+1)}
                Return ($VersionsVPN | Sort-Object)
                Break
        }
        "Offline" {
                $VersionsOffline = @()
                Get-ChildItem "$($LocalPetrelBase)\Bin\*\Petrel.exe" | ? {$_.DirectoryName -like "$($LocalPetrelBase)\Bin\20*" } | Select DirectoryName | %{$VersionsOffline += $_.DirectoryName.Substring($_.DirectoryName.LastIndexOf("\")+1)}
                Return ($VersionsOffline | Sort-Object)
                Break
        }
        "DATAROOM" {
                $VersionsDataRoom = @()
                Get-ChildItem "$($LocalPetrelBase)\Bin\*\Petrel.exe" | ? {$_.DirectoryName -like "$($LocalPetrelBase)\Bin\20*" } | Select DirectoryName | %{$VersionsDataRoom += $_.DirectoryName.Substring($_.DirectoryName.LastIndexOf("\")+1)}
                Return ($VersionsDataRoom | Sort-Object)
                Break
        }

    } #end switch mode
} #end Function Get-MyPetrelVersions


Function Show-MyPetrel {
    <#   
    .DESCRIPTION 
         Run MyPetrel Interactive GUI
    .EXAMPLE
        Show-MyPetrel
    #>

    #Update load progress GUI
    Update-LoadProgressGUI -WindowsFormsObject $InitiateMyPetrelGUI -IncrementProgressPercent 20
       
    # Load .Net GUI assemblies
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    
    # Use OS theme (=rich style)
    [System.Windows.Forms.Application]::EnableVisualStyles() 
    
    # MyMode
    $MyMode = Get-MyMode $Mode

    # MyVersions
    $MyVersions = Get-MyPetrelVersions $MyMode

    # Latency & BandWidth (troughput)
    If(!($MyMode -eq "Offline")) {
    
        $Latency = Get-Latency
        $BandWidth = Get-BandWidth
    }
    
    # Local Version available?
    $LocalVersion = (Get-ChildItem $LocalPetrelBinFolder | Select-Object -first 1).basename   

    If ($LocalVersion) {
    
        Set-PetrelVersion $LocalVersion
    
        # Only run directly if user has access to the version
        If($MyVersions -contains $SpecificVersion) { 

            $RunSpecificVersion = $True
        
        } #end if running directly
           
    } Else {

        Set-PetrelVersion $MyVersions[0]
     
    } #end if local version available
         
    # Extract Icon from current Petrel installation
    If(Test-Path $LocalPetrelExeFile) {

        $PetrelIcon = [system.drawing.icon]::ExtractAssociatedIcon("$LocalPetrelExeFile")

    } Else {  

        $PetrelIcon = [system.drawing.icon]::ExtractAssociatedIcon("$NetworkPetrelVersionBinExeFile")   
         
    } #end if icon
    
    # Fixed sizes / margins 
    $MyPetrelWidth = 585
    $GroupboxWidth = 530
    $MarginWidth = 20
    $MarginHeight = 25
    $GroupboxContentWidth = $GroupboxWidth - (2 * $MarginWidth)

    $DefaultFontSize = 9
    $ButtonFontSize = 8

    #HTML webbrowser control placement in groupbox
    $HTMLWidth = 7
    $HTMLHeight = 12
    #HTML buffer size at bottom of groupbx
    $HTMLGroupBoxBuffer = 15
       

    # DPI aware -31012018/RNOR -> Exclude Win10 from this
    
    If ($Script:OS -ne "WIN10") {

        # - resizes font size if users have display on 125% or 150%
        $AppliedDPI = (Get-ItemProperty -path "HKCU:\Control Panel\Desktop\WindowMetrics" -name AppliedDPI).AppliedDPI

        If($AppliedDPI -gt 100) {

           $DefaultFontSize = ($DefaultFontSize * 96) / $AppliedDPI
           $ButtonFontSize = ($ButtonFontSize * 96) / $AppliedDPI
           Write-DebugLog "MyPetrel DPI setting: DefaultFontSize=$DefaultFontSize ButtonFontSize=$ButtonFontSize"
       
        } # end if DPI is set above default
    }

    # Colors+ from INI file
    If($IniSettings["GUI_$MyMode"]) {
        $Title = $IniSettings["GUI_$MyMode"]["Title"]
        $BackgroundColor = $IniSettings["GUI_$MyMode"]["BackgroundColor"]
        $TextColor = $IniSettings["GUI_$MyMode"]["TextColor"]
        $HighlightTextColor = $IniSettings["GUI_$MyMode"]["HighlightTextColor"]
        $ButtonTextColor = $IniSettings["GUI_$MyMode"]["ButtonTextColor"]
        $ButtonBackgroundColor = $IniSettings["GUI_$MyMode"]["ButtonBackgroundColor"]
        $ButtonClickedBackgroundColor = $IniSettings["GUI_$MyMode"]["ButtonClickedBackgroundColor"]

    } #End if ini settings for $Mode
    
    If(!$Title) { $Title = $IniSettings["GUI_DEFAULT"]["Title"] }
    If(!$BackgroundColor) { $BackgroundColor = $IniSettings["GUI_DEFAULT"]["BackgroundColor"] }
    If(!$TextColor) { $TextColor = $IniSettings["GUI_DEFAULT"]["TextColor"] }
    If(!$HighlightTextColor) { $HighlightTextColor = $IniSettings["GUI_DEFAULT"]["HighlightTextColor"] }
    If(!$ButtonTextColor) { $ButtonTextColor = $IniSettings["GUI_DEFAULT"]["ButtonTextColor"] }
    If(!$ButtonBackgroundColor) { $ButtonBackgroundColor = $IniSettings["GUI_DEFAULT"]["ButtonBackgroundColor"] }
    If(!$ButtonClickedBackgroundColor) { $ButtonClickedBackgroundColor = $IniSettings["GUI_DEFAULT"]["ButtonClickedBackgroundColor"] }
 
    
    # Portal URLs
    $PetrelSupportPortalURL = $IniSettings["PETREL_PORTAL"]["PetrelSupportPortalURL"]
    $PetrelSystemPortalURL = $IniSettings["PETREL_PORTAL"]["PetrelSystemPortalURL"]
    $CleanupPortalURL = $IniSettings["PETREL_PORTAL"]["CleanupPortalURL"]

    # Fonts
	$TextFont = New-Object System.Drawing.Font("Arial",$DefaultFontSize,[System.Drawing.FontStyle]::Regular)	
    $TextBoldFont = New-Object System.Drawing.Font("Arial",$DefaultFontSize,[System.Drawing.FontStyle]::Bold)	
    $TextItalicFont = New-Object System.Drawing.Font("Arial",$DefaultFontSize,[System.Drawing.FontStyle]::Italic)	
    $InfoTextFontSize = 30
  
    #Checkboxes
    $CheckBoxSpacerHeight = 5

    # Buttons
    $ButtonFont = New-Object System.Drawing.Font([System.Drawing.Font],$ButtonFontSize,[System.Drawing.FontStyle]::Regular)
    $ButtonClickedFont = New-Object System.Drawing.Font([System.Drawing.Font],$ButtonFontSize,[System.Drawing.FontStyle]::Italic)
    $ButtonHeight = 25
    $ButtonWidth = 150
    $ButtonSpacerWidth = 20           
    $ButtonSpacerHeight = 10
   
    $LineHeight = 14   
            
    # Dynamic groupbox heights controlled by pointer on Y axis   
    $Script:GlobalPointerY = $MarginHeight   
    
    #######################
    # GUI Skeleton
    #######################
    
    #  
	# Main Frame
    #
    
    $MyPetrelGUI = New-Object System.Windows.Forms.Form 
    $MyPetrelGUI.Text = "$Title - v.$WrapperRelease"             
    $MyPetrelGUI.FormBorderStyle = "FixedDialog"				
    $MyPetrelGUI.MinimizeBox = $False
    $MyPetrelGUI.MaximizeBox = $False
    $MyPetrelGUI.ShowInTaskbar = $True
    $MyPetrelGUI.KeyPreview = $True		
    $MyPetrelGUI.Icon = $PetrelIcon
    $MyPetrelGUI.BackColor = "$BackgroundColor"
    $MyPetrelGUI.ForeColor = "$TextColor"
    $MyPetrelGUI.Width = $MyPetrelWidth
    
    $ToolTip = New-Object System.Windows.Forms.Tooltip
    $ToolTip.AutomaticDelay = 1000
    
    #
    # 1. Info 
    #
    
    $Info = New-Object System.Windows.Forms.Groupbox   
    $Info.Font = $TextBoldFont 
    $info.Location = "$MarginWidth, $MarginHeight"
    $Info.Width = $GroupboxWidth
    #$Info.Autosize = $True
    $Info.Name = "Info"
    $Info.Text = "Info" 
    $Info.ForeColor = "$TextColor"
    $MyPetrelGUI.Controls.Add($Info)

    $InfoText = New-Object System.Windows.Forms.WebBrowser
    $InfoText.Name = "InfoText"
    $InfoText.Location = "$HTMLWidth, $HTMLHeight"
    $InfoText.Width = $GroupboxContentWidth
    $InfoText.Height = 30
    $InfoText.ScrollBarsEnabled = $False
    #$InfoText.AutoSize = $True
    $InfoText.SendToBack()
    $Info.Controls.Add($InfoText)
    
    $ToolTip.SetToolTip($InfoText, "Version: $WrapperRelease`nAuthor: $WrapperAuthor")
    
    #
    # 2. Cleanup Info
    #

    $CleanupCheck = New-Object 'System.Windows.Forms.Groupbox'
    $CleanupCheck.Font = $TextBoldFont
    $CleanupCheck.Location = "$MarginWidth, 70"
    $CleanupCheck.Width = $GroupboxWidth
    $CleanupCheck.Height = 50
    $CleanupCheck.Name = "CleanupCheck"
    $CleanupCheck.Text = "Cleanup tasks"
    $CleanupCheck.ForeColor = "$TextColor"
    $CleanupCheck.Visible = $False

    $CleanupCheckText =  New-Object System.Windows.Forms.WebBrowser
    $CleanupCheckText.Name = "CleanupCheckText"
    $CleanupCheckText.Location = "$HTMLWidth, $HTMLHeight"
    $CleanupCheckText.Width = $GroupboxContentWidth
    $CleanupCheckText.Height = 20
    $CleanupCheckText.ScrollBarsEnabled = $False
    $CleanupCheckText.SendToBack()
    $CleanupCheckText.Visible = $False
    
    $ToolTip.SetToolTip($CleanupCheckText, "Lists your current data cleanup tasks")

    $MyPetrelGUI.Controls.Add($CleanupCheck)
    $CleanupCheck.Controls.Add($CleanupCheckText)


    #
    # 3. System Check
    #
    
    $SystemCheck = New-Object 'System.Windows.Forms.Groupbox'
    $SystemCheck.Font = $TextBoldFont
    $SystemCheck.Location = "$MarginWidth, 90"
    $SystemCheck.Width = $GroupboxWidth
    $SystemCheck.Height = 50
    $SystemCheck.Name = "SystemCheck"
    $SystemCheck.Text = "System check"
    $SystemCheck.ForeColor = "$TextColor"

    $SystemCheckText =  New-Object System.Windows.Forms.WebBrowser
    #$SystemCheckText = New-Object 'System.Windows.Forms.Label'
    #$SystemCheckText.Font = $TextFont
    $SystemCheckText.Name = "SystemCheckText"
    $SystemCheckText.Location = "$HTMLWidth, $HTMLHeight"
    $SystemCheckText.Width = $GroupboxContentWidth
    $SystemCheckText.Height = 20
    $SystemCheckText.ScrollBarsEnabled = $False
    $SystemCheckText.SendToBack()
    #$SystemCheckText.Text = "Checking settings..."

    $ToolTip.SetToolTip($SystemCheckText, "Please consult the Petrel portal for Petrel best practices")

    $MyPetrelGUI.Controls.Add($SystemCheck)
    $SystemCheck.Controls.Add($SystemCheckText)


    
    #
    # 4. Version 
    #
   
    $PickVersion = New-Object System.Windows.Forms.GroupBox
    $PickVersion.Font = $TextBoldFont
    $PickVersion.Location = "$MarginWidth, 110"
    $PickVersion.Size = "$GroupboxWidth, 50"
    $PickVersion.Name = "Versions"
    $PickVersion.Text = "Versions"
    $PickVersion.ForeColor = "$TextColor"
    
    $MyPetrelGUI.Controls.Add($PickVersion)    

    $PickVersionKillAllBox = New-Object System.Windows.Forms.CheckBox 
    $PickVersionKillAllBox.Location = "$MarginWidth, $MarginHeight"
    $PickVersionKillAllBox.Font = $TextItalicFont
    $PickVersionKillAllBox.Size = "$(2*$ButtonWidth), 20"
    $PickVersionKillAllBox.Checked = $False
    $PickVersionKillAllBox.Text = "Clear Petrel settings" 
    $PickVersion.Controls.Add($PickVersionKillAllBox)
    
    $ToolTip.SetToolTip($PickVersionKillAllBox, "Revert to 'factory settings' and resync the Petrel version")
    
    $PickVersionTestPluginsBox = New-Object System.Windows.Forms.CheckBox 
    #$PickVersionTestPluginsBox.Location = "$MarginWidth, $(3 * $MarginHeight)"
    $PickVersionTestPluginsBox.Font = $TextItalicFont
    $PickVersionTestPluginsBox.Size = "$(2*$ButtonWidth), 0"
    $PickVersionTestPluginsBox.Checked = $False
    $PickVersionTestPluginsBox.Text = "Enable test plugins" 
    $PickVersionTestPluginsBox.Enabled = $False
    $PickVersion.Controls.Add($PickVersionTestPluginsBox)
    
    $ToolTip.SetToolTip($PickVersionTestPluginsBox, "Enable all test plugins")

    $PickVersionKeepPluginsBox = New-Object System.Windows.Forms.CheckBox 
    #$PickVersionKeepPluginsBox.Location = "$MarginWidth, $(2 * $MarginHeight)"
    $PickVersionKeepPluginsBox.Font = $TextItalicFont
    $PickVersionKeepPluginsBox.Size = "$(2*$ButtonWidth), 0"
    $PickVersionKeepPluginsBox.Checked = $False
    $PickVersionKeepPluginsBox.Text = "Enable production plugins" 
    $PickVersionKeepPluginsBox.Enabled = $False
    $PickVersion.Controls.Add($PickVersionKeepPluginsBox)
    
    $ToolTip.SetToolTip($PickVersionKeepPluginsBox, "Enable all production plugins")
    
    $PickVersionEnableHistoryCleanBox = New-Object System.Windows.Forms.CheckBox 
    #$PickVersionEnableHistoryCleanBox.Location = "$MarginWidth, $(2 * $MarginHeight)"
    $PickVersionEnableHistoryCleanBox.Font = $TextItalicFont
    $PickVersionEnableHistoryCleanBox.Size = "$(2*$ButtonWidth), 0"
    $PickVersionEnableHistoryCleanBox.Checked = $False
    $PickVersionEnableHistoryCleanBox.Text = "Enable project history clean" 
    $PickVersionEnableHistoryCleanBox.Enabled = $False
    $PickVersion.Controls.Add($PickVersionEnableHistoryCleanBox)
    
    $ToolTip.SetToolTip($PickVersionEnableHistoryCleanBox, "Enable project history clean")

    $PickVersionSyncNetworkSettings = New-Object System.Windows.Forms.CheckBox 
    #$PickVersionSyncNetworkSettings.Location = "$MarginWidth, $(4 * $MarginHeight)"
    $PickVersionSyncNetworkSettings.Font = $TextItalicFont
    $PickVersionSyncNetworkSettings.Size = "$(2*$ButtonWidth), 0"
    $PickVersionSyncNetworkSettings.Checked = $True
    $PickVersionSyncNetworkSettings.Text = "Enable sync of Petrel settings from network" 
    $PickVersionSyncNetworkSettings.Enabled = $False
    $PickVersion.Controls.Add($PickVersionSyncNetworkSettings)
    
    $ToolTip.SetToolTip($PickVersionSyncNetworkSettings, "Enable sync of Petrel settings from network")
        
    $PickVersionText = New-Object 'System.Windows.Forms.Label'
    $PickVersionText.ForeColor = "$HighlightTextColor"
    $PickVersionText.Font = $TextItalicFont
    $PickVersionText.Name = "InfoText"
    $PickVersionText.Location = "$MarginWidth, 30"
    $PickVersionText.Size = "$GroupboxContentWidth, 15"
    $PickVersionText.Text = "Please choose Petrel version"
        
    $PickVersion.Controls.Add($PickVersionText)

    # Progress Bar
    $PickVersionProgressBar = New-Object System.Windows.Forms.ProgressBar
    $PickVersionProgressBar.Name = 'progressBar1'
    $PickVersionProgressBar.Value = 0
    $PickVersionProgressBar.Style="Continuous"
    $PickVersionProgressBar.Size = "$GroupboxContentWidth, 15"
    $PickVersionProgressBar.Location = "$MarginWidth, 35"
    
    $PickVersion.Controls.Add($PickVersionProgressBar)
        
    
    #
    # 5. License Servers
    # 
    
    $LicensePick = New-Object 'System.Windows.Forms.Groupbox'
    $LicensePick.Font = $TextBoldFont
    $LicensePick.Location = "$MarginWidth, 270"
    $LicensePick.Width = $GroupboxWidth
    $LicensePick.Height = 50
    $LicensePick.Name = "LicensePick"
    $LicensePick.Text = "Available License Servers"
    $LicensePick.ForeColor = "$TextColor"
    
    $MyPetrelGUI.Controls.Add($LicensePick)
    
    $LicensePick.Visible = $False
    
    #
    # Cancel Button
    #
    
    $CancelButton = New-Object System.Windows.Forms.Button
    $CancelButton.Location = "$($MarginWidth + $GroupboxWidth - $CancelButton.Width), 340"
    $CancelButton.Text = "Cancel"
    $CancelButton.Font = $ButtonFont
    $CancelButton.ForeColor = "$ButtonTextColor"
    $CancelButton.UseVisualStyleBackColor = $True
    $CancelButton.Add_Click({$MyPetrelGUI.Close()})				
    $MyPetrelGUI.Controls.Add($CancelButton)
		
    $ToolTip.SetToolTip($CancelButton, "No Petrel today. Let me out of here.")    
        	
    ############################
    # End - GUI Skeleton
    ############################
    
    
    ############################
    # Events / Dynamic heights
    ############################    


    #Verify that we have disk space available before we allowuser to kill previous version
    If ($DiskFreeSpaceCheck -eq $False) {
        
        Write-DebugLog "Disabling ""Clear Petrel Settings"" because of low disk space ($([int]($FreeSpace/1gb)) Gb)" 
        $PickVersionKillAllBox.Enabled = $False
        $PickVersionKillAllBox.Text = "Clear Petrel settings (Disabled - check diskspace)" 
        
    }

    # Disable 'Clear Petrel Settings' if run offline (would destroy the installation)
    If(($MyMode -eq "Offline") -or ($MyMode -eq "VPN") -or ($MyMode -eq "DATAROOM")) {

        $PickVersionKillAllBox.Enabled = $False
        $ToolTip.SetToolTip($PickVersionKillAllBox, "Disabled when running offline or through VPN")
    
    } #End if offline
    
    # Enable 'Enable production plugins' if run in test or VPN mode (disabled by default)
    If(($MyMode -eq "Test") -or ($MyMode -eq "VPN")) {
    
        $PickVersionKeepPluginsBox.Location = "$MarginWidth, $((1 + ($PickVersion.Controls | ?{$_.AccessibilityObject -like '*Owner = System.Windows.Forms.CheckBox*' -and $_.Height -ne 0} | Measure).Count) * $MarginHeight)"
        $PickVersionKeepPluginsBox.Enabled = $True
        $PickVersionKeepPluginsBox.Height = 20

        If($MyMode -eq "Test") {

	        $PickVersionTestPluginsBox.Location = "$MarginWidth, $((1 + ($PickVersion.Controls | ?{$_.AccessibilityObject -like '*Owner = System.Windows.Forms.CheckBox*' -and $_.Height -ne 0} | Measure).Count) * $MarginHeight)"
            $PickVersionTestPluginsBox.Enabled = $True
            $PickVersionTestPluginsBox.Height = 20
                        
            $ToolTip.SetToolTip($PickVersionTestPluginsBox, "Enable all test plugins while running in test mode")
            $ToolTip.SetToolTip($PickVersionKeepPluginsBox, "Enable all production plugins while running in test mode")
          
        } Else {
            #In VPN mode, enable selection box to sync network settings
            $PickVersionSyncNetworkSettings.Location = "$MarginWidth, $((1 + ($PickVersion.Controls | ?{$_.AccessibilityObject -like '*Owner = System.Windows.Forms.CheckBox*' -and $_.Height -ne 0} | Measure).Count) * $MarginHeight)"
            $PickVersionSyncNetworkSettings.Enabled = $True
            $PickVersionSyncNetworkSettings.Height = 20
            $ToolTip.SetToolTip($PickVersionSyncNetworkSettings, "Enable sync of settings from network through VPN. NOTE: This can slow down Petrel severely")

            #Set tooltip for Enable Production Plugins
            $ToolTip.SetToolTip($PickVersionKeepPluginsBox, "Enable all production plugins through VPN. NOTE: This can slow down Petrel severely")
        }

    } #End If in test mode

    # Enable 'Enable project history clean' for PDM's in production mode
    $GroupPDM = "fg_PDM"
    $MyGroups = Get-MyADGroups
    
    If(($MyMode -like "GG*") -AND ($MyGroups -contains "$GroupPDM")) {
        #Calculate how many check boxes that is already enabled and place this one below
        $PickVersionEnableHistoryCleanBox.Location = "$MarginWidth, $((1 + ($PickVersion.Controls | ?{$_.AccessibilityObject -like '*Owner = System.Windows.Forms.CheckBox*' -and $_.Height -ne 0} | Measure).Count) * $MarginHeight)"
        $PickVersionEnableHistoryCleanBox.Enabled = $True
        $PickVersionEnableHistoryCleanBox.Height = 20
    } #end if PDM in prod

    # One button per version     
    $Counter = 0
    If($MyVersions.Length -gt 0) {

        ForEach ($AvVersion in $MyVersions) {

            $counter += 1
          
            $button = New-Object System.Windows.Forms.Button
            $button.Size = "$ButtonWidth,$ButtonHeight"
            $button.Font = $ButtonFont
            $button.Text = $AvVersion 
            $button.Name = $AvVersion
            $button.Tag = $AvVersion 
            $button.ForeColor = "$ButtonTextColor"
            $button.UseVisualStyleBackColor = $True

            #Calculate number and sizes of checkboxes
            $NumberOfEnabledCheckBoxes = ($PickVersion.Controls | ?{$_.AccessibilityObject -like '*Owner = System.Windows.Forms.CheckBox*' -and $_.Height -gt 0} | Measure).Count
            $TotalCheckBoxHeight = (($PickVersion.Controls | ?{$_.AccessibilityObject -like '*Owner = System.Windows.Forms.CheckBox*'}).Height | Measure -Sum).Sum
        
            #Place the buttons
            If ($counter % 3 -eq 1) {
                # First column
                If ($counter -eq 1) {
                    # Row 1 // Set Y-base for first row buttons
                    $ButtonY = $MarginHeight + $ButtonSpacerHeight + $TotalCheckBoxHeight + ($CheckBoxSpacerHeight * $NumberOfEnabledCheckBoxes)
                } Else {
                    # Row 2+ // Move Y-base for row buttons
                    $ButtonY += $ButtonHeight + $ButtonSpacerHeight
                }
                $button.Location = "$MarginWidth, $ButtonY"
            
            } 
            ElseIf ($counter %3 -eq 2) {
                # Second column
                $button.Location = "$($MarginWidth + $ButtonWidth + $ButtonSpacerWidth), $ButtonY"
            }
            Else {
                # Third column
                $button.Location = "$($MarginWidth + 2*$ButtonWidth + 2*$ButtonSpacerWidth), $ButtonY"
            }
        
            # If version exists locally - then a *
            If(Test-Path "$LocalPetrelBinFolder\$AvVersion") {
            
                $button.Text += " *"
                Write-DebugLog "Petrel $AvVersion available (also locally)" 
                $ToolTip.SetToolTip($button, "Available locally")
                
            } Else {
            
                Write-DebugLog "Petrel $AvVersion available" 
                $ToolTip.SetToolTip($button, "Not available locally. Click to load $AvVersion")
                
            } #End if available locally


            #Eventually tag supported Studio versions
            $EnableStudioInfo = [bool]::Parse($IniSettings["STUDIO"]["EnableStudioInfo"].Trim())
            If ($EnableStudioInfo) {
                $StudioInfoText = $IniSettings["STUDIO"]["StudioInfoText"].Trim()
                $SupportedStudioVersions = $IniSettings["STUDIO"]["Versions"].Split(",") | % {$_.Trim()} | Sort-Object

                $AvMainVersion = $AvVersion.Substring(0,4)
                If ($SupportedStudioVersions -notcontains $AvMainVersion) {
                    $button.Text += " $($StudioInfoText)"
                    $ToolTip.SetToolTip($button,"$($ToolTip.GetToolTip($button)). Version not supported in Petrel Studio.")
                }
                
            }
 
            # Function Invoke-MyPetrelFull will resize the GUI and set the chosen version into play
            # - $LockVersionButtons disables the buttons after the first one is chosen
            $button.Add_Click({ If(!$Script:LockVersionButtons) { $Script:LockVersionButtons=$True; Invoke-MyPetrelFull } })
                    
            $PickVersion.Controls.Add($button)
  
        } # end ForEach in $MyVersions    
    
    } Else {
        
        $PickVersionKillAllBox.Visible = $False
        $PickVersionProgressBar.Visible = $False
        Write-DebugLog "No access to Petrel." 
        $PickVersionText.Text = "No access to Petrel. Please apply through AccessIT."

    } # End If available versions exist

    #Update load progress GUI
    Update-LoadProgressGUI -WindowsFormsObject $InitiateMyPetrelGUI -IncrementProgressPercent 20

    #
    # GroupBox: Info - construct text based on selections
    #
    
    $InfoTextHTML = $Nothing
    $InfoTextHTML = "<html><body style='Background-color:$BackgroundColor'><font face='arial' color=$TextColor><font style='font-size:$($DefaultFontSize)pt;'>"
    $InfoTextHTML += "Welcome to MyPetrel, $(Get-MyADUserProperty "givenname")<br><br>"
    
    
    #Use friendly name for mode
    $DisplayUserMode = Switch ($MyMode) {
        "GG" {'GG'}
        "RE" {'RE'}
        "GG_RE"  {'RE and GG'}
        Default {$MyMode}
    }

    #Show currenty Petrel mode
    $InfoTextHTML += "Petrel is running in <b><font color=$HighlightTextColor>$($DisplayUserMode.ToUpper()) MODE</font></b><br>"

    #Show text based on available checkboxes
    $InfoTextHTML += "<ul style='margin-top: 0; margin-left: 20px;'>"
    If ($PickVersionKillAllBox.Enabled) {
        $InfoTextHTML += "<li>Enabling ""$($PickVersionKillAllBox.Text)"" checkbox below will clean/reset Petrel configuration on this computer</li><br>"
    }
    If ($PickVersionKeepPluginsBox.Enabled) {
        $InfoTextHTML += "<li>Enable productions plugins by using the ""$($PickVersionKeepPluginsBox.Text)"" checkbox below</li><br>"
    }
    If ($PickVersionTestPluginsBox.Enabled) {
        $InfoTextHTML += "<li>Enable test plugins by using the ""$($PickVersionTestPluginsBox.Text)"" checkbox below</li><br>"
    }
    If ($PickVersionEnableHistoryCleanBox.Enabled) {
        $InfoTextHTML += "<li>Enable history clean in projects by using the ""$($PickVersionEnableHistoryCleanBox.Text)"" checkbox below (PDMs only)</li><br>"
    }
    If ($PickVersionSyncNetworkSettings.Enabled) {
        $InfoTextHTML += "<li>Untick the ""$($PickVersionSyncNetworkSettings.Text)"" checkbox below to skip syncing current Petrel configuration from network share. Might be useful when VPN connection is slow.</li><br>"
    }
    $InfoTextHTML += "</ul>" 

    #If not in offline or dataroom mode, provide links and MOTD
    If (($MyMode -eq "Offline") -or ($MyMode -eq "DATAROOM")) {
    }
    Else {
        #General info
        $InfoTextHTML += "Helpful links:<ul style='margin-top: 0; margin-left: 20px;'>"
        $InfoTextHTML += "<li>Link to <a href=$PetrelSystemPortalURL target=""_blank"">Petrel portal</a></li>"
        
        #End helpful links
        $InfoTextHTML += "</ul>"
    
        #Get Cleanup Info
        If ($($IniSettings["PETREL_PORTAL"]["EnableCleanupPortal"]) -eq 1) {
            #Cleanup check - format HTML og get results
            $CleanupCheckTextHTML = $Nothing
            $CleanupCheckTextHTML = "<html><body style='Background-color:$BackgroundColor'><font face='arial' color=$TextColor><font style='font-size:$($DefaultFontSize)pt;'>"
            $CleanupCheckTextHTML += Get-CleanupInfo
            $CleanupCheckText.DocumentText = $CleanupCheckTextHTML.Replace("`r`n","<br>")
        }
        Else {
            $CleanupCheck.Height = 0
            $CleanupCheckText.Height = 0
            $CleanupCheckTextHTML = $Nothing
        }
        
        # Get MessageOfTheDay file in HTML format
        If (Test-Path $NetworkMotdFile) {
            $InfoTextHTML += Get-Content $NetworkMotdFile
            Write-DebugLog "Getting and showing content from MOTD file $NetworkMotdFile"
        }
    }
    
    Update-LoadProgressGUI -WindowsFormsObject $InitiateMyPetrelGUI -IncrementProgressPercent 10

    #InfoText - make sure we format all text with HTML newline
    $InfoText.DocumentText = $InfoTextHTML.Replace("`r`n","<br>")
    
    #System check - format HTML and get results
    $SystemCheckTextHTML = $Nothing
    $SystemCheckTextHTML = "<html><body style='Background-color:$BackgroundColor'><font face='arial' color=$TextColor><font style='font-size:$($DefaultFontSize)pt;'>"
    $SystemCheckTextHTML += Invoke-SystemCheck
    $SystemCheckText.DocumentText = $SystemCheckTextHTML.Replace("`n","<br>")

    #Update load progress GUI
    Update-LoadProgressGUI -WindowsFormsObject $InitiateMyPetrelGUI -IncrementProgressPercent 10
    
    #When HTML is updated and processed, calculate the size
    $InfoText.Add_DocumentCompleted(
        {
            # Info groupbox height
            $InfoText.Height = $InfoText.Document.Body.ScrollRectangle.Height
            $Info.Height = $InfoText.Height + $HTMLGroupBoxBuffer

            # Cleanup info height (if enabled)
            If ($($IniSettings["PETREL_PORTAL"]["EnableCleanupPortal"]) -eq 1 -And $CleanupCheckTextHTML) {
                $CleanupCheck.Visible = $True
                $CleanupCheckText.Visible = $True
                $CleanupCheckText.Height = $CleanupCheckText.Document.Body.ScrollRectangle.Height
                $CleanupCheck.Height = $CleanupCheckText.Height + $HTMLGroupBoxBuffer
            }

            # System check height
            $SystemCheckText.Height = $SystemCheckText.Document.Body.ScrollRectangle.Height
            $SystemCheck.Height = $SystemCheckText.Height + $HTMLGroupBoxBuffer

            # Move dynamic vertical pointer
            $Script:GlobalPointerY += $Info.Height + $MarginHeight


            # Cleanup check location (if enabled and visible)
            If ($CleanupCheck.Visible -eq $True) {
                #$CleanupCheck.Location = "$MarginWidth, $($Script:GlobalPointerY+$MarginHeight)"
                $CleanupCheck.Location = "$MarginWidth, $Script:GlobalPointerY"
                $CleanupCheckText.SendToBack()
                $LocalPointerY += $CleanupCheck.Height + $MarginHeight
                $Script:GlobalPointerY += $CleanupCheck.Height + $MarginHeight
            }
 
            # System check location
            $SystemCheck.Location = "$MarginWidth, $Script:GlobalPointerY"
            $LocalPointerY += $SystemCheck.Height + $MarginHeight
            $Script:GlobalPointerY += $SystemCheck.Height + $MarginHeight
 
            # Set top-right of version groupbox
            $PickVersion.Location = "$MarginWidth, $Script:GlobalPointerY"

            # Local vertical pointer inside the groupbox
            $LocalPointerY = $ButtonY + $ButtonHeight + $ButtonSpacerHeight
    
            # Set internal location for version text 
            $PickVersionText.Location = "$MarginWidth, $LocalPointerY"
    
            # Move internal pointer to progressbar
            $LocalPointerY += $PickVersionText.Height + $ButtonSpacerHeight
    
            # Set internal location for version progressbar
            $PickVersionProgressBar.Location = "$MarginWidth, $LocalPointerY"
    
            # Move internal pointer to bottom of groupbox
            $LocalPointerY += $PickVersionProgressBar.Height + (2 * $ButtonSpacerHeight)
  
            # Update Groupbox height
            $PickVersion.Height = $LocalPointerY

            # Move dynamic vertical pointer
            $Script:GlobalPointerY += $PickVersion.Height + $MarginHeight   


            # Set MyPetrel main form height
            $MyPetrelGUI.Height = $Script:GlobalPointerY + (3 * $MarginHeight) + $CancelButton.Height

            # Set Cancel button location
            $CancelButton.Location = "$($MarginWidth + $GroupboxWidth - $CancelButton.Width), $Script:GlobalPointerY"

        }
    )


    #Manually center MyPetrel GUI. StartPosition = "CenterScreen" will not count for growth of window in Y size, so add a Y buffer that is subtracted from the value
    $MyPetrelGUI_YBuffer = 300
    $MyPetrelGUI.StartPosition = "Manual"
    $MyPetrelGUI.Location = "$([int](([System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea.Width/2) - ($MyPetrelGUI.Width/2))), $([int](([System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea.Height/2) - ($MyPetrelGUI.Height/2) - $MyPetrelGUI_YBuffer))"

    #Close and terminate load progress GUI
    Close-LoadProgressGUI -WindowsFormsObject $InitiateMyPetrelGUI -IncrementProgressPercent 20
    $InitiateMyPetrelGUI = $Nothing
       
    # Run explicit version automatically
    If ($RunSpecificVersion -eq $True) {
        #Add timer objects
        $Timer = New-Object 'System.Windows.Forms.Timer'
        
        #What to process in event
        $Timer_Tick={
            $Timer.Stop()
            #Activate MyPetrel GUI
            $MyPetrelGUI.Activate()
            #Start specific Petrel version
            Invoke-MyPetrelFull $SpecificVersion
        }

        #Enable timer
        $Timer.Enabled = $True
        $Timer.Interval = 50

        #Add Event
        $Timer.Add_Tick($Timer_Tick)
        $MyPetrelGUI.ResumeLayout()
    }

    
    #Show GUI and wait for user response 
    $MyPetrelGUI.ShowDialog()  
} #End Function Show-MyPetrel


Function Get-CleanupInfo {
    <#   
    .DESCRIPTION 
        Reads cleanup info from cleanup portal and returns a HTML formatted string with details
    #>

    $CleanupInfoHTML = $Nothing
    $CleanupInfoHTML = "<html><body style='Background-color:$BackgroundColor'><font face='arial' color=$TextColor><font style='font-size:$($DefaultFontSize)pt;'>"

    #Cleanup info, if enabled in INI file, check status of job and provide link to user if there is cleanup tasks
    If ($($IniSettings["PETREL_PORTAL"]["EnableCleanupPortal"]) -eq 1) {
        $JobWaitCleanupTaskCheck = $JobStartCleanupTaskCheck | Wait-Job -Timeout 2
        $JobReceiveCleanupTaskCheck = $JobStartCleanupTaskCheck | Receive-Job -OutVariable CleanupInfo -ErrorAction SilentlyContinue
        If ($CleanupInfo.ProjectObjects -ge 1 -Or $CleanupInfo.StudioObjects -ge 1) {
            $WarningDate = $IniSettings["PETREL_PORTAL"]["WarningThreshold"]
            $CleanupInfoHTML += "You have the following <a href=$($CleanupPortalURL)$($IniSettings["PETREL_PORTAL"]["CleanupPortalPage"]) target=""_blank"">data cleanup</a> tasks:"
            $CleanupInfoHTML += "<ul style='margin-top: 0; margin-left: 20px;'>"
            If ($CleanupInfo.ProjectObjects -ge 1) {
                $FirstProjectDelete = [datetime]::ParseExact($CleanupInfo.ProjectFirstDelete, "dd.MM.yyyy", [CultureInfo]::InvariantCulture).ToShortDateString()
                $HTMLDeleteInfo = $Nothing
                $HTMLDeleteInfo = "<li>$($CleanupInfo.ProjectObjects) Petrel project(s) will be deleted on $($FirstProjectDelete).</li>"
                If ($(New-TimeSpan -End $FirstProjectDelete).Days -lt $WarningDate) {
                    $HTMLDeleteInfo = "<font color=red>$HTMLDeleteInfo</font>"
                }
                $CleanupInfoHTML += $HTMLDeleteInfo
            }
            If ($CleanupInfo.StudioObjects -ge 1) {
                $FirstStudioDelete = [datetime]::ParseExact($CleanupInfo.StudioFirstDelete, "dd.MM.yyyy", [CultureInfo]::InvariantCulture).ToShortDateString()
                $HTMLDeleteInfo = $Nothing
                $HTMLDeleteInfo = "<li>$($CleanupInfo.StudioObjects) Petrel Studio object(s) will be deleted on $($FirstStudioDelete).</li>"
                If ($(New-TimeSpan -End $FirstStudioDelete).Days -lt $WarningDate) {
                    $HTMLDeleteInfo = "<font color=red>$HTMLDeleteInfo</font>"
                }
                $CleanupInfoHTML += $HTMLDeleteInfo
          
            }
            $CleanupInfoHTML += "</ul>"
            Write-DebugLog -Text "User has cleanup tasks - Projects: $($CleanupInfo.ProjectObjects) Studio: $($CleanupInfo.StudioObjects). Cleanup info generated on $($CleanupInfo.UpdateTime)"
        }
        Else {
            $CleanupInfoHTML = "You don't have have any current cleanup tasks!"
        }
    }
    Else {
        $CleanupInfoHTML = "Cleanup task check is not currently enabled"
    }

    Return $CleanupInfoHTML

} #End Function Get-CleanupInfo



Function Invoke-MyPetrelFull {
    <#   
    .DESCRIPTION 
        Expand MyPetrel GUI to show System check & license servers
        Not a proper/standalone function     
    #>
    param($Version)

    # Button clicked
    If(!($Version)) {

        $button = $this
        $Version = $button.Tag

    } Else {

        $button = ($PickVersion.Controls.Find("$Version", $True))[0]
    }
   
    $button.Font = $ButtonClickedFont
    $button.BackColor = $ButtonClickedBackgroundColor

    $PickVersionText.Text = "Preparing Petrel $Version"

    # Only expand if Petrel version is ok
    If (Invoke-PetrelVersion $Version) {
    
        # Update tooltip for all version buttons
        Foreach ($Control in $PickVersion.Controls) {
            
            $ToolTip.SetToolTip($Control, "Version $Version already chosen")
       
        } #end foreach
        
        #$SystemCheck.Visible = $True; 
        #Invoke-SystemCheck $Version;
    
        $LicensePick.Visible = $True;
        Show-LicenseServers $Version;

        $MyPetrelGUI.Height = 10 * $MarginHeight + $Info.Height + $CleanupCheck.Height + $SystemCheck.Height + $PickVersion.Height + $LicensePick.Height + $CancelButton.Height

        $CancelButton.Location = "$($MarginWidth + $GroupboxWidth - $CancelButton.Width), $($MyPetrelGUI.Height - (4 * $MarginHeight))"

    } # End If Petrel version is ok

} #End Function Invoke-MyPetrelFull


Function Set-PetrelVersion {
    <#   
    .DESCRIPTION 
        Set Petrel Version and script parameters      
    .PARAMETER NewVersion
        Petrel version to be set
    .EXAMPLE
        Set-PetrelVersion 2014.5
    #>    
    param (
        [string] $NewVersion
    ) 

    $Script:PetrelVersion = $NewVersion
    $Script:Version_Major = $NewVersion.Split(".")[0]
    $Script:Version_Minor = $NewVersion.Split(".")[1]

    # Set parameters in script scope

    $Script:LocalPetrelBinVersionFolder = "$LocalPetrelBinFolder\$NewVersion"
    $Script:LocalPetrelExeFile = "$LocalPetrelBinVersionFolder\petrel.exe"
    $Script:LocalPetrelExeConfigFile = "$LocalPetrelBinVersionFolder\petrel.exe.config"

    $Script:NetworkPetrelVersionBinFolder = "$NetworkPetrelBase\Bin\$NewVersion"
    $Script:NetworkPetrelVersionBinExeFile = "$NetworkPetrelVersionBinFolder\petrel.exe"

    $Script:NetworkPetrelVersionConfigFolder = "$NetworkPetrelBase\Config\$NewVersion"
    $Script:LocalPetrelVersionConfigFolder = "$LocalPetrelConfigFolder\$NewVersion"

    $Script:AppDataPetrelVersionFolder = ${ENV:APPDATA} + "\Schlumberger\Petrel\$Version_Major"
    $Script:ProgramDataPetrelVersionFolder = ${ENV:PROGRAMDATA} + "\Schlumberger\Petrel\$Version_Major"

} #End Function Set-PetrelVersion


Function Install-SccmApplication {
   <#   
    .DESCRIPTION 
        Install Petrel requirements from SCCM (Equinor applications)
    .PARAMETER PackageID
        SCCM packageID
    .EXAMPLE
        Install-SccmApplication "Install", "SCS019BC"
    #>
    
    param (
        [string] $Id,
        [string] $PackageId
    ) 

    (New-Object -ComObject uiresource.uiresourcemgr).ExecuteProgram("$Id", "$PackageId", 1)

} #End Function Install-SccmApplication


Function Get-SccmApplicationStatus {
   <#   
    .DESCRIPTION 
        Get application installation state from SCCM (Equinor applications)
    .PARAMETER ID
        SCCM Name/ID
    .PARAMETER PackageID
        SCCM packageID
    .EXAMPLE
        Get-SccmApplicationStatus "Install", "SCS019BC"
    #>
    
    param (
        [string] $Id,
        [string] $PackageId
    ) 

    (New-Object -ComObject uiresource.uiresourcemgr).GetDownloadStatus("$Id", "$PackageId").Status

} #End Function Get-SccmApplicationStatus


Function Show-BalloonTip {
    <#   
    .DESCRIPTION 
        Show Windows information balloon       
    .PARAMETER text
        Text to be shown
    .EXAMPLE
        Show-BalloonTip "Hello World!"
    #>
    
    param (
        [string] $text
    ) 

    # Load .Net GUI assembly
    Add-Type -AssemblyName System.Windows.Forms

    $balloonInfo=[system.windows.forms.tooltipicon]::Info
    
    $notify = New-Object system.windows.forms.notifyicon 
    $notify.icon = $PetrelIcon 
    $notify.visible = $True 	
    $notify.showballoontip(10,"Petrel",$text,$balloonInfo)    
    
} #End Function Show-BalloonTip


Function Initialize-Shortcut {
    <#   
    .DESCRIPTION 
        Create specific Petrel shortcut      
    .PARAMETER Description
        Shortcut name
    .PARAMETER Arguments
        Shortcut arguments
    .EXAMPLE
        Initialize-Shortcut -Description "Petrel 2014.5" -Arguments "-Version 2014.5"
    #>
    
    param (
        [string] $Description,
        [string] $Arguments
    ) 

    $WshShell = New-Object -ComObject WScript.Shell

    If(!(Test-Path $ShortcutFolder)) {
        New-Item $ShortcutFolder -Type Directory
    } 
    
    $ShortcutPath = $ShortcutFolder + "\" + $Description + ".lnk"

    # Icons doesn't like C:	
    $IconExePath = $LocalPetrelExeFile.Replace("C:","%systemdrive%")

    If(!(Test-Path $ShortcutPath)) {
        $Shortcut = $WshShell.CreateShortcut($ShortcutPath)
        $Shortcut.TargetPath = $ScriptPath
        $Shortcut.Description = $Description
        $Shortcut.Arguments = $Arguments
        $Shortcut.IconLocation = "$IconExePath,0"
        $Shortcut.Save()
    }
    
} #End Function Initialize-Shortcut


Function Initialize-PetrelHelp {
    <#   
    .DESCRIPTION 
        Run Petrel help indexer (as background job)
    .EXAMPLE
        Initialize-PetrelHelp
    #>

    #First make sure that we don't have any existing indexes
    If (Test-Path "$Script:AppDataPetrelVersionFolder\Dox") {
        Write-DebugLog "Cleaning folder ""$Script:AppDataPetrelVersionFolder\Dox"" so that new help indexes can be generated"
        Remove-Item -Path "$Script:AppDataPetrelVersionFolder\Dox" -Recurse -Force
    }

    
    # The job spawns a new process, so variables have to be included as arguments
    # Since syncing help files are done in the background and includes many files -> have to guess on when to start -> start-sleep
    $indexer = { Start-Sleep 120; & $args[0] $args[1] $args[2] }
    Start-Job -ScriptBlock $indexer -ArgumentList "$LocalPetrelBinVersionFolder\DocIndexer.exe","/add","$LocalPetrelBinVersionFolder\Dox\HelpCenter"

} #End Function Initialize-PetrelHelp


Function Sync-PetrelSetup {
    <#   
    .DESCRIPTION 
        Keep local Petrel installation in sync with central managed files & plugins 
    .EXAMPLE
        Sync-PetrelSetup
    #>
    
    # 1. Sync Startup.vbs wrapper + SCCM_Execute.ps1 PS script for handling SCCM part
    & robocopy $NetworkPetrelBase $LocalPetrelBase "Startup.vbs" /R:1 /W:1
    & robocopy $NetworkPetrelBase $LocalPetrelBase "SCCM_Execute.ps1" /R:1 /W:1

    # 2. Sync RE specific setup
    $MyGroups = Get-MyADGroups 
    
    If($MyGroups -contains "$GroupRE") {

        Write-DebugLog "Synchronizing RE specific Equinor setup"

        # Set path to Eclipse 
        $ENV:ECLPath = "C:\Appl\ecl"
        
        # Use Emacs if no editor is set 
        IF (!(Test-Path ENV:Editor)) {
            
            $NetworkEmacs = "G:\Prog\Global\Petrel\Program\MyPetrel\Bin\Emacs"
            $LocalEmacs = "C:\Appl\Schlumberger\Bin\Emacs"

            If(!(Test-Path $LocalEmacs)) {

                # Sync portable client to local machine as background job
                Write-DebugLog "Synchronizing Emacs to local machine"
                $EmacsArgumentList = "$NetworkEmacs $LocalEmacs /MT:32 /E /R:1 /W:1"
                Start-Process -FilePath robocopy.exe -ArgumentList $EmacsArgumentList -verbose -PassThru -NoNewWindow;

            } # end if emacs is missing

            $ENV:Editor = "$LocalEmacs\emacs-24.5-bin-i686-mingw32\bin\emacs.exe"
        }
    } #end if RE mode

	# 3. Sync License profile settings. Only applies for Petrel 2015 and newer
    If ($Version_Major -ge 2015) {

        # TODO :: Profiles from dedicated profiles folder?
	    & robocopy "$NetworkPetrelVersionConfigFolder\Sync\Images" "$AppDataPetrelVersionFolder\Images" /MIR /R:1 /w:1
	    & robocopy "$NetworkPetrelVersionConfigFolder\Sync" $AppDataPetrelVersionFolder "profiles.xml" /R:1 /w:1
    
    } #end if version >= 2015
   
    # 4. Sync setting for Seismic Well Tie. Only applies for Petrel 2017 and newer
    If ($Version_Major -ge 2017) {

	    & robocopy "$NetworkPetrelVersionConfigFolder\Sync" $AppDataPetrelVersionFolder "SwtOwt.xml" /R:1 /w:1
    
    } #end if version >= 2017

    # 5. Sync central Features.json file that controls pre-commersial settings in Petrel. Only applies for Petrel 2018 and newer.
    If ($Version_Major -ge 2018) {
        & robocopy "$NetworkPetrelVersionConfigFolder\Sync" $AppDataPetrelVersionFolder "Features.json" /R:1 /w:1
    }

    # 6. Sync/Update Petrel search indexes (KJRAN/RNOR 18012018)
    Update-PetrelSearch

    # 7. Sync Local Network plugins
    & robocopy "$NetworkPetrelVersionConfigFolder\ExtensionsLocal" "$LocalPetrelVersionConfigFolder\ExtensionsLocal" /MT:32 /MIR /R:1 /W:1

    # 8. Sync PetrelConfiguration.xml 
    & robocopy "$NetworkPetrelVersionConfigFolder\Sync" $ProgramDataPetrelVersionFolder "PetrelConfiguration.xml" /R:1 /W:1

    # 9. TEMP - Force clean up the CRS version issues 
    #& robocopy "$NetworkPetrelVersionBinFolder\XML" "$LocalPetrelBinVersionFolder\XML" "CoordinateCatalogConfiguration.xml" /R:1 /W:1

    # 10. Sync CRS Catalog configuration. Not all versions is updated to where to store the CRS file, so check MyPetrel.ini if we should override the version folder name
    If ($IniSettings["PETREL_CRS_FOLDER"][$Version_Major]) {
        & robocopy "$NetworkDataBase\CRSCatalogConfiguration\$($Version_Major).1" "$AppDataPetrelVersionFolder\..\CRSCatalogConfiguration\$($IniSettings["PETREL_CRS_FOLDER"][$Version_Major]).1" /E /R:1 /W:1
    }
    Else {
        & robocopy "$NetworkDataBase\CRSCatalogConfiguration\$($Version_Major).1" "$AppDataPetrelVersionFolder\..\CRSCatalogConfiguration\$($Version_Major).1" /E /R:1 /W:1
    }

    # 11. Wipe any PEDATABASE settings, as they mess up CRS import for Petrel. Also wipe command line proxy setings, they causes hang in Petrel 2019.3.
    $Env:PEDATABASE = ""
    $Env:HTTP_PROXY = ""
    $Env:HTTPS_PROXY = ""

    # 12. Sync Custom Web map
    & robocopy "$NetworkDataBase\CustomWebMap" $AppDataPetrelVersionFolder "WebmapCustomGallery.mapcfg" /R:1 /W:1
    
    # 13. Sync XML Catalog
    If(Test-Path $LocalPetrelBinVersionFolder) {
        & robocopy "$NetworkDataBase\XML" "$LocalPetrelBinVersionFolder\XML" /E /R:1 /W:1
    }
    # 14. Sync Studio DB Configuration
    If ($Version_Major -ge 2015) {
        If ($MyMode -eq "Test" -Or $MyMode -eq "Admin") {
            & robocopy "$NetworkDataBase\Studio\Config\$Version_Major\Test" "$ProgramDataPetrelVersionFolder\Studio\" "Connections.xml" "StudioConfig.txt" /R:1 /W:1
        }
        Else {
            & robocopy "$NetworkDataBase\Studio\Config\$Version_Major" "$ProgramDataPetrelVersionFolder\Studio\" "Connections.xml" "StudioConfig.txt" /R:1 /W:1
        }
    }
    Else {
        & robocopy "$NetworkDataBase\Studio\Config" "$ProgramDataPetrelVersionFolder\Studio\" "Connections.xml" /R:1 /W:1
    }

    # 15. Sync G:\Prog\Global\Petrel\Data\LogCatalog
    If(Test-Path $LocalPetrelBinVersionFolder) {
        & robocopy "$NetworkDataBase\LogCatalog" "$LocalPetrelBinVersionFolder\XML" /E /R:1 /W:1
    }
    
    # 16. Sync WorldMap Configuration
    & robocopy "$NetworkDataBase\WorldMap" "$ProgramDataPetrelVersionFolder\Studio\WorldMap" "WorldMapSettings.xml" /R:1 /W:1

    # 17. Sync Equinor Well Section templates
    & robocopy "$NetworkDataBase\Statoil templates" "$LocalPetrelBinVersionFolder\Resources\WellSectionTemplate\Statoil templates" /E /R:1 /W:1

    # 18. Sync Equinor Well Symbols
    & robocopy "$NetworkDataBase\WellSymbols" "$LocalPetrelBinVersionFolder\Resources\WellSymbols" /MT:32 /E /R:1 /W:1 /XC

    # 19. Delete duplicated dll file; causes Studio Transfer Tool issue (RNOR 19.02.2018)
    $StudioProblemFile = "$Env:AppData\Statoil Internal Toolbox\2016\Prod\Slb.Ocean.Petrel.UI.Wpf.Controls.dll"
    If (Test-Path $StudioProblemFile) {
        del "$Env:AppData\Statoil Internal Toolbox\2016\Prod\Slb.Ocean.Petrel.UI.Wpf.Controls.dll"
    }
	
	# 20. Sync central FeatureFlags.json file that controls pre-commersial settings in Petrel. Only applies for Petrel 2021 and newer.
    If ($Version_Major -ge 2021) {
    & robocopy "$NetworkPetrelVersionConfigFolder\Sync" $AppDataPetrelVersionFolder "FeatureFlags.json" /R:1 /w:1
    }


} #End Function Sync-PetrelSetup



Function Sync-LocalVersion {
    <#   
    .DESCRIPTION 
        Keep local Petrel version binaries in sync with centrally managed binaries.
        Ignoring all timestamps, and only adding missing files (no /MIR).
    .PARAMETER Source
        Petrel version binary folder on network
    .PARAMETER Destination
        Petrel version binary folder on local machine
    #>
    Param (
            [String]$Source,
            [String]$Destination
            )
    
    # Same versions?
    If($Source.split("\")[-1] -eq $Destination.split("\")[-1]) {
    
        $FilesMissing = $((& robocopy $Source $Destination /xc /xn /xo /E /MT:32 /W:1 /R:1 /L | ? {$_ -like "*New File*"}).count )
        Write-DebugLog "Needs to sync $FilesMissing files to $Destination for Petrel to be in sync"
        
        If ($FilesMissing -gt 0) {
              
            # Fix local installation            
            $RobocopyParameters = "/xc /xn /xo /E /MT:32 /W:1 /R:1"
            $RobocopyLogPath = [System.IO.Path]::GetTempFileName()
            $RobocopyArgumentList = '"{0}" "{1}" /LOG:"{2}" {3}' -f $Source, $Destination, $RobocopyLogPath, $RobocopyParameters
            $RobocopyProcess = Start-Process -FilePath robocopy.exe -ArgumentList $RobocopyArgumentList -Verbose -PassThru -NoNewWindow; 
    
            Write-DebugLog "Auto-repairing local installation ($FilesMissing files)"
            Write-ErrorLog "Auto-repairing local installation ($FilesMissing files)"
    
            While(!$RobocopyProcess.HasExited) {
                $PickVersionText.Text = "Auto-repairing local Petrel $ChosenVersion installation .." 
                [System.Windows.Forms.Application]::DoEvents()     
            }
            
        } else {
            Write-DebugLog "Local installation ok"
            $PickVersionText.Text = "Local installation ok"
        } #end if local install not ok 
            
    } Else {
        # Todo :: Create error 
        Write-DebugLog "Error - Version mismatch!"
        Write-ErrorLog "Version mismatch!"
    }

} #end Function Sync-LocalVersion


Function Clear-Folder {
    <#   
    .DESCRIPTION 
        Deletes files in folder recursively
    .PARAMETER Folder
        Folder to be cleared
    .EXAMPLE
        Clear-Folder $Env:Temp
    #>
    
    param (
        [string] $Folder
    ) 

    Get-ChildItem -Path $Folder -Recurse | Remove-Item -Force -Recurse
    Write-DebugLog "Clearing folder $Folder"

} #End Function Clear-Folder


Function Invoke-PetrelVersion {
    <#   
    .DESCRIPTION 
        Invoke Petrel version, setup, sync and host check
    .PARAMETER ChosenVersion
        Petrel version to be used
    .EXAMPLE
        Invoke-PetrelVersion 2014.5
    #>  
    param (
        [string] $ChosenVersion
    ) 

    Write-DebugLog "Petrel $ChosenVersion chosen" 

    # Set version environment 
    Set-PetrelVersion $ChosenVersion 
  
    # Wipe all Petrel settings?
    If($PickVersionKillAllBox.Checked -eq $True) {

        Write-DebugLog "Kill All button activated - Resyncing Petrel" 

        # Wipe Version's %Appdata%  
        Clear-Folder $AppDataPetrelVersionFolder

        # Wipe Petrel\Studio folder under %AppData%
        Clear-Folder "$($Env:Appdata)\Schlumberger\Petrel\Studio"

        #Wipe CRSCatalogConfiguration
        Clear-Folder "$($Env:Appdata)\Schlumberger\Petrel\CRSCatalogConfiguration"

        # Wipe %Programdata%
        Clear-Folder $ProgramDataPetrelVersionFolder
        
        # Wipe config folder (all versions)
        Clear-Folder $LocalPetrelConfigFolder
    
        # Wipe shortcut folder 
        Clear-Folder $ShortcutFolder
    
        # Force 'upgrade'
        # - all binaries will be removed
        # - all shortcuts will be removed
        Move-Item $LocalPetrelBinVersionFolder $($LocalPetrelBinVersionFolder + "_Delete") -force
        Start-Job -ScriptBlock { Remove-Item $args[0] -Recurse -Force } -ArgumentList $($LocalPetrelBinVersionFolder + "_Delete")
             
        Write-UpgradeLog "Petrel settings cleared"
        Write-DebugLog "Petrel setting cleared"
        
    } #End If killbox is checked
  
    # Ocean Home (to enable MSI plugin install & make some plugins function properly)
    # - Set parameters in process & user scope 
    $OceanHome86 = "Ocean${Version_Major}Home"
    
    If((Get-ChildItem Env:$OceanHome86).Value -ne "$LocalPetrelBinVersionFolder\") {

	
        Write-DebugLog "Setting Permanent User variable $OceanHome86 = $LocalPetrelBinVersionFolder\" 
        [Environment]::SetEnvironmentVariable("$OceanHome86", "$LocalPetrelBinVersionFolder\", "Process")
        [Environment]::SetEnvironmentVariable("$OceanHome86", "$LocalPetrelBinVersionFolder\", "User")

    }

    $OceanHome64 = "Ocean${Version_Major}Home_x64"
    
    If((Get-ChildItem Env:$OceanHome64).Value -ne "$LocalPetrelBinVersionFolder\") {

	
        Write-DebugLog "Setting Permanent User variable $OceanHome64 = $LocalPetrelBinVersionFolder\" 
        [Environment]::SetEnvironmentVariable("$OceanHome64", "$LocalPetrelBinVersionFolder\", "Process")
        [Environment]::SetEnvironmentVariable("$OceanHome64", "$LocalPetrelBinVersionFolder\", "User")

    }

    # Upgrade
    If(!(Test-Path $("$LocalPetrelBinFolder\$ChosenVersion"))) {                  

        # Load version binaries
        # Breaks function if the sync is not ok (like full disk)
        If((Sync-Version $ChosenVersion) -like "*False") {

            Write-DebugLog "Loading failed - exiting"
            Return $false

        } #end if sync error

        # Wipe shortcut folder 
        Clear-Folder $ShortcutFolder
        
        #RNOR 14.01.2019 - Disabled - Help Indexes are pre-compiled under Petrel bin folder
        # Update Petrel Help (delayed start)
        #Write-DebugLog "Running Petrel Help indexing"
        #Initialize-PetrelHelp
        
        Write-UpgradeLog "Petrel upgraded"
        Write-DebugLog "Petrel upgraded"

    } ElseIf (!($MyMode -eq "Offline") -and !($MyMode -eq "VPN")) {
    
        # Health check - local vs network version
        Write-DebugLog "Verifying local installation"
        $PickVersionText.Text = "Verifying local version of Petrel $ChosenVersion"
        
        [System.Windows.Forms.Application]::DoEvents()
        
        #Measure runtime for coming sync job
        $StartTime = $Nothing
        $EndTime = $Nothing

        #Sync Petrel
        $StartTime = Get-Date
        Sync-LocalVersion $NetworkPetrelVersionBinFolder $LocalPetrelBinVersionFolder
        $EndTime = Get-Date

        #Measure timeused and report to errorlog if over threshold
        $TimeUsed = $EndTime - $StartTime
        If ($TimeUsed.Seconds -gt 60) {
            Write-DebugLog "Synhcronization of Petrel is higher than the configured threshold - time used: $($TimeUsed.Seconds)"
            Write-ErrorLog "Synhcronization of Petrel is higher than the configured threshold - time used: $($TimeUsed.Seconds)"
        }
        
    } #End If upgrade or check current version

    # Dongle shortcut
    
    If(($(Get-DongleID)) -and !(Test-Path "$ShortcutFolder\MyPetrel - Local Dongle.lnk")) {

        Write-DebugLog "Creating personal shortcut: 'MyPetrel - Local Dongle'" 
        Initialize-Shortcut "MyPetrel - Local Dongle" "-Version $ChosenVersion"

    } # End If Dongle

    #Create shortcuts
    If(($(Get-MyADGroups) -contains $GroupTest) -and !(Test-Path "$ShortcutFolder\MyPetrel - Test Mode.lnk")) {

        Write-DebugLog "Creating personal shortcut: 'MyPetrel - Test Mode'" 
        Initialize-Shortcut "MyPetrel - Test Mode" "-Mode Test"

    } # End If TestUser

    If(($(Get-MyADGroups) -contains $GroupAdmin) -and !(Test-Path "$ShortcutFolder\MyPetrel - Admin Mode.lnk")) {

        Write-DebugLog "Creating personal shortcut: 'MyPetrel - Admin Mode'" 
        Initialize-Shortcut "MyPetrel - Admin Mode" "-Mode Admin"

    } # End If AdminUser

    If(($($Env:UserName).ToLower().StartsWith("guest_")) -and !(Test-Path "$ShortcutFolder\MyPetrel - Data Room.lnk")) {

        Write-DebugLog "Creating personal shortcut: 'MyPetrel - Data Room'" 
        Initialize-Shortcut "MyPetrel - Data Room" ""

    } # End If DataRoom

    # Test/VPN mode - disable production plugins if radio button is not ticked
    If((($MyMode -eq "Test") -or ($MyMode -eq "VPN") -or ($MyMode -eq "DATAROOM")) -and ($PickVersionKeepPluginsBox.Checked -eq $False)) {
    
        If(!(Test-Path "${LocalPetrelExeConfigFile}.PROD")) {
        
            # Keep the two default pluginproviders (UserAppData & CommonAppData)
            # Remove the two production pluginproviders (NetworkPlugin & LocalNetworkPlugin)
            
            Write-DebugLog "Disabling production plugins" 

            # Backup production version of petrel.exe.config
            Copy-Item "$LocalPetrelExeConfigFile" "${LocalPetrelExeConfigFile}.PROD"

            # Remove Production PluginProviders
            [xml]$PetrelConfig = Get-Content $LocalPetrelExeConfigFile
            $pluginProviders = $petrelConfig.configuration.oceanconfiguration.pluginmanagersettings.pluginproviders
            $pluginProviders.add | ? { $_.Name -like "*Network*" } | % { $pluginProviders.RemoveChild($_) }
            $PetrelConfig.Save($LocalPetrelExeConfigFile)  
    
        } #end if first time in test mode
    
    } Else {

        # Set petrel.exe.config back to production mode
        If(Test-Path "${LocalPetrelExeConfigFile}.PROD") {

            Write-UpgradeLog "Enabling production plugins (reverting from test mode)"
            Write-DebugLog "Enabling production plugins (reverting from test mode)"
            Move-Item "${LocalPetrelExeConfigFile}.PROD" "$LocalPetrelExeConfigFile" -force
        
        } #end if testmode last run

    } #end if test mode    
    
    # Read current petrel.exe.config
    [xml]$PetrelConfig = Get-Content $LocalPetrelExeConfigFile
    $pluginProviders = $petrelConfig.configuration.oceanconfiguration.pluginmanagersettings.pluginproviders

    # Test network plugin name + folder
    $TestPluginChannelName = "NetworkTestPlugin"
    $TestPluginChannelFolder = "${NetworkPetrelVersionConfigFolder}\ExtensionsTest" 

    # Enable Network Test Plugin Channel if in test mode and network test plugin checkbox ticked
    If(($MyMode -eq "Test") -and ($PickVersionTestPluginsBox.Checked -eq $True)) {
             
        # Enable test channel if it doesn't exist
	# PS2 doesn't support the following..
        #If(!($pluginProviders.Add.Name.Contains("${TestPluginChannelName}")))  {
	If(!(($pluginProviders.Add | Select Name) -match "${TestPluginChannelName}")) {

            Write-DebugLog "Enabling network test plugins"
            
            # Clone first plugin channel
            $PluginProviderTest = ($pluginProviders.Add)[0].clone()
               
            # Create Omega channel
            $PluginProviderTest.name = "${TestPluginChannelName}"
            $PluginProviderTest.uri = "${TestPluginChannelFolder}\PluginManagerSettings.xml"
            $PluginProviderTest.SetAttribute("readonly","True")
   
            $PluginProviders.appendchild($PluginProviderTest)
        
            # Write to petrel.exe.config
            $PetrelConfig.Save($LocalPetrelExeConfigFile)

        } # end if network test plugin doesn't exist from before

    # PS2 not supporting this..
    #} ElseIf ($pluginProviders.Add.Name.Contains("${TestPluginChannelName}")) {
    } ElseIf (($pluginProviders.Add | Select Name) -match "${TestPluginChannelName}") {

        # Remove test plugin channel 
        Write-DebugLog "Removing network test plugins"

        $pluginProviders.add | ? { $_.Name -eq "$TestPluginChannelName" } | % { $pluginProviders.RemoveChild($_) }
        $PetrelConfig.Save($LocalPetrelExeConfigFile)
    
    } #end if in test mode and network test plugin checkbox ticked


    # Enable clear history for PDM's in production if ticked
    If($PickVersionEnableHistoryCleanBox.Enabled -eq $True) {
    
        [xml]$PetrelExePDM = Get-Content "$LocalPetrelExeConfigFile"
    
        If($PickVersionEnableHistoryCleanBox.Checked -eq $True) {
        
            Write-DebugLog "Enabling project history clean" 
            $PetrelExePDM.Configuration.appSettings.Add | ? {$_.key -eq "DisableCleanProjectHistory"} | % { $_.Value = "False" }
            $PetrelExePDM.Save($LocalPetrelExeConfigFile) 
            
        } Else {
            
            $CleanValue = ($PetrelExePDM.Configuration.appSettings.Add | ? {$_.key -eq "DisableCleanProjectHistory"}).Value
            
            If($CleanValue -eq "False") {
        
                Write-DebugLog "Disabling project history clean" 
                $PetrelExePDM.Configuration.appSettings.Add | ? {$_.key -eq "DisableCleanProjectHistory"} | % { $_.Value = "True" }
                $PetrelExePDM.Save($LocalPetrelExeConfigFile) 
            
            } 
        
        } # end if enable history is checked
        
         
        
    } # end if pdm in production

    # Omega Machine - enable SIP plugins
    # - also enabled in test mode
    If($(Get-ADComputerGroup $GroupSIP)) {

        # Only add once
        If(!(Test-Path "${LocalPetrelExeConfigFile}.OMEGA")) {

            Write-DebugLog "Adding Omega network plugin provider" 

            # Omega plugins network repository
            $ExtensionOmegaFolder = "${NetworkPetrelVersionConfigFolder}\ExtensionsOmega"
       
            # Backup production version of petrel.exe.config
            Copy-Item "$LocalPetrelExeConfigFile" "${LocalPetrelExeConfigFile}.OMEGA"
 
            # Add Omega plugin provider to petrel.exe.config        
            Set-OmegaPetrelExeConfig "$LocalPetrelExeConfigFile" "$ExtensionOmegaFolder"     

        } Else {
        
            Write-DebugLog "Omega network plugin provider already present"
        
        } #end if omega
    
    } Elseif ($($MyGroups -contains "$GroupGeoteric")) {
            # Only add once
            If(!(Test-Path "${LocalPetrelExeConfigFile}.Geoteric")) {

                Write-DebugLog "Adding Geoteric network plugin provider" 
    
                # Geoteric plugins network repository
                $ExtensionGeotericFolder = "${NetworkPetrelVersionConfigFolder}\ExtensionsGeoteric"
           
                # Backup production version of petrel.exe.config
                Copy-Item "$LocalPetrelExeConfigFile" "${LocalPetrelExeConfigFile}.Geoteric"
     
                # Add Geoteric plugin provider to petrel.exe.config        
                Set-GeotericPetrelExeConfig "$LocalPetrelExeConfigFile" "$ExtensionGeotericFolder"     
    
            } Else {
            
                Write-DebugLog "Geoteric network plugin provider already present"
            
            } #end elseif Geoteric
    } Else {

        # Set petrel.exe.config back to prod mode
        If(Test-Path "${LocalPetrelExeConfigFile}.OMEGA") {

            Write-UpgradeLog "Disabling Omega network plugin provider"
            Move-Item "${LocalPetrelExeConfigFile}.OMEGA" "$LocalPetrelExeConfigFile" -force
        
        } #end if omega last run
    
    } #end if omega mode     
    
    # Sync Equinor setup - if online
    If(Test-Path $NetworkPetrelBase) {
        If ($MyMode -eq "VPN" -And $PickVersionSyncNetworkSettings.Checked -eq $False) {
            Write-DebugLog "Skip synchronizing Equinor setup as we are in $MyMode mode and checkbox for syncing network settings is set to $($PickVersionSyncNetworkSettings.Checked)" 
        }
        Else {
            Write-DebugLog "Synchronizing Equinor setup" 
            $PickVersionText.Text = "Synchronizing Petrel $ChosenVersion Equinor setup"
            [System.Windows.Forms.Application]::DoEvents()
            Sync-PetrelSetup 
        }
    
    } #end if online

    $PickVersionText.Text = "Petrel $ChosenVersion loaded" 
    $PickVersionProgressBar.Value = 100   
 
    Return $True
  
} #end Function Invoke-PetrelVersion


Function Set-OmegaPetrelExeConfig {
    <#   
    .DESCRIPTION 
        Add Omega plugin provider
    .PARAMETER PetrelExeConfig
        Path to petrel.exe.config
    .PARAMETER ExtensionsFolder
        Folder containing Omega plugins
    .EXAMPLE
        Set-OmegaPetrelExeConfig "C:\appl\schlumberger\bin\2014.5\petrel.exe.config" "G:\Prog\Global\Petrel\Program\MyPetrel\Config\2014.5\ExtensionsOmega"
    #>
    param (
            [string] $PetrelExeConfig,
            [string] $ExtensionsFolder
            )

    [xml]$PetrelConfig = Get-Content $PetrelExeConfig
    $pluginProviders = $petrelConfig.configuration.oceanconfiguration.pluginmanagersettings.pluginproviders
        
    # Clone first network production channel
    $PluginProviderOmega = ($pluginProviders.Add)[2].clone()
               
    # Create Omega channel
    $PluginProviderOmega.name = "OmegaNetworkPlugin"
    $PluginProviderOmega.uri = "${ExtensionsFolder}\PluginManagerSettings.xml"
    $PluginProviderOmega.readonly = "True"
   
    $PluginProviders.appendchild($PluginProviderOmega)
        
    # Write to petrel.exe.config
    $PetrelConfig.Save($PetrelExeConfig)

} #end Function Set-OmegaPetrelExeConfig   

Function Set-GeotericPetrelExeConfig {
    <#   
    .DESCRIPTION 
        Add Geoteric plugin provider
    .PARAMETER PetrelExeConfig
        Path to petrel.exe.config
    .PARAMETER ExtensionsFolder
        Folder containing Geoteric plugins
    .EXAMPLE
        Set-GeotericPetrelExeConfig "C:\appl\schlumberger\bin\2014.5\petrel.exe.config" "G:\Prog\Global\Petrel\Program\MyPetrel\Config\2014.5\ExtensionsGeoteric"
    #>
    param (
            [string] $PetrelExeConfig,
            [string] $ExtensionsFolder
            )

    [xml]$PetrelConfig = Get-Content $PetrelExeConfig
    $pluginProviders = $petrelConfig.configuration.oceanconfiguration.pluginmanagersettings.pluginproviders
        
    # Clone first network production channel
    $PluginProviderGeoteric = ($pluginProviders.Add)[2].clone()
               
    # Create Geoteric channel
    $PluginProviderGeoteric.name = "GeotericNetworkPlugin"
    $PluginProviderGeoteric.uri = "${ExtensionsFolder}\PluginManagerSettings.xml"
    $PluginProviderGeoteric.readonly = "True"
   
    $PluginProviders.appendchild($PluginProviderGeoteric)
        
    # Write to petrel.exe.config
    $PetrelConfig.Save($PetrelExeConfig)

} #end Function Set-GeotericPetrelExeConfig


Function Get-ADComputerGroup {
    <#   
    .DESCRIPTION 
        Check whether the computer computer object is in specifc OU, multiple can be specified separated by semicolon
    .PARAMETER Group
        OU path to check
    .OUTPUT
        Group object (if any)
    .EXAMPLE
        Get-ADComputerGroup "OU=Hosted Desktops RGS"
    #>
    
    param (
        [string]$OU
    )

    If (!($Script:GlobalComputerOU)) {
        $Script:GlobalComputerOU = (New-Object ADSISearcher([ADSI]"LDAP://$ComputerDNSDomain","(cn=$Env:ComputerName)")).FindOne().path
    }

    $OUs = $OU.Split(";")
    $OUs | %{
        $TestOU = $Nothing
        $TestOU = $_.Trim()
        If ($TestOU) {
             $Script:GlobalComputerOU | ? {$_ -like "*$TestOU*" }
        }
    }

} #End Function Get-ADComputerGroup


Function Invoke-SystemCheck {
    <#   
    .DESCRIPTION 
        Check hardware & software towards Petrel requirements
    .EXAMPLE
        Invoke-SystemCheck
    #>   

    #Initiate Arrays
    $SystemWarning = @()
        
    #
    # Prerequisites from SCCM
    # 

      
    $MissingSccmRequirements = @()


    $Prerequisites = $IniSettings["PREREQUISITES_DEFAULT"]
    $Prerequisites += $IniSettings["PREREQUISITES_$($Script:OS)"]

    
    ForEach ($Prerequisite in ($Prerequisites.GetEnumerator())) { 
          
        $SoftwareName = $Prerequisite.Name
        $WhatToCheck = $ExecutionContext.InvokeCommand.ExpandString($Prerequisite.Value)
        
        # Not all prerequisites are defined in SCCM
        $SCCM = $IniSettings["SCCM_APPLICATIONS"]["$SoftwareName"]
        
        $SccmName = $Nothing
        $SccmId = $Nothing
        If($SCCM) {
            $SccmName = $SCCM.Split(",")[0].trim()
            $SccmId = $SCCM.Split(",")[1].trim()
        }
        
        If(!(Get-Item "$WhatToCheck")) {

            If($SccmId) {
                    
                $AddSccm = New-Object PSObject -Property @{PackageId = $SccmId;ProgramName = $SccmName}
                $MissingSccmRequirements += $AddSccm
                
                Write-DebugLog "$SoftwareName auto-installing" 
                Write-PrerequisiteLog "$SoftwareName auto-installing"
                
            } Else {
                
                Write-DebugLog "$SoftwareName missing" 
                Write-PrerequisiteLog "$SoftwareName missing"
                
            } # End If requirement exists in sccm       
        } #End If requirement exists
    } #End foreach requirement

    
    # Run script block as background job to get missing prerequisites installed
    $SCCM_Script = "c:\appl\Schlumberger\SCCM_Execute.ps1"
    If ($MissingSccmRequirements) {
        If (Test-Path $SCCM_Script) {
            Write-DebugLog "Starting $SCCM_Script to install prerequisites from SCCM" 
            Start-Job -ScriptBlock {c:\appl\Schlumberger\SCCM_Execute.ps1 -MissingSccmRequirements $args[0] -LogFileName $args[1]} -Name SCCM -ArgumentList ($MissingSccmRequirements,"MyPetrel_SCCM.log") | Out-Null
        }
        Else {
            Write-DebugLog "Could not find $SCCM_Script to install prerequisites from SCCM" 
        }
    }
    
    #Verify PowerShell version is at least on version 3, if not report errors to local and central log
    $MinPSVersion = 3
    If ($PSVersionTable.PSVersion.Major -lt $MinPSVersion) {
        Write-DebugLog "PowerShell version $($PSVersionTable.PSVersion.Major) is less than the recommended version ($MinPSVersion)"
        Write-ErrorLog "PowerShell version $($PSVersionTable.PSVersion.Major) is less than the recommended version ($MinPSVersion)"
    }

 
     # Commented out 20150907 :: Not 100% sure these three checks are correct
    <#
  
    # Graphics settings 
        
    $Nvidia = get-ciminstance cim_videocontroller | ? {$_.Name -like 'Nvidia*'}

    If ($Nvidia) {

        # Graphics driver updated
        # Version 340.84 = 9.18.13.4084
        # Version 347.88 = 9.18.13.4788
        $Nvidia_RecommendedVersion = "9.18.13.4084"
        [int]$Nvidia_RecommendedVersionFix = $Nvidia_RecommendedVersion.Replace(".","")
        [int]$Nvidia_InstalledVersion = ($Nvidia.DriverVersion).Replace(".","")

        If ($Nvidia_InstalledVersion -lt $Nvidia_RecommendedVersionFix) {
            $SystemWarning += "Nvidia Graphics driver is outdated"
            Write-PrerequisiteLog "Nvidia Graphics driver is outdated ($Nvidia_InstalledVersion vs $Nvidia_RecommendedVersionFix)"
        }

    } Else {
        $SystemWarning += "No Nvidia Graphics card detected"
    }    
    #>

    #
    # System Settings
    #

    # Checking free diskspace      
    If ($DiskFreeSpaceCheck -eq $False) {
        
        [int]$FreeSpaceGB = $FreeSpace / 1GB
        Write-DebugLog "Low disk space ($FreeSpaceGB GB)" 
        $SystemWarning += New-Object psobject -Property @{Text = "Disk space is low ($FreeSpaceGB GB); will impact Petrel operations!"; Color = "Red"}
                
    } # End If low on diskspace

    # Checking Nvidia 3D Settings
    If(Test-Path "C:\Program Files\NVIDIA Corporation") {

        $NvidiaWMI = Get-WmiObject -namespace "root\cimv2\nv" -class Profile

        If($NvidiaWMI) {

            $Nvidia3DProfile = "Workstation App - Dynamic Streaming"
            $NvidiaDynamicStreaming = $NvidiaWMI | Select name | Where-Object { $_.name -eq "$Nvidia3DProfile" }

            If(!($NvidiaDynamicStreaming)) {
                           
                $NvidiaChangeStatus = Invoke-WmiMethod -Namespace "root\cimv2\nv" -class ProfileManager -Name SetCurrentProfile3D -ArgumentList $Nvidia3DProfile
                If ($NvidiaChangeStatus.ReturnValue -eq $True) {
                    Write-DebugLog "Nvidia profile successfully set to ""$Nvidia3DProfile"""
                    Write-ErrorLog "Nvidia profile successfully set to ""$Nvidia3DProfile"""
                    $SystemWarning += New-Object psobject -Property @{Text = "Successfully configured NVidia 3D settings"; Color = "Green"}
                }
                Else {
                    Write-DebugLog "Nvidia profile failed to change to ""$Nvidia3DProfile"""
                    Write-ErrorLog "Nvidia profile failed to change to ""$Nvidia3DProfile"""
                    $SystemWarning += New-Object psobject -Property @{Text = "Failed to automatically configure NVidia 3D settings"; Color = "Black"}
                }

            } # End If Nvidia 3D settings are wrong 

        } Else {

            Write-DebugLog "Missing Nvidia WMI" 
            Write-ErrorLog "Missing Nvidia WMI"

        } #end if Nvidia WMI is installed/available
    } # End If Nvidia card

    # WiFi check on Windows 10
    If ($Script:OS -eq "WIN10") {
        $DomainConnection = Get-NetConnectionProfile | ?{$_.NetworkCategory -eq "DomainAuthenticated"}
        $NICInfo = Get-NetAdapter -InterfaceIndex $DomainConnection.InterfaceIndex
        $ConnectionType = $NICInfo.MediaType
        Switch ($ConnectionType) {
            "Native 802.11" {$WiFiConnected = $True}
            default {$WiFiConnected = $False}
        }
        If ($WiFiConnected) {
            Write-DebugLog "WiFi connection found active towards statoil.net domain: $($NICInfo | Out-String)"
            Write-ErrorLog "WiFi connection found active towards statoil.net domain"
            $SystemWarning += New-Object psobject -Property @{Text = "Active WiFi connection found; will affect network performance"; Color = "Red"}
        }
    }


    # If SystemWarning, format to HTML with bullett points 
    If ($SystemWarning) {
        $SystemWarningHTML = $Nothing
        $SystemWarningHTML = "<ul style='margin-top: 0; margin-left: 20px;'>"
        $SystemWarning | %{
            $SystemWarningHTML += "<li><font color=""$($_.Color)"">$($_.Text)</font></li>"
        }
        $SystemWarningHTML += "</ul>"
        Return $SystemWarningHTML
    }
    Else {
       Return "All good!"
    }
    # End If SystemWarning
    
} #End Function Invoke-SystemCheck


Function Set-Profile {
   <#   
    .DESCRIPTION 
        Set profiles.xml
    .PARAMETER Area
        Site abbreviation
    .EXAMPLE
        Set-Profile "JAK"        
    #>   
    param (
        [string] $Area
    )
    
    $Source1 = "$NetworkPetrelVersionConfigFolder\Profiles\Profiles_$Area.xml"
    $Source2 = "$NetworkPetrelVersionConfigFolder\Sync\Profiles.xml"
    $Destination = "$AppDataPetrelVersionFolder\Profiles.xml"
    
    If(Test-Path $Source1) {
    
        Copy-Item $Source1 $Destination
        
    } ElseIf (Test-Path $Source2) {
    
        Copy-Item $Source2 $Destination

    } #end if network profile

} #end Function Set-Profile


Function Get-DongleID {
    <#   
    .DESCRIPTION 
        Get ID from connected Codemeter USB dongle
    .EXAMPLE
        Get-DongleID 
    .OUTPUTS
        Dongle ID (if any)
    #>
    
	$searchPattern = "- CmContainer with Serial Number "   
	$CMUOutput = ""
	
	# Get the DongleID++ from Codemeter 
	If (Test-Path $CodemeterCmuExeFile) { 

        $CMUOutput = & $CodemeterCmuExeFile "/l"

    } #end if codemeter.exe exists
	
	ForEach ($line in $CMUOutput)
	{
		If ($line.StartsWith($SearchPattern))
		{
            # $line = <searchPattern>dongleID <whatever>
            # dongleID gets returned through the pipeline
            $line.Replace($searchPattern,"").split(" ")[0]
		}
	}
} #end Function Get-DongleID


Function Invoke-DongleLicense {
    <#   
    .DESCRIPTION 
        Invoke local license server process 
    .EXAMPLE
        Invoke-DongleLicense 
    #>

    $DongleID = Get-DongleID
    
    If ($DongleID) {

        # Licence file source and destination
        $RemoteLicFile = "$NetworkDongleFolder\LicenseFiles\$DongleID.lic"
        $LocalLicFile = "$LocalDongleFolder\petrel.lic"

        # Local license directory 
        If (!(Test-Path -path $LocalDongleFolder)) {
            New-Item $LocalDongleFolder -Type Directory
        }

        # Sync the dongle license file (if on network)
        If (Test-Path $RemoteLicFile) { 
            Copy-Item $RemoteLicFile $LocalLicFile -Force 
        }  
        
        # Log dongle ID to central log file
        Write-DongleLog "$DongleID"

        # Sync license binaries (if on network)
        & robocopy "$NetworkDongleFolder\Bin" $LocalDongleFolder /E /R:1 /W:1
  
        # Auto-generate profiles.xml file
        Set-DongleProfile "$AppDataPetrelVersionFolder\profiles.xml" $LocalLicFile 
  
        Start-Sleep 2
  
        # Starts service if we have a license file
        If (Test-Path $LocalLicFile) {
        
            "Start-Process $LmgrdExeFile -WorkingDirectory $LmgrdFolder -ArgumentList -c $LocalLicFile" 
            # Start-Process is buggy regarding return codes - so have to assume it's working
            Start-Process $LmgrdExeFile -WorkingDirectory $LmgrdFolder -ArgumentList "-c $LocalLicFile"  
            
            #Try to verify that slbsls process is started and responding to TCP port
            $slbslsStatus = Test-ProcessWithTCPConnection "slbsls" 
            Write-DebugLog "Dongle: SLBSLS running status + TCP connection result: $slbslsStatus"
            
        } Else {

            Write-DebugLog "No local license file detected for dongle ID $DongleID"
            Write-ErrorLog "No local license file detected for dongle ID $DongleID"
            Show-BalloonTip "Error: No local license file detected"

        } #end if license file exists
        
    } Else {

        Write-DebugLog "No dongle detected" 
        Write-ErrorLog "No Dongle detected"
        Show-BalloonTip "Error: No Dongle detected"

    } #end if dongle is present
} #end Function Invoke-DongleLicense


Function Set-DongleProfile {
   <#   
    .DESCRIPTION 
        Auto-generate a dongle profiles.xml
    .PARAMETER ProfileFile
        Current profiles.xml
    .PARAMETER LicenseFile
        Dongle license file        
    #>
    
    param (
        [string] $ProfileFile,
        [string] $LicenseFile
    )

    Write-DebugLog "Setting profile.xml for local dongle" 
    
    # Use current profiles file as skeleton
    [XML]$DongleProfile = Get-Content $ProfileFile
    
    If ($DongleProfile.Profiles.Profile[0]) {
        $ProfileTemp = ($DongleProfile.Profiles.Profile[0]).clone()
    } Else {
        $ProfileTemp = ($DongleProfile.Profiles.Profile).clone()
    }
    
    # Remove old features
    $OldFeatures = $DongleProfile.profiles.SelectNodes("Profile")
    ForEach ($OldFeature in $OldFeatures) {
        $DongleProfile.profiles.RemoveChild($OldFeature)
    }

    # Get all features from dongle license file
    $Features = Get-Content $LicenseFile | Where-Object { $_ -Like "Feature *" } | ForEach-Object { $_.Split(" ")[1] }
        
    ForEach ($Feature in $Features) { 
        
        $ProfileTemp.Name = "$(${Env:Username}.ToUpper())" + " $Count"
        $ProfileTemp.Icon = "dongle.jpg"
        $ProfileTemp.SelectionBaseId = "$Feature"
        $DongleProfile.profiles.AppendChild($ProfileTemp)
        
        $Count += 1
        
    } # end foreach feature
    
    # Save new profiles file
    $DongleProfile.Save("$ProfileFile")
    
} #end Function Set-DongleProfile


Function Set-LicenseServer {
    <#   
    .DESCRIPTION 
        Set Petrel license server 
    .PARAMETER LicenseServer
        Point towards correct license server
    .EXAMPLE
        Set-LicenseServer 27009@petrel-lic-no.statoil.net
    #>  
    param (
        [string] $LicenseServer
    )
    
    Write-DebugLog "Setting license server $LicenseServer" 
    $ENV:SLBSLS_LICENSE_FILE = $LicenseServer

} #end Function Set-LicenseServer

Function Test-TCPPort {
    <#   
    .DESCRIPTION 
        Check if TCP port on specified host is working
    .PARAMETER HostName
        Host of which the test should be run against
    .PARAMETER Port
        TCP port to run the test against
    .PARAMETER TimeOut
        Seconds to wait for response
    .EXAMPLE
        Test-TCPPort -HostName st-w01 -Port 389 -Timeout 2000
        Test-TCPPort -HostName localhost -Port 27009 
    #>
    param (
        [string]$HostName,
        [int]$Port,
        [int]$Timeout = 10000
    )

    $TCPPortConnected = $False

    Try {
        $TCPClient = New-Object System.Net.Sockets.TcpClient
        $Connect = $TCPClient.BeginConnect($HostName,$Port, $Null, $Null)
        $ConnectResult = $Connect.AsyncWaitHandle.WaitOne($Timeout,$False)
        $TCPClient.Close()
        If ($ConnectResult) {
            $TCPPortConnected = $True
            Write-DebugLog "Successfully connected to $($HostName):$($Port)"
        
        }

        Return $TCPPortConnected
    }
    Catch {
        Write-DebugLog "Unable to connect to $HostName $Port"
        Return $TCPPortConnected
    }



} #End Function Test-TCPPort

Function Test-TCPPortUsingRunspace {
    <#   
    .DESCRIPTION 
        Check if TCP port on specified host is responding. Used runspace to run it async so other things can be processed while waiting
    .PARAMETER HostName
        Host of which the test should be run against
    .PARAMETER Port
        TCP port to run the test against
    .PARAMETER TimeOut
        Seconds to wait for response
    .EXAMPLE
        Test-TCPPortUsingRunspace -HostName st-w01 -Port 389 -Timeout 2000
        Test-TCPPortUsingRunspace localhost -Port 27009 
    #>
    param(
        $HostName,
        $Port,
        $TimeOut = 5000
    )

    #ScriptBlock to check for license server availability
    $VerifyTCPPort = {
        param(
            $HostName,
            $Port,
            $TimeOut
        )

        Try {
            $TCPClient = New-Object System.Net.Sockets.TcpClient
            $Connect = $TCPClient.BeginConnect($HostName,$Port, $Null, $Null)
            $ConnectResult = $Connect.AsyncWaitHandle.WaitOne($Timeout,$False)
            $TCPClient.Close()
            If ($ConnectResult) {
                $TCPPortConnected = $True
            }
            Else {
                $TCPPortConnected = $False
            }
            If ($TCPPortConnected) {            
                [PSCustomObject]@{
                    HostName = $HostName
                    Port = $Port
                    Connected = $True
                }
            }
            Else {
                [PSCustomObject]@{
                    HostName = $HostName
                    Port = $Port
                    Connected = $False
                }
            }
        }
        Catch {
                [PSCustomObject]@{
                    HostName = $HostName
                    Port = $Port
                    Connected = $False
                }
        }

    }

    #Create Runspace for background execution
    $TCPCheckRunSpace = [RunspaceFactory]::CreateRunspace()
    $TCPCheckPowerShell = [PowerShell]::Create()
    $TCPCheckPowerShell.RunSpace = $TCPCheckRunSpace
    $TCPCheckRunSpace.Open()

    #Add scriptblock and arguments to Runspace
    [void]$TCPCheckPowerShell.AddScript($VerifyTCPPort)
    [void]$TCPCheckPowerShell.AddArgument($HostName)
    [void]$TCPCheckPowerShell.AddArgument($Port)
    [void]$TCPCheckPowerShell.AddArgument($TimeOut)

    #Kick off job and return object so that we can track status
    Return [PSCustomObject]@{ Pipe = $TCPCheckPowerShell; Status = $TCPCheckPowerShell.BeginInvoke()}

} #End Function Test-TCPPortUsingRunspace


Function Test-ProcessWithTCPConnection {
    <#   
    .DESCRIPTION 
        Check if a process is started locally and responding to TCP connections
    .PARAMETER ProcessName
        Name of the process to check for without extention
    .PARAMETER MaxLoops
        How many times to check before aborting
    .EXAMPLE
        Test-ProcessWithTCPConnection -ProcessName lmgrd -MaxLoops 40
    #>
    param(
        [string]$ProcessName,
        [int]$MaxLoops = 40
    )

    [int]$SleepMilliseconds = 500
    $LoopCounter = 1

    Do {
        $ProcessListening = $False

        #Check if process is in running process list
        $ProcessId = (Get-Process $ProcessName -ErrorAction SilentlyContinue).Id
        Write-DebugLog "Found ProcessID: $ProcessId for ProcessName: $ProcessName"
        If ($ProcessId) {
            #For now, just care about IPv4 listener
            $TCPListen = netstat -ano | Select-String -Pattern "\sTCP\s+0.0.0.0.+$ProcessId"
            
            If ($TCPListen) {
                $CurrentTCPPort = $TCPListen.ToString()
                $CurrentTCPPort = $CurrentTCPPort.Split(" ")
                $CurrentTCPPort = $CurrentTCPPort[6].Substring(8)
                #Test that port is actually responding to TCP connection              
                Write-DebugLog "Found $ProcessName listening on TCP port $CurrentTCPPort"
                $ProcessListening = Test-TCPPort -HostName localhost -Port $CurrentTCPPort -Timeout 1000
            }
            Else {
                Write-DebugLog "ProcessName: $ProcessName is not yet listening, waiting and trying once more; attempt=$LoopCounter"
                Start-Sleep -Milliseconds $SleepMilliseconds

            }
        }
        Else {
            #Process not starting, wait before retrying loop
            Write-DebugLog "Process $ProcessName not found, waiting and trying once more; attempt=$LoopCounter"
            Start-Sleep -Milliseconds $SleepMilliseconds
        }

        $LoopCounter++
    } While ($LoopCounter -le $MaxLoops -And $ProcessListening -eq $False)

    Return $ProcessListening
} #End Function Test-ProcessWithTCPConnection

Function Test-RegistryValue {
      <#   
    .DESCRIPTION 
        Checks is registry value already exists (shortcoming of Test-Path)
    .PARAMETER Path
        Registry key to check
    .PARAMETER Value
        Registry value to check
    .EXAMPLE
        Test-RegistryValue -Path "HKCU:\Software\Statoil\MyPetrel" -Value "Version"
        Checks and return true if HKCU\Software\Statoil\MyPetrel\Version exists
    #>
    param (
        [string]$Path,
        [string]$Value
    )

    Try {
        Get-ItemProperty -Path $Path -Name $Value -ErrorAction Stop | Out-Null
        Return $True
    }

    Catch {
        Return $False
    }
} #End Function Test-RegistryValue

Function Set-CompatibilityMode {
      <#   
    .DESCRIPTION 
        Set Windows compatibilty mode for an EXE file
    .PARAMETER EXEFile
        EXE file that should receive compatibilty settings
    .PARAMETER CompatibilityMode
        Compatibility Mode setting (fx. WIN7RTM, WIN8RTM, HIGHDPIWARE), combine multiple in one string. Special variant "NONE" will remove existing setting for specific exefile
    .EXAMPLE
        Set-CompatibiltyMode -EXEFile "c:\appl\Schlumberger\bin\2016.4\Petrel.exe" -CompatibilityMode "WIN7RTM"
        Set-CompatibiltyMode -EXEFile "c:\appl\Schlumberger\bin\2016.4\Petrel.exe" -CompatibilityMode "NONE"
        Sets specified exe file to run in WIN7RTM mode
    #>
    param (
        [string]$EXEFile,
        [string]$CompatibilityMode
    )

    $RegistryKey = "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"
    If (!(Test-Path $RegistryKey)) {
        New-Item $RegistryKey
    }

    If ($CompatibilityMode -eq "NONE") {
        Try {
            If (Test-RegistryValue -Path $RegistryKey -Value $EXEFile) {
                Remove-ItemProperty -Path $RegistryKey -Name $EXEFile
                Write-DebugLog "Removing compatibility mode for ""$EXEFile"""
            }
        }

        Catch {
            Write-DebugLog "Failed to remove compatibility mode for ""$EXEFile"""
        }
    }
    Else {
        If (Test-Path "$EXEFile") {
            If (!(Test-RegistryValue -Path $RegistryKey -Value $EXEFile)) {
                Try {
                    New-ItemProperty -Path $RegistryKey -Name $EXEFile -Value $CompatibilityMode | Out-Null
                    Write-PrerequisiteLog "Setting compatibility mode ""$CompatibilityMode"" for ""$EXEFile"""
                    Write-DebugLog "Setting compatibility mode ""$CompatibilityMode"" for ""$EXEFile"""
                }

                Catch {
                    Write-DebugLog "Failed to set compatibility mode ""$CompatibilityMode"" for ""$EXEFile"""
                }
            }
        }
    }


} #end function Set-CompatibilityMode

Function Start-Petrel {
    <#   
    .DESCRIPTION 
        Start Petrel process
    .EXAMPLE
        Start-Petrel C:\Appl\Schlumberger\Bin\2015.2\petrel.exe
    #>
    
    param (
        [string] $PetrelExeFile = $Script:LocalPetrelExeFile
    ) 

    # Start Petrel
    If (Test-Path $PetrelExeFile) {

        #Get levels from ini file
        $UserWarningLevel = $IniSettings["LICENSE_RESTRICTIONS"]["UserWarningLevel"]
        $UserBlockLevel = $IniSettings["LICENSE_RESTRICTIONS"]["UserBlockLevel"]

        #If user is part of the exception, set $UserBlockLevel to define level
        $UserBlockLevelExceptionList = $IniSettings["LICENSE_RESTRICTIONS"]["ExceptionList"]
        $UserBlockLevelExceptionValue = $IniSettings["LICENSE_RESTRICTIONS"]["ExceptionValue"]
        $ExceptionCSV = import-csv $UserBlockLevelExceptionList -Encoding UTF7
        If ($ExceptionCSV.Name -contains $Env:Username){
            $UserBlockLevel = $UserBlockLevelExceptionValue
        }

        #Check and warn user if Petrel is already running
        $JobWaitLicenseCheck = $JobStartLicenseCheck | Wait-Job -Timeout 1

        #Explicit cast retuned object to array to get count (issue in <= PS 3.0)
        $LicenseInfo  = $JobWaitLicenseCheck | Receive-Job -ErrorAction SilentlyContinue
        
        #Set default outcome of dialog box if user not are using licenses
        $UserSelection = [System.Windows.Forms.DialogResult]::Yes

        #If not in dataroom, check if JSON object is returned, ie. user has one or more licenses checked out (count does not handle 1, so check one specific attribute from JSON to catch those)
        If (!($MyMode -eq "DATAROOM") -And (($LicenseInfo.Count -ge 2) -Or ($LicenseInfo.LicenseUser -eq $Env:UserName))) {
            
            #Check number of licenses used related to current MyPetrel mode
            $MyLicenses = $LicenseInfo | ?{$Area -like "*$($_.FeatureName)*"}

            #Count doesn't support 1 object, so construct number of licenses used to new variable
            If (($MyLicenses.Count -ge 2) -Or ($MyLicenses.Count -eq 0)) {
                $MyCurrentLicenseCount = $MyLicenses.Count
            }
            ElseIf ($MyLicenses.LicenseUser -eq $Env:UserName) {
                $MyCurrentLicenseCount = 1
            }

            # Add correct text to output based on if one or more licenses are used
            If ($MyCurrentLicenseCount -ge 2) {
                $LicenseInfoString = "You are already using $($MyCurrentLicenseCount) Petrel licenses:`n`n"
            }
            Else {
                $LicenseInfoString = "You are already using 1 Petrel license:`n`n"
            }
                
            #Format date/time of license chechout to local date/time format
            $MyLicenses | %{
                $LicenseCheckoutTime = [datetime]::ParseExact($_.LicenseTime, "yyyyMMdd-HHmm", [CultureInfo]::InvariantCulture).ToShortDateString() + " " + [datetime]::ParseExact($_.LicenseTime, "yyyyMMdd-HHmm", [CultureInfo]::InvariantCulture).ToShortTimeString()
                $LicenseInfoString += "Mode: $($_.FeatureName)  Client: $($_.LicenseHost)  StartTime: $LicenseCheckoutTime`n"
            }
            $LicenseInfoString += "`n"

            #Evaluate how we continue based on number of current licenses in use
            Switch ($MyCurrentLicenseCount) {
                {($_ -ge $UserBlockLevel)} {
                    #Rest of information to provide to user
                    $LicenseInfoString += "You have reached the maximum number of allowed Petrel licenses.`n`n"
                    $LicenseInfoString += "You will need to stop one of the Petrel licenses and then allow 2 minutes for the system to update before restarting MyPetrel to continue.`n`n"
                    $UserSelection = [System.Windows.Forms.MessageBox]::Show($LicenseInfoString,"Petrel Licenses","OK","Error")
                    $UserSelection = "No"

                    #Document in debug log also
                    Write-DebugLog "Blocking user from starting Petrel since user already has $MyCurrentLicenseCount licenses in use"
                    Write-ErrorLog "Blocking user from starting Petrel because user has reached block limit of $UserBlockLevel"

                    #Exit switch
                    Break

                }
                {($_ -ge $UserWarningLevel)} {
                    #Rest of information to provide to user
                    $LicenseInfoString += "If you check out an another license you must take responsibility for freeing up that license as soon as you have finished using it, "
                    $LicenseInfoString += "otherwise you could block other users from accessing Petrel.`n`n"
                    $LicenseInfoString += "Are you sure you want to check out another license?"
                    $UserSelection = [System.Windows.Forms.MessageBox]::Show($LicenseInfoString,"Petrel Licenses","YesNo","Warning")

                    #Document in debug log also
                    Write-DebugLog "Warning user about starting Petrel since user already has $MyCurrentLicenseCount licenses in use"

                    #Exit switch
                    Break

                }
                default {
                    $UserSelection = "Yes"
                }
            }
            
        }

        If ($UserSelection -eq "Yes") {
            Write-DebugLog "Starting Petrel - $PetrelExeFile" 
	        Start-Process $PetrelExeFile -WorkingDirectory $(Split-Path $PetrelExeFile)
        }
        Else {
            Write-DebugLog "User already has Petrel running and selected to opt out of running Petrel"
        }

    } Else {
        
        Write-DebugLog "Petrel executable $PetrelExeFile is missing"
        Show-BalloonTip "Error: Petrel executable $PetrelExeFile is missing" 
        Write-ErrorLog "Petrel executable $PetrelExeFile is missing"
    }
      
    # Close any GUI
	If ($MyPetrelGUI) { 

        Close-Form

    } #End If GUI

} #end Function Start-Petrel


Function Close-Form {
 
    Write-UsageLog "$MyMode Mode,$($ENV:SLBSLS_LICENSE_FILE)"
 
    # Bug in PS2 -> Can't exit before all jobs are finished
    $jobs = (Get-Job -state running | Measure-Object).count 
		
    If($jobs -gt 0) {
        
        Write-DebugLog "Running jobs - hiding MyPetrel GUI" 
        $MyPetrelGUI.Visible = $False

        While($jobs) {    
            	
            Start-Sleep -Seconds 5
            $jobs = (Get-Job -State Running | Measure-Object).Count 
            
        } #end while jobs are running
    } #end if jobs
      
    Write-DebugLog "All done - Closing MyPetrel GUI" 
    $MyPetrelGUI.Close()      

} #end function Close-Form


function Sync-Version {
    <#   
    .SYNOPSIS
        Upgrades Petrel on local machine
    .DESCRIPTION 
        This function starts 4 parallell threads:
        1. Delete current Petrel version (as background job) if not on RGS/SIP
        2. Load new Petrel version (showing in GUI), except binaries in 3 & 4
        3. Load new Petrel version's help files (as background job)
        4. Load new Petrel version's wellsymbols (as background job)
        When thread 2 is finished, Petrel can be started
    .EXAMPLE
        Sync-Version 2015.2
    #>
    [CmdletBinding()]
    param (
            [Parameter(Mandatory = $true)]
            [string] $Version
    )
    
    Write-DebugLog "Start loading Petrel $Version" 

    # Network version available?
    If(!(Test-Path $NetworkPetrelVersionBinFolder)) {
 
	Write-DebugLog "Network version not available at $NetworkPetrelVersionBinFolder" 
        Write-ErrorLog "Network version not available at $NetworkPetrelVersionBinFolder"
        $PickVersionText.Text = "ERROR: Petrel G:\ drive version not available." 
        $PickVersionProgressBar.Value = 0
        Return $false

    } #end if network version is available
  
    # Enough free space to sync new binaries?
    If ($FreeSpace -lt $RequiredFreeSpace) {
        
        [int]$GbFreeSpace = $FreeSpace/1GB
        Write-DebugLog "Not enough space on disk ($GbFreeSpace GB)" 
        Write-ErrorLog "Not enough space on disk ($GbFreeSpace GB)"
        $PickVersionText.Text = "ERROR: Need $([int]($RequiredFreeSpace/1gb)) GB free disk space to load Petrel." 
        $PickVersionProgressBar.Value = 0
        Return $false
                
    } Else {

        $CommonRobocopyArguments = "/MT:32 /E /FFT /NP /NFL /NDL /NC /BYTES /NJH /NJS" 

        #If local bin folder exists (ie. not first run)
        If (Test-Path $LocalPetrelBinFolder) {
	        # 1. Delete current Petrel version (as background job) if not on RGS/SIP
            If (!$(Get-ADComputerGroup $GroupRGS) -And !$(Get-ADComputerGroup $GroupSIP)) {

	            [String]$BckPetrelVersionsFolder = "${LocalPetrelBinFolder}_bck"
                Try {
	                Move-Item $LocalPetrelBinFolder $BckPetrelVersionsFolder -Force -ErrorAction Stop -ErrorVariable BckPetrelError
	                Start-Job -Scriptblock { Remove-Item $args[0] -Recurse -Force } -ArgumentList $BckPetrelVersionsFolder
                }
                Catch {
                    Write-DebugLog "Renaming folder $LocalPetrelBinFolder to $BckPetrelVersionsFolder failed. Error:  $($BckPetrelError.ErrorRecord)"
                    Write-ErrorLog "Renaming folder $LocalPetrelBinFolder to $BckPetrelVersionsFolder failed. Error:  $($BckPetrelError.ErrorRecord)"
                }
        
            } # End if not on RGS or SIP
        } #End If Local bin folders exists

	    # 2. Load new Petrel version (showing in GUI), except binaries in 3 & 4
		Copy-WithProgress -Source $NetworkPetrelVersionBinFolder -Destination $LocalPetrelBinVersionFolder -Verbose;      
 
	    # 3. Load new Petrel version's help files (as background job)
        $DocArgumentList = "$NetworkPetrelVersionBinFolder\Dox $LocalPetrelBinVersionFolder\Dox $CommonRobocopyArguments"
		Start-Process -FilePath robocopy.exe -ArgumentList $DocArgumentList -verbose -PassThru -NoNewWindow;
        
        # 4. Update global variable to state that an install/upgrade of Petrel has been done
        $Script:SyncNewVersion = $True

	    # Removed 18012018 because sync will be done from a Equinor maintained location
        #4. Load new Petrel version's wellsymbols (as background job)
		#$WellSymbolsArgumentList = "$NetworkPetrelVersionBinFolder\Resources\Wellsymbols $LocalPetrelBinVersionFolder\Resources\Wellsymbols $CommonRobocopyArguments"
		#Start-Process -FilePath robocopy.exe -ArgumentList $WellSymbolsArgumentList -verbose -PassThru -NoNewWindow; 

    } #End If Free space
     
    Write-DebugLog "Done loading Petrel $Version" 
    
} #end function Sync-Version


function Copy-WithProgress {
    <#   
    .SYNOPSIS
        Running parallell file copy while keeping track of progress
    .DESCRIPTION 
        The function first performs a dry run to get number / total size of files.
        Then, actual copying is started - keeping track of progress by 
        monitoring the log file
        This function starts 4 parallell threads:
    .OUTPUT
        Elapsed copy time in seconds 
     .EXAMPLE
        Sync-Version 2015.2
    #>
    [CmdletBinding()]
    param (
            [Parameter(Mandatory = $true)]
            [string] $Source,
            [Parameter(Mandatory = $true)]
            [string] $Destination      
    ) 

    #All except dox
    $RobocopyParams = "/MT:32 /E /FFT /NP /NDL /NC /BYTES /NJH /NJS /XD $Source\Dox /W:1 /R:1";

    # Dry run to get total number of files
    $DryRunLogPath = [System.IO.Path]::GetTempFileName()    
    $DryRunArgumentList = '"{0}" "{1}" /LOG:"{2}" /L {3}' -f $Source, $Destination, $DryRunLogPath, $RobocopyParams;
    Start-Process -Wait -FilePath robocopy.exe -ArgumentList $DryRunArgumentList -NoNewWindow;
    $FilesTotal = (Get-Content -Path $DryRunLogPath).Count;
    Write-DebugLog "Petrel needs to sync $FilesTotal files to be in sync"

    # Start parallell file sync
    $RobocopyLogPath = [System.IO.Path]::GetTempFileName()
    $RobocopyArgumentList = '"{0}" "{1}" /LOG:"{2}" {3}' -f $Source, $Destination, $RobocopyLogPath, $RobocopyParams
    $RobocopyProcess = Start-Process -FilePath robocopy.exe -ArgumentList $RobocopyArgumentList -Verbose -PassThru -NoNewWindow; 

    $StartTime =  (Get-Date -UFormat %s).Replace(",",".")
   
    # Monitor log file / update progress bar while copying
    while (!$RobocopyProcess.HasExited) {

        Start-Sleep -Milliseconds 500;
        
        $FilesCopied = (Get-Content -Path $RobocopyLogPath).Count
 
        If($FilesCopied -gt 0) {
              
            [System.Windows.Forms.Application]::DoEvents()
  
            $PercentCompleted = ($FilesCopied/$FilesTotal)*100      
            $PercentRemaining = 100 - $PercentCompleted
        
            $PickVersionProgressBar.Value = $PercentCompleted
            
            $ElapsedTime = $((Get-Date -UFormat %s).Replace(",",".")) - $StartTime

            # Add 5 seconds as the count is not 100% accurate
            [int]$TimeLeft = 5 + ($ElapsedTime * $PercentRemaining / $PercentCompleted)
                
            If ($TimeLeft -ge 60) {
                                
                [int]$Minutes = $TimeLeft / 60
                If($Minutes -eq 1) {
                    $TimeRemaining = "About one minute"
                } Else {
                    $TimeRemaining = "About $Minutes minutes"
                }

            } Else {
                
                If($TimeLeft -le 0) { 
                    $TimeLeft = 3
                }
                $TimeRemaining = "About $TimeLeft seconds"            
                
            } # end if timeleft 

        } Else {
        
            # Graphical trick - dummy progress bar due to 
            # robocopy log file not being updated instantly
            $dummycounter += 1
            
            If($dummycounter -gt 8) {

                $PickVersionProgressBar.Value = $dummycounter
                $TimeRemaining = "Less than one minute"

            } Else {
                
                $TimeRemaining = "Some minutes"

            }#end if dummycounter          
            
        } # end if files are copied
        
        $PickVersionText.Text = "Upgrading to Petrel $Version - $TimeRemaining remaining"

   } #end while robocopy process
      
   $ElapsedTime 
    
} #End Function Copy-WithProgress


Function Show-LicenseServers {
    <#   
    .DESCRIPTION 
        Show Petrel license servers
    .PARAMETER sites
        Array with license server information
    .EXAMPLE
        Show-LicenseServers 2014.5
    #>   
    param (
        [string] $Version
    )

    #Get license server status from previously created runspace, and make sure it's completed before we check. 
    #Check when we start so that we can abort if we are stuck in loop
    $StartLoop = Get-Date
    If (!$Script:RunspaceLicenseServerCheck.Status.IsCompleted) {
        #Loop until job is finished or start a new timeout as failsafe is we get stuck in loop
        Do { 
            Start-sleep -m 100 
        } 
        While (!$Script:RunspaceLicenseServerCheck.Status.IsCompleted -Or ((New-TimeSpan -Start $StartLoop).Milliseconds -lt $($IniSettings["LICENSESERVER"]["Timeout"])))
    }
    $LicenseServerStatus = $Script:RunspaceLicenseServerCheck.Pipe.EndInvoke($Script:RunspaceLicenseServerCheck.Status) 

    # Set top-right of license server groupbox
    $LicensePick.Location = "$MarginWidth, $GlobalPointerY" 
    
    # Load version setup from INI file
    If($IniSettings["PROFILES_$Version"]) {

        $ProfilesVersion = $IniSettings["PROFILES_$Version"]
    
    } Else {
      
        $ProfilesVersion = $IniSettings["PROFILES_DEFAULT"]
        If ($LicenseServerStatus.Connected -ne $True) {
            $ProfilesVersion += $IniSettings["PROFILES_RECOVERY"]
            $LicenseStatusText = "Enabling recovery license servers in GUI since license server $($LicenseServerStatus.HostName) on port $($LicenseServerStatus.Port) connection status is $($LicenseServerStatus.Connected)"
            Write-DebugLog $LicenseStatusText
            Write-ErrorLog $LicenseStatusText
        }
        Else {
            Write-DebugLog "Successfully verified that Petrel license server $($LicenseServerStatus.HostName) on port $($LicenseServerStatus.Port) connection status is $($LicenseServerStatus.Connected)"
        }
    
    } #End If Specific Profile

    $counter = 0

    # My Petrel AD Groups
    $MyGroups = Get-MyAdGroups 

    # Hack for data room usage
    If($MyMode -eq "DATAROOM") {
        
            $MyGroups = "Petrel Europe"

    } #end if data room

    #Sort profile list as integer, ie. based on profile number from MyPetrel.ini
    ForEach ($Profile in ($ProfilesVersion.GetEnumerator() | Sort-Object @{e={$_.Name -as [int]}})) {
    
        $Values = $Profile.Value.Split(",")
        
        [string]$area = $Values[0].Trim()
        [string]$text = $Values[1].Trim()
        [string]$server = $Values[2].Trim()
        [string]$groups = $Values[3]

        $ProfileGroups = $groups.Split(";") | ForEach-Object { $_.Trim() }

        # Remove license servers the user doesn't have access to
        If(!$Area -or !$ProfileGroups) {

            # No profile or group limitation => ok

        } ElseIf($MyMode -eq "Offline") {
            
            Write-DebugLog "License server $text not applicable for offline usage"
            Continue
            
        } ElseIf($MyMode -eq "SIP") {

            If($ProfileGroups -contains "Omega") {
            
                # Dummy group 'Omega' => ok

            } Else {

                Write-DebugLog "License server $text not applicable for SIP"
                Continue
            }

        } ElseIf(!(Compare-Object $ProfileGroups $MyGroups -IncludeEqual -ExcludeDifferent)) {

            Write-DebugLog "No access to license server $text (need AD group $ProfileGroups)"
            Continue

        } 
            
        # Create license server buttons
        If($area -or (Get-DongleID)) {

            #Create button
            $button = New-Object System.Windows.Forms.Button
            $button.Size = "$ButtonWidth, $ButtonHeight"
            $button.Font = $ButtonFont
            $button.Text = $text  
            $button.Tag = "$area,$server"
            $button.ForeColor = "$ButtonTextColor"
            $button.BackColor = "$ButtonBackgroundColor"
            $button.UseVisualStyleBackColor = $True

            #Place the button on correct spot in the groupbox
            $counter += 1
            If ($counter %3 -eq 1) {
                #First column
                If ($counter -eq 1) {
                    #First row
                    $ButtonY = $MarginHeight
                }
                Else {
                    # 2nd and following rows
                    $ButtonY += $ButtonY + $ButtonSpacerHeight
                }
                $button.Location = "$MarginWidth, $ButtonY"
            }
            ElseIf ($counter %3 -eq 2) {
                #Second column
                $button.Location = "$($MarginWidth + $ButtonWidth + $ButtonSpacerWidth), $ButtonY"
            }
            Else {
                #Third column
                $button.Location = "$($MarginWidth + 2*$ButtonWidth + 2*$ButtonSpacerWidth), $ButtonY"
            }


            # Set tooltip based on network or local dongle
            If ($area) {			

                Write-DebugLog "Available license server: $text" 
                $ToolTip.SetToolTip($button, "Run Petrel $Version towards the `"$text`" license server")   
                
            } Else {
 
                Write-DebugLog "Local dongle available" 
                $ToolTip.SetToolTip($button, "Run Petrel $Version towards the local USB dongle")
             
            } #end if server or dongle		
     
            $button.Add_Click({ Invoke-PetrelProcess } )  
            $LicensePick.Controls.Add($button)  
                
        } #End If Server/Dongle        
    
    } #end ForEach licenseserver

    # Update height of license server groupbox
    $LicensePick.Height = $ButtonY + 2*$MarginHeight
    
} #end Function Show-LicenseServers 


Function Invoke-PetrelProcess {
      <#   
    .DESCRIPTION 
        Set profile & license server/process, invoke Petrel process
    .PARAMETER area
        Profile area 
    .PARAMETER server
        License server string
    .EXAMPLE
        Invoke-PetrelProcess -Area EUR -Server 27009@petrel-lic-no.statoil.net
        Run with Europe profile towards license server petrel-lic-no
    #>
    
    # License environment is put into the button's tag as 'area,server'
    $LicenseButton = $This
    $LicenseButtonTag = $LicenseButton.Tag
    
    $Area = $LicenseButtonTag.Split(",")[0]
    $Server = $LicenseButtonTag.Split(",")[1]

    # Network or Dongle license
    If($Area) {

        Set-Profile $area 
        
    } Else {
        
        #Make sure we have a profile.xml file before editing it
        If (!(Test-Path "$AppDataPetrelVersionFolder\profiles.xml")) {
            Set-Profile "GG"
            Write-DebugLog "No default profiles.xml found, copying profiles.xml for GG to allow local edit for dongle"
        }

        Invoke-DongleLicense 
    
    } #end if network or dongle license

    Set-LicenseServer "$server" 
    Start-Petrel

} #end Function Invoke-PetrelProcess


Function Approve-RemoveInstalledPetrel {
    <#   
    .DESCRIPTION 
        Ask user to delete installed Petrel versions, and invoke deletion on yes
    .EXAMPLE
        Approve-RemoveInstalledPetrel
        If installed version exists, get menu asking for removal. 
    #>
   
    # Old executables
    $InstalledPetrel2013 = Test-Path "C:\Program Files\Schlumberger\Petrel 2013\Petrel.exe"  
    $InstalledPetrel2014 = Test-Path "C:\Program Files\Schlumberger\Petrel 2014\Petrel.exe"
    $InstalledPetrel2015 = Test-Path "C:\Program Files\Schlumberger\Petrel 2015\Petrel.exe"

    # Old installations present?
    If($InstalledPetrel2013 -or $InstalledPetrel2014 -or $InstalledPetrel2015) {

        # Only ask once per month
        $QuietDays = 30

        # File for timestamp
        $TimestampFile = ${ENV:PROGRAMDATA} + "\Schlumberger\Petrel\2014\RemovalRequested.txt"

        # Check if asked recently
        If(Test-Path $TimestampFile) {

            $LastWrite = (Get-Item $TimestampFile).LastWriteTime
            $TimeSpan = New-TimeSpan -Days $QuietDays

            If(((Get-Date) - $LastWrite) -lt $TimeSpan) {

                Return $False

            } #end if file is newer than quiet days

         } #end if timestamp file exists

        
        # Ask for removal of old installations
        [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") 
        $DeleteOldPetrel = [System.Windows.Forms.MessageBox]::Show("An old version of Petrel is installed on this machine. Can this be removed?" , "MyPetrel Clean Up" , 4)

        If($DeleteOldPetrel -eq "Yes") {

        # DELETE!
	    Write-DebugLog "Removing old Petrel versions"
            
	    $UninstallPetrel = {
		
		$Sccm = New-Object -ComObject uiresource.uiresourcemgr
		$Sccm.ExecuteProgram("Uninstall", "SCS02BDA", 1)
            
	    }

	    # As background job to avoid delay
	    Start-Job $UninstallPetrel -Name UninstallOldPetrel 
            
        } Else {

            # Update timestamp
	    Write-DebugLog "Delaying deletion of old Petrel versions"
            "" > $TimestampFile

        } #end if ok to delete

    } #end if local installations are present

} #End Function Approve-RemoveInstalledPetrel




Function Get-MyADGroupsRecursive {
   <#
   .SYNOPSIS
     Get all users AD groups recursivly
   .DESCRIPTION
     Get all users AD groups recursivly from AD and returl an array containig the name of all AD groups
   .NOTES
     Version 1.0
   #>

   $ErrorActionPreference = "SilentlyContinue"

   $MyGroups = @()
   ([Security.Principal.WindowsIdentity]::GetCurrent()).Claims | ?{$_.Type -eq "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid"} | %{
      $Group = $Nothing
      $Group = New-Object psobject -Property @{Group = ((New-Object System.Security.Principal.SecurityIdentifier($_.Value)).Translate([System.Security.Principal.NTAccount])).Value}
      $MyGroups += $Group
   }

   Write-DebugLog "Found $($MyGroups.Groups.Count) AD groups the current user $($Env:UserName) is member of"

   Return $MyGroups
} #End Function Get-MyADgroupsRecursive


Function Update-PetrelSearchIndex {
   <#
   .SYNOPSIS
     Create and update %appdata%\schlumberger\petrel\studio\LocalIndexList.config from G:\Prog\Global\Petrel\Program\MyPetrel\StudioIndex\MasterIndexList.config
   .DESCRIPTION
     Read the global index file and compare to local file and update local if needed.
     Will only add to local file
   .PARAMETER
     Name of local index file
   .PARAMETER
     Name of global index file
   .PARANETER
     Array containing all users AD groups
   .NOTES
     Version 1.0
   #>

   param(
      [string] $MasterIndex,
      [string] $LocalIndex,
	  [string[]] $ADR
      )

    # Make sure we have a minimal Index file

       if (!(Test-Path $LocalIndex)) {
          New-Item -ItemType Directory -Force -Path $env:APPDATA\Schlumberger\Petrel\Studio > $null
          Add-Content $LocalIndex "STUDIOINDEXLIST1"
          Add-Content $LocalIndex "file:///$($Env:LOCALAPPDATA.Replace("\","/"))/Schlumberger/Petrel/Studio/Default.index"
       }

    # Check that both master and local index file exsist before doing anything
    # Read both files if they exsis and build a hash table of the user local index file

       If (Test-Path $MasterIndex) {
          $MasterData = Import-Csv $MasterIndex
          if (Test-Path $LocalIndex) {
             $LocalData  = Get-Content $LocalIndex
             $LocalHash = @{}
             $n = 1
             foreach ($item in $LocalData) {
                $LocalHash.Add($item, $n)
                $n++
             }

    # Add data from the master list if they are missing and user have access, remove items if user no longer gave access or is force removed
             $iChange = 0
             $n = 101
			 $k = 0
             foreach ($item in $MasterData.FilePath) {
                if (!$LocalHash.ContainsKey($item) -and $ADR -match $MasterData[$k].AD -and $MasterData[$k].Keep -eq "1") {
                   $LocalHash.add($item, $n)
                   $n++
                   $iChange = 1
                }
                if ($item -ne "STUDIOINDEXLIST1") {
                   if (($LocalHash.ContainsKey($item) -and !($ADR -match $MasterData[$k].AD)) -or $MasterData[$k].Keep -eq "0") {
                      $LocalHash.Remove($item)
                      $iChange = 1
                   }
                }
				$k++
             }

    # Output a new index file in anything has changed
             if ($iChange -eq 1) {
                $LocalOut = @()
                foreach ($key in $LocalHash.Keys) {
                   $LocalOut += $key
                }
                $LocalOut = $LocalOut | Sort-Object -Descending
                Set-content $LocalIndex $LocalOut
             }

          }
       }
} #End Function Update-PetrelSearchIndex

Function Update-PetrelSearchSettings {
   <#
   .SYNOPSIS
     Create and update %appdata%\schlumberger\petrel\studio\LocalSettings.config from G:\Prog\Global\Petrel\Program\MyPetrel\StudioIndex\MasterIndexList.config
   .DESCRIPTION
     Read the global index file and compare to local file and update local settings if needed.
     Will only add to local file
   .PARAMETER
     Name of local settings file
   .PARAMETER
     Name of global index file
   .PARANETER
     Array containing all users AD groups
   .NOTES
     Version 1.0
   #>

   param(
      [string] $MasterIndex,
      [string] $LocalSettings,
	  [string[]] $ADR
      )

    # Read the master index data and create a default local settings file if it's missing
   If (Test-Path $MasterIndex) {
      $MasterData = Import-Csv $MasterIndex

      if (!(Test-Path $LocalSetting)) {
         $def = @{
            DataEnvironementFiles = @()
            DefaultIndexKey = "file:\/\/\/$($Env:LOCALAPPDATA.Replace("\","\/"))\/Schlumberger\/Petrel\/Studio\/Default.index"
            IndexSettings = @(
                               @{
                               IndexKey = "file:\/\/\/$($Env:LOCALAPPDATA.Replace("\","\/"))\/Schlumberger\/Petrel\/Studio\/Default.index"
                               IsEnabled = $True
                              }
                            )
            LocalIndexListFile = "$ENV:AppData\Schlumberger\Petrel\Studio\LocalIndexList.config"
            SelectedConfigFilter = 'All'
         }
         $def1 = $def | ConvertTo-Json -Compress -Depth 10
         Add-Content $LocalSetting $def1
      }

    # Read the user local setting file, convert it from Json and build a hash table of the Index setting part
      $LocalData = Get-Content $LocalSetting -Raw | ConvertFrom-Json

      $LocalHash = @{}
      $n = 0
      foreach ($item in $LocalData.IndexSettings.IndexKey) {
         if ($item) {
            $LocalHash.add($item, $LocalData.IndexSettings[$n].IsEnabled)
            $n++
        }
      }

    # Add data from the master list if they are missing and user have access, remove items if user no longer gave access or is force removed
      $iChange = 0
      $n = 101
	  $k = 0
      foreach ($item in $MasterData.FilePath) {
         if (!$LocalHash.ContainsKey($item) -and $item -ne "STUDIOINDEXLIST1" -and $ADR -match $MasterData[$k].AD -and $MasterData[$k].Keep -eq "1") {
            $LocalHash.add($item, $True)
            $n++
            $iChange = 1
         }
         if ($LocalHash.ContainsKey($item) -and $item -ne "STUDIOINDEXLIST1" -and !($ADR -match $MasterData[$k].AD) -or $MasterData[$k].Keep -eq "0") {
            $LocalHash.Remove($item)
            if ($LocalData.DefaultIndexKey -eq $item) {
               $LocalData.DefaultIndexKey = "file:///G:/Sub_Appl_Data/Petrel/OSL_Europe/Global/public/ref/index/OSL-GLOBAL_PUBLIC/OSL_EUROPE-GLOBAL_PUBLIC.index"
            }
            $iChange = 1
         }
		 $k++
      }
 
    #Write the output if anything has been added or removed
      if ($iChange -eq 1) {
         $LocalData.IndexSettings = @()
         foreach ($key in $LocalHash.Keys) {
            $val = $LocalHash[$key]
            $LocalData.IndexSettings += @(@{'IndexKey' = $key; IsEnabled = $val})
         }
         $ll = $LocalData | ConvertTo-Json -Compress -Depth 10
         Set-Content $LocalSetting $ll
         Write-DebugLog "Updated Petrel Search settings"
      }
   }
} #end Function Update-PetrelSearchSettings

Function Update-PetrelSearch {
   <#
   .SYNOPSIS
     Create and update %appdata%\schlumberger\petrel\Studio\LocalSettings.config and
                       %appdata%\Schlumberger\Petrel\Studio\LocalIndexList.config from 
                       G:\Prog\Global\Petrel\Program\MyPetrel\StudioIndex\MasterIndexList.config
   .DESCRIPTION

   .NOTES
     Version 1.0
   #>

   param(
        )

    $MasterIndex = "G:\Prog\Global\Petrel\Data\Studio\SearchIndex\MasterIndexList.config"
    $LocalIndex  = "$env:APPDATA\Schlumberger\Petrel\Studio\LocalIndexList.config"
    $LocalSetting = "$env:APPDATA\Schlumberger\Petrel\Studio\LocalSettings.config"

	$ADR = Get-MyADGroupsRecursive

    Update-PetrelSearchIndex $MasterIndex $LocalIndex $ADR
    Update-PetrelSearchSettings $MasterIndex $LocalSetting $ADR
} #end Function Update-PetrelSearch

Function Update-Userenvvariables{
    <#
   .SYNOPSIS
        Updates and creates the User Environment variables.
   .DESCRIPTION
        Updates and creates the User Environment variables which are defined in the MyPetrel.ini file.
        This function is called by the start-Mypetrel function.
   .NOTES
     Version 1.0
   #>
    $EnvVariables = $IniSettings["USER_ENV_VARIABLES"]
    foreach($setting in $EnvVariables.GetEnumerator()){
        $VariableName = $setting.name
        $VariableValue = $setting.value
        [Environment]::SetEnvironmentVariable($VariableName, $VariableValue, "User")
    }
}

# -----------------------------------------------------------------------------------------
# Execute
# -----------------------------------------------------------------------------------------

If ($MyInvocation.InvocationName -ne '.') {

    # Called directly
    Write-DebugLog "-----------------"
    Write-DebugLog "Starting MyPetrel"

    #Start progress GUI
    $InitiateMyPetrelGUI = Start-LoadProgressGUI -WindowsTitleText "Loading MyPetrel $WrapperRelease" -WindowsLabelText "Preparing MyPetrel....."

    # Check old installations
    Approve-RemoveInstalledPetrel

    # Start the show
    Start-MyPetrel

} Else {

    "Dot sourced - giving access to the functions:"
    "---------------------------------------------"
    Get-Content $MyInvocation.MyCommand.Name | Where-Object {$_ -like "Function*"} | ForEach-Object {($_.split(" "))[1]} | Sort-Object
}

