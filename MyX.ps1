<#  
.SYNOPSIS  
    General Role Based Application Wrapper
.DESCRIPTION
    This script/app gives access to software based on roles. 
    It reads an ini file containing the applications' environment,
    and dynamically creates the application menu. The applications
    can be run from network or local machine, where environment 
    & prerequisites are automatically installed / set up.
.NOTES  
    File Name  : MyX.ps1 / <whatever>.exe 
    Version    : 1.1.18
    Author     : Marius Gjerde Naalsund - mngj@statoil.com
    Updated by : Leif Erik Betten - leeb@equinor.com
    Updated    : 2025.03.21
#>
Param (
        [string] $IniFile,
        [string] $Mode
    ) 

# -----------------------------------------------------------------------------------------
# Environment
# -----------------------------------------------------------------------------------------

$Script:DoNotStart = ""

# No error message GUI's
$ErrorActionPreference = "SilentlyContinue"

# If run as exe
$ScriptFullPath = [Environment]::GetCommandLineArgs()[0]

# If run as ps1 script
If($ScriptFullPath.EndsWith("powershell.exe")) {
    
    $ScriptFullPath = $MyInvocation.MyCommand.Definition
}

$ScriptBaseFolder = Split-Path -Parent "$ScriptFullPath"
$ScriptName = (Split-Path -Leaf "$ScriptFullPath").Replace(".exe","").Replace(".ps1","")


# Get ?.ini file or create a dummy one
If($IniFile -and (Test-Path $IniFile)) {

    $NetworkIniFile = "$IniFile"
    $Alternate = 1

} ElseIf ($ScriptName -and (Test-Path $("${ScriptBaseFolder}\${ScriptName}.ini"))) {

    $NetworkIniFile = "${ScriptName}.ini"

} Else {

    # TODO - make ini auto-create by GUI!
    # No existing ini-file. Create a template.
    
    "Could not find the Ini file. Exiting"
    write-host "Script full path: $ScriptFullPath"
    write-host "Script base folder: $ScriptBaseFolder"
    write-host "Script name: $ScriptName"
    $NetworkIniFile

    #$NetworkIniFile = "${ScriptBaseFolder}\${ScriptName}.ini"
    #$CreateIniTemplate = 1
    
} #end if Alternate mode using specific ini file    

# Icons folder
$NetworkIconsFolder = "$ScriptBaseFolder\Icons"


# -----------------------------------------------------------------------------------------
# Functions
# -----------------------------------------------------------------------------------------

Function Write-Log {
    <#   
    .DESCRIPTION 
        Append to log file
    .PARAMETER Text
        Text to be appended
    .PARAMETER LogFile
        Logfile to be appended to 
    .EXAMPLE
        Write-Log "Hello World!" "C:\Temp\Temp.log"
    #>
    param (
            [string] $Text,
            [string] $LogFile,
            [string] $Site,
            [string] $ProgramName,
            [string] $Application            
    )
       
    $Now = Get-Date -uFormat %Y.%m.%d-%H:%M:%S
    $User = ($Env:Username).ToLower()
    $Box = ($Env:Computername).ToLower()
    $ADSiteName = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("System\CurrentControlSet\Services\NetLogon\Parameters").GetValue("DynamicSiteName").Split([Char]0)[0]

    $LogString = "$Now;$User;$Box;$ADSiteName;;;$ProgramName;$Application;$Text"

    # Writing to network log files can take time -> run as background job
    If($Logfile.StartsWith("G")) {
    
        Start-Job -ScriptBlock { Add-Content $args[0] -Value $args[1] } -Argumentlist $LogFile,$LogString
    
    } Else { 
    
        Add-Content "$LogFile" -Value "$LogString" 
        
    } # end if logfile is on the network

} #end function write-log


Function Write-UsageLog {
    <#   
    .DESCRIPTION 
        Log all application startups to a global usage file
    .PARAMETER Text
        Text to be appended
    .EXAMPLE
        Write-UsageLog "A started"
    #>
    param (
            [string] $Site,
            [string] $ProgramName,
            [string] $Application,
            [string] $Text
            )

    $LogFromInifile = $NetworkIniFile.Split(".")[0]

    $LogFile = "${IniCentralLogFolder}\${LogFromIniFile}.log"
    Write-Log "$Text" "$LogFile" "$Site" "$ProgramName" "$Application" 
        
} # end Function Write-UsageLog


Function Write-ErrorLog {
    <#   
    .DESCRIPTION 
        Log script errors
    .PARAMETER Text
        Text to be appended
    .EXAMPLE
        Write-ErrorLog "Hello World!" 
    #>
    param (
            [string] $Text
            )

    If($IniCentralLogFolder) {
        $LogFile = "${IniCentralLogFolder}\${ScriptName}Error.log"
        Write-Log "$Text" "$LogFile"
    }
    $LogFile = "$(${Env:Temp})\$($ScriptName)Error.log"
    Write-Log "$Text" "$LogFile"
        
} # end Function Write-ErrorLog


Function Write-DebugLog {
    <#   
    .DESCRIPTION 
        Log debug steps
    .PARAMETER Text
        Text to be appended
    .EXAMPLE
        Write-DebugLog "Hello World!" 
    #>
    param (
            [string] $Text
            )

    $LogFile = "$(${Env:Temp})\$($ScriptName)Debug.log"
    Write-Log "$Text" "$LogFile"
        
} # end Function Write-ErrorLog


Function Get-Location {
    <#   
    .DESCRIPTION 
        Get physical location the machine is running from
        Not 100% guaranteed, as it's using logon server to 
        provide the info
    .OUTPUT
        Site abbreviation
    .EXAMPLE
        Get-Location
    #>
       
    $Env:Logonserver.Replace("\\","").Split("-")[0].ToLower()
        
} # end Function Get-Location


Function Invoke-Offline {
   <#   
    .DESCRIPTION 
        Enable/Disable offline usage by caching exe/ini files + icons, and 
        creating/removing user offline shortcut
    #>

    # Path to local shortcut
    $ShortcutPath = ${Env:Appdata} + "\Microsoft\Windows\Start Menu\Programs\" + $Header + " - Offline.lnk"
    # Offline button
    $OfflineButton = $Window.FindName("ButtonOffline")

    # Enable/disable depending on shortcut presence

    If(!(Test-Path $ShortcutPath)) {

        # Enable offline cache

        # Cache exe file
        Write-DebugLog "Offline cache sync: Executable $ScriptName from $ScriptBaseFolder to $OfflineFolder" 
        Start-Process -WindowStyle Hidden -FilePath robocopy.exe -ArgumentList @("""$ScriptBaseFolder""","""$OfflineFolder""","""${ScriptName}.exe""","/R:1","/W:1") -Wait
    
        # Cache ini file
        Write-DebugLog "Offline cache sync: Inifile $ScriptName from $ScriptBaseFolder to $OfflineFolder" 
        Start-Process -WindowStyle Hidden -FilePath robocopy.exe -ArgumentList @("""$ScriptBaseFolder""","""$OfflineFolder""","""$NetworkIniFile""","/R:1","/W:1") -Wait

        # Cache icons folder
        Write-DebugLog "Offline cache sync: Icons folder from $ScriptBaseFolder to $OfflineFolder" 
        Start-Process -WindowStyle Hidden -FilePath robocopy.exe -ArgumentList @("""${ScriptBaseFolder}/Icons""","""${OfflineFolder}/Icons""","/E","/MT:32","/R:1","/W:1") -Wait

        # Create user shortcut to local executable

        If(!(Test-Path $ShortcutPath)) {

            $LocalExePath = $OfflineFolder + "\${ScriptName}.exe"
            $IconExePath = $ScriptPath.Replace("C:","%systemdrive%")
            $Arguments = "$NetworkIniFile OFFLINE"

            $WshShell = New-Object -ComObject WScript.Shell
            $Shortcut = $WshShell.CreateShortcut($ShortcutPath)
            $Shortcut.TargetPath = $LocalExePath
            $Shortcut.WorkingDirectory = $OfflineFolder
            $Shortcut.Description = "$Header - Offline"
            $Shortcut.Arguments = $Arguments
            $Shortcut.IconLocation = "$IconExePath,0"
            $Shortcut.Save()
        }
    
        # Change icon on top in main window
        $OfflineButton.Content = 'ñ'
        $OfflineButton.Tooltip = "Available offline (using local shortcut). Click to disable this functionality."
    
    } Else {

        # Disable offline cache
        
        # Remove exe file
        Remove-Item "$OfflineFolder/${ScriptName}.exe" | out-null

        # Remove ini file
        Remove-Item "$OfflineFolder/$NetworkIniFile" | out-null

        # Remove icons folder
        Remove-Item "$OfflineFolder/Icons" -Recurse -Force | out-null

        # Remove user shortut to local executable
        Remove-Item $ShortcutPath | out-null

        # Change icon on top in main window
        $OfflineButton.Content = 'ò'
        $OfflineButton.Tooltip = "Click to enable offline functionality. Will create a new shortcut named `"$header - Offline`", to be used offline."

    } #end if enable/disable

} #end function Invoke-Offline


Function Invoke-Access {
    <#   
    .DESCRIPTION 
        Get Access(IT) info from .ini file and redirect to access request
    .EXAMPLE
        Invoke-Access "Petromod" "2017.1"
        Start AccessIT with Petromod as key
    #>
    param ( [string]$ProgramName,
            [string]$Application
            )

    # ProgramName & Application comes either from button or as arguments        
    If($ProgramName -and $Application) {

       # Not implemented 
    
    } Else {

        $ProgramName = $this.Tag.Split("_")[0]
        $Application = $this.Tag.Split("_")[1]
       
    } #end if run from arguments or button

    # Start each [ACCESS_x_y] entry
    $AccessChecks = "ACCESS",
                    "ACCESS_${ProgramName}",
                    "ACCESS_${ProgramName}_${Site}",
                    "ACCESS_${ProgramName}_${Application}",
                    "ACCESS_${ProgramName}_${Application}_${Site}"

    ForEach ($Check in $AccessChecks) {

        If($IniSettings["$Check"]) {
            
            ForEach ($i in ($IniSettings["$Check"].GetEnumerator())) {
            
                $key = $i.Name
                $value = $i.Value
                
                # Browsers need ".." to run the uri's
                If(!($value.StartsWith("'")) -and !($value.StartsWith("`""))) {

                     $value = "`"$value`""

                }
                
                $AccesscheckInPlace = 1
                    
                Write-DebugLog "Start Access request: $key -> $value"
                & Start-Application "$key" "$value" 
                    
            } #end foreach entry
        } #end if not empty
    } #end foreach check

    if(!$AccesscheckInPlace) {

        Write-DebugLog "No access request regime set up for : $ProgramName $Application"
    }

} #end function Invoke-Access


Function Invoke-Application {
    <#   
    .DESCRIPTION 
        Set environment+ from .ini file and start the application
    .EXAMPLE
        Invoke-Application "OpenWorks" "OWLauncher"
        Start OpenWorks default launcher menu
    #>
    param ( [string]$ProgramName,
            [string]$Application
            )
     
    # ProgramName & Application comes either from button or as arguments        
    If($ProgramName -and $Application) {

       # Not implemented 
    
    } Else {

        $ProgramName = $this.Tag.Split("_")[0]
        $Application = $this.Tag.Split("_")[1]
       
    } #end if run from arguments or button

    # Variable to track where we are
    $Script:ButtonClicked = "${ProgramName}_${Application}".replace("`.","").replace("`,","")    

    # Disable the button while setting things up
    #$Button = $Window.FindName("Button_$($Script:ButtonClicked)")
    #$Button.IsEnabled = $False

    # Disable topmost from main window
    $Window.Topmost = $False

    Write-DebugLog "Invoke: $ProgramName - $Application"

    #
    # .INI file
    #

    #
    # Location
    #    
    
    If($SpecificSite) {
    
        $Site = $SpecificSite
        Write-DebugLog "Location set to `"$Site`" (specific)"     
    
    } Else {
    
        [string]$Site = Get-Location
        Write-DebugLog "Location set to `"$Site`" (logon site)"     
    }
    

    #
    # Registry + Environment + License + FileSync + FolderSync
    #
    
    $Settings = "Registry", "Environment", "License", "LocalCache", "FileSync", "FolderSync"

    # No sync in offline mode
    If($Mode -eq "OFFLINE") {

        Write-DebugLog "Offline mode -> No synchronization"
        $Settings = "Registry", "Environment", "License"
    }

    ForEach ($Setting in $Settings) {    

        $Function = "Set-$Setting"

        # Approved settings from ini file
        $Checks =   "${Setting}",
                    "${Setting}_${ProgramName}",
                    "${Setting}_${ProgramName}_${Site}",
                    "${Setting}_${ProgramName}_${Application}",
                    "${Setting}_${ProgramName}_${Application}_${Site}"

        ForEach ($Check in $Checks) {

            If($IniSettings["$Check"]) {
            
                # Need ordered hash. PS3 has [ordered], but that's not available on PS2
                ForEach ($i in ($IniSettings["$Check"].GetEnumerator() | Sort-Object value -descending)) {
            
                    $key = $i.Name
                    $value = $i.Value
                    
                    Write-DebugLog "Set ${Setting}: $key -> $value"
                    # This calls the function Set-Registry, Set-Environment, Set-Foldersync, etc.
                    & "Set-$Setting" "$key" "$value" 
                    
                } #end foreach entry
            } #end if not empty
        } #end foreach check
         
    } #end foreach setting 
 
    #
    # Run 
    #

    # Start the application when all background setup jobs are completed

    $SetupTimer = New-Object System.Windows.Threading.DispatcherTimer       
    $SetupTimer.Interval = [TimeSpan]"0:0:1"
    $SetupTimer.Tag = ($ProgramName,$Application)

    $SetupTimer.Add_Tick({            
               
        $ProgramName = $this.Tag[0]
        $Application = $this.Tag[1]
                    
        $SetupIsRunning = Get-Job -State Running | ? { $_.Name -Like "Setup_*" }
     
        If ($SetupIsRunning) {  
     
            #Write-DebugLog "Background setup jobs still running."   
                        
        } Else {
           
            # Removing the setup jobs
            Get-Job | ? { $_.Name -Like "Setup_*" } | Remove-Job 
            
            # Call the function to delete all other folder versions
            Remove-OtherFolderVersions "$ProgramName" "$Application"

            # Return to the Invoke-Application function            
            Start-PreApplication "$ProgramName" "$Application"

            # Enable the button when all is done
            $Button = $Window.FindName("Button_$($Script:ButtonClicked)")
            $Button.IsEnabled = $True

            # End the timer            
            $This.Stop()
        }

    }) #end setup tick

    #Start timer
    Write-DebugLog "Start verifying background setup jobs are completed"
    $SetupTimer.Start()
    
    Write-DebugLog "All background setup jobs completed"

} #end function Invoke-Application

Function Remove-OtherFolderVersions {
    <#
    .DESCRIPTION
        Deletes all other folder versions except the current one
    #>
    param ( [string]$ProgramName,
            [string]$Application
    )

    # Check if the INI file contains the "DeleteOtherVersions" setting
    If ($IniSettings["Delete"].DeleteOtherVersions -eq "Strict") {

        # Get the current folder version
        $CurrentFolderVersion = $IniSettings["LOCALCACHE_$ProgramName`_$Application"].values

        # Get the parent folder of the current folder version
        $ParentFolder = Split-Path $CurrentFolderVersion -Parent

        # Get the name of the current folder version
        $CurrentFolderName = Split-Path $CurrentFolderVersion -Leaf

        # Get all subfolders of the parent folder that start with the folder name
        $Subfolders = Get-ChildItem -Path $ParentFolder -Directory | Where-Object { $_.Name -like "$ProgramName*" }

        # Loop through the subfolders and delete any folder version that is not the current one
        ForEach ($Subfolder in $Subfolders) {
            If ($Subfolder.Name -ne $CurrentFolderName) {
                Write-DebugLog "Deleting folder $($Subfolder.FullName)"
                Remove-Item -Path $Subfolder.FullName -Recurse -Force
            }
        }
        
    } elseif ($IniSettings["Delete"].DeleteOtherVersions -eq "Active") {
        # Get the current folder version specified in the INI file
        $CurrentFolderVersion = $IniSettings["LOCALCACHE_$ProgramName`_$Application"].values

        # Get the parent folder of the current folder version
        $ParentFolder = Split-Path $CurrentFolderVersion -Parent

        # Get path to all versions of program in ini file
        foreach ($section in $IniSettings.Keys) {
            if ($section -like "LOCALCACHE_$ProgramName`_*") {
                $Path = $IniSettings[$section].values
                $FolderPathInIni += $Path
            }
        }

        # Get all subfolders of the parent folder that start with the folder name
        $Subfolders = Get-ChildItem -Path $ParentFolder -Directory | Where-Object { $_.Name -like "$ProgramName*" }

        # Loop through the subfolders and delete any folder version that is not the current one specified in the INI file
        ForEach ($Subfolder in $Subfolders) {
            If ($Subfolder.FullName -notin $FolderPathInIni) {
                Write-DebugLog "Deleting folder $($Subfolder.FullName)"
                Remove-Item -Path $Subfolder.FullName -Recurse -Force
            }
        }
    } Else {
        
        Write-DebugLog "DeleteOtherVersions setting is not set or not set correctly in the INI file. Skipping folder deletion."
        
    }

} #end function Delete-OtherFolderVersions

Function Start-PreApplication {

    param ( [string]$ProgramName,
            [string]$Application
    )

    $Check = "LAUNCH_${ProgramName}_${Application}"

    Foreach ($key in $IniSettings["$Check"].Keys) {

       [string]$Command = $key
       [string]$Arguments = $IniSettings["$Check"].Item($key).Split(",")[0]
       [string]$WorkingDirectory = $IniSettings["$Check"].Item($key).Split(",")[1]

       # TODO - Several commands support

        $Xname = "${ProgramName}_${Application}".replace("`.","").replace("`,","") ; 
        $Button = $Window.FindName("Button_$Xname");  
        $OnMouseOverLayer = $Window.FindName("OnMouseOver_$Xname")
        $RunningLayer = $Window.FindName("Running_$Xname")

       If ($Command) {
        
        # Wait for the Setup_LocalCache job to finish
        Wait-Job -Name "Setup_LocalCache"

        # Only start the application if the local cache is identical to the G drive
        if($DoNotStart -ne "true"){     
        $Proc = Start-Application "$Command" "$Arguments" "$WorkingDirectory"
        }                 
        
        # Write to central log folder
        If($IniCentralLogFolder) {
            
            Write-UsageLog "$Site" "$ProgramName" "$Application" "$Command $Arguments"
        }      
 
        # Close GUI if closure flag is set on the application
        If($TerminateGUI) {

            Write-DebugLog "Close the GUI due to closure flag set on $ProgramName $Application"
            Close-Form
        }
              

        # Background job to check app process status                        
        $MyRunningApp = {
            
            param( $ProcID )
                    
            While (Get-Process -Id $ProcID) {
              
                Start-Sleep 1                     
                
            } #end while        
        } #end myrunningapp
            
        $Running = Get-Job -Name $Xname -ErrorAction SilentlyContinue
            
        # Only monitor one job (in case of several run commands)
        # Unordered hash => random job monitored
        # TODO: Possible with process tree / child processes / etc ?
        If(!$Running) {
            Start-Job $MyRunningApp -Name $Xname -ArgumentList ($($Proc.Id))
        }
         
        $Running = Get-Job -Name $Xname -ErrorAction SilentlyContinue
            
        # Show in GUI if running
        If($Running ) {
     
            $ProcessID = $Proc.Id
                
            $MyTimer = new-object System.Windows.Threading.DispatcherTimer
               
            $MyTimer.Interval = [TimeSpan]"0:0:1"
            $MyTimer.Tag = ($Xname,$ProcessID,$Button)

            #Add event per tick       
            $MyTimer.Add_Tick({
                
                # Parallell Threading
                $Xname = $this.Tag[0]
                $ProcessID = $this.Tag[1]  
                $Button = $this.Tag[2] 

                $Button.background = "$ButtonRunningColor"

                $OnMouseOverLabel = $Window.FindName("OnMouseOver_$Xname")
                    
                $RunningLabel = $Window.FindName("Running_$Xname")
                $RunningLabel.Visibility = "Visible"
                $RunningLabel.Opacity = "0.3"
                    
                $Running = Get-Job -Name $Xname -ErrorAction SilentlyContinue
     
                If ($($Running.State) -eq "Running") {  
                        
                    # GUI trick - Moving text
                    # TODO - memory leak
                    Switch ($($RunningLabel.Content)) {
                        
                        "8      " { $RunningLabel.Content = " 8     "; Break }
                        " 8     " { $RunningLabel.Content = "  8    "; Break }
                        "  8    " { $RunningLabel.Content = "   8   "; Break }
                        "   8   " { $RunningLabel.Content = "    8  "; Break }
                        "    8  " { $RunningLabel.Content = "     8 "; Break }
                        "     8 " { $RunningLabel.Content = "      8"; Break }
                        default { $RunningLabel.Content = "8      " }  
                    }        
                        
                } Else {
    
                    $RunningLabel.Visibility = "Hidden"                       
                    $Button.Background = "$ButtonBackgroundColor"
                        
                    # Clean up (to be able to see running state more than once)
                    Remove-Job -Name $Xname                
                        
                    $This.Stop()
                }
                    
                [Windows.Input.InputEventHandler]{ $Window.UpdateLayout() }   
            })

            #Start timer
            $MyTimer.Start()
    
        } Else {
        
            $Button.background = "Red"
            $RunningLayer.Content = "r"
            $RunningLayer.Visibility = "Visible"
            $RunningLayer.Toolbox = "Problem running application - $Command $Arguments"
                
            Write-ErrorLog "Problem running application - $Command $Arguments"
            
        } #end if running
     } #end if command
    } #end foreach


} #end Function Start-PreApplication


Function Install-SccmApplication {
   <#   
    .DESCRIPTION 
        NOT USED. Install Petrel requirements from SCCM (Statoil applications)
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

} #end Function Install-SccmApplication


Function Get-MyADGroups {
    <#   
    .DESCRIPTION 
        Get my AD groups
    .EXAMPLE
        Get-MyADGroups
    #>
    #([ADSISEARCHER]"samaccountname=$($env:USERNAME)").Findone().Properties.memberof -replace '^CN=([^,]+).+$','$1'
    (New-Object ADSISearcher([ADSI]"LDAP://statoil.net","(samaccountname=$($env:USERNAME))")).Findone().Properties.memberof -replace '^CN=([^,]+).+$','$1'

} #end Function Get-MyADGroups


Function Get-MyWrapperApplications {
    <#   
    .DESCRIPTION 
        Get available applications based on who I am
    .OUTPUT
        2 dimensional array of available applications / no access applications
    .EXAMPLE
        Get-MyWrapperApplications
    #>
    param ([switch] $AlternateMode)

    $MyGroups = Get-MyADGroups
    
    $MyWrapperApplications = @()
    
    # Add any user specific application arguments
    <#
    # NOT CURRENTLY USED
    If($ProductName -and $ApplicationName) {
    
        If(($IniSettings["APPLICATIONS"].values) -like "*$($ProductName)*") {
        
            write-debuglog "Application X: $ProductName (Specified directly)"
            $MyWrapperApplications += , ("$ProductName","$ApplicationName","$ProductName # on the fly","")
            
        } #end if specified program is defined in ini file
    } #end if specified program is set
    #>

    # Filter ini file apps through the user's AD groups
    ForEach($Application in ($IniSettings["APPLICATIONS"].GetEnumerator() | Sort-Object @{e={$_.Name -as [int]}})) {
    
        $prog = $Application.Value.Split(",")[0].Trim()
        $appname = $Application.Value.Split(",")[1].Trim()
        $humanname = $Application.Value.Split(",")[2].Trim()
        
        If(!($Mode -eq "OFFLINE")) {

            # AD access group(s)
            If($Application.Value.Split(",")[3]) {
        
                [array]$adgroups = $Application.Value.Split(",")[3].Split(";") #.Trim()
        
            } #end if access for several AD groups

            <#
            Auto-start of application (w/wo close+GUI)
                0 / nothing = normal
                1 = normal start + close GUI
                2 = auto-start w/GUI
                3 = auto-start + close GUI
                4 = auto-start without GUI
            #>
            If($Application.Value.Split(",")[4]) {
        
                $autostart = [int]($Application.Value.Split(",")[4])
        
            } else {
        
                $autostart = 0
        
            }#end if access for several AD groups

            $Access = 0

            # Loop through the application group(s) to see if the user has access to any of them
            ForEach ($adgroup in $adgroups) {

                $adgroup = $adgroup.Trim()

                If($MyGroups -like "$($adgroup)*"){
        
                    $Access = 1
                    Break
                } 
            } #end foreach ad group

        } Else {

            $Access = 0

            $tst = $(($IniSettings["LOCALCACHE_${prog}_${appname}"]).Values)
            write-debuglog "testing $tst - $prog - $appname"

            If(Test-Path $(($IniSettings["LOCALCACHE_${prog}_${appname}"]).Values)) {
                
                

                $Access = 1
            } 

        } #end if on network or offline

        # Set the application in launch or 'apply for access' mode
        If($Access) {

            write-debuglog "Application $($Application.Name): $humanname [Access ok]"
            # Flag 1 = Access
            $MyWrapperApplications += , ("$prog","$appname","$humanname",1,$autostart)

        } Else {

            write-debuglog "Application $($Application.Name): $humanname [No Access]"
            # Flag 0 = No access
            $MyWrapperApplications += , ("$prog","$appname","$humanname",0,0)

        } #end if access or not
        
    }

    $MyWrapperApplications
    
} #end Function Get-MyPetrelVersions


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
        switch -regex -file $FilePath  
        {  
            "^\[(.+)\]$" # Section  
            {  
                $section = $matches[1]  
                $ini[$section] = @{}  
                $CommentCount = 0  
            }  
            "^(#.*)$" # Comment  
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

} #end Function Get-IniContent 


Function Set-License {
	param ( 
		[string]$Variable,
		[string]$Value        
	)
    
    Set-Environment "$Variable" "$Value"
    
} #end function Set-License


Function Set-Environment {
	param ( 
		[string]$Variable,
		[string]$Text
	)

    # Text is "value[, 1]"
    $Value = $Text.Split(",")[0]
    [int]$Persistent = $Text.Split(",")[1]

	# Expanding (in case of %...%)
    $Variable = [System.Environment]::ExpandEnvironmentVariables("$Variable")
	$Value = [System.Environment]::ExpandEnvironmentVariables("$Value")
	
    # Process variable
	[Environment]::SetEnvironmentVariable("$Variable", "$Value", "Process")

    # Persistent user variable
    If($Persistent) {

        [Environment]::SetEnvironmentVariable("$Variable", "$Value", "User")

    } #end if set as user variable 

} #end function Set-Environment


Function Set-Registry {
	param ( 
		[Parameter(Mandatory=$true)][string]$Key,
		[Parameter(Mandatory=$true)][string]$Value
	)

	# Expanding (in case of %...%)
    $Key = [System.Environment]::ExpandEnvironmentVariables("$Key")
    $Key = $Key.Replace("HKEY_CURRENT_USER","HKCU:")
	$RegistryValue = [System.Environment]::ExpandEnvironmentVariables("$Value")
	
    # Key is either (default) or Name = x
    # If Key ends with \ it will be set (default)

    $SplitKey = $Key.Split("\")
    
    #PS3 only#[string]$RegistryPath = Join-String ($SplitKey[0..($SplitKey.count-2)]) -Separator "\"
    [string]$RegistryPath = ($SplitKey[0..($SplitKey.count-2)]) -Join "\"
    [string]$Name = $SplitKey[-1]
	
    If(Get-ItemProperty -path "$RegistryPath" -name "$Name") {
    
        Set-Itemproperty  -Path "$RegistryPath" -Name "$Name" -Value "$RegistryValue" | out-null
        
    } Else {
    
	# Create key recursively if not already existing
	If(!(Get-Item -Path "$RegistryPath")) {

		New-Item -Path "$RegistryPath" -Force | out-null

	} #end if key does not exist

        New-Itemproperty  -Path "$RegistryPath" -Name "$Name" -Value "$RegistryValue" -PropertyType String | out-null
    
    } #end if key exists or not 
    
} #end Function Set-Registry


Function Set-LocalCache {
	param ( 
		[String]$Source,
		[String]$Destination
	)

    
    #Get flags
    If($Destination.Contains(",")) {
        $RobocopyPurgeFlag = $Destination.Split(",")[1].Trim()
        $Destination = $Destination.Split(",")[0].Trim()
    }   

    $Source = ([System.Environment]::ExpandEnvironmentVariables("$source")).TrimEnd("\")
    $Destination = ([System.Environment]::ExpandEnvironmentVariables("$destination")).TrimEnd("\")
 
    Write-DebugLog "Cache base folder from $Source set to $Destination"
    
    # Get difference as file count

    $OSFullVersion = (Get-CimInstance Win32_OperatingSystem).Version
    [int]$OSMajorVersion = $OSFullVersion.Split(".")[0]

    Write-DebugLog "OS Version: $OSFullVersion"

    # Dry run (only) if local cache exists
    If(Test-Path $Destination) {

        Write-DebugLog "Start dry run (as background job)"
        if (test-path "$env:TEMP\DryRobocopy.log") {
            remove-item -Force "$env:TEMP\DryRobocopy.log"
        }
        $DryRunJob = Start-Job -name Setup_DryRunLocalCache -Scriptblock { Param($Source,$Destination); Robocopy "$Source" "$Destination" /L /MT:32 /E /FFT /NP /NDL /NC /BYTES /NJH /NJS /W:1 /R:1 /LOG+:$env:TEMP\DryRobocopy.log} -ArgumentList $Source,$Destination

    } #end if local cache exists

    $DryRunTimer = new-object System.Windows.Threading.DispatcherTimer       
    $DryRunTimer.Interval = [TimeSpan]"0:0:1"
    $DryRunTimer.Tag = ($ButtonClicked, $Source, $Destination,$RobocopyPurgeFlag)

    $DryRunTimer.Add_Tick({            
               
        $Xname = $this.Tag[0]
        $Source = $this.Tag[1]
        $Destination = $this.Tag[2]
        $RobocopyPurgeFlag = $this.Tag[3]
        
        # Find the relevant button label
        $DryRunButton = $Window.FindName("Button_$Xname")

        $Running = Get-Job -Name "Setup_DryRunLocalCache" -ErrorAction SilentlyContinue

        If (($($Running.State) -eq "Running") -or ($($Running.State) -eq "NotStarted")) {              

            # Wait for the dryrun to finish
            Write-DebugLog "Dry run in progress (State: $($Running.State))"
                        
        } Else {
   
            $FilesTotal = (Get-Content "$env:TEMP\DryRobocopy.log" | Measure-Object –Line).Lines

            # Set button back to original angle
            $DryRunButton.RenderTransform = New-Object System.Windows.Media.RotateTransform -ArgumentList 0,0,0        
            [Windows.Input.InputEventHandler]{ $Window.UpdateLayout() }  
 
            # Clean up (to be able to see running state more than once)
            Remove-Job -Name "Setup_DryRunLocalCache"               
            
            # Dry run shows missing files, or sometimes give false positive on empty destination
            If(($FilesTotal -gt 0) -or !(Test-Path $Destination)) {

                $OnMouseOverLabel = $Window.FindName("OnMouseOver_$ButtonClicked")
                $RunningLabel = $Window.FindName("Running_$ButtonClicked")
                $RunningLabel.Visibility = "Hidden"
                $CachingLabel = $Window.FindName("Caching_$ButtonClicked")
                $CachingLabel.Visibility = "Visible"
                [Windows.Input.InputEventHandler]{ $Window.UpdateLayout() } 

                If(!(Test-Path $Destination)) {

                    # Get number of files to synchronize (for visualizing progress)
                    $FilesTotal = (Get-ChildItem $Source -Recurse -File).Count
                    Write-DebugLog "Local cache not existing ($FilesTotal files)"

                } Else {

                    Write-DebugLog "Dry run complete. Local cache not in sync ($FilesTotal files)"

                } #if local cache exists or not

                # Start local cache process
                Copy-WithProgress -Source "$Source" -Destination "$Destination" -FilesTotal $FilesTotal -Flag $RobocopyPurgeFlag
            
            } Else {
            
                Write-DebugLog "Dry run complete. Local cache all good ($FilesTotal)."

            }#end if cache needs update 
                        
            $This.Stop()
        
        } #end if background cache job is running

    }) #end cache tick setup

    # Start monitoring the cache progress
    $DryRunTimer.Start() 


} #end function Set-LocalCache


Function Copy-WithProgress {
    <#   
    .SYNOPSIS
        Running parallel file copy while keeping track of progress
    .DESCRIPTION 
        The function first performs a dry run to get number / total size of files.
        Then, actual copying is started - keeping track of progress by 
        monitoring the log file
    .OUTPUT
        Elapsed copy time in seconds 
     .EXAMPLE
        Copy-WithProgress c:\temp\temp c:\appl\cache\example
    #>
    [CmdletBinding()]
    param (
            [Parameter(Mandatory = $true)]
            [string]$Source,
            [Parameter(Mandatory = $true)]
            [string]$Destination,
            [int]$FilesTotal,
            [string]$Flag
    ) 
    $Script:Count = 1
    #Resolve variables
    $Source = [System.Environment]::ExpandEnvironmentVariables("$Source")
    $Destination = [System.Environment]::ExpandEnvironmentVariables("$Destination")

    If ($Flag -eq 1) {
        $RobocopyArgument = "/PURGE"
        Write-DebugLog "  Enabling cache job with /Purge option"
    }

    # Robocopy cache job
    Write-DebugLog "Start cache job (as background job)"
    $Script:DoNotStart = ""
    # Do a check if the user har write access to the robocopy logfile
    if (test-path "$env:TEMP\Robocopy.log") {
        Try { [io.file]::OpenWrite("$env:TEMP\Robocopy.log").close() }
        Catch { $Script:DoNotStart = "True" 
            Write-DebugLog "No write access to $env:TEMP\Robocopy.log"
        }
        Remove-Item -Force "$env:TEMP\Robocopy.log"
    }

    $job = Start-Job -name Setup_LocalCache -Scriptblock { 
        Param($Source,$Destination,$Flag)
        $output = Robocopy @("$Source","$Destination","/MT:32","/E",$Flag,"/MIR","/R:1","/W:1","/NJH","/NJS","/tee","/LOG+:$env:TEMP\Robocopy.log")
        $output
    } -ArgumentList $Source,$Destination,$RobocopyArgument
    
    # Show slider in tile while caching
    $CacheTimer = new-object System.Windows.Threading.DispatcherTimer       
    $CacheTimer.Interval = [TimeSpan]"0:0:1"
    $CacheTimer.Tag = ($ButtonClicked,$FilesTotal)

    $CacheTimer.Add_Tick({            
        $Xname = $this.Tag[0]
        $FilesTotal = $this.Tag[1] 
        # Find the relevant button label
        $CachingLabel = $Window.FindName("Caching_$Xname")
        # Only 1 local cache background job             
        $Running = Get-Job -Name "Setup_LocalCache" -ErrorAction SilentlyContinue
        # Dummy counter for graphical trick
        $Script:Count++
        If ($($Running.State) -eq "Running") {  
            # Get counter from the background job output cache
            $FilesCopied = ($Running | Receive-Job -Keep | ? { !($_.Startswith("100%")) }).Count
            $PercentageCopied = "{0:N0}" -f (100 * $FilesCopied / $FilesTotal)                              
            # Graphic trick to 'show progress' as robocopy writes in bulk     
            If($PercentageCopied -le 20) {
                if($Script:Count -lt 20) {
                    $PercentageCopied = $Script:Count
                    Start-Sleep -Seconds 3
                    } Else {
                    $PercentageCopied = 19
                    }
            } Else {
                Write-DebugLog "Local cache at ${PercentageCopied}%"   
            }  
            # Label shrinks from tilewidth to 0 (like removing a layer)
            $CachingLabel.Width = $TileWidth * (100 - $PercentageCopied) / 100
            [Windows.Input.InputEventHandler]{ $Window.UpdateLayout() }     
        } Else {
            # Hide the button cache layer
            $CachingLabel.Visibility = "Hidden"   
            [Windows.Input.InputEventHandler]{ $Window.UpdateLayout() }  
            
            # Check log file for errors
            try {
                $log = Get-Content "$env:TEMP\Robocopy.log" -ErrorAction Stop
                if ($log | Select-String -Pattern "ERROR: RETRY LIMIT EXCEEDED.") {
                    Write-DebugLog "Error occurred during sync, see $env:TEMP\Robocopy.log for more info"
                    $Script:DoNotStart = "True"
                    [System.Windows.Forms.MessageBox]::Show("Not able to copy all files, will not be able to start Techlog")
                }
                else {
                    Write-DebugLog "Local cache at 100%"
                }
            } catch {
                Write-Warning "Error reading log file: $_"
            }
            $This.Stop()
        } #end if background cache job is running
    }) #end cache tick setup

    # Start monitoring the cache progress
    $CacheTimer.Start()

} #end function Copy-WithProgress

Function Set-FileSync {
	param ( 
		[System.IO.FileInfo]$Source,
		[String]$Destination
	)

    # Destination can contain flags 
    #
    # Flag = 1 -> Don't copy if the file exists
    # 

    If($Destination.Contains(",")) {

        $Flag = $Destination.Split(",")[1].Trim()
        $Destination = $Destination.Split(",")[0].Trim()

    }

    $Source = [System.Environment]::ExpandEnvironmentVariables("$Source")
    $Destination = [System.Environment]::ExpandEnvironmentVariables("$Destination").TrimEnd('\')

    $SourcePath = $Source.DirectoryName
    $SourceFile = $Source.Name
    
    If(($Flag -eq 1) -and (Test-Path ${Destination}\${SourceFile})) {

        Write-DebugLog "File $SourceFile from $SourcePath already exists as $Destination (No-overwrite flag set ($Flag))"

    } Else {

        Write-DebugLog "Sync file $SourceFile from $SourcePath to $Destination" 
        Start-Process -WindowStyle Hidden -FilePath RoboCopy.exe -ArgumentList @("""$SourcePath""","""$Destination""","""$SourceFile""","/R:1","/W:1") -Wait
    
    } #end if file should be copied

} #end function Set-FileSync

Function Set-FolderSync {
	param ( 
		[String]$Source,
		[String]$Destination
	)

    #Get Flags
    If($Destination.Contains(",")) {
        $Flag = $Destination.Split(",")[1].Trim()
        $Destination = $Destination.Split(",")[0].Trim()
    }
   
    $Source = [System.Environment]::ExpandEnvironmentVariables("$Source")
    $Destination = [System.Environment]::ExpandEnvironmentVariables("$Destination")
 
    #Perform sync
    Write-DebugLog "Sync folder $Source to $Destination"
    If ($Flag -eq 1) {
        Write-DebugLog "Syncing with /Purge option"
        Start-Process -WindowStyle Hidden -FilePath RoboCopy.exe -ArgumentList @("""$Source""","""$Destination""","/E","/PURGE","/MT:32","/R:1","/W:1") -Wait
        
    }
    Else {
        Start-Process -WindowStyle Hidden -FilePath RoboCopy.exe -ArgumentList @("""$Source""","""$Destination""","/E","/MT:32","/R:1","/W:1") -Wait
    }

   
} #End Function Set-FolderSync

Function Start-Application {
	param ( 
		[string]$Command,
		[string]$Arguments,
        [string]$WorkingDirectory
	)

    $Command = [System.Environment]::ExpandEnvironmentVariables("$Command")
    $Arguments = [System.Environment]::ExpandEnvironmentVariables("$Arguments")
    $WorkingDirectory = [System.Environment]::ExpandEnvironmentVariables("$WorkingDirectory")

    If(!$WorkingDirectory) {

        Try {
    	   $WorkingDirectory = ([system.io.fileinfo]$Command).directoryname 
        } Catch { 
            Write-DebugLog "Error: Can not find start directory for $Command $Arguments" 
        }     
    } #end if specific workingdiretory is not set

    # No arguments -> hidden window
    # Dummy arguments ('') -> normal window
    If($Script:DoNotStart -ne "True"){
        IF($Arguments) {
    
            If($Arguments -eq "''") {
        
                Write-DebugLog "Starting $Command from folder $WorkingDirectory [windowsstyle normal]"
                $Proc = Start-Process -FilePath $Command -WorkingDirectory $WorkingDirectory -PassThru
        
            } Else {
        
                Write-DebugLog "Starting $Command $Arguments from folder $WorkingDirectory"
                $Proc = Start-Process -FilePath $Command -Argumentlist $Arguments -WorkingDirectory $WorkingDirectory -PassThru 
        
            } #end if dummy arguments
    
        } Else {
        
            Write-DebugLog "Starting $Command from folder $WorkingDirectory [windowsstyle hidden]"
            $Proc = Start-Process -FilePath $Command -WorkingDirectory $WorkingDirectory -WindowStyle Hidden -PassThru
    
        } # end if arguments
    }
    # Return process object
    $Proc

} #end Function Start-Application


Function Close-Form {
          
    $Window.WindowState = 'Minimized'
    #$Window.ShowInTaskbar = 'False'

    # Bug in PS2 -> Can't exit before all background SCCM jobs are finished
    #$jobs = (get-job -Name SCCMjob,SCCM_Background,Setup_DryRunLocalCache,Setup_LocalCache -state running | Measure-Object).count 
	$Jobs = (Get-Job -State Running | Measure-Object).count 	

    If($Jobs) {
        
		Write-DebugLog "Running jobs - only hiding the GUI" 

        While($Jobs) {    
            	
    		Start-Sleep -Seconds 5
            $jobs = (Get-Job -State Running | Measure-Object).count 
            
        } #end while jobs are running
    } #end if jobs

    #Also cleanup runspaces
    If ($Global:MyRunSpaces.Status) {
        Write-DebugLog "Found Runspaces, make sure they are finished before we terminate"

        While ($Global:MyRunSpaces.Status -ne $null) {
            $Completed = $Global:MyRunSpaces | ?{$_.Status.IsCompleted -eq $True}
            ForEach ($RunSpace in $Completed) {
                $RunSpace.Pipe.EndInvoke($RunSpace.Status)
                $RunSpace.Status = $Null
            }
        }

        #Cleanup RunspacePool objects
        $RunSpacePool.Close()
        $RunSpacePool.Dispose()
    }

    Write-DebugLog "Closing ${ScriptName}.exe"
    Start-Sleep 2
    
    Get-Process "$ScriptName" | Stop-Process  

} #End Function Close-Form


Function Show-MyWrapper {

    Add-Type -assemblyName PresentationFramework   

    # Create a template .INI file if it doesn't exist
    If($CreateIniTemplate) {
        Set-IniTemplate "$NetworkIniFile"
    }
    
    # Read the .INI file
    $IniSettings = Get-IniContent "$($NetworkIniFile)"

    $GetMyWrapperApplications = Get-MyWrapperApplications
   
    If($GetMyWrapperApplications) {

        If($GetMyWrapperApplications[0].Count -gt 1) {
    
            # Array - two or more applications
            $MyWrapperApplications = $GetMyWrapperApplications
    
        } Else {
    
            # String - only one application
            $MyWrapperApplications = , ($GetMyWrapperApplications)
        } 
        
    } Else {
    
        # No Applications available -> No buttons

    } #end if there are 0, 1 or several applications

    [int]$IniColumns = $IniSettings["CUSTOMIZATION"]["Columns"]
    If($IniColumns -gt 0) {
        $Columns = $IniColumns
    } Else {
        $Columns = 3
    }
    
    # Default Window width depends on number of columns
    
    # Where is Powershell's ternary operator??

    $IniTitle = $IniSettings["CUSTOMIZATION"]["Title"]
    If($IniTitle ) { $Title = $IniTitle } 
    Else { $Title = "Title" }
    
    $IniHeader = $IniSettings["CUSTOMIZATION"]["Header"]
    If($IniHeader ) { $Header = $IniHeader } 
    Else { $Header = "Header" }

    $IniStatus = $IniSettings["CUSTOMIZATION"]["Status"]
    If($MyWrapperApplications) {
        If($IniStatus) { $Status = $IniStatus } 
        Else { $Status = "" }
    } Else { $Status = "No applications available. Please apply to get access." }
    
    $IniCentralLogFolder = $IniSettings["CUSTOMIZATION"]["CentralLogFolder"]

    $OfflineFolder = $IniSettings["CUSTOMIZATION"]["OfflineFolder"]
    
    $IniCompact = $IniSettings["CUSTOMIZATION"]["Compact"]
        
    $IniInfoText = $IniSettings["CUSTOMIZATION"]["InfoText"]
    If($IniInfoText ) { $InfoText = $IniInfoText } 
    Else { $InfoText = "" }
    
    $IniBackgroundColor = $IniSettings["CUSTOMIZATION"]["BackgroundColor"]
    If($IniBackgroundColor ) { $BackgroundColor = $IniBackgroundColor } 
    Else { $BackgroundColor = "#85c1f5" }
 
    $IniButtonBackgroundColor = $IniSettings["CUSTOMIZATION"]["ButtonBackgroundColor"]
    If($IniButtonBackgroundColor ) { $ButtonBackgroundColor = $IniButtonBackgroundColor } 
    Else { $ButtonBackgroundColor = "#4b98dc" }

    $IniButtonRunningColor = $IniSettings["CUSTOMIZATION"]["ButtonRunningColor"]
    If($IniButtonRunningColor ) { $ButtonRunningColor = $IniButtonRunningColor } 
    Else { $ButtonRunningColor = "Green" }

    $IniTextColor = $IniSettings["CUSTOMIZATION"]["TextColor"]
    If($IniTextColor ) { $TextColor = $IniTextColor } 
    Else { $TextColor = "White" }

    $IniButtonTextColor = $IniSettings["CUSTOMIZATION"]["ButtonTextColor"]
    If($IniButtonTextColor ) { $ButtonTextColor = $IniButtonTextColor } 
    Else { $ButtonTextColor = "White" }
 
    $IniOpacity = $IniSettings["CUSTOMIZATION"]["Opacity"]
    If($IniOpacity ) { $Opacity = $IniOpacity } 
    Else { $Opacity = "1.0" }
 
    # GUI environment
    
    $TileWidth = 150
    $TileHeight = 70
    $TileMargin = 5

    $SideMargin = $TileWidth / 3
    $HeaderHeight = $TileHeight * 1.2

    $HeaderWidth = $Columns * ($TileWidth + (2 * $TileMargin))
    $WindowWidth = $HeaderWidth + (4 * $TileMargin) + (2 * $SideMargin) 

    #Build the GUI
    [xml]$xaml = @"
    <Window 
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="$Title" 
    Width="$WindowWidth" 
    SizeToContent="Height" 
    AllowsTransparency="True" 
    Opacity="$Opacity"
    WindowStyle="None" 
    BorderThickness="5" 
    ResizeMode="CanResizeWithGrip"    
    ShowActivated="True">
    

    <Window.Resources>
        <Style x:Key="ButtonDefault" TargetType="Button">
            <Setter Property="Background" Value="$ButtonBackgroundColor" />
            <Setter Property="Foreground" Value="$ButtonTextColor" />
            <Setter Property="Height" Value="$TileHeight" />
            <Setter Property="Width" Value="$TileWidth" />
            <Setter Property="Margin" Value="$TileMargin" />
            <Setter Property="Opacity" Value="0.8" />
            <Setter Property="Cursor" Value="Hand" />
            <Setter Property="RenderTransformOrigin" Value="0.5,0.5" />
            <Setter Property="RenderTransform">
                <Setter.Value>
                    <RotateTransform />
                </Setter.Value>
            </Setter>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="{x:Type Button}">
                        <Border Background="{TemplateBinding Background}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>         
            <Style.Triggers>
                <EventTrigger RoutedEvent="Button.Click">
                    <BeginStoryboard>
                        <Storyboard TargetProperty="RenderTransform.Angle">
                            <DoubleAnimation 
                                From="-5" To="5" Duration="0:0:0.05" 
                                AutoReverse="True"
                                RepeatBehavior="3x"
                                FillBehavior="Stop" />
                        </Storyboard>
                        
                    </BeginStoryboard>
                </EventTrigger>               
            </Style.Triggers>          
        </Style>  
             
        <Style x:Key="ButtonPrerequisite" BasedOn="{StaticResource ButtonDefault}" TargetType="Button">
            <Setter Property="Opacity" Value="0.3" />
        </Style>

        <Style x:Key="ButtonNoAccess" BasedOn="{StaticResource ButtonDefault}" TargetType="Button">
            <Setter Property="Opacity" Value="0.3" />
        </Style>

        <Style x:Key="OnMouseOver_TextBlock" TargetType="Label">

            <Setter Property="Background" Value="$ButtonRunningColor" />
            <Setter Property="Foreground" Value="$ButtonTextColor" />
            <Setter Property="Height" Value="$TileHeight" />
            <Setter Property="Width" Value="$TileWidth" />
            <Setter Property="Opacity" Value="0.6" />
            <Setter Property="HorizontalContentAlignment" Value="Center" />
            <Setter Property="VerticalContentAlignment" Value="Center" />
            <Setter Property="FontSize" Value="48" />
            <Setter Property="FontFamily" Value="Webdings" />
            <Setter Property='Visibility' Value='Hidden' />
            
            <Style.Triggers>
                <DataTrigger Binding='{Binding RelativeSource={RelativeSource Mode=FindAncestor,AncestorType={x:Type Button}},Path=IsMouseOver}' Value='True'>
                    <Setter Property='Visibility' Value='Visible' />
                </DataTrigger>
            </Style.Triggers>  

        </Style> 
        
        <Style x:Key="Running_Label" TargetType="Label">
        
            <Setter Property="Background" Value="$ButtonBackgroundColor" />
            <Setter Property="Foreground" Value="$ButtonTextColor" />
            <Setter Property="Height" Value="$TileHeight" />
            <Setter Property="Width" Value="$TileWidth" />
            <Setter Property="Opacity" Value="0.9" />
            <Setter Property="HorizontalContentAlignment" Value="Center" />
            <Setter Property="VerticalContentAlignment" Value="Center" />
            <Setter Property="FontSize" Value="48" />
            <Setter Property="FontFamily" Value="Webdings" />
            <Setter Property='Visibility' Value='Hidden' />
        
        </Style> 
 
         <Style x:Key="Caching_Label" TargetType="Label">
        
            <Setter Property="Background" Value="$ButtonRunningColor" />
            <Setter Property="Foreground" Value="$ButtonTextColor" />
            <Setter Property="Height" Value="$TileHeight" />
            <Setter Property="Width" Value="10" />
            <Setter Property="Opacity" Value="0.9" />
            <Setter Property="HorizontalAlignment" Value="Right" />
            <Setter Property="HorizontalContentAlignment" Value="Center" />
            <Setter Property="VerticalContentAlignment" Value="Center" />
            <Setter Property="FontSize" Value="48" />
            <Setter Property="FontFamily" Value="Webdings" />
            <Setter Property='Visibility' Value='Hidden' />
        
        </Style>

        <Style x:Key="ButtonClose" TargetType="Button">
            <Setter Property="Background" Value="{x:Null}" />
            <Setter Property="Foreground" Value="$ButtonTextColor" />
            <Setter Property="Width" Value="23" />
            <Setter Property="Height" Value="23" />
            <Setter Property="Opacity" Value="0.5" />
            <Setter Property="VerticalAlignment" Value="Top" />
            <Setter Property="Margin" Value="-3 5 5 0" />
            <Setter Property="FontSize" Value="14" />
            <Setter Property="FontWeight" Value="Bold" />
            <Setter Property="FontFamily" Value="Webdings" />
            <Setter Property="VerticalAlignment" Value="Center" />
            <Setter Property="BorderThickness" Value="0" />
            <Setter Property="BorderBrush" Value="#85c1f5" />
        </Style>
    </Window.Resources>
    
    <Border Background="$BackgroundColor" BorderThickness="2"> 
           
        <Grid x:Name = "MainContent">
        
            <Grid.RowDefinitions>
                <RowDefinition x:Name = "TitleBar" Height="30"/>
                <RowDefinition x:Name = "MainRowHeader" Height="$HeaderHeight" />
                <RowDefinition Height="*" />
                <RowDefinition x:Name = "MainRowBottom" Height="$SideMargin" />
            </Grid.RowDefinitions>  
                                
            <Grid.ColumnDefinitions>
                <ColumnDefinition x:Name = "MainColumnLeft" Width="$SideMargin"/>
                <ColumnDefinition Width='*'/>
                <ColumnDefinition x:Name = "MainColumnRight" Width="$SideMargin"/>
            </Grid.ColumnDefinitions>    

          	<Label x:Name = "Button0" Grid.Row = '1' Grid.Column = '1' Height="$HeaderHeight" Width = "$HeaderWidth" HorizontalAlignment = 'Left' BorderThickness = '0' BorderBrush = `"$TextColor`" Foreground = '$TextColor'>
                <DockPanel LastChildFill="True">  
                    <Label x:Name = "LabelHeader" DockPanel.Dock = "Top" FontFamily = 'Segoe UI' Foreground = `"$TextColor`" FontSize = '24' Height = '40' Content = "$Header"/>
                    <Label DockPanel.Dock = "Left" FontStyle = 'Italic' Foreground = `"$TextColor`" VerticalAlignment = 'Bottom' Content = "$Status"/>
                    <TextBlock TextWrapping = 'Wrap' DockPanel.Dock = "Right" HorizontalAlignment = 'Right' Margin = '0' Text = "$InfoText"/>
                </DockPanel>  
            </Label>
            
            <WrapPanel Grid.Row = '0' Grid.Column = '1' Grid.ColumnSpan = '2' HorizontalAlignment = 'Right' DockPanel.Dock="Right">
                <Button Content = '0' Name="ButtonMinimize" Style="{StaticResource ButtonClose}"/>
                <Button Content = '2' Name="ButtonToggleZoom" Style="{StaticResource ButtonClose}"/>
                <Button Content = 'r' Name="ButtonClose" Style="{StaticResource ButtonClose}" />
            </WrapPanel>        

            <WrapPanel x:Name = "ButtonPanel" Grid.Row = '2' Grid.Column = '1'>

        	$($MyWrapperApplications | ? { $_ } | % { 
    
    			# Create a bunch of buttons with different values depending on access / no access
    			$i = $_ 
                $progname = $i[0].Trim()
                $appname = $i[1].Trim()
                $humanname = $i[2].Trim()
                $access = $i[3]
                $autostart = $i[4]
                $Tag = "${progname}_${appname}"
                $Xname = $Tag.replace("`.","").replace("`,","") 
                
                $PrereqForeground , $PrereqBackground = Get-Prerequisite $progname $appname

                If($PrereqForeground -and $Access) {    

                    $Style = "ButtonPrerequisite"
                    $Content = "q"
                    #$Tooltip = "Click to install missing prerequisites needed to run $humanname"
                
                } ElseIf(!$Access) {
                
                    $Style = "ButtonNoAccess"
                    $Content = "Ï"
                
                } Else {
                
                    $Style = "ButtonDefault"
                    $Content = "4"
                }

    			$out = "<Button  
                        x:Name = `"Button_$Xname`" 
                        Tag = `"$Tag`" 
                        Style=`"{StaticResource $Style}`"
                        >                               
                            <Grid>
                                <Grid.RowDefinitions>
                                    <RowDefinition Height='21' />
                                    <RowDefinition Height='24' />
                                    <RowDefinition Height='25' />
                                </Grid.RowDefinitions>   
                               
                                <Grid.ColumnDefinitions>
                                    <ColumnDefinition Width='45'/>
                                    <ColumnDefinition Width='60'/>
                                    <ColumnDefinition Width='45'/>
                                </Grid.ColumnDefinitions>                    
                                
                                <TextBlock x:Name = `"TextBlockTop_$Xname`" Grid.Row = '0' Grid.Column = '0' Grid.ColumnSpan = '3' FontWeight = 'Normal' FontSize = '11' FontFamily = 'Segoe UI' HorizontalAlignment = 'Left' Text = `"`" Margin = '0' />
                                <Label x:Name = `"Label_$Xname`" Grid.Row = '1' Grid.Column = '1' HorizontalAlignment = 'Center' Padding = '0'>
                                    <Image Source= `"${ScriptBaseFolder}\icons\$progname.$appname.ico`" Height = '24' Width = '24' />
                                </Label>
                                <TextBlock x:Name = `"TextBlock_$Xname`" Grid.Row = '2' Grid.Column = '0' Grid.ColumnSpan = '3' FontWeight = 'Normal' FontSize = '11' FontFamily = 'Segoe UI' HorizontalAlignment = 'Left' VerticalAlignment = 'Bottom' Text = `"$HumanName`" Margin = '5 0 5 5' />
                                                       
                                <Label Content = `"$Content`" x:Name = `"OnMouseOver_$Xname`" Style=`"{StaticResource OnMouseOver_TextBlock}`" Grid.RowSpan = '3' Grid.ColumnSpan = '3' Grid.ZIndex = '2' />                                  
                                <Label Content = `"HEI`" x:Name = `"Running_$Xname`" Style=`"{StaticResource Running_Label}`" Grid.RowSpan = '3' Grid.ColumnSpan = '3' Grid.ZIndex = '2' />                                  
                                <Label Content = `"q`" x:Name = `"Caching_$Xname`" Style=`"{StaticResource Caching_Label}`" Grid.RowSpan = '3' Grid.ColumnSpan = '3' Grid.ZIndex = '2' />                                  
                                
                                <Label x:Name = `"CompactLabel_$Xname`" Grid.Row = '0' Grid.Column = '0' Grid.ColumnSpan = '3' Grid.ZIndex = '1' HorizontalAlignment = 'Left' Padding = '0' Visibility = 'Hidden'>
                                    <Grid>
                                         <Grid.RowDefinitions>
                                            <RowDefinition Height='24' />
                                        </Grid.RowDefinitions>   
                                        <Grid.ColumnDefinitions>
                                            <ColumnDefinition Width='30'/>
                                            <ColumnDefinition Width='120'/>
                                        </Grid.ColumnDefinitions>  
                                        
                                        <Label Grid.Column = '0' Padding = '0' >
                                            <Image Source= `"${ScriptBaseFolder}\icons\$progname.$appname.ico`" Height = '24' Width = '24' /> 
                                        </Label>
                                        <TextBlock Grid.Column = '1' Width = '120' FontWeight = 'Normal' FontSize = '11' FontFamily = 'Segoe UI' VerticalAlignment = 'Center' Foreground = `"$ButtonTextColor`">
                                            $HumanName
                                        </TextBlock>
                                    </Grid>
                                </Label>
                                    
                            </Grid>
                        </Button>"
                        
    			"$out" 
	       })

        </WrapPanel>
        </Grid>
    </Border>
</Window>

"@

    $reader=(New-Object System.Xml.XmlNodeReader $xaml)
    $Window=[Windows.Markup.XamlReader]::Load( $reader )

    $CloseButton = $Window.FindName("ButtonClose");
    $CloseButton.Add_Click({ Close-Form }) 

    $CloseButton = $Window.FindName("ButtonOffline");
    $CloseButton.Add_Click({ Invoke-Offline }) 

    $ToggleButton = $Window.FindName("ButtonToggleZoom")
    $ToggleButton.Add_Click({ Invoke-Toggle })

    $MinimizeButton = $Window.FindName("ButtonMinimize")
    $MinimizeButton.Add_Click({ $Window.WindowState = 'Minimized' })

    $Window.Add_MouseLeftButtonDown({ $Window.Topmost = $False; $Window.DragMove() })
    $Window.Add_MouseDoubleClick({ Invoke-Toggle })
    $Window.Add_MouseRightButtonDown({ & Notepad $NetworkIniFile })


    $MyWrapperApplications | % { 

        $i = $_ 
        $progname = $i[0] 
        $appname = $i[1]
        $humanname = $i[2]
        $access = $i[3]
        $flag = $i[4]
        $Xname = "${progname}_${appname}".replace("`.","").replace("`,","") ; 

        switch ($flag) {
            0 { $autostart = 0; $closegui = 0; $nogui = 0 }
            1 { $autostart = 0; $closegui = 1; $nogui = 0 }
            2 { $autostart = 1; $closegui = 0; $nogui = 0 }
            3 { $autostart = 1; $closegui = 1; $nogui = 0 }
            4 { $autostart = 1; $closegui = 1; $nogui = 1 }
        }

        $Button = $Window.FindName("Button_$Xname"); 
        $OnMouseOverLayer = $Window.FindName("OnMouseOver_$Xname")
     
        If($nogui) {

            Write-DebugLog "flag is set to $flag - nogui is set to $nogui"
            $Script:HideGUI = 1
        }

        $PrereqForeground , $PrereqBackground = Get-Prerequisite $progname $appname
 
        If(!$Access) {
        
            # Show button to redirect to AccessIT etc [ACCESS_x_y] if any access link value is set 
            # Otherwise remove the button

            # Any available [ACCESS_x_y] ?
            $AccessChecks = "ACCESS",
                            "ACCESS_${ProgName}",
                            "ACCESS_${ProgName}_${Site}",
                            "ACCESS_${ProgName}_${AppName}",
                            "ACCESS_${ProgName}_${AppName}_${Site}"
        
            $AccessChecks | % { If($IniSettings["$_"]) { $ShowAccessButton = 1 } }          

            If($ShowAccessButton) {

                $OnMouseOverLayer.Tooltip = "Click to request access to $humanname"
                $Button.Add_Click({ Invoke-Access })
    
            } Else {

                Write-DebugLog "No access regime set for ${ProgName} ${AppName}"

                # No access + No access link -> No button
                ($Button.Parent).Children.Remove($Button)

            } #end if access link is set

        } ElseIf ($PrereqForeground -or $PrereqBackground) {
        
            If($autostart) {
                
                Write-DebugLog "Auto start $progname $appname (Flag: $flag)"
                $Button.IsEnabled = $False; 
                Invoke-Prerequisite $progname $appname

                If($closegui) {

                    # Kill the GUI after the application process is started
                    $Script:TerminateGUI = 1
                }
            } 

            If($PrereqForeground) {
            
                $OnMouseOverLayer.Tooltip = "Click to install missing prerequisites needed to run $humanname"
            }

            If($closegui) {
            
                $Button.Add_Click({ $Script:TerminateGUI = 1; $This.IsEnabled = $False; Invoke-Prerequisite }) 

            } Else {

                $Button.Add_Click({ $This.IsEnabled = $False; Invoke-Prerequisite }) 
            }
    
        } Else {
       
            If($autostart) {
                
                Write-DebugLog "Auto start $progname $appname (Flag: $flag)"
                $Button.IsEnabled = $False; 
                Invoke-Application $progname $appname

                If($closegui) {

                    # Kill the GUI after the application process is started
                    $Script:TerminateGUI = 1
                }
            } 

            If($closegui) {
            
                # Kill the GUI after the application process is started
                $Button.Add_Click({ $Window.Topmost = $False; $Script:TerminateGUI = 1; $This.IsEnabled = $False; Invoke-Application }) 

            } Else {

                $Button.Add_Click({ $Window.Topmost = $False; $This.IsEnabled = $False; Invoke-Application }) 

            }
        } #end if access/prerequisite/normal
    } #end for all applications

    # Start small / in compact size
    If($IniCompact -eq "1") {

        Invoke-Toggle
    }

    # Trick to activate the window / put it in front (topmost deactivated by left mouse click)
    $dummy = $Window.Activate()
    $Window.Topmost = $True  
    $dummy = $Window.Focus()         
    
    # Hide the GUI if it is set explicitly off
    if($HideGUI) {

        Write-DebugLog "NoGUI flag set. Hiding the GUI"
        $Window.WindowState = 'Minimized'  
        # TODO: Remove from system tray   
    } 

    # Run the GUI process
    $Window.ShowDialog() | Out-Null

} #end Function Show-MyWrapper 


Function Invoke-ButtonJump {

    $Button = $This
    $Xname = $Button.Tag
        
    $MyTimer = new-object System.Windows.Threading.DispatcherTimer
   
    $MyTimer.Interval = [TimeSpan]"0:0:1"
    $MyTimer.Tag = ($Xname,$Button)
    #$MyTimer.Tag = ($Button)

                #Add event per tick       
                $MyTimer.Add_Tick({
                
                    # Parallell Threading
                    $Xname = $this.Tag[0]
                    $Button = $this.Tag[1] 
                    $Button.background = "Green"
                    $Button.Height = $Button.Height + 2

                    [Windows.Input.InputEventHandler]{ $Window.UpdateLayout() }   
                })

                #Start timer
                $MyTimer.Start()

} #end Function Invoke-ButtonJump


Function Invoke-Toggle {

    $MainGrid = $Window.FindName("ButtonPanel")
    $MainColumnLeft = $Window.FindName("MainColumnLeft")
    $MainColumnRight = $Window.FindName("MainColumnRight")
    $MainRowBottom = $Window.FindName("MainRowBottom")
    $MainRowHeader = $Window.FindName("MainRowHeader")
    $Header = $Window.FindName("LabelHeader")
    $TitleBar = $Window.FindName("TitleBar")

    If($Window.Width -gt 300) {
        
        # Mimimize
        $Window.Width = "$($TileWidth + 20)" 
        $TitleBar.Height = "0"
        $MainColumnLeft.Width = "5"
        $MainColumnRight.Width = "5"      
        $MainRowHeader.Height="30"
        $MainRowBottom.Height = "5"
        $Header.FontSize = "11"
        
        $MainGrid.Children | ? { $_ -is [system.windows.controls.button] } | % { 
               
                $Button = $_
                $Button.height = "21" 
                $Button.Margin = "2"
                $Xname = ($Button.Tag).replace("`.","").replace("`,","")
                $CompactLabel = $Window.FindName("CompactLabel_$Xname")
                $CompactLabel.Visibility = 'Visible'
       
                }
    
    } Else {
    
        # Maximize
        $Window.Width = "$WindowWidth" 
        $TitleBar.Height = "30"
        $MainColumnLeft.Width = "$SideMargin"
        $MainColumnRight.Width = "$SideMargin"
        $MainRowHeader.Height="$HeaderHeight"
        $MainRowBottom.Height = "$SideMargin"
        $Header.FontSize = "24"
        
        $MainGrid.Children | ? { $_ -is [system.windows.controls.button] } | % { 
               
                $Button = $_
                $Button.height = "$TileHeight" 
                $Button.Margin = "$TileMargin"
                $Xname = ($Button.Tag).replace("`.","").replace("`,","")
                
                $CompactLabel = $Window.FindName("CompactLabel_$Xname")
                $CompactLabel.Visibility = 'Hidden'
                
                }
    }

} #end Function Invoke-Toggle


Function Invoke-Prerequisite {
   param ( [string]$ProgName,
            [string]$AppName
            )
     
    # ProgramName & Application comes either from button or as arguments        
    If($ProgName -and $AppName) {

        # Find the button attached to the application
        $Xname = "${ProgName}_${AppName}".replace("`.","").replace("`,","") 
        $Button = $Window.FindName("Button_$Xname")  

    } Else {

        # Extract Program/Application from the clicked button
        $Button = $This
        $ProgName = $this.Tag.Split("_")[0]
        $AppName = $this.Tag.Split("_")[1]
       
    } #end if run from arguments or button     

    #Write-DebugLog "Checking prerequisites"

    $PrereqForeground , $PrereqBackground = Get-Prerequisite $ProgName $AppName

    #Write-DebugLog "Foreground: $PrereqForeground"
    #Write-DebugLog "Background: $PrereqBackground"

    #
    # SCCM autoinstall template
    #
    
    $InstallSccm = {
   
        param( 
            [String[]] $MissingSccmRequirementsBackground
            )

        # 
        # Contribution by Rune Norberg :: rnor@statoil.com
        #

        Function Write-SCCMDebugLog {
            <#   
            .DESCRIPTION 
                Write to Petrel SCCM debug log  
            .PARAMETER Text
                Text to be appended to debug log
            .EXAMPLE
                Write-SCCMDebugLog "Starting Petrel 2015.3" 
            #>
            param (
                    [string] $Text
                    )

            #If name of logfile not specified, use current script name
            #If (!($LogFileName)) {$LogFileName = "$($PSCommandPath.SubString($PSCommandPath.LastIndexOf("\")+1,$PSCommandPath.LastIndexOf(".")-$PSCommandPath.LastIndexOf("\")-1)).log"}
            $Now = Get-Date -uformat %Y%m%d%H%M%S
            $LogFile = "$($Env:Temp)\${ScriptName}SCCM.log"
            Write-Host "$Now -> $Text"
            Add-Content $LogFile -Value "$Now;$Text"
        } # End Function Write-SCCMDebugLog

        Function Get-ApplicationCatalogURL {
            <#   
            .DESCRIPTION 
                Find possible management points via MP, and assigns the first that respond with status cocde 200 to the check
            .EXAMPLE
                $PortalURL = Get-ApplicationCatalogURL
            #>

            #First request list of SCCM Management Points
            $PossibleMPs = gwmi -Namespace "root\ccm" -Class SMS_LookupMP

            #Loop through list and assign value from first MP that responds
            ForEach ($mp in $PossibleMPs) {
                If ((Invoke-WebRequest -Uri "http://$($mp.Name)//sms_mp/.sms_aut?mplist").StatusCode -eq "200") {
                    $AssignedMP = $mp.Name
                    Break
                }
            }

            If ($AssignedMP) {
                Return "http://$AssignedMP/CMUserService_WindowsAuth"
            }
            Else {
                Throw "Could not find any active MPs that responds correctly"
            }

        } #End Function Get-ApplicationCatalogURL

        Function Get-SCCMUserPolicyFromApplicationPortal {
            <#   
            .DESCRIPTION 
                Get (download) user policies from SCCM application catalog
            .PARAMETER PackageID
                SCCM PackageId, for packages it requires the ProgramId to be set, for applications it required the "_ScopeID...." identifier
            .PARAMETER ProgramID
                SCCM ProgramId ID, either "<PackageId>-<Program>" for old packages or "_ScopeID...." for new applications
            .EXAMPLE
                Get-SCCMUserPolicyFromApplicationPortal -PackageId "RPS00E7D" -ProgramId "Install"
            .EXAMPLE
                Get-SCCMUserPolicyFromApplicationPortal -Packageid "ScopeId...."
            #>
    
            param (
                [string] $PackageId,
                [string] $ProgramId
            ) 
    
            #FunctionName
            $FunctionName = $MyInvocation.MyCommand.Name

            #Initially set download status to false
            [bool]$PolicyDownloaded = $False

            #If package ("old" type) then packageid will be 8 characters, if not it will be longer and hence an application
            If ($PackageId.Length -eq 8) {
                $ApplicationId = "$PackageId-$ProgramId"
            }
            Else {
                $ApplicationId = $PackageId
            }
            Write-SCCMDebugLog "$FunctionName-> Application ID: $ApplicationId" 

            #Get device and user identificator
            Try {
                $DeviceID  = ([wmiclass]'ROOT\ccm\ClientSdk:CCM_SoftwareCatalogUtilities').GetDeviceId()
                $ClientId = $DeviceId.ClientId+","+$DeviceId.SignedClientid
                $SignedClientId = $DeviceId.SignedClientId
                Write-SCCMDebugLog "$FunctionName-> Client IDs: $($DeviceId.ClientID)" 
            }
            Catch {
                Write-SCCMDebugLog "$FunctionName-> Unable to get SCCM client ID." 
                Return $PolicyDownloaded
            }

            #Get SCCM Application Portal URL assigned to this client
            Try {
                $PortalURL = Get-ApplicationCatalogURL
                Write-SCCMDebugLog "$FunctionName-> Discovered SCCM Portal URL: $PortalURL" 
            }
            Catch {
                Write-SCCMDebugLog "$FunctionName-> Unable to get SCCM Portal URL. Exiting function......"
                Return $PolicyDownloaded
            }

            #Format SOAP request
            [xml]$SOAP = '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">  
                <s:Body>
                    <InstallApplication xmlns="http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/SoftwareCatalog/Website" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
                        <applicationID>'+$ApplicationId+'</applicationID>
                        <deviceID>'+$ClientId+'</deviceID>
                        <reserved/>
                    </InstallApplication>
                </s:Body>
            </s:Envelope>'

            #SOAP request header
            $Headers = @{"SOAPAction" = "http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/SoftwareCatalog/Website/InstallApplication"}

            #URI to portal
            $URI = "$PortalURL/applicationviewservice.asmx"

            #Post the web request
            Try {
                Write-SCCMDebugLog "Invoke-WebRequest $URI -Method POST -ContentType 'text/xml' -Body $SOAP -Headers $Headers -UseDefaultCredentials -UseBasicParsing"
                $SCCMUserPolicyRaw = Invoke-WebRequest $URI -Method POST -ContentType 'text/xml' -Body $SOAP -Headers $Headers -UseDefaultCredentials -UseBasicParsing

                Write-SCCMDebugLog "$FunctionName-> User Policy download status: $($SCCMUserPolicyRaw.StatusCode)"
                Write-SCCMDebugLog "$FunctionName-> User Policy downloaded size: $($SCCMUserPolicyRaw.RawContentLength)" 
                $PolicyDownloaded = $True
            }
            Catch {
                Write-SCCMDebugLog "SCCMDownloadUserPolicy-> Download of user policy failed. StatusCode: $($SCCMUserPolicyRaw.StatusCode), StatusDescription: $($SCCMUserPolicyRaw.StatusDescription)"
                Return $PolicyDownloaded
            }

            #Get bodysignature and body in correct format
            Try {
                Write-SCCMDebugLog "$FunctionName-> PowerShell Language Mode: $($ExecutionContext.SessionState.LanguageMode)"
                [xml]$SCCMUserPolicy = $SCCMUserPolicyRaw.Content
                Write-SCCMDebugLog "$FunctionName-> SCCMUserPolicy: $SCCMUserPolicy"
                $Body = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($SCCMUserPolicy.Envelope.body.InstallApplicationResponse.InstallApplicationResult.PolicyAssignmentsDocument))
                Write-SCCMDebugLog "$FunctionName-> SCCMBody ()"
                $BodySignature = $SCCMUserPolicy.Envelope.body.InstallApplicationResponse.InstallApplicationResult.BodySignature
                Write-SCCMDebugLog "$FunctionName-> SCCMBodySignature: $BodySignature"
            }
            Catch {
                $PolicyDownloaded = $False
                Write-SCCMDebugLog "$FunctionName-> Unable to get body in SCCM User Policy."
                Return $PolicyDownloaded
            }

            #Policy Source can be "LOCAL" or "SMS:<SMSSITECODE>
            #$PolicySource = "LOCAL"
            #Get assigned sitecode to ensure that policy is injected with correct sitecode
            Try {
                $SCCMClientObj = New-Object -ComObject "Microsoft.SMS.Client"
                $SCCMAssignedSiteCode =  $SCCMClientObj.GetAssignedSite()
                $PolicySource = "SMS:$SCCMAssignedSiteCode"
                Write-SCCMDebugLog "$FunctionName-> Client SCCM Assigned SiteCode: $SCCMAssignedSiteCode" 
            }
            Catch {
                $PolicySource = "LOCAL"
                Write-SCCMDebugLog "$FunctionName-> Unable to get SCCM Assigned SiteCode. Setting PolicySource to LOCAL"
            }

            #Inject downloaded user policy into local SCCM client
            Try {
                $ExecutionStatus = ([wmiclass]'ROOT\ccm\ClientSdk:CCM_SoftwareCatalogUtilities').ApplyPolicyEx($Body, $BodySignature, $PolicySource)
                Write-SCCMDebugLog "$FunctionName-> Success: SCCM User Policy Inject Status: $($ExecutionStatus.ReturnValue)"
            }
            Catch {
                Write-SCCMDebugLog "$FunctionName-> Error: SCCM User Policy Inject Status: $($ExecutionStatus.ReturnValue)" 
            }

            #Refresh user policy
            Try {
                $WMIUserPolicyUpdate = Invoke-WmiMethod -Namespace root\ccm\ClientSDK -Class CCM_ClientUtilities -Name GetUserPolicy
                Write-SCCMDebugLog "$FunctionName-> Refreshing user policy success: $($WMIUserPolicyUpdate.ReturnValue)"
            }
            Catch {
                Write-SCCMDebugLog "$FunctionName-> Refreshing user policy failed: $($WMIUserPolicyUpdate.ReturnValue)"
            }

            Write-SCCMDebugLog "$FunctionName-> End Application ID: $ApplicationId" 

            Return $PolicyDownloaded
        } #end Function Get-SCCMUserPolicyFromApplicationPortal


        Function Get-SCCMUserPolicyExistence {
            <#   
            .DESCRIPTION 
                Verifies that SCCM policy is in place
            .PARAMETER PackageID
                SCCM packageID
            .PARAMETER ProgramId
                SCCM programID
            .PARAMETER MaxLoops
                Max number of iterations in the loop before giving up to find policy
            .EXAMPLE
                Get-SCCMUserPolicyExistenceForPackage "SCS019BC" "Install" 1
            #>
    
            param (
                [string] $PackageId,
                [string] $ProgramId,
                [int] $MaxLoops
            ) 

            #FunctionName
            $FunctionName = $MyInvocation.MyCommand.Name

            #Set maximum number of loops if not specified
            If (!($MaxLoops)) {$MaxLoops = 40}

            #Loop specified number of times and check if policy is available
            $Counter = 0
            Do {
                If ($Counter -gt 1) {Start-Sleep -Seconds 1}
                $Counter++

                #If length of packagestring is 8, then package and program; else application
                If ($PackageID.Length -eq 8) {

                    $Check = gwmi -Namespace "root\ccm\clientsdk" CCM_Program -Filter "PackageId=""$($PackageId)"" AND ProgramId=""$($ProgramId)"""
                    $PolicyExist = [bool]$Check
                }
                Else {
        
                    $Check = gwmi -Namespace "root\ccm\clientsdk" CCM_Application -Filter "Id=""$($PackageId)"""
                    $PolicyExist = [bool]$Check
                }
                #Write status to log
                If ($PackageId.Length -eq 8) {
                    Write-SCCMDebugLog "$FunctionName-> UserPolicy for package $PackageID and program $ProgramId status: $PolicyExist"
                }
                Else {
                    Write-SCCMDebugLog "$FunctionName-> UserPolicy for application $PackageID status: $PolicyExist"
                }
            } Until (($PolicyExist) -Or ($Counter -eq $MaxLoops))

            #Return status related to if we did a successful download or not of a user policy
            Return $PolicyExist

        } #end Function Get-SCCMUserPolicyExistence
             
        ForEach ($MissingSccmRequirement in $MissingSccmRequirementsBackground) { 
        
                $Name = $MissingSccmRequirement.Split(",")[0].Trim()
                $PackageId = $MissingSccmRequirement.Split(",")[1].Trim()
            
                "Missing: $MissingSccmRequirement"
                Write-SCCMDebugLog "Main-> Missing: $MissingSccmRequirement"

                "Checking if user policies are available, if not download them and loop until they are visible"
                Write-SCCMDebugLog "Main-> Checking if user policies are available for $PackageId-$Name"
                "Main-> Checking if user policies are available for $PackageId-$Name"

                If (!(Get-SCCMUserPolicyExistence -PackageId $PackageId -ProgramId $Name -MaxLoops 1)) {

                    Write-SCCMDebugLog "Main-> Need to download user policy for $PackageId-$Name"
                    "Main-> Need to download user policy for $PackageId-$Name"
                
                    If (Get-SCCMUserPolicyFromApplicationPortal -PackageId $PackageId -ProgramId $Name) {
                
                        Write-SCCMDebugLog "Main-> Checking if user policies are available for $PackageId-$Name after download"
                        "Main-> Checking if user policies are available for $PackageId-$Name after download"

                        Get-SCCMUserPolicyExistence -PackageId $PackageId -ProgramId $Name -MaxLoops 600
                
                    }
                
                } Else {
                
                    Write-SCCMDebugLog "Main-> User policy for $PackageId-$Name already exists"
                
                } # end if policy exists for the package/application

                # Packages & Applications install differently
                If($PackageID.Length -eq 8) {             
                    
                    # Package install

                    $Sccm = New-Object -ComObject uiresource.uiresourcemgr
                
                    Try {
                        Write-SCCMDebugLog "Installing ProgramID $Name, Packageid $PackageId"
                        $Sccm.ExecuteProgram("$Name", "$PackageId", 1)
                    } Catch {

                        Write-SCCMDebugLog "Error installing ProgramID $Name, Packageid $PackageId"
                        # SCCM doesn't respond
                        $SCCMerror = 1
                        break
                    }
  
                    $Counter = $InstallationStatus = 0
        
                    # Let SCCM start
                    While ($InstallationStatus -lt 1) {
            
                        $InstallationStatus = $Sccm.GetDownloadStatus("$Name", "$PackageId").status
                
                        Write-SCCMDebugLog "InstallationStatus: $InstallationStatus"

                        $Counter += 1
                        If($Counter -gt 60) { break }
                        Start-Sleep 1              
                
                    } #end while installation is starting
        
                    # Wait until current installation is finished
                    While ($InstallationStatus -gt 0) {
       
                        $InstallationStatus = $Sccm.GetDownloadStatus("$Name", "$PackageId").status
                
                        Write-SCCMDebugLog "InstallationStatus: $InstallationStatus"

                        $Counter += 1
                        If($Counter -gt 600) { break }
                        Start-Sleep 1 
                
                    } #end while installation is running  
                        
                    Write-SCCMDebugLog "InstallationStatus: $InstallationStatus"
                    Write-SCCMDebugLog "Done installing ProgramID $Name, Packageid $PackageId"


                } Else {

                    # Application install

                    $Application = (Get-CimInstance -ClassName CCM_Application -Namespace "root\ccm\clientSDK"| Where-Object {$_.ID -like $PackageID})
 
                    $Args = @{EnforcePreference = [UINT32] 0
                        Id = "$($Application.id)"
                        IsMachineTarget = $Application.IsMachineTarget
                        IsRebootIfNeeded = $False
                        Priority = 'High'
                        Revision = "$($Application.Revision)" }
 
                    Try {

                        Write-SCCMDebugLog "Installing Application $PackageID"

                        Invoke-CimMethod -Namespace "root\ccm\clientSDK" -ClassName CCM_Application -MethodName Install -Arguments $Args
                    
                    } Catch {

                        Write-SCCMDebugLog "Error installing Application $PackageID"
                        # SCCM doesn't respond
                        $SCCMerror = 1
                        break
                    }
 
                } # end if package or application

         } #end foreach missing sccm requirement   
            
                If ($SCCMerror -eq 1) {

                     Write-SCCMDebugLog "Error installing -> Red flag"

                    # Installation error. SCCM is most probably busy with something else.
                    # Running a bogus command will give HasMoreData = True, which we can use later
                    ThisBogusCommandWillCorruptThisJob
                }    
                
                       
        } # end $InstallSccm

    #
    # FOREGROUND JOBS (showing in GUI)
    #


 
    If($PrereqForeground) {

        Write-DebugLog "Starting foreground prerequisite: $PrereqForeground"

        #Create Runspace
        $ForegroundRunSpace = [RunspaceFactory]::CreateRunspace()
        $ForegroundRunSpace.Name = $PrereqForeground
        $ForegroundPowerShell = [PowerShell]::Create()
        $ForegroundPowerShell.RunSpace = $ForegroundRunSpace
        $ForegroundRunSpace.Open()

        #Add scritblock and parameters
        [void]$ForegroundPowerShell.AddScript($InstallSccm)
        [void]$ForegroundPowerShell.AddArgument($PrereqForeground)
        
        #Update global array to keep track of created runspaces
        $Global:MyRunSpaces += [PSCustomObject]@{ Pipe = $ForegroundPowerShell; Status = $ForegroundPowerShell.BeginInvoke()}
        #$ForegroundRunSpace = $ForegroundPowerShell.BeginInvoke()
    
        Write-DebugLog "  Foreground runspace started for installation"

    } #End If foreground prerequisite

    If($ForegroundRunSpace) {
        
        $Script:WorkingButton = $Button   
        $Script:timer = new-object System.Windows.Threading.DispatcherTimer
        $Script:ButtonAngle = 0

        #Fire off every .1 second
        $timer.Interval = [TimeSpan]"0:0:0.10"

        $Timer.Tag = ($ProgName,$AppName)

        #Add event per tick
        $timer.Add_Tick({

            $ProgName = $This.Tag[0]
            $AppName = $This.Tag[1]

            $Button = $Script:WorkingButton
            

            # Verify if the application is installed ok
            # Caution: Endless loop if it doesn't succeed
            $PrereqForeground , $PrereqBackground = Get-Prerequisite $ProgName $AppName
 
            #If (!($ForegroundRunSpace.IsCompleted) -or $PrereqForeground) {
            If ($PrereqForeground) {
        
                # Spinning tile
                $Script:ButtonAngle = ($Script:ButtonAngle + 5) % 360
                $Button.background = "$ButtonRunningColor"
                $Button.RenderTransform = New-Object System.Windows.Media.RotateTransform -ArgumentList $Script:ButtonAngle,0,0
                            
            } Else {
               
                # Change the button overlay
                $Xname = ("${ProgName}_${AppName}").replace("`.","").replace("`,","")
                $OnMouseOverLabel = $Window.FindName("OnMouseOver_$Xname")
                $OnMouseOverLabel.Tooltip = "Ready to run!"
                $OnMouseOverLabel.Content = "4"

                $Button.background = "$ButtonBackgroundColor"
                $Button.Style = $Window.Resources["ButtonDefault"] 
                
                $Button.RenderTransform = New-Object System.Windows.Media.RotateTransform -ArgumentList 0,0,0
                
                Write-DebugLog "Foreground prerequisite successfully installed"


                # Clear the prerequisites table
                $IniSettings["PREREQUISITE_${ProgName}_${AppName}"] = ""

                # Start application when foreground job completes
                Invoke-Application $ProgName $AppName
                
                $timer.Stop()           
            }
            
            [Windows.Input.InputEventHandler]{ $Window.UpdateLayout() }
            
        })

        #Start timer
        $timer.Start()

    } ElseIf($PrereqForeground) {
    
       $Button.background = "Red"   
       
    } #end if foreground prerequisite job starts 
     
 
    #
    # BACKGROUND JOBS (not showing in GUI)
    #
 
    If($PrereqBackground) {

        Write-DebugLog "Starting background prerequisite: $PrereqBackground"

        #Create Runspace
        $BackgroundRunSpace = [RunspaceFactory]::CreateRunspace()
        $BackgroundPowerShell = [PowerShell]::Create()
        $BackgroundPowerShell.RunSpace = $BackgroundRunSpace
        $BackgroundRunSpace.Open()

        #Add scritblock and parameters
        [void]$BackgroundPowerShell.AddScript($InstallSccm)
        [void]$BackgroundPowerShell.AddArgument($PrereqBackground)
        
        #Update global array to keep track of created runspaces
        $Global:MyRunSpaces += [PSCustomObject]@{ Pipe = $BackgroundPowerShell; Status = $BackgroundPowerShell.BeginInvoke()}
    
        Write-DebugLog "  Background runspace started for installation"
    }

    # Start Application if only background job
    If($BackgroundRunSpace) {
    
        Invoke-Application $ProgName $AppName
    }
            
} #End Function Invoke-Prerequisite


Function Get-Prerequisite {

    Param ($ProgName, $AppName)

    #
    # Prerequisites
    #
    $CheckPrerequisite = @{}

   	# Global 
    $CheckGlobal = $IniSettings["PREREQUISITE"]
    If($CheckGlobal.Count -gt 0) { 

        $CheckPrerequisite += $CheckGlobal
    }

    # Default 
    $CheckDefault = $IniSettings["PREREQUISITE_${ProgName}"]
    If($CheckDefault.Count -gt 0) { 

        $CheckPrerequisite += $CheckDefault
    }
    
    # Specific 
    $CheckSpecific = $IniSettings["PREREQUISITE_${ProgName}_${AppName}"]
    If($CheckSpecific.Count -gt 0) { 

        $CheckPrerequisite += $CheckSpecific
    } 
    
    $MissingSccmRequirements = @()
    $MissingSccmRequirementsBackground = @()

    Foreach ($i in $CheckPrerequisite.Keys) {
    
        #Write-DebugLog "Testing Prerequisite $i - $($CheckPrerequisite[$i])"
        $Prerequisite = [System.Environment]::ExpandEnvironmentVariables("$($CheckPrerequisite[$i])")
        
        If(!(Test-Path $Prerequisite)) {

            #Return $False
            
            
            $SCCM = $IniSettings["SCCM_APPLICATIONS"]
            
            If($SCCM.ContainsKey("$i")) {
               
                # Background or foreground installation
                If($SCCM["$i"].split(",")[2]) {

                    Write-DebugLog "Missing Background prerequisite $i ($ProgName/$AppName)"
                    $MissingSccmRequirementsBackground += , $($SCCM[$i] + "," + $i)
                
                } Else {
                
                    Write-DebugLog "Missing Foreground prerequisite $i ($ProgName/$AppName)"
                    $MissingSccmRequirements += , $($SCCM[$i] + "," + $i)
                
                } #end if background installation flag is set
                
            } Else {
            
                Write-DebugLog "Missing Prerequisite $($i.keys) doesn't have an SCCM entry ($ProgName/$AppName)"
                
            } #end if in sccm
        } Else {
        
            Write-debuglog "Verified Prerequisite $i ($ProgName/$AppName)" 
        
        } #end if
    } #end foreach application

    If($MissingSccmRequirements -or $MissingSccmRequirementsBackground) {
       
       Return ($MissingSccmRequirements,$MissingSccmRequirementsBackground)
       
    } Else {

        Return $False

    }

   # Return $True

} #end Function Get-Prerequisite


# -----------------------------------------------------------------------------------------
# Execute
# -----------------------------------------------------------------------------------------

If ($MyInvocation.InvocationName -ne ‘.‘) {

    # Called directly
    Write-DebugLog "-------------------------------------------------------------------------"
    Write-DebugLog "START $($MyInvocation.InvocationName)"
    Write-DebugLog "-------------------------------------------------------------------------"

    #Create array object to hold eventual Runspaces that we need to create. Runspaces can be used to exec async code that needs PowerShell to be inn FullLanguage mode (eg. not Constrained Language Mode).
    $Global:MyRunSpaces = @()


    # Start the GUI
    Show-MyWrapper

    #Wait until all Runspaces are finished before we quit
    While ($Global:MyRunSpaces.Status -ne $null) {
        $Completed = $Global:MyRunSpaces | ?{$_.Status.IsCompleted -eq $True}
        ForEach ($RunSpace in $Completed) {
            $RunSpace.Pipe.EndInvoke($RunSpace.Status)
            $RunSpace.Status = $Null
        }
    }

    #Cleanup Runspace objects
    $RunSpacePool.Close()
    $RunSpacePool.Dispose()
 
} Else {

    Write-DebugLog "DOT SOURCE $($MyInvocation.InvocationName)"

    "---------------------------------------------"
    "$($MyInvocation.MyCommand.Name) - Available functions:"
    "---------------------------------------------"
    
    Get-Content $MyInvocation.MyCommand.Path | Where-Object {$_ -like "Function*"} | ForEach-Object {($_.split(" "))[1]} | Sort-Object
}

# -----------------------------------------------------------------------------------------
# TheEnd
# -----------------------------------------------------------------------------------------