<#	
    .SYNOPSIS
        Applies Windows 10 Optimizations and configurations. Supports VDI optmizations	
    
    .DESCRIPTION
		Applies Windows 10 Optimizations and configurations. Supports VDI optmizations
        Utilizes LGPO.exe to apply group policy item where neceassary.
        Utilizes MDT/SCCM TaskSequence property control
            Configurable using custom variables in MDT/SCCM

    .INPUTS
        '// Global Settings
        CFG_DisableConfigScript
        CFG_UseLGPOForConfigs
        LGPOPath

        '// VDI Preference
        CFG_OptimizeForVDI
        CFG_EnableVisualPerformance

        '// User Preference
        CFG_InstallLogonScript
        CFG_LogonScriptPath
        CFG_EnableDarkTheme
        CFG_EnableTaskbarAutoColor
        CFG_DisableFontSmoothing
        CFG_CleanSampleFolders
        CFG_DisableCortana
        CFG_DisableInternetSearch
        CFG_EnableOfficeOneNote
        CFG_DisableOneDrive
        CFG_DisableWindowsFirstLoginAnimation
        CFG_DisableIEFirstRunWizard
        CFG_DisableWMPFirstRunWizard
        CFG_ShowKnownExtensions
        CFG_ShowHiddenFiles
        CFG_ShowThisPCOnDesktop
        CFG_ShowUserFolderOnDesktop
        CFG_RemoveRecycleBinOnDesktop
        CFG_Hide3DObjectsFromExplorer
        CFG_DisableEdgeShortcut
        CFG_DisableStoreOnTaskbar
        CFG_DisableActivityHistory
        CFG_SetSmartScreenFilter
        CFG_EnableNumlockStartup
        CFG_DisableAppSuggestions

        '// System Settings
        CFG_InstallPSModules
        CFG_SetPowerCFG
        CFG_PowerCFGFilePath
        CFG_EnableIEEnterpriseMode
        CFG_IEEMSiteListPath
        CFG_ApplyCustomHost
        HostPath
        CFG_EnableSecureLogonCAD
        CFG_DisableAllNotifications
        CFG_EnableVerboseMsg
        CFG_DisableAutoRun
        CFG_PreferIPv4OverIPv6
        CFG_EnableAppsRunAsAdmin
        CFG_HideDrives
        CFG_DisableActionCenter
        CFG_DisableFeedback
        CFG_DisableWUP2P
        CFG_DisablePreviewBuild
        CFG_DisableDriverUpdates
        CFG_DisableWindowsUpgrades
        CFG_ApplyPrivacyMitigations
        CFG_RemoveRebootOnLockScreen
        CFG_RemoveUnusedPrinters

        '//System Adv Settings
        CFG_DisableSmartCardLogon
        CFG_ForceStrictSmartCardLogon
        CFG_EnableFIPS
        CFG_EnableCredGuard
        CFG_DisableUAC
        CFG_EnableStrictUAC
        CFG_EnableRDP
        CFG_EnableWinRM
        CFG_EnableRemoteRegistry
        CFG_EnableUEV
        CFG_EnableAppV
        CFG_EnablePSLogging
        CFG_EnableLinuxSubSystem
        CFG_DisableAdminShares
        CFG_DisableSchTasks
        CFG_DisableDefender
        CFG_DisableFirewall
        CFG_DisableWireless
        CFG_DisableBluetooth
        CFG_DisableNewNetworkDialog
        CFG_DisableInternetServices
        CFG_DisabledUnusedServices
        CFG_DisabledUnusedFeatures
        CFG_DisableIndexing
        CFG_RemoveActiveSetupComponents
        CFG_PreCompileAssemblies
        CFG_OptimizeNetwork

    .NOTES
        Author:         Richard Tracy
        Last Update:    05/29/2019
        Version:        3.1.8
        Thanks to:      unixuser011,W4RH4WK,TheVDIGuys,cluberti

    .EXAMPLE
        #Copy this to MDT CustomSettings.ini

        Properties=CFG_DisableConfigScript,CFG_UseLGPOForConfigs,LGPOPath,CFG_OptimizeForVDI,CFG_EnableVisualPerformance,CFG_InstallLogonScript,CFG_LogonScriptPath,CFG_EnableDarkTheme,CFG_EnableTaskbarAutoColor,CFG_DisableFontSmoothing,CFG_DisableCortana,CFG_DisableInternetSearch,CFG_EnableOfficeOneNote,CFG_DisableOneDrive,CFG_DisableWindowsFirstLoginAnimation,CFG_DisableIEFirstRunWizard,CFG_DisableWMPFirstRunWizard,CFG_ShowKnownExtensions,CFG_ShowHiddenFiles,CFG_ShowThisPCOnDesktop,CFG_ShowUserFolderOnDesktop,CFG_RemoveRecycleBinOnDesktop,CFG_Hide3DObjectsFromExplorer,CFG_DisableEdgeShortcut,CFG_DisableStoreOnTaskbar,CFG_DisableActivityHistory,CFG_SetSmartScreenFilter,CFG_EnableNumlockStartup,CFG_DisableAppSuggestions,,#// System Settings,CFG_InstallPSModules,CFG_SetPowerCFG,CFG_PowerCFGFilePath,CFG_EnableIEEnterpriseMode,CFG_IEEMSiteListPath,CFG_ApplyCustomHost,HostPath,CFG_EnableSecureLogonCAD,CFG_DisableAllNotifications,CFG_EnableVerboseMsg,CFG_DisableAutoRun,CFG_PreferIPv4OverIPv6,CFG_EnableAppsRunAsAdmin,CFG_HideDrives,CFG_DisableActionCenter,CFG_DisableFeedback,CFG_DisableWUP2P,CFG_DisablePreviewBuild,CFG_DisableDriverUpdates,CFG_DisableWindowsUpgrades,CFG_ApplyPrivacyMitigations,CFG_RemoveRebootOnLockScreen,CFG_DisableSmartCardLogon,CFG_ForceStrictSmartCardLogon,CFG_EnableFIPS,CFG_EnableCredGuard,CFG_DisableUAC,CFG_EnableStrictUAC,CFG_EnableRDP,CFG_EnableWinRM,CFG_EnableRemoteRegistry,CFG_EnableUEV,CFG_EnableAppV,CFG_EnablePSLogging,CFG_EnableLinuxSubSystem,CFG_DisableAdminShares,CFG_DisableSchTasks,CFG_DisableDefender,CFG_DisableFirewall,CFG_DisableWireless,CFG_DisableBluetooth,CFG_DisableNewNetworkDialog,CFG_DisableInternetServices,CFG_DisabledUnusedServices,CFG_DisabledUnusedFeatures,CFG_DisableIndexing,CFG_RemoveActiveSetupComponents,CFG_PreCompileAssemblies,CFG_OptimizeNetwork,CFG_RemoveUnusedPrinters

        #Then add each option to a priority specifically for your use, like:
        [Default]
        CFG_UseLGPOForConfigs=True
        CFG_EnableVerboseMsg=True
        CFG_DisableAutoRun=True
        CFG_CleanSampleFolders=True
        ...

        #Add script to task sequence

    .LINK
        https://github.com/TheVDIGuys/W10_1803_VDI_Optimize
        https://github.com/cluberti/VDI/blob/master/ConfigAsVDI.ps1

    .LOGS
        3.1.8 - May 29, 2019 - fixed UnusedFeature issue and set-usersettings default users, and user freidnly displays for apps removal
                                resolved all VSC problems  
        3.1.7 - May 28, 2019 - fixed Get-SMSTSENV log path
        3.1.6 - May 24, 2019 - Added Unused Printer removal, fixed DisableIEFirstRunWizard section
        3.1.5 - May 15, 2019 - Added Get-ScriptPpath function to support VScode and ISE; fixed Set-UserSettings 
        3.1.4 - May 10, 2019 - added strict smart card login scenario; reorganized controls in categories
                                fixed PS module import 
        3.1.3 - May 9, 2019 - added reboot lockscreen and separated fontsmoothing option
        3.1.2 - Apr 25, 2019 - Updated SYNOPSIS, Add OptimizeNetwork switch
        3.1.1 - Apr 17, 2019 - added App-V and UE-V control
        3.1.0 - Apr 17, 2019 - added Set-UserSetting function
        3.0.4 - Apr 12, 2019 - added more Windwos 10 settings check
        3.0.1 - Apr 12, 2019 - fixed progress bar for each user, removed extension script check
        3.0.0 - Apr 4, 2019 -  added progress bar for tasksequence
        2.5.0 - Mar 29, 2019 - added more options from theVDIGuys script
        2.1.6 - Mar 13, 2019 - Commented out Windows 10 old items
        2.1.5 - Mar 13, 2019 - Fixed mitigations script and removed null outputs
        2.1.3 - Mar 12, 2019 - Fixed TyLGPO Trigger on some keys
        2.1.0 - Mar 12, 2019 - Updatd LGPO process as global variable and added param for it
        2.0.0 - Mar 11, 2019 - Split STIGs and EMET mitcations to Seperate script (WIn10STIGAndMitigations.ps1)
        1.5.0 - Mar 8, 2019  - Add a lot more VDI Optimizations using Vmware OSOT xml, changed Configure-RegistryItem to Set-SystemSettings
        1.2.4 - Mar 8, 2019  - Fixed relative path for LGPO.exe
        1.2.7 - Mar 7, 2019  - updated EMET aas hashtables, added SID translation for registry hive loading
        1.2.5 - Mar 7, 2019  - Cleaned up log comments, Fixed EMET mitigations for windows 10 versions
        1.2.4 - Mar 7, 2019  - Added EMET mitigations, fixed Write-LogEntry
        1.2.0 - Mar 7, 2019  - Added new capabilities, VDI Optimizations control, fixed Configure-bluetooth,Configure-RegistryItem function
        1.1.8 - Dec 14, 2018 - Added User profile registry loop
        1.1.2 - Dec 14, 2018 - Added more property checks, Merged Configure-LGPO with Configure-RegistryItem functiuon
        1.1.0 - Dec 13, 2018 - Added Bluetooth Function, LGPO Function, Added STIGs
        1.0.0 - Nov 20, 2018 - initial 
 
#> 


##*===========================================================================
##* FUNCTIONS
##*===========================================================================

Function Test-IsISE {
    # try...catch accounts for:
    # Set-StrictMode -Version latest
    try {    
        return ($null -ne $psISE);
    }
    catch {
        return $false;
    }
}
Function Get-ScriptPath {
    # Makes debugging from ISE easier.
    if ($PSScriptRoot -eq "")
    {
        if (Test-IsISE)
        {
            $psISE.CurrentFile.FullPath
            #$root = Split-Path -Parent $psISE.CurrentFile.FullPath
        }
        else
        {
            $context = $psEditor.GetEditorContext()
            $context.CurrentFile.Path
            #$root = Split-Path -Parent $context.CurrentFile.Path
        }
    }
    else
    {
        #$PSScriptRoot
        $PSCommandPath
        #$MyInvocation.MyCommand.Path
    }
}

Function Get-SMSTSENV{
    param(
        [switch]$ReturnLogPath,
        [switch]$NoWarning
    )
    
    Begin{
        ## Get the name of this function
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
    }
    Process{
        try{
            # Create an object to access the task sequence environment
            $Script:tsenv = New-Object -COMObject Microsoft.SMS.TSEnvironment 
        }
        catch{
            If(${CmdletName}){$prefix = "${CmdletName} ::" }Else{$prefix = "" }
            If(!$NoWarning){Write-Warning ("{0}Task Sequence environment not detected. Running in stand-alone mode." -f $prefix)}
            
            #set variable to null
            $Script:tsenv = $null
        }
        Finally{
            #set global Logpath
            if ($Script:tsenv){
                #grab the progress UI
                $Script:TSProgressUi = New-Object -ComObject Microsoft.SMS.TSProgressUI

                # Convert all of the variables currently in the environment to PowerShell variables
                $tsenv.GetVariables() | ForEach-Object { Set-Variable -Name "$_" -Value "$($tsenv.Value($_))" }
                
                # Query the environment to get an existing variable
                # Set a variable for the task sequence log path
                
                #Something like: C:\MININT\SMSOSD\OSDLOGS
                #[string]$LogPath = $tsenv.Value("LogPath")
                #Somthing like C:\WINDOWS\CCM\Logs\SMSTSLog
                [string]$LogPath = $tsenv.Value("_SMSTSLogPath")
                
            }
            Else{
                [string]$LogPath = $env:Temp
            }
        }
    }
    End{
        #If output log path if specified , otherwise output ts environment
        If($ReturnLogPath){
            return $LogPath
        }
        Else{
            return $Script:tsenv
        }
    }
}


Function Format-ElapsedTime($ts) {
    $elapsedTime = ""
    if ( $ts.Minutes -gt 0 ){$elapsedTime = [string]::Format( "{0:00} min. {1:00}.{2:00} sec.", $ts.Minutes, $ts.Seconds, $ts.Milliseconds / 10 );}
    else{$elapsedTime = [string]::Format( "{0:00}.{1:00} sec.", $ts.Seconds, $ts.Milliseconds / 10 );}
    if ($ts.Hours -eq 0 -and $ts.Minutes -eq 0 -and $ts.Seconds -eq 0){$elapsedTime = [string]::Format("{0:00} ms.", $ts.Milliseconds);}
    if ($ts.Milliseconds -eq 0){$elapsedTime = [string]::Format("{0} ms", $ts.TotalMilliseconds);}
    return $elapsedTime
}

Function Format-DatePrefix{
    [string]$LogTime = (Get-Date -Format 'HH:mm:ss.fff').ToString()
	[string]$LogDate = (Get-Date -Format 'MM-dd-yyyy').ToString()
    return ($LogDate + " " + $LogTime)
}

Function Write-LogEntry{
    param(
        [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
        [Parameter(Mandatory=$false,Position=2)]
		[string]$Source = '',
        [parameter(Mandatory=$false)]
        [ValidateSet(0,1,2,3,4)]
        [int16]$Severity,

        [parameter(Mandatory=$false, HelpMessage="Name of the log file that the entry will written to.")]
        [ValidateNotNullOrEmpty()]
        [string]$OutputLogFile = $Global:LogFilePath,

        [parameter(Mandatory=$false)]
        [switch]$Outhost
    )
    Begin{
        [string]$LogTime = (Get-Date -Format 'HH:mm:ss.fff').ToString()
        [string]$LogDate = (Get-Date -Format 'MM-dd-yyyy').ToString()
        [int32]$script:LogTimeZoneBias = [timezone]::CurrentTimeZone.GetUtcOffset([datetime]::Now).TotalMinutes
        [string]$LogTimePlusBias = $LogTime + $script:LogTimeZoneBias
        
    }
    Process{
        # Get the file name of the source script
        Try {
            If ($script:MyInvocation.Value.ScriptName) {
                [string]$ScriptSource = Split-Path -Path $script:MyInvocation.Value.ScriptName -Leaf -ErrorAction 'Stop'
            }
            Else {
                [string]$ScriptSource = Split-Path -Path $script:MyInvocation.MyCommand.Definition -Leaf -ErrorAction 'Stop'
            }
        }
        Catch {
            $ScriptSource = ''
        }
        
        
        If(!$Severity){$Severity = 1}
        $LogFormat = "<![LOG[$Message]LOG]!>" + "<time=`"$LogTimePlusBias`" " + "date=`"$LogDate`" " + "component=`"$ScriptSource`" " + "context=`"$([Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " + "type=`"$Severity`" " + "thread=`"$PID`" " + "file=`"$ScriptSource`">"
        
        # Add value to log file
        try {
            Out-File -InputObject $LogFormat -Append -NoClobber -Encoding Default -FilePath $OutputLogFile -ErrorAction Stop
        }
        catch {
            Write-Host ("[{0}] [{1}] :: Unable to append log entry to [{1}], error: {2}" -f $LogTimePlusBias,$ScriptSource,$OutputLogFile,$_.Exception.ErrorMessage) -ForegroundColor Red
        }
    }
    End{
        If($Outhost -or $Global:OutTohost){
            If($Source){
                $OutputMsg = ("[{0}] [{1}] :: {2}" -f $LogTimePlusBias,$Source,$Message)
            }
            Else{
                $OutputMsg = ("[{0}] [{1}] :: {2}" -f $LogTimePlusBias,$ScriptSource,$Message)
            }

            Switch($Severity){
                0       {Write-Host $OutputMsg -ForegroundColor Green}
                1       {Write-Host $OutputMsg -ForegroundColor Gray}
                2       {Write-Warning $OutputMsg}
                3       {Write-Host $OutputMsg -ForegroundColor Red}
                4       {If($Global:Verbose){Write-Verbose $OutputMsg}}
                default {Write-Host $OutputMsg}
            }
        }
    }
}

function Show-ProgressStatus
{
    <#
    .SYNOPSIS
        Shows task sequence secondary progress of a specific step
    
    .DESCRIPTION
        Adds a second progress bar to the existing Task Sequence Progress UI.
        This progress bar can be updated to allow for a real-time progress of
        a specific task sequence sub-step.
        The Step and Max Step parameters are calculated when passed. This allows
        you to have a "max steps" of 400, and update the step parameter. 100%
        would be achieved when step is 400 and max step is 400. The percentages
        are calculated behind the scenes by the Com Object.
    
    .PARAMETER Message
        The message to display the progress
    .PARAMETER Step
        Integer indicating current step
    .PARAMETER MaxStep
        Integer indicating 100%. A number other than 100 can be used.
    .INPUTS
         - Message: String
         - Step: Long
         - MaxStep: Long
    .OUTPUTS
        None
    .EXAMPLE
        Set's "Custom Step 1" at 30 percent complete
        Show-ProgressStatus -Message "Running Custom Step 1" -Step 100 -MaxStep 300
    
    .EXAMPLE
        Set's "Custom Step 1" at 50 percent complete
        Show-ProgressStatus -Message "Running Custom Step 1" -Step 150 -MaxStep 300
    .EXAMPLE
        Set's "Custom Step 1" at 100 percent complete
        Show-ProgressStatus -Message "Running Custom Step 1" -Step 300 -MaxStep 300
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string] $Message,
        [Parameter(Mandatory=$true)]
        [int]$Step,
        [Parameter(Mandatory=$true)]
        [int]$MaxStep,
        [string]$SubMessage,
        [int]$IncrementSteps,
        [switch]$Outhost
    )

    Begin{

        If($SubMessage){
            $StatusMessage = ("{0} [{1}]" -f $Message,$SubMessage)
        }
        Else{
            $StatusMessage = $Message

        }
    }
    Process
    {
        If($Script:tsenv){
            $Script:TSProgressUi.ShowActionProgress(`
                $Script:tsenv.Value("_SMSTSOrgName"),`
                $Script:tsenv.Value("_SMSTSPackageName"),`
                $Script:tsenv.Value("_SMSTSCustomProgressDialogMessage"),`
                $Script:tsenv.Value("_SMSTSCurrentActionName"),`
                [Convert]::ToUInt32($Script:tsenv.Value("_SMSTSNextInstructionPointer")),`
                [Convert]::ToUInt32($Script:tsenv.Value("_SMSTSInstructionTableSize")),`
                $StatusMessage,`
                $Step,`
                $Maxstep)
        }
        Else{
            Write-Progress -Activity "$Message ($Step of $Maxstep)" -Status $StatusMessage -PercentComplete (($Step / $Maxstep) * 100) -id 1
        }
    }
    End{
        Write-LogEntry $Message -Severity 1 -Outhost:$Outhost
    }
}

Function Set-Bluetooth{
    [CmdletBinding()] 
    Param (
    [Parameter(Mandatory=$true)][ValidateSet('Off', 'On')]
    [string]$DeviceStatus
    )
    Begin{
        ## Get the name of this function
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
    }
    Process{
        Add-Type -AssemblyName System.Runtime.WindowsRuntime
        $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
        Function Await($WinRtTask, $ResultType) {
            $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
            $netTask = $asTask.Invoke($null, @($WinRtTask))
            $netTask.Wait(-1) | Out-Null
            $netTask.Result
        }
        [Windows.Devices.Radios.Radio,Windows.System.Devices,ContentType=WindowsRuntime] | Out-Null
        [Windows.Devices.Radios.RadioAccessStatus,Windows.System.Devices,ContentType=WindowsRuntime] | Out-Null
        Await ([Windows.Devices.Radios.Radio]::RequestAccessAsync()) ([Windows.Devices.Radios.RadioAccessStatus]) | Out-Null
        $radios = Await ([Windows.Devices.Radios.Radio]::GetRadiosAsync()) ([System.Collections.Generic.IReadOnlyList[Windows.Devices.Radios.Radio]])
        $bluetooth = $radios | Where-Object { $_.Kind -eq 'Bluetooth' }
        [Windows.Devices.Radios.RadioState,Windows.System.Devices,ContentType=WindowsRuntime] | Out-Null
        If($bluetooth){
            Try{
                Await ($bluetooth.SetStateAsync($DeviceStatus)) ([Windows.Devices.Radios.RadioAccessStatus]) | Out-Null
            }
            Catch{
                Write-LogEntry ("Unable to configure Bluetooth Settings: {0}" -f $_.Exception.ErrorMessage) -Severity 3 -Source ${CmdletName}
            }
            Finally{
                #If ((Get-Service bthserv).Status -eq 'Stopped') { Start-Service bthserv }
            }
        }
        Else{
            Write-LogEntry ("No Bluetooth found") -Severity 0 -Source ${CmdletName}
        }
    }
    End{}
}


function Disable-Indexing {
    Param($Drive)
    $obj = Get-WmiObject -Class Win32_Volume -Filter "DriveLetter='$Drive'"
    $indexing = $obj.IndexingEnabled
    if("$indexing" -eq $True){
        Write-Host "Disabling indexing of drive $Drive"
        $obj | Set-WmiInstance -Arguments @{IndexingEnabled=$False} | Out-Null
    }
}

Function Convert-ToHexString{
    [Parameter(Mandatory=$true,Position=0)]
    Param ([string]$str)

    $bytes=[System.Text.Encoding]::UniCode.GetBytes($str)
    return ([byte[]]$bytes)
}

Function Convert-FromHexString{
    [Parameter(Mandatory=$true,Position=0)]
    Param ($hex)
    [System.Text.Encoding]::UniCode.GetString($hex)
}

Function Set-SystemSetting {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact='Medium')]
    Param (

    [Parameter(Mandatory=$true,Position=0)]
    [Alias("Path")]
    [string]$RegPath,

    [Parameter(Mandatory=$false,Position=1)]
    [Alias("v")]
    [string]$Name,

    [Parameter(Mandatory=$false,Position=2)]
    [Alias("d")]
    $Value,

    [Parameter(Mandatory=$false,Position=3)]
    [ValidateSet('None','String','Binary','DWord','ExpandString','MultiString','QWord')]
    [Alias("PropertyType","t")]
    $Type,

    [Parameter(Mandatory=$false,Position=4)]
    [Alias("f")]
    [switch]$Force,

    [Parameter(Mandatory=$false)]
    [boolean]$TryLGPO,

    [Parameter(Mandatory=$false)]
    $LGPOExe = $Global:LGPOPath,

    [Parameter(Mandatory=$false)]
    [string]$LogPath,

    [Parameter(Mandatory=$false)]
    [switch]$RemoveFile

    )
    Begin
    {
        ## Get the name of this function
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name

        if (-not $PSBoundParameters.ContainsKey('Verbose')) {
            $VerbosePreference = $PSCmdlet.SessionState.PSVariable.GetValue('VerbosePreference')
        }

        if (-not $PSBoundParameters.ContainsKey('Confirm')) {
            $ConfirmPreference = $PSCmdlet.SessionState.PSVariable.GetValue('ConfirmPreference')
        }
        if (-not $PSBoundParameters.ContainsKey('WhatIf')) {
            $WhatIfPreference = $PSCmdlet.SessionState.PSVariable.GetValue('WhatIfPreference')
        }

    }
    Process
    {
        $RegKeyHive = ($RegPath).Split('\')[0].Replace('Registry::','').Replace(':','')

        #if Name not specified, grab last value from full path
        If(!$Name){
            $RegKeyPath = Split-Path ($RegPath).Split('\',2)[1] -Parent
            $RegKeyName = Split-Path ($RegPath).Split('\',2)[1] -Leaf
        }
        Else{
            $RegKeyPath = ($RegPath).Split('\',2)[1]
            $RegKeyName = $Name
        }

        #The -split operator supports specifying the maximum number of sub-strings to return.
        #Some values may have additional commas in them that we don't want to split (eg. LegalNoticeText)
        [String]$Value = $Value -split ',',2

        Switch($RegKeyHive){
            HKEY_LOCAL_MACHINE {$LGPOHive = 'Computer';$RegHive = 'HKLM:'}
            MACHINE {$LGPOHive = 'Computer';$RegHive = 'HKLM:'}
            HKLM {$LGPOHive = 'Computer';$RegHive = 'HKLM:'}
            HKEY_CURRENT_USER {$LGPOHive = 'User';$RegHive = 'HKCU:'}
            HKEY_USERS {$LGPOHive = 'User';$RegHive = 'Registry::HKEY_USERS'}
            HKCU {$LGPOHive = 'User';$RegHive = 'HKCU:'}
            HKU {$LGPOHive = 'User';$RegHive = 'Registry::HKEY_USERS'}
            USER {$LGPOHive = 'User';$RegHive = 'HKCU:'}
            default {$LGPOHive = 'Computer';$RegHive = 'HKLM:'}
        }

        #convert registry type to LGPO type
        Switch($Type){
            'None' {$LGPORegType = 'NONE'}
            'String' {$LGPORegType = 'SZ'}
            'ExpandString' {$LGPORegType = 'EXPAND_SZ'}
            'Binary' {$LGPORegType = 'BINARY'; $value = Convert-ToHexString $value}
            'DWord' {$LGPORegType = 'DWORD'}
            'QWord' {$LGPORegType = 'DWORD_BIG_ENDIAN'}
            'MultiString' {$LGPORegType = 'LINK'}
            default {$LGPORegType = 'DWORD'}
        }

        Try{
            #check if tryLGPO is set and path is set
            If($TryLGPO -and $LGPOExe)
            {
                #does LGPO path exist?
                If(Test-Path $LGPOExe)
                {
                    #$lgpoout = $null
                    $lgpoout = "; ----------------------------------------------------------------------`r`n"
                    $lgpoout += "; PROCESSING POLICY`r`n"
                    $lgpoout += "; Source file:`r`n"
                    $lgpoout += "`r`n"
                    
                    # build a unique output file
                    $LGPOfile = ($RegKeyHive + '-' + $RegKeyPath.replace('\','-').replace(' ','') + '-' + $RegKeyName.replace(' ','') + '.lgpo')
                    
                    #Remove the Username or SID from Registry key path
                    If($LGPOHive -eq 'User'){
                        $UserID = $RegKeyPath.Split('\')[0]
                        If($UserID -match "DEFAULT|S-1-5-21-(\d+-?){4}$"){
                            $RegKeyPath = $RegKeyPath.Replace($UserID+"\","")
                        }
                    }
                    #complete LGPO file
                    Write-LogEntry ("LGPO applying [{3}] to registry: [{0}\{1}\{2}] as a Group Policy item" -f $RegHive,$RegKeyPath,$RegKeyName,$RegKeyName) -Severity 4 -Source ${CmdletName}
                    $lgpoout += "$LGPOHive`r`n"
                    $lgpoout += "$RegKeyPath`r`n"
                    $lgpoout += "$RegKeyName`r`n"
                    $lgpoout += "$($LGPORegType):$Value`r`n"
                    $lgpoout += "`r`n"
                    $lgpoout | Out-File "$env:Temp\$LGPOfile"

                    If($VerbosePreference){$args = "/v /q /t"}Else{$args="/q /t"}
                    Write-LogEntry "Start-Process $LGPOExe -ArgumentList '/t $env:Temp\$LGPOfile' -RedirectStandardError '$env:Temp\$LGPOfile.stderr.log'" -Severity 4 -Source ${CmdletName}
                    
                    If(!$WhatIfPreference){$result = Start-Process $LGPOExe -ArgumentList "$args $env:Temp\$LGPOfile /v" -RedirectStandardError "$env:Temp\$LGPOfile.stderr.log" -Wait -NoNewWindow -PassThru | Out-Null}
                    Write-LogEntry ("LGPO ran successfully. Exit code: {0}" -f $result.ExitCode) -Severity 4
                }
                Else{
                    Write-LogEntry ("LGPO will not be used. Path not found: {0}" -f $LGPOExe) -Severity 3

                }
            }
            Else{
                Write-LogEntry ("LGPO not enabled. Hardcoding registry keys [{0}\{1}\{2}]...." -f $RegHive,$RegKeyPath,$RegKeyName) -Severity 0 -Source ${CmdletName}
            }
        }
        Catch{
            If($TryLGPO -and $LGPOExe){
                Write-LogEntry ("LGPO failed to run. exit code: {0}. Hardcoding registry keys [{1}\{2}\{3}]...." -f $result.ExitCode,$RegHive,$RegKeyPath,$RegKeyName) -Severity 3 -Source ${CmdletName}
            }
        }
        Finally
        {
            #wait for LGPO file to finish generating
            start-sleep 1
            
            #verify the registry value has been set
            Try{
                If( -not(Test-Path ($RegHive +'\'+ $RegKeyPath)) ){
                    Write-LogEntry ("Key was not set; Hardcoding registry keys [{0}\{1}] with value [{2}]...." -f ($RegHive +'\'+ $RegKeyPath),$RegKeyName,$Value) -Severity 0 -Source ${CmdletName}
                    New-Item -Path ($RegHive +'\'+ $RegKeyPath) -Force -WhatIf:$WhatIfPreference -ErrorAction SilentlyContinue | Out-Null
                    New-ItemProperty -Path ($RegHive +'\'+ $RegKeyPath) -Name $RegKeyName -PropertyType $Type -Value $Value -Force:$Force -WhatIf:$WhatIfPreference -ErrorAction SilentlyContinue -PassThru
                } 
                Else{
                    Write-LogEntry ("Key name not found. Creating key name [{1}] at path [{0}] with value [{2}]" -f ($RegHive +'\'+ $RegKeyPath),$RegKeyName,$Value) -Source ${CmdletName}
                    Set-ItemProperty -Path ($RegHive +'\'+ $RegKeyPath) -Name $RegKeyName -Value $Value -Force:$Force -WhatIf:$WhatIfPreference -ErrorAction SilentlyContinue -PassThru
                }
            }
            Catch{
                Write-LogEntry ("Unable to set registry key [{0}\{1}\{2}] with value [{3}]" -f $RegHive,$RegKeyPath,$RegKeyName,$Value) -Severity 2 -Source ${CmdletName}
            }

        }
    }
    End {
        #cleanup LGPO logs
        If(!$WhatIfPreference){$RemoveFile =  $false}

        If($LGPOfile -and (Test-Path "$env:Temp\$LGPOfile") -and $RemoveFile){
               Remove-Item "$env:Temp\$LGPOfile" -ErrorAction SilentlyContinue | Out-Null
               #Remove-Item "$env:Temp" -Include "$LGPOfile*" -Recurse -Force
        }
    }

}


Function Set-UserSetting {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact='Medium')]
    Param (
        [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [Alias("Path")]
        [string]$RegPath,

        [Parameter(Mandatory=$false,Position=1)]
        [Alias("v")]
        [string]$Name,

        [Parameter(Mandatory=$false,Position=2)]
        [Alias("d")]
        $Value,

        [Parameter(Mandatory=$false,Position=3)]
        [ValidateSet('None','String','Binary','DWord','ExpandString','MultiString','QWord')]
        [Alias("PropertyType","t")]
        [string]$Type,

        [Parameter(Mandatory=$false,Position=4)]
        [ValidateSet('CurrentUser','AllUsers','DefaultUser')]
        [Alias("Users")]
        [string]$ApplyTo = $Global:ApplyToProfiles,


        [Parameter(Mandatory=$false,Position=5)]
        [Alias("r")]
        [switch]$Remove,

        [Parameter(Mandatory=$false,Position=6)]
        [Alias("f")]
        [switch]$Force,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,

        [Parameter(Mandatory=$false)]
        [boolean]$TryLGPO,

        [Parameter(Mandatory=$false)]
        $LGPOExe = $Global:LGPOPath,

        [Parameter(Mandatory=$false)]
        [string]$LogPath

    )
    Begin
    {
        ## Get the name of this function
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name

        if (-not $PSBoundParameters.ContainsKey('Verbose')) {
            $VerbosePreference = $PSCmdlet.SessionState.PSVariable.GetValue('VerbosePreference')
        }

        if (-not $PSBoundParameters.ContainsKey('Confirm')) {
            $ConfirmPreference = $PSCmdlet.SessionState.PSVariable.GetValue('ConfirmPreference')
        }
        if (-not $PSBoundParameters.ContainsKey('WhatIf')) {
            $WhatIfPreference = $PSCmdlet.SessionState.PSVariable.GetValue('WhatIfPreference')
        }

        #If user profile variable doesn't exist, build one
        If(!$Global:UserProfiles){
            # Get each user profile SID and Path to the profile
            $AllProfiles = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" | Where-Object {$_.PSChildName -match "S-1-5-21-(\d+-?){4}$" } | 
                    Select-Object @{Name="SID"; Expression={$_.PSChildName}}, @{Name="UserHive";Expression={"$($_.ProfileImagePath)\NTuser.dat"}}, @{Name="UserName";Expression={Split-Path $_.ProfileImagePath -Leaf}}

            # Add in the DEFAULT User Profile (Not be confused with .DEFAULT)
            $DefaultProfile = "" | Select-Object SID, UserHive,UserName
            $DefaultProfile.SID = "DEFAULT"
            $DefaultProfile.Userhive = "$env:systemdrive\Users\Default\NTuser.dat"
            $DefaultProfile.UserName = "Default"

            #Add it to the UserProfile list
            $Global:UserProfiles = @()
            $Global:UserProfiles += $AllProfiles
            $Global:UserProfiles += $DefaultProfile

            #get current users sid
            [string]$CurrentSID = (Get-WmiObject win32_useraccount | Where-Object {$_.name -eq $env:username}).SID
        }
    }
    Process
    { 
        #grab the hive from the regpath
        $RegKeyHive = ($RegPath).Split('\')[0].Replace('Registry::','').Replace(':','')
        
        #Grab user keys and profiles based on whom it will be applied to
        Switch($ApplyTo){
            'AllUsers'      {$RegHive = 'HKEY_USERS'; $ProfileList = $Global:UserProfiles}
            'CurrentUser'   {$RegHive = 'HKCU'      ; $ProfileList = ($Global:UserProfiles | Where-Object{$_.SID -eq $CurrentSID})}
            'DefaultUser'   {$RegHive = 'HKU'       ; $ProfileList = $DefaultProfile}
            default         {$RegHive = $RegKeyHive ; $ProfileList = ($Global:UserProfiles | Where-Object{$_.SID -eq $CurrentSID})}
        }
        
        #check if hive is local machine.
        If($RegKeyHive -match "HKEY_LOCAL_MACHINE|HKLM|HKCR"){
            Write-LogEntry ("Registry path [{0}] is not a user path. Use Set-SystemSetting cmdlet instead" -f $RegKeyHive) -Severity 2 -Source ${CmdletName}
            return
        }
        #check if hive was found and is a user hive
        ElseIf($RegKeyHive -match "HKEY_USERS|HKEY_CURRENT_USER|HKCU|HKU"){
            #if Name not specified, grab last value from full path
             If(!$Name){
                 $RegKeyPath = Split-Path ($RegPath).Split('\',2)[1] -Parent
                 $RegKeyName = Split-Path ($RegPath).Split('\',2)[1] -Leaf
             }
             Else{
                 $RegKeyPath = ($RegPath).Split('\',2)[1]
                 $RegKeyName = $Name
             } 
        }
        ElseIf($ApplyTo){
            #if Name not specified, grab last value from full path
            If(!$Name){
                $RegKeyPath = Split-Path ($RegPath) -Parent
                $RegKeyName = Split-Path ($RegPath) -Leaf
            }
            Else{
                $RegKeyPath = $RegPath
                $RegKeyName = $Name
            } 
        }
        Else{
            Write-LogEntry ("User registry hive was not found or specified in Keypath [{0}]. Either use the -ApplyTo Switch or specify user hive [eg. HKCU\]..." -f $RegPath) -Severity 3 -Source ${CmdletName}
            return
        }
  
        #loope through profiles as long as the hive is not the current user hive
        If($RegHive -notmatch 'HKCU|HKEY_CURRENT_USER'){

            $p = 1
            # Loop through each profile on the machine
            Foreach ($UserProfile in $ProfileList) {
                
                Try{
                    $objSID = New-Object System.Security.Principal.SecurityIdentifier($UserProfile.SID)
                    $UserName = $objSID.Translate([System.Security.Principal.NTAccount]) 
                }
                Catch{
                    $UserName = $UserProfile.UserName
                }

                If($Message){Show-ProgressStatus -Message $Message -SubMessage ("(Users: {0} of {1})" -f $p,$ProfileList.count) -Step $p -MaxStep $ProfileList.count}

                #loadhive if not mounted
                If (($HiveLoaded = Test-Path Registry::HKEY_USERS\$($UserProfile.SID)) -eq $false) {
                    Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE LOAD HKU\$($UserProfile.SID) $($UserProfile.UserHive)" -Wait -WindowStyle Hidden
                    $HiveLoaded = $true
                }

                If ($HiveLoaded -eq $true) {   
                    If($Message){Write-LogEntry ("{0} for User [{1}]..." -f $Message,$UserName)}
                    If($Remove){
                        Remove-ItemProperty "$RegHive\$($UserProfile.SID)\$RegKeyPath" -Name $RegKeyName -Force:$Force -WhatIf:$WhatIfPreference -ErrorAction SilentlyContinue | Out-Null  
                    }
                    Else{
                        Set-SystemSetting -Path "$RegHive\$($UserProfile.SID)\$RegKeyPath" -Name $RegKeyName -Type $Type -Value $Value -Force:$Force -WhatIf:$WhatIfPreference -TryLGPO:$TryLGPO
                    }
                }

                #remove any leftover reg process and then remove hive
                If ($HiveLoaded -eq $true) {
                    [gc]::Collect()
                    Start-Sleep -Seconds 3
                    Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE UNLOAD HKU\$($UserProfile.SID)" -Wait -PassThru -WindowStyle Hidden | Out-Null
                }
                $p++
            }
        }
        Else{
            If($Message){Write-LogEntry ("{0} for [{1}]..." -f $Message,$ProfileList.UserName)}
            If($Remove){
                Remove-ItemProperty "$RegHive\$RegKeyPath\$RegKeyPath" -Name $RegKeyName -Force:$Force -WhatIf:$WhatIfPreference -ErrorAction SilentlyContinue | Out-Null  
            }
            Else{
                Set-SystemSetting -Path "$RegHive\$RegKeyPath" -Name $RegKeyName -Type $Type -Value $Value -Force:$Force -WhatIf:$WhatIfPreference -TryLGPO:$TryLGPO
            }
        }

    }
    End {
       If($Message){Show-ProgressStatus -Message "Completed $Message"  -Step 1 -MaxStep 1}
    }
}

function Set-PowerPlan {
    <#
     Get-WmiObject -Class Win32_PowerPlan -Namespace root\cimv2\power -Filter "ElementName= 'Balanced'" | Invoke-WmiMethod -Name Activate | Out-Null
    Start-Process "C:\Windows\system32\powercfg.exe" -ArgumentList "-SETACTIVE 381b4222-f694-41f0-9685-ff5bb260df2e" -Wait -NoNewWindow
    Start-Process "C:\Windows\system32\powercfg.exe" -ArgumentList "-x -standby-timeout-ac 0" -Wait -NoNewWindow
    #>
    [CmdletBinding(SupportsShouldProcess = $True)]
    param (

        [ValidateSet("High performance", "Balanced", "Power saver")]
        [ValidateNotNullOrEmpty()]
        [string]$PreferredPlan = "High Performance",
        
        [ValidateSet("On", "Off")]
        [string]$Hibernate,

        [ValidateRange(0,120)]
        [int32]$ACTimeout,

        [ValidateRange(0,120)]
        [int32]$DCTimeout,

        [ValidateRange(0,120)]
        [int32]$ACMonitorTimeout,

        [ValidateRange(0,120)]
        [int32]$DCMonitorTimeout,

        [string]$ComputerName = $env:COMPUTERNAME
    )
    Begin
    {
        ## Get the name of this function
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name

        if (-not $PSBoundParameters.ContainsKey('Verbose')) {
            $VerbosePreference = $PSCmdlet.SessionState.PSVariable.GetValue('VerbosePreference')
        }

        if (-not $PSBoundParameters.ContainsKey('Confirm')) {
            $ConfirmPreference = $PSCmdlet.SessionState.PSVariable.GetValue('ConfirmPreference')
        }
        if (-not $PSBoundParameters.ContainsKey('WhatIf')) {
            $WhatIfPreference = $PSCmdlet.SessionState.PSVariable.GetValue('WhatIfPreference')
        }

    }
    Process
    {
        Write-LogEntry ("Setting power plan to `"{0}`"" -f $PreferredPlan) -Source ${CmdletName}

        $guid = (Get-WmiObject -Class Win32_PowerPlan -Namespace root\cimv2\power -Filter "ElementName='$PreferredPlan'" -ComputerName $ComputerName).InstanceID.ToString()
        $regex = [regex]"{(.*?)}$"
        $plan = $regex.Match($guid).groups[1].value

        $process = Get-WmiObject -Query "SELECT * FROM Meta_Class WHERE __Class = 'Win32_Process'" -Namespace "root\cimv2" -ComputerName $ComputerName
        Try{
            If($VerbosePreference){Write-LogEntry ("COMMAND: powercfg -S $plan") -Severity 4 -Source ${CmdletName} -Outhost}
            $process.Create("powercfg -S $plan") | Out-Null
        }
        Catch{
            Write-LogEntry ("Failed to create power confugration:" -f $_.Exception.Message) -Severity 3 -Source ${CmdletName} -Outhost
        }

        $Output = "Power plan set to "
        $Output += "`"" + ((Get-WmiObject -Class Win32_PowerPlan -Namespace root\cimv2\power -Filter "IsActive='$True'" -ComputerName $ComputerName).ElementName) + "`""

        $params = ""

        If($Hibernate){
                $params += "-H $Hibernate"
                $Output += " with hibernate set to [$Hibernate]" 
        }

        If(($ACTimeout -ge 0) -or ($DCTimeout -ge 0) -or ($ACMonitorTimeout -ge 0) -or ($DCMonitorTimeout -ge 0)){$params += " -x "}
        
        If($ACTimeout -ge 0){
                $params += "-standby-timeout-ac $ACTimeout "
                $Output += " . The AC System timeout was set to [$($ACTimeout.ToString())]" 
        }

        If($DCTimeout -ge 0){
                $params += "-standby-timeout-dc $DCTimeout "
                $Output += " . The DC System timeout was set to [$($DCTimeout.ToString())]" 
        }

        If($ACMonitorTimeout -ge 0){
                $params += "-standby-timeout-ac $ACMonitorTimeout "
                $Output += " . The AC Monitor timeout was set to [$($ACMonitorTimeout.ToString())]" 
        }

        If($DCMonitorTimeout -ge 0){
                $params += "-standby-timeout-dc $DCMonitorTimeout "
                $Output += " . The DC Monitor timeout was set to [$($DCMonitorTimeout.ToString())]" 
        }

        Try{
            If($VerbosePreference){Write-LogEntry ("COMMAND: powercfg $params") -Severity 4 -Source ${CmdletName} -Outhost}
            $process.Create("powercfg $params") | Out-Null
        }
        Catch{
            Write-LogEntry ("Failed to set power confugration:" -f $_.Exception.Message) -Severity 3 -Source ${CmdletName} -Outhost
        }
    }
    End {
        #Write-Host $Output
        Write-LogEntry ("{0}" -f $Output) -Source ${CmdletName}
    }
}


Function Copy-ItemWithProgress
{
    [CmdletBinding()]
    Param
    (
    [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true,Position=0)]
    [string]$Source,
    [Parameter(Mandatory=$true,Position=1)]
    [string]$Destination,
    [Parameter(Mandatory=$false,Position=3)]
    [switch]$Force
    )

    Begin{
        $Source = $Source
    
        #get the entire folder structure
        $Filelist = Get-Childitem $Source -Recurse

        #get the count of all the objects
        $Total = $Filelist.count

        #establish a counter
        $Position = 0
    }
    Process{
        #Stepping through the list of files is quite simple in PowerShell by using a For loop
        foreach ($File in $Filelist)

        {
            #On each file, grab only the part that does not include the original source folder using replace
            $Filename = ($File.Fullname).replace($Source,'')
        
            #rebuild the path for the destination:
            $DestinationFile = ($Destination+$Filename)
        
            #get just the folder path
            $DestinationPath = Split-Path $DestinationFile -Parent

            #show progress
            Show-ProgressStatus -Message "Copying data from $source to $Destination" -Step (($Position/$total)*100) -MaxStep $total

            #create destination directories
            If (-not (Test-Path $DestinationPath) ) {
                New-Item $DestinationPath -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
            }

            #do copy (enforce)
            Try{
                Copy-Item $File.FullName -Destination $DestinationFile -Force:$Force -ErrorAction:$VerbosePreference -Verbose:($PSBoundParameters['Verbose'] -eq $true) | Out-Null
                Write-Verbose ("Copied file [{0}] to [{1}]" -f $File.FullName,$DestinationFile)
            }
            Catch{
                Write-Host ("Unable to copy file in {0} to {1}; Error: {2}" -f $File.FullName,$DestinationFile ,$_.Exception.Message) -ForegroundColor Red
                break
            }
            #bump up the counter
            $Position++
        }
    }
    End{
        Show-ProgressStatus -Message "Copy completed" -Step $total -MaxStep $total
    }
}

##*===========================================================================
##* VARIABLES
##*===========================================================================
# Use function to get paths because Powershell ISE and other editors have differnt results
$scriptPath = Get-ScriptPath
[string]$scriptDirectory = Split-Path $scriptPath -Parent
[string]$scriptName = Split-Path $scriptPath -Leaf
[string]$scriptBaseName = [System.IO.Path]::GetFileNameWithoutExtension($scriptName)

[int]$OSBuildNumber = (Get-WmiObject -Class Win32_OperatingSystem).BuildNumber
[string]$OsCaption = (Get-WmiObject -class Win32_OperatingSystem).Caption

#Create Paths
$ToolsPath = Join-Path $scriptDirectory -ChildPath 'Tools'
$AdditionalScriptsPath = Join-Path $scriptDirectory -ChildPath 'Scripts'
$ModulesPath = Join-Path -Path $scriptDirectory -ChildPath 'PSModules'
$BinPath = Join-Path -Path $scriptDirectory -ChildPath 'Bin'
$FilesPath = Join-Path -Path $scriptDirectory -ChildPath 'Files'


#check if running in verbose mode
$Global:Verbose = $false
If($PSBoundParameters.ContainsKey('Debug') -or $PSBoundParameters.ContainsKey('Verbose')){
    $Global:Verbose = $PsBoundParameters.Get_Item('Verbose')
    $VerbosePreference = 'Continue'
    Write-Verbose ("[{0}] [{1}] :: VERBOSE IS ENABLED." -f (Format-DatePrefix),$scriptName)
}
Else{
    $VerbosePreference = 'SilentlyContinue'
}

#build log name
[string]$FileName = $scriptBaseName +'.log'
#build global log fullpath
$Global:LogFilePath = Join-Path (Get-SMSTSENV -ReturnLogPath -NoWarning) -ChildPath $FileName
Write-Host "logging to file: $LogFilePath" -ForegroundColor Cyan

##*===========================================================================
##* DEFAULTS: Configurations are here (change values if needed)
##*===========================================================================
# Global Settings
[boolean]$DisableScript = $false
[boolean]$UseLGPO = $true
[string]$Global:LGPOPath = "$ToolsPath\LGPO\LGPO.exe"
# VDI Preference
[boolean]$OptimizeForVDI = $false 
[boolean]$EnableVisualPerformance = $false
# User Preference
[boolean]$InstallLogonScript = $false
[string]$LogonScriptPath = "$PSscriptRoot\Win10-Logon.ps1"
[boolean]$EnableDarkTheme = $true
[boolean]$EnableTaskbarAutoColor = $false
[boolean]$DisableFontSmoothing = $false
[boolean]$CleanSampleFolders = $false
[boolean]$DisableCortana = $false
[boolean]$DisableInternetSearch = $false 
[boolean]$EnableOfficeOneNote = $false
[boolean]$DisableOneDrive = $false
[boolean]$DisableWindowsFirstLoginAnimation = $false
[boolean]$DisableIEFirstRunWizard = $false
[boolean]$DisableWMPFirstRunWizard = $false
[boolean]$ShowKnownExtensions = $false
[boolean]$ShowHiddenFiles = $false
[boolean]$ShowThisPCOnDesktop = $false
[boolean]$ShowUserFolderOnDesktop = $false
[boolean]$RemoveRecycleBinOnDesktop = $false
[boolean]$Hide3DObjectsFromExplorer = $false
[boolean]$DisableEdgeShortcutCreation = $false
[boolean]$DisableStoreOnTaskbar = $false
[boolean]$DisableActivityHistory = $false
[string]$SetSmartScreenFilter = 'User' # Set to 'Off','User','Admin'
[boolean]$EnableNumlockStartup = $false
[boolean]$DisableAppSuggestions = $false
# System Settings
[boolean]$InstallPSModules = $false
[psobject]$InstallModules = Get-ChildItem $ModulesPath -Filter *.psm1 -Recurse
[string]$SetPowerCFG = 'Custom' # Set 'Custom','High Performance','Balanced'
[string]$PowerCFGFilePath = "$FilesPath\AlwaysOnPowerScheme.pow"
[boolean]$EnableIEEnterpriseMode = $false
[string]$IEEMSiteListPath = ''
[boolean]$ApplyCustomHost = $false
[string]$HostPath = "$FilesPath\WindowsTelemetryhosts"
[boolean]$EnableSecureLogonCAD = $false
[boolean]$DisableAllNotifications = $false
[boolean]$EnableVerboseStatusMsg = $false
[boolean]$DisableAutoRun = $false
[boolean]$PreferIPv4OverIPv6 = $false
[boolean]$EnableAppsRunAsAdmin = $false
[boolean]$HideDrivesWithNoMedia = $false
[boolean]$DisableActionCenter = $false
[boolean]$DisableFeedback = $false
[boolean]$DisableWUP2P = $false
[boolean]$DisablePreviewBuild = $false
[boolean]$DisableDriverUpdates = $false
[boolean]$DisableWindowsUpgrades = $false
[boolean]$ApplyPrivacyMitigations = $false
[boolean]$RemoveRebootOnLockScreen = $false
[boolean]$RemoveUnusedPrinters = $false
# System Adv Settings
[boolean]$DisableSmartCardLogon = $false
[boolean]$ForceStrictSmartCardLogon = $false
[boolean]$EnableFIPS = $false
[boolean]$EnableCredGuard = $false
[boolean]$DisableUAC = $false
[boolean]$EnableStrictUAC = $false
[boolean]$EnableRDP = $false
[boolean]$EnableWinRM = $false
[boolean]$EnableRemoteRegistry = $false
[boolean]$EnableUEV = $false
[boolean]$EnableAppV = $false
[boolean]$EnablePSLogging = $false
[boolean]$EnableLinuxSubSystem = $false
[boolean]$DisableAdminShares = $false
[boolean]$DisableSchTasks = $false
[boolean]$DisableDefender = $false
[boolean]$DisableFirewall = $false
[boolean]$DisableWireless = $false
[boolean]$DisableBluetooth = $false
[boolean]$DisableNewNetworkDialog = $false
[boolean]$DisableInternetServices = $false
[boolean]$DisabledUnusedServices = $false
[boolean]$DisabledUnusedFeatures = $false
[boolean]$DisableIndexing = $false
[boolean]$RemoveActiveSetupComponents = $false
[boolean]$PreCompileAssemblies = $false
[boolean]$OptimizeNetwork = $false


# Configurations comes from Tasksequence
# When running in Tasksequence and configureation exists, use that instead
If(Get-SMSTSENV){
    # Global Settings
    If($tsenv:CFG_DisableConfigScript){[boolean]$DisableScript = [boolean]::Parse($tsenv.Value("CFG_DisableConfigScript"))}
    If($tsenv:CFG_UseLGPOForConfigs){[boolean]$UseLGPO = [boolean]::Parse($tsenv.Value("CFG_UseLGPOForConfigs"))}
    If($tsenv:LGPOPath){[string]$Global:LGPOPath = $tsenv.Value("LGPOPath")}
    # VDI Preference
    If($tsenv:CFG_OptimizeForVDI){[boolean]$OptimizeForVDI = [boolean]::Parse($tsenv.Value("CFG_OptimizeForVDI"))} 
    If($tsenv:CFG_EnableVisualPerformance){[boolean]$EnableVisualPerformance = [boolean]::Parse($tsenv.Value("CFG_EnableVisualPerformance"))}
    # User Preference
    If($tsenv:CFG_InstallLogonScript){[boolean]$InstallLogonScript = [boolean]::Parse($tsenv.Value("CFG_InstallLogonScript"))}
    If($tsenv:CFG_LogonScriptPath){[string]$LogonScriptPath = $tsenv.Value("CFG_LogonScriptPath")}
    If($tsenv:CFG_EnableDarkTheme){[boolean]$EnableDarkTheme = [boolean]::Parse($tsenv.Value("CFG_EnableDarkTheme"))}
    If($tsenv:CFG_EnableTaskbarAutoColor){[boolean]$EnableTaskbarAutoColor = [boolean]::Parse($tsenv.Value("CFG_EnableTaskbarAutoColor"))}
    If($tsenv:CFG_DisableFontSmoothing){[boolean]$DisableFontSmoothing = [boolean]::Parse($tsenv.Value("CFG_DisableFontSmoothing"))}
    If($tsenv:CFG_DisableCortana){[boolean]$DisableCortana = [boolean]::Parse($tsenv.Value("CFG_DisableCortana"))}
    If($tsenv:CFG_DisableInternetSearch){[boolean]$DisableInternetSearch = [boolean]::Parse($tsenv.Value("CFG_DisableInternetSearch"))} 
    If($tsenv:CFG_EnableOfficeOneNote){[boolean]$EnableOfficeOneNote = [boolean]::Parse($tsenv.Value("CFG_EnableOfficeOneNote"))}
    If($tsenv:CFG_DisableOneDrive){[boolean]$DisableOneDrive = [boolean]::Parse($tsenv.Value("CFG_DisableOneDrive"))}
    If($tsenv:CFG_DisableWindowsFirstLoginAnimation){[boolean]$DisableWindowsFirstLoginAnimation = [boolean]::Parse($tsenv.Value("CFG_DisableWindowsFirstLoginAnimation"))}
    If($tsenv:CFG_DisableIEFirstRunWizard){[boolean]$DisableIEFirstRunWizard = [boolean]::Parse($tsenv.Value("CFG_DisableIEFirstRunWizard"))}
    If($tsenv:CFG_DisableWMPFirstRunWizard){[boolean]$DisableWMPFirstRunWizard = [boolean]::Parse($tsenv.Value("CFG_DisableWMPFirstRunWizard"))}
    If($tsenv:CFG_ShowKnownExtensions){[boolean]$ShowKnownExtensions = [boolean]::Parse($tsenv.Value("CFG_ShowKnownExtensions"))}
    If($tsenv:CFG_ShowHiddenFiles){[boolean]$ShowHiddenFiles = [boolean]::Parse($tsenv.Value("CFG_ShowHiddenFiles"))}
    If($tsenv:CFG_ShowThisPCOnDesktop){[boolean]$ShowThisPCOnDesktop = [boolean]::Parse($tsenv.Value("CFG_ShowThisPCOnDesktop"))}
    If($tsenv:CFG_ShowUserFolderOnDesktop){[boolean]$ShowUserFolderOnDesktop = [boolean]::Parse($tsenv.Value("CFG_ShowUserFolderOnDesktop"))}
    If($tsenv:CFG_RemoveRecycleBinOnDesktop){[boolean]$RemoveRecycleBinOnDesktop = [boolean]::Parse($tsenv.Value("CFG_RemoveRecycleBinOnDesktop"))}
    If($tsenv:CFG_Hide3DObjectsFromExplorer){[boolean]$Hide3DObjectsFromExplorer = [boolean]::Parse($tsenv.Value("CFG_Hide3DObjectsFromExplorer"))}
    If($tsenv:CFG_DisableEdgeShortcut){[boolean]$DisableEdgeShortcutCreation = [boolean]::Parse($tsenv.Value("CFG_DisableEdgeShortcut"))}
    If($tsenv:CFG_DisableStoreOnTaskbar){[boolean]$DisableStoreOnTaskbar = [boolean]::Parse($tsenv.Value("CFG_DisableStoreOnTaskbar"))}
    If($tsenv:CFG_DisableActivityHistory){[boolean]$DisableActivityHistory = [boolean]::Parse($tsenv.Value("CFG_DisableActivityHistory"))}
    If($tsenv:CFG_SetSmartScreenFilter){[string]$SetSmartScreenFilter = $tsenv.Value("CFG_SetSmartScreenFilter")}
    If($tsenv:CFG_EnableNumlockStartup){[boolean]$EnableNumlockStartup = [boolean]::Parse($tsenv.Value("CFG_EnableNumlockStartup"))}
    If($tsenv:CFG_DisableAppSuggestions){[boolean]$DisableAppSuggestions = [boolean]::Parse($tsenv.Value("CFG_DisableAppSuggestions"))}
    # System Settings
    If($tsenv:CFG_InstallPSModules){[boolean]$InstallPSModules = [boolean]::Parse($tsenv.Value("CFG_InstallPSModules"))}
    If($tsenv:CFG_SetPowerCFG){[string]$SetPowerCFG = $tsenv.Value("CFG_SetPowerCFG")}
    If($tsenv:CFG_PowerCFGFilePath){[string]$PowerCFGFilePath = $tsenv.Value("CFG_PowerCFGFilePath")}
    If($tsenv:CFG_EnableIEEnterpriseMode){[boolean]$EnableIEEnterpriseMode = [boolean]::Parse($tsenv.Value("CFG_EnableIEEnterpriseMode"))}
    If($tsenv:CFG_IEEMSiteListPath){[string]$IEEMSiteListPath = $tsenv.Value("CFG_IEEMSiteListPath")}
    If($tsenv:CFG_ApplyCustomHost){[boolean]$ApplyCustomHost = [boolean]::Parse($tsenv.Value("CFG_ApplyCustomHost"))}
    If($tsenv:HostPath){[string]$HostPath = $tsenv.Value("HostPath")}
    If($tsenv:CFG_EnableSecureLogonCAD){[boolean]$EnableSecureLogonCAD = [boolean]::Parse($tsenv.Value("CFG_EnableSecureLogonCAD"))}
    If($tsenv:CFG_DisableAllNotifications){[boolean]$DisableAllNotifications = [boolean]::Parse($tsenv.Value("CFG_DisableAllNotifications"))}
    If($tsenv:CFG_EnableVerboseMsg){[boolean]$EnableVerboseStatusMsg = [boolean]::Parse($tsenv.Value("CFG_EnableVerboseMsg"))}
    If($tsenv:CFG_DisableAutoRun){[boolean]$DisableAutoRun = [boolean]::Parse($tsenv.Value("CFG_DisableAutorun"))}
    If($tsenv:CFG_PreferIPv4OverIPv6){[boolean]$PreferIPv4OverIPv6 = [boolean]::Parse($tsenv.Value("CFG_PreferIPv4OverIPv6"))}
    If($tsenv:CFG_EnableAppsRunAsAdmin){[boolean]$EnableAppsRunAsAdmin = [boolean]::Parse($tsenv.Value("CFG_EnableAppsRunAsAdmin"))}
    If($tsenv:CFG_HideDrives){[boolean]$HideDrivesWithNoMedia = [boolean]::Parse($tsenv.Value("CFG_HideDrives"))}
    If($tsenv:CFG_DisableActionCenter){[boolean]$DisableActionCenter = [boolean]::Parse($tsenv.Value("CFG_DisableActionCenter"))}
    If($tsenv:CFG_DisableFeedback){[boolean]$DisableFeedback = [boolean]::Parse($tsenv.Value("CFG_DisableFeedback"))}
    If($tsenv:CFG_DisableWUP2P){[boolean]$DisableWUP2P = [boolean]::Parse($tsenv.Value("CFG_DisableWUP2P"))}
    If($tsenv:CFG_DisablePreviewBuild){[boolean]$DisablePreviewBuild = [boolean]::Parse($tsenv.Value("CFG_DisablePreviewBuild"))}
    If($tsenv:CFG_DisableDriverUpdates){[boolean]$DisableDriverUpdates = [boolean]::Parse($tsenv.Value("CFG_DisableDriverUpdates"))}
    If($tsenv:CFG_DisableWindowsUpgrades){[boolean]$DisableWindowsUpgrades = [boolean]::Parse($tsenv.Value("CFG_DisableWindowsUpgrades"))}
    If($tsenv:CFG_ApplyPrivacyMitigations){[boolean]$ApplyPrivacyMitigations = [boolean]::Parse($tsenv.Value("CFG_ApplyPrivacyMitigations"))}
    If($tsenv:CFG_RemoveRebootOnLockScreen){[boolean]$RemoveRebootOnLockScreen = [boolean]::Parse($tsenv.Value("CFG_RemoveRebootOnLockScreen"))}
    If($tsenv:CFG_RemoveUnusedPrinters){[boolean]$RemoveUnusedPrinters = [boolean]::Parse($tsenv.Value("CFG_RemoveUnusedPrinters"))}
    # System Adv Settings
    If($tsenv:CFG_DisableSmartCardLogon){[boolean]$DisableSmartCardLogon = [boolean]::Parse($tsenv.Value("CFG_DisableSmartCardLogon"))}
    If($tsenv:CFG_ForceStrictSmartCardLogon){[boolean]$ForceStrictSmartCardLogon = [boolean]::Parse($tsenv.Value("CFG_ForceStrictSmartCardLogon"))}
    If($tsenv:CFG_EnableFIPS){[boolean]$EnableFIPS = [boolean]::Parse($tsenv.Value("CFG_EnableFIPS"))}
    If($tsenv:CFG_EnableCredGuard){[boolean]$EnableCredGuard = [boolean]::Parse($tsenv.Value("CFG_EnableCredGuard"))}
    If($tsenv:CFG_DisableUAC){[boolean]$DisableUAC = [boolean]::Parse($tsenv.Value("CFG_DisableUAC"))}
    If($tsenv:CFG_EnableStrictUAC){[boolean]$EnableStrictUAC = [boolean]::Parse($tsenv.Value("CFG_EnableStrictUAC"))}
    If($tsenv:CFG_EnableRDP){[boolean]$EnableRDP = [boolean]::Parse($tsenv.Value("CFG_EnableRDP"))}
    If($tsenv:CFG_EnableWinRM){[boolean]$EnableWinRM = [boolean]::Parse($tsenv.Value("CFG_EnableWinRM"))}
    If($tsenv:CFG_EnableRemoteRegistry){[boolean]$EnableRemoteRegistry = [boolean]::Parse($tsenv.Value("CFG_EnableRemoteRegistry"))}
    If($tsenv:CFG_EnableUEV){[boolean]$EnableUEV = [boolean]::Parse($tsenv.Value("CFG_EnableUEV"))}
    If($tsenv:CFG_EnableAppV){[boolean]$EnableAppV = [boolean]::Parse($tsenv.Value("CFG_EnableAppV"))}
    If($tsenv:CFG_EnablePSLogging){[boolean]$EnablePSLogging = [boolean]::Parse($tsenv.Value("CFG_EnablePSLogging"))}
    If($tsenv:CFG_EnableLinuxSubSystem){[boolean]$EnableLinuxSubSystem = [boolean]::Parse($tsenv.Value("CFG_EnableLinuxSubSystem"))}
    If($tsenv:CFG_DisableAdminShares){[boolean]$DisableAdminShares = [boolean]::Parse($tsenv.Value("CFG_DisableAdminShares"))}
    If($tsenv:CFG_DisableSchTasks){[boolean]$DisableSchTasks = [boolean]::Parse($tsenv.Value("CFG_DisableSchTasks"))}
    If($tsenv:CFG_DisableDefender){[boolean]$DisableDefender = [boolean]::Parse($tsenv.Value("CFG_DisableDefender"))}
    If($tsenv:CFG_DisableFirewall){[boolean]$DisableFirewall = [boolean]::Parse($tsenv.Value("CFG_DisableFirewall"))}
    If($tsenv:CFG_DisableWireless){[boolean]$DisableWireless = [boolean]::Parse($tsenv.Value("CFG_DisableWireless"))}
    If($tsenv:CFG_DisableBluetooth){[boolean]$DisableBluetooth = [boolean]::Parse($tsenv.Value("CFG_DisableBluetooth"))}
    If($tsenv:CFG_DisableNewNetworkDialog){[boolean]$DisableNewNetworkDialog = [boolean]::Parse($tsenv.Value("CFG_DisableNewNetworkDialog"))}
    If($tsenv:CFG_DisableInternetServices){[boolean]$DisableInternetServices = [boolean]::Parse($tsenv.Value("CFG_DisableInternetServices"))}
    If($tsenv:CFG_DisabledUnusedServices){[boolean]$DisabledUnusedServices = [boolean]::Parse($tsenv.Value("CFG_DisabledUnusedServices"))}
    If($tsenv:CFG_DisabledUnusedFeatures){[boolean]$DisabledUnusedFeatures = [boolean]::Parse($tsenv.Value("CFG_DisabledUnusedFeatures"))}
    If($tsenv:CFG_DisableIndexing){[boolean]$DisableIndexing = [boolean]::Parse($tsenv.Value("CFG_DisableIndexing"))}
    If($tsenv:CFG_RemoveActiveSetupComponents){[boolean]$RemoveActiveSetupComponents = [boolean]::Parse($tsenv.Value("CFG_RemoveActiveSetupComponents"))}
    If($tsenv:CFG_PreCompileAssemblies){[boolean]$PreCompileAssemblies = [boolean]::Parse($tsenv.Value("CFG_PreCompileAssemblies"))}
    If($tsenv:CFG_OptimizeNetwork){[boolean]$OptimizeNetwork = [boolean]::Parse($tsenv.Value("CFG_OptimizeNetwork"))}
}

# Ultimately disable the entire script. This is useful for testing and using one task sequences with many rules
If($DisableScript){
    Write-LogEntry "Script is disabled!"
    Exit 0
}

#check if LGPO file exists in Tools directory or Specified LGPOPath
$FindLGPO = Get-ChildItem $Global:LGPOPath -Filter LGPO.exe -ErrorAction SilentlyContinue
If($FindLGPO){
    $Global:LGPOPath = $FindLGPO.FullName
}
Else{
    $UseLGPO = $false
}

# Get Onenote paths
$OneNotePathx86 = Get-ChildItem "${env:ProgramFiles(x86)}" -Recurse -Filter "ONENOTE.EXE"
$OneNotePathx64 = Get-ChildItem "$env:ProgramFiles" -Recurse -Filter "ONENOTE.EXE"
If($OneNotePathx86){$OneNotePath = $OneNotePathx86}
If($OneNotePathx64){$OneNotePath = $OneNotePathx64}

#if running in a tasksequence; apply user settings to all user profiles (use ApplyTo param cmdlet Set-UserSettings )
If(Get-SMSTSENV -NoWarning){$Global:ApplyToProfiles = 'AllUsers'}Else{$Global:ApplyToProfiles = 'CurrentUser'}
If((Get-SMSTSENV -NoWarning) -and -not($psISE)){$Global:OutTohost = $false}Else{$Global:OutTohost = $true}

#grab all Show-ProgressStatus commands in script and count them
$script:Maxsteps = ([System.Management.Automation.PsParser]::Tokenize((Get-Content $scriptPath), [ref]$null) | Where-Object { $_.Type -eq 'Command' -and $_.Content -eq 'Show-ProgressStatus' }).Count
#set counter to one
$stepCounter = 1
##*===========================================================================
##* MAIN
##*===========================================================================
If ($InstallPSModules)
{
    $CFGMessage = "Installing PowerShell Modules"
    Show-ProgressStatus -Message $CFGMessage -Step ($stepCounter++) -MaxStep $script:Maxsteps

    If(Test-Path "$BinPath\nuget"){
        #Install Nuget prereq
        $NuGetAssemblySourcePath = Get-ChildItem "$BinPath\nuget" -Recurse -Filter *.dll
        If($NuGetAssemblySourcePath){
            $NuGetAssemblyVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($NuGetAssemblySourcePath.FullName).FileVersion
            $NuGetAssemblyDestPath = "$env:ProgramFiles\PackageManagement\ProviderAssemblies\nuget\$NuGetAssemblyVersion"
            If (!(Test-Path $NuGetAssemblyDestPath)){
                Write-LogEntry ("Copying nuget Assembly [{0}] to [{1}]..." -f $NuGetAssemblyVersion,$NuGetAssemblyDestPath)
                New-Item $NuGetAssemblyDestPath -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
                Copy-ItemWithProgress -Source $NuGetAssemblySourcePath.FullName -Destination $NuGetAssemblyDestPath
            }
        }
    }

    If($InstallModules.count -gt 0){
        Foreach($module in $InstallModules){
            
            #remove the modules path from the full path to get the sub folders
            $Startfolders = ($module.FullName).replace("$modulesPath\","")

            #only need the fist folder after modules path
            $ModuleFolder = $Startfolders.split("\")[0]

            #copy the root directory and its contents
            Copy-ItemWithProgress -Source "$modulesPath\$ModuleFolder" -Destination "$env:ProgramFiles\WindowsPowerShell\Modules\$ModuleFolder" -Force
            
            #now grab the copied module location (search for the psm1)
            #$copiedmodule = Get-ChildItem "$env:ProgramFiles\WindowsPowerShell\Modules\$ModuleFolder" -Filter *.psm1 -Recurse | select -First 1
            #Import-Module -name $copiedmodule.FullName -Global -NoClobber -Force | Out-Null
        }
    }

}
Else{$stepCounter++}


If($RemoveRebootOnLockScreen){
    Show-ProgressStatus -Message "Disabling Shutdown on Lock screen..." -Step ($stepCounter++) -MaxStep $script:Maxsteps
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ShutdownWithoutLogon' -Type DWord -Value '0' -Force -TryLGPO:$true
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'DisablePasswordChange' -Type DWord -Value '1' -Force
}
Else{$stepCounter++}


If($DisableActionCenter)
{
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:45] :: "}
    $CFGMessage = "Disabling Windows Action Center Notifications"
    Show-ProgressStatus -Message("{0}{1}" -f $prefixmsg,$CFGMessage) -Step ($stepCounter++) -MaxStep $script:Maxsteps

    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell' -Name 'UseActionCenterExperience' -Type DWord -Value 0 -Force
    
    Set-UserSetting -Message $CFGMessage -Path 'SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'DisableNotificationCenter' -Type DWord -Value 1 -Force -TryLGPO:$true
    Set-UserSetting -Message $CFGMessage -Path 'SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'DisableNotificationCenter' -Type DWord -Value 1 -Force -TryLGPO:$true

}
Else{$stepCounter++}


If($DisableFeedback)
{
    $CFGMessage = "Disabling Feedback Notifications"
    #Show-ProgressStatus -Message $CFGMessage -Step ($stepCounter++) -MaxStep $script:Maxsteps

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:7] [Optional] :: "}
    Set-UserSetting -Message ("{1}{0}" -f $CFGMessage,$prefixmsg) -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name 'NumberOfSIUFInPeriod' -Type DWord -Value 0 -Force
    Set-UserSetting -Message ("{1}{0}" -f $CFGMessage,$prefixmsg) -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name 'PeriodInNanoSeconds' -Type DWord -Value 0 -Force

    Write-LogEntry "Disabling all feedback Scheduled Tasks..."
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null

    Write-LogEntry "Disabling all feedback notifications..."
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'DoNotShowFeedbackNotifications' -Type DWord -Value '1' -Force -TryLGPO:$true

}
Else{$stepCounter++}


If($DisableWindowsUpgrades)
{
    Show-ProgressStatus -Message "Disabling Windows Upgrades from Windows Updates..." -Step ($stepCounter++) -MaxStep $script:Maxsteps

    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Gwx' -Name 'DisableGwx' -Type DWord -Value 1 -Force | Out-Null
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'DisableOSUpgrade' -Type DWord -Value 1 -Force | Out-Null

    Write-LogEntry "Disabling access the Insider build controls in the Advanced Options "
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'LimitEnhancedDiagnosticDataWindowsAnalytics' -Type DWord -Value 1 -Force | Out-Null  
}
Else{$stepCounter++}


If($DisableDriverUpdates)
{
    Show-ProgressStatus -Message "Disabling driver offering through Windows Update..." -Step ($stepCounter++) -MaxStep $script:Maxsteps
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata' -Name 'PreventDeviceMetadataFromNetwork' -Type DWord -Value 1 -Force -TryLGPO:$true
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching' -Name 'DontPromptForWindowsUpdate' -Type DWord -Value 1 -Force -TryLGPO:$true
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching' -Name 'DontSearchWindowsUpdate' -Type DWord -Value 1 -Force -TryLGPO:$true
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching' -Name 'DriverUpdateWizardWuSearchEnabled' -Type DWord -Value 0 -Force -TryLGPO:$true
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'ExcludeWUDriversInQualityUpdate' -Type DWord -Value 1 -Force -TryLGPO:$true
}
Else{$stepCounter++}


If($DisableStoreOnTaskbar)
{
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:68] :: "}
    Show-ProgressStatus -Message ("{0} Disabling Pinning of Microsoft Store app on the taskbar" -f $prefixmsg) -Step ($stepCounter++) -MaxStep $script:Maxsteps

    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoPinningStoreToTaskbar' -Type DWord -Value 1 -Force | Out-Null
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' -Name 'RemoveWindowsStore' -Type DWord -Value 1 -Force -TryLGPO:$true | Out-Null
}
Else{$stepCounter++}


If ($EnableOfficeOneNote -and $OneNotePath)
{
    Show-ProgressStatus -Message "Setting OneNote file association to the desktop app" -Step ($stepCounter++) -MaxStep $script:Maxsteps

	New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
	New-Item -Path 'Registry::HKCR\onenote-cmd\Shell\Open' -Name 'Command' -Force | Out-Null
    New-ItemProperty -Path 'Registry::HKCR\onenote-cmd\Shell\Open\Command' -Name '@' -Type String -Value $OneNotePath.FullName -Force | Out-Null
	Remove-PSDrive -Name "HKCR" | Out-Null
}
Else{$stepCounter++}


If($EnablePSLogging)
{
    Show-ProgressStatus -Message "Enabling Powershell Script Logging" -Step ($stepCounter++) -MaxStep $script:Maxsteps

	Write-LogEntry "Enabling Powershell Script Block Logging"
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Type DWord -Value 1 -Force -TryLGPO:$true | Out-Null

    Write-LogEntry "Enabling Powershell Transcription Logging..."
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'EnableTranscripting' -Type DWord -Value 1 -Force -TryLGPO:$true | Out-Null
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'EnableInvocationHeader' -Type DWord -Value 1 -Force -TryLGPO:$true | Out-Null
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'OutputDirectory' -Value "" -Force -TryLGPO:$true | Out-Null

    Write-LogEntry "Enabling Powershell Module Logging..."
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name 'EnableModuleLogging' -Type DWord -Value 1 -Force -TryLGPO:$true | Out-Null
    #Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name 'ModuleNames' -Value "" -Force | Out-Null
}
Else{$stepCounter++}


If ($EnableVerboseStatusMsg)
{
    #https://support.microsoft.com/en-us/help/325376/how-to-enable-verbose-startup-shutdown-logon-and-logoff-status-message
    Show-ProgressStatus -Message "Setting Windows Startup to Verbose messages" -Step ($stepCounter++) -MaxStep $script:Maxsteps

    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'VerboseStatus' -Type DWord -Value 1 -Force | Out-Null
    If(Test-Path ('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\SYSTEM\DisableStatusMessages') ){
        Remove-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DisableStatusMessages' -Force | Out-Null
    }
}
Else{$stepCounter++}


If (($ApplyCustomHost) -and (Test-Path $HostPath) )
{
    $HostFile = Split-Path $HostPath -Leaf
    Show-ProgressStatus -Message ("Copying custom hosts file [{0}] to windows" -f $HostFile) -Step ($stepCounter++) -MaxStep $script:Maxsteps

    Copy-Item $HostPath -Destination "$env:Windir\System32\Drivers\etc\hosts" -Force | Out-Null
}
Else{$stepCounter++}


If ($SetPowerCFG -eq 'Balanced')
{
    #Set Balanced to Default
    Show-ProgressStatus -Message ("Setting Power configurations to [{0}]"  -f $SetPowerCFG) -Step ($stepCounter++) -MaxStep $script:Maxsteps

    Set-PowerPlan -PreferredPlan $SetPowerCFG
}
Else{$stepCounter++}


If ($SetPowerCFG -eq 'High Performance')
{
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:60 & 61] :: "}
    Show-ProgressStatus -Message ("{0}Setting Power configurations to [{1}]..."  -f $prefixmsg,$SetPowerCFG) -Step ($stepCounter++) -MaxStep $script:Maxsteps

    If($OptimizeForVDI){
        Set-PowerPlan -PreferredPlan $SetPowerCFG -ACTimeout 0 -DCTimeout 0 -ACMonitorTimeout 0 -DCMonitorTimeout 0 -Hibernate Off
    }
    Else{
        Set-PowerPlan -PreferredPlan $SetPowerCFG
    }
    
    Write-LogEntry "Disabling Fast Startup..."
	Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name 'HiberbootEnabled' -Type DWord -Value 0 -Force

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:54] :: "}
    Write-LogEntry ("{0}Removing turn off hard disk after..."  -f $prefixmsg)
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\0012ee47-9041-4b5d-9b77-535fba8b1442\6738e2c4-e8a5-4a42-b16a-e040e769756e' -Name 'Attributes' -Type DWord -Value 1 -Force
}
Else{$stepCounter++}


If (($SetPowerCFG -eq 'Custom') -and (Test-Path $PowerCFGFilePath) -and !$OptimizeForVDI)
{
    $AOPGUID = '50b056f5-0cf6-42f1-9351-82a490d70ef4'
    $PowFile = Split-Path $PowerCFGFilePath -Leaf
    Show-ProgressStatus -Message ("Setting Power configurations to [{0}] using file [{1}]" -f $SetPowerCFG,"$env:TEMP\$PowFile") -Step ($stepCounter++) -MaxStep $script:Maxsteps

    Copy-Item $PowerCFGFilePath -Destination "$env:Windir\Temp\$PowFile" -Force | Out-Null
    Start-Process "C:\Windows\system32\powercfg.exe" -ArgumentList "-IMPORT `"$env:Windir\Temp\$PowFile`" $AOPGUID" -Wait -NoNewWindow
    Start-Process "C:\Windows\system32\powercfg.exe" -ArgumentList "-SETACTIVE $AOPGUID" -Wait -NoNewWindow
    Start-Process "C:\Windows\system32\powercfg.exe" -ArgumentList "-H OFF" -Wait -NoNewWindow
}
Else{$stepCounter++}


If($HideDrivesWithNoMedia)
{
    Show-ProgressStatus -Message "Hiding Drives With NoMedia" -Step ($stepCounter++) -MaxStep $script:Maxsteps
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideDrivesWithNoMedia' -Type DWord -Value '1' -Force
}
Else{$stepCounter++}


If ($DisableAutoRun)
{
    Show-ProgressStatus -Message "Disabling Autorun" -Step ($stepCounter++) -MaxStep $script:Maxsteps

    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoAutoplayfornonVolume' -Value 1 -Force -TryLGPO:$true | Out-Null
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoAutorun' -Value 1 -Force
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoDriveTypeAutoRun' -Type DWord -Value 0xFF -Force

    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'HonorAutorunSetting' -Type DWord -Value 1 -Force
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveAutoRun' -Type DWord -Value 67108863 -Force
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutorun' -Type DWord -Value 0xFF -Force

    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping\Autorun.inf' -Name '(Default)' -Value "@SYS:DoesNotExist" -Force -ErrorAction SilentlyContinue | Out-Null
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Cdrom' -Name AutoRun -Type DWord -Value 0 -Force

    #windows 10 only
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:6] [Optional] :: "}
    Set-UserSetting -Message ("{0}Disabling Devices Auto" -f $prefixmsg) -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers' -Name 'DisableAutoPlay' -Type DWord -Value 1 -Force

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:6] :: "}
    Set-UserSetting -Message ("{0}Disabling Honor Autorun:" -f $prefixmsg) -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'HonorAutorunSetting' -Type DWord -Value 1 -Force
    Set-UserSetting -Message ("{0}Disabling NoDrive Autorun" -f $prefixmsg) -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveAutoRun' -Type DWord -Value 67108863 -Force
    Set-UserSetting -Message ("{0}Disabling No DriveType Autorun" -f $prefixmsg) -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutorun' -Type DWord -Value 0xFF -Force
    Set-UserSetting -Message ("{0}Disabling Autoplay" -f $prefixmsg) -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers' -Name 'DisableAutoPlay' -Type DWord -Value 1 -Force
    
}
Else{$stepCounter++}


If($EnableFIPS)
{
    Show-ProgressStatus -Message "Enabling FIPS Algorithm Policy" -Step ($stepCounter++) -MaxStep $script:Maxsteps
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy' -Name 'Enabled' -Type DWord -Value 1 -Force
}
Else{$stepCounter++}


If ($EnableRDP)
{
    Show-ProgressStatus -Message "Enabling RDP" -Step ($stepCounter++) -MaxStep $script:Maxsteps
	Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Type DWord -Value 0 -Force
	Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Type DWord -Value 1 -Force
	Set-NetFirewallRule -DisplayGroup "Remote Desktop" -Enabled True -Action Allow -Profile Any
}
Else{$stepCounter++}



If ($EnableAPPV)
{
    Show-ProgressStatus -Message "Enabling Microsoft App-V" -Step ($stepCounter++) -MaxStep $script:Maxsteps
	If($OSBuildNumber -ge 14393){
        Enable-Uev | Out-null
    }
    Else{
        Write-LogEntry ("Application Virtualization client does not exist on Windows [{0}]; install App-V client from MDOP..." -f $OSBuildNumber)
    }	
}
Else{$stepCounter++}


If ($EnableUEV)
{
    Show-ProgressStatus -Message "Enabling Microsoft UE-V" -Step ($stepCounter++) -MaxStep $script:Maxsteps
    If($OSBuildNumber -ge 14393){
        Enable-Appv | Out-null
    }
    Else{
        Write-LogEntry ("User Experience Virtualization client does not exist on Windows [{0}]; install UE-V client from MDOP..." -f $OSBuildNumber)
    }	
}
Else{$stepCounter++}


If ($DisableOneDrive)
{
    Show-ProgressStatus -Message "Disabling OneDrive" -Step ($stepCounter++) -MaxStep $script:Maxsteps

    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'DisableFileSync' -Type DWord -Value '1' -Force -TryLGPO:$true
	
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:50] :: "}
    Write-LogEntry ("{0}Disabling synchronizing files to onedrive..." -f $prefixmsg)
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'DisableFileSyncNGSC' -Type DWord -Value '1' -Force -TryLGPO:$true

    Write-LogEntry "Preventing OneDrive from generating network traffic"
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'PreventNetworkTrafficPreUserSignIn' -Type DWord -Value '1' -Force
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Skydrive' -Name 'DisableLibrariesDefaultSaveToSkyDrive' -Type DWORD -Value '1' -Force  
    
    Set-SystemSetting -Path 'Registry::HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder' -Name 'Attributes' -Type DWord -Value 0 -ErrorAction SilentlyContinue -Force

    Write-LogEntry "Disabling personal accounts for OneDrive synchronization..."
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'DisablePersonalSync' -Type DWord -Value '1' -Force
    Set-UserSetting -Message 'Removing Onedrive' -RegPath 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'OneDriveSetup' -Remove -Force
    
    #uninstall  OneDrive
    if (Test-Path "C:\Windows\System32\OneDriveSetup.exe"){
        Write-LogEntry ("Attempting to uninstall Onedrive from x64 system...")
        Get-Process OneDrive -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        #Get-Process explorer -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Process "C:\Windows\System32\OneDriveSetup.exe" -ArgumentList "/uninstall" -Wait -PassThru -WindowStyle Hidden | Out-Null
        #Start-Process -FilePath "$env:Windir\Explorer.exe" -Wait -ErrorAction SilentlyContinue
    }

    if (Test-Path "C:\Windows\SysWOW64\OneDriveSetup.exe"){
        Write-LogEntry ("Attempting to uninstall Onedrive from x86 system...")
        Get-Process OneDrive -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        #Get-Process explorer -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Process "C:\Windows\SysWOW64\OneDriveSetup.exe" -ArgumentList "/uninstall" -Wait -PassThru -WindowStyle Hidden | Out-Null
        #Start-Process -FilePath "$env:Windir\Explorer.exe" -Wait -ErrorAction SilentlyContinue
    }

    Remove-Item -Path "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue

    # remove OneDrive shortcuts
    Remove-Item -Path 'C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk' -Force
    Remove-Item -Path 'C:\Windows\ServiceProfiles\NetworkService\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk' -Force

    #remove registry references to onedrive
    Remove-Item -Path 'Registry::HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path 'Registry::HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' -Recurse -ErrorAction SilentlyContinue

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:203] :: "}
    Set-UserSetting -Message ("{0}Disabling Microsoft OneDrive startup run..." -f $prefixmsg) -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' -Name OneDrive -Type Binary -Value 0300000064A102EF4C3ED101 -Force
    If ($OSBuildNumber -le 15063)
    {
        Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{A52BBA46-E9E1-435f-B3D9-28DAA648C0F6}' -Recurse -ErrorAction SilentlyContinue
        Remove-Item -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{A52BBA46-E9E1-435f-B3D9-28DAA648C0F6}' -Recurse -ErrorAction SilentlyContinue
        Set-SystemSetting -Path 'Registry::HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' -Name 'System.IsPinnedToNameSpaceTree' -Value '0' -Force
        Set-SystemSetting -Path 'Registry::HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' -Name 'System.IsPinnedToNameSpaceTree' -Value '0' -Force
    }
}
Else{
    $stepCounter++
}


If ($PreferIPv4OverIPv6)
{
    Show-ProgressStatus -Message "Modifying IPv6 bindings to prefer IPv4 over IPv6" -Step ($stepCounter++) -MaxStep $script:Maxsteps
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'DisabledComponents' -Type DWord -Value '32' -Force
}
Else{$stepCounter++}


If($DisableAllNotifications)
{
    $notifications = [ordered]@{
        "Windows.SystemToast.SecurityAndMaintenance"="Security and Maintenance Notifications"
        "Microsoft.SkyDrive.Desktop"="OneDrive Notifications"
        "Microsoft.Windows.Photos_8wekyb3d8bbwe!App"="Photos Notifications"
        "Microsoft.WindowsStore_8wekyb3d8bbwe!App"="Store Notifications"
        "Windows.SystemToast.Suggested"="Suggested Notifications"
        "microsoft.windowscommunicationsapps_8wekyb3d8bbwe!microsoft.windowslive.calendar"="Calendar Notifications"
        "Microsoft.Windows.Cortana_cw5n1h2txyewy!CortanaUI"="Cortana Notifications"
        "microsoft.windowscommunicationsapps_8wekyb3d8bbwe!microsoft.windowslive.mail"="Mail Notifications:"
        "Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge"="Edge Notifications"
        "Windows.SystemToast.AudioTroubleshooter"="Audio Notifications"
        "Windows.SystemToast.AutoPlay"="Autoplay Notifications"
        "Windows.SystemToast.BackgroundAccess"="Battery Saver Notifications"
        "Windows.SystemToast.BdeUnlock"="Bitlocker Notifications"
        "Microsoft.BingNews_8wekyb3d8bbwe!AppexNews"="News Notifications"
        "windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel"="Settings Notifications"
        "Windows.System.Continuum"="Tablet Notifications"
        "Windows.SystemToast.RasToastNotifier"="VPN Notifications"
        "Windows.SystemToast.HelloFace"="Windows Hello Notifications"
        "Windows.SystemToast.WiFiNetworkManager"="Wireless Notifications"
    }   
    Show-ProgressStatus -Message "Disabling Toast Notifications" -Step ($stepCounter++) -MaxStep $script:Maxsteps
    $i = 1
    #loop each notification    
    Foreach ($key in $notifications.GetEnumerator()){  
        $FriendlyName = $key.Value
        Set-UserSetting -Message ("Disabling {0} notification: {1} of {2}" -f $FriendlyName,$i,$notifications.count) -Path ('SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\' + $key.Key) -Name Enabled -Value 0 -Type DWord -Force
        $i ++
    }
    Set-UserSetting -Message "Disabling Toast notifications to the lock screen" -Path 'SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' -Name 'NoToastApplicationNotificationOnLockScreen' -Type DWord -Value '1' -Force -TryLGPO:$true

    Write-LogEntry "Disabling Non-critical Notifications from Windows Security..."
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications' -Name 'DisableEnhancedNotifications' -Type DWord -Value '1' -Force -TryLGPO:$true

    Write-LogEntry "Disabling All Notifications from Windows Security using..."
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications' -Name 'DisableNotifications' -Type DWord -Value '1' -Force -TryLGPO:$true
}
Else{$stepCounter++}


If ($DisableIEFirstRunWizard)
{
	# Disable IE First Run Wizard
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:40] :: "}
    Show-ProgressStatus -Message ("{0}Disabling IE First Run Wizard" -f $prefixmsg) -Step ($stepCounter++) -MaxStep $script:Maxsteps
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main' -Name 'DisableFirstRunCustomize' -Type DWord -Value '1' -Force -TryLGPO:$true
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main' -Name 'RunOnceHasShown' -Type DWord -Value '1' -Force
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main' -Name 'RunOnceComplete' -Type DWord -Value '1' -Force

    Set-UserSetting -Message ("{0}Disabling IE First Run Wizard" -f $prefixmsg) -Path 'SOFTWARE\Policies\Microsoft\Internet Explorer\Main' -Name 'DisableFirstRunCustomize' -Type DWord -Value '1' -Force -TryLGPO:$true
    Set-UserSetting -Message "Setting Show Run in IE" -Path 'SOFTWARE\Microsoft\Internet Explorer\Main' -Name 'RunOnceHasShown' -Type DWord -Value '1' -Force
    Set-UserSetting -Message "Setting Run Once Comleted in IE" -Path 'SOFTWARE\Microsoft\Internet Explorer\Main' -Name 'RunOnceComplete' -Type DWord -Value '1' -Force

}
Else{$stepCounter++}


If ($DisableWMPFirstRunWizard)
{
	# Disable IE First Run Wizard
    Show-ProgressStatus -Message "Disabling Media Player First Run Wizard" -Step ($stepCounter++) -MaxStep $script:Maxsteps	
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\MediaPlayer\Preferences' -Name 'AcceptedEULA' -Type DWord -Value '1' -Force
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\MediaPlayer\Preferences' -Name 'FirstTime' -Type DWord -Value '1' -Force
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer' -Name 'GroupPrivacyAcceptance' -Type DWord -Value '1' -Force -TryLGPO:$true
}
Else{$stepCounter++}


If($EnableSecureLogonCAD)
{
  	# Disable IE First Run Wizard
	Show-ProgressStatus -Message "Enabling Secure Logon Screen Settings..." -Step ($stepCounter++) -MaxStep $script:Maxsteps
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'DisableCAD' -Type DWord -Value '0' -Force
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DontDisplayLastUserName' -Type DWord -Value '1' -Force
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'BlockDomainPicturePassword' -Type DWord -Value '1' -Force
}
Else{$stepCounter++}


# Disable New Network dialog box
If ($DisableNewNetworkDialog)
{
    Show-ProgressStatus -Message "Disabling New Network Dialog" -Step ($stepCounter++) -MaxStep $script:Maxsteps
    Set-SystemSetting 'HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet' -Name 'EnableActiveProbing' -Type DWord -Value '0' -Force
}
Else{$stepCounter++}


If($RemoveActiveSetupComponents){

    #https://kb.vmware.com/s/article/2100337?lang=en_US#q=Improving%20log%20in%20time
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations :: "}	
    
    $activeComponentsGUID = [ordered]@{
        "{2C7339CF-2B09-4501-B3F3-F3508C9228ED}"="205:Theme Component"
        "{2D46B6DC-2207-486B-B523-A557E6D54B47}"="206:ie4uinit.exe –ClearIconCache"
        "{44BBA840-CC51-11CF-AAFA-00AA00B6015C}"="207:DirectDrawEx"
        "{6BF52A52-394A-11d3-B153-00C04F79FAA6}"="208:Microsoft Windows Media Player"
        "{89820200-ECBD-11cf-8B85-00AA005B4340}"="209:IE4_SHELLID"
        "{89820200-ECBD-11cf-8B85-00AA005B4383}"="210:BASEIE40_W2K"
        "{89B4C1CD-B018-4511-B0A1-5476DBF70820}"="211:DOTNETFRAMEWORKS"
        ">{22d6f312-b0f6-11d0-94ab-0080c74c7e95}"="212:WMPACCESS"
    }
    Show-ProgressStatus -Message "Disabling Active Setup components" -Step ($stepCounter++) -MaxStep $script:Maxsteps
    $i = 1

    Foreach ($key in $activeComponentsGUID.GetEnumerator()){
        $ColonSplit = $key.Value -match ":"
        If($ColonSplit){
            $OSODID = ($key.Value).split(":")[0]
            $FriendlyName = ($key.Value).split(":")[1]
            Write-LogEntry ("VDI Optimizations [OSOT ID:{0}] :: Disabling {1} Feature..." -f $OSODID,$FriendlyName)
        }
        Else{
            $FriendlyName = $key.Value
            Write-LogEntry ("{0}Disabling Active Setup components [{1}]..." -f $prefixmsg,$FriendlyName)
        }

        Show-ProgressStatus -Message "Disabling Active Setup components" -SubMessage ("Removing: {2} ({0} of {1})" -f $i,$activeComponentsGUID.count,$FriendlyName) -Step $i -MaxStep $activeComponentsGUID.count

        If(Test-Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\$($key.Key)" ){
            Remove-ItemProperty -Path ('HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\' + $key.Key) -Name 'StubPath' -Force -ErrorAction SilentlyContinue | Out-Null
        }
        
        Start-Sleep -Seconds 5
        $i++
    }

}
Else{$stepCounter++}


If ($DisabledUnusedFeatures)
{
    $features = [ordered]@{
        "Printing-Foundation-InternetPrinting-Client"="Internet Printing"
        "FaxServicesClientPackage"="Fax and scanning"
    }
    
    #disable more features for VDI
    If($OptimizeForVDI){
        
        $features = $features + @{
            "WindowsMediaPlayer"="67:Windows Media Player"
            "WCF-Services45"="69:ASP.Net 4.5 WCF"
            "Xps-Foundation-Xps-Viewer"="70:Xps Viewer"
            "Printing-XPSServices-Features"="Xps Services"
            "WorkFolders-Client"="Work folders Client"
        }
    }
    Show-ProgressStatus -Message "Disabling Unused Features" -Step ($stepCounter++) -MaxStep $script:Maxsteps

    $i = 1
    Foreach ($key in $features.GetEnumerator()){
        $ColonSplit = $key.Value -match ":"
        If($ColonSplit){
            $OSODID = ($key.Value).split(":")[0]
            $FriendlyName = ($key.Value).split(":")[1]
            If($OptimizeForVDI){$prefixmsg = ("VDI Optimizations [OSOT ID:{0}] ::" -f $OSODID)}
        }
        Else{
            $FriendlyName = $key.Value
            If($OptimizeForVDI){$prefixmsg = ("VDI Optimizations - UnusedFeatures :: ")}   
        }

        Show-ProgressStatus -Message "Disabling Unused Features" -SubMessage ("{2} ({0} of {1})" -f $i,$features.count,$FriendlyName) -Step $i -MaxStep $features.count

        Try{
            Write-LogEntry ("{0}Unused Features :: Disabling {1} Feature..." -f $prefixmsg,$FriendlyName)
            $result = Get-WindowsOptionalFeature -Online -FeatureName $key.key | Disable-WindowsOptionalFeature -Online -NoRestart -ErrorAction Stop -WarningAction SilentlyContinue
            if ($results.RestartNeeded -eq $true) {
                Write-LogEntry ("Reboot is required for disabling the [{0}] Feature" -f $FriendlyName)
            }
        }
        Catch [System.Management.Automation.ActionPreferenceStopException]{
            Write-LogEntry ("Unable to Remove {0} Feature: {1}" -f $FriendlyName,$_) -Severity 3
        }


        Start-Sleep -Seconds 10
        $i++ 
    }
    
    Write-LogEntry "Removing Default Fax Printer..."
    Remove-Printer -Name "Fax" -ErrorAction SilentlyContinue
}
Else{$stepCounter++}


If ($DisabledUnusedServices)
{
    
    $services = [ordered]@{
        HomeGroupListener="152:HomeGroup Listener Services"
        HomeGroupProvider="153:HomeGroup Provider Services"
        RetailDemo="172:Retail Demo"
    }

    #disable more services for VDI
    If($OptimizeForVDI){
        $services = $services + @{
            AJRouter="135:AJRouter Router"
            ALG="136:Application Layer Gateway"
            BITS="137:Background Intelligent Transfer"
            wbengine="138:Block Level Backup Engine"
            bthserv="139:Bluetooth Support"
            BthHFSrv="307:Wireless Bluetooth Headsets"
            BDESVC="140:Bitlocker Drive Encryption"
            Browser="141:Computer Browser"
            PeerDistSvc="142:BranchCache"
            #DeviceAssociationService="143:Device Association"
            DsmSvc="144:Device Setup Manager"
            DPS="145:Diagnostic Policy"
            WdiServiceHost="146:Diagnostic Service Host"
            WdiSystemHost="147:Diagnostic System Host"
            DiagTrack="148:Diagnostics Tracking"
            Fax="149:Fax"
            fdPHost="150:Function Discovery Provider Host"
            FDResPub="151:Function Discovery Resource Publication"
            vmickvpexchange="154:Hyper-V Data Exchange"
            vmicguestinterface="155:Hyper-V Guest Service Interface"
            vmicshutdown="156:Hyper-V Guest Shutdown"
            vmicheartbeat="157:Hyper-V Heartbeat"
            vmicrdv="158:Hyper-V Remote Desktop Virtualization"
            vmictimesync="159:Hyper-V Time Synchronization"
            vmicvmsession="160:Hyper-V VM Session"
            vmicvss="161:Hyper-V Volume Shadow Copy Requestor"
            UI0Detect="162:Interactive Services Detection"
            SharedAccess="163:Internet Connection Sharing (ICS)"
            iphlpsvc="164:IP Helper"
            MSiSCSI="165:Microsoft iSCSI Initiator"
            swprv="166:Microsoft Software Shadow Copy Provider"
            CscService="167:Offline Files"
            defragsvc="168:Drive Optimization Capabilities"
            PcaSvc="169:Program Compatibility Assistant"
            QWAVE="170:Quality Windows Audio Video Experience"
            wercplsupport="171:Reports and Solutions Control Panel Support" 
            SstpSvc="173:Secure Socket Tunneling Protocol"
            wscsvc="174:Security Center"
            #"ShellHWDetection="178:Shell Hardware Detection"
            SNMPTRAP="179:SNMP Trap"
            svsvc="180:Spot Verifier"
            SSDPSRV="181:SSDP Discovery"
            WiaRpc="182:Still Image Acquisition Events"
            StorSvc="183:Store Storage"
            SysMain="184:Superfetch"
            TapiSrv="185:Telephony"
            Themes="186:Themes"
            #upnphost="187:Universal PnP Host"
            VSS="188:Volume Shadow Copy"
            SDRSVC="189:Windows Backup"
            WcsPlugInService="180:Windows Color System"
            wcncsvc="191:Windows Connect Now – Config Registrar"
            #WSearch="195:Windows Search"
            #wuauserv="196:Windows Update"
            Wlansvc="197:WLAN AutoConfig"
            WwanSvc="198:WWAN AutoConfig"
            WbioSrvc="298:Biometric"
            AppIDSvc="299:Identity of an Application"
            'diagnosticshub.standardcollector.service'="300:Diagnostics Hub"
            DoSvc="302:Delivery Optimization"
            EFS="303:Encrypting File System"
            Eaphost="304:Extensible Authentication Protocol"
            stisvc="311:Windows Image Acquisition (WIA)"
            NlaSvc="Network Location Awareness"
            #"Audiosrv="Audio"
            PimIndexMaintenanceSvc="Contact Data"
        }
        $i = 1

        Foreach ($key in $services.GetEnumerator()){
            #write-host ("`"{1}`"=`"{0}`"" -f $key.Key,$key.Value)

            $ColonSplit = $key.Value -match ":"
            If($ColonSplit){
                $OSODID = ($key.Value).split(":")[0]
                $SvcName = ($key.Value).split(":")[1]
                If($OptimizeForVDI){$prefixmsg = ("VDI Optimizations [OSOT ID:{0}] ::" -f $OSODID)}
            }
            Else{
                $SvcName = $key.Value
                If($OptimizeForVDI){$prefixmsg = ("VDI Optimizations - UnusedServices :: ")}
            }
            Write-LogEntry ("{0}Disabling {1} Service [{2}]..." -f $prefixmsg,$SvcName,$key.Key)

            Show-ProgressStatus -Message "Disabling Internet Service" -SubMessage ("Removing: {2} ({0} of {1})" -f $i,$services.count,$SvcName) -Step $i -MaxStep $services.count

            Try{
                Set-Service $key.Key -StartupType Disabled -ErrorAction Stop | Out-Null
            }
            Catch [System.Management.Automation.ActionPreferenceStopException]{
                Write-LogEntry ("Unable to Disable {0} Service: {1}" -f $SvcName,$_) -Severity 3
            }

            Start-Sleep -Seconds 10
            $i++
        }
    }

    #detect if system is a tablet
    #if not disable tablet service
    Add-Type @"
using System.Runtime.InteropServices;
namespace WinAPI
{	
    public class User32 { 
    [DllImport("user32.dll")] public static extern int GetSystemMetrics(int nIndex); }
}
"@

    if (-not($Result = [WinAPI.User32]::GetSystemMetrics(86) -band 0x41 -eq 0x41) ) {
        Try{
            Set-Service TabletInputService -StartupType Disabled -ErrorAction Stop | Out-Null
        }
        Catch [System.Management.Automation.ActionPreferenceStopException]{
            Write-LogEntry ("Unable to disable Tablet Service: {0}" -f $_) -Severity 3
        }
    }

}
Else{$stepCounter++}


# Disable Services
If ($DisableInternetServices -and $OptimizeForVDI)
{
    $services = [ordered]@{
        XblAuthManager="199:Xbox Live Auth Manager"
        XblGameSave="200:Xbox Live Game Save"
        XboxNetApiSvc="201:Xbox Live Networking"
        XboxGipSvc="Xbox Accessory Management"
        XboxGip="Xbox Game Input Protocol Driver"
        BcastDVRUserService="GameDVR and Broadcast User"
        xbgm="Xbox Game Monitoring"
        wlidsvc="309:Microsoft Account Sign-in Assistant"
        WerSvc="Windows Error Reporting"
        WMPNetworkSvc="Windows Mediaplayer Sharing"
        DiagTrack="Diagnostic Tracking"
        dmwappushservice="WAP Push Message Routing Data Collection"
        MessagingService="WIndows Text Messaging"
        CDPSvc="Connected Device Platform"
        CDPUserSvc="Connected Device Platform User"
        OneSyncSvc="Sync Host"
        icssvc="194:Windows Mobile Hotspot"
        DcpSvc="301:Data Collection and Publishing"
        lfsvc="308:Geolocation"
        MapsBroker="305:Maps Manager"
        SensorDataService="175:Sensor Data"
        SensrSvc="176:Sensor Monitoring"
        SensorService="177:Sensor"
        DusmSvc="Data Usage Subscription Management"
    }
    $i = 1

    Foreach ($key in $services.GetEnumerator()){
        $ColonSplit = $key.Value -match ":"
        If($ColonSplit){
            $OSODID = ($key.Value).split(":")[0]
            $SvcName = ($key.Value).split(":")[1]
            Write-LogEntry ("VDI Optimizations [OSOT ID:{0}] :: Disabling {1} Service [{2}]..." -f $OSODID,$SvcName,$key.Key)
        }
        Else{
            $SvcName = $key.Value
            Write-LogEntry ("Disabling {0} Service [{1}]..." -f $SvcName,$key.Key)
        }

        Show-ProgressStatus -Message "Disabling Internet Service" -SubMessage ("Removing: {2} ({0} of {1})" -f $i,$services.count,$SvcName) -Step $i -MaxStep $services.count

        Try{
            Set-Service $key.Key -StartupType Disabled -ErrorAction Stop | Out-Null
        }
        Catch [System.Management.Automation.ActionPreferenceStopException]{
            Write-LogEntry ("Unable to Disable {0} Service: {1}" -f $SvcName,$_) -Severity 3
        }

        Start-Sleep -Seconds 10
        $i++
    }

}
Else{$stepCounter++}


If($DisableSmartCardLogon){
    $services = [ordered]@{
        SCardSvr="Smart Card"
        ScDeviceEnum="Smart Card Device Enumeration Service"
        SCPolicySvc="Smart Card Removal Policy"
    }
    $i = 1
     
    Foreach ($key in $services.GetEnumerator()){
        $ColonSplit = $key.Value -match ":"
        If($ColonSplit){
            $OSODID = ($key.Value).split(":")[0]
            $SvcName = ($key.Value).split(":")[1]
            Write-LogEntry ("VDI Optimizations [OSOT ID:{0}] :: Disabling {1} Service [{2}]..." -f $OSODID,$SvcName,$key.Key)
        }
        Else{
            $SvcName = $key.Value
            Write-LogEntry ("Disabling {0} Service [{1}]..." -f $SvcName,$key.Key)
        }

        Show-ProgressStatus -Message "Disabling SmartCard Service" -SubMessage ("Removing: {2} ({0} of {1})" -f $i,$services.count,$SvcName) -Step $i -MaxStep $services.count

        Try{
            Set-Service $key.Key -StartupType Disabled -ErrorAction Stop | Out-Null
        }
        Catch [System.Management.Automation.ActionPreferenceStopException]{
            Write-LogEntry ("Unable to Disable {0} Service: {1}" -f $SvcName,$_) -Severity 3
        }

        Start-Sleep -Seconds 10
        $i++
    }
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'SCForeOption' -Type DWord -Value '0' -Force -TryLGPO:$true 
}
Else{$stepCounter++}


If($ForceStrictSmartCardLogon){
    Show-ProgressStatus -Message "Forcing smartcard login..." -Step ($stepCounter++) -MaxStep $script:Maxsteps

    Write-LogEntry "Change provider to default to smartcard login"
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SYSTEM\DefaultCredentialProvider' -Name 'SmartCardCredentialProvider' -Type String -Value '{8FD7E19C-3BF7-489B-A72C-846AB3678C96}' -Force -TryLGPO:$true  
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider' -Name 'SmartCardCredentialProvider' -Type DWord -Value '1' -Force -TryLGPO:$true  
  
    Write-LogEntry "Allow certificates with no extended key usage certificate attribute"
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider' -Name 'AllowCertificatesWithNoEKU' -Type DWord -Value '1' -Force -TryLGPO:$true
    
    Write-LogEntry "Allow Integrated Unblock screen to be displayed at the time of logon"
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider' -Name 'AllowIntegratedUnblock' -Type DWord -Value '1' -Force -TryLGPO:$true
    
    Write-LogEntry "Filter duplicate logon certificates"
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider' -Name 'FilterDuplicateCerts' -Type DWord -Value '1' -Force -TryLGPO:$true
    
    Write-LogEntry "Force the reading of all certificates from the smart card"
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider' -Name 'ForceReadingAllCertificates' -Type DWord -Value '1' -Force -TryLGPO:$true
    
    Write-LogEntry "Allow signature keys valid for Logon"
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider' -Name 'AllowSignatureOnlyKeys' -Type DWord -Value '1' -Force -TryLGPO:$true
    
    Write-LogEntry "Allow time invalid certificates"
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider' -Name 'AllowTimeInvalidCertificates' -Type DWord -Value '1' -Force -TryLGPO:$true
    
    Write-LogEntry "Display string when smart card is blocked"
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider' -Name 'IntegratedUnblockPromptString' -Type DWord -Value '1' -Force -TryLGPO:$true
    
    Write-LogEntry "Reverse the subject name stored in a certificate when displaying"
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider' -Name 'ReverseSubject' -Type DWord -Value '1' -Force -TryLGPO:$true
    
    Write-LogEntry "Prevent plaintext PINs from being returned by Credential Manager"
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider' -Name 'DisallowPlaintextPin' -Type DWord -Value '1' -Force -TryLGPO:$true
    
    Write-LogEntry "Allow user name hint"
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider' -Name 'X509HintsNeeded' -Type DWord -Value '1' -Force -TryLGPO:$true
    
    Write-LogEntry "Allow ECC certificates to be used for logon and authentication"
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider' -Name 'EnumerateECCCerts' -Type DWord -Value '1' -Force -TryLGPO:$true
    
    Write-LogEntry "Disabling smartcard reader if no reader found"
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider' -Name 'DisplayEmptySmartCardTileWhenNoReader' -Type DWord -Value '0' -Force -TryLGPO:$true
    
    Write-LogEntry "Configuring Smart Card removal to Force Logoff..."
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'SCRemoveOption' -Type String  -Value 2 -Force

    Write-LogEntry "Disabling Picture Password Login"
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{2135f72a-90b5-4ed3-a7f1-8bb705ac276a}' -Name 'Disabled' -Type DWord -Value '1' -Force
    
    Write-LogEntry "Disabling Windows Hello Login"
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{8AF662BF-65A0-4D0A-A540-A338A999D36F}' -Name 'Disabled' -Type DWord -Value '1' -Force
    
    Write-LogEntry "Disabling Biometrics Login"
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{BEC09223-B018-416D-A0AC-523971B639F5}' -Name 'Disabled' -Type DWord -Value '1' -Force
    
    Write-LogEntry "Disabling PIN Login"
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{cb82ea12-9f71-446d-89e1-8d0924e1256e}' -Name 'Disabled' -Type DWord -Value '1' -Force
    
    Write-LogEntry "Disabling Cloud Experience Credential Login"
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{C5D7540A-CD51-453B-B22B-05305BA03F07}' -Name 'Disabled' -Type DWord -Value '1' -Force
    
    Write-LogEntry "Disabling Password Login"
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}' -Name 'Disabled' -Type DWord -Value '1' -Force
}
Else{$stepCounter++}

If ($DisableDefender)
{
    $services = [ordered]@{
        Sense="Windows Defender Advanced Threat Protection"
        WdNisSvc="Windows Defender Antivirus Network Inspection"
        SecurityHealthService="Windows Security"
        WinDefend="Windows Defender Antivirus"

    }
    $i = 1

    Foreach ($key in $services.GetEnumerator()){
        $ColonSplit = $key.Value -match ":"
        If($ColonSplit){
            $OSODID = ($key.Value).split(":")[0]
            $SvcName = ($key.Value).split(":")[1]
            Write-LogEntry ("VDI Optimizations [OSOT ID:{0}] :: Disabling {1} Service [{2}]..." -f $OSODID,$SvcName,$key.Key)
        }
        Else{
            $SvcName = $key.Value
            Write-LogEntry ("Disabling {0} Service [{1}]..." -f $SvcName,$key.Key)
        }

        Show-ProgressStatus -Message "Disabling Defender Service" -SubMessage ("Removing: {2} ({0} of {1})" -f $i,$services.count,$SvcName) -Step $i -MaxStep $services.count

        Try{
            Set-Service $key.Key -StartupType Disabled -ErrorAction Stop | Out-Null
        }
        Catch [System.Management.Automation.ActionPreferenceStopException]{
            Write-LogEntry ("Unable to Disable {0} Service: {1}" -f $SvcName,$_) -Severity 3
        }
        
        Start-Sleep -Seconds 10
        $i++
    }

    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name 'DisableAntiSpyware' -Type DWord -Value 1 -Force -TryLGPO:$true
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray' -Name 'HideSystray' -Type DWord -Value 1 -Force -TryLGPO:$true
    If ($OSBuildNumber -eq 14393) {
        Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'WindowsDefender' -ErrorAction SilentlyContinue
    } 
    ElseIf ($OSBuildNumber -ge 15063) {
        Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'SecurityHealth' -ErrorAction SilentlyContinue
    }

    Write-LogEntry "Disabling Malicious Software Removal Tool offering"
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MRT' -Name 'DontOfferThroughWUAU' -Type DWord -Value 1 -Force -TryLGPO:$true

    Write-LogEntry "Disabling Windows Defender Cloud..."
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' -Name 'SpynetReporting' -Type DWord -Value 0 -Force -TryLGPO:$true
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' -Name 'SubmitSamplesConsent' -Type DWord -Value 2 -Force -TryLGPO:$true
}
Else{$stepCounter++}


If ($EnableRemoteRegistry)
{
    Show-ProgressStatus -Message "Enabling Remote registry services" -Step ($stepCounter++) -MaxStep $script:Maxsteps
    Try{
        Get-Service 'RemoteRegistry' |Set-Service  -StartupType Automatic -ErrorAction Stop
        Start-Service 'RemoteRegistry' -ErrorAction Stop
    }
    Catch [System.Management.Automation.ActionPreferenceStopException]{
        Write-LogEntry ("Unable to enable Remote registry: {0}" -f $_) -Severity 3
    }
}
Else{$stepCounter++}


If ($DisableWireless -or $OptimizeForVDI)
{
    Show-ProgressStatus -Message "Disabling Wireless Services" -Step ($stepCounter++) -MaxStep $script:Maxsteps
    Try{
        Get-Service 'wcncsvc' | Set-Service -StartupType Disabled -ErrorAction Stop
        Get-Service 'WwanSvc' | Set-Service -StartupType Disabled -ErrorAction Stop
    }
    Catch [System.Management.Automation.ActionPreferenceStopException]{
        Write-LogEntry ("Unable to Disable Wireless Services: {0}" -f $_) -Severity 3
    }
}
Else{$stepCounter++}


If ($DisableBluetooth -or $OptimizeForVDI)
{
    Show-ProgressStatus -Message "Disabling Bluetooth" -Step ($stepCounter++) -MaxStep $script:Maxsteps
    
    Set-Bluetooth -DeviceStatus Off
}
Else{$stepCounter++}


# Disable Scheduled Tasks
If ($DisableSchTasks)
{
    Show-ProgressStatus -Message "Disabling Scheduled Tasks" -Step ($stepCounter++) -MaxStep $script:Maxsteps
    
	$scheduledtasks = @{
        "Microsoft Application Experience\Microsoft Compatibility Appraiser Scheduled Task"="\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
        "Microsoft Application Experience\ProgramDataUpdater Scheduled Task"="\Microsoft\Windows\Application Experience\ProgramDataUpdater"
        "Microsoft Startup Application Experience\StartupAppTask Scheduled Task"="\Microsoft\Windows\Application Experience\StartupAppTask"
	    "Microsoft CEIP Consolidator Scheduled Task"="\Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
	    "Microsoft USB CEIP Scheduled Task"="\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
	    "Microsoft Maps Toast Task Scheduled Task"="\Microsoft\Windows\Maps\MapsToastTask"
	    "Microsoft Maps Update Task Scheduled Task"="\Microsoft\Windows\Maps\MapsUpdateTask"
	    "Microsoft Family Safety Monitor Scheduled Task"="\Microsoft\Windows\Shell\FamilySafetyMonitor"
	    "Microsoft Resolution Host Scheduled Task"="\Microsoft\Windows\WDI\ResolutionHost"
	    "Microsoft Windows Media Sharing UpdateLibrary Scheduled Task"="\Microsoft\Windows\Windows Media Sharing\UpdateLibrary"
	    "Microsoft Proxy Scheduled Task"="\Microsoft\Windows\Autochk\Proxy"
	    "Microsoft Cloud Experience Host Create Object Task Scheduled Task"="\Microsoft\Windows\CloudExperienceHost\CreateObjectTask"
	    "Microsoft Siuf DmClient Scheduled Task"="\Microsoft\Windows\Feedback\Siuf\DmClient"
	    "Microsoft Siuf\DmClientOnScenarioDownload Scheduled Task"="\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload"
	    "Microsoft FamilySafetyRefreshTask Scheduled Task"="\Microsoft\Windows\Shell\FamilySafetyRefreshTask"
	    "Microsoft Windows Error Reporting\QueueReporting Scheduled Task"="\Microsoft\Windows\Windows Error Reporting\QueueReporting"
	    "Microsoft XblGameSaveTask Scheduled Task"="\Microsoft\XblGameSave\XblGameSaveTask"
    }

    Foreach ($task in $scheduledtasks.GetEnumerator()){
        Write-LogEntry ('Disabling [{0}]' -f $task.Key)
        Disable-ScheduledTask -TaskName $task.Value -ErrorAction SilentlyContinue | Out-Null
    }

    If($OptimizeForVDI)
    {
        $AdditionalScheduledTasks = @{
            "Microsoft Application Experience\AitAgent Scheduled Task"="\Microsoft\Windows\Application Experience\AitAgent"
            "Microsoft Bluetooth UninstallDeviceTask Scheduled Task"="\Microsoft\Windows\Bluetooth\UninstallDeviceTask"
            "Microsoft Customer Experience Improvement Program\BthSQM Scheduled Task"="\Microsoft\Windows\Customer Experience Improvement Program\BthSQM"
            "Microsoft Customer Experience Improvement Program\KernelCeipTask Scheduled Task"="\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask"
            "Microsoft Defrag\ScheduledDefrag Scheduled Task"="\Microsoft\Windows\Defrag\ScheduledDefrag"
            "Microsoft DiskDiagnostic\Microsoft-WindowsDiskDiagnosticDataCollector Scheduled Task"="\Microsoft\Windows\DiskDiagnostic\Microsoft-WindowsDiskDiagnosticDataCollector"
            "Microsoft DiskDiagnostic\Microsoft-WindowsDiskDiagnosticResolver Scheduled Task"="\Microsoft\Windows\DiskDiagnostic\Microsoft-WindowsDiskDiagnosticResolver"
            "Microsoft FileHistory\File History (maintenance mode) Scheduled Task"="\Microsoft\Windows\FileHistory\File History (maintenance mode)"
            "Microsoft Live\Roaming\MaintenanceTask Scheduled Task"="\Microsoft\Windows\Live\Roaming\MaintenanceTask"
            "Microsoft Live\Roaming\SynchronizeWithStorage Scheduled Task"="\Microsoft\Windows\Live\Roaming\SynchronizeWithStorage"
            "Microsoft Maintenance\WinSAT Scheduled Task"="\Microsoft\Windows\Maintenance\WinSAT"
            "Microsoft Mobile Broadband Accounts\MNO Metadata Parser Scheduled Task"="\Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser"
            "Microsoft MobilePC\HotStart Scheduled Task"="\Microsoft\Windows\MobilePC\HotStart"
            "Microsoft Power Efficiency Diagnostics\AnalyzeSYSTEM\Microsoft\Windows\Ras\MobilityManager Scheduled Task"="\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSYSTEM\Microsoft\Windows\Ras\MobilityManager"
            "Microsoft SideShow\AutoWake Scheduled Task"="\Microsoft\Windows\SideShow\AutoWake"
            "Microsoft SideShow\GadgetManager Scheduled Task"="\Microsoft\Windows\SideShow\GadgetManager"
            "Microsoft SideShow\SessionAgent Scheduled Task"="\Microsoft\Windows\SideShow\SessionAgent"
            "Microsoft SideShow\SystemDataProviders Scheduled Task"="\Microsoft\Windows\SideShow\SystemDataProviders"
            "Microsoft SpacePort\SpaceAgentTask Scheduled Task"="\Microsoft\Windows\SpacePort\SpaceAgentTask"
            "Microsoft SystemRestore\SR Scheduled Task"="\Microsoft\Windows\SystemRestore\SR"
            #"Microsoft UPnP\UPnPHostConfig Scheduled Task"="\Microsoft\Windows\UPnP\UPnPHostConfig"
            "Microsoft Windows Defender\Windows Defender Cache Maintenance Scheduled Task"="\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance"
            "Microsoft Windows Defender\Windows Defender Scheduled Scan Scheduled Task"="\Microsoft\Windows\Windows Defender\Windows Defender Cleanup\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan"
            "Microsoft Windows Defender\Windows Defender Verification Scheduled Task"="\Microsoft\Windows\Windows Defender\Windows Defender Verification"
            "Microsoft WindowsBackup\ConfigNotification Scheduled Task"="\Microsoft\Windows\WindowsBackup\ConfigNotification"
        }

        Foreach ($task in $AdditionalScheduledTasks.GetEnumerator()){
            Write-LogEntry ('Disabling [{0}] for VDI' -f $task.Key)
            Disable-ScheduledTask -TaskName $task.Value -ErrorAction SilentlyContinue | Out-Null
        }
    }
}
Else{$stepCounter++}


If ($DisableCortana)
{
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:33] :: "}
    Show-ProgressStatus -Message ("{0}Disabling Cortana" -f $prefixmsg) -Step ($stepCounter++) -MaxStep $script:Maxsteps

	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowCortana' -Type DWord -Value '0' -Force -TryLGPO:$true
    
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:14] :: "}
    Write-LogEntry ("{0}Disabling Search option in taskbar" -f $prefixmsg)
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'SearchboxTaskbarMode' -Type DWord -Value '0' -Force	
    
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:42] :: " -f $prefixmsg}
    Write-LogEntry ("{0}Disabling search and Cortana to use location")
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowSearchToUseLocation' -Type DWord -Value '0' -Force -TryLGPO:$true    

    Set-UserSetting -Message "Disabling Cortana Consent" -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Search' -Name 'CortanaConsent' -Type DWord -Value 0 -Force 
    Set-UserSetting -Message "Disabling Privacy Policy" -Path 'SOFTWARE\Microsoft\Personalization\Settings' -Name 'AcceptedPrivacyPolicy' -Type DWord -Value 0 -Force 
    Set-UserSetting -Message "Disabling Text Collection" -Path 'SOFTWARE\Microsoft\InputPersonalization' -Name 'RestrictImplicitTextCollection' -Type DWord -Value 1 -Force 
    Set-UserSetting -Message "Disabling Ink Collection" -Path 'SOFTWARE\Microsoft\InputPersonalization' -Name 'RestrictImplicitInkCollection' -Type DWord -Value 1 -Force 
    Set-UserSetting -Message "Disabling contacts" -Path 'SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore' -Name 'HarvestContacts' -Type DWord -Value 0 -Force 
    
}
Else{$stepCounter++}


If($DisableInternetSearch){
    
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:12] :: "}
    Show-ProgressStatus -Message ("{0}Disabling Bing Search" -f $prefixmsg) -Step ($stepCounter++) -MaxStep $script:Maxsteps

	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'BingSearchEnabled' -Type DWord -Value '0' -Force -TryLGPO:$true

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:47] :: "}
    Write-LogEntry ("Disable search web when searching pc" -f $prefixmsg)
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'ConnectedSearchUseWeb' -Type DWord -Value '0' -Force -TryLGPO:$true
    
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:55] :: "}
    Write-LogEntry ("{0}Disabling Web Search in search bar" -f $prefixmsg)
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'DisableWebSearch' -Type DWord -Value '0' -Force -TryLGPO:$true 
    
    Set-UserSetting -Message "Disabling Bing Search" -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Search' -Name 'BingSearchEnabled' -Type DWord -Value 0 
}
Else{$stepCounter++}


# Privacy and mitigaton settings
# See: https://docs.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services
If ($ApplyPrivacyMitigations)
{
    Show-ProgressStatus -Message "Disabling Privacy Mitigations" -Step ($stepCounter++) -MaxStep $script:Maxsteps

    
    Write-LogEntry "Privacy Mitigations :: Disabling NCSI active test..."
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator' -Name 'NoActiveProbe' -Type DWord -Value '0' -Force -TryLGPO:$true
    
    Write-LogEntry "Disabling automatic installation of network devices..."
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private' -Name 'AutoSetup' -Type DWord -Value 0 -Force

    Write-LogEntry "Privacy Mitigations :: Disabling customer experience improvement program..."
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\SQMClient\Windows' -Name 'CEIPEnable' -Type DWord -Value '0' -Force

    Write-LogEntry "Privacy Mitigations :: Disabling sending settings to cloud..."
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync' -Name 'DisableSettingSync' -Type DWord -Value 2 -Force -TryLGPO:$true
    
    Write-LogEntry "Privacy Mitigations :: Disabling synchronizing files to cloud..."
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync' -Name 'DisableSettingSyncUserOverride' -Type DWord -Value 1 -Force -TryLGPO:$true

    Write-LogEntry "Privacy Mitigations :: Disabling sending additional info with error reports..."
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' -Name 'DontSendAdditionalData' -Type DWord -Value 1 -Force -TryLGPO:$true
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting' -Name 'Disabled' -Type DWord -Value 1 -Force

	Write-LogEntry "Privacy Mitigations :: Disallowing the user to change sign-in options..."
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Settings' -Name 'AllowSignInOptions' -Type DWord -Value '0' -Force
	
    Write-LogEntry "Privacy Mitigations :: Disabling Microsoft accounts for modern style apps..."
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'MSAOptional' -Value 1 -Force -TryLGPO:$true

	# Disable the Azure AD Sign In button in the settings app
	Write-LogEntry "Privacy Mitigations :: Disabling Sending data to Microsoft for Application Compatibility Program Inventory..."
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' -Name 'DisableInventory' -Type DWord -Value '1' -Force -TryLGPO:$true
	
	Write-LogEntry "Privacy Mitigations :: Disabling the Microsoft Account Sign-In Assistant..."
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'NoConnectedUser' -Type DWord -Value '3' -Force
	
	# Disable the MSA Sign In button in the settings app
	Write-LogEntry "Privacy Mitigations :: Disabling MSA sign-in options..."
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Settings' -Name 'AllowYourAccount' -Type DWord -Value '0' -Force
	
	Write-LogEntry "Privacy Mitigations :: Disabling camera usage on user's lock screen..."
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name 'NoLockScreenCamera' -Type DWord -Value '1' -Force -TryLGPO:$true
	
    Write-LogEntry "Privacy Mitigations :: Disabling lock screen slideshow..."
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name 'NoLockScreenSlideshow' -Value 1 -Force -TryLGPO:$true
    
    Write-LogEntry "Privacy Mitigations :: Disabling Consumer Features..."
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableWindowsConsumerFeatures' -Type DWord -Value '1' -Force -TryLGPO:$true

    Write-LogEntry "Privacy Mitigations :: Disable the `"how to use Windows`" contextual popups"
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableSoftLanding' -Type DWord -Value '1' -Force -TryLGPO:$true

	# Offline maps
	Write-LogEntry "Privacy Mitigations :: Turning off unsolicited network traffic on the Offline Maps settings page..."
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps' -Name 'AllowUntriggeredNetworkTrafficOnSettingsPage' -Type DWord -Value '0' -Force -TryLGPO:$true

	Write-LogEntry "Privacy Mitigations :: Turning off Automatic Download and Update of Map Data..."
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps' -Name 'AutoDownloadAndUpdateMapData' -Type DWord -Value '0' -Force -TryLGPO:$true
    Set-SystemSetting -Path 'HKLM:\SYSTEM\Maps' -Name 'AutoUpdateEnabled' -Type DWord -Value 0	-Force

	# Microsoft Edge
	Write-LogEntry "Privacy Mitigations :: Enabling Do Not Track in Microsoft Edge..."
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main' -Name 'DoNotTrack' -Type DWord -Value '1' -Force -TryLGPO:$true
	
	Write-LogEntry "Privacy Mitigations :: Disallow web content on New Tab page in Microsoft Edge..."
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\SearchScopes' -Name 'AllowWebContentOnNewTabPage' -Type DWord -Value '0' -Force
	
	# General stuff
	Write-LogEntry "Privacy Mitigations :: Turning off the advertising ID..."
	#Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -Name 'Enabled' -Type DWord -Value '0' -Force
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo' -Name 'DisabledByGroupPolicy' -Type DWord -Value 1 -Force -TryLGPO:$true

	Write-LogEntry "Privacy Mitigations :: Turning off Location Tracking..."
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessLocation' -Type DWord -Value '0' -Force -TryLGPO:$true
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' -Name 'DisableLocation' -Type DWord -Value '0' -Force -TryLGPO:$true
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location' -Name 'Value' -Type String -Value "Deny" -Force 
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}' -Name 'SensorPermissionState' -Type DWord -Value 0 -Force 
	Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration' -Name 'Status' -Type DWord -Value 0 -Force 

	# Stop getting to know me
	Write-LogEntry "Privacy Mitigations :: Turning off automatic learning..."
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization' -Name 'RestrictImplicitInkCollection' -Type DWord -Value '1' -Force -TryLGPO:$true
	# Turn off updates to the speech recognition and speech synthesis models
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences' -Name 'ModelDownloadAllowed' -Type DWord -Value '0' -Force
	
	Write-LogEntry "Privacy Mitigations :: Disallowing Windows apps to access account information..."
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessAccountInfo' -Type DWord -Value '2' -Force -TryLGPO:$true

    Write-LogEntry "Privacy Mitigations :: Disabling Xbox features..."
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR' -Name 'AllowGameDVR' -Type DWord -Value 0 -Force -TryLGPO:$true

    Write-LogEntry "Privacy Mitigations :: Disabling WiFi Sense..."
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting' -Name 'Value' -Type DWord -Value 0 -Force
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots' -Name 'Value' -Type DWord -Value 0 -Force
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config' -Name 'AutoConnectAllowedOEM' -Type DWord -Value 0
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config' -Name 'WiFISenseAllowed' -Type DWord -Value 0

    Write-LogEntry "Privacy Mitigations :: Disabling all feedback notifications..."
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'DoNotShowFeedbackNotifications' -Type DWord -Value '1' -Force -TryLGPO:$true

    If($OptimizeForVDI){$prefixmsg += "VDI Optimizations [OSOT ID:53] :: "}
	Write-LogEntry ("Privacy Mitigations :: {0}Disabling telemetry..." -f $prefixmsg)
	$OsCaption = (Get-WmiObject -class Win32_OperatingSystem).Caption
	If ($OsCaption -like "*Enterprise*" -or $OsCaption -like "*Education*"){
		$TelemetryLevel = "0"
		Write-LogEntry "Privacy Mitigations :: Enterprise edition detected. Supported telemetry level: Security."
	}
	Else{
		$TelemetryLevel = "1"
		Write-LogEntry "Privacy Mitigations :: Lowest supported telemetry level: Basic."
	}
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value $TelemetryLevel -Force -TryLGPO:$true
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value $TelemetryLevel -Force
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value $TelemetryLevel -Force
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform' -Name 'NoGenTicket' -Type DWord -Value 1 -Force -TryLGPO:$true

    Write-LogEntry "Privacy Mitigations :: Hiding 'Share' context menu item"
    Remove-Item -LiteralPath 'Registry::HKCR\*\shellex\ContextMenuHandlers\Sharing' -ErrorAction SilentlyContinue
	Remove-Item -Path 'Registry::HKCR\Directory\Background\shellex\ContextMenuHandlers\Sharing' -ErrorAction SilentlyContinue
	Remove-Item -Path 'Registry::HKCR\Directory\shellex\ContextMenuHandlers\Sharing' -ErrorAction SilentlyContinue
	Remove-Item -Path 'Registry::HKCR\Drive\shellex\ContextMenuHandlers\Sharing' -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath 'Registry::HKCR\*\shellex\ContextMenuHandlers\ModernSharing' -ErrorAction SilentlyContinue

    Set-UserSetting -Message 'Privacy Mitigations :: Disabling Tailored Experiences' -Path 'SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableTailoredExperiencesWithDiagnosticData' -Type DWord -Value 1 -Force -TryLGPO:$true
    Set-UserSetting -Message 'Privacy Mitigations :: Hiding Microsoft Account Protection warning' -Path 'SOFTWARE\Microsoft\Windows Security Health\State' -Name 'AccountProtection_MicrosoftAccount_Disconnected' -Type DWord -Value 1 -Force 
	Set-UserSetting -Message 'Privacy Mitigations :: Disabling Website Access to Language List' -Path 'Control Panel\International\User Profile' -Name 'HttpAcceptLanguageOptOut' -Type DWord -Value 1 -Force 
    Set-UserSetting -Message 'Disabling GameBar' -Path 'SOFTWARE\Microsoft\GameBar' -Name 'AutoGameModeEnabled' -Type DWord -Value 0 
	Set-UserSetting -Message 'Disabling Game DVR' -Path 'SYSTEM\GameConfigStore' -Name 'GameDVR_Enabled' -Type DWord -Value 0 

}
Else{$stepCounter++}

If($DisablePreviewBuild)
{
    Write-LogEntry "Disabling PreviewBuilds capability"
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds' -Name 'AllowBuildPreview' -Type DWord -Value 0 -Force -TryLGPO:$true
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds' -Name 'EnableConfigFlighting' -Type DWord -Value 0 -Force -TryLGPO:$true
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds' -Name 'EnableExperimentation' -Type DWord -Value 0 -Force -TryLGPO:$true
}

If ($EnableWinRM)
{
    Show-ProgressStatus -Message "Enabling WinRM" -Step ($stepCounter++) -MaxStep $script:Maxsteps

    $networkListManager = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]"{DCB00C01-570F-4A9B-8D69-199FDBA5723B}")) 
    $connections = $networkListManager.GetNetworkConnections() 

    # Set network location to Private for all networks 
    $connections | ForEach-Object{$_.GetNetwork().SetCategory(1)}

    # REQUIRED: set network to private before enabling winrm
    $netprofile = (Get-NetConnectionProfile -InterfaceAlias Ethernet*).NetworkCategory
    if (($netprofile -eq "Private") -or ($netprofile -eq "DomainAuthenticated")){<#do noting#>}Else{Set-NetConnectionProfile -NetworkCategory Private}

    Try{
        Enable-PSRemoting -Force -SkipNetworkProfileCheck -ErrorAction SilentlyContinue | Out-Null
        Start-Process winrm -ArgumentList 'qc -quiet' -Wait -NoNewWindow -RedirectStandardOutput ((Get-SMSTSENV -ReturnLogPath -NoWarning) + "\winrm.log") | Out-Null

        If(!(Get-Item WSMan:\localhost\Listener\Listener_*\Port)){Set-Item WSMan:\localhost\Listener\Listener_*\Port -Value '5985' -Force | Out-Null}
        If(!(Get-Item WSMan:\localhost\Listener\Listener_*\Address)){Set-Item WSMan:\localhost\Listener\Listener_*\Address -Value '*' -Force | Out-Null}
        If(!(Get-Item WSMan:\localhost\Listener\Listener_*\Transport)){Set-Item WSMan:\localhost\Listener\Listener_*\Transport -Value 'HTTP' -Force | Out-Null}

        Set-item WSMan:\localhost\Client\Auth\Basic -Value 'true' -Force | Out-Null
        Set-Item WSMan:\localhost\Client\AllowUnencrypted -Value 'true' -Force | Out-Null
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value '*' -Force | Out-Null

        Set-Item WSMan:\localhost\Service\Auth\Basic -Value 'true' -Force | Out-Null

        Set-WSManInstance -ResourceUri winrm/config -ValueSet @{MaxTimeoutms = "1800000"} | Out-Null

        Set-item WSMan:\localhost\Shell\MaxMemoryPerShellMB -Value '800' -Force | Out-Null

        If(!$DisableFirewall)
        {
            netsh advfirewall firewall set rule group="Windows Remote Administration" new enable=yes  | Out-Null
            netsh advfirewall firewall set rule name="Windows Remote Management (HTTP-In)" new enable=yes action=allow  | Out-Null
        }

        Set-Service winrm -startuptype "auto" 
        Restart-Service winrm  | Out-Null

    }
    Catch{
        Write-LogEntry ("Unable to setup WinRM: {0}" -f $_.Exception.ErrorMessage) -Severity 3
    }
}
Else{$stepCounter++}


If($EnableStrictUAC)
{
    Show-ProgressStatus -Message "Enabling strict UAC Level" -Step ($stepCounter++) -MaxStep $script:Maxsteps

    Write-LogEntry "Enabling UAC prompt administrators for consent on the secure desktop..."
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -Type DWord -Value 2 -Force -TryLGPO:$true
    
    Write-LogEntry "Disabling elevation UAC prompt User for consent on the secure desktop..."
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorUser -Type DWord -Value 0 -Force -TryLGPO:$true

    Write-LogEntry "Enabling elevation UAC prompt detect application installations and prompt for elevation..."
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableInstallerDetection' -Type DWord -Value 1 -Force -TryLGPO:$true
    
    Write-LogEntry "Enabling elevation UAC UIAccess applications that are installed in secure locations..."
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableSecureUAIPaths' -Type DWord -Value 1 -Force -TryLGPO:$true

    Write-LogEntry "Enabling Enable virtualize file and registry write failures to per-user locations.."
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableVirtualization' -Type DWord -Value 1 -Force -TryLGPO:$true
        
    Write-LogEntry "Enabling UAC for all administrators..."
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Type DWord -Value 1 -Force -TryLGPO:$true

    Write-LogEntry "Filter Local administrator account privileged tokens..."
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy' -Type DWord -Value 0 -Force -TryLGPO:$true

    Write-LogEntry "Enabling User Account Control approval mode..."
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'FilterAdministratorToken' -Type DWord -Value 1 -Force -TryLGPO:$true

    Write-LogEntry "Disabling enumerating elevated administator accounts..."
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI' -Name 'EnumerateAdministrators' -Type DWord -Value 0 -Force -TryLGPO:$true

    Write-LogEntry "Enable All credential or consent prompting will occur on the interactive user's desktop..."
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'PromptOnSecureDesktop' -Type DWord -Value 1 -Force -TryLGPO:$true

    Write-LogEntry "Enforce cryptographic signatures on any interactive application that requests elevation of privilege..."
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ValidateAdminCodeSignatures' -Type DWord -Value 0 -Force -TryLGPO:$true

}
Else{$stepCounter++}


If ($EnableAppsRunAsAdmin)
{
    Show-ProgressStatus -Message "Enabling UAC to allow Apps to run as Administrator" -Step ($stepCounter++) -MaxStep $script:Maxsteps
    
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'FilterAdministratorToken' -Type DWord -Value '1' -Force -TryLGPO:$true
}
Else{$stepCounter++}


If ($DisableUAC)
{
    Show-ProgressStatus -Message "Disabling User Access Control" -Step ($stepCounter++) -MaxStep $script:Maxsteps

    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Type DWord -Value '0' -Force -TryLGPO:$true
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Type DWord -Value '0' -Forc -TryLGPO:$truee
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'PromptOnSecureDesktop' -Type DWord -Value '0' -Force -TryLGPO:$true
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'FilterAdministratorToken' -Type DWord -Value 0 -Force -TryLGPO:$true
}
Else{$stepCounter++}


If ($DisableAdminShares)
{
    Show-ProgressStatus -Message "Disabling implicit administrative shares" -Step ($stepCounter++) -MaxStep $script:Maxsteps
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'AutoShareWks' -Type DWord -Value 0
}
Else{$stepCounter++}


If ($DisableWUP2P -or $OptimizeForVDI)
{
    If($OptimizeForVDI){$prefixmsg += "VDI Optimizations [OSOT ID:31] :: "}
    Show-ProgressStatus -Message ("{0}Disable P2P WIndows Updates..." -f $prefixmsg) -Step ($stepCounter++) -MaxStep $script:Maxsteps

    If ($OSBuildNumber -eq 10240) {
		# Method used in 1507
		Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config' -Name 'DownloadMode' -Type DWord -Value '1' -Force
        Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config' -Name 'DownloadModeRestricted' -Type DWord -Value '1' -Force
	}
    ElseIf ($OSBuildNumber -le 14393) {
		# Method used in 1511 and 1607
		Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' -Name 'DownloadMode' -Type DWord -Value '1' -Force -TryLGPO:$true
	}
    Else {
		# Method used since 1703
		Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' -Name 'DODownloadMode' -ErrorAction SilentlyContinue
	}
    #adds windows update back to control panel (permissions needs to be changed)
    #Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX' -Name 'IsConvergedUpdateStackEnabled' -Type DWord -Value '0' -Force
}
Else{$stepCounter++}


If ($EnableIEEnterpriseMode)
{
    Show-ProgressStatus -Message "Enabling Enterprise Mode option in IE" -Step ($stepCounter++) -MaxStep $script:Maxsteps

    If(Test-Path $IEEMSiteListPath){
        Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\EnterpriseMode' -Name 'Enable' -Type DWord -Value '1' -Force -TryLGPO:$true
        Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\EnterpriseMode' -Name 'Sitelist' -Value $IEEMSiteListPath -Force -TryLGPO:$true
    }
    Else{
        Write-LogEntry ("IE Enterprise XML Path [{0}] is not found..." -f $IEEMSiteListPath)
    }
}
Else{$stepCounter++}


# Logon script
If ($InstallLogonScript -and (Test-Path $LogonScriptPath) )
{
    Show-ProgressStatus -Message "Copying Logon script to $env:windir\Scripts" -Step ($stepCounter++) -MaxStep $script:Maxsteps

	If (!(Test-Path "$env:windir\Scripts"))
	{
		New-Item "$env:windir\Scripts" -ItemType Directory
	}
	Copy-Item -Path $LogonScriptPath -Destination "$env:windir\Scripts\Logon.ps1" -Force | Out-Null
	
    Set-UserSetting -Message "Creating RunOnce entries" -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Runonce' -Name 'Logon' -Type DWord -Value "Powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File $env:windir\Scripts\Logon.ps1" -Force

}
Else{$stepCounter++}


If($EnableCredGuard)
{
    Show-ProgressStatus -Message "Enabling Virtualization Based Security" -Step ($stepCounter++) -MaxStep $script:Maxsteps

    if ($OSBuildNumber -gt 14393) {
        try {
            # For version older than Windows 10 version 1607 (build 14939), enable required Windows Features for Credential Guard
            Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-HyperVisor -Online -All -LimitAccess -NoRestart -ErrorAction Stop | Out-Null
            Write-LogEntry "Successfully enabled Microsoft-Hyper-V-HyperVisor feature"
        }
        catch [System.Exception] {
            Write-LogEntry ("An error occured when enabling Microsoft-Hyper-V-HyperVisor. Error: -f $_") -Severity 3
        }

        try {
            # For version older than Windows 10 version 1607 (build 14939), add the IsolatedUserMode feature as well
            Enable-WindowsOptionalFeature -FeatureName IsolatedUserMode -Online -All -LimitAccess -NoRestart -ErrorAction Stop | Out-Null
            Write-LogEntry "Successfully enabled IsolatedUserMode feature"
        }
        catch [System.Exception] {
            Write-LogEntry ("An error occured when enabling IsolatedUserMode. Error: -f $_") -Severity 3
        }
    }
    
    Write-LogEntry "Enabling Virtualization-based protection of code integrity..."
    #https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/enable-virtualization-based-protection-of-code-integrity
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -Name 'RequirePlatformSecurityFeatures' -Type DWord -Value 1 -Force
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -Name 'EnableVirtualizationBasedSecurity' -Type DWord -Value 1 -Force
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -Name 'Locked' -Type DWord -Value 0 -Force
    If ($OSBuildNumber -lt 14393) {
        Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -Name 'HypervisorEnforcedCodeIntegrity' -Type DWord -Value 1 -Force
    }
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -Name 'Enabled' -Type DWord -Value 1 -Force
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -Name 'Locked' -Type DWord -Value 0 -Force

    Write-LogEntry "STIG Rule ID: SV-78089r7_rule :: Enabling Credential Guard on domain-joined systems..."
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LsaCfgFlags' -Type DWord -Value 1 -Force   
    
    $DeviceGuardProperty = Get-CimInstance –ClassName Win32_DeviceGuard –Namespace root\Microsoft\Windows\DeviceGuard
    If($DeviceGuardProperty.VirtualizationBasedSecurityStatus -eq 1){
        Write-LogEntry ("Successfully enabled Credential Guard, version: {0}" -f $DeviceGuardProperty.Version)   
    }
    Else{
        Write-LogEntry "Unable to enabled Credential Guard, may not be supported on this model, trying a differnet way" -Severity 2
        . $AdditionalScriptsPath\DG_Readiness_Tool_v3.6.ps1 -Enable -CG
    }
}
Else{$stepCounter++}


If($EnableLinuxSubSystem)
{
    Show-ProgressStatus -Message "Enabling Linux Subsystem" -Step ($stepCounter++) -MaxStep $script:Maxsteps
    If ($OSBuildNumber -eq 14393) {
		# 1607 needs developer mode to be enabled
		Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock' -Name 'AllowDevelopmentWithoutDevLicense' -Type DWord -Value 1
		Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock' -Name 'AllowAllTrustedApps' -Type DWord -Value 1
	}
    Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -NoRestart -WarningAction SilentlyContinue | Out-Null
}
Else{$stepCounter++}


# VDI ONLY CONFIGS
# ===================================
If ($OptimizeForVDI)
{
    Show-ProgressStatus -Message "Configuring VDI Optimizations..." -Step ($stepCounter++) -MaxStep $script:Maxsteps

	
    Write-LogEntry "VDI Optimizations :: Hiding network options from Lock Screen..."
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'DontDisplayNetworkSelectionUI' -Type DWord -Value 1 -Force -TryLGPO:$true

    Write-LogEntry ("VDI Optimizations :: Enabling clearing of recent files on exit...")
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'ClearRecentDocsOnExit' -Type DWord -Value 1 -Force
    
    Write-LogEntry ("VDI Optimizations :: Disabling recent files lists...")
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoRecentDocsHistory' -Type DWord -Value 1 -Force

    Write-LogEntry "VDI Optimizations [OSOT ID:30] :: Disabling Background Layout Service"
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OptimalLayout' -Name 'EnableAutoLayout' -Type DWord -Value 0 -Force

    Write-LogEntry "VDI Optimizations [OSOT ID:31] :: Disabling CIFS Change Notifications"
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoRemoteRecursiveEvents' -Type DWord -Value 0 -Force
    
    Write-LogEntry ("VDI Optimizations :: Disabling Storage Sense")
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageSense' -Name 'AllowStorageSenseGlobal' -Type DWord -Value 0 -Force -TryLGPO:$true

    Write-LogEntry "VDI Optimizations [OSOT ID:32] :: Disabling customer experience improvement program..."
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\SQMClient\Windows' -Name 'CEIPEnable' -Type DWord -Value '0' -Force

    Write-LogEntry "VDI Optimizations [OSOT ID:34] :: Enabling Automatically Reboot for the Crash Control"
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name 'AutoReboot' -Type DWord -Value 1 -Force

    Write-LogEntry "VDI Optimizations [OSOT ID:35] :: Disabling sending alert for the Crash Control..."
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name 'SendAlert' -Type DWord -Value 0 -Force

    Write-LogEntry "VDI Optimizations [OSOT ID:36] :: Disabling writing event to the system log for the Crash Control..."
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name 'LogEvent' -Type DWord -Value 0 -Force

    #Optional
    Write-LogEntry "VDI Optimizations [OSOT ID:37] :: Disable Creation of Crash Dump and removes it..."
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name 'CrashDumpEnabled' -Type DWord -Value 0 -Force

    Write-LogEntry "VDI Optimizations [OSOT ID:38] :: Disabling IPv6..."
	Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'DisabledComponents' -Type DWord -Value '255' -Force
    
    #Optional
    #Write-LogEntry "VDI Optimizations [OSOT ID:39] :: Enabling wait time for disk write or read to take place on the SAN without throwing an error..."
	#Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name "TimeOutValue' -Type DWord -Value '200' -Force

    Write-LogEntry "VDI Optimizations [OSOT ID:41] :: Enabling 120 sec wait timeout for a services..."
	Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name 'ServicesPipeTimeout' -Type DWord -Value '120000' -Force

    #Optional
    Write-LogEntry "VDI Optimizations [OSOT ID:46] :: Removing previous versions capability..."
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'NoPreviousVersionsPage' -Type DWord -Value '1' -Force

    Write-LogEntry "VDI Optimizations [OSOT ID:52] :: Disabling TCP/IP Task Offload..."
	Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP\Parameters' -Name 'DisableTaskOffload' -Type DWord -Value '1' -Force

    #Write-LogEntry "VDI Optimizations [OSOT ID:57] :: Disabling Automatic Update - important for non persistent VMs..."
	#Set-SystemSetting -Path 'HKLM:\SYSTEM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoUpdate' -Type DWord -Value '1' -Force

    Write-LogEntry "VDI Optimizations [OSOT ID:63] :: Disabling NTFS Last Access Timestamp..."
    Start-process fsutil -ArgumentList 'behavior set disablelastaccess 1' -Wait -NoNewWindow
    
    Write-LogEntry "VDI Optimizations [OSOT ID:287] :: Disabling  Boot Optimize Function..."
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Dfrg\BootOptimizeFunction' -Name 'Enable' -Type String -Value '0' -Force

    Write-LogEntry "VDI Optimizations :: Disable Superfetch"
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -Name 'EnableSuperfetch' -Type DWord -Value 0 -Force 

    Write-LogEntry "VDI Optimizations :: Disabling Paging Executive..."
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'DisablePagingExecutive' -Value 1 -Force

    Write-LogEntry "VDI Optimizations :: Disable Storing Recycle Bin Files"
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer' -Name 'NoRecycleFiles' -Type DWord -Value 1 -Force

    Write-LogEntry "VDI Optimizations :: Disk Timeout Value"
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\services\Disk' -Name 'TimeOutValue' -Type DWord -Value 200 -Force

    Write-LogEntry "VDI Optimizations :: Application Event Log Max Size"
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\services\eventlog\Application' -Name 'MaxSize' -Type DWord -Value 100000 -Force

    Write-LogEntry "VDI Optimizations :: Application Event Log Retention"
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\services\eventlog\Application' -Name 'Retention' -Type DWord -Value 0 -Force

    Write-LogEntry "VDI Optimizations :: System Event Log Max Size"
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\services\eventlog\System' -Name 'MaxSize' -Type DWord -Value 100000 -Force

    Write-LogEntry "VDI Optimizations :: System Event Log Retention"
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\services\eventlog\System' -Name 'Retention' -Type DWord -Value 0 -Force

    Write-LogEntry "VDI Optimizations :: Security Event Log Max Size"
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\services\eventlog\Security' -Name 'MaxSize' -Type DWord -Value 100000 -Force

    Write-LogEntry "VDI Optimizations :: Disabling Security Event Log Retention"
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\services\eventlog\Security' -Name 'Retention' -Type DWord -Value 0 -Force

    Write-LogEntry "VDI Optimizations :: Disabling Boot GUI"
    Start-process bcdedit -ArgumentList '/set BOOTUX disabled' -Wait -NoNewWindow | Out-Null

    Write-LogEntry "VDI Optimizations [OSOT ID:290] :: Disabling Boot Debugging"
    Start-process bcdedit -ArgumentList '/bootdebug off' -Wait -NoNewWindow | Out-Null

    Write-LogEntry "VDI Optimizations [OSOT ID:291] :: Disabling Debugging"
    Start-process bcdedit -ArgumentList '/debug off' -Wait -NoNewWindow | Out-Null

    Write-LogEntry "VDI Optimizations [OSOT ID:292] :: Disabling Boot Logging"
    Start-process bcdedit -ArgumentList '/set bootlog no' -Wait -NoNewWindow | Out-Null

    Write-LogEntry "VDI Optimizations :: Disabling automatic recovery mode during boot"
    Start-process bcdedit -ArgumentList '/set BootStatusPolicy IgnoreAllFailures' -Wait -NoNewWindow | Out-Null

    Write-LogEntry "VDI Optimizations :: Disabling System Recovery and Factory reset"
    Start-process reagentc -ArgumentList '/disable'  -Wait -NoNewWindow | Out-Null

    #Write-LogEntry "VDI Optimizations :: Setting Data Execution Prevention (DEP) policy to OptOut"
    #Start-process bcdedit -ArgumentList '/set nx OptOut'  -Wait -NoNewWindow | Out-Null

    Write-LogEntry "VDI Optimizations :: Delete Restore Points for System Restore"
    Start-process vssadmin -ArgumentList 'delete shadows /All /Quiet' -Wait -NoNewWindow | Out-Null
    
    <#
    Write-LogEntry "VDI Optimizations :: Disabling Bootup Trace Loggers"
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AppModel' -Name Start -Type DWord -Value 0 -Force
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\CloudExperienceHostOOBE' -Name Start -Type DWord -Value 0 -Force
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DiagLog' -Name Start -Type DWord -Value 0 -Force
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\NtfsLog' -Name Start -Type DWord -Value 0 -Force
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\TileStore' -Name Start -Type DWord -Value 0 -Force
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\UBPM' -Name Start -Type DWord -Value 0 -Force
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiDriverIHVSession' -Name Start -Type DWord -Value 0 -Force
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession' -Name Start -Type DWord -Value 0 -Force
    #>

    

    Write-LogEntry "VDI Optimizations :: Disabling TLS 1.0"
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Name 'Enabled' -Type DWORD -Value '0' -Force
	Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Name 'DisabledByDefault' -Type DWORD -Value '1' -Force
	Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'Enabled' -Type DWORD -Value '0' -Force
	Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'DisabledByDefault' -Type DWORD -Value '1' -Force

    
    Set-UserSetting -Message "VDI Optimizations :: Change Explorer Default View..." -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'LaunchTo' -Type DWord -Value 1 -Force 
    Set-UserSetting -Message "VDI Optimizations :: Settings Temporary Internet Files to Non Persistent" -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Cache' -Name 'Persistent' -Type DWord -Value 0 -Force
    Set-UserSetting -Message "VDI Optimizations [OSOT 11] :: Disable RSS Feeds" -Path 'SOFTWARE\Microsoft\Feeds' -Name 'SyncStatus' -Type DWord -Value 0 -Force
    Set-UserSetting -Message "VDI Optimizations [OSOT ID:8] :: Disabling show most used apps at start menu" -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'Start_TrackProgs' -Type DWord -Value 0 -Force
    Set-UserSetting -Message "VDI Optimizations [OSOT ID:9] :: Disabling show recent items at start menu" -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'Start_TrackDocs' -Type DWord -Value 0 -Force
    Set-UserSetting -Message "VDI Optimizations [OSOT ID:30] :: Disabling Toast notifications to the lock screen" -Path 'SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' -Name 'NoToastApplicationNotificationOnLockScreen' -Type DWord -Value '1' -Force
    Set-UserSetting -Message "VDI Optimizations [VDIGUYS] :: Remove People Button From the Task Bar in Windows" -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People' -Name 'PeopleBand' -Type DWord -Value 0 -Force


    Set-UserSetting -Message "VDI Optimizations :: Disabling Storage Sense [01]" -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -Name 01 -Type DWord -Value 0 -Force
    Set-UserSetting -Message "VDI Optimizations :: Disabling Storage Sense [02]" -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -Name 02 -Type DWord -Value 0 -Force
    Set-UserSetting -Message "VDI Optimizations :: Disabling Storage Sense [04]" -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -Name 04 -Type DWord -Value 0 -Force
    Set-UserSetting -Message "VDI Optimizations :: Disabling Storage Sense [08]" -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -Name 08 -Type DWord -Value 0 -Force
    Set-UserSetting -Message "VDI Optimizations :: Disabling Storage Sense [32]" -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -Name 32 -Type DWord -Value 0 -Force
    Set-UserSetting -Message "VDI Optimizations :: Disabling Storage Sense [128]" -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -Name 128 -Type DWord -Value 0 -Force
    Set-UserSetting -Message "VDI Optimizations :: Disabling Storage Sense [256]" -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -Name 256 -Type DWord -Value 0 -Force
    Set-UserSetting -Message "VDI Optimizations :: Disabling Storage Sense [512]" -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -Name 512 -Type DWord -Value 0 -Force
    Set-UserSetting -Message "VDI Optimizations :: Disabling Storage Sense [2048]" -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' -Name 2048 -Type DWord -Value 0 -Force
    
}
Else{$stepCounter++}


IF($OptimizeNetwork){

    Write-LogEntry "VDI Optimizations :: Configuring SMB Modifications for performance"
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'DisableBandwidthThrottling' -Type "DWORD" -Value "1" -Force
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'FileInfoCacheEntriesMax' -Type "DWORD" -Value "1024" -Force
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'DirectoryCacheEntriesMax' -Type "DWORD" -Value "1024" -Force
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'FileNotFoundCacheEntriesMax' -Type "DWORD" -Value "1024" -Force
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'DormantFileLimit' -Type "DWORD" -Value "256" -Force
   
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'DisableLargeMtu' -Type DWORD -Value '0' -Force
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'MaxCmds' -Type DWORD -Value '8000' -Force
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'EnableWsd' -Type DWORD -Value '0' -Force
    
    # NIC Advanced Properties performance settings for network biased environments
    If(Get-NetAdapterAdvancedProperty -IncludeHidden -DisplayName "Send Buffer Size" -ErrorAction SilentlyContinue){
        Set-NetAdapterAdvancedProperty -DisplayName "Send Buffer Size" -DisplayValue 4MB
    }
}
Else{$stepCounter++}


If($DisableActivityHistory)
 {
    # Disable Activity History feed in Task View
    #Note: The checkbox "Let Windows collect my activities from this PC" remains checked even when the function is disabled
    Show-ProgressStatus -Message "Disabling Disabling Activity History" -Step ($stepCounter++) -MaxStep $script:Maxsteps

	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableActivityFeed' -Type DWord -Value 0 -Force -TryLGPO:$true
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'PublishUserActivities' -Type DWord -Value 0 -Force -TryLGPO:$true
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'UploadUserActivities' -Type DWord -Value 0 -Force -TryLGPO:$true
}
Else{$stepCounter++}

If($DisableFontSmoothing)
{
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:89] :: "}
    Write-LogEntry ("{0}Disabling Smooth edges of screen fonts Visual Effect..." -f $prefixmsg)
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\FontSmoothing' -Name 'DefaultValue' -Type DWord -Value '0' -Force
}
Else{$stepCounter++}


If($EnableVisualPerformance)
{
    #Additional Performance changes
    
    # thanks to camxct
    #https://github.com/camxct/Win10-Initial-Setup-Script/blob/master/Win10.psm1
    Show-ProgressStatus -Message "Adjusting visual effects for performance" -Step ($stepCounter++) -MaxStep $script:Maxsteps	

    Write-LogEntry ("Disabling Checkbox selections on folders and files..." -f $prefixmsg)
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'AutoCheckSelect' -Type DWord -Value '0' -Force

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:83] :: "}
    Write-LogEntry ("{0}Disabling Animate windows when minimizing and maxmizing Visual Effect..." -f $prefixmsg)
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\AnimateMinMax' -Name 'DefaultValue' -Type DWord -Value '0' -Force

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:84] :: "}
    Write-LogEntry ("{0}Disabling Animations in the taskbar Visual Effect..." -f $prefixmsg)
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TaskbarAnimations' -Name 'DefaultValue' -Type DWord -Value '0' -Force
    
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:85] :: "}
    Write-LogEntry ("{0}Disabling Enable Peek Visual Effect..." -f $prefixmsg)
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMEnabled' -Name 'DefaultValue' -Type DWord -Value '0' -Force
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMAeroPeekEnabled' -Name 'DefaultValue' -Type DWord -Value '0' -Force

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:86] :: "}
    Write-LogEntry ("{0}Disabling Save taskbar thumbnail previews Visual Effect..." -f $prefixmsg)
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMSaveThumbnailEnabled' -Name 'DefaultValue' -Type DWord -Value '0' -Force

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:87] :: "}
    Write-LogEntry ("{0}Disabling Show translucent selection rectangle Visual Effect..." -f $prefixmsg)
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListviewAlphaSelect' -Name 'DefaultValue' -Type DWord -Value '0' -Force

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:88] :: "}
    Write-LogEntry ("{0}Disabling Show window contents while dragging Visual Effect..." -f $prefixmsg)
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DragFullWindows' -Name 'DefaultValue' -Type DWord -Value '0' -Force

    
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:90] :: "}
    Write-LogEntry ("{0}Disabling Use drop shadows for icon labels on the desktop Visual Effect..." -f $prefixmsg)
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListviewShadow' -Name 'DefaultValue' -Type DWord -Value '0' -Force
    
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:72] :: "}
    Set-UserSetting -Message ("{0}Setting Windows Visual Effects to Optimized for best performance" -f $prefixmsg) -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' -Name 'VisualFXSetting' -Type DWord -Value 3 -Force
    Set-UserSetting -Message ("{0}Disabling Checkbox selections on folders and files" -f $prefixmsg) -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'AutoCheckSelect' -Type DWord -Value '0' -Force

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:83] :: "}
	Set-UserSetting -Message ("{0}Disabling Animate windows when minimizing and maxmizing Visual Effect" -f $prefixmsg) -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\AnimateMinMax' -Name 'DefaultValue' -Type DWord -Value '0' -Force

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:84] :: "}
	Set-UserSetting -Message ("{0}Disabling Animations in the taskbar Visual Effect" -f $prefixmsg) -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TaskbarAnimations' -Name 'DefaultValue' -Type DWord -Value '0' -Force

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:85] :: "}
    Set-UserSetting -Message ("{0}Disabling Enable Peek Visual Effect" -f $prefixmsg) -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMEnabled' -Name 'DefaultValue' -Type DWord -Value '0' -Force
    Set-UserSetting -Message ("{0}Disabling Enable Peek Visual Effect" -f $prefixmsg) -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMAeroPeekEnabled' -Name 'DefaultValue' -Type DWord -Value '0' -Force

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:86] :: "}
	Set-UserSetting -Message ("{0}Disabling Save taskbar thumbnail previews Visual Effect" -f $prefixmsg) -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMSaveThumbnailEnabled' -Name 'DefaultValue' -Type DWord -Value '0' -Force

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:87] :: "}
	Set-UserSetting -Message ("{0}Disabling Show translucent selection rectangle Visual Effect" -f $prefixmsg) -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListviewAlphaSelect' -Name 'DefaultValue' -Type DWord -Value '0' -Force

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:88] :: "}
	Set-UserSetting -Message ("{0}Disabling Show window contents while dragging Visual Effect" -f $prefixmsg) -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DragFullWindows' -Name 'DefaultValue' -Type DWord -Value '0' -Force

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:89] :: "}
	Set-UserSetting -Message ("{0}Disabling Smooth edges of screen fonts Visual Effect" -f $prefixmsg) -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\FontSmoothing' -Name 'DefaultValue' -Type DWord -Value '0' -Force

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:90] :: "}
	Set-UserSetting -Message ("{0}Disabling Use drop shadows for icon labels on the desktop Visual Effect" -f $prefixmsg) -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListviewShadow' -Name 'DefaultValue' -Type DWord -Value '0' -Force
    
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:73] :: "}
    Set-UserSetting -Message ("{0}Disabling Animate windows when minimizing and maxmizing Visual Effect" -f $prefixmsg) -Path 'Control Panel\Desktop\WindowMetrics' -Name 'MinAnimate' -Type String -Value 0 -Force

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:74] :: "}
    Set-UserSetting -Message ("{0}Disabling Animations in the taskbar Visual Effect" -f $prefixmsg) -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'TaskbarAnimations' -Type DWord -Value 0 -Force

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:75] :: "}
    Set-UserSetting -Message ("{0}Disabling Peek Visual Effect" -f $prefixmsg) -Path 'SOFTWARE\Microsoft\Windows\DWM' -Name 'EnableAeroPeek' -Type DWord -Value 0 -Force

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:76] :: "}
    Set-UserSetting -Message ("{0}Turning off Play animations in windows" -f $prefixmsg) -Path 'Control Panel\Desktop' -Name 'UserPreferencesMask' -Type Binary -Value 9012038010000000 -Force

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:77] :: "}
    Set-UserSetting -Message ("{0}Disabling Save taskbar thumbnail previews Visual Effect" -f $prefixmsg) -Path 'SOFTWARE\Microsoft\Windows\DWM' -Name 'AlwaysHibernateThumbnails' -Type DWord -Value 0 -Force

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:78] :: "}
    Set-UserSetting -Message ("{0}Disabling Show translucent selection rectangle Visual Effect" -f $prefixmsg) -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ListviewAlphaSelect' -Type DWord -Value 0 -Force

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:79] :: "}
    Set-UserSetting -Message ("{0}Disabling Show window contents while dragging Visual Effect" -f $prefixmsg) -Path 'Control Panel\Desktop' -Name 'DragFullWindows' -Type String -Value 0 -Force

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:80] :: "}
    Set-UserSetting -Message ("{0}Disabling Smooth edges of screen fonts Visual Effect" -f $prefixmsg) -Path 'Control Panel\Desktop' -Name 'FontSmoothing' -Type String -Value 0 -Force

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:81] :: "}
    Set-UserSetting -Message ("{0}Disabling Use drop shadows for icon labels on the desktop Visual Effect" -f $prefixmsg) -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ListviewShadow' -Type DWord -Value 0 -Force

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:10] :: "}
    Write-LogEntry ("{0}Disabling Keyboard and Menu Delay for AllUsers" -f $prefixmsg)
    Set-UserSetting -Message ("{0}Setting Delaying Show the Reduce Menu" -f $prefixmsg) -Path 'Control Panel\Desktop' -Name MenuShowDelay -Type DWord -Value 120 -Force
	Set-UserSetting -Message ("{0}Removing Keyboard Delay the Reduce Menu" -f $prefixmsg) -Path 'Control Panel\Keyboard' -Name 'KeyboardDelay' -Type DWord -Value 0 -Force
    
    Set-UserSetting -Message ("Disabling creating thumbnail cache [Thumbs.db] on local Folder") -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'DisableThumbnailCache' -Type DWord -Value 1 -Force
    Set-UserSetting -Message ("Disabling creating thumbnail cache [Thumbs.db] on Network Folders") -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'DisableThumbsDBOnNetworkFolders' -Type DWord -Value 1 -Force
    Set-UserSetting -Message ("Enabling TaskBar Icons Only") -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'IconsOnly' -Type DWord -Value 1 -Force
    Set-UserSetting -Message ("Disabling Desktop Shortcut Icons") -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideIcons' -Type DWord -Value 0 -Force   
    Set-UserSetting -Message ("Disabling Explorer Information Tip") -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ShowInfoTip' -Type DWord -Value 0 -Force
    Set-UserSetting -Message ("Disabling Combobox Slide Animations") -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ComboBoxAnimation' -Name 'DefaultApplied' -Type DWord -Value '0' -Force
    Set-UserSetting -Message ("Disabling Window Animations") -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ControlAnimations' -Name 'DefaultApplied' -Type DWord -Value '0' -Force
    Set-UserSetting -Message ("Disabling Cursor Shadow") -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\CursorShadow' -Name 'DefaultApplied' -Type DWord -Value '0' -Force
    Set-UserSetting -Message ("Disabling Content while dragging") -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DragFullWindows' -Name 'DefaultApplied' -Type DWord -Value '0' -Force
    Set-UserSetting -Message ("Disabling Window shadows") -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DropShadow' -Name 'DefaultApplied' -Type DWord -Value '0' -Force
    Set-UserSetting -Message ("Disabling Listbox smooth scrolling") -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListBoxSmoothScrolling' -Name 'DefaultApplied' -Type DWord -Value '0' -Force
    Set-UserSetting -Message ("Disabling Start Menu Animations") -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\MenuAnimation' -Name 'DefaultApplied' -Type DWord -Value '0' -Force
    Set-UserSetting -Message ("Disabling Windows Fade") -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\SelectionFade' -Name 'DefaultApplied' -Type DWord -Value '0' -Force
    Set-UserSetting -Message ("Disabling Themes") -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\Themes' -Name 'DefaultApplied' -Type DWord -Value '0' -Force
    Set-UserSetting -Message ("Disabling Thumbnails") -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ThumbnailsOrIcon' -Name 'DefaultApplied' -Type DWord -Value '0' -Force
    Set-UserSetting -Message ("Disabling ToolTip Animations") -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TooltipAnimation' -Name 'DefaultApplied' -Type DWord -Value '0' -Force
}
Else{$stepCounter++}


If($EnableDarkTheme)
{
    Show-ProgressStatus -Message "Enabling Dark Theme" -Step ($stepCounter++) -MaxStep $script:Maxsteps
    Set-UserSetting -Message "Enabling Dark Theme" -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name 'AppsUseLightTheme' -Type DWord -Value 0 -Force 
}
Else{$stepCounter++}


If($EnableTaskbarAutoColor)
{
    Show-ProgressStatus -Message "Enabing Taskbar AutoColorization" -Step ($stepCounter++) -MaxStep $script:Maxsteps
    Set-UserSetting -Message "Enabing Taskbar AutoColorization" -Path 'Control Panel\Desktop' -Name AutoColorization -Type DWord -Value 1
}
Else{$stepCounter++}


If($EnableNumlockStartup)
{
    Show-ProgressStatus -Message "Enabling NumLock after startup" -Step ($stepCounter++) -MaxStep $script:Maxsteps

    #Write-LogEntry  ("Enabing Num lock for Default")
	#Set-SystemSetting -Path 'HKEY_USERS\.DEFAULT\Control Panel\Keyboard' -Name 'InitialKeyboardIndicators' -Type DWord -Value 2147483650 -Force
    Set-UserSetting -Message "Enabing Num lock" -Path 'Control Panel\Keyboard' -Name InitialKeyboardIndicators -Type DWord -Value 2147483650 -Force

	Add-Type -AssemblyName System.Windows.Forms
	If (!([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
		$wsh = New-Object -ComObject WScript.Shell
		$wsh.SendKeys('{NUMLOCK}')
	}
}
Else{$stepCounter++}


If($ShowKnownExtensions)
{
    Show-ProgressStatus -Message "Enabling known extensions" -Step ($stepCounter++) -MaxStep $script:Maxsteps
    Set-UserSetting -Message "Showing known file extensions" -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideFileExt' -Type DWord -Value 0 -Force
   
    #Write-LogEntry "Showing known file extensions for SYSTEM..."
	#Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideFileExt' -Type DWord -Value 0 -Force

}
Else{$stepCounter++}


If($ShowHiddenFiles)
{   
    Show-ProgressStatus -Message "Enabling hidden files" -Step ($stepCounter++) -MaxStep $script:Maxsteps
    Set-UserSetting -Message "Showing hidden files" -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'Hidden' -Type DWord -Value 1 -Force
}
Else{$stepCounter++}


If($ShowThisPCOnDesktop)
{
    Show-ProgressStatus -Message "Adding 'This PC' desktop shortcut" -Step ($stepCounter++) -MaxStep $script:Maxsteps
    Set-UserSetting -Message "Adding 'This PC' desktop shortcut" -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu' -Name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -Type DWord -Value 0 -Force
    Set-UserSetting -Message "Adding 'This PC' desktop shortcut" -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{20D04FE0-3AEA-1069-A2D8-08002B30309D}' -Type DWord -Value 0 -Force
}
Else{$stepCounter++}


If($ShowUserFolderOnDesktop)
{
    Show-ProgressStatus -Message "Adding 'User Folder' desktop shortcut" -Step ($stepCounter++) -MaxStep $script:Maxsteps
    Set-UserSetting -Message "Adding 'User Folder' desktop shortcut" -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu' -Name '{59031a47-3f72-44a7-89c5-5595fe6b30ee}' -Type DWord -Value 0 -Force
    Set-UserSetting -Message "Adding 'User Folder' desktop shortcut" -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{59031a47-3f72-44a7-89c5-5595fe6b30ee}' -Type DWord -Value 0 -Force
}
Else{$stepCounter++}


If($RemoveRecycleBinOnDesktop)
{
    Show-ProgressStatus -Message "Removing 'Recycle Bin' desktop shortcut" -Step ($stepCounter++) -MaxStep $script:Maxsteps
    Set-UserSetting -Message "Removing 'Recycle Bin' desktop shortcut" -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu' -Name '{645FF040-5081-101B-9F08-00AA002F954E}' -Type DWord -Value 1 -Force
    Set-UserSetting -Message "Removing 'Recycle Bin' desktop shortcut" -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{645FF040-5081-101B-9F08-00AA002F954E}' -Type DWord -Value 1 -Force
}
Else{$stepCounter++}


# Disable Application suggestions and automatic installation
If ($DisableAppSuggestions)
{
    $AppSuggestions = [ordered]@{
        ContentDeliveryAllowed="Content Delivery"
	    OemPreInstalledAppsEnabled="Oem PreInstalled Apps"
	    PreInstalledAppsEnabled="PreInstalled Apps"
	    PreInstalledAppsEverEnabled="PreInstalled Apps Ever"
	    SilentInstalledAppsEnabled="Automatically Installing Suggested Apps"
	    "SubscribedContent-310093Enabled"="Show me the Windows welcome experience after updates and occasionally when I sign in to highlight what's new and suggested"
	    "SubscribedContent-338387Enabled"="Get fun facts, tips and more from Windows and Cortana on your lock screen"
	    "SubscribedContent-338388Enabled"="Occasionally show suggestions in Start"
	    "SubscribedContent-338389Enabled"="Get Tips, Tricks, and Suggestions Notifications"
	    "SubscribedContent-338393Enabled"="Show me sggested Content in Settings app"
        "SubscribedContent-353694Enabled"="Show me sggested Content in Settings app"   
        "SubscribedContent-353696Enabled"="Show me sggested Content in Settings app"
	    "SubscribedContent-353698Enabled"="Show suggestions occasionally in Timeline"
	    SystemPaneSuggestionsEnabled="SystemPane Suggestions"
    }
    $i = 1

    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableWindowsConsumerFeatures' -Type DWord -Value 1 -Force -TryLGPO:$true

    Foreach ($key in $AppSuggestions.GetEnumerator()){
        $AdName = $key.Value
        Write-LogEntry ("Disabling `"{0}`" option [{1}]..." -f $AdName,$key.Key)

        Show-ProgressStatus -Message "Disabling App Suggestions" -SubMessage ("Disabling: `"{2}`" ({0} of {1})" -f $i,$AppSuggestions.count,$AdName) -Step $i -MaxStep $AppSuggestions.count
        Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name $key.Key -Type DWord -Value 0

        Set-UserSetting -Message "Disabling App Suggestion" -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name $key.Key -Type DWord -Value 0 -Force
        <#
        If ($OSBuildNumber -ge 17134) {
            Set-UserSetting -Message "Disabling App Suggestion" -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\*windows.data.placeholdertilecollection\Current' -Name 'Data' -Type Binary -Value " 虦퐁�ǔ " -Force
        }
        #>
    }

    Stop-Process -Name "ShellExperienceHost" -Force -ErrorAction SilentlyContinue
}
Else{$stepCounter++}


If($Hide3DObjectsFromExplorer)
{
    Show-ProgressStatus -Message "Hiding 3D Objects icon from Explorer namespace" -Step ($stepCounter++) -MaxStep $script:Maxsteps
    Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}' -Recurse -ErrorAction SilentlyContinue -Force  | Out-Null
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag' -Name 'ThisPCPolicy' -Type String -Value "Hide" -Force
    Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}' -Recurse -ErrorAction SilentlyContinue
}
Else{$stepCounter++}


If($DisableEdgeShortcutCreation)
{
    Show-ProgressStatus -Message "Disabling Edge shortcut creation" -Step ($stepCounter++) -MaxStep $script:Maxsteps
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'DisableEdgeDesktopShortcutCreation' -Type DWord -Value 1 -Force
    
    Write-LogEntry "Disabling Edge preload..."
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main' -Name 'AllowPrelaunch' -Type DWord -Value 0 -Force -TryLGPO:$true
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader' -Name 'AllowTabPreloading' -Type DWord -Value 0 -Force -TryLGPO:$true
}
Else{$stepCounter++}


If($SetSmartScreenFilter)
{
	switch($SetSmartScreenFilter){
    'Off'  {$value = 0;$label = "to Disable"}
    'User'  {$value = 1;$label = "to Warning Users"}
    'admin' {$value = 2;$label = "to Require Admin approval"}
    default {$value = 1;$label = "to Warning Users"}
    }
    Show-ProgressStatus -Message "Configuring Smart Screen Filter $label" -Step ($stepCounter++) -MaxStep $script:Maxsteps

    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableSmartScreen' -Type DWord -Value $value -Force -TryLGPO:$true
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'ShellSmartScreenLevel' -Type String -Value "Block" -Force -TryLGPO:$true

    Write-LogEntry "Enabling Smart Screen Filter on Edge..."
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' -Name 'PreventOverride' -Type DWord -Value 1 -Force -TryLGPO:$true
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' -Name 'PreventOverrideAppRepUnknown' -Type DWord -Value 1 -Force -TryLGPO:$true
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' -Name 'EnabledV9' -Type DWord -Value $value -Force -TryLGPO:$true
}
Else{$stepCounter++}


If ($DisableFirewall)
{
    
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:59] :: "}
    Show-ProgressStatus -Message ("{0}Disabling Windows Firewall on all profiles" -f $prefixmsg) -Step ($stepCounter++) -MaxStep $script:Maxsteps
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile' -Name 'EnableFirewall' -Type DWord -Value 0 -Force -TryLGPO:$true
    
    netsh advfirewall set allprofiles state off | Out-Null
    Try{
        Get-Service 'mpssvc' | Set-Service -StartupType Disabled -ErrorAction Stop
    }
    Catch [System.Management.Automation.ActionPreferenceStopException]{
        Write-LogEntry ("Unable to Disable Windows Firewall: {0}" -f $_) -Severity 3
    }
}
Else{$stepCounter++}


If($CleanSampleFolders)
{
    Show-ProgressStatus -Message "Cleaning Sample Folders" -Step ($stepCounter++) -MaxStep $script:Maxsteps

    Remove-Item "$env:PUBLIC\Music\Sample Music" -Recurse -ErrorAction SilentlyContinue | Out-Null
    Remove-Item "$env:PUBLIC\Pictures\Sample Pictures" -Recurse -ErrorAction SilentlyContinue | Out-Null
    Remove-Item "$env:PUBLIC\Recorded TV\Sample Media" -Recurse -ErrorAction SilentlyContinue | Out-Null
    Remove-Item "$env:PUBLIC\Videos\Sample Videos" -Recurse -ErrorAction SilentlyContinue | Out-Null
}
Else{$stepCounter++}


If($DisableIndexing -or $OptimizeForVDI)
{
    Show-ProgressStatus -Message "Disable Indexing on $env:SystemDrive" -Step ($stepCounter++) -MaxStep $script:Maxsteps

    Disable-Indexing $env:SystemDrive
}
Else{$stepCounter++}


If ($DisableRestore -or $OptimizeForVDI)
{
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:66] :: "}
    Show-ProgressStatus -Message ("{0}Disabling system restore..." -f $prefixmsg) -Step ($stepCounter++) -MaxStep $script:Maxsteps

    Disable-ComputerRestore -drive c:\
}
Else{$stepCounter++}


If ($PreCompileAssemblies -or $OptimizeForVDI)
{
    #https://www.emc.com/collateral/white-papers/h14854-optimizing-windows-virtual-desktops-deploys.pdf
    #https://blogs.msdn.microsoft.com/dotnet/2012/03/20/improving-launch-performance-for-your-desktop-applications/
    Show-ProgressStatus -Message "Pre-compile .NET framework assemblies. This can take a while...." -Step ($stepCounter++) -MaxStep $script:Maxsteps

    Start-Process "$env:windir\Microsoft.NET\Framework\v4.0.30319\ngen.exe" -ArgumentList "update /force" -Wait -NoNewWindow
    Start-Process "$env:windir\Microsoft.NET\Framework\v4.0.30319\ngen.exe" -ArgumentList "executequeueditems" -Wait -NoNewWindow
}
Else{$stepCounter++}


If($RemoveUnusedPrinters)
{
    Show-ProgressStatus -Message ("Removing Unused Local Printers...") -Step ($stepCounter++) -MaxStep $script:Maxsteps
    
    $filter = "Microsoft XPS Document Writer|Microsoft Print to PDF|OneNote" #Send To OneNote 16
    Get-Printer | Where-Object{($_.Name -notmatch $filter) -and ($_.Type -eq 'Local') } | Remove-Printer -PassThru -Confirm:$false
}
Else{$stepCounter++}

Show-ProgressStatus -Message 'Completed Windows 10 Optimizations and Configuration' -Step $script:maxSteps -MaxStep $script:maxSteps