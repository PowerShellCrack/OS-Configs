<#	
	.NOTES
	===========================================================================
	 Originally Created by:   	Anton Romanyuk
     Added more capibilities:   Richard Tracy
	 Filename:     	            Win10OptimizeAndConfig.ps1
     Last Updated:              12/14/2018
	===========================================================================
	.DESCRIPTION
		Applies Windows 10 Optimazations and configurations. Supports VDI optmizations
        Utilizes LGPO.exe to apply group policy item where neceassary. 
        Supports MDT/SCCM TaskSequence variables:
           _SMSTSLogPath . Logs to temp if not used
        Configurable using custom variables:
            CFG_UseLGPOForConfigs
            LGPOPath
            CFG_SetPowerCFG
            CFG_PowerCFGFilePath
            CFG_EnableVerboseMsg
            CFG_EnablePSLogging
            CFG_ApplySTIGItems
            CFG_DisableAutoRun
            CFG_CleanSampleFolders
            CFG_DisableCortana
            CFG_DisableInternetSearch
            CFG_EnableVDIOptimizations
            CFG_EnableOfficeOneNote
            CFG_EnableRDP
            CFG_DisableOneDrive
            CFG_PreferIPv4OverIPv6
            CFG_RemoveActiveSetupComponents
            CFG_DisableWindowsFirstLoginAnimation
            CFG_DisableIEFirstRunWizard
            CFG_DisableWMPFirstRunWizard
            CFG_DisableEdgeIconCreation
            CFG_DisableNewNetworkDialog
            CFG_DisableInternetServices
            CFG_DisabledUnusedServices
            CFG_DisabledUnusedFeatures
            CFG_DisableSchTasks
            CFG_DisableDefender
            CFG_DisableFirewall
            CFG_DisableWireless
            CFG_DisableBluetooth
            CFG_EnableRemoteRegistry
            CFG_DisableFirewall
            CFG_ApplyPrivacyMitigations
            CFG_EnableCredGuard
            CFG_InstallLogonScript
            CFG_LogonScriptPath
            CFG_EnableWinRM
            CFG_EnableAppsRunAsAdmin
            CFG_DisableUAC
            CFG_DisableWUP2P
            CFG_EnableIEEnterpriseMode
            CFG_IEEMSiteListPath
            CFG_PreCompileAssemblies
            CFG_DisableIndexing
            CFG_EnableSecureLogon
            CFG_HideDrives
            CFG_DisableAllNotifications
            CFG_InstallPSModules
#>


##*===========================================================================
##* FUNCTIONS
##*===========================================================================
function Write-LogEntry {
    param(
        [parameter(Mandatory=$true, HelpMessage="Value added to the log file.")]
        [ValidateNotNullOrEmpty()]
        [string]$Value,

        [parameter(Mandatory=$false)]
        [ValidateSet(0,1,2,3)]
        [int16]$Severity,

        [parameter(Mandatory=$false, HelpMessage="Name of the log file that the entry will written to.")]
        [ValidateNotNullOrEmpty()]
        [string]$fileArgName = $LogFilePath,

        [parameter(Mandatory=$false)]
        [switch]$Outhost
    )
    
    [string]$LogTime = (Get-Date -Format 'HH:mm:ss.fff').ToString()
	[string]$LogDate = (Get-Date -Format 'MM-dd-yyyy').ToString()
	[int32]$script:LogTimeZoneBias = [timezone]::CurrentTimeZone.GetUtcOffset([datetime]::Now).TotalMinutes
	[string]$LogTimePlusBias = $LogTime + $script:LogTimeZoneBias
    #  Get the file name of the source script

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
    $LogFormat = "<![LOG[$Value]LOG]!>" + "<time=`"$LogTimePlusBias`" " + "date=`"$LogDate`" " + "component=`"$ScriptSource`" " + "context=`"$([Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " + "type=`"$Severity`" " + "thread=`"$PID`" " + "file=`"$ScriptSource`">"
    
    # Add value to log file
    try {
        Out-File -InputObject $LogFormat -Append -NoClobber -Encoding Default -FilePath $LogFilePath -ErrorAction Stop
    }
    catch [System.Exception] {
        Write-LogEntry -Message "Unable to append log entry to $LogFilePath file"
    }
    If($Outhost){
        Switch($Severity){
            0       {Write-Host $Value -ForegroundColor Gray}
            1       {Write-Host $Value}
            2       {Write-Warning $Value}
            3       {Write-Host $Value -ForegroundColor Red}
            default {Write-Host $Value}
        }
    }
}

Function Config-Bluetooth{
    [CmdletBinding()] 
    Param (
    [Parameter(Mandatory=$true)][ValidateSet('Off', 'On')]
    [string]$DeviceStatus
    )
    If ((Get-Service bthserv).Status -eq 'Stopped') { Start-Service bthserv }
    
    Add-Type -AssemblyName System.Runtime.WindowsRuntime
    $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | ? { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
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
    $bluetooth = $radios | ? { $_.Kind -eq 'Bluetooth' }
    [Windows.Devices.Radios.RadioState,Windows.System.Devices,ContentType=WindowsRuntime] | Out-Null
    If($bluetooth){
        Try{
            Await ($bluetooth.SetStateAsync($DeviceStatus)) ([Windows.Devices.Radios.RadioAccessStatus]) | Out-Null
        }
        Catch{
            Write-LogEntry ("Unable to configure Bluetooth Settings: {0}" -f $_.Exception.ErrorMessage) -Severity 3 -Outhost
        }
    }
    Else{
        Write-LogEntry ("No Bluetooth found") -Severity 0 -Outhost
    }
    
}


function Disable-Indexing {
    Param($Drive)
    $obj = Get-WmiObject -Class Win32_Volume -Filter "DriveLetter='$Drive'"
    $indexing = $obj.IndexingEnabled
    if("$indexing" -eq $True){
        write-host "Disabling indexing of drive $Drive"
        $obj | Set-WmiInstance -Arguments @{IndexingEnabled=$False} | Out-Null
    }
}



Function Configure-RegistryItem {
    [CmdletBinding()] 
    Param (
    [Parameter(Mandatory=$true)]
    [Alias("Path")]
    [string]$RegPath,
    [Parameter(Mandatory=$false)]
    [string]$Name,
    [Parameter(Mandatory=$true)]
    [string]$Value,
    [Parameter(Mandatory=$false)]
    [ValidateSet('None','String','Binary','DWord','ExpandString','MultiString','QWord')]
    [Alias("PropertyType")]
    $Type,
    [boolean]$TryLGPO = $Global:LGPOForConfigs,
    $LGPOExe = $Global:LGPOPath,
    [string]$LogPath,
    [switch]$Force
    )
    Begin
    {
         If($TryLGPO){
            #$lgpoout = $null
            $lgpoout = "; ----------------------------------------------------------------------`r`n"
            $lgpoout += "; PROCESSING POLICY`r`n"
            $lgpoout += "; Source file:`r`n"
            $lgpoout += "`r`n"
        }
    }

    Process
    {
        If($TryLGPO -and $LGPOExe){
            If(Test-Path $LGPOExe){
                $RegKeyHive = ($RegPath).Split('\')[0].Replace(':','')
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
                    HKEY_LOCAL_MACHINE {$LGPOHive = 'Computer';$RegProperty = 'HKLM:'}
                    MACHINE {$LGPOHive = 'Computer';$RegProperty = 'HKLM:'}
                    HKLM {$LGPOHive = 'Computer';$RegProperty = 'HKLM:'}
                    HKEY_CURRENT_USER {$LGPOHive = 'User';$RegProperty = 'HKCU:'}
                    HKEY_USERS {$LGPOHive = 'User';$RegProperty = 'HKCU:'}
                    HKCU {$LGPOHive = 'User';$RegProperty = 'HKCU:'}
                    HKU {$LGPOHive = 'User';$RegProperty = 'HKCU:'}
                    USER {$LGPOHive = 'User';$RegProperty = 'HKCU:'}
                    default {$LGPOHive = 'Computer';$RegProperty = 'HKLM:'}
                }

                #https://www.motobit.com/help/RegEdit/cl72.htm
                <#Switch($Type){
                    0 {$RegType = 'NONE'}
                    1 {$RegType = 'SZ'}
                    2 {$RegType = 'EXPAND_SZ'}
                    3 {$RegType = 'BINARY'}
                    4 {$RegType = 'DWord'}
                    5 {$RegType = 'DWord_BIG_ENDIAN'}
                    6 {$RegType = 'LINK'}
                    7 {$RegType = 'SZ'}
                }
                #>
                Switch($Type){
                    'None' {$RegType = 'NONE'}
                    'String' {$RegType = 'SZ'}
                    'ExpandString' {$RegType = 'EXPAND_SZ'}
                    'Binary' {$RegType = 'BINARY'}
                    'DWord' {$RegType = 'DWORD'}
                    'QWord' {$RegType = 'DWORD_BIG_ENDIAN'}
                    'MultiString' {$RegType = 'LINK'}
                    default {$RegType = 'DWORD'}
                }
                # build a unique output file
                $LGPOfile = ($RegKeyHive + '-' + $RegKeyPath.replace('\','-').replace(' ','') + '-' + $RegKeyName.replace(' ','') + '.lgpo')
            
                #complete LGPO file
                Write-Verbose ("LGPO applying [{3}] to registry: [{0}\{1}\{2}] as a Group Policy item" -f $RegProperty,$RegKeyPath,$RegKeyName,$RegKeyName)
                $lgpoout += "$LGPOHive`r`n"
                $lgpoout += "$RegKeyPath`r`n"
                $lgpoout += "$RegKeyName`r`n"
                $lgpoout += "$($RegType):$Value`r`n"
                $lgpoout += "`r`n"
                $lgpoout | Out-File "$env:Temp\$LGPOfile"

                Write-Verbose "Start-Process $LGPOExe -ArgumentList '/t $env:Temp\$LGPOfile' -RedirectStandardError '$env:Temp\$LGPOfile.stderr.log'"
                $result = Start-Process $LGPOExe -ArgumentList "/t $env:Temp\$LGPOfile /v" -RedirectStandardError "$env:Temp\$LGPOfile.stderr.log" -Wait -NoNewWindow -PassThru
            }
            Else{
                Write-Verbose ("LGPO will not be used. Path not found: {0}" -f $LGPOExe)
            }
        }
    }
    End {
        If(!$result -or $result.ExitCode -ne 0){
            Write-Host ("LGPO failed to run. exit code: {0}. Hardcoding registry keys...." -f $result.ExitCode) -ForegroundColor Gray
            If(Test-Path ($RegProperty +'\'+ $RegKeyPath)){
                Configure-RegistryItem -Path ($RegProperty +'\'+ $RegKeyPath) -Name $RegKeyName -Value $Value -Type $Type -Force:$Force    
            }
            Else{
                New-Item -Path ($RegProperty +'\'+ $RegKeyPath) -Name $RegKeyName -Force:$Force | Out-Null
                Configure-RegistryItem -Path ($RegProperty +'\'+ $RegKeyPath) -Name $RegKeyName -Type DWord -Value $Value -Force:$Force
                Configure-RegistryItem -Path ($RegProperty +'\'+ $RegKeyPath) -Name $RegKeyName -Value $Value -Type $Type -Force:$Force
            }
        }
        Else{
            Write-Verbose  ("LGPO ran successfully. Exit code: {0}" -f $result.ExitCode)
        }

        If(Test-Path "$env:Temp\$LGPOfile"){
               Remove-Item "$env:Temp\$LGPOfile" -Force
               #Remove-Item "$env:Temp" -Include "$LGPOfile*" -Recurse -Force
        }
    }

}
##*===========================================================================
##* VARIABLES
##*===========================================================================
## Instead fo using $PSScriptRoot variable, use the custom InvocationInfo for ISE runs
If (Test-Path -LiteralPath 'variable:HostInvocation') { $InvocationInfo = $HostInvocation } Else { $InvocationInfo = $MyInvocation }
[string]$scriptDirectory = Split-Path -Path $InvocationInfo.MyCommand.Definition -Parent
[string]$scriptPath = $InvocationInfo.MyCommand.Definition
[string]$scriptName = [IO.Path]::GetFileNameWithoutExtension($scriptPath)

#Create Paths
$ToolsPath = Join-Path $scriptDirectory -ChildPath Tools
$AdditionalScriptsPath = Join-Path $scriptDirectory -ChildPath Scripts

# Get each user profile SID and Path to the profile
$AllProfiles = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" | Where {$_.PSChildName -match "S-1-5-21-(\d+-?){4}$" } | Select-Object @{Name="SID"; Expression={$_.PSChildName}}, @{Name="UserHive";Expression={"$($_.ProfileImagePath)\NTuser.dat"}}

# Add in the .DEFAULT User Profile
$DefaultProfile = "" | Select-Object SID, UserHive
$DefaultProfile.SID = ".DEFAULT"
$DefaultProfile.Userhive = "$env:PUBLIC\NTuser.dat"

#Add it to the UserProfile list
$UserProfiles = @()
$UserProfiles += $AllProfiles
$UserProfiles += $DefaultProfile

Try
{
	$tsenv = New-Object -COMObject Microsoft.SMS.TSEnvironment
	#$logPath = $tsenv.Value("LogPath")
    $LogPath = $tsenv.Value("_SMSTSLogPath")
}
Catch
{
	Write-Warning "TS environment not detected. Assuming stand-alone mode."
	$LogPath = $env:TEMP
}

[string]$FileName = $scriptName +'.log'
$LogFilePath = Join-Path -Path $LogPath -ChildPath $FileName


# DEFAULTS: Configurations are hardcoded here (change values if needed)
[boolean]$Global:LGPOForConfigs = $true
[string]$Global:LGPOPath = "$ToolsPath\LGPO\LGPO.exe"
[ValidateSet('Custom','High Performance','Balanced')]$SetPowerCFG = 'Custom'
[string]$PowerCFGFilePath = "AlwaysOnPowerScheme.pow"
[boolean]$EnablePSLogging = $false
[boolean]$EnableSystemVerboseMsg = $false
[boolean]$ApplySTIGItems = $false
[boolean]$DisableAutoRun = $false
[boolean]$CleanSampleFolders = $false
[boolean]$DisableCortana = $false
[boolean]$DisableInternetSearch = $false 
[boolean]$EnableVDIOptimizations = $false 
[boolean]$EnableOfficeOneNote = $false
[boolean]$EnableRDP = $false
[boolean]$DisableOneDrive = $false
[boolean]$PreferIPv4OverIPv6 = $false
[boolean]$RemoveActiveSetupComponents = $false
[boolean]$DisableWindowsFirstLoginAnimation = $false
[boolean]$DisableIEFirstRunWizard = $false
[boolean]$DisableWMPFirstRunWizard = $false
[boolean]$DisableEdgeIconCreation = $false
[boolean]$DisableNewNetworkDialog = $false
[boolean]$DisableInternetServices = $false
[boolean]$DisabledUnusedServices = $false
[boolean]$DisabledUnusedFeatures = $false
[boolean]$DisableSchTasks = $false
[boolean]$DisableDefender = $false
[boolean]$DisableFirewall = $false
[boolean]$DisableWireless = $false
[boolean]$DisableBluetooth = $false
[boolean]$EnableRemoteRegistry = $false
[boolean]$DisableFirewall = $false
[boolean]$ApplyPrivacyMitigations = $false
[boolean]$EnableCredGuard = $false
[boolean]$InstallLogonScript = $false
[string]$LogonScriptPath = "$PSscriptRoot\Win10-Logon.ps1"
[boolean]$EnableWinRM = $false
[boolean]$EnableAppsRunAsAdmin = $false
[boolean]$DisableUAC = $false
[boolean]$DisableWUP2P = $false
[boolean]$DisableCortana = $false
[boolean]$EnableIEEnterpriseMode = $false
[string]$IEEMSiteListPath = ''
[boolean]$PreCompileAssemblies = $false
[boolean]$DisableIndexing = $false
[boolean]$EnableSecureLogonCtrlAltDelete = $false
[boolean]$HideDrivesWithNoMedia = $false
[boolean]$DisableAllNotifications = $false
[boolean]$InstallPSModules = $false
[psobject]$InstallModulesPath = Get-ChildItem "$PSscriptRoot\PSModules" -Filter *.psm1 -Recurse

# When running in Tasksequence and configureation exists, use that instead
If($tsenv){
    # Configurations comes from Tasksequence
    If($tsenv:CFG_UseLGPOForConfigs){[boolean]$Global:LGPOForConfigs = [boolean]::Parse($tsenv.Value("CFG_UseLGPOForConfigs"))}
    If($tsenv:LGPOPath){[string]$Global:LGPOPath = $tsenv.Value("LGPOPath")}
    If($tsenv:CFG_SetPowerCFG){[boolean]$SetPowerCFG = [boolean]::Parse($tsenv.Value("CFG_SetPowerCFG"))}
    If($tsenv:CFG_PowerCFGFilePath){[string]$PowerCFGFilePath = $tsenv.Value("CFG_PowerCFGFilePath")}
    If($tsenv:CFG_EnablePSLoggingg){[boolean]$EnablePSLogging = [boolean]::Parse($tsenv.Value("CFG_EnablePSLogging"))}
    If($tsenv:CFG_EnableVerboseMsg){[boolean]$EnableVerboseMsg = [boolean]::Parse($tsenv.Value("CFG_EnableVerboseMsg"))}
    If($tsenv:CFG_ApplySTIGItems){[boolean]$ApplySTIGItems = [boolean]::Parse($tsenv.Value("CFG_ApplySTIGItems"))}
    If($tsenv:CFG_DisableAutoRun){[boolean]$DisableAutoRun = [boolean]::Parse($tsenv.Value("CFG_DisableAutorun"))}
    If($tsenv:CFG_CleanSampleFolders){[boolean]$CleanSampleFolders = [boolean]::Parse($tsenv.Value("CFG_CleanSampleFolders"))}
    If($tsenv:CFG_DisableCortana){[boolean]$DisableCortana = [boolean]::Parse($tsenv.Value("CFG_DisableCortana"))}
    If($tsenv:CFG_DisableInternetSearch){[boolean]$DisableInternetSearch = [boolean]::Parse($tsenv.Value("CFG_DisableInternetSearch"))} 
    If($tsenv:EnableVDIOptimizations){[boolean]$EnableVDIOptimizations = [boolean]::Parse($tsenv.Value("EnableVDIOptimizations"))} 
    If($tsenv:CFG_EnableOfficeOneNote){[boolean]$EnableOfficeOneNote = [boolean]::Parse($tsenv.Value("CFG_EnableOfficeOneNote"))}
    If($tsenv:CFG_EnableRDP){[boolean]$EnableRDP = [boolean]::Parse($tsenv.Value("CFG_EnableRDP"))}
    If($tsenv:CFG_DisableOneDrive){[boolean]$DisableOneDrive = [boolean]::Parse($tsenv.Value("CFG_DisableOneDrive"))}
    If($tsenv:CFG_PreferIPv4OverIPv6){[boolean]$PreferIPv4OverIPv6 = [boolean]::Parse($tsenv.Value("CFG_PreferIPv4OverIPv6"))}
    If($tsenv:CFG_RemoveActiveSetupComponents){[boolean]$RemoveActiveSetupComponents = [boolean]::Parse($tsenv.Value("CFG_RemoveActiveSetupComponents"))}
    If($tsenv:CFG_DisableWindowsFirstLoginAnimation){[boolean]$DisableWindowsFirstLoginAnimation = [boolean]::Parse($tsenv.Value("CFG_DisableWindowsFirstLoginAnimation"))}
    If($tsenv:CFG_DisableIEFirstRunWizard){[boolean]$DisableIEFirstRunWizard = [boolean]::Parse($tsenv.Value("CFG_DisableIEFirstRunWizard"))}
    If($tsenv:CFG_DisableWMPFirstRunWizard){[boolean]$DisableWMPFirstRunWizard = [boolean]::Parse($tsenv.Value("CFG_DisableWMPFirstRunWizard"))}
    If($tsenv:CFG_DisableEdgeIconCreation){[boolean]$DisableEdgeIconCreation = [boolean]::Parse($tsenv.Value("CFG_DisableEdgeIconCreation"))}
    If($tsenv:CFG_DisableNewNetworkDialog){[boolean]$DisableNewNetworkDialog = [boolean]::Parse($tsenv.Value("CFG_DisableNewNetworkDialog"))}
    If($tsenv:CFG_DisableInternetServices){[boolean]$DisableInternetServices = [boolean]::Parse($tsenv.Value("CFG_DisableInternetServices"))}
    If($tsenv:CFG_DisabledUnusedServices){[boolean]$DisabledUnusedServices = [boolean]::Parse($tsenv.Value("CFG_DisabledUnusedServices"))}
    If($tsenv:CFG_DisabledUnusedFeatures){[boolean]$DisabledUnusedFeatures = [boolean]::Parse($tsenv.Value("CFG_DisabledUnusedFeatures"))}
    If($tsenv:CFG_DisableSchTasks){[boolean]$DisableSchTasks = [boolean]::Parse($tsenv.Value("CFG_DisableSchTasks"))}
    If($tsenv:CFG_DisableDefender){[boolean]$DisableDefender = [boolean]::Parse($tsenv.Value("CFG_DisableDefender"))}
    If($tsenv:CFG_DisableFirewall){[boolean]$DisableFirewall = [boolean]::Parse($tsenv.Value("CFG_DisableFirewall"))}
    If($tsenv:CFG_DisableWireless){[boolean]$DisableWireless = [boolean]::Parse($tsenv.Value("CFG_DisableWireless"))}
    If($tsenv:CFG_DisableBluetooth){[boolean]$DisableBluetooth = [boolean]::Parse($tsenv.Value("CFG_DisableBluetooth"))}
    If($tsenv:CFG_EnableRemoteRegistry){[boolean]$EnableRemoteRegistry = [boolean]::Parse($tsenv.Value("CFG_EnableRemoteRegistry"))}
    If($tsenv:CFG_DisableFirewall){[boolean]$DisableFirewall = [boolean]::Parse($tsenv.Value("CFG_DisableFirewall"))}
    If($tsenv:ApplyPrivacyMitigations){[boolean]$ApplyPrivacyMitigations = [boolean]::Parse($tsenv.Value("ApplyPrivacyMitigations"))}
    If($tsenv:CFG_EnableCredGuard){[boolean]$EnableCredGuard = [boolean]::Parse($tsenv.Value("CFG_EnableCredGuard"))}
    If($tsenv:CFG_InstallLogonScript){[boolean]$InstallLogonScript = [boolean]::Parse($tsenv.Value("CFG_InstallLogonScript"))}
    If($tsenv:CFG_LogonScriptPath){[string]$LogonScriptPath = $tsenv.Value("CFG_LogonScriptPath")}
    If($tsenv:CFG_EnableWinRM){[boolean]$EnableWinRM = [boolean]::Parse($tsenv.Value("CFG_EnableWinRM"))}
    If($tsenv:CFG_EnableAppsRunAsAdmin){[boolean]$EnableAppsRunAsAdmin = [boolean]::Parse($tsenv.Value("CFG_EnableAppsRunAsAdmin"))}
    If($tsenv:CFG_DisableUAC){[boolean]$DisableUAC = [boolean]::Parse($tsenv.Value("CFG_DisableUAC"))}
    If($tsenv:CFG_DisableWUP2P){[boolean]$DisableWUP2P = [boolean]::Parse($tsenv.Value("CFG_DisableWUP2P"))}
    If($tsenv:CFG_EnableIEEnterpriseMode){[boolean]$EnableIEEnterpriseMode = [boolean]::Parse($tsenv.Value("CFG_EnableIEEnterpriseMode"))}
    If($tsenv:CFG_IEEMSiteListPath){[string]$IEEMSiteListPath = $tsenv.Value("CFG_IEEMSiteListPath")}
    If($tsenv:CFG_PreCompileAssemblies){[boolean]$PreCompileAssemblies = [boolean]::Parse($tsenv.Value("CFG_PreCompileAssemblies"))}
    If($tsenv:CFG_DisableIndexing){[boolean]$DisableIndexing = [boolean]::Parse($tsenv.Value("CFG_DisableIndexing"))}
    If($tsenv:CFG_EnableSecureLogon){[boolean]$EnableSecureLogonCtrlAltDelete = [boolean]::Parse($tsenv.Value("CFG_EnableSecureLogon"))}
    If($tsenv:CFG_HideDrives){[boolean]$HideDrivesWithNoMedia = [boolean]::Parse($tsenv.Value("CFG_HideDrives"))}
    If($tsenv:CFG_DisableAllNotifications){[boolean]$DisableAllNotifications = [boolean]::Parse($tsenv.Value("CFG_DisableAllNotifications"))}
    If($tsenv:CFG_InstallPSModules){[boolean]$InstallPSModules = [boolean]::Parse($tsenv.Value("CFG_InstallPSModules"))}

}


#$VerbosePreference = 'SilentlyContinue'
$VerbosePreference = 'Continue'


$OneNotePathx86 = Get-ChildItem "${env:ProgramFiles(x86)}" -Recurse -Filter "ONENOTE.EXE"
$OneNotePathx64 = Get-ChildItem "$env:ProgramFiles" -Recurse -Filter "ONENOTE.EXE"
If($OneNotePathx86){$OneNotePath = $OneNotePathx86}
If($OneNotePathx64){$OneNotePath = $OneNotePathx64}

##*===========================================================================
##* MAIN
##*===========================================================================
If ($InstallPSModules)
{
    If($InstallModulesPath.count -gt 0){
        Write-LogEntry "Installing PowerShell Modules:" -Severity 1 -Outhost
        Foreach($module in $InstallModulesPath){
           Import-Module -name $module.FullName -Global -NoClobber -Force -Verbose -ErrorAction SilentlyContinue | Out-Null
        }
    }

}

If ($EnableOfficeOneNote -and $OneNotePath)
{
	# Mount HKCR drive
	Write-LogEntry "Setting OneNote file association to the desktop app." -Severity 1 -Outhost
	New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
	New-Item -Path 'Registry::HKCR\onenote-cmd\Shell\Open' -Name 'Command' -Force | Out-Null
    New-ItemProperty -Path "Registry::HKCR\onenote-cmd\Shell\Open\Command" -Name "@" -Type String -Value $OneNotePath.FullName -Force | Out-Null
	Remove-PSDrive -Name "HKCR" | Out-Null
}

If($EnablePSLogging)
{
    Write-LogEntry ("Enabling Powershell Script Block Logging") -Severity 1 -Outhost
    #New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell" -Name ScriptBlockLogging -Force | Out-Null
    Configure-RegistryItem -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Type DWord -Value 1 -Force | Out-Null

    Write-LogEntry ("Enabling Powershell Transcription Logging") -Severity 1 -Outhost
    #New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell" -name Transcription -Force | Out-Null
    Configure-RegistryItem -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Type DWord -Value 1 -Force | Out-Null
    Configure-RegistryItem -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableInvocationHeader" -Type DWord -Value 1 -Force | Out-Null
    Configure-RegistryItem -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "OutputDirectory" -Value "" -Force | Out-Null

    Write-LogEntry ("Enabling Powershell Module Logging Logging") -Severity 1 -Outhost
    #New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell" -name ModuleLogging -Force | Out-Null
    Configure-RegistryItem -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Type DWord -Value 1 -Force | Out-Null
    #Configure-RegistryItem -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "ModuleNames" -Value "" -Force | Out-Null
}

If ($EnableSystemVerboseMsg -or $EnableVDIOptimizations)
{
    #https://support.microsoft.com/en-us/help/325376/how-to-enable-verbose-startup-shutdown-logon-and-logoff-status-message
    Write-LogEntry ("Setting Windows Startup to Verbose messages") -Severity 1 -Outhost
    Configure-RegistryItem -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -Type DWord -Value 1 -Force | Out-Null
    If(Test-Path ('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableStatusMessages') ){
        Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name 'DisableStatusMessages' -Force | Out-Null
    }
}

If (($SetPowerCFG -eq 'Custom') -and (Test-Path $PowerCFGFilePath) )
{
    Write-LogEntry ("Setting Power configurations to: [{0}] using file [{1}] -f $SetPowerCFG,$PowerCFGFilePath") -Severity 1 -Outhost
    Start-Process "C:\Windows\system32\powercfg.exe" -ArgumentList "-IMPORT $PowerCFGFilePath $AOPGUID" -Wait -NoNewWindow
    Start-Process "C:\Windows\system32\powercfg.exe" -ArgumentList "-SETACTIVE $AOPGUID" -Wait -NoNewWindow
}

If(($SetPowerCFG -eq 'Custom') -or $EnableVDIOptimizations)
{
    Write-LogEntry "Disabling Hibernation in Power configurations" -Severity 1 -Outhost
    Start-Process "C:\Windows\system32\powercfg.exe" -ArgumentList " -H OFF" -Wait -NoNewWindow
}

If ($SetPowerCFG -eq 'High Performance' -and !$EnableVDIOptimizations)
{
    Write-LogEntry "Setting Power configurations to: $SetPowerCFG" -Severity 1 -Outhost
    #Set High Performacne to Default 
    Get-WmiObject -Class Win32_PowerPlan -Namespace root\cimv2\power -Filter "ElementName= 'High Performance'" | Invoke-WmiMethod -Name Activate
    powercfg.exe -SETACTIVE 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
    $exe = "C:\Windows\system32\powercfg.exe"
    $arguments = "-x -standby-timeout-ac 0"
    $proc = [Diagnostics.Process]::Start($exe, $arguments)
    $proc.WaitForExit()
}

If ($SetPowerCFG -eq 'Balanced' -and !$EnableVDIOptimizations)
{
     #Set Balanced to Default
    Write-LogEntry "Setting Power configurations to: $SetPowerCFG" -Severity 1 -Outhost
    Get-WmiObject -Class Win32_PowerPlan -Namespace root\cimv2\power -Filter "ElementName= 'Balanced'" | Invoke-WmiMethod -Name Activate
    powercfg.exe -SETACTIVE 381b4222-f694-41f0-9685-ff5bb260df2e
    $exe = "C:\Windows\system32\powercfg.exe"
    $arguments = "-x -standby-timeout-ac 0"
    $proc = [Diagnostics.Process]::Start($exe, $arguments)
    $proc.WaitForExit()
}

If($HideDrivesWithNoMedia)
{
    Write-LogEntry "Hiding Drives With NoMedia..." -Severity 1 -Outhost
	Configure-RegistryItem -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideDrivesWithNoMedia' -Type DWord -Value '1' -Force | Out-Null
}

If ($DisableAutoRun)
{
    Write-LogEntry "Disabling Autorun for local machine..." -Severity 1 -Outhost
    Configure-RegistryItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name HonorAutorunSetting -Type DWord -Value 1 -Force | Out-Null
    Configure-RegistryItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveAutoRun -Type DWord -Value 67108863 -Force | Out-Null
    Configure-RegistryItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutorun -Type DWord -Value 0xFF -Force | Out-Null

    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping\Autorun.inf' -Name '(Default)' -Value "@SYS:DoesNotExist" -Force | Out-Null
    Configure-RegistryItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Cdrom' -Name AutoRun -Type DWord -Value 0 -Force | Out-Null

    Write-LogEntry "Disabling Autorun for default users..." -Severity 1 -Outhost
    Set-ItemProperty -Path "Registry::HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name HonorAutorunSetting -Type DWord -Value 1 -Force | Out-Null
    Set-ItemProperty -Path "Registry::HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoDriveAutoRun -Type DWord -Value 67108863 -Force | Out-Null
    Set-ItemProperty -Path "Registry::HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoDriveTypeAutorun -Type DWord -Value 0xFF -Force | Out-Null

    Write-LogEntry ("Disabling Autorun for Current user: {0}..." -f $env:USERNAME) -Severity 1 -Outhost
    Configure-RegistryItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name HonorAutorunSetting -Type DWord -Value 1 -Force | Out-Null
    Configure-RegistryItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoDriveAutoRun -Type DWord -Value 67108863 -Force | Out-Null
    Configure-RegistryItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoDriveTypeAutorun -Type DWord -Value 0xFF -Force | Out-Null

    # Loop through each profile on the machine</p>
    Foreach ($UserProfile in $UserProfiles) {
        
        # Load User ntuser.dat if it's not already loaded
        If (($ProfileWasLoaded = Test-Path Registry::HKEY_USERS\$($UserProfile.SID)) -eq $false) {
            Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE LOAD HKU\$($UserProfile.SID) $($UserProfile.UserHive)" -Wait -WindowStyle Hidden
            # Manipulate the registry
            $settingspath = "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
            
            Write-Host ("Disabling Autorun on SID: {0}" -f $UserProfile.SID)
            #New-Item -Path $settingspath -ErrorAction SilentlyContinue | Out-Null
            Set-ItemProperty -Path $settingspath -Name HonorAutorunSetting -Type DWord -Value 1 -Force | Out-Null
            Set-ItemProperty -Path $settingspath -Name NoDriveAutoRun -Type DWord -Value 67108863 -Force | Out-Null
            Set-ItemProperty -Path $settingspath -Name NoDriveTypeAutorun -Type DWord -Value 0xFF -Force | Out-Null
        }

        # Unload NTuser.dat        
        If ($ProfileWasLoaded -eq $false) {
            [gc]::Collect()
            Start-Sleep 1
            Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE UNLOAD HKU\$($UserProfile.SID)" -Wait -PassThru  -WindowStyle Hidden | Out-Null
        }
    }


}

If ($ApplySTIGItems)
{
    Write-LogEntry "Stig Item: Disabling Winlogon's Auto Restart Shell..." -Severity 1 -Outhost
    Configure-RegistryItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'AutoRestartShell' -Value 0 -Force | Out-Null

	Write-LogEntry "Stig Item: Disabling Session Kernel Exception Chain Validation..." -Severity 1 -Outhost
    Configure-RegistryItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' -Name 'DisableExceptionChainValidation' -Value 0 -Force | Out-Null

	Write-LogEntry "Stig Item: Clearing Session Subsystem's..." -Severity 1 -Outhost
    Configure-RegistryItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\SubSystems' -Name 'Optional' -Type MultiString -Value "" -Force | Out-Null

    Write-LogEntry "Stig Item: Disabling File System's 8.3 Name Creation..." -Severity 1 -Outhost
    Configure-RegistryItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name 'NtfsDisable8dot3NameCreation' -Value 1 -Force | Out-Null

    Write-LogEntry "Stig Item: Disabling RASMAN PPP Parameters..." -Severity 1 -Outhost
    Configure-RegistryItem -Path 'HKLM:\SYSTEM\CurrentControlSet\services\RasMan\Parameters' -Name 'DisableSavePassword' -Value 1 -Force | Out-Null
    Configure-RegistryItem -Path 'HKLM:\SYSTEM\CurrentControlSet\services\RasMan\Parameters' -Name 'Logging' -Value 1 -Force | Out-Null
    Configure-RegistryItem -Path 'HKLM:\SYSTEM\CurrentControlSet\services\RasMan\PPP' -Name 'ForceEncryptedData' -Value 1 -Force | Out-Null
    Configure-RegistryItem -Path 'HKLM:\SYSTEM\CurrentControlSet\services\RasMan\PPP' -Name 'ForceEncryptedPassword' -Value 2 -Force | Out-Null
    Configure-RegistryItem -Path 'HKLM:\SYSTEM\CurrentControlSet\services\RasMan\PPP' -Name 'SecureVPN' -Value 1 -Force | Out-Null
}

If ($EnableRDP)
{
	Write-LogEntry "Enabling RDP..." -Severity 1 -Outhost
	Configure-RegistryItem -Path -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -Value 0 | Out-Null
	Configure-RegistryItem -Path -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "UserAuthentication" -Value 1 | Out-Null
	Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
}

If ($DisableOneDrive)
{
	Write-LogEntry "Turning off OneDrive..." -Severity 1 -Outhost
    ##New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows' -Name 'OneDrive' -Force | Out-Null
	Configure-RegistryItem -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'DisableFileSyncNGSC' -Type DWord -Value '1' -Force | Out-Null
	Configure-RegistryItem -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'PreventNetworkTrafficPreUserSignIn' -Type DWord -Value '1' -Force | Out-Null
    Configure-RegistryItem -Path -Path 'Registry::HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder' -Name Attributes -Type DWord -Value 0 -ErrorAction SilentlyContinue -Force | Out-Null
}

If ($PreferIPv4OverIPv6)
{
	# Use 0x20 to prefer IPv4 over IPv6 by changing entries in the prefix policy table. 
	Write-LogEntry "Modifying IPv6 bindings to prefer IPv4 over IPv6..." -Severity 1 -Outhost
	Configure-RegistryItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'DisabledComponents' -Type DWord -Value '32' -Force | Out-Null
}

If($DisableAllNotifications)
{
    $notifications = @{
        "Disabling Security and Maintenance Notifications"="Windows.SystemToast.SecurityAndMaintenance"
        "Disabling OneDrive Notifications"="Microsoft.SkyDrive.Desktop"
        "Disabling Photos Notifications"="Microsoft.Windows.Photos_8wekyb3d8bbwe!App"
        "Disabling Store Notifications"="Microsoft.WindowsStore_8wekyb3d8bbwe!App"
        "Disabling Suggested Notifications"="Windows.SystemToast.Suggested"
        "Disabling Calendar Notifications"="microsoft.windowscommunicationsapps_8wekyb3d8bbwe!microsoft.windowslive.calendar"
        "Disabling Cortana Notifications"="Microsoft.Windows.Cortana_cw5n1h2txyewy!CortanaUI"
        "Disabling Mail Notifications:"="microsoft.windowscommunicationsapps_8wekyb3d8bbwe!microsoft.windowslive.mail"
        "Disabling Edge Notifications"="Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge"
        "Disabling Audio Notifications"="Windows.SystemToast.AudioTroubleshooter"
        "Disabling Autoplay Notifications"="Windows.SystemToast.AutoPlay"
        "Disabling Battery Saver Notifications"="Windows.SystemToast.BackgroundAccess"
        "Disabling Bitlocker Notifications"="Windows.SystemToast.BdeUnlock"
        "Disabling News Notifications"="Microsoft.BingNews_8wekyb3d8bbwe!AppexNews"
        "Disabling Settings Notifications"="windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel"
        "Disabling Tablet Notifications"="Windows.System.Continuum"
        "Disabling VPN Notifications"="Windows.SystemToast.RasToastNotifier"
        "Disabling Windows Hello Notifications"="Windows.SystemToast.HelloFace"
        "Disabling Wireless Notifications"="Windows.SystemToast.WiFiNetworkManager"
    }
    
    # Loop through each profile on the machine</p>
    Foreach ($UserProfile in $UserProfiles) {
        
        # Load User ntuser.dat if it's not already loaded
        If (($ProfileWasLoaded = Test-Path Registry::HKEY_USERS\$($UserProfile.SID)) -eq $false) {
            Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE LOAD HKU\$($UserProfile.SID) $($UserProfile.UserHive)" -Wait -WindowStyle Hidden
            # Manipulate the registry
            $settingspath = "Registry::HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings"
            Foreach ($key in $notifications.GetEnumerator()){
                Write-Host ("{0} on SID: {1}" -f $key.Key,$UserProfile.SID)
                #New-Item -Path ($settingspath + "\" + $key.Value) -ErrorAction SilentlyContinue | Out-Null
                Configure-RegistryItem -Path ($settingspath + "\" + $key.Value) -Name Enabled -Value 0 -Type DWord -ErrorAction SilentlyContinue | Out-Null
            }
        }

        # Unload NTuser.dat        
        If ($ProfileWasLoaded -eq $false) {
            [gc]::Collect()
            Start-Sleep 1
            Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE UNLOAD HKU\$($UserProfile.SID)" -Wait -PassThru  -WindowStyle Hidden | Out-Null
        }
    }
}


If ($DisabledIEFirstRunWizard)
{
    $notifications = @{
        "Disabling IE First Run"="DisabledFirstRunCustomize"
        "Setting IE Run Once to Has Shown"="RunOnceHasShown"
        "Setting IE Run Once to Complete"="RunOnceComplete"
    }
	# Disable IE First Run Wizard
	Write-LogEntry "Disabling IE First Run Wizard for SYSTEM..." -Severity 1 -Outhost
	##New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft' -Name 'Internet Explorer' -Force | Out-Null
	##New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer' -Name 'Main' -Force | Out-Null
	Configure-RegistryItem -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main' -Name DisableFirstRunCustomize -Type DWord -Value '1' -Force | Out-Null

    # Loop through each profile on the machine</p>
    Foreach ($UserProfile in $UserProfiles) {
        
        # Load User ntuser.dat if it's not already loaded
        If (($ProfileWasLoaded = Test-Path Registry::HKEY_USERS\$($UserProfile.SID)) -eq $false) {
            Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE LOAD HKU\$($UserProfile.SID) $($UserProfile.UserHive)" -Wait -WindowStyle Hidden
            # Manipulate the registry
            $settingspath = "Registry::HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Internet Explorer\Main"
            Foreach ($key in $notifications.GetEnumerator()){
                Write-Host ("{0} on SID: {1}" -f $key.Key,$UserProfile.SID)
                ##New-Item -Path ($settingspath + "\" + $key.Value) -ErrorAction SilentlyContinue | Out-Null
                Configure-RegistryItem -Path ($settingspath + "\" + $key.Value) -Name Enabled -Value 0 -Type DWord -ErrorAction SilentlyContinue | Out-Null
            }
        }

        # Unload NTuser.dat        
        If ($ProfileWasLoaded -eq $false) {
            [gc]::Collect()
            Start-Sleep 1
            Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE UNLOAD HKU\$($UserProfile.SID)" -Wait -PassThru  -WindowStyle Hidden | Out-Null
        }
    }

}

If ($DisableWMPFirstRunWizard)
{
	# Disable IE First Run Wizard
	Write-LogEntry "Disabling Media Player First Run Wizard..." -Severity 1 -Outhost
	Configure-RegistryItem -Path 'HKLM:\Software\Microsoft\MediaPlayer\Preferences' -Name AcceptedEULA -Type DWord -Value '1' -Force | Out-Null
    Configure-RegistryItem -Path 'HKLM:\Software\Microsoft\MediaPlayer\Preferences' -Name FirstTime -Type DWord -Value '1' -Force | Out-Null
    Configure-RegistryItem -Path 'HKLM:\Software\Policies\Microsoft\WindowsMediaPlayer' -Name GroupPrivacyAcceptance -Type DWord -Value '1' -Force | Out-Null
}

If($EnableSecureLogonCtrlAltDelete)
{
  	# Disable IE First Run Wizard
	Write-LogEntry "Enabled Secure Logon Screen Settings..." -Severity 1 -Outhost
	Configure-RegistryItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DisableCAD -Type DWord -Value '0' -Force | Out-Null
    Configure-RegistryItem -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name DontDisplayLastUserName -Type DWord -Value '1' -Force | Out-Null
    Configure-RegistryItem -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name BlockDomainPicturePassword -Type DWord -Value '1' -Force | Out-Null
}

If ($DisableEdgeIconCreation)
{
	Write-LogEntry "Disabling Microsoft Edge desktop icon creation..." -Severity 1 -Outhost
	Configure-RegistryItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'Explorer' -Type DWord -Value '1' -Force | Out-Null
	Configure-RegistryItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'DisableEdgeDesktopShortcutCreation' -Type DWord -Value '1' -Force | Out-Null
}

# Disable New Network dialog box
If ($DisableNewNetworkDialog)
{
	Write-LogEntry "Disabling New Network Dialog..." -Severity 1 -Outhost
	##New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Network' -Name 'NewNetworkWindowOff' -Force | Out-Null
    Configure-RegistryItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet' -Name 'EnableActiveProbing' -Type DWord -Value '0' -Force | Out-Null
}

If($RemoveActiveSetupComponents -or $EnableVDIOptimizations){

    #https://kb.vmware.com/s/article/2100337?lang=en_US#q=Improving%20log%20in%20time
    Write-LogEntry "Disabling Active Setup components to speed up login time" -Severity 1 -Outhost
    $activeComponentsGUID = @{
        "Theme Component" = "{2C7339CF-2B09-4501-B3F3-F3508C9228ED}"
        "ie4uinit.exe –ClearIconCache" = "{2D46B6DC-2207-486B-B523-A557E6D54B47}"
        "DirectDrawEx" = "{44BBA840-CC51-11CF-AAFA-00AA00B6015C}"
        "Microsoft Windows Media Player" = "{6BF52A52-394A-11d3-B153-00C04F79FAA6}"
        "IE4_SHELLID" = "{89820200-ECBD-11cf-8B85-00AA005B4340}"
        "BASEIE40_W2K" = "{89820200-ECBD-11cf-8B85-00AA005B4383}"
        "DOTNETFRAMEWORKS" = "{89B4C1CD-B018-4511-B0A1-5476DBF70820}"
        "WMPACCESS" = ">{22d6f312-b0f6-11d0-94ab-0080c74c7e95"
    }

    $activeComponentsGUID | ForEach-Object{
        If(Test-Path ('HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\' + $_.Value + '\StubPath') ){
            Write-LogEntry 'Removing Active Component: ' + $_.Key -Severity 1 -Outhost
            Remove-ItemProperty -Path ('HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\' + $_.Value) -Name 'StubPath' -Force | Out-Null
        }

    }
}


# Disable Services
If ($DisableInternetServices -or $EnableVDIOptimizations)
{
	Write-LogEntry "Disabling Microsoft Account Sign-in Assistant Service..." -Severity 1 -Outhost
	Set-Service wlidsvc -StartupType Disabled -ErrorAction SilentlyContinue
	
	Write-LogEntry "Disabling Windows Error Reporting Service..." -Severity 1 -Outhost
	Set-Service WerSvc -StartupType Disabled -ErrorAction SilentlyContinue
	
	Write-LogEntry "Disabling Xbox Live Auth Manager Service..." -Severity 1 -Outhost
	Set-Service XblAuthManager -StartupType Disabled -ErrorAction SilentlyContinue
	
	Write-LogEntry "Disabling Xbox Live Game Save Service..." -Severity 1 -Outhost
	Set-Service XblGameSave -StartupType Disabled -ErrorAction SilentlyContinue
	
	Write-LogEntry "Disabling Xbox Live Networking Service Service..." -Severity 1 -Outhost
	Set-Service XboxNetApiSvc -StartupType Disabled -ErrorAction SilentlyContinue
	
	Write-LogEntry "Disabling Xbox Accessory Management Service..." -Severity 1 -Outhost
	Set-Service XboxGipSvc -StartupType Disabled -ErrorAction SilentlyContinue

    Write-LogEntry "Disabling Windows Mediaplayer Sharing Service" -Severity 1 -Outhost
    Set-Service WMPNetworkSvc -StartupType Disabled -ErrorAction SilentlyContinue
    
}

If ($DisabledUnusedServices -or $EnableVDIOptimizations)
{
    Write-LogEntry "Disabling Homegroup Services" -Severity 1 -Outhost
    Set-Service HomeGroupListener -StartupType Disabled -ErrorAction SilentlyContinue
    Set-Service HomeGroupProvider -StartupType Disabled -ErrorAction SilentlyContinue

    If($EnableVDIOptimizations){
        Write-LogEntry "VDI Optimizations: Disabling SuperFetch Service..." -Severity 1 -Outhost
        Set-Service SuperFetch -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations: Disabling Diagnostic Policy Service..." -Severity 1 -Outhost
        Set-Service DPS -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations: Disabling Themes Service..." -Severity 1 -Outhost
        Set-Service Themes -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations: Disabling IP Helper Service..." -Severity 1 -Outhost
        Set-Service iphlpsvc -StartupType Disabled -ErrorAction SilentlyContinue


        Write-LogEntry "VDI Optimizations: Disabling Network Location Awareness Service..." -Severity 1 -Outhost
        Set-Service NlaSvc -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations: Disabling Security Center Service..." -Severity 1 -Outhost
        Set-Service wscsvc -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations: Disabling Windows Audio Service..." -Severity 1 -Outhost
        Set-Service Audiosrv -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations: Disabling Shell Hardware Detection Service..." -Severity 1 -Outhost
        Set-Service ShellHWDetection -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations: Disabling Windows Connect Now – Config Registrar Service..." -Severity 1 -Outhost
        Set-Service wcncsvc -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations: Disabling SSDP Discovery Service..." -Severity 1 -Outhost
        Set-Service SSDPSRV -StartupType Disabled -ErrorAction SilentlyContinue

        #Write-LogEntry "VDI Optimizations: Disabling Windows Update Service..." -Severity 1 -Outhost
        #Set-Service wuauserv -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations: Disabling Telephony Service..." -Severity 1 -Outhost
        Set-Service TapiSrv -StartupType Disabled -ErrorAction SilentlyContinue
    }
}

If ($DisabledUnusedFeatures)
{
    Write-LogEntry "Disabling Internet Printing" -Severity 1 -Outhost
    Try{
        Disable-WindowsOptionalFeature -FeatureName Printing-Foundation-InternetPrinting-Client -Online -NoRestart -ErrorAction Stop | Out-Null
    }
    Catch [System.Management.Automation.ActionPreferenceStopException]{
        Write-LogEntry ("Unable to Disable Internet Printing: {0}" -f $_) -Severity 3 -Outhost
    }

    Write-LogEntry "Disabling Fax and scanning" -Severity 1 -Outhost
    Try{
        Disable-WindowsOptionalFeature -FeatureName FaxServicesClientPackage -Online -NoRestart -ErrorAction Stop | Out-Null
    }
    Catch [System.Management.Automation.ActionPreferenceStopException]{
        Write-LogEntry ("Unable to Disable Internet Printing: {0}" -f $_) -Severity 3 -Outhost
    }
    
}

If ($DisableDefender -or $EnableVDIOptimizations)
{
    Write-LogEntry "Disabling Windows Defender" -Severity 1 -Outhost
    Try{
        Get-Service 'Sense' | Set-Service -StartupType Disabled -ErrorAction Stop
        Get-Service 'WdNisSvc' | Set-Service -StartupType Disabled -ErrorAction Stop
        Get-Service 'SecurityHealthService' | Set-Service -StartupType Disabled -ErrorAction Stop
        Get-Service 'WinDefend' | Set-Service -StartupType Disabled -ErrorAction Stop
    }
    Catch [System.Management.Automation.ActionPreferenceStopException]{
        Write-LogEntry ("Unable to Disable Windows Defender: {0}" -f $_) -Severity 3 -Outhost
    }
}

If ($DisableFirewall)
{
    Write-LogEntry "Disabling Windows Firewall" -Severity 1 -Outhost
    netsh advfirewall set allprofiles state off | Out-Null
    Try{
        Get-Service 'mpssvc' | Set-Service -StartupType Disabled -ErrorAction Stop
    }
    Catch [System.Management.Automation.ActionPreferenceStopException]{
        Write-LogEntry ("Unable to Disable Windows Firewall: {0}" -f $_) -Severity 3 -Outhost
    }
}

If ($DisableWireless -or $EnableVDIOptimizations)
{
    Write-LogEntry "Disabling Wireless Services" -Severity 1 -Outhost
    Try{
        Get-Service 'wcncsvc' | Set-Service -StartupType Disabled -ErrorAction Stop
        Get-Service 'WwanSvc' | Set-Service -StartupType Disabled -ErrorAction Stop
    }
    Catch [System.Management.Automation.ActionPreferenceStopException]{
        Write-LogEntry ("Unable to Disable Wireless Services: {0}" -f $_) -Severity 3 -Outhost
    }
}

If ($EnableRemoteRegistry -or $EnableVDIOptimizations)
{
    Write-LogEntry "Starting Remote registry services" -Severity 1 -Outhost
    Try{
        Get-Service 'RemoteRegistry' |Set-Service  -StartupType Automatic -ErrorAction Stop
        Start-Service 'RemoteRegistry' -ErrorAction Stop
    }
    Catch [System.Management.Automation.ActionPreferenceStopException]{
        Write-LogEntry ("Unable to enable Remote registry: {0}" -f $_) -Severity 3 -Outhost
    }
}

If ($DisableBluetooth)
{
    Write-LogEntry "Disabling Bluetooth..." -Severity 1 -Outhost
    Config-Bluetooth -DeviceStatus Off
}

# Disable Scheduled Tasks
If ($DisableSchTasks -or $EnableVDIOptimizations)
{
    Write-LogEntry "Disabling Scheduled Tasks..." -Severity 1 -Outhost
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
        Write-LogEntry ('Disabling [{0}]' -f $task.Key) -Severity 1 -Outhost
        Disable-ScheduledTask -TaskName $task.Value -ErrorAction SilentlyContinue | Out-Null
    }

    If($EnableVDIOptimizations)
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
            "Microsoft Power Efficiency Diagnostics\AnalyzeSystem\Microsoft\Windows\Ras\MobilityManager Scheduled Task"="\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem\Microsoft\Windows\Ras\MobilityManager"
            "Microsoft SideShow\AutoWake Scheduled Task"="\Microsoft\Windows\SideShow\AutoWake"
            "Microsoft SideShow\GadgetManager Scheduled Task"="\Microsoft\Windows\SideShow\GadgetManager"
            "Microsoft SideShow\SessionAgent Scheduled Task"="\Microsoft\Windows\SideShow\SessionAgent"
            "Microsoft SideShow\SystemDataProviders Scheduled Task"="\Microsoft\Windows\SideShow\SystemDataProviders"
            "Microsoft SpacePort\SpaceAgentTask Scheduled Task"="\Microsoft\Windows\SpacePort\SpaceAgentTask"
            "Microsoft SystemRestore\SR Scheduled Task"="\Microsoft\Windows\SystemRestore\SR"
            "Microsoft UPnP\UPnPHostConfig Scheduled Task"="\Microsoft\Windows\UPnP\UPnPHostConfig"
            "Microsoft Windows Defender\Windows Defender Cache Maintenance Scheduled Task"="\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance"
            "Microsoft Windows Defender\Windows Defender Scheduled Scan Scheduled Task"="\Microsoft\Windows\Windows Defender\Windows Defender Cleanup\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan"
            "Microsoft Windows Defender\Windows Defender Verification Scheduled Task"="\Microsoft\Windows\Windows Defender\Windows Defender Verification"
            "Microsoft WindowsBackup\ConfigNotification Scheduled Task"="\Microsoft\Windows\WindowsBackup\ConfigNotification"
        }

        Foreach ($task in $AdditionalScheduledTasks.GetEnumerator()){
            Write-LogEntry ('Disabling [{0}] for VDI' -f $task.Key) -Severity 1 -Outhost
            Disable-ScheduledTask -TaskName $task.Value -ErrorAction SilentlyContinue | Out-Null
        }
    }
}

If ($DisableRestore -or $EnableVDIOptimizations)
{
    Write-LogEntry "Disable system restore" -Severity 1 -Outhost
    Disable-ComputerRestore -drive c:\
}

If ($DisableCortana)
{
    # Disable Cortana
	Write-LogEntry "Disabling Cortana..." -Severity 1 -Outhost
	#New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\' -Name 'Windows Search' -Force | Out-Null
	Configure-RegistryItem -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowCortana' -Type DWord -Value '0' -Force | Out-Null
}

If ($DisableInternetSearch)
{
	# Configure Search Options:
	Write-LogEntry "Configuring Search Options..." -Severity 1 -Outhost
	Configure-RegistryItem -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowSearchToUseLocation' -Type DWord -Value '0' -Force | Out-Null
	# Disallow search and Cortana to use location
	Configure-RegistryItem -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'ConnectedSearchUseWeb' -Type DWord -Value '0' -Force | Out-Null
    # Disable cortona option in taskbar
	Configure-RegistryItem -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'SearchboxTaskbarMode' -Type DWord -Value '0' -Force | Out-Null
	
    # Do not allow web search
	Configure-RegistryItem -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'DisableWebSearch' -Type DWord -Value '0' -Force | Out-Null
    # Do not allow Cortona to use web search with bing
	Configure-RegistryItem -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'BingSearchEnabled' -Type DWord -Value '0' -Force | Out-Null
}


# Privacy and mitigaton settings
# See: https://docs.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services
If ($ApplyPrivacyMitigations)
{
	Write-LogEntry "Disallowing the user to change sign-in options..." -Severity 1 -Outhost
	#New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device" -Name "Settings" -Force | Out-Null
	Configure-RegistryItem -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Settings' -Name 'AllowSignInOptions' -Type DWord -Value '0' -Force | Out-Null
	
	# Disable the Azure AD Sign In button in the settings app
	Write-LogEntry "Disabling Azure AD sign-in options..." -Severity 1 -Outhost
	Configure-RegistryItem -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Settings' -Name 'AllowWorkplace' -Type DWord -Value '0' -Force | Out-Null
	
	Write-LogEntry "Disabling the Microsoft Account Sign-In Assistant..." -Severity 1 -Outhost
	Configure-RegistryItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'NoConnectedUser' -Type DWord -Value '3' -Force | Out-Null
	
	# Disable the MSA Sign In button in the settings app
	Write-LogEntry "Disabling MSA sign-in options..." -Severity 1 -Outhost
	Configure-RegistryItem -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Settings' -Name 'AllowYourAccount' -Type DWord -Value '0' -Force | Out-Null
	
	Write-LogEntry "Disabling camera usage on user's lock screen..." -Severity 1 -Outhost
	#New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "Personalization" -Force | Out-Null
	Configure-RegistryItem -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name 'NoLockScreenCamera' -Type DWord -Value '1' -Force | Out-Null
	
	Write-LogEntry "Disabling lock screen slideshow..." -Severity 1 -Outhost
	Configure-RegistryItem -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name 'NoLockScreenSlideshow' -Type DWord -Value '1' -Force | Out-Null
	
	# Offline maps
	Write-LogEntry "Turning off unsolicited network traffic on the Offline Maps settings page..." -Severity 1 -Outhost
    #New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "Maps" -Force | Out-Null	
    Configure-RegistryItem -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps' -Name 'AllowUntriggeredNetworkTrafficOnSettingsPage' -Type DWord -Value '0' -Force | Out-Null
	Write-LogEntry "Turning off Automatic Download and Update of Map Data..." -Severity 1 -Outhost
	Configure-RegistryItem -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps' -Name 'AutoDownloadAndUpdateMapData' -Type DWord -Value '0' -Force | Out-Null
	
	# Microsoft Edge
	Write-LogEntry "Enabling Do Not Track in Microsoft Edge..." -Severity 1 -Outhost
	Configure-RegistryItem -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main' -Name 'DoNotTrack' -Type DWord -Value '1' -Force | Out-Null
	
	Write-LogEntry "Disallow web content on New Tab page in Microsoft Edge..." -Severity 1 -Outhost
    #New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge" -Name "SearchScopes" -Force | Out-Null	
	Configure-RegistryItem -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\SearchScopes' -Name 'AllowWebContentOnNewTabPage' -Type DWord -Value '0' -Force | Out-Null
	
	# General stuff
	Write-LogEntry "Turning off the advertising ID..." -Severity 1 -Outhost
	#New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion" -Name "AdvertisingInfo" -Force | Out-Null
	Configure-RegistryItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -Name 'Enabled' -Type DWord -Value '0' -Force | Out-Null
	
	Write-LogEntry "Turning off location..." -Severity 1 -Outhost
    #New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "AppPrivacy" -Force | Out-Null
	Configure-RegistryItem -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessLocation' -Type DWord -Value '0' -Force | Out-Null
	#New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "LocationAndSensors" -Force | Out-Null
    Configure-RegistryItem -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' -Name 'DisableLocation' -Type DWord -Value '0' -Force | Out-Null
	
	# Stop getting to know me
	Write-LogEntry "Turning off automatic learning..." -Severity 1 -Outhost
    #New-Item -Path "HKLM:\Software\Policies\Microsoft" -Name "InputPersonalization" -Force | Out-Null	
    Configure-RegistryItem -Path 'HKLM:\Software\Policies\Microsoft\InputPersonalization' -Name 'RestrictImplicitInkCollection' -Type DWord -Value '1' -Force | Out-Null
	# Turn off updates to the speech recognition and speech synthesis models
	Configure-RegistryItem -Path 'HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences' -Name 'ModelDownloadAllowed' -Type DWord -Value '0' -Force | Out-Null
	
	Write-LogEntry "Disallowing Windows apps to access account information..." -Severity 1 -Outhost
	#New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows" -Name "AppPrivacy" -Force | Out-Null
	Configure-RegistryItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessAccountInfo' -Type DWord -Value '2' -Force | Out-Null
	
	Write-LogEntry "Disabling all feedback notifications..." -Severity 1 -Outhost
	Configure-RegistryItem -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'DoNotShowFeedbackNotifications' -Type DWord -Value '1' -Force | Out-Null
	
	Write-LogEntry "Disabling telemetry..."
	$OsCaption = (Get-WmiObject -class Win32_OperatingSystem).Caption
	
	If ($OsCaption -like "*Enterprise*" -or $OsCaption -like "*Education*")
	{
		$TelemetryLevel = "0"
		Write-LogEntry "Enterprise edition detected. Supported telemetry level: Security." -Severity 1 -Outhost
	}
	Else
	{
		$TelemetryLevel = "1"
		Write-LogEntry "Lowest supported telemetry level: Basic." -Severity 1 -Outhost
	}
	Configure-RegistryItem -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value $TelemetryLevel -Force | Out-Null
}


If($CleanSampleFolders){
    Write-LogEntry "Cleaning Sample Folders..." -Severity 1 -Outhost
    Remove-Item "$env:PUBLIC\Music\Sample Music" -Recurse -ErrorAction SilentlyContinue | Out-Null
    Remove-Item "$env:PUBLIC\Pictures\Sample Pictures" -Recurse -ErrorAction SilentlyContinue | Out-Null
    Remove-Item "$env:PUBLIC\Recorded TV\Sample Media" -Recurse -ErrorAction SilentlyContinue | Out-Null
    Remove-Item "$env:PUBLIC\Videos\Sample Videos" -Recurse -ErrorAction SilentlyContinue | Out-Null
}

If ($EnableWinRM)
{
    Write-LogEntry "Enabling WinRM" -Severity 1 -Outhost
    $winrm = Start-Process winrm -ArgumentList 'quickconfig -q' -Wait -PassThru -NoNewWindow
    If($winrm.ExitCode -eq 0){

        If(!(Get-Item WSMan:\localhost\Listener\Listener_*\Port)){Set-Item WSMan:\localhost\Listener\Listener_*\Port -Value '5985' -Force}
        If(!(Get-Item WSMan:\localhost\Listener\Listener_*\Address)){Set-Item WSMan:\localhost\Listener\Listener_*\Address -Value '*' -Force}
        If(!(Get-Item WSMan:\localhost\Listener\Listener_*\Transport)){Set-Item WSMan:\localhost\Listener\Listener_*\Transport -Value 'HTTP' -Force}

        Set-item WSMan:\localhost\Client\Auth\Basic -Value 'true' -Force
        Set-Item WSMan:\localhost\Client\AllowUnencrypted -Value 'true' -Force
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value '*' -Force

        Set-Item WSMan:\localhost\Service\Auth\Basic -Value 'true' -Force

        Set-WSManInstance -ResourceUri winrm/config -ValueSet @{MaxTimeoutms = "1800000"} | Out-Null

        Set-item WSMan:\localhost\Shell\MaxMemoryPerShellMB -Value '800' -Force | Out-Null

        Enable-PSRemoting -Force | Out-Null

        If(!$DisableFirewall)
        {
            netsh advfirewall firewall set rule group="Windows Remote Administration" new enable=yes
            netsh advfirewall firewall set rule name="Windows Remote Management (HTTP-In)" new enable=yes action=allow
        }

        Set-Service winrm -startuptype "auto"
        Restart-Service winrm  | Out-Null
    }
    Else{
        Write-LogEntry ("Unable to setup WinRM: {0}" -f $result.ExitCode) -Severity 3 -Outhost
    }
}


If ($EnableAppsRunAsAdmin -or $DisableUAC)
{
    Write-LogEntry "Enabling Apps to run as Administrator..." -Severity 1 -Outhost
    Configure-RegistryItem -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name FilterAdministratorToken -Type DWord -Value '1' -Force | Out-Null
}

If ($DisableUAC)
{
    Write-LogEntry "Disabling User Access Control..." -Severity 1 -Outhost
    Configure-RegistryItem -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Type DWord -Value '0' -Force | Out-Null
    Configure-RegistryItem -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -Type DWord -Value '0' -Force | Out-Null
    Configure-RegistryItem -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name PromptOnSecureDesktop -Type DWord -Value '0' -Force | Out-Null
}


If ($DisableWUP2P)
{
    Write-LogEntry "Disable P2P WIndows Updates..." -Severity 1 -Outhost
    Configure-RegistryItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config' -Name DODownloadMode -Type DWord -Value '0' -Force | Out-Null
    #adds windows update back to control panel (permissions ned to be changed)
    #Configure-RegistryItem -Path 'HKLM:\Software\Microsoft\WindowsUpdate\UX' -Name IsConvergedUpdateStackEnabled -Type DWord -Value '0' -Force | Out-Null
}


If ( ($EnableIEEnterpriseMode) -and ($IEEMSiteListPath) )
{
    If(Test-Path $IEEMSiteListPath){
        Write-LogEntry "Enabling Enterprise Mode option in IE..." -Severity 1 -Outhost
        Configure-RegistryItem -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\EnterpriseMode' -Name Enable -Type DWord -Value '1' -Force | Out-Null
        Configure-RegistryItem -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\EnterpriseMode' -Name Sitelist -Value $IEEMSiteListPath -Force | Out-Null
    }
    Else{
        Write-LogEntry ("IE Enterprise XML Path [{0}] is not found..." -f $IEEMSiteListPath) -Severity 2 -Outhost
    }
}

# Logon script
If ($InstallLogonScript -and (Test-Path $LogonScriptPath) )
{
	Write-LogEntry "Copying Logon script to $env:windir\Scripts" -Severity 1 -Outhost
	If (!(Test-Path "$env:windir\Scripts"))
	{
		#New-Item "$env:windir\Scripts" -ItemType Directory
	}
	Copy-Item -Path $LogonScriptPath -Destination "$env:windir\Scripts\Logon.ps1" -Force | Out-Null
	
    # load default hive
	Start-Process -FilePath "reg.exe" -ArgumentList "LOAD HKLM:\DEFAULT $env:systemdrive\Users\Default\NTUSER.DAT"
	# create RunOnce entries current / new user(s)
	Write-LogEntry "Creating RunOnce entries..." -Severity 1 -Outhost
	Configure-RegistryItem -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\Runonce" -Name "Logon" -Value "Powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File $env:windir\Scripts\Logon.ps1"
	Configure-RegistryItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Runonce" -Name "Logon" -Value "Powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File $env:windir\Scripts\Logon.ps1"
	
    # unload default hive
	Start-Process -FilePath "reg.exe" -ArgumentList "UNLOAD HKLM:\DEFAULT"
}

If($EnableCredGuard)
{
    if ([int](Get-WmiObject -Class Win32_OperatingSystem).BuildNumber -gt 14393) {
        try {
            # For version older than Windows 10 version 1607 (build 14939), enable required Windows Features for Credential Guard
            Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-HyperVisor -Online -All -LimitAccess -NoRestart -ErrorAction Stop | Out-Null
            Write-LogEntry "Successfully enabled Microsoft-Hyper-V-HyperVisor feature" -Severity 1 -Outhost
        }
        catch [System.Exception] {
            Write-LogEntry ("An error occured when enabling Microsoft-Hyper-V-HyperVisor. Error: -f $_") -Severity 3 -Outhost
        }

        try {
            # For version older than Windows 10 version 1607 (build 14939), add the IsolatedUserMode feature as well
            Enable-WindowsOptionalFeature -FeatureName IsolatedUserMode -Online -All -LimitAccess -NoRestart -ErrorAction Stop | Out-Null
            Write-LogEntry "Successfully enabled IsolatedUserMode feature" -Severity 1 -Outhost
        }
        catch [System.Exception] {
            Write-LogEntry ("An error occured when enabling IsolatedUserMode. Error: -f $_") -Severity 3 -Outhost
        }
    }
    
    Write-LogEntry "Attempting to enable Deviceguard security" -Severity 1 -Outhost
    #https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/enable-virtualization-based-protection-of-code-integrity
    Configure-RegistryItem -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name RequirePlatformSecurityFeatures -Type DWord -Value 1 -Force | Out-Null
    Configure-RegistryItem -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name EnableVirtualizationBasedSecurity -Type DWord -Value 1 -Force | Out-Null
    Configure-RegistryItem -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name Locked -Type DWord -Value 0 -Force | Out-Null
    If ([int](Get-WmiObject -Class Win32_OperatingSystem).BuildNumber -lt 14393) {
        Configure-RegistryItem -Path "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name HypervisorEnforcedCodeIntegrity -Type DWord -Value 1 -Force | Out-Null
    }
    Configure-RegistryItem -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name Enabled -Type DWord -Value 1 -Force | Out-Null
    Configure-RegistryItem -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name Locked -Type DWord -Value 0 -Force | Out-Null

    Configure-RegistryItem -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name LsaCfgFlags -Type DWord -Value 1 -Force | Out-Null
    $DeviceGuardProperty = Get-CimInstance –ClassName Win32_DeviceGuard –Namespace root\Microsoft\Windows\DeviceGuard
    If($DeviceGuardProperty.VirtualizationBasedSecurityStatus -eq 1){
        Write-LogEntry ("Successfully enabled Credential Guard, version: {0}" -f $DeviceGuardProperty.Version) -Severity 1 -Outhost   
    }
    Else{
        Write-LogEntry "Unable to enabled Credential Guard, may not be supported on this model, trying a differnet way" -Severity 2 -Outhost
        . $AdditionalScriptsPath\DG_Readiness_Tool_v3.6.ps1 -Enable -CG
    }
}


If($DisableIndexing -or $EnableVDIOptimizations){
    Write-LogEntry "Disable Indexing on $env:SystemDrive" -Severity 1 -Outhost
    Disable-Indexing $env:SystemDrive
}


If ($PreCompileAssemblies -or $EnableVDIOptimizations)
{
    #https://www.emc.com/collateral/white-papers/h14854-optimizing-windows-virtual-desktops-deploys.pdf
    #https://blogs.msdn.microsoft.com/dotnet/2012/03/20/improving-launch-performance-for-your-desktop-applications/
    Write-LogEntry "Pre-compile .NET framework assemblies. This can take a while...." -Severity 1 -Outhost
    Start-Process "$env:windir\Microsoft.NET\Framework\v4.0.30319\ngen.exe" -ArgumentList "update /force" -Wait -NoNewWindow
    Start-Process "$env:windir\Microsoft.NET\Framework\v4.0.30319\ngen.exe" -ArgumentList "executequeueditems" -Wait -NoNewWindow
}


If ($EnableVDIOptimizations)
{
    Write-LogEntry "VDI Optimizations: Disabling Paging Executive..." -Severity 1 -Outhost
    Configure-RegistryItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'DisablePagingExecutive' -Value 1 -Force | Out-Null

    Write-LogEntry "VDI Optimizations: Disabling NTFS Last Access" -Severity 1 -Outhost
    Start-process fsutil -ArgumentList 'behavior set disablelastaccess 1 ' -Wait -NoNewWindow  | Out-Null
}
