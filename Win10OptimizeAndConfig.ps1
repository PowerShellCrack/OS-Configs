<#	
	.NOTES
	===========================================================================
	 Originally Created by:   	Anton Romanyuk
     Added more capibilities:   Richard Tracy
	 Filename:     	ApplyWin10Otimizations.ps1
	===========================================================================
	.DESCRIPTION
		Applies Windows 10 enterprise-oriented optimizations and privacy mitigations 
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
    Await ($bluetooth.SetStateAsync($BluetoothStatus)) ([Windows.Devices.Radios.RadioAccessStatus]) | Out-Null
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



Function Set-RegistryItembyLGPO {
    [CmdletBinding()] 
    Param (
    $RegPath,
    $Name,
    $Value,
    [Parameter(Mandatory=$true)][ValidateSet('None','SZ','EXPAND_SZ','BINARY','REG_MULTI_SZ','DWORD')]$Type,
    $TryLGPO,
    $LGPOExe,
    $LogPath
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
        If($TryLGPO){
            $RegKeyHive = ($RegPath).Split('\')[0]
            $RegKeyPath = Split-Path ($RegPath).Split('\',2)[1] -Parent

            #The -split operator supports specifying the maximum number of sub-strings to return.
            #Some values may have additional commas in them that we don't want to split (eg. LegalNoticeText)
            [String]$Value = $Value -split ',',2

            Switch($RegKeyHive){
                MACHINE {$LGPOHive = 'Computer';$RegProperty = 'HKLM:'}
                USER {$LGPOHive = 'User';$RegProperty = 'HKCU:'}
            }

            #https://www.motobit.com/help/RegEdit/cl72.htm
            Switch($Type){
                0 {$RegType = 'NONE'}
                1 {$RegType = 'SZ'}
                2 {$RegType = 'EXPAND_SZ'}
                3 {$RegType = 'BINARY'}
                4 {$RegType = 'DWORD'}
                5 {$RegType = 'DWORD_BIG_ENDIAN'}
                6 {$RegType = 'LINK'}
                7 {$RegType = 'SZ'}
            }
    
            Write-host "   Adding Registry: $RegProperty\$RegKeyPath\$RegName" -ForegroundColor DarkGray
            $lgpoout += "$LGPOHive`r`n"
            $lgpoout += "$RegKeyPath`r`n"
            $lgpoout += "$Name`r`n"
            $lgpoout += "$($RegType):$Value`r`n"
            $lgpoout += "`r`n"
            

            $lgpoout | Out-File "$env:Temp\$RegName.lgpo"

            $result = Start-Process $LGPOExe -ArgumentList "/t ""$env:Temp\$($GPO.name).lgpo""" -RedirectStandardError "$workingLogPath\$($GPO.name).lgpo.stderr.log" -Wait -NoNewWindow -PassThru
        }
    }
    End {
        If(!$result -or $result.ExitCode -ne 0){
            If(Test-Path $RegPath\$Name){
                Set-ItemProperty $RegPath -Name $Name -Value $Value -Type $Type -Force | Out-Null     
            }
            Else{
                New-ItemProperty -Path $RegPath -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null 
            }
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
[boolean]$LGPOForConfigs = $false
[string]$LGPOPath = ''
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

# When running in Tasksequence and configureation exists, use that instead
If($tsenv){
    # Configurations comes from Tasksequence
    If($tsenv:CFG_UseLGPOForConfigs){[boolean]$LGPOForConfigs = [boolean]::Parse($tsenv.Value("CFG_UseLGPOForConfigs"))}
    If($tsenv:LGPOPath){[string]$LGPOPath = $tsenv.Value("LGPOPath")}
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
    If($tsenv:CFG_DisableWindowsFirstLoginAnimation{[boolean]$DisableWindowsFirstLoginAnimation = [boolean]::Parse($tsenv.Value("CFG_DisableWindowsFirstLoginAnimation"))}
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
}
##*===========================================================================
##* MAIN
##*===========================================================================
$OneNotePathx86 = Get-ChildItem "${env:ProgramFiles(x86)}" -Recurse -Filter "ONENOTE.EXE"
$OneNotePathx64 = Get-ChildItem "$env:ProgramFiles" -Recurse -Filter "ONENOTE.EXE"
If($OneNotePathx86){$OneNotePath = $OneNotePathx86}
If($OneNotePathx64){$OneNotePath = $OneNotePathx64}

If ($EnableOfficeOneNote -and $OneNotePath)
{
	# Mount HKCR drive
	Write-LogEntry "Setting OneNote file association to the desktop app." -Severity 1 -Outhost
	New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT"
	New-Item -Path 'HKCR:\onenote-cmd\Shell\Open' -Name 'Command' -Force
    New-ItemProperty -Path "HKCR:\onenote-cmd\Shell\Open\Command" -Name "@" -PropertyType String -Value $OneNotePath.FullName -Force
	Remove-PSDrive -Name "HKCR"
}

If($EnablePSLogging)
{
    Write-LogEntry ("Enabling Powershell Script Block Logging") -Severity 1 -Outhost
    New-ItemProperty -Path "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -PropertyType DWord -Value 1 -Force

    Write-LogEntry ("Enabling Powershell Transcription Logging") -Severity 1 -Outhost
    New-ItemProperty -Path "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableInvocationHeader" -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "OutputDirectory" -Value "" -Force

    Write-LogEntry ("Enabling Powershell Module Logging Logging") -Severity 1 -Outhost
    New-ItemProperty -Path "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -PropertyType DWord -Value 1  -Force
    #New-ItemProperty -Path "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "ModuleNames" -Value "" -Force
}

If ($EnableSystemVerboseMsg -or $EnableVDIOptimizations)
{
    #https://support.microsoft.com/en-us/help/325376/how-to-enable-verbose-startup-shutdown-logon-and-logoff-status-message
    Write-LogEntry ("Setting Windows Startup to Verbose messages") -Severity 1 -Outhost
    New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -PropertyType DWord -Value 1  -Force
    If(Test-Path ('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableStatusMessages') ){
        Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name 'DisableStatusMessages' -Force
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

If ($DisableAutoRun)
{
    $LocalMachinePath ='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    $AllUsersPath = "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    $CurrentUserPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"

    Write-LogEntry "Disabling Autorun for local machine..." -Severity 1 -Outhost
    Set-ItemProperty $LocalMachinePath -Name HonorAutorunSetting -Type DWord -Value 1 -Force
    Set-ItemProperty $LocalMachinePath -Name NoDriveAutoRun -Type DWord -Value 67108863 -Force
    Set-ItemProperty $LocalMachinePath -Name NoDriveTypeAutorun -Type DWord -Value 0xFF -Force

    Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping\Autorun.inf' -Name '(Default)' -Value "@SYS:DoesNotExist" -Force
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Cdrom' -Name AutoRun -Type DWord -Value 0 -Force

    Write-LogEntry "Disabling Autorun for all users..." -Severity 1 -Outhost
    Set-ItemProperty $AllUsersPath -Name HonorAutorunSetting -Type DWord -Value 1 -Force
    Set-ItemProperty $AllUsersPath -Name NoDriveAutoRun -Type DWord -Value 67108863 -Force
    Set-ItemProperty $AllUsersPath -Name NoDriveTypeAutorun -Type DWord -Value 0xFF -Force

    Write-LogEntry ("Disabling Autorun for Current user: {0}..." -f $env:USERNAME) -Severity 1 -Outhost
    Set-ItemProperty $CurrentUserPath -Name HonorAutorunSetting -Type DWord -Value 1 -Force
    Set-ItemProperty $CurrentUserPath -Name NoDriveAutoRun -Type DWord -Value 67108863 -Force
    Set-ItemProperty $CurrentUserPath -Name NoDriveTypeAutorun -Type DWord -Value 0xFF -Force
}

If ($ApplySTIGItems)
{
    Write-LogEntry "Stig Item: Disabling Winlogon's Auto Restart Shell..." -Severity 1 -Outhost
    Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'AutoRestartShell' -Value 0 -Force

	Write-LogEntry "Stig Item: Disabling Session Kernel Exception Chain Validation..." -Severity 1 -Outhost
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' -Name 'DisableExceptionChainValidation' -Value 0 -Force

	Write-LogEntry "Stig Item: Clearing Session Subsystem's..." -Severity 1 -Outhost
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\SubSystems' -Name 'Optional' -Type REG_MULTI_SZ -Value "" -Force

    Write-LogEntry "Stig Item: Disabling File System's 8.3 Name Creation..." -Severity 1 -Outhost
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name 'NtfsDisable8dot3NameCreation' -Value 1 -Force

    Write-LogEntry "Stig Item: Disabling RASMAN PPP Parameters..." -Severity 1 -Outhost
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\services\RasMan\Parameters' -Name 'DisableSavePassword' -Value 1 -Force
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\services\RasMan\Parameters' -Name 'Logging' -Value 1 -Force
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\services\RasMan\PPP' -Name 'ForceEncryptedData' -Value 1 -Force
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\services\RasMan\PPP' -Name 'ForceEncryptedPassword' -Value 2 -Force
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\services\RasMan\PPP' -Name 'SecureVPN' -Value 1 -Force
}

If ($EnableRDP)
{
	Write-LogEntry "Enabling RDP..." -Severity 1 -Outhost
	Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -Value 0  
	Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "UserAuthentication" -Value 1  
	Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
}

If ($DisableOneDrive)
{
	Write-LogEntry "Turning off OneDrive..." -Severity 1 -Outhost
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows' -Name 'OneDrive' -Force
	New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'DisableFileSyncNGSC' -PropertyType DWORD -Value '1' -Force
	New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'PreventNetworkTrafficPreUserSignIn' -PropertyType DWORD -Value '1' -Force
    Set-ItemProperty -Path 'HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder' -name Attributes -Type DWORD -Value 0 -Force 
}

If ($PreferIPv4OverIPv6)
{
	# Use 0x20 to prefer IPv4 over IPv6 by changing entries in the prefix policy table. 
	Write-LogEntry "Modifying IPv6 bindings to prefer IPv4 over IPv6..." -Severity 1 -Outhost
	New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'DisabledComponents' -PropertyType DWORD -Value '32' -Force
}

If ($DisableIEFirstRunWizard)
{
	# Disable IE First Run Wizard
	Write-LogEntry "Disabling IE First Run Wizard..." -Severity 1 -Outhost
	New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft' -Name 'Internet Explorer' -Force
	New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer' -Name 'Main' -Force
	New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main' -Name DisableFirstRunCustomize -PropertyType DWORD -Value '1' -Force
        
    New-ItemProperty -Path 'HKCU:\Software\Microsoft\Internet Explorer\Main' -Name DisableFirstRunCustomize -PropertyType DWORD -Value '1' -Force
    New-ItemProperty -Path 'HKCU:\Software\Microsoft\Internet Explorer\Main' -Name RunOnceHasShown -PropertyType DWORD -Value '1' -Force
    New-ItemProperty -Path 'HKCU:\Software\Microsoft\Internet Explorer\Main' -Name RunOnceComplete -PropertyType DWORD -Value '1' -Force

    New-ItemProperty -Path 'HKEY_USERS\.DEFAULT\Software\Microsoft\Internet Explorer\Main' -Name DisableFirstRunCustomize -PropertyType DWORD -Value '1' -Force
    New-ItemProperty -Path 'HKEY_USERS\.DEFAULT\Software\Microsoft\Internet Explorer\Main' -Name RunOnceHasShown -PropertyType DWORD -Value '1' -Force
    New-ItemProperty -Path 'HKEY_USERS\.DEFAULT\Software\Microsoft\Internet Explorer\Main' -Name RunOnceComplete -PropertyType DWORD -Value '1' -Force
}

If ($DisableWMPFirstRunWizard)
{
	# Disable IE First Run Wizard
	Write-LogEntry "Disabling Media Player First Run Wizard..." -Severity 1 -Outhost
	New-ItemProperty -Path 'HKLM:\Software\Microsoft\MediaPlayer\Preferences' -Name AcceptedEULA -PropertyType DWORD -Value '1' -Force
    New-ItemProperty -Path 'HKLM:\Software\Microsoft\MediaPlayer\Preferences' -Name FirstTime -PropertyType DWORD -Value '1' -Force
    New-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\WindowsMediaPlayer' -Name GroupPrivacyAcceptance -PropertyType DWORD -Value '1' -Force
}

If ($DisableEdgeIconCreation)
{
	Write-LogEntry "Disabling Microsoft Edge desktop icon creation..." -Severity 1 -Outhost
	New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'Explorer' -PropertyType DWORD -Value '1' -Force
	New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'DisableEdgeDesktopShortcutCreation' -PropertyType DWORD -Value '1' -Force
}

# Disable New Network dialog box
If ($DisableNewNetworkDialog)
{
	Write-LogEntry "Disabling New Network Dialog..." -Severity 1 -Outhost
	New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Network' -Name 'NewNetworkWindowOff' -Force
    New-ItemProperty 'HKLM:\System\CurrentControlSet\Services\NlaSvc\Parameters\Internet' -Name 'EnableActiveProbing' -PropertyType DWORD -Value '0' -Force
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
            Remove-ItemProperty -Path ('HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\' + $_.Value) -Name 'StubPath' -Force
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
    Disable-WindowsOptionalFeature -FeatureName Printing-Foundation-InternetPrinting-Client -Online -NoRestart -ErrorAction Stop

    Write-LogEntry "Disabling Fax and scanning" -Severity 1 -Outhost
    Disable-WindowsOptionalFeature -FeatureName FaxServicesClientPackage -Online -NoRestart -ErrorAction Stop
}

If ($DisableDefender -or $EnableVDIOptimizations)
{
    Write-LogEntry "Disabling Windows Defender" -Severity 1 -Outhost
    Set-Service 'WinDefend' -StartupType Disabled
}

If ($DisableWireless -or $EnableVDIOptimizations)
{
    Write-LogEntry "Disabling Wireless Services" -Severity 1 -Outhost
    Set-Service 'wcncsvc' -StartupType Disabled
    Set-Service 'WwanSvc' -StartupType Disabled
}

If ($DisableFirewall)
{
    Write-LogEntry "Disabling Windows Firewall" -Severity 1 -Outhost
    netsh advfirewall set allprofiles state off
}

If ($EnableRemoteRegistry -or $EnableVDIOptimizations)
{
    Write-LogEntry "Starting Remote registry services" -Severity 1 -Outhost
    Set-Service 'RemoteRegistry' -StartupType Automatic
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
	Disable-ScheduledTask -TaskName "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
	Disable-ScheduledTask -TaskName "\Microsoft\Windows\Application Experience\ProgramDataUpdater"
	Disable-ScheduledTask -TaskName "\Microsoft\Windows\Application Experience\StartupAppTask"
	Disable-ScheduledTask -TaskName "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
	Disable-ScheduledTask -TaskName "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
	Disable-ScheduledTask -TaskName "\Microsoft\Windows\Maps\MapsToastTask"
	Disable-ScheduledTask -TaskName "\Microsoft\Windows\Maps\MapsUpdateTask"
	Disable-ScheduledTask -TaskName "\Microsoft\Windows\Shell\FamilySafetyMonitor"
	Disable-ScheduledTask -TaskName "\Microsoft\Windows\WDI\ResolutionHost"
	Disable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Media Sharing\UpdateLibrary"
	Disable-ScheduledTask -TaskName "\Microsoft\Windows\Autochk\Proxy"
	Disable-ScheduledTask -TaskName "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask"
	Disable-ScheduledTask -TaskName "\Microsoft\Windows\Feedback\Siuf\DmClient"
	Disable-ScheduledTask -TaskName "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload"
	Disable-ScheduledTask -TaskName "\Microsoft\Windows\Shell\FamilySafetyRefreshTask"
	Disable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Error Reporting\QueueReporting"
	Disable-ScheduledTask -TaskName "\Microsoft\XblGameSave\XblGameSaveTask"

    If($EnableVDIOptimizations)
    {
        Disable-ScheduledTask -TaskName "\Microsoft\Windows\Application Experience\AitAgent"
        #Disable-ScheduledTask -TaskName "\Microsoft\Windows\Application Experience\ProgramDataUpdater"
        #Disable-ScheduledTask -TaskName "\Microsoft\Windows\Application Experience\StartupAppTask"
        #Disable-ScheduledTask -TaskName "\Microsoft\Windows\Autochk\Proxy"
        Disable-ScheduledTask -TaskName "\Microsoft\Windows\Bluetooth\UninstallDeviceTask"
        Disable-ScheduledTask -TaskName "\Microsoft\Windows\Customer Experience Improvement Program\BthSQM"
        #Disable-ScheduledTask -TaskName "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
        Disable-ScheduledTask -TaskName "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask"
        #Disable-ScheduledTask -TaskName "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
        Disable-ScheduledTask -TaskName "\Microsoft\Windows\Defrag\ScheduledDefrag"
        Disable-ScheduledTask -TaskName "\Microsoft\Windows\DiskDiagnostic\Microsoft-WindowsDiskDiagnosticDataCollector"
        Disable-ScheduledTask -TaskName "\Microsoft\Windows\DiskDiagnostic\Microsoft-WindowsDiskDiagnosticResolver"
        Disable-ScheduledTask -TaskName "\Microsoft\Windows\FileHistory\File History (maintenance mode)"
        Disable-ScheduledTask -TaskName "\Microsoft\Windows\Live\Roaming\MaintenanceTask"
        Disable-ScheduledTask -TaskName "\Microsoft\Windows\Live\Roaming\SynchronizeWithStorage"
        Disable-ScheduledTask -TaskName "\Microsoft\Windows\Maintenance\WinSAT"
        Disable-ScheduledTask -TaskName "\Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser"
        Disable-ScheduledTask -TaskName "\Microsoft\Windows\MobilePC\HotStart"
        Disable-ScheduledTask -TaskName "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem\Microsoft\Windows\Ras\MobilityManager"
        Disable-ScheduledTask -TaskName "\Microsoft\Windows\SideShow\AutoWake"
        Disable-ScheduledTask -TaskName "\Microsoft\Windows\SideShow\GadgetManager"
        Disable-ScheduledTask -TaskName "\Microsoft\Windows\SideShow\SessionAgent"
        Disable-ScheduledTask -TaskName "\Microsoft\Windows\SideShow\SystemDataProviders"
        Disable-ScheduledTask -TaskName "\Microsoft\Windows\SpacePort\SpaceAgentTask"
        Disable-ScheduledTask -TaskName "\Microsoft\Windows\SystemRestore\SR"
        Disable-ScheduledTask -TaskName "\Microsoft\Windows\UPnP\UPnPHostConfig"
        Disable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance"
        Disable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan"
        Disable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Defender\Windows Defender Verification"
        #Disable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Error Reporting\QueueReporting"
        #Disable-ScheduledTask -TaskName "\Microsoft\Windows\Windows Media Sharing\UpdateLibrary"
        Disable-ScheduledTask -TaskName "\Microsoft\Windows\WindowsBackup\ConfigNotification"    }
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
	New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\' -Name 'Windows Search' -Force
	New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowCortana' -PropertyType DWORD -Value '0' -Force
}

If ($DisableInternetSearch)
{
	# Configure Search Options:
	Write-LogEntry "Configuring Search Options..." -Severity 1 -Outhost
	New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowSearchToUseLocation' -PropertyType DWORD -Value '0' -Force
	# Disallow search and Cortana to use location
	New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'ConnectedSearchUseWeb' -PropertyType DWORD -Value '0' -Force
    # Disable cortona option in taskbar
	New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'SearchboxTaskbarMode' -PropertyType DWORD -Value '0' -Force
	
    # Do not allow web search
	New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'DisableWebSearch' -PropertyType DWORD -Value '0' -Force
    # Do not allow Cortona to use web search with bing
	New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'BingSearchEnabled' -PropertyType DWORD -Value '0' -Force
}


# Privacy and mitigaton settings
# See: https://docs.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services
If ($ApplyPrivacyMitigations)
{
	Write-LogEntry "Disallowing the user to change sign-in options..."v
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device" -Name "Settings" -Force
	New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Settings' -Name 'AllowSignInOptions' -PropertyType DWORD -Value '0' -Force
	
	# Disable the Azure AD Sign In button in the settings app
	Write-LogEntry "Disabling Azure AD sign-in options..." -Severity 1 -Outhost
	New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Settings' -Name 'AllowWorkplace' -PropertyType DWORD -Value '0' -Force
	
	Write-LogEntry "Disabling the Microsoft Account Sign-In Assistant..." -Severity 1 -Outhost
	New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'NoConnectedUser' -PropertyType DWORD -Value '3' -Force
	
	# Disable the MSA Sign In button in the settings app
	Write-LogEntry "Disabling MSA sign-in options..." -Severity 1 -Outhost
	New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Settings' -Name 'AllowYourAccount' -PropertyType DWORD -Value '0' -Force
	
	Write-LogEntry "Disabling camera usage on user's lock screen..." -Severity 1 -Outhost
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "Personalization" -Force
	New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name 'NoLockScreenCamera' -PropertyType DWORD -Value '1' -Force
	
	Write-LogEntry "Disabling lock screen slideshow..." -Severity 1 -Outhost
	New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name 'NoLockScreenSlideshow' -PropertyType DWORD -Value '1' -Force
	
	# Offline maps
	Write-LogEntry "Turning off unsolicited network traffic on the Offline Maps settings page..." -Severity 1 -Outhost
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "Maps" -Force	
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps' -Name 'AllowUntriggeredNetworkTrafficOnSettingsPage' -PropertyType DWORD -Value '0' -Force
	Write-LogEntry "Turning off Automatic Download and Update of Map Data..." -Severity 1 -Outhost
	New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps' -Name 'AutoDownloadAndUpdateMapData' -PropertyType DWORD -Value '0' -Force
	
	# Microsoft Edge
	Write-LogEntry "Enabling Do Not Track in Microsoft Edge..." -Severity 1 -Outhost
	New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main' -Name 'DoNotTrack' -PropertyType DWORD -Value '1' -Force
	
	Write-LogEntry "Disallow web content on New Tab page in Microsoft Edge..." -Severity 1 -Outhost
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge" -Name "SearchScopes" -Force	
	New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\SearchScopes' -Name 'AllowWebContentOnNewTabPage' -PropertyType DWORD -Value '0' -Force
	
	# General stuff
	Write-LogEntry "Turning off the advertising ID..." -Severity 1 -Outhost
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion" -Name "AdvertisingInfo" -Force
	New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -Name 'Enabled' -PropertyType DWORD -Value '0' -Force
	
	Write-LogEntry "Turning off location..." -Severity 1 -Outhost
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "AppPrivacy" -Force
	New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessLocation' -PropertyType DWORD -Value '0' -Force
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "LocationAndSensors" -Force
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' -Name 'DisableLocation' -PropertyType DWORD -Value '0' -Force
	
	# Stop getting to know me
	Write-LogEntry "Turning off automatic learning..." -Severity 1 -Outhost
    New-Item -Path "HKLM:\Software\Policies\Microsoft" -Name "InputPersonalization" -Force	
    New-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\InputPersonalization' -Name 'RestrictImplicitInkCollection' -PropertyType DWORD -Value '1' -Force
	# Turn off updates to the speech recognition and speech synthesis models
	New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences' -Name 'ModelDownloadAllowed' -PropertyType DWORD -Value '0' -Force
	
	Write-LogEntry "Disallowing Windows apps to access account information..." -Severity 1 -Outhost
	New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows" -Name "AppPrivacy" -Force
	New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessAccountInfo' -PropertyType DWORD -Value '2' -Force
	
	Write-LogEntry "Disabling all feedback notifications..." -Severity 1 -Outhost
	New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'DoNotShowFeedbackNotifications' -PropertyType DWORD -Value '1' -Force
	
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
	New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -PropertyType DWORD -Value $TelemetryLevel -Force
}


If($CleanSampleFolders){
    Write-LogEntry "Cleaning Sample Folders..." -Severity 1 -Outhost
    Remove-Item "$env:PUBLIC\Music\Sample Music" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:PUBLIC\Pictures\Sample Pictures" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:PUBLIC\Recorded TV\Sample Media" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:PUBLIC\Videos\Sample Videos" -Recurse -Force -ErrorAction SilentlyContinue
}

If ($EnableWinRM)
{
    Write-LogEntry "Enabling WinRM" -Severity 1 -Outhost
    Enable-PSRemoting -Force | Out-Null
    winrm quickconfig -q
    winrm quickconfig -transport:http
    winrm set winrm/config '@{MaxTimeoutms="1800000"}'
    winrm set winrm/config/winrs '@{MaxMemoryPerShellMB="800"}'
    winrm set winrm/config/service '@{AllowUnencrypted="true"}'
    winrm set winrm/config/service/auth '@{Basic="true"}'
    winrm set winrm/config/client/auth '@{Basic="true"}'
    winrm set winrm/config/listener?Address=*+Transport=HTTP '@{Port="5985"}'

    If(!$DisableFirewall)
    {
        netsh advfirewall firewall set rule group="Windows Remote Administration" new enable=yes
        netsh advfirewall firewall set rule name="Windows Remote Management (HTTP-In)" new enable=yes action=allow
    }

    Set-Service winrm -startuptype "auto"
    Restart-Service winrm  | Out-Null
}


If ($EnableAppsRunAsAdmin -or $DisableUAC)
{
    Write-LogEntry "Enabling Apps to run as Administrator..." -Severity 1 -Outhost
    New-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name FilterAdministratorToken -PropertyType DWORD -Value '1' -Force
}

If ($DisableUAC)
{
    Write-LogEntry "Disabling User Access Control..." -Severity 1 -Outhost
    New-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -PropertyType DWORD -Value '0' -Force
    New-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -PropertyType DWORD -Value '0' -Force
    New-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name PromptOnSecureDesktop -PropertyType DWORD -Value '0' -Force
}


If ($DisableWUP2P)
{
    Write-LogEntry "Disable P2P WIndows Updates..." -Severity 1 -Outhost
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config' -Name DODownloadMode -PropertyType DWORD -Value '0' -Force
    New-ItemProperty -Path 'HKLM:\Software\Microsoft\WindowsUpdate\UX' -Name IsConvergedUpdateStackEnabled -PropertyType DWORD -Value '0' -Force
}


If ( ($EnableIEEnterpriseMode)  -and (Test-Path $IEEMSiteListPath) )
{
    Write-LogEntry "Enabling Enterprise Mode option in IE..." -Severity 1 -Outhost
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\EnterpriseMode' -Name Enable -PropertyType DWORD -Value '1' -Force
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\EnterpriseMode' -Name Sitelist -Value $IEEMSiteListPath -Force
}

# Logon script
If ($InstallLogonScript -and (Test-Path $LogonScriptPath) )
{
	Write-LogEntry "Copying Logon script to C:\Windows\Scripts" -Severity 1 -Outhost
	If (!(Test-Path "C:\Windows\Scripts"))
	{
		New-Item "C:\Windows\Scripts" -ItemType Directory
	}
	Copy-Item -Path $LogonScriptPath -Destination "C:\Windows\Scripts\Logon.ps1" -Force
	# load default hive
	Start-Process -FilePath "reg.exe" -ArgumentList "LOAD HKLM\DEFAULT C:\Users\Default\NTUSER.DAT"
	# create RunOnce entries current / new user(s)
	Write-LogEntry "Creating RunOnce entries..." -Severity 1 -Outhost
	New-ItemProperty -Path "HKLM:\Default\Software\Microsoft\Windows\CurrentVersion\Runonce" -Name "Logon" -Value "Powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\Windows\Scripts\Logon.ps1"
	New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Runonce" -Name "Logon" -Value "Powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\Windows\Scripts\Logon.ps1"
	# unload default hive
	Start-Process -FilePath "reg.exe" -ArgumentList "UNLOAD HKLM\DEFAULT"
}

If($EnableCredGuard)
{
if ([int](Get-WmiObject -Class Win32_OperatingSystem).BuildNumber -lt 14393) {
        try {
            # For version older than Windows 10 version 1607 (build 14939), enable required Windows Features for Credential Guard
            Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-HyperVisor -Online -All -LimitAccess -NoRestart -ErrorAction Stop
            Write-LogEntry "Successfully enabled Microsoft-Hyper-V-HyperVisor feature" -Severity 1 -Outhost

            # For version older than Windows 10 version 1607 (build 14939), add the IsolatedUserMode feature as well
            Enable-WindowsOptionalFeature -FeatureName IsolatedUserMode -Online -All -LimitAccess -NoRestart -ErrorAction Stop
            Write-LogEntry "Successfully enabled IsolatedUserMode feature" -Severity 1 -Outhost
        }
        catch [System.Exception] {
            Write-LogEntry "An error occured when enabling required windows features" -Severity 3 -Outhost
        }
    }
    
    # Add required registry key for Credential Guard
    $RegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
    if (-not(Test-Path -Path $RegistryKeyPath)) {
        Write-LogEntry "Creating HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard registry key" -Severity 1 -Outhost
        New-Item -Path $RegistryKeyPath -ItemType Directory -Force
    }

    # Add registry value RequirePlatformSecurityFeatures - 1 for Secure Boot only, 3 for Secure Boot and DMA Protection
    Write-LogEntry "Adding HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard\RequirePlatformSecurityFeatures value as DWORD with data 1" -Severity 1 -Outhost
    New-ItemProperty -Path $RegistryKeyPath -Name RequirePlatformSecurityFeatures -PropertyType DWORD -Value 1 -Outhost

    # Add registry value EnableVirtualizationBasedSecurity - 1 for Enabled, 0 for Disabled
    Write-LogEntry "Adding HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard\EnableVirtualizationBasedSecurity value as DWORD with data 1" -Severity 1 -Outhost
    New-ItemProperty -Path $RegistryKeyPath -Name EnableVirtualizationBasedSecurity -PropertyType DWORD -Value 1 -Outhost

    # Add registry value LsaCfgFlags - 1 enables Credential Guard with UEFI lock, 2 enables Credential Guard without lock, 0 for Disabled
    Write-LogEntry "Adding HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\LsaCfgFlags value as DWORD with data 1" -Severity 1 -Outhost
    New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name LsaCfgFlags -PropertyType DWORD -Value 1

    # Write end of log file
    Write-LogEntry "Successfully enabled Credential Guard" -Severity 1 -Outhost
}


If($DisableIndexing -or $EnableVDIOptimizations){
    Write-LogEntry "Disable Indexing on $env:SystemDrive" -Severity 1 -Outhost
    Disable-Indexing $env:SystemDrive
}


If ($PreCompileAssemblies -or $EnableVDIOptimizations)
{
    #https://www.emc.com/collateral/white-papers/h14854-optimizing-windows-virtual-desktops-deploys.pdf
    #https://blogs.msdn.microsoft.com/dotnet/2012/03/20/improving-launch-performance-for-your-desktop-applications/
    Write-LogEntry "Pre-compile .NET framework assemblies" -Severity 1 -Outhost
    Start-Process "%windir%\Microsoft.NET\Framework\v4.0.30319\ngen.exe" -ArgumentList "update /force" -Wait -NoNewWindow
    Start-Process "%windir%\Microsoft.NET\Framework\v4.0.30319\ngen.exe" -ArgumentList "executequeueditems" -Wait -NoNewWindow
}


If ($EnableVDIOptimizations)
{
    Write-LogEntry "VDI Optimizations: Disabling Paging Executive..." -Severity 1 -Outhost
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'DisablePagingExecutive' -Value 1 -Force

    Write-LogEntry "VDI Optimizations: Disabling NTFS Last Access" -Severity 1 -Outhost
    Start-process fsutil -ArgumentList 'behavior set disablelastaccess 1 ' -Wait -NoNewWindow


}


