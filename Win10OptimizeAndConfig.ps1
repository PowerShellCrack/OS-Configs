<#	
	.NOTES
	===========================================================================
	 Originally Created by:   	Anton Romanyuk
     Added more capibilities:   Richard Tracy
	 Filename:     	            Win10OptimizeAndConfig.ps1
     Last Updated:              03/08/2019
     Thanks to:                 unixuser011,W4RH4WK
	===========================================================================
	.DESCRIPTION
		Applies Windows 10 Optimizations and configurations. Supports VDI optmizations
        Utilizes LGPO.exe to apply group policy item where neceassary.
        Applies DISA stigs for Windows 10 
        Utilizes MDT/SCCM TaskSequence variables:
           _SMSTSLogPath

    . PARAM
        Configurable using custom variables in MDT/SCCM:
            CFG_DisableScript
            CFG_UseLGPOForConfigs
            LGPOPath
            CFG_SetPowerCFG
            CFG_PowerCFGFilePath
            CFG_EnableVerboseMsg
            CFG_EnablePSLogging
            CFG_ApplySTIGItems
            CFG_EnableFIPS
            CFG_DisableAutoRun
            CFG_CleanSampleFolders
            CFG_DisableCortana
            CFG_DisableInternetSearch
            CFG_OptimizeForVDI
            CFG_EnableOfficeOneNote
            CFG_EnableRDP
            CFG_DisableOneDrive
            CFG_PreferIPv4OverIPv6
            CFG_RemoveActiveSetupComponents
            CFG_DisableWindowsFirstLoginAnimation
            CFG_DisableIEFirstRunWizard
            CFG_DisableWMPFirstRunWizard
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
            CFG_EnableVisualPerformance
            CFG_EnableDarkTheme
            CFG_EnableNumlockStartup
            CFG_ShowKnownExtensions
            CFG_ShowHiddenFiles
            CFG_ShowThisPCOnDesktop
            CFG_ShowUserFolderOnDesktop
            CFG_Hide3DObjectsFromExplorer
            CFG_DisableEdgeShortcut
            CFG_SetSmartScreenFilter
            CFG_EnableStrictUAC
            CFG_ApplyCustomHost
            HostPath
            CFG_DisableStoreOnTaskbar
            CFG_DisableActionCenter
            CFG_DisableFeedback
            CFG_DisableWindowsUpgrades
            CFG_ApplyEMETMitigations
    
    . EXAMPLE
        #Copy this to MDT CustomSettings.ini
        Properties=CFG_DisableScript,CFG_UseLGPOForConfigs,LGPOPath,CFG_SetPowerCFG,CFG_PowerCFGFilePath,CFG_EnableVerboseMsg,CFG_ApplySTIGItems,CFG_EnableFIPS,CFG_DisableAutoRun,
        CFG_CleanSampleFolders,CFG_DisableCortana,CFG_DisableInternetSearch,CFG_OptimizeForVDI,CFG_EnableOfficeOneNote,CFG_EnableRDP,CFG_DisableOneDrive,CFG_PreferIPv4OverIPv6,
        CFG_RemoveActiveSetupComponents,CFG_DisableWindowsFirstLoginAnimation,CFG_DisableIEFirstRunWizard,CFG_DisableWMPFirstRunWizard,CFG_DisableNewNetworkDialog,
        CFG_DisableInternetServices,CFG_DisabledUnusedServices,CFG_DisabledUnusedFeatures,CFG_DisableSchTasks,CFG_DisableDefender,CFG_DisableFirewall,CFG_DisableWireless,CFG_DisableBluetooth,
        CFG_EnableRemoteRegistry,CFG_DisableFirewall,CFG_ApplyPrivacyMitigations,CFG_EnableCredGuard,CFG_InstallLogonScript,CFG_LogonScriptPath,CFG_EnableWinRM,CFG_EnableAppsRunAsAdmin,
        CFG_DisableUAC,CFG_DisableWUP2P,CFG_EnableIEEnterpriseMode,CFG_IEEMSiteListPath,CFG_PreCompileAssemblies,CFG_EnableSecureLogon,CFG_HideDrives,CFG_DisableAllNotifications,
        CFG_InstallPSModules,CFG_EnableVisualPerformance,CFG_EnableDarkTheme,CFG_EnableNumlockStartup,CFG_ShowKnownExtensions,CFG_ShowHiddenFiles,CFG_ShowThisPCOnDesktop,
        CFG_ShowUserFolderOnDesktop,CFG_Hide3DObjectsFromExplorer,CFG_DisableEdgeShortcut,SCCMSiteServer,AppVolMgrServer,AdminMenuConfigPath,CFG_SetSmartScreenFilter,CFG_EnableStrictUAC,
        CFG_ApplyCustomHost,HostPath,CFG_DisableStoreOnTaskbar,CFG_DisableActionCenter,CFG_DisableFeedback,CFG_DisableWindowsUpgrades,CFG_ApplyEMETMitigations

        Then add each option to a priority specifically for your use, like:
        [Default]
        CFG_UseLGPOForConfigs=True
        CFG_SetPowerCFG=Custom
        CFG_PowerCFGFilePath=%DeployRoot%\Scripts\Custom\OS-Configs\AlwaysOnPowerScheme.pow
        CFG_EnableVerboseMsg=True
        CFG_ApplySTIGItems=True
        CFG_DisableAutoRun=True
        CFG_CleanSampleFolders=True
        ...

#> 


##*===========================================================================
##* FUNCTIONS
##*===========================================================================

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
    $CombinedDateTime = "$LogDate $LogTime"
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
    ## Get the name of this function
    [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name

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
    $LogFormat = "<![LOG[$Message]LOG]!>" + "<time=`"$LogTimePlusBias`" " + "date=`"$LogDate`" " + "component=`"$ScriptSource`" " + "context=`"$([Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " + "type=`"$Severity`" " + "thread=`"$PID`" " + "file=`"$ScriptSource`">"
    
    # Add value to log file
    try {
        Out-File -InputObject $LogFormat -Append -NoClobber -Encoding Default -FilePath $OutputLogFile -ErrorAction Stop
    }
    catch {
        Write-Host ("[{0}] [{1}] :: Unable to append log entry to [{1}], error: {2}" -f $LogTimePlusBias,$ScriptSource,$OutputLogFile,$_.Exception.ErrorMessage) -ForegroundColor Red
    }
    If($Outhost){
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

Function Config-Bluetooth{
    [CmdletBinding()] 
    Param (
    [Parameter(Mandatory=$true)][ValidateSet('Off', 'On')]
    [string]$DeviceStatus
    )

    ## Get the name of this function
    [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name

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


Function Set-SystemSettings {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact='Medium')]
    Param (

    [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
    [Alias("Path")]
    [string]$RegPath,

    [Parameter(Mandatory=$false,Position=1,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
    [Alias("v")]
    [string]$Name,

    [Parameter(Mandatory=$false,Position=2,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
    [Alias("d")]
    $Value,

    [Parameter(Mandatory=$false,Position=3,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
    [ValidateSet('None','String','Binary','DWord','ExpandString','MultiString','QWord')]
    [Alias("PropertyType","t")]
    $Type,

    [Parameter(Mandatory=$false)]
    [boolean]$TryLGPO = $Global:LGPOForConfigs,

    [Parameter(Mandatory=$false)]
    $LGPOExe = $Global:LGPOPath,

    [Parameter(Mandatory=$false)]
    [string]$LogPath,

    [Parameter(Mandatory=$false,Position=4,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
    [Alias("f")]
    [switch]$Force,

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
        
        Try{
            #check if tryLGPO is set and path is set
            If($TryLGPO -and $LGPOExe){
                #does LGPO path exist?
                If(Test-Path $LGPOExe){
                    # build a unique output file
                    $LGPOfile = ($RegKeyHive + '-' + $RegKeyPath.replace('\','-').replace(' ','') + '-' + $RegKeyName.replace(' ','') + '.lgpo')
            
                    #complete LGPO file
                    Write-LogEntry ("LGPO applying [{3}] to registry: [{0}\{1}\{2}] as a Group Policy item" -f $RegProperty,$RegKeyPath,$RegKeyName,$RegKeyName) -Severity 4 -Source ${CmdletName} -Outhost
                    $lgpoout += "$LGPOHive`r`n"
                    $lgpoout += "$RegKeyPath`r`n"
                    $lgpoout += "$RegKeyName`r`n"
                    $lgpoout += "$($RegType):$Value`r`n"
                    $lgpoout += "`r`n"
                    $lgpoout | Out-File "$env:Temp\$LGPOfile"

                    If($VerbosePreference){$args="/v /q /t"}Else{$args="/q /t"}
                    Write-LogEntry "Start-Process $LGPOExe -ArgumentList '/t $env:Temp\$LGPOfile' -RedirectStandardError '$env:Temp\$LGPOfile.stderr.log'" -Severity 4 -Source ${CmdletName} -Outhost
                    Write-Verbose "Start-Process $LGPOExe -ArgumentList `"$args $env:Temp\$LGPOfile /v`" -RedirectStandardError `"$env:Temp\$LGPOfile.stderr.log`" -Wait -NoNewWindow -PassThru"
                    If(!$WhatIfPreference){$result = Start-Process $LGPOExe -ArgumentList "$args $env:Temp\$LGPOfile /v" -RedirectStandardError "$env:Temp\$LGPOfile.stderr.log" -Wait -NoNewWindow -PassThru | Out-Null}
                    Write-LogEntry ("LGPO ran successfully. Exit code: {0}" -f $result.ExitCode) -Severity 4 -Outhost
                }
                Else{
                    Write-LogEntry ("LGPO will not be used. Path not found: {0}" -f $LGPOExe) -Severity 3 -Outhost

                }
            }
            Else{
                Write-LogEntry ("LGPO not enabled. Hardcoding registry keys [{0}\{1}\{2}]...." -f $RegProperty,$RegKeyPath,$RegKeyName) -Severity 0 -Source ${CmdletName} -Outhost
            }
        }
        Catch{
            If($TryLGPO -and $LGPOExe){
                Write-LogEntry ("LGPO failed to run. exit code: {0}. Hardcoding registry keys [{1}\{2}\{3}]...." -f $result.ExitCode,$RegProperty,$RegKeyPath,$RegKeyName) -Severity 3 -Source ${CmdletName} -Outhost
            }
        }
        Finally
        {
            start-sleep 3
            
            #verify the registry value has been set
            Try{
                If( -not(Test-Path ($RegProperty +'\'+ $RegKeyPath)) ){
                    Write-LogEntry ("Key was not set; Hardcoding registry keys [{0}\{1}] with value [{2}]...." -f ($RegProperty +'\'+ $RegKeyPath),$RegKeyName,$Value) -Severity 0 -Source ${CmdletName} -Outhost
                    New-Item -Path ($RegProperty +'\'+ $RegKeyPath) -Force -WhatIf:$WhatIfPreference | Out-Null
                    New-ItemProperty -Path ($RegProperty +'\'+ $RegKeyPath) -Name $RegKeyName -PropertyType $RegType -Value $Value -Force:$Force -WhatIf:$WhatIfPreference | Out-Null
                } 
                Else{
                    Write-LogEntry ("Key name not found. Creating key name [{1}] at path [{0}] with value [{2}]" -f ($RegProperty +'\'+ $RegKeyPath),$RegKeyName,$Value) -Severity 1 -Source ${CmdletName} -Outhost
                    Set-ItemProperty -Path ($RegProperty +'\'+ $RegKeyPath) -Name $RegKeyName -Value $Value -Force:$Force -WhatIf:$WhatIfPreference | Out-Null
                }
            }
            Catch{
                Write-LogEntry ("Unable to set registry key [{0}\{1}\{2}] with value [{3}]" -f $RegProperty,$RegKeyPath,$RegKeyName,$Value) -Severity 2 -Source ${CmdletName} -Outhost
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
        ## Get the name of this function
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name

        Write-LogEntry ("Setting power plan to `"{0}`"" -f $PreferredPlan) -Severity 1 -Source ${CmdletName} -Outhost

        $guid = (Get-WmiObject -Class Win32_PowerPlan -Namespace root\cimv2\power -Filter "ElementName='$PreferredPlan'" -ComputerName $ComputerName).InstanceID.ToString()

        $regex = [regex]"{(.*?)}$"

        $plan = $regex.Match($guid).groups[1].value

        #powercfg -S $plan
        $process = Get-WmiObject -Query "SELECT * FROM Meta_Class WHERE __Class = 'Win32_Process'" -Namespace "root\cimv2" -ComputerName $ComputerName
        $results = $process.Create("powercfg -S $plan")
    
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
            If($VerbosePreference){Write-LogEntry ("powercfg $params") -Outhost}
            $results = $process.Create("powercfg $params")
        }
        Catch{
            
        }
    }
    End {
        #Write-Host $Output
        Write-LogEntry ("{0}" -f $Output) -Severity 1 -Source ${CmdletName} -Outhost
    }
}
##*===========================================================================
##* VARIABLES
##*===========================================================================
## Instead fo using $PSScriptRoot variable, use the custom InvocationInfo for ISE runs
If (Test-Path -LiteralPath 'variable:HostInvocation') { $InvocationInfo = $HostInvocation } Else { $InvocationInfo = $MyInvocation }
[string]$scriptDirectory = Split-Path $MyInvocation.MyCommand.Path -Parent
[string]$scriptName = Split-Path $MyInvocation.MyCommand.Path -Leaf
[string]$scriptBaseName = [System.IO.Path]::GetFileNameWithoutExtension($scriptName)
[int]$OSBuildNumber = (Get-WmiObject -Class Win32_OperatingSystem).BuildNumber

#Create Paths
$ToolsPath = Join-Path $scriptDirectory -ChildPath 'Tools'
$AdditionalScriptsPath = Join-Path $scriptDirectory -ChildPath 'Scripts'
$ModulesPath = Join-Path -Path $scriptDirectory -ChildPath 'PSModules'
$BinPath = Join-Path -Path $scriptDirectory -ChildPath 'Bin'
$FilesPath = Join-Path -Path $scriptDirectory -ChildPath 'Files'

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

$Global:Verbose = $false
If($PSBoundParameters.ContainsKey('Debug') -or $PSBoundParameters.ContainsKey('Verbose')){
    $Global:Verbose = $PsBoundParameters.Get_Item('Verbose')
    $VerbosePreference = 'Continue'
    Write-Verbose ("[{0}] [{1}] :: VERBOSE IS ENABLED." -f (Format-DatePrefix),$scriptName)
}
Else{
    $VerbosePreference = 'SilentlyContinue'
}

Try
{
	$tsenv = New-Object -COMObject Microsoft.SMS.TSEnvironment
    $Progress = New-Object -ComObject Microsoft.SMS.TSprogressUI
	#$logPath = $tsenv.Value("LogPath")
    $LogPath = $tsenv.Value("_SMSTSLogPath")
}
Catch
{
	Write-Warning "TS environment not detected. Assuming stand-alone mode."
}

If(!$LogPath){$LogPath = $env:TEMP}
[string]$FileName = $scriptBaseName +'.log'
$Global:LogFilePath = Join-Path $LogPath -ChildPath $FileName
Write-Host "Using log file: $LogFilePath"

# DEFAULTS: Configurations are hardcoded here (change values if needed)
[boolean]$DisableScript =  $false
[boolean]$Global:LGPOForConfigs = $true
[string]$Global:LGPOPath = "$ToolsPath\LGPO\LGPO.exe"
[ValidateSet('Custom','High Performance','Balanced')]$SetPowerCFG = 'Custom'
[string]$PowerCFGFilePath = "$FilesPath\AlwaysOnPowerScheme.pow"
[boolean]$EnablePSLogging = $false
[boolean]$EnableSystemVerboseMsg = $false
[boolean]$ApplySTIGItems = $false
[boolean]$EnableFIPS = $false
[boolean]$DisableAutoRun = $false
[boolean]$CleanSampleFolders = $false
[boolean]$DisableCortana = $false
[boolean]$DisableInternetSearch = $false 
[boolean]$OptimizeForVDI = $false 
[boolean]$EnableOfficeOneNote = $false
[boolean]$EnableRDP = $false
[boolean]$DisableOneDrive = $false
[boolean]$PreferIPv4OverIPv6 = $false
[boolean]$RemoveActiveSetupComponents = $false
[boolean]$DisableWindowsFirstLoginAnimation = $false
[boolean]$DisableIEFirstRunWizard = $false
[boolean]$DisableWMPFirstRunWizard = $false
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
[psobject]$InstallModulesPath = Get-ChildItem $ModulesPath -Filter *.psm1 -Recurse
[boolean]$EnableVisualPerformance = $false
[boolean]$EnableDarkTheme = $false
[boolean]$EnableNumlockStartup = $false
[boolean]$ShowKnownExtensions = $false
[boolean]$ShowHiddenFiles = $false
[boolean]$ShowThisPCOnDesktop = $false
[boolean]$ShowUserFolderOnDesktop = $false
[boolean]$Hide3DObjectsFromExplorer = $false
[boolean]$DisableEdgeShortcutCreation = $false
[ValidateSet('Off','User','Admin')]
[string]$SetSmartScreenFilter = 'Admin'
[boolean]$EnableStrictUAC = $false
[boolean]$ApplyCustomHost = $false
[string]$HostPath = "$FilesPath\WindowsTelemetryhosts"
[string[]]$UnpinTaskbarApps = "Microsoft Edge","Microsoft Store"
[boolean]$DisableStoreOnTaskbar = $false
[boolean]$DisableActionCenter = $false
[boolean]$DisableFeedback = $false
[boolean]$DisableWindowsUpgrades = $false
[boolean]$ApplyEMETMitigations = $false

# When running in Tasksequence and configureation exists, use that instead
If($tsenv){
    # Configurations comes from Tasksequence
    If($tsenv:CFG_DisableScript){[boolean]$DisableScript = [boolean]::Parse($tsenv.Value("CFG_DisableScript"))}
    If($tsenv:CFG_UseLGPOForConfigs){[boolean]$Global:LGPOForConfigs = [boolean]::Parse($tsenv.Value("CFG_UseLGPOForConfigs"))}
    If($tsenv:LGPOPath){[string]$Global:LGPOPath = $tsenv.Value("LGPOPath")}
    If($tsenv:CFG_SetPowerCFG){[string]$SetPowerCFG = $tsenv.Value("CFG_SetPowerCFG")}
    If($tsenv:CFG_PowerCFGFilePath){[string]$PowerCFGFilePath = $tsenv.Value("CFG_PowerCFGFilePath")}
    If($tsenv:CFG_EnablePSLoggingg){[boolean]$EnablePSLogging = [boolean]::Parse($tsenv.Value("CFG_EnablePSLogging"))}
    If($tsenv:CFG_EnableVerboseMsg){[boolean]$EnableVerboseMsg = [boolean]::Parse($tsenv.Value("CFG_EnableVerboseMsg"))}
    If($tsenv:CFG_ApplySTIGItems){[boolean]$ApplySTIGItems = [boolean]::Parse($tsenv.Value("CFG_ApplySTIGItems"))}
    If($tsenv:CFG_EnableFIPS){[boolean]$EnableFIPS = [boolean]::Parse($tsenv.Value("CFG_EnableFIPS"))}
    If($tsenv:CFG_DisableAutoRun){[boolean]$DisableAutoRun = [boolean]::Parse($tsenv.Value("CFG_DisableAutorun"))}
    If($tsenv:CFG_CleanSampleFolders){[boolean]$CleanSampleFolders = [boolean]::Parse($tsenv.Value("CFG_CleanSampleFolders"))}
    If($tsenv:CFG_DisableCortana){[boolean]$DisableCortana = [boolean]::Parse($tsenv.Value("CFG_DisableCortana"))}
    If($tsenv:CFG_DisableInternetSearch){[boolean]$DisableInternetSearch = [boolean]::Parse($tsenv.Value("CFG_DisableInternetSearch"))} 
    If($tsenv:CFG_OptimizeForVDI){[boolean]$OptimizeForVDI = [boolean]::Parse($tsenv.Value("CFG_OptimizeForVDI"))} 
    If($tsenv:CFG_EnableOfficeOneNote){[boolean]$EnableOfficeOneNote = [boolean]::Parse($tsenv.Value("CFG_EnableOfficeOneNote"))}
    If($tsenv:CFG_EnableRDP){[boolean]$EnableRDP = [boolean]::Parse($tsenv.Value("CFG_EnableRDP"))}
    If($tsenv:CFG_DisableOneDrive){[boolean]$DisableOneDrive = [boolean]::Parse($tsenv.Value("CFG_DisableOneDrive"))}
    If($tsenv:CFG_PreferIPv4OverIPv6){[boolean]$PreferIPv4OverIPv6 = [boolean]::Parse($tsenv.Value("CFG_PreferIPv4OverIPv6"))}
    If($tsenv:CFG_RemoveActiveSetupComponents){[boolean]$RemoveActiveSetupComponents = [boolean]::Parse($tsenv.Value("CFG_RemoveActiveSetupComponents"))}
    If($tsenv:CFG_DisableWindowsFirstLoginAnimation){[boolean]$DisableWindowsFirstLoginAnimation = [boolean]::Parse($tsenv.Value("CFG_DisableWindowsFirstLoginAnimation"))}
    If($tsenv:CFG_DisableIEFirstRunWizard){[boolean]$DisableIEFirstRunWizard = [boolean]::Parse($tsenv.Value("CFG_DisableIEFirstRunWizard"))}
    If($tsenv:CFG_DisableWMPFirstRunWizard){[boolean]$DisableWMPFirstRunWizard = [boolean]::Parse($tsenv.Value("CFG_DisableWMPFirstRunWizard"))}
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
    If($tsenv:CFG_ApplyPrivacyMitigations){[boolean]$ApplyPrivacyMitigations = [boolean]::Parse($tsenv.Value("CFG_ApplyPrivacyMitigations"))}
    If($tsenv:CFG_EnableCredGuard){[boolean]$EnableCredGuard = [boolean]::Parse($tsenv.Value("CFG_EnableCredGuard"))}
    If($tsenv:CFG_InstallLogonScript){[boolean]$InstallLogonScript = [boolean]::Parse($tsenv.Value("CFG_InstallLogonScript"))}
    If($tsenv:CFG_LogonScriptPath){[string]$LogonScriptPath = $tsenv.Value("CFG_LogonScriptPath")}
    If($tsenv:CFG_EnableWinRM){[boolean]$EnableWinRM = [boolean]::Parse($tsenv.Value("CFG_EnableWinRM"))}
    If($tsenv:CFG_EnableAppsRunAsAdmin){[boolean]$EnableAppsRunAsAdmin = [boolean]::Parse($tsenv.Value("CFG_EnableAppsRunAsAdmin"))}
    If($tsenv:CFG_DisableUAC){[boolean]$DisableUAC = [boolean]::Parse($tsenv.Value("CFG_DisableUAC"))}
    If($tsenv:CFG_EnableStrictUAC){[boolean]$EnableStrictUAC = [boolean]::Parse($tsenv.Value("CFG_EnableStrictUAC"))}
    If($tsenv:CFG_DisableWUP2P){[boolean]$DisableWUP2P = [boolean]::Parse($tsenv.Value("CFG_DisableWUP2P"))}
    If($tsenv:CFG_EnableIEEnterpriseMode){[boolean]$EnableIEEnterpriseMode = [boolean]::Parse($tsenv.Value("CFG_EnableIEEnterpriseMode"))}
    If($tsenv:CFG_IEEMSiteListPath){[string]$IEEMSiteListPath = $tsenv.Value("CFG_IEEMSiteListPath")}
    If($tsenv:CFG_PreCompileAssemblies){[boolean]$PreCompileAssemblies = [boolean]::Parse($tsenv.Value("CFG_PreCompileAssemblies"))}
    If($tsenv:CFG_DisableIndexing){[boolean]$DisableIndexing = [boolean]::Parse($tsenv.Value("CFG_DisableIndexing"))}
    If($tsenv:CFG_EnableSecureLogon){[boolean]$EnableSecureLogonCtrlAltDelete = [boolean]::Parse($tsenv.Value("CFG_EnableSecureLogon"))}
    If($tsenv:CFG_HideDrives){[boolean]$HideDrivesWithNoMedia = [boolean]::Parse($tsenv.Value("CFG_HideDrives"))}
    If($tsenv:CFG_DisableAllNotifications){[boolean]$DisableAllNotifications = [boolean]::Parse($tsenv.Value("CFG_DisableAllNotifications"))}
    If($tsenv:CFG_InstallPSModules){[boolean]$InstallPSModules = [boolean]::Parse($tsenv.Value("CFG_InstallPSModules"))}
    If($tsenv:CFG_EnableVisualPerformance){[boolean]$EnableVisualPerformance = [boolean]::Parse($tsenv.Value("CFG_EnableVisualPerformance"))}
    If($tsenv:CFG_EnableDarkTheme){[boolean]$EnableDarkTheme = [boolean]::Parse($tsenv.Value("CFG_EnableDarkTheme"))}
    If($tsenv:CFG_EnableNumlockStartup){[boolean]$EnableNumlockStartup = [boolean]::Parse($tsenv.Value("CFG_EnableNumlockStartup"))}
    If($tsenv:CFG_ShowKnownExtensions){[boolean]$ShowKnownExtensions = [boolean]::Parse($tsenv.Value("CFG_ShowKnownExtensions"))}
    If($tsenv:CFG_ShowHiddenFiles){[boolean]$ShowHiddenFiles = [boolean]::Parse($tsenv.Value("CFG_ShowHiddenFiles"))}
    If($tsenv:CFG_ShowThisPCOnDesktop){[boolean]$ShowThisPCOnDesktop = [boolean]::Parse($tsenv.Value("CFG_ShowThisPCOnDesktop"))}
    If($tsenv:CFG_ShowUserFolderOnDesktop){[boolean]$ShowUserFolderOnDesktop = [boolean]::Parse($tsenv.Value("CFG_ShowUserFolderOnDesktop"))}
    If($tsenv:CFG_Hide3DObjectsFromExplorer){[boolean]$Hide3DObjectsFromExplorer = [boolean]::Parse($tsenv.Value("CFG_Hide3DObjectsFromExplorer"))}
    If($tsenv:CFG_DisableEdgeShortcut){[boolean]$DisableEdgeShortcutCreation = [boolean]::Parse($tsenv.Value("CFG_DisableEdgeShortcut"))}
    If($tsenv:CFG_UnpinTaskbarApps){[string[]]$UnpinTaskbarApps = $tsenv.Value("CFG_UnpinTaskbarApps")}
    If($tsenv:CFG_SetSmartScreenFilter){[string]$SetSmartScreenFilter = $tsenv.Value("CFG_SetSmartScreenFilter")}
    If($tsenv:CFG_ApplyCustomHost){[boolean]$ApplyCustomHost = [boolean]::Parse($tsenv.Value("CFG_ApplyCustomHost"))}
    If($tsenv:HostPath){[string]$HostPath = $tsenv.Value("HostPath")}
    If($tsenv:CFG_DisableStoreOnTaskbar){[boolean]$DisableStoreOnTaskbar = [boolean]::Parse($tsenv.Value("CFG_DisableStoreOnTaskbar"))}
    If($tsenv:CFG_DisableActionCenter){[boolean]$DisableActionCenter = [boolean]::Parse($tsenv.Value("CFG_DisableActionCenter"))}
    If($tsenv:CFG_DisableFeedback){[boolean]$DisableFeedback = [boolean]::Parse($tsenv.Value("CFG_DisableFeedback"))}
    If($tsenv:CFG_DisableWindowsUpgrades){[boolean]$DisableWindowsUpgrades = [boolean]::Parse($tsenv.Value("CFG_DisableWindowsUpgrades"))}
    If($tsenv:CFG_ApplyEMETMitigations){[boolean]$ApplyEMETMitigations = [boolean]::Parse($tsenv.Value("CFG_ApplyEMETMitigations"))}
}

# Ultimately disable the entire script. This is useful for testing and using one task sequences with many rules
If($DisableScript){
    Write-LogEntry "Script is disabled!" -Severity 1 -Outhost
    Exit 0
}

#$VerbosePreference = 'SilentlyContinue'
$VerbosePreference = 'Continue'

#check if LGPO file exists in Tools directory or Specified LGPOPath
$FindLGPO = Get-ChildItem $Global:LGPOPath -Filter LGPO.exe -ErrorAction SilentlyContinue
If($FindLGPO){
    $Global:LGPOPath = $FindLGPO.FullName
}
Else{
    $Global:LGPOForConfigs = $false
}

# Get Onenote paths
$OneNotePathx86 = Get-ChildItem "${env:ProgramFiles(x86)}" -Recurse -Filter "ONENOTE.EXE"
$OneNotePathx64 = Get-ChildItem "$env:ProgramFiles" -Recurse -Filter "ONENOTE.EXE"
If($OneNotePathx86){$OneNotePath = $OneNotePathx86}
If($OneNotePathx64){$OneNotePath = $OneNotePathx64}

##*===========================================================================
##* MAIN
##*===========================================================================
If ($InstallPSModules)
{
    #Install Nuget prereq
    $NuGetAssemblySourcePath = Get-ChildItem "$BinPath\nuget" -Recurse -Filter *.dll
    If($NuGetAssemblySourcePath){
        $NuGetAssemblyVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($NuGetAssemblySourcePath.FullName).FileVersion
        $NuGetAssemblyDestPath = "$env:ProgramFiles\PackageManagement\ProviderAssemblies\nuget\$NuGetAssemblyVersion"
        If (!(Test-Path $NuGetAssemblyDestPath)){
            Write-LogEntry ("Copying nuget Assembly [{0}] to [{1}]..." -f $NuGetAssemblyVersion,$NuGetAssemblyDestPath) -Outhost
            New-Item $NuGetAssemblyDestPath -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
            Copy-Item -Path $NuGetAssemblySourcePath.FullName -Destination $NuGetAssemblyDestPath -Force -ErrorAction SilentlyContinue | Out-Null
        }
    }


    If($InstallModulesPath.count -gt 0){
        $i = 1
        Write-LogEntry "Installing PowerShell Modules..." -Severity 1 -Outhost
        Foreach($module in $InstallModulesPath){
           Import-Module -name $module.FullName -Global -NoClobber -Force | Out-Null
           Write-Progress -Activity "Installing PowerShell Module..." -Status $module.FullName -PercentComplete ($i / $InstallModulesPath.count * 100)
           $i++
        }
    }

}


If($DisableActionCenter -or $OptimizeForVDI){
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:45] :: "}
    Write-LogEntry ("{0}Disabling Windows Action Center Notifications..." -f $prefixmsg) -Severity 1 -Outhost
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" -Name "UseActionCenterExperience" -Type DWord -Value 0 -Force | Out-Null
}


If($DisableFeedback -or $OptimizeForVDI){
    # Loop through each profile on the machine
    Foreach ($UserProfile in $UserProfiles) {
        If($UserProfile.SID -ne ".DEFAULT"){
            $objSID = New-Object System.Security.Principal.SecurityIdentifier($UserProfile.SID)
            $UserID = $objSID.Translate([System.Security.Principal.NTAccount])
        }
        Else{
            $UserID = $UserProfile.SID
        }

        # Load User ntuser.dat if it's not already loaded
        If (($ProfileWasLoaded = Test-Path Registry::HKEY_USERS\$($UserProfile.SID)) -eq $false) {
            Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE LOAD HKU\$($UserProfile.SID) $($UserProfile.UserHive)" -Wait -WindowStyle Hidden
            # Manipulate the registry
            
            If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:7] :: "}
            Write-LogEntry ("{0}Disabling Feedback Notifications for User: {1}..." -f $prefixmsg,$UserID) -Severity 1 -Outhost
            $settingspath = "HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Siuf\Rules"
            Set-ItemProperty -Path $settingspath -Name NumberOfSIUFInPeriod -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
            Set-ItemProperty -Path $settingspath -Name PeriodInNanoSeconds -Type DWord -Value 0 -Force -ErrorAction SilentlyContinue | Out-Null
        }

        # Unload NTuser.dat        
        If ($ProfileWasLoaded -eq $false) {
            [gc]::Collect()
            Start-Sleep 1
            Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE UNLOAD HKU\$($UserProfile.SID)" -Wait -PassThru  -WindowStyle Hidden | Out-Null
        }
    }

}


If($DisableWindowsUpgrades){
    Write-LogEntry "Disabling Windows Upgrades from Windows Updates..." -Severity 1 -Outhost
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Gwx" -Name "DisableGwx" -Type DWord -Value 1 -Force | Out-Null
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DisableOSUpgrade" -Type DWord -Value 1 -Force | Out-Null
}


If($DisableStoreOnTaskbar -or $OptimizeForVDI){
    Write-LogEntry "Disabling Pinning of Microsoft Store app on the taskbar..." -Severity 1 -Outhost
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoPinningStoreToTaskbar" -Type DWord -Value 1 -Force | Out-Null

    If($OptimizeForVDI){
        Write-LogEntry "VDI Optimizations [OSOT ID:68] :: Disabling Pinning of Microsoft Store app on the taskbar..." -Severity 1 -Outhost
        Set-SystemSettings -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "RemoveWindowsStore" -Type DWord -Value 1 -Force | Out-Null
    }
}


If ($EnableOfficeOneNote -and $OneNotePath)
{
	# Mount HKCR drive
	Write-LogEntry "Setting OneNote file association to the desktop app..." -Severity 1 -Outhost
	New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
	New-Item -Path 'Registry::HKCR\onenote-cmd\Shell\Open' -Name 'Command' -Force | Out-Null
    New-ItemProperty -Path "Registry::HKCR\onenote-cmd\Shell\Open\Command" -Name "@" -Type String -Value $OneNotePath.FullName -Force | Out-Null
	Remove-PSDrive -Name "HKCR" | Out-Null
}


If($ApplySTIGItems -or $EnablePSLogging)
{
    Write-LogEntry "Enabling Powershell Script Block Logging..." -Severity 1 -Outhost
    If($ApplySTIGItems){Write-LogEntry "STIG Rule ID: SV-83411r1_rule" -Severity 1 -Outhost}
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Type DWord -Value 1 -Force | Out-Null

    Write-LogEntry "Enabling Powershell Transcription Logging..." -Severity 1 -Outhost
    #New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell" -name Transcription -Force | Out-Null
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Type DWord -Value 1 -Force | Out-Null
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableInvocationHeader" -Type DWord -Value 1 -Force | Out-Null
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "OutputDirectory" -Value "" -Force | Out-Null

    Write-LogEntry "Enabling Powershell Module Logging Logging..." -Severity 1 -Outhost
    #New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell" -name ModuleLogging -Force | Out-Null
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Type DWord -Value 1 -Force | Out-Null
    #Set-SystemSettings -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "ModuleNames" -Value "" -Force | Out-Null
}


If ($EnableSystemVerboseMsg)
{
    #https://support.microsoft.com/en-us/help/325376/how-to-enable-verbose-startup-shutdown-logon-and-logoff-status-message
    Write-LogEntry "Setting Windows Startup to Verbose messages..." -Severity 1 -Outhost
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -Type DWord -Value 1 -Force | Out-Null
    If(Test-Path ('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\SYSTEM\DisableStatusMessages') ){
        Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name 'DisableStatusMessages' -Force | Out-Null
    }
}


If (($ApplyCustomHost) -and (Test-Path $HostPath) )
{
    $HostFile = Split-Path $HostPath -Leaf
    Write-LogEntry ("Copying custom hosts file [{0}] to windows..." -f $HostFile) -Severity 1 -Outhost
    Copy-Item $HostPath -Destination "$env:Windir\System32\Drivers\etc\hosts" -Force | Out-Null
}


If ($SetPowerCFG -eq 'Balanced')
{
    #Set Balanced to Default
    Write-LogEntry ("Setting Power configurations to [{0}]..."  -f $SetPowerCFG) -Severity 1 -Outhost
    Set-PowerPlan -PreferredPlan $SetPowerCFG
}


If ( ($SetPowerCFG -eq 'High Performance') -or $OptimizeForVDI)
{
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:60 & 61] :: "}
    Write-LogEntry ("{0}Setting Power configurations to [{0}]..."  -f $prefixmsg,$SetPowerCFG) -Severity 1 -Outhost
    If($OptimizeForVDI){
        Set-PowerPlan -PreferredPlan $SetPowerCFG -ACTimeout 0 -DCTimeout 0 -ACMonitorTimeout 0 -DCMonitorTimeout 0 -Hibernate Off
    }
    Else{
        Set-PowerPlan -PreferredPlan $SetPowerCFG
    }
    
    Write-LogEntry "Disabling Fast Startup..." -Severity 1 -Outhost
	Set-SystemSettings -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0 -Force | Out-Null

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:54] :: "}
    Write-LogEntry ("{0}Removing turn off hard disk after..."  -f $prefixmsg) -Severity 1 -Outhost
    Set-SystemSettings -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\0012ee47-9041-4b5d-9b77-535fba8b1442\6738e2c4-e8a5-4a42-b16a-e040e769756e" -Name "Attributes" -Type DWord -Value 1 -Force | Out-Null
}

If (($SetPowerCFG -eq 'Custom') -and (Test-Path $PowerCFGFilePath) -and !$OptimizeForVDI)
{
    $AOPGUID = '50b056f5-0cf6-42f1-9351-82a490d70ef4'
    $PowFile = Split-Path $PowerCFGFilePath -Leaf
    Write-LogEntry ("Setting Power configurations to [{0}] using file [{1}]" -f $SetPowerCFG,"$env:TEMP\$PowFile") -Severity 1 -Outhost
    Copy-Item $PowerCFGFilePath -Destination "$env:Windir\Temp\$PowFile" -Force | Out-Null
    Start-Process "C:\Windows\system32\powercfg.exe" -ArgumentList "-IMPORT `"$env:Windir\Temp\$PowFile`" $AOPGUID" -Wait -NoNewWindow
    Start-Process "C:\Windows\system32\powercfg.exe" -ArgumentList "-SETACTIVE $AOPGUID" -Wait -NoNewWindow
    Start-Process "C:\Windows\system32\powercfg.exe" -ArgumentList "-H OFF" -Wait -NoNewWindow
}


If($HideDrivesWithNoMedia)
{
    Write-LogEntry "Hiding Drives With NoMedia..." -Severity 1 -Outhost
	Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideDrivesWithNoMedia' -Type DWord -Value '1' -Force | Out-Null
}


If ($ApplySTIGItems -or $DisableAutoRun)
{
    Write-LogEntry "Disabling Autorun for local machine..." -Severity 1 -Outhost
    
    If($ApplySTIGItems){Write-LogEntry "STIG Rule ID: SV-78039r1_rule" -Severity 1 -Outhost}
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name NoAutoplayfornonVolume -Value 1 -Force | Out-Null

    If($ApplySTIGItems){Write-LogEntry "STIG Rule ID: SV-78161r1_rule" -Severity 1 -Outhost}
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name NoAutorun -Value 1 -Force | Out-Null

    If($ApplySTIGItems){Write-LogEntry "STIG Rule ID: SV-78163r1_rule" -Severity 1 -Outhost}
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name NoDriveTypeAutoRun -Type DWord -Value 0xFF -Force | Out-Null

    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name HonorAutorunSetting -Type DWord -Value 1 -Force | Out-Null
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveAutoRun -Type DWord -Value 67108863 -Force | Out-Null
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoDriveTypeAutorun -Type DWord -Value 0xFF -Force | Out-Null

    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping\Autorun.inf' -Name '(Default)' -Value "@SYS:DoesNotExist" -Force -ErrorAction SilentlyContinue | Out-Null
    Set-SystemSettings -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Cdrom' -Name AutoRun -Type DWord -Value 0 -Force | Out-Null

    Write-LogEntry "Disabling Autorun for default users..." -Severity 1 -Outhost
    Set-ItemProperty -Path "Registry::HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name HonorAutorunSetting -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path "Registry::HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoDriveAutoRun -Type DWord -Value 67108863 -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path "Registry::HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoDriveTypeAutorun -Type DWord -Value 0xFF -Force -ErrorAction SilentlyContinue | Out-Null

    Write-LogEntry ("Disabling Autorun for Current user: {0}..." -f $env:USERNAME) -Severity 1 -Outhost
    Set-SystemSettings -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name HonorAutorunSetting -Type DWord -Value 1 -Force | Out-Null
    Set-SystemSettings -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoDriveAutoRun -Type DWord -Value 67108863 -Force | Out-Null
    Set-SystemSettings -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoDriveTypeAutorun -Type DWord -Value 0xFF -Force | Out-Null

    #windows 10 only
    Set-SystemSettings -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name DisableAutoPlay -Type DWord -Value 1 -Force | Out-Null

    # Loop through each profile on the machine
    Foreach ($UserProfile in $UserProfiles) {
        If($UserProfile.SID -ne ".DEFAULT"){
            $objSID = New-Object System.Security.Principal.SecurityIdentifier($UserProfile.SID)
            $UserID = $objSID.Translate([System.Security.Principal.NTAccount])
        }
        Else{
            $UserID = $UserProfile.SID
        }

        # Load User ntuser.dat if it's not already loaded
        If (($ProfileWasLoaded = Test-Path Registry::HKEY_USERS\$($UserProfile.SID)) -eq $false) {
            Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE LOAD HKU\$($UserProfile.SID) $($UserProfile.UserHive)" -Wait -WindowStyle Hidden
            # Manipulate the registry
            $settingspath = "HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
            
            If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:6] :: "}
            Write-LogEntry ("{0}Disabling Autorun for User: {1}..." -f $prefixmsg,$UserID) -Outhost
            #New-Item -Path $settingspath -ErrorAction SilentlyContinue | Out-Null
            Set-ItemProperty -Path $settingspath -Name HonorAutorunSetting -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
            Set-ItemProperty -Path $settingspath -Name NoDriveAutoRun -Type DWord -Value 67108863 -Force -ErrorAction SilentlyContinue | Out-Null
            Set-ItemProperty -Path $settingspath -Name NoDriveTypeAutorun -Type DWord -Value 0xFF -Force -ErrorAction SilentlyContinue | Out-Null

            $settingspath = "Registry::HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers"
            Set-ItemProperty -Path $settingspath -Name DisableAutoPlay -Type DWord -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null
        }

        # Unload NTuser.dat        
        If ($ProfileWasLoaded -eq $false) {
            [gc]::Collect()
            Start-Sleep 1
            Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE UNLOAD HKU\$($UserProfile.SID)" -Wait -PassThru  -WindowStyle Hidden | Out-Null
        }
    }
}


If( ($ApplySTIGItems -and $EnableFIPS) -or $EnableFIPS){
    If($ApplySTIGItems){Write-LogEntry "STIG Rule ID: SV-78301r1_rule" -Severity 1 -Outhost}
    Write-LogEntry "Enabling FIPS Algorithm Policy" -Severity 1 -Outhost
    Set-SystemSettings -Path "HKLM\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy" -Name "Enabled" -Type DWord -Value 1 -Force | Out-Null
}


If ($EnableRDP)
{
	Write-LogEntry "Enabling RDP..." -Severity 1 -Outhost
	Set-SystemSettings -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Type DWord -Value 0 -Force | Out-Null
	Set-SystemSettings -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Type DWord -Value 1 -Force | Out-Null
	Set-NetFirewallRule -DisplayGroup "Remote Desktop" -Enabled True -Action Allow -Profile Any
}


If ($DisableOneDrive)
{
	Write-LogEntry "Turning off OneDrive..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'DisableFileSync' -Type DWord -Value '1' -Force | Out-Null
	
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:50] :: "}
    Write-LogEntry ("{0}Disabling synchronizing files to onedrive..." -f $prefixmsg) -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'DisableFileSyncNGSC' -Type DWord -Value '1' -Force | Out-Null


	Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'PreventNetworkTrafficPreUserSignIn' -Type DWord -Value '1' -Force | Out-Null
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Skydrive' -Name 'DisableLibrariesDefaultSaveToSkyDrive' -Type DWORD -Value '1' -Force | Out-Null 
    
    Set-SystemSettings -Path 'HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder' -Name Attributes -Type DWord -Value 0 -ErrorAction SilentlyContinue -Force | Out-Null

    If($ApplySTIGItems){Write-LogEntry "STIG Rule ID: SV-96851r1_rule :: Disabling personal accounts for OneDrive synchronization..." -Severity 1 -Outhost
        Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'DisablePersonalSync' -Type DWord -Value '1' -Force | Out-Null
    }

    # Load User ntuser.dat if it's not already loaded
    If (($ProfileWasLoaded = Test-Path Registry::HKEY_USERS\$($UserProfile.SID)) -eq $false) {
        Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE LOAD HKU\$($UserProfile.SID) $($UserProfile.UserHive)" -Wait -WindowStyle Hidden

        Write-LogEntry ("Removing Onedrive from starting on logon for SID: {0}..." -f $UserProfile.SID) -Outhost
        Remove-Itemproperty -Path "HKEY_USERS\$($UserProfile.SID)\Software\Microsoft\Windows\CurrentVersion\Run" -Name 'OneDriveSetup' -ErrorAction SilentlyContinue | Out-Null
    }

    # Unload NTuser.dat        
    If ($ProfileWasLoaded -eq $false) {
        [gc]::Collect()
        Start-Sleep 1
        Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE UNLOAD HKU\$($UserProfile.SID)" -Wait -PassThru  -WindowStyle Hidden | Out-Null
    }
}
Else{
    #Write-LogEntry "STIG Rule ID: SV-98853r1_rule :: Allowing OneDrive synchronizing of accounts for DoD organization..." -Severity 1 -Outhost
    #Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive\AllowTenantList' -Name '{ORG GUID}' -Type String -Value '{ORG GUID}' -Force | Out-Null
}


If ($PreferIPv4OverIPv6)
{
    Write-LogEntry "Modifying IPv6 bindings to prefer IPv4 over IPv6..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'DisabledComponents' -Type DWord -Value '32' -Force | Out-Null
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
    
    # Loop through each profile on the machine
    Foreach ($UserProfile in $UserProfiles) {
        If($UserProfile.SID -ne ".DEFAULT"){
            $objSID = New-Object System.Security.Principal.SecurityIdentifier($UserProfile.SID)
            $UserID = $objSID.Translate([System.Security.Principal.NTAccount])
        }
        Else{
            $UserID = $UserProfile.SID
        }

        # Load User ntuser.dat if it's not already loaded
        If (($ProfileWasLoaded = Test-Path Registry::HKEY_USERS\$($UserProfile.SID)) -eq $false) {
            Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE LOAD HKU\$($UserProfile.SID) $($UserProfile.UserHive)" -Wait -WindowStyle Hidden
            # Manipulate the registry
            $settingspath = "HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings"
            Foreach ($key in $notifications.GetEnumerator()){
                Write-LogEntry ("Removing Notification messages for User: {0}..." -f $UserID) -Outhost
                #New-Item -Path ($settingspath + "\" + $key.Value) -ErrorAction SilentlyContinue | Out-Null
                Set-SystemSettings -Path ($settingspath + "\" + $key.Value) -Name Enabled -Value 0 -Type DWord -ErrorAction SilentlyContinue | Out-Null

                If($ApplySTIGItems){
                    Write-LogEntry ("STIG Rule ID: SV-78329r1_rule :: Disabling Toast notifications to the lock screen for user: {0}" -f $UserProfile.SID) -Severity 1 -Outhost
                    Set-SystemSettings -Path "HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name NoToastApplicationNotificationOnLockScreen -Type DWord -Value '1' -Force | Out-Null
                }

            }
        }

        # Unload NTuser.dat        
        If ($ProfileWasLoaded -eq $false) {
            [gc]::Collect()
            Start-Sleep 1
            Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE UNLOAD HKU\$($UserProfile.SID)" -Wait -PassThru  -WindowStyle Hidden | Out-Null
        }
    }

    Write-LogEntry "Disabling Non-critical Notifications from Windows Security..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications' -Name DisableEnhancedNotifications -Type DWord -Value '1' -Force | Out-Null

    Write-LogEntry "Disabling All Notifications from Windows Security using..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications' -Name DisableNotifications -Type DWord -Value '1' -Force | Out-Null
}


If ($DisabledIEFirstRunWizard -or $OptimizeForVDI)
{
	# Disable IE First Run Wizard
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:40] :: "}
    Write-LogEntry ("{0}Disabling IE First Run Wizard..." -f $prefixmsg) -Outhost
	Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main' -Name DisableFirstRunCustomize -Type DWord -Value '1' -Force | Out-Null
}


If ($DisableWMPFirstRunWizard)
{
	# Disable IE First Run Wizard
	Write-LogEntry "Disabling Media Player First Run Wizard..." -Severity 1 -Outhost
	Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\MediaPlayer\Preferences' -Name AcceptedEULA -Type DWord -Value '1' -Force | Out-Null
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\MediaPlayer\Preferences' -Name FirstTime -Type DWord -Value '1' -Force | Out-Null
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer' -Name GroupPrivacyAcceptance -Type DWord -Value '1' -Force | Out-Null
}


If($EnableSecureLogonCtrlAltDelete)
{
  	# Disable IE First Run Wizard
	Write-LogEntry "Enabling Secure Logon Screen Settings..." -Severity 1 -Outhost
	Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DisableCAD -Type DWord -Value '0' -Force | Out-Null
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name DontDisplayLastUserName -Type DWord -Value '1' -Force | Out-Null
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name BlockDomainPicturePassword -Type DWord -Value '1' -Force | Out-Null
}


# Disable New Network dialog box
If ($DisableNewNetworkDialog)
{
	Write-LogEntry "Disabling New Network Dialog..." -Severity 1 -Outhost
    Set-SystemSettings 'HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet' -Name 'EnableActiveProbing' -Type DWord -Value '0' -Force | Out-Null
}


If($RemoveActiveSetupComponents -or $OptimizeForVDI){

    #https://kb.vmware.com/s/article/2100337?lang=en_US#q=Improving%20log%20in%20time
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:205-212] :: "}	
    Write-LogEntry ("{0}Disabling Active Setup components to speed up login time" -f $prefixmsg) -Severity 1 -Outhost
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


If ($DisabledUnusedFeatures)
{
    Write-LogEntry "Disabling Internet Printing" -Severity 3 -Outhost
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
    
    Write-LogEntry "Removing Default Fax Printer..." -Severity 1 -Outhost
    Remove-Printer -Name "Fax" -ErrorAction SilentlyContinue

    If($OptimizeForVDI){
        Write-LogEntry "VDI Optimizations [OSOT ID:67] :: Disabling Windows Media Player" -Severity 1 -Outhost
        Try{
            Disable-WindowsOptionalFeature -FeatureName WindowsMediaPlayer -Online -NoRestart -ErrorAction Stop | Out-Null
        }
        Catch [System.Management.Automation.ActionPreferenceStopException]{
            Write-LogEntry ("Unable to Windows Media Player: {0}" -f $_) -Severity 3 -Outhost
        }

        Write-LogEntry "VDI Optimizations [OSOT ID:69] :: Disabling WCF-Services 45" -Severity 1 -Outhost
        Try{
            Disable-WindowsOptionalFeature -FeatureName WCF-Services45 -Online -NoRestart -ErrorAction Stop | Out-Null
        }
        Catch [System.Management.Automation.ActionPreferenceStopException]{
            Write-LogEntry ("Unable to WCF-Services 45: {0}" -f $_) -Severity 3 -Outhost
        }

        Write-LogEntry "VDI Optimizations [OSOT ID:70] :: Disabling Xps-Foundation" -Severity 1 -Outhost
        Try{
            Disable-WindowsOptionalFeature -FeatureName Xps-Foundation-Xps-Viewer -Online -NoRestart -ErrorAction Stop | Out-Null
        }
        Catch [System.Management.Automation.ActionPreferenceStopException]{
            Write-LogEntry ("Unable to Xps-Foundation: {0}" -f $_) -Severity 3 -Outhost
        }
    }

}


If ($DisabledUnusedServices -or $OptimizeForVDI)
{
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:152] :: "}
    Write-LogEntry ("HomeGroup Listener Services" -f $prefixmsg) -Severity 1 -Outhost
    Set-Service HomeGroupListener -StartupType Disabled -ErrorAction SilentlyContinue
    
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:153] :: "}
    Write-LogEntry ("HomeGroup Provider Services" -f $prefixmsg) -Severity 1 -Outhost
    Set-Service HomeGroupProvider -StartupType Disabled -ErrorAction SilentlyContinue

    If($OptimizeForVDI){
        
        Write-LogEntry "VDI Optimizations [OSOT ID:135] :: Disabling AJRouter Router Service..." -Severity 1 -Outhost
        Set-Service AJRouter -StartupType Disabled -ErrorAction SilentlyContinue
        
        Write-LogEntry "VDI Optimizations [OSOT ID:136] :: Disabling Application Layer Gateway Service..." -Severity 1 -Outhost
        Set-Service ALG -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:137] :: Disabling Background Intelligent Transfer Service..." -Severity 1 -Outhost
        Set-Service BITS -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:138] :: Disabling Block Level Backup Engine Service..." -Severity 1 -Outhost
        Set-Service wbengine -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:139] :: Disabling Bluetooth Support Service..." -Severity 1 -Outhost
        Set-Service bthserv -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:140] :: Disabling Bitlocker Drive Encryption Service..." -Severity 1 -Outhost
        Set-Service BDESVC -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:141] :: Disabling Computer Browser Service..." -Severity 1 -Outhost
        Set-Service Browser -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:142] :: Disabling BranchCache Service..." -Severity 1 -Outhost
        Set-Service PeerDistSvc -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:143] :: Disabling Device Association Service..." -Severity 1 -Outhost
        Set-Service DeviceAssociationService -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:144] :: Disabling Device Setup Manager Service..." -Severity 1 -Outhost
        Set-Service DsmSvc -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:145] :: Disabling Diagnostic Policy Service..." -Severity 1 -Outhost
        Set-Service DPS -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:146] :: Disabling Diagnostic Service Host Service..." -Severity 1 -Outhost
        Set-Service WdiServiceHost -StartupType Disabled -ErrorAction SilentlyContinue
        
        Write-LogEntry "VDI Optimizations [OSOT ID:147] :: Disabling Diagnostic System Host Service..." -Severity 1 -Outhost
        Set-Service WdiSystemHost -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:148] :: Disabling Diagnostics Tracking Service..." -Severity 1 -Outhost
        Set-Service DiagTrack -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:149] :: Disabling Fax Service..." -Severity 1 -Outhost
        Set-Service Fax -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:150] :: Disabling Function Discovery Provider Host Service..." -Severity 1 -Outhost
        Set-Service fdPHost -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:151] :: Disabling Function Discovery Resource Publication Service..." -Severity 1 -Outhost
        Set-Service FDResPub -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:154] :: Disabling Hyper-V Data Exchange Service..." -Severity 1 -Outhost
        Set-Service vmickvpexchange -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:155] :: Disabling Hyper-V Guest Service Interface Service..." -Severity 1 -Outhost
        Set-Service vmicguestinterface -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:156] :: Disabling Hyper-V Guest Shutdown Service..." -Severity 1 -Outhost
        Set-Service vmicshutdown -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:157] :: Disabling Hyper-V Heartbeat Service..." -Severity 1 -Outhost
        Set-Service vmicheartbeat -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:158] :: Disabling Hyper-V Remote Desktop Virtualization Service..." -Severity 1 -Outhost
        Set-Service vmicrdv -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:159] :: Disabling Hyper-V Time Synchronization Service..." -Severity 1 -Outhost
        Set-Service vmictimesync -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:160] :: Disabling Hyper-V VM Session Service..." -Severity 1 -Outhost
        Set-Service vmicvmsession -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:161] :: Disabling Hyper-V Volume Shadow Copy Requestor Service..." -Severity 1 -Outhost
        Set-Service vmicvss -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:162] :: Disabling Interactive Services Detection Service..." -Severity 1 -Outhost
        Set-Service UI0Detect -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:163] :: Disabling Internet Connection Sharing (ICS) Service..." -Severity 1 -Outhost
        Set-Service SharedAccess -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:164] :: Disabling IP Helper Service..." -Severity 1 -Outhost
        Set-Service iphlpsvc -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:165] :: Disabling Microsoft iSCSI Initiator Service..." -Severity 1 -Outhost
        Set-Service MSiSCSI -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:166] :: Disabling Microsoft Software Shadow Copy Provider Service..." -Severity 1 -Outhost
        Set-Service swprv -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:167] :: Disabling Disable Offline Files Service..." -Severity 1 -Outhost
        Set-Service CscService -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:168] :: Disabling Drive Optimization Capabilities Service..." -Severity 1 -Outhost
        Set-Service defragsvc -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:169] :: Disabling Program Compatibility Assistant Service..." -Severity 1 -Outhost
        Set-Service PcaSvc -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:170] :: Disabling Quality Windows Audio Video Experience Service..." -Severity 1 -Outhost
        Set-Service QWAVE -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:171] :: Disabling Reports and Solutions Control Panel Support Service..." -Severity 1 -Outhost
        Set-Service wercplsupport -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:172] :: Disabling Retail Demo Service..." -Severity 1 -Outhost
        Set-Service RetailDemo -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:173] :: DisablingSecure Socket Tunneling Protocol Service..." -Severity 1 -Outhost
        Set-Service SstpSvc -StartupType Disabled -ErrorAction SilentlyContinue

        #Write-LogEntry "VDI Optimizations [OSOT ID:174] :: Disabling Security Center Service..." -Severity 1 -Outhost
        #Set-Service wscsvc -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:175] :: Disabling Sensor Data Service..." -Severity 1 -Outhost
        Set-Service SensorDataService -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:176] :: Disabling Sensor Monitoring Service..." -Severity 1 -Outhost
        Set-Service SensrSvc -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:177] :: Disabling Sensor Service..." -Severity 1 -Outhost
        Set-Service SensorService -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:178] :: Disabling Shell Hardware Detection Service..." -Severity 1 -Outhost
        Set-Service ShellHWDetection -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:179] :: Disabling SNMP Trap Service..." -Severity 1 -Outhost
        Set-Service SNMPTRAP -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:180] :: Disabling Spot Verifier Service..." -Severity 1 -Outhost
        Set-Service svsvc -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:181] :: Disabling SSDP Discovery Service..." -Severity 1 -Outhost
        Set-Service SSDPSRV -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:182] :: Disabling Still Image Acquisition Events Service..." -Severity 1 -Outhost
        Set-Service WiaRpc -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:183] :: Disabling Store Storage Service..." -Severity 1 -Outhost
        Set-Service StorSvc -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:184] :: Disabling Superfetch Service..." -Severity 1 -Outhost
        Set-Service SysMain -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:185] :: Disabling Telephony Service..." -Severity 1 -Outhost
        Set-Service TapiSrv -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:186] :: Disabling Themes Service..." -Severity 1 -Outhost
        Set-Service Themes -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:187] :: Disabling Universal PnP Host Service..." -Severity 1 -Outhost
        Set-Service upnphost -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:188] :: Disabling Volume Shadow Copy Service..." -Severity 1 -Outhost
        Set-Service VSS -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:189] :: Disabling Windows Backup Service..." -Severity 1 -Outhost
        Set-Service SDRSVC -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:180] :: Disabling Windows Color System Service..." -Severity 1 -Outhost
        Set-Service WcsPlugInService -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:191] :: Disabling Windows Connect Now – Config Registrar Service..." -Severity 1 -Outhost
        Set-Service wcncsvc -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:192] :: Disabling Windows Error Reporting Service..." -Severity 1 -Outhost
        Set-Service WerSvc -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:193] :: Disabling Windows Media Center Network Sharing Service..." -Severity 1 -Outhost
        Set-Service WMPNetworkSvc -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:194] :: Disabling Windows Mobile Hotspot Service..." -Severity 1 -Outhost
        Set-Service icssvc -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:195] :: Disabling Windows Search Service..." -Severity 1 -Outhost
        Set-Service WSearch -StartupType Disabled -ErrorAction SilentlyContinue

        #Write-LogEntry "VDI Optimizations [OSOT ID:196] :: Disabling Windows Update Service..." -Severity 1 -Outhost
        #Set-Service wuauserv -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:197] :: Disabling WLAN AutoConfig Service..." -Severity 1 -Outhost
        Set-Service Wlansvc -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:198] :: Disabling WWAN AutoConfig Service..." -Severity 1 -Outhost
        Set-Service WwanSvc -StartupType Disabled -ErrorAction SilentlyContinue

        #Write-LogEntry "VDI Optimizations - UnusedServices :: Disabling Network Location Awareness Service..." -Severity 1 -Outhost
        #Set-Service NlaSvc -StartupType Disabled -ErrorAction SilentlyContinue

        #Write-LogEntry "VDI Optimizations - UnusedServices :: Disabling Audio..." -Severity 1 -Outhost
	    #Set-Service Audiosrv -StartupType Disabled
        
        Write-LogEntry "VDI Optimizations [OSOT ID:298] :: Disabling Biometric Service..." -Severity 1 -Outhost
        Set-Service WbioSrvc -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:299] :: Disabling Identity of an Application Service..." -Severity 1 -Outhost
        Set-Service AppIDSvc -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:300] :: Disabling Diagnostics Hub Service..." -Severity 1 -Outhost
        Set-Service diagnosticshub.standardcollector.service -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:301] :: Disabling Data Collection and Publishing Service..." -Severity 1 -Outhost
        Set-Service DcpSvc -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:302] :: Disabling Delivery Optimization Service..." -Severity 1 -Outhost
        Set-Service DoSvc -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:303] :: Disabling Encrypting File System Service..." -Severity 1 -Outhost
        Set-Service EFS -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:304] :: Disabling Extensible Authentication Protocol Service..." -Severity 1 -Outhost
        Set-Service Eaphost -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:305] :: Disabling Maps Manager Service..." -Severity 1 -Outhost
        Set-Service MapsBroker -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:306] :: Disabling WAP Push Messages Service..." -Severity 1 -Outhost
        Set-Service dmwappushsvc -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:307] :: Disabling Wireless Bluetooth Headsets Service..." -Severity 1 -Outhost
        Set-Service BthHFSrv -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:308] :: Disabling Geolocation Service..." -Severity 1 -Outhost
        Set-Service lfsvc -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:310] :: DisablingTouch Keyboard and Handwriting Panel Service..." -Severity 1 -Outhost
        Set-Service TabletInputService -StartupType Disabled -ErrorAction SilentlyContinue

        Write-LogEntry "VDI Optimizations [OSOT ID:311] :: Disabling Windows Image Acquisition (WIA) Service..." -Severity 1 -Outhost
        Set-Service stisvc -StartupType Disabled -ErrorAction SilentlyContinue

        
    }
}


# Disable Services
If ($DisableInternetServices -or $OptimizeForVDI)
{
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:199] :: "}	
	Write-LogEntry ("{0}Internet Services :: Disabling Xbox Live Auth Manager Service..." -f $prefixmsg) -Severity 1 -Outhost
	Set-Service XblAuthManager -StartupType Disabled -ErrorAction SilentlyContinue
    
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:200] :: "}	
	Write-LogEntry ("{0}Internet Services :: Disabling Xbox Live Game Save Service..." -f $prefixmsg) -Severity 1 -Outhost
	Set-Service XblGameSave -StartupType Disabled -ErrorAction SilentlyContinue

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:201] :: "}	
	Write-LogEntry ("{0}Internet Services :: Disabling Xbox Live Networking Service Service..." -f $prefixmsg) -Severity 1 -Outhost
	Set-Service XboxNetApiSvc -StartupType Disabled -ErrorAction SilentlyContinue

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:309] :: "}	
	Write-LogEntry ("{0}Internet Services :: Disabling Microsoft Account Sign-in Assistant Service..." -f $prefixmsg) -Severity 1 -Outhost
	Set-Service wlidsvc -StartupType Disabled -ErrorAction SilentlyContinue

	Write-LogEntry ("Internet Services :: Disabling Windows Error Reporting Service..." -f $prefixmsg) -Severity 1 -Outhost
	Set-Service WerSvc -StartupType Disabled -ErrorAction SilentlyContinue
	
	Write-LogEntry ("Internet Services :: Disabling Xbox Accessory Management Service..." -f $prefixmsg) -Severity 1 -Outhost
	Set-Service XboxGipSvc -StartupType Disabled -ErrorAction SilentlyContinue
	   
    Write-LogEntry ("Internet Services :: Disabling Windows Mediaplayer Sharing Service" -f $prefixmsg) -Severity 1 -Outhost
    Set-Service WMPNetworkSvc -StartupType Disabled -ErrorAction SilentlyContinue
	
    Write-LogEntry ("Internet Services :: Disabling Diagnostic Tracking..." -f $prefixmsg) -Severity 1 -Outhost
    Set-Service DiagTrack -StartupType Disabled -ErrorAction SilentlyContinue
	
    Write-LogEntry ("Internet Services :: Disabling WAP Push Service..." -f $prefixmsg) -Severity 1 -Outhost
    Set-Service dmwappushservice -StartupType Disabled -ErrorAction SilentlyContinue
    
}



If ($DisableDefender -or $OptimizeForVDI)
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


If ($DisableWireless -or $OptimizeForVDI)
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


If ($EnableRemoteRegistry -or $OptimizeForVDI)
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


If ($ApplySTIGItems -or $DisableBluetooth)
{
    Write-LogEntry "Disabling Bluetooth..." -Severity 1 -Outhost
    Config-Bluetooth -DeviceStatus Off
}


# Disable Scheduled Tasks
If ($DisableSchTasks -or $OptimizeForVDI)
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
        }    }
}


If ($DisableRestore -or $OptimizeForVDI)
{
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:66] :: "}
    Write-LogEntry ("{0}Disabling system restore..." -f $prefixmsg) -Severity 1 -Outhost
    Disable-ComputerRestore -drive c:\
}


If ($DisableCortana -or $OptimizeForVDI)
{
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:33] :: "}
	Write-LogEntry ("{0}Disabling Cortana..." -f $prefixmsg) -Severity 1 -Outhost
	Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowCortana' -Type DWord -Value '0' -Force | Out-Null
    
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:14] :: "}
    Write-LogEntry ("{0}Disabling Search option in taskbar" -f $prefixmsg) -Severity 1 -Outhost
	Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'SearchboxTaskbarMode' -Type DWord -Value '0' -Force | Out-Null	
    
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:42] :: " -f $prefixmsg}
    Write-LogEntry ("{0}Disabling search and Cortana to use location") -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowSearchToUseLocation' -Type DWord -Value '0' -Force | Out-Null    
}


If($DisableInternetSearch -or $OptimizeForVDI){
    
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:12] :: "}
    Write-LogEntry ("{0}Disabling Bing Search..." -f $prefixmsg) -Severity 1 -Outhost
	Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'BingSearchEnabled' -Type DWord -Value '0' -Force | Out-Null

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:47] :: "}
    Write-LogEntry ("Disable search web when searching pc" -f $prefixmsg) -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'ConnectedSearchUseWeb' -Type DWord -Value '0' -Force | Out-Null
    
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:55] :: "}
    Write-LogEntry ("{0}Disabling Web Search in search bar" -f $prefixmsg) -Severity 1 -Outhost
	Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'DisableWebSearch' -Type DWord -Value '0' -Force | Out-Null 
}


# Privacy and mitigaton settings
# See: https://docs.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services
If ($ApplyPrivacyMitigations -or $ApplySTIGItems)
{
    Write-LogEntry "Privacy Mitigations :: Disabling customer experience improvement program..." -Severity 1 -Outhost
	Set-SystemSettings -Path 'HKLM:\Software\Microsoft\SQMClient\Windows' -Name 'CEIPEnable' -Type DWord -Value '0' -Force | Out-Null
    
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:48] :: "}
    Write-LogEntry ("Privacy Mitigations :: {0}Disabling sending settings to cloud..." -f $prefixmsg) -Severity 1 -Outhost
	Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync' -Name 'DisableSettingSync' -Type DWord -Value 2 -Force | Out-Null
    
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:51] :: "}
    Write-LogEntry ("Privacy Mitigations :: {0}Disabling synchronizing files to cloud..." -f $prefixmsg) -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SettingSync' -Name 'DisableSettingSyncUserOverride' -Type DWord -Value 1 -Force | Out-Null

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:56] :: "}
    Write-LogEntry ("Privacy Mitigations :: {0}Disabling sending additional info with error reports..." -f $prefixmsg) -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' -Name 'DontSendAdditionalData' -Type DWord -Value 1 -Force | Out-Null

	Write-LogEntry "Privacy Mitigations :: Disallowing the user to change sign-in options..." -Severity 1 -Outhost
	Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Settings' -Name 'AllowSignInOptions' -Type DWord -Value '0' -Force | Out-Null
	
    If($ApplySTIGItems){$prefixmsg = "STIG Rule ID: SV-78039r1_rule :: "}
    Write-LogEntry ("Privacy Mitigations :: {0}Disabling Microsoft accounts for modern style apps..." -f $prefixmsg) -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'MSAOptional' -Value 1 -Force | Out-Null

	# Disable the Azure AD Sign In button in the settings app
	Write-LogEntry "Privacy Mitigations :: Disabling Sending data to Microsoft for Application Compatibility Program Inventory..." -Severity 1 -Outhost
	Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' -Name 'DisableInventory' -Type DWord -Value '1' -Force | Out-Null
	
	Write-LogEntry "Privacy Mitigations :: Disabling the Microsoft Account Sign-In Assistant..." -Severity 1 -Outhost
	Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'NoConnectedUser' -Type DWord -Value '3' -Force | Out-Null
	
	# Disable the MSA Sign In button in the settings app
	Write-LogEntry "Privacy Mitigations :: Disabling MSA sign-in options..." -Severity 1 -Outhost
	Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Settings' -Name 'AllowYourAccount' -Type DWord -Value '0' -Force | Out-Null
	
	Write-LogEntry "Privacy Mitigations :: Disabling camera usage on user's lock screen..." -Severity 1 -Outhost
    If($ApplySTIGItems){Write-LogEntry "STIG Rule ID: SV-78035r1_rule." -Severity 1 -Outhost}	
	Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name 'NoLockScreenCamera' -Type DWord -Value '1' -Force | Out-Null
	
    Write-LogEntry "Privacy Mitigations :: Disabling lock screen slideshow..." -Severity 1 -Outhost
    If($ApplySTIGItems){Write-LogEntry "STIG Rule ID: SV-78039r1_rule" -Severity 1 -Outhost}
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name 'NoLockScreenSlideshow' -Value 1 -Force | Out-Null

    Write-LogEntry "Privacy Mitigations :: Disabling Consumer Features..." -Severity 1 -Outhost
    If($ApplySTIGItems){Write-LogEntry "STIG Rule ID: SV-86395r2_rule" -Severity 1 -Outhost}
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableWindowsConsumerFeatures' -Type DWord -Value '1' -Force | Out-Null

    Write-LogEntry "Privacy Mitigations :: Disable the `"how to use Windows`" contextual popups" -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableSoftLanding' -Type DWord -Value '1' -Force | Out-Null

	# Offline maps
	Write-LogEntry "Privacy Mitigations :: Turning off unsolicited network traffic on the Offline Maps settings page..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps' -Name 'AllowUntriggeredNetworkTrafficOnSettingsPage' -Type DWord -Value '0' -Force | Out-Null
	Write-LogEntry "Privacy Mitigations :: Turning off Automatic Download and Update of Map Data..." -Severity 1 -Outhost
	Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps' -Name 'AutoDownloadAndUpdateMapData' -Type DWord -Value '0' -Force | Out-Null
	
	# Microsoft Edge
	Write-LogEntry "Privacy Mitigations :: Enabling Do Not Track in Microsoft Edge..." -Severity 1 -Outhost
	Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main' -Name 'DoNotTrack' -Type DWord -Value '1' -Force | Out-Null
	
	Write-LogEntry "Privacy Mitigations :: Disallow web content on New Tab page in Microsoft Edge..." -Severity 1 -Outhost
    #New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge" -Name "SearchScopes" -Force | Out-Null	
	Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\SearchScopes' -Name 'AllowWebContentOnNewTabPage' -Type DWord -Value '0' -Force | Out-Null
	
	# General stuff
	Write-LogEntry "Privacy Mitigations :: Turning off the advertising ID..." -Severity 1 -Outhost
	#New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion" -Name "AdvertisingInfo" -Force | Out-Null
	Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -Name 'Enabled' -Type DWord -Value '0' -Force | Out-Null
	
	Write-LogEntry "Privacy Mitigations :: Turning off location..." -Severity 1 -Outhost
    #New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "AppPrivacy" -Force | Out-Null
	Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessLocation' -Type DWord -Value '0' -Force | Out-Null
	#New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "LocationAndSensors" -Force | Out-Null
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' -Name 'DisableLocation' -Type DWord -Value '0' -Force | Out-Null
	
	# Stop getting to know me
	Write-LogEntry "Privacy Mitigations :: Turning off automatic learning..." -Severity 1 -Outhost
    #New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name "InputPersonalization" -Force | Out-Null	
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization' -Name 'RestrictImplicitInkCollection' -Type DWord -Value '1' -Force | Out-Null
	# Turn off updates to the speech recognition and speech synthesis models
	Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Speech_OneCore\Preferences' -Name 'ModelDownloadAllowed' -Type DWord -Value '0' -Force | Out-Null
	
	Write-LogEntry "Privacy Mitigations :: Disallowing Windows apps to access account information..." -Severity 1 -Outhost
	#New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows" -Name "AppPrivacy" -Force | Out-Null
	Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows\AppPrivacy' -Name 'LetAppsAccessAccountInfo' -Type DWord -Value '2' -Force | Out-Null

    Write-LogEntry "Privacy Mitigations :: Disabling Xbox features..." -Severity 1 -Outhost
    If($ApplySTIGItems){Write-LogEntry "STIG Rule ID: SV-89091r1_rule" -Severity 1 -Outhost}
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0 -Force | Out-Null

    Write-LogEntry "Privacy Mitigations :: Disabling WiFi Sense..." -Severity 1 -Outhost
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0 -Force | Out-Null
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0 -Force | Out-Null
    
    Write-LogEntry "STIG Rule ID: SV-78035r1_rule :: Disabling Wifi Sense..." -Severity 1 -Outhost
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Type DWord -Value 0 -Force | Out-Null

    Write-LogEntry "Privacy Mitigations :: Disabling all feedback notifications..." -Severity 1 -Outhost
	Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'DoNotShowFeedbackNotifications' -Type DWord -Value '1' -Force | Out-Null


    If($ApplySTIGItems){$prefixmsg = "STIG Rule ID: SV-78173r3_rule :: "}
    If($OptimizeForVDI){$prefixmsg += "VDI Optimizations [OSOT ID:53] :: "}
	Write-LogEntry ("Privacy Mitigations :: {0}Disabling telemetry..." -f $prefixmsg) -Outhost
	$OsCaption = (Get-WmiObject -class Win32_OperatingSystem).Caption
	If ($OsCaption -like "*Enterprise*" -or $OsCaption -like "*Education*"){
		$TelemetryLevel = "0"
		Write-LogEntry "Privacy Mitigations :: Enterprise edition detected. Supported telemetry level: Security." -Severity 1 -Outhost
	}
	Else{
		$TelemetryLevel = "1"
		Write-LogEntry "Privacy Mitigations :: Lowest supported telemetry level: Basic." -Severity 1 -Outhost
	}
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value $TelemetryLevel -Force | Out-Null


    If($ApplySTIGItems){Write-LogEntry "STIG Rule ID: SV-96859r1_rule" -Severity 1 -Outhost}
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'LimitEnhancedDiagnosticDataWindowsAnalytics' -Type DWord -Value 1 -Force | Out-Null   
}


If($CleanSampleFolders)
{
    Write-LogEntry "Cleaning Sample Folders..." -Severity 1 -Outhost
    Remove-Item "$env:PUBLIC\Music\Sample Music" -Recurse -ErrorAction SilentlyContinue | Out-Null
    Remove-Item "$env:PUBLIC\Pictures\Sample Pictures" -Recurse -ErrorAction SilentlyContinue | Out-Null
    Remove-Item "$env:PUBLIC\Recorded TV\Sample Media" -Recurse -ErrorAction SilentlyContinue | Out-Null
    Remove-Item "$env:PUBLIC\Videos\Sample Videos" -Recurse -ErrorAction SilentlyContinue | Out-Null
}


If ($EnableWinRM)
{
    Write-LogEntry "Enabling WinRM" -Severity 1 -Outhost
    
    $networkListManager = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]"{DCB00C01-570F-4A9B-8D69-199FDBA5723B}")) 
    $connections = $networkListManager.GetNetworkConnections() 

    # Set network location to Private for all networks 
    $connections | % {$_.GetNetwork().SetCategory(1)}

    # REQUIRED: set network to private before enabling winrm
    $netprofile = (Get-NetConnectionProfile -InterfaceAlias Ethernet*).NetworkCategory
    if (($netprofile -eq "Private") -or ($netprofile -eq "DomainAuthenticated")){<#do noting#>}Else{Set-NetConnectionProfile -NetworkCategory Private}

    If($ApplySTIGItems){
        Write-LogEntry "STIG Rule ID: SV-77825r1_rule :: Disabling Basic Authentication for WinRM" -Severity 1 -Outhost
        Set-SystemSettings -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowBasic" -Type DWord -Value 0 -Force | Out-Null
        Set-SystemSettings -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowBasic" -Type DWord -Value 0 -Force | Out-Null

        Write-LogEntry "STIG Rule ID: SV-77829r1_rule :: Disabling unencrypted traffic for WinRM" -Severity 1 -Outhost
        Set-SystemSettings -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowUnencryptedTraffic" -Type DWord -Value 0 -Force | Out-Null
        Set-SystemSettings -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowUnencryptedTraffic" -Type DWord -Value 0 -Force | Out-Null

        Write-LogEntry "STIG Rule ID: SV-77831r1_rule :: Disabling Digest authentication for WinRM" -Severity 1 -Outhost
        Set-SystemSettings -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowDigest" -Type DWord -Value 0 -Force | Out-Null

        Write-LogEntry "STIG Rule ID: SV-77831r1_rule :: Disabling Digest authentication for WinRM" -Severity 1 -Outhost
        Set-SystemSettings -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "DisableRunAs" -Type DWord -Value 1 -Force | Out-Null
    }

    Try{
        $winrm = Start-Process winrm -ArgumentList 'qc -quiet' -Wait -PassThru -NoNewWindow | Out-Null
        
        $psremoting = Enable-PSRemoting -Force -SkipNetworkProfileCheck -ErrorAction SilentlyContinue | Out-Null

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
        Write-LogEntry ("Unable to setup WinRM: {0}" -f $_.Exception.ErrorMessage) -Severity 3 -Outhost
    }
}


If($ApplySTIGItems -or $EnableStrictUAC)
{
    Write-LogEntry "Setting strict UAC Level and enabling admin approval mode..." -Severity 1 -Outhost

    If($ApplySTIGItems){Write-LogEntry "STIG Rule ID: SV-78309r1_rule :: Enabling UAC prompt administrators for consent on the secure desktop..." -Severity 1 -Outhost}
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -Type DWord -Value 2 -Force | Out-Null
    
    If($ApplySTIGItems){Write-LogEntry "STIG Rule ID: SV-78311r1_rule :: Disabling elevation UAC prompt User for consent on the secure desktop..." -Severity 1 -Outhost}
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorUser -Type DWord -Value 0 -Force | Out-Null

    If($ApplySTIGItems){Write-LogEntry "STIG Rule ID: SV-78315r1_rule :: Enabling elevation UAC prompt detect application installations and prompt for elevation..." -Severity 1 -Outhost}
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableInstallerDetection" -Type DWord -Value 1 -Force | Out-Null
    
    If($ApplySTIGItems){Write-LogEntry "STIG Rule ID: SV-78315r1_rule :: Enabling elevation UAC UIAccess applications that are installed in secure locations..." -Severity 1 -Outhost}
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableSecureUAIPaths" -Type DWord -Value 1 -Force | Out-Null

    If($ApplySTIGItems){Write-LogEntry "STIG Rule ID: SV-78321r1_rule :: Enabling Enable virtualize file and registry write failures to per-user locations.." -Severity 1 -Outhost}
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableVirtualization" -Type DWord -Value 1 -Force | Out-Null
        
    If($ApplySTIGItems){Write-LogEntry "STIG Rule ID: SV-78319r1_rule :: Enabling UAC for all administrators..." -Severity 1 -Outhost}
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Type DWord -Value 1 -Force | Out-Null

    If($ApplySTIGItems){Write-LogEntry "STIG Rule ID: SV-78087r2_rule :: FIlter Local administrator account privileged tokens..." -Severity 1 -Outhost}
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Type DWord -Value 0 -Force | Out-Null

    If($ApplySTIGItems){Write-LogEntry "STIG Rule ID: SV-78307r1_rule :: Enabling User Account Control approval mode..." -Severity 1 -Outhost}
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "FilterAdministratorToken" -Type DWord -Value 1 -Force | Out-Null

    If($ApplySTIGItems){Write-LogEntry "STIG Rule ID: SV-78307r1_rule :: Disabling enumerating elevated administator accounts..." -Severity 1 -Outhost}
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" -Name "EnumerateAdministrators" -Type DWord -Value 0 -Force | Out-Null

    If($ApplySTIGItems -eq $false){
        Write-LogEntry "Enable All credential or consent prompting will occur on the interactive user's desktop..." -Severity 1 -Outhost
        Set-SystemSettings -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1 -Force | Out-Null

        Write-LogEntry "Enforce cryptographic signatures on any interactive application that requests elevation of privilege..." -Severity 1 -Outhost
        Set-SystemSettings -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ValidateAdminCodeSignatures" -Type DWord -Value 0 -Force | Out-Null
    }
}


If ($EnableAppsRunAsAdmin)
{
    If($ApplySTIGItems){Write-LogEntry "STIG Rule ID: SV-78307r1_rule :: Enabling User Account Control approval mode for local Administrator" -Severity 1 -Outhost}
    Else{Write-LogEntry "Enabling UAC to allow Apps to run as Administrator..." -Severity 1 -Outhost}
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name FilterAdministratorToken -Type DWord -Value '1' -Force | Out-Null
}


If ($DisableUAC)
{
    Write-LogEntry "Disabling User Access Control..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Type DWord -Value '0' -Force | Out-Null
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -Type DWord -Value '0' -Force | Out-Null
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name PromptOnSecureDesktop -Type DWord -Value '0' -Force | Out-Null
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name FilterAdministratorToken -Type DWord -Value 0 -Force | Out-Null
}


If ($ApplySTIGItems -or $DisableWUP2P -or $OptimizeForVDI)
{
    If($ApplySTIGItems){$prefixmsg = "STIG Rule ID: SV-80171r3_rule :: "}
    If($OptimizeForVDI){$prefixmsg += "VDI Optimizations [OSOT ID:31] :: "}
    Write-LogEntry ("{0}Disable P2P WIndows Updates..." -f $prefixmsg) -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config' -Name DownloadMode -Type DWord -Value '0' -Force | Out-Null
    
    #adds windows update back to control panel (permissions ned to be changed)
    #Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX' -Name IsConvergedUpdateStackEnabled -Type DWord -Value '0' -Force | Out-Null
}


If ($EnableIEEnterpriseMode)
{
    If(Test-Path $IEEMSiteListPath){
        Write-LogEntry "Enabling Enterprise Mode option in IE..." -Severity 1 -Outhost
        Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\EnterpriseMode' -Name Enable -Type DWord -Value '1' -Force | Out-Null
        Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\EnterpriseMode' -Name Sitelist -Value $IEEMSiteListPath -Force | Out-Null
    }
    Else{
        Write-LogEntry ("IE Enterprise XML Path [{0}] is not found..." -f $IEEMSiteListPath) -Severity 1 -Outhost
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
	
    Set-SystemSettings -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Runonce" -Name "Logon" -Value "Powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File $env:windir\Scripts\Logon.ps1" -Force | Out-Null
	
    # load default hive
	Start-Process -FilePath "reg.exe" -ArgumentList "LOAD HKLM:\DEFAULT $env:systemdrive\Users\Default\NTUSER.DAT"
	
    # create RunOnce entries current / new user(s)
	Write-LogEntry "Creating RunOnce entries..." -Severity 1 -Outhost
	Set-SystemSettings -Path "HKLM:\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Runonce" -Name "Logon" -Value "Powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File $env:windir\Scripts\Logon.ps1" -Force | Out-Null
	
    # unload default hive
	Start-Process -FilePath "reg.exe" -ArgumentList "UNLOAD HKLM:\DEFAULT"
}


If($EnableCredGuard -and !$OptimizeForVDI)
{
    
    Write-LogEntry "STIG Rule ID: SV-78085r5_rule :: Enabling Virtualization Based Security..." -Severity 1 -Outhost
    
    if ($OSBuildNumber -gt 14393) {
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
    
    Write-LogEntry "STIG Rule ID: SV-78093r6_rule :: Enabling Virtualization-based protection of code integrity..." -Severity 1 -Outhost
    #https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/enable-virtualization-based-protection-of-code-integrity
    Set-SystemSettings -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name RequirePlatformSecurityFeatures -Type DWord -Value 1 -Force | Out-Null
    Set-SystemSettings -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name EnableVirtualizationBasedSecurity -Type DWord -Value 1 -Force | Out-Null
    Set-SystemSettings -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name Locked -Type DWord -Value 0 -Force | Out-Null
    If ([int](Get-WmiObject -Class Win32_OperatingSystem).BuildNumber -lt 14393) {
        Set-SystemSettings -Path "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name HypervisorEnforcedCodeIntegrity -Type DWord -Value 1 -Force | Out-Null
    }
    Set-SystemSettings -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name Enabled -Type DWord -Value 1 -Force | Out-Null
    Set-SystemSettings -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name Locked -Type DWord -Value 0 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78089r7_rule :: Enabling Credential Guard on domain-joined systems..." -Severity 1 -Outhost
    Set-SystemSettings -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LsaCfgFlags -Type DWord -Value 1 -Force | Out-Null   
    
    $DeviceGuardProperty = Get-CimInstance –ClassName Win32_DeviceGuard –Namespace root\Microsoft\Windows\DeviceGuard
    If($DeviceGuardProperty.VirtualizationBasedSecurityStatus -eq 1){
        Write-LogEntry ("Successfully enabled Credential Guard, version: {0}" -f $DeviceGuardProperty.Version) -Severity 1 -Outhost   
    }
    Else{
        Write-LogEntry "Unable to enabled Credential Guard, may not be supported on this model, trying a differnet way" -Severity 2 -Outhost
        . $AdditionalScriptsPath\DG_Readiness_Tool_v3.6.ps1 -Enable -CG
    }
}
Else{
    #. $AdditionalScriptsPath\DG_Readiness_Tool_v3.6.ps1 -Disable
}


If($DisableIndexing)
{
    Write-LogEntry "Disable Indexing on $env:SystemDrive" -Severity 1 -Outhost
    Disable-Indexing $env:SystemDrive
}


If ($PreCompileAssemblies -or $OptimizeForVDI)
{
    #https://www.emc.com/collateral/white-papers/h14854-optimizing-windows-virtual-desktops-deploys.pdf
    #https://blogs.msdn.microsoft.com/dotnet/2012/03/20/improving-launch-performance-for-your-desktop-applications/
    Write-LogEntry "Pre-compile .NET framework assemblies. This can take a while...." -Severity 1 -Outhost
    Start-Process "$env:windir\Microsoft.NET\Framework\v4.0.30319\ngen.exe" -ArgumentList "update /force" -Wait -NoNewWindow
    Start-Process "$env:windir\Microsoft.NET\Framework\v4.0.30319\ngen.exe" -ArgumentList "executequeueditems" -Wait -NoNewWindow
}


# VDI ONLY CONFIGS
# ===================================
If ($OptimizeForVDI)
{
    Write-LogEntry "VDI Optimizations [OSOT ID:30] :: Disabling Background Layout Service" -Severity 1 -Outhost
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OptimalLayout" -Name EnableAutoLayout -Type DWord -Value 0 -Force | Out-Null

    Write-LogEntry "VDI Optimizations [OSOT ID:31] :: Disabling CIFS Change Notifications" -Severity 1 -Outhost
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoRemoteRecursiveEvents -Type DWord -Value 0 -Force | Out-Null
    
    Write-LogEntry "VDI Optimizations [OSOT ID:32] :: Disabling customer experience improvement program..." -Severity 1 -Outhost
	Set-SystemSettings -Path 'HKLM:\Software\Microsoft\SQMClient\Windows' -Name 'CEIPEnable' -Type DWord -Value '0' -Force | Out-Null

    Write-LogEntry "VDI Optimizations [OSOT ID:34] :: Enabling Automatically Reboot for the Crash Control" -Severity 1 -Outhost
    Set-SystemSettings -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name AutoReboot -Type DWord -Value 1 -Force | Out-Null

    Write-LogEntry "VDI Optimizations [OSOT ID:35] :: Disabling sending alert for the Crash Control..." -Severity 1 -Outhost
    Set-SystemSettings -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name SendAlert -Type DWord -Value 0 -Force | Out-Null

    Write-LogEntry "VDI Optimizations [OSOT ID:36] :: Disabling writing event to the system log for the Crash Control..." -Severity 1 -Outhost
    Set-SystemSettings -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name LogEvent -Type DWord -Value 0 -Force | Out-Null

    #Optional
    Write-LogEntry "VDI Optimizations [OSOT ID:37] :: Disable Creation of Crash Dump and removes it..." -Severity 1 -Outhost
    Set-SystemSettings -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name CrashDumpEnabled -Type DWord -Value 0 -Force | Out-Null

    Write-LogEntry "VDI Optimizations [OSOT ID:38] :: Disabling IPv6..." -Severity 1 -Outhost
	Set-SystemSettings -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'DisabledComponents' -Type DWord -Value '255' -Force | Out-Null
    
    #Optional
    #Write-LogEntry "VDI Optimizations [OSOT ID:39] :: Enabling wait time for disk write or read to take place on the SAN without throwing an error..." -Severity 1 -Outhost
	#Set-SystemSettings -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'TimeOutValue' -Type DWord -Value '200' -Force | Out-Null

    Write-LogEntry "VDI Optimizations [OSOT ID:41] :: Enabling 120 sec wait timeout for a services..." -Severity 1 -Outhost
	Set-SystemSettings -Path 'HKLM:\System\CurrentControlSet\Control' -Name 'ServicesPipeTimeout' -Type DWord -Value '120000' -Force | Out-Null

    #Optional
    Write-LogEntry "VDI Optimizations [OSOT ID:46] :: Removing previous versions capability..." -Severity 1 -Outhost
	Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'NoPreviousVersionsPage' -Type DWord -Value '1' -Force | Out-Null

    Write-LogEntry "VDI Optimizations [OSOT ID:52] :: Disabling TCP/IP Task Offload..." -Severity 1 -Outhost
	Set-SystemSettings -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP\Parameters' -Name 'DisableTaskOffload' -Type DWord -Value '1' -Force | Out-Null

    #Write-LogEntry "VDI Optimizations [OSOT ID:57] :: Disabling Automatic Update - important for non persistent VMs..." -Severity 1 -Outhost
	#Set-SystemSettings -Path 'HKLM:\SYSTEM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoUpdate' -Type DWord -Value '1' -Force | Out-Null

    Write-LogEntry "VDI Optimizations [OSOT ID:63] :: Disabling NTFS Last Access Timestamp..." -Severity 1 -Outhost
    Start-process fsutil -ArgumentList 'behavior set disablelastaccess 1' -Wait -NoNewWindow | Out-Null
    
    Write-LogEntry "VDI Optimizations [OSOT ID:287] :: Disabling  Boot Optimize Function..." -Severity 1 -Outhost
	Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Dfrg\BootOptimizeFunction' -Name 'Enable' -Type String -Value '0' -Force | Out-Null

    Write-LogEntry "VDI Optimizations :: Disable Superfetch" -Severity 1 -Outhost
    Set-SystemSettings -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name EnableSuperfetch -Type DWord -Value 0 -Force | Out-Null 

    Write-LogEntry "VDI Optimizations :: Disabling Paging Executive..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'DisablePagingExecutive' -Value 1 -Force | Out-Null

    Write-LogEntry "VDI Optimizations :: Disable Storing Recycle Bin Files" -Severity 1 -Outhost
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" -Name NoRecycleFiles -Type DWord -Value 1 -Force | Out-Null

    Write-LogEntry "VDI Optimizations :: Disk Timeout Value" -Severity 1 -Outhost
    Set-SystemSettings -Path "HKLM:\SYSTEM\CurrentControlSet\services\Disk" -Name TimeOutValue -Type DWord -Value 200 -Force | Out-Null

    Write-LogEntry "VDI Optimizations :: Application Event Log Max Size" -Severity 1 -Outhost
    Set-SystemSettings -Path "HKLM:\SYSTEM\CurrentControlSet\services\eventlog\Application" -Name MaxSize -Type DWord -Value 100000 -Force | Out-Null

    Write-LogEntry "VDI Optimizations :: Application Event Log Retention" -Severity 1 -Outhost
    Set-SystemSettings -Path "HKLM:\SYSTEM\CurrentControlSet\services\eventlog\Application" -Name Retention -Type DWord -Value 0 -Force | Out-Null

    Write-LogEntry "VDI Optimizations :: System Event Log Max Size" -Severity 1 -Outhost
    Set-SystemSettings -Path "HKLM:\SYSTEM\CurrentControlSet\services\eventlog\System" -Name MaxSize -Type DWord -Value 100000 -Force | Out-Null

    Write-LogEntry "VDI Optimizations :: System Event Log Retention" -Severity 1 -Outhost
    Set-SystemSettings -Path "HKLM:\SYSTEM\CurrentControlSet\services\eventlog\System" -Name Retention -Type DWord -Value 0 -Force | Out-Null

    Write-LogEntry "VDI Optimizations :: Security Event Log Max Size" -Severity 1 -Outhost
    Set-SystemSettings -Path "HKLM:\SYSTEM\CurrentControlSet\services\eventlog\Security" -Name MaxSize -Type DWord -Value 100000 -Force | Out-Null

    Write-LogEntry "VDI Optimizations :: Disabling Security Event Log Retention" -Severity 1 -Outhost
    Set-SystemSettings -Path "HKLM:\SYSTEM\CurrentControlSet\services\eventlog\Security" -Name Retention -Type DWord -Value 0 -Force | Out-Null

    Write-LogEntry "VDI Optimizations :: Disabling Boot GUI" -Severity 1 -Outhost
    Start-process bcdedit -ArgumentList '/set BOOTUX disabled' -Wait -NoNewWindow | Out-Null

    Write-LogEntry "VDI Optimizations [OSOT ID:290] :: Disabling Boot Debugging" -Severity 1 -Outhost
    Start-process bcdedit -ArgumentList '/bootdebug off' -Wait -NoNewWindow | Out-Null

    Write-LogEntry "VDI Optimizations [OSOT ID:291] :: Disabling Debugging" -Severity 1 -Outhost
    Start-process bcdedit -ArgumentList '/debug off' -Wait -NoNewWindow | Out-Null

    Write-LogEntry "VDI Optimizations [OSOT ID:292] :: Disabling Boot Logging" -Severity 1 -Outhost
    Start-process bcdedit -ArgumentList '/set bootlog no' -Wait -NoNewWindow | Out-Null

    Write-LogEntry "VDI Optimizations :: Delete Restore Points for System Restore" -Severity 1 -Outhost
    Start-process vssadmin -ArgumentList 'delete shadows /All /Quiet' -Wait -NoNewWindow | Out-Null

    # Loop through each profile on the machine
    Foreach ($UserProfile in $UserProfiles) {
        If($UserProfile.SID -ne ".DEFAULT"){
            $objSID = New-Object System.Security.Principal.SecurityIdentifier($UserProfile.SID)
            $UserID = $objSID.Translate([System.Security.Principal.NTAccount])
        }
        Else{
            $UserID = $UserProfile.SID
        }

        # Load User ntuser.dat if it's not already loaded
        If (($ProfileWasLoaded = Test-Path Registry::HKEY_USERS\$($UserProfile.SID)) -eq $false) {
            Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE LOAD HKU\$($UserProfile.SID) $($UserProfile.UserHive)" -Wait -WindowStyle Hidden

            Write-LogEntry ("VDI Optimizations :: Settings Temporary Internet Files to Non Persistent for User: {0}..." -f $UserID) -Outhost
            Set-SystemSettings -Path "HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Cache" -Name Persistent -Value 0 -Type DWord -ErrorAction SilentlyContinue | Out-Null
                
            Write-LogEntry ("VDI Optimizations [ID 11] :: Disable RSS Feeds for User: {0}..." -f $UserID) -Outhost
            Set-SystemSettings -Path "HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Feeds" -Name SyncStatus -Type DWord -Value 0 -Force | Out-Null

            Write-LogEntry ("VDI Optimizations:: Disabling Storage Sense for User: {0}..." -f $UserID) -Outhost
            Remove-ItemProperty -Path "Registry::HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Recurse -ErrorAction SilentlyContinue | Out-Null

            Write-LogEntry ("VDI Optimizations [OSOT ID:8] :: Disabling show most used apps at start menu for User: {0}..." -f $UserID) -Outhost
            Set-SystemSettings -Path "HKEY_USERS\$($UserProfile.SID)\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name Start_TrackProgs -Type DWord -Value 0 -Force | Out-Null

            Write-LogEntry ("VDI Optimizations [OSOT ID:9] :: Disabling show recent items at start menu for User: {0}..." -f $UserID) -Outhost
            Set-SystemSettings -Path "HKEY_USERS\$($UserProfile.SID)\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name Start_TrackDocs -Type DWord -Value 0 -Force | Out-Null
            
            Write-LogEntry ("VDI Optimizations [OSOT ID:203] :: Disabling Microsoft OneDrive startup run for User: {0}..." -f $UserID) -Outhost
            Set-SystemSettings -Path "HKEY_USERS\$($UserProfile.SID)\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" -Name OneDrive -Type Binary -Value 0300000064A102EF4C3ED101 -Force | Out-Null

            If($ApplySTIGItems){
                Write-LogEntry ("STIG Rule ID: SV-78329r1_rule :: Disabling Toast notifications to the lock screen for user: {0}" -f $UserID) -Severity 1 -Outhost
                Set-SystemSettings -Path "HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name NoToastApplicationNotificationOnLockScreen -Type DWord -Value '1' -Force | Out-Null
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



If($EnableVisualPerformance -or $OptimizeForVDI)
{
    # thanks to camxct
    #https://github.com/camxct/Win10-Initial-Setup-Script/blob/master/Win10.psm1
    Write-LogEntry "Adjusting visual effects for performance..." -Severity 1 -Outhost
	
    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:83] :: "}
    Write-LogEntry ("Disabling Animate windows when minimizing and maxmizing Visual Effect..." -f $prefixmsg) -Severity 1 -Outhost
	Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\AnimateMinMax' -Name 'DefaultValue' -Type DWord -Value '0' -Force | Out-Null

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:84] :: "}
    Write-LogEntry ("Disabling Animations in the taskbar Visual Effect..." -f $prefixmsg) -Severity 1 -Outhost
	Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TaskbarAnimations' -Name 'DefaultValue' -Type DWord -Value '0' -Force | Out-Null

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:85] :: "}
    Write-LogEntry ("Disabling Enable Peek Visual Effect..." -f $prefixmsg) -Severity 1 -Outhost
	Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMAeroPeekEnabled' -Name 'DefaultValue' -Type DWord -Value '0' -Force | Out-Null

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:86] :: "}
    Write-LogEntry ("Disabling Save taskbar thumbnail previews Visual Effect..." -f $prefixmsg) -Severity 1 -Outhost
	Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMSaveThumbnailEnabled' -Name 'DefaultValue' -Type DWord -Value '0' -Force | Out-Null

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:87] :: "}
    Write-LogEntry ("Disabling Show translucent selection rectangle Visual Effect..." -f $prefixmsg) -Severity 1 -Outhost
	Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListviewAlphaSelect' -Name 'DefaultValue' -Type DWord -Value '0' -Force | Out-Null

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:88] :: "}
    Write-LogEntry ("Disabling Show window contents while dragging Visual Effect..." -f $prefixmsg) -Severity 1 -Outhost
	Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DragFullWindows' -Name 'DefaultValue' -Type DWord -Value '0' -Force | Out-Null

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:89] :: "}
    Write-LogEntry ("Disabling Smooth edges of screen fonts Visual Effect..." -f $prefixmsg) -Severity 1 -Outhost
	Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\FontSmoothing' -Name 'DefaultValue' -Type DWord -Value '0' -Force | Out-Null

    If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:90] :: "}
    Write-LogEntry ("Disabling Use drop shadows for icon labels on the desktop Visual Effect..." -f $prefixmsg) -Severity 1 -Outhost
	Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListviewShadow' -Name 'DefaultValue' -Type DWord -Value '0' -Force | Out-Null


    # Loop through each profile on the machine
    Foreach ($UserProfile in $UserProfiles) {
        If($UserProfile.SID -ne ".DEFAULT"){
            $objSID = New-Object System.Security.Principal.SecurityIdentifier($UserProfile.SID)
            $UserID = $objSID.Translate([System.Security.Principal.NTAccount])
        }
        Else{
            $UserID = $UserProfile.SID
        }

        # Load User ntuser.dat if it's not already loaded
        If (($ProfileWasLoaded = Test-Path Registry::HKEY_USERS\$($UserProfile.SID)) -eq $false) {
            Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE LOAD HKU\$($UserProfile.SID) $($UserProfile.UserHive)" -Wait -WindowStyle Hidden

            If($OptimizeForVDI){
                Write-LogEntry ("VDI Optimizations [OSOT ID:72] :: Setting Windows Visual Effects to Optimized for best performance for User: {0}..." -f $UserID) -Outhost
                Set-SystemSettings -Path "HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 2 -Force | Out-Null
            }
            Else{
                Write-LogEntry ("Setting Windows Visual Effects to Optimized for best performance for User: {0}..." -f $UserID) -Outhost
                Set-SystemSettings -Path "HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3 -Force | Out-Null
            }

            If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:73] :: "}
            Write-LogEntry ("{0}Disabling Animate windows when minimizing and maxmizing Visual Effect for User: {1}..." -f $prefixmsg,$UserID) -Outhost
            Set-SystemSettings -Path "HKEY_USERS\$($UserProfile.SID)\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value 0 -Force | Out-Null

            If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:74] :: "}
            Write-LogEntry ("{0}Disabling Animations in the taskbar Visual Effect for User: {1}..." -f $prefixmsg,$UserID) -Outhost
            Set-SystemSettings -Path "HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 0 -Force | Out-Null

            If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:75] :: "}
            Write-LogEntry ("{0}Disabling Peek Visual Effect for User: {1}..." -f $prefixmsg,$UserID) -Outhost
            Set-SystemSettings -Path "HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 0 -Force | Out-Null

            If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:76] :: "}
            Write-LogEntry ("{0}Turning off Play animations in windows for User: {1}..." -f $prefixmsg,$UserID) -Outhost
            Set-SystemSettings -Path "HKEY_USERS\$($UserProfile.SID)\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value 9012038010000000 -Force | Out-Null

            If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:77] :: "}
            Write-LogEntry ("{0}Disabling Save taskbar thumbnail previews Visual Effect for User: {1}..." -f $prefixmsg,$UserID) -Outhost
            Set-SystemSettings -Path "HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\DWM" -Name "AlwaysHibernateThumbnails" -Type DWord -Value 0 -Force | Out-Null

            If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:78] :: "}
            Write-LogEntry ("{0}Disabling Show translucent selection rectangle Visual Effect for User: {1}..." -f $prefixmsg,$UserID) -Outhost
            Set-SystemSettings -Path "HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 0 -Force | Out-Null

            If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:79] :: "}
            Write-LogEntry ("{0}Disabling Show window contents while dragging Visual Effect for User: {1}..." -f $prefixmsg,$UserID) -Outhost
            Set-SystemSettings -Path "HKEY_USERS\$($UserProfile.SID)\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value 0 -Force | Out-Null

            If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:80] :: "}
            Write-LogEntry ("{0}Disabling Smooth edges of screen fonts Visual Effect for User: {1}..." -f $prefixmsg,$UserID) -Outhost
            Set-SystemSettings -Path "HKEY_USERS\$($UserProfile.SID)\Control Panel\Desktop" -Name "FontSmoothing" -Type String -Value 0 -Force | Out-Null

            If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:81] :: "}
            Write-LogEntry ("{0}Disabling Use drop shadows for icon labels on the desktop Visual Effect for User: {1}..." -f $prefixmsg,$UserID) -Outhost
            Set-SystemSettings -Path "HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 0 -Force | Out-Null

            If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:10] :: "}
            Write-LogEntry ("{0}Disabling Delaying Show the Reduce Menu for User: {1}..." -f $prefixmsg,$UserID) -Outhost
            Set-SystemSettings -Path "HKEY_USERS\$($UserProfile.SID)\Control Panel\Desktop" -Name MenuShowDelay -Type DWord -Value 120 -Force | Out-Null

            #Other settings
	        #Set-SystemSettings -Path "HKEY_USERS\$($UserProfile.SID)\Control Panel\Keyboard" -Name "KeyboardDelay" -Type DWord -Value 0 -Force | Out-Null
	        #Set-SystemSettings -Path "HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "IconsOnly" -Type DWord -Value 1 -Force | Out-Null
            
            Write-LogEntry ("Disabling Disable creating thumbnail cache [Thumbs.db] on local Folders for User: {0}..." -f $UserID) -Outhost
            Set-SystemSettings -Path "HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbnailCache" -Type DWord -Value 1 -Force | Out-Null
            
            Write-LogEntry ("Disabling Disable creating thumbnail cache [Thumbs.db] on Network Folders for User: {0}..." -f $UserID) -Outhost
            Set-SystemSettings -Path "HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbsDBOnNetworkFolders" -Type DWord -Value 1 -Force | Out-Null
        }

        # Unload NTuser.dat        
        If ($ProfileWasLoaded -eq $false) {
            [gc]::Collect()
            Start-Sleep 1
            Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE UNLOAD HKU\$($UserProfile.SID)" -Wait -PassThru  -WindowStyle Hidden | Out-Null
        }
    }

}


If($EnableDarkTheme)
{
    # thanks to camxct
    #https://github.com/camxct/Win10-Initial-Setup-Script/blob/master/Win10.psm1
    Write-LogEntry "Enabling Dark Theme..." -Severity 1 -Outhost
	Set-SystemSettings -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 0 -Force | Out-Null
}


If($EnableNumlockStartup)
{
	Write-LogEntry "Enabling NumLock after startup..." -Severity 1 -Outhost
	# Loop through each profile on the machine
    Foreach ($UserProfile in $UserProfiles) {
        If($UserProfile.SID -ne ".DEFAULT"){
            $objSID = New-Object System.Security.Principal.SecurityIdentifier($UserProfile.SID)
            $UserID = $objSID.Translate([System.Security.Principal.NTAccount])
        }
        Else{
            $UserID = $UserProfile.SID
        }

        # Load User ntuser.dat if it's not already loaded
        If (($ProfileWasLoaded = Test-Path Registry::HKEY_USERS\$($UserProfile.SID)) -eq $false) {
            Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE LOAD HKU\$($UserProfile.SID) $($UserProfile.UserHive)" -Wait -WindowStyle Hidden           
            Write-LogEntry  ("Enabing Num lock for  for User: {0}..." -f $UserID) -Outhost
            Set-SystemSettings -Path "HKEY_USERS\$($UserProfile.SID)\Control Panel\Keyboard" -Name InitialKeyboardIndicators -Value 2147483650 -Type DWord -ErrorAction SilentlyContinue -Force | Out-Null
        }

        # Unload NTuser.dat        
        If ($ProfileWasLoaded -eq $false) {
            [gc]::Collect()
            Start-Sleep 1
            Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE UNLOAD HKU\$($UserProfile.SID)" -Wait -PassThru  -WindowStyle Hidden | Out-Null
        }
    }

	Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483650 -Force -ErrorAction SilentlyContinue | Out-Null

	Add-Type -AssemblyName System.Windows.Forms
	If (!([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
		$wsh = New-Object -ComObject WScript.Shell
		$wsh.SendKeys('{NUMLOCK}')
	}
}


If($ShowKnownExtensions)
{
	Write-LogEntry "Showing known file extensions..." -Severity 1 -Outhost
	Set-SystemSettings -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0 -Force | Out-Null

    # load default hive
	Start-Process -FilePath "reg.exe" -ArgumentList "LOAD HKLM:\DEFAULT $env:systemdrive\Users\Default\NTUSER.DAT"

    Write-LogEntry "Showing known file extensions for default.." -Severity 1 -Outhost
	Set-SystemSettings -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0 -Force | Out-Null

    # unload default hive
	Start-Process -FilePath "reg.exe" -ArgumentList "UNLOAD HKLM:\DEFAULT"
}


If($ShowHiddenFiles)
{
	Write-LogEntry "Showing hidden files..." -Severity 1 -Outhost
	Set-SystemSettings -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1 -Force | Out-Null

    # load default hive
	Start-Process -FilePath "reg.exe" -ArgumentList "LOAD HKLM:\DEFAULT $env:systemdrive\Users\Default\NTUSER.DAT"

    Write-LogEntry "Showing hidden files for default.." -Severity 1 -Outhost
	Set-SystemSettings -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1 -Force | Out-Null

    # unload default hive
	Start-Process -FilePath "reg.exe" -ArgumentList "UNLOAD HKLM:\DEFAULT"
}


If($ShowThisPCOnDesktop)
{
	Write-LogEntry "Showing This PC shortcut on desktop..." -Severity 1 -Outhost
	Set-SystemSettings -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0 -Force | Out-Null
	Set-SystemSettings -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0 -Force | Out-Null

    # load default hive
	Start-Process -FilePath "reg.exe" -ArgumentList "LOAD HKLM:\DEFAULT $env:systemdrive\Users\Default\NTUSER.DAT"

    Write-LogEntry "Showing This PC shortcut on desktop for default.." -Severity 1 -Outhost
    Set-SystemSettings -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0 -Force | Out-Null
	Set-SystemSettings -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0 -Force | Out-Null

    # unload default hive
	Start-Process -FilePath "reg.exe" -ArgumentList "UNLOAD HKLM:\DEFAULT"
}


If($ShowUserFolderOnDesktop)
{
	Write-LogEntry "Showing User Folder shortcut on desktop..." -Severity 1 -Outhost
	Set-SystemSettings -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Type DWord -Value 0 -Force | Out-Null
	Set-SystemSettings -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Type DWord -Value 0 -Force | Out-Null

    # load default hive
	Start-Process -FilePath "reg.exe" -ArgumentList "LOAD HKLM:\DEFAULT $env:systemdrive\Users\Default\NTUSER.DAT"

    Write-LogEntry "Showing User Folder shortcut on desktop for default.." -Severity 1 -Outhost
    Set-SystemSettings -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Type DWord -Value 0 -Force | Out-Null
	Set-SystemSettings -Path "HKLM:\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Type DWord -Value 0 -Force | Out-Null

    # unload default hive
	Start-Process -FilePath "reg.exe" -ArgumentList "UNLOAD HKLM:\DEFAULT"
}


If($Hide3DObjectsFromExplorer)
{
	Write-LogEntry "Hiding 3D Objects icon from Explorer namespace..." -Severity 1 -Outhost
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue -Force | Out-Null
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value Hide -Force | Out-Null

}


If($DisableEdgeShortcutCreation)
{
	Write-LogEntry "Disabling Edge shortcut creation..." -Severity 1 -Outhost
	Set-SystemSettings -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "DisableEdgeDesktopShortcutCreation" -Type DWord -Value 1 -Force | Out-Null
}


If($ApplySTIGItems -or $SetSmartScreenFilter)
{
	switch($SetSmartScreenFilter){
    'Off'  {$value = 0;$label = "to Disable"}
    'User'  {$value = 1;$label = "to Warning Users"}
    'admin' {$value = 2;$label = "to Require Admin approval"}
    default {$value = 1;$label = "to Warning Users"}
    }
    Write-LogEntry "Configuring Smart Screen Filter $label..." -Severity 1 -Outhost
    If($ApplySTIGItems){Write-LogEntry "STIG Rule ID: SV-78175r5_rule" -Severity 1 -Outhost}
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Type DWord -Value $value -Force | Out-Null
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "ShellSmartScreenLevel" -Type String -Value "Block" -Force | Out-Null

    Write-LogEntry "Enabling Smart Screen Filter on Edge..." -Severity 1 -Outhost
    If($ApplySTIGItems){Write-LogEntry "STIG Rule ID: SV-78189r5_rule" -Severity 1 -Outhost}
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "PreventOverride" -Type DWord -Value 1 -Force | Out-Null

    If($ApplySTIGItems){Write-LogEntry "STIG Rule ID: SV-78191r5_rule" -Severity 1 -Outhost}
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "PreventOverrideAppRepUnknown" -Type DWord -Value 1 -Force | Out-Null

    If($ApplySTIGItems){Write-LogEntry "STIG Rule ID: SV-78191r5_rule" -Severity 1 -Outhost}
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Type DWord -Value 1 -Force | Out-Null
}


If ($DisableFirewall -or $OptimizeForVDI)
{
    If($ApplySTIGItems){
        Write-LogEntry "STIG Rule ID: SV-77889r1_rule :: Enabling Windows Firewall..." -Severity 1 -Outhost
        netsh advfirewall set allprofiles state on | Out-Null
    }
    Else{
        If($OptimizeForVDI){$prefixmsg = "VDI Optimizations [OSOT ID:59] :: "}
        Write-LogEntry ("Disabling Windows Firewall on all profiles..." -f $prefixmsg) -Severity 1 -Outhost
        netsh advfirewall set allprofiles state off | Out-Null
        Try{
            Get-Service 'mpssvc' | Set-Service -StartupType Disabled -ErrorAction Stop
        }
        Catch [System.Management.Automation.ActionPreferenceStopException]{
            Write-LogEntry ("Unable to Disable Windows Firewall: {0}" -f $_) -Severity 3 -Outhost
        }
    }
}

If ($ApplySTIGItems)
{
    If($OptimizeForVDI){
        Write-LogEntry "Ignoring Stig Rule ID: SV-77813r4_rule :: Enabling TPM..." -Severity 1 -Outhost
        Write-LogEntry "Ignoring Stig Rule ID: SV-91779r3_rule :: Enabling UEFI..." -Severity 1 -Outhost
        Write-LogEntry "Ignoring Stig Rule ID: SV-91781r2_rule :: Enabling SecureBoot..." -Severity 1 -Outhost
        Write-LogEntry "Ignoring Stig Rule ID: SV-78085r5_rule :: Enabling Virtualization Based Security..." -Severity 1 -Outhost
        Write-LogEntry "Ignoring Stig Rule ID: SV-78089r7_rule :: Enabling Credential Guard..." -Severity 1 -Outhost
        Write-LogEntry "Ignoring Stig Rule ID: SV-78093r6_rule :: Enabling Virtualization-based protection of code integrity..." -Severity 1 -Outhost
    }

    Write-LogEntry "STIG Rule ID: SV-78219r1_rule :: Disabling saved password for RDP..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'DisablePasswordSaving' -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78223r1_rule :: Forcing password prompt for RDP connections..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fPromptForPassword' -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78221r1_rule :: Preventing sharing of local drives with RDP Session Hosts..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fDisableCdm' -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78221r1_rule :: Enabling RDP Session Hosts secure RPC communications..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fEncryptRPCTraffic' -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78221r1_rule :: Enabling RDP encryption level to High..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'MinEncryptionLevel' -Value 3 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78207r5_rule :: Enabling hardware security device requirement with Windows Hello..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork' -Name 'RequireSecurityDevice' -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78211r5_rule :: Enabling minimum pin length of six characters or greater..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity' -Name 'MinimumPINLength' -Value 6 -Force | Out-Null

   

    Write-LogEntry "STIG Rule ID: SV-78107r1_rule :: Enabling Audit policy using subcategories..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'SCENoApplyLegacyAuditPolicy' -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78125r1_rule :: Disabling Local accounts with blank passwords..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LimitBlankPasswordUse' -Value 1 -Force | Out-Null
    
    Write-LogEntry "STIG Rule ID: SV-78229r1_rule :: Disabling Anonymous SID/Name translation..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name 'TurnOffAnonymousBlock' -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78235r1_rule :: Disabling Anonymous enumeration of SAM accounts..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymousSAM' -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78239r1_rule :: Disabling Anonymous enumeration of shares..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous' -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-86393r3_rule :: Restricting Remote calls to the Security Account Manager (SAM) to Administrators..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name 'RestrictRemoteSAM' -Type String -Value "O:BAG:BAD:(A;;RC;;;BA)" -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78253r1_rule :: Restricting Services using Local System that use Negotiate when reverting to NTLM authentication..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name 'UseMachineId' -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78245r1_rule :: Disabling prevent anonymous users from having the same rights as the Everyone group..." -Severity 1 -Outhost
    Write-LogEntry "STIG Rule ID: SV-77863r2_rule :: Disabling Let everyone permissions apply to anonymous users..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'EveryoneIncludesAnonymous' -Value 0 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78255r1_rule :: Disabling NTLM from falling back to a Null session..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\System\CurrentControlSet\Control\LSA\MSV1_0' -Name 'allownullsessionfallback' -Value 0 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78295r1_rule :: Disabling requirement for NTLM SSP based clients" -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\System\CurrentControlSet\Control\LSA\MSV1_0' -Name 'NTLMMinClientSec' -Value 0 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78257r1_rule :: Disabling PKU2U authentication using online identities..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\System\CurrentControlSet\Control\LSA\pku2u' -Name 'AllowOnlineID' -Value 0 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78285r1_rule :: Disabling Kerberos encryption types DES and RC4..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' -Type DWord -Name 'SupportedEncryptionTypes' -Value 0x7ffffff8 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78287r1_rule :: Disabling LAN Manager hash of passwords for storage..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name 'NoLMHash' -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID:  SV-78291r1_rule :: Disabling NTLMv2 response only, and to refuse LM and NTLM..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Value 5 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78293r1_rule :: Enabling LDAP client signing level..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' -Name 'LDAPClientIntegrity' -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78129r1_rule :: Enabling Outgoing secure channel traffic encryption or signature..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'RequireSignOrSeal' -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78133r1_rule :: Enabling Outgoing secure channel traffic encryption when possible..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'SealSecureChannel' -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78137r1_rule :: Enabling Outgoing secure channel traffic encryption when possible..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'SignSecureChannel' -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78143r1_rule :: Disabling the ability to reset computer account password..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'DisablePasswordChange' -Value 1 -Force | Out-Null
    
    Write-LogEntry "STIG Rule ID:  SV-78151r1_rule :: Configuring maximum age for machine account password to 30 days..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'MaximumPasswordAge' -Value 30 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78155r1_rule :: Configuring strong session key for machine account password..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'RequireStrongKey' -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78159r2_rule :: Configuring machine inactivity limit must be set to 15 minutes..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'InactivityTimeoutSecs' -Value 900 -Force | Out-Null

    <#
    Write-LogEntry "STIG Rule ID: SV-78165r2_rule :: Configuring legal notice logon notification..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Type String -Name LegalNoticeText -Value ("`
        You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.`
        By using this IS (which includes any device attached to this IS), you consent to the following conditions:`
        -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.`
        -At any time, the USG may inspect and seize data stored on this IS.`
        -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.`
        -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.`
        -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.")`
     -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78171r1_rule :: Configuring legal notice logon title box..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Type String -Name LegalNoticeCaption -Value "DoD Notice and Consent Banner" -Force | Out-Null
    #>

    Write-LogEntry "STIG Rule ID: SV-78177r1_rule :: Disabling Caching of logon credentials" -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Type String -Name 'CachedLogonsCount' -Value 10 -Force | Out-Null
    
    If($OptimizeForVDI){
        Write-LogEntry "STIG Rule ID: SV-78187r1_rule :: Configuring Smart Card removal to Force Logoff..." -Severity 1 -Outhost
        Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Type String -Name 'SCRemoveOption' -Value 2 -Force | Out-Null
    }
    Else{
        Write-LogEntry "STIG Rule ID: SV-78187r1_rule :: Configuring Smart Card removal to Lock Workstation..." -Severity 1 -Outhost
        Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Type String -Name 'SCRemoveOption' -Value 1 -Force | Out-Null
    }

    Write-LogEntry "STIG Rule ID: SV-89399r1_rule :: Disabling Server Message Block (SMB) v1 Service ..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' -Name 'Start' -Value 4 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-89393r1_rule :: Disabling Secondary Logon service" -Severity 1 -Outhost
    Try{
        Get-Service 'seclogon' | Set-Service -StartupType Disabled -ErrorAction Stop
    }
    Catch [System.Management.Automation.ActionPreferenceStopException]{
        Write-LogEntry ("Unable to disable Secondary Login Service: {0}" -f $_) -Severity 3 -Outhost
    }

    Write-LogEntry "STIG Rule ID: SV-83439r2_rule :: Enabling Data Execution Prev ention (DEP) boot configuration" -Severity 1 -Outhost
	Manage-Bde -Protectors -Disable C:
    Start-process bcdedit -ArgumentList '/set nx OptOut' -Wait -NoNewWindow | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78185r1_rule :: Enabling Explorer Data Execution Prevention policy" -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoDataExecutionPrevention' -Value 0 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78181r3_rule :: Enabling File Explorer shell protocol protected mode" -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'PreXPSP2ShellProtocolBehavior' -Value 0 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-89089r2_rule :: Preventing Microsoft Edge browser data from being cleared on exit" -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Privacy' -Name 'ClearBrowsingHistoryOnExit' -Value 0 -Force | Out-Null

    # Disable for CAC card login
    #Write-LogEntry "STIG Rule ID: SV-83445r4_rule :: Disabling Session Kernel Exception Chain Validation..." -Severity 1 -Outhost
    #Set-SystemSettings -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' -Name 'DisableExceptionChainValidation' -Value 0 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78045r1_rule/SV-78049r1_rule :: Setting IPv6 source routing to highest protection..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'DisableIpSourceRouting' -Value 2 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78053r1_rule :: Disabling ICMP redirects from overriding Open Shortest Path First (OSPF) generated routes..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'EnableICMPRedirect' -Value 0 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78057r1_rule :: Disabling NetBIOS name release requests except from WINS servers..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters' -Name 'NoNameReleaseOnDemand' -Value 1 -Force | Out-Null
    
    Write-LogEntry "STIG Rule ID: SV-86387r1_rule :: Disabling WDigest Authentication..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest' -Name 'UseLogonCredential' -Value 0 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-86953r1_rule :: Removing Run as different user contect menu..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Classes\batfile\shell\runasuser' -Name 'SuppressionPolicy' -Value 4096 -Force | Out-Null
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Classes\cmdfile\shell\runasuser' -Name 'SuppressionPolicy' -Value 4096 -Force | Out-Null
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Classes\exefile\shell\runasuser' -Name 'SuppressionPolicy' -Value 4096 -Force | Out-Null
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Classes\mscfile\shell\runasuser' -Name 'SuppressionPolicy' -Value 4096 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78059r2_rule :: Disabling insecure logons to an SMB server..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' -Name 'AllowInsecureGuestAuth' -Value 0 -Force | Out-Null
    
    Write-LogEntry "STIG Rule ID: SV-78193r1_rule :: Enabling SMB packet signing..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\Parameters' -Name 'RequireSecuritySignature' -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78197r1_rule :: Enabling SMB packet signing when possible..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\Parameters' -Name 'EnableSecuritySignature' -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78201r1_rule :: Disabling plain text password on SMB Servers..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\Parameters' -Name 'EnablePlainTextPassword' -Value 0 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-85261r2_rule :: Disabling Server Message Block (SMB) v1 on Server..." -Severity 1 -Outhost
    Try{
        Disable-WindowsOptionalFeature -FeatureName SMB1Protocol -Online -NoRestart -ErrorAction Stop | Out-Null
    }
    Catch [System.Management.Automation.ActionPreferenceStopException]{
        Write-LogEntry ("Unable to remove SMB1Protocol Feature: {0}" -f $_) -Severity 3 -Outhost
    }

    Set-SystemSettings -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1' -Value 0 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78209r1_rule :: Enabling SMB Server packet signing..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanManServer\Parameters' -Name 'RequireSecuritySignature' -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78213r1_rule :: Enabling SMB Srver packet signing when possible..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanManServer\Parameters' -Name 'EnableSecuritySignature' -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78249r1_rule :: Disabling  Anonymous access to Named Pipes and Shares..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanManServer\Parameters' -Name 'RestrictNullSessAccess' -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-86389r1_rule :: Disabling Internet connection sharing..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections' -Name 'NC_ShowSharedAccessUI' -Value 0 -Force | Out-Null
    
    Write-LogEntry "STIG Rule ID: SV-78067r1_rule :: Disabling Internet connection sharing..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' -Name '\\*\NETLOGON' -Type String -Value "RequireMutualAuthentication=1, RequireIntegrity=1" -Force | Out-Null
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' -Name '\\*\SYSVOL' -Type String -Value "RequireMutualAuthentication=1, RequireIntegrity=1" -Force | Out-Null
    
    Write-LogEntry "STIG Rule ID: SV-89087r1_rule :: Enabling prioritize ECC Curves with longer key lengths..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -Name 'EccCurves' -Type MultiString -Value "NistP384 NistP256" -Force | Out-Null
    
    Write-LogEntry "STIG Rule ID: SV-78071r2_rule :: Limiting simultaneous connections to the Internet or a Windows domain..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy' -Name 'fMinimizeConnections' -Value 1 -Force | Out-Null
    
    Write-LogEntry "STIG Rule ID: SV-78075r1_rule :: Limiting simultaneous connections to the Internet or a Windows domain..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy' -Name 'fBlockNonDomain' -Value 1 -Force | Out-Null
   
    Write-LogEntry "STIG Rule ID: SV-83409r1_rule :: Enabling event logging for command line ..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Force | Out-Null
	
    Write-LogEntry "STIG Rule ID: SV-89373r1_rule :: Enabling Remote host allows delegation of non-exportable credentials..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' -Name 'AllowProtectedCreds' -Value 1 -Force | Out-Null
    
    Write-LogEntry "STIG Rule ID: SV-78097r1_rule :: Disabling Early Launch Antimalware, Boot-Start Driver Initialization Policy..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch' -Name 'DriverLoadPolicy' -Value 8 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78099r1_rule :: Enabling Group Policy objects reprocessing..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}' -Name 'NoGPOListChanges' -Value 0 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78105r1_rule :: Disablng Downloading print driver packages over HTTP..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' -Name 'DisableWebPnPDownload' -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78111r1_rule :: Disablng Web publishing and online ordering wizards..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoWebServices' -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78113r1_rule :: Disablng Printing over HTTP..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' -Name 'DisableHTTPPrinting' -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78117r1_rule :: Enabling device authentication using certificates if possible..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' -Name 'DevicePKInitEnabled' -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78119r1_rule :: Disabling network selection user interface (UI) on the logon screen..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'DontDisplayNetworkSelectionUI' -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78123r1_rule :: Disabling local user enumerating..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnumerateLocalUsers' -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78135r1_rule :: Enabling users must be prompted for a password on resume from sleep (on battery)..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51' -Name 'DCSettingIndex' -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78139r1_rule :: Enabling users must be prompted for a password on resume from sleep (on battery)..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51' -Name 'ACSettingIndex' -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78141r1_rule :: Disabling Solicited Remote Assistance..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fAllowToGetHelp' -Value 0 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78147r1_rule :: Disabling Unauthenticated RPC clients..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc' -Name 'RestrictRemoteClients' -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78149r2_rule :: Disabling Microsoft accounts for modern style apps..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'MSAOptional' -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78167r3_rule :: Enabling enhanced anti-spoofing for facial recognition..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures' -Name 'EnhancedAntiSpoofing' -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-96853r1_rule :: Preventing certificate error overrides in Microsoft Edge..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Internet Settings' -Name 'PreventCertErrorOverrides' -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78195r4_rule :: Disabling InPrivate browsing in Microsoft Edge..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main' -Name 'AllowInPrivate' -Value 0 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78195r4_rule :: Disabling password manager in Microsoft Edge..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main' -Name 'FormSuggest Passwords' -Type String -Value "no" -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78233r1_rule :: Disabling attachments from RSS feeds..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds' -Name 'DisableEnclosureDownload' -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78237r1_rule :: Disabling Basic authentication to RSS feeds..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds' -Name 'AllowBasicAuthInClear' -Value 0 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78241r1_rule :: Disabling indexing of encrypted files..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowIndexingEncryptedStoresOrItems' -Value 0 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-77811r1_rule :: Disabling changing installation options for users..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'EnableUserControl' -Value 0 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-77815r1_rule :: Disabling Windows Installer installation with elevated privileges..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -Value 0 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-77819r1_rule :: Enabling notification if a web-based program attempts to install..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'SafeForScripting' -Value 0 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-77823r1_rule :: Disabling Automatically signing in the last interactive user after a system-initiated restart..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DisableAutomaticRestartSignOn' -Value 0 -Force | Out-Null

    # Loop through each profile on the machine
    Foreach ($UserProfile in $UserProfiles) {
        If($UserProfile.SID -ne ".DEFAULT"){
            $objSID = New-Object System.Security.Principal.SecurityIdentifier($UserProfile.SID)
            $UserID = $objSID.Translate([System.Security.Principal.NTAccount])
        }
        Else{
            $UserID = $UserProfile.SID
        }

        # Load User ntuser.dat if it's not already loaded
        If (($ProfileWasLoaded = Test-Path Registry::HKEY_USERS\$($UserProfile.SID)) -eq $false) {
            Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE LOAD HKU\$($UserProfile.SID) $($UserProfile.UserHive)" -Wait -WindowStyle Hidden 
                  
            Write-LogEntry ("STIG Rule ID: SV-78331r2_rule :: Perserving Zone information on attachments for User: {0}" -f $UserID) -Severity 1 -Outhost
            Set-SystemSettings -Path "HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name SaveZoneInformation -Value 2 -Type DWord -ErrorAction SilentlyContinue | Out-Null
        }

        # Unload NTuser.dat        
        If ($ProfileWasLoaded -eq $false) {
            [gc]::Collect()
            Start-Sleep 1
            Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE UNLOAD HKU\$($UserProfile.SID)" -Wait -PassThru  -WindowStyle Hidden | Out-Null
        }
    }

    Write-LogEntry "STIG Rule ID: SV-18420r1_rule :: Disabling File System's 8.3 Name Creation..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name 'NtfsDisable8dot3NameCreation' -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-77873r1_rule :: Disabling Simple TCP/IP Services and Feature..." -Severity 1 -Outhost
    Try{
        Disable-WindowsOptionalFeature -FeatureName SimpleTCP -Online -NoRestart -ErrorAction Stop | Out-Null
    }
    Catch [System.Management.Automation.ActionPreferenceStopException]{
        Write-LogEntry ("Unable to remove Simple TCP/IP Feature: {0}" -f $_) -Severity 3 -Outhost
    }

    Write-LogEntry "STIG Rule ID: SV-77875r1_rule :: Disabling Telnet Client Feature..." -Severity 1 -Outhost
    Try{
        Disable-WindowsOptionalFeature -FeatureName TelnetClient -Online -NoRestart -ErrorAction Stop | Out-Null
    }
    Catch [System.Management.Automation.ActionPreferenceStopException]{
        Write-LogEntry ("Unable to remove TelnetClient: {0}" -f $_) -Severity 3 -Outhost
    }

    Write-LogEntry "STIG Rule ID: SV-85259r1_rule :: Disabling Windows PowerShell 2.0 Feature..." -Severity 1 -Outhost
    Try{
        Disable-WindowsOptionalFeature -FeatureName MicrosoftWindowsPowerShellV2 -Online -NoRestart -ErrorAction Stop | Out-Null
        Disable-WindowsOptionalFeature -FeatureName MicrosoftWindowsPowerShellV2Root -Online -NoRestart -ErrorAction Stop | Out-Null
    }
    Catch [System.Management.Automation.ActionPreferenceStopException]{
        Write-LogEntry ("Unable to remove PowerShellV2 Feature: {0}" -f $_) -Severity 3 -Outhost
    }

    #Write-LogEntry "STIG Rule ID: SV-78069r4_rule :: DoD Root CA certificates must be installed in the Trusted Root Store..." -Severity 1 -Outhost
    #Get-ChildItem -Path Cert:Localmachine\root | Where Subject -Like "*DoD*" | FL Subject, Thumbprint, NotAfter

    #Write-LogEntry "STIG Rule ID: SV-78073r3_rule :: External Root CA certificates must be installed in the Trusted Root Store on unclassified systems..." -Severity 1 -Outhost
    #Get-ChildItem -Path Cert:Localmachine\root | Where Subject -Like "*ECA*" | FL Subject, Thumbprint, NotAfter

    #Write-LogEntry "STIG Rule ID: SV-78077r4_rule :: DoD Interoperability Root CA cross-certificates must be installed in the Untrusted Certificates Store on unclassified systemss..." -Severity 1 -Outhost
    #Get-ChildItem -Path Cert:Localmachine\disallowed | Where {$_.Issuer -Like "*DoD Interoperability*" -and $_.Subject -Like "*DoD*"} | FL Subject, Issuer, Thumbprint, NotAfter
    
    #Write-LogEntry "STIG Rule ID: SV-78079r3_rule :: US DoD CCEB Interoperability Root CA cross-certificates must be installed in the Untrusted Certificates Store on unclassified systems." -Severity 1 -Outhost
    #Get-ChildItem -Path Cert:Localmachine\disallowed | Where Issuer -Like "*CCEB Interoperability*" | FL Subject, Issuer, Thumbprint, NotAfter
    
    #Write-LogEntry "Clearing Session Subsystem's..." -Severity 1 -Outhost
    #Set-SystemSettings -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\SubSystems' -Name 'Optional' -Type MultiString -Value "" -Force | Out-Null

    <#
    Write-LogEntry "Disabling RASMAN PPP Parameters..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SYSTEM\CurrentControlSet\services\RasMan\Parameters' -Name 'DisableSavePassword' -Value 1 -Force | Out-Null
    Set-SystemSettings -Path 'HKLM:\SYSTEM\CurrentControlSet\services\RasMan\Parameters' -Name 'Logging' -Value 1 -Force | Out-Null
    Set-SystemSettings -Path 'HKLM:\SYSTEM\CurrentControlSet\services\RasMan\PPP' -Name 'ForceEncryptedData' -Value 1 -Force | Out-Null
    Set-SystemSettings -Path 'HKLM:\SYSTEM\CurrentControlSet\services\RasMan\PPP' -Name 'ForceEncryptedPassword' -Value 2 -Force | Out-Null
    Set-SystemSettings -Path 'HKLM:\SYSTEM\CurrentControlSet\services\RasMan\PPP' -Name 'SecureVPN' -Value 1 -Force | Out-Null
    #>
}


If($ApplySTIGItems -or $ApplyEMETMitigations)
{
    if ($OSBuildNumber -gt 17763) {
      <#
        Set-ProcessMitigation System -enable DEP
        Set-ProcessMitigation System -enable BottomUp
        Set-ProcessMitigation System -enable ForceRelocateImages
        Set-ProcessMitigation System -enable EnableExportAddressFilter
        Set-ProcessMitigation System -enable EnableExportAddressFilterPlus
        Set-ProcessMitigation System -enable EnableImportAddressFilter
        Set-ProcessMitigation System -enable EnableRopStackPivot
        Set-ProcessMitigation System -enable EnableRopCallerCheck
        Set-ProcessMitigation System -enable EnableRopSimExec
        Set-ProcessMitigation System -enable AllowStoreSignedBinaries
        Set-ProcessMitigation System -enable AllowThreadsToOptOut
        Set-ProcessMitigation System -enable BlockDynamicCode
        Set-ProcessMitigation System -enable BlockLowLabelImageLoads
        Set-ProcessMitigation system -enable BlockRemoteImageLoads
        Set-ProcessMitigation system -enable CFG
        Set-ProcessMitigation System -enable DisableExtensionPoints
        Set-ProcessMitigation System -enable DisableNonSystemFonts
        Set-ProcessMitigation System -enable DisableWin32kSystemCalls
        Set-ProcessMitigation System -enable DisallowChildProcessCreation
        Set-ProcessMitigation System -enable EmulateAtlThunks
        Set-ProcessMitigation System -enable EnforceModuleDependencySigning
        Set-ProcessMitigation System -enable HighEntropy
        Set-ProcessMitigation System -enable MicrosoftSignedOnly
        Set-ProcessMitigation System -enable PreferSystem32
        Set-ProcessMitigation System -enable RequireInfo
        Set-ProcessMitigation system -enable SEHOP
        Set-ProcessMitigation system -enable StrictHandle
        Set-ProcessMitigation system -enable SuppressExports
        Set-ProcessMitigation system -enable TerminateOnError 
    #>

        Write-LogEntry "STIG Rule ID: SV-91787r3_rule :: Enabling Data Execution Prevention (DEP) for exploit protection..." -Severity 1 -Outhost
        If((Get-ProcessMitigation -System).DEP.Enable -eq "OFF"){
              Set-Processmitigation -System -Enable DEP
        }

        Write-LogEntry "STIG Rule ID: SV-91791r4_rule :: Enabling (Bottom-Up ASLR) for exploit protection..." -Severity 1 -Outhost
        If((Get-ProcessMitigation -System).ASLR.BottomUp -eq "OFF"){
            Set-Processmitigation -System -Enable BottomUp
        }

        Write-LogEntry "STIG Rule ID: SV-91793r3_rule :: Enabling Control flow guard (CFG) for exploit protection..." -Severity 1 -Outhost
        If((Get-ProcessMitigation -System).CFG.Enable -eq "OFF"){
            Set-Processmitigation -System -Enable CFG
        }

        Write-LogEntry "STIG Rule ID: SV-91797r3_rule :: Enabling Validate exception chains (SEHOP) for exploit protection..." -Severity 1 -Outhost
        If((Get-ProcessMitigation -System).CFG.Enable -eq "OFF"){
            Set-Processmitigation -System -Enable SEHOP
        }

        Write-LogEntry "STIG Rule ID: SV-91799r3_rule :: Enabling Validate heap integrity for exploit protection..." -Severity 1 -Outhost
        If((Get-ProcessMitigation -System).CFG.Enable -eq "OFF"){
            Set-Processmitigation -System -Enable TerminateOnError
        }


        #DEP: ON
        $ApplicationMitigationsDep = @{
            "SV-91885r2_rule:"="Acrobat.exe"
            "SV-91887r2_rule"="AcroRd32.exe"
            "SV-91897r2_rule"="EXCEL.EXE"
            "SV-91901r2_rule"="firefox.exe"
            "SV-91891r2_rule"="chrome.exe"
            "SV-91905r2_rule"="FLTLDR.EXE"
            "SV-91909r2_rule"="GROOVE.EXE"
            "SV-91913r2_rule"="iexplore.exe"
            "SV-91917r2_rule"="INFOPATH.EXE"
            "SV-91919r2_rule Part 1"="java.exe"
            "SV-91919r2_rule Part 2"="javaw.exe"
            "SV-91919r2_rule Part 3"="javaws.exe"
            "SV-91923r2_rule"="lync.exe"
            "SV-91927r2_rule"="MSACCESS.EXE"
            "SV-91929r2_rule"="MSPUB.EXE"
            "SV-91935r2_rule"="OIS.EXE"
            "SV-91931r2_rule"="OneDrive.exe"
            "SV-91939r2_rule"="OUTLOOK.EXE"
            "SV-91941r2_rule"="plugin-container.exe"
            "SV-91943r2_rule"="POWERPNT.EXE"
            "SV-91945r2_rule"="PPTVIEW.EXE"
            "SV-91951r2_rule"="VISIO.EXE"
            "SV-91955r2_rule"="VPREVIEW.EXE"
            "SV-91959r2_rule"="WINWORD.EXE"
            "SV-91963r2_rule"="wmplayer.exe"
            "SV-91965r2_rule"="wordpad.exe"
        }

        #ASLR: BottomUp: ON
        $ApplicationMitigationsASLR_BU = @{
            "SV-91885r2_rule:"="Acrobat.exe"
            "SV-91887r2_rule"="AcroRd32.exe"
            "SV-91901r2_rule"="firefox.exe"
            "SV-91913r2_rule"="iexplore.exe"
        }

        #ASLR: ForceRelocateImages: ON
        $ApplicationMitigationsASLR_FRI = @{
            "SV-91885r2_rule:"="Acrobat.exe"
            "SV-91887r2_rule"="AcroRd32.exe"
            "SV-91901r2_rule"="firefox.exe"
            "SV-91897r2_rule"="EXCEL.EXE"
            "SV-91913r2_rule"="iexplore.exe"
            "SV-91917r2_rule"="INFOPATH.EXE"
            "SV-91923r2_rule"="lync.exe"
            "SV-91927r2_rule"="MSACCESS.EXE"
            "SV-91929r2_rule"="MSPUB.EXE"
            "SV-91931r2_rule"="OneDrive.exe"
            "SV-91939r2_rule"="OUTLOOK.EXE"
            "SV-91943r2_rule"="POWERPNT.EXE"
            "SV-91945r2_rule"="PPTVIEW.EXE"
            "SV-91951r2_rule"="VISIO.EXE"
            "SV-91955r2_rule"="VPREVIEW.EXE"
            "SV-91959r2_rule"="WINWORD.EXE"
        }

        #BlockRemoteImageLoads: ON
        $ApplicationMitigationsImageLoad = @{
            "SV-91905r2_rule"="FLTLDR.EXE"
             "SV-91909r2_rule"="GROOVE.EXE"
             "SV-91931r2_rule"="OneDrive.exe"
        }

        #Payload All options: ON
        $ApplicationMitigationsAllPayload = @{
            "SV-91885r2_rule:"="Acrobat.exe"
            "SV-91887r2_rule"="AcroRd32.exe"
            "SV-91891r2_rule"="chrome.exe"
            "SV-91901r2_rule"="firefox.exe"
            "SV-91897r2_rule"="EXCEL.EXE"
            "SV-91905r2_rule"="FLTLDR.EXE"
            "SV-91909r2_rule"="GROOVE.EXE"
            "SV-91913r2_rule"="iexplore.exe"
            "SV-91917r2_rule"="INFOPATH.EXE"
            "SV-91919r2_rule Part 1"="java.exe"
            "SV-91919r2_rule Part 2"="javaw.exe"
            "SV-91919r2_rule Part 3"="javaws.exe"
            "SV-91923r2_rule"="lync.exe"
            "SV-91927r2_rule"="MSACCESS.EXE"
            "SV-91929r2_rule"="MSPUB.EXE"
            "SV-91935r2_rule"="OIS.EXE"
            "SV-91931r2_rule"="OneDrive.exe"
            "SV-91939r2_rule"="OUTLOOK.EXE"
            "SV-91941r2_rule"="plugin-container.exe"
            "SV-91943r2_rule"="POWERPNT.EXE"
            "SV-91945r2_rule"="PPTVIEW.EXE"
            "SV-91951r2_rule"="VISIO.EXE"
            "SV-91955r2_rule"="VPREVIEW.EXE"
            "SV-91959r2_rule"="WINWORD.EXE"
            "SV-91965r2_rule"="wordpad.exe"
        }

        #EnableRopStackPivot: ON
        #EnableRopCallerCheck: ON
        #EnableRopSimExec: ON
        $ApplicationMitigationsPayloadROP = @{
            "SV-91963r2_rule"="wmplayer.exe"
        }


        #DisallowChildProcessCreation: ON
        $ApplicationMitigationsChild = @{
            "SV-91905r2_rule"="FLTLDR.EXE"
             "SV-91909r2_rule"="GROOVE.EXE"
        }

        Foreach ($Mitigation in $ApplicationMitigationsDep.GetEnumerator()){
            Write-LogEntry ("STIG Rule ID: {0}: Enabling Exploit Protection mitigation [DEP : ON] for {1}..." -f $Mitigation.Key,$Mitigation.Value) -Severity 1 -Outhost
            If(-not(Get-ProcessMitigation -Name $Mitigation.Value)){
                Set-ProcessMitigation $Mitigation.Value -enable DEP
            }
        }

        Foreach ($Mitigation in $ApplicationMitigationsASLR_BU.GetEnumerator()){
            Write-LogEntry ("STIG Rule ID: {0}: Enabling Exploit Protection mitigation [ASLR:BottomUp : ON] for {1}..." -f $Mitigation.Key,$Mitigation.Value) -Severity 1 -Outhost
            If(-not(Get-ProcessMitigation -Name $Mitigation.Value)){
                Set-ProcessMitigation $Mitigation.Value -enable BottomUp
            }
        }

        Foreach ($Mitigation in $ApplicationMitigationsASLR_FRI.GetEnumerator()){
            Write-LogEntry ("STIG Rule ID: {0}: Enabling Exploit Protection mitigation [ASLR:ForceRelocateImages : ON] for {1}..." -f $Mitigation.Key,$Mitigation.Value) -Severity 1 -Outhost
            If(-not(Get-ProcessMitigation -Name $Mitigation.Value)){
                Set-ProcessMitigation $Mitigation.Value -enable ForceRelocateImages
            }
        }

        Foreach ($Mitigation in $ApplicationMitigationsImageLoad.GetEnumerator()){
            Write-LogEntry ("STIG Rule ID: {0}: Enabling Exploit Protection mitigation [BlockRemoteImageLoads : ON] for {1}..." -f $Mitigation.Key,$Mitigation.Value) -Severity 1 -Outhost
            If(-not(Get-ProcessMitigation -Name $Mitigation.Value)){
                Set-ProcessMitigation $Mitigation.Value -enable BlockRemoteImageLoads
            }
        }

        Foreach ($Mitigation in $ApplicationMitigationsAllPayload.GetEnumerator()){
            Write-LogEntry ("STIG Rule ID: {0}: Enabling Exploit Protection mitigation[Payload:Export & Rop* : ON] options for {1}..." -f $Mitigation.Key,$Mitigation.Value) -Severity 1 -Outhost
            If(-not(Get-ProcessMitigation -Name $Mitigation.Value)){
                Set-ProcessMitigation $Mitigation.Value -enable EnableExportAddressFilter
                Set-ProcessMitigation $Mitigation.Value -enable EnableExportAddressFilterPlus
                Set-ProcessMitigation $Mitigation.Value -enable EnableImportAddressFilter
                Set-ProcessMitigation $Mitigation.Value -enable EnableRopStackPivot
                Set-ProcessMitigation $Mitigation.Value -enable EnableRopCallerCheck
                Set-ProcessMitigation $Mitigation.Value -enable EnableRopSimExec
            }
        }

        Foreach ($Mitigation in $ApplicationMitigationsPayloadROP.GetEnumerator()){
            Write-LogEntry ("STIG Rule ID: {0}: Enabling Exploit Protection mitigation [Payload:Rop* : ON] for {1}..." -f $Mitigation.Key,$Mitigation.Value) -Severity 1 -Outhost
            If(-not(Get-ProcessMitigation -Name $Mitigation.Value)){
                Set-ProcessMitigation $Mitigation.Value -enable EnableRopStackPivot
                Set-ProcessMitigation $Mitigation.Value -enable EnableRopCallerCheck
                Set-ProcessMitigation $Mitigation.Value -enable EnableRopSimExec
            }
        }

        Foreach ($Mitigation in $ApplicationMitigationsChild.GetEnumerator()){
            Write-LogEntry ("STIG Rule ID: {0}: Enabling Exploit Protection mitigation [DisallowChildProcessCreation : ON] for {1}..." -f $Mitigation.Key,$Mitigation.Value) -Severity 1 -Outhost
            If(-not(Get-ProcessMitigation -Name $Mitigation.Value)){
                Set-ProcessMitigation $Mitigation.Value -enable DisallowChildProcessCreation
            }
        }
    }
    Else{
        Write-LogEntry ("Unable to process mitigations due to OS version [{0}]. Please upgrade or install EMET" -f $OSBuildNumber) -Severity 1 -Outhost      
    }
}