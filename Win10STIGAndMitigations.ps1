<#	
	.NOTES
	===========================================================================
     Author:   Richard Tracy
	 Filename:     	            Win10STIGAndMitigations.ps1
     Last Updated:              03/08/2019
     Thanks to:                 unixuser011,W4RH4WK
	===========================================================================
	.DESCRIPTION
        Applies DISA stigs for Windows 10 
        Utilizes MDT/SCCM TaskSequence variables:
           _SMSTSLogPath

    . PARAM
        Configurable using custom variables in MDT/SCCM:
            CFG_ApplySTIGItems
            CFG_ApplyEMETMitigations
            CFG_OptimizeForVDI
    
    . EXAMPLE
        #Copy this to MDT CustomSettings.ini
        Properties=CFG_ApplySTIGItems,CFG_ApplyEMETMitigations,CFG_OptimizeForVDI

        Then add each option to a priority specifically for your use, like:
        [Default]
        CFG_ApplySTIGItems=True
        CFG_ApplyEMETMitigations=True
        CFG_OptimizeForVDI=False

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

        Write-LogEntry ("Setting power plan to `"{0}`"" -f $PreferredPlan) -Source ${CmdletName} -Outhost

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
            If($VerbosePreference){Write-LogEntry ("powercfg $params") -Source ${CmdletName} -Outhost}
            $results = $process.Create("powercfg $params")
        }
        Catch{
            throw $_.Exception.Message
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
$DefaultProfile.SID = "DEFAULT"
$DefaultProfile.Userhive = "$env:systemdrive\Users\Default\NTuser.dat"

#Add it to the UserProfile list
$UserProfiles = @()
$UserProfiles += $AllProfiles
$UserProfiles += $DefaultProfile

#get current users sid
[string]$CurrentSID = (gwmi win32_useraccount | ? {$_.name -eq $env:username}).SID


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
[boolean]$ApplySTIGItems = $false
[boolean]$ApplyEMETMitigations = $false
[boolean]$OptimizeForVDI = $false

# When running in Tasksequence and configureation exists, use that instead
If($tsenv){
    If($tsenv:CFG_ApplySTIGItems){[boolean]$ApplySTIGItems = [boolean]::Parse($tsenv.Value("CFG_ApplySTIGItems"))}
    If($tsenv:CFG_ApplyEMETMitigations){[boolean]$ApplyEMETMitigations = [boolean]::Parse($tsenv.Value("CFG_ApplyEMETMitigations"))}
    If($tsenv:CFG_OptimizeForVDI){[boolean]$OptimizeForVDI = [boolean]::Parse($tsenv.Value("CFG_OptimizeForVDI"))} 
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

If($ApplySTIGItems )
{
    If($OptimizeForVDI){
        Write-LogEntry "Ignoring Stig Rule ID: SV-77813r4_rule :: Enabling TPM..." -Severity 1 -Outhost
        Write-LogEntry "Ignoring Stig Rule ID: SV-91779r3_rule :: Enabling UEFI..." -Severity 1 -Outhost
        Write-LogEntry "Ignoring Stig Rule ID: SV-91781r2_rule :: Enabling SecureBoot..." -Severity 1 -Outhost
        Write-LogEntry "Ignoring Stig Rule ID: SV-78085r5_rule :: Enabling Virtualization Based Security..." -Severity 1 -Outhost
        Write-LogEntry "Ignoring Stig Rule ID: SV-78089r7_rule :: Enabling Credential Guard..." -Severity 1 -Outhost
        Write-LogEntry "Ignoring Stig Rule ID: SV-78093r6_rule :: Enabling Virtualization-based protection of code integrity..." -Severity 1 -Outhost
    }

    Write-LogEntry "STIG Rule ID: SV-83411r1_rule :: Enabling Powershell Script Block Logging..." -Severity 1 -Outhost
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Type DWord -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78039r1_rule :: Disabling Autorun for local volumes..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name NoAutoplayfornonVolume -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78161r1_rule :: Disabling Autorun for local machine..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name NoAutorun -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78163r1_rule :: Disabling Autorun for local drive..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name NoDriveTypeAutoRun -Type DWord -Value 0xFF -Force | Out-Null

    Write-LogEntry "Disabling Bluetooth..." -Severity 1 -Outhost
    Config-Bluetooth -DeviceStatus Off

    Write-LogEntry "TIG Rule ID: SV-78301r1_rule :: Enabling FIPS Algorithm Policy" -Severity 1 -Outhost
    Set-SystemSettings -Path "HKLM\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy" -Name "Enabled" -Type DWord -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-96851r1_rule :: Disabling personal accounts for OneDrive synchronization..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'DisablePersonalSync' -Type DWord -Value '1' -Force | Out-Null

    # Privacy and mitigaton settings
    # See: https://docs.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services
    Write-LogEntry "STIG Rule ID: SV-78039r1_rule :: Privacy Mitigations :: Disabling Microsoft accounts for modern style apps..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'MSAOptional' -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78035r1_rule :: Privacy Mitigations :: Disabling camera usage on user's lock screen..." -Severity 1 -Outhost
	Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name 'NoLockScreenCamera' -Type DWord -Value '1' -Force | Out-Null
	
    Write-LogEntry "STIG Rule ID: SV-78039r1_rule :: Privacy Mitigations :: Disabling lock screen slideshow..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name 'NoLockScreenSlideshow' -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-86395r2_rule :: Privacy Mitigations :: Disabling Consumer Features..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableWindowsConsumerFeatures' -Type DWord -Value '1' -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-89091r1_rule :: Privacy Mitigations :: Disabling Xbox features..." -Severity 1 -Outhost
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0 -Force | Out-Null

	Write-LogEntry ("STIG Rule ID: SV-78173r3_rule :: Privacy Mitigations :: {0}Disabling telemetry..." -f $prefixmsg) -Outhost
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

    Write-LogEntry "STIG Rule ID: SV-96859r1_rule: Disabling access the Insider build controls in the Advanced Options.." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'LimitEnhancedDiagnosticDataWindowsAnalytics' -Type DWord -Value 1 -Force | Out-Null  

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

    Write-LogEntry "STIG Rule ID: SV-78309r1_rule :: Enabling UAC prompt administrators for consent on the secure desktop..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -Type DWord -Value 2 -Force | Out-Null
    
    Write-LogEntry "STIG Rule ID: SV-78311r1_rule :: Disabling elevation UAC prompt User for consent on the secure desktop..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorUser -Type DWord -Value 0 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78315r1_rule :: Enabling elevation UAC prompt detect application installations and prompt for elevation..." -Severity 1 -Outhost
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableInstallerDetection" -Type DWord -Value 1 -Force | Out-Null
    
    Write-LogEntry "STIG Rule ID: SV-78315r1_rule :: Enabling elevation UAC UIAccess applications that are installed in secure locations..." -Severity 1 -Outhost
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableSecureUAIPaths" -Type DWord -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78321r1_rule :: Enabling Enable virtualize file and registry write failures to per-user locations.." -Severity 1 -Outhost
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableVirtualization" -Type DWord -Value 1 -Force | Out-Null
        
    Write-LogEntry "STIG Rule ID: SV-78319r1_rule :: Enabling UAC for all administrators..." -Severity 1 -Outhost
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Type DWord -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78087r2_rule :: FIlter Local administrator account privileged tokens..." -Severity 1 -Outhost}
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Type DWord -Value 0 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78307r1_rule :: Enabling User Account Control approval mode..." -Severity 1 -Outhost
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "FilterAdministratorToken" -Type DWord -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78307r1_rule :: Disabling enumerating elevated administator accounts..." -Severity 1 -Outhost
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" -Name "EnumerateAdministrators" -Type DWord -Value 0 -Force | Out-Null

    If($ApplySTIGItems -eq $false){
        Write-LogEntry "Enable All credential or consent prompting will occur on the interactive user's desktop..." -Severity 1 -Outhost
        Set-SystemSettings -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1 -Force | Out-Null

        Write-LogEntry "Enforce cryptographic signatures on any interactive application that requests elevation of privilege..." -Severity 1 -Outhost
        Set-SystemSettings -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ValidateAdminCodeSignatures" -Type DWord -Value 0 -Force | Out-Null
    }

    If(!$OptimizeForVDI)
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

    
    Write-LogEntry "STIG Rule ID: SV-80171r3_rule :: Disable P2P WIndows Updates..." -Severity 1 -Outhost
    Set-SystemSettings -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config' -Name DownloadMode -Type DWord -Value '0' -Force | Out-Null

    Write-LogEntry ("STIG Rule ID: SV-78329r1_rule :: Disabling Toast notifications to the lock screen for user: {0}" -f $UserID) -Severity 1 -Outhost
    Set-SystemSettings -Path "HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name NoToastApplicationNotificationOnLockScreen -Type DWord -Value '1' -Force | Out-Null


	switch($SetSmartScreenFilter){
    'Off'  {$value = 0;$label = "to Disable"}
    'User'  {$value = 1;$label = "to Warning Users"}
    'admin' {$value = 2;$label = "to Require Admin approval"}
    default {$value = 1;$label = "to Warning Users"}
    }
    Write-LogEntry "Configuring Smart Screen Filte :: Configuring Smart Screen Filter $label..." -Severity 1 -Outhost}
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Type DWord -Value $value -Force | Out-Null
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "ShellSmartScreenLevel" -Type String -Value "Block" -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78189r5_rule :: Enabling Smart Screen Filter warnings on Edge..." -Severity 1 -Outhost
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "PreventOverride" -Type DWord -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78191r5_rule :: Prevent bypassing SmartScreen Filter warnings..." -Severity 1 -Outhost
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "PreventOverrideAppRepUnknown" -Type DWord -Value 1 -Force | Out-Null

    Write-LogEntry "STIG Rule ID: SV-78191r5_rule :: Enabling SmartScreen filter for Microsoft Edge" -Severity 1 -Outhost
    Set-SystemSettings -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Type DWord -Value 1 -Force | Out-Null


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

    $p = 1
    # Loop through each profile on the machine
    Foreach ($UserProfile in $UserProfiles) {
        If($UserProfile.SID -eq "DEFAULT"){
            $UserID = $UserProfile.SID
        }
        Else{
            $objSID = New-Object System.Security.Principal.SecurityIdentifier($UserProfile.SID)
            $UserID = $objSID.Translate([System.Security.Principal.NTAccount])  
        }
        Write-Progress -Id 1 -Activity ("User Profile [{0} of {1}]" -f $p,$UserProfiles.count) -Status "Profile: $UserID" -CurrentOperation ("Loading Hive [{0}]" -f $UserProfile.UserHive) -PercentComplete ($p / $UserProfiles.count * 100)


        #loadhive if not mounted
        If (($HiveLoaded = Test-Path Registry::HKEY_USERS\$($UserProfile.SID)) -eq $false) {
            Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE LOAD HKU\$($UserProfile.SID) $($UserProfile.UserHive)" -Wait -WindowStyle Hidden
            $HiveLoaded = $true
        }

        If ($HiveLoaded -eq $true) {
            Write-LogEntry ("STIG Rule ID: SV-78331r2_rule :: Perserving Zone information on attachments for User: {0}" -f $UserID) -Severity 1 -Outhost
            Set-SystemSettings -Path "HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name SaveZoneInformation -Value 2 -Type DWord -ErrorAction SilentlyContinue | Out-Null
            Start-Sleep 1
        }

        #remove any leftove reg process and then remove hive
        If ($HiveLoaded -eq $true) {
            [gc]::Collect()
            Start-Sleep 1
            Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE UNLOAD HKU\$($UserProfile.SID)" -Wait -PassThru  -WindowStyle Hidden | Out-Null
        }
        $p++
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