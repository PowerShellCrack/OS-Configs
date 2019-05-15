<#	
	.SYNOPSIS
        Applies DISA stigs for Windows 10 
    
    .DESCRIPTION
        Applies DISA stigs for Windows 10 
        Utilizes LGPO.exe to apply group policy item where neceassary.
        Utilizes MDT/SCCM TaskSequence property control
        Configurable using custom variables in MDT/SCCM

    .PARAM
        '// Global Settings
        DisableSTIGScript
        CFG_UseLGPOForConfigs
        LGPOPath
        
        '// VDI Preference
        CFG_OptimizeForVDI

        '// STIG Settings
        CFG_ApplySTIGItems
        CFG_ApplyEMETMitigations
        

    .NOTES
        Author:         Richard Tracy
        Last Update:    05/10/2019
        Version:        2.1.1
           
    .EXAMPLE
        #Copy this to MDT CustomSettings.ini
        Properties=CFG_UseLGPOForConfigs,LGPOPath,CFG_OptimizeForVDI,CFG_ApplySTIGItems,CFG_ApplyEMETMitigations

        #Then add each option to a priority specifically for your use, like:
        [Default]
        CFG_OptimizeForVDI=False
        CFG_ApplySTIGItems=True
        CFG_ApplyEMETMitigations=True
        
        #Add script to task sequence

    .LOGS
        2.1.2 - May 15, 2019 - Added Get-ScriptPpath function to support VScode and ISE; fixed Set-UserSettings   
        2.1.1 - May 10, 2019 - reorganized controls in categories
        2.1.0 - Apr 17, 2019 - added Set-UserSetting function
        2.0.0 - Apr 12, 2019 - added more Windows 10 settings check
        1.5.0 - Mar 29, 2019 - added more options from theVDIGuys script
        1.1.5 - Mar 13, 2019 - Fixed mitigations script and removed null outputs
        1.1.0 - Mar 12, 2019 - Updatd LGPO process as global variable and added param for it
        1.0.0 - Nov 20, 2018 - split from config script 
#> 


##*===========================================================================
##* FUNCTIONS
##*===========================================================================
Function Test-IsISE {
    # try...catch accounts for:
    # Set-StrictMode -Version latest
        try {    
            return $psISE -ne $null;
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
        #$root = $PSScriptRoot
        $MyInvocation.MyCommand.Path
    }
}

Function Import-SMSTSENV{
    ## Get the name of this function
    [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
    
    try{
        # Create an object to access the task sequence environment
        $Script:tsenv = New-Object -COMObject Microsoft.SMS.TSEnvironment 
        #test if variables exist
        $tsenv.GetVariables()  #| % { Write-Output "$ScriptName - $_ = $($tsenv.Value($_))" }
    }
    catch{
        If(${CmdletName}){$prefix = "${CmdletName} ::" }Else{$prefix = "" }
        Write-Warning ("{0}Task Sequence environment not detected. Running in stand-alone mode." -f $prefix)
        
        #set variable to null
        $Script:tsenv = $null
    }
    Finally{
        #set global Logpath
        if ($tsenv){
            #grab the progress UI
            $Script:TSProgressUi = New-Object -ComObject Microsoft.SMS.TSProgressUI

            # Query the environment to get an existing variable
            # Set a variable for the task sequence log path
            #$Global:Logpath = $tsenv.Value("LogPath")
            $Global:Logpath = $tsenv.Value("_SMSTSLogPath")

            # Or, convert all of the variables currently in the environment to PowerShell variables
            $tsenv.GetVariables() | % { Set-Variable -Name "$_" -Value "$($tsenv.Value($_))" }
        }
        Else{
            $Global:Logpath = $env:TEMP
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
            'Binary' {$LGPORegType = 'BINARY'}
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
    [CmdletBinding()]
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
    [string]$Type,

    [Parameter(Mandatory=$false,Position=4,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
    [ValidateSet('CurrentUser','AllUsers','Default')]
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

    }
    Process
    { 
        $RegKeyHive = ($RegPath).Split('\')[0].Replace('Registry::','').Replace(':','')

        #check if hive is local machine.
        If($RegKeyHive -match "HKEY_LOCAL_MACHINE|HKLM|HKCR"){
            Write-LogEntry "Registry path is not a user path. Use Set-SystemSetting cmdlet"
            return
        }
        #check if hive is user hive
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
            #since a hive was not found, check if its specified

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
            Write-LogEntry "User registry key not found or specified. Unable to continue..." -Severity 3
            return

        }

        #If user profile variable doesn't exist, build one
        If(!$Global:UserProfiles){
            # Get each user profile SID and Path to the profile
            $AllProfiles = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" | Where {$_.PSChildName -match "S-1-5-21-(\d+-?){4}$" } | Select-Object @{Name="SID"; Expression={$_.PSChildName}}, @{Name="UserHive";Expression={"$($_.ProfileImagePath)\NTuser.dat"}}

            # Add in the .DEFAULT User Profile
            $DefaultProfile = "" | Select-Object SID, UserHive
            $DefaultProfile.SID = "DEFAULT"
            $DefaultProfile.Userhive = "$env:systemdrive\Users\Default\NTuser.dat"

            #Add it to the UserProfile list
            $Global:UserProfiles = @()
            $Global:UserProfiles += $AllProfiles
            $Global:UserProfiles += $DefaultProfile

            #get current users sid
            [string]$CurrentSID = (gwmi win32_useraccount | ? {$_.name -eq $env:username}).SID
        }

        #overwrite Hive if specified
        If($ApplyTo){
            Switch($ApplyTo){
                'AllUsers' {$RegHive = "HKEY_USERS"; $ProfileList = $Global:UserProfiles}
                'CurrentUser'   {$RegHive = "HKCU" ; $ProfileList = $Global:UserProfiles }
                'Default'       {$RegHive = "HKU"  ; $ProfileList = 'Default'}
            }
        }
        Else{
            $RegHive = $RegKeyHive
        }
               
        If($RegHive -eq "HKEY_USERS"){

            $p = 1
            # Loop through each profile on the machine
            Foreach ($UserProfile in $ProfileList) {
                
                Try{
                    $objSID = New-Object System.Security.Principal.SecurityIdentifier($UserProfile.SID)
                    $UserID = $objSID.Translate([System.Security.Principal.NTAccount]) 
                }
                Catch{
                    $UserID = $UserProfile.SID
                }

                If($Message){Show-ProgressStatus -Message $Message -SubMessage ("for user profile ({0} of {1})" -f $p,$ProfileList.count) -Step $p -MaxStep $ProfileList.count}

                #loadhive if not mounted
                If (($HiveLoaded = Test-Path Registry::HKEY_USERS\$($UserProfile.SID)) -eq $false) {
                    Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE LOAD HKU\$($UserProfile.SID) $($UserProfile.UserHive)" -Wait -WindowStyle Hidden
                    $HiveLoaded = $true
                }

                If ($HiveLoaded -eq $true) {   
                    If($Message){Write-LogEntry ("{0} for User [{1}]..." -f $Message,$UserID)}
                    If($Remove){
                        Remove-ItemProperty "$RegHive\$($UserProfile.SID)\$RegKeyPath" -Name $Name -ErrorAction SilentlyContinue | Out-Null  
                    }
                    Else{
                        Set-SystemSetting -Path "$RegHive\$($UserProfile.SID)\$RegKeyPath" -Name $Name -Type $Type -Value $Value -Force:$Force -TryLGPO:$TryLGPO
                    }
                }

                #remove any leftove reg process and then remove hive
                If ($HiveLoaded -eq $true) {
                    [gc]::Collect()
                    Start-Sleep -Seconds 3
                    Start-Process -FilePath "CMD.EXE" -ArgumentList "/C REG.EXE UNLOAD HKU\$($UserProfile.SID)" -Wait -PassThru -WindowStyle Hidden | Out-Null
                }
                $p++
            }
        }
        Else{
            If($Message){Write-LogEntry ("{0} for [{1}]..." -f $Message,$ApplyTo)}
            If($Remove){
                Remove-ItemProperty "$RegHive\$($UserProfile.SID)\$RegKeyPath" -Name $Name -ErrorAction SilentlyContinue | Out-Null  
            }
            Else{
                Set-SystemSetting -Path "$RegHive\$RegKeyPath" -Name $Name -Type $Type -Value $Value -Force:$Force -TryLGPO:$TryLGPO
            }
        }

    }
    End {
       If($Message){Show-ProgressStatus -Message "Completed $Message"  -Step 1 -MaxStep 1}
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


Import-SMSTSENV

#Create Paths
$ToolsPath = Join-Path $scriptDirectory -ChildPath 'Tools'
$AdditionalScriptsPath = Join-Path $scriptDirectory -ChildPath 'Scripts'
$ModulesPath = Join-Path -Path $scriptDirectory -ChildPath 'PSModules'
$BinPath = Join-Path -Path $scriptDirectory -ChildPath 'Bin'
$FilesPath = Join-Path -Path $scriptDirectory -ChildPath 'Files'

#if running in a tasksequence; apply user settings to all user profiles (use ApplyTo param cmdlet Set-UserSettings )
If($tsenv){$Global:ApplyToProfiles = 'AllUsers'}Else{$Global:ApplyToProfiles = 'CurrentUser'}
If($tsenv -and -not($psISE)){$Global:OutToHost = $false}Else{$Global:OutToHost = $true}

#grab all Show-ProgressStatus commands in script and count them
$script:Maxsteps = ([System.Management.Automation.PsParser]::Tokenize((gc "$PSScriptRoot\$($MyInvocation.MyCommand.Name)"), [ref]$null) | where { $_.Type -eq 'Command' -and $_.Content -eq 'Show-ProgressStatus' }).Count
#set counter to one
$stepCounter = 1

$Global:Verbose = $false
If($PSBoundParameters.ContainsKey('Debug') -or $PSBoundParameters.ContainsKey('Verbose')){
    $Global:Verbose = $PsBoundParameters.Get_Item('Verbose')
    $VerbosePreference = 'Continue'
    Write-Verbose ("[{0}] [{1}] :: VERBOSE IS ENABLED." -f (Format-DatePrefix),$scriptName)
}
Else{
    $VerbosePreference = 'SilentlyContinue'
}

If(!$LogPath){$LogPath = $env:TEMP}
[string]$FileName = $scriptBaseName +'.log'
$Global:LogFilePath = Join-Path $LogPath -ChildPath $FileName
Write-Host "Using log file: $LogFilePath"

##*===========================================================================
##* DEFAULTS: Configurations are hardcoded here (change values if needed)
##*===========================================================================
#// Global Settings
[boolean]$DisableScript = $false
[string]$Global:LGPOPath = "$ToolsPath\LGPO\LGPO.exe"
[boolean]$UseLGPO = $true

#// VDI Preference
[boolean]$OptimizeForVDI = $false

#// STIG Settings
[boolean]$ApplySTIGItems = $false
[boolean]$ApplyEMETMitigations = $false



# When running in Tasksequence and configureation exists, use that instead
If($tsenv){
    #// Global Settings
    If($tsenv:CFG_DisableSTIGScript){[boolean]$DisableScript = [boolean]::Parse($tsenv.Value("CFG_DisableSTIGScript"))}
    If($tsenv:CFG_UseLGPOForConfigs){[boolean]$UseLGPO = [boolean]::Parse($tsenv.Value("CFG_UseLGPOForConfigs"))}
    If($tsenv:LGPOPath){[string]$Global:LGPOPath = $tsenv.Value("LGPOPath")}
    
    #// VDI Preference
    If($tsenv:CFG_OptimizeForVDI){[boolean]$OptimizeForVDI = [boolean]::Parse($tsenv.Value("CFG_OptimizeForVDI"))} 
    
    #// STIG Settings
    If($tsenv:CFG_ApplySTIGItems){[boolean]$ApplySTIGItems = [boolean]::Parse($tsenv.Value("CFG_ApplySTIGItems"))}
    If($tsenv:CFG_ApplyEMETMitigations){[boolean]$ApplyEMETMitigations = [boolean]::Parse($tsenv.Value("CFG_ApplyEMETMitigations"))}
}

# Ultimately disable the entire script. This is useful for testing and using one task sequences with many rules
If($DisableScript){
    Write-LogEntry "Script is disabled!" -Outhost
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
    $UseLGPO = $false
}

##*===========================================================================
##* MAIN
##*===========================================================================

If($ApplySTIGItems )
{
    
    Show-ProgressStatus -Message "Applying STIG Items..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost

    If($OptimizeForVDI){
        Write-LogEntry "Ignoring Stig Rule ID: SV-77813r4_rule :: Enabling TPM..." -Outhost
        Write-LogEntry "Ignoring Stig Rule ID: SV-91779r3_rule :: Enabling UEFI..." -Outhost
        Write-LogEntry "Ignoring Stig Rule ID: SV-91781r2_rule :: Enabling SecureBoot..." -Outhost
        Write-LogEntry "Ignoring Stig Rule ID: SV-78085r5_rule :: Enabling Virtualization Based Security..." -Outhost
        Write-LogEntry "Ignoring Stig Rule ID: SV-78089r7_rule :: Enabling Credential Guard..." -Outhost
        Write-LogEntry "Ignoring Stig Rule ID: SV-78093r6_rule :: Enabling Virtualization-based protection of code integrity..." -Outhost
    }

    Show-ProgressStatus -Message "STIG Rule ID: SV-83411r1_rule :: Enabling Powershell Script Block Logging..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Type DWord -Value 1 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "Applying STIG Items..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost

    Show-ProgressStatus -Message "STIG Rule ID: SV-78039r1_rule :: Disabling Autorun for local volumes..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name NoAutoplayfornonVolume -Value 1 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-78161r1_rule :: Disabling Autorun for local machine..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name NoAutorun -Value 1 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-78163r1_rule :: Disabling Autorun for local drive..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name NoDriveTypeAutoRun -Type DWord -Value 0xFF -Force -TryLGPO:$true

    Show-ProgressStatus -Message "Disabling Bluetooth..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Config-Bluetooth -DeviceStatus Off

    Show-ProgressStatus -Message "TIG Rule ID: SV-78301r1_rule :: Enabling FIPS Algorithm Policy" -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path "HKLM\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy" -Name Enabled -Type DWord -Value 1 -Force

    Show-ProgressStatus -Message "STIG Rule ID: SV-96851r1_rule :: Disabling personal accounts for OneDrive synchronization..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'DisablePersonalSync' -Type DWord -Value '1' -Force -TryLGPO:$true

    # Privacy and mitigaton settings
    # See: https://docs.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services
    Show-ProgressStatus -Message "STIG Rule ID: SV-78039r1_rule :: Privacy Mitigations :: Disabling Microsoft accounts for modern style apps..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'MSAOptional' -Value 1 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-78035r1_rule :: Privacy Mitigations :: Disabling camera usage on user's lock screen..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name 'NoLockScreenCamera' -Type DWord -Value '1' -Force -TryLGPO:$true
	
    Show-ProgressStatus -Message "STIG Rule ID: SV-78039r1_rule :: Privacy Mitigations :: Disabling lock screen slideshow..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name 'NoLockScreenSlideshow' -Value 1 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-86395r2_rule :: Privacy Mitigations :: Disabling Consumer Features..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableWindowsConsumerFeatures' -Type DWord -Value '1' -Force -TryLGPO:$true| Out-Null

    Show-ProgressStatus -Message "STIG Rule ID: SV-89091r1_rule :: Privacy Mitigations :: Disabling Xbox features..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0 -Force -TryLGPO:$true

	Write-LogEntry ("STIG Rule ID: SV-78173r3_rule :: Privacy Mitigations :: {0}Disabling telemetry..." -f $prefixmsg) -Outhost
	If ($OsCaption -like "*Enterprise*" -or $OsCaption -like "*Education*"){
		$TelemetryLevel = "0"
		Write-LogEntry "Privacy Mitigations :: Enterprise edition detected. Supported telemetry level: Security." -Outhost
	}
	Else{
		$TelemetryLevel = "1"
		Write-LogEntry "Privacy Mitigations :: Lowest supported telemetry level: Basic." -Outhost
	}
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value $TelemetryLevel -Force -TryLGPO:$true
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value $TelemetryLevel -Force
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value $TelemetryLevel -Force

    Show-ProgressStatus -Message "STIG Rule ID: SV-96859r1_rule: Disabling access the Insider build controls in the Advanced Options.." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'LimitEnhancedDiagnosticDataWindowsAnalytics' -Type DWord -Value 1 -Force -TryLGPO:$true  

    Show-ProgressStatus -Message "STIG Rule ID: SV-77825r1_rule :: Disabling Basic Authentication for WinRM" -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowBasic" -Type DWord -Value 0 -Force -TryLGPO:$true
    Set-SystemSetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowBasic" -Type DWord -Value 0 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-77829r1_rule :: Disabling unencrypted traffic for WinRM" -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowUnencryptedTraffic" -Type DWord -Value 0 -Force -TryLGPO:$true
    Set-SystemSetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowUnencryptedTraffic" -Type DWord -Value 0 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-77831r1_rule :: Disabling Digest authentication for WinRM" -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowDigest" -Type DWord -Value 0 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-77831r1_rule :: Disabling Digest authentication for WinRM" -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "DisableRunAs" -Type DWord -Value 1 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-78309r1_rule :: Enabling UAC prompt administrators for consent on the secure desktop..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -Type DWord -Value 2 -Force -TryLGPO:$true
    
    Show-ProgressStatus -Message "STIG Rule ID: SV-78311r1_rule :: Disabling elevation UAC prompt User for consent on the secure desktop..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorUser -Type DWord -Value 0 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-78315r1_rule :: Enabling elevation UAC prompt detect application installations and prompt for elevation..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableInstallerDetection" -Type DWord -Value 1 -Force -TryLGPO:$true
    
    Show-ProgressStatus -Message "STIG Rule ID: SV-78315r1_rule :: Enabling elevation UAC UIAccess applications that are installed in secure locations..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableSecureUAIPaths" -Type DWord -Value 1 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-78321r1_rule :: Enabling Enable virtualize file and registry write failures to per-user locations.." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableVirtualization" -Type DWord -Value 1 -Force -TryLGPO:$true
        
    Show-ProgressStatus -Message "STIG Rule ID: SV-78319r1_rule :: Enabling UAC for all administrators..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Type DWord -Value 1 -Force

    Show-ProgressStatus -Message "STIG Rule ID: SV-78087r2_rule :: FIlter Local administrator account privileged tokens..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Type DWord -Value 0 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-78307r1_rule :: Enabling User Account Control approval mode..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "FilterAdministratorToken" -Type DWord -Value 1 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-78307r1_rule :: Disabling enumerating elevated administator accounts..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" -Name "EnumerateAdministrators" -Type DWord -Value 0 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "Enable All credential or consent prompting will occur on the interactive user's desktop..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "Enforce cryptographic signatures on any interactive application that requests elevation of privilege..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ValidateAdminCodeSignatures" -Type DWord -Value 0 -Force -TryLGPO:$true


    If(!$OptimizeForVDI)
    {
    
        Write-LogEntry "STIG Rule ID: SV-78085r5_rule :: Enabling Virtualization Based Security..." -Outhost
    
        if ($OSBuildNumber -gt 14393) {
            try {
                # For version older than Windows 10 version 1607 (build 14939), enable required Windows Features for Credential Guard
                Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-HyperVisor -Online -All -LimitAccess -NoRestart -ErrorAction Stop | Out-Null
                Write-LogEntry "Successfully enabled Microsoft-Hyper-V-HyperVisor feature" -Outhost
            }
            catch [System.Exception] {
                Write-LogEntry ("An error occured when enabling Microsoft-Hyper-V-HyperVisor. Error: -f $_") -Severity 3 -Outhost
            }

            try {
                # For version older than Windows 10 version 1607 (build 14939), add the IsolatedUserMode feature as well
                Enable-WindowsOptionalFeature -FeatureName IsolatedUserMode -Online -All -LimitAccess -NoRestart -ErrorAction Stop | Out-Null
                Write-LogEntry "Successfully enabled IsolatedUserMode feature" -Outhost
            }
            catch [System.Exception] {
                Write-LogEntry ("An error occured when enabling IsolatedUserMode. Error: -f $_") -Severity 3 -Outhost
            }
        }

        Write-LogEntry "Enabling Windows Defender Application Guard..." -Outhost
        Enable-WindowsOptionalFeature -online -FeatureName "Windows-Defender-ApplicationGuard" -NoRestart -WarningAction SilentlyContinue | Out-Null
    
        Show-ProgressStatus -Message "STIG Rule ID: SV-78093r6_rule :: Enabling Virtualization-based protection of code integrity..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
        #https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/enable-virtualization-based-protection-of-code-integrity
        Set-SystemSetting -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name RequirePlatformSecurityFeatures -Type DWord -Value 1 -Force
        Set-SystemSetting -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name EnableVirtualizationBasedSecurity -Type DWord -Value 1 -Force
        Set-SystemSetting -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name Locked -Type DWord -Value 0 -Force
        If ($OSBuildNumber -lt 14393) {
            Set-SystemSetting -Path "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name HypervisorEnforcedCodeIntegrity -Type DWord -Value 1 -Force
        }
        Set-SystemSetting -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name Enabled -Type DWord -Value 1 -Force
        Set-SystemSetting -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name Locked -Type DWord -Value 0 -Force

        Show-ProgressStatus -Message "STIG Rule ID: SV-78089r7_rule :: Enabling Credential Guard on domain-joined systems..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
        Set-SystemSetting -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LsaCfgFlags -Type DWord -Value 1 -Force   
    
        $DeviceGuardProperty = Get-CimInstance –ClassName Win32_DeviceGuard –Namespace root\Microsoft\Windows\DeviceGuard
        If($DeviceGuardProperty.VirtualizationBasedSecurityStatus -eq 1){
            Write-LogEntry ("Successfully enabled Credential Guard, version: {0}" -f $DeviceGuardProperty.Version)-Outhost   
        }
        Else{
            Write-LogEntry "Unable to enabled Credential Guard, may not be supported on this model, trying a differnet way" -Severity 2 -Outhost
            . $AdditionalScriptsPath\DG_Readiness_Tool_v3.6.ps1 -Enable -CG
        }
        Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue
    }

    Show-ProgressStatus -Message "STIG Rule ID: SV-80171r3_rule :: Disable P2P WIndows Updates..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config' -Name DownloadMode -Type DWord -Value '0' -Force

	switch($SetSmartScreenFilter){
        'Off'   {$value = 0;$label = "to Disable"}
        'User'  {$value = 1;$label = "to Warning Users"}
        'admin' {$value = 2;$label = "to Require Admin approval"}
        default {$value = 1;$label = "to Warning Users"}
    }
    Show-ProgressStatus -Message "Configuring Smart Screen Filte :: Configuring Smart Screen Filter $label..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Type DWord -Value $value -Force -TryLGPO:$true
    Set-SystemSetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "ShellSmartScreenLevel" -Type String -Value "Block" -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-78189r5_rule :: Enabling Smart Screen Filter warnings on Edge..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "PreventOverride" -Type DWord -Value 1 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-78191r5_rule :: Prevent bypassing SmartScreen Filter warnings..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "PreventOverrideAppRepUnknown" -Type DWord -Value 1 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-78191r5_rule :: Enabling SmartScreen filter for Microsoft Edge" -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Type DWord -Value 1 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-78219r1_rule :: Disabling saved password for RDP..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'DisablePasswordSaving' -Value 1 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-78223r1_rule :: Forcing password prompt for RDP connections..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fPromptForPassword' -Value 1 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-78221r1_rule :: Preventing sharing of local drives with RDP Session Hosts..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fDisableCdm' -Value 1 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-78221r1_rule :: Enabling RDP Session Hosts secure RPC communications..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fEncryptRPCTraffic' -Value 1 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-78221r1_rule :: Enabling RDP encryption level to High..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'MinEncryptionLevel' -Value 3 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-78207r5_rule :: Enabling hardware security device requirement with Windows Hello..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork' -Name 'RequireSecurityDevice' -Value 1 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-78211r5_rule :: Enabling minimum pin length of six characters or greater..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity' -Name 'MinimumPINLength' -Value 6 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-78107r1_rule :: Enabling Audit policy using subcategories..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'SCENoApplyLegacyAuditPolicy' -Value 1 -Force

    Show-ProgressStatus -Message "STIG Rule ID: SV-78125r1_rule :: Disabling Local accounts with blank passwords..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LimitBlankPasswordUse' -Value 1 -Force
    
    Show-ProgressStatus -Message "STIG Rule ID: SV-78229r1_rule :: Disabling Anonymous SID/Name translation..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name 'TurnOffAnonymousBlock' -Value 1 -Force

    Show-ProgressStatus -Message "STIG Rule ID: SV-78235r1_rule :: Disabling Anonymous enumeration of SAM accounts..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymousSAM' -Value 1 -Force

    Show-ProgressStatus -Message "STIG Rule ID: SV-78239r1_rule :: Disabling Anonymous enumeration of shares..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous' -Value 1 -Force

    Show-ProgressStatus -Message "STIG Rule ID: SV-86393r3_rule :: Restricting Remote calls to the Security Account Manager (SAM) to Administrators..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name 'RestrictRemoteSAM' -Type String -Value "O:BAG:BAD:(A;;RC;;;BA)" -Force

    Show-ProgressStatus -Message "STIG Rule ID: SV-78253r1_rule :: Restricting Services using Local System that use Negotiate when reverting to NTLM authentication..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name 'UseMachineId' -Value 1 -Force

    Show-ProgressStatus -Message "STIG Rule ID: SV-78245r1_rule :: Disabling prevent anonymous users from having the same rights as the Everyone group..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Show-ProgressStatus -Message "STIG Rule ID: SV-77863r2_rule :: Disabling Let everyone permissions apply to anonymous users..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'EveryoneIncludesAnonymous' -Value 0 -Force

    Show-ProgressStatus -Message "STIG Rule ID: SV-78255r1_rule :: Disabling NTLM from falling back to a Null session..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\System\CurrentControlSet\Control\LSA\MSV1_0' -Name 'allownullsessionfallback' -Value 0 -Force

    Show-ProgressStatus -Message "STIG Rule ID: SV-78295r1_rule :: Disabling requirement for NTLM SSP based clients" -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\System\CurrentControlSet\Control\LSA\MSV1_0' -Name 'NTLMMinClientSec' -Value 0 -Force

    Show-ProgressStatus -Message "STIG Rule ID: SV-78257r1_rule :: Disabling PKU2U authentication using online identities..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\System\CurrentControlSet\Control\LSA\pku2u' -Name 'AllowOnlineID' -Value 0 -Force

    Show-ProgressStatus -Message "STIG Rule ID: SV-78285r1_rule :: Disabling Kerberos encryption types DES and RC4..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' -Type DWord -Name 'SupportedEncryptionTypes' -Value 0x7ffffff8 -Force

    Show-ProgressStatus -Message "STIG Rule ID: SV-78287r1_rule :: Disabling LAN Manager hash of passwords for storage..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name 'NoLMHash' -Value 1 -Force

    Show-ProgressStatus -Message "STIG Rule ID:  SV-78291r1_rule :: Disabling NTLMv2 response only, and to refuse LM and NTLM..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\System\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Value 5 -Force

    Show-ProgressStatus -Message "STIG Rule ID: SV-78293r1_rule :: Enabling LDAP client signing level..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' -Name 'LDAPClientIntegrity' -Value 1 -Force

    Show-ProgressStatus -Message "STIG Rule ID: SV-78129r1_rule :: Enabling Outgoing secure channel traffic encryption or signature..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'RequireSignOrSeal' -Value 1 -Force

    Show-ProgressStatus -Message "STIG Rule ID: SV-78133r1_rule :: Enabling Outgoing secure channel traffic encryption when possible..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'SealSecureChannel' -Value 1 -Force

    Show-ProgressStatus -Message "STIG Rule ID: SV-78137r1_rule :: Enabling Outgoing secure channel traffic encryption when possible..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'SignSecureChannel' -Value 1 -Force

    Show-ProgressStatus -Message "STIG Rule ID: SV-78143r1_rule :: Disabling the ability to reset computer account password..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'DisablePasswordChange' -Value 1 -Force
    
    Show-ProgressStatus -Message "STIG Rule ID:  SV-78151r1_rule :: Configuring maximum age for machine account password to 30 days..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'MaximumPasswordAge' -Value 30 -Force

    Show-ProgressStatus -Message "STIG Rule ID: SV-78155r1_rule :: Configuring strong session key for machine account password..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'RequireStrongKey' -Value 1 -Force

    Show-ProgressStatus -Message "STIG Rule ID: SV-78159r2_rule :: Configuring machine inactivity limit must be set to 15 minutes..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'InactivityTimeoutSecs' -Value 900 -Force -TryLGPO:$true

    <#
    Show-ProgressStatus -Message "STIG Rule ID: SV-78165r2_rule :: Configuring legal notice logon notification..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Type String -Name LegalNoticeText -Value ("`
        You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.`
        By using this IS (which includes any device attached to this IS), you consent to the following conditions:`
        -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.`
        -At any time, the USG may inspect and seize data stored on this IS.`
        -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.`
        -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.`
        -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.")`
     -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-78171r1_rule :: Configuring legal notice logon title box..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Type String -Name LegalNoticeCaption -Value "DoD Notice and Consent Banner" -Force -TryLGPO:$true
    #>

    Show-ProgressStatus -Message "STIG Rule ID: SV-78177r1_rule :: Disabling Caching of logon credentials" -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Type String -Name 'CachedLogonsCount' -Value 10 -Force
    
    If($OptimizeForVDI){
        Write-LogEntry "STIG Rule ID: SV-78187r1_rule :: Configuring Smart Card removal to Force Logoff..." -Outhost
        Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Type String -Name 'SCRemoveOption' -Value 2 -Force
    }
    Else{
        Write-LogEntry "STIG Rule ID: SV-78187r1_rule :: Configuring Smart Card removal to Lock Workstation..." -Outhost
        Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Type String -Name 'SCRemoveOption' -Value 1 -Force
    }

    Show-ProgressStatus -Message "STIG Rule ID: SV-89399r1_rule :: Disabling Server Message Block (SMB) v1 Service ..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' -Name 'Start' -Value 4 -Force

    Show-ProgressStatus -Message "STIG Rule ID: SV-89393r1_rule :: Disabling Secondary Logon service" -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Try{
        Get-Service 'seclogon' | Set-Service -StartupType Disabled -ErrorAction Stop
    }
    Catch [System.Management.Automation.ActionPreferenceStopException]{
        Write-LogEntry ("Unable to disable Secondary Login Service: {0}" -f $_) -Severity 3 -Outhost
    }

    Show-ProgressStatus -Message "STIG Rule ID: SV-83439r2_rule :: Enabling Data Execution Prev ention (DEP) boot configuration" -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
	Manage-Bde -Protectors -Disable C:
    Start-process bcdedit -ArgumentList '/set nx OptOut' -Wait -NoNewWindow | Out-Null

    Show-ProgressStatus -Message "STIG Rule ID: SV-78185r1_rule :: Enabling Explorer Data Execution Prevention policy" -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoDataExecutionPrevention' -Value 0 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-78181r3_rule :: Enabling File Explorer shell protocol protected mode" -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'PreXPSP2ShellProtocolBehavior' -Value 0 -Force

    Show-ProgressStatus -Message "STIG Rule ID: SV-89089r2_rule :: Preventing Microsoft Edge browser data from being cleared on exit" -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Privacy' -Name 'ClearBrowsingHistoryOnExit' -Value 0 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-83445r4_rule :: Disabling Session Kernel Exception Chain Validation..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' -Name 'DisableExceptionChainValidation' -Value 0 -Force

    Show-ProgressStatus -Message "STIG Rule ID: SV-78045r1_rule/SV-78049r1_rule :: Setting IPv6 source routing to highest protection..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'DisableIpSourceRouting' -Value 2 -Force

    Show-ProgressStatus -Message "STIG Rule ID: SV-78053r1_rule :: Disabling ICMP redirects from overriding Open Shortest Path First (OSPF) generated routes..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'EnableICMPRedirect' -Value 0 -Force

    Show-ProgressStatus -Message "STIG Rule ID: SV-78057r1_rule :: Disabling NetBIOS name release requests except from WINS servers..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters' -Name 'NoNameReleaseOnDemand' -Value 1 -Force
    
    Show-ProgressStatus -Message "STIG Rule ID: SV-86387r1_rule :: Disabling WDigest Authentication..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest' -Name 'UseLogonCredential' -Value 0 -Force

    Show-ProgressStatus -Message "STIG Rule ID: SV-86953r1_rule :: Removing Run as different user contect menu..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Classes\batfile\shell\runasuser' -Name 'SuppressionPolicy' -Value 4096 -Force
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Classes\cmdfile\shell\runasuser' -Name 'SuppressionPolicy' -Value 4096 -Force
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Classes\exefile\shell\runasuser' -Name 'SuppressionPolicy' -Value 4096 -Force
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Classes\mscfile\shell\runasuser' -Name 'SuppressionPolicy' -Value 4096 -Force

    Show-ProgressStatus -Message "STIG Rule ID: SV-78059r2_rule :: Disabling insecure logons to an SMB server..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' -Name 'AllowInsecureGuestAuth' -Value 0 -Force -TryLGPO:$true
    
    Show-ProgressStatus -Message "STIG Rule ID: SV-78193r1_rule :: Enabling SMB packet signing..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\Parameters' -Name 'RequireSecuritySignature' -Value 1 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-78197r1_rule :: Enabling SMB packet signing when possible..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\Parameters' -Name 'EnableSecuritySignature' -Value 1 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-78201r1_rule :: Disabling plain text password on SMB Servers..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\Parameters' -Name 'EnablePlainTextPassword' -Value 0 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-85261r2_rule :: Disabling Server Message Block (SMB) v1 on Server..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Try{
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
        #Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force
        Disable-WindowsOptionalFeature -FeatureName SMB1Protocol -Online -NoRestart -ErrorAction Stop | Out-Null
    }
    Catch [System.Management.Automation.ActionPreferenceStopException]{
        Write-LogEntry ("Unable to remove SMB1Protocol Feature: {0}" -f $_) -Severity 3 -Outhost
    }

    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1' -Value 0 -Force

    Show-ProgressStatus -Message "STIG Rule ID: SV-78209r1_rule :: Enabling SMB Server packet signing..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanManServer\Parameters' -Name 'RequireSecuritySignature' -Value 1 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-78213r1_rule :: Enabling SMB Srver packet signing when possible..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanManServer\Parameters' -Name 'EnableSecuritySignature' -Value 1 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-78249r1_rule :: Disabling  Anonymous access to Named Pipes and Shares..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanManServer\Parameters' -Name 'RestrictNullSessAccess' -Value 1 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-86389r1_rule :: Disabling Internet connection sharing..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections' -Name 'NC_ShowSharedAccessUI' -Value 0 -Force -TryLGPO:$true
    
    Show-ProgressStatus -Message "STIG Rule ID: SV-78067r1_rule :: Disabling Internet connection sharing..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' -Name '\\*\NETLOGON' -Type String -Value "RequireMutualAuthentication=1, RequireIntegrity=1" -Force -TryLGPO:$true
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths' -Name '\\*\SYSVOL' -Type String -Value "RequireMutualAuthentication=1, RequireIntegrity=1" -Force -TryLGPO:$true
    
    Show-ProgressStatus -Message "STIG Rule ID: SV-89087r1_rule :: Enabling prioritize ECC Curves with longer key lengths..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002' -Name 'EccCurves' -Type MultiString -Value "NistP384 NistP256" -Force -TryLGPO:$true
    
    Show-ProgressStatus -Message "STIG Rule ID: SV-78071r2_rule :: Limiting simultaneous connections to the Internet or a Windows domain..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy' -Name 'fMinimizeConnections' -Value 1 -Force -TryLGPO:$true
    
    Show-ProgressStatus -Message "STIG Rule ID: SV-78075r1_rule :: Limiting simultaneous connections to the Internet or a Windows domain..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy' -Name 'fBlockNonDomain' -Value 1 -Force -TryLGPO:$true
   
    Show-ProgressStatus -Message "STIG Rule ID: SV-83409r1_rule :: Enabling event logging for command line ..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Force -TryLGPO:$true
	
    Show-ProgressStatus -Message "STIG Rule ID: SV-89373r1_rule :: Enabling Remote host allows delegation of non-exportable credentials..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' -Name 'AllowProtectedCreds' -Value 1 -Force -TryLGPO:$true
    
    Show-ProgressStatus -Message "STIG Rule ID: SV-78097r1_rule :: Disabling Early Launch Antimalware, Boot-Start Driver Initialization Policy..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch' -Name 'DriverLoadPolicy' -Value 8 -Force

    Show-ProgressStatus -Message "STIG Rule ID: SV-78099r1_rule :: Enabling Group Policy objects reprocessing..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}' -Name 'NoGPOListChanges' -Value 0 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-78105r1_rule :: Disablng Downloading print driver packages over HTTP..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' -Name 'DisableWebPnPDownload' -Value 1 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-78111r1_rule :: Disablng Web publishing and online ordering wizards..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoWebServices' -Value 1 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-78113r1_rule :: Disablng Printing over HTTP..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' -Name 'DisableHTTPPrinting' -Value 1 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-78117r1_rule :: Enabling device authentication using certificates if possible..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' -Name 'DevicePKInitEnabled' -Value 1 -Force

    Show-ProgressStatus -Message "STIG Rule ID: SV-78119r1_rule :: Disabling network selection user interface (UI) on the logon screen..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'DontDisplayNetworkSelectionUI' -Value 1 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-78123r1_rule :: Disabling local user enumerating..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnumerateLocalUsers' -Value 1 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-78135r1_rule :: Enabling users must be prompted for a password on resume from sleep (on battery)..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51' -Name 'DCSettingIndex' -Value 1 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-78139r1_rule :: Enabling users must be prompted for a password on resume from sleep (on battery)..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51' -Name 'ACSettingIndex' -Value 1 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-78141r1_rule :: Disabling Solicited Remote Assistance..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fAllowToGetHelp' -Value 0 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-78147r1_rule :: Disabling Unauthenticated RPC clients..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc' -Name 'RestrictRemoteClients' -Value 1 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-78149r2_rule :: Disabling Microsoft accounts for modern style apps..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'MSAOptional' -Value 1 -Force

    Show-ProgressStatus -Message "STIG Rule ID: SV-78167r3_rule :: Enabling enhanced anti-spoofing for facial recognition..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures' -Name 'EnhancedAntiSpoofing' -Value 1 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-96853r1_rule :: Preventing certificate error overrides in Microsoft Edge..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Internet Settings' -Name 'PreventCertErrorOverrides' -Value 1 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-78195r4_rule :: Disabling InPrivate browsing in Microsoft Edge..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main' -Name 'AllowInPrivate' -Value 0 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-78195r4_rule :: Disabling password manager in Microsoft Edge..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main' -Name 'FormSuggest Passwords' -Type String -Value "no" -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-78233r1_rule :: Disabling attachments from RSS feeds..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds' -Name 'DisableEnclosureDownload' -Value 1 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-78237r1_rule :: Disabling Basic authentication to RSS feeds..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds' -Name 'AllowBasicAuthInClear' -Value 0 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-78241r1_rule :: Disabling indexing of encrypted files..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowIndexingEncryptedStoresOrItems' -Value 0 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-77811r1_rule :: Disabling changing installation options for users..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'EnableUserControl' -Value 0 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-77815r1_rule :: Disabling Windows Installer installation with elevated privileges..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -Value 0 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-77819r1_rule :: Enabling notification if a web-based program attempts to install..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'SafeForScripting' -Value 0 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-77823r1_rule :: Disabling Automatically signing in the last interactive user after a system-initiated restart..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DisableAutomaticRestartSignOn' -Value 0 -Force

    Set-UserSetting -Message "STIG Rule ID: SV-78331r2_rule :: Perserving Zone information on attachments" -Path "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name SaveZoneInformation -Value 2 -Type DWord -Force -TryLGPO:$true

    Show-ProgressStatus -Message "STIG Rule ID: SV-18420r1_rule :: Disabling File System's 8.3 Name Creation..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name 'NtfsDisable8dot3NameCreation' -Value 1 -Force

    Show-ProgressStatus -Message "STIG Rule ID: SV-77873r1_rule :: Disabling Simple TCP/IP Services and Feature..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Try{
        Disable-WindowsOptionalFeature -FeatureName SimpleTCP -Online -NoRestart -ErrorAction Stop | Out-Null
    }
    Catch [System.Management.Automation.ActionPreferenceStopException]{
        Write-LogEntry ("Unable to remove Simple TCP/IP Feature: {0}" -f $_) -Severity 3 -Outhost
    }

    Show-ProgressStatus -Message "STIG Rule ID: SV-77875r1_rule :: Disabling Telnet Client Feature..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Try{
        Disable-WindowsOptionalFeature -FeatureName TelnetClient -Online -NoRestart -ErrorAction Stop | Out-Null
    }
    Catch [System.Management.Automation.ActionPreferenceStopException]{
        Write-LogEntry ("Unable to remove TelnetClient: {0}" -f $_) -Severity 3 -Outhost
    }

    Show-ProgressStatus -Message "STIG Rule ID: SV-85259r1_rule :: Disabling Windows PowerShell 2.0 Feature..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Try{
        Disable-WindowsOptionalFeature -FeatureName MicrosoftWindowsPowerShellV2 -Online -NoRestart -ErrorAction Stop | Out-Null
        Disable-WindowsOptionalFeature -FeatureName MicrosoftWindowsPowerShellV2Root -Online -NoRestart -ErrorAction Stop | Out-Null
    }
    Catch [System.Management.Automation.ActionPreferenceStopException]{
        Write-LogEntry ("Unable to remove PowerShellV2 Feature: {0}" -f $_) -Severity 3 -Outhost
    }

    #Show-ProgressStatus -Message "STIG Rule ID: SV-78069r4_rule :: DoD Root CA certificates must be installed in the Trusted Root Store..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    #Get-ChildItem -Path Cert:Localmachine\root | Where Subject -Like "*DoD*" | FL Subject, Thumbprint, NotAfter

    #Show-ProgressStatus -Message "STIG Rule ID: SV-78073r3_rule :: External Root CA certificates must be installed in the Trusted Root Store on unclassified systems..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    #Get-ChildItem -Path Cert:Localmachine\root | Where Subject -Like "*ECA*" | FL Subject, Thumbprint, NotAfter

    #Show-ProgressStatus -Message "STIG Rule ID: SV-78077r4_rule :: DoD Interoperability Root CA cross-certificates must be installed in the Untrusted Certificates Store on unclassified systemss..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    #Get-ChildItem -Path Cert:Localmachine\disallowed | Where {$_.Issuer -Like "*DoD Interoperability*" -and $_.Subject -Like "*DoD*"} | FL Subject, Issuer, Thumbprint, NotAfter
    
    #Show-ProgressStatus -Message "STIG Rule ID: SV-78079r3_rule :: US DoD CCEB Interoperability Root CA cross-certificates must be installed in the Untrusted Certificates Store on unclassified systems." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    #Get-ChildItem -Path Cert:Localmachine\disallowed | Where Issuer -Like "*CCEB Interoperability*" | FL Subject, Issuer, Thumbprint, NotAfter
    
    #Show-ProgressStatus -Message "Clearing Session Subsystem's..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    #Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\SubSystems' -Name 'Optional' -Type MultiString -Value "" -Force

    <#
    Show-ProgressStatus -Message "Disabling RASMAN PPP Parameters..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\services\RasMan\Parameters' -Name 'DisableSavePassword' -Value 1 -Force
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\services\RasMan\Parameters' -Name 'Logging' -Value 1 -Force
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\services\RasMan\PPP' -Name 'ForceEncryptedData' -Value 1 -Force
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\services\RasMan\PPP' -Name 'ForceEncryptedPassword' -Value 2 -Force
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\services\RasMan\PPP' -Name 'SecureVPN' -Value 1 -Force
    #>

    Show-ProgressStatus -Message "Disabling LLMNR..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
	Set-SystemSetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type DWord -Value 0 -Force -TryLGPO:$true
    
    Show-ProgressStatus -Message "Disabling NCSI active test..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
	Set-SystemSetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" -Name "NoActiveProbe" -Type DWord -Value 1 -Force -TryLGPO:$true

	Show-ProgressStatus -Message "Setting unknown networks profile to private..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
	Set-SystemSetting -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Name "Category" -Type DWord -Value 1 -Force -TryLGPO:$true

    Show-ProgressStatus -Message "Disabling automatic installation of network devices..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -Type DWord -Value 0
}
Else{$stepCounter++}


If($ApplyEMETMitigations)
{
    Show-ProgressStatus -Message "Enabling Controlled Folder Access..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue
    
    Show-ProgressStatus -Message "Disabling Controlled Folder Access..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
	Set-MpPreference -EnableControlledFolderAccess Disabled -ErrorAction SilentlyContinue
    
    Show-ProgressStatus -Message "Enabling Core Isolation Memory Integrity..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    Set-SystemSetting -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Type DWord -Value 1 -Force

    Show-ProgressStatus -Message "Enabling Windows Defender Application Guard..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
	Enable-WindowsOptionalFeature -online -FeatureName "Windows-Defender-ApplicationGuard" -NoRestart -WarningAction SilentlyContinue | Out-Null

    if ($OSBuildNumber -gt 17763) {

        Show-ProgressStatus -Message "STIG Rule ID: SV-91787r3_rule :: Enabling Data Execution Prevention (DEP) for exploit protection..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
        If((Get-ProcessMitigation -System).DEP.Enable -eq "OFF"){
              Set-Processmitigation -System -Enable DEP
        }

        Show-ProgressStatus -Message "STIG Rule ID: SV-91791r4_rule :: Enabling (Bottom-Up ASLR) for exploit protection..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
        If((Get-ProcessMitigation -System).ASLR.BottomUp -eq "OFF"){
            Set-Processmitigation -System -Enable BottomUp
        }

        Show-ProgressStatus -Message "STIG Rule ID: SV-91793r3_rule :: Enabling Control flow guard (CFG) for exploit protection..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
        If((Get-ProcessMitigation -System).CFG.Enable -eq "OFF"){
            Set-Processmitigation -System -Enable CFG
        }

        Show-ProgressStatus -Message "STIG Rule ID: SV-91797r3_rule :: Enabling Validate exception chains (SEHOP) for exploit protection..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
        If((Get-ProcessMitigation -System).CFG.Enable -eq "OFF"){
            Set-Processmitigation -System -Enable SEHOP
        }

        Show-ProgressStatus -Message "STIG Rule ID: SV-91799r3_rule :: Enabling Validate heap integrity for exploit protection..." -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
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
            Write-LogEntry ("STIG Rule ID: {0}: Enabling Exploit Protection mitigation [DEP : ON] for {1}..." -f $Mitigation.Key,$Mitigation.Value)-Outhost
            If(-not(Get-ProcessMitigation -Name $Mitigation.Value)){
                Set-ProcessMitigation $Mitigation.Value -enable DEP
            }
        }

        Foreach ($Mitigation in $ApplicationMitigationsASLR_BU.GetEnumerator()){
            Write-LogEntry ("STIG Rule ID: {0}: Enabling Exploit Protection mitigation [ASLR:BottomUp : ON] for {1}..." -f $Mitigation.Key,$Mitigation.Value)-Outhost
            If(-not(Get-ProcessMitigation -Name $Mitigation.Value)){
                Set-ProcessMitigation $Mitigation.Value -enable BottomUp
            }
        }

        Foreach ($Mitigation in $ApplicationMitigationsASLR_FRI.GetEnumerator()){
            Write-LogEntry ("STIG Rule ID: {0}: Enabling Exploit Protection mitigation [ASLR:ForceRelocateImages : ON] for {1}..." -f $Mitigation.Key,$Mitigation.Value)-Outhost
            If(-not(Get-ProcessMitigation -Name $Mitigation.Value)){
                Set-ProcessMitigation $Mitigation.Value -enable ForceRelocateImages
            }
        }

        Foreach ($Mitigation in $ApplicationMitigationsImageLoad.GetEnumerator()){
            Write-LogEntry ("STIG Rule ID: {0}: Enabling Exploit Protection mitigation [BlockRemoteImageLoads : ON] for {1}..." -f $Mitigation.Key,$Mitigation.Value)-Outhost
            If(-not(Get-ProcessMitigation -Name $Mitigation.Value)){
                Set-ProcessMitigation $Mitigation.Value -enable BlockRemoteImageLoads
            }
        }

        Foreach ($Mitigation in $ApplicationMitigationsAllPayload.GetEnumerator()){
            Write-LogEntry ("STIG Rule ID: {0}: Enabling Exploit Protection mitigation[Payload:Export & Rop* : ON] options for {1}..." -f $Mitigation.Key,$Mitigation.Value)-Outhost
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
            Write-LogEntry ("STIG Rule ID: {0}: Enabling Exploit Protection mitigation [Payload:Rop* : ON] for {1}..." -f $Mitigation.Key,$Mitigation.Value)-Outhost
            If(-not(Get-ProcessMitigation -Name $Mitigation.Value)){
                Set-ProcessMitigation $Mitigation.Value -enable EnableRopStackPivot
                Set-ProcessMitigation $Mitigation.Value -enable EnableRopCallerCheck
                Set-ProcessMitigation $Mitigation.Value -enable EnableRopSimExec
            }
        }

        Foreach ($Mitigation in $ApplicationMitigationsChild.GetEnumerator()){
            Write-LogEntry ("STIG Rule ID: {0}: Enabling Exploit Protection mitigation [DisallowChildProcessCreation : ON] for {1}..." -f $Mitigation.Key,$Mitigation.Value)-Outhost
            If(-not(Get-ProcessMitigation -Name $Mitigation.Value)){
                Set-ProcessMitigation $Mitigation.Value -enable DisallowChildProcessCreation
            }
        }
    }
    Else{
        Write-LogEntry ("Unable to process mitigations due to OS version [{0}]. Please upgrade or install EMET" -f $OSBuildNumber)-Outhost      
    }
}
Else{$stepCounter++}

Show-ProgressStatus -Message 'Completed' -Step $script:maxSteps -MaxStep $script:maxSteps