<#	
    .SYNOPSIS
        Applies Application Optimizations and configurations. Supports VDI optmizations	
    
    .DESCRIPTION
		Applies Application Optimizations and configurations. Supports VDI optmizations
        Utilizes LGPO.exe to apply group policy item where neceassary.
        Utilizes MDT/SCCM TaskSequence property control
            Configurable using custom variables in MDT/SCCM

    .PARAM
        '// Global Settings
        CFG_DisableAppScript
        CFG_UseLGPOForConfigs
        LGPOPath
        
        '// VDI Preference
        CFG_OptimizeForVDI
        
        '// Applications Settings
        CFG_DisableOfficeAnimation
        CFG_EnableIESoftwareRender
        CFG_EnableLyncStartup
        CFG_RemoveAppxPackages
        CFG_RemoveFODPackages
        
    
    .NOTES
        Author:         Richard Tracy	    
        Last Update:    05/15/2019
        Version:        1.1.1
        Thanks to:      unixuser011,W4RH4WK,TheVDIGuys,cluberti

    .EXAMPLE
        #Copy this to MDT CustomSettings.ini
        Properties=CFG_DisableAppScript,CFG_UseLGPOForConfigs,LGPOPath,CFG_DisableOfficeAnimation,CFG_EnableIESoftwareRender,CFG_EnableLyncStartup,CFG_RemoveAppxPackages,CFG_RemoveFODPackages
        
        #Then add each option to a priority specifically for your use, like:
        [Default]
        CFG_UseLGPOForConfigs=True
        CFG_DisableOfficeAnimation=True
        CFG_EnableIESoftwareRender=True
        CFG_EnableLyncStartup=True
        ...

        #Add script to task sequence

    .LINKS
        https://github.com/TheVDIGuys/W10_1803_VDI_Optimize
        https://github.com/cluberti/VDI/blob/master/ConfigAsVDI.ps1

    .LOGS
        1.1.1 - May 15, 2019 - Added Get-ScriptPpath function to support VScode and ISE; fixed Set-UserSettings  
        1.1.0 - May 10, 2019 - added appx removal Feature on Demand removal, reorganized controls in categories
        1.0.4 - May 09, 2019 - added Office detection
        1.0.0 - May 07, 2019 - initial 
 
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

#region Function Get-InstalledApplication
Function Get-InstalledApplication {
<#
.SYNOPSIS
	Retrieves information about installed applications.
.DESCRIPTION
	Retrieves information about installed applications by querying the registry. You can specify an application name, a product code, or both.
	Returns information about application publisher, name & version, product code, uninstall string, install source, location, date, and application architecture.
.PARAMETER Name
	The name of the application to retrieve information for. Performs a contains match on the application display name by default.
.PARAMETER Exact
	Specifies that the named application must be matched using the exact name.
.PARAMETER WildCard
	Specifies that the named application must be matched using a wildcard search.
.PARAMETER RegEx
	Specifies that the named application must be matched using a regular expression search.
.PARAMETER ProductCode
	The product code of the application to retrieve information for.
.PARAMETER IncludeUpdatesAndHotfixes
	Include matches against updates and hotfixes in results.
.EXAMPLE
	Get-InstalledApplication -Name 'Adobe Flash'
.EXAMPLE
	Get-InstalledApplication -ProductCode '{1AD147D0-BE0E-3D6C-AC11-64F6DC4163F1}'
.NOTES
.LINK
	http://psappdeploytoolkit.com
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[string[]]$Name,
		[Parameter(Mandatory=$false)]
		[switch]$Exact = $false,
		[Parameter(Mandatory=$false)]
		[switch]$WildCard = $false,
		[Parameter(Mandatory=$false)]
		[switch]$RegEx = $false,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[string]$ProductCode,
		[Parameter(Mandatory=$false)]
		[switch]$IncludeUpdatesAndHotfixes
	)
	
	Begin {
		## Get the name of this function and write header
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
	}
	Process {
		If ($name) {
			Write-LogEntry -Message "Get information for installed Application Name(s) [$($name -join ', ')]..." -Source ${CmdletName} -Outhost:$Outhost
		}
		If ($productCode) {
			Write-LogEntry -Message "Get information for installed Product Code [$ProductCode]..." -Source ${CmdletName} -Outhost:$Outhost
		}
		
		## Enumerate the installed applications from the registry for applications that have the "DisplayName" property
		[psobject[]]$regKeyApplication = @()
		ForEach ($regKey in $regKeyApplications) {
			If (Test-Path -LiteralPath $regKey -ErrorAction 'SilentlyContinue' -ErrorVariable '+ErrorUninstallKeyPath') {
				[psobject[]]$UninstallKeyApps = Get-ChildItem -LiteralPath $regKey -ErrorAction 'SilentlyContinue' -ErrorVariable '+ErrorUninstallKeyPath'
				ForEach ($UninstallKeyApp in $UninstallKeyApps) {
					Try {
						[psobject]$regKeyApplicationProps = Get-ItemProperty -LiteralPath $UninstallKeyApp.PSPath -ErrorAction 'Stop'
						If ($regKeyApplicationProps.DisplayName) { [psobject[]]$regKeyApplication += $regKeyApplicationProps }
					}
					Catch{
						Write-LogEntry -Message "Unable to enumerate properties from registry key path [$($UninstallKeyApp.PSPath)]. `n$(Resolve-Error)" -Severity 2 -Source ${CmdletName} -Outhost:$Outhost
						Continue
					}
				}
			}
		}
		If ($ErrorUninstallKeyPath) {
			Write-LogEntry -Message "The following error(s) took place while enumerating installed applications from the registry. `n$(Resolve-Error -ErrorRecord $ErrorUninstallKeyPath)" -Severity 2 -Source ${CmdletName} -Outhost:$Outhost
		}
		
		## Create a custom object with the desired properties for the installed applications and sanitize property details
		[psobject[]]$installedApplication = @()
		ForEach ($regKeyApp in $regKeyApplication) {
			Try {
				[string]$appDisplayName = ''
				[string]$appDisplayVersion = ''
				[string]$appPublisher = ''
				
				## Bypass any updates or hotfixes
				If (-not $IncludeUpdatesAndHotfixes) {
					If ($regKeyApp.DisplayName -match '(?i)kb\d+') { Continue }
					If ($regKeyApp.DisplayName -match 'Cumulative Update') { Continue }
					If ($regKeyApp.DisplayName -match 'Security Update') { Continue }
					If ($regKeyApp.DisplayName -match 'Hotfix') { Continue }
				}
				
				## Remove any control characters which may interfere with logging and creating file path names from these variables
				$appDisplayName = $regKeyApp.DisplayName -replace '[^\u001F-\u007F]',''
				$appDisplayVersion = $regKeyApp.DisplayVersion -replace '[^\u001F-\u007F]',''
				$appPublisher = $regKeyApp.Publisher -replace '[^\u001F-\u007F]',''
				
				## Determine if application is a 64-bit application
				[boolean]$Is64BitApp = If (($is64Bit) -and ($regKeyApp.PSPath -notmatch '^Microsoft\.PowerShell\.Core\\Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node')) { $true } Else { $false }
				
				If ($ProductCode) {
					## Verify if there is a match with the product code passed to the script
					If ($regKeyApp.PSChildName -match [regex]::Escape($productCode)) {
						Write-LogEntry -Message "Found installed application [$appDisplayName] version [$appDisplayVersion] matching product code [$productCode]." -Source ${CmdletName} -Outhost:$Outhost
						$installedApplication += New-Object -TypeName 'PSObject' -Property @{
							UninstallSubkey = $regKeyApp.PSChildName
							ProductCode = If ($regKeyApp.PSChildName -match $MSIProductCodeRegExPattern) { $regKeyApp.PSChildName } Else { [string]::Empty }
							DisplayName = $appDisplayName
							DisplayVersion = $appDisplayVersion
							UninstallString = $regKeyApp.UninstallString
							InstallSource = $regKeyApp.InstallSource
							InstallLocation = $regKeyApp.InstallLocation
							InstallDate = $regKeyApp.InstallDate
							Publisher = $appPublisher
							Is64BitApplication = $Is64BitApp
						}
					}
				}
				
				If ($name) {
					## Verify if there is a match with the application name(s) passed to the script
					ForEach ($application in $Name) {
						$applicationMatched = $false
						If ($exact) {
							#  Check for an exact application name match
							If ($regKeyApp.DisplayName -eq $application) {
								$applicationMatched = $true
								Write-LogEntry -Message "Found installed application [$appDisplayName] version [$appDisplayVersion] using exact name matching for search term [$application]." -Source ${CmdletName}
							}
						}
						ElseIf ($WildCard) {
							#  Check for wildcard application name match
							If ($regKeyApp.DisplayName -like $application) {
								$applicationMatched = $true
								Write-LogEntry -Message "Found installed application [$appDisplayName] version [$appDisplayVersion] using wildcard matching for search term [$application]." -Source ${CmdletName}
							}
						}
						ElseIf ($RegEx) {
							#  Check for a regex application name match
							If ($regKeyApp.DisplayName -match $application) {
								$applicationMatched = $true
								Write-LogEntry -Message "Found installed application [$appDisplayName] version [$appDisplayVersion] using regex matching for search term [$application]." -Source ${CmdletName}
							}
						}
						#  Check for a contains application name match
						ElseIf ($regKeyApp.DisplayName -match [regex]::Escape($application)) {
							$applicationMatched = $true
							Write-LogEntry -Message "Found installed application [$appDisplayName] version [$appDisplayVersion] using contains matching for search term [$application]." -Source ${CmdletName}
						}
						
						If ($applicationMatched) {
							$installedApplication += New-Object -TypeName 'PSObject' -Property @{
								UninstallSubkey = $regKeyApp.PSChildName
								ProductCode = If ($regKeyApp.PSChildName -match $MSIProductCodeRegExPattern) { $regKeyApp.PSChildName } Else { [string]::Empty }
								DisplayName = $appDisplayName
								DisplayVersion = $appDisplayVersion
								UninstallString = $regKeyApp.UninstallString
								InstallSource = $regKeyApp.InstallSource
								InstallLocation = $regKeyApp.InstallLocation
								InstallDate = $regKeyApp.InstallDate
								Publisher = $appPublisher
								Is64BitApplication = $Is64BitApp
							}
						}
					}
				}
			}
			Catch {
				Write-LogEntry -Message "Failed to resolve application details from registry for [$appDisplayName]. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName} -Outhost:$Outhost
				Continue
			}
		}
		
		Write-Output -InputObject $installedApplication
	}
	End {
	}
}
#endregion


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
[boolean]$DisableScript =  $false
[boolean]$UseLGPO = $true
[string]$Global:LGPOPath = "$ToolsPath\LGPO\LGPO.exe"

#// VDI Preference
[boolean]$OptimizeForVDI = $false

#// Applications Settings
[boolean]$DisableOfficeAnimation = $false
[boolean]$EnableIESoftwareRender = $false
[boolean]$EnableLyncStartup = $false
[boolean]$RemoveAppxPackages = $false
[boolean]$RemoveFODPackages = $false


# When running in Tasksequence and configureation exists, use that instead
If($tsenv){
    #// Global Settings
    If($tsenv:CFG_DisableAppScript){[boolean]$DisableScript = [boolean]::Parse($tsenv.Value("CFG_DisableAppScript"))}
    If($tsenv:CFG_UseLGPOForConfigs){[boolean]$UseLGPO = [boolean]::Parse($tsenv.Value("CFG_UseLGPOForConfigs"))}
    If($tsenv:LGPOPath){[string]$Global:LGPOPath = $tsenv.Value("LGPOPath")}
    #// VDI Preference
    If($tsenv:CFG_OptimizeForVDI){[boolean]$OptimizeForVDI = [boolean]::Parse($tsenv.Value("CFG_OptimizeForVDI"))}
    #// Applications Settings
    If($tsenv:CFG_DisableOfficeAnimation){[string]$DisableOfficeAnimation = $tsenv.Value("CFG_DisableOfficeAnimation")}
    If($tsenv:CFG_EnableIESoftwareRender){[string]$EnableIESoftwareRender = $tsenv.Value("CFG_EnableIESoftwareRender")}
    If($tsenv:CFG_EnableLyncStartup){[boolean]$EnableLyncStartup = [boolean]::Parse($tsenv.Value("CFG_EnableLyncStartup"))}
    If($tsenv:CFG_RemoveAppxPackages){[boolean]$RemoveAppxPackages = [boolean]::Parse($tsenv.Value("CFG_RemoveAppxPackages"))}
    If($tsenv:CFG_RemoveFODPackages){[boolean]$RemoveFODPackages = [boolean]::Parse($tsenv.Value("CFG_RemoveFODPackages"))}
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

$OfficeInstalled = Get-InstalledApplication "Microsoft Office" | Select -First 1
If($OfficeInstalled){
    If( $OfficeInstalled.Is64BitApplication ) {$OfficeLocation = $env:ProgramFiles} Else {$OfficeLocation = ${env:ProgramFiles(x86)}}
    $OfficeVersion = [string]([version]$OfficeInstalled.DisplayVersion).Major + '.' + [string]([version]$OfficeInstalled.DisplayVersion).Minor
    $OfficeFolder = 'Office' + [string]([version]$OfficeInstalled.DisplayVersion).Major
}

##*===========================================================================
##* MAIN
##*===========================================================================

If($EnableIESoftwareRender){
    Set-UserSetting -Message "Enabling Software Rendering For IE" -Path "SOFTWARE\Microsoft\Internet Explorer\Main" -Name 'UseSWRender' -Type DWord -Value 1 -Force
    Set-UserSetting -Message "Disabling First Run Wizard For IE" -Path "SOFTWARE\Microsoft\Internet Explorer\Main" -Name 'DisableFirstRunCustomize' -Type DWord -Value 3 -Force
}
Else{$stepCounter++}


If ($DisableOfficeAnimation -and $OfficeInstalled){
    Set-UserSetting -Message "Disabling OST Cache mode for Office 2016" -Path "SOFTWARE\Policies\Microsoft\Office\$OfficeVersion\Outlook\ost" -Name 'NoOST' -Type DWord -Value 2 -Force
    Set-UserSetting -Message "Disabling Exchange cache mode for Office 2016" -Path "SOFTWARE\Policies\Microsoft\Office\$OfficeVersion\Outlook\cache mode" -Name 'Enable' -Type DWord -Value 0 -Force
}
Else{$stepCounter++}


If ($DisableOfficeAnimation -and $OfficeInstalled){
    Set-UserSetting -Message "Disabling Hardware Acceleration for Office 2016" -Path "SOFTWARE\Microsoft\Office\$OfficeVersion\Common\Graphics" -Name 'DisableHardwareAcceleration' -Type DWord -Value 1 -Force
    Set-UserSetting -Message "Disabling Animation for Office 2016" -Path "SOFTWARE\Microsoft\Office\$OfficeVersion\Common\Graphics" -Name 'DisableAnimation' -Type DWord -Value 1 -Force
    Set-UserSetting -Message "Disabling First Run Boot for Office 2016" -Path "SOFTWARE\Microsoft\Office\$OfficeVersion\FirstRun" -Name 'BootRTM' -Type DWord -Value 1 -Force
    Set-UserSetting -Message "Disabling First Run Movie for Office 2016" -Path "SOFTWARE\Microsoft\Office\$OfficeVersion\FirstRun" -Name 'DisableMovie' -Type DWord -Value 1 -Force
    Set-UserSetting -Message "Disabling First Run Optin for Office 2016" -Path "SOFTWARE\Microsoft\Office\$OfficeVersion\Common\General" -Name 'showfirstrunoptin' -Type DWord -Value 1 -Force
    Set-UserSetting -Message "Disabling First Run Optin for Office 2016" -Path "SOFTWARE\Microsoft\Office\$OfficeVersion\Common\PTWatson" -Name 'PTWOption' -Type DWord -Value 1 -Force
    Set-UserSetting -Message "Disabling CEIP for Office 2016" -Path "SOFTWARE\Microsoft\Office\$OfficeVersion\Common" -Name 'qmenable' -Type DWord -Value 1 -Force
    Set-UserSetting -Message "Accepting Eulas for Office 2016" -Path "SOFTWARE\Microsoft\Office\$OfficeVersion\Registration" -Name 'AcceptAllEulas' -Type DWord -Value 1 -Force
    Set-UserSetting -Message "Disabling Default File Types for Office 2016" -Path "SOFTWARE\Microsoft\Office\$OfficeVersion\Common\General" -Name 'ShownFileFmtPrompt' -Type DWord -Value 1 -Force
}
Else{$stepCounter++}



If($EnableLyncStartup -and $OfficeInstalled)
{
    Set-UserSetting -Message "Enabling Skype for Business Startup" -Path "SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Lync" -Type String -Value """$OfficeLocation\Microsoft Office\Office16\lync.exe"" /fromrunkey" -Force
}
Else{$stepCounter++}


If($RemoveAppxPackages)
{
    Show-ProgressStatus -Message "Removing AppxPackage and AppxProvisioningPackage" -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    
    # Get a list of all apps
    $AppArrayList = Get-AppxPackage -PackageTypeFilter Bundle -AllUsers | Select-Object -Property Name, PackageFullName | Sort-Object -Property Name

    # White list of appx packages to keep installed
    $WhiteListedApps = @(
        "Microsoft.DesktopAppInstaller",
        "Microsoft.MSPaint",
        "Microsoft.Windows.Photos",
        "Microsoft.StorePurchaseApp",
        "Microsoft.MicrosoftStickyNotes",
        "Microsoft.WindowsAlarms",
        "Microsoft.WindowsCalculator",
        #"Microsoft.WindowsCommunicationsApps", # Mail, Calendar etc
        "Microsoft.WindowsSoundRecorder",
        "Microsoft.RemoteDesktop",
        "Microsoft.WindowsStore"
    )

    $p = 1
    $c = 0
    # Loop through the list of appx packages
    foreach ($App in $AppArrayList) {

        # If application name not in appx package white list, remove AppxPackage and AppxProvisioningPackage
        if (($App.Name -in $WhiteListedApps)) {
            $status = "Skipping excluded application package: $($App.Name)"
            Write-LogEntry -Value $status -Outhost
        }
        else {
            # Gather package names
            $AppPackageFullName = Get-AppxPackage -Name $App.Name | Select-Object -ExpandProperty PackageFullName
            $AppProvisioningPackageName = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $App.Name } | Select-Object -ExpandProperty PackageName

            # Attempt to remove AppxPackage
            if ($AppPackageFullName -ne $null) {
                $status = "Removing application package: $($App.Name)"
                Show-ProgressStatus -Message $status -Step $p -MaxStep $AppArrayList.count
                
                try {
                    Remove-AppxPackage -Package $AppPackageFullName -ErrorAction Stop | Out-Null
                    Write-LogEntry -Value "Successfully removed application package: $($App.Name)" -Outhost
                    $c++
                }
                catch [System.Exception] {
                    Write-LogEntry -Value "Failed removing AppxPackage: $($_.Exception.Message)" -Severity 3 -Outhost
                }
            }
            else {
                Write-LogEntry -Value "Unable to locate AppxPackage for app: $($App.Name)" -Outhost
            }

            # Attempt to remove AppxProvisioningPackage
            if ($AppProvisioningPackageName -ne $null) {
                Write-LogEntry -Value "Removing application provisioning package: $($AppProvisioningPackageName)"
                try {
                    Remove-AppxProvisionedPackage -PackageName $AppProvisioningPackageName -Online -ErrorAction Stop | Out-Null
                    Write-LogEntry -Value "Successfully removed application provisioning package: $AppProvisioningPackageName" -Outhost
                }
                catch [System.Exception] {
                    Write-LogEntry -Value "Failed removing AppxProvisioningPackage: $($_.Exception.Message)" -Severity 3 -Outhost
                }
            }
            else {
                Write-LogEntry -Value "Unable to locate AppxProvisioningPackage for app: $($App.Name)" -Outhost
            }

        }

        $p++
    }

    Write-LogEntry -Value ("Removed {0} built-in AppxPackage and AppxProvisioningPackage" -f $c) -Outhost
}
Else{$stepCounter++}


If($RemoveFODPackages)
{
    Show-ProgressStatus -Message "Starting Features on Demand V2 removal process" -Step ($stepCounter++) -MaxStep $script:Maxsteps -Outhost
    
    # White list of Features On Demand V2 packages
    $WhiteListOnDemand = "NetFX3|Tools.Graphics.DirectX|Tools.DeveloperMode.Core|Language|Browser.InternetExplorer|ContactSupport|OneCoreUAP|Media.WindowsMediaPlayer|Rsat"

    # Get Features On Demand that should be removed
    $OnDemandFeatures = Get-WindowsCapability -Online | Where-Object { $_.Name -notmatch $WhiteListOnDemand -and $_.State -like "Installed"} | Select-Object -ExpandProperty Name

    try {

        # Handle cmdlet limitations for older OS builds
        if ($OSBuildNumber -le "16299") {
            $OnDemandFeatures = Get-WindowsCapability -Online -ErrorAction Stop | Where-Object { $_.Name -notmatch $WhiteListOnDemand -and $_.State -like "Installed"} | Select-Object -ExpandProperty Name
        }
        else {
            $OnDemandFeatures = Get-WindowsCapability -Online -LimitAccess -ErrorAction Stop | Where-Object { $_.Name -notmatch $WhiteListOnDemand -and $_.State -like "Installed"} | Select-Object -ExpandProperty Name
        }
        $f=1
        foreach ($Feature in $OnDemandFeatures) {
            try {
                Show-ProgressStatus -Message "Removing Feature on Demand V2 package: $($Feature)" -Step $f -MaxStep $OnDemandFeatures.count -Outhost
                # Handle cmdlet limitations for older OS builds
                if ($OSBuildNumber -le "16299") {
                    Get-WindowsCapability -Online -ErrorAction Stop | Where-Object { $_.Name -like $Feature } | Remove-WindowsCapability -Online -ErrorAction Stop | Out-Null
                }
                else {
                    Get-WindowsCapability -Online -LimitAccess -ErrorAction Stop | Where-Object { $_.Name -like $Feature } | Remove-WindowsCapability -Online -ErrorAction Stop | Out-Null
                }
            }
            catch [System.Exception] {
                Write-LogEntry -Message "Failed to remove Feature on Demand V2 package: $($_.Exception.Message)" -Severity 3 -Outhost
            }

            $f++
        }
    }
    catch [System.Exception] {
        Write-LogEntry -Message "Failed attempting to list Feature on Demand V2 packages: $($_.Exception.Message)" -Severity 3 -Outhost
    }
    # Complete
    Show-ProgressStatus -Message "Completed Features on Demand V2 removal process" -Step $script:maxSteps -MaxStep $script:maxSteps

}
Else{$stepCounter++}


Show-ProgressStatus -Message 'Completed' -Step $script:maxSteps -MaxStep $script:maxSteps