<#	
    .SYNOPSIS
        Applies Windows Server 16 Optimizations and configurations
    
    .DESCRIPTION
		Applies Windows Server 16 Optimizations and configurations.
        Utilizes LGPO.exe to apply group policy item where neceassary.
        Utilizes MDT/SCCM TaskSequence property control
            Configurable using custom variables in MDT/SCCM

    .EXAMPLE
        powershell.exe -ExecutionPolicy Bypass -file "Svr16OptimizeAndConfig.ps1"
    
    .INFO
        Script:         Svr16OptimizeAndConfig.ps1
        Author:         Richard Tracy
        Email:          richard.tracy@hotmail.com
        Twitter:        @rick2_1979
        Website:        www.powershellcrack.com
        Last Update:    06/20/2019
        Version:        11.0
        Thanks to:      unixuser011,W4RH4WK,TheVDIGuys,cluberti,JGSpiers
    

    .INPUTS
        '// Global Settings
        CFG_DisableScript
        CFG_UseLGPOForConfigs
        LGPOPath

        '//Server Performance
        CFG_OptimizeServerOS 

        '//User Preference
        CFG_DisableIEFirstRunWizard
        CFG_ShowKnownExtensions
        CFG_ShowHiddenFiles
        CFG_SetSmartScreenFilter
        CFG_DisableIEESCforAdmins
        CFG_DisableIEESCforUsers
        CFG_DisableServerManagerLogonLaunch

        '// System Settings
        CFG_InstallPSModules
        CFG_ApplyCustomHost
        HostPath
        CFG_EnableSecureLogonCAD
        CFG_EnableVerboseStatusMsg
        CFG_DisableAutoRun
        CFG_DisableActionCenter
        CFG_ApplyPrivacyMitigations
        CFG_DisableWindowsUpdates
        CFG_PreferIPv4OverIPv6
        CFG_RemoveVMToolsTrayIcon
        CFG_DisableShutdownEventTracker

        '// System Adv Settings
        CFG_EnableFIPS
        CFG_DisableUAC
        CFG_EnableStrictUAC
        CFG_EnableRDP
        CFG_EnableWinRM
        CFG_EnableRemoteRegistry
        CFG_EnablePSLogging
        CFG_DisableAdminShares
        CFG_DisableSchTasks
        CFG_DisableFirewall
        CFG_RemoveDefender
        CFG_DisabledUnusedServices
        CFG_DisabledHyperVServices
        CFG_MoveEventLogsToDrive
        CFG_OptimizeNetwork


    .EXAMPLE
        #Copy this to MDT CustomSettings.ini

        Properties=CFG_DisableScript,CFG_UseLGPOForConfigs,LGPOPath,CFG_OptimizeServerOS,CFG_DisableIEFirstRunWizard,CFG_ShowKnownExtensions,CFG_ShowHiddenFiles,CFG_SetSmartScreenFilter,
        CFG_DisableIEESCforAdmins,CFG_DisableIEESCforUsers,CFG_DisableServerManagerLogonLaunch,CFG_InstallPSModules,CFG_ApplyCustomHost,HostPath,CFG_EnableSecureLogonCAD,CFG_EnableVerboseStatusMsg,CFG_DisableAutoRun,
        CFG_DisableActionCenter,CFG_ApplyPrivacyMitigations,CFG_DisableWindowsUpdates,CFG_PreferIPv4OverIPv6,CFG_RemoveVMToolsTrayIcon,CFG_DisableShutdownEventTracker,CFG_EnableFIPS,CFG_DisableUAC,
        CFG_EnableStrictUAC,CFG_EnableRDP,CFG_EnableWinRM,CFG_EnableRemoteRegistry,CFG_EnablePSLogging,CFG_DisableAdminShar,esCFG_DisableSchTasks,CFG_DisableFirewall,CFG_RemoveDefender,
        CFG_DisabledUnusedServices,CFG_DisabledHyperVServices,CFG_MoveEventLogsToDrive,CFG_OptimizeNetwork
        
        #Then add each option to a priority specifically for your use, like:
        [Default]
        CFG_UseLGPOForConfigs=True
        CFG_EnableVerboseMsg=True
        CFG_DisableAutoRun=True
        CFG_OptimizeServerOS=True
        

        #Add script to task sequence

    .DISCLOSURE
        THE SCRIPT IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES 
        OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. BY USING OR DISTRIBUTING THIS SCRIPT, YOU AGREE THAT IN NO EVENT 
        SHALL RICHARD TRACY OR ANY AFFILATES BE HELD LIABLE FOR ANY DAMAGES WHATSOEVER RESULTING FROM USING OR DISTRIBUTION OF THIS SCRIPT, INCLUDING,
        WITHOUT LIMITATION, ANY SPECIAL, CONSEQUENTIAL, INCIDENTAL OR OTHER DIRECT OR INDIRECT DAMAGES. BACKUP UP ALL DATA BEFORE PROCEEDING. 
    
    .CHANGE LOG
        1.1.0 - Jun 20, 2019 - Consolidated settings into sections; formatted some of Jspiers in my format; wrote examples
        1.0.0 - Jun 18, 2019 - initial 
#>
 
##*===========================================================================
##* FUNCTIONS
##*===========================================================================

Function Test-IsISE {
  # trycatch accounts for:
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
      [switch]$ReturnLogPath
  )
  
  Begin{
      ## Get the name of this function
      [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
      
      if (-not $PSBoundParameters.ContainsKey('Verbose')) {
        $VerbosePreference = $PSCmdlet.SessionState.PSVariable.GetValue('VerbosePreference')
      }
  }
  Process{
      If(${CmdletName}){$prefix = "${CmdletName} ::" }Else{$prefix = "" }

      try{
          # Create an object to access the task sequence environment
          $Script:tsenv = New-Object -COMObject Microsoft.SMS.TSEnvironment
          Write-Verbose ("{0}Task Sequence environment detected!" -f $prefix)
      }
      catch{
          Write-Verbose ("{0}Task Sequence environment not detected. Running in stand-alone mode" -f $prefix)
          
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
  if ( $ts.Minutes -gt 0 ){$elapsedTime = [string]::Format( "{0:00} min. {1:00}.{2:00} sec", $ts.Minutes, $ts.Seconds, $ts.Milliseconds / 10 );}
  else{$elapsedTime = [string]::Format( "{0:00}.{1:00} sec", $ts.Seconds, $ts.Milliseconds / 10 );}
  if ($ts.Hours -eq 0 -and $ts.Minutes -eq 0 -and $ts.Seconds -eq 0){$elapsedTime = [string]::Format("{0:00} ms", $ts.Milliseconds);}
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

      [parameter(Mandatory=$false, HelpMessage="Name of the log file that the entry will written to")]
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
          default {$LGPORegType = 'DWORD';$Type = 'DWord'}
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
              Write-LogEntry ("LGPO not enabled. Hardcoding registry keys [{0}\{1}\{2}]" -f $RegHive,$RegKeyPath,$RegKeyName) -Severity 0 -Source ${CmdletName}
          }
      }
      Catch{
          If($TryLGPO -and $LGPOExe){
              Write-LogEntry ("LGPO failed to run. exit code: {0}. Hardcoding registry keys [{1}\{2}\{3}]" -f $result.ExitCode,$RegHive,$RegKeyPath,$RegKeyName) -Severity 3 -Source ${CmdletName}
          }
      }
      Finally
      {
          #wait for LGPO file to finish generating
          start-sleep 1
          
          #verify the registry value has been set
          Try{
              If( -not(Test-Path ($RegHive +'\'+ $RegKeyPath)) ){
                  Write-LogEntry ("Key was not set; Hardcoding registry keys [{0}\{1}] with value [{2}]" -f ($RegHive +'\'+ $RegKeyPath),$RegKeyName,$Value) -Severity 0 -Source ${CmdletName}
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
          Write-LogEntry ("User registry hive was not found or specified in Keypath [{0}]. Either use the -ApplyTo Switch or specify user hive [eg. HKCU\]" -f $RegPath) -Severity 3 -Source ${CmdletName}
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
                  If($Message){Write-LogEntry ("{0} for User [{1}]" -f $Message,$UserName)}
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
          If($Message){Write-LogEntry ("{0} for [{1}]" -f $Message,$ProfileList.UserName)}
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
$ModulesPath = Join-Path -Path $scriptDirectory -ChildPath 'PSModules'
$BinPath = Join-Path -Path $scriptDirectory -ChildPath 'Bin'
$FilesPath = Join-Path -Path $scriptDirectory -ChildPath 'Files'


#check if running in verbose mode
$Global:Verbose = $false
If($PSBoundParameters.ContainsKey('Debug') -or $PSBoundParameters.ContainsKey('Verbose')){
    $Global:Verbose = $PsBoundParameters.Get_Item('Verbose')
    $VerbosePreference = 'Continue'
    Write-Verbose ("[{0}] [{1}] :: VERBOSE IS ENABLED" -f (Format-DatePrefix),$scriptName)
}
Else{
    $VerbosePreference = 'SilentlyContinue'
}

#build log name
[string]$FileName = $scriptBaseName +'.log'
#build global log fullpath
$Global:LogFilePath = Join-Path (Get-SMSTSENV -ReturnLogPath) -ChildPath $FileName
Write-Host "logging to file: $LogFilePath" -ForegroundColor Cyan

##*===========================================================================
##* DEFAULTS: Configurations are here (change values if needed)
##*===========================================================================
# Global Settings
[boolean]$DisableScript = $false
[boolean]$UseLGPO = $true
[string]$Global:LGPOPath = "$ToolsPath\LGPO\LGPO.exe"
# Server Performance
[boolean]$OptimizeServerOS = $false 

# User Preference
[boolean]$DisableIEFirstRunWizard = $false
[boolean]$ShowKnownExtensions = $false
[boolean]$ShowHiddenFiles = $false
[string]$SetSmartScreenFilter = 'User' # Set to 'Off','User','Admin'
[boolean]$DisableIEESCforAdmins = $false
[boolean]$DisableIEESCforUsers = $false
[boolean]$DisableServerManagerLogonLaunch = $false
# System Settings
[boolean]$InstallPSModules = $false
[psobject]$InstallModules = Get-ChildItem $ModulesPath -Filter *.psm1 -Recurse
[boolean]$ApplyCustomHost = $false
[string]$HostPath = "$FilesPath\WindowsTelemetryhosts"
[boolean]$EnableSecureLogonCAD = $false
[boolean]$EnableVerboseStatusMsg = $false
[boolean]$DisableAutoRun = $false
[boolean]$DisableActionCenter = $false
[boolean]$ApplyPrivacyMitigations = $false
[boolean]$DisableWindowsUpdates = $false
[boolean]$PreferIPv4OverIPv6 = $false
[boolean]$RemoveVMToolsTrayIcon = $false
[boolean]$CFG_DisableShutdownEventTracker = $false

# System Adv Settings
[boolean]$EnableFIPS = $false
[boolean]$DisableUAC = $false
[boolean]$EnableStrictUAC = $false
[boolean]$EnableRDP = $false
[boolean]$EnableWinRM = $false
[boolean]$EnableRemoteRegistry = $false
[boolean]$EnablePSLogging = $false
[boolean]$DisableAdminShares = $false
[boolean]$DisableSchTasks = $false
[boolean]$DisableFirewall = $false
[boolean]$RemoveDefender = $false
[boolean]$DisabledUnusedServices = $false
[boolean]$DisabledHyperVServices = $false
[string]$MoveEventLogsToDrive = $false
[boolean]$OptimizeNetwork = $false

# Configurations comes from Tasksequence
# When running in Tasksequence and configureation exists, use that instead
If(Get-SMSTSENV){
    # Global Settings
    If($tsenv:CFG_DisableConfigScript){[boolean]$DisableScript = [boolean]::Parse($tsenv.Value("CFG_DisableConfigScript"))}
    If($tsenv:CFG_UseLGPOForConfigs){[boolean]$UseLGPO = [boolean]::Parse($tsenv.Value("CFG_UseLGPOForConfigs"))}
    If($tsenv:LGPOPath){[string]$Global:LGPOPath = $tsenv.Value("LGPOPath")}
    # Server Performance
    If($tsenv:CFG_OptimizeServerOS){[boolean]$OptimizeServerOS = [boolean]::Parse($tsenv.Value("CFG_OptimizeServerOS"))} 

    # User Preference
    If($tsenv:CFG_DisableIEFirstRunWizard){[boolean]$DisableIEFirstRunWizard = [boolean]::Parse($tsenv.Value("CFG_DisableIEFirstRunWizard"))}
    If($tsenv:CFG_ShowKnownExtensions){[boolean]$ShowKnownExtensions = [boolean]::Parse($tsenv.Value("CFG_ShowKnownExtensions"))}
    If($tsenv:CFG_ShowHiddenFiles){[boolean]$ShowHiddenFiles = [boolean]::Parse($tsenv.Value("CFG_ShowHiddenFiles"))}
    If($tsenv:CFG_SetSmartScreenFilter){[string]$SetSmartScreenFilter = $tsenv.Value("CFG_SetSmartScreenFilter")}
    If($tsenv:CFG_DisableIEESCAdmins){[boolean]$DisableIEESCforAdmins = [boolean]::Parse($tsenv.Value("CFG_DisableIEESCAdmins"))}
    If($tsenv:CFG_DisableIEESCUsers){[boolean]$DisableIEESCforUsers = [boolean]::Parse($tsenv.Value("CFG_DisableIEESCUsers"))}
    If($tsenv:CFG_DisableServerManagerLogonLaunch){[boolean]$DisableServerManagerLogonLaunch = [boolean]::Parse($tsenv.Value("CFG_DisableServerManagerLogonLaunch"))}

    # System Settings
    If($tsenv:CFG_InstallPSModules){[boolean]$InstallPSModules = [boolean]::Parse($tsenv.Value("CFG_InstallPSModules"))}
    If($tsenv:CFG_ApplyCustomHost){[boolean]$ApplyCustomHost = [boolean]::Parse($tsenv.Value("CFG_ApplyCustomHost"))}
    If($tsenv:HostPath){[string]$HostPath = $tsenv.Value("HostPath")}
    If($tsenv:CFG_EnableSecureLogonCAD){[boolean]$EnableSecureLogonCAD = [boolean]::Parse($tsenv.Value("CFG_EnableSecureLogonCAD"))}
    If($tsenv:CFG_EnableVerboseMsg){[boolean]$EnableVerboseStatusMsg = [boolean]::Parse($tsenv.Value("CFG_EnableVerboseMsg"))}
    If($tsenv:CFG_DisableAutoRun){[boolean]$DisableAutoRun = [boolean]::Parse($tsenv.Value("CFG_DisableAutorun"))}
    If($tsenv:CFG_DisableActionCenter){[boolean]$DisableActionCenter = [boolean]::Parse($tsenv.Value("CFG_DisableActionCenter"))}
    If($tsenv:CFG_ApplyPrivacyMitigations){[boolean]$ApplyPrivacyMitigations = [boolean]::Parse($tsenv.Value("CFG_ApplyPrivacyMitigations"))}
    If($tsenv:CFG_DisableWindowsUpdates){[boolean]$DisableWindowsUpdates = [boolean]::Parse($tsenv.Value("CFG_DisableWindowsUpdates"))}
    If($tsenv:CFG_PreferIPv4OverIPv6){[boolean]$PreferIPv4OverIPv6 = [boolean]::Parse($tsenv.Value("CFG_PreferIPv4OverIPv6"))}
    If($tsenv:CFG_RemoveVMToolsTrayIcon){[boolean]$RemoveVMToolsTrayIcon = [boolean]::Parse($tsenv.Value("CFG_RemoveVMToolsTrayIcon"))}
    If($tsenv:CFG_DisableShutdownEventTracker){[boolean]$CFG_DisableShutdownEventTracker = [boolean]::Parse($tsenv.Value("CFG_DisableShutdownEventTracker"))}

    # System Adv Settings
    If($tsenv:CFG_EnableFIPS){[boolean]$EnableFIPS = [boolean]::Parse($tsenv.Value("CFG_EnableFIPS"))}
    If($tsenv:CFG_DisableUAC){[boolean]$DisableUAC = [boolean]::Parse($tsenv.Value("CFG_DisableUAC"))}
    If($tsenv:CFG_EnableStrictUAC){[boolean]$EnableStrictUAC = [boolean]::Parse($tsenv.Value("CFG_EnableStrictUAC"))}
    If($tsenv:CFG_EnableRDP){[boolean]$EnableRDP = [boolean]::Parse($tsenv.Value("CFG_EnableRDP"))}
    If($tsenv:CFG_EnableWinRM){[boolean]$EnableWinRM = [boolean]::Parse($tsenv.Value("CFG_EnableWinRM"))}
    If($tsenv:CFG_EnableRemoteRegistry){[boolean]$EnableRemoteRegistry = [boolean]::Parse($tsenv.Value("CFG_EnableRemoteRegistry"))}
    If($tsenv:CFG_EnablePSLogging){[boolean]$EnablePSLogging = [boolean]::Parse($tsenv.Value("CFG_EnablePSLogging"))}
    If($tsenv:CFG_DisableAdminShares){[boolean]$DisableAdminShares = [boolean]::Parse($tsenv.Value("CFG_DisableAdminShares"))}
    If($tsenv:CFG_DisableSchTasks){[boolean]$DisableSchTasks = [boolean]::Parse($tsenv.Value("CFG_DisableSchTasks"))}
    If($tsenv:CFG_DisableFirewall){[boolean]$DisableFirewall = [boolean]::Parse($tsenv.Value("CFG_DisableFirewall"))}
    If($tsenv:CFG_RemoveDefender){[boolean]$RemoveDefender = [boolean]::Parse($tsenv.Value("CFG_RemoveDefender"))}
    If($tsenv:CFG_DisabledUnusedServices){[boolean]$DisabledUnusedServices = [boolean]::Parse($tsenv.Value("CFG_DisabledUnusedServices"))}
    If($tsenv:CFG_DisabledHyperVServices){[boolean]$DisabledHyperVServices = [boolean]::Parse($tsenv.Value("CFG_DisabledHyperVServices"))}
    If($tsenv:CFG_EventLogDrive){[string]$MoveEventLogsToDrive = $tsenv.Value("CFG_EventLogDrive")}
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

#if running in a tasksequence; apply user settings to all user profiles (use ApplyTo param cmdlet Set-UserSettings )
If(Get-SMSTSENV){$Global:ApplyToProfiles = 'AllUsers'}Else{$Global:ApplyToProfiles = 'CurrentUser'}
If((Get-SMSTSENV) -and -not($psISE)){$Global:OutTohost = $false}Else{$Global:OutTohost = $true}

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
                Write-LogEntry ("Copying nuget Assembly [{0}] to [{1}]" -f $NuGetAssemblyVersion,$NuGetAssemblyDestPath)
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


If($EnablePSLogging)
{
    Show-ProgressStatus -Message "Enabling Powershell Script Logging" -Step ($stepCounter++) -MaxStep $script:Maxsteps

	Write-LogEntry "Enabling Powershell Script Block Logging"
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Type DWord -Value 1 -Force -TryLGPO:$true | Out-Null

    Write-LogEntry "Enabling Powershell Transcription Logging"
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'EnableTranscripting' -Type DWord -Value 1 -Force -TryLGPO:$true | Out-Null
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'EnableInvocationHeader' -Type DWord -Value 1 -Force -TryLGPO:$true | Out-Null
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'OutputDirectory' -Value "" -Force -TryLGPO:$true | Out-Null

    Write-LogEntry "Enabling Powershell Module Logging"
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


If ($DisableServerManagerLogonLaunch)
{
    Set-UserSetting -Message ("Disabling Server Manager from launching on login:") -Path 'SOFTWARE\Microsoft\ServerManager' -Name 'DoNotOpenServerManagerAtLogon' -Type DWord -Value 1 -Force
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


If ($PreferIPv4OverIPv6)
{
    Show-ProgressStatus -Message "Modifying IPv6 bindings to prefer IPv4 over IPv6" -Step ($stepCounter++) -MaxStep $script:Maxsteps
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'DisabledComponents' -Type DWord -Value '32' -Force
}
Else{$stepCounter++}


If($EnableSecureLogonCAD)
{
  	# Disable IE First Run Wizard
	Show-ProgressStatus -Message "Enabling Secure Logon Screen Settings" -Step ($stepCounter++) -MaxStep $script:Maxsteps
	Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'DisableCAD' -Type DWord -Value '0' -Force
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DontDisplayLastUserName' -Type DWord -Value '1' -Force
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'BlockDomainPicturePassword' -Type DWord -Value '1' -Force
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

    Write-LogEntry "Enabling Smart Screen Filter on Edge"
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' -Name 'PreventOverride' -Type DWord -Value 1 -Force -TryLGPO:$true
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' -Name 'PreventOverrideAppRepUnknown' -Type DWord -Value 1 -Force -TryLGPO:$true
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' -Name 'EnabledV9' -Type DWord -Value $value -Force -TryLGPO:$true
}
Else{$stepCounter++}



If($DisableIEESCforAdmins){
    Write-LogEntry "Disabling IE ESC For Admins" -Outhost
    Remove-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}' -Name StubPath -Force | Out-Null
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}' -Name IsInstalled -Type DWord -Value 0 -Force
}
Else{$stepCounter++}


If($DisableIEESCforUsers){
    Write-LogEntry "Disabling IE ESC For Users" -Outhost
    Remove-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}' -Name StubPath -Force | Out-Null
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}' -Name IsInstalled -Type DWord -Value 0 -Force
}
Else{$stepCounter++}


If($EnableStrictUAC)
{
    Show-ProgressStatus -Message "Enabling strict UAC Level" -Step ($stepCounter++) -MaxStep $script:Maxsteps

    Write-LogEntry "Enabling UAC prompt administrators for consent on the secure desktop"
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -Type DWord -Value 2 -Force -TryLGPO:$true
    
    Write-LogEntry "Disabling elevation UAC prompt User for consent on the secure desktop"
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorUser -Type DWord -Value 0 -Force -TryLGPO:$true

    Write-LogEntry "Enabling elevation UAC prompt detect application installations and prompt for elevation"
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableInstallerDetection' -Type DWord -Value 1 -Force -TryLGPO:$true
    
    Write-LogEntry "Enabling elevation UAC UIAccess applications that are installed in secure locations"
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableSecureUAIPaths' -Type DWord -Value 1 -Force -TryLGPO:$true

    Write-LogEntry "Enabling Enable virtualize file and registry write failures to per-user locations."
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableVirtualization' -Type DWord -Value 1 -Force -TryLGPO:$true
        
    Write-LogEntry "Enabling UAC for all administrators"
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Type DWord -Value 1 -Force -TryLGPO:$true

    Write-LogEntry "Filter Local administrator account privileged tokens"
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy' -Type DWord -Value 0 -Force -TryLGPO:$true

    Write-LogEntry "Enabling User Account Control approval mode"
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'FilterAdministratorToken' -Type DWord -Value 1 -Force -TryLGPO:$true

    Write-LogEntry "Disabling enumerating elevated administator accounts"
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI' -Name 'EnumerateAdministrators' -Type DWord -Value 0 -Force -TryLGPO:$true

    Write-LogEntry "Enable All credential or consent prompting will occur on the interactive user's desktop"
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'PromptOnSecureDesktop' -Type DWord -Value 1 -Force -TryLGPO:$true

    Write-LogEntry "Enforce cryptographic signatures on any interactive application that requests elevation of privilege"
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ValidateAdminCodeSignatures' -Type DWord -Value 0 -Force -TryLGPO:$true

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
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'AutoShareWks' -Type DWord -Value 0 -Force
}
Else{$stepCounter++}


If($CFG_DisableShutdownEventTracker)
{
    Show-ProgressStatus -Message "Disabling Shutdown Event Tracker" -Step ($stepCounter++) -MaxStep $script:Maxsteps
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability' -Name 'ShutdownReasonUI' -Type DWord -Value 0 -Force
}
Else{$stepCounter++}


If($DisableWindowsUpdates)
{
    Show-ProgressStatus -Message "Disabling Windows Updates" -Step ($stepCounter++) -MaxStep $script:Maxsteps
    
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' -Name 'NoAutoUpdate' -Type DWord -Value 1 -Force
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' -Name 'AUOptions' -Type DWord -Value 1 -Force
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' -Name 'ScheduleInstallDay' -Type DWord -Value 0 -Force
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' -Name 'ScheduleInstallTime' -Type DWord -Value 3 -Force
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'DisableOSUpgrade' -Type DWord -Value 1 -Force -TryLGPO:$true
}
Else{$stepCounter++}


If($DisableActionCenter)
{
    Show-ProgressStatus -Message("Disabling Windows Action Center Notifications") -Step ($stepCounter++) -MaxStep $script:Maxsteps

    #Write-LogEntry "hide the Action Center in 2012 R2"
    #Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'HideSCAHealth' -Type DWord -Value 1 -Force

    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell' -Name 'UseActionCenterExperience' -Type DWord -Value 0 -Force
    
    Set-UserSetting -Message "Disabling Windows Action Center Notifications" -Path 'SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'DisableNotificationCenter' -Type DWord -Value 1 -Force -TryLGPO:$true
}
Else{$stepCounter++}


If ($ApplyPrivacyMitigations)
{
    # Privacy and mitigaton settings
    # See: https://docs.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services

    Write-LogEntry ("Privacy Mitigations :: Disabling telemetry")
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value 0 -Force -TryLGPO:$true
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value 0 -Force
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value 0 -Force

    Write-LogEntry ("Privacy Mitigations :: Disable offline files")
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NetCache' -Name 'Enabled' -Type DWord -Value 0 -Force
}


If ($OptimizeServerOS){
    Write-LogEntry "Server Optimizations [SOPT ID:30] :: Disabling Background Layout Service"
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OptimalLayout' -Name 'EnableAutoLayout' -Type DWord -Value 0 -Force
    
    Write-LogEntry "Server Optimizations [SOPT ID:31] :: Disabling CIFS Change Notifications"
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoRemoteRecursiveEvents' -Type DWord -Value 0 -Force

    Write-LogEntry "Server Optimizations [SOPT ID:35] :: Disabling sending alert for the Crash Control"
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name 'SendAlert' -Type DWord -Value 0 -Force

    Write-LogEntry "Server Optimizations [SOPT ID:32] :: Increase services startup timeout from 30 to 45 second"
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name 'ServicesPipeTimeout' -Type DWord -Value 0xafc8 -Force

    Write-LogEntry "Server Optimizations [SOPT ID:33] :: Reduce Dedicated DumpFile to 2 MB"
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name 'DumpFileSize' -Type String -Value '2' -Force
    
    Write-LogEntry "Server Optimizations [SOPT ID:34] :: Enabling Automatically Reboot for the Crash Control"
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name 'AutoReboot' -Type DWord -Value 1 -Force

    Write-LogEntry "Server Optimizations [SOPT ID:35] :: Disabling sending alert for the Crash Control"
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name 'SendAlert' -Type DWord -Value 0 -Force

    Write-LogEntry "Server Optimizations [SOPT ID:36] :: Disabling writing event to the system log for the Crash Control"
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name 'LogEvent' -Type DWord -Value 0 -Force

    Write-LogEntry "Server Optimizations [SOPT ID:37] :: Disable Creation of Crash Dump and removes it"
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name 'CrashDumpEnabled' -Type DWord -Value 0 -Force

    Write-LogEntry "Server Optimizations [SOPT ID:38] :: Ignore Page file Size"
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name 'IgnorePagefileSize' -Type String -Value '1' -Force

    #Optional
    #Write-LogEntry "Server Optimizations [SOPT ID:39] :: Enabling wait time for disk write or read to take place on the SAN without throwing an error"
    #Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name "TimeOutValue' -Type DWord -Value '200' -Force

    Write-LogEntry "Server Optimizations [SOPT ID:40] :: Keep drivers and kernel on physical memory"
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'DisablePagingExecutive' -Type DWord -Value 0 -Force 
    
    Write-LogEntry "Server Optimizations [SOPT ID:41] :: Disable clear Page File at shutdown"
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'DisablePagingExecutive' -Type DWord -Value 0 -Force 

    Write-LogEntry "Server Optimizations [SOPT ID:42] :: Hide hard error messages"
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Windows' -Name 'ErrorMode' -Type DWord -Value 2 -Force 

    Write-LogEntry "Server Optimizations [SOPT ID:43] :: Log print job error notifications in Event Viewer"
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers' -Name 'EventLog' -Type DWord -Value 1 -Force 

    Write-LogEntry "Server Optimizations [SOPT ID:10] :: Reducing Application Event Log size"
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Application' -Name 'MaxSize' -Type DWord -Value 100000 -Force

    Write-LogEntry "VDI Optimizations :: Disabling Application Event Log Retention"
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\services\eventlog\Application' -Name 'Retention' -Type DWord -Value 0 -Force

    Write-LogEntry "Server Optimizations [SOPT ID:11] :: Reducing Security Event Log size"
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security' -Name 'MaxSize' -Type DWord -Value 100000 -Force 

    Write-LogEntry "VDI Optimizations :: Disabling Security Event Log Retention"
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\services\eventlog\Security' -Name 'Retention' -Type DWord -Value 0 -Force

    Write-LogEntry "Server Optimizations [SOPT ID:12] :: Reducing System Event Log size"
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\System' -Name 'MaxSize' -Type DWord -Value 100000 -Force
    
    Write-LogEntry "VDI Optimizations :: Disabling System Event Log Retention"
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\services\eventlog\System' -Name 'Retention' -Type DWord -Value 0 -Force

    Write-LogEntry "Server Optimizations [SOPT ID:287] :: Disabling  Boot Optimize Function"
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Dfrg\BootOptimizeFunction' -Name 'Enable' -Type String -Value '0' -Force
    
    Write-LogEntry "Server Optimizations [SOPT ID:200] :: Disable Logon Background Image."
    Set-SystemSetting -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'DisableLogonBackgroundImage' -Type DWord -Value 1 -Force -TryLGPO:$true
    
    Write-LogEntry "Server Optimizations [SOPT ID:288] :: Disk Timeout Value"
    Set-SystemSetting -Path 'HKLM:\SYSTEM\CurrentControlSet\services\Disk' -Name 'TimeOutValue' -Type DWord -Value 200 -Force
}
Else{$stepCounter++}


If($ShowKnownExtensions)
{
    Show-ProgressStatus -Message "Enabling known extensions" -Step ($stepCounter++) -MaxStep $script:Maxsteps
    Set-UserSetting -Message "Showing known file extensions" -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideFileExt' -Type DWord -Value 0 -Force
   
    #Write-LogEntry "Showing known file extensions for SYSTEM"
	#Set-SystemSetting -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideFileExt' -Type DWord -Value 0 -Force

}
Else{$stepCounter++}


If($ShowHiddenFiles)
{   
    Show-ProgressStatus -Message "Enabling hidden files" -Step ($stepCounter++) -MaxStep $script:Maxsteps
    Set-UserSetting -Message "Showing hidden files" -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'Hidden' -Type DWord -Value 1 -Force
}
Else{$stepCounter++}


If($RemoveVMToolsTrayIcon){
    if ( Test-Path "$Env:Programfiles\VMware\VMware Tools" ){
        Show-ProgressStatus -Message("Removing VM Tools Tray icon from taskbar") -Step ($stepCounter++) -MaxStep $script:Maxsteps
        Set-SystemSetting -Path 'HKLM:\SOFTWARE\VMware, Inc.\VMware Tools' -Name 'ShowTray' -Type DWord -Value 0 -Force
    }
}
Else{$stepCounter++}


If ($RemoveDefender)
{
    #Removing Windows Defender which also removes Scheduled Tasks and services related to Windows Defender
    Show-ProgressStatus -Message("Removing Windows defender Feature") -Step ($stepCounter++) -MaxStep $script:Maxsteps
    Try{
        Remove-WindowsFeature "Windows-Defender-Features" -ErrorAction Stop | Out-Null
    }
    Catch [System.Management.Automation.ActionPreferenceStopException]{
        Write-LogEntry ("Unable to Remove Windows defender. {0}" -f $_) -Severity 3
    }
}
Else{$stepCounter++}


If ($DisabledUnusedServices)
{
    $services = [ordered]@{
            AJRouterA="llJoyn Router Service"
            ALG="Application Layer Gateway Service"               
            AppMgmt="Application Management"
            BITS="Background Intelligent Transfer Service"
            bthserv="Bluetooth Support Service"
            DcpSvc="DataCollectionPublishingService"
            DPS="Diagnostic Policy Service"
            WdiServiceHost="Diagnostic Service Host"
            WdiSystemHost="Diagnostic System Host"
            DiagTrack="Connected User Experiences and Telemetry [Diagnostics Tracking Service]"
            dmwappushservice="dmwappushsvc"
            MapsBroker="Downloaded Maps Manager"
            EFS="Encrypting File System [EFS]"
            Eaphost="Extensible Authentication Protocol"
            FDResPub="Function Discovery Resource Publication"
            lfsvc="Geolocation Service"
            UI0Detect="Interactive Services Detection"
            SharedAccess="Internet Connection Sharing [ICS]"
            iphlpsvc="IP Helper"
            lltdsvc="Link-Layer Topology Discovery Mapper"
            "diagnosticshub.standardcollector.service"="Microsoft [R] Diagnostics Hub Standard Collector Service"
            wlidsvc="Microsoft Account Sign-in Assistant"
            MSiSCSI="Microsoft iSCSI Initiator Service"
            smphost="Microsoft Storage Spaces SMP"
            NcbService="Network Connection Broker"
            NcaSvc="Network Connectivity Assistant"
            defragsvc="Optimize drives"
            wercplsupport="Problem Reports and Solutions Control Panel"
            PcaSvc="Program Compatibility Assistant Service"
            QWAVE="Quality Windows Audio Video Experience"
            RmSvc="Radio Management Service"
            RasMan="Remote Access Connection Manager"
            SstpSvc="Secure Socket Tunneling Protocol Service"
            SensorDataService="Sensor Data Service"
            SensrSvc="Sensor Monitoring Service"
            SensorService="Sensor Service"
            SNMPTRAP="SNMP Trap"
            sacsvr="Special Administration Console Helper"
            svsvc="Spot Verifier"
            SSDPSRV="SSDP Discovery"
            TieringEngineService="Storage Tiers Management"
            SysMain="Superfetch"
            TapiSrv="Telephony"
            UALSVC="User Access Logging Service"
            Wcmsvc="Windows Connection Manager"
            WerSvc="Windows Error Reporting Service"
            wisvc="Windows Insider Service"
            icssvc="Windows Mobile Hotspot Service"
            wuauserv="Windows Update"
            dot3svc="Wired AutoConfig"
            XblAuthManager="Xbox Live Auth Manager"
            XblGameSave="Xbox Live Game Save"
    }

    $i = 1
    Foreach ($key in $services.GetEnumerator()){
        #write-host ("`"{1}`"=`"{0}`"" -f $key.Key,$key.Value)
        $SvcName = $key.Value
        
        Write-LogEntry ("Disabling {0} Service [{1}]" -f $SvcName,$key.Key)

        Show-ProgressStatus -Message "Disabling Unused Service" -SubMessage ("Removing: {2} ({0} of {1})" -f $i,$services.count,$SvcName) -Step $i -MaxStep $services.count

        Try{
            Set-Service $key.Key -StartupType Disabled -ErrorAction Stop | Out-Null
        }
        Catch [System.Management.Automation.ActionPreferenceStopException]{
            Write-LogEntry ("Unable to Disable {0} Service: {1}" -f $SvcName,$_) -Severity 3
        }

        Start-Sleep -Seconds 10
        $i++
    }

    $SyncService = Get-Service -Name OneSync* | select -ExpandProperty Name
    Set-Service $SyncService -StartupType Disabled -ErrorAction Stop | Out-Null

}
Else{$stepCounter++}


# Disable Scheduled Tasks
If ($DisableSchTasks)
{
    Show-ProgressStatus -Message "Disabling Scheduled Tasks" -Step ($stepCounter++) -MaxStep $script:Maxsteps

    $ScheduledTasks = [ordered]@{
          "AD RMS Rights Policy Template Management (Manual)"="\Microsoft\Windows\Active Directory Rights Management Services Client"
          "EDP Policy Manager"="\Microsoft\Windows\AppID"
          "SmartScreenSpecific"="\Microsoft\Windows\AppID"
          "Microsoft Compatibility Appraiser"="\Microsoft\Windows\Application Experience"
          "ProgramDataUpdater"="\Microsoft\Windows\Application Experience"
          "StartupAppTask"="\Microsoft\Windows\Application Experience"
          "CleanupTemporaryState"="\Microsoft\Windows\ApplicationData"
          "DsSvcCleanup"="\Microsoft\Windows\ApplicationData"
          "Proxy"="\Microsoft\Windows\Autochk"
          "UninstallDeviceTask"="\Microsoft\Windows\Bluetooth"
          "AikCertEnrollTask"="\Microsoft\Windows\CertificateServicesClient"
          "CryptoPolicyTask"="\Microsoft\Windows\CertificateServicesClient"
          "KeyPreGenTask"="\Microsoft\Windows\CertificateServicesClient"
          "ProactiveScan"="\Microsoft\Windows\Chkdsk"
          "CreateObjectTask"="\Microsoft\Windows\CloudExperienceHost"
          "Consolidator"="\Microsoft\Windows\Customer Experience Improvement Program"
          "KernelCeipTask"="\Microsoft\Windows\Customer Experience Improvement Program"
          "UsbCeip"="\Microsoft\Windows\Customer Experience Improvement Program"
          "Data Integrity Scan"="\Microsoft\Windows\Data Integrity Scan"
          "Data Integrity Scan for Crash Recovery"="\Microsoft\Windows\Data Integrity Scan"
          "ScheduledDefrag"="\Microsoft\Windows\Defrag"
          "Device"="\Microsoft\Windows\Device Information"
          "Scheduled"="\Microsoft\Windows\Diagnosis"
          "SilentCleanup"="\Microsoft\Windows\DiskCleanup"
          "Microsoft-Windows-DiskDiagnosticDataCollector"="\Microsoft\Windows\DiskDiagnostic"
          "Notifications"="\Microsoft\Windows\Location"
          "WindowsActionDialog"="\Microsoft\Windows\Location"
          "WinSAT"="\Microsoft\Windows\Maintenance"
          "MapsToastTask"="\Microsoft\Windows\Maps"
          "MNO Metadata Parser"="\Microsoft\Windows\Mobile Broadband Accounts"
          "LPRemove"="\Microsoft\Windows\MUI"
          "GatherNetworkInfo"="\Microsoft\Windows\NetTrace"
          "Secure-Boot-Update"="\Microsoft\Windows\PI"
          "Sqm-Tasks"="\Microsoft\Windows\PI"
          "AnalyzeSystem"="\Microsoft\Windows\Power Efficiency Diagnostics"
          "MobilityManager"="\Microsoft\Windows\Ras"
          "VerifyWinRE"="\Microsoft\Windows\RecoveryEnvironment"
          "RegIdleBackup"="\Microsoft\Windows\Registry"
          "CleanupOldPerfLogs"="\Microsoft\Windows\Server Manager"
          "StartComponentCleanup"="\Microsoft\Windows\Servicing"
          "IndexerAutomaticMaintenance"="\Microsoft\Windows\Shell"
          "Configuration"="\Microsoft\Windows\Software Inventory Logging"
          "SpaceAgentTask"="\Microsoft\Windows\SpacePort"
          "SpaceManagerTask"="\Microsoft\Windows\SpacePort"
          "SpeechModelDownloadTask"="\Microsoft\Windows\Speech"
          "Storage Tiers Management Initialization"="\Microsoft\Windows\Storage Tiers Management"
          "Tpm-HASCertRetr"="\Microsoft\Windows\TPM"
          "Tpm-Maintenance"="\Microsoft\Windows\TPM"
          "Schedule Scan"="\Microsoft\Windows\UpdateOrchestrator"
          "ResolutionHost"="\Microsoft\Windows\WDI"
          "QueueReporting"="\Microsoft\Windows\Windows Error Reporting"
          "BfeOnServiceStartTypeChange"="\Microsoft\Windows\Windows Filtering Platform"
          "Automatic App Update"="\Microsoft\Windows\WindowsUpdate"
          "Scheduled Start"="\Microsoft\Windows\WindowsUpdate"
          "sih"="\Microsoft\Windows\WindowsUpdate"
          "sihboot"="\Microsoft\Windows\WindowsUpdate"
          "XblGameSaveTask"="\Microsoft\XblGameSave"
          "XblGameSaveTaskLogon"="\Microsoft\XblGameSave"
    }

    Foreach ($task in $ScheduledTasks.GetEnumerator()){
        Write-LogEntry ('Disabling [{0}]' -f $task.Key)
        Disable-ScheduledTask -TaskName $task.Value -ErrorAction SilentlyContinue | Out-Null
    }

}
Else{$stepCounter++}


If($DisabledHyperVServices)
{
    $services = [ordered]@{
        HvHost="HV Host Service"
        vmickvpexchange="Hyper-V Data Exchange Service"
        vmicguestinterface="Hyper-V Guest Service Interface"
        vmicshutdown="Hyper-V Guest Shutdown Interface"
        vmicheartbeat="Hyper-V Heartbeat Service"
        vmicvmsession="Hyper-V PowerShell Direct Service"
        vmicrdv="Hyper-V Remote Desktop Virtualization Service"
        vmictimesync="Hyper-V Time Synchronization Service"
        vmicvss="Hyper-V Volume Shadow Copy Requestor"
    }

    $i = 1
    Foreach ($key in $services.GetEnumerator()){
        #write-host ("`"{1}`"=`"{0}`"" -f $key.Key,$key.Value)
        $SvcName = $key.Value
        
        Write-LogEntry ("Disabling {0} Service [{1}]" -f $SvcName,$key.Key)

        Show-ProgressStatus -Message "Disabling Hyper-V Service" -SubMessage ("Removing: {2} ({0} of {1})" -f $i,$services.count,$SvcName) -Step $i -MaxStep $services.count

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


If($MoveEventLogsToDrive){
    Write-LogEntry ("Moving Security Event Log from default location to $MoveEventLogsToDrive") -Severity 1 -Outhost
    Set-SystemSetting -Path 'HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security' -Name 'File' -Type  -Value "$($MoveEventLogsToDrive):\Event Logs\Security.evtx"

    Write-LogEntry ("Movinge System Event Log from default location to $MoveEventLogsToDrive") -Severity 1 -Outhost
    Set-SystemSetting -Path 'HKLM\SYSTEM\CurrentControlSet\Services\EventLog\System' -Name 'File' -Type REG_EXPAND_SZ -Value "$($MoveEventLogsToDrive):\Event Logs\Security.evtx"
}


If($OptimizeNetwork)
{
    Write-LogEntry "Server Optimizations :: Configuring SMB Modifications for performance"
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