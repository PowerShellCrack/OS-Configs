
<#
.SYNOPSIS
Chocolatey Wrapper

.DESCRIPTION
Wrapper arround the Chocolatey (Chocolatey.org) package wrapper system.

.NOTES

This script will read in a list of chocolatey packages from the MDT Chocolatey variable 
and install each package locally.

The Chocolatey scripts are kept in the c:\minint folder so they are not added to any images.
Because of this, be aware of any "Portable" applications that are installed under c:\minint.

CustomSettings.ini example:

[Settings]
Priority=Default
Properties=Chocolatey

[Default]
...
Chocolatey001=WindowsADK
Chocolatey002=AdobeReader
Chocolatey003=vcredist2010

.LINK

Microsoft Deployment Toolkit Extensions https://github.com/keithga/DeployShared
Copyright Keith Garner, all rights reserved.

http://keithga.wordpress.com
http://Chocolatey.org

#>

[CmdletBinding()]
param(
    [parameter(ValueFromRemainingArguments=$true)]
    [string[]]$Packages = $TSEnvList:Chocolatey
)

write-verbose "Construct a local path for Chocolatey"
if ($env:ChocolateyInstall -eq $Null)
{
    $env:ChocolateyInstall = [Environment]::GetEnvironmentVariable( "ChocolateyInstall" , [System.EnvironmentVariableTarget]::User)
    if ( -not $env:ChocolateyInstall)
    {
        $env:ChocolateyInstall = join-path ([System.Environment]::GetFolderPath("CommonApplicationData")) "Chocolatey"
        if ( test-path "c:\MININT\SMSOSD\OSDLOGS\bdd.log" )
        {
            $env:ChocolateyInstall = "c:\MININT\Chocolatey"
        }
        else
        {
            $env:ChocolateyInstall = "$($tsenv:LogPath)\..\Chocolatey"
        }
    }
}

$ChocoExe = join-path $env:ChocolateyInstall "bin\choco.exe"

write-verbose "Chocolatey Program: $ChocoExe"
if ( ! (test-path $ChocoExe ) )
{
    write-verbose "Install Chocolatey..."
    Invoke-Expression ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1'))
    if (!(test-path $ChocoExe))
    {
        throw "Chocolatey Install not found!"
    }
}


write-verbose "Install Chocolatey packages from within MDT"
foreach ( $Package in $Packages ) 
{
    write-verbose "Install Chocolatey Package: $ChocoExe $Package"
    invoke-expression "cmd.exe /c $chocoExe Install $Package  -y -v 2>&1" | write-verbose

    if ( $LastExitCode -eq 3010 )
    {
        oEnvironment.Item("SMSTSRebootRequested") = "true"
    }

}

write-verbose "Chocolatey install done"
