# Windows 10 Optimization And Configurations
 - Applies all types of settings for Windows 10. Script variables can be set either internal (standalone) or using MDT/SCCM Task sequence custom properties. Ultimately MDT/SCCM properties will overwrite internal variable if set. 

## Prerequisites
 - Group Policy Support - download LGPO (https://www.microsoft.com/en-us/download/confirmation.aspx?id=55319) and place it ins the Tools folder
 - CredGuard Support - download creadguard script by Microsoft (https://www.microsoft.com/en-us/download/confirmation.aspx?id=53337)
 - Modules Install - Any Modules, place in PSModules directory
 
## Add to MDT CustomSettings.ini
<<<<<<< HEAD
    
	- Properties=CFG_UseLGPOForConfigs,LGPOPath,CFG_SetPowerCFG,CFG_PowerCFGFilePath,CFG_EnableVerboseMsg,CFG_ApplySTIGItems,CFG_DisableAutoRun,
	CFG_CleanSampleFolders,CFG_DisableCortana,CFG_DisableInternetSearch,CFG_EnableVDIOptimizations,CFG_EnableOfficeOneNote,CFG_EnableRDP,CFG_DisableOneDrive,CFG_PreferIPv4OverIPv6,
	CFG_RemoveActiveSetupComponents,CFG_DisableWindowsFirstLoginAnimation,CFG_DisableIEFirstRunWizard,CFG_DisableWMPFirstRunWizard,CFG_DisableEdgeIconCreation,CFG_DisableNewNetworkDialog,
	CFG_DisableInternetServices,CFG_DisabledUnusedServices,CFG_DisabledUnusedFeatures,CFG_DisableSchTasks,CFG_DisableDefender,CFG_DisableFirewall,CFG_DisableWireless,CFG_DisableBluetooth,
	CFG_EnableRemoteRegistry,CFG_DisableFirewall,CFG_ApplyPrivacyMitigations,CFG_EnableCredGuard,CFG_InstallLogonScript,CFG_LogonScriptPath,CFG_EnableWinRM,CFG_EnableAppsRunAsAdmin,
	CFG_DisableUAC,CFG_DisableWUP2P,CFG_EnableIEEnterpriseMode,CFG_IEEMSiteListPath,CFG_PreCompileAssemblies,CFG_EnableSecureLogon,CFG_HideDrives,CFG_DisableAllNotifications,
	CFG_InstallPSModules,CFG_EnableVisualPerformance,CFG_EnableDarkTheme,CFG_EnableNumlockStartup,CFG_ShowKnownExtensions,CFG_ShowHiddenFiles,CFG_ShowThisPCOnDesktop,
	CFG_ShowUserFolderOnDesktop,CFG_Hide3DObjectsFromExplorer,CFG_DisableEdgeShortcut,SCCMSiteServer,AppVolMgrServer,AdminMenuConfigPath,CFG_SetSmartScreenFilter,CFG_EnableStrictUAC,
	CFG_ApplyCustomHost,HostPath,CFG_DisableStoreOnTaskbar,CFG_DisableActionCenter,CFG_DisableFeedback,CFG_DisableWindowsUpgrades
=======
    Properties=CFG_UseLGPOForConfigs,LGPOPath,CFG_SetPowerCFG,CFG_PowerCFGFilePath,CFG_EnableVerboseMsg,CFG_EnablePSLogging,CFG_ApplySTIGItems,CFG_DisableAutoRun,CFG_CleanSampleFolders,CFG_DisableCortana,CFG_DisableInternetSearch,CFG_EnableVDIOptimizations,CFG_EnableOfficeOneNote,CFG_EnableRDP,CFG_DisableOneDrive,CFG_PreferIPv4OverIPv6,CFG_RemoveActiveSetupComponents,CFG_DisableWindowsFirstLoginAnimation,CFG_DisableIEFirstRunWizard,CFG_DisableWMPFirstRunWizard,CFG_DisableEdgeIconCreation,CFG_DisableNewNetworkDialog,CFG_DisableInternetServices,CFG_DisabledUnusedServices,CFG_DisabledUnusedFeatures,CFG_DisableSchTasks,CFG_DisableDefender,CFG_DisableFirewall,CFG_DisableWireless,CFG_DisableBluetooth,CFG_EnableRemoteRegistry,CFG_DisableFirewall,CFG_ApplyPrivacyMitigations,CFG_EnableCredGuard,CFG_InstallLogonScript,CFG_LogonScriptPath,CFG_EnableWinRM,CFG_EnableAppsRunAsAdmin,CFG_DisableUAC,CFG_DisableWUP2P,CFG_EnableIEEnterpriseMode,CFG_IEEMSiteListPath,CFG_PreCompileAssemblies,CFG_DisableIndexing,CFG_EnableSecureLogon,CFG_HideDrives,CFG_DisableAllNotifications,CFG_InstallPSModules
>>>>>>> e333b134ff84cc1dd09aac7a0846ff59ae825370

## Configuration Settings (see CustomSettings.exmaple.ini)
    CFG_UseLGPOForConfigs=True
    CFG_SetPowerCFG=[Custom|High Performance|Balanced]
    CFG_PowerCFGFilePath=%DeployRoot%\Scripts\Custom\OS-Configs\AlwaysOnPowerScheme.pow
    CFG_ApplySTIGItems=True
    CFG_EnableVerboseMsg=True
    CFG_EnablePSLogging=True
    CFG_DisableAutoRun=True
    CFG_CleanSampleFolders=True
    CFG_DisableCortana=True
    CFG_DisableInternetSearch=True
    CFG_EnableVDIOptimizations=True
    CFG_EnableOfficeOneNote=True
    ...




