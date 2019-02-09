# Windows 10 Optimization And Configurations
 - Applies all types of settings for Windows 10. Script variables can be set either internal (standalone) or using MDT/SCCM Task sequence custom properties. Ultimately MDT/SCCM properties will overwrite internal variable if set. 

## Options not working (yet)
** Reason: the goal is to set any registry settings within local gpo instead of hard coding the registry **
 - CFG_UseLGPOForConfigs=True 
 - LGPOPath=%DeployRoot%\Scripts\Custom\OS-Configs\Tools\LGPO
 
## Add to MDT CustomSettings.ini
    
	- Properties=CFG_UseLGPOForConfigs,LGPOPath,CFG_SetPowerCFG,CFG_PowerCFGFilePath,CFG_EnableVerboseMsg,CFG_ApplySTIGItems,CFG_DisableAutoRun,
	CFG_CleanSampleFolders,CFG_DisableCortana,CFG_DisableInternetSearch,CFG_EnableVDIOptimizations,CFG_EnableOfficeOneNote,CFG_EnableRDP,CFG_DisableOneDrive,CFG_PreferIPv4OverIPv6,
	CFG_RemoveActiveSetupComponents,CFG_DisableWindowsFirstLoginAnimation,CFG_DisableIEFirstRunWizard,CFG_DisableWMPFirstRunWizard,CFG_DisableEdgeIconCreation,CFG_DisableNewNetworkDialog,
	CFG_DisableInternetServices,CFG_DisabledUnusedServices,CFG_DisabledUnusedFeatures,CFG_DisableSchTasks,CFG_DisableDefender,CFG_DisableFirewall,CFG_DisableWireless,CFG_DisableBluetooth,
	CFG_EnableRemoteRegistry,CFG_DisableFirewall,CFG_ApplyPrivacyMitigations,CFG_EnableCredGuard,CFG_InstallLogonScript,CFG_LogonScriptPath,CFG_EnableWinRM,CFG_EnableAppsRunAsAdmin,
	CFG_DisableUAC,CFG_DisableWUP2P,CFG_EnableIEEnterpriseMode,CFG_IEEMSiteListPath,CFG_PreCompileAssemblies,CFG_EnableSecureLogon,CFG_HideDrives,CFG_DisableAllNotifications,
	CFG_InstallPSModules,CFG_EnableVisualPerformance,CFG_EnableDarkTheme,CFG_EnableNumlockStartup,CFG_ShowKnownExtensions,CFG_ShowHiddenFiles,CFG_ShowThisPCOnDesktop,
	CFG_ShowUserFolderOnDesktop,CFG_Hide3DObjectsFromExplorer,CFG_DisableEdgeShortcut,SCCMSiteServer,AppVolMgrServer,AdminMenuConfigPath,CFG_SetSmartScreenFilter,CFG_EnableStrictUAC,
	CFG_ApplyCustomHost,HostPath,CFG_DisableStoreOnTaskbar,CFG_DisableActionCenter,CFG_DisableFeedback,CFG_DisableWindowsUpgrades

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




