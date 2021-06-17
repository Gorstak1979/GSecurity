@echo off
CLS
ECHO.
ECHO =============================
ECHO Running Admin shell
ECHO =============================

:init
setlocal DisableDelayedExpansion
set "batchPath=%~0"
for %%k in (%0) do set batchName=%%~nk
set "vbsGetPrivileges=%temp%\OEgetPriv_%batchName%.vbs"
setlocal EnableDelayedExpansion

:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)
ECHO.
ECHO **************************************
ECHO Invoking UAC for Privilege Escalation
ECHO **************************************

ECHO Set UAC = CreateObject^("Shell.Application"^) > "%vbsGetPrivileges%"
ECHO args = "ELEV " >> "%vbsGetPrivileges%"
ECHO For Each strArg in WScript.Arguments >> "%vbsGetPrivileges%"
ECHO args = args ^& strArg ^& " "  >> "%vbsGetPrivileges%"
ECHO Next >> "%vbsGetPrivileges%"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%vbsGetPrivileges%"
"%SystemRoot%\System32\WScript.exe" "%vbsGetPrivileges%" %*
exit /B

:gotPrivileges
setlocal & pushd .
cd /d %~dp0
if '%1'=='ELEV' (del "%vbsGetPrivileges%" 1>nul 2>nul  &  shift /1)
Title GSecurity
Color 0b
:: Make current folder active one
pushd %~dp0
:: Remove user account
net user defaultuser0 /delete
:: Debloat
powershell "Get-AppxPackage -AllUsers | Where {($_.Name -notlike '*store*')} | Where {($_.Name -notlike '*Edge*')} | Where {($_.Name -notlike '*nvidia*')} | Where {($_.Name -notlike '*identity*')} | Where {($_.Name -notlike '*host*')} | Where {($_.Name -notlike '*calc*')} | Where {($_.Name -notlike '*photos*')} | Remove-AppxPackage"
powershell "Get-AppxProvisionedPackage -Online | Where {($_.Name -notlike '*store*')} | Where {($_.Name -notlike '*Edge*')} | Where {($_.Name -notlike '*nvidia*')} | Where {($_.Name -notlike '*identity*')} | Where {($_.Name -notlike '*host*')} | Where {($_.Name -notlike '*calc*')} | Where {($_.Name -notlike '*photos*')} | Remove-AppxProvisionedPackage -Online"
:: Take ownership of desktop
takeown /F "%SystemDrive%\Users\Public\Desktop" /r /d y
icacls "%SystemDrive%\Users\Public\Desktop" /grant:r %username%:(OI)(CI)F /t /l /q /c
takeown /F "%USERPROFILE%\Desktop" /r /d y
icacls "%USERPROFILE%\Desktop" /grant:r %username%:(OI)(CI)F /t /l /q /c
:: Configure DNS
wmic nicconfig where (IPEnabled=TRUE) call SetDNSServerSearchOrder ("5.2.75.75", "94.140.14.14", "1.1.1.1")
:: Setup tasks
schtasks /DELETE /TN "Adobe Flash Player PPAPI Notifier" /f
schtasks /DELETE /TN "Adobe Flash Player Updater" /f
schtasks /DELETE /TN "AMDLinkUpdate" /f
schtasks /DELETE /TN "Driver Easy Scheduled Scan" /f
schtasks /DELETE /TN "GPU Tweak II" /f
schtasks /DELETE /TN "klcp_update" /f
schtasks /DELETE /TN "ModifyLinkUpdate" /f
schtasks /DELETE /TN "Repairing Yandex Browser update service" /f
schtasks /DELETE /TN "StartDVR" /f
schtasks /DELETE /TN "StartCN" /f
schtasks /DELETE /TN "System update for Yandex Browser" /f
schtasks /DELETE /TN "Update for Yandex Browser" /f
schtasks /Change /TN "CreateExplorerShellUnelevatedTask" /Enable
schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319" /Disable
schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64" /Disable
schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64 Critical" /Disable
schtasks /Change /TN "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 Critical" /Disable
schtasks /Change /TN "Microsoft\Windows\ApplicationData\appuriverifierdaily" /Disable
schtasks /Change /TN "Microsoft\Windows\ApplicationData\appuriverifierinstall" /Disable
schtasks /Change /TN "Microsoft\Windows\ApplicationData\CleanupTemporaryState" /Disable
schtasks /Change /TN "Microsoft\Windows\ApplicationData\DsSvcCleanup" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable
schtasks /Change /TN "Microsoft\Windows\AppxDeploymentClient\Pre-staged app cleanup" /Disable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable
schtasks /Change /TN "Microsoft\Windows\BrokerInfrastructure\BgTaskRegistrationMaintenanceTask" /Disable
schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
schtasks /Change /TN "Microsoft\Windows\Device Information\Device" /Disable
schtasks /Change /TN "Microsoft\Windows\Defrag\ScheduledDefrag" /Disable
schtasks /Change /TN "Microsoft\Windows\Diagnosis\Scheduled" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskCleanup\SilentCleanup" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\StorageSense" /Disable
schtasks /Change /TN "Microsoft\Windows\DUSM\dusmtask" /Disable
schtasks /Change /TN "Microsoft\Windows\EnterpriseMgmt\MDMMaintenenceTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /Disable
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /Disable
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable
schtasks /Change /TN "Microsoft\Windows\Flighting\OneSettings\RefreshCache" /Disable
schtasks /Change /TN "Microsoft\Windows\HelloFace\FODCleanupTask" /Disable
schtasks /Change /TN "Microsoft\Windows\InstallService\ScanForUpdates" /Disable
schtasks /Change /TN "Microsoft\Windows\InstallService\ScanForUpdatesAsUser" /Disable
schtasks /Change /TN "Microsoft\Windows\InstallService\WakeUpAndContinueUpdates" /Disable
schtasks /Change /TN "Microsoft\Windows\InstallService\WakeUpAndScanForUpdates" /Disable
schtasks /Change /TN "Microsoft\Windows\InstallService\SmartRetry" /Disable
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\Installation" /Disable
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\ReconcileLanguageResources" /Disable
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\Uninstallation" /Disable
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /Disable
schtasks /Change /TN "Microsoft\Windows\Location\Notifications" /Disable
schtasks /Change /TN "Microsoft\Windows\Location\WindowsActionDialog" /Disable
schtasks /Change /TN "Microsoft\Windows\Management\Provisioning\Cellular" /Disable
schtasks /Change /TN "Microsoft\Windows\Management\Provisioning\Logon" /Disable
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable
schtasks /Change /TN "Microsoft\Windows\Maps\MapsToastTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Maps\MapsUpdateTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser" /Disable
schtasks /Change /TN "Microsoft\Windows\Multimedia\SystemSoundsService" /Disable
schtasks /Change /TN "Microsoft\Windows\NlaSvc\WiFiTask" /Disable
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable
schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /Disable
schtasks /Change /TN "Microsoft\Windows\Printing\EduPrintProv" /Disable
schtasks /Change /TN "Microsoft\Windows\PushToInstall\Registration" /Disable
schtasks /Change /TN "Microsoft\Windows\Ras\MobilityManager" /Disable
schtasks /Change /TN "Microsoft\Windows\RecoveryEnvironment\VerifyWinRE" /Disable
schtasks /Change /TN "Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask" /Disable
schtasks /Change /TN "Microsoft\Windows\RetailDemo\CleanupOfflineContent" /Disable
schtasks /Change /TN "Microsoft\Windows\Servicing\StartComponentCleanup" /Disable
schtasks /Change /TN "Microsoft\Windows\SettingSync\BackgroundUploadTask" /Disable
schtasks /Change /TN "Microsoft\Windows\SettingSync\BackupTask" /Disable
schtasks /Change /TN "Microsoft\Windows\SettingSync\NetworkStateChangeTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Shell\CreateObjectTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Setup\SetupCleanupTask" /Disable
schtasks /Change /TN "Microsoft\Windows\SpacePort\SpaceAgentTask" /Disable
schtasks /Change /TN "Microsoft\Windows\SpacePort\SpaceManagerTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Speech\HeadsetButtonPress" /Disable
schtasks /Change /TN "Microsoft\Windows\Speech\SpeechModelDownloadTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Storage Tiers Management\Storage Tiers Management Initialization" /Disable
schtasks /Change /TN "Microsoft\Windows\Subscription\EnableLicenseAcquisition" /Disable
schtasks /Change /TN "Microsoft\Windows\Subscription\LicenseAcquisition" /Disable
schtasks /Change /TN "Microsoft\Windows\Sysmain\ResPriStaticDbSync" /Disable
schtasks /Change /TN "Microsoft\Windows\Sysmain\WsSwapAssessmentTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Task Manager\Interactive" /Disable
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /Disable
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\SynchronizeTime" /Disable
schtasks /Change /TN "Microsoft\Windows\Time Zone\SynchronizeTimeZone" /Disable
schtasks /Change /TN "Microsoft\Windows\TPM\Tpm-HASCertRetr" /Disable
schtasks /Change /TN "Microsoft\Windows\TPM\Tpm-Maintenance" /Disable
schtasks /Change /TN "Microsoft\Windows\UPnP\UPnPHostConfig" /Disable
schtasks /Change /TN "Microsoft\Windows\USB\Usb-Notifications" /Disable
schtasks /Change /TN "Microsoft\Windows\User Profile Service\HiveUploadTask" /Disable
schtasks /Change /TN "Microsoft\Windows\WCM\WiFiTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Media Sharing\UpdateLibrary" /Disable
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Scheduled Start" /Disable
schtasks /Change /TN "Microsoft\Windows\WlanSvc\CDSSync" /Disable
schtasks /Change /TN "Microsoft\Windows\WOF\WIM-Hash-Management" /Disable
schtasks /Change /TN "Microsoft\Windows\WOF\WIM-Hash-Validation" /Disable
schtasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Logon Synchronization" /Disable
schtasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Maintenance Work" /Disable
schtasks /Change /TN "Microsoft\Windows\Workplace Join\Automatic-Device-Join" /Disable
schtasks /Change /TN "Microsoft\Windows\WwanSvc\NotificationTask" /Disable
:: Firewall rules deletion
Echo Y | Reg.exe delete "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Defaults\FirewallPolicy\FirewallRules" /f
Echo Y | Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Defaults\FirewallPolicy\FirewallRules" /f
Echo Y | Reg.exe delete "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\AppIso\FirewallRules" /f
Echo Y | Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\AppIso\FirewallRules" /f
Echo Y | Reg.exe delete "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Configurable\System" /f
Echo Y | Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Configurable\System" /f
Echo Y | Reg.exe delete "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\System" /f
Echo Y | Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\System" /f
Echo Y | Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /f
:: Privacy
echo "" > C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl
:: prclaunchky
net user administrator /active:yes
sc delete SessionEnv
sc stop SessionEnv
sc delete TermService
sc stop TermService
sc delete UmRdpService
sc stop UmRdpService
sc delete RemoteRegistry
sc stop RemoteRegistry
sc delete Rasman
sc stop Rasman
sc delete RasAuto
sc delete RmSvc
takeown /f C:\Windows\System32\termsrv.dll
cacls termsrv.dll /E /P %username%:F
del C:\Windows\System32\termsrv.dll
takeown /f C:\Windows\System32\termmgr.dll
cacls termmgr.dll /E /P %username%:F
del C:\Windows\System32\termmgr.dll
sc delete CDPSvc
sc stop CDPSvc
sc delete CDPUserSvc
sc stop CDPUsersvc
sc delete DiagTrack
sc stop DiagTrack
sc delete PimIndexMaintenanceSvc
sc stop PimIndexMaintenanceSvc
sc config DPS start= disabled
sc stop DPS
sc config WdiServiceHost start= disabled
sc stop WdiServiceHost
sc config WdiSystemHost start= disabled
sc stop WdiSystemHost
net user administrator /active:yes
sc config NlaSvc start= disabled
sc config netprofm start= disabled
sc config AppVClient start= disabled
sc config Wecsvc start= disabled
sc config WerSvc start= disabled
sc config EventLog start= disabled
sc delete RdpVideoMiniport
sc delete tsusbflt
sc delete tsusbhub 
sc delete TsUsbGD
sc delete RDPDR
sc delete rdpbus
sc start rdpbus
sc stop rdpbus
sc delete RasPppoe
sc delete NdisWan
sc delete NdisTapi
sc delete ndiswanlegacy
sc delete wanarpv6
sc delete wanarp
sc delete RasAcd
takeown /f C:\Windows\System32\drivers\rdpbus.sys
cacls C:\Windows\System32\drivers\rdpbus.sys /E /P %username%:F
del C:\Windows\System32\drivers\rdpbus.sys
:: Import registry tweaks
Echo Y | Reg.exe add "HKCU\Control Panel\Accessibility" /v "MessageDuration" /t REG_DWORD /d "5" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Accessibility" /v "MinimumHitRadius" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Accessibility\AudioDescription" /v "Locale" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Accessibility\AudioDescription" /v "On" /t REG_SZ /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Accessibility\Blind Access" /v "On" /t REG_SZ /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Accessibility\HighContrast" /v "Flags" /t REG_SZ /d "126" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Accessibility\HighContrast" /v "High Contrast Scheme" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Accessibility\HighContrast" /v "Previous High Contrast Scheme MUI Value" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Preference" /v "On" /t REG_SZ /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "AutoRepeatDelay" /t REG_SZ /d "1000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "AutoRepeatRate" /t REG_SZ /d "500" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "BounceTime" /t REG_SZ /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "DelayBeforeAcceptance" /t REG_SZ /d "1000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "126" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Last BounceKey Setting" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Last Valid Delay" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Last Valid Repeat" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Last Valid Wait" /t REG_DWORD /d "1000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Accessibility\MouseKeys" /v "Flags" /t REG_SZ /d "62" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Accessibility\MouseKeys" /v "MaximumSpeed" /t REG_SZ /d "80" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Accessibility\MouseKeys" /v "TimeToMaximumSpeed" /t REG_SZ /d "3000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Accessibility\On" /v "Locale" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Accessibility\On" /v "On" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Accessibility\ShowSounds" /v "On" /t REG_SZ /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Accessibility\SlateLaunch" /v "ATapp" /t REG_SZ /d "narrator" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Accessibility\SlateLaunch" /v "LaunchAT" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Accessibility\SoundSentry" /v "Flags" /t REG_SZ /d "2" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Accessibility\SoundSentry" /v "FSTextEffect" /t REG_SZ /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Accessibility\SoundSentry" /v "TextEffect" /t REG_SZ /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Accessibility\SoundSentry" /v "WindowsEffect" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "510" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Accessibility\TimeOut" /v "Flags" /t REG_SZ /d "2" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Accessibility\TimeOut" /v "TimeToWait" /t REG_SZ /d "300000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "62" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Appearance" /v "SchemeLangID" /t REG_BINARY /d "0904" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Appearance" /v "NewCurrent" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Appearance" /v "Current" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Appearance\New Schemes" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Appearance\Schemes" /v "@themeui.dll,-850" /t REG_BINARY /d "02000000460000000100000011000000110000001400000014000000f5ffffff000000000000000000000000bc02000000000000000000004d006900630072006f0073006f00660074002000530061006e0073002000530065007200690066000000fc7f2214fc7fb0fe120000000000000000009823eb770f0000000f000000f5ffffff000000000000000000000000bc02000000000000000000004d006900630072006f0073006f00660074002000530061006e0073002000530065007200690066000000f077002014000000001080051400f01f1400000014001200000012000000f5ffffff0000000000000000000000009001000000000000000000004d006900630072006f0073006f00660074002000530061006e0073002000530065007200690066000000140088fbe87702020000acb9f0770000000020000000f5ffffff0000000000000000000000009001000000000000000000004d006900630072006f0073006f00660074002000530061006e007300200053006500720069006600000000000000000000000000000000007c6be87700000000f5ffffff0000000000000000000000009001000000000000000000004d006900630072006f0073006f00660074002000530061006e007300200053006500720069006600000000000600000018000000fffffffff04b21fc00c4f077f5ffffff000000000000000000000000bc02000000000000000000004d006900630072006f0073006f00660074002000530061006e007300200053006500720069006600000014000b00000000ff120050000000c0fe12000c10000100000000000000000000ff0000ffff000000000000000000ffffff00ffffff00ffff0000ffffff000000ff0000ffff000000000000800000ffffff00000000008080800000ff0000ffffff0000000000c0c0c000ffffff00ffffff00ffff000000000000c0c0c0008080ff000000ff0000ffff00" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Appearance\Schemes" /v "@themeui.dll,-851" /t REG_BINARY /d "02000000460000000100000011000000110000001400000014000000f5ffffff000000000000000000000000bc02000000000000000000004d006900630072006f0073006f00660074002000530061006e0073002000530065007200690066000000fc7f2214fc7fb0fe120000000000000000009823eb770f0000000f000000f5ffffff000000000000000000000000bc02000000000000000000004d006900630072006f0073006f00660074002000530061006e0073002000530065007200690066000000f077002014000000001080051400f01f1400000014001200000012000000f5ffffff0000000000000000000000009001000000000000000000004d006900630072006f0073006f00660074002000530061006e0073002000530065007200690066000000140088fbe87702020000acb9f0770000000020000000f5ffffff0000000000000000000000009001000000000000000000004d006900630072006f0073006f00660074002000530061006e007300200053006500720069006600000000000000000000000000000000007c6be87700000000f5ffffff0000000000000000000000009001000000000000000000004d006900630072006f0073006f00660074002000530061006e007300200053006500720069006600000000000600000018000000fffffffff04b21fc00c4f077f5ffffff000000000000000000000000bc02000000000000000000004d006900630072006f0073006f00660074002000530061006e007300200053006500720069006600000014000b00000000ff120050000000c0fe12000c100001000000000000000000ffff000000ff000000000000000000ffffff0000ff000000ff00000000000000ffff000000ff00ffffff000000ff00ffffff000000000080808000c0c0c00000ff0000ffffff00c0c0c000ffffff00ffffff0000000000ffff0000c0c0c0008080ff0000ffff000000ff00" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Appearance\Schemes" /v "@themeui.dll,-852" /t REG_BINARY /d "02000000460000000100000011000000110000001400000014000000f5ffffff000000000000000000000000bc02000000000000000000004d006900630072006f0073006f00660074002000530061006e0073002000530065007200690066000000fc7f2214fc7fb0fe120000000000000000009823eb770f0000000f000000f5ffffff000000000000000000000000bc02000000000000000000004d006900630072006f0073006f00660074002000530061006e0073002000530065007200690066000000f077002014000000001080051400f01f1400000014001200000012000000f5ffffff0000000000000000000000009001000000000000000000004d006900630072006f0073006f00660074002000530061006e0073002000530065007200690066000000140088fbe87702020000acb9f0770000000020000000f5ffffff0000000000000000000000009001000000000000000000004d006900630072006f0073006f00660074002000530061006e007300200053006500720069006600000000000000000000000000000000007c6be87700000000f5ffffff0000000000000000000000009001000000000000000000004d006900630072006f0073006f00660074002000530061006e007300200053006500720069006600000000000600000018000000fffffffff04b21fc00c4f077f5ffffff000000000000000000000000bc02000000000000000000004d006900630072006f0073006f00660074002000530061006e007300200053006500720069006600000014000b00000000ff120050000000c0fe12000c100001000000000000000080008000008000000000000000000000ffffff00ffffff00ffffff00ffffff00ffff0000008000000000000080008000ffffff00000000008080800000ff0000ffffff00ffffff00c0c0c000ffffff00ffffff00ffffff0000000000c0c0c0008080ff008000800000800000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Appearance\Schemes" /v "@themeui.dll,-853" /t REG_BINARY /d "02000000460000000100000011000000110000001400000014000000f5ffffff000000000000000000000000bc02000000000000000000004d006900630072006f0073006f00660074002000530061006e0073002000530065007200690066000000fc7f2214fc7fb0fe120000000000000000009823eb770f0000000f000000f5ffffff000000000000000000000000bc02000000000000000000004d006900630072006f0073006f00660074002000530061006e0073002000530065007200690066000000f077002014000000001080051400f01f1400000014001200000012000000f5ffffff000000000000000000000000bc02000000000000000000004d006900630072006f0073006f00660074002000530061006e0073002000530065007200690066000000140088fbe87702020000acb9f0770000000020000000f5ffffff0000000000000000000000009001000000000000000000004d006900630072006f0073006f00660074002000530061006e007300200053006500720069006600000000000000000000000000000000007c6be87700000000f5ffffff000000000000000000000000bc02000000000000000000004d006900630072006f0073006f00660074002000530061006e007300200053006500720069006600000000000600000018000000fffffffff04b21fc00c4f077f5ffffff000000000000000000000000bc02000000000000000000004d006900630072006f0073006f00660074002000530061006e007300200053006500720069006600000014000b00000000ff120050000000c0fe12000c100001ffffff00ffffff0000000000ffffff00ffffff00ffffff00000000000000000000000000ffffff0080808000c0c0c0008080800000000000ffffff00ffffff0080808000008000000000000000000000c0c0c00000000000c0c0c00000000000ffffff00c0c0c0000000000000000000ffffff00" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Appearance\Schemes" /v "@themeui.dll,-854" /t REG_BINARY /d "02000000f40100000100000010000000100000001200000012000000f5ffffff000000000000000000000000bc02000000000000000000005400610068006f006d006100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0000000f000000f5ffffff000000000000000000000000bc02000000000000000000005400610068006f006d006100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001200000012000000f5ffffff0000000000000000000000009001000000000000000000005400610068006f006d00610000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f5ffffff0000000000000000000000009001000000000000000000005400610068006f006d00610000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f5ffffff0000000000000000000000009001000000000000000000005400610068006f006d00610000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f5ffffff0000000000000000000000009001000000000000000000005400610068006f006d00610000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000d4d0c8003a6ea5000a246a0080808000d4d0c800ffffff00000000000000000000000000ffffff00d4d0c800d4d0c800808080000a246a00ffffff00d4d0c800808080008080800000000000d4d0c800ffffff0040404000d4d0c80000000000ffffe100b5b5b50000008000a6caf000c0c0c000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Bluetooth\FileSquirtInstalled" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Colors" /v "ActiveBorder" /t REG_SZ /d "180 180 180" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Colors" /v "ActiveTitle" /t REG_SZ /d "153 180 209" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Colors" /v "AppWorkspace" /t REG_SZ /d "171 171 171" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Colors" /v "Background" /t REG_SZ /d "0 0 0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Colors" /v "ButtonAlternateFace" /t REG_SZ /d "0 0 0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Colors" /v "ButtonDkShadow" /t REG_SZ /d "105 105 105" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Colors" /v "ButtonFace" /t REG_SZ /d "240 240 240" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Colors" /v "ButtonHilight" /t REG_SZ /d "255 255 255" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Colors" /v "ButtonLight" /t REG_SZ /d "227 227 227" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Colors" /v "ButtonShadow" /t REG_SZ /d "160 160 160" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Colors" /v "ButtonText" /t REG_SZ /d "0 0 0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Colors" /v "GradientActiveTitle" /t REG_SZ /d "185 209 234" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Colors" /v "GradientInactiveTitle" /t REG_SZ /d "215 228 242" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Colors" /v "GrayText" /t REG_SZ /d "109 109 109" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Colors" /v "Hilight" /t REG_SZ /d "0 120 215" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Colors" /v "HilightText" /t REG_SZ /d "255 255 255" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Colors" /v "HotTrackingColor" /t REG_SZ /d "0 102 204" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Colors" /v "InactiveBorder" /t REG_SZ /d "244 247 252" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Colors" /v "InactiveTitle" /t REG_SZ /d "191 205 219" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Colors" /v "InactiveTitleText" /t REG_SZ /d "0 0 0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Colors" /v "InfoText" /t REG_SZ /d "0 0 0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Colors" /v "InfoWindow" /t REG_SZ /d "255 255 225" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Colors" /v "Menu" /t REG_SZ /d "240 240 240" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Colors" /v "MenuBar" /t REG_SZ /d "240 240 240" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Colors" /v "MenuHilight" /t REG_SZ /d "0 120 215" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Colors" /v "MenuText" /t REG_SZ /d "0 0 0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Colors" /v "Scrollbar" /t REG_SZ /d "200 200 200" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Colors" /v "TitleText" /t REG_SZ /d "0 0 0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Colors" /v "Window" /t REG_SZ /d "255 255 255" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Colors" /v "WindowFrame" /t REG_SZ /d "100 100 100" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Colors" /v "WindowText" /t REG_SZ /d "0 0 0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Cursors" /v "AppStarting" /t REG_SZ /d "C:\Windows\cursors\aero_working.ani" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Cursors" /v "Arrow" /t REG_SZ /d "C:\Windows\cursors\aero_arrow.cur" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Cursors" /v "ContactVisualization" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Cursors" /v "CursorBaseSize" /t REG_DWORD /d "32" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Cursors" /v "GestureVisualization" /t REG_DWORD /d "31" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Cursors" /v "Hand" /t REG_SZ /d "C:\Windows\cursors\aero_link.cur" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Cursors" /v "Help" /t REG_SZ /d "C:\Windows\cursors\aero_helpsel.cur" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Cursors" /v "No" /t REG_SZ /d "C:\Windows\cursors\aero_unavail.cur" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Cursors" /v "NWPen" /t REG_SZ /d "C:\Windows\cursors\aero_pen.cur" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Cursors" /v "Scheme Source" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Cursors" /v "SizeAll" /t REG_SZ /d "C:\Windows\cursors\aero_move.cur" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Cursors" /v "SizeNESW" /t REG_SZ /d "C:\Windows\cursors\aero_nesw.cur" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Cursors" /v "SizeNS" /t REG_SZ /d "C:\Windows\cursors\aero_ns.cur" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Cursors" /v "SizeNWSE" /t REG_SZ /d "C:\Windows\cursors\aero_nwse.cur" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Cursors" /v "SizeWE" /t REG_SZ /d "C:\Windows\cursors\aero_ew.cur" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Cursors" /v "UpArrow" /t REG_SZ /d "C:\Windows\cursors\aero_up.cur" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Cursors" /v "Wait" /t REG_SZ /d "C:\Windows\cursors\aero_busy.ani" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Cursors" /ve /t REG_SZ /d "Windows Default" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "ActiveWndTrackTimeout" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "BlockSendInputResets" /t REG_SZ /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "CaretTimeout" /t REG_DWORD /d "5000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "CaretWidth" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "ClickLockTime" /t REG_DWORD /d "1200" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "CoolSwitchColumns" /t REG_SZ /d "7" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "CoolSwitchRows" /t REG_SZ /d "3" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "CursorBlinkRate" /t REG_SZ /d "530" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "DockMoving" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "DragFromMaximize" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "DragFullWindows" /t REG_SZ /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "DragHeight" /t REG_SZ /d "4" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "DragWidth" /t REG_SZ /d "4" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "FocusBorderHeight" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "FocusBorderWidth" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "FontSmoothing" /t REG_SZ /d "2" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "FontSmoothingGamma" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "FontSmoothingOrientation" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "FontSmoothingType" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "ForegroundFlashCount" /t REG_DWORD /d "7" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "ForegroundLockTimeout" /t REG_DWORD /d "200000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "LeftOverlapChars" /t REG_SZ /d "3" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "400" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "MouseWheelRouting" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "PaintDesktopVersion" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "Pattern" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "RightOverlapChars" /t REG_SZ /d "3" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "ScreenSaveActive" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "SnapSizing" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "TileWallpaper" /t REG_SZ /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "WallPaper" /t REG_SZ /d "C:\Users\Administrator\AppData\Local\Microsoft\Windows\Themes\GHOSTV3\DesktopBackground\img0.jpg" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "WallpaperOriginX" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "WallpaperOriginY" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "WallpaperStyle" /t REG_SZ /d "10" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "WheelScrollChars" /t REG_SZ /d "3" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "WheelScrollLines" /t REG_SZ /d "3" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "WindowArrangementActive" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "Win8DpiScaling" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "DpiScalingVer" /t REG_DWORD /d "4096" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d "9012038010000000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "MaxVirtualDesktopDimension" /t REG_DWORD /d "3840" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "MaxMonitorDimension" /t REG_DWORD /d "3840" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "TranscodedImageCount" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "LastUpdated" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "TranscodedImageCache" /t REG_BINARY /d "7ac30100a5360600000a0000400600000080ff6bb4d7d60143003a005c00550073006500720073005c00410064006d0069006e006900730074007200610074006f0072005c0041007000700044006100740061005c004c006f00630061006c005c004d006900630072006f0073006f00660074005c00570069006e0064006f00770073005c005400680065006d00650073005c00470048004f0053005400560033005c004400650073006b0074006f0070004200610063006b00670072006f0075006e0064005c0069006d00670030002e006a00700067000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d "256" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\Colors" /v "ActiveBorder" /t REG_SZ /d "212 208 200" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\Colors" /v "ActiveTitle" /t REG_SZ /d "10 36 106" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\Colors" /v "AppWorkSpace" /t REG_SZ /d "128 128 128" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\Colors" /v "ButtonAlternateFace" /t REG_SZ /d "181 181 181" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\Colors" /v "ButtonDkShadow" /t REG_SZ /d "64 64 64" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\Colors" /v "ButtonFace" /t REG_SZ /d "212 208 200" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\Colors" /v "ButtonHiLight" /t REG_SZ /d "255 255 255" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\Colors" /v "ButtonLight" /t REG_SZ /d "212 208 200" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\Colors" /v "ButtonShadow" /t REG_SZ /d "128 128 128" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\Colors" /v "ButtonText" /t REG_SZ /d "0 0 0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\Colors" /v "GradientActiveTitle" /t REG_SZ /d "166 202 240" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\Colors" /v "GradientInactiveTitle" /t REG_SZ /d "192 192 192" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\Colors" /v "GrayText" /t REG_SZ /d "128 128 128" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\Colors" /v "Hilight" /t REG_SZ /d "10 36 106" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\Colors" /v "HilightText" /t REG_SZ /d "255 255 255" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\Colors" /v "HotTrackingColor" /t REG_SZ /d "0 0 128" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\Colors" /v "InactiveBorder" /t REG_SZ /d "212 208 200" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\Colors" /v "InactiveTitle" /t REG_SZ /d "128 128 128" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\Colors" /v "InactiveTitleText" /t REG_SZ /d "212 208 200" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\Colors" /v "InfoText" /t REG_SZ /d "0 0 0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\Colors" /v "InfoWindow" /t REG_SZ /d "255 255 255" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\Colors" /v "Menu" /t REG_SZ /d "212 208 200" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\Colors" /v "MenuText" /t REG_SZ /d "0 0 0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\Colors" /v "Scrollbar" /t REG_SZ /d "212 208 200" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\Colors" /v "TitleText" /t REG_SZ /d "255 255 255" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\Colors" /v "Window" /t REG_SZ /d "255 255 255" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\Colors" /v "WindowFrame" /t REG_SZ /d "0 0 0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\Colors" /v "WindowText" /t REG_SZ /d "0 0 0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "BorderWidth" /t REG_SZ /d "-15" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "CaptionFont" /t REG_BINARY /d "dcffffff0000000000000000000000009001000000000001000005005300650067006f006500200055004900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "CaptionHeight" /t REG_SZ /d "-330" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "CaptionWidth" /t REG_SZ /d "-330" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "IconFont" /t REG_BINARY /d "dcffffff0000000000000000000000009001000000000001000005005300650067006f006500200055004900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "IconTitleWrap" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MenuFont" /t REG_BINARY /d "dcffffff0000000000000000000000009001000000000001000005005300650067006f006500200055004900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MenuHeight" /t REG_SZ /d "-285" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MenuWidth" /t REG_SZ /d "-285" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MessageFont" /t REG_BINARY /d "dcffffff0000000000000000000000009001000000000001000005005300650067006f006500200055004900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "ScrollHeight" /t REG_SZ /d "-255" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "ScrollWidth" /t REG_SZ /d "-255" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "Shell Icon Size" /t REG_SZ /d "32" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "SmCaptionFont" /t REG_BINARY /d "dcffffff0000000000000000000000009001000000000001000005005300650067006f006500200055004900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "SmCaptionHeight" /t REG_SZ /d "-330" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "SmCaptionWidth" /t REG_SZ /d "-330" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "StatusFont" /t REG_BINARY /d "dcffffff0000000000000000000000009001000000000001000005005300650067006f006500200055004900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "PaddedBorderWidth" /t REG_SZ /d "-60" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "AppliedDPI" /t REG_DWORD /d "288" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "IconSpacing" /t REG_SZ /d "-1125" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "IconVerticalSpacing" /t REG_SZ /d "-1125" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop\MuiCached" /v "MachinePreferredUILanguages" /t REG_MULTI_SZ /d "en-US" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Input Method" /v "Show Status" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Input Method\Hot Keys\00000010" /v "Key Modifiers" /t REG_BINARY /d "02c00000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Input Method\Hot Keys\00000010" /v "Target IME" /t REG_BINARY /d "00000000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Input Method\Hot Keys\00000010" /v "Virtual Key" /t REG_BINARY /d "20000000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Input Method\Hot Keys\00000011" /v "Key Modifiers" /t REG_BINARY /d "04c00000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Input Method\Hot Keys\00000011" /v "Target IME" /t REG_BINARY /d "00000000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Input Method\Hot Keys\00000011" /v "Virtual Key" /t REG_BINARY /d "20000000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Input Method\Hot Keys\00000012" /v "Key Modifiers" /t REG_BINARY /d "02c00000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Input Method\Hot Keys\00000012" /v "Target IME" /t REG_BINARY /d "00000000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Input Method\Hot Keys\00000012" /v "Virtual Key" /t REG_BINARY /d "be000000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Input Method\Hot Keys\00000070" /v "Key Modifiers" /t REG_BINARY /d "02c00000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Input Method\Hot Keys\00000070" /v "Target IME" /t REG_BINARY /d "00000000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Input Method\Hot Keys\00000070" /v "Virtual Key" /t REG_BINARY /d "20000000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Input Method\Hot Keys\00000071" /v "Key Modifiers" /t REG_BINARY /d "04c00000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Input Method\Hot Keys\00000071" /v "Target IME" /t REG_BINARY /d "00000000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Input Method\Hot Keys\00000071" /v "Virtual Key" /t REG_BINARY /d "20000000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Input Method\Hot Keys\00000072" /v "Key Modifiers" /t REG_BINARY /d "03c00000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Input Method\Hot Keys\00000072" /v "Target IME" /t REG_BINARY /d "00000000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Input Method\Hot Keys\00000072" /v "Virtual Key" /t REG_BINARY /d "bc000000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Input Method\Hot Keys\00000104" /v "Key Modifiers" /t REG_BINARY /d "06c00000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Input Method\Hot Keys\00000104" /v "Target IME" /t REG_BINARY /d "110401e0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Input Method\Hot Keys\00000104" /v "Virtual Key" /t REG_BINARY /d "30000000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Input Method\Hot Keys\00000200" /v "Key Modifiers" /t REG_BINARY /d "03c00000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Input Method\Hot Keys\00000200" /v "Target IME" /t REG_BINARY /d "00000000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Input Method\Hot Keys\00000200" /v "Virtual Key" /t REG_BINARY /d "47000000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Input Method\Hot Keys\00000201" /v "Key Modifiers" /t REG_BINARY /d "03c00000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Input Method\Hot Keys\00000201" /v "Target IME" /t REG_BINARY /d "00000000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Input Method\Hot Keys\00000201" /v "Virtual Key" /t REG_BINARY /d "4b000000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Input Method\Hot Keys\00000202" /v "Key Modifiers" /t REG_BINARY /d "03c00000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Input Method\Hot Keys\00000202" /v "Target IME" /t REG_BINARY /d "00000000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Input Method\Hot Keys\00000202" /v "Virtual Key" /t REG_BINARY /d "4c000000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Input Method\Hot Keys\00000203" /v "Key Modifiers" /t REG_BINARY /d "03c00000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Input Method\Hot Keys\00000203" /v "Target IME" /t REG_BINARY /d "00000000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Input Method\Hot Keys\00000203" /v "Virtual Key" /t REG_BINARY /d "56000000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International" /v "Locale" /t REG_SZ /d "00000409" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International" /v "LocaleName" /t REG_SZ /d "en-US" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International" /v "s1159" /t REG_SZ /d "AM" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International" /v "s2359" /t REG_SZ /d "PM" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International" /v "sCurrency" /t REG_SZ /d "$" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International" /v "sDate" /t REG_SZ /d "/" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International" /v "sDecimal" /t REG_SZ /d "." /f
Echo Y | Reg.exe add "HKCU\Control Panel\International" /v "sGrouping" /t REG_SZ /d "3;0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International" /v "sLanguage" /t REG_SZ /d "ENU" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International" /v "sList" /t REG_SZ /d "," /f
Echo Y | Reg.exe add "HKCU\Control Panel\International" /v "sLongDate" /t REG_SZ /d "dddd, MMMM d, yyyy" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International" /v "sMonDecimalSep" /t REG_SZ /d "." /f
Echo Y | Reg.exe add "HKCU\Control Panel\International" /v "sMonGrouping" /t REG_SZ /d "3;0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International" /v "sMonThousandSep" /t REG_SZ /d "," /f
Echo Y | Reg.exe add "HKCU\Control Panel\International" /v "sNativeDigits" /t REG_SZ /d "0123456789" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International" /v "sNegativeSign" /t REG_SZ /d "-" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International" /v "sPositiveSign" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International" /v "sShortDate" /t REG_SZ /d "M/d/yyyy" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International" /v "sThousand" /t REG_SZ /d "," /f
Echo Y | Reg.exe add "HKCU\Control Panel\International" /v "sTime" /t REG_SZ /d ":" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International" /v "sTimeFormat" /t REG_SZ /d "h:mm:ss tt" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International" /v "sShortTime" /t REG_SZ /d "h:mm tt" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International" /v "sYearMonth" /t REG_SZ /d "MMMM yyyy" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International" /v "iCalendarType" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International" /v "iCountry" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International" /v "iCurrDigits" /t REG_SZ /d "2" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International" /v "iCurrency" /t REG_SZ /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International" /v "iDate" /t REG_SZ /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International" /v "iDigits" /t REG_SZ /d "2" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International" /v "NumShape" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International" /v "iFirstDayOfWeek" /t REG_SZ /d "6" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International" /v "iFirstWeekOfYear" /t REG_SZ /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International" /v "iLZero" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International" /v "iMeasure" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International" /v "iNegCurr" /t REG_SZ /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International" /v "iNegNumber" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International" /v "iPaperSize" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International" /v "iTime" /t REG_SZ /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International" /v "iTimePrefix" /t REG_SZ /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International" /v "iTLZero" /t REG_SZ /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International\Geo" /v "Nation" /t REG_SZ /d "244" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International\User Profile" /v "Languages" /t REG_MULTI_SZ /d "en-US" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International\User Profile" /v "ShowAutoCorrection" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International\User Profile" /v "ShowTextPrediction" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International\User Profile" /v "ShowCasing" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International\User Profile" /v "ShowShiftLock" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\Control Panel\International\User Profile\en-US" /v "0409:00000409" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Keyboard" /v "InitialKeyboardIndicators" /t REG_SZ /d "2" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Keyboard" /v "KeyboardDelay" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Keyboard" /v "KeyboardSpeed" /t REG_SZ /d "31" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Mouse" /v "ActiveWindowTracking" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Mouse" /v "Beep" /t REG_SZ /d "No" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Mouse" /v "DoubleClickHeight" /t REG_SZ /d "4" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Mouse" /v "DoubleClickSpeed" /t REG_SZ /d "500" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Mouse" /v "DoubleClickWidth" /t REG_SZ /d "4" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Mouse" /v "ExtendedSounds" /t REG_SZ /d "No" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseHoverHeight" /t REG_SZ /d "4" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "400" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseHoverWidth" /t REG_SZ /d "4" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "10" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "6" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "10" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseTrails" /t REG_SZ /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d "0000000000000000156e000000000000004001000000000029dc0300000000000000280000000000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Mouse" /v "SmoothMouseYCurve" /t REG_BINARY /d "0000000000000000fd11010000000000002404000000000000fc12000000000000c0bb0100000000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Mouse" /v "SnapToDefaultButton" /t REG_SZ /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Mouse" /v "SwapMouseButtons" /t REG_SZ /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Personalization\Desktop Slideshow" /f
Echo Y | Reg.exe add "HKCU\Control Panel\PowerCfg" /v "CurrentPowerPolicy" /t REG_SZ /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\PowerCfg\GlobalPowerPolicy" /v "Policies" /t REG_BINARY /d "01000000000000000300000010000000000000000300000010000000020000000300000000000000020000000300000000000000020000000100000000000000020000000100000000000000010000000300000003000000000000c00100000005000000010000000a0000000000000003000000010000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000016000000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\PowerCfg\PowerPolicies\0" /v "Description" /t REG_SZ /d "This scheme is suited to most home or desktop computers that are left plugged in all the time." /f
Echo Y | Reg.exe add "HKCU\Control Panel\PowerCfg\PowerPolicies\0" /v "Name" /t REG_SZ /d "Home/Office Desk" /f
Echo Y | Reg.exe add "HKCU\Control Panel\PowerCfg\PowerPolicies\0" /v "Policies" /t REG_BINARY /d "01000000020000000100000000000000020000000000000000000000000000002c0100003232000304000000040000000000000000000000b00400002c01000000000000580200000101645064640000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\PowerCfg\PowerPolicies\1" /v "Description" /t REG_SZ /d "This scheme is designed for extended battery life for portable computers on the road." /f
Echo Y | Reg.exe add "HKCU\Control Panel\PowerCfg\PowerPolicies\1" /v "Name" /t REG_SZ /d "Portable/Laptop" /f
Echo Y | Reg.exe add "HKCU\Control Panel\PowerCfg\PowerPolicies\1" /v "Policies" /t REG_BINARY /d "01000000020000000100000000000000020000000100000000000000b00400002c0100003232030304000000040000000000000000000000840300002c010000080700002c0100000101645064640000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\PowerCfg\PowerPolicies\2" /v "Description" /t REG_SZ /d "This scheme keeps the monitor on for doing presentations." /f
Echo Y | Reg.exe add "HKCU\Control Panel\PowerCfg\PowerPolicies\2" /v "Name" /t REG_SZ /d "Presentation" /f
Echo Y | Reg.exe add "HKCU\Control Panel\PowerCfg\PowerPolicies\2" /v "Policies" /t REG_BINARY /d "01000000020000000100000000000000020000000100000000000000000000008403000032320302040000000400000000000000000000000000000000000000000000002c0100000101505064640000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\PowerCfg\PowerPolicies\3" /v "Description" /t REG_SZ /d "This scheme keeps the computer running so that it can be accessed from the network.  Use this scheme if you do not have network wakeup hardware." /f
Echo Y | Reg.exe add "HKCU\Control Panel\PowerCfg\PowerPolicies\3" /v "Name" /t REG_SZ /d "Always On" /f
Echo Y | Reg.exe add "HKCU\Control Panel\PowerCfg\PowerPolicies\3" /v "Policies" /t REG_BINARY /d "0100000002000000010000000000000002000000000000000000000000000000000000003232000004000000040000000000000000000000b00400008403000000000000080700000001646464640000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\PowerCfg\PowerPolicies\4" /v "Description" /t REG_SZ /d "This scheme keeps the computer on and optimizes it for high performance." /f
Echo Y | Reg.exe add "HKCU\Control Panel\PowerCfg\PowerPolicies\4" /v "Name" /t REG_SZ /d "Minimal Power Management" /f
Echo Y | Reg.exe add "HKCU\Control Panel\PowerCfg\PowerPolicies\4" /v "Policies" /t REG_BINARY /d "01000000020000000100000000000000020000000000000000000000000000002c0100003232030304000000040000000000000000000000840300002c01000000000000840300000001646464640000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\PowerCfg\PowerPolicies\5" /v "Description" /t REG_SZ /d "This scheme is extremely aggressive for saving power." /f
Echo Y | Reg.exe add "HKCU\Control Panel\PowerCfg\PowerPolicies\5" /v "Name" /t REG_SZ /d "Max Battery" /f
Echo Y | Reg.exe add "HKCU\Control Panel\PowerCfg\PowerPolicies\5" /v "Policies" /t REG_BINARY /d "01000000020000000100000000000000020000000500000000000000b0040000780000003232030204000000040000000000000000000000840300003c00000000000000b40000000101643264640000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Quick Actions\Pinned" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Sound" /v "Beep" /t REG_SZ /d "yes" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Sound" /v "ExtendedSounds" /t REG_SZ /d "yes" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Accessibility" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components\{2C7339CF-2B09-4501-B3F3-F3508C9228ED}" /v "Version" /t REG_SZ /d "1,1,1,9" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components\{2C7339CF-2B09-4501-B3F3-F3508C9228ED}" /v "Locale" /t REG_SZ /d "EN" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components\{6BF52A52-394A-11d3-B153-00C04F79FAA6}" /v "Version" /t REG_SZ /d "12,0,10011,16384" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components\{6BF52A52-394A-11d3-B153-00C04F79FAA6}" /v "Locale" /t REG_SZ /d "EN" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components\{89820200-ECBD-11cf-8B85-00AA005B4340}" /v "Version" /t REG_SZ /d "10,0,19041,0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components\{89820200-ECBD-11cf-8B85-00AA005B4340}" /v "Locale" /t REG_SZ /d "en" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components\{89820200-ECBD-11cf-8B85-00AA005B4383}" /v "Version" /t REG_SZ /d "11,1,19041,0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components\{89820200-ECBD-11cf-8B85-00AA005B4383}" /v "Locale" /t REG_SZ /d "*" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components\{89B4C1CD-B018-4511-B0A1-5476DBF70820}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components\{8A69D345-D564-463c-AFF1-A69D9E530F96}" /v "Version" /t REG_SZ /d "43,0,0,0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\ActiveSync\JobDispatcher\JobRegistry\1.1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\ActiveSync\Partners" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE UserData NT\RegBackup\0" /v "1e4389adc72d1376" /t REG_BINARY /d "2c0053004f004600540057004100520045005c004d006900630072006f0073006f00660074005c00570069006e0064006f00770073005c00430075007200720065006e007400560065007200730069006f006e005c0049006e007400650072006e00650074002000530065007400740069006e00670073002c000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE UserData NT\RegBackup\0" /v "57fd7ae3ffc55848" /t REG_BINARY /d "2c0053004f004600540057004100520045005c004d006900630072006f0073006f00660074005c00570069006e0064006f00770073005c00430075007200720065006e007400560065007200730069006f006e005c0049006e007400650072006e00650074002000530065007400740069006e00670073002c000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE UserData NT\RegBackup\0" /v "0cac0ebdfbfe17fc" /t REG_BINARY /d "2c0053004f004600540057004100520045005c004d006900630072006f0073006f00660074005c00570069006e0064006f00770073005c00430075007200720065006e007400560065007200730069006f006e005c004500780070006c006f007200650072005c004d0065006e0075004f0072006400650072002c000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE UserData NT\RegBackup\0" /v "0e925ec83d9dc2c6" /t REG_BINARY /d "2c0053006f006600740077006100720065005c004d006900630072006f0073006f00660074005c0049006e007400650072006e006500740020004500780070006c006f007200650072005c004d00610069006e002c000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE UserData NT\RegBackup\0" /v "2189ccb98b7938df" /t REG_BINARY /d "2c0053006f006600740077006100720065005c004d006900630072006f0073006f00660074005c0049006e007400650072006e006500740020004500780070006c006f007200650072005c004d00610069006e002c000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE UserData NT\RegBackup\0" /v "0e925ec89c508cfc" /t REG_BINARY /d "2c0053006f006600740077006100720065005c004d006900630072006f0073006f00660074005c0049006e007400650072006e006500740020004500780070006c006f007200650072005c004d00610069006e002c000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE UserData NT\RegBackup\0" /v "d71d59f8acb86b4b" /t REG_BINARY /d "2c0053006f006600740077006100720065005c004d006900630072006f0073006f00660074005c0049006e007400650072006e006500740020004500780070006c006f007200650072005c0049006e007400650072006e006100740069006f006e0061006c002c000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE UserData NT\RegBackup\0" /v "464363ac15fb3565" /t REG_BINARY /d "2c0053006f006600740077006100720065005c004d006900630072006f0073006f00660074005c0049006e007400650072006e006500740020004500780070006c006f007200650072005c0049006e007400650072006e006100740069006f006e0061006c002c000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE UserData NT\RegBackup\0" /v "99d760eefa52d88b" /t REG_BINARY /d "2c0053006f006600740077006100720065005c004d006900630072006f0073006f00660074005c00570069006e0064006f00770073005c00430075007200720065006e007400560065007200730069006f006e005c0049006e007400650072006e00650074002000530065007400740069006e00670073005c005a006f006e00650073002c000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE UserData NT\RegBackup\0" /v "92cb6f10673beaf6" /t REG_BINARY /d "2c0053006f006600740077006100720065005c004d006900630072006f0073006f00660074005c0049006e007400650072006e006500740020004500780070006c006f007200650072002c000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE UserData NT\RegBackup\0" /v "f45197b394e8e4b0" /t REG_BINARY /d "2c0053006f006600740077006100720065005c004d006900630072006f0073006f00660074005c0049006e007400650072006e006500740020004500780070006c006f007200650072005c00420072006f00770073006500720045006d0075006c006100740069006f006e005c004c006f0077004d00690063002c000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE UserData NT\RegBackup\0" /v "f45197b39d9317c2" /t REG_BINARY /d "2c0053006f006600740077006100720065005c004d006900630072006f0073006f00660074005c0049006e007400650072006e006500740020004500780070006c006f007200650072005c00420072006f00770073006500720045006d0075006c006100740069006f006e005c004c006f0077004d00690063002c000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE UserData NT\RegBackup\0" /v "56cf089a8df4d52f" /t REG_BINARY /d "2c0053006f006600740077006100720065005c004d006900630072006f0073006f00660074005c0049006e007400650072006e006500740020004500780070006c006f007200650072005c00420072006f00770073006500720045006d0075006c006100740069006f006e002c000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE UserData NT\RegBackup\0" /v "75b5e0d3f0890ec7" /t REG_BINARY /d "2c0053006f006600740077006100720065005c004d006900630072006f0073006f00660074005c0049006e007400650072006e006500740020004500780070006c006f007200650072005c00420072006f00770073006500720045006d0075006c006100740069006f006e002c000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE UserData NT\RegBackup\0" /v "464363acf2aab808" /t REG_BINARY /d "2c0053006f006600740077006100720065005c004d006900630072006f0073006f00660074005c0049006e007400650072006e006500740020004500780070006c006f007200650072005c00540061006200620065006400420072006f007700730069006e0067002c000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE UserData NT\RegBackup\0" /v "57fd7ae3ca9283bd" /t REG_BINARY /d "2c0053004f004600540057004100520045005c004d006900630072006f0073006f00660074005c00570069006e0064006f00770073005c00430075007200720065006e007400560065007200730069006f006e005c0049006e007400650072006e00650074002000530065007400740069006e00670073005c0035002e0030005c00430061006300680065002c000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE UserData NT\RegBackup\0" /v "4895c3bdf0399432" /t REG_BINARY /d "2c0053004f004600540057004100520045005c004d006900630072006f0073006f00660074005c00570069006e0064006f00770073005c00430075007200720065006e007400560065007200730069006f006e005c0049006e007400650072006e00650074002000530065007400740069006e00670073005c0035002e0030005c004c006f007700430061006300680065002c000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE UserData NT\RegBackup\0.map" /v "1e4389adc72d1376" /t REG_SZ /d ",1,HKCU,SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings,WarnAlwaysOnPost," /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE UserData NT\RegBackup\0.map" /v "57fd7ae3ffc55848" /t REG_SZ /d ",1,HKCU,SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings,HeaderExclusionListForCache," /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE UserData NT\RegBackup\0.map" /v "0cac0ebdfbfe17fc" /t REG_SZ /d ",33,HKCU,SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MenuOrder\Start Menu\&Favorites," /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE UserData NT\RegBackup\0.map" /v "0e925ec83d9dc2c6" /t REG_SZ /d ",1,HKCU,Software\Microsoft\Internet Explorer\Main,Default Channels," /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE UserData NT\RegBackup\0.map" /v "2189ccb98b7938df" /t REG_SZ /d ",1,HKCU,Software\Microsoft\Internet Explorer\Main,Additional Channels," /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE UserData NT\RegBackup\0.map" /v "0e925ec89c508cfc" /t REG_SZ /d ",1,HKCU,Software\Microsoft\Internet Explorer\Main,FavIntelliMenus," /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE UserData NT\RegBackup\0.map" /v "d71d59f8acb86b4b" /t REG_SZ /d ",1,HKCU,Software\Microsoft\Internet Explorer\International,Default_CodePage," /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE UserData NT\RegBackup\0.map" /v "464363ac15fb3565" /t REG_SZ /d ",1,HKCU,Software\Microsoft\Internet Explorer\International,CodePointToFontMap," /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE UserData NT\RegBackup\0.map" /v "99d760eefa52d88b" /t REG_SZ /d ",33,HKCU,Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\LMZL," /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE UserData NT\RegBackup\0.map" /v "92cb6f10673beaf6" /t REG_SZ /d ",1,HKCU,Software\Microsoft\Internet Explorer\Extensions\CmdMapping,{c95fe080-8f5d-11d2-a20b-00aa003c157a}," /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE UserData NT\RegBackup\0.map" /v "f45197b394e8e4b0" /t REG_SZ /d ",1,HKCU,Software\Microsoft\Internet Explorer\BrowserEmulation\LowMic,IECompatVersionHigh," /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE UserData NT\RegBackup\0.map" /v "f45197b39d9317c2" /t REG_SZ /d ",1,HKCU,Software\Microsoft\Internet Explorer\BrowserEmulation\LowMic,IECompatVersionLow," /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE UserData NT\RegBackup\0.map" /v "56cf089a8df4d52f" /t REG_SZ /d ",1,HKCU,Software\Microsoft\Internet Explorer\BrowserEmulation,IECompatVersionHigh," /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE UserData NT\RegBackup\0.map" /v "75b5e0d3f0890ec7" /t REG_SZ /d ",1,HKCU,Software\Microsoft\Internet Explorer\BrowserEmulation,IECompatVersionLow," /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE UserData NT\RegBackup\0.map" /v "464363acf2aab808" /t REG_SZ /d ",1,HKCU,Software\Microsoft\Internet Explorer\TabbedBrowsing,QuickTabsThreshold," /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE UserData NT\RegBackup\0.map" /v "57fd7ae3ca9283bd" /t REG_SZ /d ",1,HKCU,SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Content,CacheLimit," /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE UserData NT\RegBackup\0.map" /v "4895c3bdf0399432" /t REG_SZ /d ",1,HKCU,SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\LowCache\Content,CacheLimit," /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE.HKCUZoneInfo\RegBackup\0" /v "e1be3f182420a0a0" /t REG_BINARY /d "2c0053006f006600740077006100720065005c004d006900630072006f0073006f00660074005c00570069006e0064006f00770073005c00430075007200720065006e007400560065007200730069006f006e005c0049006e007400650072006e00650074002000530065007400740069006e00670073002c000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE.HKCUZoneInfo\RegBackup\0" /v "57fd7ae31ab34c2c" /t REG_BINARY /d "2c0053004f004600540057004100520045005c004d006900630072006f0073006f00660074005c00570069006e0064006f00770073005c00430075007200720065006e007400560065007200730069006f006e005c0049006e007400650072006e00650074002000530065007400740069006e00670073005c0035002e0030005c00430061006300680065002c000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE.HKCUZoneInfo\RegBackup\0.map" /v "e1be3f182420a0a0" /t REG_SZ /d ",33,HKCU,Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones," /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE.HKCUZoneInfo\RegBackup\0.map" /v "57fd7ae31ab34c2c" /t REG_SZ /d ",33,HKCU,SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache," /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE40.UserAgent\RegBackup\0" /v "ef29a4ec885fa451" /t REG_BINARY /d "2c0053006f006600740077006100720065005c004d006900630072006f0073006f00660074005c00570069006e0064006f00770073005c00430075007200720065006e007400560065007200730069006f006e005c0049006e007400650072006e00650074002000530065007400740069006e00670073002c00550073006500720020004100670065006e0074002c000000010054004d006f007a0069006c006c0061002f0035002e0030002000280063006f006d00700061007400690062006c0065003b0020004d00530049004500200039002e0030003b002000570069006e003300320029000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE40.UserAgent\RegBackup\0" /v "2ba02e083fadee33" /t REG_BINARY /d "2c0053006f006600740077006100720065005c004d006900630072006f0073006f00660074005c00570069006e0064006f00770073005c00430075007200720065006e007400560065007200730069006f006e005c0049006e007400650072006e00650074002000530065007400740069006e00670073002c004900450035005f00550041005f004200610063006b00750070005f0046006c00610067002c0000000100080035002e0030000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE40.UserAgent\RegBackup\0.map" /v "ef29a4ec885fa451" /t REG_SZ /d ",33,HKCU,Software\Microsoft\Windows\CurrentVersion\Internet Settings,User Agent," /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Advanced INF Setup\IE40.UserAgent\RegBackup\0.map" /v "2ba02e083fadee33" /t REG_SZ /d ",33,HKCU,Software\Microsoft\Windows\CurrentVersion\Internet Settings,IE5_UA_Backup_Flag," /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Assistance\Client\1.0\Settings" /v "FirstTimeHelppaneStartup" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Assistance\Client\1.0\Settings" /v "Height" /t REG_DWORD /d "340" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Assistance\Client\1.0\Settings" /v "ImplicitFeedback" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Assistance\Client\1.0\Settings" /v "OnlineAssist" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Assistance\Client\1.0\Settings" /v "PositionX" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Assistance\Client\1.0\Settings" /v "PositionY" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Assistance\Client\1.0\Settings" /v "UserID" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Assistance\Client\1.0\Settings" /v "Width" /t REG_DWORD /d "510" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\AuthCookies\Live\Default\DIDC" /v "URL" /t REG_SZ /d "https://login.live.com" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\AuthCookies\Live\Default\DIDC" /v "Name" /t REG_SZ /d "DIDC" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\AuthCookies\Live\Default\DIDC" /v "Data" /t REG_SZ /d "ct%%3D1623833118%%26hashalg%%3DSHA256%%26bver%%3D24%%26appid%%3DDefault%%26da%%3D%%253CEncryptedData%%2520xmlns%%253D%%2522http://www.w3.org/2001/04/xmlenc%%2523%%2522%%2520Id%%253D%%2522devicesoftware%%2522%%2520Type%%253D%%2522http://www.w3.org/2001/04/xmlenc%%2523Element%%2522%%253E%%253CEncryptionMethod%%2520Algorithm%%253D%%2522http://www.w3.org/2001/04/xmlenc%%2523tripledes-cbc%%2522%%253E%%253C/EncryptionMethod%%253E%%253Cds:KeyInfo%%2520xmlns:ds%%253D%%2522http://www.w3.org/2000/09/xmldsig%%2523%%2522%%253E%%253Cds:KeyName%%253Ehttp://Passport.NET/STS%%253C/ds:KeyName%%253E%%253C/ds:KeyInfo%%253E%%253CCipherData%%253E%%253CCipherValue%%253ECYCC7s6eb1NH0fZLHzmrtzl7jcNgLoCa7zuwaUL0ouaEfL%%252B1wWUEgUai0OGDIuI3Wa/%%252B1Pjb46%%252BDvYjEcs5zj4h0OwX18k%%252BaeeRAON8sQ45Rq4MLePd9jkDERyp1eYke7SkACujcq73efVHpops8PLu60Xr1YUfN7/5bYIWmfv%%252BekqZcCURRr9Oz/C4M1LkokjRWPq82k26nsD0o3WHwsqboHJZJcqmalXCfhKUGKaDy9rPLPlHCtCCI2UG9mYV8AWs1MJ5HDbMcvIs/80K9nk0Gj4pkiMyW/ZJM8FeAKbSVE6sHxqUbu7izJ8e%%252Bp2yiHA66gT%%252B4N%%252B4UEALHcgmuk%%252Be%%252BcJ/mZnJxfY5LrYGg9p2gzoYEgFsGwTuda9bTiGy3m5qHTER3sfeSMlmsBgmqC6z1nk3/9VG5Rw8LvhXfaUdUx479/9%%252BbSJQOdbKJY5ShwKm34d6s3k80g5S3teFhaG6pOld5iUjZOiUQWLfca2MasvNSgqAF/OAokeHNDLj0lg%%253D%%253D%%253C/CipherValue%%253E%%253C/CipherData%%253E%%253C/EncryptedData%%253E%%26nonce%%3D2ZSoac7zE%%252Fac8mocGSa0XVrK7lt0Ss3q%%26hash%%3DFJ9aqnBHWh5WWnZgY7zJgov%%252BxcjT6z6v2fUtTqEiX%%252BA%%253D%%26dd%%3D1; path=/; domain=login.live.com; secure; httponly" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\AuthCookies\Live\Default\DIDC" /v "P3P" /t REG_SZ /d "CP=\"CAO DSP COR ADMa DEV CONo TELo CUR PSA PSD TAI IVDo OUR SAMi BUS DEM NAV STA UNI COM INT PHY ONL FIN PUR LOCi CNT\"" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\AuthCookies\Live\Default\DIDC" /v "Flags" /t REG_DWORD /d "8256" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Avalon.Graphics" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Clipboard" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\CommsAPHost\Test" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\CTF\Assemblies\0x00000409\{34745C63-B2F0-4784-8B67-5E12C8701A31}" /v "Default" /t REG_SZ /d "{00000000-0000-0000-0000-000000000000}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\CTF\Assemblies\0x00000409\{34745C63-B2F0-4784-8B67-5E12C8701A31}" /v "Profile" /t REG_SZ /d "{00000000-0000-0000-0000-000000000000}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\CTF\Assemblies\0x00000409\{34745C63-B2F0-4784-8B67-5E12C8701A31}" /v "KeyboardLayout" /t REG_DWORD /d "67699721" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\CTF\DirectSwitchHotkeys" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\CTF\HiddenDummyLayouts" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\CTF\SortOrder\AssemblyItem\0x00000409\{34745C63-B2F0-4784-8B67-5E12C8701A31}\00000000" /v "CLSID" /t REG_SZ /d "{00000000-0000-0000-0000-000000000000}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\CTF\SortOrder\AssemblyItem\0x00000409\{34745C63-B2F0-4784-8B67-5E12C8701A31}\00000000" /v "KeyboardLayout" /t REG_DWORD /d "67699721" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\CTF\SortOrder\AssemblyItem\0x00000409\{34745C63-B2F0-4784-8B67-5E12C8701A31}\00000000" /v "Profile" /t REG_SZ /d "{00000000-0000-0000-0000-000000000000}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\CTF\SortOrder\Language" /v "00000000" /t REG_SZ /d "00000409" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\CTF\TIP" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\EventSystem\{26c409cc-ae86-11d1-b616-00805fc79216}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\F12" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Fax\FaxOptions" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Fax\fxsclnt\Archive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Fax\fxsclnt\Confirm" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Fax\Setup" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Fax\UserInfo" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Feeds" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\FTP" /v "Use PASV" /t REG_SZ /d "yes" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\GameBar" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\GameBarApi" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\IdentityCRL" /v "MigrationDone" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\IdentityCRL\ExtendedProperties" /v "LID" /t REG_SZ /d "001840047220F990" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\IdentityCRL\Immersive\production\Property" /v "001840047220F990" /t REG_BINARY /d "0100000001000000d08c9ddf0115d1118c7a00c04fc297eb010000003c3bc39b8482064abd0c51587cdec25d0000000002000000000010660000000100002000000025ebceb95ff42988c5ffaba68f1c2d85e441d39404a9563ac3aaf043fdea70a7000000000e80000000020000200000004b8484345bfb823067dea5072a331ce4d7d1873f59519e3068f6d634ecefa1fd80000000341b98f1637f6a0062e11e5d7ee662f050a2d274ef0f31a245a85b1dda3da257c0c084ad2a6381bf3a1e02a4f08c607a6c69756ba14f7277e83694d4495cd0d6fb9361f55f997c8a985a9257830885a5f71a9ecea11dc6fe07c0b0c2885014c18e2c42e165509b402d5d61fc1fe37e4cb04818ef8567a8b3fec8a1ac0b2e792b40000000851de41aaaa6f4b56a3afd14397107e1016949ec649c0140c2c0187bf2c5abd755b67ea559406d2190f1e88b06eeed242e610bf855e01d9017145b2d300a8b0b" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\IdentityCRL\Immersive\production\Token\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723" /v "DeviceTicket" /t REG_BINARY /d "0100000001000000d08c9ddf0115d1118c7a00c04fc297eb010000003c3bc39b8482064abd0c51587cdec25d00000000020000000000106600000001000020000000d69ae27379c8a2cdcd4c9bdd757bf82c97d161901c24fa85957eb810b1c6e218000000000e8000000002000020000000d02b7b8e09d3e8cc2a1846fd5e388550a62ca70221045e15112da4fb1709861360080000105517ae6f4eb5bda3f3d2758e076ff683f8a8cfce4ee52b60df7bc9924fa0c8490d0735e7d1fdb830eff617ad632e63436ab24fd32371d6f7fffbe718ea350eaabffa8ffe82162e354ade5803a411dd4574301103cd3ab769fa1ee394432a5d17d5ec0d68d97074843222c35d0badb9c31f0f69161efc7391d1129b5bcdfd99e8f0a85f9696294c8096fc88a80f2c64b68f25a2dec5d69b3d28419c56eaa4f08379f6058b1f482868d2d2fbbb5c62b59b11da916e8a050799d0df8e31b1ddccfc5acd713f86ac8c6ad3fbb0afa1038e984b0b4216b294cb77098943acc989528e3c15d5f8f843568cef350ee8959e001542bb65e32fd28f26351afae1f0491e2cea375263090eba4f5032361551b4cf8006342ae3994b4e03385016f573e85acc7f5eea93ce1dea2c855b75ea59b9c46ab552d22eac45a1bee6d0b1ea501e94640a1d6d63b33dd203f24cbc73b0bb31709deb4f9c087e02d24cc48098373f5514a97c7e561f0f22abcd0f2fdc2da461a8d1361b84cb36be0579e20b261f92451dfff2b0e71f71f3478545b1afb59f4dce695c8c6552a41793b3a39833920d2e594559995658ca841a37bd953123ae68959b09a88ab88ccbf9d00956630515874904769614f7c5dfe86ab48ab077565a26e637e06a0addbc4164011394c2e04c5fd379bde37d04f7dba082da6eac77d6d2326ff485e30604ea57770111d33ec20883ba1bb3778ab4a45fef1d24dac11d4b3c4c7823d6fe1550f1daa102b0d232471bf8f981126310355d26a6a43bd7cbdcc118a908ef613aced937c5c83449d81b6fc7abd0f1bcb80d1cdb8818487807cad4183fd0ad080c9e1a483211b3cbebaf3b9971afceb6b1b8d75866c2c905f6d487c66f624c745cca30f8e8242d32904023aa298ae2a897bd776612301bec404994961906fc0d26b5445d1e71a99f8f0b4f7936293db25e9a644aac67455d03e1ce66be2bf3e7a863758ec76926efa26fe771aeecaa4149230660c3c302a8b6392f6a260d3cf7c89d3c5c85f1981a83676a9ab7e14ea246abe0f13224759ccfb890b0e0dcce70d5ebba1f81902c467c2840b4513c069b6ae170ff8b634ff7b8b1f2d87b10e371324bc129d7ca093315e4f589b72522e6e5038eb802266d23ea3250cfa3318ec3ab8852be75564bd2bfa0cde90b0435dcbe14e302f3a2f35c19102cd4fdaab0da42d0b8d7245a13dedfe97dcf74aafe0d0029907e5ee3853dc24c78a1525cb17ca4c23e06012b700b783f78ff07b5505784ce186160e588a8d22a2ca19a42ac5c6173acefa54444a4c79b3b296f57d9ed4214c0b2aef18cd34835524a8d1acf71d59871dbb9d20576af6a09cd69fc0c944bf9a9f34aa3ef152dd0d44128b97ccc0bf14218f2cb5af36b63eda0f42b2d789caa509bc51d554d88fb8ad8c6b4e1aa82131e960786988aed499b622007557751717e27369dbcca40b2e15d965777bc3369359e6180f395ee793fe120bd256e2218dc37ad2d929fd2346f41b27a14756ea4f914b23bf3b14a8f3851558bdcc88f0eb0442a6e2c18534ac9fa628cc0832d5a31aa618ee7f0fa6eec46c75c31c5b708207c3a3b59a8c18badea415acdc18225a95d822bf031a68ca35322e71dfee963b72f1d54feaee5edd93ad5e9c7a9e65e489e7b0e533e4c3c1b1fc9b3e51c0b6c8924964b02ae485112f1705fa94a5c94e9e5b857b342264b0e522dbee36dfba226b04b8fb1b0b92d51e477535efc371518e1aa50437f4cf071da38ef3314c7d12789548fda8dcbd043601920777e8b1a698f8f47e2f5305097377c30e186ed958f4ca94a38713e9485948ce3d4f20a4507b7a8568cabe99bc96afe7f7f81728bfcf1309d30cad6a07b1a8c8d220bf862a8691c21e8798c22c2f557a4bcfdef2709b37e5847cede7788b310d8b972080cd8aab2fe3af501ea400987cf5cb57503d55502a071cb0254df78b914daddc7da806a661f72add5252812680dbbe2424b336765355ab01ee6a794d350a3ac345390589566369a36ee27594d92eeb0a4cd6555939b544102c3960120a5d7be487843bf7e3763e226c42698ffeded2ae34e911053ec909d657986cfa50c01045067b966f4bf790f5fde2d50c2c95e2a0f25807eb6db31ca23b240ce3e422dc1ff72333826ce6e0d0b960642e6bd24b4a1face48832409618dd7769c30e708a7526d483c511a1c2a03f14bc46f8391784955dde871a6ec6a5b80def2ce061e0e730ba723a1b970f6ed4dff733562736607cb4c454282fe5610e31b34dac20bb1610842187c6d7ff5e2e5ee81bc8577671200b919487d834a85374922794375f194ede2184c52d632b3d5dfb2e811ffd4c0496e35fa14f48f4a6a60b5ddbc41117a8e5034ec23c6b6762ceae59d4d891e7ba38673256fc8de1ad3169d614db672e99b9140e28eaf1e731822f63388ef66f5740980054461522285506c0a5faf3095f2d98fde636b26b6cc625ef3bb508df25f60a749b81dcbe88d33564ac8542dafae8fd4bdcea2d396b2c1c6fd33a9d93f257098e7b203b549d3d8116675b5e93e1c243690d6f5f373f34b07b2f3e74ce4ec1d4eaf8a66a0762209648e2c5471fb2e28ce8ff11967350d6fb7d7923099766048aac547551decac9cd7a8eb0120db5866109f4231c33c5aeb6c5705a11d9ce43beab7f92a19f329f1503ae910ba4ac62dbf8da2e92e2338c2315bef8d4aed42d4106e49516aef93a36572d615fee15d5415f75010b36873f3886ea5d0aef32441485de39baad41efa8291de63a53101eb878d2dd3c0e4d05f4e78ac93625b28d0724f67ac29519fa70e3ded757a6422ebd412118e9d961d0b32bc1c4a0ccf7fee903f9d1cc7530ee35c3f6aed3b3ab2dc36e718bdc0a2e1a6e0bf18dff96d3029d641069e1957030ff798078823dd668d5d765305943413a13becfc2ea96af6aea90664c27f100dfd3eec104c0501f4b1ef4de6f037e2928f26266b8461e79292dc6e6632a5047439a66524f28c7871dc577aad4a924a40000000f0ace9617f15cd01782a230e1b82ff15ea768068e64c6619227187534934800d32799c6353c741823d508c69fd24ea74a0ec579a805a1947058d06f63bc03096" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\IdentityCRL\Immersive\production\Token\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723" /v "DeviceId" /t REG_SZ /d "001840047220F990" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\IdentityCRL\Immersive\production\Token\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723" /v "ApplicationFlags" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\IdentityCRL\Immersive\production\Token\S-1-15-2-536077884-713174666-1066051701-3219990555-339840825-1966734348-1611281757" /v "DeviceTicket" /t REG_BINARY /d "0100000001000000d08c9ddf0115d1118c7a00c04fc297eb010000003c3bc39b8482064abd0c51587cdec25d00000000020000000000106600000001000020000000f9c40f3ec06ea274da9d773ce1bd9d30d86c0ee64cad0313ae750790c9e3ff52000000000e8000000002000020000000f664ff890a844d0c32cd067334073a96cbf4ddacac9d0ce4d7f8eadc5705d97e60080000bfcb42f2eac37f55eb874b4eed765c8d605ebe15c62307fff3b70a1436f85b451c780c31b01f7173e872452afe3aa9bad46e2a96d0def5c82c5e4fca41c535bc22d5f8bdb774e46dcb79e8c4c35e368d261c92c701e56a9abbdfbfd2e053392e819eaa840e09360dc832fe91545b724a18bfbd84c5946b8ac48a42521c276305032889738522904bad7a327a71be848d7fd6a900393beb97d46b7e0e144d830581870451827bf8e22beebd9ab1dad258f4b3106e15adfe2a1788d56a2654db4f27b536932aa7f17ece68e9f90dd3a0c10cde90f64af0b5a769c181605c31d588f24b670487fbb8546118a557d3525be8716d33a1a3ba3d2c910cb07238395a113545c8ad82fafa0d38c7979db35fb01baace5913baeb7718f52c6372247b9afeef09903d7591622a9595ba589dd03380521be1ad5bd3473d036b6ec276217dca803c355840c4082d6ff5abf5adc48325c73e50ac5ab8c787c1ccd4eb2f0b053742d2a1a8cc792e51db2f42209955a4e1d19d1de5a3d732e22d33ab598569b0f0dc60b21a34adfdadd0cf23881136f60a7dc02b2779be153f1590ce97ef87d1d512534258e20eb6d9efd81fe0cac0d0f4e30cc70e5c30f47057a2023795ded76c768668d07a5e93f1455aedb122eeed9b00ba0d008354172bac66ebbed8d15f66b7341ddd9eefea71cfd5aa0e547f9c0815cc68d5ed0fcc2ca1274f76c8710fda95cf9a7a3e9e88448a617ed92d58e9cba6951b161353901f2e9dc5849466a0723c23667c693bc7bbc9ed86b5057f7d4b6dac82bb7cb5c13d10011d0b0f629ea973e0227b02206539344cfaf7333156d0c5832872b992ecc81fbb8e40ec4d06f89fffc689093a4eae02c7032f9a949f75830cdce6784ceff17f2862b1d5a444d75ddab26ba11441179643448502fdc29a01544d007442410c567a9b950c5831e01aad3f8d7d4be159b5ec35082c0b724593014ba87bc5c82034b01511bb86d3137ebab17c5734a68a48bcfbee72db4e3a0d1e9aa1d09ef7c988376fef56f05dd4a0f4a68b2180dc6b5201d55c245d669013d93e763927c650e667f8f6997a66445c96800cc6de96bb52377a2043307dbfd820d138765b5a3911a81d2b4b691aa03c745d01040d40ed03c97ce51fcafefba8fe5bb38aa65036531754b6a7615599f662b615e5bfe48a7738c70737d9d5302547e8abc79091f6f533645e59c11722a18920750f46f0f7ccc458e28ecbc3b95a6eef126d44ca6c3036a1c9f4452a32add8bd6f98e889ef9fc7572321169ebd97110e18ddc7edfa4c58fca6525884e92447306b3556b4fa15ee79edb80579fd3c2417acf2a50e8d446e2fbfe2edbcd37e462c79e83f15e85497bd4f890cd36daddf967f42658448ccec806ced2b6954127b433c5d79811185e1399eea173036a244e0af68c2c6bfaa435491e6529ae1ea5d6feda25525af4d36530311ff2ddaf267fc8ccab36dcdd84aa4bc9cff18864ceb53915383539e2dfe26838dd20f9cc82e969645549cf831b6131d2a5d0c09e714c4fded3c0e038b2cfccc8056ecb7b56d3b2e7e193601fdb1f041d6d5dcb0f28c05a953ee2bc8fdfba25a74e6484cd7070236e451b10c8d9ae2b8d2ffab30f3f8d04d6ee7dedbc0e486625c43cccc1466fca8b9f16dda3f3426e5ac0b8d796cfbe92c4c0a3eba5ea4158f852b046e7e01a3317d0a685b419b253ad4000971b6b47f8d4d1506309d5cfce7a9b766fea245638c41110e9b719939581916521c02855aeeef7d391e2770ad13001a93d0e118b61493fc927d7a9bef26ba7224cbe640ab3cbcbebffd88deb623c8f2fe9f7d588c7a37b85bc3cf00ab5a8edfdca4d75ad59264e1cde053202b1cf0a7ed2572c11bfcefc7191a9d999b14e422fcc7956d51ef908eebd62a2b9e166e1725dfd86a859aa2c160423c67543dd3de25e4495751b66c23c0793917f57056f2b371d276bfa76dbcf6587acef37c3a1b0a5899fc5f1cd27475797fe772c645385aac925a49b116e28f8e7fc0c7a8b87796169b450ff907ad7f0f1ef9b9eec831115170e9b3f00829dca947821e2884ff9f918babc411cc0e8bb4bf3855adbdd06aa700d2d10eb620f2eb8215718aa990af4f3357f73f28a36e98d7427a8713f01bccd264eb99b7cba5df3448e1fac61f384f65b2da207d63a0b2a8daa24d00d839cf7e1665ba37305a615b96b7d9b0414aa1fd429b833d4c91c5f7b04fff7c42d19f903e212af14032a1f75833b9aee799fd9ce6bb3c55f84381d3c32134ae08a8e19fb9e70f3a0b077a788627d53e1fafadf6522d74cab2fbc41f5bd45a0cb5039b0a64018e03e0cd2fabf7109dc7574419f37a56c0048d60bc9c378cfc9b90262ac9d35b66694f3df939b747a1a59a46e55c5c95f13586295c5bae13dec5be6437d3090af533bd1d330b7404d041f78a1b5ad1e1ad33714c543d583133903224b4a54f05c91f97ae89f22ce5becff20c57cd5fa8092a224f395883a35ee7d646018d3a0679d31b5465bcd3e47d59c356db8f26bf009b066be5af1bc2edf4840432947010408d15a98f2e9a2b6493f35833dc6da04098cfaf13de317c1c398bcbaf7e0b65e4fe9196b663cc59031926be243c1e24174499f91bf1634d5915d1fab5994337d7beabdf58ec66963af039f12992240c4cf9be644ac1db5ac7084bf9204e2c4cfb9e34673beb1cc1d613b1e0db91121e1e2f07694db354071a069187843923f83169d1373b3b781a1ca7255beede2d6f2263cab402a281511660b089e778ec6688a8b019785a11598814ede14bcc3ff2ef2915ec9e00b5eb4f4c6bfa5806e59ef7a644e65b7f14c9e49da24d93daf3b326c45111857677c72543886d5368d9560e2a9f2a368119cc66a9a5f2c6e14f3ab355dbb80f0c803163155c170dc7cd99b52680a2d8ccd53ab30729dbf69de0936083fbe9661ea6b51b4d0c3297e8244b02df5cbe6967240a6d1775615a2bc7985924b01b8078fc2f9eb9bcf1e7c33d830e346781c8a616a9c43397c75c40000000534509e631155d572e368002ac96610edeb1f61f332396601e196c254dfbf4a8d6c778c2eadeda0968c538cd478d491fb88a59f8a20bf49b5a9bc6965918b5bf" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\IdentityCRL\Immersive\production\Token\S-1-15-2-536077884-713174666-1066051701-3219990555-339840825-1966734348-1611281757" /v "DeviceId" /t REG_SZ /d "001840047220F990" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\IdentityCRL\Immersive\production\Token\S-1-15-2-536077884-713174666-1066051701-3219990555-339840825-1966734348-1611281757" /v "ApplicationFlags" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\IdentityCRL\Immersive\production\Token\{28520974-CE92-4F36-A219-3F255AF7E61E}" /v "DeviceTicket" /t REG_BINARY /d "0100000001000000d08c9ddf0115d1118c7a00c04fc297eb010000003c3bc39b8482064abd0c51587cdec25d00000000020000000000106600000001000020000000d5a1d35e02d8b4e2fe2d36a7cd8350c333c7abdf8a25c9bae36ab59a6bcf8cff000000000e800000000200002000000045dc6a649c500007b457c195df8672ad9117e48acee6b1d2a4ae13083b11c960b006000096b85bbfbbe9280756d4963f9757cdfeb196455bb92725ee3fab3d67edbbb2fbe49fc68c81491219e2255a9a2219948b0716f8c315292fc420eab1ee88d8746ea26f95f8730d63d9e56e39a77048ba247516b76016606426e78db1673b7271343f527c5d51a3ce7eed7b2e9a177ba5c190a87f6e3b4f795b5f42ac5f3436ce447eb8cc4ae01b2e0ec8157cc019de7b7dd26bb7355551cebe2a951e5f9cff79c42d6d1ef32190d85594ef3f72c5964fdb686771732030ed63e973ce9d8889ff03d464bd97321bfb16db21ad3171b6afd3f0de59f07dc560eeda63f8660a9ac3867b52131f8c841878c084c63990cbd90d6d85a3f1665d9c2968a7ab584eedd335893110a806ab646b127bdbad454402b89c4a44dedac1d1dd333b5afbf69ce393d82163e3f05c6f3da779794d4b6838fc87db88654d2870bc48838d5bfdd91e434ebb98e86311aa043c1136a2580e1dc25ce9f01a550ab20c09992673c82c804bfebb2a4f2d77a994495613b6b2c303f9a1c8031a69956081541bcb14751a8c013ce7290e432bf1bdd17408053eef945bb66481ae8beee9dd39078a2bbdf653888f452b9b4803a81da65bebaba974c0d3438fb6f944f9f5862777a231b2764a8a4688f41e6a9de3790a863ae4a930d0ee22ffd3ff9edbd7dc483c83f8434bbd21f803a52b052fba5ddd7a40d0e1616ba2540dbf0d073515b0852b2e867d0a94ffb36b73cb2802ddef27dc458f69f37407e93f6568dcec0b2409bb5967b9eec6e020a72a0b617ccd178f20bccd8ef9e47b0e0e5064e58652cb6ad5e63f8bbca88632e65507a2e3e9071c27fdb7d68d0b03939c05523271225eb370f06bef74da6077566f38259d131e15850c6ee704d889c4002bb70ad595d677f0a4cf9e3a04509882e2e825c655cfb9d0452a6fa489665fcd58ad8338a53928032c9921c4e5697771a398ce61b4acf061c0b1af7e348de3bf8c7ada0c8a3fd77b78c06057fba38076835ee6a4072578ba86f08789704e73324aed2162ee76fedf5e1d9a70e3bc903afd1f421e8afd4b58b2baa439ee7b79b3c26de86b0c09f573dd719ae0a3eac28f0aa40063cc5d0ded6ae5b7ca7c1248fc02d370169514332575d49edc6a542a5c7fea85b7846a4c4bc473f9f8ce74045e867cccf170b77e2f5a01dc0f0ff8e7fd5d005288e561c4557dba85c9fdcb5db1b4aba1887ed717d58422f6d4bd605e74ecd9558fa93681054f6b7739a4f90d3eeda93bf8aa4148fe1f77642859a9f6aa7252c6fae2958bb8525628b607b38eba69369f55461c3e34c8c89863de07b306faa6ce1a2fdb17bb5181bc113f0996bb860a5d3bdb0f50a050f7220350d27f968f1fa5f221b47a25aa36d5d42f1aa2cf97fced2b4a17f081850b09f8fc6fefa7d74525b818e38e3d53d3e9f88cb86eab2aab7be29491f45a2f4d999cb40b2aa1928b40d35011c9d941f723d5d2be0d8fb41931ca3f7808f82e4d8b6afab6577355346bc88bb083913496cf7897c134da4d70fcaec93a3dc16ee90b839a021bad6d66b3bc6d89701ab88ca7aa0f414f32d6ea40578aa79743e0a4d064e44d92840a79010c4ab97ca0401bff24959cca9d76a8e04bc1659dbb2750ac03cada31fadd3fcabe65639051bf635e58ae7720a29664c3997f47a6ddf64e0de8d44553110fe4885f4d8cdd9f2ce5a5a06f7c7fad3681a06b0e73ec8ea3a600c66ad64910269c7b45c9a395e03d9d7b68269cb87f2d412a011714a4d07f3724a3c08c78234c83066ac314b73299db99f1fbe68e2911f7fdd02c67dd52575bb21ad271c3954d723fb876e5aaaa6e845faf7706a9d33fac0ad2ad7ecac3b2f9766f2c7304bccbbe51e9d19f4026959dc9a535a7a57c533ad37434abcddfbb68161bc67cca2da11cb15ee4d165f0d4ed2713e007493949c4a0639fe209f00949ee61754872879a49b613adcb9be8171f768eb6c3c4c1bca0bafbcb3c27ea72a2afe9e78cb28b50d767c171705ff9a62109112f3136265dd9c526da0dbe6675f99a64a5339879dc7df1721f7aa192b8707dab79b8d3653dbe9f9c2e5fc53e0eae839549bc7b3f18ae0d406c05004cb015ddffc63b7102ab341e62e0372892560e8c3acbb82e4a87b4f5da314922ba06092c8435e665504e60c115dee1d1ba07c14286c6c4c7a4496fc51cecbce54278c18b23a3654de1013b029e10652dbfd06da3d701e6ef4a290968b2b4ef19eeb0d1fc6621f8b2d730d90b17c33c3fa0b2479a383e34f789160141dee9c65b66acaa5b565dd2e5e681281d316a0de4dd7d8c8044518953805166783b7b28aea21d3810bcd231076b4d81b9a38e6eb3b07a426dedd34c3ec51b0167af0881a785e6dc4f2f425d63affa824c0d454699491a5824459043c2471f93d2a1847d351e23910d1a73a340000000bdf89e0b4f4deb03958060d4047827f46147ac45c8465b9fbf84828bc373d315211f48fb356bd68585dd72d5b278ae25ed6e8b25c92b57a040dfde7ae2eaf2a9" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\IdentityCRL\Immersive\production\Token\{28520974-CE92-4F36-A219-3F255AF7E61E}" /v "DeviceId" /t REG_SZ /d "001840047220F990" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\IdentityCRL\Immersive\production\Token\{28520974-CE92-4F36-A219-3F255AF7E61E}" /v "ApplicationFlags" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\IdentityCRL\Immersive\production\Token\{D6D5A677-0872-4AB0-9442-BB792FCE85C5}" /v "DeviceTicket" /t REG_BINARY /d "0100000001000000d08c9ddf0115d1118c7a00c04fc297eb010000003c3bc39b8482064abd0c51587cdec25d00000000020000000000106600000001000020000000913f405236aeb3d6d152c40581fcce707d0140875397d15f19c32490b02a11a6000000000e80000000020000200000000d355a547606e7d3fac5014924f094d007fa395a2c0fb6fa28df8c2c87b40251100d00007220281b6f98752d426cd3931ebb9dc03944a4d4a18bdbbfa2df9b328877582abef0fe7b59fe74c8be59db2ae0608c32cd14711d95c321f87a15165639f40e86e74c0edb5a1caa4724d6ef55a71be5f3b6a8afd84077201c362356d3c275d51eabf619728eaa555f5ca59e287429f91661fb1c522e5575d5af23535e0d9153ca0227038a47ec99a94e64b2898addae8d6d122c114f8f41828ab26fa6ec98786c97d6ccd052202a1745768c662147c688593c2fb84e302ded2954951230417d075d17d99f55b3edb877e572403f2287ee7659273723002a16bf3f4685d092c62394c072219ddb0d3684e3ceabfae183fd62bcb148918f3a693fad86faaf644bf07c3118246167612d5250050ebaa70d5b038e88ada5be8b4a96bdb50cae6a90a98618e08a4a08e27a8c7a371dae3cee139510e944aa8260decee64175e9c932a575254b66606b4f8471d656eca696ba7767673f0edd60544cd9f3366041b2566c12e04bd7b6ab6fa7ccf02ab27682561a6b0540dba7f4fc56804b096c5e9084f873b184f22cb6f0214299e42d3dd06fc4050e93ee84391cf0b06554c47b799c8f8aadb90c062bceb78537d2c4fdf9b3f77f17aeab41482d4d112a201c74ccba3c143908d09db0a1e0e199957556d8321d8ed4bb467dd12ac17ae6eaa0d241b4bc3c96cc8ab15f962c689a52484506cbd29e1cd96056ece8d6e69e24fcb5fdfd2f8020147855517d0c017fe96968ffe90eac4ded1942190304c78c00d6a5bc7c87b2f7fb2ce39be2eccc231627e494014a6d9b83bf49a2a9b9565bdf433c9ed49176a307efa5178494bb26564f25931b839e712bde920bfb19239501bc85f2acc7bd7fe6f9cf2023f5948bb591536da1246fafec347e59489a32314df51e4445fb18d27d14b0cf379a2a0291ccb67b040019e36b8ebd0f9f05d080e201c6cba71499371331744d94327825a165576481cdb0c77b26901bd8b769319c2414604b67b3c20bdf7ebd13befc92dff4ebb8fa39b944ea3b73a7e05932cb4b9eedf5c534a6e9c98d6b2cd2972a5db42720682862f710b14a6675dcee4e520cdac060188a5ebc335a0a589b633b01884353b3aa19100a46449e023d9dff90dd39f4a8b749b2101664cace8ebafaa4a2028eb2f5d503fb394c5c789e2087cd7679a3f7d338f2de7a08d34e67fbc2fa77b71a8b0f1b10059efa69b8336571dd28b4157d562b1f87986e1dc6b7c7a7081363dcec4294b47baaf4a61d651ab049af6de1e570c51f53002b8053e2afad3c6ac83be3f610be82b28fb03b25d4f6f11a51da96ce2f97cd7b27dc21cfd1b8dc0578eba019bd784b740466691fdf477b625dc3ad097ac552db66205981255296b1325645564c777e7aed0b27e9139a53a34ecaa422f60e3762d1f31a7540886d6e02c76a9d1fe16ff0dec031206041a70ae1967a51f95293ac7c3f41b670b722e4a794c498873381b82dac7a473544be5e98487c5ffb5485ccd397738882f25036acd973230af9217aed66733e7873cbd9c0a231a62120c25d7e74d4be9a54afa1922b501a460eba1dbb35755faec3c198b52a14ef8acaaaa39d1502dc2f71bdd296ba33b36ddffa139088ea873fcb18ac459b055f9ff6491b585ab675cb0add1ba5ca29b55726bf3797591bd00b379bd92f6d7f04d7c64db8c1f428f196b17c37e7791db7270ab3c58f9d6252a09ff253226dbdf14053847b9e967d70a0b249566bd41f04d78b0f4ee060166aa9fb0e7e8a8e5f09761b0e39eb08e359e4b497e3ea39974769d7717fbfe9af0c764ac4041588d27ea84ef9758be966b3f30114a8e7068dab33bafda88388212747e403d2963057a0545179a2e2ce87a16f00e2206a77125f5b62006b9dfb8aba2433f9c5171dfa337894bde46c51c82c636ebdf320b5e568ed95d2d6498adca540cab578f28409f0bed4b88d7af04bc13daba36113b1c12d5cd712fef7446184260aa7bdef10aa0d7b80cbcfc88d965886978a20208f6c5bea2741698c37867eddffc663cee9b7302c15019ea0b787be4f7c0888709dd404fde874c7146db3636490503204398263894e26e4ed5f06f3061b409083f09d9d16a2ee6d0e9c19550c78ed9c92e270316b5ea07586e0d2a2d0f0d378468053e42131d192af0fe861d72b72c1b26fd214d5ce02e41b66d0243540e66306b9267062b9ca73fd1a7c7499a628e3630b150ee0a517e56934e0f0d40907df72b45341c32342c74c7b1f279a02091e46b5eeb159b90e49bdc8f7c66bbf3f8261d95a0e609bb59f34645c46950814b250002f08f5cda5a100cdb171b7a5251b7eb5a9a76aa6252831b0a2af4b83c2885569a9156c628b1f1bf3937b98fd2115ed17f58772b8dc950e30a5332124e7bb9f92f7d07258968cf33b02a6532e968858a7f701b9510ccbe478e4e9c9dcf9fea200c0d0c94c36699c239c6a26376a3ce91580a468260a65337833b01732a2f4d51ff1ed5f689c86ee7732a85996e92971b86e657b2780c0c305cf0114ef21818072e9c16afe09ff24a98b5a7af331669a5ad1d893ed1099e3bf1777b611a0a62938cff230f724d9f53c1ce89753c6d45a21fc5a3a21e76da566fa63d701d8f7eb6d13d7b9018e210e06b9f8388154f7526061174bb39a6251dbbcdd2d0cf1c77bde159ef388d3cb4ae0aa231c4abecf0d4da24437ffb70daf28b37f88c31550008015e8b85c0555ae4730c82c852191e5895f5cdf773cd35423ccfdb4db68d284a8a2305159974d76f5b430342963f2d07754fa17e7fccb4773d2824c9a78b60dc3dfd1b6c05e3bc6f6c90557c4d2bd0aab90bc3356526337cbe6cc2bbb2e8e695192cd2f13f01b84abe910b18bbe5f8499c683583c39ad094f218e9aa7125bab4f4d689f2dc9ba8f3142b4927202b0dbba9a7ed22a97eeb388594ffa2f97180c2593331b438fdb10ff8b3e41b8045597c51da10910d3f5637ec9c54cbfc61169d954b065248d1057535d7cd2298e7ef82768281e86c3f52fa7a95a6d69c7fad45f1d3ca59aeeb8d50761d5b10f752c97bb3d42290ca7b7c56e8feaf33342ff18b97f7f34c33b9cd2c13e80a153cb3d2859f9d6b1b8a3a4583e4f0768ecb32986fc82214fd07d2f4df72105ebe84d897ffdc9452ad3b126cca2494bb41827ebef744729ee111f4ce94b2248b4e3e79608dc071a2422585468a89a3ca06070c69647dab0669d88029ba1f86e91eca87b3da18082c6554302d29e3a17984d88b4068c471cc5534ba1023169f3f7fa6456164fb23fa6cbff4c9b5c6bca4716bf723aa18c1409e8e82cd70c66741f6336db41d82e0a6f65c163a8917d76b07086054f24524a72ecd3c7f93e294f35b6bd686e8632d66bd9782edd56ac6e7b0affe704a3d54f4725c089ece3d7f17f681080af78b6289ed407bc96a657a02eaa398c939a13fbc100b50fc87d465aa39af9d81fc802cdcf25d4e4055d2572b63f30c43fbb65bfa95d2e69d4ddf2f025d06f48fbab4a834bf84ff39953d1cef169690b100076146da8db578eba1cb8d393950e37b30ac2e2fa6b95ec7360f83bb143f0e8eb36c7abcca5150b73852312e7650660b2a468944120d89e13dfff17085e1afc88e4886170627c5c15b8e0cc1dc98bc496cb8e59b674b90c38f534f7dd633d9eb3838956f005d4d6f923a6b7c7d7ab668b9322b5c978807535a438da29c5a08c858ef5651c73f61f1ad1fd5212b03ca0e694893572931b24ab3a9aa607f5d299b6dd971008169b3aca7292e808954514ab00a9a6e1b6a14e0e91207f5f1f7147e5da5b7931caf0359b6ecb4280919ce63587ee4e56b76ed8c144138666ce59ec3290ee3811ed2755b73f7b593e1caccd5ccffd8384c9fcf223e92722b03a585e6524a013d8c09f98f7e84f5b110fd6ecad2e22ede9c654c306d5a11e3e17dc7a01a083f97957544c667c3200ce2e4d947426d19085a07f263eabe72d24cc2af49f318cb3d2e847e8689987c21e9ac676bb967a9040c6a656069df718fc657864105a9ff00bd8cadb12741026a71462fbc8d26b803eb40bb435f6518ac0b8a08bdd8558855e0e21c096000363dcab82eb038709600c955c779b1b0f552dfc9d68d4054c12956814ce788798e3f200a517cc4ee5668564a70b3cb2c1f8fff6590da2c9854816c6a5f394dccf8b2c19466a8a24280b95e61bf8b18af3df941a2b63984261d0d28909c9c98c4b4c02145e22889848cf956350cd7fc3bf5b801e8d9744a44c109b1757d19e94d594bc2df7d2e31846c5b30fbebdacc7f97463d75c78e754345652a69da550d514bb830cbb49953560838c6bf5f82540afb7a41f8844fae05a3669af126d4a8e82c14b023aade139ec391697b962ba560cd319799f7163d986b69b03bf41743b6845e99f0f5a9af623f227f6357a9bf885f3abd4a55cd53ee41d1612ffee7415ccffd72f4c3b625dda73e71ee49b90a0b9c89c99f3c1f84f3b07bff6255b0d1621fc8f72643c2d9b55877ef48b399adc2e6d4ace052a1ca16eb2565bef83943a66f1eb70700d7291bdecd30336ff3650eb98346158826bce8d7bc9813cbcc50eb986cd0dba46c2d13e07d38f27dfb8b11efc9566ae9ee00a968ffe44db9625eac65b6f265d825542a0efa0009aed112099a53ce8f0c02fa6f5e77ca61d5e2958bfbed57a62e0c20f04e873ea4c092d0b58a29ae2121ef231f687a49467d9f4ec27deb55f310547099b2e400000000e021f50a6fe1ae250fd3f0e8a1605db3e6797c39e54dc8267598599b9675499e9a933f41672e09d2ee8d47683576c51a6375989235dfb70092261248367af25" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\IdentityCRL\Immersive\production\Token\{D6D5A677-0872-4AB0-9442-BB792FCE85C5}" /v "DeviceId" /t REG_SZ /d "001840047220F990" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\IdentityCRL\Immersive\production\Token\{D6D5A677-0872-4AB0-9442-BB792FCE85C5}" /v "ApplicationFlags" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\IME\15.0\IMETC" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Input\EC" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Input\Locales" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Input\TIPC" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Input\TSF\Tsf3Override" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Input\TypingInsights" /v "Insights" /t REG_BINARY /d "02000000071de8c131cc8360a3d6d9c1330a686b165aba2e235f5a5c" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\InputMethod\CandidateWindow\CHS\1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\InputMethod\CandidateWindow\CHS\2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\InputMethod\Settings\CHS" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\InputMethod\Settings\CHT" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Connection Wizard" /v "Completed" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\BrowserEmulation" /v "CVListTTL" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\BrowserEmulation" /v "UnattendLoaded" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\BrowserEmulation" /v "IECompatVersionHigh" /t REG_DWORD /d "268435456" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\BrowserEmulation" /v "IECompatVersionLow" /t REG_DWORD /d "395196024" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\BrowserEmulation" /v "CVListXMLVersionLow" /t REG_DWORD /d "395196024" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\BrowserEmulation" /v "CVListXMLVersionHigh" /t REG_DWORD /d "268435456" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\BrowserEmulation" /v "CVListDomainAttributeSet" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\BrowserEmulation" /v "StaleCompatCache" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\BrowserEmulation" /v "MSCompatibilityMode" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\BrowserEmulation\LowMic" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Desktop\General" /v "WallpaperSource" /t REG_SZ /d "C:\Windows\web\wallpaper\Windows\img0.jpg" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Document Windows" /v "height" /t REG_BINARY /d "00000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Document Windows" /v "Maximized" /t REG_SZ /d "no" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Document Windows" /v "width" /t REG_BINARY /d "00000080" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Document Windows" /v "x" /t REG_BINARY /d "00000080" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Document Windows" /v "y" /t REG_BINARY /d "00000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\DomainSuggestion" /v "NextUpdateDate" /t REG_DWORD /d "330598109" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\DomainSuggestion\FileNames" /v "en-US" /t REG_SZ /d "en-US.1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\DOMStorage\microsoft.com" /v "NumberOfSubdomains" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\DOMStorage\microsoft.com" /v "Total" /t REG_DWORD /d "48" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\DOMStorage\Total" /ve /t REG_DWORD /d "29819" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\DOMStorage\www.microsoft.com" /ve /t REG_DWORD /d "48" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\DOMStorage\www.youtube.com" /ve /t REG_DWORD /d "29771" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\DOMStorage\youtube.com" /v "NumberOfSubdomains" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\DOMStorage\youtube.com" /v "Total" /t REG_DWORD /d "29771" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\EUPP Protected - It is a violation of Windows Policy to modify. See aka.ms/browserpolicy" /v "FirstRunComplete" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\EUPP Protected - It is a violation of Windows Policy to modify. See aka.ms/browserpolicy\DHP" /v "BackupHomePage" /t REG_BINARY /d "0100000033000000af178b74dea7a8ab9b54c1e88fc17975403d5078359ba2b2d6e19613c27157aeb9710a1c1155118e67b3493d95489483fafaff020000000e0000007536374669565959327030253364" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\EUPP Protected - It is a violation of Windows Policy to modify. See aka.ms/browserpolicy\DHP" /v "ChangeNotice" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\EUPP Protected - It is a violation of Windows Policy to modify. See aka.ms/browserpolicy\DSP" /v "BackupDefaultSearchScope" /t REG_BINARY /d "0000000032090000d13d3e6951694a06d9a230ed08c2240c8bffd1c91473aa3e8795b79f2ebae4a44da80aa268ca3eb654a0218225697b3eba2adfcd3e927126c157b6cb9813693fcebb0b2bcf2fcafa428f0f5c333d4be2dace69c28a467f39b45afc133eaa16fa09181f05a8ba4301f10eed5e375e1118f88b45f39faf308abe3e3b4fab9da81b1f5d75f4038a82c401bf39cd1eec2069f7011dc475ee29fc57a4beb82f0e3255b82b57c774bf5a26784199111e07967e02d09f8320215dbd262a2c76a41b0c2332238b3c6679ee4c9f33328d14cfc9ac309805d3aa6950130371ca331be697fed9e3cd6fa7d7c65c0e37c37ade645f4958f94b9d7ae70a7afc191bcf958d0b5d620de6d3f1fb3a7c70eca5e0d5e6d1d41593369b67b99a0f82c21a1257322a81543fcec56f04f8268df1c595a675e5f33f06c66cb100484edf0c4f7cb0f36a1aa41acfa91412c2d155e83f51a231d236c7f1353ed7dcb61a6a98b91c17f269b7263fe99aed4415e24b70ecceca3a31b1a9f6bfff166ecf2210043a7f714e6a049f4cf8a6d9bca7eed428d6ffc9b04965a8b4b22912d4c18511f167a5ed2621dd77e30d9e11993b5734b2484fbab3bd78e3cbbe14c72f3bd3b9ffd50e259c452ec4a2e57373fb102747addef28d635140b8dbafe033a05757d1ceafd8dfce9ba1af2a99292502ef4a9ab8fe4ef3e0e2163f8499e90e45d8b79afe80e267de2724511c8150d0cd041353753e67ca4a9a05656682ce943f2fdf7330840ddeea163396162f15f97e2a0b92825163b0c10a3d23218a0cf2ae7d3a4002bc841914a4fc52bacadf0c342d1dc2815520aa65735f0a55d11b51b3e3432515ed16837a6152faa6ce82490f89032811dcd1b656e6936fa23b2d1f6cf4615909f6a1273e2066867b13f8942e02139bd136b791b4c97460a82a71d9fac511df7ebc8da77e995f2dda2eb2c5b37a4ae9639adb859fe4c58806bae99b7d2365bb1492572d5c64b9a461bd76f2bda5b73466d4eb9f372dfbb25e4ed530161eced16bc029bbf6fd6f5db21fcf276cfe2fa37975136b9d7f95d54fe3a1b1e3be3b76248f875c6e2e06f46bf00964e0d84efc3eabf342ef4b45cc795175bc05b6853addce09a8e24855ab2d6dc2e538aecf7e5441a6414e30e9bf7c3e44719df82a1d370225137485285c99d805cc967d308d5ad4cb6fdab85112f8b07619c9025b85d2c808bc4381b5a14d1cfe1c1982a2b1f268b20db33ddd2d8d622182aac556d64ee785e16e9cd452eb93325de1145742bba08547f991dd6bdbb8c78760d6189f4bef0a7f17e117fc11c654810dbf0ba0544d9357cce7d35f8206b8540c45546a6a95affb5cbaa67c61029eadbfe1f2fb5fa49a534cf07361223feeb9cc16c05e49d94e245f64f30879d0c1df16c1e74f7bb6322a996a82db5a298aa3c141b6378905aecf3ef835b9faaa676d32e7f3ba47fa3970d3a7798accd5d85c0c3f1beecaeebd461b9ec044850c3e6b33d020186595583b1a8704a3172ae739cbd09fc8ac79ddc214e020dab858958538459f50740197398e4f45dcdb3eadca1fe449b2cf1c3a594b170b7d35228f8e637c3b8413bafb2f4f2cedd4b86bc0bf282852cfd3653ae0de0621109a13df1bd33f1e07e4b23f117d1227e44e579b5307905246599af22bef2c7ed988bb1638a898e71b860b90063898501d3d8c7553dab4bf38ffb8b6a19c5a1923a09a836e02c70bed98ad6315a0fa7f7a251da9a1c2a4b50566beae360714f6d88089a1b300428f0ebc4159f0d572dc55a679a969e00e17f22e24859b4e462462cade14f3c4c2055a91482ca7f7ecc94060248726522cf8aff7502001936b915f1c193a176d56eaf6b611b7db261edf5ef35b0cac398d59ef61196bf6f447a6e117fa47541b1f3f13cd4306b5825faf82fe245c93b5ec37750db232109333be675cb3f687ed7e892475a779c72b8060af23633044e77ce54e997b0f7d8fb75ed48989c6c205700ddb4dd4f7cf411017a8011c9809ed86b814a6c05ded074a4e504028c9558263693ef7c52ec0e49f2bc5384757d3e85308a9d4ee4b591d1d73cc1f080109842d774d129ae9e934dc359568bfc304f93a76b7c33ef1eaef378399c7e050272b4482dc3d1c71b55169e11f312743223ebf8ff1136d7c499f8d847ed94ff9b5967dca211a33fea25b129b1433634eefd892b46265a568dc4ba71fd1f3a9a7fde766589647473caf72bf063e0e2207bfe7d4586657d6ce1b1571bd44b76516123d4324cb6671dcb5b6c04613625a616b8cd48d1a8a05b9f71b0478c7c3af357cb8ec884b165837e2474e161dcfd7d518e535df0f9eaf93697fd3de90b8a1f299778a0791f68d0084458eb32bf5d9acdb137782883341a2bd5f2e823537177ed99c4a5eeba83a09cdd089929873f7d18e3678cef2e9ca8d25ddfd56a0de5a2fe34672ea17cb74108808d5eba6eb333a626f300b96601afdb517f1e45d4f66f03395fa5d8afe8fa6650e8d0fdcfc9bdde9dcf58f3939a841072f1849e628a63e74a946c4fbe39b2371003794c046173bb99e30293f12890e874358078d0a2fb8a5a100d7491957a365ff8a48e8691d6e7bd611dd1b8cd1460d7592a50496f339d29fb1a1943f991b7f2b3d01120583d810a24af3b147bdd49be3e723bd6a488e07c21476c3f7f47f4ba4b52d35bad9569123ce50d6e3e196bcaf203454283eac442a26325ce093ee628a36432c283a059c79e4279a00905748f8b953cb6e0286c5f62ad29e9932fb66fd4cf47eef9d9a2ac55bf1933f2bdcd5ddaba55dde5b67b3489057f1c4aaf9661d143871aff54aed2573bc5e3e21fa6a8029a4081602e1e73f81fc77008464320a1426b9071b3eb8baafc6039ef0c5c9ff7da4b0b7cf4e1cfbeeb8a4ec0d4f07e4f89b8699809a7ba5ad6de8fff9c95a7ce721706214dc6c9c1c13092a16e737cb03b4ed04f2162404df67c3013953c415c1e3d3b57c2cb341834c5159e50833dfe115d0e88c20f8f81551c044dcccecec5fea6152f580dc0cf8cef118ccdd4d401303f2e5279881a1b4899c682627a91f79311ed7ac7c041c7df110096495070ece4be39be20f58202d61490eef5561d0ee3d95e586725691841152cbd6204f6986fd5daa54a744934e9279d472d6ba1d1b822f1d4042758b58f5a4fd000a4771def139b2a971aa1b4d11025b354f3928bf8cd41d4dc5bb29a27c0a413856e746f6224653766a6fd98825f34351378a0f380767879fd1fc8d37ab3536f274e50867d7512d9cfa35ebbbdab32c779015f4e28916f9b9c52cd63ff9da7b4744e6d7ea970de0010000000e00000052474d58666256615430552533640200000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\GPU" /v "SoftwareFallback" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\GPU" /v "VendorId" /t REG_DWORD /d "5140" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\GPU" /v "DeviceId" /t REG_DWORD /d "140" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\GPU" /v "SubSysId" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\GPU" /v "Revision" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\GPU" /v "AdapterInfo" /t REG_SZ /d "vendorId=\"0x1414\",deviceID=\"0x8c\",subSysID=\"0x0\",revision=\"0x0\",version=\"10.0.19041.546\"hypervisor=\"No Hypervisor (No SLAT)\"" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Help_Menu_URLs" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\IESettingSync" /v "SlowSettingLastChanged" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\IESettingSync" /v "SlowSettingLastChanged_TIMESTAMP" /t REG_BINARY /d "5452fcfb8b62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\IESettingSync" /v "SlowSettingTypesChanged" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\IETld\LowMic" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\IntelliForms" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International" /v "AcceptLanguage" /t REG_SZ /d "en-US,en;q=0.5" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\10" /v "IEPropFontName" /t REG_SZ /d "Kokila" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\10" /v "IEFixedFontName" /t REG_SZ /d "Kokila" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\11" /v "IEPropFontName" /t REG_SZ /d "Shonar Bangla" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\11" /v "IEFixedFontName" /t REG_SZ /d "Shonar Bangla" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\12" /v "IEPropFontName" /t REG_SZ /d "Raavi" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\12" /v "IEFixedFontName" /t REG_SZ /d "Raavi" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\13" /v "IEPropFontName" /t REG_SZ /d "Shruti" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\13" /v "IEFixedFontName" /t REG_SZ /d "Shruti" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\14" /v "IEPropFontName" /t REG_SZ /d "Kalinga" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\14" /v "IEFixedFontName" /t REG_SZ /d "Kalinga" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\15" /v "IEPropFontName" /t REG_SZ /d "Vijaya" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\15" /v "IEFixedFontName" /t REG_SZ /d "Vijaya" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\16" /v "IEPropFontName" /t REG_SZ /d "Vani" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\16" /v "IEFixedFontName" /t REG_SZ /d "Vani" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\17" /v "IEPropFontName" /t REG_SZ /d "Tunga" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\17" /v "IEFixedFontName" /t REG_SZ /d "Tunga" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\18" /v "IEPropFontName" /t REG_SZ /d "Kartika" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\18" /v "IEFixedFontName" /t REG_SZ /d "Kartika" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\19" /v "IEPropFontName" /t REG_SZ /d "Leelawadee UI" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\19" /v "IEFixedFontName" /t REG_SZ /d "Cordia New" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\20" /v "IEPropFontName" /t REG_SZ /d "Leelawadee UI" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\20" /v "IEFixedFontName" /t REG_SZ /d "Leelawadee UI" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\21" /v "IEPropFontName" /t REG_SZ /d "Microsoft Himalaya" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\21" /v "IEFixedFontName" /t REG_SZ /d "Microsoft Himalaya" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\22" /v "IEPropFontName" /t REG_SZ /d "Sylfaen" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\22" /v "IEFixedFontName" /t REG_SZ /d "Sylfaen" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\23" /v "IEPropFontName" /t REG_SZ /d "Gulim" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\23" /v "IEFixedFontName" /t REG_SZ /d "GulimChe" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\24" /v "IEPropFontName" /t REG_SZ /d "MS PGothic" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\24" /v "IEFixedFontName" /t REG_SZ /d "MS Gothic" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\25" /v "IEPropFontName" /t REG_SZ /d "PMingLiu" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\25" /v "IEFixedFontName" /t REG_SZ /d "MingLiu" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\26" /v "IEPropFontName" /t REG_SZ /d "Simsun" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\26" /v "IEFixedFontName" /t REG_SZ /d "NSimsun" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\27" /v "IEPropFontName" /t REG_SZ /d "Ebrima" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\27" /v "IEFixedFontName" /t REG_SZ /d "Ebrima" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\28" /v "IEPropFontName" /t REG_SZ /d "Gadugi" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\28" /v "IEFixedFontName" /t REG_SZ /d "Gadugi" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\29" /v "IEPropFontName" /t REG_SZ /d "Gadugi" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\29" /v "IEFixedFontName" /t REG_SZ /d "Gadugi" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\3" /v "IEPropFontName" /t REG_SZ /d "Times New Roman" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\3" /v "IEFixedFontName" /t REG_SZ /d "Courier New" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\30" /v "IEPropFontName" /t REG_SZ /d "Microsoft Yi Baiti" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\30" /v "IEFixedFontName" /t REG_SZ /d "Microsoft Yi Baiti" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\31" /v "IEPropFontName" /t REG_SZ /d "Segoe UI Symbol" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\31" /v "IEFixedFontName" /t REG_SZ /d "Segoe UI Symbol" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\32" /v "IEPropFontName" /t REG_SZ /d "Segoe UI Historic" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\32" /v "IEFixedFontName" /t REG_SZ /d "Segoe UI Historic" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\33" /v "IEPropFontName" /t REG_SZ /d "Segoe UI Historic" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\33" /v "IEFixedFontName" /t REG_SZ /d "Segoe UI Historic" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\34" /v "IEPropFontName" /t REG_SZ /d "Iskoola Pota" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\34" /v "IEFixedFontName" /t REG_SZ /d "Iskoola Pota" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\35" /v "IEPropFontName" /t REG_SZ /d "Estrangelo Edessa" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\35" /v "IEFixedFontName" /t REG_SZ /d "Estrangelo Edessa" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\36" /v "IEPropFontName" /t REG_SZ /d "Myanmar Text" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\36" /v "IEFixedFontName" /t REG_SZ /d "Myanmar Text" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\37" /v "IEPropFontName" /t REG_SZ /d "Leelawadee UI" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\37" /v "IEFixedFontName" /t REG_SZ /d "Leelawadee UI" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\38" /v "IEPropFontName" /t REG_SZ /d "MV Boli" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\38" /v "IEFixedFontName" /t REG_SZ /d "MV Boli" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\39" /v "IEPropFontName" /t REG_SZ /d "Mongolian Baiti" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\39" /v "IEFixedFontName" /t REG_SZ /d "Mongolian Baiti" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\4" /v "IEPropFontName" /t REG_SZ /d "Times New Roman" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\4" /v "IEFixedFontName" /t REG_SZ /d "Courier New" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\5" /v "IEPropFontName" /t REG_SZ /d "Times New Roman" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\5" /v "IEFixedFontName" /t REG_SZ /d "Courier New" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\6" /v "IEPropFontName" /t REG_SZ /d "Times New Roman" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\6" /v "IEFixedFontName" /t REG_SZ /d "Courier New" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\7" /v "IEPropFontName" /t REG_SZ /d "Times New Roman" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\7" /v "IEFixedFontName" /t REG_SZ /d "Times New Roman" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\8" /v "IEPropFontName" /t REG_SZ /d "Times New Roman" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\8" /v "IEFixedFontName" /t REG_SZ /d "Courier New" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\9" /v "IEPropFontName" /t REG_SZ /d "Times New Roman" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\International\Scripts\9" /v "IEFixedFontName" /t REG_SZ /d "Courier New" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\InternetRegistry" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\LinksBar" /v "LinksFolderMigrate" /t REG_BINARY /d "044c900bd762d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\LowRegistry\Audio\PolicyConfig\PropertyStore\3815464b_0" /ve /t REG_SZ /d "{2}.\\?\hdaudio#func_01&ven_10de&dev_0051&subsys_15691287&rev_1001#{6994ad04-93ef-11d0-a3cc-00a0c9223196}\topo01/00010001|\Device\HarddiskVolume3\Program Files\Mozilla Firefox\firefox.exe%%b{00000000-0000-0000-0000-000000000000}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\LowRegistry\Audio\PolicyConfig\PropertyStore\3815464b_0\{219ED5A0-9CBF-4F3A-B927-37C9E5C5F14F}" /v "3" /t REG_BINARY /d "04000000000000000000803f000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\LowRegistry\Audio\PolicyConfig\PropertyStore\3815464b_0\{219ED5A0-9CBF-4F3A-B927-37C9E5C5F14F}" /v "4" /t REG_BINARY /d "0420000000000000180000000000000000000000000000000000803f0000803f" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\LowRegistry\Audio\PolicyConfig\PropertyStore\3815464b_0\{219ED5A0-9CBF-4F3A-B927-37C9E5C5F14F}" /v "5" /t REG_BINARY /d "0b0000000000000000000000000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\LowRegistry\Audio\PolicyConfig\PropertyStore\702fdffc_0" /ve /t REG_SZ /d "{2}.\\?\hdaudio#func_01&ven_10ec&dev_0887&subsys_1458a0a3&rev_1003#{6994ad04-93ef-11d0-a3cc-00a0c9223196}\espeakertopo/00010001|\Device\HarddiskVolume3\Program Files\Mozilla Firefox\firefox.exe%%b{00000000-0000-0000-0000-000000000000}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\LowRegistry\Audio\PolicyConfig\PropertyStore\702fdffc_0\{219ED5A0-9CBF-4F3A-B927-37C9E5C5F14F}" /v "3" /t REG_BINARY /d "04000000000000000000803f000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\LowRegistry\Audio\PolicyConfig\PropertyStore\702fdffc_0\{219ED5A0-9CBF-4F3A-B927-37C9E5C5F14F}" /v "4" /t REG_BINARY /d "0420000000000000180000000000000000000000000000000000803f0000803f" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\LowRegistry\Audio\PolicyConfig\PropertyStore\702fdffc_0\{219ED5A0-9CBF-4F3A-B927-37C9E5C5F14F}" /v "5" /t REG_BINARY /d "0b0000000000000000000000000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\LowRegistry\Audio\PolicyConfig\PropertyStore\f01896c7_0" /ve /t REG_SZ /d "{2}.\\?\hdaudio#func_01&ven_10ec&dev_0887&subsys_1458a0a3&rev_1003#{6994ad04-93ef-11d0-a3cc-00a0c9223196}\espeakertopo/00010001|#%%b{A9EF3FD9-4240-455E-A4D5-F2B3301887B2}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\LowRegistry\Audio\PolicyConfig\PropertyStore\f01896c7_0\{219ED5A0-9CBF-4F3A-B927-37C9E5C5F14F}" /v "3" /t REG_BINARY /d "04000000000000000000803f000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\LowRegistry\Audio\PolicyConfig\PropertyStore\f01896c7_0\{219ED5A0-9CBF-4F3A-B927-37C9E5C5F14F}" /v "4" /t REG_BINARY /d "0420000000000000180000000000000000000000000000000000803f0000803f" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\LowRegistry\Audio\PolicyConfig\PropertyStore\f01896c7_0\{219ED5A0-9CBF-4F3A-B927-37C9E5C5F14F}" /v "5" /t REG_BINARY /d "0b0000000000000000000000000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\LowRegistry\DOMStorage" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\LowRegistry\DontShowMeThisDialogAgain" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Anchor Underline" /t REG_SZ /d "yes" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Cache_Update_Frequency" /t REG_SZ /d "yes" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Disable Script Debugger" /t REG_SZ /d "yes" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DisableScriptDebuggerIE" /t REG_SZ /d "yes" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Display Inline Images" /t REG_SZ /d "yes" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Do404Search" /t REG_BINARY /d "01000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Local Page" /t REG_SZ /d "%%11%%\blank.htm" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Save_Session_History_On_Exit" /t REG_SZ /d "no" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Search Page" /t REG_SZ /d "http://go.microsoft.com/fwlink/?LinkId=54896" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Show_FullURL" /t REG_SZ /d "no" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Show_StatusBar" /t REG_SZ /d "yes" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Show_ToolBar" /t REG_SZ /d "yes" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Show_URLinStatusBar" /t REG_SZ /d "yes" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Show_URLToolBar" /t REG_SZ /d "yes" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Use_DlgBox_Colors" /t REG_SZ /d "yes" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "UseClearType" /t REG_SZ /d "no" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "XMLHTTP" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Enable Browser Extensions" /t REG_SZ /d "yes" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Play_Background_Sounds" /t REG_SZ /d "yes" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Play_Animations" /t REG_SZ /d "yes" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Start Page" /t REG_SZ /d "http://go.microsoft.com/fwlink/p/?LinkId=255141" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "CompatibilityFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "SearchBandMigrationVersion" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "FullScreen" /t REG_SZ /d "no" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Window_Placement" /t REG_BINARY /d "2c0000000000000001000000ffffffffffffffffffffffffffffffff2400000024000000440300007c020000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "ImageStoreRandomFolder" /t REG_SZ /d "523nc4e" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Start Page_TIMESTAMP" /t REG_BINARY /d "508308fc8b62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "SyncHomePage Protected - It is a violation of Windows Policy to modify. See aka.ms/browserpolicy" /t REG_BINARY /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "IE10RunOncePerInstallCompleted" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "IE10RunOnceCompletionTime" /t REG_BINARY /d "044c900bd762d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "IE10TourShown" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "IE10TourShownTime" /t REG_BINARY /d "044c900bd762d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main\WindowsSearch" /v "Version" /t REG_SZ /d "10.0.19041.844" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main\WindowsSearch" /v "User Favorites Path" /t REG_SZ /d "file:///C:\Users\Administrator\Favorites\\" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main\WindowsSearch" /v "UpgradeTime" /t REG_BINARY /d "044c900bd762d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main\WindowsSearch" /v "ConfiguredScopes" /t REG_DWORD /d "5" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\MINIE" /v "TabBandWidth" /t REG_DWORD /d "500" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\New Windows" /v "PopupMgr" /t REG_SZ /d "yes" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\New Windows" /v "Use Anchor Hover Color" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\New Windows" /v "UseSecBand" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\PageSetup" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Protected - It is a violation of Windows Policy to modify. See aka.ms/browserpolicy" /v "HomepagesUpgradeVersion" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Protected - It is a violation of Windows Policy to modify. See aka.ms/browserpolicy" /v "SearchScopesUpgradeVersion" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Recovery\AdminActive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Recovery\PendingRecovery" /v "AdminActive" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\RepId" /v "PublicId" /t REG_SZ /d "{7757600D-F40F-4609-922B-78C3E15EF461}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes" /v "DefaultScope" /t REG_SZ /d "{0633EE93-D776-472f-A0FF-E1416B8B2E3A}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes" /v "KnownProvidersUpgradeTime" /t REG_BINARY /d "044c900bd762d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes" /v "Version" /t REG_DWORD /d "5" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes" /v "UpgradeTime" /t REG_BINARY /d "044c900bd762d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{0633EE93-D776-472f-A0FF-E1416B8B2E3A}" /v "DisplayName" /t REG_SZ /d "Bing" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{0633EE93-D776-472f-A0FF-E1416B8B2E3A}" /v "FaviconURLFallback" /t REG_SZ /d "http://www.bing.com/favicon.ico" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{0633EE93-D776-472f-A0FF-E1416B8B2E3A}" /v "FaviconPath" /t REG_SZ /d "C:\Users\Administrator\AppData\LocalLow\Microsoft\Internet Explorer\Services\search_{0633EE93-D776-472f-A0FF-E1416B8B2E3A}.ico" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{0633EE93-D776-472f-A0FF-E1416B8B2E3A}" /v "FaviconURL" /t REG_SZ /d "http://www.bing.com/favicon.ico" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{0633EE93-D776-472f-A0FF-E1416B8B2E3A}" /v "URL" /t REG_SZ /d "http://www.bing.com/search?q={searchTerms}&src=IE-SearchBox&FORM=IESR02" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{0633EE93-D776-472f-A0FF-E1416B8B2E3A}" /v "SuggestionsURLFallback" /t REG_SZ /d "http://api.bing.com/qsml.aspx?query={searchTerms}&maxwidth={ie:maxWidth}&rowheight={ie:rowHeight}&sectionHeight={ie:sectionHeight}&FORM=IESS02&market={language}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{0633EE93-D776-472f-A0FF-E1416B8B2E3A}" /v "SuggestionsURL" /t REG_SZ /d "http://api.bing.com/qsml.aspx?query={searchTerms}&maxwidth={ie:maxWidth}&rowheight={ie:rowHeight}&sectionHeight={ie:sectionHeight}&FORM=IESS02&market={language}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{0633EE93-D776-472f-A0FF-E1416B8B2E3A}" /v "NTURL" /t REG_SZ /d "http://www.bing.com/search?q={searchTerms}&src=IE-SearchBox&FORM=IENTSR" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{0633EE93-D776-472f-A0FF-E1416B8B2E3A}" /v "NTTopResultURL" /t REG_SZ /d "http://www.bing.com/search?q={searchTerms}&src=IE-SearchBox&FORM=IENTTR" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{0633EE93-D776-472f-A0FF-E1416B8B2E3A}" /v "NTSuggestionsURL" /t REG_SZ /d "http://api.bing.com/qsml.aspx?query={searchTerms}&market={language}&maxwidth={ie:maxWidth}&rowheight={ie:rowHeight}&sectionHeight={ie:sectionHeight}&FORM=IENTSS" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{0633EE93-D776-472f-A0FF-E1416B8B2E3A}" /v "NTLogoPath" /t REG_SZ /d "C:\Users\Administrator\AppData\LocalLow\Microsoft\Internet Explorer\Services\\" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\SearchScopes\{0633EE93-D776-472f-A0FF-E1416B8B2E3A}" /v "NTLogoURL" /t REG_SZ /d "http://go.microsoft.com/fwlink/?LinkID=403856&language={language}&scale={scalelevel}&contrast={contrast}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Security" /v "Safety Warning Level" /t REG_SZ /d "Query" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Security" /v "Sending_Security" /t REG_SZ /d "Medium" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Security" /v "Viewing_Security" /t REG_SZ /d "Low" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Services" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Settings" /v "Anchor Color" /t REG_SZ /d "0,0,255" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Settings" /v "Anchor Color Visited" /t REG_SZ /d "128,0,128" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Settings" /v "Background Color" /t REG_SZ /d "192,192,192" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Settings" /v "Text Color" /t REG_SZ /d "0,0,0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Settings" /v "Use Anchor Hover Color" /t REG_SZ /d "No" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Setup" /v "UrlHistoryMigrationTime" /t REG_BINARY /d "044c900bd762d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Suggested Sites" /v "LogFileFolder" /t REG_SZ /d "C:\Users\Administrator\AppData\Local\Microsoft\Windows\INetCache\Low" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Suggested Sites" /v "DataStreamEnabledState" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Suggested Sites" /v "MigrationTime" /t REG_BINARY /d "044c900bd762d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\TabbedBrowsing" /v "TabsStickyMode" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\TabbedBrowsing" /v "NTPMigrationVer" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\TabbedBrowsing" /v "NTPFirstRun" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\TabbedBrowsing\NewTabPage" /v "DecayDateQueue" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000003c3bc39b8482064abd0c51587cdec25d00000000020000000000106600000001000020000000836282683dc6da978202c14aadcd7d82fb5300b8ef8175be2d985b52ee153019000000000e80000000020000200000001c11eb8e0b6e2f96d614fcab5d484658d971c29f394cc83ca2cf2d4626f177b5200000004d25dfcc62ee36459d82bcdcbfbd1f43549d1652e572cd3004487f09264fceed400000001626ce6784130b7cc9247c3c3dbdd5f565d2a6dd3c7fa443246ee1ce3cc98caee470a71c736ff1801c9c4a7d940370df77f79b778510269f68e9a5b7873ab2ea" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\TabbedBrowsing\NewTabPage" /v "LastProcessed" /t REG_BINARY /d "d07191545162d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\TabbedBrowsing\NewTabPage" /v "MFV" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000003c3bc39b8482064abd0c51587cdec25d00000000020000000000106600000001000020000000fe5da166d897d6c10c349b908736e81070c1feaff7cbde4983edff87d096728b000000000e80000000020000200000009a0dcc07caea2039ddd0ef9cfc89f957faa23243bbb8931e1b1a8f22578db8f71001000013cd3b3ac74a547a49c6de5df7e3fc06fb8c1a1afdf3be2be65fb4fbd759f4bcb57befa1ce48c0637e68d5b270929fbf5a9fa328902c8ffa5287a3e4c1b5ed9afef934bb4addc6aa0242ee7ba101ca1a9e0b9b7f76cefb494678dee2de9d7c26315a86ad9c01fe9cfc6cd377d00fc3ab8c4e883330a22c78c54aa17ea5fadc2978865e394b4180512de193ec9f9df4f0f0d781f6ae04c1c83f4df308689a1c9bfe81cba55e3858d7e875d8026d9ca3534c1c64970ffe41f608b2702b8dd7ede24de79ff2556b6d0bc65697736abac7fa33769769cdd6679a42647d63f7b2ef9ebef1f2b6ff12fbbd69e33482fe73a94765089d3a7c2caf5da538e13e421bf9c73b3a50f9031a5f18e06132d1750227e140000000ff5a1105418708ec76e09e53c70cc9f116916a3b935f754ab98c20f7200efbad0b09e16d7af7280108b6dae82633e250f215733f6c68f42e9e5dcf4e1b266d6f" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Toolbar" /v "Locked" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Toolbar\ShellBrowser" /v "ITBar7Layout" /t REG_BINARY /d "13000000000000000000000020000000100000000000000001000000010700006a01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Toolbar\WebBrowser" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\TypedURLs" /v "url1" /t REG_SZ /d "http://go.microsoft.com/fwlink/p/?LinkId=255141" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\URLSearchHooks" /v "{CFBFAE00-17A6-11D0-99CB-00C04FD64497}" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\User Preferences" /v "3DB9590C4C4C26C4CCBDD94ECAD790359708C3267B" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000003c3bc39b8482064abd0c51587cdec25d000000000200000000001066000000010000200000009745f247daacffb871f424ee44fd5d1b4c80d73d964a11ecf691f8503384ae05000000000e8000000002000020000000318964514289c67c48331a0d2f9e785b640fad1e0c2ab209678247ca94d6e58c500000000172ed0ce69e1f39f11db5959b1685da65652c9bbd77fe0551c485496162b87f6e536d4b10a8488e0c278cdbfdc7614186928eb5e397fc48ec67129322378a5cb7630f21899ee7c06e71f53d41f2f1cf400000004674e6ccccc98e5dc1b27388aa1da943fce10b757d80b72952b14b0a05f438898afa7c824b277095ff13781f1f3cc93b9a4264db7f59560da448cbd98f8f91ab" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\User Preferences" /v "2BB20B33B4171CDAAB6469225AE6A582ED33D7B488" /t REG_BINARY /d "01000000d08c9ddf0115d1118c7a00c04fc297eb010000003c3bc39b8482064abd0c51587cdec25d000000000200000000001066000000010000200000001ea7532960578e7349291d091b539ef4176c513caf1ac90d84cd9ead2c1ca331000000000e80000000020000200000004996f638879b1dd0d48ed7956202837ee5fad752992ecad178364ee2dec1f696100000004ee5b4386a43a97a2db13d486ef4fd0d400000004e2403f65176f0a590707b9802a5ddc821423b8f444173ac8decdfe9fd24d43b4abfb0c1025e10fd4035ffc086df11a4ba6d119792764c320b316697137f7197" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\VersionManager" /v "FirstCheckForUpdateLowDateTime" /t REG_DWORD /d "117848163" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\VersionManager" /v "FirstCheckForUpdateHighDateTime" /t REG_DWORD /d "30892729" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\Zoom" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Keyboard\Native Media Players\WMP" /v "AppName" /t REG_SZ /d "Windows Media Player" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Keyboard\Native Media Players\WMP" /v "ExePath" /t REG_SZ /d "C:\Program Files\Windows Media Player\wmplayer.exe" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Health" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Player\Settings" /v "Client ID" /t REG_SZ /d "{17C248FE-E0EF-44AF-AA71-E9A3AB41C2C2}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "ObfuscatedSyncPlaylistsPath" /t REG_SZ /d "C:\Users\Administrator\AppData\Local\Microsoft\Media Player\Sync Playlists\en-US\00009B07" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "AcceptedPrivacyStatement" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "AddVideosFromPicturesLibrary" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "AutoAddMusicToLibrary" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "AutoAddVideoToLibrary" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "DeleteRemovesFromComputer" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "DisableLicenseRefresh" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "FirstRun" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "FlushRatingsToFiles" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "LibraryHasBeenRun" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "MetadataRetrieval" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "SilentAcquisition" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "SilentDRMConfiguration" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "DisableMRU" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "UsageTracking" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "SendUserGUID" /t REG_BINARY /d "00" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "AskMeAgain" /t REG_SZ /d "No" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "StartInMediaGuide" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "SnapToVideoV11" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\MobilePC\AdaptableSettings" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\MSF\Registration\Listen" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Multimedia\Audio\DefaultEndpoint" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Narrator\NoRoam" /v "RunningState" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\OneDrive" /v "EnableDownlevelInstallOnBluePlus" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\OneDrive" /v "EnableTHDFFeatures" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Osk" /v "RunningState" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\PeerNet\Event_Config" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Phone\ShellUI\WindowSizing\Microsoft.Windows.Search_cw5n1h2txyewy!CortanaUI" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Phone\ShellUI\WindowSizing\Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Phone\ShellUI\WindowSizing\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Phone\ShellUI\WindowSizing\MicrosoftWindows.Client.CBS_cw5n1h2txyewy!InputApp" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Phone\ShellUI\WindowSizing\windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Remote Assistance" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\ScreenMagnifier" /v "RunningState" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Sensors" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Speech\Preferences\AppCompatDisableDictation" /v "dwm.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Speech\Preferences\AppCompatDisableDictation" /v "tabtip.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Speech\Preferences\AppCompatDisableMSAA" /v "devenv.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Speech\Preferences\AppCompatDisableMSAA" /v "taskmgr.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Speech Virtual" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\SystemCertificates\CA\Certificates" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\SystemCertificates\CA\CRLs" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\SystemCertificates\CA\CTLs" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\SystemCertificates\Disallowed\Certificates" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\SystemCertificates\Disallowed\CRLs" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\SystemCertificates\Disallowed\CTLs" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\SystemCertificates\MY" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\SystemCertificates\Root\CRLs" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\SystemCertificates\Root\CTLs" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\SystemCertificates\Root\ProtectedRoots" /v "Certificates" /t REG_BINARY /d "1800000001000000e0106ec58b62d7010000000018000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\SystemCertificates\SmartCardRoot\Certificates" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\SystemCertificates\SmartCardRoot\CRLs" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\SystemCertificates\SmartCardRoot\CTLs" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\SystemCertificates\trust\Certificates" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\SystemCertificates\trust\CRLs" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\SystemCertificates\trust\CTLs" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\SystemCertificates\TrustedPeople\Certificates" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\SystemCertificates\TrustedPeople\CRLs" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\SystemCertificates\TrustedPeople\CTLs" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\SystemCertificates\TrustedPublisher\Certificates" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\SystemCertificates\TrustedPublisher\CRLs" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\SystemCertificates\TrustedPublisher\CTLs" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\UEV\Agent" /v "UserConsoleVersion" /t REG_SZ /d "10.0.19041.746" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\WAB\WAB4\Wab File Name" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\WcmSvc\Tethering\Roaming" /v "PermissionsSet" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\wfs\DraftsView" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\wfs\InboxView" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\wfs\IncomingView" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\wfs\OutboxView" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\wfs\SentItemsView" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\AssignedAccessConfiguration" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ActivityDataModel" /v "RebuildIndexerVersion" /t REG_DWORD /d "21" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ActivityDataModel\ReaderRevisionInfo" /v "117CBA3D-1BBC-C716-E9D4-F8E7879A88B2" /t REG_MULTI_SZ /d "1㜱　笀 †䐢瑡扡獡䥥獮慴据䥥≤㨠㌠㠲㜰ਬ†∠敓畱湥散•›㌱ⰷ †愢瑣癩瑩卹潴敲摉•›ㄢ㜱䉃㍁ⵄ䈱䍂䌭ㄷⴶ㥅㑄䘭䔸㠷㤷㡁䈸∲ਬ†∠楦瑬牥•›੻†††椢剳慥䙤汩整≲㨠〠ਬ†††漢楲楧䙮汩整䭲祥•›ⰰ ††∠瑳瑡䙥汩整䭲祥•›ⰰ ††∠獵牥捁楴湯瑓瑡䙥汩整≲㨠〠 †੽੽" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ActivityDataModel\Settings" /v "DefaultWebAccountStatus" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\1527c705-839a-4832-9118-54d4Bd6a0c89_cw5n1h2txyewy" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\c5e2524a-ea46-4f67-841f-6a9465d9d515_cw5n1h2txyewy" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\E2A4F912-2574-4A75-9BB0-0D023378592B_cw5n1h2txyewy" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE_cw5n1h2txyewy" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\Microsoft.AccountsControl_cw5n1h2txyewy" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\Microsoft.AsyncTextService_8wekyb3d8bbwe" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\Microsoft.BioEnrollment_cw5n1h2txyewy" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\Microsoft.CredDialogHost_cw5n1h2txyewy" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\Microsoft.ECApp_8wekyb3d8bbwe" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\Microsoft.HEIFImageExtension_8wekyb3d8bbwe" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\Microsoft.LockApp_cw5n1h2txyewy" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\Microsoft.VCLibs.140.00_8wekyb3d8bbwe" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\Microsoft.VP9VideoExtensions_8wekyb3d8bbwe" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\Microsoft.WebpImageExtension_8wekyb3d8bbwe" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\Microsoft.Win32WebViewHost_cw5n1h2txyewy" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\Microsoft.Windows.Apprep.ChxApp_cw5n1h2txyewy" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\Microsoft.Windows.AssignedAccessLockApp_cw5n1h2txyewy" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\Microsoft.Windows.CallingShellApp_cw5n1h2txyewy" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\Microsoft.Windows.CapturePicker_cw5n1h2txyewy" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\Microsoft.Windows.NarratorQuickStart_8wekyb3d8bbwe" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\Microsoft.Windows.OOBENetworkCaptivePortal_cw5n1h2txyewy" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\Microsoft.Windows.OOBENetworkConnectionFlow_cw5n1h2txyewy" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\Microsoft.Windows.ParentalControls_cw5n1h2txyewy" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\Microsoft.Windows.PeopleExperienceHost_cw5n1h2txyewy" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\Microsoft.Windows.PinningConfirmationDialog_cw5n1h2txyewy" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\Microsoft.Windows.Search_cw5n1h2txyewy" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\Microsoft.Windows.SecureAssessmentBrowser_cw5n1h2txyewy" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\Microsoft.Windows.XGpuEjectDialog_cw5n1h2txyewy" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\Microsoft.XboxGameCallableUI_cw5n1h2txyewy" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\MicrosoftWindows.Client.CBS_cw5n1h2txyewy" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\MicrosoftWindows.UndockedDevKit_cw5n1h2txyewy" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\NcsiUwpApp_8wekyb3d8bbwe" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\NVIDIACorp.NVIDIAControlPanel_56jybvy8sckqj" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\RealtekSemiconductorCorp.RealtekAudioControl_dt26b99r8h8gj" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\Windows.CBSPreview_cw5n1h2txyewy" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\windows.immersivecontrolpanel_cw5n1h2txyewy" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\IndexedDB\Windows.PrintDialog_cw5n1h2txyewy" /v "PerPackageIndexedDBEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\SysTray" /v "Services" /t REG_DWORD /d "31" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX6eg8h5sxqq90pv53845wmnbewywdqq5h_.3g2" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXk0g4vb8gvt7b93tg50ybcy892pge6jmt_.3g2" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXmk63adfvvewttqzmezsgagxtcyyr84tx_.3g2" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX6eg8h5sxqq90pv53845wmnbewywdqq5h_.3gp" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXk0g4vb8gvt7b93tg50ybcy892pge6jmt_.3gp" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXmk63adfvvewttqzmezsgagxtcyyr84tx_.3gp" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXk0g4vb8gvt7b93tg50ybcy892pge6jmt_.3gp2" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX6eg8h5sxqq90pv53845wmnbewywdqq5h_.3gpp" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXk0g4vb8gvt7b93tg50ybcy892pge6jmt_.3gpp" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXmk63adfvvewttqzmezsgagxtcyyr84tx_.3gpp" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXmgw6pxxs62rbgfp9petmdyb4fx7rnd4k_.3mf" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXcdh38jxzbcberv50vxg2tg4k84kfnewn_.3mf" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXr0rz9yckydawgnrx5df1t9s57ne60yhn_.3mf" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXvhc4p7vz4b485xfp46hhk3fq3grkdgjg_.3mf" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX9v2an58zgtq78h18jgmp43b5gza6b2jp_.aac" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs_.aac" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs_.ac3" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX9v2an58zgtq78h18jgmp43b5gza6b2jp_.adt" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs_.adt" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX9v2an58zgtq78h18jgmp43b5gza6b2jp_.adts" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs_.adts" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs_.amr" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h_.arw" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "WMP11.AssocFile.ASF_.asf" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXk0g4vb8gvt7b93tg50ybcy892pge6jmt_.asf" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX6eg8h5sxqq90pv53845wmnbewywdqq5h_.avi" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXk0g4vb8gvt7b93tg50ybcy892pge6jmt_.avi" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXmk63adfvvewttqzmezsgagxtcyyr84tx_.avi" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXcdh38jxzbcberv50vxg2tg4k84kfnewn_.bmp" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h_.cr2" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h_.crw" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXcdh38jxzbcberv50vxg2tg4k84kfnewn_.dib" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXmk63adfvvewttqzmezsgagxtcyyr84tx_.divx" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "docxfile_.docx" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs_.ec3" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXvepbp3z66accmsd0x877zbbxjctkpr6t_.epub" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h_.erf" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXmgw6pxxs62rbgfp9petmdyb4fx7rnd4k_.fbx" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXcdh38jxzbcberv50vxg2tg4k84kfnewn_.fbx" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXr0rz9yckydawgnrx5df1t9s57ne60yhn_.fbx" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXvhc4p7vz4b485xfp46hhk3fq3grkdgjg_.fbx" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX9v2an58zgtq78h18jgmp43b5gza6b2jp_.flac" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs_.flac" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXcdh38jxzbcberv50vxg2tg4k84kfnewn_.gif" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXmgw6pxxs62rbgfp9petmdyb4fx7rnd4k_.glb" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXcdh38jxzbcberv50vxg2tg4k84kfnewn_.glb" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXr0rz9yckydawgnrx5df1t9s57ne60yhn_.glb" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXvhc4p7vz4b485xfp46hhk3fq3grkdgjg_.glb" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXmgw6pxxs62rbgfp9petmdyb4fx7rnd4k_.gltf" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXcdh38jxzbcberv50vxg2tg4k84kfnewn_.gltf" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXr0rz9yckydawgnrx5df1t9s57ne60yhn_.gltf" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXvhc4p7vz4b485xfp46hhk3fq3grkdgjg_.gltf" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX4hxtad77fbk3jkkeerkrm0ze94wjf3s9_.htm" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX4hxtad77fbk3jkkeerkrm0ze94wjf3s9_.html" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "icofile_.ico" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "PBrush_.ico" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXcdh38jxzbcberv50vxg2tg4k84kfnewn_.ico" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXzwr976v2e060wada4gabrk1x69h2dbwy_.inf" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXhk4des8gf2xat3wtyzc5q06ny78jhkqx_.ini" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXcdh38jxzbcberv50vxg2tg4k84kfnewn_.jfif" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXcdh38jxzbcberv50vxg2tg4k84kfnewn_.jpe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXcdh38jxzbcberv50vxg2tg4k84kfnewn_.jpeg" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXcdh38jxzbcberv50vxg2tg4k84kfnewn_.jpg" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXfeqk92xmhxtyxytgbhn7tdqk70syjc6v_.jpg" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h_.kdc" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX4ztfk9wxr86nxmzzq47px0nh0e58b8fw_.log" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "WMP11.AssocFile.M2TS_.m2t" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX6eg8h5sxqq90pv53845wmnbewywdqq5h_.m2t" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXk0g4vb8gvt7b93tg50ybcy892pge6jmt_.m2t" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXmk63adfvvewttqzmezsgagxtcyyr84tx_.m2t" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "WMP11.AssocFile.M2TS_.m2ts" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX6eg8h5sxqq90pv53845wmnbewywdqq5h_.m2ts" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXk0g4vb8gvt7b93tg50ybcy892pge6jmt_.m2ts" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXmk63adfvvewttqzmezsgagxtcyyr84tx_.m2ts" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "WMP11.AssocFile.m3u_.m3u" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX9v2an58zgtq78h18jgmp43b5gza6b2jp_.m3u" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs_.m3u" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX5sy1gww9q4g2gt941cdxxd7s07xe5vph_.m4a" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX9v2an58zgtq78h18jgmp43b5gza6b2jp_.m4a" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs_.m4a" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs_.m4r" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX6eg8h5sxqq90pv53845wmnbewywdqq5h_.m4v" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXk0g4vb8gvt7b93tg50ybcy892pge6jmt_.m4v" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXmk63adfvvewttqzmezsgagxtcyyr84tx_.m4v" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs_.mka" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "WMP11.AssocFile.MKV_.mkv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX6eg8h5sxqq90pv53845wmnbewywdqq5h_.mkv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXk0g4vb8gvt7b93tg50ybcy892pge6jmt_.mkv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXmk63adfvvewttqzmezsgagxtcyyr84tx_.mkv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "WMP11.AssocFile.MPEG_.mod" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX6eg8h5sxqq90pv53845wmnbewywdqq5h_.mod" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXmk63adfvvewttqzmezsgagxtcyyr84tx_.mod" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX6eg8h5sxqq90pv53845wmnbewywdqq5h_.mov" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXk0g4vb8gvt7b93tg50ybcy892pge6jmt_.mov" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXmk63adfvvewttqzmezsgagxtcyyr84tx_.mov" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXmk63adfvvewttqzmezsgagxtcyyr84tx_.mp2" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX9v2an58zgtq78h18jgmp43b5gza6b2jp_.mp3" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs_.mp3" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX6eg8h5sxqq90pv53845wmnbewywdqq5h_.mp4" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXk0g4vb8gvt7b93tg50ybcy892pge6jmt_.mp4" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXmk63adfvvewttqzmezsgagxtcyyr84tx_.mp4" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX6eg8h5sxqq90pv53845wmnbewywdqq5h_.mp4v" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXk0g4vb8gvt7b93tg50ybcy892pge6jmt_.mp4v" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXmk63adfvvewttqzmezsgagxtcyyr84tx_.mp4v" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX9v2an58zgtq78h18jgmp43b5gza6b2jp_.mpa" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs_.mpa" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX6eg8h5sxqq90pv53845wmnbewywdqq5h_.mpe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXmk63adfvvewttqzmezsgagxtcyyr84tx_.mpe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX6eg8h5sxqq90pv53845wmnbewywdqq5h_.mpeg" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXmk63adfvvewttqzmezsgagxtcyyr84tx_.mpeg" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX6eg8h5sxqq90pv53845wmnbewywdqq5h_.mpg" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXmk63adfvvewttqzmezsgagxtcyyr84tx_.mpg" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "WMP11.AssocFile.MPEG_.mpv2" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX6eg8h5sxqq90pv53845wmnbewywdqq5h_.mpv2" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXmk63adfvvewttqzmezsgagxtcyyr84tx_.mpv2" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h_.mrw" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX6eg8h5sxqq90pv53845wmnbewywdqq5h_.mts" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXk0g4vb8gvt7b93tg50ybcy892pge6jmt_.mts" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXmk63adfvvewttqzmezsgagxtcyyr84tx_.mts" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h_.nef" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h_.nrw" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXmgw6pxxs62rbgfp9petmdyb4fx7rnd4k_.obj" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXcdh38jxzbcberv50vxg2tg4k84kfnewn_.obj" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXr0rz9yckydawgnrx5df1t9s57ne60yhn_.obj" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXvhc4p7vz4b485xfp46hhk3fq3grkdgjg_.obj" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXd7df65yysmdaz9xc1vjxts4ng22x2n5f_.obj" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "odtfile_.odt" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs_.oga" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs_.ogg" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX6eg8h5sxqq90pv53845wmnbewywdqq5h_.ogm" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX6eg8h5sxqq90pv53845wmnbewywdqq5h_.ogv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX6eg8h5sxqq90pv53845wmnbewywdqq5h_.ogx" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs_.opus" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h_.orf" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723_.pdf" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h_.pef" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXmgw6pxxs62rbgfp9petmdyb4fx7rnd4k_.ply" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXcdh38jxzbcberv50vxg2tg4k84kfnewn_.ply" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXr0rz9yckydawgnrx5df1t9s57ne60yhn_.ply" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXvhc4p7vz4b485xfp46hhk3fq3grkdgjg_.ply" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXcdh38jxzbcberv50vxg2tg4k84kfnewn_.png" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXxf01pj590w7z9mxmyv3nx0a9ewj3e51g_.ps1" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXc9vj55m1n3559gcjff0scsqeket80zp7_.psd1" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX1b0e9ytcwx0wcmvkdey0h6af04t1ta3z_.psm1" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h_.raf" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h_.raw" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "rtffile_.rtf" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h_.rw2" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h_.rwl" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX4ztfk9wxr86nxmzzq47px0nh0e58b8fw_.scp" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h_.sr2" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h_.srw" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXmgw6pxxs62rbgfp9petmdyb4fx7rnd4k_.stl" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXcdh38jxzbcberv50vxg2tg4k84kfnewn_.stl" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXr0rz9yckydawgnrx5df1t9s57ne60yhn_.stl" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXvhc4p7vz4b485xfp46hhk3fq3grkdgjg_.stl" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXde74bfzw9j31bzhcvsrxsyjnhhbq66cs_.svg" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX43hnxtbyyps62jhe9sqpdzxn1790zetc_.tif" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX86746z2101ayy2ygv3g96e4eqdf8r99j_.tif" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXcdh38jxzbcberv50vxg2tg4k84kfnewn_.tif" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX43hnxtbyyps62jhe9sqpdzxn1790zetc_.tiff" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX86746z2101ayy2ygv3g96e4eqdf8r99j_.tiff" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXcdh38jxzbcberv50vxg2tg4k84kfnewn_.tiff" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX6eg8h5sxqq90pv53845wmnbewywdqq5h_.tod" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXmk63adfvvewttqzmezsgagxtcyyr84tx_.tod" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX6eg8h5sxqq90pv53845wmnbewywdqq5h_.ts" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXmk63adfvvewttqzmezsgagxtcyyr84tx_.ts" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX6eg8h5sxqq90pv53845wmnbewywdqq5h_.tts" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXmk63adfvvewttqzmezsgagxtcyyr84tx_.tts" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX4ztfk9wxr86nxmzzq47px0nh0e58b8fw_.txt" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "vcard_wab_auto_file_.vcf" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX9v2an58zgtq78h18jgmp43b5gza6b2jp_.wav" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs_.wav" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX6eg8h5sxqq90pv53845wmnbewywdqq5h_.webm" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX6eg8h5sxqq90pv53845wmnbewywdqq5h_.wm" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXk0g4vb8gvt7b93tg50ybcy892pge6jmt_.wm" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXmk63adfvvewttqzmezsgagxtcyyr84tx_.wm" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX9v2an58zgtq78h18jgmp43b5gza6b2jp_.wma" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs_.wma" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX6eg8h5sxqq90pv53845wmnbewywdqq5h_.wmv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXk0g4vb8gvt7b93tg50ybcy892pge6jmt_.wmv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXmk63adfvvewttqzmezsgagxtcyyr84tx_.wmv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX9v2an58zgtq78h18jgmp43b5gza6b2jp_.wpl" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs_.wpl" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX4ztfk9wxr86nxmzzq47px0nh0e58b8fw_.wtx" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXcc58vyzkbjbs4ky0mxrmxf8278rk9b3t_.xml" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX6eg8h5sxqq90pv53845wmnbewywdqq5h_.xvid" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXmk63adfvvewttqzmezsgagxtcyyr84tx_.xvid" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs_.zpl" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX9v2an58zgtq78h18jgmp43b5gza6b2jp_.zpl" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXtggqqtcfspt6ks3fjzyfppwc05yxwtwy_mswindowsmusic" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX6w6n4f8xch1s3vzwf3af6bfe88qhxbza_mswindowsvideo" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX2jm25qtmp2qxstv333wv5mne3k5bf4bm_.bmp" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX2jm25qtmp2qxstv333wv5mne3k5bf4bm_.dib" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX2jm25qtmp2qxstv333wv5mne3k5bf4bm_.gif" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX2jm25qtmp2qxstv333wv5mne3k5bf4bm_.ico" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX2jm25qtmp2qxstv333wv5mne3k5bf4bm_.jfif" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX2jm25qtmp2qxstv333wv5mne3k5bf4bm_.jpe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX2jm25qtmp2qxstv333wv5mne3k5bf4bm_.jpeg" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX2jm25qtmp2qxstv333wv5mne3k5bf4bm_.jpg" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX2jm25qtmp2qxstv333wv5mne3k5bf4bm_.png" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX2jm25qtmp2qxstv333wv5mne3k5bf4bm_.tiff" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX2jm25qtmp2qxstv333wv5mne3k5bf4bm_.tif" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX2jm25qtmp2qxstv333wv5mne3k5bf4bm_.arw" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX2jm25qtmp2qxstv333wv5mne3k5bf4bm_.cr2" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX2jm25qtmp2qxstv333wv5mne3k5bf4bm_.crw" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX2jm25qtmp2qxstv333wv5mne3k5bf4bm_.erf" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX2jm25qtmp2qxstv333wv5mne3k5bf4bm_.kdc" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX2jm25qtmp2qxstv333wv5mne3k5bf4bm_.mrw" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX2jm25qtmp2qxstv333wv5mne3k5bf4bm_.nef" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX2jm25qtmp2qxstv333wv5mne3k5bf4bm_.nrw" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX2jm25qtmp2qxstv333wv5mne3k5bf4bm_.orf" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX2jm25qtmp2qxstv333wv5mne3k5bf4bm_.pef" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX2jm25qtmp2qxstv333wv5mne3k5bf4bm_.raw" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX2jm25qtmp2qxstv333wv5mne3k5bf4bm_.rw2" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX2jm25qtmp2qxstv333wv5mne3k5bf4bm_.rwl" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX2jm25qtmp2qxstv333wv5mne3k5bf4bm_.sr2" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX2jm25qtmp2qxstv333wv5mne3k5bf4bm_.srw" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX2jm25qtmp2qxstv333wv5mne3k5bf4bm_.jxr" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX2jm25qtmp2qxstv333wv5mne3k5bf4bm_.wdp" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "Windows.Sandbox_.wsb" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX2jm25qtmp2qxstv333wv5mne3k5bf4bm_.dng" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXq0fevzme2pys62n3e0fbqa7peapykr8v_http" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX90nv6nhay5n6a98fnetv7tpk64pp35es_https" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX7rm9drdg8sk7vqndwj3sdjw11x96jc0y_microsoft-edge" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppX3xxs313wwkfjhythsb8q46xdsq8d2cvv_microsoft-edge-holographic" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "AppXdn5b0j699ka5fqvrr3pgjad0evqarm6d_ms-xbl-3d8b930f" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "Paint.Picture_.bmp" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "PhotoViewer.FileAssoc.Tiff_.bmp" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "CABFolder_.cab" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "chm.file_.chm" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "Applications\Notepad.exe_.css" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "Applications\WordPad.exe_.css" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "Applications\Notepad.exe_.csv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "Applications\WordPad.exe_.csv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "Paint.Picture_.dib" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "PhotoViewer.FileAssoc.Tiff_.dib" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "giffile_.gif" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "PBrush_.gif" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "PhotoViewer.FileAssoc.Tiff_.gif" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "inffile_.inf" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "inifile_.ini" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "Applications\WordPad.exe_.ini" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "Windows.IsoFile_.iso" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "PBrush_.jfif" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "PhotoViewer.FileAssoc.Tiff_.jfif" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "PBrush_.jpe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "PhotoViewer.FileAssoc.Tiff_.jpe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "PBrush_.jpeg" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "PhotoViewer.FileAssoc.Tiff_.jpeg" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "PBrush_.jpg" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "PhotoViewer.FileAssoc.Tiff_.jpg" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "JSFile_.js" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "wdpfile_.jxr" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "PhotoViewer.FileAssoc.Tiff_.jxr" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "txtfile_.log" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "MSInfoFile_.nfo" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "PBrush_.png" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "PhotoViewer.FileAssoc.Tiff_.png" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "Microsoft.PowerShellScript.1_.ps1" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "Microsoft.PowerShellData.1_.psd1" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "Microsoft.PowerShellModule.1_.psm1" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "regfile_.reg" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "txtfile_.scp" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "TIFImage.Document_.tif" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "PBrush_.tif" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "TIFImage.Document_.tiff" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "PBrush_.tiff" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "ttffile_.ttf" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "txtfile_.txt" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "textfile_.txt" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "wdpfile_.wdp" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "PBrush_.webp" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "txtfile_.wtx" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "xmlfile_.xml" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "Applications\Notepad.exe_.xml" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "Applications\WordPad.exe_.xml" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "CompressedFolder_.zip" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "IE.HTTP_http" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "IE.HTTPS_https" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "WMP11.AssocFile.3G2_.3g2" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "WMP11.AssocFile.3GP_.3gp" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "WMP11.AssocFile.3G2_.3gp2" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "WMP11.AssocFile.3GP_.3gpp" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "WMP11.AssocFile.ADTS_.aac" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "WMP11.AssocFile.ADTS_.adt" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "WMP11.AssocFile.ADTS_.adts" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "WMP11.AssocFile.AVI_.avi" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "WMP11.AssocFile.FLAC_.flac" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "htmlfile_.htm" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "Applications\notepad.exe_.htm" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "htmlfile_.html" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "WMP11.AssocFile.M4A_.m4a" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "WMP11.AssocFile.MP4_.m4v" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "WMP11.AssocFile.MOV_.mov" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "WMP11.AssocFile.MP3_.MP2" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "WMP11.AssocFile.MP3_.mp3" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "WMP11.AssocFile.MP4_.mp4" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "WMP11.AssocFile.MP4_.mp4v" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "WMP11.AssocFile.MPEG_.mpa" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "WMP11.AssocFile.MPEG_.MPE" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "WMP11.AssocFile.MPEG_.mpeg" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "WMP11.AssocFile.MPEG_.mpg" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "WMP11.AssocFile.M2TS_.mts" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "WMP11.AssocFile.TTS_.TS" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "WMP11.AssocFile.TTS_.TTS" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "InternetShortcut_.url" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "WMP11.AssocFile.WAV_.wav" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "Microsoft.Website_.website" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "WMP11.AssocFile.ASF_.wm" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "WMP11.AssocFile.WMA_.wma" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "WMP11.AssocFile.WMV_.wmv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "WMP11.AssocFile.WPL_.WPL" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "desktopthemepackfile_.deskthemepack" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "VBSFile_.vbs" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "FirefoxURL-308046B0AF4A39CB_http" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "FirefoxURL-308046B0AF4A39CB_https" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "FirefoxHTML-308046B0AF4A39CB_.htm" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "FirefoxHTML-308046B0AF4A39CB_.html" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "Msi.Package_.msi" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "cplfile_.cpl" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "ms-settings_ms-settings" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-1255970798-2717750985-493741290-1721212560-3530798636-1829112236-3118580706\App.AppX2dpzn89f97jxafp1y36xe6wxhgmg4f2w.mca" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-1255970798-2717750985-493741290-1721212560-3530798636-1829112236-3118580706\App.AppX2dpzn89f97jxafp1y36xe6wxhgmg4f2w.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.Apprep.ChxApp_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-1255970798-2717750985-493741290-1721212560-3530798636-1829112236-3118580706\App.AppXpr0cqn9hyh17cda0cgksrex1dxvzkb2p.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-1255970798-2717750985-493741290-1721212560-3530798636-1829112236-3118580706\App.AppXpr0cqn9hyh17cda0cgksrex1dxvzkb2p.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.Apprep.ChxApp_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-1310292540-1029022339-4008023048-2190398717-53961996-4257829345-603366646\DPI.PerMonitorAware.AppXx61dd75z8d6k9psy6v8fvjyhx5rdj4sa.mca" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-1310292540-1029022339-4008023048-2190398717-53961996-4257829345-603366646\DPI.PerMonitorAware.AppXx61dd75z8d6k9psy6v8fvjyhx5rdj4sa.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Win32WebViewHost_cw5n1h2txyewy!DPI.PerMonitorAware" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-1310292540-1029022339-4008023048-2190398717-53961996-4257829345-603366646\DPI.PerMonitorAware.AppXzcbtbn40cg9w591ak7v7s31jmnrb2dtb.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-1310292540-1029022339-4008023048-2190398717-53961996-4257829345-603366646\DPI.PerMonitorAware.AppXzcbtbn40cg9w591ak7v7s31jmnrb2dtb.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Win32WebViewHost_cw5n1h2txyewy!DPI.PerMonitorAware" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-1310292540-1029022339-4008023048-2190398717-53961996-4257829345-603366646\DPI.SystemAware.AppX64ebpmrryzntbexxxw7yf7wg0ktmstk9.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-1310292540-1029022339-4008023048-2190398717-53961996-4257829345-603366646\DPI.SystemAware.AppX64ebpmrryzntbexxxw7yf7wg0ktmstk9.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Win32WebViewHost_cw5n1h2txyewy!DPI.SystemAware" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-1310292540-1029022339-4008023048-2190398717-53961996-4257829345-603366646\DPI.SystemAware.AppXbkxyyah4yxs5bbvr8mm9jakm6th16xgt.mca" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-1310292540-1029022339-4008023048-2190398717-53961996-4257829345-603366646\DPI.SystemAware.AppXbkxyyah4yxs5bbvr8mm9jakm6th16xgt.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Win32WebViewHost_cw5n1h2txyewy!DPI.SystemAware" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-1310292540-1029022339-4008023048-2190398717-53961996-4257829345-603366646\DPI.Unaware.AppXjfk1mgekja4enqszpv8bcvpeea6c4fee.mca" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-1310292540-1029022339-4008023048-2190398717-53961996-4257829345-603366646\DPI.Unaware.AppXjfk1mgekja4enqszpv8bcvpeea6c4fee.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Win32WebViewHost_cw5n1h2txyewy!DPI.Unaware" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-1310292540-1029022339-4008023048-2190398717-53961996-4257829345-603366646\DPI.Unaware.AppXnx8qefgavf26bggx97rh01nz1wf27jbr.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-1310292540-1029022339-4008023048-2190398717-53961996-4257829345-603366646\DPI.Unaware.AppXnx8qefgavf26bggx97rh01nz1wf27jbr.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Win32WebViewHost_cw5n1h2txyewy!DPI.Unaware" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-138780814-3997110584-2874353029-2041838810-3659441231-3169655024-3643974355\App.AppX5etbqw91j08snachsz8b8qw3h740sx6t.mca" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-138780814-3997110584-2874353029-2041838810-3659441231-3169655024-3643974355\App.AppX5etbqw91j08snachsz8b8qw3h740sx6t.mca" /v "AppUserModelId" /t REG_SZ /d "NcsiUwpApp_8wekyb3d8bbwe!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-138780814-3997110584-2874353029-2041838810-3659441231-3169655024-3643974355\App.AppXjmzeb84qew8cqvrtd68fh32hdqxycf7a.mca" /v "Capabilities" /t REG_DWORD /d "262148" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-138780814-3997110584-2874353029-2041838810-3659441231-3169655024-3643974355\App.AppXjmzeb84qew8cqvrtd68fh32hdqxycf7a.mca" /v "AppUserModelId" /t REG_SZ /d "NcsiUwpApp_8wekyb3d8bbwe!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-138780814-3997110584-2874353029-2041838810-3659441231-3169655024-3643974355\App.AppXqrs5nj32f8rqzvfjkch3vd45v4p8syw2.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-138780814-3997110584-2874353029-2041838810-3659441231-3169655024-3643974355\App.AppXqrs5nj32f8rqzvfjkch3vd45v4p8syw2.mca" /v "AppUserModelId" /t REG_SZ /d "NcsiUwpApp_8wekyb3d8bbwe!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-138780814-3997110584-2874353029-2041838810-3659441231-3169655024-3643974355\App.AppXw175g9nmx2zykh9fyt6xjc0xf8vmj1w6.mca" /v "Capabilities" /t REG_DWORD /d "262156" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-138780814-3997110584-2874353029-2041838810-3659441231-3169655024-3643974355\App.AppXw175g9nmx2zykh9fyt6xjc0xf8vmj1w6.mca" /v "AppUserModelId" /t REG_SZ /d "NcsiUwpApp_8wekyb3d8bbwe!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-1443768658-4142614663-2184295616-261691820-2296379425-3814639016-258098527\App.AppX00mtp953crf7493tv7fsdmgswkfbwxa0.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-1443768658-4142614663-2184295616-261691820-2296379425-3814639016-258098527\App.AppX00mtp953crf7493tv7fsdmgswkfbwxa0.mca" /v "AppUserModelId" /t REG_SZ /d "F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-1443768658-4142614663-2184295616-261691820-2296379425-3814639016-258098527\App.AppXm49et8kcqgs940g99tfmc3pq0mvkx6yb.mca" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-1443768658-4142614663-2184295616-261691820-2296379425-3814639016-258098527\App.AppXm49et8kcqgs940g99tfmc3pq0mvkx6yb.mca" /v "AppUserModelId" /t REG_SZ /d "F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-1484987186-1222498055-1895867193-3865138943-3428356477-682207028-3900627692\Microsoft.Windows.CBSPreview.AppXd56ebff74hb8k26acaz7bnawb3canxt5.mca" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-1484987186-1222498055-1895867193-3865138943-3428356477-682207028-3900627692\Microsoft.Windows.CBSPreview.AppXd56ebff74hb8k26acaz7bnawb3canxt5.mca" /v "AppUserModelId" /t REG_SZ /d "Windows.CBSPreview_cw5n1h2txyewy!Microsoft.Windows.CBSPreview" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-1484987186-1222498055-1895867193-3865138943-3428356477-682207028-3900627692\Microsoft.Windows.CBSPreview.AppXphj0kxfenxrfh0jbmz9fpemzwe6k8gn3.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-1484987186-1222498055-1895867193-3865138943-3428356477-682207028-3900627692\Microsoft.Windows.CBSPreview.AppXphj0kxfenxrfh0jbmz9fpemzwe6k8gn3.mca" /v "AppUserModelId" /t REG_SZ /d "Windows.CBSPreview_cw5n1h2txyewy!Microsoft.Windows.CBSPreview" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-155514346-2573954481-755741238-1654018636-1233331829-3075935687-2861478708\App.AppX0kpnt2cmwhnj6p1s9h9fc5cmcm9tydy2.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-155514346-2573954481-755741238-1654018636-1233331829-3075935687-2861478708\App.AppX0kpnt2cmwhnj6p1s9h9fc5cmcm9tydy2.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-155514346-2573954481-755741238-1654018636-1233331829-3075935687-2861478708\App.AppXgxgm8gs8b9vsjsd9gvhmnf95vcbc9q6e.mca" /v "Capabilities" /t REG_DWORD /d "12" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-155514346-2573954481-755741238-1654018636-1233331829-3075935687-2861478708\App.AppXgxgm8gs8b9vsjsd9gvhmnf95vcbc9q6e.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-155514346-2573954481-755741238-1654018636-1233331829-3075935687-2861478708\App.AppXqjpwwnvk2vq1mkj9z67cgpg823dk9wpe.mca" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-155514346-2573954481-755741238-1654018636-1233331829-3075935687-2861478708\App.AppXqjpwwnvk2vq1mkj9z67cgpg823dk9wpe.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-155514346-2573954481-755741238-1654018636-1233331829-3075935687-2861478708\App.AppXv10hny8ma6f03y0jtdfdejxzfevy2pkd.mca" /v "Capabilities" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-155514346-2573954481-755741238-1654018636-1233331829-3075935687-2861478708\App.AppXv10hny8ma6f03y0jtdfdejxzfevy2pkd.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-1910091885-1573563583-1104941280-2418270861-3411158377-2822700936-2990310272\App.AppX4ncqz34bbtt07eqzhagpn4c10ehepw0a.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-1910091885-1573563583-1104941280-2418270861-3411158377-2822700936-2990310272\App.AppX4ncqz34bbtt07eqzhagpn4c10ehepw0a.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-1910091885-1573563583-1104941280-2418270861-3411158377-2822700936-2990310272\App.AppXk4mkt6sb5zpexjgjxt2wtr7fczahhtxh.mca" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-1910091885-1573563583-1104941280-2418270861-3411158377-2822700936-2990310272\App.AppXk4mkt6sb5zpexjgjxt2wtr7fczahhtxh.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-1912509539-3368118754-2471371924-3037708167-1407372224-1099830378-371392376\Microsoft.Windows.AppResolverUX.AppXns49mzrk3h735db2qmrebqa2x6zddsxm.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-1912509539-3368118754-2471371924-3037708167-1407372224-1099830378-371392376\Microsoft.Windows.AppResolverUX.AppXns49mzrk3h735db2qmrebqa2x6zddsxm.mca" /v "AppUserModelId" /t REG_SZ /d "E2A4F912-2574-4A75-9BB0-0D023378592B_cw5n1h2txyewy!Microsoft.Windows.AppResolverUX" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-1912509539-3368118754-2471371924-3037708167-1407372224-1099830378-371392376\Microsoft.Windows.AppResolverUX.AppXv006bebexv4ndcc70sn6z1yykwfsx9kj.mca" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-1912509539-3368118754-2471371924-3037708167-1407372224-1099830378-371392376\Microsoft.Windows.AppResolverUX.AppXv006bebexv4ndcc70sn6z1yykwfsx9kj.mca" /v "AppUserModelId" /t REG_SZ /d "E2A4F912-2574-4A75-9BB0-0D023378592B_cw5n1h2txyewy!Microsoft.Windows.AppResolverUX" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-19479607-1015771884-3827151630-3301822711-2267158487-4079414233-1230461222\App.AppXa2a0fe7wbv0nk2855y3jj4t0nd7m2a8t.mca" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-19479607-1015771884-3827151630-3301822711-2267158487-4079414233-1230461222\App.AppXa2a0fe7wbv0nk2855y3jj4t0nd7m2a8t.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.BioEnrollment_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-19479607-1015771884-3827151630-3301822711-2267158487-4079414233-1230461222\App.AppXxjsg0xv0s4ngp3th9n2c7a5aawjvhv4t.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-19479607-1015771884-3827151630-3301822711-2267158487-4079414233-1230461222\App.AppXxjsg0xv0s4ngp3th9n2c7a5aawjvhv4t.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.BioEnrollment_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-2181377398-65118716-3454236486-3173511759-2711617951-3120918280-1642988593\Microsoft.Windows.CallingShellApp.AppX2f2yw8gwg05t6jv24vx7x28m8n3sgnwb.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-2181377398-65118716-3454236486-3173511759-2711617951-3120918280-1642988593\Microsoft.Windows.CallingShellApp.AppX2f2yw8gwg05t6jv24vx7x28m8n3sgnwb.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.CallingShellApp_cw5n1h2txyewy!Microsoft.Windows.CallingShellApp" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-2181377398-65118716-3454236486-3173511759-2711617951-3120918280-1642988593\Microsoft.Windows.CallingShellApp.AppXpa7ran8mvre3kcqa90hq67czz8296h4s.mca" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-2181377398-65118716-3454236486-3173511759-2711617951-3120918280-1642988593\Microsoft.Windows.CallingShellApp.AppXpa7ran8mvre3kcqa90hq67czz8296h4s.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.CallingShellApp_cw5n1h2txyewy!Microsoft.Windows.CallingShellApp" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-2376884767-3641813526-1736181949-1293975252-228260496-2789807194-3363476418\microsoft.windows.immersivecontrolpanel.AppX21vkvh811r5jcd4wena93d7ssr5fh769.mca" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-2376884767-3641813526-1736181949-1293975252-228260496-2789807194-3363476418\microsoft.windows.immersivecontrolpanel.AppX21vkvh811r5jcd4wena93d7ssr5fh769.mca" /v "AppUserModelId" /t REG_SZ /d "windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-2376884767-3641813526-1736181949-1293975252-228260496-2789807194-3363476418\microsoft.windows.immersivecontrolpanel.AppXkvcc5604paztw62ak4eesbbqcbsh1c4v.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-2376884767-3641813526-1736181949-1293975252-228260496-2789807194-3363476418\microsoft.windows.immersivecontrolpanel.AppXkvcc5604paztw62ak4eesbbqcbsh1c4v.mca" /v "AppUserModelId" /t REG_SZ /d "windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-2434737943-167758768-3180539153-984336765-1107280622-3591121930-2677285773\App.AppXntnmv70n83rg2dwd1f3b1jfjg1szddck.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-2434737943-167758768-3180539153-984336765-1107280622-3591121930-2677285773\App.AppXntnmv70n83rg2dwd1f3b1jfjg1szddck.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-2434737943-167758768-3180539153-984336765-1107280622-3591121930-2677285773\App.AppXw912w7a1bx0h9jc59hc3wbmx68td2n2v.wwa" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-2434737943-167758768-3180539153-984336765-1107280622-3591121930-2677285773\App.AppXw912w7a1bx0h9jc59hc3wbmx68td2n2v.wwa" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-2652307757-2298579837-578647688-3387406430-2756081349-614783772-2601174805\App.AppX4tatq20fa0sebpjex1bks2crcsaw2j12.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-2652307757-2298579837-578647688-3387406430-2756081349-614783772-2601174805\App.AppX4tatq20fa0sebpjex1bks2crcsaw2j12.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.PinningConfirmationDialog_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-2652307757-2298579837-578647688-3387406430-2756081349-614783772-2601174805\App.AppXx1kd012aaxraxkw1drzz6h3rcwfsqb5m.mca" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-2652307757-2298579837-578647688-3387406430-2756081349-614783772-2601174805\App.AppXx1kd012aaxraxkw1drzz6h3rcwfsqb5m.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.PinningConfirmationDialog_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-2705751783-1496458293-2835996032-3143071717-1071345625-677459937-2760321769\App.AppXkv6gpr5wnhe0ccmvxfqm9rwwkpnckm2z.mca" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-2705751783-1496458293-2835996032-3143071717-1071345625-677459937-2760321769\App.AppXkv6gpr5wnhe0ccmvxfqm9rwwkpnckm2z.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.AssignedAccessLockApp_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-2705751783-1496458293-2835996032-3143071717-1071345625-677459937-2760321769\App.AppXs0kxhbr2mxxp8mqszmbhnhkjbawyapdr.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-2705751783-1496458293-2835996032-3143071717-1071345625-677459937-2760321769\App.AppXs0kxhbr2mxxp8mqszmbhnhkjbawyapdr.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.AssignedAccessLockApp_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-2758101530-1321080646-1475665648-4066602542-2880396197-3643791541-2654759312\WindowsDefaultLockScreen.AppXs5nhtq2qewbpnhvekb05kqpmg96qtf7s.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-2758101530-1321080646-1475665648-4066602542-2880396197-3643791541-2654759312\WindowsDefaultLockScreen.AppXs5nhtq2qewbpnhvekb05kqpmg96qtf7s.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.LockApp_cw5n1h2txyewy!WindowsDefaultLockScreen" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-2758101530-1321080646-1475665648-4066602542-2880396197-3643791541-2654759312\WindowsDefaultLockScreen.AppXw289frmm5h7en9xhcas005wk93ssm403.mca" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-2758101530-1321080646-1475665648-4066602542-2880396197-3643791541-2654759312\WindowsDefaultLockScreen.AppXw289frmm5h7en9xhcas005wk93ssm403.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.LockApp_cw5n1h2txyewy!WindowsDefaultLockScreen" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-283421221-3183566570-1718213290-751554359-3541592344-2312209569-3374928651\Global.IrisService.AppX4v6gb1ky7wec6aebg8dxpset8xwhzm0h.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-283421221-3183566570-1718213290-751554359-3541592344-2312209569-3374928651\Global.IrisService.AppX4v6gb1ky7wec6aebg8dxpset8xwhzm0h.mca" /v "AppUserModelId" /t REG_SZ /d "MicrosoftWindows.Client.CBS_cw5n1h2txyewy!Global.IrisService" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-283421221-3183566570-1718213290-751554359-3541592344-2312209569-3374928651\Global.IrisService.AppXnpw2wspmxg49yvh26y9jrqkskbz88tjf.wwa" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-283421221-3183566570-1718213290-751554359-3541592344-2312209569-3374928651\Global.IrisService.AppXnpw2wspmxg49yvh26y9jrqkskbz88tjf.wwa" /v "AppUserModelId" /t REG_SZ /d "MicrosoftWindows.Client.CBS_cw5n1h2txyewy!Global.IrisService" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-283421221-3183566570-1718213290-751554359-3541592344-2312209569-3374928651\InputApp.AppX79xxrny661mfvj91a39km0wv3mwvsthj.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-283421221-3183566570-1718213290-751554359-3541592344-2312209569-3374928651\InputApp.AppX79xxrny661mfvj91a39km0wv3mwvsthj.mca" /v "AppUserModelId" /t REG_SZ /d "MicrosoftWindows.Client.CBS_cw5n1h2txyewy!InputApp" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-283421221-3183566570-1718213290-751554359-3541592344-2312209569-3374928651\InputApp.AppXn13vw841fjq94wg9r9zev7nkh4fzvrqr.mca" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-283421221-3183566570-1718213290-751554359-3541592344-2312209569-3374928651\InputApp.AppXn13vw841fjq94wg9r9zev7nkh4fzvrqr.mca" /v "AppUserModelId" /t REG_SZ /d "MicrosoftWindows.Client.CBS_cw5n1h2txyewy!InputApp" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-283421221-3183566570-1718213290-751554359-3541592344-2312209569-3374928651\PackageMetadata.AppX9sfmnfjzbg8e1hgxcm5b9233zzz08j61.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-283421221-3183566570-1718213290-751554359-3541592344-2312209569-3374928651\PackageMetadata.AppX9sfmnfjzbg8e1hgxcm5b9233zzz08j61.mca" /v "AppUserModelId" /t REG_SZ /d "MicrosoftWindows.Client.CBS_cw5n1h2txyewy!PackageMetadata" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-283421221-3183566570-1718213290-751554359-3541592344-2312209569-3374928651\PackageMetadata.AppXpr7jb2xtzjkv5mcc6kzwmmf4wkjfmmv7.wwa" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-283421221-3183566570-1718213290-751554359-3541592344-2312209569-3374928651\PackageMetadata.AppXpr7jb2xtzjkv5mcc6kzwmmf4wkjfmmv7.wwa" /v "AppUserModelId" /t REG_SZ /d "MicrosoftWindows.Client.CBS_cw5n1h2txyewy!PackageMetadata" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-283421221-3183566570-1718213290-751554359-3541592344-2312209569-3374928651\ScreenClipping.AppX9pewgz8gnv4rcfgpmp3ch2dy214hte2x.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-283421221-3183566570-1718213290-751554359-3541592344-2312209569-3374928651\ScreenClipping.AppX9pewgz8gnv4rcfgpmp3ch2dy214hte2x.mca" /v "AppUserModelId" /t REG_SZ /d "MicrosoftWindows.Client.CBS_cw5n1h2txyewy!ScreenClipping" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-283421221-3183566570-1718213290-751554359-3541592344-2312209569-3374928651\ScreenClipping.AppXp66xxq8fxzdtp7cpmkjkg83zqxxcnvz4.mca" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-283421221-3183566570-1718213290-751554359-3541592344-2312209569-3374928651\ScreenClipping.AppXp66xxq8fxzdtp7cpmkjkg83zqxxcnvz4.mca" /v "AppUserModelId" /t REG_SZ /d "MicrosoftWindows.Client.CBS_cw5n1h2txyewy!ScreenClipping" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-284907560-3695622717-2124867970-90980536-1928201052-1028515541-1033863524\App.AppX8nx5ctc7a2rymhhqecncj22ggcppjjv9.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-284907560-3695622717-2124867970-90980536-1928201052-1028515541-1033863524\App.AppX8nx5ctc7a2rymhhqecncj22ggcppjjv9.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.AsyncTextService_8wekyb3d8bbwe!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-284907560-3695622717-2124867970-90980536-1928201052-1028515541-1033863524\App.AppXp4wpase8zw5nnymbgr8d5yakzewpv9jj.mca" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-284907560-3695622717-2124867970-90980536-1928201052-1028515541-1033863524\App.AppXp4wpase8zw5nnymbgr8d5yakzewpv9jj.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.AsyncTextService_8wekyb3d8bbwe!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-2898358160-2674498462-884353026-2121724658-4041462237-504707911-3813979657\App.AppX5yrvmcr5cq9pzc0jry5b7qx8t9wx61dy.mca" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-2898358160-2674498462-884353026-2121724658-4041462237-504707911-3813979657\App.AppX5yrvmcr5cq9pzc0jry5b7qx8t9wx61dy.mca" /v "AppUserModelId" /t REG_SZ /d "RealtekSemiconductorCorp.RealtekAudioControl_dt26b99r8h8gj!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-2898358160-2674498462-884353026-2121724658-4041462237-504707911-3813979657\App.AppXd7brh4pjcv9dd7sva14e72d13nr5ca99.mca" /v "Capabilities" /t REG_DWORD /d "262144" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-2898358160-2674498462-884353026-2121724658-4041462237-504707911-3813979657\App.AppXd7brh4pjcv9dd7sva14e72d13nr5ca99.mca" /v "AppUserModelId" /t REG_SZ /d "RealtekSemiconductorCorp.RealtekAudioControl_dt26b99r8h8gj!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-2898358160-2674498462-884353026-2121724658-4041462237-504707911-3813979657\App.AppXmwfy586yd0znz6wq1gca6bg62qngmw36.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-2898358160-2674498462-884353026-2121724658-4041462237-504707911-3813979657\App.AppXmwfy586yd0znz6wq1gca6bg62qngmw36.mca" /v "AppUserModelId" /t REG_SZ /d "RealtekSemiconductorCorp.RealtekAudioControl_dt26b99r8h8gj!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3072599432-1607568789-957273504-856596282-71567818-1546726304-1084662928\App.AppXae7ns4wrcwqfrezfq8vbxt6js06chync.mca" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3072599432-1607568789-957273504-856596282-71567818-1546726304-1084662928\App.AppXae7ns4wrcwqfrezfq8vbxt6js06chync.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.ParentalControls_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3072599432-1607568789-957273504-856596282-71567818-1546726304-1084662928\App.AppXvmpg6dcwprmasbfvsg72464kc4dn6q18.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3072599432-1607568789-957273504-856596282-71567818-1546726304-1084662928\App.AppXvmpg6dcwprmasbfvsg72464kc4dn6q18.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.ParentalControls_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3110756066-2507771734-389907848-353554127-1230786711-3973453966-120447785\Microsoft.Windows.FilePicker.AppXgjtm720dsgjynxxnpt2sapy700ec5y9t.mca" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3110756066-2507771734-389907848-353554127-1230786711-3973453966-120447785\Microsoft.Windows.FilePicker.AppXgjtm720dsgjynxxnpt2sapy700ec5y9t.mca" /v "AppUserModelId" /t REG_SZ /d "1527c705-839a-4832-9118-54d4Bd6a0c89_cw5n1h2txyewy!Microsoft.Windows.FilePicker" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3110756066-2507771734-389907848-353554127-1230786711-3973453966-120447785\Microsoft.Windows.FilePicker.AppXpxjkswhvgr4kesbr9ja5cwvq9p7snv17.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3110756066-2507771734-389907848-353554127-1230786711-3973453966-120447785\Microsoft.Windows.FilePicker.AppXpxjkswhvgr4kesbr9ja5cwvq9p7snv17.mca" /v "AppUserModelId" /t REG_SZ /d "1527c705-839a-4832-9118-54d4Bd6a0c89_cw5n1h2txyewy!Microsoft.Windows.FilePicker" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3119458392-1009845475-4083330090-3659807469-4003170139-1239840055-303833190\App.AppXa2hm0xhd6608a8x0hsrtnfknxd9w462b.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3119458392-1009845475-4083330090-3659807469-4003170139-1239840055-303833190\App.AppXa2hm0xhd6608a8x0hsrtnfknxd9w462b.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.OOBENetworkCaptivePortal_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3119458392-1009845475-4083330090-3659807469-4003170139-1239840055-303833190\App.AppXm1h5fnqe5s7vr84qvt82w4nj04jz56qj.mca" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3119458392-1009845475-4083330090-3659807469-4003170139-1239840055-303833190\App.AppXm1h5fnqe5s7vr84qvt82w4nj04jz56qj.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.OOBENetworkCaptivePortal_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3127391486-654165588-1135944943-943820645-244210695-3344878592-833444881\Microsoft.Windows.XGpuEjectDialog.AppX5nqr6m04dhsrz9223hm7xzwdqqxcmxqv.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3127391486-654165588-1135944943-943820645-244210695-3344878592-833444881\Microsoft.Windows.XGpuEjectDialog.AppX5nqr6m04dhsrz9223hm7xzwdqqxcmxqv.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.XGpuEjectDialog_cw5n1h2txyewy!Microsoft.Windows.XGpuEjectDialog" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3127391486-654165588-1135944943-943820645-244210695-3344878592-833444881\Microsoft.Windows.XGpuEjectDialog.AppXp7aa4b9certnda7tg336nyjffpy2xn28.mca" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3127391486-654165588-1135944943-943820645-244210695-3344878592-833444881\Microsoft.Windows.XGpuEjectDialog.AppXp7aa4b9certnda7tg336nyjffpy2xn28.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.XGpuEjectDialog_cw5n1h2txyewy!Microsoft.Windows.XGpuEjectDialog" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3147918054-4251542582-2404553452-1793583264-1546801782-1235146273-4024180735\App.AppX3g7kd1zg4a65n0t2ds4j7hffbf62pp9n.mca" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3147918054-4251542582-2404553452-1793583264-1546801782-1235146273-4024180735\App.AppX3g7kd1zg4a65n0t2ds4j7hffbf62pp9n.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.CapturePicker_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3147918054-4251542582-2404553452-1793583264-1546801782-1235146273-4024180735\App.AppX9298rzzjqee0e6z69a168a2kkea3272g.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3147918054-4251542582-2404553452-1793583264-1546801782-1235146273-4024180735\App.AppX9298rzzjqee0e6z69a168a2kkea3272g.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.CapturePicker_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3155986392-3975291318-3290200901-3688105942-3149078057-1179077593-1847296678\Microsoft.Windows.PrintDialog.AppX6fe08qd05jq9n5xymcarszkywdk3r16w.mca" /v "Capabilities" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3155986392-3975291318-3290200901-3688105942-3149078057-1179077593-1847296678\Microsoft.Windows.PrintDialog.AppX6fe08qd05jq9n5xymcarszkywdk3r16w.mca" /v "AppUserModelId" /t REG_SZ /d "Windows.PrintDialog_cw5n1h2txyewy!Microsoft.Windows.PrintDialog" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3155986392-3975291318-3290200901-3688105942-3149078057-1179077593-1847296678\Microsoft.Windows.PrintDialog.AppXskcrzs22qh136w607wsfv5z9v35zx4r5.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3155986392-3975291318-3290200901-3688105942-3149078057-1179077593-1847296678\Microsoft.Windows.PrintDialog.AppXskcrzs22qh136w607wsfv5z9v35zx4r5.mca" /v "AppUserModelId" /t REG_SZ /d "Windows.PrintDialog_cw5n1h2txyewy!Microsoft.Windows.PrintDialog" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3155986392-3975291318-3290200901-3688105942-3149078057-1179077593-1847296678\Microsoft.Windows.PrintDialog.AppXv42rtrb1mc702dzsntwk7td5q0r8d235.mca" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3155986392-3975291318-3290200901-3688105942-3149078057-1179077593-1847296678\Microsoft.Windows.PrintDialog.AppXv42rtrb1mc702dzsntwk7td5q0r8d235.mca" /v "AppUserModelId" /t REG_SZ /d "Windows.PrintDialog_cw5n1h2txyewy!Microsoft.Windows.PrintDialog" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3454040486-2837767420-2398300611-2444005331-4037059961-341738144-1918557667\App.AppX0gvsk56qd1efc2bvj1270yh7b0t3zh7s.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3454040486-2837767420-2398300611-2444005331-4037059961-341738144-1918557667\App.AppX0gvsk56qd1efc2bvj1270yh7b0t3zh7s.mca" /v "AppUserModelId" /t REG_SZ /d "MicrosoftWindows.UndockedDevKit_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3454040486-2837767420-2398300611-2444005331-4037059961-341738144-1918557667\App.AppXvwatxgqwq9wkytde26tvrpye1hbmy3yq.mca" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3454040486-2837767420-2398300611-2444005331-4037059961-341738144-1918557667\App.AppXvwatxgqwq9wkytde26tvrpye1hbmy3yq.mca" /v "AppUserModelId" /t REG_SZ /d "MicrosoftWindows.UndockedDevKit_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppX2dz2dz7bvszf1srfbwq1tqyrpq3nvxf6.mca" /v "Capabilities" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppX2dz2dz7bvszf1srfbwq1tqyrpq3nvxf6.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppX447jn8wbjb1qsw3jxkndb19cwgsrtrkk.mca" /v "Capabilities" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppX447jn8wbjb1qsw3jxkndb19cwgsrtrkk.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppX4h7afn0qpsyh64hybzh15tyefm7d0qdq.mca" /v "Capabilities" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppX4h7afn0qpsyh64hybzh15tyefm7d0qdq.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppX4jgsjrmghnx5xnjbxq6f4rt8d7x6fz56.mca" /v "Capabilities" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppX4jgsjrmghnx5xnjbxq6f4rt8d7x6fz56.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppX51ysthdartafshx0m8z8re49sw398b43.mca" /v "Capabilities" /t REG_DWORD /d "16" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppX51ysthdartafshx0m8z8re49sw398b43.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppX76q4xtxwbj16z0zkyp0pnwtt6m850rvk.mca" /v "Capabilities" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppX76q4xtxwbj16z0zkyp0pnwtt6m850rvk.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppX7rzacqv9fsema8p3fjbs30qgtgv0xzyg.mca" /v "Capabilities" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppX7rzacqv9fsema8p3fjbs30qgtgv0xzyg.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppX8f33pzjqtv84a2ha2f38qat9mf90c7mf.mca" /v "Capabilities" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppX8f33pzjqtv84a2ha2f38qat9mf90c7mf.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppX9s1cz53zc86xn39kwrb02jyft9ecn62r.mca" /v "Capabilities" /t REG_DWORD /d "8" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppX9s1cz53zc86xn39kwrb02jyft9ecn62r.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppXa372cjaa29frn3f9zb3m28rmfsm402nx.mca" /v "Capabilities" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppXa372cjaa29frn3f9zb3m28rmfsm402nx.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppXc65f4bpmvhdf1eywcqqjxjnd97jhppae.mca" /v "Capabilities" /t REG_DWORD /d "8" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppXc65f4bpmvhdf1eywcqqjxjnd97jhppae.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppXd0xdpmda6yga5apk33mnm930q635edtv.mca" /v "Capabilities" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppXd0xdpmda6yga5apk33mnm930q635edtv.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppXdca9rykvbm0qn1fw9m2dbx828p2w3h8p.mca" /v "Capabilities" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppXdca9rykvbm0qn1fw9m2dbx828p2w3h8p.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppXea6epmb5w19sjwy9ckw8md46dm93nhkq.mca" /v "Capabilities" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppXea6epmb5w19sjwy9ckw8md46dm93nhkq.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppXepn41j6xz2a9jhpbym70kbpkpf20r7sk.mca" /v "Capabilities" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppXepn41j6xz2a9jhpbym70kbpkpf20r7sk.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppXfnethrsp7zb4s2ekfph2b5f7cgbkbswt.mca" /v "Capabilities" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppXfnethrsp7zb4s2ekfph2b5f7cgbkbswt.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppXp8rc4ks9rvg8gqj1xc36xt4rss738hjz.mca" /v "Capabilities" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppXp8rc4ks9rvg8gqj1xc36xt4rss738hjz.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppXrr05phpxx3rq1kpwp0y4avzvdfcsr75s.mca" /v "Capabilities" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppXrr05phpxx3rq1kpwp0y4avzvdfcsr75s.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppXryc2qd338f5728r9gzzazav8206ba77s.mca" /v "Capabilities" /t REG_DWORD /d "8" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppXryc2qd338f5728r9gzzazav8206ba77s.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppXw3qcpc7p849541dp39vvqd01bn7z9ybh.mca" /v "Capabilities" /t REG_DWORD /d "8" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppXw3qcpc7p849541dp39vvqd01bn7z9ybh.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppXwdz8g2fxr36xz0tdtagygnvemf85s7gg.mca" /v "Capabilities" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppXwdz8g2fxr36xz0tdtagygnvemf85s7gg.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppXx4zfy1ffv3wctgdz2vypnybzjkh27jhw.mca" /v "Capabilities" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppXx4zfy1ffv3wctgdz2vypnybzjkh27jhw.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppXxyrxfkapamrp843pd5arq545p9wtj2nq.mca" /v "Capabilities" /t REG_DWORD /d "8" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppXxyrxfkapamrp843pd5arq545p9wtj2nq.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppXyvyv4mghdjas8j88defq0w1hc410kvzt.mca" /v "Capabilities" /t REG_DWORD /d "8" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppXyvyv4mghdjas8j88defq0w1hc410kvzt.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppXyww6zxjd3hpc08q55n9j7nztzza8mz1m.mca" /v "Capabilities" /t REG_DWORD /d "8" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723\App.AppXyww6zxjd3hpc08q55n9j7nztzza8mz1m.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3733603082-4179795269-1217541644-381468798-1681740699-3059609168-2054985149\App.AppXrtkg3ebdrtg67k8v75mvnm3zfpjceykd.mca" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3733603082-4179795269-1217541644-381468798-1681740699-3059609168-2054985149\App.AppXrtkg3ebdrtg67k8v75mvnm3zfpjceykd.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.SecureAssessmentBrowser_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3733603082-4179795269-1217541644-381468798-1681740699-3059609168-2054985149\App.AppXz50byegdp9v0stee495y21kv0xbyqgzm.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3733603082-4179795269-1217541644-381468798-1681740699-3059609168-2054985149\App.AppXz50byegdp9v0stee495y21kv0xbyqgzm.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.SecureAssessmentBrowser_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3784866113-3187381476-3433752343-3391928953-3760210436-1684329488-1912184601\App.AppXdqxdgc0xdfggkz6d2z69jy8ey85eejq7.mca" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3784866113-3187381476-3433752343-3391928953-3760210436-1684329488-1912184601\App.AppXdqxdgc0xdfggkz6d2z69jy8ey85eejq7.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.OOBENetworkConnectionFlow_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3784866113-3187381476-3433752343-3391928953-3760210436-1684329488-1912184601\App.AppXxfb02mawce7c6efa0xn7xxbtrnvdjgcj.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3784866113-3187381476-3433752343-3391928953-3760210436-1684329488-1912184601\App.AppXxfb02mawce7c6efa0xn7xxbtrnvdjgcj.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.OOBENetworkConnectionFlow_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3911328773-608413955-1309177842-678056087-3306350038-3682494511-2300153425\App.AppXemdecxs7zy6dn89skd64q94137qvpzfs.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3911328773-608413955-1309177842-678056087-3306350038-3682494511-2300153425\App.AppXemdecxs7zy6dn89skd64q94137qvpzfs.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.PeopleExperienceHost_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3911328773-608413955-1309177842-678056087-3306350038-3682494511-2300153425\App.AppXv3y9x55a7eq2mt4f5qfd56ewff2nbzm8.mca" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3911328773-608413955-1309177842-678056087-3306350038-3682494511-2300153425\App.AppXv3y9x55a7eq2mt4f5qfd56ewff2nbzm8.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.PeopleExperienceHost_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3912597219-1073764063-4221279274-2430493127-3107599948-1184173955-951593363\App.AppXax817xdz5sbxr49yd24terbbc7kzrnbq.mca" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3912597219-1073764063-4221279274-2430493127-3107599948-1184173955-951593363\App.AppXax817xdz5sbxr49yd24terbbc7kzrnbq.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.ECApp_8wekyb3d8bbwe!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3912597219-1073764063-4221279274-2430493127-3107599948-1184173955-951593363\App.AppXzx3y7df1exwenz6j3n59f2kky5z0n5rc.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-3912597219-1073764063-4221279274-2430493127-3107599948-1184173955-951593363\App.AppXzx3y7df1exwenz6j3n59f2kky5z0n5rc.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.ECApp_8wekyb3d8bbwe!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-4264928162-86341590-2006646042-3756743162-890444002-3415177634-881149292\App.AppX9k1r07j2j1r760b134v3zpg7kyf754bx.mca" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-4264928162-86341590-2006646042-3756743162-890444002-3415177634-881149292\App.AppX9k1r07j2j1r760b134v3zpg7kyf754bx.mca" /v "AppUserModelId" /t REG_SZ /d "c5e2524a-ea46-4f67-841f-6a9465d9d515_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-4264928162-86341590-2006646042-3756743162-890444002-3415177634-881149292\App.AppXx83m4by3p4r0rr7jqaqfc35t2x3npbzn.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-4264928162-86341590-2006646042-3756743162-890444002-3415177634-881149292\App.AppXx83m4by3p4r0rr7jqaqfc35t2x3npbzn.mca" /v "AppUserModelId" /t REG_SZ /d "c5e2524a-ea46-4f67-841f-6a9465d9d515_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-515815643-2845804217-1874292103-218650560-777617685-4287762684-137415000\App.AppX61hpp0btbpr7ww8e8y4q7ga99y3mb921.mca" /v "Capabilities" /t REG_DWORD /d "12" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-515815643-2845804217-1874292103-218650560-777617685-4287762684-137415000\App.AppX61hpp0btbpr7ww8e8y4q7ga99y3mb921.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-515815643-2845804217-1874292103-218650560-777617685-4287762684-137415000\App.AppX8mekmt3tnzpj2rqvv32phe9zztvazy1x.mca" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-515815643-2845804217-1874292103-218650560-777617685-4287762684-137415000\App.AppX8mekmt3tnzpj2rqvv32phe9zztvazy1x.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-515815643-2845804217-1874292103-218650560-777617685-4287762684-137415000\App.AppXce0rcsqhwpztn79s8y3ad2aht6sj1bwj.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-515815643-2845804217-1874292103-218650560-777617685-4287762684-137415000\App.AppXce0rcsqhwpztn79s8y3ad2aht6sj1bwj.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-536077884-713174666-1066051701-3219990555-339840825-1966734348-1611281757\CortanaUI.AppX49we79s9ab0xp8xpjb6t6g31ep03r71y.mca" /v "Capabilities" /t REG_DWORD /d "8" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-536077884-713174666-1066051701-3219990555-339840825-1966734348-1611281757\CortanaUI.AppX49we79s9ab0xp8xpjb6t6g31ep03r71y.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.Search_cw5n1h2txyewy!CortanaUI" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-536077884-713174666-1066051701-3219990555-339840825-1966734348-1611281757\CortanaUI.AppX8ax287rv6463156dhdx1ew1yaw2aw6h0.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-536077884-713174666-1066051701-3219990555-339840825-1966734348-1611281757\CortanaUI.AppX8ax287rv6463156dhdx1ew1yaw2aw6h0.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.Search_cw5n1h2txyewy!CortanaUI" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-536077884-713174666-1066051701-3219990555-339840825-1966734348-1611281757\CortanaUI.AppXf8r3d8cn5hd71h9jyzah6ak9f3shj2d2.mca" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-536077884-713174666-1066051701-3219990555-339840825-1966734348-1611281757\CortanaUI.AppXf8r3d8cn5hd71h9jyzah6ak9f3shj2d2.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.Search_cw5n1h2txyewy!CortanaUI" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-536077884-713174666-1066051701-3219990555-339840825-1966734348-1611281757\ShellFeedsUI.AppX2yqybqqe5gc7j4rpgq2fn5hyjjtqk6wa.mca" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-536077884-713174666-1066051701-3219990555-339840825-1966734348-1611281757\ShellFeedsUI.AppX2yqybqqe5gc7j4rpgq2fn5hyjjtqk6wa.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.Search_cw5n1h2txyewy!ShellFeedsUI" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-536077884-713174666-1066051701-3219990555-339840825-1966734348-1611281757\ShellFeedsUI.AppXe6thh8rmn270wdveaxmp569ccfw5zra6.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-536077884-713174666-1066051701-3219990555-339840825-1966734348-1611281757\ShellFeedsUI.AppXe6thh8rmn270wdveaxmp569ccfw5zra6.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.Search_cw5n1h2txyewy!ShellFeedsUI" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-536077884-713174666-1066051701-3219990555-339840825-1966734348-1611281757\ShellFeedsUI.AppXfbff151h5bmghg166fvn34ccayg70vts.mca" /v "Capabilities" /t REG_DWORD /d "12" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-536077884-713174666-1066051701-3219990555-339840825-1966734348-1611281757\ShellFeedsUI.AppXfbff151h5bmghg166fvn34ccayg70vts.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.Search_cw5n1h2txyewy!ShellFeedsUI" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-577703620-721806600-2575725278-1938300505-2177978512-2240326487-1220425747\App.AppXa2g9313bzvs2knz17p3sr2k6j7ftv102.mca" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-577703620-721806600-2575725278-1938300505-2177978512-2240326487-1220425747\App.AppXa2g9313bzvs2knz17p3sr2k6j7ftv102.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.NarratorQuickStart_8wekyb3d8bbwe!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-577703620-721806600-2575725278-1938300505-2177978512-2240326487-1220425747\App.AppXrqc8rqrdfw94pdkgeb2y6znzvahde82y.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-577703620-721806600-2575725278-1938300505-2177978512-2240326487-1220425747\App.AppXrqc8rqrdfw94pdkgeb2y6znzvahde82y.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.Windows.NarratorQuickStart_8wekyb3d8bbwe!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-932905279-1352884144-690731472-1935380077-77221151-3040906485-3167188873\App.AppXhwyds4rk7x1n5d19trv30fn7fbe01fjx.mca" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-932905279-1352884144-690731472-1935380077-77221151-3040906485-3167188873\App.AppXhwyds4rk7x1n5d19trv30fn7fbe01fjx.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.CredDialogHost_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-932905279-1352884144-690731472-1935380077-77221151-3040906485-3167188873\App.AppXr6j54agfmsnf11n440jb928bzsqqdekm.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-932905279-1352884144-690731472-1935380077-77221151-3040906485-3167188873\App.AppXr6j54agfmsnf11n440jb928bzsqqdekm.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.CredDialogHost_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-957941444-2271171641-4049211970-804197638-2225746618-2474488012-4131196493\Microsoft.XboxGameCallableUI.AppX1cmwnn74xnybt9sthpeww9n07vye06vx.mca" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-957941444-2271171641-4049211970-804197638-2225746618-2474488012-4131196493\Microsoft.XboxGameCallableUI.AppX1cmwnn74xnybt9sthpeww9n07vye06vx.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.XboxGameCallableUI_cw5n1h2txyewy!Microsoft.XboxGameCallableUI" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-957941444-2271171641-4049211970-804197638-2225746618-2474488012-4131196493\Microsoft.XboxGameCallableUI.AppX8s458wyr2sn7smnarg3rs49chrqg84qg.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-957941444-2271171641-4049211970-804197638-2225746618-2474488012-4131196493\Microsoft.XboxGameCallableUI.AppX8s458wyr2sn7smnarg3rs49chrqg84qg.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.XboxGameCallableUI_cw5n1h2txyewy!Microsoft.XboxGameCallableUI" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-969871995-3242822759-583047763-1618006129-3578262429-3647035748-2471858633\App.AppXbe6cegqrk9q6d482qh2x7dkmydv38qp5.mca" /v "Capabilities" /t REG_DWORD /d "484124" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-969871995-3242822759-583047763-1618006129-3578262429-3647035748-2471858633\App.AppXbe6cegqrk9q6d482qh2x7dkmydv38qp5.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.AccountsControl_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-969871995-3242822759-583047763-1618006129-3578262429-3647035748-2471858633\App.AppXh7n19g4ar4fcxzvgc9xhqhz2gsyfkcbf.mca" /v "Capabilities" /t REG_DWORD /d "28" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Notifications\BackgroundCapability\S-1-15-2-969871995-3242822759-583047763-1618006129-3578262429-3647035748-2471858633\App.AppXh7n19g4ar4fcxzvgc9xhqhz2gsyfkcbf.mca" /v "AppUserModelId" /t REG_SZ /d "Microsoft.AccountsControl_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "Migrated" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\1527c705-839a-4832-9118-54d4Bd6a0c89_cw5n1h2txyewy" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\c5e2524a-ea46-4f67-841f-6a9465d9d515_cw5n1h2txyewy" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\E2A4F912-2574-4A75-9BB0-0D023378592B_cw5n1h2txyewy" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE_cw5n1h2txyewy" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.AccountsControl_cw5n1h2txyewy" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.AsyncTextService_8wekyb3d8bbwe" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.BioEnrollment_cw5n1h2txyewy" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.CredDialogHost_cw5n1h2txyewy" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.ECApp_8wekyb3d8bbwe" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.LockApp_cw5n1h2txyewy" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Win32WebViewHost_cw5n1h2txyewy" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Windows.Apprep.ChxApp_cw5n1h2txyewy" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Windows.AssignedAccessLockApp_cw5n1h2txyewy" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Windows.CallingShellApp_cw5n1h2txyewy" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Windows.CapturePicker_cw5n1h2txyewy" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Windows.NarratorQuickStart_8wekyb3d8bbwe" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Windows.OOBENetworkCaptivePortal_cw5n1h2txyewy" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Windows.OOBENetworkConnectionFlow_cw5n1h2txyewy" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Windows.ParentalControls_cw5n1h2txyewy" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Windows.PeopleExperienceHost_cw5n1h2txyewy" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Windows.PinningConfirmationDialog_cw5n1h2txyewy" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Windows.Search_cw5n1h2txyewy\Microsoft.Windows.Search_cw5n1h2txyewy!CortanaUI" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Windows.SecureAssessmentBrowser_cw5n1h2txyewy" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Windows.XGpuEjectDialog_cw5n1h2txyewy" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.XboxGameCallableUI_cw5n1h2txyewy" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\MicrosoftWindows.Client.CBS_cw5n1h2txyewy" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\MicrosoftWindows.UndockedDevKit_cw5n1h2txyewy" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\NcsiUwpApp_8wekyb3d8bbwe\NcsiUwpApp_8wekyb3d8bbwe!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\NVIDIACorp.NVIDIAControlPanel_56jybvy8sckqj" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\RealtekSemiconductorCorp.RealtekAudioControl_dt26b99r8h8gj" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Windows.CBSPreview_cw5n1h2txyewy" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\windows.immersivecontrolpanel_cw5n1h2txyewy" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Windows.PrintDialog_cw5n1h2txyewy" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData" /v "Value" /t REG_SZ /d "Allow" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData\Microsoft.Win32WebViewHost_cw5n1h2txyewy" /v "Value" /t REG_SZ /d "Allow" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData\Microsoft.Windows.NarratorQuickStart_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Allow" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData\Microsoft.Windows.Search_cw5n1h2txyewy" /v "Value" /t REG_SZ /d "Allow" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy" /v "Value" /t REG_SZ /d "Allow" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData\NcsiUwpApp_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Allow" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy" /v "Value" /t REG_SZ /d "Prompt" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts\MicrosoftWindows.Client.CBS_cw5n1h2txyewy" /v "Value" /t REG_SZ /d "Prompt" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\gazeInput\Microsoft.ECApp_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Prompt" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location\Microsoft.Win32WebViewHost_cw5n1h2txyewy" /v "Value" /t REG_SZ /d "Prompt" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Microsoft.Win32WebViewHost_cw5n1h2txyewy" /v "Value" /t REG_SZ /d "Prompt" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Microsoft.Windows.SecureAssessmentBrowser_cw5n1h2txyewy" /v "Value" /t REG_SZ /d "Prompt" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary\MicrosoftWindows.Client.CBS_cw5n1h2txyewy" /v "Value" /t REG_SZ /d "Allow" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation\Microsoft.AccountsControl_cw5n1h2txyewy" /v "Value" /t REG_SZ /d "Prompt" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy" /v "Value" /t REG_SZ /d "Prompt" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\Microsoft.Win32WebViewHost_cw5n1h2txyewy" /v "Value" /t REG_SZ /d "Prompt" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wifiData" /v "Value" /t REG_SZ /d "Allow" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wifiData\Microsoft.Win32WebViewHost_cw5n1h2txyewy" /v "Value" /t REG_SZ /d "Allow" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wifiData\Microsoft.Windows.NarratorQuickStart_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Allow" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wifiData\Microsoft.Windows.Search_cw5n1h2txyewy" /v "Value" /t REG_SZ /d "Allow" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wifiData\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy" /v "Value" /t REG_SZ /d "Allow" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wifiData\NcsiUwpApp_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Allow" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" /v "RomeSdkChannelUserAuthzPolicy" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" /v "NearShareChannelUserAuthzPolicy" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" /v "EnableRemoteLaunchToast" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" /v "CdpUserSettingsVersion" /t REG_SZ /d "RS4" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ClickNote\UserCustomization\DoubleClickBelowLock" /v "Override" /t REG_DWORD /d "5" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ClickNote\UserCustomization\DoubleClickBelowLock" /v "PenWorkspaceVerb" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ClickNote\UserCustomization\LongPressBelowLock" /v "Override" /t REG_DWORD /d "5" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ClickNote\UserCustomization\LongPressBelowLock" /v "PenWorkspaceVerb" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ClickNote\UserCustomization\SingleClickBelowLock" /v "Override" /t REG_DWORD /d "8" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ClickNote\UserCustomization\SingleClickBelowLock" /v "PenWorkspaceVerb" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore" /v "Version" /t REG_DWORD /d "6" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\$$windows.data.notifications.quiethourssettings\Current" /v "Data" /t REG_BINARY /d "02000000a23046bf8b62d7010000000043420100c20a01d214284d006900630072006f0073006f00660074002e005100750069006500740048006f00750072007300500072006f00660069006c0065002e0055006e007200650073007400720069006300740065006400ca280000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\$$windows.data.platform.partitioning.activepartitions\Current" /v "Data" /t REG_BINARY /d "020000009f9c5ebf8b62d70100000000434201000d10120104267b00420033004300360034004500360032002d0034003700350041002d0034003000450033002d0038003800370033002d003500420035003300340031004600370046003400350041007d0000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\$$windows.data.platform.partitioning.systempartitionindex\Current" /v "Data" /t REG_BINARY /d "0200000085555ebf8b62d70100000000434201000d030a01020d120a01267b00420033004300360034004500360032002d0034003700350041002d0034003000450033002d0038003800370033002d003500420035003300340031004600370046003400350041007d004a094457696e646f77732e446174612e506c6174666f726d2e506172746974696f6e696e672e446576696365457870657269656e6365506172746974696f6e4d6574616461746126f4a3f9fabbd1d8eb010110022a04801443030000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\$de${b3c64e62-475a-40e3-8873-5b5341f7f45a}$$windows.data.curatedtilecollection.tilecollectioncontainer\Current" /v "Data" /t REG_BINARY /d "02000000580be1c48b62d70100000000434201000b0a02120e530074006100720074002e00540069006c0065004700720069006400001211530074006100720074002e00530075006700670065007300740069006f006e0073000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\$de${b3c64e62-475a-40e3-8873-5b5341f7f45a}$$windows.data.placeholdertilecollection\Current" /v "Data" /t REG_BINARY /d "02000000e7a66bc58b62d701000000004342010000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\$de${b3c64e62-475a-40e3-8873-5b5341f7f45a}$$windows.data.placeholdertilecollectionlocal\Current" /v "Data" /t REG_BINARY /d "02000000f8ae6bc58b62d701000000004342010000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\$de${b3c64e62-475a-40e3-8873-5b5341f7f45a}$$windows.data.unifiedtile.localstartglobalproperties\Current" /v "Data" /t REG_BINARY /d "02000000eac0c2c48b62d701000000004342010000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\$de${b3c64e62-475a-40e3-8873-5b5341f7f45a}$$windows.data.unifiedtile.localstarttilepropertiesmap\Current" /v "Data" /t REG_BINARY /d "02000000f5879b058f62d70100000000434201000d120a615150007e00310035003200370063003700300035002d0038003300390061002d0034003800330032002d0039003100310038002d003500340064003400420064003600610030006300380039005f006300770035006e0031006800320074007800790065007700790021004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e00460069006c0065005000690063006b0065007200c6649780a4a2bcd1d8eb01d0d208005450007e00450032004100340046003900310032002d0032003500370034002d0034004100370035002d0039004200420030002d003000440030003200330033003700380035003900320042005f006300770035006e0031006800320074007800790065007700790021004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e004100700070005200650073006f006c0076006500720055005800c6649780a4a2bcd1d8eb01d0d208003850007e00460034003600440034003000300030002d0046004400320032002d0034004400420034002d0041004300380045002d003400450031004400440044004500380032003800460045005f006300770035006e003100680032007400780079006500770079002100410070007000c6649780a4a2bcd1d8eb01d0d208002e50007e004d006900630072006f0073006f00660074002e004100410044002e00420072006f006b006500720050006c007500670069006e005f006300770035006e003100680032007400780079006500770079002100410070007000c664ea8ef3febbd1d8eb01d0d208002d50007e004d006900630072006f0073006f00660074002e004100630063006f0075006e007400730043006f006e00740072006f006c005f006300770035006e003100680032007400780079006500770079002100410070007000c6649780a4a2bcd1d8eb01d0d208002e50007e004d006900630072006f0073006f00660074002e004100730079006e006300540065007800740053006500720076006900630065005f003800770065006b007900620033006400380062006200770065002100410070007000c664c6c4ada2bcd1d8eb01d0d208002b50007e004d006900630072006f0073006f00660074002e00420069006f0045006e0072006f006c006c006d0065006e0074005f006300770035006e003100680032007400780079006500770079002100410070007000c66485e788fcbbd1d8eb01d0d208002c50007e004d006900630072006f0073006f00660074002e0043007200650064004400690061006c006f00670048006f00730074005f006300770035006e003100680032007400780079006500770079002100410070007000c664c6c4ada2bcd1d8eb01d0d208002350007e004d006900630072006f0073006f00660074002e00450043004100700070005f003800770065006b007900620033006400380062006200770065002100410070007000c664c6c4ada2bcd1d8eb01d0d208003050007e004d006900630072006f0073006f00660074002e00480045004900460049006d0061006700650045007800740065006e00730069006f006e005f003800770065006b007900620033006400380062006200770065002100410070007000c664fc88b7a2bcd1d8eb01d0d208003a50007e004d006900630072006f0073006f00660074002e004c006f0063006b004100700070005f006300770035006e003100680032007400780079006500770079002100570069006e0064006f0077007300440065006600610075006c0074004c006f0063006b00530063007200650065006e00c664c6c4ada2bcd1d8eb01d0d208003050007e004d006900630072006f0073006f00660074002e0056005000390056006900640065006f0045007800740065006e00730069006f006e0073005f003800770065006b007900620033006400380062006200770065002100410070007000c664fc88b7a2bcd1d8eb01d0d208003050007e004d006900630072006f0073006f00660074002e00570065006200700049006d0061006700650045007800740065006e00730069006f006e005f003800770065006b007900620033006400380062006200770065002100410070007000c664fc88b7a2bcd1d8eb01d0d208003e50007e004d006900630072006f0073006f00660074002e00570069006e0033003200570065006200560069006500770048006f00730074005f006300770035006e0031006800320074007800790065007700790021004400500049002e005000650072004d006f006e00690074006f00720041007700610072006500c664c6c4ada2bcd1d8eb01d0d208003a50007e004d006900630072006f0073006f00660074002e00570069006e0033003200570065006200560069006500770048006f00730074005f006300770035006e0031006800320074007800790065007700790021004400500049002e00530079007300740065006d0041007700610072006500c664c6c4ada2bcd1d8eb01d0d208003650007e004d006900630072006f0073006f00660074002e00570069006e0033003200570065006200560069006500770048006f00730074005f006300770035006e0031006800320074007800790065007700790021004400500049002e0055006e0061007700610072006500c664c6c4ada2bcd1d8eb01d0d208003350007e004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e004100700070007200650070002e004300680078004100700070005f006300770035006e003100680032007400780079006500770079002100410070007000c664c6c4ada2bcd1d8eb01d0d208003b50007e004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e00410073007300690067006e00650064004100630063006500730073004c006f0063006b004100700070005f006300770035006e003100680032007400780079006500770079002100410070007000c664c6c4ada2bcd1d8eb01d0d208005350007e004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e00430061006c006c0069006e0067005300680065006c006c004100700070005f006300770035006e0031006800320074007800790065007700790021004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e00430061006c006c0069006e0067005300680065006c006c00410070007000c664c6c4ada2bcd1d8eb01d0d208003350007e004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e0043006100700074007500720065005000690063006b00650072005f006300770035006e003100680032007400780079006500770079002100410070007000c664c6c4ada2bcd1d8eb01d0d208003950007e004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e0043006c006f007500640045007800700065007200690065006e006300650048006f00730074005f006300770035006e003100680032007400780079006500770079002100410070007000c664e499ecfbbbd1d8eb01d0d208003c50007e004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e0043006f006e00740065006e007400440065006c00690076006500720079004d0061006e0061006700650072005f006300770035006e003100680032007400780079006500770079002100410070007000c664feceb085bcd1d8eb01d0d208003850007e004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e004e00610072007200610074006f00720051007500690063006b00530074006100720074005f003800770065006b007900620033006400380062006200770065002100410070007000c664c6c4ada2bcd1d8eb01d0d208003e50007e004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e004f004f00420045004e006500740077006f0072006b00430061007000740069007600650050006f007200740061006c005f006300770035006e003100680032007400780079006500770079002100410070007000c66492e7b180bcd1d8eb01d0d208003f50007e004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e004f004f00420045004e006500740077006f0072006b0043006f006e006e0065006300740069006f006e0046006c006f0077005f006300770035006e003100680032007400780079006500770079002100410070007000c6649dd3fcfebbd1d8eb01d0d208003650007e004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e0050006100720065006e00740061006c0043006f006e00740072006f006c0073005f006300770035006e003100680032007400780079006500770079002100410070007000c664c6c4ada2bcd1d8eb01d0d208003a50007e004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e00500065006f0070006c00650045007800700065007200690065006e006300650048006f00730074005f006300770035006e003100680032007400780079006500770079002100410070007000c664c6c4ada2bcd1d8eb01d0d208003f50007e004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e00500069006e006e0069006e00670043006f006e006600690072006d006100740069006f006e004400690061006c006f0067005f006300770035006e003100680032007400780079006500770079002100410070007000c664fc88b7a2bcd1d8eb01d0d208003250007e004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e005300650061007200630068005f006300770035006e00310068003200740078007900650077007900210043006f007200740061006e00610055004900c664b3c69d85bcd1d8eb01d0d208003550007e004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e005300650061007200630068005f006300770035006e0031006800320074007800790065007700790021005300680065006c006c004600650065006400730055004900c664b3c69d85bcd1d8eb01d0d208003d50007e004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e005300650063007500720065004100730073006500730073006d0065006e007400420072006f0077007300650072005f006300770035006e003100680032007400780079006500770079002100410070007000c664fc88b7a2bcd1d8eb01d0d208003950007e004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e005300680065006c006c0045007800700065007200690065006e006300650048006f00730074005f006300770035006e003100680032007400780079006500770079002100410070007000c6649fb2e883bcd1d8eb01d0d208003d50007e004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e00530074006100720074004d0065006e00750045007800700065007200690065006e006300650048006f00730074005f006300770035006e003100680032007400780079006500770079002100410070007000c664ccebcf82bcd1d8eb01d0d208005350007e004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e00580047007000750045006a006500630074004400690061006c006f0067005f006300770035006e0031006800320074007800790065007700790021004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e00580047007000750045006a006500630074004400690061006c006f006700c664fc88b7a2bcd1d8eb01d0d208004950007e004d006900630072006f0073006f00660074002e00580062006f007800470061006d006500430061006c006c00610062006c006500550049005f006300770035006e0031006800320074007800790065007700790021004d006900630072006f0073006f00660074002e00580062006f007800470061006d006500430061006c006c00610062006c00650055004900c664fc88b7a2bcd1d8eb01d0d208003e50007e004d006900630072006f0073006f0066007400570069006e0064006f00770073002e0043006c00690065006e0074002e004300420053005f006300770035006e00310068003200740078007900650077007900210047006c006f00620061006c002e0049007200690073005300650072007600690063006500c66485c6f480bcd1d8eb01d0d208003450007e004d006900630072006f0073006f0066007400570069006e0064006f00770073002e0043006c00690065006e0074002e004300420053005f006300770035006e00310068003200740078007900650077007900210049006e00700075007400410070007000c66485c6f480bcd1d8eb01d0d208003b50007e004d006900630072006f0073006f0066007400570069006e0064006f00770073002e0043006c00690065006e0074002e004300420053005f006300770035006e0031006800320074007800790065007700790021005000610063006b006100670065004d006500740061006400610074006100c66485c6f480bcd1d8eb01d0d208003a50007e004d006900630072006f0073006f0066007400570069006e0064006f00770073002e0043006c00690065006e0074002e004300420053005f006300770035006e003100680032007400780079006500770079002100530063007200650065006e0043006c0069007000700069006e006700c66485c6f480bcd1d8eb01d0d208003350007e004d006900630072006f0073006f0066007400570069006e0064006f00770073002e0055006e0064006f0063006b00650064004400650076004b00690074005f006300770035006e003100680032007400780079006500770079002100410070007000c664e6e2bc82bcd1d8eb01d0d208004b50007e004e005600490044004900410043006f00720070002e004e005600490044004900410043006f006e00740072006f006c00500061006e0065006c005f00350036006a0079006200760079003800730063006b0071006a0021004e005600490044004900410043006f00720070002e004e005600490044004900410043006f006e00740072006f006c00500061006e0065006c00c664f5fbc4f2ced1d8eb01d0d204001e50007e004e006300730069005500770070004100700070005f003800770065006b007900620033006400380062006200770065002100410070007000c664fc88b7a2bcd1d8eb01d0d208004050007e005200650061006c00740065006b00530065006d00690063006f006e0064007500630074006f00720043006f00720070002e005200650061006c00740065006b0041007500640069006f0043006f006e00740072006f006c005f006400740032003600620039003900720038006800380067006a002100410070007000c664edff91bed1d1d8eb01d0d204003f50007e00570069006e0064006f00770073002e0043004200530050007200650076006900650077005f006300770035006e0031006800320074007800790065007700790021004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e004300420053005000720065007600690065007700c664fc88b7a2bcd1d8eb01d0d208004150007e00570069006e0064006f00770073002e005000720069006e0074004400690061006c006f0067005f006300770035006e0031006800320074007800790065007700790021004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e005000720069006e0074004400690061006c006f006700c664fc88b7a2bcd1d8eb01d0d208003850007e00630035006500320035003200340061002d0065006100340036002d0034006600360037002d0038003400310066002d003600610039003400360035006400390064003500310035005f006300770035006e003100680032007400780079006500770079002100410070007000c6649780a4a2bcd1d8eb01d0d208005550007e00770069006e0064006f00770073002e0069006d006d0065007200730069007600650063006f006e00740072006f006c00700061006e0065006c005f006300770035006e0031006800320074007800790065007700790021006d006900630072006f0073006f00660074002e00770069006e0064006f00770073002e0069006d006d0065007200730069007600650063006f006e00740072006f006c00700061006e0065006c00c664d6f6f183bcd1d8eb01d0d204001257007e003300300038003000340036004200300041004600340041003300390043004200c66494a484b9c8d1d8eb01d0d200000857007e004300680072006f006d006500c664f7f7c69dcdd1d8eb01d0d200004057007e004d006900630072006f0073006f00660074002e004100750074006f00470065006e006500720061007400650064002e007b00380041004100340037003300360035002d0042003200420033002d0031003900360031002d0036003900450042002d004600380036003600450033003700360042003100320046007d00c664dae593a6bcd1d8eb01d0d200004057007e004d006900630072006f0073006f00660074002e004100750074006f00470065006e006500720061007400650064002e007b00380041004200440039003400460042002d0045003700440036002d0038003400410036002d0041003900390037002d004300390031003800450044004400450030004100450035007d00c664dae593a6bcd1d8eb01d0d200004057007e004d006900630072006f0073006f00660074002e004100750074006f00470065006e006500720061007400650064002e007b00390032003300440044003400370037002d0035003800340036002d0036003800360042002d0041003600350039002d003000460043004300440037003300380035003100410038007d00c664dae593a6bcd1d8eb01d0d200004057007e004d006900630072006f0073006f00660074002e004100750074006f00470065006e006500720061007400650064002e007b00420042003000340034004200460044002d0032003500420037002d0032004600410041002d0032003200410038002d003600330037003100410039003300450030003400350036007d00c664dae593a6bcd1d8eb01d0d200004057007e004d006900630072006f0073006f00660074002e004100750074006f00470065006e006500720061007400650064002e007b00420044003300460039003200340045002d0035003500460042002d0041003100420041002d0039004400450036002d004200350030004600390046003200340036003000410043007d00c664dae593a6bcd1d8eb01d0d200004057007e004d006900630072006f0073006f00660074002e004100750074006f00470065006e006500720061007400650064002e007b00430031004300360046003800410043002d0034003000410033002d0030004600350043002d0031003400360046002d003600350041003900440043003700300042004200420034007d00c664dae593a6bcd1d8eb01d0d200004057007e004d006900630072006f0073006f00660074002e004100750074006f00470065006e006500720061007400650064002e007b00430038003000340042004200410037002d0046004100350046002d0043004200460037002d0038004200350035002d003200300039003600450035004600390037003200430042007d00c664dae593a6bcd1d8eb01d0d200004057007e004d006900630072006f0073006f00660074002e004100750074006f00470065006e006500720061007400650064002e007b00440041004100310036003800440045002d0034003300300036002d0043003800420043002d0038004300310031002d004200350039003600320034003000420044004400450044007d00c664dae593a6bcd1d8eb01d0d200002457007e004d006900630072006f0073006f00660074002e0049006e007400650072006e00650074004500780070006c006f007200650072002e00440065006600610075006c007400c664dae593a6bcd1d8eb01d0d200002757007e004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e00410064006d0069006e0069007300740072006100740069007600650054006f006f006c007300c664dae593a6bcd1d8eb01d0d200001c57007e004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e0043006f006d0070007500740065007200c664dae593a6bcd1d8eb01d0d200002057007e004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e0043006f006e00740072006f006c00500061006e0065006c00c664dae593a6bcd1d8eb01d0d200001c57007e004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e004500780070006c006f00720065007200c664dae593a6bcd1d8eb01d0d200002157007e004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e004d00650064006900610050006c00610079006500720033003200c664dae593a6bcd1d8eb01d0d200002157007e004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e00520065006d006f00740065004400650073006b0074006f007000c664dae593a6bcd1d8eb01d0d200002357007e004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e005300680065006c006c002e00520075006e004400690061006c006f006700c664dae593a6bcd1d8eb01d0d200003457007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c004d006400530063006800650064002e00650078006500c664dae593a6bcd1d8eb01d0d200003a57007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c005200650063006f007600650072007900440072006900760065002e00650078006500c664dae593a6bcd1d8eb01d0d200003957007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c0053006e0069007000700069006e00670054006f006f006c002e00650078006500c664dae593a6bcd1d8eb01d0d200002f57007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c00570046002e006d0073006300c664dae593a6bcd1d8eb01d0d200003057007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c005700460053002e00650078006500c664dae593a6bcd1d8eb01d0d200005257007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c00570069006e0064006f007700730050006f007700650072005300680065006c006c005c00760031002e0030005c0050006f007700650072005300680065006c006c005f004900530045002e00650078006500c664dae593a6bcd1d8eb01d0d200004e57007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c00570069006e0064006f007700730050006f007700650072005300680065006c006c005c00760031002e0030005c0070006f007700650072007300680065006c006c002e00650078006500c664dae593a6bcd1d8eb01d0d200003457007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c0063006800610072006d00610070002e00650078006500c664dae593a6bcd1d8eb01d0d200003557007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c0063006c00650061006e006d00670072002e00650078006500c664dae593a6bcd1d8eb01d0d200003057007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c0063006d0064002e00650078006500c664dae593a6bcd1d8eb01d0d200003357007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c0063006f006d006500780070002e006d0073006300c664dae593a6bcd1d8eb01d0d200003357007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c006400660072006700750069002e00650078006500c664dae593a6bcd1d8eb01d0d200003557007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c0069007300630073006900630070006c002e00650078006500c664dae593a6bcd1d8eb01d0d200003457007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c006d00610067006e006900660079002e00650078006500c664dae593a6bcd1d8eb01d0d200003557007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c006d00730063006f006e006600690067002e00650078006500c664dae593a6bcd1d8eb01d0d200003557007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c006d00730069006e0066006f00330032002e00650078006500c664dae593a6bcd1d8eb01d0d200003457007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c006d0073007000610069006e0074002e00650078006500c664dae593a6bcd1d8eb01d0d200003557007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c006e00610072007200610074006f0072002e00650078006500c664dae593a6bcd1d8eb01d0d200003457007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c006e006f00740065007000610064002e00650078006500c664dae593a6bcd1d8eb01d0d200003557007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c006f0064006200630061006400330032002e00650078006500c664dae593a6bcd1d8eb01d0d200003057007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c006f0073006b002e00650078006500c664dae593a6bcd1d8eb01d0d200003c57007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c007000720069006e0074006d0061006e006100670065006d0065006e0074002e006d0073006300c664dae593a6bcd1d8eb01d0d200003057007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c007000730072002e00650078006500c664dae593a6bcd1d8eb01d0d200003857007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c0071007500690063006b006100730073006900730074002e00650078006500c664dae593a6bcd1d8eb01d0d200003557007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c00730065007200760069006300650073002e006d0073006300c664dae593a6bcd1d8eb01d0d200003657007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c00770069006e0033003200630061006c0063002e00650078006500c664dae593a6bcd1d8eb01d0d200005257007e007b00360044003800300039003300370037002d0036004100460030002d0034003400340042002d0038003900350037002d004100330037003700330046003000320032003000300045007d005c0043006f006d006d006f006e002000460069006c00650073005c004d006900630072006f0073006f006600740020005300680061007200650064005c0049006e006b005c006d00690070002e00650078006500c664dae593a6bcd1d8eb01d0d200004b57007e007b00360044003800300039003300370037002d0036004100460030002d0034003400340042002d0038003900350037002d004100330037003700330046003000320032003000300045007d005c00570069006e0064006f007700730020004e0054005c004100630063006500730073006f0072006900650073005c0077006f00720064007000610064002e00650078006500c664dae593a6bcd1d8eb01d0d200005257007e007b00440036003500320033003100420030002d0042003200460031002d0034003800350037002d0041003400430045002d004100380045003700430036004500410037004400320037007d005c00570069006e0064006f007700730050006f007700650072005300680065006c006c005c00760031002e0030005c0050006f007700650072005300680065006c006c005f004900530045002e00650078006500c664dae593a6bcd1d8eb01d0d200004e57007e007b00440036003500320033003100420030002d0042003200460031002d0034003800350037002d0041003400430045002d004100380045003700430036004500410037004400320037007d005c00570069006e0064006f007700730050006f007700650072005300680065006c006c005c00760031002e0030005c0070006f007700650072007300680065006c006c002e00650078006500c664dae593a6bcd1d8eb01d0d200003557007e007b00440036003500320033003100420030002d0042003200460031002d0034003800350037002d0041003400430045002d004100380045003700430036004500410037004400320037007d005c006f0064006200630061006400330032002e00650078006500c664dae593a6bcd1d8eb01d0d200003457007e007b00460033003800420046003400300034002d0031004400340033002d0034003200460032002d0039003300300035002d003600370044004500300042003200380046004300320033007d005c0072006500670065006400690074002e00650078006500c664dae593a6bcd1d8eb01d0d2000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\$de${b3c64e62-475a-40e3-8873-5b5341f7f45a}$$windows.data.unifiedtile.localstartvolatiletilepropertiesmap\Current" /v "Data" /t REG_BINARY /d "020000007c3b67418f62d70100000000434201000d120a051257007e003300300038003000340036004200300041004600340041003300390043004200c70ad7c4223bc51401c61eb08e8cc4d1d1d8eb01001c57007e004d004900430052004f0053004f00460054002e00570049004e0044004f00570053002e004500580050004c004f00520045005200c70a3d2f8a3ac51402c61ee0a494e5f2d1d8eb01003457007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c004d0053005000410049004e0054002e00450058004500c70ab522b83ac61ecccabb87b8d1d8eb01003957007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c0053004e0049005000500049004e00470054004f004f004c002e00450058004500c70a5e1e213cc61ecccabb87b8d1d8eb01003457007e007b00460033003800420046003400300034002d0031004400340033002d0034003200460032002d0039003300300035002d003600370044004500300042003200380046004300320033007d005c0052004500470045004400490054002e00450058004500c70a8225b539c51401c61ec088958bf4d1d8eb010000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\$de${b3c64e62-475a-40e3-8873-5b5341f7f45a}$$windows.data.unifiedtile.roamedtilepropertiesmap\Current" /v "Data" /t REG_BINARY /d "0200000053baddc48b62d70100000000434201000d120a315550007e00770069006e0064006f00770073002e0069006d006d0065007200730069007600650063006f006e00740072006f006c00700061006e0065006c005f006300770035006e0031006800320074007800790065007700790021006d006900630072006f0073006f00660074002e00770069006e0064006f00770073002e0069006d006d0065007200730069007600650063006f006e00740072006f006c00700061006e0065006c000ac60af891f3a6bcd1d8eb01c2140100ca0a00004057007e004d006900630072006f0073006f00660074002e004100750074006f00470065006e006500720061007400650064002e007b00380041004100340037003300360035002d0042003200420033002d0031003900360031002d0036003900450042002d004600380036003600450033003700360042003100320046007d000ac60af891f3a6bcd1d8eb01c2140100ca0a00004057007e004d006900630072006f0073006f00660074002e004100750074006f00470065006e006500720061007400650064002e007b00380041004200440039003400460042002d0045003700440036002d0038003400410036002d0041003900390037002d004300390031003800450044004400450030004100450035007d000ac60af891f3a6bcd1d8eb01c2140100ca0a00004057007e004d006900630072006f0073006f00660074002e004100750074006f00470065006e006500720061007400650064002e007b00390032003300440044003400370037002d0035003800340036002d0036003800360042002d0041003600350039002d003000460043004300440037003300380035003100410038007d000ac60af891f3a6bcd1d8eb01c2140100ca0a00004057007e004d006900630072006f0073006f00660074002e004100750074006f00470065006e006500720061007400650064002e007b00420042003000340034004200460044002d0032003500420037002d0032004600410041002d0032003200410038002d003600330037003100410039003300450030003400350036007d000ac60af891f3a6bcd1d8eb01c2140100ca0a00004057007e004d006900630072006f0073006f00660074002e004100750074006f00470065006e006500720061007400650064002e007b00420044003300460039003200340045002d0035003500460042002d0041003100420041002d0039004400450036002d004200350030004600390046003200340036003000410043007d000ac60af891f3a6bcd1d8eb01c2140100ca0a00004057007e004d006900630072006f0073006f00660074002e004100750074006f00470065006e006500720061007400650064002e007b00430031004300360046003800410043002d0034003000410033002d0030004600350043002d0031003400360046002d003600350041003900440043003700300042004200420034007d000ac60af891f3a6bcd1d8eb01c2140100ca0a00004057007e004d006900630072006f0073006f00660074002e004100750074006f00470065006e006500720061007400650064002e007b00430038003000340042004200410037002d0046004100350046002d0043004200460037002d0038004200350035002d003200300039003600450035004600390037003200430042007d000ac60af891f3a6bcd1d8eb01c2140100ca0a00004057007e004d006900630072006f0073006f00660074002e004100750074006f00470065006e006500720061007400650064002e007b00440041004100310036003800440045002d0034003300300036002d0043003800420043002d0038004300310031002d004200350039003600320034003000420044004400450044007d000ac60af891f3a6bcd1d8eb01c2140100ca0a00002457007e004d006900630072006f0073006f00660074002e0049006e007400650072006e00650074004500780070006c006f007200650072002e00440065006600610075006c0074000ac60af891f3a6bcd1d8eb01c2140100ca0a00002757007e004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e00410064006d0069006e0069007300740072006100740069007600650054006f006f006c0073000ac60af891f3a6bcd1d8eb01c2140100ca0a00001c57007e004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e0043006f006d00700075007400650072000ac60af891f3a6bcd1d8eb01c2140100ca0a00002057007e004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e0043006f006e00740072006f006c00500061006e0065006c000ac60af891f3a6bcd1d8eb01c2140100ca0a00001c57007e004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e004500780070006c006f007200650072000ac60af891f3a6bcd1d8eb01c2140100ca0a00002157007e004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e004d00650064006900610050006c006100790065007200330032000ac60af891f3a6bcd1d8eb01c2140100ca0a00002157007e004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e00520065006d006f00740065004400650073006b0074006f0070000ac60af891f3a6bcd1d8eb01c2140100ca0a00002357007e004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e005300680065006c006c002e00520075006e004400690061006c006f0067000ac60af891f3a6bcd1d8eb01c2140100ca0a00003457007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c004d006400530063006800650064002e006500780065000ac60af891f3a6bcd1d8eb01c2140100ca0a00003a57007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c005200650063006f007600650072007900440072006900760065002e006500780065000ac60af891f3a6bcd1d8eb01c2140100ca0a00003957007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c0053006e0069007000700069006e00670054006f006f006c002e006500780065000ac60af891f3a6bcd1d8eb01c2140100ca0a00002f57007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c00570046002e006d00730063000ac60af891f3a6bcd1d8eb01c2140100ca0a00003057007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c005700460053002e006500780065000ac60af891f3a6bcd1d8eb01c2140100ca0a00005257007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c00570069006e0064006f007700730050006f007700650072005300680065006c006c005c00760031002e0030005c0050006f007700650072005300680065006c006c005f004900530045002e006500780065000ac60af891f3a6bcd1d8eb01c2140100ca0a00004e57007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c00570069006e0064006f007700730050006f007700650072005300680065006c006c005c00760031002e0030005c0070006f007700650072007300680065006c006c002e006500780065000ac60af891f3a6bcd1d8eb01c2140100ca0a00003457007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c0063006800610072006d00610070002e006500780065000ac60af891f3a6bcd1d8eb01c2140100ca0a00003557007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c0063006c00650061006e006d00670072002e006500780065000ac60af891f3a6bcd1d8eb01c2140100ca0a00003057007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c0063006d0064002e006500780065000ac60af891f3a6bcd1d8eb01c2140100ca0a00003357007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c0063006f006d006500780070002e006d00730063000ac60af891f3a6bcd1d8eb01c2140100ca0a00003357007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c006400660072006700750069002e006500780065000ac60af891f3a6bcd1d8eb01c2140100ca0a00003557007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c0069007300630073006900630070006c002e006500780065000ac60af891f3a6bcd1d8eb01c2140100ca0a00003457007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c006d00610067006e006900660079002e006500780065000ac60af891f3a6bcd1d8eb01c2140100ca0a00003557007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c006d00730063006f006e006600690067002e006500780065000ac60af891f3a6bcd1d8eb01c2140100ca0a00003557007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c006d00730069006e0066006f00330032002e006500780065000ac60af891f3a6bcd1d8eb01c2140100ca0a00003457007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c006d0073007000610069006e0074002e006500780065000ac60af891f3a6bcd1d8eb01c2140100ca0a00003557007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c006e00610072007200610074006f0072002e006500780065000ac60af891f3a6bcd1d8eb01c2140100ca0a00003457007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c006e006f00740065007000610064002e006500780065000ac60af891f3a6bcd1d8eb01c2140100ca0a00003557007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c006f0064006200630061006400330032002e006500780065000ac60af891f3a6bcd1d8eb01c2140100ca0a00003057007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c006f0073006b002e006500780065000ac60af891f3a6bcd1d8eb01c2140100ca0a00003c57007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c007000720069006e0074006d0061006e006100670065006d0065006e0074002e006d00730063000ac60af891f3a6bcd1d8eb01c2140100ca0a00003057007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c007000730072002e006500780065000ac60af891f3a6bcd1d8eb01c2140100ca0a00003857007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c0071007500690063006b006100730073006900730074002e006500780065000ac60af891f3a6bcd1d8eb01c2140100ca0a00003557007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c00730065007200760069006300650073002e006d00730063000ac60af891f3a6bcd1d8eb01c2140100ca0a00003657007e007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c00770069006e0033003200630061006c0063002e006500780065000ac60af891f3a6bcd1d8eb01c2140100ca0a00005257007e007b00360044003800300039003300370037002d0036004100460030002d0034003400340042002d0038003900350037002d004100330037003700330046003000320032003000300045007d005c0043006f006d006d006f006e002000460069006c00650073005c004d006900630072006f0073006f006600740020005300680061007200650064005c0049006e006b005c006d00690070002e006500780065000ac60af891f3a6bcd1d8eb01c2140100ca0a00004b57007e007b00360044003800300039003300370037002d0036004100460030002d0034003400340042002d0038003900350037002d004100330037003700330046003000320032003000300045007d005c00570069006e0064006f007700730020004e0054005c004100630063006500730073006f0072006900650073005c0077006f00720064007000610064002e006500780065000ac60af891f3a6bcd1d8eb01c2140100ca0a00005257007e007b00440036003500320033003100420030002d0042003200460031002d0034003800350037002d0041003400430045002d004100380045003700430036004500410037004400320037007d005c00570069006e0064006f007700730050006f007700650072005300680065006c006c005c00760031002e0030005c0050006f007700650072005300680065006c006c005f004900530045002e006500780065000ac60af891f3a6bcd1d8eb01c2140100ca0a00004e57007e007b00440036003500320033003100420030002d0042003200460031002d0034003800350037002d0041003400430045002d004100380045003700430036004500410037004400320037007d005c00570069006e0064006f007700730050006f007700650072005300680065006c006c005c00760031002e0030005c0070006f007700650072007300680065006c006c002e006500780065000ac60af891f3a6bcd1d8eb01c2140100ca0a00003557007e007b00440036003500320033003100420030002d0042003200460031002d0034003800350037002d0041003400430045002d004100380045003700430036004500410037004400320037007d005c006f0064006200630061006400330032002e006500780065000ac60af891f3a6bcd1d8eb01c2140100ca0a00003457007e007b00460033003800420046003400300034002d0031004400340033002d0034003200460032002d0039003300300035002d003600370044004500300042003200380046004300320033007d005c0072006500670065006400690074002e006500780065000ac60af891f3a6bcd1d8eb01c2140100ca0a000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\$de${b3c64e62-475a-40e3-8873-5b5341f7f45a}$$windows.data.unifiedtile.startglobalproperties\Current" /v "Data" /t REG_BINARY /d "020000005b9bd1c48b62d7010000000043420100cb320a0305ceabd3e90224daf40344c38a016682e58bb1aefdfdbb3c0005a08ffcc103248ad0034480990166b0b599dccdb097de4d00058691cc930524aaa30144c38401669ff79db187cbd1acd40100c23c01c55a0100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\$de${b3c64e62-475a-40e3-8873-5b5341f7f45a}$start.suggestions$windows.data.curatedtilecollection.tilecollection\Current" /v "Data" /t REG_BINARY /d "02000000bb0de1c48b62d70100000000434201000a0a00ca32000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\$de${b3c64e62-475a-40e3-8873-5b5341f7f45a}$start.tilegrid$windows.data.curatedtilecollection.tilecollection\Current" /v "Data" /t REG_BINARY /d "020000001399af058f62d70100000000434201000a0a00d0140cca3200d07804e22c01010000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\$microsoft.quiethoursprofile.unrestricted$windows.data.notifications.quiethoursprofile\Current" /v "Data" /t REG_BINARY /d "02000000a635a04a8d62d7010000000043420100c20a01cd140602050001010102010301040100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\$quietmoment0$windows.data.notifications.quietmoment\Current" /v "Data" /t REG_BINARY /d "02000000310956048f62d70100000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\$quietmoment1$windows.data.notifications.quietmoment\Current" /v "Data" /t REG_BINARY /d "0200000014b456048f62d70100000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\$quietmoment2$windows.data.notifications.quietmoment\Current" /v "Data" /t REG_BINARY /d "02000000af5057048f62d70100000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\$quietmoment4$windows.data.notifications.quietmoment\Current" /v "Data" /t REG_BINARY /d "020000006feb57048f62d70100000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\$quietmoment5$windows.data.notifications.quietmoment\Current" /v "Data" /t REG_BINARY /d "02000000959758048f62d70100000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\$quietmomentemergency$windows.data.notifications.quietmoment\Current" /v "Data" /t REG_BINARY /d "02000000aca757048f62d7010000000043420100c20a01c21401d21e284d006900630072006f0073006f00660074002e005100750069006500740048006f00750072007300500072006f00660069006c0065002e0055006e007200650073007400720069006300740065006400ca500000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\$quietmomentfullscreen$windows.data.notifications.quietmoment\Current" /v "Data" /t REG_BINARY /d "02000000744a58048f62d7010000000043420100c20a01c21401d21e264d006900630072006f0073006f00660074002e005100750069006500740048006f00750072007300500072006f00660069006c0065002e0041006c00610072006d0073004f006e006c007900c22801ca500000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\$quietmomentgame$windows.data.notifications.quietmoment\Current" /v "Data" /t REG_BINARY /d "02000000ea0657048f62d7010000000043420100c20a01c21401d21e284d006900630072006f0073006f00660074002e005100750069006500740048006f00750072007300500072006f00660069006c0065002e005000720069006f0072006900740079004f006e006c007900c22801ca500000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\$quietmomentpresentation$windows.data.notifications.quietmoment\Current" /v "Data" /t REG_BINARY /d "02000000367456048f62d7010000000043420100c20a01c21401d21e264d006900630072006f0073006f00660074002e005100750069006500740048006f00750072007300500072006f00660069006c0065002e0041006c00610072006d0073004f006e006c007900c22801ca500000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\$quietmomentscheduled$windows.data.notifications.quietmoment\Current" /v "Data" /t REG_BINARY /d "02000000958655048f62d7010000000043420100c20a01d21e284d006900630072006f0073006f00660074002e005100750069006500740048006f00750072007300500072006f00660069006c0065002e005000720069006f0072006900740079004f006e006c007900c22801d13280e0aa8a9930d13c80e0f6c5d50eca500000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\DefaultAccount\Cloud\default$windows.data.bluelightreduction.bluelightreductionstate\windows.data.bluelightreduction.bluelightreductionstate" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\DefaultAccount\Cloud\default$windows.data.bluelightreduction.settings\windows.data.bluelightreduction.settings" /v "Data" /t REG_BINARY /d "434201000a0026d1f3a6860600" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\DefaultAccount\Cloud\default$windows.data.input.devices.pensyncedsettings\windows.data.input.devices.pensyncedsettings" /v "Data" /t REG_BINARY /d "434201000a0026d0f3a6860600" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\DefaultAccount\CloudCacheInvalidator" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\DefaultAccount\Current\default$windows.data.bluelightreduction.bluelightreductionstate\windows.data.bluelightreduction.bluelightreductionstate" /v "Data" /t REG_BINARY /d "434201000a0201002a2a000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\DefaultAccount\Current\default$windows.data.bluelightreduction.settings\windows.data.bluelightreduction.settings" /v "Data" /t REG_BINARY /d "434201000a0201002a06d1f3a686062a2b0e1543420100ca140e1500ca1e0e0700ca3200ca3c0000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\DefaultAccount\Current\default$windows.data.globalization.culture.culturesettings\windows.data.globalization.culture.culturesettings" /v "Data" /t REG_BINARY /d "434201000a0201002a2a000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\DefaultAccount\Current\default$windows.data.input.devices.mousesyncedsettings\windows.data.input.devices.mousesyncedsettings" /v "Data" /t REG_BINARY /d "434201000a0201002a2a000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\DefaultAccount\Current\default$windows.data.input.devices.pensyncedsettings\windows.data.input.devices.pensyncedsettings" /v "Data" /t REG_BINARY /d "434201000a0201002a06d0f3a686062a2b0e0743420100020100000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\Store\DefaultAccount\Current\default$windows.data.input.devices.touchpadsyncedsettings\windows.data.input.devices.touchpadsyncedsettings" /v "Data" /t REG_BINARY /d "434201000a0201002a2a000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\SystemMetaData" /v "HasCuratedTileCollectionsInitialized" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore\StoreInit" /v "HasStoreCacheInitialized" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "FeatureManagementEnabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SlideshowEnabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "IdentityProvider" /t REG_SZ /d "{ED4515F3-DA33-4717-9228-3D8668614BE6}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\CreativeEvents\FeatureManagement" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\CreativeEvents\SubscribedContent-202914" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\CreativeEvents\SubscribedContent-280815" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\CreativeEvents\SubscribedContent-310091" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\CreativeEvents\SubscribedContent-310093" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\CreativeEvents\SubscribedContent-314559" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\CreativeEvents\SubscribedContent-338387" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\CreativeEvents\SubscribedContent-338388" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\CreativeEvents\SubscribedContent-338389" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\CreativeEvents\SubscribedContent-353694" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\CreativeEvents\SubscribedContent-353698" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\CreativeEvents\SubscribedContent-88000045" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\CreativeEvents\SubscribedContent-88000161" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\CreativeEvents\SubscribedContent-88000163" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\CreativeEvents\SubscribedContent-88000165" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Health\Placement-10" /v "HealthEvaluation" /t REG_BINARY /d "040000006e0074008c87e5e98b62d70102000200000000008c87e5e98b62d70101010000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Health\Placement-8" /v "HealthEvaluation" /t REG_BINARY /d "0400000000000000869cd9e98b62d7010200020000000000869cd9e98b62d70101010000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Health\Placement-SubscribedContent-202914" /ve /t REG_BINARY /d "040000000000000000000000000000002fc2891a9062d7010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Health\Placement-SubscribedContent-202914" /v "HealthEvaluation" /t REG_BINARY /d "0400000000000000869cd9e98b62d7010200020000000000869cd9e98b62d70101010000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Health\Placement-SubscribedContent-280815" /ve /t REG_BINARY /d "040000000000000000000000000000002fc2891a9062d7010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Health\Placement-SubscribedContent-280815" /v "HealthEvaluation" /t REG_BINARY /d "0400000000000000869cd9e98b62d7010200020000000000869cd9e98b62d70101010000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Health\Placement-SubscribedContent-310091" /ve /t REG_BINARY /d "04000000fa7f0000adb1d7108f62d7018010f38e9262d701803ae1108f62d7010000000000000000bfa272168f62d7010000000000000000000000000000000000000000000000000000000000000000000000000000000001010100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Health\Placement-SubscribedContent-310091" /v "HealthEvaluation" /t REG_BINARY /d "0400000000000000c3fedbe98b62d7010200020000000000c3fedbe98b62d70107010000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Health\Placement-SubscribedContent-310093" /ve /t REG_BINARY /d "04000000fa7f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Health\Placement-SubscribedContent-310093" /v "HealthEvaluation" /t REG_BINARY /d "0400000000000000c3fedbe98b62d7010200020000000000c3fedbe98b62d70101010000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Health\Placement-SubscribedContent-314559" /ve /t REG_BINARY /d "04000000fa7f000095c9fbea8b62d70176b2c7120c68d701101cc1625d81d80100000000000000004f28540b8c62d7018e52410b8c62d701000000000000000000000000000000000200000002000000000000000000000001000100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Health\Placement-SubscribedContent-314559" /v "HealthEvaluation" /t REG_BINARY /d "0400000000000000c3fedbe98b62d7010200020000000000c3fedbe98b62d70104010000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Health\Placement-SubscribedContent-338387" /ve /t REG_BINARY /d "04000000fa7f000000000000000000002fc2891a9062d7010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Health\Placement-SubscribedContent-338387" /v "HealthEvaluation" /t REG_BINARY /d "04000000000000008c87e5e98b62d70102000200000000008c87e5e98b62d70101010000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Health\Placement-SubscribedContent-338388" /ve /t REG_BINARY /d "04000000fa7f000000000000000000002fc2891a9062d7010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Health\Placement-SubscribedContent-338388" /v "HealthEvaluation" /t REG_BINARY /d "04000000000000008c87e5e98b62d70102000200000000008c87e5e98b62d70101010000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Health\Placement-SubscribedContent-338389" /ve /t REG_BINARY /d "04000000fa7f0000c08c4c148e62d70176b2c7120c68d70119efb882ecafe7010000000000000000d9637c278e62d7010000000000000000000000000000000000000000000000000100000001000000000000000000000001000100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Health\Placement-SubscribedContent-338389" /v "HealthEvaluation" /t REG_BINARY /d "04000000000000008c87e5e98b62d70102000200000000008c87e5e98b62d70103010000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Health\Placement-SubscribedContent-353694" /ve /t REG_BINARY /d "04000000fa7f000000000000000000002fc2891a9062d7010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Health\Placement-SubscribedContent-353694" /v "HealthEvaluation" /t REG_BINARY /d "04000000000000008c87e5e98b62d70102000200000000008c87e5e98b62d70101010000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Health\Placement-SubscribedContent-353698" /ve /t REG_BINARY /d "04000000fa7f000000000000000000002fc2891a9062d7010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Health\Placement-SubscribedContent-353698" /v "HealthEvaluation" /t REG_BINARY /d "04000000000000008c87e5e98b62d70102000200000000008c87e5e98b62d70101010000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Health\Placement-SubscribedContent-88000045" /ve /t REG_BINARY /d "04000000fa7f000000000000000000002fc2891a9062d7010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Health\Placement-SubscribedContent-88000045" /v "HealthEvaluation" /t REG_BINARY /d "04000000000000008c87e5e98b62d70102000200000000008c87e5e98b62d70101010000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Health\Placement-SubscribedContent-88000161" /ve /t REG_BINARY /d "04000000fa7f000000000000000000002fc2891a9062d7010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Health\Placement-SubscribedContent-88000161" /v "HealthEvaluation" /t REG_BINARY /d "04000000000000008c87e5e98b62d70102000200000000008c87e5e98b62d70101010000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Health\Placement-SubscribedContent-88000163" /ve /t REG_BINARY /d "04000000fa7f000000000000000000002fc2891a9062d7010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Health\Placement-SubscribedContent-88000163" /v "HealthEvaluation" /t REG_BINARY /d "04000000000000008c87e5e98b62d70102000200000000008c87e5e98b62d70101010000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Health\Placement-SubscribedContent-88000165" /ve /t REG_BINARY /d "04000000fa7f000000000000000000002fc2891a9062d7010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Health\Placement-SubscribedContent-88000165" /v "HealthEvaluation" /t REG_BINARY /d "04000000000000008c87e5e98b62d70102000200000000008c87e5e98b62d70101010000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Renderers\SubscribedContent-310091" /v "Version" /t REG_SZ /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Renderers\SubscribedContent-310092" /v "Version" /t REG_SZ /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Renderers\SubscribedContent-338380" /v "Version" /t REG_SZ /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Renderers\SubscribedContent-338381" /v "Version" /t REG_SZ /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Renderers\SubscribedContent-338387" /v "Version" /t REG_SZ /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Renderers\SubscribedContent-338388" /v "Version" /t REG_SZ /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions\310091" /v "ContentId" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions\310091" /v "ShortContentId" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions\310091" /v "Availability" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions\310091" /v "HasContent" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions\310091" /v "UpdateDrivenByExpiration" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions\314559" /v "ContentId" /t REG_SZ /d "6178388666`O_4AOYTTU0E003_4JMQAPESW8D7_4JMQAPESUISJ_4JMQAPESW8C7_4APOPFMFWEFO_4AZCW44IWOJI_4AXFDTC2S7AU_4AOYTTU0SI44_4JMQAPEQSAT2`5`nr76n983804r9ns03nnppp17sp86285o`86081555`869004`687443972655555555" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions\314559" /v "ShortContentId" /t REG_SZ /d "ae21a438359e4af58aaccc62fc31730b" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions\314559" /v "Availability" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions\314559" /v "HasContent" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions\314559" /v "UpdateDrivenByExpiration" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions\314559" /v "AvailabilityForAllContentIds" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions\338387" /v "SubscriptionContext" /t REG_SZ /d "sc-mode=0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions\338389" /v "ContentId" /t REG_SZ /d "6178389584`673555555556172954`5`p1p99qo37n46910oo370q778599r3631`159355`883834`682726299555555555" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions\338389" /v "ShortContentId" /t REG_SZ /d "c6c44db82a91465bb825d223044e8186" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions\338389" /v "Availability" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions\338389" /v "HasContent" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions\338389" /v "UpdateDrivenByExpiration" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /v "2FE3CB00.PicsArt-PhotoStudio_crhqpqs3x1ygc" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /v "5319275A.WhatsAppDesktop_cv1g1gvanyjgm" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /v "6F71D7A7.HotspotShieldFreeVPN_nsbqstbb9qxb6" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /v "828B5831.HiddenCityMysteryofShadows_ytsefhwckbdv6" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /v "9E2F88E3.Twitter_wgeqdkkx372wm" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /v "AdobeSystemsIncorporated.AdobePhotoshopExpress_ynb6jyjzte8ga" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /v "DolbyLaboratories.DolbyAccess_rz1tebttyb220" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /v "Facebook.317180B0BB486_8xx8rvfyw5nnt" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /v "Microsoft.BingNews_8wekyb3d8bbwe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /v "Microsoft.BingWeather_8wekyb3d8bbwe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /v "Microsoft.MSPaint_8wekyb3d8bbwe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /v "Microsoft.MicrosoftSolitaireCollection_8wekyb3d8bbwe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /v "Microsoft.Todos_8wekyb3d8bbwe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /v "Microsoft.YourPhone_8wekyb3d8bbwe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /v "Microsoft.ZuneVideo_8wekyb3d8bbwe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /v "Nordcurrent.CookingFever_m9bz608c1b9ra" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /v "PLRWorldwideSales.FishdomPlayrix_1feq88045d2v2" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /v "ROBLOXCorporation.ROBLOX_55nm5eh3cm0pr" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /v "SpotifyAB.SpotifyMusic_zpdnekdrzrea0" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Cortana" /v "IsAvailable" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceSetup" /v "AppInstallNotificationChangeStamp" /t REG_DWORD /d "84" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceSetup" /v "AppUninstallNotificationChangeStamp" /t REG_DWORD /d "32" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowFrequent" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ExplorerStartupTraceRecorded" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShellState" /t REG_BINARY /d "240000003e28000000000000000000000000000001000000130000000000000072000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "UserSignedIn" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "SIDUpdatedOnLibraries" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "LocalKnownFoldersMigrated" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "TelemetrySalt" /t REG_DWORD /d "5" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "FirstRunTelemetryComplete" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "AppReadinessLogonComplete" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "PostAppInstallTasksCompleted" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Accent" /v "StartColorMenu" /t REG_DWORD /d "4286390878" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Accent" /v "AccentColorMenu" /t REG_DWORD /d "4287768686" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Accent" /v "AccentPalette" /t REG_BINARY /d "88868aff834d9fff7b31a1ff6e2892ff5e227dff4f1d69ff3a154dff88179800" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_SearchFiles" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "StartMenuAdminTools" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ServerAdminUI" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCompColor" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DontPrettyPath" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowInfoTip" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideIcons" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "MapNetDrvBtn" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "WebView" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Filter" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "SeparateProcess" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "AutoCheckSelect" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTypeOverlay" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowStatusBar" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "StoreAppsOnTaskbar" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewAlphaSelect" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCortanaButton" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ReindexedProfile" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "StartMenuInit" /t REG_DWORD /d "13" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarStateLastRun" /t REG_BINARY /d "d8b9c96000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v "DisableAutoplay" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\BamThrottling" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\BannerStore" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\BitBucket" /v "LastEnum" /t REG_MULTI_SZ /d "0,{2b64f90c-9f96-46f1-a376-acf0a2cb369c}\00,{91a25c35-4f0b-4905-91dc-0593731c8f48}\00,{16c183b7-eb27-490c-a5bb-aa6eede5e4a9}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\BitBucket\Volume\{16c183b7-eb27-490c-a5bb-aa6eede5e4a9}" /v "MaxCapacity" /t REG_DWORD /d "25894" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\BitBucket\Volume\{16c183b7-eb27-490c-a5bb-aa6eede5e4a9}" /v "NukeOnDelete" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\BitBucket\Volume\{2b64f90c-9f96-46f1-a376-acf0a2cb369c}" /v "MaxCapacity" /t REG_DWORD /d "7765" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\BitBucket\Volume\{2b64f90c-9f96-46f1-a376-acf0a2cb369c}" /v "NukeOnDelete" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\BitBucket\Volume\{91a25c35-4f0b-4905-91dc-0593731c8f48}" /v "MaxCapacity" /t REG_DWORD /d "145126" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\BitBucket\Volume\{91a25c35-4f0b-4905-91dc-0593731c8f48}" /v "NukeOnDelete" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" /v "Settings" /t REG_BINARY /d "0c0002000a01000060000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" /v "FullPath" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\DefaultIcon" /ve /t REG_SZ /d "C:\Windows\System32\imageres.dll,-109" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CLSID\{59031A47-3F72-44A7-89C5-5595FE6B30EE}\DefaultIcon" /ve /t REG_SZ /d "C:\Windows\System32\imageres.dll,-123" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\DefaultIcon" /v "empty" /t REG_EXPAND_SZ /d "%%SystemRoot%%\System32\imageres.dll,-55" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\DefaultIcon" /v "full" /t REG_EXPAND_SZ /d "%%SystemRoot%%\System32\imageres.dll,-54" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\DefaultIcon" /ve /t REG_EXPAND_SZ /d "%%SystemRoot%%\System32\imageres.dll,-55" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CLSID\{871C5380-42A0-1069-A2EA-08002B30309D}\ShellFolder" /v "Attributes" /t REG_DWORD /d "1048576" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}\DefaultIcon" /ve /t REG_SZ /d "C:\Windows\System32\imageres.dll,-25" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\CIDSizeMRU" /v "MRUListEx" /t REG_BINARY /d "00000000ffffffff" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\CIDSizeMRU" /v "0" /t REG_BINARY /d "72006500670065006400690074002e00650078006500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000780000007800000038040000640200007e000000a8000000d40200009402000000000000000000000000000000000000000000000000000000000000000000000100000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRULegacy" /v "MRUListEx" /t REG_BINARY /d "00000000ffffffff" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRULegacy" /v "0" /t REG_BINARY /d "72006500670065006400690074002e00650078006500000014001f50e04fd020ea3a6910a2d808002b30309d19002f453a5c000000000000000000000000000000000000005a00310000000000d052c52b100052656769737472790000420009000400efbec552ef7ed05215492e0000003400000000000200000000000000000000000000000003b29f0052006500670069007300740072007900000018000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\*" /v "0" /t REG_BINARY /d "14001f50e04fd020ea3a6910a2d808002b30309d19002f453a5c000000000000000000000000000000000000005a00310000000000d052c52b100052656769737472790000420009000400efbec552ef7ed05215492e0000003400000000000200000000000000000000000000000003b29f0052006500670069007300740072007900000018006000320000000000000000008000484b435543502e7265670000460009000400efbe00000000000000002e000000000000000000000000000000000000000000000000000000000048004b0043005500430050002e0072006500670000001a000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\*" /v "MRUListEx" /t REG_BINARY /d "0100000000000000ffffffff" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\*" /v "1" /t REG_BINARY /d "14001f50e04fd020ea3a6910a2d808002b30309d19002f453a5c000000000000000000000000000000000000005a00310000000000d052c52b100052656769737472790000420009000400efbec552ef7ed05215492e0000003400000000000200000000000000000000000000000003b29f0052006500670069007300740072007900000018006000320000000000000000008000484b4355534d2e7265670000460009000400efbe00000000000000002e000000000000000000000000000000000000000000000000000000000048004b004300550053004d002e0072006500670000001a000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\reg" /v "0" /t REG_BINARY /d "14001f50e04fd020ea3a6910a2d808002b30309d19002f453a5c000000000000000000000000000000000000005a00310000000000d052c52b100052656769737472790000420009000400efbec552ef7ed05215492e0000003400000000000200000000000000000000000000000003b29f0052006500670069007300740072007900000018006000320000000000000000008000484b435543502e7265670000460009000400efbe00000000000000002e000000000000000000000000000000000000000000000000000000000048004b0043005500430050002e0072006500670000001a000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\reg" /v "MRUListEx" /t REG_BINARY /d "0100000000000000ffffffff" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\reg" /v "1" /t REG_BINARY /d "14001f50e04fd020ea3a6910a2d808002b30309d19002f453a5c000000000000000000000000000000000000005a00310000000000d052c52b100052656769737472790000420009000400efbec552ef7ed05215492e0000003400000000000200000000000000000000000000000003b29f0052006500670069007300740072007900000018006000320000000000000000008000484b4355534d2e7265670000460009000400efbe00000000000000002e000000000000000000000000000000000000000000000000000000000048004b004300550053004d002e0072006500670000001a000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Discardable\PostSetup\Component Categories\{00021493-0000-0000-C000-000000000046}\Enum" /v "Implementing" /t REG_BINARY /d "000000000000000000000000000000000000000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Discardable\PostSetup\Component Categories\{00021494-0000-0000-C000-000000000046}\Enum" /v "Implementing" /t REG_BINARY /d "000000000000000000000000000000000000000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Discardable\PostSetup\Component Categories64\{00021493-0000-0000-C000-000000000046}\Enum" /v "Implementing" /t REG_BINARY /d "1c00000001000000e50706000300100008002d0027001d0101000000644ea2ef78b0d01189e400c04fc9e26e" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Discardable\PostSetup\Component Categories64\{00021494-0000-0000-C000-000000000046}\Enum" /v "Implementing" /t REG_BINARY /d "1c00000001000000e50706000300100008002d002700a90100000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppLaunch" /v "308046B0AF4A39CB" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppLaunch" /v "Microsoft.Windows.Explorer" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched" /v "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\cmd.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched" /v "E:\Registry\RegCoolX64\RegCool.exe" /t REG_DWORD /d "5" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\ShowJumpView" /v "E:\Registry\RegCoolX64\RegCool.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.3g2\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.3g2\OpenWithProgids" /v "WMP11.AssocFile.3G2" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.3g2\UserChoice" /v "ProgId" /t REG_SZ /d "WMP11.AssocFile.3G2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.3g2\UserChoice" /v "Hash" /t REG_SZ /d "bjf1bIFm5EE=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.3gp\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.3gp\OpenWithProgids" /v "WMP11.AssocFile.3GP" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.3gp\UserChoice" /v "ProgId" /t REG_SZ /d "WMP11.AssocFile.3GP" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.3gp\UserChoice" /v "Hash" /t REG_SZ /d "eHnewkff7DE=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.3gp2\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.3gp2\OpenWithProgids" /v "WMP11.AssocFile.3G2" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.3gp2\UserChoice" /v "ProgId" /t REG_SZ /d "WMP11.AssocFile.3G2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.3gp2\UserChoice" /v "Hash" /t REG_SZ /d "EL5+aV+EG3A=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.3gpp\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.3gpp\OpenWithProgids" /v "WMP11.AssocFile.3GP" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.3gpp\UserChoice" /v "ProgId" /t REG_SZ /d "WMP11.AssocFile.3GP" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.3gpp\UserChoice" /v "Hash" /t REG_SZ /d "jV5ycKVoxrA=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.3mf\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.aac\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.aac\OpenWithProgids" /v "WMP11.AssocFile.ADTS" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.aac\UserChoice" /v "ProgId" /t REG_SZ /d "WMP11.AssocFile.ADTS" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.aac\UserChoice" /v "Hash" /t REG_SZ /d "0wlunoOrSV8=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.adt\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.adt\OpenWithProgids" /v "WMP11.AssocFile.ADTS" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.adt\UserChoice" /v "ProgId" /t REG_SZ /d "WMP11.AssocFile.ADTS" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.adt\UserChoice" /v "Hash" /t REG_SZ /d "i+nXO/fJJ8g=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.adts\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.adts\OpenWithProgids" /v "WMP11.AssocFile.ADTS" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.adts\UserChoice" /v "ProgId" /t REG_SZ /d "WMP11.AssocFile.ADTS" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.adts\UserChoice" /v "Hash" /t REG_SZ /d "vW+clMZbhRo=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.aif\OpenWithProgids" /v "WMP11.AssocFile.AIFF" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.aifc\OpenWithProgids" /v "WMP11.AssocFile.AIFF" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.aiff\OpenWithProgids" /v "WMP11.AssocFile.AIFF" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.arw\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.asf\OpenWithProgids" /v "WMP11.AssocFile.ASF" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.asx\OpenWithProgids" /v "WMP11.AssocFile.ASX" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.au\OpenWithProgids" /v "WMP11.AssocFile.AU" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.avi\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.avi\OpenWithProgids" /v "WMP11.AssocFile.AVI" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.avi\UserChoice" /v "ProgId" /t REG_SZ /d "WMP11.AssocFile.AVI" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.avi\UserChoice" /v "Hash" /t REG_SZ /d "6YKANoH4yco=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.bak\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.bat\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.bat\OpenWithProgids" /v "batfile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.bin\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.bmp\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.bmp\OpenWithProgids" /v "Paint.Picture" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.bmp\UserChoice" /v "ProgId" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.bmp\UserChoice" /v "Hash" /t REG_SZ /d "M8W+ss0zpcg=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.cab\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.cab\OpenWithProgids" /v "CABFolder" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.cdxml\OpenWithProgids" /v "Microsoft.PowerShellCmdletDefinitionXML.1" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.cfg\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.chm\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.chm\OpenWithProgids" /v "chm.file" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.cpl\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.cpl\OpenWithProgids" /v "cplfile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.cr2\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.crw\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.cs\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.css\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.css\OpenWithProgids" /v "CSSfile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.csv\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.dat\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.db\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.db\OpenWithProgids" /v "dbfile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.dds\OpenWithProgids" /v "ddsfile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.deskthemepack\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.deskthemepack\OpenWithProgids" /v "desktopthemepackfile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.dib\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.dib\OpenWithProgids" /v "Paint.Picture" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.dib\UserChoice" /v "ProgId" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.dib\UserChoice" /v "Hash" /t REG_SZ /d "4zG7hOhLAVA=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.dll\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.dll\OpenWithProgids" /v "dllfile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.dng\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.doc\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.docx\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.docx\OpenWithProgids" /v "docxfile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.emf\OpenWithProgids" /v "emffile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.erf\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.exe\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.exe\OpenWithProgids" /v "exefile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.flac\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.flac\OpenWithProgids" /v "WMP11.AssocFile.FLAC" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.flac\UserChoice" /v "ProgId" /t REG_SZ /d "WMP11.AssocFile.FLAC" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.flac\UserChoice" /v "Hash" /t REG_SZ /d "JHZsR6BNnAM=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.fon\OpenWithProgids" /v "fonfile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.gif\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.gif\OpenWithProgids" /v "giffile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.gif\UserChoice" /v "ProgId" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.gif\UserChoice" /v "Hash" /t REG_SZ /d "7+MpEjuqlHs=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.htm\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.htm\OpenWithProgids" /v "htmlfile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.htm\UserChoice" /v "ProgId" /t REG_SZ /d "FirefoxHTML-308046B0AF4A39CB" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.htm\UserChoice" /v "Hash" /t REG_SZ /d "uRb5/p8Ycfs=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.html\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.html\OpenWithProgids" /v "htmlfile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.html\UserChoice" /v "ProgId" /t REG_SZ /d "FirefoxHTML-308046B0AF4A39CB" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.html\UserChoice" /v "Hash" /t REG_SZ /d "Lw1smbJzrwk=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.ico\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.ico\OpenWithProgids" /v "icofile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.ico\UserChoice" /v "ProgId" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.ico\UserChoice" /v "Hash" /t REG_SZ /d "A4lLpfCnSpQ=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.idx\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.inf\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.inf\OpenWithProgids" /v "inffile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.ini\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.ini\OpenWithProgids" /v "inifile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.ipa\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.iso\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.iso\OpenWithProgids" /v "Windows.IsoFile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.itc2\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.itdb\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.itl\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jfif\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jfif\OpenWithProgids" /v "pjpegfile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jfif\UserChoice" /v "ProgId" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jfif\UserChoice" /v "Hash" /t REG_SZ /d "iEnYOprIWis=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpe\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpe\OpenWithProgids" /v "jpegfile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpe\UserChoice" /v "ProgId" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpe\UserChoice" /v "Hash" /t REG_SZ /d "8lFrpRi/Css=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpeg\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpeg\OpenWithProgids" /v "jpegfile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpeg\UserChoice" /v "ProgId" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpeg\UserChoice" /v "Hash" /t REG_SZ /d "YQbrFV94xhg=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpg\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpg\OpenWithProgids" /v "jpegfile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpg\UserChoice" /v "ProgId" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpg\UserChoice" /v "Hash" /t REG_SZ /d "oqXnJPB1G1E=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jps\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.js\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.js\OpenWithProgids" /v "JSFile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.json\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jxr\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jxr\OpenWithProgids" /v "wdpfile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jxr\UserChoice" /v "ProgId" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jxr\UserChoice" /v "Hash" /t REG_SZ /d "LuTK2k53K3g=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.kdc\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.lnk\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.lnk\OpenWithProgids" /v "lnkfile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.log\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.log\OpenWithProgids" /v "txtfile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.m1v\OpenWithProgids" /v "WMP11.AssocFile.MPEG" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.m2t\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.m2t\OpenWithProgids" /v "WMP11.AssocFile.M2TS" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.m2t\UserChoice" /v "ProgId" /t REG_SZ /d "WMP11.AssocFile.M2TS" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.m2t\UserChoice" /v "Hash" /t REG_SZ /d "tP7bxKbNXfI=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.m2ts\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.m2ts\OpenWithProgids" /v "WMP11.AssocFile.M2TS" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.m2ts\UserChoice" /v "ProgId" /t REG_SZ /d "WMP11.AssocFile.M2TS" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.m2ts\UserChoice" /v "Hash" /t REG_SZ /d "6ceYve29wro=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.M2V\OpenWithProgids" /v "WMP11.AssocFile.MPEG" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.m3u\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.m3u\OpenWithProgids" /v "WMP11.AssocFile.m3u" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.m3u\UserChoice" /v "ProgId" /t REG_SZ /d "WMP11.AssocFile.m3u" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.m3u\UserChoice" /v "Hash" /t REG_SZ /d "SNtJ0MPvqJU=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.m4a\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.m4a\OpenWithProgids" /v "WMP11.AssocFile.M4A" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.m4a\UserChoice" /v "ProgId" /t REG_SZ /d "WMP11.AssocFile.M4A" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.m4a\UserChoice" /v "Hash" /t REG_SZ /d "UEbZu717mwg=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.m4v\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.m4v\OpenWithProgids" /v "WMP11.AssocFile.MP4" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.m4v\UserChoice" /v "ProgId" /t REG_SZ /d "WMP11.AssocFile.MP4" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.m4v\UserChoice" /v "Hash" /t REG_SZ /d "u620vOtPFJ0=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.map\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mdb\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mht\OpenWithProgids" /v "mhtmlfile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mhtml\OpenWithProgids" /v "mhtmlfile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mid\OpenWithProgids" /v "WMP11.AssocFile.MIDI" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.midi\OpenWithProgids" /v "WMP11.AssocFile.MIDI" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mk3d\OpenWithProgids" /v "WMP11.AssocFile.MK3D" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mka\OpenWithProgids" /v "WMP11.AssocFile.MKA" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mkv\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mkv\OpenWithProgids" /v "WMP11.AssocFile.MKV" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mkv\UserChoice" /v "ProgId" /t REG_SZ /d "WMP11.AssocFile.MKV" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mkv\UserChoice" /v "Hash" /t REG_SZ /d "+4NViyy8EdQ=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mod\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mod\OpenWithProgids" /v "WMP11.AssocFile.MPEG" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mod\UserChoice" /v "ProgId" /t REG_SZ /d "WMP11.AssocFile.MPEG" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mod\UserChoice" /v "Hash" /t REG_SZ /d "Kp2F1eHcHJE=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mov\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mov\OpenWithProgids" /v "WMP11.AssocFile.MOV" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mov\UserChoice" /v "ProgId" /t REG_SZ /d "WMP11.AssocFile.MOV" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mov\UserChoice" /v "Hash" /t REG_SZ /d "PzTcbpZtUvg=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.MP2\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.MP2\OpenWithProgids" /v "WMP11.AssocFile.MP3" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.MP2\UserChoice" /v "ProgId" /t REG_SZ /d "WMP11.AssocFile.MP3" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.MP2\UserChoice" /v "Hash" /t REG_SZ /d "KPCdPPWTcB4=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mp2v\OpenWithProgids" /v "WMP11.AssocFile.MPEG" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mp3\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mp3\OpenWithProgids" /v "WMP11.AssocFile.MP3" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mp3\UserChoice" /v "ProgId" /t REG_SZ /d "WMP11.AssocFile.MP3" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mp3\UserChoice" /v "Hash" /t REG_SZ /d "cLdME7t4DBk=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mp4\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mp4\OpenWithProgids" /v "WMP11.AssocFile.MP4" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mp4\UserChoice" /v "ProgId" /t REG_SZ /d "WMP11.AssocFile.MP4" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mp4\UserChoice" /v "Hash" /t REG_SZ /d "vLlbvzAKoUU=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mp4v\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mp4v\OpenWithProgids" /v "WMP11.AssocFile.MP4" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mp4v\UserChoice" /v "ProgId" /t REG_SZ /d "WMP11.AssocFile.MP4" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mp4v\UserChoice" /v "Hash" /t REG_SZ /d "egpT+2CRbH0=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mpa\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mpa\OpenWithProgids" /v "WMP11.AssocFile.MPEG" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mpa\UserChoice" /v "ProgId" /t REG_SZ /d "WMP11.AssocFile.MPEG" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mpa\UserChoice" /v "Hash" /t REG_SZ /d "Hxqsd6j6ZDA=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.MPE\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.MPE\OpenWithProgids" /v "WMP11.AssocFile.MPEG" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.MPE\UserChoice" /v "ProgId" /t REG_SZ /d "WMP11.AssocFile.MPEG" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.MPE\UserChoice" /v "Hash" /t REG_SZ /d "ZF9mPnKerpE=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mpeg\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mpeg\OpenWithProgids" /v "WMP11.AssocFile.MPEG" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mpeg\UserChoice" /v "ProgId" /t REG_SZ /d "WMP11.AssocFile.MPEG" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mpeg\UserChoice" /v "Hash" /t REG_SZ /d "gmV3xzwMl30=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mpg\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mpg\OpenWithProgids" /v "WMP11.AssocFile.MPEG" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mpg\UserChoice" /v "ProgId" /t REG_SZ /d "WMP11.AssocFile.MPEG" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mpg\UserChoice" /v "Hash" /t REG_SZ /d "js9qJyl5hrs=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mpv2\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mpv2\OpenWithProgids" /v "WMP11.AssocFile.MPEG" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mpv2\UserChoice" /v "ProgId" /t REG_SZ /d "WMP11.AssocFile.MPEG" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mpv2\UserChoice" /v "Hash" /t REG_SZ /d "G2vv5JXWJYE=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mrw\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.msi\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.msi\OpenWithProgids" /v "Msi.Package" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mts\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mts\OpenWithProgids" /v "WMP11.AssocFile.M2TS" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mts\UserChoice" /v "ProgId" /t REG_SZ /d "WMP11.AssocFile.M2TS" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.mts\UserChoice" /v "Hash" /t REG_SZ /d "BZiaBarf0PM=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.nef\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.nfo\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.nfo\OpenWithProgids" /v "MSInfoFile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.nrw\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.obj\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.ocx\OpenWithProgids" /v "ocxfile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.odc\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.odt\OpenWithProgids" /v "odtfile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.one\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.onetoc2\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.orf\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.otf\OpenWithProgids" /v "otffile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pdf\UserChoice" /v "ProgId" /t REG_SZ /d "AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pdf\UserChoice" /v "Hash" /t REG_SZ /d "5QGHy/pBm8g=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pef\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pls\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.png\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.png\OpenWithProgids" /v "pngfile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.png\UserChoice" /v "ProgId" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.png\UserChoice" /v "Hash" /t REG_SZ /d "JGYWQ5DK2B4=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.ppt\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pptx\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.ps1\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.ps1\OpenWithProgids" /v "Microsoft.PowerShellScript.1" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.ps1xml\OpenWithProgids" /v "Microsoft.PowerShellXMLData.1" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.psd\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.psd1\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.psd1\OpenWithProgids" /v "Microsoft.PowerShellData.1" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.psm1\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.psm1\OpenWithProgids" /v "Microsoft.PowerShellModule.1" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pssc\OpenWithProgids" /v "Microsoft.PowerShellSessionConfiguration.1" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.pst\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.rar\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.raw\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.reg\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.reg\OpenWithProgids" /v "regfile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.rle\OpenWithProgids" /v "rlefile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.rmi\OpenWithProgids" /v "WMP11.AssocFile.MIDI" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.rtf\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.rtf\OpenWithProgids" /v "rtffile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.rw2\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.rwl\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.scf\OpenWithProgids" /v "SHCmdFile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.scp\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.scp\OpenWithProgids" /v "txtfile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.search-ms\OpenWithProgids" /v "SearchFolder" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.shtml\OpenWithProgids" /v "shtmlfile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.snd\OpenWithProgids" /v "WMP11.AssocFile.AU" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.sr2\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.srw\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.stl\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.swf\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.sys\OpenWithProgids" /v "sysfile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.tif\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.tif\OpenWithProgids" /v "TIFImage.Document" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.tif\UserChoice" /v "ProgId" /t REG_SZ /d "TIFImage.Document" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.tif\UserChoice" /v "Hash" /t REG_SZ /d "VMQgD7BCGpA=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.tiff\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.tiff\OpenWithProgids" /v "TIFImage.Document" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.tiff\UserChoice" /v "ProgId" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.tiff\UserChoice" /v "Hash" /t REG_SZ /d "RoT74CHytGA=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.tmp\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.TS\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.TS\OpenWithProgids" /v "WMP11.AssocFile.TTS" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.TS\UserChoice" /v "ProgId" /t REG_SZ /d "WMP11.AssocFile.TTS" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.TS\UserChoice" /v "Hash" /t REG_SZ /d "SYDOWdv5ffs=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.ttc\OpenWithProgids" /v "ttcfile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.ttf\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.ttf\OpenWithProgids" /v "ttffile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.TTS\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.TTS\OpenWithProgids" /v "WMP11.AssocFile.TTS" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.TTS\UserChoice" /v "ProgId" /t REG_SZ /d "WMP11.AssocFile.TTS" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.TTS\UserChoice" /v "Hash" /t REG_SZ /d "JfmGeBAnpxo=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.txt\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.txt\OpenWithProgids" /v "txtfile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.txt\UserChoice" /v "ProgId" /t REG_SZ /d "txtfile" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.txt\UserChoice" /v "Hash" /t REG_SZ /d "wfZr3M3TSgs=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.url\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.url\OpenWithProgids" /v "InternetShortcut" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.url\UserChoice" /v "ProgId" /t REG_SZ /d "IE.AssocFile.URL" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.url\UserChoice" /v "Hash" /t REG_SZ /d "7LsRAz/bobk=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.vbs\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.vbs\OpenWithProgids" /v "VBSFile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.vssettings\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.wav\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.wav\OpenWithProgids" /v "WMP11.AssocFile.WAV" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.wav\UserChoice" /v "ProgId" /t REG_SZ /d "WMP11.AssocFile.WAV" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.wav\UserChoice" /v "Hash" /t REG_SZ /d "OgXma9QD29w=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.wax\OpenWithProgids" /v "WMP11.AssocFile.WAX" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.wdp\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.wdp\OpenWithProgids" /v "wdpfile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.webp\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.website\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.website\OpenWithProgids" /v "Microsoft.Website" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.website\UserChoice" /v "ProgId" /t REG_SZ /d "IE.AssocFile.WEBSITE" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.website\UserChoice" /v "Hash" /t REG_SZ /d "59S+8u7sxaA=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.wm\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.wm\OpenWithProgids" /v "WMP11.AssocFile.ASF" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.wm\UserChoice" /v "ProgId" /t REG_SZ /d "WMP11.AssocFile.ASF" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.wm\UserChoice" /v "Hash" /t REG_SZ /d "lpkkLPgYx0I=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.wma\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.wma\OpenWithProgids" /v "WMP11.AssocFile.WMA" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.wma\UserChoice" /v "ProgId" /t REG_SZ /d "WMP11.AssocFile.WMA" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.wma\UserChoice" /v "Hash" /t REG_SZ /d "hJUjr2i1fSs=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.wmf\OpenWithProgids" /v "wmffile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.wmv\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.wmv\OpenWithProgids" /v "WMP11.AssocFile.WMV" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.wmv\UserChoice" /v "ProgId" /t REG_SZ /d "WMP11.AssocFile.WMV" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.wmv\UserChoice" /v "Hash" /t REG_SZ /d "vI6PJ4BlVlY=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.wmx\OpenWithProgids" /v "WMP11.AssocFile.ASX" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.WPL\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.WPL\OpenWithProgids" /v "WMP11.AssocFile.WPL" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.WPL\UserChoice" /v "ProgId" /t REG_SZ /d "WMP11.AssocFile.WPL" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.WPL\UserChoice" /v "Hash" /t REG_SZ /d "DQjmaxijHNw=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.wsb\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.wtx\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.wtx\OpenWithProgids" /v "txtfile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.wvx\OpenWithProgids" /v "WMP11.AssocFile.WVX" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.xls\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.xlsx\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.xml\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.xml\OpenWithProgids" /v "xmlfile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.xsl\OpenWithProgids" /v "xslfile" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.zip\OpenWithList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.zip\OpenWithProgids" /v "CompressedFolder" /t REG_NONE /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\LogonStats" /v "FirstLogonTime" /t REG_BINARY /d "e50706000300100008002b003a005600" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\LogonStats" /v "FirstLogonTimeOnCurrentInstallation" /t REG_BINARY /d "e50706000300100008002b003a005600" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\LowRegistry" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MenuOrder\Favorites" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Modules\CommonPlaces" /v "Order" /t REG_BINARY /d "08000000020000008c0400000100000006000000c200000000000000b40073002200434653461c003200760100002835f6aa2000444f43554d457e312e4c4e4b00000000741a595e96dfd3488d671733bcee28baa66c4ad3c262344c8a7c14709c1ad9386c0007000400efbe1e3572a91e3572a926000000dca80000000003000000000000000000420044006f00630075006d0065006e00740073002e006c006e006b00000040007300680065006c006c00330032002e0064006c006c002c002d003200310037003700300000004800000000000000b600000002000000a80073001e0043465346180032006a0100002835f6aa20004d757369632e6c6e6b000000741a595e96dfd3488d671733bcee28baa66c4ad3c262344c8a7c14709c1ad938640007000400efbe1e3571a91e3571a926000000daa800000000030000000000000000003a004d0075007300690063002e006c006e006b00000040007300680065006c006c00330032002e0064006c006c002c002d003200310037003900300000004400000000000000c000000001000000b20073002200434653461c003200730100002835f6aa200050696374757265732e6c6e6b00000000741a595e96dfd3488d671733bcee28baa66c4ad3c262344c8a7c14709c1ad9386a0007000400efbe1e3571a91e3571a926000000dba800000000030000000000000000004000500069006300740075007200650073002e006c006e006b00000040007300680065006c006c00330032002e0064006c006c002c002d003200310037003700390000004800000000000000ba00000005000000ac0073002000434653461a0032003c0100002835f6aa20005075626c69632e6c6e6b00000000741a595e96dfd3488d671733bcee28baa66c4ad3c262344c8a7c14709c1ad938660007000400efbe2835f6aa2835f6aa26000000b5b300000000080000000000000000003c005000750062006c00690063002e006c006e006b00000040007300680065006c006c00330032002e0064006c006c002c002d003200310038003100360000004600000000000000d000000003000000c20073002200434653461c003200560200002835f6aa2000524543454e547e312e4c4e4b00000000741a595e96dfd3488d671733bcee28baa66c4ad3c262344c8a7c14709c1ad9387a0007000400efbe1e3571a91e3571a926000000d9a80000000003000000000000000000500052006500630065006e0074006c00790020004300680061006e006700650064002e006c006e006b00000040007300680065006c006c00330032002e0064006c006c002c002d003300320038003100330000004800000000000000be00000004000000b00073002200434653461c003200630100002835f6aa200053656172636865732e6c6e6b00000000741a595e96dfd3488d671733bcee28baa66c4ad3c262344c8a7c14709c1ad938680007000400efbe1e3571a91e3571a926000000d8a800000000030000000000000000004000530065006100720063006800650073002e006c006e006b00000040007300680065006c006c00330032002e0064006c006c002c002d00390030003300310000004800000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Modules\CommonPlaces\CFD" /v "Order" /t REG_BINARY /d "08000000020000000a0700000100000009000000c200000003000000b40073002200434653461c003200760100002835f6aa2000444f43554d457e312e4c4e4b00000000741a595e96dfd3488d671733bcee28baa66c4ad3c262344c8a7c14709c1ad9386c0007000400efbe1e3572a91e3572a926000000dca80000000003000000000000000000420044006f00630075006d0065006e00740073002e006c006e006b00000040007300680065006c006c00330032002e0064006c006c002c002d003200310037003700300000004800000000000000b600000005000000a80073001e0043465346180032006a0100002835f6aa20004d757369632e6c6e6b000000741a595e96dfd3488d671733bcee28baa66c4ad3c262344c8a7c14709c1ad938640007000400efbe1e3571a91e3571a926000000daa800000000030000000000000000003a004d0075007300690063002e006c006e006b00000040007300680065006c006c00330032002e0064006c006c002c002d003200310037003900300000004400000000000000c000000004000000b20073002200434653461c003200730100002835f6aa200050696374757265732e6c6e6b00000000741a595e96dfd3488d671733bcee28baa66c4ad3c262344c8a7c14709c1ad9386a0007000400efbe1e3571a91e3571a926000000dba800000000030000000000000000004000500069006300740075007200650073002e006c006e006b00000040007300680065006c006c00330032002e0064006c006c002c002d003200310037003700390000004800000000000000ba00000008000000ac0073002000434653461a0032003c0100002835f6aa20005075626c69632e6c6e6b00000000741a595e96dfd3488d671733bcee28baa66c4ad3c262344c8a7c14709c1ad938660007000400efbe2835f6aa2835f6aa26000000b5b300000000080000000000000000003c005000750062006c00690063002e006c006e006b00000040007300680065006c006c00330032002e0064006c006c002c002d003200310038003100360000004600000000000000d000000006000000c20073002200434653461c003200560200002835f6aa2000524543454e547e312e4c4e4b00000000741a595e96dfd3488d671733bcee28baa66c4ad3c262344c8a7c14709c1ad9387a0007000400efbe1e3571a91e3571a926000000d9a80000000003000000000000000000500052006500630065006e0074006c00790020004300680061006e006700650064002e006c006e006b00000040007300680065006c006c00330032002e0064006c006c002c002d003300320038003100330000004800000000000000be00000007000000b00073002200434653461c003200630100002835f6aa200053656172636865732e6c6e6b00000000741a595e96dfd3488d671733bcee28baa66c4ad3c262344c8a7c14709c1ad938680007000400efbe1e3571a91e3571a926000000d8a800000000030000000000000000004000530065006100720063006800650073002e006c006e006b00000040007300680065006c006c00330032002e0064006c006c002c002d00390030003300310000004800000000000000e200000001000000d3000000cd00ded1ec23bf00040000000000490000003153505330f125b7ef471a10a5f102608c9eebac2d0000000a00000000080000001c00000052006500630065006e007400200050006c0061006300650073000000000000002d00000031535053a66a63283d95d211b5d600c04fd918d0110000001a000000000300000000000020000000004500000031535053fcb3b4b9512b424ab5d8324146afcf25290000000200000000111000001600000014001f806d7a8722a1371a4691b0dbda5aaebc99000000000000000000000000000000000000000000c200000000000000b3000000ad00ded1ec239f000400000000003d0000003153505330f125b7ef471a10a5f102608c9eebac210000000a0000000008000000100000004400650073006b0074006f0070000000000000002d00000031535053a66a63283d95d211b5d600c04fd918d0110000001a000000000300000001000020000000003100000031535053fcb3b4b9512b424ab5d8324146afcf251500000002000000001110000002000000000000000000000000000000000000000000000000da00000002000000cb000000c500ded1ec23b700040000000000410000003153505330f125b7ef471a10a5f102608c9eebac250000000a00000000080000001200000043006f006d007000750074006500720000000000000000002d00000031535053a66a63283d95d211b5d600c04fd918d0110000001a000000000300000002000020000000004500000031535053fcb3b4b9512b424ab5d8324146afcf25290000000200000000111000001600000014001f50e04fd020ea3a6910a2d808002b30309d000000000000000000000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Modules\GlobalSettings\ProperTreeModuleInner" /v "ProperTreeModuleInner" /t REG_BINARY /d "94000000900000003153505305d5cdd59c2e1b10939708002b2cf9ae4100000030000000004e0061007600500061006e0065005f00530068006f0077004c00690062007200610072007900500061006e00650000000b000000ffff00003300000022000000004e0061007600500061006e0065005f0046006900720073007400520075006e0000000b000000000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Modules\NavPane" /v "ExpandedState" /t REG_BINARY /d "06000000160014001f80cb859f6720028040b29b5540cc05aab60000010000004d0000001c00000031535053a66a63283d95d211b5d600c04fd918d0000000002d00000031535053357ec777e31b5043a48c7563d727776d1100000002000000000b000000ffff00000000000000000000160014001f60983ffbb4eac18d42a78ad1f5659cba930000010000004d0000001c00000031535053a66a63283d95d211b5d600c04fd918d0000000002d00000031535053357ec777e31b5043a48c7563d727776d1100000002000000000b000000ffff00000000000000000000160014001f580d1a2cf021be504388b07367fc96ef3c0000010000004d0000001c00000031535053a66a63283d95d211b5d600c04fd918d0000000002d00000031535053357ec777e31b5043a48c7563d727776d1100000002000000000b000000000000000000000000000000570055001f002f0010b7a6f519002f473a5c00000000000000000000000000000000000000000000000000000000000000000000000000741a595e96dfd3488d671733bcee28ba772cfbf52f0e164aa3813e560c68bc830000010000004d0000001c00000031535053a66a63283d95d211b5d600c04fd918d0000000002d00000031535053357ec777e31b5043a48c7563d727776d1100000002000000000b000000000000000000000000000000570055001f002f0010b7a6f519002f463a5c00000000000000000000000000000000000000000000000000000000000000000000000000741a595e96dfd3488d671733bcee28ba772cfbf52f0e164aa3813e560c68bc830000010000004d0000001c00000031535053a66a63283d95d211b5d600c04fd918d0000000002d00000031535053357ec777e31b5043a48c7563d727776d1100000002000000000b000000000000000000000000000000160014001f50e04fd020ea3a6910a2d808002b30309d0000010000004d0000001c00000031535053a66a63283d95d211b5d600c04fd918d0000000002d00000031535053357ec777e31b5043a48c7563d727776d1100000002000000000b000000000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\CPC\Volume\{16c183b7-eb27-490c-a5bb-aa6eede5e4a9}" /v "Data" /t REG_BINARY /d "d60d00000df0adba01000000080000000000008000000000000000300000000000000000ff06e703ff00000016000000a8105a6e1f000000040000000b0000000000000000000000000000000000000000005c005c003f005c00530054004f005200410047004500230056006f006c0075006d00650023007b00330038006300330061003700650036002d0063006500630061002d0031003100650062002d0061006400610033002d003800300036006500360066003600650036003900360033007d002300300030003000300030003000300030003000310031003000300030003000300023007b00350033006600350036003300300064002d0062003600620066002d0031003100640030002d0039003400660032002d003000300061003000630039003100650066006200380062007d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005c005c003f005c0056006f006c0075006d0065007b00310036006300310038003300620037002d0065006200320037002d0034003900300063002d0061003500620062002d006100610036006500650064006500350065003400610039007d005c00000057006f0072006b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004e005400460053000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffff0000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\CPC\Volume\{16c183b7-eb27-490c-a5bb-aa6eede5e4a9}" /v "Generation" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\CPC\Volume\{2b64f90c-9f96-46f1-a376-acf0a2cb369c}" /v "Data" /t REG_BINARY /d "d60d00000df0adba41000000080000000000008000000000000000300000000000000000ff06e703ff000000160000009a7b06861f000000044000000b0000000000000000000000000000000000000000005c005c003f005c00530054004f005200410047004500230056006f006c0075006d00650023007b00330038006300330061003700650034002d0063006500630061002d0031003100650062002d0061006400610033002d003800300036006500360066003600650036003900360033007d002300300030003000300030003000300030003000370035003000300030003000300023007b00350033006600350036003300300064002d0062003600620066002d0031003100640030002d0039003400660032002d003000300061003000630039003100650066006200380062007d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005c005c003f005c0056006f006c0075006d0065007b00320062003600340066003900300063002d0039006600390036002d0034003600660031002d0061003300370036002d006100630066003000610032006300620033003600390063007d005c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004e005400460053000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffff0000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\CPC\Volume\{2b64f90c-9f96-46f1-a376-acf0a2cb369c}" /v "Generation" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\CPC\Volume\{38c3a7ee-ceca-11eb-ada3-806e6f6e6963}" /v "Data" /t REG_BINARY /d "d60d00000df0adba0100000004000000000000840000000000000030000000000000000006020200ff000000100000000000214e1e00000004004000070000000000000000000000000000000000000000005c005c003f005c00530054004f005200410047004500230056006f006c0075006d00650023005f003f003f005f00550053004200530054004f00520023004400690073006b002600560065006e005f00530061006e004400690073006b002600500072006f0064005f0055006c0074007200610026005200650076005f0031002e00300030002300340043003500330030003000300031003200360030003700300031003100310033003400330031002600300023007b00350033006600350036003300300037002d0062003600620066002d0031003100640030002d0039003400660032002d003000300061003000630039003100650066006200380062007d0023007b00350033006600350036003300300064002d0062003600620066002d0031003100640030002d0039003400660032002d003000300061003000630039003100650066006200380062007d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005c005c003f005c0056006f006c0075006d0065007b00330038006300330061003700650065002d0063006500630061002d0031003100650062002d0061006400610033002d003800300036006500360066003600650036003900360033007d005c000000560065006e0074006f00790000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000065007800460041005400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffff0000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\CPC\Volume\{38c3a7ee-ceca-11eb-ada3-806e6f6e6963}" /v "Generation" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\CPC\Volume\{38c3a7ef-ceca-11eb-ada3-806e6f6e6963}" /v "Data" /t REG_BINARY /d "d60d00000df0adba0100000004000000000000840000000000000030000000000000000006020200ff00000010000000b9cf3b131e00000004004000070000000000000000000000000000000000000000005c005c003f005c00530054004f005200410047004500230056006f006c0075006d00650023007b00330038006300330061003700650033002d0063006500630061002d0031003100650062002d0061006400610033002d003800300036006500360066003600650036003900360033007d002300300030003000300030003000300037003300430030003000300030003000300023007b00350033006600350036003300300064002d0062003600620066002d0031003100640030002d0039003400660032002d003000300061003000630039003100650066006200380062007d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005c005c003f005c0056006f006c0075006d0065007b00330038006300330061003700650066002d0063006500630061002d0031003100650062002d0061006400610033002d003800300036006500360066003600650036003900360033007d005c000000560054004f0059004500460049000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000046004100540000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffff0000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\CPC\Volume\{38c3a7ef-ceca-11eb-ada3-806e6f6e6963}" /v "Generation" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\CPC\Volume\{91a25c35-4f0b-4905-91dc-0593731c8f48}" /v "Data" /t REG_BINARY /d "d60d00000df0adba01000000080000000000008000000000000000300000000000000000ff06e703ff00000016000000a318511e1f000000040000000b0000000000000000000000000000000000000000005c005c003f005c00530054004f005200410047004500230056006f006c0075006d00650023007b00330038006300330061003700650035002d0063006500630061002d0031003100650062002d0061006400610033002d003800300036006500360066003600650036003900360033007d002300300030003000300030003000300030003000310031003000300030003000300023007b00350033006600350036003300300064002d0062003600620066002d0031003100640030002d0039003400660032002d003000300061003000630039003100650066006200380062007d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005c005c003f005c0056006f006c0075006d0065007b00390031006100320035006300330035002d0034006600300062002d0034003900300035002d0039003100640063002d003000350039003300370033003100630038006600340038007d005c000000530074006f007200610067006500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004e005400460053000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffff0000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\CPC\Volume\{91a25c35-4f0b-4905-91dc-0593731c8f48}" /v "Generation" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\CPC\Volume\{f68c1308-24d9-48de-a5c1-26d4af39b9c0}" /v "Data" /t REG_BINARY /d "d60d00000df0adba0100000008000000000000800000000000000030000000000000000006020200ff0000001000000098bfff7e1e000000040000000b0000000000000000000000000000000000000000005c005c003f005c00530054004f005200410047004500230056006f006c0075006d00650023007b00330038006300330061003700650034002d0063006500630061002d0031003100650062002d0061006400610033002d003800300036006500360066003600650036003900360033007d002300300030003000300030003000300030003000300031003000300030003000300023007b00350033006600350036003300300064002d0062003600620066002d0031003100640030002d0039003400660032002d003000300061003000630039003100650066006200380062007d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005c005c003f005c0056006f006c0075006d0065007b00660036003800630031003300300038002d0032003400640039002d0034003800640065002d0061003500630031002d003200360064003400610066003300390062003900630030007d005c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000046004100540033003200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffff0000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\CPC\Volume\{f68c1308-24d9-48de-a5c1-26d4af39b9c0}" /v "Generation" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\{16c183b7-eb27-490c-a5bb-aa6eede5e4a9}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\{2b64f90c-9f96-46f1-a376-acf0a2cb369c}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\{38c3a7ee-ceca-11eb-ada3-806e6f6e6963}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\{38c3a7ef-ceca-11eb-ada3-806e6f6e6963}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\{91a25c35-4f0b-4905-91dc-0593731c8f48}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation" /v "PackageListVersion" /t REG_DWORD /d "770" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.549981C3F5F10_8wekyb3d8bbwe" /v "InstallState" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.549981C3F5F10_8wekyb3d8bbwe" /v "InstallProgress" /t REG_DWORD /d "100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.549981C3F5F10_8wekyb3d8bbwe" /v "ErrorDetail" /t REG_DWORD /d "2147944003" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.BingWeather_8wekyb3d8bbwe" /v "InstallState" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.BingWeather_8wekyb3d8bbwe" /v "InstallProgress" /t REG_DWORD /d "100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.BingWeather_8wekyb3d8bbwe" /v "ErrorDetail" /t REG_DWORD /d "2147944003" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe" /v "InstallState" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe" /v "InstallProgress" /t REG_DWORD /d "100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe" /v "ErrorDetail" /t REG_DWORD /d "2147944003" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.GetHelp_8wekyb3d8bbwe" /v "InstallState" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.GetHelp_8wekyb3d8bbwe" /v "InstallProgress" /t REG_DWORD /d "100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.GetHelp_8wekyb3d8bbwe" /v "ErrorDetail" /t REG_DWORD /d "2147944003" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.Getstarted_8wekyb3d8bbwe" /v "InstallState" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.Getstarted_8wekyb3d8bbwe" /v "InstallProgress" /t REG_DWORD /d "100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.Getstarted_8wekyb3d8bbwe" /v "ErrorDetail" /t REG_DWORD /d "2147944003" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.Microsoft3DViewer_8wekyb3d8bbwe" /v "InstallState" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.Microsoft3DViewer_8wekyb3d8bbwe" /v "InstallProgress" /t REG_DWORD /d "100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.Microsoft3DViewer_8wekyb3d8bbwe" /v "ErrorDetail" /t REG_DWORD /d "2147944003" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.MicrosoftEdge.Stable_8wekyb3d8bbwe" /v "InstallState" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.MicrosoftEdge.Stable_8wekyb3d8bbwe" /v "InstallProgress" /t REG_DWORD /d "100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.MicrosoftEdge.Stable_8wekyb3d8bbwe" /v "ErrorDetail" /t REG_DWORD /d "2147944003" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" /v "InstallState" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" /v "InstallProgress" /t REG_DWORD /d "100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" /v "ErrorDetail" /t REG_DWORD /d "2147944003" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe" /v "InstallState" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe" /v "InstallProgress" /t REG_DWORD /d "100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe" /v "ErrorDetail" /t REG_DWORD /d "2147944003" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.MicrosoftSolitaireCollection_8wekyb3d8bbwe" /v "InstallState" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.MicrosoftSolitaireCollection_8wekyb3d8bbwe" /v "InstallProgress" /t REG_DWORD /d "100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.MicrosoftSolitaireCollection_8wekyb3d8bbwe" /v "ErrorDetail" /t REG_DWORD /d "2147944003" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe" /v "InstallState" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe" /v "InstallProgress" /t REG_DWORD /d "100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe" /v "ErrorDetail" /t REG_DWORD /d "2147944003" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.MixedReality.Portal_8wekyb3d8bbwe" /v "InstallState" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.MixedReality.Portal_8wekyb3d8bbwe" /v "InstallProgress" /t REG_DWORD /d "100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.MixedReality.Portal_8wekyb3d8bbwe" /v "ErrorDetail" /t REG_DWORD /d "2147944003" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.MSPaint_8wekyb3d8bbwe" /v "InstallState" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.MSPaint_8wekyb3d8bbwe" /v "InstallProgress" /t REG_DWORD /d "100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.MSPaint_8wekyb3d8bbwe" /v "ErrorDetail" /t REG_DWORD /d "2147944003" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.Office.OneNote_8wekyb3d8bbwe" /v "InstallState" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.Office.OneNote_8wekyb3d8bbwe" /v "InstallProgress" /t REG_DWORD /d "100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.Office.OneNote_8wekyb3d8bbwe" /v "ErrorDetail" /t REG_DWORD /d "2147944003" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.People_8wekyb3d8bbwe" /v "InstallState" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.People_8wekyb3d8bbwe" /v "InstallProgress" /t REG_DWORD /d "100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.People_8wekyb3d8bbwe" /v "ErrorDetail" /t REG_DWORD /d "2147944003" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.ScreenSketch_8wekyb3d8bbwe" /v "InstallState" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.ScreenSketch_8wekyb3d8bbwe" /v "InstallProgress" /t REG_DWORD /d "100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.ScreenSketch_8wekyb3d8bbwe" /v "ErrorDetail" /t REG_DWORD /d "2147944003" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.SkypeApp_kzf8qxf38zg5c" /v "InstallState" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.SkypeApp_kzf8qxf38zg5c" /v "InstallProgress" /t REG_DWORD /d "100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.SkypeApp_kzf8qxf38zg5c" /v "ErrorDetail" /t REG_DWORD /d "2147944003" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.StorePurchaseApp_8wekyb3d8bbwe" /v "InstallState" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.StorePurchaseApp_8wekyb3d8bbwe" /v "InstallProgress" /t REG_DWORD /d "100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.StorePurchaseApp_8wekyb3d8bbwe" /v "ErrorDetail" /t REG_DWORD /d "2147944003" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.Wallet_8wekyb3d8bbwe" /v "InstallState" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.Wallet_8wekyb3d8bbwe" /v "InstallProgress" /t REG_DWORD /d "100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.Wallet_8wekyb3d8bbwe" /v "ErrorDetail" /t REG_DWORD /d "2147944003" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.WebMediaExtensions_8wekyb3d8bbwe" /v "InstallState" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.WebMediaExtensions_8wekyb3d8bbwe" /v "InstallProgress" /t REG_DWORD /d "100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.WebMediaExtensions_8wekyb3d8bbwe" /v "ErrorDetail" /t REG_DWORD /d "2147944003" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.Windows.Photos_8wekyb3d8bbwe" /v "InstallState" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.Windows.Photos_8wekyb3d8bbwe" /v "InstallProgress" /t REG_DWORD /d "100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.Windows.Photos_8wekyb3d8bbwe" /v "ErrorDetail" /t REG_DWORD /d "2147944003" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.WindowsAlarms_8wekyb3d8bbwe" /v "InstallState" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.WindowsAlarms_8wekyb3d8bbwe" /v "InstallProgress" /t REG_DWORD /d "100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.WindowsAlarms_8wekyb3d8bbwe" /v "ErrorDetail" /t REG_DWORD /d "2147944003" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.WindowsCalculator_8wekyb3d8bbwe" /v "InstallState" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.WindowsCalculator_8wekyb3d8bbwe" /v "InstallProgress" /t REG_DWORD /d "100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.WindowsCalculator_8wekyb3d8bbwe" /v "ErrorDetail" /t REG_DWORD /d "2147944003" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.WindowsCamera_8wekyb3d8bbwe" /v "InstallState" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.WindowsCamera_8wekyb3d8bbwe" /v "InstallProgress" /t REG_DWORD /d "100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.WindowsCamera_8wekyb3d8bbwe" /v "ErrorDetail" /t REG_DWORD /d "2147944003" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\microsoft.windowscommunicationsapps_8wekyb3d8bbwe" /v "InstallState" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\microsoft.windowscommunicationsapps_8wekyb3d8bbwe" /v "InstallProgress" /t REG_DWORD /d "100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\microsoft.windowscommunicationsapps_8wekyb3d8bbwe" /v "ErrorDetail" /t REG_DWORD /d "2147944003" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.WindowsFeedbackHub_8wekyb3d8bbwe" /v "InstallState" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.WindowsFeedbackHub_8wekyb3d8bbwe" /v "InstallProgress" /t REG_DWORD /d "100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.WindowsFeedbackHub_8wekyb3d8bbwe" /v "ErrorDetail" /t REG_DWORD /d "2147944003" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.WindowsMaps_8wekyb3d8bbwe" /v "InstallState" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.WindowsMaps_8wekyb3d8bbwe" /v "InstallProgress" /t REG_DWORD /d "100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.WindowsMaps_8wekyb3d8bbwe" /v "ErrorDetail" /t REG_DWORD /d "2147944003" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.WindowsSoundRecorder_8wekyb3d8bbwe" /v "InstallState" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.WindowsSoundRecorder_8wekyb3d8bbwe" /v "InstallProgress" /t REG_DWORD /d "100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.WindowsSoundRecorder_8wekyb3d8bbwe" /v "ErrorDetail" /t REG_DWORD /d "2147944003" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.WindowsStore_8wekyb3d8bbwe" /v "InstallState" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.WindowsStore_8wekyb3d8bbwe" /v "InstallProgress" /t REG_DWORD /d "100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.WindowsStore_8wekyb3d8bbwe" /v "ErrorDetail" /t REG_DWORD /d "2147944003" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.Xbox.TCUI_8wekyb3d8bbwe" /v "InstallState" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.Xbox.TCUI_8wekyb3d8bbwe" /v "InstallProgress" /t REG_DWORD /d "100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.Xbox.TCUI_8wekyb3d8bbwe" /v "ErrorDetail" /t REG_DWORD /d "2147944003" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.XboxApp_8wekyb3d8bbwe" /v "InstallState" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.XboxApp_8wekyb3d8bbwe" /v "InstallProgress" /t REG_DWORD /d "100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.XboxApp_8wekyb3d8bbwe" /v "ErrorDetail" /t REG_DWORD /d "2147944003" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.XboxGameOverlay_8wekyb3d8bbwe" /v "InstallState" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.XboxGameOverlay_8wekyb3d8bbwe" /v "InstallProgress" /t REG_DWORD /d "100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.XboxGameOverlay_8wekyb3d8bbwe" /v "ErrorDetail" /t REG_DWORD /d "2147944003" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe" /v "InstallState" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe" /v "InstallProgress" /t REG_DWORD /d "100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe" /v "ErrorDetail" /t REG_DWORD /d "2147944003" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.XboxIdentityProvider_8wekyb3d8bbwe" /v "InstallState" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.XboxIdentityProvider_8wekyb3d8bbwe" /v "InstallProgress" /t REG_DWORD /d "100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.XboxIdentityProvider_8wekyb3d8bbwe" /v "ErrorDetail" /t REG_DWORD /d "2147944003" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.XboxSpeechToTextOverlay_8wekyb3d8bbwe" /v "InstallState" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.XboxSpeechToTextOverlay_8wekyb3d8bbwe" /v "InstallProgress" /t REG_DWORD /d "100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.XboxSpeechToTextOverlay_8wekyb3d8bbwe" /v "ErrorDetail" /t REG_DWORD /d "2147944003" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.YourPhone_8wekyb3d8bbwe" /v "InstallState" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.YourPhone_8wekyb3d8bbwe" /v "InstallProgress" /t REG_DWORD /d "100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.YourPhone_8wekyb3d8bbwe" /v "ErrorDetail" /t REG_DWORD /d "2147944003" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.ZuneMusic_8wekyb3d8bbwe" /v "InstallState" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.ZuneMusic_8wekyb3d8bbwe" /v "InstallProgress" /t REG_DWORD /d "100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.ZuneMusic_8wekyb3d8bbwe" /v "ErrorDetail" /t REG_DWORD /d "2147944003" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.ZuneVideo_8wekyb3d8bbwe" /v "InstallState" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.ZuneVideo_8wekyb3d8bbwe" /v "InstallProgress" /t REG_DWORD /d "100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Package Installation\Microsoft.ZuneVideo_8wekyb3d8bbwe" /v "ErrorDetail" /t REG_DWORD /d "2147944003" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\QuietHours" /v "Enable" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" /v "MRUListEx" /t REG_BINARY /d "00000000ffffffff" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" /v "0" /t REG_BINARY /d "3a003a007b00300032003500410035003900330037002d0041003600420045002d0034003600380036002d0041003800340034002d003300360046004500340042004500430038004200360044007d0000007400320000000000000000000000506f776572204f7074696f6e732e6c6e6b00540009000400efbe00000000000000002e000000000000000000000000000000000000000000000000000000000050006f0077006500720020004f007000740069006f006e0073002e006c006e006b00000020000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Ribbon" /v "MinimizedStateTabletModeOff" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Ribbon" /v "QatItems" /t REG_BINARY /d "3c7369713a637573746f6d554920786d6c6e733a7369713d22687474703a2f2f736368656d61732e6d6963726f736f66742e636f6d2f77696e646f77732f323030392f726962626f6e2f716174223e3c7369713a726962626f6e206d696e696d697a65643d2274727565223e3c7369713a71617420706f736974696f6e3d2230223e3c7369713a736861726564436f6e74726f6c733e3c7369713a636f6e74726f6c206964513d227369713a3136313238222076697369626c653d2266616c73652220617267756d656e743d223022202f3e3c7369713a636f6e74726f6c206964513d227369713a3136313239222076697369626c653d2266616c73652220617267756d656e743d223022202f3e3c7369713a636f6e74726f6c206964513d227369713a3132333532222076697369626c653d2266616c73652220617267756d656e743d223022202f3e3c7369713a636f6e74726f6c206964513d227369713a3132333834222076697369626c653d22747275652220617267756d656e743d223022202f3e3c7369713a636f6e74726f6c206964513d227369713a3132333336222076697369626c653d22747275652220617267756d656e743d223022202f3e3c7369713a636f6e74726f6c206964513d227369713a3132333537222076697369626c653d2266616c73652220617267756d656e743d223022202f3e3c2f7369713a736861726564436f6e74726f6c733e3c2f7369713a7161743e3c2f7369713a726962626f6e3e3c2f7369713a637573746f6d55493e" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /v "a" /t REG_SZ /d "regedit\1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /v "MRUList" /t REG_SZ /d "a" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SearchPlatform\Preferences" /v "BreadCrumbBarSearchDefault" /t REG_SZ /d "MSNSearch" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SearchPlatform\Preferences" /v "DisableAutoNavigateURL" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SearchPlatform\Preferences" /v "DisableAutoResolveEmailAddrs" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SearchPlatform\Preferences" /v "DisableResultsInNewWindow" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SearchPlatform\Preferences" /v "DisableTabbedBrowsing" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SearchPlatform\Preferences" /v "EditSavedSearch" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SearchPlatform\Preferences" /v "IEAddressBarSearchDefault" /t REG_SZ /d "MSNSearch" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "!Do not use this registry key" /t REG_SZ /d "Use the SHGetFolderPath or SHGetKnownFolderPath function instead" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "AppData" /t REG_SZ /d "C:\Users\Administrator\AppData\Roaming" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Local AppData" /t REG_SZ /d "C:\Users\Administrator\AppData\Local" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "CD Burning" /t REG_SZ /d "C:\Users\Administrator\AppData\Local\Microsoft\Windows\Burn\Burn" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "{1B3EA5DC-B587-4786-B4EF-BD1DC332AEAE}" /t REG_SZ /d "C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Libraries" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Video" /t REG_SZ /d "C:\Users\Administrator\Videos" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Pictures" /t REG_SZ /d "C:\Users\Administrator\Pictures" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Desktop" /t REG_SZ /d "C:\Users\Administrator\Desktop" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "History" /t REG_SZ /d "C:\Users\Administrator\AppData\Local\Microsoft\Windows\History" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "NetHood" /t REG_SZ /d "C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Network Shortcuts" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "{56784854-C6CB-462B-8169-88E350ACB882}" /t REG_SZ /d "C:\Users\Administrator\Contacts" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "{00BCFC5A-ED94-4E48-96A1-3F6217F21990}" /t REG_SZ /d "C:\Users\Administrator\AppData\Local\Microsoft\Windows\RoamingTiles" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Cookies" /t REG_SZ /d "C:\Users\Administrator\AppData\Local\Microsoft\Windows\INetCookies" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Favorites" /t REG_SZ /d "C:\Users\Administrator\Favorites" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "SendTo" /t REG_SZ /d "C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\SendTo" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Start Menu" /t REG_SZ /d "C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "My Music" /t REG_SZ /d "C:\Users\Administrator\Music" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Programs" /t REG_SZ /d "C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Recent" /t REG_SZ /d "C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Recent" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "PrintHood" /t REG_SZ /d "C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Printer Shortcuts" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "{7D1D3A04-DEBB-4115-95CF-2F29DA2920DA}" /t REG_SZ /d "C:\Users\Administrator\Searches" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "{374DE290-123F-4565-9164-39C4925E467B}" /t REG_SZ /d "C:\Users\Administrator\Downloads" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "{A520A1A4-1780-4FF6-BD18-167343C5AF16}" /t REG_SZ /d "C:\Users\Administrator\AppData\LocalLow" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Startup" /t REG_SZ /d "C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Administrative Tools" /t REG_SZ /d "C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Administrative Tools" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Personal" /t REG_SZ /d "C:\Users\Administrator\Documents" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "{BFB9D5E0-C6A9-404C-B2B2-AE6DB6AF4968}" /t REG_SZ /d "C:\Users\Administrator\Links" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Cache" /t REG_SZ /d "C:\Users\Administrator\AppData\Local\Microsoft\Windows\INetCache" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Templates" /t REG_SZ /d "C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Templates" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "{4C5C32FF-BB9D-43B0-B5B4-2D72E54EAAA4}" /t REG_SZ /d "C:\Users\Administrator\Saved Games" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Fonts" /t REG_SZ /d "C:\Windows\Fonts" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shutdown" /v "CleanShutdown" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartPage" /v "StartMenu_Start_Time" /t REG_BINARY /d "93e954bf8b62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartPage" /v "Start_JumpListModernTime" /t REG_BINARY /d "715d6abf8b62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Streams\Desktop" /v "TaskbarWinXP" /t REG_BINARY /d "0c000000080000000100000000000000aa4f2868486ad0118c7800c04fd918b400000000400d000000000000780000000000000000000000780000000000000001000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3" /v "Settings" /t REG_BINARY /d "30000000feffffff0200000003000000ba0000007800000000000000f8070000000f0000700800002001000001000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TabletMode" /v "STCDefaultMigrationCompleted" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband" /v "FavoritesResolve" /t REG_BINARY /d "3b0300004c0000000114020000000000c000000000000046830080002000000021df7ec58b62d70121df7ec58b62d701a8b6c6daddacd501970100000000000001000000000000000000000000000000a0013a001f80c827341f105c1042aa032ee45287d668260001002600efbe12000000715d6abf8b62d701df7c7cc58b62d70121df7ec58b62d70114005600310000000000d052854511005461736b42617200400009000400efbed0528545d05285452e00000012600100000001000000000000000000000000000000bbe7ef005400610073006b00420061007200000016000e01320097010000874f0749200046494c4545587e312e4c4e4b00007c0009000400efbed0528545d05285452e00000013600100000001000000000000000000520000000000589c4400460069006c00650020004500780070006c006f007200650072002e006c006e006b00000040007300680065006c006c00330032002e0064006c006c002c002d003200320030003600370000001c00220000001e00efbe02005500730065007200500069006e006e006500640000001c00120000002b00efbeae0586c58b62d7011c00420000001d00efbe02004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e004500780070006c006f0072006500720000001c000000a40000001c000000010000001c0000002d00000000000000a300000011000000030000009a7b06861000000000433a5c55736572735c41646d696e6973747261746f725c417070446174615c526f616d696e675c4d6963726f736f66745c496e7465726e6574204578706c6f7265725c517569636b204c61756e63685c557365722050696e6e65645c5461736b4261725c46696c65204578706c6f7265722e6c6e6b000060000000030000a0580000000000000077696e2d74756876746f65656e333900b4d12e2cf0ce7b4da3885c2489ccc31cb7b55055caceeb11ada418c04d0d0e12b4d12e2cf0ce7b4da3885c2489ccc31cb7b55055caceeb11ada418c04d0d0e1245000000090000a03900000031535053b1166d44ad8d7048a748402ea43d788c1d0000006800000000480000000cf9642b969ff146a376acf0a2cb369c000000000000000000000000eb0200004c0000000114020000000000c000000000000046830080002000000088c58b8d8c62d701f4278e8d8c62d701f35cd3858c62d701c5030000000000000100000000000000000000000000000056013a001f80c827341f105c1042aa032ee45287d668260001002600efbe12000000715d6abf8b62d701df7c7cc58b62d70188c58b8d8c62d70114005600310000000000d052374611005461736b42617200400009000400efbed0528545d05237462e0000001260010000000100000000000000000000000000000078eb2a015400610073006b0042006100720000001600c4003200c5030000d0523046200046697265666f782e6c6e6b00480009000400efbed0523746d05237462e0000000e5e01000000050000000000000000000000000000000d198b00460069007200650066006f0078002e006c006e006b0000001a00220000001e00efbe02005500730065007200500069006e006e006500640000001a00120000002b00efbef4278e8d8c62d7011a002e0000001d00efbe0200330030003800300034003600420030004100460034004100330039004300420000001a0000009e0000001c000000010000001c0000002d000000000000009d00000011000000030000009a7b06861000000000433a5c55736572735c41646d696e6973747261746f725c417070446174615c526f616d696e675c4d6963726f736f66745c496e7465726e6574204578706c6f7265725c517569636b204c61756e63685c557365722050696e6e65645c5461736b4261725c46697265666f782e6c6e6b000060000000030000a0580000000000000077696e2d74756876746f65656e333900b4d12e2cf0ce7b4da3885c2489ccc31cba3444197fceeb11ada518c04d0d0e12b4d12e2cf0ce7b4da3885c2489ccc31cba3444197fceeb11ada518c04d0d0e1245000000090000a03900000031535053b1166d44ad8d7048a748402ea43d788c1d0000006800000000480000000cf9642b969ff146a376acf0a2cb369c000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband" /v "Favorites" /t REG_BINARY /d "00a40100003a001f80c827341f105c1042aa032ee45287d668260001002600efbe12000000715d6abf8b62d701df7c7cc58b62d70121df7ec58b62d70114005600310000000000d052854511005461736b42617200400009000400efbed0528545d05285452e00000012600100000001000000000000000000000000000000bbe7ef005400610073006b00420061007200000016001201320097010000874f0749200046494c4545587e312e4c4e4b00007c0009000400efbed0528545d05285452e00000013600100000001000000000000000000520000000000589c4400460069006c00650020004500780070006c006f007200650072002e006c006e006b00000040007300680065006c006c00330032002e0064006c006c002c002d003200320030003600370000001c00120000002b00efbeae0586c58b62d7011c00420000001d00efbe02004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e004500780070006c006f0072006500720000001c00260000001e00efbe0200530079007300740065006d00500069006e006e006500640000001c00000000560100003a001f80c827341f105c1042aa032ee45287d668260001002600efbe12000000715d6abf8b62d701df7c7cc58b62d70188c58b8d8c62d70114005600310000000000d052374611005461736b42617200400009000400efbed0528545d05237462e0000001260010000000100000000000000000000000000000078eb2a015400610073006b0042006100720000001600c4003200c5030000d0523046200046697265666f782e6c6e6b00480009000400efbed0523746d05237462e0000000e5e01000000050000000000000000000000000000000d198b00460069007200650066006f0078002e006c006e006b0000001a00120000002b00efbef4278e8d8c62d7011a002e0000001d00efbe0200330030003800300034003600420030004100460034004100330039004300420000001a00220000001e00efbe02005500730065007200500069006e006e006500640000001a000000ff" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband" /v "FavoritesChanges" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband" /v "FavoritesVersion" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins" /v "MailPin" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "AppData" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Roaming" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Cache" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Local\Microsoft\Windows\INetCache" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Cookies" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Local\Microsoft\Windows\INetCookies" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Desktop" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\Desktop" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Favorites" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\Favorites" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "History" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Local\Microsoft\Windows\History" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Local AppData" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Local" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Music" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\Music" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Pictures" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\Pictures" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "My Video" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\Videos" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "NetHood" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Roaming\Microsoft\Windows\Network Shortcuts" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Personal" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\Documents" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "PrintHood" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Roaming\Microsoft\Windows\Printer Shortcuts" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Programs" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Recent" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Roaming\Microsoft\Windows\Recent" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "SendTo" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Roaming\Microsoft\Windows\SendTo" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Start Menu" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Roaming\Microsoft\Windows\Start Menu" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Startup" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Templates" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Roaming\Microsoft\Windows\Templates" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "{374DE290-123F-4565-9164-39C4925E467B}" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\Downloads" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{9E04CAB2-CC14-11DF-BB8C-A2F1DED72085}" /v "Version" /t REG_DWORD /d "5" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{9E04CAB2-CC14-11DF-BB8C-A2F1DED72085}\Count" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{A3D53349-6E61-4557-8FC7-0028EDCEEBF6}" /v "Version" /t REG_DWORD /d "5" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{A3D53349-6E61-4557-8FC7-0028EDCEEBF6}\Count" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{B267E3AD-A825-4A09-82B9-EEC22AA3B847}" /v "Version" /t REG_DWORD /d "5" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{B267E3AD-A825-4A09-82B9-EEC22AA3B847}\Count" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{BCB48336-4DDD-48FF-BB0B-D3190DACB3E2}" /v "Version" /t REG_DWORD /d "5" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{BCB48336-4DDD-48FF-BB0B-D3190DACB3E2}\Count" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CAA59E3C-4792-41A5-9909-6A6A8D32490E}" /v "Version" /t REG_DWORD /d "5" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CAA59E3C-4792-41A5-9909-6A6A8D32490E}\Count" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}" /v "Version" /t REG_DWORD /d "5" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count" /v "HRZR_PGYPHNPbhag:pgbe" /t REG_BINARY /d "ffffffff000000000000000000000000000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bfffffffff000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count" /v "{1NP14R77-02R7-4R5Q-O744-2RO1NR5198O7}\FavccvatGbby.rkr" /t REG_BINARY /d "000000000e00000015000000a0680600000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bfffffffff4ce5ee808b62d70100000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count" /v "HRZR_PGYFRFFVBA" /t REG_BINARY /d "000000001600000031000000a9711d000e00000015000000a06806007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c0053006e0069007000700069006e00670054006f006f006c002e0065007800650000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e00000015000000a06806007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c0053006e0069007000700069006e00670054006f006f006c002e0065007800650000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e00000015000000a06806007b00310041004300310034004500370037002d0030003200450037002d0034004500350044002d0042003700340034002d003200450042003100410045003500310039003800420037007d005c0053006e0069007000700069006e00670054006f006f006c002e006500780065000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count" /v "{1NP14R77-02R7-4R5Q-O744-2RO1NR5198O7}\zfcnvag.rkr" /t REG_BINARY /d "00000000020000000300000060ea0000000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bfffffffff4ce5ee808b62d70100000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count" /v "{1NP14R77-02R7-4R5Q-O744-2RO1NR5198O7}\pzq.rkr" /t REG_BINARY /d "0000000000000000090000007a2c0800000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bfffffffff000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count" /v "Zvpebfbsg.Jvaqbjf.Rkcybere" /t REG_BINARY /d "00000000030000000100000035400000000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bfffffffff6012a52c8f62d70100000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count" /v "{1NP14R77-02R7-4R5Q-O744-2RO1NR5198O7}\jfpevcg.rkr" /t REG_BINARY /d "000000000000000001000000941e0000000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bfffffffff000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count" /v "{1NP14R77-02R7-4R5Q-O744-2RO1NR5198O7}\fuhgqbja.rkr" /t REG_BINARY /d "0000000000000000000000000f000000000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bfffffffff000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count" /v "P:\Tubfg Gbbyobk\gbbyobk.hcqngre.k64.rkr" /t REG_BINARY /d "00000000010000000000000000000000000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bfffffffff50c6abee8b62d70100000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count" /v "Zvpebfbsg.VagreargRkcybere.Qrsnhyg" /t REG_BINARY /d "000000000000000002000000317b0200000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bfffffffff000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count" /v "P:\Tubfg Gbbyobk\jtrg\Sversbk Vafgnyyre.rkr" /t REG_BINARY /d "00000000000000000000000010000000000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bfffffffff000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count" /v "P:\Hfref\Nqzvavfgengbe\NccQngn\Ybpny\Grzc\7mF4P7S61S3\frghc-fgho.rkr" /t REG_BINARY /d "000000000000000001000000907f0000000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bfffffffff000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count" /v "308046O0NS4N39PO" /t REG_BINARY /d "00000000010000000300000055990600000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bfffffffff300783188d62d70100000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count" /v "jvaqbjf.vzzrefvirpbagebycnary_pj5a1u2gklrjl!zvpebfbsg.jvaqbjf.vzzrefvirpbagebycnary" /t REG_BINARY /d "0000000000000000020000001b200000000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bfffffffff000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count" /v "Zvpebfbsg.Jvaqbjf.JvaqbjfVafgnyyre" /t REG_BINARY /d "00000000000000000200000010680000000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bfffffffff000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count" /v "Zvpebfbsg.Jvaqbjf.PbagebyCnary" /t REG_BINARY /d "00000000000000000100000004290000000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bfffffffff000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count" /v "R:\Ertvfgel\ErtPbbyK64\ErtPbby.rkr" /t REG_BINARY /d "0000000001000000010000000d250000000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bfffffffffe09f53348f62d70100000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count" /v "Zvpebfbsg.Jvaqbjf.FuryyRkcrevraprUbfg_pj5a1u2gklrjl!Ncc" /t REG_BINARY /d "000000000000000000000000ee020000000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bfffffffff000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count" /v "Zvpebfbsg.Jvaqbjf.Furyy.EhaQvnybt" /t REG_BINARY /d "0000000000000000010000002b180000000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bfffffffff000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count" /v "{S38OS404-1Q43-42S2-9305-67QR0O28SP23}\ertrqvg.rkr" /t REG_BINARY /d "000000000100000001000000dc0d0300000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bfffffffff404465418f62d70100000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F2A1CB5A-E3CC-4A2E-AF9D-505A7009D442}" /v "Version" /t REG_DWORD /d "5" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F2A1CB5A-E3CC-4A2E-AF9D-505A7009D442}\Count" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}" /v "Version" /t REG_DWORD /d "5" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count" /v "HRZR_PGYPHNPbhag:pgbe" /t REG_BINARY /d "ffffffff000000000000000000000000000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bfffffffff000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count" /v "{0139Q44R-6NSR-49S2-8690-3QNSPNR6SSO8}\Npprffbevrf\Favccvat Gbby.yax" /t REG_BINARY /d "000000000e000000000000000e000000000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bfffffffff4ce5ee808b62d70100000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count" /v "HRZR_PGYFRFFVBA" /t REG_BINARY /d "000000001400000000000000140000000e000000000000000e0000007b00300031003300390044003400340045002d0036004100460045002d0034003900460032002d0038003600390030002d003300440041004600430041004500360046004600420038007d005c004100630063006500730073006f0072006900650073005c0053006e0069007000700069006e006700200054006f006f006c002e006c006e006b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e000000000000000e0000007b00300031003300390044003400340045002d0036004100460045002d0034003900460032002d0038003600390030002d003300440041004600430041004500360046004600420038007d005c004100630063006500730073006f0072006900650073005c0053006e0069007000700069006e006700200054006f006f006c002e006c006e006b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e000000000000000e0000007b00300031003300390044003400340045002d0036004100460045002d0034003900460032002d0038003600390030002d003300440041004600430041004500360046004600420038007d005c004100630063006500730073006f0072006900650073005c0053006e0069007000700069006e006700200054006f006f006c002e006c006e006b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count" /v "{0139Q44R-6NSR-49S2-8690-3QNSPNR6SSO8}\Npprffbevrf\Cnvag.yax" /t REG_BINARY /d "00000000020000000000000002000000000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bfffffffff4ce5ee808b62d70100000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count" /v "P:\Hfref\Nqzvavfgengbe\Qrfxgbc\Tubfg Gbbyobk.yax" /t REG_BINARY /d "00000000010000000000000001000000000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bfffffffff50c6abee8b62d70100000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count" /v "{9R3995NO-1S9P-4S13-O827-48O24O6P7174}\GnfxOne\Sversbk.yax" /t REG_BINARY /d "00000000010000000000000001000000000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bfffffffff300783188d62d70100000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count" /v "{9R3995NO-1S9P-4S13-O827-48O24O6P7174}\GnfxOne\Svyr Rkcybere.yax" /t REG_BINARY /d "00000000020000000000000002000000000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bf000080bfffffffff6012a52c8f62d70100000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{FA99DFC7-6AC2-453A-A5E2-5E2AFF4507BD}" /v "Version" /t REG_DWORD /d "5" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{FA99DFC7-6AC2-453A-A5E2-5E2AFF4507BD}\Count" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VirtualDesktops" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\AnimateMinMax" /v "DefaultValue" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\AnimateMinMax" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ComboBoxAnimation" /v "DefaultValue" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ComboBoxAnimation" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ControlAnimations" /v "DefaultValue" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ControlAnimations" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\CursorShadow" /v "DefaultValue" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\CursorShadow" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DragFullWindows" /v "DefaultValue" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DragFullWindows" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DropShadow" /v "DefaultValue" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DropShadow" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMAeroPeekEnabled" /v "DefaultValue" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMAeroPeekEnabled" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMEnabled" /v "DefaultValue" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMEnabled" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMSaveThumbnailEnabled" /v "DefaultValue" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMSaveThumbnailEnabled" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\FontSmoothing" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListBoxSmoothScrolling" /v "DefaultValue" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListBoxSmoothScrolling" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListviewAlphaSelect" /v "DefaultValue" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListviewAlphaSelect" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListviewShadow" /v "DefaultValue" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListviewShadow" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\MenuAnimation" /v "DefaultValue" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\MenuAnimation" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\SelectionFade" /v "DefaultValue" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\SelectionFade" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TaskbarAnimations" /v "DefaultValue" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TaskbarAnimations" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\Themes" /v "DefaultValue" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\Themes" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ThumbnailsOrIcon" /v "DefaultValue" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ThumbnailsOrIcon" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TooltipAnimation" /v "DefaultValue" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TooltipAnimation" /v "DefaultApplied" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers" /v "BackgroundHistoryPath0" /t REG_SZ /d "C:\Users\Administrator\AppData\Local\Microsoft\Windows\Themes\GHOSTV3\DesktopBackground\img0.jpg" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers" /v "BackgroundHistoryPath1" /t REG_SZ /d "c:\windows\web\wallpaper\windows\img0.jpg" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers" /v "BackgroundHistoryPath2" /t REG_SZ /d "c:\windows\web\wallpaper\theme1\img1.jpg" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers" /v "BackgroundHistoryPath3" /t REG_SZ /d "c:\windows\web\wallpaper\theme1\img13.jpg" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers" /v "BackgroundHistoryPath4" /t REG_SZ /d "c:\windows\web\wallpaper\theme1\img2.jpg" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers\Images" /v "ID-1" /t REG_SZ /d "WLgOA8BRHpxAZJ3PnSUiFXVl+vGMubCABAgJA8uvQAAAAQfbP77iiddAX6z0/uoYXHwl+M9vLK21BQBACCAdAwBADZ0UGZBAxAAAAAAAQLVfFJDABBHcEFGdhBAAAQnGZ5llfPNSNe2Fzwr7oobxNr/3femVBl4RFf8aAb7fABQCAQAAv7L0S1XRQLVfF5CAAAQ6cFAAAAQAAAAAAAAAAAAAAAAAAAAAKTHYAEEAwBAcAQEAhBAdAEGAAAgQAAFAxAAAAAAAQL1gFBDAM92YhxGA8AQCAQAAv7L0S1XRQL1gF5CAAAA/cFAAAAQAAAAAAAAAAAAAAAAAAAAAshy0AwEAvBwYAEGAsBAAAQBAcBQMAAAAAAA0SFYRwAQTJNkUPNlfxAAAEBQCAQAAv7L0S1XRQL1gF5CAAAg/cFAAAAQAAAAAAAAAAAAAAAAAAAAAADfEA0EApBwYAIHAvBwcA8GAmBAdAAAAYAgVAEDAAAAAAAtUDWEMAcVauR2b3NHAABQCAQAAv7L0S1XRQL1gF5CAAAgAdFAAAAQAAAAAAAAAAAAAAAAAAAAA/9qLAcFApBgbAQGAvBwdAMHAAAgFAQFAxAAAAAAAQL1gFBBAUhWZtV2cAAgPAkAAEAw7+CtUDWE0SNYRuAAAAA7XBAAAAIAAAAAAAAAAAAAAAAAAAAQeJeCAUBAaAUGAtBQZAMHAAAgFAYFAxAAAAAAAQL1gFBBAHh0TTRlVzAAQAkAAEAw7+CtUDWE0SNYRuAAAAQ7XBAAAAIAAAAAAAAAAAAAAAAAAAAQeJeCAHBASA8EATBAVAYFAzAAAAYBAsBQMAAAAAAA0SNYRQAARFN1SU9kfxAAAUBQCAQAAv7L0SNYRQL1gF5CAAAgxfFAAAAQAAAAAAAAAAAAAAAAAAAAA5l4JAQEAlBwcAsGA0BwbAAHACBQYAMGArBwZAIHAvBQdA4GAkBAAAgBAAAA" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers\Images" /v "ID-2" /t REG_SZ /d "WLgOA8BRHpxAZJ3PnSUiFXVl+vGMubCABAgJA8uvQAAAAQfbP77iiddAX6z0/uoYXHwl+M9vLK21BQBACCAdAwBADZ0UGZBAxAAAAAAAQLVfFJDABBHcEFGdhBAAAQnGZ5llfPNSNe2Fzwr7oobxNr/3femVBl4RFf8aAb7fABQCAQAAv7L0S1XRQLVfF5CAAAQ6cFAAAAQAAAAAAAAAAAAAAAAAAAAAKTHYAEEAwBAcAQEAhBAdAEGAAAgQAAFAxAAAAAAAQL1gFBDAM92YhxGA8AQCAQAAv7L0S1XRQL1gF5CAAAA/cFAAAAQAAAAAAAAAAAAAAAAAAAAAshy0AwEAvBwYAEGAsBAAAQBAcBQMAAAAAAA0SFYRwAQTJNkUPNlfxAAAEBQCAQAAv7L0S1XRQL1gF5CAAAg/cFAAAAQAAAAAAAAAAAAAAAAAAAAAADfEA0EApBwYAIHAvBwcA8GAmBAdAAAAYAgVAEDAAAAAAAtUDWEMAcVauR2b3NHAABQCAQAAv7L0S1XRQL1gF5CAAAgAdFAAAAQAAAAAAAAAAAAAAAAAAAAA/9qLAcFApBgbAQGAvBwdAMHAAAgFAQFAxAAAAAAAQL1gFBBAUhWZtV2cAAgPAkAAEAw7+CtUDWE0SNYRuAAAAA7XBAAAAIAAAAAAAAAAAAAAAAAAAAQeJeCAUBAaAUGAtBQZAMHAAAgFAYFAxAAAAAAAQL1gFBBAHh0TTRlVzAAQAkAAEAw7+CtUDWE0SNYRuAAAAQ7XBAAAAIAAAAAAAAAAAAAAAAAAAAQeJeCAHBASA8EATBAVAYFAzAAAAYBAsBQMAAAAAAA0SNYRQAARFN1SU9kfxAAAUBQCAQAAv7L0SNYRQL1gF5CAAAgxfFAAAAQAAAAAAAAAAAAAAAAAAAAA5l4JAQEAlBwcAsGA0BwbAAHACBQYAMGArBwZAIHAvBQdA4GAkBAAAgBAAAA" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:0000000000030276" /v "VirtualDesktop" /t REG_BINARY /d "100000003030445600000000000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000302A2" /v "VirtualDesktop" /t REG_BINARY /d "1000000030304456e4f3de5e4f26b348a051fa28c2300fed" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:000000000004025E" /v "VirtualDesktop" /t REG_BINARY /d "100000003030445600000000000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:000000000005021C" /v "VirtualDesktop" /t REG_BINARY /d "100000003030445600000000000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000602EA" /v "VirtualDesktop" /t REG_BINARY /d "100000003030445600000000000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000602EC" /v "VirtualDesktop" /t REG_BINARY /d "100000003030445600000000000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000B01D2" /v "VirtualDesktop" /t REG_BINARY /d "1000000030304456e4f3de5e4f26b348a051fa28c2300fed" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\DesktopSwitchCompleted" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ImmersiveShell\PersistedApplicationData\Volatile" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\LogonSoundHasBeenPlayed" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ModeTriggerCachedKey" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\RunStuffHasBeenRun" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\StartupHasBeenRun" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\TabletModeControllerInitialized" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\VirtualDesktops" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Ext\Stats\{6BF52A52-394A-11D3-B153-00C04F79FAA6}\iexplore" /v "Type" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Ext\Stats\{6BF52A52-394A-11D3-B153-00C04F79FAA6}\iexplore" /v "Flags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Ext\Stats\{6BF52A52-394A-11D3-B153-00C04F79FAA6}\iexplore" /v "Count" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Ext\Stats\{6BF52A52-394A-11D3-B153-00C04F79FAA6}\iexplore" /v "Time" /t REG_BINARY /d "e50706000300100008002e000700d501" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Ext\Stats\{F6D90F11-9C73-11D3-B32E-00C04F990BB4}\iexplore" /v "Type" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Ext\Stats\{F6D90F11-9C73-11D3-B32E-00C04F990BB4}\iexplore" /v "Flags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Ext\Stats\{F6D90F11-9C73-11D3-B32E-00C04F990BB4}\iexplore" /v "Count" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Ext\Stats\{F6D90F11-9C73-11D3-B32E-00C04F990BB4}\iexplore" /v "Time" /t REG_BINARY /d "e50706000300100008002d003600b901" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\FileAssociations" /v "Version" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\FileAssociations\MicrosoftExperiences" /v "EnlightenmentSample1" /t REG_SZ /d "Y/yCA658o/A=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\FileHistory\RestoreUI" /v "FolderViewType" /t REG_SZ /d "MediumIcons" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\FileHistory\RestoreUI" /v "SearchResultsViewType" /t REG_SZ /d "Content" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\FileHistory\RestoreUI" /v "WindowLocation" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "KGLToGCSUpdatedRevision" /t REG_DWORD /d "1824" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "KGLRevision" /t REG_DWORD /d "1824" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\GroupMembership" /v "Group0" /t REG_SZ /d "S-1-5-21-2807429842-3194115458-1915057576-513" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\GroupMembership" /v "Group1" /t REG_SZ /d "S-1-1-0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\GroupMembership" /v "Group2" /t REG_SZ /d "S-1-5-114" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\GroupMembership" /v "Group3" /t REG_SZ /d "S-1-5-32-544" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\GroupMembership" /v "Group4" /t REG_SZ /d "S-1-5-32-545" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\GroupMembership" /v "Group5" /t REG_SZ /d "S-1-5-4" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\GroupMembership" /v "Group6" /t REG_SZ /d "S-1-2-1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\GroupMembership" /v "Group7" /t REG_SZ /d "S-1-5-11" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\GroupMembership" /v "Group8" /t REG_SZ /d "S-1-5-15" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\GroupMembership" /v "Group9" /t REG_SZ /d "S-1-5-113" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\GroupMembership" /v "Group10" /t REG_SZ /d "S-1-2-0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\GroupMembership" /v "Group11" /t REG_SZ /d "S-1-5-64-10" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\GroupMembership" /v "Group12" /t REG_SZ /d "S-1-16-12288" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\GroupMembership" /v "Count" /t REG_DWORD /d "13" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History" /v "PolicyOverdue" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\PolicyApplicationState" /v "PolicyState" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Holographic" /v "FirstRunSucceeded" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Holographic\StageManagement" /v "DisableQuickRoomSetup" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Holographic\StageManagement" /v "DisableStageNearbyRequirement" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Holographic\UsageInfo" /v "Build" /t REG_SZ /d "19041.1.amd64fre.vb_release.191206-1406" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "ActiveLearning" /t REG_SZ /d "0x00000001" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "AnsiChar" /t REG_SZ /d "0x00000001" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "AutoCandState" /t REG_SZ /d "0x00000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "BallonUI" /t REG_SZ /d "0x00000001" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "BeepEnable" /t REG_SZ /d "0x00000001" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "Big5CharOnly" /t REG_SZ /d "0x00000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "CandidateLargeFont" /t REG_SZ /d "0x00000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "CandidateSortType" /t REG_SZ /d "0x00000001" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "ChangJie.All.ActiveAlphaNum" /t REG_SZ /d "0x00000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "ChangJie.All.ZkeyAsWildCard" /t REG_SZ /d "0x00000001" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "ChangJie.AssociatedWord" /t REG_SZ /d "0x00000001" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "ChangJie.IsOfflineReading" /t REG_SZ /d "0x00000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "ChangJie.ReadLayout" /t REG_SZ /d "0x00010030" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "CharMode" /t REG_SZ /d "0x00000001" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "CustomLayout" /t REG_BINARY /d "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "DefaultLanguage" /t REG_SZ /d "0x00000001" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "Delemiter" /t REG_SZ /d "0x00000001" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "Domain" /t REG_SZ /d "0x00000001" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "EnableCNSReading" /t REG_SZ /d "0x00000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "EnableExtensionA_Char" /t REG_SZ /d "0x00000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "EnableExtensionB_Char" /t REG_SZ /d "0x00000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "EudpSCK" /t REG_SZ /d "0x00000001" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "Fuzzy" /t REG_SZ /d "0x00000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "HFTLearning" /t REG_SZ /d "0x00000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "Intellegnt.Eudp" /t REG_SZ /d "0x00000001" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "Intelligent.AssociatedWord" /t REG_SZ /d "0x00000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "Intelligent.AutoFinalize" /t REG_SZ /d "0x00000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "Intelligent.AutoInputSwitch" /t REG_SZ /d "0x00000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "Intelligent.EnableFinal" /t REG_SZ /d "0x00000001" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "Intelligent.EscapeFunc" /t REG_SZ /d "0x00000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "LeadingIndicator" /t REG_SZ /d "0x00000001" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "Legacy.AutoFinalize" /t REG_SZ /d "0x00000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "Legacy.AutoInputSwitch" /t REG_SZ /d "0x00000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "Legacy.EnableFinal" /t REG_SZ /d "0x00000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "Legacy.EscapeFunc" /t REG_SZ /d "0x00000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "Legacy.Eudp" /t REG_SZ /d "0x00000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "Legacy.Modeless" /t REG_SZ /d "0x00000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "MaxCharPerSentence" /t REG_SZ /d "0x00000020" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "NewChangJie.Modeless" /t REG_SZ /d "0x00000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "NewPhonetic.IntCharMode" /t REG_SZ /d "0x00000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "NewPhonetic.Modeless" /t REG_SZ /d "0x00000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "NewQuick.Modeless" /t REG_SZ /d "0x00000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "Phonetic.All.ActiveAlphaNum" /t REG_SZ /d "0x00000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "Phonetic.All.ZkeyAsWildCard" /t REG_SZ /d "0x00000001" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "Phonetic.AssociatedWord" /t REG_SZ /d "0x00000001" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "Phonetic.IntCharMode" /t REG_SZ /d "0x00000001" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "Phonetic.IsOfflineReading" /t REG_SZ /d "0x00000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "Phonetic.ReadLayout" /t REG_SZ /d "0x00020010" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "PhrManEudpSortType" /t REG_SZ /d "0x00000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "PhrManSelfLearnSortType" /t REG_SZ /d "0x00000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "PluginLexiconInfo" /t REG_BINARY /d "0000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "PuncEnable" /t REG_SZ /d "0x00000001" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "Quick.AssociatedWord" /t REG_SZ /d "0x00000001" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "Quick.ZkeyAsWildCard" /t REG_SZ /d "0x00000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "ReconvertLength" /t REG_SZ /d "0x00000020" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "ReservedWord" /t REG_BINARY /d "0800000001000000010000000100000001000000010000002f002f0000000000000000000000000000000000000000000000660069006c006500000000000000000000000000000000000000660074007000000000000000000000000000000000000000000068007400740070000000000000000000000000000000000000006d00610069006c0074006f0000000000000000000000000000006e00650077007300000000000000000000000000000000000000770069006e0064006f007700730000000000000000000000000077007700770000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000001000000010000000100000001000000010000000100000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "ReversedReadingType" /t REG_SZ /d "0x00000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "SelfLearning" /t REG_SZ /d "0x00000001" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "SharedEudp" /t REG_SZ /d "0x00000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "ShiftLeft" /t REG_SZ /d "0x00000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "ShiftRight" /t REG_SZ /d "0x00000001" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "Surrogate" /t REG_SZ /d "0x00000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "Trigram" /t REG_SZ /d "0x00000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "UserSymbolMapping" /t REG_BINARY /d "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200031003200330034003500360037003800390030006100620063006400650066006700680069006a006b006c006d006e006f0070007100720073007400750076007700780079007a002d003d005c005b005d003b0027002c002e002f006000003011ff12ff13ff14ff15ff16ff17ff18ff19ff10ff41ff42ff43ff44ff45ff46ff47ff48ff49ff4aff4bff4cff4dff4eff4fff50ff51ff52ff53ff54ff55ff56ff57ff58ff59ff5aff00251dff3cff1430153054fe19200cff02300fff35202000210040002300240025005e0026002a00280029004100420043004400450046004700480049004a004b004c004d004e004f0050005100520053005400550056005700580059005a005f002b007c007b007d003a0022003c003e003f007e00003001ff20ff03ff04ff05ff3ffe06ff0aff08ff09ff21ff22ff23ff24ff25ff26ff27ff28ff29ff2aff2bff2cff2dff2eff2fff30ff31ff32ff33ff34ff35ff36ff37ff38ff39ff3aff3fff0bff5cff5bff5dff1aff1d201cff1eff1fff5eff200031003200330034003500360037003800390030006100620063006400650066006700680069006a006b006c006d006e006f0070007100720073007400750076007700780079007a002d003d005c005b005d003b0027002c002e002f006000003011ff12ff13ff14ff15ff16ff17ff18ff19ff10ff41ff42ff43ff44ff45ff46ff47ff48ff49ff4aff4bff4cff4dff4eff4fff50ff51ff52ff53ff54ff55ff56ff57ff58ff59ff5aff00251dff3cff1430153054fe19200cff02300fff35202000210040002300240025005e0026002a00280029004100420043004400450046004700480049004a004b004c004d004e004f0050005100520053005400550056005700580059005a005f002b007c007b007d003a0022003c003e003f007e00003001ff20ff03ff04ff05ff3ffe06ff0aff08ff09ff21ff22ff23ff24ff25ff26ff27ff28ff29ff2aff2bff2cff2dff2eff2fff30ff31ff32ff33ff34ff35ff36ff37ff38ff39ff3aff3fff0bff5cff5bff5dff1aff1d201cff1eff1fff5eff200031003200330034003500360037003800390030006100620063006400650066006700680069006a006b006c006d006e006f0070007100720073007400750076007700780079007a002d003d005c005b005d003b0027002c002e002f006000003011ff12ff13ff14ff15ff16ff17ff18ff19ff10ff41ff42ff43ff44ff45ff46ff47ff48ff49ff4aff4bff4cff4dff4eff4fff50ff51ff52ff53ff54ff55ff56ff57ff58ff59ff5aff00251dff3cff1430153054fe19200cff02300fff35202000210040002300240025005e0026002a00280029004100420043004400450046004700480049004a004b004c004d004e004f0050005100520053005400550056005700580059005a005f002b007c007b007d003a0022003c003e003f007e00003001ff20ff03ff04ff05ff3ffe06ff0aff08ff09ff21ff22ff23ff24ff25ff26ff27ff28ff29ff2aff2bff2cff2dff2eff2fff30ff31ff32ff33ff34ff35ff36ff37ff38ff39ff3aff3fff0bff5cff5bff5dff1aff1d201cff1eff1fff5eff" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70" /v "VirtualInputMode" /t REG_SZ /d "0x00000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70\FuzzyScheme" /v "Data" /t REG_BINARY /d "873f0000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ime\IMTC70\FuzzyScheme" /v "Name" /t REG_SZ /d "{EF8C6C27-997A-4af2-BC0E-A15C84790F8C}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "TabletMode" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell\StateStore" /v "ResetCacheCount" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\InstallService\State" /v "AutoUpdateLastSuccessTime" /t REG_SZ /d "2021-06-16T01:48:06-07:00" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "CertificateRevocation" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "DisableCachingOfSSLPages" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "IE5_UA_Backup_Flag" /t REG_SZ /d "5.0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "PrivacyAdvanced" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "SecureProtocols" /t REG_DWORD /d "2688" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "User Agent" /t REG_SZ /d "Mozilla/4.0 (compatible; MSIE 8.0; Win32)" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "ZonesSecurityUpgrade" /t REG_BINARY /d "044c900bd762d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "WarnonZoneCrossing" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "EnableNegotiate" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "ProxyEnable" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MigrateProxy" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache" /v "ContentLimit" /t REG_DWORD /d "330" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache" /v "TotalContentLimit" /t REG_DWORD /d "495" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache" /v "AppContainerTotalContentLimit" /t REG_DWORD /d "1000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache" /v "AppContainerContentLimit" /t REG_DWORD /d "50" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache" /v "Version" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Content" /v "CachePrefix" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Content" /v "CacheVersion" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Content" /v "CacheLimit" /t REG_DWORD /d "337920" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Cookies" /v "CachePrefix" /t REG_SZ /d "Cookie:" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Cookies" /v "CacheVersion" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Cookies" /v "CacheLimit" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\DNTException" /v "CachePrefix" /t REG_SZ /d "DNTException:" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\DNTException" /v "CachePath" /t REG_SZ /d "C:\Users\Administrator\AppData\Local\Microsoft\Windows\INetCookies\DNTException" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\DNTException" /v "CacheRelativePath" /t REG_SZ /d "Microsoft\Windows\INetCookies\DNTException" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\DNTException" /v "CacheOptions" /t REG_DWORD /d "768" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\DNTException" /v "CacheRepair" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\DNTException" /v "CacheLimit" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\DOMStore" /v "CachePrefix" /t REG_SZ /d "DOMStore" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\DOMStore" /v "CachePath" /t REG_SZ /d "C:\Users\Administrator\AppData\Local\Microsoft\Internet Explorer\DOMStore" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\DOMStore" /v "CacheRelativePath" /t REG_SZ /d "Microsoft\Internet Explorer\DOMStore" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\DOMStore" /v "CacheOptions" /t REG_DWORD /d "8" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\DOMStore" /v "CacheRepair" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\DOMStore" /v "CacheLimit" /t REG_DWORD /d "1000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\EmieSiteList" /v "CachePrefix" /t REG_SZ /d "EmieSiteList:" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\EmieSiteList" /v "CachePath" /t REG_SZ /d "C:\Users\Administrator\AppData\Local\Microsoft\Internet Explorer\EmieSiteList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\EmieSiteList" /v "CacheRelativePath" /t REG_SZ /d "Microsoft\Internet Explorer\EmieSiteList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\EmieSiteList" /v "CacheOptions" /t REG_DWORD /d "768" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\EmieSiteList" /v "CacheRepair" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\EmieSiteList" /v "CacheLimit" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\EmieUserList" /v "CachePrefix" /t REG_SZ /d "EmieUserList:" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\EmieUserList" /v "CachePath" /t REG_SZ /d "C:\Users\Administrator\AppData\Local\Microsoft\Internet Explorer\EmieUserList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\EmieUserList" /v "CacheRelativePath" /t REG_SZ /d "Microsoft\Internet Explorer\EmieUserList" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\EmieUserList" /v "CacheOptions" /t REG_DWORD /d "768" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\EmieUserList" /v "CacheRepair" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\EmieUserList" /v "CacheLimit" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\feedplat" /v "CachePrefix" /t REG_SZ /d "feedplat:" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\feedplat" /v "CachePath" /t REG_SZ /d "C:\Users\Administrator\AppData\Local\Microsoft\Feeds Cache" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\feedplat" /v "CacheRelativePath" /t REG_SZ /d "Microsoft\Feeds Cache" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\feedplat" /v "CacheOptions" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\feedplat" /v "CacheRepair" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\feedplat" /v "CacheLimit" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\iecompat" /v "CachePrefix" /t REG_SZ /d "iecompat:" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\iecompat" /v "CachePath" /t REG_SZ /d "C:\Users\Administrator\AppData\Local\Microsoft\Windows\IECompatCache" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\iecompat" /v "CacheRelativePath" /t REG_SZ /d "Microsoft\Windows\IECompatCache" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\iecompat" /v "CacheOptions" /t REG_DWORD /d "777" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\iecompat" /v "CacheRepair" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\iecompat" /v "CacheLimit" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\iecompatua" /v "CachePrefix" /t REG_SZ /d "iecompatua:" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\iecompatua" /v "CachePath" /t REG_SZ /d "C:\Users\Administrator\AppData\Local\Microsoft\Windows\IECompatUaCache" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\iecompatua" /v "CacheRelativePath" /t REG_SZ /d "Microsoft\Windows\IECompatUaCache" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\iecompatua" /v "CacheOptions" /t REG_DWORD /d "777" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\iecompatua" /v "CacheRepair" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\iecompatua" /v "CacheLimit" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\iedownload" /v "CachePrefix" /t REG_SZ /d "iedownload:" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\iedownload" /v "CachePath" /t REG_SZ /d "C:\Users\Administrator\AppData\Local\Microsoft\Windows\IEDownloadHistory" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\iedownload" /v "CacheRelativePath" /t REG_SZ /d "Microsoft\Windows\IEDownloadHistory" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\iedownload" /v "CacheOptions" /t REG_DWORD /d "9" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\iedownload" /v "CacheRepair" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\iedownload" /v "CacheLimit" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\MSHist012021061620210617" /v "CachePrefix" /t REG_SZ /d ":2021061620210617: " /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\MSHist012021061620210617" /v "CachePath" /t REG_SZ /d "C:\Users\Administrator\AppData\Local\Microsoft\Windows\History\History.IE5\MSHist012021061620210617" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\MSHist012021061620210617" /v "CacheRelativePath" /t REG_SZ /d "Microsoft\Windows\History\History.IE5\MSHist012021061620210617" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\MSHist012021061620210617" /v "CacheOptions" /t REG_DWORD /d "11" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\MSHist012021061620210617" /v "CacheRepair" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Extensible Cache\MSHist012021061620210617" /v "CacheLimit" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\History" /v "CachePrefix" /t REG_SZ /d "Visited:" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\History" /v "CacheVersion" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\History" /v "CacheLimit" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\LowCache" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\User Agent\Post Platform" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Cache" /v "Persistent" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" /v "SavedLegacySettings" /t REG_BINARY /d "4600000002000000090000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" /v "DefaultConnectionSettings" /t REG_BINARY /d "4600000002000000090000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Http Filters\RPA" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0" /v "DisplayName" /t REG_SZ /d "Computer" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0" /v "PMDisplayName" /t REG_SZ /d "Computer [Protected Mode]" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0" /v "Description" /t REG_SZ /d "Your computer" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0" /v "Icon" /t REG_SZ /d "shell32.dll#0016" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0" /v "LowIcon" /t REG_SZ /d "inetcpl.cpl#005422" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0" /v "CurrentLevel" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0" /v "Flags" /t REG_DWORD /d "33" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0" /v "1200" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0" /v "1400" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1" /v "DisplayName" /t REG_SZ /d "Local intranet" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1" /v "PMDisplayName" /t REG_SZ /d "Local intranet [Protected Mode]" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1" /v "Description" /t REG_SZ /d "This zone contains all Web sites that are on your organization's intranet." /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1" /v "Icon" /t REG_SZ /d "shell32.dll#0018" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1" /v "LowIcon" /t REG_SZ /d "inetcpl.cpl#005423" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1" /v "CurrentLevel" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1" /v "Flags" /t REG_DWORD /d "219" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1" /v "1200" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1" /v "1400" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2" /v "DisplayName" /t REG_SZ /d "Trusted sites" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2" /v "PMDisplayName" /t REG_SZ /d "Trusted sites [Protected Mode]" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2" /v "Description" /t REG_SZ /d "This zone contains Web sites that you trust not to damage your computer or data." /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2" /v "Icon" /t REG_SZ /d "inetcpl.cpl#00004480" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2" /v "LowIcon" /t REG_SZ /d "inetcpl.cpl#005424" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2" /v "CurrentLevel" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2" /v "Flags" /t REG_DWORD /d "33" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2" /v "1200" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2" /v "1400" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\3" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\3" /v "DisplayName" /t REG_SZ /d "Internet" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\3" /v "PMDisplayName" /t REG_SZ /d "Internet [Protected Mode]" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\3" /v "Description" /t REG_SZ /d "This zone contains all Web sites you haven't placed in other zones" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\3" /v "Icon" /t REG_SZ /d "inetcpl.cpl#001313" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\3" /v "LowIcon" /t REG_SZ /d "inetcpl.cpl#005425" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\3" /v "CurrentLevel" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\3" /v "Flags" /t REG_DWORD /d "33" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\3" /v "1200" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\3" /v "1400" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4" /v "DisplayName" /t REG_SZ /d "Restricted sites" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4" /v "PMDisplayName" /t REG_SZ /d "Restricted sites [Protected Mode]" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4" /v "Description" /t REG_SZ /d "This zone contains Web sites that could potentially damage your computer or data." /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4" /v "Icon" /t REG_SZ /d "inetcpl.cpl#00004481" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4" /v "LowIcon" /t REG_SZ /d "inetcpl.cpl#005426" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4" /v "CurrentLevel" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4" /v "Flags" /t REG_DWORD /d "33" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4" /v "1200" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4" /v "1400" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\P3P\History" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Passport\LowDAMap" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap" /v "ProxyByPass" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap" /v "IntranetName" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap" /v "UNCAsIntranet" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap" /v "AutoDetect" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\ProtocolDefaults" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\ProtocolDefaults" /v "http" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\ProtocolDefaults" /v "https" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\ProtocolDefaults" /v "ftp" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\ProtocolDefaults" /v "file" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\ProtocolDefaults" /v "@ivt" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\ProtocolDefaults" /v "shell" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\ProtocolDefaults" /v "knownfolder" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Ranges" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones" /v "SelfHealCount" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones" /v "SecuritySafe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" /v "DisplayName" /t REG_SZ /d "Computer" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" /v "PMDisplayName" /t REG_SZ /d "Computer [Protected Mode]" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" /v "Description" /t REG_SZ /d "Your computer" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" /v "Icon" /t REG_SZ /d "shell32.dll#0016" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" /v "LowIcon" /t REG_SZ /d "inetcpl.cpl#005422" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" /v "CurrentLevel" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" /v "Flags" /t REG_DWORD /d "33" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" /v "1200" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" /v "1400" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" /v "DisplayName" /t REG_SZ /d "Local intranet" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" /v "PMDisplayName" /t REG_SZ /d "Local intranet [Protected Mode]" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" /v "Description" /t REG_SZ /d "This zone contains all Web sites that are on your organization's intranet." /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" /v "Icon" /t REG_SZ /d "shell32.dll#0018" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" /v "LowIcon" /t REG_SZ /d "inetcpl.cpl#005423" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" /v "CurrentLevel" /t REG_DWORD /d "66816" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" /v "Flags" /t REG_DWORD /d "219" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" /v "1200" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" /v "1400" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" /v "2500" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" /v "DisplayName" /t REG_SZ /d "Trusted sites" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" /v "PMDisplayName" /t REG_SZ /d "Trusted sites [Protected Mode]" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" /v "Description" /t REG_SZ /d "This zone contains Web sites that you trust not to damage your computer or data." /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" /v "Icon" /t REG_SZ /d "inetcpl.cpl#00004480" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" /v "LowIcon" /t REG_SZ /d "inetcpl.cpl#005424" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" /v "CurrentLevel" /t REG_DWORD /d "69632" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" /v "Flags" /t REG_DWORD /d "71" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" /v "1200" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" /v "1400" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "DisplayName" /t REG_SZ /d "Internet" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "PMDisplayName" /t REG_SZ /d "Internet [Protected Mode]" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "Description" /t REG_SZ /d "This zone contains all Web sites you haven't placed in other zones" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "Icon" /t REG_SZ /d "inetcpl.cpl#001313" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "LowIcon" /t REG_SZ /d "inetcpl.cpl#005425" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "CurrentLevel" /t REG_DWORD /d "70912" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "Flags" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1200" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1400" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "DisplayName" /t REG_SZ /d "Restricted sites" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "PMDisplayName" /t REG_SZ /d "Restricted sites [Protected Mode]" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "Description" /t REG_SZ /d "This zone contains Web sites that could potentially damage your computer or data." /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "Icon" /t REG_SZ /d "inetcpl.cpl#00004481" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "LowIcon" /t REG_SZ /d "inetcpl.cpl#005426" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "CurrentLevel" /t REG_DWORD /d "73728" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "Flags" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1200" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1400" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen" /v "LockAppAumId" /t REG_SZ /d "Microsoft.LockApp_cw5n1h2txyewy!WindowsDefaultLockScreen" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Mobility" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "QuietHoursTelemetryLastRun" /t REG_BINARY /d "65bcc96000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PenWorkspace\Notes" /v "NotesApp" /t REG_SZ /d "Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe!App" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "DisableThumbnails" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PowerCPL" /v "PlansVisible" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PrecisionTouchPad" /v "AAPThreshold" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PrecisionTouchPad" /v "CursorSpeed" /t REG_DWORD /d "10" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PrecisionTouchPad" /v "EnableEdgy" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PrecisionTouchPad" /v "LeaveOnWithMouse" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PrecisionTouchPad" /v "PanEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PrecisionTouchPad" /v "RightClickZoneEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PrecisionTouchPad" /v "ScrollDirection" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PrecisionTouchPad" /v "TapAndDrag" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PrecisionTouchPad" /v "TapsEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PrecisionTouchPad" /v "TwoFingerTapEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PrecisionTouchPad" /v "ZoomEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PrecisionTouchPad\Status" /v "Enabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" /v "DatabaseMigrationCompleted" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Applications\Windows.SystemToast.CloudExperienceHostLauncher" /v "ApplicationType" /t REG_DWORD /d "1073741824" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Applications\Windows.SystemToast.CloudExperienceHostLauncher" /v "Capabilities" /t REG_DWORD /d "9471" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Applications\Windows.SystemToast.CloudExperienceHostLauncher" /v "PackageMoniker" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Applications\Windows.SystemToast.CloudExperienceHostLauncherCustom" /v "ApplicationType" /t REG_DWORD /d "1073741824" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Applications\Windows.SystemToast.CloudExperienceHostLauncherCustom" /v "Capabilities" /t REG_DWORD /d "9471" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Applications\Windows.SystemToast.CloudExperienceHostLauncherCustom" /v "PackageMoniker" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Applications\Windows.SystemToast.DisplaySettings" /v "ApplicationType" /t REG_DWORD /d "1073741824" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Applications\Windows.SystemToast.DisplaySettings" /v "Capabilities" /t REG_DWORD /d "9471" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Applications\Windows.SystemToast.DisplaySettings" /v "PackageMoniker" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Applications\Windows.SystemToast.FodHelper" /v "ApplicationType" /t REG_DWORD /d "1073741824" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Applications\Windows.SystemToast.FodHelper" /v "Capabilities" /t REG_DWORD /d "9471" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Applications\Windows.SystemToast.FodHelper" /v "PackageMoniker" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Applications\Windows.SystemToast.MobilityExperience" /v "ApplicationType" /t REG_DWORD /d "1073741824" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Applications\Windows.SystemToast.MobilityExperience" /v "Capabilities" /t REG_DWORD /d "9471" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Applications\Windows.SystemToast.MobilityExperience" /v "PackageMoniker" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Applications\Windows.SystemToast.Suggested" /v "ApplicationType" /t REG_DWORD /d "1073741824" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Applications\Windows.SystemToast.Suggested" /v "Capabilities" /t REG_DWORD /d "9471" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Applications\Windows.SystemToast.Suggested" /v "PackageMoniker" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Applications\Windows.SystemToast.WindowsTip" /v "ApplicationType" /t REG_DWORD /d "1073741824" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Applications\Windows.SystemToast.WindowsTip" /v "Capabilities" /t REG_DWORD /d "9471" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Applications\Windows.SystemToast.WindowsTip" /v "PackageMoniker" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup" /v "Completed" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\1527c705-839a-4832-9118-54d4Bd6a0c89_cw5n1h2txyewy!Microsoft.Windows.FilePicker" /v "Setting" /t REG_SZ /d "c:tile,s:lock:toast,s:tile,s:banner,s:toast,s:badge,s:audio,s:voip,s:listenerEnabled,c:cloud,c:toast,c:badge,c:ringing,c:tickle" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\1527c705-839a-4832-9118-54d4Bd6a0c89_cw5n1h2txyewy!Microsoft.Windows.FilePicker" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\c5e2524a-ea46-4f67-841f-6a9465d9d515_cw5n1h2txyewy!App" /v "Setting" /t REG_SZ /d "c:tile,s:lock:toast,s:tile,s:banner,s:toast,s:badge,s:audio,s:voip,s:listenerEnabled,c:cloud,c:toast,c:badge,c:ringing,c:tickle" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\c5e2524a-ea46-4f67-841f-6a9465d9d515_cw5n1h2txyewy!App" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\E2A4F912-2574-4A75-9BB0-0D023378592B_cw5n1h2txyewy!Microsoft.Windows.AppResolverUX" /v "Setting" /t REG_SZ /d "c:tile,s:lock:toast,s:tile,s:banner,s:toast,s:badge,s:audio,s:voip,s:listenerEnabled,c:cloud,c:toast,c:badge,c:ringing,c:tickle" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\E2A4F912-2574-4A75-9BB0-0D023378592B_cw5n1h2txyewy!Microsoft.Windows.AppResolverUX" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE_cw5n1h2txyewy!App" /v "Setting" /t REG_SZ /d "c:tile,s:lock:toast,s:tile,s:banner,s:toast,s:badge,s:audio,s:voip,s:listenerEnabled,c:cloud,c:toast,c:badge,c:ringing,c:tickle" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE_cw5n1h2txyewy!App" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\FamilySafety_Settings" /v "Setting" /t REG_SZ /d "c:cloud,c:internet,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\FamilySafety_Settings" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\FamilySafety_Settings" /v "wnsId" /t REG_SZ /d "windows.familysafety_cw5n1h2txyewy" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\FamilySafety_Settings" /v "wnfEventName" /t REG_SZ /d "4725692431943338101" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy!App" /v "Setting" /t REG_SZ /d "c:toast,c:badge,c:cloud,c:internet,c:ringing,c:tile,c:tickle,s:toast,s:audio,s:badge,s:banner,s:listenerEnabled,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy!App" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.AccountsControl_cw5n1h2txyewy!App" /v "Setting" /t REG_SZ /d "c:tile,s:lock:toast,s:tile,s:banner,s:toast,s:badge,s:audio,s:voip,s:listenerEnabled,c:cloud,c:toast,c:internet,c:badge,c:ringing,c:tickle" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.AccountsControl_cw5n1h2txyewy!App" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.AsyncTextService_8wekyb3d8bbwe!App" /v "Setting" /t REG_SZ /d "c:tile,s:lock:toast,s:tile,s:banner,s:toast,s:badge,s:audio,s:voip,s:listenerEnabled,c:cloud,c:toast,c:badge,c:ringing,c:tickle" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.AsyncTextService_8wekyb3d8bbwe!App" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.BioEnrollment_cw5n1h2txyewy!App" /v "Setting" /t REG_SZ /d "c:toast,c:badge,c:cloud,c:ringing,c:tile,c:tickle,s:toast,s:audio,s:badge,s:banner,s:listenerEnabled,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.BioEnrollment_cw5n1h2txyewy!App" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.CredDialogHost_cw5n1h2txyewy!App" /v "Setting" /t REG_SZ /d "c:tile,s:lock:toast,s:tile,s:banner,s:toast,s:badge,s:audio,s:voip,s:listenerEnabled,c:cloud,c:toast,c:badge,c:ringing,c:tickle" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.CredDialogHost_cw5n1h2txyewy!App" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.ECApp_8wekyb3d8bbwe!App" /v "Setting" /t REG_SZ /d "c:tile,s:lock:toast,s:tile,s:banner,s:toast,s:badge,s:audio,s:voip,s:listenerEnabled,c:cloud,c:toast,c:badge,c:ringing,c:tickle" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.ECApp_8wekyb3d8bbwe!App" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.HEIFImageExtension_8wekyb3d8bbwe!App" /v "Setting" /t REG_SZ /d "c:tile,s:lock:toast,s:tile,s:banner,s:toast,s:badge,s:audio,s:voip,s:listenerEnabled,c:cloud,c:toast,c:badge,c:ringing,c:tickle" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.HEIFImageExtension_8wekyb3d8bbwe!App" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.LockApp_cw5n1h2txyewy!WindowsDefaultLockScreen" /v "Setting" /t REG_SZ /d "c:tile,s:lock:toast,s:tile,s:banner,s:toast,s:badge,s:audio,s:voip,s:listenerEnabled,c:cloud,c:toast,c:internet,c:badge,c:ringing,c:tickle" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.LockApp_cw5n1h2txyewy!WindowsDefaultLockScreen" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.VP9VideoExtensions_8wekyb3d8bbwe!App" /v "Setting" /t REG_SZ /d "c:tile,s:lock:toast,s:tile,s:banner,s:toast,s:badge,s:audio,s:voip,s:listenerEnabled,c:cloud,c:toast,c:badge,c:ringing,c:tickle" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.VP9VideoExtensions_8wekyb3d8bbwe!App" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.WebpImageExtension_8wekyb3d8bbwe!App" /v "Setting" /t REG_SZ /d "c:tile,s:lock:toast,s:tile,s:banner,s:toast,s:badge,s:audio,s:voip,s:listenerEnabled,c:cloud,c:toast,c:badge,c:ringing,c:tickle" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.WebpImageExtension_8wekyb3d8bbwe!App" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Win32WebViewHost_cw5n1h2txyewy!DPI.PerMonitorAware" /v "Setting" /t REG_SZ /d "c:tile,s:lock:toast,s:tile,s:banner,s:toast,s:badge,s:audio,s:voip,s:listenerEnabled,c:cloud,c:toast,c:internet,c:badge,c:ringing,c:tickle" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Win32WebViewHost_cw5n1h2txyewy!DPI.PerMonitorAware" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Win32WebViewHost_cw5n1h2txyewy!DPI.SystemAware" /v "Setting" /t REG_SZ /d "c:tile,s:lock:toast,s:tile,s:banner,s:toast,s:badge,s:audio,s:voip,s:listenerEnabled,c:cloud,c:toast,c:internet,c:badge,c:ringing,c:tickle" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Win32WebViewHost_cw5n1h2txyewy!DPI.SystemAware" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Win32WebViewHost_cw5n1h2txyewy!DPI.Unaware" /v "Setting" /t REG_SZ /d "c:tile,s:lock:toast,s:tile,s:banner,s:toast,s:badge,s:audio,s:voip,s:listenerEnabled,c:cloud,c:toast,c:internet,c:badge,c:ringing,c:tickle" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Win32WebViewHost_cw5n1h2txyewy!DPI.Unaware" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.Apprep.ChxApp_cw5n1h2txyewy!App" /v "Setting" /t REG_SZ /d "c:tile,s:lock:toast,s:tile,s:banner,s:toast,s:badge,s:audio,s:voip,s:listenerEnabled,c:cloud,c:toast,c:internet,c:badge,c:ringing,c:tickle" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.Apprep.ChxApp_cw5n1h2txyewy!App" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.AssignedAccessLockApp_cw5n1h2txyewy!App" /v "Setting" /t REG_SZ /d "c:tile,s:lock:toast,s:tile,s:banner,s:toast,s:badge,s:audio,s:voip,s:listenerEnabled,c:cloud,c:toast,c:badge,c:ringing,c:tickle" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.AssignedAccessLockApp_cw5n1h2txyewy!App" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.CallingShellApp_cw5n1h2txyewy!Microsoft.Windows.CallingShellApp" /v "Setting" /t REG_SZ /d "c:tile,s:lock:toast,s:tile,s:banner,s:toast,s:badge,s:audio,s:voip,s:listenerEnabled,c:cloud,c:toast,c:badge,c:ringing,c:tickle" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.CallingShellApp_cw5n1h2txyewy!Microsoft.Windows.CallingShellApp" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.CapturePicker_cw5n1h2txyewy!App" /v "Setting" /t REG_SZ /d "c:tile,s:lock:toast,s:tile,s:banner,s:toast,s:badge,s:audio,s:voip,s:listenerEnabled,c:cloud,c:toast,c:badge,c:ringing,c:tickle" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.CapturePicker_cw5n1h2txyewy!App" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy!App" /v "Setting" /t REG_SZ /d "c:toast,c:badge,c:cloud,c:internet,c:ringing,c:tile,c:tickle,s:toast,s:audio,s:badge,s:banner,s:listenerEnabled,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.CloudExperienceHost_cw5n1h2txyewy!App" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy!App" /v "Setting" /t REG_SZ /d "c:toast,c:badge,c:cloud,c:internet,c:ringing,c:tile,c:tickle,s:toast,s:audio,s:badge,s:banner,s:listenerEnabled,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy!App" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.InputSwitchToastHandler" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.InputSwitchToastHandler" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.InputSwitchToastHandler" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.LanguageComponentsInstaller" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.LanguageComponentsInstaller" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.LanguageComponentsInstaller" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.NarratorQuickStart_8wekyb3d8bbwe!App" /v "Setting" /t REG_SZ /d "c:tile,s:lock:toast,s:tile,s:banner,s:toast,s:badge,s:audio,s:voip,s:listenerEnabled,c:cloud,c:toast,c:internet,c:badge,c:ringing,c:tickle" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.NarratorQuickStart_8wekyb3d8bbwe!App" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.OOBENetworkCaptivePortal_cw5n1h2txyewy!App" /v "Setting" /t REG_SZ /d "c:toast,c:badge,c:cloud,c:internet,c:ringing,c:tile,c:tickle,s:toast,s:audio,s:badge,s:banner,s:listenerEnabled,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.OOBENetworkCaptivePortal_cw5n1h2txyewy!App" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.OOBENetworkConnectionFlow_cw5n1h2txyewy!App" /v "Setting" /t REG_SZ /d "c:toast,c:badge,c:cloud,c:ringing,c:tile,c:tickle,s:toast,s:audio,s:badge,s:banner,s:listenerEnabled,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.OOBENetworkConnectionFlow_cw5n1h2txyewy!App" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.ParentalControls" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.ParentalControls" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.ParentalControls" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.ParentalControls_cw5n1h2txyewy!App" /v "Setting" /t REG_SZ /d "c:tile,s:lock:toast,s:tile,s:banner,s:toast,s:badge,s:audio,s:voip,s:listenerEnabled,c:cloud,c:toast,c:internet,c:badge,c:ringing,c:tickle" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.ParentalControls_cw5n1h2txyewy!App" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.PeopleExperienceHost_cw5n1h2txyewy!App" /v "Setting" /t REG_SZ /d "c:tile,s:lock:toast,s:tile,s:banner,s:toast,s:badge,s:audio,s:voip,s:listenerEnabled,c:cloud,c:toast,c:internet,c:badge,c:ringing,c:tickle" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.PeopleExperienceHost_cw5n1h2txyewy!App" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.PinningConfirmationDialog_cw5n1h2txyewy!App" /v "Setting" /t REG_SZ /d "c:tile,s:lock:toast,s:tile,s:banner,s:toast,s:badge,s:audio,s:voip,s:listenerEnabled,c:cloud,c:toast,c:badge,c:ringing,c:tickle" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.PinningConfirmationDialog_cw5n1h2txyewy!App" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.Search_cw5n1h2txyewy!CortanaUI" /v "Setting" /t REG_SZ /d "c:toast,c:badge,c:cloud,c:internet,c:ringing,c:tile,c:tickle,s:toast,s:audio,s:badge,s:banner,s:listenerEnabled,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.Search_cw5n1h2txyewy!CortanaUI" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.Search_cw5n1h2txyewy!ShellFeedsUI" /v "Setting" /t REG_SZ /d "c:toast,c:badge,c:cloud,c:internet,c:ringing,c:tile,c:tickle,s:toast,s:audio,s:badge,s:banner,s:listenerEnabled,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.Search_cw5n1h2txyewy!ShellFeedsUI" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.SecureAssessmentBrowser_cw5n1h2txyewy!App" /v "Setting" /t REG_SZ /d "c:tile,s:lock:toast,s:tile,s:banner,s:toast,s:badge,s:audio,s:voip,s:listenerEnabled,c:cloud,c:toast,c:internet,c:badge,c:ringing,c:tickle" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.SecureAssessmentBrowser_cw5n1h2txyewy!App" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy!App" /v "Setting" /t REG_SZ /d "c:toast,c:badge,c:cloud,c:internet,c:ringing,c:tile,c:tickle,s:toast,s:audio,s:badge,s:banner,s:listenerEnabled,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy!App" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy!App" /v "Setting" /t REG_SZ /d "c:toast,c:badge,c:cloud,c:internet,c:ringing,c:tile,c:tickle,s:toast,s:audio,s:badge,s:banner,s:listenerEnabled,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy!App" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.XGpuEjectDialog_cw5n1h2txyewy!Microsoft.Windows.XGpuEjectDialog" /v "Setting" /t REG_SZ /d "c:tile,s:lock:toast,s:tile,s:banner,s:toast,s:badge,s:audio,s:voip,s:listenerEnabled,c:cloud,c:toast,c:badge,c:ringing,c:tickle" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.Windows.XGpuEjectDialog_cw5n1h2txyewy!Microsoft.Windows.XGpuEjectDialog" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.WindowsStore_8wekyb3d8bbwe!App" /v "Setting" /t REG_SZ /d "s:banner,s:toast,s:audio,c:toast,c:ringing" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.WindowsStore_8wekyb3d8bbwe!App" /v "appType" /t REG_SZ /d "app:desktop" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.WindowsStore_8wekyb3d8bbwe!App" /v "wnsId" /t REG_SZ /d "NonImmersivePackage" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.XboxGameCallableUI_cw5n1h2txyewy!Microsoft.XboxGameCallableUI" /v "Setting" /t REG_SZ /d "c:tile,s:lock:toast,s:tile,s:banner,s:toast,s:badge,s:audio,s:voip,s:listenerEnabled,c:cloud,c:toast,c:internet,c:badge,c:ringing,c:tickle" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Microsoft.XboxGameCallableUI_cw5n1h2txyewy!Microsoft.XboxGameCallableUI" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\MicrosoftWindows.Client.CBS_cw5n1h2txyewy!Global.IrisService" /v "Setting" /t REG_SZ /d "c:toast,c:badge,c:cloud,c:internet,c:ringing,c:tile,c:tickle,s:toast,s:audio,s:badge,s:banner,s:listenerEnabled,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\MicrosoftWindows.Client.CBS_cw5n1h2txyewy!Global.IrisService" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\MicrosoftWindows.Client.CBS_cw5n1h2txyewy!InputApp" /v "Setting" /t REG_SZ /d "c:toast,c:badge,c:cloud,c:internet,c:ringing,c:tile,c:tickle,s:toast,s:audio,s:badge,s:banner,s:listenerEnabled,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\MicrosoftWindows.Client.CBS_cw5n1h2txyewy!InputApp" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\MicrosoftWindows.Client.CBS_cw5n1h2txyewy!PackageMetadata" /v "Setting" /t REG_SZ /d "c:toast,c:badge,c:cloud,c:internet,c:ringing,c:tile,c:tickle,s:toast,s:audio,s:badge,s:banner,s:listenerEnabled,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\MicrosoftWindows.Client.CBS_cw5n1h2txyewy!PackageMetadata" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\MicrosoftWindows.Client.CBS_cw5n1h2txyewy!ScreenClipping" /v "Setting" /t REG_SZ /d "c:toast,c:badge,c:cloud,c:internet,c:ringing,c:tile,c:tickle,s:toast,s:audio,s:badge,s:banner,s:listenerEnabled,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\MicrosoftWindows.Client.CBS_cw5n1h2txyewy!ScreenClipping" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\MicrosoftWindows.UndockedDevKit_cw5n1h2txyewy!App" /v "Setting" /t REG_SZ /d "c:toast,c:badge,c:cloud,c:ringing,c:tile,c:tickle,s:toast,s:audio,s:badge,s:banner,s:listenerEnabled,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\MicrosoftWindows.UndockedDevKit_cw5n1h2txyewy!App" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\NcsiUwpApp_8wekyb3d8bbwe!App" /v "Setting" /t REG_SZ /d "c:tile,s:lock:toast,s:tile,s:banner,s:toast,s:badge,s:audio,s:voip,s:listenerEnabled,c:cloud,c:toast,c:internet,c:badge,c:ringing,c:tickle" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\NcsiUwpApp_8wekyb3d8bbwe!App" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\NVIDIACorp.NVIDIAControlPanel_56jybvy8sckqj!NVIDIACorp.NVIDIAControlPanel" /v "Setting" /t REG_SZ /d "c:tile,s:lock:toast,s:tile,s:banner,s:toast,s:badge,s:audio,s:voip,s:listenerEnabled,c:cloud,c:toast,c:internet,c:badge,c:ringing,c:tickle" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\NVIDIACorp.NVIDIAControlPanel_56jybvy8sckqj!NVIDIACorp.NVIDIAControlPanel" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\RealtekSemiconductorCorp.RealtekAudioControl_dt26b99r8h8gj!App" /v "Setting" /t REG_SZ /d "c:tile,s:lock:toast,s:tile,s:banner,s:toast,s:badge,s:audio,s:voip,s:listenerEnabled,c:cloud,c:toast,c:badge,c:ringing,c:tickle" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\RealtekSemiconductorCorp.RealtekAudioControl_dt26b99r8h8gj!App" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.CBSPreview_cw5n1h2txyewy!Microsoft.Windows.CBSPreview" /v "Setting" /t REG_SZ /d "c:tile,s:lock:toast,s:tile,s:banner,s:toast,s:badge,s:audio,s:voip,s:listenerEnabled,c:cloud,c:toast,c:badge,c:ringing,c:tickle" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.CBSPreview_cw5n1h2txyewy!Microsoft.Windows.CBSPreview" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.Defender" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.Defender" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.Defender" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel" /v "Setting" /t REG_SZ /d "c:toast,c:tile,s:toast,s:audio,s:badge,s:banner,s:listenerEnabled,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel" /v "appType" /t REG_SZ /d "app:immersive" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.System.AppInitiatedDownload" /v "Setting" /t REG_SZ /d "c:toast,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.System.AppInitiatedDownload" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.System.AppInitiatedDownload" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.System.Audio" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.System.Audio" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.System.Audio" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.System.Continuum" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.System.Continuum" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.System.Continuum" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.System.MiracastReceiver" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.System.MiracastReceiver" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.System.MiracastReceiver" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.System.NearShareExperienceReceive" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.System.NearShareExperienceReceive" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.System.NearShareExperienceReceive" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.System.ShareExperience" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.System.ShareExperience" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.System.ShareExperience" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.AudioTroubleshooter" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.AudioTroubleshooter" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.AudioTroubleshooter" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.AutoPlay" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.AutoPlay" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.AutoPlay" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.BackgroundAccess" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.BackgroundAccess" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.BackgroundAccess" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.BackupReminder" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.BackupReminder" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.BackupReminder" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.BdeUnlock" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.BdeUnlock" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.BdeUnlock" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.BitLockerPolicyRefresh" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.BitLockerPolicyRefresh" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.BitLockerPolicyRefresh" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Bthprops" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Bthprops" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Bthprops" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.BthQuickPair" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.BthQuickPair" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.BthQuickPair" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Calling" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Calling" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Calling" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Calling.SystemAlertNotification" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Calling.SystemAlertNotification" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Calling.SystemAlertNotification" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.CloudExperienceHostLauncher" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.CloudExperienceHostLauncher" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.CloudExperienceHostLauncher" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.CloudExperienceHostLauncherCustom" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.CloudExperienceHostLauncherCustom" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.CloudExperienceHostLauncherCustom" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Compat" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Compat" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Compat" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.DeviceConsent" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.DeviceConsent" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.DeviceConsent" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.DeviceEnrollmentActivity" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.DeviceEnrollmentActivity" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.DeviceEnrollmentActivity" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.DeviceManagement" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.DeviceManagement" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.DeviceManagement" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Devices" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Devices" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Devices" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.DisplaySettings" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.DisplaySettings" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.DisplaySettings" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.EnterpriseDataProtection" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.EnterpriseDataProtection" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.EnterpriseDataProtection" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Explorer" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Explorer" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Explorer" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.FodHelper" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.FodHelper" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.FodHelper" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.HelloFace" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.HelloFace" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.HelloFace" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.LocationManager" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.LocationManager" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.LocationManager" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.LowDisk" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.LowDisk" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.LowDisk" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.MobilityExperience" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.MobilityExperience" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.MobilityExperience" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.NfpAppAcquire" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.NfpAppAcquire" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.NfpAppAcquire" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.NfpAppLaunch" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.NfpAppLaunch" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.NfpAppLaunch" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.NfpDevicePairing" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.NfpDevicePairing" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.NfpDevicePairing" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.NfpReceiveContent" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.NfpReceiveContent" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.NfpReceiveContent" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Print.Notification" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Print.Notification" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Print.Notification" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.RasToastNotifier" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.RasToastNotifier" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.RasToastNotifier" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.SecurityAndMaintenance" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.SecurityAndMaintenance" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.SecurityAndMaintenance" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.SecurityCenter" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.SecurityCenter" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.SecurityCenter" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.ServiceInitiatedHealing.Notification" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.ServiceInitiatedHealing.Notification" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.ServiceInitiatedHealing.Notification" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Share" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Share" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Share" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.SoftLanding" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.SoftLanding" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.SoftLanding" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.SpeechServices" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.SpeechServices" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.SpeechServices" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.StorSvc" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.StorSvc" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.StorSvc" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Suggested" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Suggested" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Suggested" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Usb.Notification" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Usb.Notification" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Usb.Notification" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.WiFiNetworkManager" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.WiFiNetworkManager" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.WiFiNetworkManager" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.WindowsTip" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.WindowsTip" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.WindowsTip" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.WindowsUpdate.Notification" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.WindowsUpdate.Notification" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.WindowsUpdate.Notification" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Wwansvc" /v "Setting" /t REG_SZ /d "c:toast,c:ringing,s:tickle,s:toast,s:audio,s:badge,s:banner,s:lock:badge,s:listenerEnabled,s:lock:tile,s:lock:toast,s:tile,s:voip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Wwansvc" /v "appType" /t REG_SZ /d "app:system" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\Backup\Windows.SystemToast.Wwansvc" /v "wnsId" /t REG_SZ /d "System" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\wpnidm" /v "Path" /t REG_SZ /d "C:\Users\Administrator\AppData\Local\Microsoft\Windows\Notifications\wpnidm" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications\wpnidm" /v "ContainerSize" /t REG_DWORD /d "1048576" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RADAR" /v "CLResolutionInterval" /t REG_DWORD /d "5" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RADAR" /v "DisplayInterval" /t REG_DWORD /d "1440" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Screensavers\Bubbles\Screen 1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Screensavers\Bubbles\Screen 2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Screensavers\Mystify\Screen 1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Screensavers\Mystify\Screen 2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Screensavers\Ribbons\Screen 1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Screensavers\Ribbons\Screen 2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Screensavers\ssText3d\Screen 1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Screensavers\ssText3d\Screen 2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "InstalledWin32AppsRevision" /t REG_SZ /d "{459FA3D2-D55B-4E31-B750-6AE09E25E876}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "InstalledPackagedAppsRevision" /t REG_SZ /d "{E78A6A5D-A36D-416D-A7E3-FCF73DD75716}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "IsAssignedAccess" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaStateLastRun" /t REG_BINARY /d "d8b9c96000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "NamespaceSettingsRevision" /t REG_SZ /d "{0C68961E-84A0-4F04-BA08-14E199D0BB99}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search\Flighting" /v "CachedFeatureString" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search\Microsoft.Windows.Search_cw5n1h2txyewy\AppsConstraintIndex" /v "CurrentConstraintIndexCabPath" /t REG_SZ /d "C:\Users\Administrator\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\LocalState\ConstraintIndex\Input_{4194318b-ab64-4ec0-b0f0-54051b9bd5d3}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search\Microsoft.Windows.Search_cw5n1h2txyewy\AppsConstraintIndex" /v "LatestConstraintIndexFolder" /t REG_SZ /d "C:\Users\Administrator\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\LocalState\ConstraintIndex\Apps_{57f0c790-4c93-4ac0-aee3-975e664ff15c}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search\Microsoft.Windows.Search_cw5n1h2txyewy\AppsConstraintIndex" /v "IndexedLanguage" /t REG_SZ /d "en-US" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search\Microsoft.Windows.Search_cw5n1h2txyewy\SettingsConstraintIndex" /v "CurrentConstraintIndexCabPath" /t REG_SZ /d "C:\Users\Administrator\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\LocalState\ConstraintIndex\Input_{4194318b-ab64-4ec0-b0f0-54051b9bd5d3}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search\Microsoft.Windows.Search_cw5n1h2txyewy\SettingsConstraintIndex" /v "LatestConstraintIndexFolder" /t REG_SZ /d "C:\Users\Administrator\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\LocalState\ConstraintIndex\Settings_{b1923176-7a58-4521-b8dd-69ddfa344c9d}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search\Microsoft.Windows.Search_cw5n1h2txyewy\SettingsConstraintIndex" /v "IndexedLanguage" /t REG_SZ /d "en-US" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search\Launch" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v "SafeSearchMode" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Security and Maintenance\Checks\{01979c6a-42fa-414c-b8aa-eee2c8202018}.check.100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Security and Maintenance\Checks\{01979c6a-42fa-414c-b8aa-eee2c8202018}.check.101" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Security and Maintenance\Checks\{11CD958A-C507-4EF3-B3F2-5FD9DFBD2C78}.check.101" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Security and Maintenance\Checks\{2374911B-B114-42FE-900D-54F95FEE92E5}.check.100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Security and Maintenance\Checks\{34A3697E-0F10-4E48-AF3C-F869B5BABEBB}.check.9001" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Security and Maintenance\Checks\{34A3697E-0F10-4E48-AF3C-F869B5BABEBB}.check.9002" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Security and Maintenance\Checks\{34A3697E-0F10-4E48-AF3C-F869B5BABEBB}.check.9003" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Security and Maintenance\Checks\{34A3697E-0F10-4E48-AF3C-F869B5BABEBB}.check.9004" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Security and Maintenance\Checks\{3FF37A1C-A68D-4D6E-8C9B-F79E8B16C482}.check.100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Security and Maintenance\Checks\{852FB1F8-5CC6-4567-9C0E-7C330F8807C2}.check.100" /v "CheckSetting" /t REG_BINARY /d "23004100430042006c006f00620000000000000000000000010000001000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Security and Maintenance\Checks\{96F4A050-7E31-453C-88BE-9634F4E02139}.check.8010" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Security and Maintenance\Checks\{A5268B8E-7DB5-465b-BAB7-BDCDA39A394A}.check.100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Security and Maintenance\Checks\{AA4C798D-D91B-4B07-A013-787F5803D6FC}.check.100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Security and Maintenance\Checks\{B447B4DB-7780-11E0-ADA3-18A90531A85A}.check.100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Security and Maintenance\Checks\{C8E6F269-B90A-4053-A3BE-499AFCEC98C4}.check.0" /v "CheckSetting" /t REG_BINARY /d "23004100430042006c006f00620000000000000000000000010000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Security and Maintenance\Checks\{DE7B24EA-73C8-4A09-985D-5BDADCFA9017}.check.800" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Security and Maintenance\Checks\{E8433B72-5842-4d43-8645-BC2C35960837}.check.100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Security and Maintenance\Checks\{E8433B72-5842-4d43-8645-BC2C35960837}.check.101" /v "CheckSetting" /t REG_BINARY /d "23004100430042006c006f00620000000000000000000000010000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Security and Maintenance\Checks\{E8433B72-5842-4d43-8645-BC2C35960837}.check.102" /v "CheckSetting" /t REG_BINARY /d "23004100430042006c006f00620000000000000000000000010000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Security and Maintenance\Checks\{E8433B72-5842-4d43-8645-BC2C35960837}.check.104" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Security and Maintenance\Checks\{E8433B72-5842-4d43-8645-BC2C35960837}.check.106" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Security and Maintenance\Providers\EventLog\{01979c6a-42fa-414c-b8aa-eee2c8202018}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Security and Maintenance\Providers\EventLog\{11CD958A-C507-4EF3-B3F2-5FD9DFBD2C78}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Security and Maintenance\Providers\EventLog\{2374911B-B114-42FE-900D-54F95FEE92E5}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Security and Maintenance\Providers\EventLog\{34A3697E-0F10-4E48-AF3C-F869B5BABEBB}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Security and Maintenance\Providers\EventLog\{A5268B8E-7DB5-465b-BAB7-BDCDA39A394A}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Security and Maintenance\Providers\EventLog\{AA4C798D-D91B-4B07-A013-787F5803D6FC}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "BackupPolicy" /t REG_DWORD /d "60" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "DeviceMetadataUploaded" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "SettingsVersion" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "PriorLogons" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "SettingsVersion" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /v "Enabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "SettingsVersion" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "SettingsVersion" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "SettingsVersion" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "SettingsVersion" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions" /v "HasFlushedShellExtCache" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached" /v "{4234D49B-0245-4DF3-B780-3893943456E1} {000214E6-0000-0000-C000-000000000046} 0xFFFF" /t REG_BINARY /d "010000000000000061dcd0bf8b62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached" /v "{B2952B16-0E07-4E5A-B993-58C52CB94CAE} {000214E6-0000-0000-C000-000000000046} 0xFFFF" /t REG_BINARY /d "01000000000000006ac7dcbf8b62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached" /v "{C7657C4A-9F68-40FA-A4DF-96BC08EB3551} {E357FCCD-A995-4576-B01F-234630154E96} 0xFFFF" /t REG_BINARY /d "0100000000000000f9f601c18b62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached" /v "{D9144DCD-E998-4ECA-AB6A-DCD83CCBA16D} {0C6C4200-C589-11D0-999A-00C04FD655E1} 0xFFFF" /t REG_BINARY /d "0100000000000000f6402fc18b62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached" /v "{4E77131D-3629-431C-9818-C5679DC83E81} {0C6C4200-C589-11D0-999A-00C04FD655E1} 0xFFFF" /t REG_BINARY /d "0100000000000000f6402fc18b62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached" /v "{FBF23B40-E3F0-101B-8488-00AA003E56F8} {000214F9-0000-0000-C000-000000000046} 0xFFFF" /t REG_BINARY /d "0100000000000000d38829c28b62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached" /v "{FBF23B40-E3F0-101B-8488-00AA003E56F8} {000214FA-0000-0000-C000-000000000046} 0xFFFF" /t REG_BINARY /d "0100000000000000d38829c28b62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached" /v "{40DD6E20-7C17-11CE-A804-00AA003CA9F6} {000214FC-0000-0000-C000-000000000046} 0xFFFF" /t REG_BINARY /d "010000000000000039f6f7c38b62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached" /v "{2227A280-3AEA-1069-A2DE-08002B30309D} {000214E6-0000-0000-C000-000000000046} 0xFFFF" /t REG_BINARY /d "010000000000000060e25fc58b62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached" /v "{04731B67-D933-450A-90E6-4ACD2E9408FE} {ADD8BA80-002B-11D0-8F0F-00C04FD7D062} 0xFFFF" /t REG_BINARY /d "010000000000000020ca8ac58b62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached" /v "{00021401-0000-0000-C000-000000000046} {000214E4-0000-0000-C000-000000000046} 0xFFFF" /t REG_BINARY /d "0100000000000000134ca2ee8b62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached" /v "{596AB062-B4D2-4215-9F74-E9109B0A8153} {000214E4-0000-0000-C000-000000000046} 0xFFFF" /t REG_BINARY /d "010000000000000069aba5f28b62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached" /v "{474C98EE-CF3D-41F5-80E3-4AAB0AB04301} {000214E4-0000-0000-C000-000000000046} 0xFFFF" /t REG_BINARY /d "010000000000000069aba5f28b62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached" /v "{E61BF828-5E63-4287-BEF1-60B1A4FDE0E3} {000214E4-0000-0000-C000-000000000046} 0xFFFF" /t REG_BINARY /d "0100000000000000770ea8f28b62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached" /v "{F81E9010-6EA4-11CE-A7FF-00AA003CA9F6} {000214E4-0000-0000-C000-000000000046} 0xFFFF" /t REG_BINARY /d "0100000000000000770ea8f28b62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached" /v "{99D353BC-C813-41EC-8F28-EAE61E702E57} {A08CE4D0-FA25-44AB-B57C-C7B1C323E0B9} 0xFFFF" /t REG_BINARY /d "0100000000000000770ea8f28b62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached" /v "{E2BF9676-5F8F-435C-97EB-11607A5BEDF7} {000214E4-0000-0000-C000-000000000046} 0xFFFF" /t REG_BINARY /d "0100000000000000770ea8f28b62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached" /v "{E2BF9676-5F8F-435C-97EB-11607A5BEDF7} {A08CE4D0-FA25-44AB-B57C-C7B1C323E0B9} 0xFFFF" /t REG_BINARY /d "0100000000000000770ea8f28b62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached" /v "{09A47860-11B0-4DA5-AFA5-26D86198A780} {000214E4-0000-0000-C000-000000000046} 0xFFFF" /t REG_BINARY /d "0100000000000000d56faaf28b62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached" /v "{23170F69-40C1-278A-1000-000100020000} {000214E4-0000-0000-C000-000000000046} 0xFFFF" /t REG_BINARY /d "0100000000000000d56faaf28b62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached" /v "{1D27F844-3A1F-4410-85AC-14651078412D} {000214E4-0000-0000-C000-000000000046} 0xFFFF" /t REG_BINARY /d "0100000000000000d56faaf28b62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached" /v "{17FE9752-0B5A-4665-84CD-569794602F5C} {7F9185B0-CB92-43C5-80A9-92277A4F7B54} 0xFFFF" /t REG_BINARY /d "010000000000000069017df98b62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached" /v "{FF393560-C2A7-11CF-BFF4-444553540000} {000214E6-0000-0000-C000-000000000046} 0xFFFF" /t REG_BINARY /d "010000000000000071a9fbfb8b62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached" /v "{470C0EBD-5D73-4D58-9CED-E91E22E23282} {000214E4-0000-0000-C000-000000000046} 0xFFFF" /t REG_BINARY /d "010000000000000074e2fb858c62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached" /v "{8D80504A-0826-40C5-97E1-EBC68F953792} {886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99} 0xFFFF" /t REG_BINARY /d "0100000000000000abfaf4af8c62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached" /v "{9C73F5E5-7AE7-4E32-A8E8-8D23B85255BF} {000214E6-0000-0000-C000-000000000046} 0xFFFF" /t REG_BINARY /d "0100000000000000faabc7da8c62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached" /v "{11DBB47C-A525-400B-9E80-A54615A090C0} {7F9185B0-CB92-43C5-80A9-92277A4F7B54} 0xFFFF" /t REG_BINARY /d "0100000000000000cbbfd8b68e62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached" /v "{BF85540E-0DF3-47BC-AC5D-305442704708} {05B2F74E-2712-46BA-BCA3-F65A46BF0E00} 0xFFFF" /t REG_BINARY /d "0100000000000000943cf8b68e62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached" /v "{C2B136E2-D50E-405C-8784-363C582BF43E} {ADD8BA80-002B-11D0-8F0F-00C04FD7D062} 0xFFFF" /t REG_BINARY /d "01000000000000008c4006b78e62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached" /v "{E97DEC16-A50D-49BB-AE24-CF682282E08D} {000214E4-0000-0000-C000-000000000046} 0xFFFF" /t REG_BINARY /d "0100000000000000ac6ea02c8f62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached" /v "{A929C4CE-FD36-4270-B4F5-34ECAC5BD63C} {000214E4-0000-0000-C000-000000000046} 0xFFFF" /t REG_BINARY /d "0100000000000000ac6ea02c8f62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached" /v "{B7373566-8FF2-45D8-AF1F-DA39F289BCF9} {A08CE4D0-FA25-44AB-B57C-C7B1C323E0B9} 0xFFFF" /t REG_BINARY /d "010000000000000086ccc12c8f62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached" /v "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C} {000214E6-0000-0000-C000-000000000046} 0xFFFF" /t REG_BINARY /d "0100000000000000cf04dc2c8f62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached" /v "{289AF617-1CC3-42A6-926C-E6A863F0E3BA} {ADD8BA80-002B-11D0-8F0F-00C04FD7D062} 0xFFFF" /t REG_BINARY /d "0100000000000000fe25cf2d8f62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached" /v "{35786D3C-B075-49B9-88DD-029876E11C01} {ADD8BA80-002B-11D0-8F0F-00C04FD7D062} 0xFFFF" /t REG_BINARY /d "01000000000000003588d12d8f62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached" /v "{9113A02D-00A3-46B9-BC5F-9C04DADDD5D7} {ADD8BA80-002B-11D0-8F0F-00C04FD7D062} 0xFFFF" /t REG_BINARY /d "010000000000000064ead32d8f62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached" /v "{2854F705-3548-414C-A113-93E27C808C85} {000214E4-0000-0000-C000-000000000046} 0xFFFF" /t REG_BINARY /d "01000000000000009e808a2f8f62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SignalManager\Peek" /v "CloudDataStoreCleared" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SignalManager\Peek\CacheStore" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass" /v "UserAuthPolicy" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\StartLayout\Migration" /v "IsTransformerDataMigrated" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\BackupReminder" /v "FirstProfileSeenTime" /t REG_BINARY /d "c9a82d508d62d701" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v "01" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\TaskFlow" /v "UpgradeVersion" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities" /v "RequestMakeCall" /t REG_SZ /d "DIALER.EXE" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Telephony\HandoffPriorities\MediaModes" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ThemeManager" /v "DllName" /t REG_EXPAND_SZ /d "%%SystemRoot%%\resources\themes\Aero\Aero.msstyles" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ThemeManager" /v "PrePolicy-DllName" /t REG_SZ /d "C:\Windows\resources\themes\Aero\Aero.msstyles" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ThemeManager" /v "LMVersion" /t REG_SZ /d "105" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ThemeManager" /v "LoadedBefore" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ThemeManager" /v "ThemeActive" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ThemeManager" /v "LastUserLangID" /t REG_SZ /d "1033" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ThemeManager" /v "LastLoadedDPI" /t REG_SZ /d "288" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ThemeManager" /v "LastLoadedDPIPlateaus" /t REG_SZ /d "33" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ThemeManager" /v "LastLoadedPPI" /t REG_SZ /d "96" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ThemeManager" /v "ColorName" /t REG_SZ /d "NormalColor" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ThemeManager" /v "SizeName" /t REG_SZ /d "NormalSize" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /v "InstallVisualStyleColor" /t REG_SZ /d "NormalColor" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /v "InstallVisualStyleSize" /t REG_SZ /d "NormalSize" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /v "LastHighContrastTheme" /t REG_EXPAND_SZ /d "%%SystemRoot%%\resources\Ease of Access Themes\hcblack.theme" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /v "ThemeChangesDesktopIcons" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /v "ThemeChangesMousePointers" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /v "WallpaperSetFromTheme" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /v "ColorSetFromTheme" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /v "CurrentTheme" /t REG_SZ /d "C:\Users\Administrator\AppData\Local\Microsoft\Windows\Themes\GHOSTV3\GHOSTV3.theme" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /v "SetupVersion" /t REG_SZ /d "10" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\HighContrast" /v "Pre-High Contrast Scheme" /t REG_SZ /d "C:\Users\Administrator\AppData\Local\Microsoft\Windows\Themes\GHOSTV3\GHOSTV3.theme" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\History" /v "AutoColor" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\History\Colors" /v "ColorHistory0" /t REG_DWORD /d "4287768686" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\History\Colors" /v "ColorHistory1" /t REG_DWORD /d "12826368" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\History\Colors" /v "ColorHistory2" /t REG_DWORD /d "4737612" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\History\Colors" /v "ColorHistory3" /t REG_DWORD /d "2298344" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\History\Colors" /v "ColorHistory4" /t REG_DWORD /d "6160618" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "ColorPrevalence" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v "ScoobeSystemSettingEnabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing" /v "State" /t REG_DWORD /d "146432" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "Composition" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "ColorizationColor" /t REG_DWORD /d "3295553682" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "ColorizationColorBalance" /t REG_DWORD /d "89" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "ColorizationAfterglow" /t REG_DWORD /d "3295553682" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "ColorizationAfterglowBalance" /t REG_DWORD /d "10" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "ColorizationBlurBalance" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "EnableWindowColorization" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "ColorizationGlassAttribute" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "AccentColor" /t REG_DWORD /d "4287768686" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "ColorPrevalence" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "AlwaysHibernateThumbnails" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "AccentColorInactive" /t REG_DWORD /d "3148067" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Associations" /v "FileAssociationsUpdateVersion" /t REG_DWORD /d "31" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice" /v "ProgId" /t REG_SZ /d "FirefoxURL-308046B0AF4A39CB" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice" /v "Hash" /t REG_SZ /d "hx4Oeg9yFGw=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice" /v "ProgId" /t REG_SZ /d "FirefoxURL-308046B0AF4A39CB" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice" /v "Hash" /t REG_SZ /d "3TzkffB+Hqo=" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\ms-aad-brokerplugin" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\ms-actioncenter" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\ms-apprep" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\ms-cxh" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\ms-device-enrollment" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\ms-edu-secureassessment" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\ms-eyecontrolspeech" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\ms-inputapp" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\ms-insights" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\ms-meetnowflyout" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\ms-oobenetwork" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\ms-penworkspace" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\ms-print-addprinter" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\ms-print-printjobs" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\ms-screenclip" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\ms-search" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\ms-wpc" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\ms-xgpueject" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\rtkuwp" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\xbox-tcui" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\BagMRU" /v "NodeSlots" /t REG_BINARY /d "02" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\BagMRU" /v "MRUListEx" /t REG_BINARY /d "ffffffff" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\BagMRU" /v "NodeSlot" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Bags\1\Desktop" /v "FFlags" /t REG_DWORD /d "1075839525" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Bags\1\Desktop" /v "Mode" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Bags\1\Desktop" /v "LogicalViewMode" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Bags\1\Desktop" /v "IconSize" /t REG_DWORD /d "48" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Bags\1\Desktop" /v "Sort" /t REG_BINARY /d "000000000000000000000000000000000100000030f125b7ef471a10a5f102608c9eebac0a00000001000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Bags\1\Desktop" /v "GroupView" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Bags\1\Desktop" /v "GroupByKey:FMTID" /t REG_SZ /d "{00000000-0000-0000-0000-000000000000}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Bags\1\Desktop" /v "GroupByKey:PID" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Bags\1\Desktop" /v "GroupByDirection" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Bags\1\Desktop" /v "IconLayouts" /t REG_BINARY /d "00000000000000000000000000000000030001000100010008000000000000002c000000000000003a003a007b00320030004400300034004600450030002d0033004100450041002d0031003000360039002d0041003200440038002d003000380030003000320042003300300033003000390044007d003e002000200000002c000000000000003a003a007b00360034003500460046003000340030002d0035003000380031002d0031003000310042002d0039004600300038002d003000300041004100300030003200460039003500340045007d003e0020002000000013000000000000004300500055004900440020004300500055002d005a002e006c006e006b003e0020007c0000000f00000000000000460069007200650066006f0078002e006c006e006b003e0020007c000000150000000000000047006f006f0067006c00650020004300680072006f006d0065002e006c006e006b003e0020007c0000002d0000000000000046006f006c006c006f00770020007500730020006f006e0020004000460061006300650062006f006f006b0020002d002000470048004f005300540053005000450043005400520045002e00750072006c003e002000200000002c0000000000000046006f006c006c006f00770020007500730020006f006e002000400059006f007500540075006200650020002d002000470048004f005300540053005000450043005400520045002e00750072006c003e002000200000001500000000000000470068006f0073007400200054006f006f006c0062006f0078002e006c006e006b003e00200020000000010000000000000002000100000000000000000001000000000000000200010000000000000000000d0000000700000001000000080000000000000000000000000000000000000000000000803f0100000000000000004002000000000000004040030000000000000080400400000000000000a0400500000000000000c04006000000803f000000000700" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Bags\1\Desktop" /v "IconNameVersion" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\TabletPC\Snipping Tool" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\TabletPC\TabSetup" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Winlogon\PasswordExpiryNotification" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store" /v "C:\Ghost Toolbox\toolbox.updater.x64.exe" /t REG_BINARY /d "534143500100000000000000070000002800000000f204000000000001000000000000000000000a0021000050bb64edddacd50100000000000000000500000010000000000000000000000000000000000000000200000028000000000000000000000000000000000000000000000000000000a7130000000000000100000001000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store" /v "C:\Program Files\Mozilla Firefox\firefox.exe" /t REG_BINARY /d "5341435001000000000000000700000028000000b81909007874090001000000000000000000000a0021000050bb64edddacd5010000000100000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store" /v "E:\Registry\RegCoolX64\RegCool.exe" /t REG_BINARY /d "534143500100000000000000070000002800000068ba0b00ed7d0c0001000000000000000000000a7322000050bb64edddacd50100000000000000000500000010000000000000000000000000000000000000000200000028000000000000000000000004000000000000000000000000000000bf310000000000000100000001000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\BackgroundModel\PreInstallTasks" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EFS" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\HostActivityManager\Volatile" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ICM" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\MsiCorruptedFileRecovery\RepairedProducts" /v "AnyIdMax" /t REG_DWORD /d "5" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\MsiCorruptedFileRecovery\RepairedProducts" /v "SameIdMax" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\MsiCorruptedFileRecovery\RepairedProducts" /v "TimeWindowMinutes" /t REG_DWORD /d "1440" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\TileDataModel\Migration\StartNonLayoutProperties" /v "Completed" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\TileDataModel\Migration\StartNonLayoutProperties_AppUsageData" /v "Completed" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\TileDataModel\Migration\StartNonLayoutProperties_TargetedContentTiles" /v "Completed" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\TileDataModel\Migration\StartTileGridLayout" /v "Completed" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\TileDataModel\Migration\TileStore" /v "Completed" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\TileDataModel\Migration\TileStore" /v "MigrationRepairAttempted" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v "Device" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v "IsMRUEstablished" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v "LegacyDefaultPrinterMode" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v "MenuDropAlignment" /t REG_SZ /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\InteractiveControl" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\Pen" /v "PenArbitrationType" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\Pen\PLOC\Settings" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "ExcludeProfileDirs" /t REG_SZ /d "AppData\Local;AppData\LocalLow;$Recycle.Bin;OneDrive;Work Folders" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "BuildNumber" /t REG_DWORD /d "19043" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "FirstLogon" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "PUUActive" /t REG_BINARY /d "23e86b570100000002000200140500001405000014050000d20000000c000d007f4ba9d74005000040050000a90100003e010000710000000000000000000000000000003c05000048000000030000002f31d2e58e62d70114050000000000000100000014050000634a000014050000d9a6140000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "DP" /t REG_BINARY /d "d200e800000000000200000023e86b57d9a61400000000002f31d2e58e62d701d0161ebf8b62d701ff681300417b020000000000000000000000000000000000649906000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows Script Host\Settings" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows Search\ProcessedSearchRoots\0000" /ve /t REG_SZ /d "defaultroot://{S-1-5-21-2807429842-3194115458-1915057576-500}/" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows Search\ProcessedSearchRoots\0000" /v "Version" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows Search\ProcessedSearchRoots\0000" /v "DoNotCreateSearchConnectors" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows Search\ProcessedSearchRoots\0001" /ve /t REG_SZ /d "file:///C:\\" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows Search\ProcessedSearchRoots\0001" /v "Version" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows Search\ProcessedSearchRoots\0001" /v "DoNotCreateSearchConnectors" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows Search\ProcessedSearchRoots\0002" /ve /t REG_SZ /d "winrt://{S-1-5-21-2807429842-3194115458-1915057576-500}/" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows Search\ProcessedSearchRoots\0002" /v "Version" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows Search\ProcessedSearchRoots\0002\Default" /v "SavePath" /t REG_SZ /d "C:\Users\Administrator\Searches\winrt--{S-1-5-21-2807429842-3194115458-1915057576-500}-.searchconnector-ms" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows Search\ProcessedSearchRoots\0003" /ve /t REG_SZ /d "iehistory://{S-1-5-21-2807429842-3194115458-1915057576-500}/" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows Search\ProcessedSearchRoots\0003" /v "Version" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows Search\ProcessedSearchRoots\0003" /v "DoNotCreateSearchConnectors" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Wisp\MultiTouch" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Wisp\Pen\SysEventParameters" /v "DblDist" /t REG_DWORD /d "20" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Wisp\Pen\SysEventParameters" /v "DblTime" /t REG_DWORD /d "300" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Wisp\Pen\SysEventParameters" /v "EraseEnable" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Wisp\Pen\SysEventParameters" /v "FlickMode" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Wisp\Pen\SysEventParameters" /v "FlickTolerance" /t REG_DWORD /d "50" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Wisp\Pen\SysEventParameters" /v "HoldMode" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Wisp\Pen\SysEventParameters" /v "HoldTime" /t REG_DWORD /d "2300" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Wisp\Pen\SysEventParameters" /v "RightMaskEnable" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Wisp\Pen\SysEventParameters" /v "Splash" /t REG_DWORD /d "50" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Wisp\Pen\SysEventParameters" /v "TapTime" /t REG_DWORD /d "100" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Wisp\Pen\SysEventParameters" /v "WaitTime" /t REG_DWORD /d "300" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Wisp\Pen\SysEventParameters\CustomFlickCommands" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Wisp\Pen\SysEventParameters\FlickCommands" /v "down" /t REG_SZ /d "{00000000-0000-0000-0000-000000000000}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Wisp\Pen\SysEventParameters\FlickCommands" /v "downLeft" /t REG_SZ /d "{00000000-0000-0000-0000-000000000000}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Wisp\Pen\SysEventParameters\FlickCommands" /v "downRight" /t REG_SZ /d "{00000000-0000-0000-0000-000000000000}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Wisp\Pen\SysEventParameters\FlickCommands" /v "left" /t REG_SZ /d "{00000000-0000-0000-0000-000000000000}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Wisp\Pen\SysEventParameters\FlickCommands" /v "right" /t REG_SZ /d "{00000000-0000-0000-0000-000000000000}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Wisp\Pen\SysEventParameters\FlickCommands" /v "up" /t REG_SZ /d "{00000000-0000-0000-0000-000000000000}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Wisp\Pen\SysEventParameters\FlickCommands" /v "upLeft" /t REG_SZ /d "{00000000-0000-0000-0000-000000000000}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Wisp\Pen\SysEventParameters\FlickCommands" /v "upRight" /t REG_SZ /d "{00000000-0000-0000-0000-000000000000}" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Wisp\Touch" /v "Bouncing" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Wisp\Touch" /v "Friction" /t REG_DWORD /d "50" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Wisp\Touch" /v "Inertia" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Wisp\Touch" /v "TouchMode_hold" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Wisp\Touch" /v "TouchModeN_DtapDist" /t REG_DWORD /d "50" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Wisp\Touch" /v "TouchModeN_DtapTime" /t REG_DWORD /d "50" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Wisp\Touch" /v "TouchModeN_HoldTime_Animation" /t REG_DWORD /d "50" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Wisp\Touch" /v "TouchModeN_HoldTime_BeforeAnimation" /t REG_DWORD /d "50" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Wisp\Touch" /v "TouchUI" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\SystemCertificates\CA\Certificates" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\SystemCertificates\CA\CRLs" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\SystemCertificates\CA\CTLs" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\SystemCertificates\Disallowed\Certificates" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\SystemCertificates\Disallowed\CRLs" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\SystemCertificates\Disallowed\CTLs" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\SystemCertificates\trust\Certificates" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\SystemCertificates\trust\CRLs" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\SystemCertificates\trust\CTLs" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPeople\Certificates" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPeople\CRLs" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPeople\CTLs" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPublisher\Certificates" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPublisher\CRLs" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPublisher\CTLs" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Cache" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Power\PowerSettings" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics" /v "Enabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Peernet" /v "Disabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\CA\Certificates" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\CA\CRLs" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\CA\CTLs" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Disallowed\Certificates" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Disallowed\CRLs" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Disallowed\CTLs" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\CRLs" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\CTLs" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\trust\Certificates" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\trust\CRLs" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\trust\CTLs" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPeople\Certificates" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPeople\CRLs" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPeople\CTLs" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPublisher\Certificates" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPublisher\CRLs" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPublisher\CTLs" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\TPM" /v "OSManagedAuthLevel" /t REG_DWORD /d "5" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\BITS" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "CallLegacyWCMPolicies" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Cache" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EnhancedStorageDevices" /v "TCGSecurityActivationDisabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections" /v "NC_PersonalFirewallConfig" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreen" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers" /v "authenticodeenabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "EnableBackupForWin8Apps" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableAcrylicBackgroundOnLogon" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\Local" /v "WCMPresent" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WSDAPI\Discovery Proxies" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" /v "fEnableUsbBlockDeviceBySetupClass" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" /v "fEnableUsbNoAckIsochWriteToDevice" /t REG_DWORD /d "80" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" /v "fEnableUsbSelectDeviceByInterface" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client\UsbBlockDeviceBySetupClasses" /v "1000" /t REG_SZ /d "{3376f4ce-ff8d-40a2-a80f-bb4359d1415c}" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client\UsbSelectDeviceByInterfaces" /v "1000" /t REG_SZ /d "{6bdd1fc6-810f-11d0-bec7-08002be2092f}" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Windows File Protection" /v "KnownDllList" /t REG_SZ /d "nlhtml.dll" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" /v "GroupPrivacyAcceptance" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "Win8DpiScaling" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "LogPixels" /t REG_DWORD /d "96" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows NT\DNSClient" /v "NameServer" /t REG_SZ /d "1.1.1.1 8.8.8.8" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v "NameServer" /t REG_SZ /d "1.1.1.1 8.8.8.8" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{EC1F4539-05EA-4B3F-81C3-A7B204C8A542}Machine\Software\Policies\Microsoft\Windows NT\DNSClient" /v "NameServer" /t REG_SZ /d "1.1.1.1 8.8.8.8" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "EnableLegacyAutoProxyFeature" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "EnableAutoDoh" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxCacheTtl" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxNegativeCacheTtl" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" /v "EnableNetworkProtection" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access" /v "EnableControlledFolderAccess" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "PUAProtection" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" /v "MpEnablePus" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "ShellSmartScreenLevel" /t REG_SZ /d "Block" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "PreventOverride" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter" /v "PreventOverride" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" /v "MpCloudBlockLevel" /t REG_DWORD /d "6" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" /v "MpBafsExtendedTimeout" /t REG_DWORD /d "50" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" /v "DisallowExploitProtectionOverride" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpyNetReporting" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AJRouter" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\ALG" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AppIDSvc" /v "Start" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AppMgmt" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AppReadiness" /v "Start" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AppVClient" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AxInstSV" /v "Start" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\BcastDVRUserService" /v "Start" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\BDESVC" /v "Start" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\BluetoothUserService" /v "Start" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\BTAGService" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\BthAvctpSvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\camsvc" /v "Start" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\CertPropSvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\ClipSVC" /v "Start" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\COMSysApp" /v "Start" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\CscService" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DeviceAssociationService" /v "Start" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DeviceInstall" /v "Start" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvc" /v "Start" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc" /v "Start" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DevQueryBroker" /v "Start" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\diagsvc" /v "Start" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DmEnrollmentSvc" /v "Start" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DsmSVC" /v "Start" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DsSvc" /v "Start" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\EapHost" /v "Start" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\EFS" /v "Start" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\embeddedmode" /v "Start" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\EntAppSvc" /v "Start" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\fastuserswitching" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Fax" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\fdPHost" /v "Start" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\FDResPub" /v "Start" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\fhsvc" /v "Start" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\FrameServer" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc" /v "Start" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\HvHost" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\iphlpsvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\IpxlatCfgSvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\irmon" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\MapsBroker" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\MSDTC" /v "Start" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\MSiSCSI" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NaturalAuthentication" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NcdAutoSetup" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NetTcpPortSharing" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PeerDistSvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PhoneSvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc" /v "Start" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\RemoteAccess" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\RemoteRegistry" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\RetailDemo" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\RpcLocator" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SCardSvr" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\ScDeviceEnum" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SCPolicySvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SEMgrSvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SensorDataService" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SensorService" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SensrSvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SessionEnv" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SmsRouter" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SNMPTRAP" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\TermService" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\UevAgentService" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\UmRdpService" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\VaultSvc" /v "Start" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\vmicguestinterface" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\vmicheartbeat" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\vmickvpexchange" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\vmicrdv" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\vmicshutdown" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\vmictimesync" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\vmicvmsession" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\vmicvss" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\wanarp" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\wanarpv6" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\wbengine" /v "Start" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\wcncsvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WdiServiceHost" /v "Start" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WdiSystemHost" /v "Start" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WebClient" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WinRM" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\wisvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\workfolderssvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WpcMonSvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WwanSvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\XblAuthManager" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\XblGameSave" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe delete "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Defaults\FirewallPolicy\FirewallRules" /f
Echo Y | Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Defaults\FirewallPolicy\FirewallRules" /f
Echo Y | Reg.exe delete "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\AppIso\FirewallRules" /f
Echo Y | Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\AppIso\FirewallRules" /f
Echo Y | Reg.exe delete "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Configurable\System" /f
Echo Y | Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Configurable\System" /f
Echo Y | Reg.exe delete "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\System" /f
Echo Y | Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\System" /f
Echo Y | Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Keyboard" /v "InitialKeyboardIndicators" /t REG_SZ /d "2" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Keyboard" /v "KeyboardDelay" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Keyboard" /v "KeyboardSpeed" /t REG_SZ /d "28" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Mouse" /v "ActiveWindowTracking" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Mouse" /v "DoubleClickHeight" /t REG_SZ /d "30" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Mouse" /v "DoubleClickSpeed" /t REG_SZ /d "500" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Mouse" /v "DoubleClickWidth" /t REG_SZ /d "30" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Mouse" /v "ExtendedSounds" /t REG_SZ /d "No" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseHoverHeight" /t REG_SZ /d "4" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "8" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseHoverWidth" /t REG_SZ /d "4" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "10" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseTrails" /t REG_SZ /d "0" /f
Echo Y | Reg.exe delete "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /f
Echo Y | Reg.exe delete "HKCU\Control Panel\Mouse" /v "SmoothMouseYCurve" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Mouse" /v "SnapToDefaultButton" /t REG_SZ /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Mouse" /v "SwapMouseButtons" /t REG_SZ /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Mouse" /v "Beep" /t REG_SZ /d "No" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Nls\CodePage" /v "ACP" /t REG_SZ /d "1252" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Nls\CodePage" /v "OEMCP" /t REG_SZ /d "437" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Nls\CodePage" /v "MACCP" /t REG_SZ /d "10000" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Nls\Language" /v "Default" /t REG_SZ /d "0409" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "autodisconnect" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "Size" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "EnableOplocks" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "32" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationDelay" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationRetries" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "LongPathsEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsAllowExtendedCharacter8dot3Rename" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsDisable8dot3NameCreation" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "8" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "ForegroundLockTimeout" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "8" /f
Echo Y | Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PagingFiles" /t REG_MULTI_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "ExistingPageFiles" /t REG_MULTI_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Dfrg\BootOptimizeFunction" /v "Enable" /t REG_SZ /d "y" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsDisableLastAccessUpdate" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoRebootWithLoggedOnUsers" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "10" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t REG_DWORD /d "10" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPER1_0SERVER" /v "iexplore.exe" /t REG_DWORD /d "10" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPERSERVER" /v "iexplore.exe" /t REG_DWORD /d "10" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "EnableBalloonTips" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "StartButtonBalloonTip" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DesktopLivePreviewHoverTime" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "DefaultTTL" /t REG_DWORD /d "64" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "EnableTCPA" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpTimedWaitDelay" /t REG_DWORD /d "30" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "Tcp1323Opts" /t REG_DWORD /d "30" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "SynAttackProtect" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "EnableDca" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TCPMaxDataRetransmissions" /t REG_DWORD /d "7" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "EnablePMTUDiscovery" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "EnablePMTUBHDetect" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Mouse" /v "DoubleClickHeight" /t REG_SZ /d "30" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Mouse" /v "DoubleClickWidth" /t REG_SZ /d "30" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Scheduling Category" /t REG_SZ /d "High" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "SFIO Priority" /t REG_SZ /d "High" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Background Only" /t REG_SZ /d "False" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Priority" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Clock Rate" /t REG_DWORD /d "2710" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "GPU Priority" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Latency Sensitive" /t REG_SZ /d "True" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "StartupDelayInMSec" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Quota System\S-1-2-0" /v "CpuRateLimit" /t REG_DWORD /d "256" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\System" /v "AllowExperimentation" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth" /v "AllowAdvertising" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Messaging" /v "AllowMessageSync" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353698Enabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "AllowClipboardHistory" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "AllowCrossDeviceClipboard" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Clipboard" /v "EnableClipboardHistory" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Deny" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Deny" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI" /v "DisablePasswordReveal" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\DiagTrack" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /v "ConfigureDoNotTrack" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /v "PaymentMethodQueryEnabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /v "SendSiteInfoToImproveServices" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /v "MetricsReportingEnabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /v "PersonalizationReportingEnabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /v "AddressBarMicrosoftSearchInBingProviderEnabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /v "UserFeedbackAllowed" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /v "AutofillCreditCardEnabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /v "AutofillAddressEnabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /v "LocalProvidersEnabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Edge" /v "SearchSuggestEnabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main" /v "DoNotTrack" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main" /v "ShowSearchSuggestionsGlobal" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead" /v "FPEnabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\ServiceUI" /v "EnableCortana" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Browser" /v "AllowAddressBarDropdown" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\ServiceUI\ShowSearchHistory" /ve /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "UserFeedbackAllowed" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "AutofillCreditCardEnabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d "5" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Windows Search" /v "CortanaConsent" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "AllowInputPersonalization" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /v "ModelDownloadAllowed" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" /v "SystemSettingsDownloadMode" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Speech" /v "AllowSpeechModelUpdate" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Rpc\Internet" /v "UseInternetPorts" /t REG_SZ /d "N" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Ole" /v "EnableDCOM" /t REG_SZ /d "N" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\NetBT\Parameters" /v "SmbDeviceEnabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\NetBT" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Messenger" /v "Start" /t REG_DWORD /d "4" /f
:: Exit
fsutil usn deletejournal /d /n c:
taskkill /f /im dllhost.exe
popd
exit/b