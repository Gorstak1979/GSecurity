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

REM ; Make current folder active one
pushd %~dp0
REM ; Debloat
powershell "Get-AppxPackage -AllUsers | Where {($_.Name -notlike '*store*')} | Where {($_.Name -notlike '*Edge*')} | Where {($_.Name -notlike '*nvidia*')} | Where {($_.Name -notlike '*identity*')} | Where {($_.Name -notlike '*host*')} | Where {($_.Name -notlike '*calc*')} | Where {($_.Name -notlike '*photos*')} | Remove-AppxPackage"
powershell "Get-AppxProvisionedPackage -Online | Where {($_.Name -notlike '*store*')} | Where {($_.Name -notlike '*Edge*')} | Where {($_.Name -notlike '*nvidia*')} | Where {($_.Name -notlike '*identity*')} | Where {($_.Name -notlike '*host*')} | Where {($_.Name -notlike '*calc*')} | Where {($_.Name -notlike '*photos*')} | Remove-AppxProvisionedPackage -Online"
REM ; Remove user account
net user defaultuser0 /delete
REM ; Take ownership of desktop
takeown /F "%SystemDrive%\Users\Public\Desktop" /r /d y
icacls "%SystemDrive%\Users\Public\Desktop" /grant:r %username%:(OI)(CI)F /t /l /q /c
takeown /F "%USERPROFILE%\Desktop" /r /d y
icacls "%USERPROFILE%\Desktop" /grant:r %username%:(OI)(CI)F /t /l /q /c
REM ; Setup tasks
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
REM ; prclaunchky
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
REM ; Tairiku Okami (tweaked)

rem ============= Remove various files, folders, startup entries and policies ==============


rem Take ownership of Desktop
takeown /s %computername% /u %username% /f "%SystemDrive%\Users\Public\Desktop" /r /d y
icacls "%SystemDrive%\Users\Public\Desktop" /grant:r %username%:(OI)(CI)F /t /l /q /c
takeown /s %computername% /u %username% /f "%USERPROFILE%\Desktop" /r /d y
icacls "%USERPROFILE%\Desktop" /grant:r %username%:(OI)(CI)F /t /l /q /c

rem Remove user account
net user defaultuser0 /delete

rem Prevent files from being run/altered/recreated
rem takeown /f "%WINDIR%\System32\sethc.exe" /a
rem icacls "%WINDIR%\System32\sethc.exe" /remove "Administrators" "Authenticated Users" "Users" "System"
rem takeown /f "%WINDIR%\SysWOW64\sethc.exe" /a
rem icacls "%WINDIR%\SysWOW64\sethc.exe" /remove "Administrators" "Authenticated Users" "Users" "System"

rem takeown /f "%WINDIR%\System32\utilman.exe" /a
rem icacls "%WINDIR%\System32\utilman.exe" /remove "Administrators" "Authenticated Users" "Users" "System"
rem takeown /f "%WINDIR%\SysWOW64\utilman.exe" /a
rem icacls "%WINDIR%\SysWOW64\utilman.exe" /remove "Administrators" "Authenticated Users" "Users" "System"

rem Remove random files/folders
del "%AppData%\Microsoft\Windows\Recent\*" /s /f /q
del "%WINDIR%\System32\sru\*" /s /f /q
rd "%SystemDrive%\AMD" /s /q
rd "%SystemDrive%\PerfLogs" /s /q
rd "%SystemDrive%\Recovery" /s /q
rd "%ProgramData%\Microsoft\Diagnosis" /s /q
rd "%ProgramData%\Microsoft\Search" /s /q
rd "%ProgramData%\Microsoft\Windows Security Health" /s /q
rd "%AppData%\ArtifexMundi\SparkPromo" /s /q
rd "%LocalAppData%\MicrosoftEdge" /s /q
rd "%LocalAppData%\Microsoft\Internet Explorer" /s /q
rd "%LocalAppData%\Microsoft\Windows\AppCache" /s /q
rd "%LocalAppData%\Microsoft\Windows\History" /s /q
rd "%LocalAppData%\Microsoft\Windows\IECompatCache" /s /q
rd "%LocalAppData%\Microsoft\Windows\IECompatUaCache" /s /q
rd "%LocalAppData%\Microsoft\Windows\INetCache" /s /q
rd "%LocalAppData%\Microsoft\Windows\INetCookies" /s /q
rd "%LocalAppData%\Microsoft\Windows\WebCache" /s /q
rd "%LocalAppData%\Packages\Microsoft.Windows.Cortana_cw5n1h2txyewy\AppData\Indexed DB" /s /q
rd "C:\Users\Mikai\3D Objects" /s /q
rem rd "C:\Users\Mikai\Documents" /s /q
rd "C:\Users\Mikai\Favorites" /s /q
rd "C:\Users\Mikai\Links" /s /q
rd "C:\Users\Mikai\Music" /s /q
rd "C:\Users\Mikai\Searches" /s /q

rem Remove/Rebuild Font Cache
icacls "%WinDir%\ServiceProfiles\LocalService" /grant:r Administrators:(OI)(CI)F /t /l /q /c
del "%WinDir%\ServiceProfiles\LocalService\AppData\Local\FontCache\*FontCache*"/s /f /q
del "%WinDir%\System32\FNTCACHE.DAT" /s /f /q

rem Remove Windows Powershell (to restore run "sfc /scannow")
rem http://www.malwaretech.com/2017/02/lets-unpack-dridex-loader.html
rem https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy
rem https://www.mrg-effitas.com/current-state-of-malicious-powershell-script-blocking
rem https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking
taskkill /im PowerShell.exe /f
taskkill /im PowerShell_ISE.exe /f
takeown /f "%ProgramFiles%\WindowsPowerShell" /a /r /d y
icacls "%ProgramFiles%\WindowsPowerShell" /inheritance:r /grant:r Administrators:(OI)(CI)F /t /l /q /c
rd "%ProgramFiles%\WindowsPowerShell" /s /q
takeown /f "%ProgramFiles(x86)%\WindowsPowerShell" /a /r /d y
icacls "%ProgramFiles(x86)%\WindowsPowerShell" /inheritance:r /grant:r Administrators:(OI)(CI)F /t /l /q /c
rd "%ProgramFiles(x86)%\WindowsPowerShell" /s /q
takeown /f "%WinDir%\System32\WindowsPowerShell" /a /r /d y
icacls "%WinDir%\System32\WindowsPowerShell" /inheritance:r /grant:r Administrators:(OI)(CI)F /t /l /q /c
rd "%WinDir%\System32\WindowsPowerShell" /s /q
takeown /f "%WinDir%\SysWOW64\WindowsPowerShell" /a /r /d y
icacls "%WinDir%\SysWOW64\WindowsPowerShell" /inheritance:r /grant:r Administrators:(OI)(CI)F /t /l /q /c
rd "%WinDir%\SysWOW64\WindowsPowerShell" /s /q

rem Remove Startup Folders
takeown /f "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup" /a /r /d y
icacls "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup" /inheritance:r /grant:r Administrators:(OI)(CI)F /t /l /q /c
del "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup\*" /s /f /q
del "%AppData%\Microsoft\Windows\Start Menu\Programs\Startup\*" /s /f /q

rem Remove random reg keys (Startup/Privacy/Policies/Malware related)
reg delete "HKCU\Software\Microsoft\Command Processor" /v "AutoRun" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\PackagedAppXDebug" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /f
reg delete "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v "Load" /f
reg delete "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /f
reg delete "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell" /f
reg delete "HKCU\Software\Policies" /f
reg delete "HKLM\Software\Microsoft\Command Processor" /v "AutoRun" /f
reg delete "HKLM\Software\Microsoft\Policies" /f
reg delete "HKLM\Software\Microsoft\Tracing" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\AppModelUnlock" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Font Drivers" /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server" /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v "AppInit_DLLs" /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit" /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "VMApplet" /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AlternateShells" /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell" /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Taskman" /f
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit" /f
reg delete "HKLM\Software\Policies" /f
reg delete "HKLM\Software\WOW6432Node\Microsoft\Policies" /f
reg delete "HKLM\Software\WOW6432Node\Microsoft\Tracing" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx" /f
reg delete "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies" /f
reg delete "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /v "AppInit_DLLs" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "VMApplet" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\AlternateShells" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\Taskman" /f
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit" /f
reg delete "HKLM\Software\WOW6432Node\Policies" /f
reg delete "HKLM\System\CurrentControlSet\Control\Keyboard Layout" /v "Scancode Map" /f
reg delete "HKLM\System\CurrentControlSet\Control\SafeBoot" /v "AlternateShell" /f
reg delete "HKLM\System\CurrentControlSet\Control\SecurePipeServers\winreg" /f
reg delete "HKLM\System\CurrentControlSet\Control\Session Manager" /v "BootExecute" /f
reg delete "HKLM\System\CurrentControlSet\Control\Session Manager" /v "Execute" /f
reg delete "HKLM\System\CurrentControlSet\Control\Session Manager" /v "SETUPEXECUTE" /f
reg delete "HKLM\System\CurrentControlSet\Control\Terminal Server\Wds\rdpwd" /v "StartupPrograms" /f


rem =========================== Restore essential startup entries ==========================


rem Run bcdedit command to check for the current status / Yes = True / No = False
rem https://msdn.microsoft.com/en-us/library/windows/hardware/ff542202(v=vs.85).aspx
bcdedit /deletevalue {current} safeboot
bcdedit /deletevalue {current} safebootalternateshell
bcdedit /deletevalue {current} removememory
bcdedit /deletevalue {current} truncatememory
bcdedit /deletevalue {current} useplatformclock
bcdedit /deletevalue {default} safeboot
bcdedit /deletevalue {default} safebootalternateshell
bcdedit /deletevalue {default} removememory
bcdedit /deletevalue {default} truncatememory
bcdedit /deletevalue {default} useplatformclock
bcdedit /set {bootmgr} displaybootmenu no
bcdedit /set {current} advancedoptions false
bcdedit /set {current} bootems no
bcdedit /set {current} bootmenupolicy legacy
bcdedit /set {current} bootstatuspolicy IgnoreAllFailures
bcdedit /set {current} disabledynamictick yes
bcdedit /set {current} recoveryenabled no
bcdedit /set {default} advancedoptions false
bcdedit /set {default} bootems no
bcdedit /set {default} bootmenupolicy legacy
bcdedit /set {default} bootstatuspolicy IgnoreAllFailures
bcdedit /set {default} disabledynamictick yes
bcdedit /set {default} recoveryenabled no

reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /t REG_SZ /d "explorer.exe" /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit" /t REG_SZ /d "C:\Windows\System32\userinit.exe," /f
reg add "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /t REG_SZ /d "explorer.exe" /f
reg add "HKLM\System\CurrentControlSet\Control\Session Manager" /v "BootExecute" /t REG_MULTI_SZ /d "autocheck autochk *" /f
reg add "HKLM\System\CurrentControlSet\Control\Session Manager" /v "SETUPEXECUTE" /t REG_MULTI_SZ /d "" /f

rem Run exe as service
rem sc.exe create POC binPath= "D:\Software\POC.exe"


rem =================================== Software Setup =====================================


rem 7-zip
reg add "HKCU\Software\7-Zip\Compression" /v "Archiver" /t "REG_SZ" /d "7z" /f
reg add "HKCU\Software\7-Zip\Compression" /v "Level" /t "REG_DWORD" /d "9" /f
reg add "HKCU\Software\7-Zip\Compression\Options\7z" /v "Level" /t "REG_DWORD" /d "9" /f
reg add "HKCU\Software\7-Zip\Options" /v "CascadedMenu" /t "REG_DWORD" /d "1" /f
reg add "HKCU\Software\7-Zip\Options" /v "ContextMenu" /t "REG_DWORD" /d "262" /f

rem 7+ Taskbar Tweaker
reg add "HKCU\Software\7 Taskbar Tweaker" /v "hidetray" /t "REG_DWORD" /d "1" /f
reg add "HKCU\Software\7 Taskbar Tweaker" /v "updcheck" /t "REG_DWORD" /d "0" /f
reg add "HKCU\Software\7 Taskbar Tweaker" /v "updcheckauto" /t "REG_DWORD" /d "0" /f
reg add "HKCU\Software\7 Taskbar Tweaker\OptionsEx" /v "w10_large_icons" /t "REG_DWORD" /d "1" /f

rem Logitech Setpoint
taskkill /im LogiAppBroker.exe /f
taskkill /im LogitechUpdate.exe /f
taskkill /im LULnchr.exe /f
taskkill /im KHALMNPR.exe /f
taskkill /im Setpoint.exe /f
del "%ProgramFiles%\Logitech\SetPointP\LogiAppBroker.exe" /s /f /q
del "%ProgramFiles%\Logitech\SetPointP\msvcp110.dll" /s /f /q
rd "%ProgramFiles%\Common Files\LogiShrd\sp6\LU1" /s /q
rd "%ProgramFiles%\Common Files\LogiShrd\Unifying\LU" /s /q

rem MPC-HC
reg add "HKCU\Software\MPC-HC\MPC-HC\Favorites" /v "RememberPosition" /t "REG_DWORD" /d "0" /f
reg add "HKCU\Software\MPC-HC\MPC-HC\Favorites\Files" /v "Name0" /t REG_SZ /d "AnimeNfo;0;0;http://itori.animenfo.com:443/\;" /f
reg add "HKCU\Software\MPC-HC\MPC-HC\Favorites\Files" /v "Name1" /t REG_SZ /d "AnimeWeb;0;0;http://s3.mediastreaming.it:8090/" /f
reg add "HKCU\Software\MPC-HC\MPC-HC\Favorites\Files" /v "Name2" /t REG_SZ /d "IrishPub;0;0;http://bb34.sonixcast.com:20038/stream" /f
reg add "HKCU\Software\MPC-HC\MPC-HC\Favorites\Files" /v "Name3" /t REG_SZ /d "Japana;0;0;http://audio.misproductions.com/japan48k" /f
reg add "HKCU\Software\MPC-HC\MPC-HC\Favorites\Files" /v "Name4" /t REG_SZ /d "LiveIreland;0;0;http://192.111.140.11:8058/stream" /f
reg add "HKCU\Software\MPC-HC\MPC-HC\Favorites\Files" /v "Name5" /t REG_SZ /d "TruckersFM;0;0;https://radio.truckers.fm" /f
reg add "HKCU\Software\MPC-HC\MPC-HC\Settings" /v "EnableSubtitles" /t "REG_DWORD" /d "0" /f
reg add "HKCU\Software\MPC-HC\MPC-HC\Settings" /v "HideCaptionMenu" /t "REG_DWORD" /d "3" /f
reg add "HKCU\Software\MPC-HC\MPC-HC\Settings" /v "HideNavigation" /t "REG_DWORD" /d "1" /f
reg add "HKCU\Software\MPC-HC\MPC-HC\Settings" /v "KeepAspectRatio" /t "REG_DWORD" /d "1" /f
reg add "HKCU\Software\MPC-HC\MPC-HC\Settings" /v "KeepHistory" /t "REG_DWORD" /d "0" /f
reg add "HKCU\Software\MPC-HC\MPC-HC\Settings" /v "LimitWindowProportions" /t "REG_DWORD" /d "1" /f
reg add "HKCU\Software\MPC-HC\MPC-HC\Settings" /v "OnTop" /t "REG_DWORD" /d "1" /f
reg add "HKCU\Software\MPC-HC\MPC-HC\Settings" /v "SnapToDesktopEdges" /t "REG_DWORD" /d "1" /f
reg add "HKCU\Software\MPC-HC\MPC-HC\Settings" /v "TrayIcon" /t "REG_DWORD" /d "1" /f
reg add "HKCU\Software\MPC-HC\MPC-HC\Settings" /v "ShowOSD" /t "REG_DWORD" /d "1" /f

rem Notepad
reg add "HKCU\Software\Microsoft\Notepad" /v "iWindowPosDX" /t REG_DWORD /d "1614" /f
reg add "HKCU\Software\Microsoft\Notepad" /v "iWindowPosDY" /t REG_DWORD /d "487" /f
reg add "HKCU\Software\Microsoft\Notepad" /v "iWindowPosX" /t REG_DWORD /d "4294967289" /f
reg add "HKCU\Software\Microsoft\Notepad" /v "iWindowPosY" /t REG_DWORD /d "380" /f

rem Regedit
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit" /v "View" /t REG_BINARY /d "2c0000000000000001000000fffffffffffffffffffffffffffffffff8ffffff0000000047060000b60100002f01000027010000780000002502000003000000" /f

rem WPS Office Free (To block ADs, just block WPS in the firewall)
del "%LocalAppData%\Kingsoft\WPS Office\10.2.0.7635\office6\wpscenter.exe" /s /f /q
del "%LocalAppData%\Kingsoft\WPS Office\10.2.0.7635\office6\wpscloudlaunch.exe" /s /f /q
taskkill /im wpscloudsvr.exe /f
takeown /f "%LocalAppData%\Kingsoft\WPS Office\10.2.0.7635\office6\wpscloudsvr.exe" /a
del "%LocalAppData%\Kingsoft\WPS Office\10.2.0.7635\office6\wpscloudsvr.exe" /s /f /q
takeown /f "%LocalAppData%\Kingsoft\WPS Office\10.2.0.7635\office6\wpscloudlaunch.exe" /a
del "%LocalAppData%\Kingsoft\WPS Office\10.2.0.7635\office6\wpscloudlaunch.exe" /s /f /q
taskkill /im updateself.exe /f
taskkill /im wpsupdate.exe /f
rd "%LocalAppData%\Kingsoft\WPS Office\10.2.0.7635\wtoolex" /s /q
schtasks /DELETE /TN "WpsExternal_Mikai_20190122225622" /f
schtasks /DELETE /TN "WpsKtpcntrQingTask_Mikai" /f
schtasks /DELETE /TN "WpsUpdateTask_Mikai" /f

rem WPS Remove context menu
reg delete "HKCU\Software\Classes\*\shellex\ContextMenuHandlers\qingshellext" /f
reg delete "HKCU\Software\Classes\Directory\Background\shellex\ContextMenuHandlers\qingshellext" /f
reg delete "HKCU\Software\Classes\Directory\shellex\ContextMenuHandlers\qingshellext" /f

rem XnView
reg add "HKCU\Software\XnView" /v "UseRegistry" /t "REG_DWORD" /d "1" /f
reg add "HKCU\Software\XnView\Browser" /v "ShowToolTips" /t "REG_DWORD" /d "0" /f
reg add "HKCU\Software\XnView\Browser" /v "StartupDirectory" /t "REG_SZ" /d "%UserProfile%\Desktop" /f
reg add "HKCU\Software\XnView\Browser" /v "StartupIn" /t "REG_DWORD" /d "2" /f
reg add "HKCU\Software\XnView\Capture" /v "Delay" /t "REG_DWORD" /d "2" /f
reg add "HKCU\Software\XnView\Capture" /v "Directory" /t "REG_SZ" /d "%UserProfile%\Desktop" /f
reg add "HKCU\Software\XnView\Capture" /v "HotKey" /t "REG_DWORD" /d "9" /f
reg add "HKCU\Software\XnView\Capture" /v "IncludeCursor" /t "REG_DWORD" /d "0" /f
reg add "HKCU\Software\XnView\Capture" /v "Method" /t "REG_DWORD" /d "0" /f
reg add "HKCU\Software\XnView\Capture" /v "Multiple" /t "REG_DWORD" /d "1" /f
reg add "HKCU\Software\XnView\Capture" /v "SaveIntoFile" /t "REG_DWORD" /d "1" /f
reg add "HKCU\Software\XnView\Start" /v "MaximizeXnviewAtStartup" /t "REG_DWORD" /d "1" /f
reg add "HKCU\Software\XnView\Start" /v "OnlyOneInstance" /t "REG_DWORD" /d "1" /f
reg add "HKCU\Software\XnView\Start" /v "PathSave" /t "REG_SZ" /d "%UserProfile%\Desktop" /f
reg add "HKCU\Software\XnView\Start" /v "SavePosition" /t "REG_DWORD" /d "0" /f
reg add "HKCU\Software\XnView\Start" /v "ShowSaveDlg" /t "REG_DWORD" /d "0" /f


rem =========================== Windows Setup plus Manual Config ===========================


rem Windows Setup 1 (Basics plus Manual software install) - https://pastebin.com/CKQed9ZX
rem Windows Setup 2 (Install drivers/software plus Manual Config) - https://pastebin.com/Lxe09qsU
rem Disable Windows Defender (run twice to disable services) - https://pastebin.com/kYCVzZPz


rem ==================================== Windows Drivers ===================================


rem It is not possible to uninstall network adapters since 1803
rem https://social.technet.microsoft.com/Forums/en-US/38e53f34-a607-4368-9d9b-7acba1d32b80/cannot-uninstall-protocols-such-as-client-for-microsoft-networks

rem AF-UNIX socket provider / Default - 
reg add "HKLM\System\CurrentControlSet\Services\afunix" /v "Start" /t REG_DWORD /d "4" /f

rem Background Activity Moderator Driver / Default - 
reg add "HKLM\System\CurrentControlSet\Services\bam" /v "Start" /t REG_DWORD /d "4" /f

rem CD-ROM Driver / Default - 1
reg add "HKLM\System\CurrentControlSet\Services\cdrom" /v "Start" /t REG_DWORD /d "4" /f

rem Link-Layer Topology Discovery Responder / Default - 2
reg add "HKLM\System\CurrentControlSet\Services\rspndr" /v "Start" /t REG_DWORD /d "4" /f

rem Link-Layer Topology Discovery Mapper I/O Driver / Default - 2
reg add "HKLM\System\CurrentControlSet\Services\lltdio" /v "Start" /t REG_DWORD /d "4" /f

rem Microsoft LLDP Protocol Driver / Default - 2
reg add "HKLM\System\CurrentControlSet\Services\MsLldp" /v "Start" /t REG_DWORD /d "4" /f

rem Microsoft Hyper-V Virtualization Infrastructure Driver / Default - 3
reg add "HKLM\System\CurrentControlSet\Services\Vid" /v "Start" /t REG_DWORD /d "4" /f

rem Microsoft Virtual Network Adapter Enumerator / Default - 3
reg add "HKLM\System\CurrentControlSet\Services\NdisVirtualBus" /v "Start" /t REG_DWORD /d "4" /f

rem NativeWifi Miniport Driver / Default - 
reg add "HKLM\System\CurrentControlSet\Services\NativeWifiP" /v "Start" /t REG_DWORD /d "4" /f

rem QoS for storage I/O traffic / Default - 2
reg add "HKLM\System\CurrentControlSet\Services\storqosflt" /v "Start" /t REG_DWORD /d "4" /f

rem QoS Multimeda Class Scheduler / Default - 2
reg add "HKLM\System\CurrentControlSet\Services\MMCSS" /v "Start" /t REG_DWORD /d "4" /f

rem QoS Packet Scheduler / Default - 1
reg add "HKLM\System\CurrentControlSet\Services\Psched" /v "Start" /t REG_DWORD /d "4" /f

rem Named pipe service trigger provider / Default - 1
rem https://msdn.microsoft.com/en-us/library/windows/desktop/aa365590(v=vs.85).aspx
reg add "HKLM\System\CurrentControlSet\Services\npsvctrig" /v "Start" /t REG_DWORD /d "4" /f

rem NetBIOS Interface / Default - 1
reg add "HKLM\System\CurrentControlSet\Services\NetBIOS" /v "Start" /t REG_DWORD /d "4" /f

rem NetBIOS over TCP/IP / Default - 1
reg add "HKLM\System\CurrentControlSet\Services\NetBT" /v "Start" /t REG_DWORD /d "4" /f

rem Remote Access IP ARP Driver / Default - 2
reg add "HKLM\System\CurrentControlSet\Services\wanarp" /v "Start" /t REG_DWORD /d "4" /f

rem Remote Desktop Device Redirector Bus Driver / Default - 3
reg add "HKLM\System\CurrentControlSet\Services\rdpbus" /v "Start" /t REG_DWORD /d "4" /f

rem Storage Spaces Driver / Default - 0
reg add "HKLM\System\CurrentControlSet\Services\spaceport" /v "Start" /t REG_DWORD /d "4" /f

rem The framework for network mini-redirectors / Default - 1
rem https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/the-redirected-drive-buffering-subsystem
reg add "HKLM\System\CurrentControlSet\Services\rdbss" /v "Start" /t REG_DWORD /d "4" /f

rem Virtual WiFi Filter Driver / Default - 
reg add "HKLM\System\CurrentControlSet\Services\vwififlt" /v "Start" /t REG_DWORD /d "4" /f


rem =========================== Windows Defender Security Center ===========================


rem ________________________________________________________________________________________
rem https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0290

rem Windows Defender Security Center service
reg add "HKLM\System\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f


rem =========================== Windows Defender Security Centre ===========================
rem -------------------------------- App & browser control ---------------------------------

rem Off - Disable Windows SmartScreen / On - Enable Windows SmartScreen 
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f

rem 0 - Disable SmartScreen Filter in Microsoft Edge / 1 - Enable
reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f

rem 0 - Disable Windows SmartScreen for Windows Store Apps / 1 - Enable
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t "REG_DWORD" /d "0" /f

rem ________________________________________________________________________________________
rem Remove Smartscreen (to restore run "sfc /scannow")
takeown /f "%WinDir%\System32\smartscreen.exe" /a
icacls "%WinDir%\System32\smartscreen.exe" /grant:r Administrators:F /c
taskkill /im smartscreen.exe /f
del "%WinDir%\System32\smartscreen.exe" /s /f /q


rem =========================== Windows Defender Security Center ===========================
rem ----------------------------- Device performance & health ------------------------------

rem ________________________________________________________________________________________
rem Specifies how the System responds when a user tries to install device driver files that are not digitally signed / 00 - Ignore / 01 - Warn / 02 - Block
reg add "HKLM\Software\Microsoft\Driver Signing" /v "Policy" /t REG_BINARY /d "01" /f

rem Prevent device metadata retrieval from the Internet / Do not automatically download manufacturers’ apps and custom icons available for your devices
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d "1" /f 
sc config DsmSvc start= disabled

rem Do you want Windows to download driver Software / 0 - Never / 1 - Allways / 2 - Install driver Software, if it is not found on my computer
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d "0" /f

rem Specify search order for device driver source locations 
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\DriverSearching" /v "DontSearchWindowsUpdate" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\DriverSearching" /v "DriverUpdateWizardWuSearchEnabled" /t REG_DWORD /d "0" /f

rem 1 - Disable driver updates in Windows Update
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f

rem Avoid the driver signing enforcement for EV cert / SHA256 Microsoft Windows signed drivers which is further enforced via Secure Boot
rem reg add "HKLM\System\CurrentControlSet\Control\CI\Policy" /v "UpgradedSystem" /t REG_DWORD /d "1" /f


rem =========================== Windows Defender Security Center ===========================
rem ------------------------------------ Family Options ------------------------------------

rem ________________________________________________________________________________________
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /Disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefreshTask" /Disable


rem =========================== Windows Defender Security Center ===========================
rem ---------------------------- Firewall & network protection -----------------------------

rem Enable Windows Firewall / AllProfiles / CurrentProfile / DomainProfile / PrivateProfile / PublicProfile
rem https://technet.microsoft.com/en-us/library/cc771920(v=ws.10).aspx
netsh advfirewall set allprofiles state on

rem Block all inbound network traffic and all outbound except allowed apps
netsh advfirewall set DomainProfile firewallpolicy blockinboundalways,blockoutbound
netsh advfirewall set PrivateProfile firewallpolicy blockinboundalways,blockoutbound
netsh advfirewall set PublicProfile firewallpolicy blockinbound,allowoutbound

rem Remove All Windows Firewall Rules
netsh advfirewall firewall delete rule name=all
rem reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /f

rem Windows Firewall Rules


rem ________________________________________________________________________________________
rem https://technet.microsoft.com/en-us/itpro/powershell/windows/defender/set-mppreference
reg delete "HKLM\Software\Policies\Microsoft\Windows Defender" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SpynetReporting" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f

rem Disable WD services
reg add "HKLM\System\CurrentControlSet\Services\WdBoot" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WdFilter" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WdNisDrv" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f

rem Disable Logging
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d "0" /f

rem Disable Tasks
schtasks /Change /TN "Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable

rem Remove context menu
reg delete "HKCR\*\shellex\ContextMenuHandlers\EPP" /f
reg delete "HKCR\Directory\shellex\ContextMenuHandlers\EPP" /f
reg delete "HKCR\Drive\shellex\ContextMenuHandlers\EPP" /f


rem =========================== Windows Defender Security Center ===========================
rem ------------------------------ Virus & threat protection -------------------------------
rem .......................... Virus & threat protection settings ..........................

rem 1 - Disable Real-time protection
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f


rem =================================== Windows Logging ====================================


rem https://blogs.technet.microsoft.com/askperf/2009/10/04/windows-7-windows-server-2008-r2-unified-background-process-manager-ubpm
rem https://msdn.microsoft.com/en-us/library/windows/desktop/aa363687(v=vs.85).aspx
rem https://technet.microsoft.com/en-us/library/cc722404(v=ws.11).aspx
rem DiagLog is required by Diagnostic Policy Service (Troubleshooting)
rem EventLog-System/EventLog-Application are required by Windows Events Log Service
rem perfmon

reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\AppModel" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\Circular Kernel Context Logger" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\CShellCircular" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\CloudExperienceHostOobe" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\EventLog-Application" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\EventLog-Security" /v "Start" /t REG_DWORD /d "1" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\EventLog-System" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DiagLog" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\FaceRecoTel" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\FaceUnlock" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\LwtNetLog" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\NetCore" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\NtfsLog" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\ReadyBoot" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\TileStore" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\Tpm" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\UBPM" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\WdiContextLog" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\WiFiDriverIHVSession" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\WiFiSession" /v "Start" /t REG_DWORD /d "0" /f


rem ================================ Windows Error Reporting ===============================


rem https://msdn.microsoft.com/en-us/library/windows/desktop/bb513638(v=vs.85).aspx

rem Disable Microsoft Support Diagnostic Tool MSDT
reg add "HKLM\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /v "DisableQueryRemoteServer" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /v "EnableQueryRemoteServer" /t REG_DWORD /d "0" /f

rem Disable System Debugger (Dr. Watson)
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AeDebug" /v "Auto" /t REG_SZ /d "0" /f

rem 1 - Disable Windows Error Reporting (WER)
reg add "HKLM\Software\Microsoft\PCHealth\ErrorReporting" /v "DoReport" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\PCHealth\ErrorReporting" /v "ShowUI" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f

rem DefaultConsent / 1 - Always ask (default) / 2 - Parameters only / 3 - Parameters and safe data / 4 - All data
reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultConsent" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultOverrideBehavior" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultConsent" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultOverrideBehavior" /t REG_DWORD /d "1" /f

rem 1 - Disable WER sending second-level data
reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f

rem 1 - Disable WER crash dialogs, popups
reg add "HKLM\Software\Microsoft\PCHealth\ErrorReporting" /v "ShowUI" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d "1" /f

rem 1 - Disable WER logging
reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f

schtasks /Change /TN "Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable

rem Windows Error Reporting Service
sc config WerSvc start= disabled

rem Remove Windows Errror Reporting (to restore run "sfc /scannow")
takeown /f "%WinDir%\System32\WerFault.exe" /a
icacls "%WinDir%\System32\WerFault.exe" /grant:r Administrators:F /c
taskkill /im WerFault.exe /f
del "%WinDir%\System32\WerFault.exe" /s /f /q


rem =================================== Windows Explorer ===================================
rem --------------------------------------- Options ----------------------------------------
rem ....................................... General ........................................

rem 2 - Open File Explorer to Quick access / 1 - Open File Explorer to This PC / 3 - Open File Explorer to Downloads
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d "1" /f

rem Single-click to open an item (point to select)
rem reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShellState" /t REG_BINARY /d "2400000017a8000000000000000000000000000001000000130000000000000073000000" /f

rem 2 - Underline icon titles consistent with my browser / 3 - Underline icon titles only when I point at them
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "IconUnderline" /t REG_DWORD /d "2" /f

rem 1 - Show recently used folders in Quick Access
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d "4" /f

rem 1 - Show frequently folders in Quick Access
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowFrequent" /t REG_DWORD /d "4" /f


rem =================================== Windows Explorer ===================================
rem --------------------------------------- Options ----------------------------------------
rem ........................................ View .........................................

rem Open Explorer - Choose the desired View - View - Options - View - Apply to Folders - OK - Close Explorer ASAP
reg delete "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags" /f
reg delete "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU" /f
reg delete "HKCU\Software\Classes\Wow6432Node\Local Settings\Software\Microsoft\Windows\Shell\Bags" /f
reg delete "HKCU\Software\Classes\Wow6432Node\Local Settings\Software\Microsoft\Windows\Shell\BagMRU" /f
reg delete "HKCU\Software\Microsoft\Windows\Shell\Bags" /f
reg delete "HKCU\Software\Microsoft\Windows\Shell\BagMRU" /f
reg delete "HKCU\Software\Microsoft\Windows\ShellNoRoam\Bags" /f
reg delete "HKCU\Software\Microsoft\Windows\ShellNoRoam\BagMRU" /f
reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell" /v "FolderType" /t REG_SZ /d "NotSpecified" /f

rem ________________________________________________________________________________________
rem Remove Network from Navigation Panel
rem Take Ownership of the Registry key - https://www.youtube.com/watch?v=M1l5ifYKefg
reg add "HKCR\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}\ShellFolder" /v "Attributes" /t REG_DWORD /d "2962489444" /f

rem 1 - Hide Quick access from This PC / 0 - Show
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "HubMode" /t REG_DWORD /d "1" /f

rem Show/Hide - 3D Objects from This PC
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f
reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f

rem Show/Hide - Desktop from This PC
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Show" /f
reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Show" /f

rem Show/Hide - Documents from This PC
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f
reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f

rem Show/Hide - Downloads from This PC
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Show" /f
reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Show" /f

rem Show/Hide - Movies from This PC
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Show" /f
reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Show" /f

rem Show/Hide - Music from This PC
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f
reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f

rem Show/Hide - Pictures from This PC
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Show" /f
reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Show" /f

rem Remove Desktop folder from This PC
rem reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" /f
rem reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" /f

rem Remove Documents folder from This PC
rem reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" /f
rem reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" /f

rem Remove Downloads folder from This PC
rem reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" /f
rem reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" /f

rem Remove Movies folder from This PC
rem reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" /f
rem reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" /f

rem Remove Music folder from This PC on
rem reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f
rem reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f

rem Remove Pictures folder from This PC
rem reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /f
rem reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /f


rem =================================== Windows Explorer ===================================
rem --------------------------------------- Options ----------------------------------------
rem .................................. Advanced Settings ...................................

rem 1 - Show hidden files, folders and drives
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d "1" /f

rem 0 - Show extensions for known file types
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d "0" /f

rem 0 - Hide protected operating system files 
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d "0" /f

rem 1 - Launch folder windows in a separate process
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "SeparateProcess" /t REG_DWORD /d "1" /f

rem 1 - Show Sync Provider Notifications in Windows Explorer (ADs)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d "0" /f

rem 1 - Use Sharing Wizard
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "SharingWizardOn" /t REG_DWORD /d "0" /f

rem Navigation pane - 1 - Expand to open folder
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "NavPaneExpandToCurrentFolder" /t REG_DWORD /d "0" /f

rem ________________________________________________________________________________________
rem 0 - All of the components of Windows Explorer run a single process / 1 - All instances of Windows Explorer run in one process and the Desktop and Taskbar run in a separate process
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "DesktopProcess" /t REG_DWORD /d "1" /f

rem Yes - Use Inline AutoComplete in File Explorer and Run Dialog / No
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete" /v "Append Completion" /t REG_SZ /d "No" /f

rem 0 - Do this for all current items checkbox / 1 - Disabled
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v "ConfirmationCheckBoxDoForAll" /t REG_DWORD /d "0" /f

rem 1 - Always show more details in copy dialog
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v "EnthusiastMode" /t REG_DWORD /d "0" /f

rem 1 - Display confirmation dialog when deleting files
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ConfirmFileDelete" /t REG_DWORD /d "1" /f

rem 1075839525 - Auto arrange icons and Align icons to grid on Desktop / 1075839520 / 1075839521 / 1075839524
reg add "HKCU\Software\Microsoft\Windows\Shell\Bags\1\Desktop" /v "FFlags" /t REG_DWORD /d "1075839525" /f

rem 1 - Disable Look for an app in the Store (How do you want to open this file)
reg add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v "NoUseStoreOpenWith" /t REG_DWORD /d "1" /f


rem ================================== Windows OneDrive ====================================


rem Remove OneDrive
taskkill /F /IM onedrive.exe
rem "%SYSTEMROOT%\System32\OneDriveSetup.exe" /uninstall
rem "%SYSTEMROOT%\SysWOW64\OneDriveSetup.exe" /uninstall
rd "%LOCALAPPDATA%\Microsoft\OneDrive" /Q /S
rd "%PROGRAMDATA%\Microsoft OneDrive" /Q /S
rd "%USERPROFILE%\OneDrive" /Q /S

rem 0 - Remove from Windows Explorer
reg add "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f
reg add "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Classes\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f

rem Hide One Drive Icon on Desktop
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /t REG_DWORD /d "1" /f

rem 1 - Disable sync files to One Drive
reg add "HKCU\Software\Microsoft\OneDrive" /v "DisablePersonalSync" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSync" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Wow6432Node\Policies\Microsoft\Windows\Onedrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d "1" /f

rem 1 - Disable saving Libraries to OneDrive
reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v "DisableLibrariesDefaultSaveToOneDrive" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Wow6432Node\Policies\Microsoft\Windows\Onedrive" /v "DisableLibrariesDefaultSaveToOneDrive" /t REG_DWORD /d "1" /f

rem 1 - Disable Sync over metered network
reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v "DisableMeteredNetworkFileSync" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Wow6432Node\Policies\Microsoft\Windows\Onedrive" /v "DisableMeteredNetworkFileSync" /t REG_DWORD /d "1" /f

rem Remove Startup entry
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDrive" /f

rem Disable Service
sc config OneSyncSvc start= disabled
sc config OneSyncSvc_Session1 start= disabled

rem Disable Task
schtasks /Change /TN "OneDrive Standalone Update Task v2" /Disable


rem ================================ Windows Optimizations =================================


rem https://msdn.microsoft.com/en-us/library/ee377058(v=bts.10).aspx
rem https://channel9.msdn.com/Blogs/Seth-Juarez/Memory-Compression-in-Windows-10-RTM
rem https://blogs.technet.microsoft.com/markrussinovich/2008/07/21/pushing-the-limits-of-windows-physical-memory

rem Determines whether user processes end automatically when the user either logs off or shuts down / 1 - Processes end automatically
reg add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "0" /f

rem Specifies the number of times the taskbar button flashes to notify the user that the system has activated a background window
rem If the time elapsed since the last user input exceeds the value of the ForegroundLockTimeout entry, the window will automatically be brought to the foreground
reg add "HKCU\Control Panel\Desktop" /v "ForegroundFlashCount" /t REG_SZ /d "0" /f

rem ForegroundLockTimeout specifies the time in milliseconds, following user input, during which the system keeps applications from moving into the foreground / 0 - Disabled / 200000 - Default
reg add "HKCU\Control Panel\Desktop" /v "ForegroundLockTimeout" /t REG_DWORD /d "0" /f

rem Specifies in milliseconds how long the System waits for user processes to end after the user clicks the End Task command button in Task Manager
reg add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "5000" /f

rem Determines how long the System waits for user processes to end after the user attempts to log off or to shut down
reg add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "5000" /f

rem Determines in milliseconds how long the System waits for services to stop after notifying the service that the System is shutting down
reg add "HKLM\System\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "5000" /f

rem Determines in milliseconds the interval from the time the cursor is pointed at a menu until the menu items are displayed
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f

rem Remove Windows Mouse Acceleration Curve
reg delete "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /f
reg delete "HKCU\Control Panel\Mouse" /v "SmoothMouseYCurve" /f

rem Mouse Hover Time in milliseconds before Pop-up Display
reg add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "0" /f

rem How long in milliseconds you want to have for a startup delay time for desktop apps that run at startup to load
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "StartupDelayInMSec" /t REG_DWORD /d "0" /f

rem n - Disable Background disk defragmentation / y - Enable How long in milliseconds you want to have for a startup delay time for desktop apps that run at startup to load
reg add "HKLM\Software\Microsoft\Dfrg\BootOptimizeFunction" /v "Enable" /t REG_SZ /d "n" /f

rem 0 - Disable Background auto-layout / Disable Optimize Hard Disk when idle
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\OptimalLayout" /v "EnableAutoLayout" /t REG_DWORD /d "0" /f

rem Disable Automatic Maintenance / Scheduled System Maintenance
reg add "HKLM\Software\Microsoft\Windows\ScheduledDiagnostics" /v "EnabledExecution" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\ScheduledDiagnostics" /v "EnabledExecution" /t REG_DWORD /d "0" /f

rem 0 - Enables 8dot3 name creation for all volumes on the system / 1 - Disables 8dot3 name creation for all volumes on the system / 2 - Sets 8dot3 name creation on a per volume basis / 3 - Disables 8dot3 name creation for all volumes except the system volume
rem fsutil 8dot3name scan c:\
fsutil behavior set disable8dot3 1

rem 1 - Disable the Encrypting File System (EFS)
fsutil behavior set disableencryption 1

rem 1 - When listing directories, NTFS does not update the last-access timestamp, and it does not record time stamp updates in the NTFS log
fsutil behavior set disablelastaccess 1

rem 5 - 5 secs / Delay Chkdsk startup time at OS Boot
reg add "HKLM\System\CurrentControlSet\Control\Session Manager" /v "AutoChkTimeout" /t REG_DWORD /d "5" /f

rem 0 - Establishes a standard size file-system cache of approximately 8 MB / 1 - Establishes a large system cache working set that can expand to physical memory, minus 4 MB, if needed
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "1" /f

rem 0 - Drivers and the kernel can be paged to disk as needed / 1 - Drivers and the kernel must remain in physical memory
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f

rem 0 - Disable Prefetch / 1 - Enable Prefetch when the application starts / 2 - Enable Prefetch when the device starts up / 3 - Enable Prefetch when the application or device starts up
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f

rem 0 - Disable SuperFetch / 1 - Enable SuperFetch when the application starts up / 2 - Enable SuperFetch when the device starts up / 3 - Enable SuperFetch when the application or device starts up
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f

rem 0 - Disable It / 1 - Default
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "SfTracingState" /t REG_DWORD /d "0" /f

rem 0 - Disable Fast Startup for a Full Shutdown / 1 - Enable Fast Startup (Hybrid Boot) for a Hybrid Shutdown
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f

rem Disable Hibernation / Disable Fast Startup (Hybrid Boot)
powercfg -h off


rem =================================== Windows Policies ===================================


rem https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-baselines
rem https://docs.microsoft.com/en-us/windows/client-management/mdm/policy-configuration-service-provider

rem 1808 - Disable the warning The Publisher could not be verified
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Associations" /v "DefaultFileTypeRisk" /t REG_DWORD /d "1808" /f

rem Disable Security warning to unblock the downloaded file
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d "1" /f

rem 1 - Disable Low Disk Space Alerts
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks " /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks " /t REG_DWORD /d "1" /f

rem 1 - Don't run specified exe 
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "DisallowRun" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "1" /t REG_SZ /d "bash.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "2" /t REG_SZ /d "mshta.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "3" /t REG_SZ /d "msra.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "4" /t REG_SZ /d "powershell_ise.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "5" /t REG_SZ /d "powershell.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "6" /t REG_SZ /d "psexec.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "7" /t REG_SZ /d "nc.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "8" /t REG_SZ /d "nc64.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "9" /t REG_SZ /d "bitsadmin.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "10" /t REG_SZ /d "cipher.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "11" /t REG_SZ /d "scrcons.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "12" /t REG_SZ /d "wbemtest.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "13" /t REG_SZ /d "winrm.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "14" /t REG_SZ /d "winrs.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "15" /t REG_SZ /d "wecutil.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "16" /t REG_SZ /d "werfault.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "17" /t REG_SZ /d "wscript.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "18" /t REG_SZ /d "cscript.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "18" /t REG_SZ /d "hh.exe" /f

rem N - Disable Distributed Component Object Model (DCOM) support in Windows / Y - Enable
reg add "HKLM\Software\Microsoft\Ole" /v "EnableDCOM" /t REG_SZ /d "N" /f

rem 0 - Disable Microsoft Windows Just-In-Time (JIT) script debugging
reg add "HKCU\Software\Microsoft\Windows Script\Settings" /v "JITDebug" /t REG_DWORD /d "0" /f
reg add "HKU\.Default\Microsoft\Windows Script\Settings" /v "JITDebug" /t REG_DWORD /d "0" /f

rem 1 - When the system detects that the user is downloading an external program that runs as part of the Windows user interface, the system searches for a digital certificate or requests that the user approve the action
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "EnforceShellExtensionSecurity" /t REG_DWORD /d "1" /f

rem Disable Active Desktop
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideIcons" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" /v "NoAddingComponents" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" /v "NoComponents" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ForceActiveDesktopOn" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoActiveDesktop" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoActiveDesktopChanges" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDesktop" /t REG_DWORD /d "0" /f

rem Enables or disables the retrieval of online tips and help for the Settings app (ADs)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "AllowOnlineTips" /t REG_DWORD /d "0" /f

rem 1 - Disable recent documents history
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d "1" /f

rem 1 - Do not add shares from recently opened documents to the My Network Places folder
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Norecentdocsnethood" /t REG_DWORD /d "1" /f

rem 0 - Disable configuring the machine at boot-up / 1 - Enable configuring the machine at boot-up / 2 - Enable configuring the machine only if DSC is in pending or current state (Default)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DSCAutomationHostEnabled" /t REG_DWORD /d "0" /f

rem 0 - Disable / 1 - Enable (Default)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableCursorSuppression" /t REG_DWORD /d "0" /f

rem 0 - Disable Administrative Shares
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "LocalAccountTokenFilterPolicy" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "AutoShareServer" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "AutoShareWks" /t REG_DWORD /d "0" /f

rem Disable SMB 1.0/2.0
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB1" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB2" /t REG_DWORD /d "0" /f

rem Disabling PowerShell script execution / Restricting PowerShell to Constrained Language mode
reg add "HKLM\Software\Policies\Microsoft\Windows\PowerShell" /v "EnableScripts" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Environment" /v "__PSLockDownPolicy" /t REG_SZ /d "4" /f

rem Determines how many user account entries Windows saves in the logon cache on the local computer.
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "CachedLogonsCount" /t REG_DWORD /d "0" /f

rem Locky ransomware using VBscript (Visual Basic Script) - https://blog.avast.com/a-closer-look-at-the-locky-ransomware
rem 0 - Disable Windows Script Host (WSH) (prevents majority of malware from working, especially when removing PowerShell as well, Disable ExecutionPolicy can be easily bypassed)
rem Also disabled via DisallowRun "wscript.exe" and "cscript.exe"
reg add "HKCU\Software\Microsoft\Windows Script Host\Settings" /v "Enabled" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows Script Host\Settings" /v "Enabled" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\WOW6432Node\Microsoft\Windows Script Host\Settings" /v "Enabled" /t REG_DWORD /d "1" /f

rem Prevent Microsoft Edge from starting and loading the Start and New Tab page at Windows startup and each time Microsoft Edge is closed
reg add "HKCU\Software\Policies\Microsoft\MicrosoftEdge" /v "AllowPrelaunch" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Policies\Microsoft\MicrosoftEdge\Main" /v "AllowPrelaunch" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Policies\Microsoft\MicrosoftEdge\TabPreloader" /v "PreventTabPreloading" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\MicrosoftEdge" /v "AllowPrelaunch" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main" /v "AllowPrelaunch" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\TabPreloader" /v "PreventTabPreloading" /t REG_DWORD /d "1" /f

rem Disable Customer Experience Improvement (CEIP/SQM - Software Quality Management)
reg add "HKLM\Software\Policies\Microsoft\Internet Explorer\SQM" /v "DisableCustomerImprovementProgram" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Messenger\Client" /v "CEIP" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f

rem 0 - Disable Application Impact Telemetry (AIT)
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f

rem 0 - Disable Inventory Collector
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f

rem 0 - Disable Program Compatibility Assistant
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "DisablePCA" /t REG_DWORD /d "1" /f

rem 1 - The device does not store the user's credentials for automatic sign-in after a Windows Update restart. The users' lock screen apps are not restarted after the system restarts.
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableAutomaticRestartSignOn" /t REG_DWORD /d "1" /f

rem 1 - Disable Steps Recorder (Steps Recorder keeps a record of steps taken by the user, the data includes user actions such as keyboard input and mouse input user interface data and screen shots)
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Steps-Recorder" /v "Enabled" /t REG_DWORD /d "0" /f

rem 1 - Specifies that Windows does not automatically encrypt eDrives
reg add "HKLM\Software\Policies\Microsoft\Windows\EnhancedStorageDevices" /v "TCGSecurityActivationDisabled" /t REG_DWORD /d "1" /f

rem Disable PerfTrack (tracking of responsiveness events)
reg add "HKLM\Software\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" /v "ScenarioExecutionEnabled" /t REG_DWORD /d "0" /f

rem 1000000000000 - Block untrusted fonts and log events / 2000000000000 - Do not block untrusted fonts / 3000000000000 - Log events without blocking untrusted fonts
reg add "HKLM\Software\Policies\Microsoft\Windows NT\MitigationOptions" /v "MitigationOptions_FontBocking" /t REG_SZ /d "1000000000000" /f

rem 1 - Enable Shutdown Event Tracker / 0 - Disable (Default)
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Reliability" /v "ShutdownReasonOn" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Reliability" /v "ShutdownReasonUI" /t REG_DWORD /d "0" /f

rem 1 - Do not allow storage of passwords and credentials for network authentication in the Credential Manager
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "DisableDomainCreds" /t REG_DWORD /d "1" /f

rem Digest Security Provider is disabled by default, but malware can enable it to recover the plain text passwords from the system’s memory (+CachedLogonsCount/+DisableDomainCreds/+DisableAutomaticRestartSignOn)
reg add "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest" /v "UseLogonCredential" /t REG_DWORD /d "0" /f

rem No-one will be a member of the built-in group, although it will still be visible in the Object Picker / 1 - all users logging on to a session on the server will be made a member of the TERMINAL SERVER USER group
reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v "TSUserEnabled" /t REG_DWORD /d "0" /f


rem =================================== Windows Policies ===================================
rem --------------------------------- User Account Control ---------------------------------

rem https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd835564(v=ws.10)
rem Reason to set UAC to Always Notify - https://technet.microsoft.com/en-us/library/2009.07.uac.aspx#id0560031

rem 0 - Elevate without prompting / 1 - Prompt for credentials on the secure desktop / 2 - Prompt for consent on the secure desktop / 3 - Prompt for credentials / 4 - Prompt for consent / 5 (Default) - Prompt for consent for non-Windows binaries
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "1" /f

rem 0 - Automatically deny elevation requests / 1 - Prompt for credentials on the secure desktop / 3 (Default) - Prompt for credentials
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d "0" /f

rem 2 (Default)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableFullTrustStartupTasks" /t REG_DWORD /d "0" /f

rem Detect application installations and prompt for elevation / 1 - Enabled (default for home) / 0 - Disabled (default for enterprise)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableInstallerDetection" /t REG_DWORD /d "1" /f

rem Run all administrators in Admin Approval Mode / 0 - Disabled (UAC) / 1 - Enabled (UAC)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "1" /f

rem Only elevate UIAccess applications that are installed in secure locations / 0 - Disabled / 1 (Default) - Enabled
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableSecureUIAPaths" /t REG_DWORD /d "0" /f

rem 0 (Default) = Disabled / 1 - Enabled
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableUwpStartupTasks" /t REG_DWORD /d "0" /f

rem Allow UIAccess applications to prompt for elevation without using the secure desktop / 0 (Default) = Disabled / 1 - Enabled
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableUIADesktopToggle" /t REG_DWORD /d "0" /f

rem https://technet.microsoft.com/en-us/itpro/windows/keep-secure/deploy-device-guard-enable-virtualization-based-security
rem 0 - Disabled / 1 - Enabled (Default)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableVirtualization" /t REG_DWORD /d "0" /f

rem Admin Approval Mode for the built-in Administrator account / 0 (Default) - Disabled / 1 - Enabled
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "FilterAdministratorToken" /t REG_DWORD /d "1" /f

rem Allow UIAccess applications to prompt for elevation without using the secure desktop / 0 (Default) - Disabled / 1 - Enabled
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d "1" /f

rem Enforce cryptographic signatures on any interactive application that requests elevation of privilege / 0 (Default) - Disabled / 1 - Enabled
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ValidateAdminCodeSignatures" /t REG_DWORD /d "1" /f

rem 1 - Enable command-line auditing
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v "ProcessCreationIncludeCmdLine_Enabled" /t REG_DWORD /d "1" /f


rem =============================== Windows Scheduled Tasks ================================


rem UAC Bypass - https://enigma0x3.net/2016/07/22/bypassing-uac-on-windows-10-using-disk-cleanup
rem UAC Bypass - https://blog.ensilo.com/darkgate-malware

rem schtasks /Change /TN "Microsoft\Windows\TextServicesFramework\MsCtfMonitor" /Enable
rem schtasks /Run /TN "Microsoft\Windows\TextServicesFramework\MsCtfMonitor"
rem schtasks /Change /TN "Microsoft\Office\OfficeBackgroundTaskHandlerRegistration" /Disable
rem schtasks /End /TN "Microsoft\Office\OfficeBackgroundTaskHandlerRegistration"

rem Disable Background Synchronization (permanently, it can not be disabled) 
schtasks /DELETE /TN "Microsoft\Windows\SettingSync\BackgroundUploadTask" /f

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


rem ================================== Windows Services ====================================


rem Security Accounts Manager has to be disabled Manually via services.msc
rem Disabling Windows Update will do nothing, but if you disable a service, it is dependent on, it will fail to start or check for updates, obviously

rem Application Information / required by UAC
rem AppX Deployment Service (AppXSVC) / required by Store
rem Background Intelligent Transfer Service / required by Windows Updates / depends on Network List Service (starts even when disabled)
rem Base Filtering Engine / required by Windows Defender Firewall
rem CNG Key Isolation / required to login to Windows Insider / Switch to Local Account / Set up PIN / Basically everything Credentials related
rem Credential Manager / required to store credentials (check User Accounts - Credential Manager) / required by apps like Windows Mail to store passwords / An administrator has blocked you from running this app.
rem Delivery Optimization / required by Windows Updates
rem Diagnostic Policy Service / required by Windows Diagnostic (Troubleshooting)
rem DHCP Client / required by Windows Updates (0x80240022)
rem Distributed Link Tracking Client / sometimes required to open shortcuts and System apps - "Windows cannot access the specified device, path, or file. You may not have the appropriate permission to access the item"
rem Geolocation Service / required by some Windows Store apps, it can not be enabled when Connected User Experiences and Telemetry is disabled
rem Microsoft Account Sign-in Assistant / required to login to Microsoft Account
rem Network Connections / required to manage Network Connections
rem Network Connection Broker / required and to change Network Settings
rem Network List Service / required by Windows Update and to change Network Settings
rem Network Location Awareness / required by Windows Update and Windows Defender Firewall
rem Network Store Interface Service / disabling disables Windows Firewall and can cause BSOD - Critical Service Failed
rem Print Spooler / required by printers
rem Radio Management Service / required to display WiFi networks
rem Web Account Manager / required to login to Microsoft Account/Store
rem Windows Biometric Service / required by biometric devices like a fingerprint reader
rem Windows Connection Manager / required by WiFi and Data Usage and Windows Update (starts even when disabled)
rem Windows Defender Firewall (Base Filtering Engine/Network Location Awareness) / required by Windows Update and Store Apps (0x80073d0a)
rem Windows Driver Foundation - User-mode Driver Framework / required by some drivers like USB devices
rem Windows Image Acquisition (WIA) / required by scanners
rem Windows Management Instrumentation / required by wmic commands / disabled to prevent fileless malware

rem Adobe Flash Player Update Service
sc config AdobeFlashPlayerUpdateSvc start= disabled

rem AMD External Events Utility
sc config "AMD External Events Utility" start= disabled

rem ASUS HM Com Service
sc config ALG start= disabled

rem ASUS Com Service
sc config asComSvc start= disabled

rem Application Layer Gateway Service
sc config asHmComSvc start= disabled

rem AppX Deployment Service (AppXSVC)
reg add "HKLM\System\CurrentControlSet\Services\AppXSvc" /v "Start" /t REG_DWORD /d "4" /f

rem AVCTP service
sc config BthAvctpSvc start= disabled

rem Background Intelligent Transfer Service
rem https://www.secureworks.com/blog/malware-lingers-with-bits
sc config BITS start= demand

rem Base Filtering Engine
reg add "HKLM\System\CurrentControlSet\Services\BFE" /v "Start" /t REG_DWORD /d "2" /f

rem Beep
sc config Beep start= disabled

rem BitLocker Drive Encryption Service
sc config BDESVC start= disabled

rem Capability Access Manager Service
sc config camsvc start= disabled

rem CDPUserSvc
sc config CDPUserSvc start= disabled

rem Certificate Propagation
sc config CertPropSvc start= disabled

rem Clipboard User Service
reg add "HKLM\System\CurrentControlSet\Services\cbdhsvc" /v "Start" /t REG_DWORD /d "4" /f

rem CNG Key Isolation
sc config KeyIso start= disabled

rem COM+ Event System
sc config EventSystem start= disabled

rem Connected User Experiences and Telemetry
sc config DiagTrack start= disabled

rem Contact Data
reg add "HKLM\System\CurrentControlSet\Services\PimIndexMaintenanceSvc" /v "Start" /t REG_DWORD /d "4" /f

rem Credential Manager
sc config VaultSvc start= disabled

rem Cryptographic Services
sc config VaultSvc start= demand

rem Data Usage
sc config DusmSvc start= disabled

rem Delivery Optimization
reg add "HKLM\System\CurrentControlSet\Services\DoSvc" /v "Start" /t REG_DWORD /d "4" /f

rem DHCP Client
sc config Dhcp start= auto

rem Diagnostic Policy Service
sc config DPS start= disabled

rem Diagnostic Hub (Privacy/Telemetry)
sc config diagnosticshub.standardcollector.service start= disabled

rem Distributed Link Tracking Client
sc config TrkWks start= demand

rem Distributed Transaction Coordinator
sc config MSDTC start= disabled

rem Device Management Wireless Application Protocol (WAP) Push message Routing Service
sc config dmwappushservice start= disabled

rem Encrypting File System (EFS)
sc config EFS start= disabled

rem Function Discovery Provider Host
sc config fdPHost start= disabled

rem Function Discovery Resource Publication
sc config FDResPub start= disabled

rem Geolocation Service
sc config lfsvc start= disabled

rem IKE and AuthIP IPsec Keying Modules
sc config IKEEXT start= disabled

rem IP Helper
sc config iphlpsvc start= disabled

rem IPsec Policy Agent
sc config PolicyAgent start= disabled

rem Network Connections
sc config Netman start= demand

rem Network List Service
sc config netprofm start= disabled

rem Network Location Awareness
sc config NlaSvc start= auto

rem Network Store Interface Service
sc config nsi start= auto

rem Optimize drives
sc config defragsvc start= disabled

rem Portable Device Enumerator Service
sc config WPDBusEnum start= disabled

rem Print Spooler
sc config Spooler start= disabled

rem Program Compatibility Assistant Service
sc config PcaSvc start= disabled

rem Radio Management Service
sc config RmSvc start= disabled

rem Remote Access Connection Manager
sc config RasMan start= disabled

rem Remote Desktop Services
sc config TermService start= disabled

rem Retail Demo
sc config RetailDemo start=disabled

rem Secure Socket Tunneling Protocol Service
sc config SstpSvc start= disabled

rem Security Centre
reg add "HKLM\System\CurrentControlSet\Services\wscsvc" /v "Start" /t REG_DWORD /d "4" /f

rem Server
sc config LanmanServer start= disabled

rem Shell Hardware Detection
sc config ShellHWDetection start= disabled

rem Smart Card
sc config SCardSvr start= disabled

rem Storage Service
sc config StorSvc start= disabled

rem SSDP Discovery
sc config SSDPSRV start= disabled

rem Superfetch
sc config SysMain start= disabled

rem System Guard Runtime Monitor Broker
reg add "HKLM\System\CurrentControlSet\Services\SgrmBroker" /v "Start" /t REG_DWORD /d "4" /f

rem TCP/IP NetBIOS Helper (Required by some internet connections like aDSL)
sc config lmhosts start= disabled

rem TeamViewer
sc config TeamViewer start= disabled

rem Themes
sc config Themes start= disabled

rem Tile Data model server
reg add "HKLM\System\CurrentControlSet\Services\tiledatamodelsvc" /v "Start" /t REG_DWORD /d "4" /f

rem Touch Keyboard and Handwriting Panel Service (keeps ctfmon.exe running)
sc config TabletInputService start= disabled

rem User Data Access
reg add "HKLM\System\CurrentControlSet\Services\UserDataSvc" /v "Start" /t REG_DWORD /d "4" /f

rem User Data Storage
reg add "HKLM\System\CurrentControlSet\Services\UnistoreSvc" /v "Start" /t REG_DWORD /d "4" /f

rem Web Account Manager
sc config TokenBroker start= disabled

rem WebClient
sc config WebClient start= disabled

rem Windows Biometric Service
sc config WbioSrvc start= disabled

rem Windows Connect Now - Config Registrar (Required by WPS WiFi connection)
sc config wcncsvc start= disabled

rem Windows Connection Manager
sc config Wcmsvc start= disabled

rem Windows Defender Firewall
reg add "HKLM\System\CurrentControlSet\Services\MpsSvc" /v "Start" /t REG_DWORD /d "2" /f

rem Windows Font Cache Service
sc config FontCache start= disabled

rem Windows Management Instrumentation
rem https://gbhackers.com/fileless-malware-wmi-eternalblue
sc config Winmgmt start= disabled

rem Windows Network Data Usage Monitoring Driver service (Kernel mode driver)
sc config ndu start= disabled

rem Windows Image Acquisition (WIA)
sc config stisvc start= disabled

rem Windows Insider Service
sc config wisvc start= disabled

rem Windows Push Notifications System Service
reg add "HKLM\System\CurrentControlSet\Services\WpnUserService" /v "Start" /t REG_DWORD /d "4" /f
sc config WpnService start= disabled

rem Windows PushToInstall Service
sc config PushToInstall start= disabled

rem Windows Remote Management (WS-Management)
sc config WinRM start= disabled

rem Windows Search
sc config WSearch start= disabled

rem Windows Time
sc config W32Time start= disabled

rem Windows Update
sc config wuauserv start= disabled

rem WinHTTP Web Proxy Auto-Discovery Service
reg add "HKLM\System\CurrentControlSet\Services\WinHttpAutoProxySvc" /v "Start" /t REG_DWORD /d "4" /f

rem WMI Performance Adapter
sc config wmiApSrv start= disabled

rem Workstation
sc config LanmanWorkstation start= disabled

rem WPS Office Cloud Service
sc config wpscloudsvr start= disabled

rem Yandex.Browser Update Service
sc config YandexBrowserService start= disabled


rem =================================== Windows Settings ===================================
rem -------------------------------------- Accounts ----------------------------------------
rem ................................. Sync your settings ...................................

rem 1 - Disable sync
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d "5" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSyncUserOverride" /t REG_DWORD /d "1" /f

rem 2 - Disable sync / 1 - Enable
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSync" /t REG_DWORD /d "2" /f

rem Individual sync settings
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\DesktopTheme" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\PackageState" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableAppSyncSettingSync" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableAppSyncSettingSyncUserOverride" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSync" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSyncUserOverride" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableCredentialsSettingSync" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableCredentialsSettingSyncUserOverride" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableDesktopThemeSettingSync" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableDesktopThemeSettingSyncUserOverride" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisablePersonalizationSettingSync" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisablePersonalizationSettingSyncUserOverride" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableStartLayoutSettingSync" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableStartLayoutSettingSyncUserOverride" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableSyncOnPaidNetwork" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSync" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSyncUserOverride" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSync" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSyncUserOverride" /t REG_DWORD /d "1" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------------- Apps ------------------------------------------
rem ................................... Apps & features ....................................

rem Choose where you can get apps from - Anywhere / PreferStore / StoreOnly / Recommendations
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "AicEnabled" /t REG_SZ /d "Anywhere" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------------- Apps ------------------------------------------
rem ................................... Apps & features ....................................
rem . . . . . . . . . . . . . . . . Programs and Features . . . . . . . . . . . . . . . . .

rem Dism /Online /Get-Features
rem Windows Basics


rem =================================== Windows Settings ===================================
rem --------------------------------------- Devices ----------------------------------------
rem ....................................... Autoplay .......................................

rem 0 - Use Autoplay for all media and devices
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v "DisableAutoplay" /t REG_DWORD /d "1" /f 

rem ________________________________________________________________________________________
rem Disable AutoPlay and AutoRun
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d "255" /f


rem =================================== Windows Settings ===================================
rem --------------------------------------- Devices ----------------------------------------
rem ........................................ Mouse .........................................
rem . . . . . . . . . . . . . . . . Additional mouse options . . . . . . . . . . . . . . . .

rem 1/6/10 - Enhance pointer precision (Mouse Acceleration)
reg add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f

rem ________________________________________________________________________________________
reg add "HKCU\Control Panel\Mouse" /v "MouseTrails" /t REG_SZ /d "0" /f


rem =================================== Windows Settings ===================================
rem --------------------------------------- Devices ---------------.-------------------------
rem ....................................... Typing ........................................

rem Autocorrect misspelled words (Privacy)
reg add "HKCU\Software\Microsoft\TabletTip\1.7" /v "EnableAutocorrection" /t REG_DWORD /d "0" /f

rem Highlight misspelled words (Privacy)
reg add "HKCU\Software\Microsoft\TabletTip\1.7" /v "EnableSpellchecking" /t REG_DWORD /d "0" /f

rem Show text suggestions as I type on the software keyboard (Privacy)
reg add "HKCU\Software\Microsoft\TabletTip\1.7" /v "EnableTextPrediction" /t REG_DWORD /d "0" /f

rem Add a space after I choose a text suggestion (Privacy)
reg add "HKCU\Software\Microsoft\TabletTip\1.7" /v "EnablePredictionSpaceInsertion" /t REG_DWORD /d "0" /f

rem Add a period after I double-tap the Spacebar (Privacy)
reg add "HKCU\Software\Microsoft\TabletTip\1.7" /v "EnableDoubleTapSpace" /t REG_DWORD /d "0" /f


rem =================================== Windows Settings ===================================
rem --------------------------------------- Devices ---------------.-------------------------
rem .................................. Pen & Windows Ink ....................................

rem Show recommended app suggestions (Privacy)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\PenWorkspace" /v "PenWorkspaceAppSuggestionsEnabled" /t REG_DWORD /d "0" /f


rem =================================== Windows Settings ===================================
rem ------------------------------------ Easy of Access ------------------------------------
rem ....................................... Keyboard .......................................

rem Sticky Keys / 26 - Disable All / 511 - Default
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "26" /f

rem Toggle Keys / 58 - Disable All / 63 - Default
reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "58" /f

rem ________________________________________________________________________________________
rem 1 - Disable Windows Key Hotkeys
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoWinKeys" /t REG_DWORD /d "1" /f
rem Disable specific Windows Key Hotkeys only (like R = Win+R)
rem reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisabledHotkeys" /t REG_EXPAND_SZ /d "R" /f


rem =================================== Windows Settings ===================================
rem ------------------------------------ Easy of Access ------------------------------------
rem ........................................ Mouse ........................................

rem Mouse Keys / 254 - Disable / 255 - Default
reg add "HKCU\Control Panel\Accessibility\MouseKeys" /v "Flags" /t REG_SZ /d "254" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------------- Gaming ----------------------------------------
rem ....................................... Game bar .......................................

rem 1 - Record game clips, screenshots, and broadcast using Game bar / Disable the message "Press Win + G to open Game bar"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f

rem 1 - Open Game bar using this button on a controller
reg add "HKCU\Software\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d "0" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------------- Gaming ----------------------------------------
rem ....................................... Game DVR .......................................

rem ________________________________________________________________________________________
rem 1 - Show tips when I start a game (ADs)
reg add "HKCU\Software\Microsoft\GameBar" /v "ShowStartupPanel" /t REG_DWORD /d "0" /f

rem 0 - Disable Fullscreen Optimizations for Current User / 0 - Enabled / 2 - Disabled
reg add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehavior" /t REG_DWORD /d "2" /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "2" /f

rem 0 - Disable Game DVR / "Press Win + G to record a clip"
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\GameDVR" /v "AllowgameDVR" /t REG_DWORD /d "0" /f

reg add "HKLM\System\CurrentControlSet\Services\BcastDVRUserService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\xbgm" /v "Start" /t REG_DWORD /d "4" /f
sc config XblAuthManager start= disabled
sc config XblGameSave start= disabled
sc config XboxGipSvc start= disabled
sc config XboxNetApiSvc start= disabled
schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTask" /Disable

rem Remove Game Bar Presence (to restore run "sfc /scannow")
takeown /f "%WinDir%\System32\GameBarPresenceWriter.exe" /a
icacls "%WinDir%\System32\GameBarPresenceWriter.exe" /grant:r Administrators:F /c
taskkill /im GameBarPresenceWriter.exe /f
del "%WinDir%\System32\GameBarPresenceWriter.exe" /s /f /q

reg add "HKCU\Software\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AudioCaptureEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "CursorCaptureEnabled" /t REG_DWORD /d "0" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------------- Gaming ----------------------------------------
rem ....................................... Game Mode ......................................

rem 0 - Disable support for Game Mode
reg add "HKCU\Software\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "0" /f

rem 1 - Use Game Mode
reg add "HKCU\Software\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "0" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------- Network & Internet ----------------------------------
rem ................................ Change adapter options ................................

rem Show public/external IP
rem nslookup myip.opendns.com. resolver1.opendns.com

rem Windows wmic command line command
rem http://www.computerhope.com/wmic.htm
rem To get adapter's index number use
rem wmic nicconfig get caption,index,TcpipNetbiosOptions

rem Disable IPv6
netsh int ipv6 isatap set state disabled
netsh int teredo set state disabled
netsh interface ipv6 6to4 set state state=disabled undoonstop=disabled
reg add "HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters" /v "DisabledComponents" /t REG_DWORD /d "255" /f

rem Setup DNS Servers on DHCP Enabled Network (CloudflareDNS)

rem Setup IP, Gateway and DNS Servers based on the MAC address (To Enable DHCP: wmic nicconfig where macaddress="28:E3:47:18:70:3D" call enabledhcp)
rem 0 - Disable LMHOSTS Lookup on all adapters / 1 - Enable
reg add "HKLM\System\CurrentControlSet\Services\NetBT\Parameters" /v "EnableLMHOSTS" /t REG_DWORD /d "0" /f

rem 2 - Disable NetBIOS over TCP/IP on all adapters / 1 - Enable / 0 - Default
wmic nicconfig where TcpipNetbiosOptions=0 call SetTcpipNetbios 2
wmic nicconfig where TcpipNetbiosOptions=1 call SetTcpipNetbios 2

rem ________________________________________________________________________________________
rem https://msdn.microsoft.com/en-us/library/windows/desktop/aa383928(v=vs.85).aspx
rem https://www.codeproject.com/articles/1158641/windows-continuous-disk-write-plus-webcachev-dat-p
rem Disable WinInetCacheServer (WinINet Caching/V01.log/WebCacheV01.dat)
rem %LocalAppData%\Microsoft\Windows\WebCache
rem Take Ownership of the Registry key - https://www.youtube.com/watch?v=M1l5ifYKefg
reg delete "HKCR\AppID\{3eb3c877-1f16-487c-9050-104dbcd66683}" /f
reg delete "HKCR\CLSID\{0358b920-0ac7-461f-98f4-58e32cd89148}" /v "AppID" /f
reg delete "HKCR\Wow6432Node\AppID\{3eb3c877-1f16-487c-9050-104dbcd66683}" /f
reg delete "HKCR\Wow6432Node\CLSID\{0358b920-0ac7-461f-98f4-58e32cd89148}" /v "AppID" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Classes\AppID\{3eb3c877-1f16-487c-9050-104dbcd66683}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Classes\CLSID\{0358b920-0ac7-461f-98f4-58e32cd89148}" /v "AppID" /f
schtasks /Change /TN "Microsoft\Windows\Wininet\CacheTask" /Disable

rem 0 - Disable WiFi Sense (shares your WiFi network login with other people)
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v "value" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v "value" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\WcmSvc\wifinetworkmanager\config" /v "AutoConnectAllowedOEM" /t REG_DWORD /d "0" /f

rem 1 - Disable Domain Name Devolution (DNS AutoCorrect) / 0 - Enabled (Default)
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "UseDomainNameDevolution" /t REG_DWORD /d "0" /f

rem Restrict NTLM: Incoming NTLM traffic - Deny All
reg add "HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0" /v "RestrictReceivingNTLMTraffic" /t REG_DWORD /d "2" /f
 
rem Restrict NTLM: Outgoing NTLM traffic to remote servers - Deny All
reg add "HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0" /v "RestrictSendingNTLMTraffic" /t REG_DWORD /d "2" /f


rem =================================== Windows Settings ===================================
rem ----------------------------------- Personalization ------------------------------------
rem ..................................... Background .......................................

rem Choose your picture (Black/Dark recommended)
rem reg add "HKCU\Control Panel\Desktop" /v "Wallpaper" /t REG_SZ /d "E:\Software\Temp\Pics\MLP Wallpapers\Wallpaper.jpg" /f

rem Choose a fit / 10 - Fill / 6 - Fit / 2 - Stretch / 0 - Tile/Center
reg add "HKCU\Control Panel\Desktop" /v "WallpaperStyle" /t REG_SZ /d "2" /f

rem ________________________________________________________________________________________

rem 60-100% Wallpaper's image quality / 85 - Default
reg add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d "100" /f


rem =================================== Windows Settings ===================================
rem ----------------------------------- Personalization ------------------------------------
rem ....................................... Colors .........................................

rem 1 - Automatically pick an accent color from my background
reg add "HKCU\Control Panel\Desktop" /v "AutoColorization" /t REG_SZ /d "0" /f

rem 1 - Transparency Effects
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "0" /f

rem 1 - Show accent color on the following surfaces - Start, taskbar, and action center
rem reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "ColorPrevalence" /t REG_DWORD /d "1" /f

rem 1 - Show accent color on the following surfaces - Title bars
reg add "HKCU\Software\Microsoft\Windows\DWM" /v "ColorPrevalence" /t REG_DWORD /d "1" /f


rem =================================== Windows Settings ===================================
rem ----------------------------------- Personalization ------------------------------------
rem ..................................... Lock screen ......................................

rem 1 - Get fun facts, tips, tricks, and more on your lock screen (ADs) / Windows Spotlight
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d "0" /f

rem ________________________________________________________________________________________
rem 1 - Disable LockScreen
reg add "HKLM\Software\Policies\Microsoft\Windows\Personalization" /v "NoLockScreen" /t REG_DWORD /d "1" /f

rem 1 - Disable Sign-in Screen Background Image
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "DisableLogonBackgroundImage" /t REG_DWORD /d "1" /f

rem 1 - Disable Windows spotlight (provides features such as different background images and text on the lock screen, suggested apps)
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightFeatures" /t REG_DWORD /d "1" /f


rem =================================== Windows Settings ===================================
rem ----------------------------------- Personalization ------------------------------------
rem ..................................... Lock screen ......................................
rem . . . . . . . . . . . . . . . . . Screen saver settings . . . . . . . . . . . . . . . .
 
rem 0 - No screen saver is selected / 1 - A screen saver is selected
reg add "HKCU\Control Panel\Desktop" /v "ScreenSaveActive" /t REG_SZ /d "1" /f

rem Specifies whether the screen saver is password-protected / 0 - No / 1 - Yes
reg add "HKCU\Control Panel\Desktop" /v "ScreenSaverIsSecure" /t REG_SZ /d "0" /f

rem Specifies in seconds how long the System remains idle before the screen saver starts
reg add "HKCU\Control Panel\Desktop" /v "ScreenSaveTimeOut" /t REG_SZ /d "500" /f

rem Screensaver - Mystify.scr
reg add "HKCU\Control Panel\Desktop" /v "SCRNSAVE.EXE" /t REG_SZ /d "C:\Windows\PONY_ALL_NO_SOUND.scr" /f


rem =================================== Windows Settings ===================================
rem ----------------------------------- Personalization ------------------------------------
rem ........................................ Start .........................................

rem 1 - Show suggestions occasionally in Start (ADs)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f

rem 1 - Show recently opened items in Jump Lists on Start or the taskbar
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d "0" /f


rem =================================== Windows Settings ===================================
rem ----------------------------------- Personalization ------------------------------------
rem ....................................... Taskbar ........................................

rem Lock the taskbar
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarSizeMove" /t REG_DWORD /d "0" /f

rem Replace Command Prompt with Windows Powershell in the menu when I right-click the start button or press Windows key+X
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DontUsePowerShellOnWinX" /t REG_DWORD /d "1" /f

rem Combine taskbar buttons / 0 - Always hide labels / 1 - When taskbar is full / 2 - Never
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarGlomLevel" /t REG_DWORD /d "0" /f

rem 1 - Show contacts on the taskbar
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v "PeopleBand" /t REG_DWORD /d "0" /f

rem ________________________________________________________________________________________
rem 0 - Turn on Quiet Hours in Action Center / Disable/Hide the message: Turn on Windows Security Center service
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_TOASTS_ENABLED" /t REG_DWORD /d "0" /f

rem 0 - Hide Task View button
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d "0" /f

rem 0 - Disable Cortana in Taskbar search
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d "0" /f

rem 0 - Hide Taskbar search / 1 - Show search icon / 2 - Show search box
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "0" /f


rem =================================== Windows Settings ===================================
rem ----------------------------------- Personalization ------------------------------------
rem ....................................... Taskbar ........................................
rem . . . . . . . . . . . . . Select which icons appear on the taskbar . . . . . . . . . . .

rem 0 - Always show all icons in the notification area / 1 - Hide Inactive Icons
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "EnableAutoTray" /t REG_DWORD /d "0" /f


rem =================================== Windows Settings ===================================
rem ----------------------------------- Personalization ------------------------------------
rem ....................................... Taskbar ........................................
rem . . . . . . . . . . . . . . . . . Turn on system icons . . . . . . . . . . . . . . . . .

rem 1 - Hide Action Center System Tray Icon in Taskbar
reg add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /t REG_DWORD /d "1" /f

rem 1 - Hide Action Network System Tray Icon in Taskbar
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCANetwork" /t REG_DWORD /d "1" /f

rem 1 - Hide Action Power System Tray Icon in Taskbar
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAPower" /t REG_DWORD /d "0" /f

rem 1 - Hide Volume System Tray Icon in Taskbar
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAVolume" /t REG_DWORD /d "1" /f


rem =================================== Windows Settings ===================================
rem ----------------------------------- Personalization ------------------------------------
rem ....................................... Themes .........................................
rem . . . . . . . . . . . . . . . . . Desktop Icon Settings . . . . . . . . . . . . . . . .

rem Hide Control Panel
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" /t REG_DWORD /d "1" /f

rem Hide Network
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" /t REG_DWORD /d "1" /f

rem Hide Recycle Bin
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{645FF040-5081-101B-9F08-00AA002F954E}" /t REG_DWORD /d "1" /f

rem Hide Quick access
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{679f85cb-0220-4080-b29b-5540cc05aab6}" /t REG_DWORD /d "1" /f

rem Hide This PC
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d "1" /f

rem Hide User's Files
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" /t REG_DWORD /d "1" /f


rem =================================== Windows Settings ===================================
rem ----------------------------------- Personalization ------------------------------------
rem ....................................... Themes .........................................
rem . . . . . . . . . . . . . . . . . . . . Sounds . . . . . . . . . . . . . . . . . . . . .

rem Delete Windows Default Sounds (Permanently)
reg delete "HKCU\AppEvents\Schemes\Apps" /f

rem When windows detects communications activity / 0 - Mute all other sounds / 1 - Reduce all other by 80% / 2 - Reduce all other by 50% / 3 - Do nothing
reg add "HKCU\Software\Microsoft\Multimedia\Audio" /v "UserDuckingPreference" /t REG_DWORD /d "3" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------------- Privacy ---------------------------------------

rem https://docs.microsoft.com/en-us/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services
rem https://docs.microsoft.com/en-us/windows/client-management/mdm/new-in-windows-mdm-enrollment-management#whatsnew10
rem https://docs.microsoft.com/en-us/windows/client-management/mdm/policy-configuration-service-provider

rem ________________________________________________________________________________________
rem Let apps access ... / 0 - Default / 1 - Enabled / 2 - Disabled
reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessGazeInput" /t REG_DWORD /d "2" /f

rem Let apps access ... / 0 - Default / 1 - Enabled / 2 - Disabled
reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMotion" /t REG_DWORD /d "2" /f

rem Let apps access ... / 0 - Default / 1 - Enabled / 2 - Disabled
reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessPhone" /t REG_DWORD /d "2" /f

rem Disable Cortana
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "AllowCortana" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaCapabilities" /t REG_SZ /d "" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "DeviceHistoryEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "IsAssignedAccess" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "IsWindowsHelloActive" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Windows Search" /v "CortanaConsent" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\PolicyManager\default\Experience\AllowCortana" /v "value" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\SearchCompanion" /v "DisableContentFileUpdates" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "DoNotUseWebResults" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchPrivacy" /t REG_DWORD /d "3" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d "0" /f

rem 1 - Let Cortana respond to "Hey Cortana"
reg add "HKCU\Software\Microsoft\Speech_OneCore\Preferences" /v "VoiceActivationOn" /t REG_DWORD /d "0" /f

rem 1- Let Cortana listen for my commands when I press Windows key + C
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "VoiceShortcut" /t REG_DWORD /d "0" /f

rem 1 - Use Cortana even when my device is locked
reg add "HKCU\Software\Microsoft\Speech_OneCore\Preferences" /v "VoiceActivationEnableAboveLockscreen" /t REG_DWORD /d "0" /f

rem Remove Cortana (SearchUI.exe)
takeown /f "%WinDir%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy" /a /r /d y
icacls "%WinDir%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy" /inheritance:r /grant:r Administrators:(OI)(CI)F /t /l /q /c
taskkill /im SearchUI.exe /f
rd "%WinDir%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy" /s /q

rem Disable keyboard input/monitoring in apps like Calc, Edge, Search, Start, Store
schtasks /Change /TN "Microsoft\Windows\TextServicesFramework\MsCtfMonitor" /Disable


rem =================================== Windows Settings ===================================
rem ---------------------------------------- Privacy ---------------------------------------
rem ...................................... Account info ....................................

rem Let apps access my name, picture, and other account info / 0 - Default / 1 - Enabled / 2 - Disabled
reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessAccountInfo" /t REG_DWORD /d "2" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------------- Privacy ---------------------------------------
rem .................................... Activity History ..................................

rem Collect Activity History / 0 - Disabled / 1 - Enabled
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d "0" /f

rem Let Windows collect my activities from this PC / 0 - Disabled / 1 - Enabled
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d "0" /f

rem Let Windows collect my activities from this PC to the cloud / 0 - Disabled / 1 - Enabled
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d "0" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------------- Privacy ---------------------------------------
rem ..................................... App diagnostic ...................................

rem Let apps access diagnostic information / 0 - Default / 1 - Enabled / 2 - Disabled
reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsGetDiagnosticInfo" /t REG_DWORD /d "2" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------------- Privacy ---------------------------------------
rem .................................... Background apps ..................................

rem Let apps run in the background / 1 - Enabled / 0 - Disabled
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t REG_DWORD /d "0" /f

rem Let apps run in the background / 0 - Enabled / 1 - Disabled
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f

rem Let apps run in the background / 0 - Default / 1 - Enabled / 2 - Disabled
reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsRunInBackground" /t REG_DWORD /d "2" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------------- Privacy ---------------------------------------
rem ....................................... Calendar .......................................

rem Let Windows apps access contacts / 0 - Default / 1 - Enabled / 2 - Disabled
reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCalendar" /t REG_DWORD /d "2" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------------- Privacy ---------------------------------------
rem ..................................... Call history .....................................

rem Let apps access my call history / 0 - Default / 1 - Enabled / 2 - Disabled
reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCallHistory" /t REG_DWORD /d "2" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------------- Privacy ---------------------------------------
rem ........................................ Camera ........................................

rem Let apps use my camera / 0 - Default / 1 - Enabled / 2 - Disabled
reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCamera" /t REG_DWORD /d "2" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCamera_ForceAllowTheseApps" /t REG_MULTI_SZ /d "" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCamera_ForceDenyTheseApps" /t REG_MULTI_SZ /d "" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCamera_UserInControlOfTheseApps" /t REG_MULTI_SZ /d "" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------------- Privacy ---------------------------------------
rem ....................................... Contacts .......................................

rem Let Windows apps access contacts / 0 - Default / 1 - Enabled / 2 - Disabled
reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessContacts" /t REG_DWORD /d "2" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------------- Privacy ---------------------------------------
rem ......................................... Email ........................................

rem Let apps access and send email / 0 - Default / 1 - Enabled / 2 - Disabled
reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessEmail" /t REG_DWORD /d "2" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------------- Privacy ---------------------------------------
rem ................................. Feedback & diagnostics ...............................

rem Diagnostic and usage data - Select how much data you send to Microsoft / 0 - Security (Not aplicable on Home/Pro, it resets to Basic) / 1 - Basic / 2 - Enhanced (Hidden) / 3 - Full
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Telemetry" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f

rem 1 - Let Microsoft provide more tailored experiences with relevant tips and recommendations by using your diagnostic data
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f

rem Feedback Frequency - Windows should ask for my feedback: 0 - Never / Removed - Automatically
reg add "HKCU\Software\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d "0" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------------- Privacy ---------------------------------------
rem ........................................ General ......................................

rem Let apps use advertising ID to make ads more interesting to you based on your app usage
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f

rem 0 - Let websites provide locally relevant content by accessing my language list (let browsers access your local language)
reg add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f

rem 1 - Let Windows track app launches to improve Start and search results (Remember commands typed in Run) / 0 - Disable and Disable "Show most used apps"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "1" /f

rem 1 - Show me suggested content in the Settings app
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d "0" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------------- Privacy ---------------------------------------
rem ....................................... Location .......................................

rem 1 - Location for this device is Off
reg add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableSensors" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f

rem 0 - Default / 1 - Enabled / 2 - Disabled
reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation" /t REG_DWORD /d "2" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------------- Privacy ---------------------------------------
rem ....................................... Messaging ......................................

rem Let apps read or send messages (text or MMS) / 0 - Default / 1 - Enabled / 2 - Disabled
reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMessaging" /t REG_DWORD /d "2" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------------- Privacy ---------------------------------------
rem ...................................... Microphone ......................................

rem Let apps use my microphone / 0 - Default / 1 - Enabled / 2 - Disabled
reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMicrophone" /t REG_DWORD /d "2" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------------- Privacy ---------------------------------------
rem ..................................... Notifications ....................................

rem Let apps access my notifications / 0 - Default / 1 - Enabled / 2 - Disabled
reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessNotifications" /t REG_DWORD /d "2" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------------- Privacy ---------------------------------------
rem ..................................... Other devices ....................................

rem Let apps automatically share and sync info with wireless devices that don't explicitly pair with your PC, tablet, or phone / 0 - Default / 1 - Enabled / 2 - Disabled
reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsSyncWithDevices" /t REG_DWORD /d "2" /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTrustedDevices" /t REG_DWORD /d "2" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------------- Privacy ---------------------------------------
rem ............................... Speech, inking, & typing ...............................

rem ________________________________________________________________________________________
reg add "HKLM\Software\Microsoft\Input" /v "InputServiceEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Input" /v "InputServiceEnabledForCCI" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\InputPersonalization" /v "AllowInputPersonalization" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d "1" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------------- Privacy ---------------------------------------
rem ........................................ Radios ........................................

rem Let apps control radios / 0 - Default / 1 - Enabled / 2 - Disabled
reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessRadios" /t REG_DWORD /d "2" /f


rem =================================== Windows Settings ===================================
rem ---------------------------------------- Privacy ---------------------------------------
rem ......................................... Tasks ........................................

rem Let apps access tasks / 0 - Default / 1 - Enabled / 2 - Disabled
reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTasks" /t REG_DWORD /d "2" /f


rem =================================== Windows Settings ===================================
rem --------------------------------------- System -----------------------------------------
rem ........................................ About .........................................

rem PC Name: LianLiPC-7NB (Computer name should not be longer than 15 characters, no spaces either)
reg add "HKLM\System\CurrentControlSet\Control\ComputerName\ActiveComputerName" /v "ComputerName" /t REG_SZ /d "CRO-PC" /f
reg add "HKLM\System\CurrentControlSet\Control\ComputerName\ComputerName" /v "ComputerName" /t REG_SZ /d "CRO-PC" /f
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "Hostname" /t REG_SZ /d "CRO-PC" /f
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "NV Hostname" /t REG_SZ /d "CRO-PC" /f

rem Support
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\OEMInformation" /v "SupportHours" /t REG_SZ /d "Within 24-48 hours" /f

rem Computer Description
reg add "HKLM\System\CurrentControlSet\services\LanmanServer\Parameters" /v "srvcomment" /t REG_SZ /d "50/50 MBps" /f


rem =================================== Windows Settings ===================================
rem --------------------------------------- System -----------------------------------------
rem ........................................ About .........................................
rem . . . . . . . . . . . . . . . . . . . System info . . . . . . . . . . . . . . . . . . .

rem System info
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v "RegisteredOrganization" /t REG_SZ /d "GSecurity" /f

rem Remote Settings - Disable Remote Assistance
reg add "HKLM\System\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\Remote Assistance" /v "fAllowFullControl" /t REG_DWORD /d "0" /f

rem System Protection - Enable System restore and Set the size
rem reg delete "HKLM\Software\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableSR" /f
rem reg delete "HKLM\Software\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableConfig" /f
rem reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\SPP\Clients" /v " {09F7EDC5-294E-4180-AF6A-FB0E6A0E9513}" /t REG_MULTI_SZ /d "1" /f
rem schtasks /Change /TN "Microsoft\Windows\SystemRestore\SR" /Enable
rem vssadmin Resize ShadowStorage /For=C: /On=C: /Maxsize=5GB
rem sc config wbengine start= demand
rem sc config swprv start= demand
rem sc config vds start= demand
rem sc config VSS start= demand

rem System Protection - Disable System restore and Set the size
reg add "HKLM\Software\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableSR" /t REG_DWORD /d "1" /f
schtasks /Change /TN "Microsoft\Windows\SystemRestore\SR" /Disable
vssadmin Resize ShadowStorage /For=C: /On=C: /Maxsize=320MB

rem Advanced system settings - Performance - Advanced - Processor Scheduling
rem 0 - Foreground and background applications equally responsive / 1 - Foreground application more responsive than background / 2 - Best foreground application response time (Default)
rem 38 - Adjust for best performance of Programs / 24 - Adjust for best performance of Background Services
reg add "HKLM\System\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation " /t REG_DWORD /d "38" /f

rem Advanced system settings - Performance - Advanced - Virtual memory
rem Disable pagefile
wmic computersystem where name="%computername%" set AutomaticManagedPagefile=False
wmic pagefileset where name="%SystemDrive%\\pagefile.sys" set InitialSize=0,MaximumSize=0
wmic pagefileset where name="%SystemDrive%\\pagefile.sys" delete

rem Advanced system settings - Startup and Recovery
rem 5 - 5 secs / Time to display list of operating systems
bcdedit /timeout 5

rem Advanced system settings - Startup and Recovery
rem 1 - Automatically Restart (on System Failure)
reg add "HKLM\System\CurrentControlSet\Control\CrashControl" /v "AutoReboot" /t REG_DWORD /d "0" /f

rem ________________________________________________________________________________________
rem Disable Remote Assistance
sc config RemoteRegistry start= disabled
reg add "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service\WinRS" /v "AllowRemoteShellAccess" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowUnsolicited" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowUnsolicitedFullControl" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "fDenyTSConnections" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "TSAppCompat" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "TSEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "TSUserEnabled" /t REG_DWORD /d "0" /f

rem Encrypt the Pagefile
rem fsutil behavior set EncryptPagingFile 1


rem =================================== Windows Settings ===================================
rem --------------------------------------- System -----------------------------------------
rem ..................................... Clipboard ........................................

rem Save multiple items / 0 - Disable / 1 - Enable
reg add "HKCU\Software\Microsoft\Clipboard" /v "EnableClipboardHistory " /t REG_DWORD /d "0" /f

rem Sync across devices / 0 - Disable / 1 - Enable
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "AllowCrossDeviceClipboard " /t REG_DWORD /d "0" /f

rem ________________________________________________________________________________________
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "AllowClipboardHistory" /t REG_DWORD /d "0" /f


rem =================================== Windows Settings ===================================
rem --------------------------------------- System -----------------------------------------
rem ............................... Notifications & actions ................................

rem 1 - Get tips, tricks, and suggestions as you use Windows (ADs)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d "0" /f

rem 0 - Get notifications from apps and other senders
reg add "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotification" /t REG_DWORD /d "1" /f

rem Show me the Windows welcome experience after updates and occasionally when I sign in to highlight what's new and suggested (ADs)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d "0" /f


rem =================================== Windows Settings ===================================
rem --------------------------------------- System -----------------------------------------
rem .................................... Power & sleep .....................................
rem . . . . . . . . . . . . . . . . Additional power settings . . . . . . . . . . . . . . .

rem Change plan settings - Change advanced power settings - Hard disk - Turn off hard disk (on battery) after
rem 0 - Never / 4294967295 - max value in seconds
reg add "HKLM\Software\Policies\Microsoft\Power\PowerSettings\E69653CA-CF7F-4F05-AA73-CB833FA90AD4" /v "DCSettingIndex" /t REG_DWORD /d "0" /f

rem Change plan settings - Change adavnced power settings - Hard disk - Turn off hard disk (plugged in) after
rem 0 - Never / 4294967295 - max value in seconds
reg add "HKLM\Software\Policies\Microsoft\Power\PowerSettings\6738E2C4-E8A5-4A42-B16A-E040E769756E" /v "ACSettingIndex" /t REG_DWORD /d "0" /f


rem =================================== Windows Settings ===================================
rem --------------------------------------- System -----------------------------------------
rem ................................. Shared Experiences ...................................

rem Let apps on other devices open apps and message apps on this device, and vice versa / 0 - Disabled
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableCdp" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableMmx" /t REG_DWORD /d "0" /f


rem =================================== Windows Settings ===================================
rem ----------------------------------- Time & language -------------------------------------
rem ..................................... Date & time .......................................

rem Time Zone - Central Europe Standard Time
tzutil /s "Central Europe Standard Time"


rem =================================== Windows Settings ===================================
rem ----------------------------------- Time & language -------------------------------------
rem ..................................... Date & time .......................................
rem . . . . . . . . . . . . Additional date, time, & regional settings . . . . . . . . . . .

rem Set Formats to Metric
reg add "HKCU\Control Panel\International" /v "iDigits" /t REG_SZ /d "2" /f
reg add "HKCU\Control Panel\International" /v "iLZero" /t REG_SZ /d "1" /f
reg add "HKCU\Control Panel\International" /v "iMeasure" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\International" /v "iNegNumber" /t REG_SZ /d "1" /f
reg add "HKCU\Control Panel\International" /v "iPaperSize" /t REG_SZ /d "1" /f
reg add "HKCU\Control Panel\International" /v "iTLZero" /t REG_SZ /d "1" /f
reg add "HKCU\Control Panel\International" /v "sDecimal" /t REG_SZ /d "," /f
reg add "HKCU\Control Panel\International" /v "sNativeDigits" /t REG_SZ /d "0123456789" /f
reg add "HKCU\Control Panel\International" /v "sNegativeSign" /t REG_SZ /d "-" /f
reg add "HKCU\Control Panel\International" /v "sPositiveSign" /t REG_SZ /d "" /f
reg add "HKCU\Control Panel\International" /v "NumShape" /t REG_SZ /d "1" /f

rem Set Time to 24h / Monday
reg add "HKCU\Control Panel\International" /v "iCalendarType" /t REG_SZ /d "1" /f
reg add "HKCU\Control Panel\International" /v "iDate" /t REG_SZ /d "1" /f
reg add "HKCU\Control Panel\International" /v "iFirstDayOfWeek" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\International" /v "iFirstWeekOfYear" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\International" /v "iTime" /t REG_SZ /d "1" /f
reg add "HKCU\Control Panel\International" /v "iTimePrefix" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\International" /v "sDate" /t REG_SZ /d "-" /f
reg add "HKCU\Control Panel\International" /v "sList" /t REG_SZ /d "," /f
reg add "HKCU\Control Panel\International" /v "sLongDate" /t REG_SZ /d "d MMMM, yyyy" /f
reg add "HKCU\Control Panel\International" /v "sMonDecimalSep" /t REG_SZ /d "." /f
reg add "HKCU\Control Panel\International" /v "sMonGrouping" /t REG_SZ /d "3;0" /f
reg add "HKCU\Control Panel\International" /v "sMonThousandSep" /t REG_SZ /d "," /f
reg add "HKCU\Control Panel\International" /v "sShortDate" /t REG_SZ /d "dd-MMM-yy" /f
reg add "HKCU\Control Panel\International" /v "sTime" /t REG_SZ /d ":" /f
reg add "HKCU\Control Panel\International" /v "sTimeFormat" /t REG_SZ /d "HH:mm:ss" /f
reg add "HKCU\Control Panel\International" /v "sShortTime" /t REG_SZ /d "HH:mm" /f
reg add "HKCU\Control Panel\International" /v "sYearMonth" /t REG_SZ /d "MMMM yyyy" /f

rem 244 - Set Location to United States / 143 - Slovakia
reg add "HKCU\Control Panel\International\Geo" /v "Nation" /t REG_SZ /d "143" /f


rem =================================== Windows Settings ===================================
rem ----------------------------------- Time & Language ------------------------------------
rem .................................. Region & Language ...................................
rem . . . . . . . . . . . . . . . Advanced keyboard settings . . . . . . . . . . . . . . . .

rem Language bar options - Advanced key settings - Change Key Sequence
rem 3 - Not assigned / 2 - CTRL+SHIFT / 1 - Left ALT+SHIFT
reg add "HKCU\Keyboard Layout\Toggle" /v "Language Hotkey" /t REG_SZ /d "3" /f
reg add "HKCU\Keyboard Layout\Toggle" /v "Hotkey" /t REG_SZ /d "3" /f
reg add "HKCU\Keyboard Layout\Toggle" /v "Layout Hotkey" /t REG_SZ /d "3" /f

rem ________________________________________________________________________________________
rem 2 - Enable Num Lock on Sign-in Screen / 2147483648 - Disable
reg add "HKU\.DEFAULT\Control Panel\Keyboard" /v "InitialKeyboardIndicators" /t REG_SZ /d "2" /f


rem =================================== Windows Settings ===================================
rem ----------------------------------- Update & security ----------------------------------
rem ........................................ Backup .......................................

rem ________________________________________________________________________________________
rem 1 - Disable File History (Creating previous versions of files/Windows Backup)
reg add "HKLM\Software\Policies\Microsoft\Windows\FileHistory" /v "Disabled" /t REG_DWORD /d "1" /f


rem =================================== Windows Settings ===================================
rem ----------------------------------- Update & security ----------------------------------
rem .................................... Windows update ....................................

rem Change active hours (18 hours) 6am to 0am - Windows Updates will not automatically restart your device during active hours
reg add "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v "ActiveHoursStart" /t REG_DWORD /d "6" /f
reg add "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v "ActiveHoursEnd" /t REG_DWORD /d "0" /f

rem Restart options - 1 - We'll show a reminder when we're going to restart.
reg add "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v "RestartNotificationsAllowed" /t REG_DWORD /d "0" /f

rem ________________________________________________________________________________________
rem Remove Windows ActiveX Flash (could be exploited within Windows/Office)
rem regsvr32 /u /s "%SystemRoot%\System32\Macromed\Flash\FlashUtil_ActiveX.dll"
takeown /f "%SystemRoot%\System32\Macromed\Flash\FlashUtil_ActiveX.exe" /a
icacls "%SystemRoot%\System32\Macromed\Flash\FlashUtil_ActiveX.exe" /inheritance:r /grant:r Administrators:F /c
del "%SystemRoot%\System32\Macromed\Flash\FlashUtil_ActiveX.exe" /f /q
takeown /f "%SystemRoot%\System32\Macromed\Flash\FlashUtil_ActiveX.dll" /a
icacls "%SystemRoot%\System32\Macromed\Flash\FlashUtil_ActiveX.dll" /inheritance:r /grant:r Administrators:F /c
del "%SystemRoot%\System32\Macromed\Flash\FlashUtil_ActiveX.dll" /f /q
takeown /f "%SystemRoot%\SysWow64\Macromed\Flash\FlashUtil_ActiveX.exe" /a
icacls "%SystemRoot%\SysWow64\Macromed\Flash\FlashUtil_ActiveX.exe" /inheritance:r /grant:r Administrators:F /c
del "%SystemRoot%\SysWow64\Macromed\Flash\FlashUtil_ActiveX.exe" /f /q
takeown /f "%SystemRoot%\SysWow64\Macromed\Flash\FlashUtil_ActiveX.dll" /a
icacls "%SystemRoot%\SysWow64\Macromed\Flash\FlashUtil_ActiveX.dll" /inheritance:r /grant:r Administrators:F /c
del "%SystemRoot%\SysWow64\Macromed\Flash\FlashUtil_ActiveX.dll" /f /q

rem Disable auto-checking for updates
takeown /f "%WINDIR%\System32\UsoClient.exe" /a
icacls "%WINDIR%\System32\UsoClient.exe" /inheritance:r /grant:r Administrators:F /c
icacls "%WINDIR%\System32\UsoClient.exe" /remove "Administrators"

rem To Restore (when there is update/upgrade updating exe, otherwise it will fail)
rem icacls "%WINDIR%\System32\UsoClient.exe" /reset

rem 1 - Disable Malicious Software Removal Tool offered via Windows Updates (MRT) + Disable Heartbeat Telemetry
reg add "HKLM\Software\Microsoft\RemovalTools\MpGears" /v "HeartbeatTrackingIndex" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\RemovalTools\MpGears" /v "SpyNetReportingLocation" /t REG_MULTI_SZ /d "" /f
reg add "HKLM\Software\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d "1" /f


rem =================================== Windows Settings ===================================
rem ----------------------------------- Update & security ----------------------------------
rem .................................... Windows update ....................................
rem . . . . . . . . . . . . . . . . . . Advanced options . . . . . . . . . . . . . . . . . .

rem Choose how updates are delivered / 0 - Turns off Delivery Optimization / 1 - Gets or sends updates and apps to PCs on the same NAT only / 2 - Gets or sends updates and apps to PCs on the same local network domain / 3 - Gets or sends updates and apps to PCs on the Internet / 99 - Simple download mode with no peering / 100 - Use BITS instead of Windows Update Delivery Optimization
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d "0" /f


rem ==================================== Windows Shell =====================================


rem Add Reset permissions to Shell/Manually Reset permissions/Take Ownership
rem http://lallouslab.net/2013/08/26/resetting-ntfs-files-permission-in-windows-graphical-utility

rem Take Ownership
rem Files/Folders - https://www.youtube.com/watch?v=x7gjZMvQHu4
rem Registry - https://www.youtube.com/watch?v=M1l5ifYKefg
rem https://ss64.com/nt/icacls.html
rem https://technet.microsoft.com/en-us/library/cc753024%28v=ws.11%29.aspx
rem https://technet.microsoft.com/en-us/library/cc753525(v=ws.11).aspx

rem Add "Take Ownership" Option in Files and Folders Context Menu in Windows
reg add "HKCR\*\shell\runas" /ve /t REG_SZ /d "Take ownership" /f
reg add "HKCR\*\shell\runas" /v "HasLUAShield" /t REG_SZ /d "" /f
reg add "HKCR\*\shell\runas" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
reg add "HKCR\*\shell\runas\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F" /f
reg add "HKCR\*\shell\runas\command" /v "IsolatedCommand" /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" && icacls \"%%1\" /grant administrators:F" /f
reg add "HKCR\Directory\shell\runas" /ve /t REG_SZ /d "Take ownership" /f
reg add "HKCR\Directory\shell\runas" /v "HasLUAShield" /t REG_SZ /d "" /f
reg add "HKCR\Directory\shell\runas" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
reg add "HKCR\Directory\shell\runas\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" /r /d y && icacls \"%%1\" /grant administrators:F /t" /f
reg add "HKCR\Directory\shell\runas\command" /v "IsolatedCommand" /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\" /r /d y && icacls \"%%1\" /grant administrators:F /t" /f

rem Remove Send To from Context Menu
rem reg delete "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\SendTo" /f

rem Remove Share from Context Menu
reg delete "HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\ModernSharing" /f
reg delete "HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\Sharing" /f
reg delete "HKLM\SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers\Sharing" /f
reg delete "HKLM\SOFTWARE\Classes\Drive\shellex\PropertySheetHandlers\Sharing" /f
reg delete "HKLM\SOFTWARE\Classes\Directory\background\shellex\ContextMenuHandlers\Sharing" /f
reg delete "HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\Sharing" /f
reg delete "HKLM\SOFTWARE\Classes\Directory\shellex\CopyHookHandlers\Sharing" /f
reg delete "HKLM\SOFTWARE\Classes\Directory\shellex\PropertySheetHandlers\Sharing" /f


rem ==================================== Windows Store =====================================
rem -------------------------------------- Settings ----------------------------------------

rem Update apps automatically / 2 - Off / 4 - On
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /v "AutoDownload" /t REG_DWORD /d "2" /f
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Automatic App Update" /Disable

rem ________________________________________________________________________________________
rem Disable Auto-install subscribed/suggested apps (games like Candy Crush Soda Saga/Minecraft)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d "0" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /f



rem ==================================== Windows Waypoint ==================================


fsutil usn deletejournal /d /n c:

rem Close Edge process
taskkill /f /im dllhost.exe

rem Run Wise Disk Cleaner
rem start "" /wait "%ProgramFiles(x86)%\Wise\Wise Disk Cleaner\WiseDiskCleaner.exe" -a

rem Run Wise Registry Cleaner
rem start "" /wait "%ProgramFiles(x86)%\Wise\Wise Registry Cleaner\WiseRegCleaner.exe" -a -all

rem https://www.tenforums.com/general-support/95776-restart-fall-creators-update-reopens-apps-before.html#post1175516
rem https://www.tenforums.com/tutorials/49963-use-sign-info-auto-finish-after-update-restart-windows-10-a.html
rem shutdown /s /f /t 0

rem Is that all? Is that ALL? Yes, that is all. That is all.
rem https://www.youtube.com/watch?v=MTjs5eo4BfI&feature=youtu.be&t=1m47s

REM ; Import registry
REM ; GSecurity
REM ; Display Scaling
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "Win8DpiScaling" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "LogPixels" /t REG_DWORD /d "96" /f
REM ; Defender
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
REM ; Services
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
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SSDPSRV" /v "Start" /t REG_DWORD /d "4" /f
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
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\W32Time" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WdiServiceHost" /v "Start" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WdiSystemHost" /v "Start" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WebClient" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WinRM" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\wisvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\workfolderssvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WpcMonSvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WSearch" /v "Start" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WwanSvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\XblAuthManager" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\XblGameSave" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" /v "Start" /t REG_DWORD /d "4" /f
REM ; Firewall rules deletion
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Defaults\FirewallPolicy\FirewallRules" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Defaults\FirewallPolicy\FirewallRules" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\AppIso\FirewallRules" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\AppIso\FirewallRules" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Configurable\System" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Configurable\System" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\System" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\System" /f
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /f
REM ; Hid
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
Reg.exe delete "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /f
Reg.exe delete "HKCU\Control Panel\Mouse" /v "SmoothMouseYCurve" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Mouse" /v "SnapToDefaultButton" /t REG_SZ /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Mouse" /v "SwapMouseButtons" /t REG_SZ /d "0" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Mouse" /v "Beep" /t REG_SZ /d "No" /f
REM ; System Locale
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Nls\CodePage" /v "ACP" /t REG_SZ /d "1252" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Nls\CodePage" /v "OEMCP" /t REG_SZ /d "437" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Nls\CodePage" /v "MACCP" /t REG_SZ /d "10000" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Nls\Language" /v "Default" /t REG_SZ /d "0409" /f
REM ; Performance Tweaks
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
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Quota System\S-1-2-0" /v "CpuRateLimit" /t REG_DWORD /d "256" /f
REM ; Privacy
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
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f
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
REM ; Worms Doors Cleaner
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Rpc\Internet" /v "UseInternetPorts" /t REG_SZ /d "N" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Ole" /v "EnableDCOM" /t REG_SZ /d "N" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" /v "SmbDeviceEnabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NetBT" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Messenger" /v "Start" /t REG_DWORD /d "4" /f
REM ; Context Menus
Reg.exe delete "HKCR\*\shell\TakeOwnership" /f
Reg.exe delete "HKCR\*\shell\runas" /f
Echo Y | Reg.exe add "HKCR\*\shell\TakeOwnership" /ve /t REG_SZ /d "Take Ownership" /f
Reg.exe delete "HKCR\*\shell\TakeOwnership" /v "Extended" /f
Echo Y | Reg.exe add "HKCR\*\shell\TakeOwnership" /v "HasLUAShield" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCR\*\shell\TakeOwnership" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCR\*\shell\TakeOwnership" /v "NeverDefault" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCR\*\shell\TakeOwnership\command" /ve /t REG_SZ /d "powershell -windowstyle hidden -command \"Start-Process cmd -ArgumentList '/c takeown /f \\\"%%1\\\" && icacls \\\"%%1\\\" /grant *S-1-3-4:F /t /c /l' -Verb runAs\"" /f
Echo Y | Reg.exe add "HKCR\*\shell\TakeOwnership\command" /v "IsolatedCommand" /t REG_SZ /d "powershell -windowstyle hidden -command \"Start-Process cmd -ArgumentList '/c takeown /f \\\"%%1\\\" && icacls \\\"%%1\\\" /grant *S-1-3-4:F /t /c /l' -Verb runAs\"" /f
Echo Y | Reg.exe add "HKCR\Directory\shell\TakeOwnership" /ve /t REG_SZ /d "Take Ownership" /f
Echo Y | Reg.exe add "HKCR\Directory\shell\TakeOwnership" /v "AppliesTo" /t REG_SZ /d "NOT (System.ItemPathDisplay:=\"C:\Users\" OR System.ItemPathDisplay:=\"C:\ProgramData\" OR System.ItemPathDisplay:=\"C:\Windows\" OR System.ItemPathDisplay:=\"C:\Windows\System32\" OR System.ItemPathDisplay:=\"C:\Program Files\" OR System.ItemPathDisplay:=\"C:\Program Files (x86)\")" /f
Reg.exe delete "HKCR\Directory\shell\TakeOwnership" /v "Extended" /f
Echo Y | Reg.exe add "HKCR\Directory\shell\TakeOwnership" /v "HasLUAShield" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCR\Directory\shell\TakeOwnership" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCR\Directory\shell\TakeOwnership" /v "Position" /t REG_SZ /d "middle" /f
Echo Y | Reg.exe add "HKCR\Directory\shell\TakeOwnership\command" /ve /t REG_SZ /d "powershell -windowstyle hidden -command \"Start-Process cmd -ArgumentList '/c takeown /f \\\"%%1\\\" /r /d y && icacls \\\"%%1\\\" /grant *S-1-3-4:F /t /c /l /q' -Verb runAs\"" /f
Echo Y | Reg.exe add "HKCR\Directory\shell\TakeOwnership\command" /v "IsolatedCommand" /t REG_SZ /d "powershell -windowstyle hidden -command \"Start-Process cmd -ArgumentList '/c takeown /f \\\"%%1\\\" /r /d y && icacls \\\"%%1\\\" /grant *S-1-3-4:F /t /c /l /q' -Verb runAs\"" /f
Echo Y | Reg.exe add "HKCR\Drive\shell\runas" /ve /t REG_SZ /d "Take Ownership" /f
Reg.exe delete "HKCR\Drive\shell\runas" /v "Extended" /f
Echo Y | Reg.exe add "HKCR\Drive\shell\runas" /v "HasLUAShield" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCR\Drive\shell\runas" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCR\Drive\shell\runas" /v "Position" /t REG_SZ /d "middle" /f
Echo Y | Reg.exe add "HKCR\Drive\shell\runas" /v "AppliesTo" /t REG_SZ /d "NOT (System.ItemPathDisplay:=\"C:\\\")" /f
Echo Y | Reg.exe add "HKCR\Drive\shell\runas\command" /ve /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\\\" /r /d y && icacls \"%%1\\\" /grant *S-1-3-4:F /t /c" /f
Echo Y | Reg.exe add "HKCR\Drive\shell\runas\command" /v "IsolatedCommand" /t REG_SZ /d "cmd.exe /c takeown /f \"%%1\\\" /r /d y && icacls \"%%1\\\" /grant *S-1-3-4:F /t /c" /f
Echo Y | Reg.exe add "HKCR\DesktopBackground\Shell\ControlPanel" /v "MUIVerb" /t REG_SZ /d "Control Panel" /f
Echo Y | Reg.exe add "HKCR\DesktopBackground\Shell\ControlPanel" /v "SubCommands" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCR\DesktopBackground\Shell\ControlPanel" /v "Icon" /t REG_SZ /d "imageres.dll,-27" /f
Echo Y | Reg.exe add "HKCR\DesktopBackground\Shell\ControlPanel" /v "Position" /t REG_SZ /d "Bottom" /f
Echo Y | Reg.exe add "HKCR\DesktopBackground\Shell\ControlPanel\shell\001flyout" /ve /t REG_SZ /d "Control Panel (Category)" /f
Echo Y | Reg.exe add "HKCR\DesktopBackground\Shell\ControlPanel\shell\001flyout" /v "Icon" /t REG_SZ /d "imageres.dll,-27" /f
Echo Y | Reg.exe add "HKCR\DesktopBackground\Shell\ControlPanel\shell\001flyout\command" /ve /t REG_SZ /d "explorer.exe shell:::{26EE0668-A00A-44D7-9371-BEB064C98683}" /f
Echo Y | Reg.exe add "HKCR\DesktopBackground\Shell\ControlPanel\shell\002flyout" /ve /t REG_SZ /d "All Control Panel Items (Icons)" /f
Echo Y | Reg.exe add "HKCR\DesktopBackground\Shell\ControlPanel\shell\002flyout" /v "Icon" /t REG_SZ /d "imageres.dll,-27" /f
Echo Y | Reg.exe add "HKCR\DesktopBackground\Shell\ControlPanel\shell\002flyout\command" /ve /t REG_SZ /d "explorer.exe shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}" /f
Echo Y | Reg.exe add "HKCR\DesktopBackground\Shell\ControlPanel\shell\003flyout" /ve /t REG_SZ /d "All Tasks (God mode)" /f
Echo Y | Reg.exe add "HKCR\DesktopBackground\Shell\ControlPanel\shell\003flyout" /v "Icon" /t REG_SZ /d "imageres.dll,-27" /f
Echo Y | Reg.exe add "HKCR\DesktopBackground\Shell\ControlPanel\shell\003flyout\command" /ve /t REG_SZ /d "explorer.exe shell:::{ED7BA470-8E54-465E-825C-99712043E01C}" /f
Echo Y | Reg.exe add "HKCR\Msi.Package\shell\Extract All...\command" /ve /t REG_SZ /d "msiexec.exe /a \"%%1\" /qb TARGETDIR=\"%%1 Contents\"" /f
Echo Y | Reg.exe add "HKCR\*\shell\hash" /v "MUIVerb" /t REG_SZ /d "Hash" /f
Echo Y | Reg.exe add "HKCR\*\shell\hash" /v "SubCommands" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCR\*\shell\hash\shell\01menu" /v "MUIVerb" /t REG_SZ /d "SHA1" /f
Echo Y | Reg.exe add "HKCR\*\shell\hash\shell\01menu\command" /ve /t REG_SZ /d "powershell -noexit get-filehash -literalpath '%%1' -algorithm SHA1 | format-list" /f
Echo Y | Reg.exe add "HKCR\*\shell\hash\shell\02menu" /v "MUIVerb" /t REG_SZ /d "SHA256" /f
Echo Y | Reg.exe add "HKCR\*\shell\hash\shell\02menu\command" /ve /t REG_SZ /d "powershell -noexit get-filehash -literalpath '%%1' -algorithm SHA256 | format-list" /f
Echo Y | Reg.exe add "HKCR\*\shell\hash\shell\03menu" /v "MUIVerb" /t REG_SZ /d "SHA384" /f
Echo Y | Reg.exe add "HKCR\*\shell\hash\shell\03menu\command" /ve /t REG_SZ /d "powershell -noexit get-filehash -literalpath '%%1' -algorithm SHA384 | format-list" /f
Echo Y | Reg.exe add "HKCR\*\shell\hash\shell\04menu" /v "MUIVerb" /t REG_SZ /d "SHA512" /f
Echo Y | Reg.exe add "HKCR\*\shell\hash\shell\04menu\command" /ve /t REG_SZ /d "powershell -noexit get-filehash -literalpath '%%1' -algorithm SHA512 | format-list" /f
Echo Y | Reg.exe add "HKCR\*\shell\hash\shell\05menu" /v "MUIVerb" /t REG_SZ /d "MACTripleDES" /f
Echo Y | Reg.exe add "HKCR\*\shell\hash\shell\05menu\command" /ve /t REG_SZ /d "powershell -noexit get-filehash -literalpath '%%1' -algorithm MACTripleDES | format-list" /f
Echo Y | Reg.exe add "HKCR\*\shell\hash\shell\06menu" /v "MUIVerb" /t REG_SZ /d "MD5" /f
Echo Y | Reg.exe add "HKCR\*\shell\hash\shell\06menu\command" /ve /t REG_SZ /d "powershell -noexit get-filehash -literalpath '%%1' -algorithm MD5 | format-list" /f
Echo Y | Reg.exe add "HKCR\*\shell\hash\shell\07menu" /v "MUIVerb" /t REG_SZ /d "RIPEMD160" /f
Echo Y | Reg.exe add "HKCR\*\shell\hash\shell\07menu\command" /ve /t REG_SZ /d "powershell -noexit get-filehash -literalpath '%%1' -algorithm RIPEMD160 | format-list" /f
Echo Y | Reg.exe add "HKCR\*\shell\hash\shell\08menu" /v "CommandFlags" /t REG_DWORD /d "32" /f
Echo Y | Reg.exe add "HKCR\*\shell\hash\shell\08menu" /v "MUIVerb" /t REG_SZ /d "Show all" /f
Echo Y | Reg.exe add "HKCR\*\shell\hash\shell\08menu\command" /ve /t REG_SZ /d "powershell -noexit get-filehash -literalpath '%%1' -algorithm SHA1 | format-list;get-filehash -literalpath '%%1' -algorithm SHA256 | format-list;get-filehash -literalpath '%%1' -algorithm SHA384 | format-list;get-filehash -literalpath '%%1' -algorithm SHA512 | format-list;get-filehash -literalpath '%%1' -algorithm MACTripleDES | format-list;get-filehash -literalpath '%%1' -algorithm MD5 | format-list;get-filehash -literalpath '%%1' -algorithm RIPEMD160 | format-list" /f
Echo Y | Reg.exe add "HKCR\Msi.Package\Shell\runas" /v "HasLUAShield" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCR\Msi.Package\shell\runas\command" /ve /t REG_EXPAND_SZ /d "\"%%SystemRoot%%\System32\msiexec.exe\" /i \"%%1\" %%*" /f
Echo Y | Reg.exe add "HKCR\DesktopBackground\Shell\Restart Explorer" /v "icon" /t REG_SZ /d "explorer.exe" /f
Echo Y | Reg.exe add "HKCR\DesktopBackground\Shell\Restart Explorer" /v "Position" /t REG_SZ /d "Bottom" /f
Echo Y | Reg.exe add "HKCR\DesktopBackground\Shell\Restart Explorer" /v "SubCommands" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCR\DesktopBackground\Shell\Restart Explorer\shell\01menu" /v "MUIVerb" /t REG_SZ /d "Restart Explorer Now" /f
Echo Y | Reg.exe add "HKCR\DesktopBackground\Shell\Restart Explorer\shell\01menu\command" /ve /t REG_EXPAND_SZ /d "cmd.exe /c taskkill /f /im explorer.exe  & start explorer.exe" /f
Echo Y | Reg.exe add "HKCR\DesktopBackground\Shell\Restart Explorer\shell\02menu" /v "MUIVerb" /t REG_SZ /d "Restart Explorer with Pause" /f
Echo Y | Reg.exe add "HKCR\DesktopBackground\Shell\Restart Explorer\shell\02menu" /v "CommandFlags" /t REG_DWORD /d "32" /f
Echo Y | Reg.exe add "HKCR\DesktopBackground\Shell\Restart Explorer\shell\02menu\command" /ve /t REG_EXPAND_SZ /d "cmd.exe /c @echo off & echo. & echo Stopping explorer.exe process . . . & echo. & taskkill /f /im explorer.exe & echo. & echo. & echo Waiting to start explorer.exe process when you are ready . . . & pause && start explorer.exe && exit" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\*\shell\Compact" /v "MUIVerb" /t REG_SZ /d "Compact" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\*\shell\Compact" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\*\shell\Compact" /v "Position" /t REG_SZ /d "middle" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\*\shell\Compact\Command" /ve /t REG_SZ /d "Compact /c /q /i /exe:lzx \"%%1\"" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\CABFolder\Shell\runas" /ve /t REG_SZ /d "Install this update" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\CABFolder\Shell\runas" /v "HasLUAShield" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\CABFolder\Shell\runas" /v "NeverDefault" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\CABFolder\Shell\runas\command" /ve /t REG_SZ /d "cmd /k C:\Windows\SysWOW64\Dism.exe /online /add-package /packagepath:\"%%1\"" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Directory\shell\OpenElevatedCmd" /ve /t REG_SZ /d "Command Prompt (Run as Administrator)" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Directory\shell\OpenElevatedCmd" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Directory\shell\OpenElevatedCmd" /v "NeverDefault" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Directory\shell\OpenElevatedCmd" /v "Icon" /t REG_SZ /d "cmd.exe" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Directory\shell\OpenElevatedCmd\command" /ve /t REG_SZ /d "PowerShell.exe -windowstyle hidden -Command \"Start-Process cmd.exe -ArgumentList '/s,/k,pushd,%%V' -Verb RunAs\"" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Directory\background\shell\OpenElevatedCmd" /ve /t REG_SZ /d "Command Prompt (Run as Administrator)" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Directory\background\shell\OpenElevatedCmd" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Directory\background\shell\OpenElevatedCmd" /v "NeverDefault" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Directory\background\shell\OpenElevatedCmd" /v "Icon" /t REG_SZ /d "cmd.exe" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Directory\background\shell\OpenElevatedCmd\command" /ve /t REG_SZ /d "PowerShell.exe -windowstyle hidden -Command \"Start-Process cmd.exe -ArgumentList '/s,/k,pushd,%%V' -Verb RunAs\"" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Drive\shell\OpenElevatedCmd" /ve /t REG_SZ /d "Command Prompt (Run as Administrator)" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Drive\shell\OpenElevatedCmd" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Drive\shell\OpenElevatedCmd" /v "NeverDefault" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Drive\shell\OpenElevatedCmd" /v "Icon" /t REG_SZ /d "cmd.exe" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Drive\shell\OpenElevatedCmd\command" /ve /t REG_SZ /d "PowerShell.exe -windowstyle hidden -Command \"Start-Process cmd.exe -ArgumentList '/s,/k,pushd,%%V' -Verb RunAs\"" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\LibraryFolder\Shell\OpenElevatedCmd" /ve /t REG_SZ /d "Command Prompt (Run as Administrator)" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\LibraryFolder\Shell\OpenElevatedCmd" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\LibraryFolder\Shell\OpenElevatedCmd" /v "NeverDefault" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\LibraryFolder\Shell\OpenElevatedCmd" /v "Icon" /t REG_SZ /d "cmd.exe" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\LibraryFolder\Shell\OpenElevatedCmd\command" /ve /t REG_SZ /d "PowerShell.exe -windowstyle hidden -Command \"Start-Process cmd.exe -ArgumentList '/s,/k,pushd,%%V' -Verb RunAs\"" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "MultipleInvokePromptMinimum" /t REG_DWORD /d "200" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Directory\shell\OpenElevatedPS" /ve /t REG_SZ /d "Windows PowerShell (Run as Administrator)" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Directory\shell\OpenElevatedPS" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Directory\shell\OpenElevatedPS" /v "NeverDefault" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Directory\shell\OpenElevatedPS" /v "Icon" /t REG_SZ /d "PowerShell.exe" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Directory\shell\OpenElevatedPS\command" /ve /t REG_SZ /d "PowerShell.exe -windowstyle hidden -Command \"Start-Process cmd.exe -ArgumentList '/s,/c,pushd,%%V && powershell' -Verb RunAs\"" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Directory\background\shell\OpenElevatedPS" /ve /t REG_SZ /d "Windows PowerShell (Run as Administrator)" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Directory\background\shell\OpenElevatedPS" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Directory\background\shell\OpenElevatedPS" /v "NeverDefault" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Directory\background\shell\OpenElevatedPS" /v "Icon" /t REG_SZ /d "PowerShell.exe" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Directory\background\shell\OpenElevatedPS\command" /ve /t REG_SZ /d "PowerShell.exe -windowstyle hidden -Command \"Start-Process cmd.exe -ArgumentList '/s,/c,pushd,%%V && powershell' -Verb RunAs\"" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Drive\shell\OpenElevatedPS" /ve /t REG_SZ /d "Windows PowerShell (Run as Administrator)" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Drive\shell\OpenElevatedPS" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Drive\shell\OpenElevatedPS" /v "NeverDefault" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Drive\shell\OpenElevatedPS" /v "Icon" /t REG_SZ /d "PowerShell.exe" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Drive\shell\OpenElevatedPS\command" /ve /t REG_SZ /d "PowerShell.exe -windowstyle hidden -Command \"Start-Process cmd.exe -ArgumentList '/s,/c,pushd,%%V && powershell' -Verb RunAs\"" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\LibraryFolder\Shell\OpenElevatedPS" /ve /t REG_SZ /d "Windows PowerShell (Run as Administrator)" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\LibraryFolder\Shell\OpenElevatedPS" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\LibraryFolder\Shell\OpenElevatedPS" /v "NeverDefault" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\LibraryFolder\Shell\OpenElevatedPS" /v "Icon" /t REG_SZ /d "PowerShell.exe" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\LibraryFolder\Shell\OpenElevatedPS\command" /ve /t REG_SZ /d "PowerShell.exe -windowstyle hidden -Command \"Start-Process cmd.exe -ArgumentList '/s,/c,pushd,%%V && powershell' -Verb RunAs\"" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\DesktopBackground\Shell\DismContextMenu" /v "MUIVerb" /t REG_SZ /d "Repair Windows Image" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\DesktopBackground\Shell\DismContextMenu" /v "Icon" /t REG_SZ /d "WmiPrvSE.exe" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\DesktopBackground\Shell\DismContextMenu" /v "Position" /t REG_SZ /d "Bottom" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\DesktopBackground\Shell\DismContextMenu" /v "SubCommands" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\DesktopBackground\Shell\DismContextMenu\shell\CheckHealth" /v "HasLUAShield" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\DesktopBackground\Shell\DismContextMenu\shell\CheckHealth" /v "MUIVerb" /t REG_SZ /d "Check Health of Windows Image" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\DesktopBackground\Shell\DismContextMenu\shell\CheckHealth\Command" /ve /t REG_SZ /d "PowerShell -windowstyle hidden -command \"Start-Process cmd -ArgumentList '/s,/k, Dism /Online /Cleanup-Image /CheckHealth' -Verb runAs\"" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\DesktopBackground\Shell\DismContextMenu\shell\RestoreHealth" /v "HasLUAShield" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\DesktopBackground\Shell\DismContextMenu\shell\RestoreHealth" /v "MUIVerb" /t REG_SZ /d "Repair Windows Image" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\DesktopBackground\Shell\DismContextMenu\shell\RestoreHealth\Command" /ve /t REG_SZ /d "PowerShell -windowstyle hidden -command \"Start-Process cmd -ArgumentList '/s,/k, Dism /Online /Cleanup-Image /RestoreHealth' -Verb runAs\"" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\*\shell\ResetNTFSPermissions" /v "MUIVerb" /t REG_SZ /d "Reset Permissions" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\*\shell\ResetNTFSPermissions" /v "NoWorkingDirectory" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\*\shell\ResetNTFSPermissions" /v "Position" /t REG_SZ /d "middle" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\*\shell\ResetNTFSPermissions\Command" /ve /t REG_SZ /d "powershell.exe -windowstyle hidden -command \"Start-Process cmd.exe -ArgumentList '/c icacls \\\"%%1\\\" /reset & pause' -Verb RunAs\"" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Directory\shell\ResetNTFSPermissions" /v "MUIVerb" /t REG_SZ /d "Reset Permissions" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Directory\shell\ResetNTFSPermissions" /v "SubCommands" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Directory\shell\ResetNTFSPermissions" /v "Position" /t REG_SZ /d "middle" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Directory\shell\ResetNTFSPermissions\Shell\01ResetPermissionsRootFolder" /v "MUIVerb" /t REG_SZ /d "Reset permissions of this folder only" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Directory\shell\ResetNTFSPermissions\Shell\01ResetPermissionsRootFolder\command" /ve /t REG_SZ /d "powershell.exe -windowstyle hidden -command \"Start-Process cmd.exe -ArgumentList '/c icacls \\\"%%1\\\" /reset & pause' -Verb RunAs\"" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Directory\shell\ResetNTFSPermissions\Shell\02ResetPermissionsAllFolders" /v "MUIVerb" /t REG_SZ /d "Reset permissions of this folder, subfolders and files" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Directory\shell\ResetNTFSPermissions\Shell\02ResetPermissionsAllFolders\command" /ve /t REG_SZ /d "powershell.exe -windowstyle hidden -command \"Start-Process cmd.exe -ArgumentList '/c icacls \\\"%%1\\\" /reset /t /c /l & pause' -Verb RunAs\"" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\VBSFile\Shell\runas" /v "HasLUAShield" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\VBSFile\Shell\runas\command" /ve /t REG_EXPAND_SZ /d "\"%%SystemRoot%%\System32\WScript.exe\" \"%%1\" %%*" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Msi.Package\shell\runas" /v "HasLUAShield" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Msi.Package\shell\runas\command" /ve /t REG_EXPAND_SZ /d "\"%%SystemRoot%%\System32\msiexec.exe\" /i \"%%1\" %%*" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Microsoft.PowerShellScript.1\Shell\runas" /v "HasLUAShield" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Microsoft.PowerShellScript.1\Shell\runas\command" /ve /t REG_EXPAND_SZ /d "powershell.exe \"-Command\" \"if((Get-ExecutionPolicy ) -ne 'AllSigned') { Set-ExecutionPolicy -Scope Process Bypass }; & '%%1'\"" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\DesktopBackground\Shell\SFCScannow" /v "MUIVerb" /t REG_SZ /d "SFC /Scannow" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\DesktopBackground\Shell\SFCScannow" /v "Icon" /t REG_SZ /d "cmd.exe" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\DesktopBackground\Shell\SFCScannow" /v "Position" /t REG_SZ /d "Bottom" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\DesktopBackground\Shell\SFCScannow" /v "SubCommands" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\DesktopBackground\Shell\SFCScannow\shell\01Scannow" /v "HasLUAShield" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\DesktopBackground\Shell\SFCScannow\shell\01Scannow" /v "MUIVerb" /t REG_SZ /d "Run SFC /Scannow" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\DesktopBackground\Shell\SFCScannow\shell\01Scannow\Command" /ve /t REG_SZ /d "PowerShell -windowstyle hidden -command \"Start-Process cmd -ArgumentList '/s,/k, sfc.exe /scannow' -Verb runAs\"" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\DesktopBackground\Shell\SFCScannow\shell\02ViewLog" /v "Icon" /t REG_SZ /d "notepad.exe" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\DesktopBackground\Shell\SFCScannow\shell\02ViewLog" /v "MUIVerb" /t REG_SZ /d "View log for SFC" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\DesktopBackground\Shell\SFCScannow\shell\02ViewLog\Command" /ve /t REG_SZ /d "PowerShell (Select-String [SR] $env:windir\Logs\CBS\CBS.log -s).Line >\"$env:userprofile\Desktop\SFC_LOG.txt\"; Start-Process -FilePath \"notepad.exe\" -ArgumentList \"$env:userprofile\Desktop\SFC_LOG.txt\"" /f
Echo Y | Reg.exe add "HKCR\Directory\Background\shell\HiddenFiles" /v "Icon" /t REG_SZ /d "imageres.dll,-5314" /f
Echo Y | Reg.exe add "HKCR\Directory\Background\shell\HiddenFiles" /v "MUIVerb" /t REG_SZ /d "Hidden items" /f
Echo Y | Reg.exe add "HKCR\Directory\Background\shell\HiddenFiles" /v "Position" /t REG_SZ /d "Bottom" /f
Reg.exe delete "HKCR\Directory\Background\shell\HiddenFiles" /v "Extended" /f
Echo Y | Reg.exe add "HKCR\Directory\Background\shell\HiddenFiles" /v "SubCommands" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCR\Directory\Background\shell\HiddenFiles\shell\Windows.ShowHiddenFiles" /v "CommandStateSync" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCR\Directory\Background\shell\HiddenFiles\shell\Windows.ShowHiddenFiles" /v "Description" /t REG_SZ /d "@shell32.dll,-37573" /f
Echo Y | Reg.exe add "HKCR\Directory\Background\shell\HiddenFiles\shell\Windows.ShowHiddenFiles" /v "ExplorerCommandHandler" /t REG_SZ /d "{f7300245-1f4b-41ba-8948-6fd392064494}" /f
Echo Y | Reg.exe add "HKCR\Directory\Background\shell\HiddenFiles\shell\Windows.ShowHiddenFiles" /v "Icon" /t REG_SZ /d "imageres.dll,-5314" /f
Echo Y | Reg.exe add "HKCR\Directory\Background\shell\HiddenFiles\shell\Windows.ShowHiddenFiles" /v "MUIVerb" /t REG_SZ /d "Hide/Show Hidden items" /f
Echo Y | Reg.exe add "HKCR\Directory\Background\shell\HiddenFiles\shell\x1menu" /v "MUIVerb" /t REG_SZ /d "Hide protected OS files" /f
Echo Y | Reg.exe add "HKCR\Directory\Background\shell\HiddenFiles\shell\x1menu" /v "Icon" /t REG_SZ /d "imageres.dll,-5314" /f
Echo Y | Reg.exe add "HKCR\Directory\Background\shell\HiddenFiles\shell\x1menu" /v "CommandFlags" /t REG_DWORD /d "32" /f
Echo Y | Reg.exe add "HKCR\Directory\Background\shell\HiddenFiles\shell\x1menu\command" /ve /t REG_SZ /d "cmd /c, REG ADD \"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\" /V ShowSuperHidden /T REG_DWORD /D 0 /F & taskkill /f /im explorer.exe & start explorer.exe" /f
Echo Y | Reg.exe add "HKCR\Directory\Background\shell\HiddenFiles\shell\x2menu" /v "MUIVerb" /t REG_SZ /d "Show protected OS files" /f
Echo Y | Reg.exe add "HKCR\Directory\Background\shell\HiddenFiles\shell\x2menu" /v "Icon" /t REG_SZ /d "imageres.dll,-5314" /f
Echo Y | Reg.exe add "HKCR\Directory\Background\shell\HiddenFiles\shell\x2menu\command" /ve /t REG_SZ /d "cmd /c, REG ADD \"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\" /V Hidden /T REG_DWORD /D 1 /F & REG ADD \"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\" /V ShowSuperHidden /T REG_DWORD /D 1 /F & taskkill /f /im explorer.exe & start explorer.exe" /f
Echo Y | Reg.exe add "HKCR\Folder\shell\HiddenFiles" /v "Icon" /t REG_SZ /d "imageres.dll,-5314" /f
Echo Y | Reg.exe add "HKCR\Folder\shell\HiddenFiles" /v "MUIVerb" /t REG_SZ /d "Hidden items" /f
Echo Y | Reg.exe add "HKCR\Folder\shell\HiddenFiles" /v "Position" /t REG_SZ /d "Bottom" /f
Reg.exe delete "HKCR\Folder\shell\HiddenFiles" /v "Extended" /f
Echo Y | Reg.exe add "HKCR\Folder\shell\HiddenFiles" /v "SubCommands" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCR\Folder\shell\HiddenFiles\shell\Windows.ShowHiddenFiles" /v "CommandStateSync" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCR\Folder\shell\HiddenFiles\shell\Windows.ShowHiddenFiles" /v "Description" /t REG_SZ /d "@shell32.dll,-37573" /f
Echo Y | Reg.exe add "HKCR\Folder\shell\HiddenFiles\shell\Windows.ShowHiddenFiles" /v "ExplorerCommandHandler" /t REG_SZ /d "{f7300245-1f4b-41ba-8948-6fd392064494}" /f
Echo Y | Reg.exe add "HKCR\Folder\shell\HiddenFiles\shell\Windows.ShowHiddenFiles" /v "Icon" /t REG_SZ /d "imageres.dll,-5314" /f
Echo Y | Reg.exe add "HKCR\Folder\shell\HiddenFiles\shell\Windows.ShowHiddenFiles" /v "MUIVerb" /t REG_SZ /d "Hide/Show Hidden items" /f
Echo Y | Reg.exe add "HKCR\Folder\shell\HiddenFiles\shell\x1menu" /v "MUIVerb" /t REG_SZ /d "Hide protected OS files" /f
Echo Y | Reg.exe add "HKCR\Folder\shell\HiddenFiles\shell\x1menu" /v "Icon" /t REG_SZ /d "imageres.dll,-5314" /f
Echo Y | Reg.exe add "HKCR\Folder\shell\HiddenFiles\shell\x1menu" /v "CommandFlags" /t REG_DWORD /d "32" /f
Echo Y | Reg.exe add "HKCR\Folder\shell\HiddenFiles\shell\x1menu\command" /ve /t REG_SZ /d "cmd /c, REG ADD \"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\" /V ShowSuperHidden /T REG_DWORD /D 0 /F & taskkill /f /im explorer.exe & start explorer.exe" /f
Echo Y | Reg.exe add "HKCR\Folder\shell\HiddenFiles\shell\x2menu" /v "MUIVerb" /t REG_SZ /d "Show protected OS files" /f
Echo Y | Reg.exe add "HKCR\Folder\shell\HiddenFiles\shell\x2menu" /v "Icon" /t REG_SZ /d "imageres.dll,-5314" /f
Echo Y | Reg.exe add "HKCR\Folder\shell\HiddenFiles\shell\x2menu\command" /ve /t REG_SZ /d "cmd /c, REG ADD \"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\" /V Hidden /T REG_DWORD /D 1 /F & REG ADD \"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\" /V ShowSuperHidden /T REG_DWORD /D 1 /F & taskkill /f /im explorer.exe & start explorer.exe" /f
Echo Y | Reg.exe add "HKCR\AllFilesystemObjects\shell\Windows.ShowFileExtensions" /v "CommandStateSync" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCR\AllFilesystemObjects\shell\Windows.ShowFileExtensions" /v "Description" /t REG_SZ /d "@shell32.dll,-37571" /f
Echo Y | Reg.exe add "HKCR\AllFilesystemObjects\shell\Windows.ShowFileExtensions" /v "ExplorerCommandHandler" /t REG_SZ /d "{4ac6c205-2853-4bf5-b47c-919a42a48a16}" /f
Echo Y | Reg.exe add "HKCR\AllFilesystemObjects\shell\Windows.ShowFileExtensions" /v "MUIVerb" /t REG_SZ /d "@shell32.dll,-37570" /f
Echo Y | Reg.exe add "HKCR\Directory\Background\shell\Windows.ShowFileExtensions" /v "CommandStateSync" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCR\Directory\Background\shell\Windows.ShowFileExtensions" /v "Description" /t REG_SZ /d "@shell32.dll,-37571" /f
Echo Y | Reg.exe add "HKCR\Directory\Background\shell\Windows.ShowFileExtensions" /v "ExplorerCommandHandler" /t REG_SZ /d "{4ac6c205-2853-4bf5-b47c-919a42a48a16}" /f
Echo Y | Reg.exe add "HKCR\Directory\Background\shell\Windows.ShowFileExtensions" /v "MUIVerb" /t REG_SZ /d "@shell32.dll,-37570" /f
Echo Y | Reg.exe add "HKCR\DesktopBackground\Shell\SafeMode" /v "icon" /t REG_SZ /d "bootux.dll,-1032" /f
Echo Y | Reg.exe add "HKCR\DesktopBackground\Shell\SafeMode" /v "MUIVerb" /t REG_SZ /d "Safe Mode" /f
Reg.exe delete "HKCR\DesktopBackground\Shell\SafeMode" /v "Position" /f
Echo Y | Reg.exe add "HKCR\DesktopBackground\Shell\SafeMode" /v "SubCommands" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCR\DesktopBackground\Shell\SafeMode\shell\001-NormalMode" /ve /t REG_SZ /d "Restart in Normal Mode" /f
Echo Y | Reg.exe add "HKCR\DesktopBackground\Shell\SafeMode\shell\001-NormalMode" /v "HasLUAShield" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCR\DesktopBackground\Shell\SafeMode\shell\001-NormalMode\command" /ve /t REG_SZ /d "powershell -windowstyle hidden -command \"Start-Process cmd -ArgumentList '/s,/c,bcdedit /deletevalue {current} safeboot & bcdedit /deletevalue {current} safebootalternateshell & shutdown -r -t 00 -f' -Verb runAs\"" /f
Echo Y | Reg.exe add "HKCR\DesktopBackground\Shell\SafeMode\shell\002-SafeMode" /ve /t REG_SZ /d "Restart in Safe Mode" /f
Echo Y | Reg.exe add "HKCR\DesktopBackground\Shell\SafeMode\shell\002-SafeMode" /v "HasLUAShield" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCR\DesktopBackground\Shell\SafeMode\shell\002-SafeMode\command" /ve /t REG_SZ /d "powershell -windowstyle hidden -command \"Start-Process cmd -ArgumentList '/s,/c,bcdedit /set {current} safeboot minimal & bcdedit /deletevalue {current} safebootalternateshell & shutdown -r -t 00 -f' -Verb runAs\"" /f
Echo Y | Reg.exe add "HKCR\DesktopBackground\Shell\SafeMode\shell\003-SafeModeNetworking" /ve /t REG_SZ /d "Restart in Safe Mode with Networking" /f
Echo Y | Reg.exe add "HKCR\DesktopBackground\Shell\SafeMode\shell\003-SafeModeNetworking" /v "HasLUAShield" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCR\DesktopBackground\Shell\SafeMode\shell\003-SafeModeNetworking\command" /ve /t REG_SZ /d "powershell -windowstyle hidden -command \"Start-Process cmd -ArgumentList '/s,/c,bcdedit /set {current} safeboot network & bcdedit /deletevalue {current} safebootalternateshell & shutdown -r -t 00 -f' -Verb runAs\"" /f
Echo Y | Reg.exe add "HKCR\DesktopBackground\Shell\SafeMode\shell\004-SafeModeCommandPrompt" /ve /t REG_SZ /d "Restart in Safe Mode with Command Prompt" /f
Echo Y | Reg.exe add "HKCR\DesktopBackground\Shell\SafeMode\shell\004-SafeModeCommandPrompt" /v "HasLUAShield" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCR\DesktopBackground\Shell\SafeMode\shell\004-SafeModeCommandPrompt\command" /ve /t REG_SZ /d "powershell -windowstyle hidden -command \"Start-Process cmd -ArgumentList '/s,/c,bcdedit /set {current} safeboot minimal & bcdedit /set {current} safebootalternateshell yes & shutdown -r -t 00 -f' -Verb runAs\"" /f
REM ; Machine policy
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\DefaultLaunchURLPerms" /v "UnknownURLPerms" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\DefaultLaunchURLPerms" /v "URLPerms" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\Services" /v "TogglePrefsSync" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\Services" /v "ToggleWebConnectors" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\SharePoint" /v "DisableSharePointFeatures" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\WebmailProfiles" /v "DisableWebmail" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\WelcomeScreen" /v "ShowWelcomeScreen" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown" /v "DisablePDFHandlerSwitching" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown" /v "DisableTrustedFolders" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown" /v "DisableTrustedSites" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown" /v "EnableFlash" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown" /v "EnhancedSecurityInBrowser" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown" /v "EnhancedSecurityStandalone" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown" /v "ProtectedMode" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown" /v "FileAttachmentPerms" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown" /v "ProtectedView" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\Cloud" /v "AdobeSendPluginToggle" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\Cloud" /v "DisableADCFileStore" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\Services" /v "TogglePrefsSync" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\Services" /v "ToggleWebConnectors" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\SharePoint" /v "DisableSharePointFeatures" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\WebmailProfiles" /v "DisableWebmail" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\WelcomeScreen" /v "ShowWelcomeScreen" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" /v "NoActiveHelp" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics" /v "Enabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" /v "EnhancedAntiSpoofing" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Conferencing" /v "NoRDS" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Control Panel\International" /v "BlockUserInputMethodsForSignIn" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment" /v "AEPolicy" /t REG_DWORD /d "7" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment" /v "OfflineExpirationPercent" /t REG_DWORD /d "10" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment" /v "OfflineExpirationStoreNames" /t REG_SZ /d "MY" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" /v "EccCurves" /t REG_MULTI_SZ /d "NistP384\0NistP256" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\7-Zip\7z.exe" /t REG_SZ /d "-EAF" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\7-Zip\7zFM.exe" /t REG_SZ /d "-EAF" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\7-Zip\7zG.exe" /t REG_SZ /d "-EAF" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\Adobe\*\Reader\AcroRd32.exe" /t REG_SZ /d "+EAF+ eaf_modules:AcroRd32.dll;Acrofx32.dll;AcroForm.api" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\Adobe\Acrobat*\Acrobat\Acrobat.exe" /t REG_SZ /d "+EAF+ eaf_modules:AcroRd32.dll;Acrofx32.dll;AcroForm.api" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\Adobe\Adobe Photoshop CS*\Photoshop.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\Foxit Reader\Foxit Reader.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\Google\Chrome\Application\chrome.exe" /t REG_SZ /d "+EAF+ eaf_modules:chrome_child.dll" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\Google\Google Talk\googletalk.exe" /t REG_SZ /d "-DEP" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\Internet Explorer\iexplore.exe" /t REG_SZ /d "+EAF+ eaf_modules:mshtml.dll;flash*.ocx;jscript*.dll;vbscript.dll;vgx.dll +ASR asr_modules:npjpi*.dll;jp2iexp.dll;vgx.dll;msxml4*.dll;wshom.ocx;scrrun.dll;vbscript.dll asr_zones:1;2" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\iTunes\iTunes.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\Java\jre*\bin\java.exe" /t REG_SZ /d "-HeapSpray" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\Java\jre*\bin\javaw.exe" /t REG_SZ /d "-HeapSpray" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\Java\jre*\bin\javaws.exe" /t REG_SZ /d "-HeapSpray" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\Microsoft Lync\communicator.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\mIRC\mirc.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\Mozilla Firefox\firefox.exe" /t REG_SZ /d "+EAF+ eaf_modules:mozjs.dll;xul.dll" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\Mozilla Firefox\plugin-container.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\Mozilla Thunderbird\plugin-container.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\Mozilla Thunderbird\thunderbird.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\OFFICE1*\EXCEL.EXE" /t REG_SZ /d "+ASR asr_modules:flash*.ocx" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\OFFICE1*\INFOPATH.EXE" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\OFFICE1*\LYNC.EXE" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\OFFICE1*\MSACCESS.EXE" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\OFFICE1*\MSPUB.EXE" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\OFFICE1*\OIS.EXE" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\OFFICE1*\OUTLOOK.EXE" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\OFFICE1*\POWERPNT.EXE" /t REG_SZ /d "+ASR asr_modules:flash*.ocx" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\OFFICE1*\PPTVIEW.EXE" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\OFFICE1*\VISIO.EXE" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\OFFICE1*\VPREVIEW.EXE" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\OFFICE1*\WINWORD.EXE" /t REG_SZ /d "+ASR asr_modules:flash*.ocx" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\Opera\*\opera.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\Opera\opera.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\Pidgin\pidgin.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\QuickTime\QuickTimePlayer.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\Real\RealPlayer\realconverter.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\Real\RealPlayer\realplay.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\Safari\Safari.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\SkyDrive\SkyDrive.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\Skype\Phone\Skype.exe" /t REG_SZ /d "-EAF" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\VideoLAN\VLC\vlc.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\Winamp\winamp.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\Windows Live\Mail\wlmail.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\Windows Live\Photo Gallery\WLXPhotoGallery.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\Windows Live\Writer\WindowsLiveWriter.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\Windows Media Player\wmplayer.exe" /t REG_SZ /d "-EAF -MandatoryASLR" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\Windows NT\Accessories\wordpad.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\WinRAR\rar.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\WinRAR\unrar.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\WinRAR\winrar.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\WinZip\winzip32.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\Defaults" /v "*\WinZip\winzip64.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\SysSettings" /v "ASLR" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\SysSettings" /v "DEP" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EMET\SysSettings" /v "SEHOP" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EventViewer" /v "MicrosoftEventVwrDisableLinks" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v "DisableExternalDMAUnderLock" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v "EnableBDEWithNoTPM" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v "MinimumPIN" /t REG_DWORD /d "6" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v "UseAdvancedStartup" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v "UseEnhancedPin" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v "UseTPM" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v "UseTPMKey" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v "UseTPMKeyPIN" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v "UseTPMPIN" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "AllowInputPersonalization" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Control Panel" /v "History" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Download" /v "CheckExeSignatures" /t REG_SZ /d "yes" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Download" /v "RunInvalidSignatures" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" /v "AllowBasicAuthInClear" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" /v "DisableEnclosureDownload" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\IEDevTools" /v "Disabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" /v "DisableEPMCompat" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" /v "Isolation" /t REG_SZ /d "PMEM" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" /v "Isolation64Bit" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL" /v "(Reserved)" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL" /v "explorer.exe" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL" /v "iexplore.exe" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING" /v "(Reserved)" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING" /v "explorer.exe" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING" /v "iexplore.exe" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING" /v "(Reserved)" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING" /v "explorer.exe" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING" /v "iexplore.exe" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" /v "(Reserved)" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" /v "explorer.exe" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL" /v "iexplore.exe" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" /v "(Reserved)" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" /v "explorer.exe" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD" /v "iexplore.exe" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE" /v "excel.exe" /t REG_DWORD /d "69632" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE" /v "msaccess.exe" /t REG_DWORD /d "69632" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE" /v "mspub.exe" /t REG_DWORD /d "69632" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE" /v "onenote.exe" /t REG_DWORD /d "69632" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE" /v "outlook.exe" /t REG_DWORD /d "69632" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE" /v "powerpnt.exe" /t REG_DWORD /d "69632" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE" /v "visio.exe" /t REG_DWORD /d "69632" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE" /v "winproj.exe" /t REG_DWORD /d "69632" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE" /v "winword.exe" /t REG_DWORD /d "69632" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\feature_safe_bindtoobject" /v "excel.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\feature_safe_bindtoobject" /v "exprwd.exe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\feature_safe_bindtoobject" /v "groove.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\feature_safe_bindtoobject" /v "msaccess.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\feature_safe_bindtoobject" /v "mse7.exe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\feature_safe_bindtoobject" /v "mspub.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\feature_safe_bindtoobject" /v "onenote.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\feature_safe_bindtoobject" /v "outlook.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\feature_safe_bindtoobject" /v "powerpnt.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\feature_safe_bindtoobject" /v "pptview.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\feature_safe_bindtoobject" /v "spdesign.exe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\feature_safe_bindtoobject" /v "visio.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\feature_safe_bindtoobject" /v "winproj.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\feature_safe_bindtoobject" /v "winword.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND" /v "(Reserved)" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND" /v "explorer.exe" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND" /v "iexplore.exe" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" /v "(Reserved)" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" /v "explorer.exe" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS" /v "iexplore.exe" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" /v "(Reserved)" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" /v "explorer.exe" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION" /v "iexplore.exe" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter" /v "PreventOverride" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter" /v "PreventOverrideAppRepUnknown" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Privacy" /v "CleanHistory" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Privacy" /v "ClearBrowsingHistoryOnExit" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Privacy" /v "EnableInPrivateBrowsing" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Restrictions" /v "NoCrashDetection" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Safety\PrivacIE" /v "DisableLogging" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Safety\PrivacIE" /v "DisableTrackingProtection" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Security" /v "DisableSecuritySettingsCheck" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Security\ActiveX" /v "BlockNonAdminActiveXInstall" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Internet Settings" /v "PreventCertErrorOverrides" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /v "FormSuggest Passwords" /t REG_SZ /d "no" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "PreventOverride" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "PreventOverrideAppRepUnknown" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\office\15.0\common\officeupdate" /v "enableautomaticupdates" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\office\15.0\common\officeupdate" /v "hideenabledisableupdates" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\office\15.0\infopath\security" /v "aptca_allowlist" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\office\15.0\lync" /v "disablehttpconnect" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\office\15.0\lync" /v "enablesiphighsecuritymode" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\office\15.0\lync" /v "savepassword" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\lync" /v "disablehttpconnect" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\lync" /v "enablesiphighsecuritymode" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\office\16.0\lync" /v "savepassword" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\OneDrive\AllowTenantList" /v "1111-2222-3333-4444" /t REG_SZ /d "1111-2222-3333-4444" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\PassportForWork" /v "RequireSecurityDevice" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\PassportForWork\ExcludeSecurityDevices" /v "TPM12" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity" /v "MinimumPINLength" /t REG_DWORD /d "6" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Peernet" /v "Disabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v "ACSettingIndex" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v "DCSettingIndex" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Speech" /v "AllowSpeechModelUpdate" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\CA\Certificates" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\CA\CRLs" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\CA\CTLs" /ve /t REG_SZ /d "" /f
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Disallowed" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\TabletTip\1.7" /v "PasswordSecurity" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\TabletTip\1.7" /v "PasswordSecurityState" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\TPM" /v "OSManagedAuthLevel" /t REG_DWORD /d "5" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "VDMDisallowed" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisablePcaUI" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsActivateWithVoiceAboveLock" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx" /v "AllowAllTrustedApps" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AxInstaller" /v "OnlyUseAXISForActiveXInstall" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\BITS" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Connect" /v "AllowProjectionToPC" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" /v "AllowProtectedCreds" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" /v "RestrictedRemoteAdministration" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI" /v "DisablePasswordReveal" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "CallLegacyWCMPolicies" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "EnableLegacyAutoProxyFeature" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "CertificateRevocation" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "EnableSSL3Fallback" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "PreventIgnoreCertErrors" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "SecureProtocols" /t REG_DWORD /d "2560" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "Security_HKLM_only" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "Security_options_edit" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "Security_zones_map_edit" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "WarnOnBadCertRecving" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Cache" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0" /v "1C00" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1" /v "1C00" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2" /v "1C00" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\3" /v "2301" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4" /v "1C00" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4" /v "2301" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Url History" /v "DaysToKeep" /t REG_DWORD /d "40" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap" /v "UNCAsIntranet" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" /v "1C00" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" /v "270C" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" /v "1201" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" /v "1C00" /t REG_DWORD /d "65536" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" /v "270C" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" /v "1201" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" /v "1C00" /t REG_DWORD /d "65536" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" /v "270C" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1001" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1004" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1201" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1206" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1209" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "120b" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "120c" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1406" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1407" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1409" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "140C" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1606" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1607" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "160A" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1802" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1804" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1806" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1809" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1A00" /t REG_DWORD /d "65536" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1C00" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2001" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2004" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2101" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2102" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2103" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2200" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2301" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2402" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2500" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2708" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2709" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "270C" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1001" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1004" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1200" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1201" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1206" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1209" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "120b" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "120c" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1400" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1402" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1405" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1406" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1407" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1409" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "140C" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1606" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1607" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1608" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "160A" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1802" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1803" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1804" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1806" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1809" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1A00" /t REG_DWORD /d "196608" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1C00" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "2000" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "2001" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "2004" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "2101" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "2102" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "2103" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "2200" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "2301" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "2402" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "2500" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "2708" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "2709" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "270C" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "LimitEnhancedDiagnosticDataWindowsAnalytics" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "ConfigureSystemGuardLaunch" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "HVCIMATRequired" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "HypervisorEnforcedCodeIntegrity" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "LsaCfgFlags" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "RequirePlatformSecurityFeatures" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" /v "DenyDeviceClasses" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" /v "DenyDeviceClassesRetroactive" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\denydeviceclasses" /v "1" /t REG_SZ /d "{d48179be-ec20-11d1-b6b8-00c04fa372a7}" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" /v "AllowRemoteRPC" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" /v "AllSigningEqual" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" /v "DisableSendGenericDriverNotFoundToWER" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" /v "DisableSendRequestAdditionalSoftwareToWER" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" /v "DisableSystemRestore" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceRedirect\Restrictions" /v "AllowRedirect" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" /v "DriverUpdateWizardWuSearchEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" /v "DontPromptForWindowsUpdate" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" /v "DontSearchWindowsUpdate" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" /v "DriverServerSelection" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EnhancedStorageDevices" /v "TCGSecurityActivationDisabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" /v "MaxSize" /t REG_DWORD /d "32768" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging" /v "EnableProtectedEventLogging" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging" /v "EncryptionCertificate" /t REG_MULTI_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" /v "MaxSize" /t REG_DWORD /d "196608" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" /v "Enabled" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" /v "MaxSize" /t REG_DWORD /d "32768" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" /v "MaxSize" /t REG_DWORD /d "32768" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoAutoplayfornonVolume" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoDataExecutionPrevention" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoHeapTerminationOnCorruption" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoUseStoreOpenWith" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameUX" /v "DownloadGameInfo" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameUX" /v "GameUpdateOptions" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" /v "NoBackgroundPolicy" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" /v "NoGPOListChanges" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HomeGroup" /v "DisableHomeGroup" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v "AlwaysInstallElevated" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v "DisableLUAPatching" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v "EnableUserControl" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v "SafeForScripting" /t REG_DWORD /d "0" /f
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\IPSec" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection" /v "DeviceEnumerationPolicy" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" /v "AllowInsecureGuestAuth" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD" /v "AllowLLTDIOOnDomain" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD" /v "AllowLLTDIOOnPublicNet" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD" /v "AllowRspndrOnDomain" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD" /v "AllowRspndrOnPublicNet" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD" /v "EnableLLTDIO" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD" /v "EnableRspndr" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD" /v "ProhibitLLTDIOOnPrivateNet" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD" /v "ProhibitRspndrOnPrivateNet" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Messaging" /v "AllowMessageSync" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections" /v "NC_PersonalFirewallConfig" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections" /v "NC_AllowNetBridge_NLA" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections" /v "NC_ShowSharedAccessUI" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections" /v "NC_StdDomainUserSetLocation" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityAssistant" /v "NamePreferenceAllowed" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityAssistant" /v "ShowUI" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityAssistant\Probes" /v "PING:myserver.corp.contoso.com" /t REG_SZ /d "PING:myserver.corp.contoso.com" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" /v "\\*\NETLOGON" /t REG_SZ /d "RequireMutualAuthentication=1,RequireIntegrity=1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" /v "\\*\SYSVOL" /t REG_SZ /d "RequireMutualAuthentication=1,RequireIntegrity=1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\NvCache" /v "OptimizeBootAndResume" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreen" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenSlideshow" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell" /v "EnableScripts" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\scriptblocklogging" /v "EnableScriptBlockLogging" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\transcription" /v "EnableTranscripting" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\transcription" /v "OutputDirectory" /t REG_SZ /d "C:\ProgramData\PS_Transcript" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "EnableConfigFlighting" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "EnableExperimentation" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56308-b6bf-11d0-94f2-00a0c91efb8b}" /v "Deny_Execute" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630b-b6bf-11d0-94f2-00a0c91efb8b}" /v "Deny_Execute" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}" /v "Deny_Execute" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56311-b6bf-11d0-94f2-00a0c91efb8b}" /v "Deny_Execute" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers" /v "authenticodeenabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /v "DisableQueryRemoteServer" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /v "EnableQueryRemoteServer" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "EnableBackupForWin8Apps" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Skydrive" /v "DisableFileSync" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableAcrylicBackgroundOnLogon" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "ShellSmartScreenLevel" /t REG_SZ /d "Block" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "AllowClipboardHistory" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "AllowCrossDeviceClipboard" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "AllowDomainPINLogon" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DeleteRoamingCache" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableLockScreenAppNotifications" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DontDisplayNetworkSelectionUI" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DontEnumerateConnectedUsers" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnumerateLocalUsers" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "LocalProfile" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PrimaryComputerEnabledRUP" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\Fdeploy" /v "PrimaryComputerEnabledFR" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition" /v "6to4_State" /t REG_SZ /d "Disabled" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition" /v "Force_Tunneling" /t REG_SZ /d "Enabled" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition" /v "ISATAP_State" /t REG_SZ /d "Disabled" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition" /v "Teredo_State" /t REG_SZ /d "Disabled" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition\IPHTTPS\IPHTTPSInterface" /v "IPHTTPS_ClientState" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TCPIP\v6Transition\IPHTTPS\IPHTTPSInterface" /v "IPHTTPS_ClientUrl" /t REG_SZ /d "about:blank" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /v "fBlockNonDomain" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /v "fMinimizeConnections" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\Local" /v "WCMPresent" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\wcn\registrars" /v "DisableFlashConfigRegistrar" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\wcn\registrars" /v "DisableInBand802DOT11Registrar" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\wcn\registrars" /v "DisableUPnPRegistrar" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\wcn\registrars" /v "DisableWPDRegistrar" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\wcn\registrars" /v "EnableRegistrars" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\wcn\UI" /v "DisableWcnUi" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\wdi\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" /v "ScenarioExecutionEnabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\wdi\{c295fbba-fd47-46ac-8bee-b1715ec634e5}" /v "DownloadToolsEnabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowIndexingEncryptedStoresOrItems" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchPrivacy" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "PreventIndexingUncachedExchangeFolders" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoRebootWithLoggedOnUsers" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" /v "AllowBasic" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" /v "AllowCredSSP" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" /v "AllowDigest" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" /v "AllowKerberos" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" /v "AllowNegotiate" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" /v "AllowUnencryptedTraffic" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\service" /v "AllowAutoConfig" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\service" /v "AllowBasic" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\service" /v "AllowCredSSP" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\service" /v "AllowKerberos" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\service" /v "AllowNegotiate" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\service" /v "AllowUnencryptedTraffic" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\service" /v "DisableRunAs" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\service" /v "HttpCompatibilityListener" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\service" /v "HttpsCompatibilityListener" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\service\WinRS" /v "AllowRemoteShellAccess" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WorkFolders" /v "AutoProvision" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin" /v "autoWorkplaceJoin" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WSDAPI\Discovery Proxies" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "PUAProtection" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions" /v "DisableAutoExclusions" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" /v "MpEnablePus" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" /v "MpCloudBlockLevel" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" /v "MpBafsExtendedTimeout" /t REG_DWORD /d "50" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableEmailScanning" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableRemovableDriveScanning" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "ScheduleDay" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" /v "ASSignatureDue" /t REG_DWORD /d "7" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" /v "AVSignatureDue" /t REG_DWORD /d "7" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" /v "ScheduleDay" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpyNetReporting" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Threats" /v "Threats_ThreatSeverityDefaultAction" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "1" /t REG_SZ /d "2" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "2" /t REG_SZ /d "2" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "4" /t REG_SZ /d "2" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "5" /t REG_SZ /d "2" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" /v "ExploitGuard_ASR_Rules" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "26190899-1602-49e8-8b27-eb1d0a1ce869" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "3b576869-a4ec-4529-8536-b80a7769e899" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "5beb7efe-fd9a-4556-801d-275e5ffc04cc" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "c1db55ab-c21a-4637-bb3f-a12568109d35" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "d3e037e1-3eb8-44c8-a917-57927947596d" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "d4f940ab-401b-4efc-aadc-ad5f3c50688a" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "e6db77e5-3df2-4cf1-b95a-636979351e5b" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access" /v "EnableControlledFolderAccess" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" /v "EnableNetworkProtection" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender ExploitGuard\Exploit Protection" /v "ExploitProtectionSettings" /t REG_SZ /d "\\YOURSHAREHERE\EP.XML" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" /v "DisallowExploitProtectionOverride" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v "EnableMulticast" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v "DisableHTTPPrinting" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v "DisableWebPnPDownload" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v "DoNotInstallCompatibleDriverFromWindowsUpdate" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers" /v "RegisterSpoolerRemoteRpcEndPoint" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v "InForest" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v "NoWarningNoElevationOnInstall" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v "Restricted" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v "ServerList" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v "TrustedServers" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v "UpdatePromptSettings" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" /v "EnableAuthEpResolution" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" /v "RestrictRemoteClients" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowSignedFiles" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowUnsignedFiles" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "DeleteTempDirsOnExit" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "DisablePasswordSaving" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowToGetHelp" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowUnsolicited" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "DenyTSConnections" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "DisableAudioCapture" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "DisableCcm" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "DisableCdm" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "DisableClip" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "DisableCpm" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "DisableLPT" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "DisableCameraRedir" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "DisablePNPRedir" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "EnableSmartCard" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "EncryptRPCTraffic" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "PromptForPassword" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "LoggingEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "MinEncryptionLevel" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "PerSessionTempDir" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "PromptForCredsOnClient" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "RedirectOnlyDefaultClientPrinter" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "SessionDirectoryExposeServerIP" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "ShareControlMessage" /t REG_SZ /d "You are about to allow other personnel to remotely control your system. You must monitor the activity until the session is closed." /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "UseCustomMessages" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "UseUniversalPrinterDriverFirst" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "ViewMessage" /t REG_SZ /d "You are about to allow other personnel to remotely connect to your system. Sensitive data should not be displayed during this session." /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" /v "EnableUsbBlockDeviceBySetupClass" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" /v "EnableUsbNoAckIsochWriteToDevice" /t REG_DWORD /d "80" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" /v "EnableUsbSelectDeviceByInterface" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client\UsbBlockDeviceBySetupClasses" /v "1000" /t REG_SZ /d "{3376f4ce-ff8d-40a2-a80f-bb4359d1415c}" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client\UsbSelectDeviceByInterfaces" /v "1000" /t REG_SZ /d "{6bdd1fc6-810f-11d0-bec7-08002be2092f}" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Windows File Protection" /v "KnownDllList" /t REG_SZ /d "nlhtml.dll" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall" /v "PolicyVersion" /t REG_DWORD /d "538" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "DefaultInboundAction" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "DefaultOutboundAction" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "DisableNotifications" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" /v "EnableFirewall" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" /v "LogDroppedPackets" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" /v "LogFileSize" /t REG_DWORD /d "16384" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging" /v "LogSuccessfulConnections" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{0BC6A788-6049-404C-8620-9CA84A90F9B6}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=In|Protocol=112|Name=VRRP|" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{0F63FC11-772D-4598-AB3A-3F9D739A7A61}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=In|Protocol=2|Name=IGMP|" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{17116813-ABCE-4858-B7A9-E89149F88B6C}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort2_10=1-67|LPort2_10=69-65535|App=%%SystemRoot%%\System32\svchost.exe|Name=svchost tcp|" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{1AB67954-115D-4DFD-84D8-49E004B70A56}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=Out|App=%%SystemRoot%%\explorer.exe|Name=explorer|" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{2544C3F8-BA9E-4614-AC6B-A4358E25173B}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=In|Protocol=17|LPort2_10=0-66|LPort2_10=69-1687|LPort2_10=1689-55554|LPort2_10=55556-65535|Name=4Torrents55555|" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{32BEF19F-0DB3-4BEA-B185-B7C669DEDB5C}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort2_10=0-66|LPort2_10=69-1687|LPort2_10=1689-55554|LPort2_10=55556-65535|Name=4Torrents55555|" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{3FB5D65C-BB7B-42BD-BD7D-1735BFCE144B}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=Out|Protocol=6|RPort2_10=0-52|RPort2_10=54-66|RPort2_10=69-79|RPort2_10=82-442|RPort2_10=444-1000|Name=TCP|" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{4CCAC58A-3834-4DB0-AFDD-E8CC4D206B72}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=Out|Protocol=17|RPort2_10=1-52|RPort2_10=54-66|RPort2_10=68-65535|App=%%SystemRoot%%\System32\svchost.exe|Name=svchost udp|" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{4CE8D585-B3FD-45D6-A549-50641B7AA09E}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=In|Protocol=60|Name=IPv6-Opts|" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{4FA87E52-9D33-46B4-9B1E-F43DF96E676F}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=Out|Protocol=43|Name=IPv6-Route|" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{6BF200DF-6F9D-483F-A1B5-C0A479FD1C16}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=In|Protocol=1|Name=ICMPv4|" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{6C0065E8-6B53-4880-B115-6D2109BE121D}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=Out|Protocol=59|Name=IPv6-NoNxt|" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{7242246C-02FC-4FE0-8C87-23A869806620}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=Out|Protocol=60|Name=IPv6-Opts|" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{7E711471-0197-4CDF-8A8F-285D204E8913}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=Out|Protocol=2|Name=IGMP|" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{8B541AB8-A1FB-4AB4-978F-903483AB0603}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=In|Protocol=58|Name=ICMPv6|" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{9347CAC4-6908-4E8B-9D45-4954CD686CEA}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=In|Protocol=59|Name=IPv6-NoNxt|" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{A4C2280E-D96D-474C-B7F8-5E551B50D803}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=Out|Protocol=47|Name=GRE|" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{ACEB7955-9176-45E9-9BCE-3890B231D802}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=Out|Protocol=41|Name=IPv6|" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{B4B43298-454A-4775-B7F9-D149EE70AC22}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=In|Protocol=43|Name=IPv6-Route|" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{C0504930-7FC9-45D0-A4C0-0183C69168E8}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=Out|Protocol=113|Name=PGM|" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{CAC95F10-BE12-4508-8F75-4450051399D8}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=In|App=%%SystemRoot%%\explorer.exe|Name=explorer|" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{CD2E1B81-F907-434F-9855-A0D6ADC47EA2}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=In|Protocol=115|Name=L2TP|" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{D3507B32-E394-4E1C-BA60-375DC173A87C}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=In|Protocol=44|Name=IPv6-Frag|" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{D554D4E5-28A3-4785-808B-7CCCB3732B40}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=In|Protocol=47|Name=GRE|" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{D69FCB0D-6042-4155-A0D8-71167AC1FF00}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=Out|Protocol=1|Name=ICMPv4|" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{D6DBF400-55D5-46F2-9360-961063CA41F8}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=Out|Protocol=112|Name=VRRP|" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{D956505D-BC90-412D-81C5-195D127761D7}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=In|Protocol=113|Name=PGM|" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{DFEBB9A0-90D2-42E9-A551-D3D3BCE876DB}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=Out|Protocol=58|Name=ICMPv6|" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{E61EC587-47AB-4195-856D-A11A843A0EF2}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=Out|Protocol=115|Name=L2TP|" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{E75B5D96-DA86-40F7-AEB3-F5B69409CB07}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=Out|Protocol=0|Name=HOPOPT|" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{E7EDF93C-E442-4E1F-94E2-79A1B371D763}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=In|Protocol=41|Name=IPv6|" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{EDA4A164-6B30-4C99-841D-1536CA429AFC}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=In|Protocol=17|LPort2_10=1-67|LPort2_10=69-65535|App=%%SystemRoot%%\System32\svchost.exe|Name=svchost udp|" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{F2A0DA0C-2ACD-434F-B64F-9E224920DCAD}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=Out|Protocol=17|RPort2_10=0-52|RPort2_10=54-66|RPort2_10=69-79|RPort2_10=82-442|RPort2_10=444-1000|Name=UDP|" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{F585C2D8-420B-466C-B1DF-7D3B8DCDAE04}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=Out|Protocol=44|Name=IPv6-Frag|" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{FDAE6651-26AC-47C4-83D2-B02F68966FB4}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=Out|Protocol=6|RPort2_10=1-52|RPort2_10=54-66|RPort2_10=68-65535|App=%%SystemRoot%%\System32\svchost.exe|Name=svchost tcp|" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "{FF684A18-2CBA-4CBB-A614-542BC1331834}" /t REG_SZ /d "v2.30|Action=Block|Active=TRUE|Dir=In|Protocol=0|Name=HOPOPT|" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "RemoteDesktop-Shadow-In-TCP" /t REG_SZ /d "v2.28|Action=Block|Active=TRUE|Dir=In|Protocol=6|App=%%SystemRoot%%\system32\RdpSa.exe|Name=@FirewallAPI.dll,-28778|Desc=@FirewallAPI.dll,-28779|EmbedCtxt=@FirewallAPI.dll,-28752|Edge=TRUE|Defer=App|" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "RemoteDesktop-UserMode-In-TCP" /t REG_SZ /d "v2.28|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort=3389|App=%%SystemRoot%%\system32\svchost.exe|Svc=termservice|Name=@FirewallAPI.dll,-28775|Desc=@FirewallAPI.dll,-28756|EmbedCtxt=@FirewallAPI.dll,-28752|" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /v "RemoteDesktop-UserMode-In-UDP" /t REG_SZ /d "v2.28|Action=Block|Active=TRUE|Dir=In|Protocol=17|LPort=3389|App=%%SystemRoot%%\system32\svchost.exe|Svc=termservice|Name=@FirewallAPI.dll,-28776|Desc=@FirewallAPI.dll,-28777|EmbedCtxt=@FirewallAPI.dll,-28752|" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "DefaultInboundAction" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "DefaultOutboundAction" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "DisableNotifications" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" /v "EnableFirewall" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" /v "LogDroppedPackets" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" /v "LogFileSize" /t REG_DWORD /d "16384" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" /v "LogSuccessfulConnections" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "AllowLocalIPsecPolicyMerge" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "AllowLocalPolicyMerge" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "DefaultInboundAction" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "DefaultOutboundAction" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "DisableNotifications" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" /v "EnableFirewall" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" /v "LogDroppedPackets" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" /v "LogFileSize" /t REG_DWORD /d "16384" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging" /v "LogSuccessfulConnections" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" /v "EnableFirewall" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Logging" /v "LogDroppedPackets" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Logging" /v "LogFilePath" /t REG_SZ /d "%%systemroot%%\system32\LogFiles\Firewall\pfirewall.log" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Logging" /v "LogFileSize" /t REG_DWORD /d "4096" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\Logging" /v "LogSuccessfulConnections" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" /v "AllowWindowsInkWorkspace" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" /v "GroupPrivacyAcceptance" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" /v "DisableAutoUpdate" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /v "AutoDownload" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /v "DisableOSUpgrade" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /v "RemoveWindowsStore" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WMDRM" /v "DisableOnline" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd" /v "AdmPwdEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" /v "NoExplicitFeedback" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" /v "NoImplicitFeedback" /t REG_DWORD /d "1" /f
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
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Internet Explorer\Control Panel" /v "FormSuggest" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Internet Explorer\Control Panel" /v "FormSuggest Passwords" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" /v "FormSuggest Passwords" /t REG_SZ /d "no" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" /v "FormSuggest PW Ask" /t REG_SZ /d "no" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" /v "Use FormSuggest" /t REG_SZ /d "no" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\access\internet" /v "donotunderlinehyperlinks" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\access\security" /v "modaltrustdecisiononly" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\access\security" /v "notbpromptunsignedaddin" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\access\security" /v "requireaddinsig" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\access\security" /v "vbawarnings" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\access\settings" /v "default file format" /t REG_DWORD /d "12" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\access\settings" /v "noconvertdialog" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\common" /v "qmenable" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\common" /v "updatereliabilitydata" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\common\broadcast" /v "disabledefaultservice" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\common\broadcast" /v "disableprogrammaticaccess" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\common\documentinformationpanel" /v "beaconing" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\common\drm" /v "disablecreation" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\common\drm" /v "includehtml" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\common\drm" /v "requireconnection" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\common\feedback" /v "enabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\common\feedback" /v "includescreenshot" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\common\fixedformat" /v "disablefixedformatdocproperties" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\common\general" /v "shownfirstrunoptin" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\common\general" /v "skydrivesigninoption" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\common\internet" /v "opendocumentsreadwritewhilebrowsing" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\common\internet" /v "relyonvml" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\common\internet" /v "useonlinecontent" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\common\mailsettings" /v "disablesignatures" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\common\mailsettings" /v "plainwraplen" /t REG_DWORD /d "132" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\common\portal" /v "linkpublishingdisabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\common\ptwatson" /v "ptwoptin" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\common\research\translation" /v "useonline" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\common\roaming" /v "roamingsettingsdisabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\common\security" /v "defaultencryption12" /t REG_SZ /d "Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\common\security" /v "disablehyperlinkwarning" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\common\security" /v "disablepasswordui" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\common\security" /v "drmencryptproperty" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\common\security" /v "encryptdocprops" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\common\security" /v "openxmlencryption" /t REG_SZ /d "Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\common\security" /v "openxmlencryptproperty" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\common\security\trusted locations" /v "allow user locations" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\common\services\fax" /v "nofax" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\common\signatures" /v "enablecreationofweakxpsignatures" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\common\signatures" /v "suppressextsigningsvcs" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\common\signin" /v "signinoptions" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\common\trustcenter" /v "trustbar" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\excel\internet" /v "donotloadpictures" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\excel\options" /v "autohyperlink" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\excel\options" /v "defaultformat" /t REG_DWORD /d "51" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\excel\options" /v "disableautorepublish" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\excel\options" /v "disableautorepublishwarning" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\excel\options" /v "extractdatadisableui" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\excel\options\binaryoptions" /v "fglobalsheet_37_1" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\excel\options\binaryoptions" /v "fupdateext_78_1" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\excel\security" /v "accessvbom" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\excel\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\excel\security" /v "excelbypassencryptedmacroscan" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\excel\security" /v "extensionhardening" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\excel\security" /v "notbpromptunsignedaddin" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\excel\security" /v "requireaddinsig" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\excel\security" /v "vbawarnings" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\excel\security" /v "webservicefunctionwarnings" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\excel\security\fileblock" /v "dbasefiles" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\excel\security\fileblock" /v "difandsylkfiles" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\excel\security\fileblock" /v "excel12betafilesfromconverters" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\excel\security\fileblock" /v "htmlandxmlssfiles" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\excel\security\fileblock" /v "openinprotectedview" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\excel\security\fileblock" /v "xl2macros" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\excel\security\fileblock" /v "xl2worksheets" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\excel\security\fileblock" /v "xl3macros" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\excel\security\fileblock" /v "xl3worksheets" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\excel\security\fileblock" /v "xl4macros" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\excel\security\fileblock" /v "xl4workbooks" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\excel\security\fileblock" /v "xl4worksheets" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\excel\security\fileblock" /v "xl9597workbooksandtemplates" /t REG_DWORD /d "5" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\excel\security\fileblock" /v "xl95workbooks" /t REG_DWORD /d "5" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\excel\security\filevalidation" /v "disableeditfrompv" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\excel\security\filevalidation" /v "enableonload" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\excel\security\filevalidation" /v "openinprotectedview" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\excel\security\protectedview" /v "disableattachmentsinpv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\excel\security\protectedview" /v "disableinternetfilesinpv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\excel\security\protectedview" /v "disableunsafelocationsinpv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\excel\security\trusted locations" /v "alllocationsdisabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\excel\security\trusted locations" /v "allownetworklocations" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\firstrun" /v "bootedrtm" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\firstrun" /v "disablemovie" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\gfx" /v "disablescreenshotautohyperlink" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\infopath" /v "disableinfopath2003emailforms" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\infopath\deployment" /v "cachemailxsn" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\infopath\deployment" /v "mailxsnwithxml" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\infopath\editor\offline" /v "cachedmodestatus" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\infopath\security" /v "allowinternetsolutions" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\infopath\security" /v "disallowattachmentcustomization" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\infopath\security" /v "editoractivexbeaconingui" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\infopath\security" /v "emailformsbeaconingui" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\infopath\security" /v "emailformsruncodeandscript" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\infopath\security" /v "enablefulltrustemailforms" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\infopath\security" /v "enableinternetemailforms" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\infopath\security" /v "enableintranetemailforms" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\infopath\security" /v "enablerestrictedemailforms" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\infopath\security" /v "gradualupgraderedirection" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\infopath\security" /v "infopathbeaconingui" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\infopath\security" /v "notbpromptunsignedaddin" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\infopath\security" /v "requireaddinsig" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\infopath\security" /v "runfulltrustsolutions" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\infopath\security" /v "runmanagedcodefrominternet" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\infopath\security" /v "signaturewarning" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\infopath\security\trusted locations" /v "alllocationsdisabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\meetings\profile" /v "serverui" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\ms project\security" /v "notbpromptunsignedaddin" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\ms project\security" /v "requireaddinsig" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\ms project\security" /v "trustwss" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\ms project\security" /v "vbawarnings" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\osm" /v "enablefileobfuscation" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\osm" /v "enablelogging" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\osm" /v "enableupload" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook" /v "disableantispam" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook" /v "disallowattachmentcustomization" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\options\autoformat" /v "pgrfafo_25_1" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\options\calendar" /v "disableweather" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\options\general" /v "check default client" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\options\general" /v "msgformat" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\options\mail" /v "blockextcontent" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\options\mail" /v "disableinfopathforms" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\options\mail" /v "editorpreference" /t REG_DWORD /d "65536" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\options\mail" /v "internet" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\options\mail" /v "intranet" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\options\mail" /v "junkmailenablelinks" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\options\mail" /v "junkmailtrustcontacts" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\options\mail" /v "junkmailtrustoutgoingrecipients" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\options\mail" /v "message plain format mime" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\options\mail" /v "message rtf format" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\options\mail" /v "readasplain" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\options\mail" /v "readsignedasplain" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\options\mail" /v "trustedzone" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\options\mail" /v "unblocksafezone" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\options\mail" /v "unblockspecificsenders" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\options\pubcal" /v "disabledav" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\options\pubcal" /v "disableofficeonline" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\options\pubcal" /v "publishcalendardetailspolicy" /t REG_DWORD /d "16384" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\options\pubcal" /v "restrictedaccessonly" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\options\pubcal" /v "singleuploadonly" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\options\rss" /v "disable" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\options\rss" /v "enableattachments" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\options\rss" /v "enablefulltexthtml" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\options\rss" /v "synctosyscfl" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\options\webcal" /v "disable" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\options\webcal" /v "enableattachments" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\rpc" /v "enablerpcencryption" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\security" /v "addintrust" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\security" /v "adminsecuritymode" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\security" /v "allowactivexoneoffforms" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\security" /v "allowuserstolowerattachments" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\security" /v "authenticationservice" /t REG_DWORD /d "9" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\security" /v "clearsign" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\security" /v "dontpromptlevel1attachclose" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\security" /v "dontpromptlevel1attachsend" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\security" /v "enableoneoffformscripts" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\security" /v "enablerememberpwd" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\security" /v "externalsmime" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\security" /v "fipsmode" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\security" /v "forcedefaultprofile" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\security" /v "level" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\security" /v "minenckey" /t REG_DWORD /d "168" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\security" /v "msgformats" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\security" /v "nocheckonsessionsecurity" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\security" /v "nondefaultstorescript" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\security" /v "promptoomaddressbookaccess" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\security" /v "promptoomaddressinformationaccess" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\security" /v "promptoomcustomaction" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\security" /v "promptoomformulaaccess" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\security" /v "promptoommeetingtaskrequestresponse" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\security" /v "promptoomsaveas" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\security" /v "promptoomsend" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\security" /v "publicfolderscript" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\security" /v "respondtoreceiptrequests" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\security" /v "sharedfolderscript" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\security" /v "showlevel1attach" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\security" /v "sigstatusnotrustdecision" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\security" /v "supressnamechecks" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\security" /v "usecrlchasing" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\outlook\security" /v "warnaboutinvalid" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\powerpoint\options" /v "defaultformat" /t REG_DWORD /d "27" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\powerpoint\options" /v "markupopensave" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\powerpoint\security" /v "accessvbom" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\powerpoint\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\powerpoint\security" /v "downloadimages" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\powerpoint\security" /v "notbpromptunsignedaddin" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\powerpoint\security" /v "powerpointbypassencryptedmacroscan" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\powerpoint\security" /v "requireaddinsig" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\powerpoint\security" /v "runprograms" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\powerpoint\security" /v "vbawarnings" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\powerpoint\security\fileblock" /v "openinprotectedview" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\powerpoint\security\fileblock" /v "powerpoint12betafilesfromconverters" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\powerpoint\security\filevalidation" /v "disableeditfrompv" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\powerpoint\security\filevalidation" /v "enableonload" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\powerpoint\security\filevalidation" /v "openinprotectedview" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\powerpoint\security\protectedview" /v "disableattachmentsinpv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\powerpoint\security\protectedview" /v "disableinternetfilesinpv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\powerpoint\security\protectedview" /v "disableunsafelocationsinpv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\powerpoint\security\trusted locations" /v "alllocationsdisabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\powerpoint\security\trusted locations" /v "allownetworklocations" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\powerpoint\slide libraries" /v "disableslideupdate" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\publisher" /v "promptforbadfiles" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\publisher\security" /v "notbpromptunsignedaddin" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\publisher\security" /v "requireaddinsig" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\publisher\security" /v "vbawarnings" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\visio\security" /v "notbpromptunsignedaddin" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\visio\security" /v "requireaddinsig" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\visio\security" /v "vbawarnings" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\wef\trustedcatalogs" /v "disableomexcatalogs" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\wef\trustedcatalogs" /v "requireserververification" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\word\options" /v "custommarkupwarning" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\word\options" /v "dontupdatelinks" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\word\options" /v "warnrevisions" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\word\security" /v "accessvbom" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\word\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\word\security" /v "notbpromptunsignedaddin" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\word\security" /v "requireaddinsig" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\word\security" /v "vbawarnings" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\word\security" /v "wordbypassencryptedmacroscan" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\word\security\fileblock" /v "openinprotectedview" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\word\security\fileblock" /v "word2000files" /t REG_DWORD /d "5" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\word\security\fileblock" /v "word2files" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\word\security\fileblock" /v "word60files" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\word\security\fileblock" /v "word95files" /t REG_DWORD /d "5" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\word\security\fileblock" /v "word97files" /t REG_DWORD /d "5" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\word\security\fileblock" /v "wordxpfiles" /t REG_DWORD /d "5" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\word\security\filevalidation" /v "disableeditfrompv" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\word\security\filevalidation" /v "enableonload" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\word\security\filevalidation" /v "openinprotectedview" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\word\security\protectedview" /v "disableattachmentsinpv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\word\security\protectedview" /v "disableinternetfilesinpv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\word\security\protectedview" /v "disableunsafelocationsinpv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\word\security\trusted locations" /v "alllocationsdisabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\word\security\trusted locations" /v "allownetworklocations" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\access\internet" /v "donotunderlinehyperlinks" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\access\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\access\security" /v "modaltrustdecisiononly" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\access\security" /v "notbpromptunsignedaddin" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\access\security" /v "requireaddinsig" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\access\security" /v "vbadigsigtrustedpublishers" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\access\security" /v "vbarequiredigsigwithcodesigningeku" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\access\security" /v "vbarequirelmtrustedpublisher" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\access\security" /v "vbawarnings" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\access\security\trusted locations" /v "allownetworklocations" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\access\settings" /v "default file format" /t REG_DWORD /d "12" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common" /v "fbabehavior" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common" /v "fbaenabledhosts" /t REG_EXPAND_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common" /v "sendcustomerdata" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\broadcast" /v "disabledefaultservice" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\broadcast" /v "disableprogrammaticaccess" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\drm" /v "requireconnection" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback" /v "includescreenshot" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\fixedformat" /v "disablefixedformatdocproperties" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\portal" /v "linkpublishingdisabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\ptwatson" /v "ptwoptin" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\research\translation" /v "useonline" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\security" /v "defaultencryption12" /t REG_SZ /d "Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\security" /v "drmencryptproperty" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\security" /v "encryptdocprops" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\security" /v "macroruntimescanscope" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\security" /v "openxmlencryption" /t REG_SZ /d "Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\security" /v "openxmlencryptproperty" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\security\trusted locations" /v "allow user locations" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\toolbars\access" /v "noextensibilitycustomizationfromdocument" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\toolbars\excel" /v "noextensibilitycustomizationfromdocument" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\toolbars\infopath" /v "noextensibilitycustomizationfromdocument" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\toolbars\outlook" /v "noextensibilitycustomizationfromdocument" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\toolbars\powerpoint" /v "noextensibilitycustomizationfromdocument" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\toolbars\project" /v "noextensibilitycustomizationfromdocument" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\toolbars\publisher" /v "noextensibilitycustomizationfromdocument" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\toolbars\visio" /v "noextensibilitycustomizationfromdocument" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\toolbars\word" /v "noextensibilitycustomizationfromdocument" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\trustcenter" /v "trustbar" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\internet" /v "donotloadpictures" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\options" /v "defaultformat" /t REG_DWORD /d "51" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\options" /v "disableautorepublish" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\options" /v "disableautorepublishwarning" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\options" /v "extractdatadisableui" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\options\binaryoptions" /v "fglobalsheet_37_1" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\options\binaryoptions" /v "fupdateext_78_1" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security" /v "accessvbom" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security" /v "excelbypassencryptedmacroscan" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security" /v "extensionhardening" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security" /v "notbpromptunsignedaddin" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security" /v "requireaddinsig" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security" /v "vbadigsigtrustedpublishers" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security" /v "vbarequiredigsigwithcodesigningeku" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security" /v "vbarequirelmtrustedpublisher" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security" /v "vbawarnings" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security" /v "webservicefunctionwarnings" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security\external content" /v "disableddeserverlaunch" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security\external content" /v "disableddeserverlookup" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security\external content" /v "enableblockunsecurequeryfiles" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security\fileblock" /v "dbasefiles" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security\fileblock" /v "difandsylkfiles" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security\fileblock" /v "htmlandxmlssfiles" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security\fileblock" /v "openinprotectedview" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security\fileblock" /v "xl2macros" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security\fileblock" /v "xl2worksheets" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security\fileblock" /v "xl3macros" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security\fileblock" /v "xl3worksheets" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security\fileblock" /v "xl4macros" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security\fileblock" /v "xl4workbooks" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security\fileblock" /v "xl4worksheets" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security\fileblock" /v "xl9597workbooksandtemplates" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security\fileblock" /v "xl95workbooks" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security\fileblock" /v "xl97workbooksandtemplates" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security\filevalidation" /v "disableeditfrompv" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security\filevalidation" /v "enableonload" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security\filevalidation" /v "openinprotectedview" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security\protectedview" /v "disableattachmentsinpv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security\protectedview" /v "disableinternetfilesinpv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security\protectedview" /v "disableintranetcheck" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security\protectedview" /v "disableunsafelocationsinpv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security\protectedview" /v "enabledatabasefileprotectedview" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security\trusted locations" /v "alllocationsdisabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security\trusted locations" /v "allownetworklocations" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\meetings\profile" /v "serverui" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\ms project\security" /v "notbpromptunsignedaddin" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\ms project\security" /v "requireaddinsig" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\ms project\security" /v "trustwss" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\ms project\security" /v "vbawarnings" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\ms project\security\trusted locations" /v "allownetworklocations" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm" /v "enablefileobfuscation" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook" /v "disallowattachmentcustomization" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\options\general" /v "msgformat" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\options\mail" /v "blockextcontent" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\options\mail" /v "internet" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\options\mail" /v "intranet" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\options\mail" /v "junkmailenablelinks" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\options\mail" /v "junkmailprotection" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\options\mail" /v "trustedzone" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\options\mail" /v "unblocksafezone" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\options\mail" /v "unblockspecificsenders" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\options\pubcal" /v "disabledav" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\options\pubcal" /v "disableofficeonline" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\options\pubcal" /v "publishcalendardetailspolicy" /t REG_DWORD /d "16384" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\options\pubcal" /v "restrictedaccessonly" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\options\rss" /v "enableattachments" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\options\rss" /v "enablefulltexthtml" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\options\webcal" /v "disable" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\options\webcal" /v "enableattachments" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\rpc" /v "enablerpcencryption" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /v "addintrust" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /v "adminsecuritymode" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /v "allowactivexoneoffforms" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /v "allowuserstolowerattachments" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /v "authenticationservice" /t REG_DWORD /d "16" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /v "clearsign" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /v "enableoneoffformscripts" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /v "enablerememberpwd" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /v "externalsmime" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /v "fileextensionsremovelevel1" /t REG_SZ /d ";" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /v "fileextensionsremovelevel2" /t REG_SZ /d ";" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /v "fipsmode" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /v "forcedefaultprofile" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /v "level" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /v "minenckey" /t REG_DWORD /d "168" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /v "msgformats" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /v "nocheckonsessionsecurity" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /v "promptoomaddressbookaccess" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /v "promptoomaddressinformationaccess" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /v "promptoomcustomaction" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /v "promptoomformulaaccess" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /v "promptoommeetingtaskrequestresponse" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /v "promptoomsaveas" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /v "promptoomsend" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /v "publicfolderscript" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /v "publishtogaldisabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /v "respondtoreceiptrequests" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /v "sharedfolderscript" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /v "showlevel1attach" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /v "supressnamechecks" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /v "usecrlchasing" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /v "warnaboutinvalid" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\options" /v "defaultformat" /t REG_DWORD /d "27" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security" /v "accessvbom" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security" /v "notbpromptunsignedaddin" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security" /v "powerpointbypassencryptedmacroscan" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security" /v "requireaddinsig" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security" /v "runprograms" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security" /v "vbadigsigtrustedpublishers" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security" /v "vbarequiredigsigwithcodesigningeku" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security" /v "vbarequirelmtrustedpublisher" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security" /v "vbawarnings" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security\fileblock" /v "binaryfiles" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security\fileblock" /v "openinprotectedview" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security\filevalidation" /v "disableeditfrompv" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security\filevalidation" /v "enableonload" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security\filevalidation" /v "openinprotectedview" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security\protectedview" /v "disableattachmentsinpv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security\protectedview" /v "disableinternetfilesinpv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security\protectedview" /v "disableintranetcheck" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security\protectedview" /v "disableunsafelocationsinpv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security\trusted locations" /v "alllocationsdisabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security\trusted locations" /v "allownetworklocations" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\publisher" /v "promptforbadfiles" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\publisher\security" /v "notbpromptunsignedaddin" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\publisher\security" /v "requireaddinsig" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\publisher\security" /v "vbadigsigtrustedpublishers" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\publisher\security" /v "vbarequiredigsigwithcodesigningeku" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\publisher\security" /v "vbarequirelmtrustedpublisher" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\publisher\security" /v "vbawarnings" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\visio\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\visio\security" /v "notbpromptunsignedaddin" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\visio\security" /v "requireaddinsig" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\visio\security" /v "vbadigsigtrustedpublishers" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\visio\security" /v "vbarequiredigsigwithcodesigningeku" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\visio\security" /v "vbarequirelmtrustedpublisher" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\visio\security" /v "vbawarnings" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\visio\security\fileblock" /v "visio2000files" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\visio\security\fileblock" /v "visio2003files" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\visio\security\fileblock" /v "visio50andearlierfiles" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\visio\security\trusted locations" /v "allownetworklocations" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\wef\trustedcatalogs" /v "requireserververification" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\word\options" /v "dontupdatelinks" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\word\security" /v "accessvbom" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\word\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\word\security" /v "notbpromptunsignedaddin" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\word\security" /v "requireaddinsig" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\word\security" /v "vbadigsigtrustedpublishers" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\word\security" /v "vbarequiredigsigwithcodesigningeku" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\word\security" /v "vbarequirelmtrustedpublisher" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\word\security" /v "vbawarnings" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\word\security" /v "wordbypassencryptedmacroscan" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\word\security\fileblock" /v "openinprotectedview" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\word\security\fileblock" /v "word2000files" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\word\security\fileblock" /v "word2003files" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\word\security\fileblock" /v "word2007files" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\word\security\fileblock" /v "word2files" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\word\security\fileblock" /v "word60files" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\word\security\fileblock" /v "word95files" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\word\security\fileblock" /v "word97files" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\word\security\fileblock" /v "wordxpfiles" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\word\security\filevalidation" /v "disableeditfrompv" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\word\security\filevalidation" /v "enableonload" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\word\security\filevalidation" /v "openinprotectedview" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\word\security\protectedview" /v "disableattachmentsinpv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\word\security\protectedview" /v "disableinternetfilesinpv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\word\security\protectedview" /v "disableintranetcheck" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\word\security\protectedview" /v "disableunsafelocationsinpv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\word\security\trusted locations" /v "alllocationsdisabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\word\security\trusted locations" /v "allownetworklocations" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\common\blog" /v "disableblog" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\common\security" /v "automationsecurity" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\common\security" /v "automationsecuritypublisher" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\common\security" /v "uficontrols" /t REG_DWORD /d "6" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\office\common\smart tag" /v "neverloadmanifests" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\OneDrive" /v "DisablePersonalSync" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\SystemCertificates\CA\Certificates" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\SystemCertificates\CA\CRLs" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\SystemCertificates\CA\CTLs" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\SystemCertificates\Disallowed\Certificates" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\SystemCertificates\Disallowed\CRLs" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\SystemCertificates\Disallowed\CTLs" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\SystemCertificates\trust\Certificates" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\SystemCertificates\trust\CRLs" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\SystemCertificates\trust\CTLs" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPeople\Certificates" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPeople\CRLs" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPeople\CTLs" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPublisher\Certificates" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPublisher\CRLs" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\SystemCertificates\TrustedPublisher\CTLs" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\vba\security" /v "allowvbaintranetreferences" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\vba\security" /v "disablestrictvbarefssecurity" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\vba\security" /v "loadcontrolsinforms" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableThirdPartySuggestions" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" /v "ScreenSaveActive" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" /v "ScreenSaverIsSecure" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" /v "SCRNSAVE.EXE" /t REG_SZ /d "scrnsave.scr" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Cache" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoCloudApplicationNotification" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotificationOnLockScreen" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /ve /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Network Connections" /v "NC_DeleteAllUserConnection" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows NT\Driver Signing" /v "BehaviorOnFailedVerify" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows NT\printers\wizard" /v "Downlevel Browse" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows NT\SharedFolders" /v "PublishDfsRoots" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows NT\SharedFolders" /v "PublishSharedFolders" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowSignedFiles" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "AllowUnsignedFiles" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "DisablePasswordSaving" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" /v "PreventCodecDownload" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Power\PowerSettings" /ve /t REG_SZ /d "" /f
REM ; SysHardener
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ValidateAdminCodeSignatures" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "SFCDisable" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\NoExecuteState" /v "LastNoExecuteRadioButtonState" /t REG_DWORD /d "14013" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "VDMDisallowed" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping\Autorun.inf" /ve /t REG_SZ /d "@SYS:DoesNotExist" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v "DisableAutoplay" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings" /v "Enabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "RequireAdmin" /f
Echo Y | Reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV8" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v "AllowTSConnections" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "SafeDllSearchMode" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "SafeProcessSearchMode" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "StartRunNoHOMEPATH" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB2" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB1" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{3245bf92-747e-45ff-87ae-afa7cbf2869a}" /v "NetbiosOptions" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{924745e8-e26a-42b7-bdc1-b4604c1fcb32}" /v "NetbiosOptions" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{ee1346b1-f081-4306-81b4-83991af38a4b}" /v "NetbiosOptions" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar" /v "TurnOffSidebar" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Sidebar\Settings" /v "AllowElevatedProcess" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v "RequireSignedAppInit_DLLs" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell" /v "EnableScripts" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "__PSLockDownPolicy" /t REG_SZ /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DusmSvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\7.0\JSPrefs" /v "bEnableJS" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\8.0\JSPrefs" /v "bEnableJS" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\9.0\JSPrefs" /v "bEnableJS" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\10.0\JSPrefs" /v "bEnableJS" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\11.0\JSPrefs" /v "bEnableJS" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\DC\JSPrefs" /v "bEnableJS" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\XI\JSPrefs" /v "bEnableJS" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\7.0\TrustManager" /v "iProtectedView" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\7.0\TrustManager" /v "bEnhancedSecurityInBrowser" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\7.0\TrustManager" /v "bEnhancedSecurityStandalone" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\8.0\TrustManager" /v "iProtectedView" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\8.0\TrustManager" /v "bEnhancedSecurityInBrowser" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\8.0\TrustManager" /v "bEnhancedSecurityStandalone" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\9.0\TrustManager" /v "iProtectedView" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\9.0\TrustManager" /v "bEnhancedSecurityInBrowser" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\9.0\TrustManager" /v "bEnhancedSecurityStandalone" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\10.0\TrustManager" /v "iProtectedView" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\10.0\TrustManager" /v "bEnhancedSecurityInBrowser" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\10.0\TrustManager" /v "bEnhancedSecurityStandalone" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\11.0\TrustManager" /v "iProtectedView" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\11.0\TrustManager" /v "bEnhancedSecurityInBrowser" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\11.0\TrustManager" /v "bEnhancedSecurityStandalone" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\DC\TrustManager" /v "iProtectedView" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\DC\TrustManager" /v "bEnhancedSecurityInBrowser" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\DC\TrustManager" /v "bEnhancedSecurityStandalone" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\XI\TrustManager" /v "iProtectedView" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\XI\TrustManager" /v "bEnhancedSecurityInBrowser" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\XI\TrustManager" /v "bEnhancedSecurityStandalone" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\7.0\Originals" /v "bAllowOpenFile" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\8.0\Originals" /v "bAllowOpenFile" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\9.0\Originals" /v "bAllowOpenFile" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\10.0\Originals" /v "bAllowOpenFile" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\11.0\Originals" /v "bAllowOpenFile" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\DC\Originals" /v "bAllowOpenFile" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\XI\Originals" /v "bAllowOpenFile" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\7.0\AVGeneral" /v "bCheckForUpdatesAtStartup" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\8.0\AVGeneral" /v "bCheckForUpdatesAtStartup" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\9.0\AVGeneral" /v "bCheckForUpdatesAtStartup" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\10.0\AVGeneral" /v "bCheckForUpdatesAtStartup" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\11.0\AVGeneral" /v "bCheckForUpdatesAtStartup" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\DC\AVGeneral" /v "bCheckForUpdatesAtStartup" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Adobe\Acrobat Reader\XI\AVGeneral" /v "bCheckForUpdatesAtStartup" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\12.0\Excel\Security" /v "VBAWarnings" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\12.0\Excel\Security" /v "WorkbookLinkWarnings" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\12.0\Excel\Security" /v "PackagerPrompt" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\12.0\PowerPoint\Security" /v "VBAWarnings" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\12.0\PowerPoint\Security" /v "PackagerPrompt" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\12.0\Word\Security" /v "VBAWarnings" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\12.0\Word\Security" /v "PackagerPrompt" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\14.0\Excel\Security" /v "VBAWarnings" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\14.0\Excel\Security" /v "WorkbookLinkWarnings" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\14.0\Excel\Security" /v "PackagerPrompt" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\14.0\PowerPoint\Security" /v "VBAWarnings" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\14.0\PowerPoint\Security" /v "PackagerPrompt" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\14.0\Word\Security" /v "VBAWarnings" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\14.0\Word\Security" /v "PackagerPrompt" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\15.0\Excel\Security" /v "VBAWarnings" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\15.0\Excel\Security" /v "WorkbookLinkWarnings" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\15.0\Excel\Security" /v "PackagerPrompt" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\15.0\PowerPoint\Security" /v "VBAWarnings" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\15.0\PowerPoint\Security" /v "PackagerPrompt" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\15.0\Word\Security" /v "VBAWarnings" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\15.0\Word\Security" /v "PackagerPrompt" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\16.0\Excel\Security" /v "VBAWarnings" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\16.0\Excel\Security" /v "WorkbookLinkWarnings" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\16.0\Excel\Security" /v "PackagerPrompt" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\16.0\PowerPoint\Security" /v "VBAWarnings" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\16.0\PowerPoint\Security" /v "PackagerPrompt" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\16.0\Word\Security" /v "VBAWarnings" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\16.0\Word\Security" /v "PackagerPrompt" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\12.0\Excel\Options" /v "DontUpdateLinks" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\12.0\Excel\Options" /v "DDEAllowed" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\12.0\Excel\Options" /v "DDECleaned" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\12.0\PowerPoint\Options" /v "DontUpdateLinks" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\12.0\Word\Options" /v "DontUpdateLinks" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\14.0\Excel\Options" /v "DontUpdateLinks" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\14.0\Excel\Options" /v "DDEAllowed" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\14.0\Excel\Options" /v "DDECleaned" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\14.0\PowerPoint\Options" /v "DontUpdateLinks" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\14.0\Word\Options" /v "DontUpdateLinks" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\15.0\Excel\Options" /v "DontUpdateLinks" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\15.0\Excel\Options" /v "DDEAllowed" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\15.0\Excel\Options" /v "DDECleaned" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\15.0\PowerPoint\Options" /v "DontUpdateLinks" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\15.0\Word\Options" /v "DontUpdateLinks" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\16.0\Excel\Options" /v "DontUpdateLinks" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\16.0\Excel\Options" /v "DDEAllowed" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\16.0\Excel\Options" /v "DDECleaned" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\16.0\PowerPoint\Options" /v "DontUpdateLinks" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\16.0\Word\Options" /v "DontUpdateLinks" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\12.0\Word\Options\WordMail" /v "DontUpdateLinks" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\14.0\Word\Options\WordMail" /v "DontUpdateLinks" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\15.0\Word\Options\WordMail" /v "DontUpdateLinks" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\16.0\Word\Options\WordMail" /v "DontUpdateLinks" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Microsoft\Office\Common\Security" /v "DisableAllActiveX" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Kingsoft\Office\6.0\wpp\Application Settings" /v "VbaSecurityLevel" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Foxit Software\Foxit Reader 6.0\Preferences\Others" /v "bEnableJS" /t REG_SZ /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Foxit Software\Foxit Reader 7.0\Preferences\Others" /v "bEnableJS" /t REG_SZ /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Foxit Software\Foxit Reader 8.0\Preferences\Others" /v "bEnableJS" /t REG_SZ /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Foxit Software\Foxit Reader 9.0\Preferences\Others" /v "bEnableJS" /t REG_SZ /d "0" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Foxit Software\Foxit Reader 6.0\Preferences\Trust Manager" /v "iProtectedView" /t REG_SZ /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Foxit Software\Foxit Reader 6.0\Preferences\Trust Manager" /v "bSafeMode" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Foxit Software\Foxit Reader 7.0\Preferences\Trust Manager" /v "iProtectedView" /t REG_SZ /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Foxit Software\Foxit Reader 7.0\Preferences\Trust Manager" /v "bSafeMode" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Foxit Software\Foxit Reader 8.0\Preferences\Trust Manager" /v "iProtectedView" /t REG_SZ /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Foxit Software\Foxit Reader 8.0\Preferences\Trust Manager" /v "bSafeMode" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Foxit Software\Foxit Reader 9.0\Preferences\Trust Manager" /v "iProtectedView" /t REG_SZ /d "2" /f
Echo Y | Reg.exe add "HKCU\SOFTWARE\Foxit Software\Foxit Reader 9.0\Preferences\Trust Manager" /v "bSafeMode" /t REG_SZ /d "1" /f
REM ; Ghost spectre user policy
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
Echo Y | Reg.exe add "HKCU\SOFTWARE\Policies\Power" /f
REM ; Ghost spectre machine policy
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
REM ; SSRP
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer" /f
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2" /f
REM ; Ifeo
Reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /f
REM ; PAC file
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "EnableLegacyAutoProxyFeature" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "AutoConfigURL" /t REG_SZ /d "https://www.proxynova.com/proxy.pac" /f
REM ; Dnscache service configuration
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "EnableAutoDoh" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxCacheTtl" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxNegativeCacheTtl" /t REG_DWORD /d "0" /f
REM ; Exit
exit /b
