@Echo Off
Title GSecurity & Color 0B
cd %systemroot%\system32
call :IsAdmin

REM ; Make current folder active one
pushd %~dp0
REM ; Remove user account
net user defaultuser0 /delete
REM ; Take ownership of desktop
takeown /F "%SystemDrive%\Users\Public\Desktop" /r /d y
icacls "%SystemDrive%\Users\Public\Desktop" /grant:r %username%:(OI)(CI)F /t /l /q /c
takeown /F "%USERPROFILE%\Desktop" /r /d y
icacls "%USERPROFILE%\Desktop" /grant:r %username%:(OI)(CI)F /t /l /q /c
REM ; Debloat
powershell -command "Get-AppxPackage -AllUsers | where-object {$_.name -notlike '*Store*' } | where-object {$_.name -notlike '*Calc*' } | where-object {$_.name -notlike '*Nvidia*' } | where-object {$_.name -notlike '*Realtek*' } | where-object {$_.name -notlike '*shell*' } | Remove-AppxPackage"
powershell -command "Get-ProvisionedAppxPackage -Online | where-object {$_.name -notlike '*Store*' } | where-object {$_.name -notlike '*Calc*' } | where-object {$_.name -notlike '*Nvidia*' } | where-object {$_.name -notlike '*Realtek*' } | where-object {$_.name -notlike '*shell*' } | Remove-ProvisionedAppxPackage -Online"
REM ; Routes (privacy)
route -p add 204.79.197.200/32 0.0.0.0
route -p add 23.218.212.69/32 0.0.0.0
route -p add 204.160.124.125/32 0.0.0.0
route -p add 8.253.14.126/32 0.0.0.0
route -p add 8.254.25.126/32 0.0.0.0
route -p add 93.184.215.200/32 0.0.0.0
route -p add 198.78.194.252/32 0.0.0.0
route -p add 198.78.209.253/32 0.0.0.0
route -p add 8.254.23.254/32 0.0.0.0
route -p add 131.253.14.76/32 0.0.0.0
route -p add 23.201.58.73/32 0.0.0.0
route -p add 204.160.124.125/32 0.0.0.0
route -p add 8.253.14.126/32 0.0.0.0
route -p add 8.254.25.126/32 0.0.0.0
route -p add 191.236.16.12/32 0.0.0.0
route -p add 157.56.91.82/32 0.0.0.0
route -p add 23.61.72.70/32 0.0.0.0
route -p add 204.160.124.125/32 0.0.0.0
route -p add 8.253.14.126/32 0.0.0.0
route -p add 8.254.25.126/32 0.0.0.0
route -p add 93.184.215.200/32 0.0.0.0
route -p add 65.52.100.7/32 0.0.0.0
route -p add 207.46.202.114/32 0.0.0.0
route -p add 65.55.252.63/32 0.0.0.0
route -p add 65.55.252.63/32 0.0.0.0
route -p add 204.79.197.200/32 0.0.0.0
route -p add 65.52.100.91/32 0.0.0.0
route -p add 104.79.156.195/32 0.0.0.0
route -p add 65.52.100.92/32 0.0.0.0
route -p add 65.55.44.108/32 0.0.0.0
route -p add 157.56.106.210/32 0.0.0.0
route -p add 168.62.11.145/32 0.0.0.0
route -p add 23.96.212.225/32 0.0.0.0
route -p add 23.96.212.225/32 0.0.0.0
route -p add 65.52.100.94/32 0.0.0.0
route -p add 65.55.252.93/32 0.0.0.0
route -p add 65.55.252.93/32 0.0.0.0
route -p add 134.170.115.60/32 0.0.0.0
route -p add 207.46.114.61/32 0.0.0.0
route -p add 65.52.108.153/32 0.0.0.0
route -p add 64.4.54.22/32 0.0.0.0
route -p add 104.79.153.53/32 0.0.0.0
route -p add 65.55.252.92/32 0.0.0.0
route -p add 65.55.252.92/32 0.0.0.0
route -p add 168.62.187.13/32 0.0.0.0
route -p add 65.52.100.9/32 0.0.0.0
route -p add 131.253.40.37/32 0.0.0.0
route -p add 64.4.54.254/32 0.0.0.0
route -p add 64.4.54.32/32 0.0.0.0
route -p add 64.4.54.254/32 0.0.0.0
route -p add 207.46.223.94/32 0.0.0.0
route -p add 65.55.252.71/32 0.0.0.0
route -p add 65.52.100.11/32 0.0.0.0
route -p add 65.52.108.29/32 0.0.0.0
route -p add 65.52.108.29/32 0.0.0.0
route -p add 65.52.100.93/32 0.0.0.0
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
REM ; Admin
net user administrator /active:yes
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
REM ; Display Scaling
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "Win8DpiScaling" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\Control Panel\Desktop" /v "LogPixels" /t REG_DWORD /d "96" /f
REM ; Firewall rules deletion
Reg.exe delete "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Defaults\FirewallPolicy\FirewallRules" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Defaults\FirewallPolicy\FirewallRules" /f
Reg.exe delete "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\AppIso\FirewallRules" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\AppIso\FirewallRules" /f
Reg.exe delete "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Configurable\System" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Configurable\System" /f
Reg.exe delete "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\System" /f
Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\System" /f
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /f
REM ; Firewall settings
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
REM ; Ifeo
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dllhost.exe" /v "Debugger" /t REG_SZ /d "svchost.exe" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\filesyncconfig.exe" /v "Debugger" /t REG_SZ /d "svchost.exe" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ftp.exe" /v "Debugger" /t REG_SZ /d "svchost.exe" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\hh.exe" /v "Debugger" /t REG_SZ /d "svchost.exe" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\livecomm.exe" /v "Debugger" /t REG_SZ /d "svchost.exe" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ngen.exe" /v "Debugger" /t REG_SZ /d "svchost.exe" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\rasphone.exe" /v "Debugger" /t REG_SZ /d "svchost.exe" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskhostw.exe" /v "Debugger" /t REG_SZ /d "svchost.exe" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wbemtest.exe" /v "Debugger" /t REG_SZ /d "svchost.exe" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wmiadap.exe" /v "Debugger" /t REG_SZ /d "svchost.exe" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wmiprvse.exe" /v "Debugger" /t REG_SZ /d "svchost.exe" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wuauclt.exe" /v "Debugger" /t REG_SZ /d "svchost.exe" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wudfhost.exe" /v "Debugger" /t REG_SZ /d "svchost.exe" /f
REM ; Machine Policy
Echo Y | Reg.exe add "HKLM\software\Adobe\Adobe Acrobat\2015\Installer" /v "DisableMaintenance" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\Adobe\Adobe Acrobat\DC\Installer" /v "DisableMaintenance" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\Classes\batfile\shell\runasuser" /v "SuppressionPolicy" /t REG_DWORD /d "4096" /f
Echo Y | Reg.exe add "HKLM\software\Classes\cmdfile\shell\runasuser" /v "SuppressionPolicy" /t REG_DWORD /d "4096" /f
Echo Y | Reg.exe add "HKLM\software\Classes\exefile\shell\runasuser" /v "SuppressionPolicy" /t REG_DWORD /d "4096" /f
Echo Y | Reg.exe add "HKLM\software\Classes\mscfile\shell\runasuser" /v "SuppressionPolicy" /t REG_DWORD /d "4096" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management" /v "excel.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management" /v "exprwd.exe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management" /v "groove.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management" /v "msaccess.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management" /v "mse7.exe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management" /v "mspub.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management" /v "onenote.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management" /v "outlook.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management" /v "powerpnt.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management" /v "pptview.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management" /v "spdesign.exe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management" /v "visio.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management" /v "winproj.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management" /v "winword.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable" /v "excel.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable" /v "exprwd.exe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable" /v "groove.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable" /v "msaccess.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable" /v "mse7.exe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable" /v "mspub.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable" /v "onenote.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable" /v "outlook.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable" /v "powerpnt.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable" /v "pptview.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable" /v "spdesign.exe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable" /v "visio.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable" /v "winproj.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable" /v "winword.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown" /v "excel.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown" /v "exprwd.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown" /v "groove.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown" /v "msaccess.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown" /v "mse7.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown" /v "mspub.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown" /v "onenote.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown" /v "outlook.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown" /v "powerpnt.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown" /v "pptview.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown" /v "spdesign.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown" /v "visio.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown" /v "winproj.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown" /v "winword.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling" /v "excel.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling" /v "exprwd.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling" /v "groove.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling" /v "msaccess.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling" /v "mse7.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling" /v "mspub.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling" /v "onenote.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling" /v "outlook.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling" /v "powerpnt.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling" /v "pptview.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling" /v "spdesign.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling" /v "visio.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling" /v "winproj.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling" /v "winword.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing" /v "excel.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing" /v "exprwd.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing" /v "groove.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing" /v "msaccess.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing" /v "mse7.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing" /v "mspub.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing" /v "onenote.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing" /v "outlook.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing" /v "powerpnt.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing" /v "pptview.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing" /v "spdesign.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing" /v "visio.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing" /v "winproj.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing" /v "winword.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching" /v "excel.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching" /v "exprwd.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching" /v "groove.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching" /v "msaccess.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching" /v "mse7.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching" /v "mspub.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching" /v "onenote.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching" /v "outlook.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching" /v "powerpnt.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching" /v "pptview.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching" /v "spdesign.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching" /v "visio.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching" /v "winproj.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching" /v "winword.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall" /v "excel.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall" /v "exprwd.exe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall" /v "groove.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall" /v "msaccess.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall" /v "mse7.exe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall" /v "mspub.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall" /v "onenote.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall" /v "outlook.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall" /v "powerpnt.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall" /v "pptview.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall" /v "spdesign.exe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall" /v "visio.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall" /v "winproj.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall" /v "winword.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload" /v "excel.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload" /v "exprwd.exe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload" /v "groove.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload" /v "msaccess.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload" /v "mse7.exe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload" /v "mspub.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload" /v "onenote.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload" /v "outlook.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload" /v "powerpnt.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload" /v "pptview.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload" /v "spdesign.exe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload" /v "visio.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload" /v "winproj.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload" /v "winword.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "excel.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "exprwd.exe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "groove.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "msaccess.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "mse7.exe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "mspub.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "onenote.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "outlook.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "powerpnt.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "pptview.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "spdesign.exe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "visio.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "winproj.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "winword.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_securityband" /v "excel.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_securityband" /v "exprwd.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_securityband" /v "groove.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_securityband" /v "msaccess.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_securityband" /v "mse7.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_securityband" /v "mspub.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_securityband" /v "onenote.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_securityband" /v "outlook.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_securityband" /v "powerpnt.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_securityband" /v "pptview.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_securityband" /v "spdesign.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_securityband" /v "visio.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_securityband" /v "winproj.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_securityband" /v "winword.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck" /v "excel.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck" /v "exprwd.exe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck" /v "groove.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck" /v "msaccess.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck" /v "mse7.exe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck" /v "mspub.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck" /v "onenote.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck" /v "outlook.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck" /v "powerpnt.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck" /v "pptview.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck" /v "spdesign.exe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck" /v "visio.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck" /v "winproj.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck" /v "winword.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url" /v "excel.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url" /v "exprwd.exe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url" /v "groove.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url" /v "msaccess.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url" /v "mse7.exe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url" /v "mspub.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url" /v "onenote.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url" /v "outlook.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url" /v "powerpnt.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url" /v "pptview.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url" /v "spdesign.exe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url" /v "visio.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url" /v "winproj.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url" /v "winword.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement" /v "excel.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement" /v "exprwd.exe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement" /v "groove.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement" /v "msaccess.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement" /v "mse7.exe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement" /v "mspub.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement" /v "onenote.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement" /v "outlook.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement" /v "powerpnt.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement" /v "pptview.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement" /v "spdesign.exe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement" /v "visio.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement" /v "winproj.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement" /v "winword.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions" /v "excel.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions" /v "exprwd.exe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions" /v "groove.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions" /v "msaccess.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions" /v "mse7.exe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions" /v "mspub.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions" /v "onenote.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions" /v "outlook.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions" /v "powerpnt.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions" /v "pptview.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions" /v "spdesign.exe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions" /v "visio.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions" /v "winproj.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions" /v "winword.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation" /v "excel.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation" /v "exprwd.exe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation" /v "groove.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation" /v "msaccess.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation" /v "mse7.exe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation" /v "mspub.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation" /v "onenote.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation" /v "outlook.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation" /v "powerpnt.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation" /v "pptview.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation" /v "spdesign.exe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation" /v "visio.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation" /v "winproj.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation" /v "winword.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}" /v "ActivationFilterOverride" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}" /v "Compatibility Flags" /t REG_DWORD /d "1024" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}" /v "ActivationFilterOverride" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}" /v "Compatibility Flags" /t REG_DWORD /d "1024" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\Office\Common\COM Compatibility" /v "Comment" /t REG_SZ /d "Block all Flash activation" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}" /v "ActivationFilterOverride" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}" /v "Compatibility Flags" /t REG_DWORD /d "1024" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}" /v "ActivationFilterOverride" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}" /v "Compatibility Flags" /t REG_DWORD /d "1024" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\wcmsvc\wifinetworkmanager\config" /v "AutoConnectAllowedOEM" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\Windows NT\CurrentVersion\Winlogon" /v "AutoAdminLogon" /t REG_SZ /d "0" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\Windows NT\CurrentVersion\Winlogon" /v "ScreenSaverGracePeriod" /t REG_SZ /d "5" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\Windows\CurrentVersion\Policies\CredUI" /v "EnumerateAdministrators" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d "255" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoOnlinePrintsWizard" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoStartBanner" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoWebServices" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\Windows\CurrentVersion\Policies\Explorer" /v "PreXPSP2ShellProtocolBehavior" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\Windows\CurrentVersion\Policies\Ext" /v "RunThisTimeEnabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\Windows\CurrentVersion\Policies\Ext" /v "VersionCheckEnabled" /t REG_DWORD /d "1" /f
Reg.exe delete "HKLM\software\microsoft\windows\currentversion\policies\servicing" /v "repaircontentserversource" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\windows\currentversion\policies\servicing" /v "LocalSourcePath" /t REG_EXPAND_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\windows\currentversion\policies\servicing" /v "UseWindowsUpdate" /t REG_DWORD /d "2" /f
Reg.exe delete "HKLM\software\microsoft\windows\currentversion\policies\system" /v "disablebkgndgrouppolicy" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\windows\currentversion\policies\system" /v "DisableAutomaticRestartSignOn" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\windows\currentversion\policies\system" /v "LocalAccountTokenFilterPolicy" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\windows\currentversion\policies\system" /v "LogonType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\windows\currentversion\policies\system" /v "MSAOptional" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\Windows\CurrentVersion\Policies\System\Audit" /v "ProcessCreationIncludeCmdLine_Enabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" /v "AllowEncryptionOracle" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\Adobe\Adobe Acrobat\2015\FeatureLockdown" /v "bDisablePDFHandlerSwitching" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\Adobe\Adobe Acrobat\2015\FeatureLockdown" /v "bDisableTrustedFolders" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\Adobe\Adobe Acrobat\2015\FeatureLockdown" /v "bDisableTrustedSites" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\Adobe\Adobe Acrobat\2015\FeatureLockdown" /v "bEnableFlash" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\Adobe\Adobe Acrobat\2015\FeatureLockdown" /v "bEnhancedSecurityInBrowser" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\Adobe\Adobe Acrobat\2015\FeatureLockdown" /v "bEnhancedSecurityStandalone" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\Adobe\Adobe Acrobat\2015\FeatureLockdown" /v "bProtectedMode" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\Adobe\Adobe Acrobat\2015\FeatureLockdown" /v "iFileAttachmentPerms" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\Adobe\Adobe Acrobat\2015\FeatureLockdown" /v "iProtectedView" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\software\policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\cCloud" /v "bAdobeSendPluginToggle" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\cCloud" /v "bDisableADCFileStore" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\cDefaultLaunchURLPerms" /v "iUnknownURLPerms" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\cDefaultLaunchURLPerms" /v "iURLPerms" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\cServices" /v "bTogglePrefsSync" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\cServices" /v "bToggleWebConnectors" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\cSharePoint" /v "bDisableSharePointFeatures" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\cWebmailProfiles" /v "bDisableWebmail" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\Adobe\Adobe Acrobat\2015\FeatureLockdown\cWelcomeScreen" /v "bShowWelcomeScreen" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\Adobe\Adobe Acrobat\DC\FeatureLockdown" /v "bDisablePDFHandlerSwitching" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\Adobe\Adobe Acrobat\DC\FeatureLockdown" /v "bDisableTrustedFolders" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\Adobe\Adobe Acrobat\DC\FeatureLockdown" /v "bDisableTrustedSites" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\Adobe\Adobe Acrobat\DC\FeatureLockdown" /v "bEnableFlash" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\Adobe\Adobe Acrobat\DC\FeatureLockdown" /v "bEnhancedSecurityInBrowser" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\Adobe\Adobe Acrobat\DC\FeatureLockdown" /v "bEnhancedSecurityStandalone" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\Adobe\Adobe Acrobat\DC\FeatureLockdown" /v "bProtectedMode" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\Adobe\Adobe Acrobat\DC\FeatureLockdown" /v "iFileAttachmentPerms" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\Adobe\Adobe Acrobat\DC\FeatureLockdown" /v "iProtectedView" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\software\policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cCloud" /v "bAdobeSendPluginToggle" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cCloud" /v "bDisableADCFileStore" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cDefaultLaunchURLPerms" /v "iUnknownURLPerms" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cDefaultLaunchURLPerms" /v "iURLPerms" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cServices" /v "bTogglePrefsSync" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cServices" /v "bToggleWebConnectors" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cSharePoint" /v "bDisableSharePointFeatures" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cWebmailProfiles" /v "bDisableWebmail" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\Adobe\Adobe Acrobat\DC\FeatureLockdown\cWelcomeScreen" /v "bShowWelcomeScreen" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\Microsoft Services\AdmPwd" /v "AdmPwdEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Biometrics" /v "Enabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Biometrics\FacialFeatures" /v "EnhancedAntiSpoofing" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Control Panel\International" /v "BlockUserInputMethodsForSignIn" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Cryptography\Configuration\SSL\00010002" /v "EccCurves" /t REG_MULTI_SZ /d "NistP384\0NistP256" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\7-Zip\7z.exe" /t REG_SZ /d "-EAF" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\7-Zip\7zFM.exe" /t REG_SZ /d "-EAF" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\7-Zip\7zG.exe" /t REG_SZ /d "-EAF" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\Adobe\*\Reader\AcroRd32.exe" /t REG_SZ /d "+EAF+ eaf_modules:AcroRd32.dll;Acrofx32.dll;AcroForm.api" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\Adobe\Acrobat*\Acrobat\Acrobat.exe" /t REG_SZ /d "+EAF+ eaf_modules:AcroRd32.dll;Acrofx32.dll;AcroForm.api" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\Adobe\Adobe Photoshop CS*\Photoshop.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\Foxit Reader\Foxit Reader.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\Google\Chrome\Application\chrome.exe" /t REG_SZ /d "+EAF+ eaf_modules:chrome_child.dll" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\Google\Google Talk\googletalk.exe" /t REG_SZ /d "-DEP" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\Internet Explorer\iexplore.exe" /t REG_SZ /d "+EAF+ eaf_modules:mshtml.dll;flash*.ocx;jscript*.dll;vbscript.dll;vgx.dll +ASR asr_modules:npjpi*.dll;jp2iexp.dll;vgx.dll;msxml4*.dll;wshom.ocx;scrrun.dll;vbscript.dll asr_zones:1;2" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\iTunes\iTunes.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\Java\jre*\bin\java.exe" /t REG_SZ /d "-HeapSpray" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\Java\jre*\bin\javaw.exe" /t REG_SZ /d "-HeapSpray" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\Java\jre*\bin\javaws.exe" /t REG_SZ /d "-HeapSpray" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\Microsoft Lync\communicator.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\mIRC\mirc.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\Mozilla Firefox\firefox.exe" /t REG_SZ /d "+EAF+ eaf_modules:mozjs.dll;xul.dll" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\Mozilla Firefox\plugin-container.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\Mozilla Thunderbird\plugin-container.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\Mozilla Thunderbird\thunderbird.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\OFFICE1*\EXCEL.EXE" /t REG_SZ /d "+ASR asr_modules:flash*.ocx" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\OFFICE1*\INFOPATH.EXE" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\OFFICE1*\LYNC.EXE" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\OFFICE1*\MSACCESS.EXE" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\OFFICE1*\MSPUB.EXE" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\OFFICE1*\OIS.EXE" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\OFFICE1*\OUTLOOK.EXE" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\OFFICE1*\POWERPNT.EXE" /t REG_SZ /d "+ASR asr_modules:flash*.ocx" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\OFFICE1*\PPTVIEW.EXE" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\OFFICE1*\VISIO.EXE" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\OFFICE1*\VPREVIEW.EXE" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\OFFICE1*\WINWORD.EXE" /t REG_SZ /d "+ASR asr_modules:flash*.ocx" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\Opera\*\opera.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\Opera\opera.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\Pidgin\pidgin.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\QuickTime\QuickTimePlayer.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\Real\RealPlayer\realconverter.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\Real\RealPlayer\realplay.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\Safari\Safari.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\SkyDrive\SkyDrive.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\Skype\Phone\Skype.exe" /t REG_SZ /d "-EAF" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\VideoLAN\VLC\vlc.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\Winamp\winamp.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\Windows Live\Mail\wlmail.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\Windows Live\Photo Gallery\WLXPhotoGallery.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\Windows Live\Writer\WindowsLiveWriter.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\Windows Media Player\wmplayer.exe" /t REG_SZ /d "-EAF -MandatoryASLR" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\Windows NT\Accessories\wordpad.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\WinRAR\rar.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\WinRAR\unrar.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\WinRAR\winrar.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\WinZip\winzip32.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\Defaults" /v "*\WinZip\winzip64.exe" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\SysSettings" /v "ASLR" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\SysSettings" /v "DEP" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EMET\SysSettings" /v "SEHOP" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\EventViewer" /v "MicrosoftEventVwrDisableLinks" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\FVE" /v "DisableExternalDMAUnderLock" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\FVE" /v "EnableBDEWithNoTPM" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\FVE" /v "MinimumPIN" /t REG_DWORD /d "6" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\FVE" /v "UseAdvancedStartup" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\FVE" /v "UseEnhancedPin" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\FVE" /v "UseTPM" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\FVE" /v "UseTPMKey" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\FVE" /v "UseTPMKeyPIN" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\FVE" /v "UseTPMPIN" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\Control Panel" /v "History" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\Download" /v "CheckExeSignatures" /t REG_SZ /d "yes" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\Download" /v "RunInvalidSignatures" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\Feeds" /v "AllowBasicAuthInClear" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\Feeds" /v "DisableEnclosureDownload" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\IEDevTools" /v "Disabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\main" /v "DisableEPMCompat" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\main" /v "Isolation" /t REG_SZ /d "PMEM" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\main" /v "Isolation64Bit" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_DISABLE_MK_PROTOCOL" /v "(Reserved)" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_DISABLE_MK_PROTOCOL" /v "explorer.exe" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_DISABLE_MK_PROTOCOL" /v "iexplore.exe" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_MIME_HANDLING" /v "(Reserved)" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_MIME_HANDLING" /v "explorer.exe" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_MIME_HANDLING" /v "iexplore.exe" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_MIME_SNIFFING" /v "(Reserved)" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_MIME_SNIFFING" /v "explorer.exe" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_MIME_SNIFFING" /v "iexplore.exe" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_ACTIVEXINSTALL" /v "(Reserved)" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_ACTIVEXINSTALL" /v "explorer.exe" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_ACTIVEXINSTALL" /v "iexplore.exe" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_FILEDOWNLOAD" /v "(Reserved)" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_FILEDOWNLOAD" /v "explorer.exe" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_FILEDOWNLOAD" /v "iexplore.exe" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE" /v "excel.exe" /t REG_DWORD /d "69632" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE" /v "msaccess.exe" /t REG_DWORD /d "69632" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE" /v "mspub.exe" /t REG_DWORD /d "69632" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE" /v "onenote.exe" /t REG_DWORD /d "69632" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE" /v "outlook.exe" /t REG_DWORD /d "69632" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE" /v "powerpnt.exe" /t REG_DWORD /d "69632" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE" /v "visio.exe" /t REG_DWORD /d "69632" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE" /v "winproj.exe" /t REG_DWORD /d "69632" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_RESTRICT_LEGACY_JSCRIPT_PER_SECURITY_ZONE" /v "winword.exe" /t REG_DWORD /d "69632" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_SECURITYBAND" /v "(Reserved)" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_SECURITYBAND" /v "explorer.exe" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_SECURITYBAND" /v "iexplore.exe" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_WINDOW_RESTRICTIONS" /v "(Reserved)" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_WINDOW_RESTRICTIONS" /v "explorer.exe" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_WINDOW_RESTRICTIONS" /v "iexplore.exe" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_ZONE_ELEVATION" /v "(Reserved)" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_ZONE_ELEVATION" /v "explorer.exe" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\main\featurecontrol\FEATURE_ZONE_ELEVATION" /v "iexplore.exe" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\PhishingFilter" /v "PreventOverride" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\PhishingFilter" /v "PreventOverrideAppRepUnknown" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\Privacy" /v "CleanHistory" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\Privacy" /v "ClearBrowsingHistoryOnExit" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\Privacy" /v "EnableInPrivateBrowsing" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\Restrictions" /v "NoCrashDetection" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\Security" /v "DisableSecuritySettingsCheck" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\internet explorer\Security\ActiveX" /v "BlockNonAdminActiveXInstall" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\MicrosoftEdge\Internet Settings" /v "PreventCertErrorOverrides" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\MicrosoftEdge\Main" /v "FormSuggest Passwords" /t REG_SZ /d "no" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\MicrosoftEdge\PhishingFilter" /v "PreventOverride" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\MicrosoftEdge\PhishingFilter" /v "PreventOverrideAppRepUnknown" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\office\15.0\common\officeupdate" /v "enableautomaticupdates" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\office\15.0\common\officeupdate" /v "hideenabledisableupdates" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\office\15.0\infopath\security" /v "aptca_allowlist" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\office\15.0\lync" /v "disablehttpconnect" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\office\15.0\lync" /v "enablesiphighsecuritymode" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\office\15.0\lync" /v "savepassword" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\office\16.0\lync" /v "disablehttpconnect" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\office\16.0\lync" /v "enablesiphighsecuritymode" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\office\16.0\lync" /v "savepassword" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\OneDrive\AllowTenantList" /v "1111-2222-3333-4444" /t REG_SZ /d "1111-2222-3333-4444" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\PassportForWork" /v "RequireSecurityDevice" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\PassportForWork\ExcludeSecurityDevices" /v "TPM12" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\PassportForWork\PINComplexity" /v "MinimumPINLength" /t REG_DWORD /d "6" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Peernet" /v "Disabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v "ACSettingIndex" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v "DCSettingIndex" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\TabletTip\1.7" /v "PasswordSecurity" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\TabletTip\1.7" /v "PasswordSecurityState" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows Defender ExploitGuard\Exploit Protection" /v "ExploitProtectionSettings" /t REG_SZ /d "\\YOURSHAREHERE\EP.XML" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows Defender" /v "PUAProtection" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows Defender\Exclusions" /v "DisableAutoExclusions" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows Defender\MpEngine" /v "MpCloudBlockLevel" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows Defender\Scan" /v "DisableEmailScanning" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows Defender\Scan" /v "DisableRemovableDriveScanning" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows Defender\Scan" /v "ScheduleDay" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows Defender\Signature Updates" /v "ASSignatureDue" /t REG_DWORD /d "7" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows Defender\Signature Updates" /v "AVSignatureDue" /t REG_DWORD /d "7" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows Defender\Signature Updates" /v "ScheduleDay" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows Defender\Spynet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows Defender\Spynet" /v "SpynetReporting" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows Defender\Threats" /v "Threats_ThreatSeverityDefaultAction" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "1" /t REG_SZ /d "2" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "2" /t REG_SZ /d "2" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "4" /t REG_SZ /d "2" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "5" /t REG_SZ /d "2" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" /v "ExploitGuard_ASR_Rules" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "26190899-1602-49e8-8b27-eb1d0a1ce869" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "3B576869-A4EC-4529-8536-B80A7769E899" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "c1db55ab-c21a-4637-bb3f-a12568109d35" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "D3E037E1-3EB8-44C8-A917-57927947596D" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v "e6db77e5-3df2-4cf1-b95a-636979351e5b" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" /v "EnableNetworkProtection" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows NT\DNSClient" /v "EnableMulticast" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows NT\Printers" /v "DisableHTTPPrinting" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows NT\Printers" /v "DisableWebPnPDownload" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows NT\Printers" /v "DoNotInstallCompatibleDriverFromWindowsUpdate" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows NT\Printers" /v "RegisterSpoolerRemoteRpcEndPoint" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows NT\Printers\PointAndPrint" /v "InForest" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows NT\Printers\PointAndPrint" /v "NoWarningNoElevationOnInstall" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows NT\Printers\PointAndPrint" /v "Restricted" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows NT\Printers\PointAndPrint" /v "ServerList" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows NT\Printers\PointAndPrint" /v "TrustedServers" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows NT\Printers\PointAndPrint" /v "UpdatePromptSettings" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows NT\Rpc" /v "RestrictRemoteClients" /t REG_DWORD /d "1" /f
Reg.exe delete "HKLM\software\policies\microsoft\windows nt\terminal services" /v "fallowfullcontrol" /f
Reg.exe delete "HKLM\software\policies\microsoft\windows nt\terminal services" /v "fallowunsolicitedfullcontrol" /f
Reg.exe delete "HKLM\software\policies\microsoft\windows nt\terminal services" /v "fusemailto" /f
Reg.exe delete "HKLM\software\policies\microsoft\windows nt\terminal services" /v "maxticketexpiry" /f
Reg.exe delete "HKLM\software\policies\microsoft\windows nt\terminal services" /v "maxticketexpiryunits" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\windows nt\terminal services" /v "DeleteTempDirsOnExit" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\windows nt\terminal services" /v "DisablePasswordSaving" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\windows nt\terminal services" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\windows nt\terminal services" /v "fAllowUnsolicited" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\windows nt\terminal services" /v "fDenyTSConnections" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\windows nt\terminal services" /v "fDisableCcm" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\windows nt\terminal services" /v "fDisableCdm" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\windows nt\terminal services" /v "fDisableLPT" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\windows nt\terminal services" /v "fDisablePNPRedir" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\windows nt\terminal services" /v "fEnableSmartCard" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\windows nt\terminal services" /v "fEncryptRPCTraffic" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\windows nt\terminal services" /v "fPromptForPassword" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\windows nt\terminal services" /v "LoggingEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\windows nt\terminal services" /v "MinEncryptionLevel" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\windows nt\terminal services" /v "PerSessionTempDir" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\windows nt\terminal services" /v "RedirectOnlyDefaultClientPrinter" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\windows nt\terminal services" /v "ShareControlMessage" /t REG_SZ /d "You are about to allow other personnel to remotely control your system. You must monitor the activity until the session is closed." /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\windows nt\terminal services" /v "UseCustomMessages" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\windows nt\terminal services" /v "ViewMessage" /t REG_SZ /d "You are about to allow other personnel to remotely connect to your system. Sensitive data should not be displayed during this session." /f
Reg.exe delete "HKLM\software\policies\microsoft\windows nt\terminal services\raunsolicit" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\AppCompat" /v "DisablePcaUI" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\AppPrivacy" /v "LetAppsActivateWithVoiceAboveLock" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\Appx" /v "AllowAllTrustedApps" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\AxInstaller" /v "OnlyUseAXISForActiveXInstall" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CredentialsDelegation" /v "AllowProtectedCreds" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CredUI" /v "DisablePasswordReveal" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings" /v "CertificateRevocation" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings" /v "EnableSSL3Fallback" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings" /v "PreventIgnoreCertErrors" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings" /v "SecureProtocols" /t REG_DWORD /d "2560" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings" /v "Security_HKLM_only" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings" /v "Security_options_edit" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings" /v "Security_zones_map_edit" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings" /v "WarnOnBadCertRecving" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0" /v "1C00" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1" /v "1C00" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2" /v "1C00" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\3" /v "2301" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4" /v "1C00" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4" /v "2301" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Url History" /v "DaysToKeep" /t REG_DWORD /d "40" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap" /v "UNCAsIntranet" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" /v "1C00" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" /v "270C" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" /v "1201" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" /v "1C00" /t REG_DWORD /d "65536" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" /v "270C" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" /v "1201" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" /v "1C00" /t REG_DWORD /d "65536" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" /v "270C" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1001" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1004" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1201" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1206" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1209" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "120b" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "120c" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1406" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1407" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1409" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "140C" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1606" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1607" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "160A" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1802" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1804" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1806" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1809" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1A00" /t REG_DWORD /d "65536" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1C00" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2001" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2004" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2101" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2102" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2103" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2200" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2301" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2402" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2500" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2708" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2709" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "270C" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1001" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1004" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1200" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1201" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1206" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1209" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "120b" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "120c" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1400" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1402" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1405" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1406" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1407" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1409" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "140C" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1606" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1607" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1608" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "160A" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1802" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1803" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1804" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1806" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1809" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1A00" /t REG_DWORD /d "196608" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "1C00" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "2000" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "2001" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "2004" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "2101" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "2102" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "2103" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "2200" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "2301" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "2402" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "2500" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "2708" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "2709" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\CurrentVersion\Internet Settings\Zones\4" /v "270C" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\DataCollection" /v "LimitEnhancedDiagnosticDataWindowsAnalytics" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\DeviceGuard" /v "ConfigureSystemGuardLaunch" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\DeviceGuard" /v "HVCIMATRequired" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\DeviceGuard" /v "HypervisorEnforcedCodeIntegrity" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\DeviceGuard" /v "LsaCfgFlags" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\DeviceGuard" /v "RequirePlatformSecurityFeatures" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\DeviceInstall\Restrictions" /v "DenyDeviceClasses" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\DeviceInstall\Restrictions" /v "DenyDeviceClassesRetroactive" /t REG_DWORD /d "1" /f
Reg.exe delete "HKLM\software\policies\microsoft\windows\deviceinstall\restrictions\denydeviceclasses" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses" /v "1" /t REG_SZ /d "{d48179be-ec20-11d1-b6b8-00c04fa372a7}" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\DeviceInstall\Settings" /v "AllowRemoteRPC" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\DeviceInstall\Settings" /v "DisableSendGenericDriverNotFoundToWER" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\DeviceInstall\Settings" /v "DisableSendRequestAdditionalSoftwareToWER" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\DeviceInstall\Settings" /v "DisableSystemRestore" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\DriverSearching" /v "DontPromptForWindowsUpdate" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\DriverSearching" /v "DontSearchWindowsUpdate" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\DriverSearching" /v "DriverServerSelection" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\EventLog\Application" /v "MaxSize" /t REG_DWORD /d "32768" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\EventLog\Security" /v "MaxSize" /t REG_DWORD /d "196608" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\EventLog\Setup" /v "MaxSize" /t REG_DWORD /d "32768" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\EventLog\System" /v "MaxSize" /t REG_DWORD /d "32768" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\Explorer" /v "NoAutoplayfornonVolume" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\Explorer" /v "NoDataExecutionPrevention" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\Explorer" /v "NoHeapTerminationOnCorruption" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\Explorer" /v "NoUseStoreOpenWith" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\GameUX" /v "DownloadGameInfo" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\GameUX" /v "GameUpdateOptions" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" /v "NoBackgroundPolicy" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" /v "NoGPOListChanges" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\HomeGroup" /v "DisableHomeGroup" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\Installer" /v "AlwaysInstallElevated" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\Installer" /v "DisableLUAPatching" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\Installer" /v "EnableUserControl" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\Installer" /v "SafeForScripting" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\Kernel DMA Protection" /v "DeviceEnumerationPolicy" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\LanmanWorkstation" /v "AllowInsecureGuestAuth" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\LLTD" /v "AllowLLTDIOOnDomain" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\LLTD" /v "AllowLLTDIOOnPublicNet" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\LLTD" /v "AllowRspndrOnDomain" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\LLTD" /v "AllowRspndrOnPublicNet" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\LLTD" /v "EnableLLTDIO" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\LLTD" /v "EnableRspndr" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\LLTD" /v "ProhibitLLTDIOOnPrivateNet" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\LLTD" /v "ProhibitRspndrOnPrivateNet" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\Network Connections" /v "NC_AllowNetBridge_NLA" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\Network Connections" /v "NC_ShowSharedAccessUI" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\Network Connections" /v "NC_StdDomainUserSetLocation" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\NetworkProvider\HardenedPaths" /v "\\*\NETLOGON" /t REG_SZ /d "RequireMutualAuthentication=1,RequireIntegrity=1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\NetworkProvider\HardenedPaths" /v "\\*\SYSVOL" /t REG_SZ /d "RequireMutualAuthentication=1,RequireIntegrity=1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\Personalization" /v "NoLockScreenSlideshow" /t REG_DWORD /d "1" /f
Reg.exe delete "HKLM\software\policies\microsoft\windows\powershell\scriptblocklogging" /v "enablescriptblockinvocationlogging" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\windows\powershell\scriptblocklogging" /v "EnableScriptBlockLogging" /t REG_DWORD /d "1" /f
Reg.exe delete "HKLM\software\policies\microsoft\windows\powershell\transcription" /v "enableinvocationheader" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\windows\powershell\transcription" /v "EnableTranscripting" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\windows\powershell\transcription" /v "OutputDirectory" /t REG_SZ /d "C:\ProgramData\PS_Transcript" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /v "DisableQueryRemoteServer" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /v "EnableQueryRemoteServer" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\Skydrive" /v "DisableFileSync" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\System" /v "AllowDomainPINLogon" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\System" /v "DisableLockScreenAppNotifications" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\System" /v "DontDisplayNetworkSelectionUI" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\System" /v "DontEnumerateConnectedUsers" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\System" /v "EnumerateLocalUsers" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\System" /v "ShellSmartScreenLevel" /t REG_SZ /d "Block" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\TCPIP\v6Transition" /v "6to4_State" /t REG_SZ /d "Disabled" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\TCPIP\v6Transition" /v "Force_Tunneling" /t REG_SZ /d "Enabled" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\TCPIP\v6Transition" /v "ISATAP_State" /t REG_SZ /d "Disabled" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\TCPIP\v6Transition" /v "Teredo_State" /t REG_SZ /d "Disabled" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\TCPIP\v6Transition\IPHTTPS\IPHTTPSInterface" /v "IPHTTPS_ClientState" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\TCPIP\v6Transition\IPHTTPS\IPHTTPSInterface" /v "IPHTTPS_ClientUrl" /t REG_SZ /d "about:blank" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\WcmSvc\GroupPolicy" /v "fBlockNonDomain" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\WcmSvc\GroupPolicy" /v "fMinimizeConnections" /t REG_DWORD /d "1" /f
Reg.exe delete "HKLM\software\policies\microsoft\windows\wcn\registrars" /v "higherprecedenceregistrar" /f
Reg.exe delete "HKLM\software\policies\microsoft\windows\wcn\registrars" /v "maxwcndevicenumber" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\windows\wcn\registrars" /v "DisableFlashConfigRegistrar" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\windows\wcn\registrars" /v "DisableInBand802DOT11Registrar" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\windows\wcn\registrars" /v "DisableUPnPRegistrar" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\windows\wcn\registrars" /v "DisableWPDRegistrar" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\windows\wcn\registrars" /v "EnableRegistrars" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\WCN\UI" /v "DisableWcnUi" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" /v "ScenarioExecutionEnabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\Windows Search" /v "AllowIndexingEncryptedStoresOrItems" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\Windows Search" /v "ConnectedSearchPrivacy" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\Windows Search" /v "PreventIndexingUncachedExchangeFolders" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\WinRM\Client" /v "AllowBasic" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\WinRM\Client" /v "AllowDigest" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\WinRM\Client" /v "AllowUnencryptedTraffic" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\WinRM\Service" /v "AllowBasic" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\WinRM\Service" /v "AllowUnencryptedTraffic" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\WinRM\Service" /v "DisableRunAs" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\Windows\WinRM\Service\WinRS" /v "AllowRemoteShellAccess" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\WindowsFirewall" /v "PolicyVersion" /t REG_DWORD /d "538" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\WindowsFirewall\DomainProfile" /v "DefaultInboundAction" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\WindowsFirewall\DomainProfile" /v "DefaultOutboundAction" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\WindowsFirewall\DomainProfile" /v "DisableNotifications" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\WindowsFirewall\DomainProfile" /v "EnableFirewall" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\WindowsFirewall\DomainProfile\Logging" /v "LogDroppedPackets" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\WindowsFirewall\DomainProfile\Logging" /v "LogFileSize" /t REG_DWORD /d "16384" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\WindowsFirewall\DomainProfile\Logging" /v "LogSuccessfulConnections" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\WindowsFirewall\FirewallRules" /v "RemoteDesktop-Shadow-In-TCP" /t REG_SZ /d "v2.28|Action=Allow|Active=TRUE|Dir=In|Protocol=6|App=%%SystemRoot%%\system32\RdpSa.exe|Name=@FirewallAPI.dll,-28778|Desc=@FirewallAPI.dll,-28779|EmbedCtxt=@FirewallAPI.dll,-28752|Edge=TRUE|Defer=App|" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\WindowsFirewall\FirewallRules" /v "RemoteDesktop-UserMode-In-TCP" /t REG_SZ /d "v2.28|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=3389|App=%%SystemRoot%%\system32\svchost.exe|Svc=termservice|Name=@FirewallAPI.dll,-28775|Desc=@FirewallAPI.dll,-28756|EmbedCtxt=@FirewallAPI.dll,-28752|" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\WindowsFirewall\FirewallRules" /v "RemoteDesktop-UserMode-In-UDP" /t REG_SZ /d "v2.28|Action=Allow|Active=TRUE|Dir=In|Protocol=17|LPort=3389|App=%%SystemRoot%%\system32\svchost.exe|Svc=termservice|Name=@FirewallAPI.dll,-28776|Desc=@FirewallAPI.dll,-28777|EmbedCtxt=@FirewallAPI.dll,-28752|" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\WindowsFirewall\PrivateProfile" /v "DefaultInboundAction" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\WindowsFirewall\PrivateProfile" /v "DefaultOutboundAction" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\WindowsFirewall\PrivateProfile" /v "DisableNotifications" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\WindowsFirewall\PrivateProfile" /v "EnableFirewall" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\WindowsFirewall\PrivateProfile\Logging" /v "LogDroppedPackets" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\WindowsFirewall\PrivateProfile\Logging" /v "LogFileSize" /t REG_DWORD /d "16384" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\WindowsFirewall\PrivateProfile\Logging" /v "LogSuccessfulConnections" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\WindowsFirewall\PublicProfile" /v "AllowLocalIPsecPolicyMerge" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\WindowsFirewall\PublicProfile" /v "AllowLocalPolicyMerge" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\WindowsFirewall\PublicProfile" /v "DefaultInboundAction" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\WindowsFirewall\PublicProfile" /v "DefaultOutboundAction" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\WindowsFirewall\PublicProfile" /v "DisableNotifications" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\WindowsFirewall\PublicProfile" /v "EnableFirewall" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\WindowsFirewall\PublicProfile\Logging" /v "LogDroppedPackets" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\WindowsFirewall\PublicProfile\Logging" /v "LogFileSize" /t REG_DWORD /d "16384" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\WindowsFirewall\PublicProfile\Logging" /v "LogSuccessfulConnections" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\WindowsInkWorkspace" /v "AllowWindowsInkWorkspace" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\WindowsMediaPlayer" /v "DisableAutoUpdate" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\WindowsMediaPlayer" /v "GroupPrivacyAcceptance" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\WindowsStore" /v "AutoDownload" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\WindowsStore" /v "DisableOSUpgrade" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\WindowsStore" /v "RemoveWindowsStore" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\policies\microsoft\WMDRM" /v "DisableOnline" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\WOW6432Node\Adobe\Adobe Acrobat\2015\Installer" /v "DisableMaintenance" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\WOW6432Node\Adobe\Adobe Acrobat\DC\Installer" /v "DisableMaintenance" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\WOW6432Node\Microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "excel.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\WOW6432Node\Microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "exprwd.exe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\WOW6432Node\Microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "groove.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\WOW6432Node\Microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "msaccess.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\WOW6432Node\Microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "mse7.exe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\WOW6432Node\Microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "mspub.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\WOW6432Node\Microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "onenote.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\WOW6432Node\Microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "outlook.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\WOW6432Node\Microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "powerpnt.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\WOW6432Node\Microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "pptview.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\WOW6432Node\Microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "spdesign.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\WOW6432Node\Microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "visio.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\WOW6432Node\Microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "winproj.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\WOW6432Node\Microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "winword.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}" /v "ActivationFilterOverride" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}" /v "Compatibility Flags" /t REG_DWORD /d "1024" /f
Echo Y | Reg.exe add "HKLM\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}" /v "ActivationFilterOverride" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}" /v "Compatibility Flags" /t REG_DWORD /d "1024" /f
Echo Y | Reg.exe add "HKLM\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}" /v "ActivationFilterOverride" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}" /v "Compatibility Flags" /t REG_DWORD /d "1024" /f
Echo Y | Reg.exe add "HKLM\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}" /v "ActivationFilterOverride" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}" /v "Compatibility Flags" /t REG_DWORD /d "1024" /f
Echo Y | Reg.exe add "HKLM\software\WOW6432Node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "excel.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\WOW6432Node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "exprwd.exe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\WOW6432Node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "groove.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\WOW6432Node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "msaccess.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\WOW6432Node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "mse7.exe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\WOW6432Node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "mspub.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\WOW6432Node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "onenote.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\WOW6432Node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "outlook.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\WOW6432Node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "powerpnt.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\WOW6432Node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "pptview.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\WOW6432Node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "spdesign.exe" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\software\WOW6432Node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "visio.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\WOW6432Node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "winproj.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\software\WOW6432Node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject" /v "winword.exe" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest" /v "UseLogonCredential" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager" /v "SafeDllSearchMode" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\System\CurrentControlSet\Policies\EarlyLaunch" /v "DriverLoadPolicy" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\System\CurrentControlSet\Services\Eventlog\Security" /v "WarningLevel" /t REG_DWORD /d "90" /f
Echo Y | Reg.exe add "HKLM\System\CurrentControlSet\Services\IPSEC" /v "NoDefaultExempt" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "Hidden" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "SMB1" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\System\CurrentControlSet\Services\MrxSmb10" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\System\CurrentControlSet\Services\Netbt\Parameters" /v "NodeType" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\System\CurrentControlSet\Services\Netbt\Parameters" /v "NoNameReleaseOnDemand" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableIPSourceRouting" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableICMPRedirect" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableIPAutoConfigurationLimits" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "KeepAliveTime" /t REG_DWORD /d "300000" /f
Echo Y | Reg.exe add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "PerformRouterDiscovery" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDataRetransmissions" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters" /v "DisableIPSourceRouting" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters" /v "TcpMaxDataRetransmissions" /t REG_DWORD /d "3" /f
REM ; PAC file
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "EnableLegacyAutoProxyFeature" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "AutoConfigURL" /t REG_SZ /d "https://www.proxynova.com/proxy.pac" /f
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
Echo Y | Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Quota System\S-1-2-0" /v "CpuRateLimit" /t REG_DWORD /d "256" /f
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
REM ; Safer Lite
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\SRPV2" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers" /v "authenticodeenabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers" /v "DefaultLevel" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers" /v "ExecutableTypes" /t REG_MULTI_SZ /d "ZOO\0ZLO\0ZFSENDTOTARGET\0Z\0XPS\0XPI\0XNK\0XML\0XLW\0XLTX\0XLTM\0XLT\0XLSM\0XLSB\0XLM\0XLL\0XLD\0XLC\0XLB\0XLAM\0XLA\0XBAP\0WSC\0WS\0WIZ\0WEBSITE\0WEBPNP\0WEBLOC\0WBK\0WAS\0VXD\0VSW\0VST\0VSS\0VSMACROS\0VBP\0VB\0TSP\0TOOL\0TMP\0TLB\0THEME\0TGZ\0TERMINAL\0TERM\0TAZ\0TAR\0SYS\0SWF\0STM\0SPL\0SLK\0SLDX\0SLDM\0SIT\0SHS\0SHB\0SETTINGCONTENT-MS\0SEARCH-MS\0SEARCHCONNECTOR-MS\0SEA\0SCT\0RTF\0RQY\0RPY\0REG\0RB\0PYZW\0PYZ\0PYX\0PYWZ\0PYW\0PYT\0PYP\0PYO\0PYI\0PYDE\0PYD\0PYC\0PY3\0PY\0PXD\0PSTREG\0PST\0PSDM1\0PSD1\0PRN\0PRINTEREXPORT\0PRG\0PRF\0PPTM\0PPSX\0PPSM\0PPS\0PPAM\0POTX\0POTM\0POT\0PLG\0PL\0PKG\0PIF\0PI\0PERL\0PCD\0OSD\0OQY\0OPS\0ODS\0NSH\0NLS\0MYDOCS\0MUI\0MSU\0MST\0MSP\0MSHXML\0MSH2XML\0MSH2\0MSH1XML\0MSH1\0MSH\0MSC\0MOF\0MMC\0MHTML\0MHT\0MDZ\0MDW\0MDT\0MDN\0MDF\0MDE\0MDB\0MDA\0MCF\0MAY\0MAW\0MAV\0MAU\0MAT\0MAS\0MAR\0MAQ\0MAPIMAIL\0MANIFEST\0MAM\0MAG\0MAF\0MAD\0LZH\0LOCAL\0LIBRARY-MS\0LDB\0LACCDB\0KSH\0JOB\0JNLP\0JAR\0ITS\0ISP\0IQY\0INS\0INF\0INI\0IME\0IE\0HTT\0HTM\0HTC\0HTA\0HQX\0HPJ\0HLP\0HEX\0H\0GZ\0GRP\0GLK\0GADGET\0FXP\0FON\0DRV\0DQY\0DOTX\0DOTM\0DOT\0DOCM\0DOCB\0DMG\0DLL\0DIR\0DIF\0DIAGCAB\0DESKTOP\0DESKLINK\0DER\0DCR\0DB\0CSV\0CSH\0CRX\0CRT\0CRAZY\0CPX\0COMMAND\0CNV\0CNT\0CLB\0CLASS\0CLA\0CHM\0CHI\0CFG\0CER\0CDB\0CAB\0BZ2\0BZ\0BAS\0AX\0ASX\0ASPX\0ASP\0ASA\0ARC\0APPREF-MS\0APPLICATION\0APP\0AIR\0ADP\0ADN\0ADE\0AD\0ACM\0ACCDT\0ACCDR\0ACCDE\0ACCDA\0INF\0MSI\0PS1\0WPC" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers" /v "Levels" /t REG_DWORD /d "462848" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers" /v "LogFileName" /t REG_SZ /d "C:\Windows\system32\LogFiles\SAFER.LOG" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers" /v "PolicyScope" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers" /v "TransparentEnabled" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\0\Paths\{C7AF2ED3-7F52-49AA-9970-712A1D8FB8F4}" /v "Description" /t REG_SZ /d "Python" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\0\Paths\{C7AF2ED3-7F52-49AA-9970-712A1D8FB8F4}" /v "ItemData" /t REG_SZ /d "Python*" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\0\Paths\{C7AF2ED3-7F52-49AA-9970-712A1D8FB8F4}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\0\Paths\{C7AF2ED3-7F52-49AA-9970-712A1D8FB8F5}" /v "Description" /t REG_SZ /d "Network js" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\0\Paths\{C7AF2ED3-7F52-49AA-9970-712A1D8FB8F5}" /v "ItemData" /t REG_SZ /d "*/*.js" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\0\Paths\{C7AF2ED3-7F52-49AA-9970-712A1D8FB8F5}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\0\Paths\{C7AF2ED3-7F52-49AA-9970-712A1D8FB8F6}" /v "Description" /t REG_SZ /d "Network exe" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\0\Paths\{C7AF2ED3-7F52-49AA-9970-712A1D8FB8F6}" /v "ItemData" /t REG_SZ /d "*/*.exe" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\0\Paths\{C7AF2ED3-7F52-49AA-9970-712A1D8FB8F6}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\0\Paths\{C7AF2ED3-7F52-49AA-9970-712A1D8FB8F7}" /v "Description" /t REG_SZ /d "Network tmp" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\0\Paths\{C7AF2ED3-7F52-49AA-9970-712A1D8FB8F7}" /v "ItemData" /t REG_SZ /d "*/*.tmp" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\0\Paths\{C7AF2ED3-7F52-49AA-9970-712A1D8FB8F7}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\0\Paths\{C7AF2ED3-7F52-49AA-9970-712A1D8FB8F8}" /v "Description" /t REG_SZ /d "Network msi" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\0\Paths\{C7AF2ED3-7F52-49AA-9970-712A1D8FB8F8}" /v "ItemData" /t REG_SZ /d "*/*.msi" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\0\Paths\{C7AF2ED3-7F52-49AA-9970-712A1D8FB8F8}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\0\Paths\{C7AF2ED3-7F52-49AA-9970-712A1D8FB8F9}" /v "Description" /t REG_SZ /d "Network vbs" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\0\Paths\{C7AF2ED3-7F52-49AA-9970-712A1D8FB8F9}" /v "ItemData" /t REG_SZ /d "*/*.vbs" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\0\Paths\{C7AF2ED3-7F52-49AA-9970-712A1D8FB8F9}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\0\URLZones\{643ADE30-2030-45AA-B54D-6C407941D825}" /v "ItemData" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\0\URLZones\{643ADE30-2030-45AA-B54D-6C407941D825}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\0\URLZones\{643ADE31-2030-45AA-B54D-6C407941D825}" /v "ItemData" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\0\URLZones\{643ADE31-2030-45AA-B54D-6C407941D825}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\0\URLZones\{643ADE32-2030-45AA-B54D-6C407941D825}" /v "ItemData" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\0\URLZones\{643ADE32-2030-45AA-B54D-6C407941D825}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\0\URLZones\{643ADE33-2030-45AA-B54D-6C407941D825}" /v "ItemData" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\0\URLZones\{643ADE33-2030-45AA-B54D-6C407941D825}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\0\URLZones\{643ADE34-2030-45AA-B54D-6C407941D825}" /v "ItemData" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\0\URLZones\{643ADE34-2030-45AA-B54D-6C407941D825}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{1016bbe0-a716-428b-822e-DE544B6A3520}" /v "Description" /t REG_SZ /d "*Allow EXE files" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{1016bbe0-a716-428b-822e-DE544B6A3520}" /v "ItemData" /t REG_SZ /d "*.exe" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{1016bbe0-a716-428b-822e-DE544B6A3520}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{1016bbe0-a716-428b-822e-DE544B6A3521}" /v "Description" /t REG_SZ /d "*Allow TMP files" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{1016bbe0-a716-428b-822e-DE544B6A3521}" /v "ItemData" /t REG_SZ /d "*.tmp" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{1016bbe0-a716-428b-822e-DE544B6A3521}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{1016bbe0-a716-428b-822e-DE544B6A3522}" /v "Description" /t REG_SZ /d "*Allow MSI files" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{1016bbe0-a716-428b-822e-DE544B6A3522}" /v "ItemData" /t REG_SZ /d "*.msi" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{1016bbe0-a716-428b-822e-DE544B6A3522}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{191CD7FA-F240-4A17-8986-94D480A6C8CA}" /v "Description" /t REG_SZ /d "%%SystemRoot%%" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{191CD7FA-F240-4A17-8986-94D480A6C8CA}" /v "ItemData" /t REG_SZ /d "C:\Windows" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{191CD7FA-F240-4A17-8986-94D480A6C8CA}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{625B53C3-AB48-4EC1-BA1F-A1EF4146FC19}" /v "Description" /t REG_SZ /d "*LNK : Start menu (AppData\Roaming)" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{625B53C3-AB48-4EC1-BA1F-A1EF4146FC19}" /v "ItemData" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Roaming\Microsoft\Windows\Start Menu\*.lnk" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{625B53C3-AB48-4EC1-BA1F-A1EF4146FC19}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{625B53C3-AB48-4EC1-BA1F-A1EF4146FC20}" /v "Description" /t REG_SZ /d "*LNK : Start menu programs (AppData\Roaming)" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{625B53C3-AB48-4EC1-BA1F-A1EF4146FC20}" /v "ItemData" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\*.lnk" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{625B53C3-AB48-4EC1-BA1F-A1EF4146FC20}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{625B53C3-AB48-4EC1-BA1F-A1EF4146FC21}" /v "Description" /t REG_SZ /d "*LNK : Start menu programs subfolders (AppData\Roaming)" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{625B53C3-AB48-4EC1-BA1F-A1EF4146FC21}" /v "ItemData" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\*\*.lnk" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{625B53C3-AB48-4EC1-BA1F-A1EF4146FC21}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{625B53C3-AB48-4EC1-BA1F-A1EF4146FC22}" /v "Description" /t REG_SZ /d "*LNK : Start menu" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{625B53C3-AB48-4EC1-BA1F-A1EF4146FC22}" /v "ItemData" /t REG_SZ /d "C:\ProgramData\Microsoft\Windows\Start Menu\*.lnk" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{625B53C3-AB48-4EC1-BA1F-A1EF4146FC22}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{625B53C3-AB48-4EC1-BA1F-A1EF4146FC23}" /v "Description" /t REG_SZ /d "*LNK : Start menu programs" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{625B53C3-AB48-4EC1-BA1F-A1EF4146FC23}" /v "ItemData" /t REG_SZ /d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\*.lnk" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{625B53C3-AB48-4EC1-BA1F-A1EF4146FC23}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{625B53C3-AB48-4EC1-BA1F-A1EF4146FC24}" /v "Description" /t REG_SZ /d "*LNK : Start menu programs subfolders" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{625B53C3-AB48-4EC1-BA1F-A1EF4146FC24}" /v "ItemData" /t REG_SZ /d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\*\*.lnk" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{625B53C3-AB48-4EC1-BA1F-A1EF4146FC24}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{625B53C3-AB48-4EC1-BA1F-A1EF4146FC25}" /v "Description" /t REG_SZ /d "*LNK : Start menu programs sub-subfolders" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{625B53C3-AB48-4EC1-BA1F-A1EF4146FC25}" /v "ItemData" /t REG_SZ /d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\*\*\*.lnk" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{625B53C3-AB48-4EC1-BA1F-A1EF4146FC25}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{625B53C3-AB48-4EC1-BA1F-A1EF4146FC26}" /v "Description" /t REG_SZ /d "*LNK : Start menu programs sub-subfolders (AppData\Roaming)" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{625B53C3-AB48-4EC1-BA1F-A1EF4146FC26}" /v "ItemData" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\*\*\*.lnk" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{625B53C3-AB48-4EC1-BA1F-A1EF4146FC26}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{6D809377-6AF0-444B-8957-A3773F02200E}" /v "Description" /t REG_SZ /d "*Default : Program Files on 64 bits" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{6D809377-6AF0-444B-8957-A3773F02200E}" /v "ItemData" /t REG_EXPAND_SZ /d "%%HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\ProgramW6432Dir%%" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{6D809377-6AF0-444B-8957-A3773F02200E}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}" /v "Description" /t REG_SZ /d "*Default : Program Files (x86) on 64 bits" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}" /v "ItemData" /t REG_EXPAND_SZ /d "%%HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\ProgramFilesDir (x86)%%" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{905E63B6-C1BF-494E-B29C-65B732D3D21A}" /v "Description" /t REG_SZ /d "*Default : Program Files (default)" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{905E63B6-C1BF-494E-B29C-65B732D3D21A}" /v "ItemData" /t REG_EXPAND_SZ /d "%%HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\ProgramFilesDir%%" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{905E63B6-C1BF-494E-B29C-65B732D3D21A}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{99a0fd77-ed0c-4e30-91ff-9d51428d2f21}" /v "Description" /t REG_SZ /d "*LNK : Power menu group 1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{99a0fd77-ed0c-4e30-91ff-9d51428d2f21}" /v "ItemData" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Local\Microsoft\Windows\WinX\Group1\*.lnk" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{99a0fd77-ed0c-4e30-91ff-9d51428d2f21}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{99a0fd77-ed0c-4e30-91ff-9d51428d2f22}" /v "Description" /t REG_SZ /d "*LNK : Power menu group 2" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{99a0fd77-ed0c-4e30-91ff-9d51428d2f22}" /v "ItemData" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Local\Microsoft\Windows\WinX\Group2\*.lnk" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{99a0fd77-ed0c-4e30-91ff-9d51428d2f22}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{99a0fd77-ed0c-4e30-91ff-9d51428d2f23}" /v "Description" /t REG_SZ /d "*LNK : Power menu group 3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{99a0fd77-ed0c-4e30-91ff-9d51428d2f23}" /v "ItemData" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Local\Microsoft\Windows\WinX\Group3\*.lnk" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{99a0fd77-ed0c-4e30-91ff-9d51428d2f23}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{B4BFCC3A-DB2C-424C-B029-7FE99A87C639}" /v "Description" /t REG_SZ /d "*LNK : ### Desktop" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{B4BFCC3A-DB2C-424C-B029-7FE99A87C639}" /v "ItemData" /t REG_EXPAND_SZ /d "%%HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\Desktop%%*.lnk" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{B4BFCC3A-DB2C-424C-B029-7FE99A87C639}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{B4BFCC3A-DB2C-424C-B029-7FE99A87C640}" /v "Description" /t REG_SZ /d "*LNK : OneDriveDesktop subfolders" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{B4BFCC3A-DB2C-424C-B029-7FE99A87C640}" /v "ItemData" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\OneDrive\Desktop\*\*.lnk" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{B4BFCC3A-DB2C-424C-B029-7FE99A87C640}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" /v "Description" /t REG_SZ /d "*LNK : Desktop" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" /v "ItemData" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\Desktop\*.lnk" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{B4BFCC3A-DB2C-424C-B029-7FE99A87C642}" /v "Description" /t REG_SZ /d "*LNK : Desktop subfolders" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{B4BFCC3A-DB2C-424C-B029-7FE99A87C642}" /v "ItemData" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\Desktop\*\*.lnk" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{B4BFCC3A-DB2C-424C-B029-7FE99A87C642}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{B4BFCC3A-DB2C-424C-B029-7FE99A87C643}" /v "Description" /t REG_SZ /d "*LNK : Public Desktop" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{B4BFCC3A-DB2C-424C-B029-7FE99A87C643}" /v "ItemData" /t REG_EXPAND_SZ /d "C:\Users\Public\Desktop\*.lnk" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{B4BFCC3A-DB2C-424C-B029-7FE99A87C643}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{B4BFCC3A-DB2C-424C-B029-7FE99A87C644}" /v "Description" /t REG_SZ /d "*LNK : TaskBar (AppData\Roaming)" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{B4BFCC3A-DB2C-424C-B029-7FE99A87C644}" /v "ItemData" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\*.lnk" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{B4BFCC3A-DB2C-424C-B029-7FE99A87C644}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{B4BFCC3A-DB2C-424C-B029-7FE99A87C645}" /v "Description" /t REG_SZ /d "*LNK : Quick Launch (AppData\Roaming)" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{B4BFCC3A-DB2C-424C-B029-7FE99A87C645}" /v "ItemData" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\*.lnk" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{B4BFCC3A-DB2C-424C-B029-7FE99A87C645}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{B4BFCC3A-DB2C-424C-B029-7FE99A87C646}" /v "Description" /t REG_SZ /d "*LNK : ImplicitAppShortcuts (AppData\Roaming)" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{B4BFCC3A-DB2C-424C-B029-7FE99A87C646}" /v "ItemData" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\ImplicitAppShortcuts\*.lnk" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{B4BFCC3A-DB2C-424C-B029-7FE99A87C646}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{B4BFCC3A-DB2C-424C-B029-7FE99A87C647}" /v "Description" /t REG_SZ /d "*LNK : ImplicitAppShortcuts subfolder (AppData\Roaming)" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{B4BFCC3A-DB2C-424C-B029-7FE99A87C647}" /v "ItemData" /t REG_EXPAND_SZ /d "%%USERPROFILE%%\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\ImplicitAppShortcuts\*\*.lnk" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{B4BFCC3A-DB2C-424C-B029-7FE99A87C647}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{C77CC673-3BA3-427D-C9DE-76D54F6DC97E}" /v "Description" /t REG_SZ /d "%%ProgramFiles(x86)%%" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{C77CC673-3BA3-427D-C9DE-76D54F6DC97E}" /v "ItemData" /t REG_SZ /d "C:\Program Files (x86)" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{C77CC673-3BA3-427D-C9DE-76D54F6DC97E}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{C77F1D47-1FE1-4E7A-869C-57659099E912}" /v "Description" /t REG_SZ /d "%%CommonProgramFiles(x86)%%" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{C77F1D47-1FE1-4E7A-869C-57659099E912}" /v "ItemData" /t REG_SZ /d "C:\Program Files (x86)\Common Files" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{C77F1D47-1FE1-4E7A-869C-57659099E912}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{D2C34AB2-529A-46B2-B293-FC853FCE72EA}" /v "Description" /t REG_SZ /d "%%ProgramFiles(x86)%%" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{D2C34AB2-529A-46B2-B293-FC853FCE72EA}" /v "ItemData" /t REG_SZ /d "C:\Program Files" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{D2C34AB2-529A-46B2-B293-FC853FCE72EA}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{D2C37D40-EA2D-11DC-8F61-0004760DFF53}" /v "Description" /t REG_SZ /d "%%CommonProgramFiles%%" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{D2C37D40-EA2D-11DC-8F61-0004760DFF53}" /v "ItemData" /t REG_SZ /d "C:\Program Files\Common Files" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{D2C37D40-EA2D-11DC-8F61-0004760DFF53}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{f073d7e6-ec43-4bf6-a2a8-536eb63b03c8}" /v "Description" /t REG_SZ /d "*Default : ProgramData\Microsoft\Windows Defender" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{f073d7e6-ec43-4bf6-a2a8-536eb63b03c8}" /v "ItemData" /t REG_EXPAND_SZ /d "%%HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\ProductAppDataPath%%" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{f073d7e6-ec43-4bf6-a2a8-536eb63b03c8}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{F38BF404-1D43-42F2-9305-67DE0B28FC23}" /v "Description" /t REG_SZ /d "*Default : Windows" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{F38BF404-1D43-42F2-9305-67DE0B28FC23}" /v "ItemData" /t REG_EXPAND_SZ /d "%%HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\SystemRoot%%" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{F38BF404-1D43-42F2-9305-67DE0B28FC23}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{F38BF404-1D43-42F2-9305-67DE0B28FC24}" /v "Description" /t REG_SZ /d "NVIDIA" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{F38BF404-1D43-42F2-9305-67DE0B28FC24}" /v "ItemData" /t REG_EXPAND_SZ /d "C:\Windows\System32\DriverStore\FileRepository\nv*" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{F38BF404-1D43-42F2-9305-67DE0B28FC24}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{F38BF404-1D43-42F2-9305-67DE0B28FC25}" /v "Description" /t REG_SZ /d "INTEL" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{F38BF404-1D43-42F2-9305-67DE0B28FC25}" /v "ItemData" /t REG_EXPAND_SZ /d "C:\Windows\System32\DriverStore\FileRepository\iighd*" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{F38BF404-1D43-42F2-9305-67DE0B28FC25}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{F38BF404-1D43-42F2-9305-67DE0B28FC26}" /v "Description" /t REG_SZ /d "AMD1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{F38BF404-1D43-42F2-9305-67DE0B28FC26}" /v "ItemData" /t REG_EXPAND_SZ /d "C:\Windows\System32\DriverStore\FileRepository\u0366969*" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{F38BF404-1D43-42F2-9305-67DE0B28FC26}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{F38BF404-1D43-42F2-9305-67DE0B28FC27}" /v "Description" /t REG_SZ /d "AMD2" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{F38BF404-1D43-42F2-9305-67DE0B28FC27}" /v "ItemData" /t REG_EXPAND_SZ /d "C:\Windows\System32\DriverStore\FileRepository\u0367126*" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{F38BF404-1D43-42F2-9305-67DE0B28FC27}" /v "SaferFlags" /t REG_DWORD /d "0" /f
REM ; Security policy
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit" /v "DefaultTemplate" /t REG_SZ /d "C:\Windows\Inf\secrecs.inf" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit" /v "EnvironmentVariables" /t REG_MULTI_SZ /d "%%AppData%%\0%%UserProfile%%\0%%AllUsersProfile%%\0%%ProgramFiles%%\0%%SystemRoot%%\0%%SystemDrive%%\0%%Temp%%\0%%Tmp%%" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit" /v "SetupCompDebugLevel" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit" /v "LastUsedDatabase" /t REG_SZ /d "C:\WINDOWS\Security\Database\secedit.sdb" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit" /v "TemplateUsed" /t REG_SZ /d "E:\Policies\Windows-10-v21H1-Security-Baseline-FINAL\GPOs\{F46647C2-3CBF-46C0-A185-0FFAE4BAF081}\DomainSysvol\GPO\Machine\microsoft\windows nt\SecEdit\GptTmpl.inf" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit" /v "LastWinLogonConfig" /t REG_DWORD /d "1309545573" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows NT/CurrentVersion/Setup/RecoveryConsole/SecurityLevel" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59076" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows NT/CurrentVersion/Setup/RecoveryConsole/SecurityLevel" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows NT/CurrentVersion/Setup/RecoveryConsole/SecurityLevel" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows NT/CurrentVersion/Setup/RecoveryConsole/SetCommand" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59077" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows NT/CurrentVersion/Setup/RecoveryConsole/SetCommand" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows NT/CurrentVersion/Setup/RecoveryConsole/SetCommand" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows NT/CurrentVersion/Winlogon/AllocateCDRoms" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59098" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows NT/CurrentVersion/Winlogon/AllocateCDRoms" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows NT/CurrentVersion/Winlogon/AllocateCDRoms" /v "ValueType" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows NT/CurrentVersion/Winlogon/AllocateDASD" /v "DisplayChoices" /t REG_MULTI_SZ /d "0|@wsecedit.dll,-59100\01|@wsecedit.dll,-59101\02|@wsecedit.dll,-59102" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows NT/CurrentVersion/Winlogon/AllocateDASD" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59099" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows NT/CurrentVersion/Winlogon/AllocateDASD" /v "DisplayType" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows NT/CurrentVersion/Winlogon/AllocateDASD" /v "ValueType" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows NT/CurrentVersion/Winlogon/AllocateFloppies" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59103" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows NT/CurrentVersion/Winlogon/AllocateFloppies" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows NT/CurrentVersion/Winlogon/AllocateFloppies" /v "ValueType" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows NT/CurrentVersion/Winlogon/CachedLogonsCount" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59030" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows NT/CurrentVersion/Winlogon/CachedLogonsCount" /v "DisplayType" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows NT/CurrentVersion/Winlogon/CachedLogonsCount" /v "DisplayUnit" /t REG_SZ /d "@wsecedit.dll,-59092" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows NT/CurrentVersion/Winlogon/CachedLogonsCount" /v "ValueType" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows NT/CurrentVersion/Winlogon/ForceUnlockLogon" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59032" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows NT/CurrentVersion/Winlogon/ForceUnlockLogon" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows NT/CurrentVersion/Winlogon/ForceUnlockLogon" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows NT/CurrentVersion/Winlogon/PasswordExpiryWarning" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59031" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows NT/CurrentVersion/Winlogon/PasswordExpiryWarning" /v "DisplayType" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows NT/CurrentVersion/Winlogon/PasswordExpiryWarning" /v "DisplayUnit" /t REG_SZ /d "@wsecedit.dll,-59093" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows NT/CurrentVersion/Winlogon/PasswordExpiryWarning" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows NT/CurrentVersion/Winlogon/ScRemoveOption" /v "DisplayChoices" /t REG_MULTI_SZ /d "0|@wsecedit.dll,-59035\01|@wsecedit.dll,-59036\02|@wsecedit.dll,-59037\03|@wsecedit.dll,-59038" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows NT/CurrentVersion/Winlogon/ScRemoveOption" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59034" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows NT/CurrentVersion/Winlogon/ScRemoveOption" /v "DisplayType" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows NT/CurrentVersion/Winlogon/ScRemoveOption" /v "ValueType" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/ConsentPromptBehaviorAdmin" /v "DisplayChoices" /t REG_MULTI_SZ /d "0|@scecli.dll,-8253\01|@scecli.dll,-8251\02|@scecli.dll,-8252\03|@scecli.dll,-8255\04|@scecli.dll,-8256\05|@scecli.dll,-8257" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/ConsentPromptBehaviorAdmin" /v "DisplayName" /t REG_SZ /d "@scecli.dll,-8200" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/ConsentPromptBehaviorAdmin" /v "DisplayType" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/ConsentPromptBehaviorAdmin" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/ConsentPromptBehaviorUser" /v "DisplayChoices" /t REG_MULTI_SZ /d "0|@scecli.dll,-8254\01|@scecli.dll,-8251\03|@scecli.dll,-8255" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/ConsentPromptBehaviorUser" /v "DisplayName" /t REG_SZ /d "@scecli.dll,-8201" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/ConsentPromptBehaviorUser" /v "DisplayType" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/ConsentPromptBehaviorUser" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/DisableCAD" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59022" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/DisableCAD" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/DisableCAD" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/DontDisplayLastUserName" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59023" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/DontDisplayLastUserName" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/DontDisplayLastUserName" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/DontDisplayLockedUserId" /v "DisplayChoices" /t REG_MULTI_SZ /d "1|@wsecedit.dll,-59025\02|@wsecedit.dll,-59026\03|@wsecedit.dll,-59027\04|@wsecedit.dll,-59159" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/DontDisplayLockedUserId" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59024" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/DontDisplayLockedUserId" /v "DisplayType" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/DontDisplayLockedUserId" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/DontDisplayUserName" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59158" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/DontDisplayUserName" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/DontDisplayUserName" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/EnableInstallerDetection" /v "DisplayName" /t REG_SZ /d "@scecli.dll,-8202" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/EnableInstallerDetection" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/EnableInstallerDetection" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/EnableLUA" /v "DisplayName" /t REG_SZ /d "@scecli.dll,-8203" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/EnableLUA" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/EnableLUA" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/EnableSecureUIAPaths" /v "DisplayName" /t REG_SZ /d "@scecli.dll,-8208" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/EnableSecureUIAPaths" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/EnableSecureUIAPaths" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/EnableUIADesktopToggle" /v "DisplayName" /t REG_SZ /d "@scecli.dll,-8225" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/EnableUIADesktopToggle" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/EnableUIADesktopToggle" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/EnableVirtualization" /v "DisplayName" /t REG_SZ /d "@scecli.dll,-8204" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/EnableVirtualization" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/EnableVirtualization" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/FilterAdministratorToken" /v "DisplayName" /t REG_SZ /d "@scecli.dll,-8207" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/FilterAdministratorToken" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/FilterAdministratorToken" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/InactivityTimeoutSecs" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59155" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/InactivityTimeoutSecs" /v "DisplayType" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/InactivityTimeoutSecs" /v "DisplayUnit" /t REG_SZ /d "@wsecedit.dll,-59095" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/InactivityTimeoutSecs" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/Kerberos/Parameters/SupportedEncryptionTypes" /v "DisplayFlags" /t REG_MULTI_SZ /d "1|@wsecedit.dll,-59122\02|@wsecedit.dll,-59123\04|@wsecedit.dll,-59124\08|@wsecedit.dll,-59125\016|@wsecedit.dll,-59126\02147483616|@wsecedit.dll,-59127" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/Kerberos/Parameters/SupportedEncryptionTypes" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59121" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/Kerberos/Parameters/SupportedEncryptionTypes" /v "DisplayType" /t REG_DWORD /d "5" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/Kerberos/Parameters/SupportedEncryptionTypes" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/LegalNoticeCaption" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59029" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/LegalNoticeCaption" /v "DisplayType" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/LegalNoticeCaption" /v "ValueType" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/LegalNoticeText" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59028" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/LegalNoticeText" /v "DisplayType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/LegalNoticeText" /v "ValueType" /t REG_DWORD /d "7" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/MaxDevicePasswordFailedAttempts" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59154" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/MaxDevicePasswordFailedAttempts" /v "DisplayType" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/MaxDevicePasswordFailedAttempts" /v "DisplayUnit" /t REG_SZ /d "@wsecedit.dll,-59156" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/MaxDevicePasswordFailedAttempts" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/NoConnectedUser" /v "DisplayChoices" /t REG_MULTI_SZ /d "0|@wsecedit.dll,-59151\01|@wsecedit.dll,-59152\03|@wsecedit.dll,-59153" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/NoConnectedUser" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59150" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/NoConnectedUser" /v "DisplayType" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/NoConnectedUser" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/PromptOnSecureDesktop" /v "DisplayName" /t REG_SZ /d "@scecli.dll,-8206" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/PromptOnSecureDesktop" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/PromptOnSecureDesktop" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/ScForceOption" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59033" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/ScForceOption" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/ScForceOption" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/ShutdownWithoutLogon" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59078" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/ShutdownWithoutLogon" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/ShutdownWithoutLogon" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/UndockWithoutLogon" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59010" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/UndockWithoutLogon" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/UndockWithoutLogon" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/ValidateAdminCodeSignatures" /v "DisplayName" /t REG_SZ /d "@scecli.dll,-8205" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/ValidateAdminCodeSignatures" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Microsoft/Windows/CurrentVersion/Policies/System/ValidateAdminCodeSignatures" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Policies/Microsoft/Cryptography/ForceKeyProtection" /v "DisplayChoices" /t REG_MULTI_SZ /d "0|@wsecedit.dll,-59087\01|@wsecedit.dll,-59088\02|@wsecedit.dll,-59089" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Policies/Microsoft/Cryptography/ForceKeyProtection" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59086" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Policies/Microsoft/Cryptography/ForceKeyProtection" /v "DisplayType" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Policies/Microsoft/Cryptography/ForceKeyProtection" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Policies/Microsoft/Windows NT/DCOM/MachineAccessRestriction" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59097" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Policies/Microsoft/Windows NT/DCOM/MachineAccessRestriction" /v "DisplayType" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Policies/Microsoft/Windows NT/DCOM/MachineAccessRestriction" /v "ValueType" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Policies/Microsoft/Windows NT/DCOM/MachineLaunchRestriction" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59096" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Policies/Microsoft/Windows NT/DCOM/MachineLaunchRestriction" /v "DisplayType" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Policies/Microsoft/Windows NT/DCOM/MachineLaunchRestriction" /v "ValueType" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Policies/Microsoft/Windows/Safer/CodeIdentifiers/AuthenticodeEnabled" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59090" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Policies/Microsoft/Windows/Safer/CodeIdentifiers/AuthenticodeEnabled" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/Software/Policies/Microsoft/Windows/Safer/CodeIdentifiers/AuthenticodeEnabled" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/AuditBaseObjects" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59002" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/AuditBaseObjects" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/AuditBaseObjects" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/CrashOnAuditFail" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59004" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/CrashOnAuditFail" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/CrashOnAuditFail" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/DisableDomainCreds" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59046" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/DisableDomainCreds" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/DisableDomainCreds" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/EveryoneIncludesAnonymous" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59049" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/EveryoneIncludesAnonymous" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/EveryoneIncludesAnonymous" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/FIPSAlgorithmPolicy/Enabled" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59085" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/FIPSAlgorithmPolicy/Enabled" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/FIPSAlgorithmPolicy/Enabled" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/ForceGuest" /v "DisplayChoices" /t REG_MULTI_SZ /d "0|@wsecedit.dll,-59056\01|@wsecedit.dll,-59057" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/ForceGuest" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59055" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/ForceGuest" /v "DisplayType" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/ForceGuest" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/FullPrivilegeAuditing" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59003" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/FullPrivilegeAuditing" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/FullPrivilegeAuditing" /v "ValueType" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/LimitBlankPasswordUse" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59001" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/LimitBlankPasswordUse" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/LimitBlankPasswordUse" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/LmCompatibilityLevel" /v "DisplayChoices" /t REG_MULTI_SZ /d "0|@wsecedit.dll,-59060\01|@wsecedit.dll,-59061\02|@wsecedit.dll,-59062\03|@wsecedit.dll,-59063\04|@wsecedit.dll,-59064\05|@wsecedit.dll,-59065" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/LmCompatibilityLevel" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59059" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/LmCompatibilityLevel" /v "DisplayType" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/LmCompatibilityLevel" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/MSV1_0/allownullsessionfallback" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59120" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/MSV1_0/allownullsessionfallback" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/MSV1_0/allownullsessionfallback" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/MSV1_0/AuditReceivingNTLMTraffic" /v "DisplayChoices" /t REG_MULTI_SZ /d "0|@wsecedit.dll,-59134\01|@wsecedit.dll,-59135\02|@wsecedit.dll,-59136" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/MSV1_0/AuditReceivingNTLMTraffic" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59131" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/MSV1_0/AuditReceivingNTLMTraffic" /v "DisplayType" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/MSV1_0/AuditReceivingNTLMTraffic" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/MSV1_0/ClientAllowedNTLMServers" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59118" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/MSV1_0/ClientAllowedNTLMServers" /v "DisplayType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/MSV1_0/ClientAllowedNTLMServers" /v "ValueType" /t REG_DWORD /d "7" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/MSV1_0/NTLMMinClientSec" /v "DisplayFlags" /t REG_MULTI_SZ /d "524288|@wsecedit.dll,-59070\0536870912|@wsecedit.dll,-59071" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/MSV1_0/NTLMMinClientSec" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59066" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/MSV1_0/NTLMMinClientSec" /v "DisplayType" /t REG_DWORD /d "5" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/MSV1_0/NTLMMinClientSec" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/MSV1_0/NTLMMinServerSec" /v "DisplayFlags" /t REG_MULTI_SZ /d "524288|@wsecedit.dll,-59070\0536870912|@wsecedit.dll,-59071" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/MSV1_0/NTLMMinServerSec" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59067" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/MSV1_0/NTLMMinServerSec" /v "DisplayType" /t REG_DWORD /d "5" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/MSV1_0/NTLMMinServerSec" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/MSV1_0/RestrictReceivingNTLMTraffic" /v "DisplayChoices" /t REG_MULTI_SZ /d "0|@wsecedit.dll,-59109\01|@wsecedit.dll,-59110\02|@wsecedit.dll,-59111" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/MSV1_0/RestrictReceivingNTLMTraffic" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59108" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/MSV1_0/RestrictReceivingNTLMTraffic" /v "DisplayType" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/MSV1_0/RestrictReceivingNTLMTraffic" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/MSV1_0/RestrictSendingNTLMTraffic" /v "DisplayChoices" /t REG_MULTI_SZ /d "0|@wsecedit.dll,-59106\01|@wsecedit.dll,-59130\02|@wsecedit.dll,-59107" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/MSV1_0/RestrictSendingNTLMTraffic" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59105" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/MSV1_0/RestrictSendingNTLMTraffic" /v "DisplayType" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/MSV1_0/RestrictSendingNTLMTraffic" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/NoLMHash" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59058" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/NoLMHash" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/NoLMHash" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/pku2u/AllowOnlineID" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59129" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/pku2u/AllowOnlineID" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/pku2u/AllowOnlineID" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/RestrictAnonymous" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59048" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/RestrictAnonymous" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/RestrictAnonymous" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/RestrictAnonymousSAM" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59047" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/RestrictAnonymousSAM" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/RestrictAnonymousSAM" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/RestrictRemoteSAM" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59157" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/RestrictRemoteSAM" /v "DisplayType" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/RestrictRemoteSAM" /v "ValueType" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/SCENoApplyLegacyAuditPolicy" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59104" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/SCENoApplyLegacyAuditPolicy" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/SCENoApplyLegacyAuditPolicy" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/SubmitControl" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59011" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/SubmitControl" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/SubmitControl" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/UseMachineId" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59133" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/UseMachineId" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Lsa/UseMachineId" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Print/Providers/LanMan Print Services/Servers/AddPrinterDrivers" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59005" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Print/Providers/LanMan Print Services/Servers/AddPrinterDrivers" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Print/Providers/LanMan Print Services/Servers/AddPrinterDrivers" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/SAM/MinimumPasswordLengthAudit" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-756" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/SAM/MinimumPasswordLengthAudit" /v "DisplayType" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/SAM/MinimumPasswordLengthAudit" /v "DisplayUnit" /t REG_SZ /d "@wsecedit.dll,-59160" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/SAM/MinimumPasswordLengthAudit" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/SAM/RelaxMinimumPasswordLengthLimits" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-755" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/SAM/RelaxMinimumPasswordLengthLimits" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/SAM/RelaxMinimumPasswordLengthLimits" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/SecurePipeServers/Winreg/AllowedExactPaths/Machine" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59054" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/SecurePipeServers/Winreg/AllowedExactPaths/Machine" /v "DisplayType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/SecurePipeServers/Winreg/AllowedExactPaths/Machine" /v "ValueType" /t REG_DWORD /d "7" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/SecurePipeServers/Winreg/AllowedPaths/Machine" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59053" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/SecurePipeServers/Winreg/AllowedPaths/Machine" /v "DisplayType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/SecurePipeServers/Winreg/AllowedPaths/Machine" /v "ValueType" /t REG_DWORD /d "7" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Session Manager/Kernel/ObCaseInsensitive" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59084" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Session Manager/Kernel/ObCaseInsensitive" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Session Manager/Kernel/ObCaseInsensitive" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Session Manager/Memory Management/ClearPageFileAtShutdown" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59079" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Session Manager/Memory Management/ClearPageFileAtShutdown" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Session Manager/Memory Management/ClearPageFileAtShutdown" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Session Manager/ProtectionMode" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59080" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Session Manager/ProtectionMode" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Session Manager/ProtectionMode" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Session Manager/SubSystems/optional" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59091" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Session Manager/SubSystems/optional" /v "DisplayType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Control/Session Manager/SubSystems/optional" /v "ValueType" /t REG_DWORD /d "7" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LanManServer/Parameters/AutoDisconnect" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59042" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LanManServer/Parameters/AutoDisconnect" /v "DisplayType" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LanManServer/Parameters/AutoDisconnect" /v "DisplayUnit" /t REG_SZ /d "@wsecedit.dll,-59094" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LanManServer/Parameters/AutoDisconnect" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LanManServer/Parameters/EnableForcedLogOff" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59045" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LanManServer/Parameters/EnableForcedLogOff" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LanManServer/Parameters/EnableForcedLogOff" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LanManServer/Parameters/EnableS4U2SelfForClaims" /v "DisplayChoices" /t REG_MULTI_SZ /d "0|@wsecedit.dll,-59147\01|@wsecedit.dll,-59148\02|@wsecedit.dll,-59149" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LanManServer/Parameters/EnableS4U2SelfForClaims" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59146" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LanManServer/Parameters/EnableS4U2SelfForClaims" /v "DisplayType" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LanManServer/Parameters/EnableS4U2SelfForClaims" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LanManServer/Parameters/EnableSecuritySignature" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59044" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LanManServer/Parameters/EnableSecuritySignature" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LanManServer/Parameters/EnableSecuritySignature" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LanManServer/Parameters/NullSessionPipes" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59051" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LanManServer/Parameters/NullSessionPipes" /v "DisplayType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LanManServer/Parameters/NullSessionPipes" /v "ValueType" /t REG_DWORD /d "7" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LanManServer/Parameters/NullSessionShares" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59052" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LanManServer/Parameters/NullSessionShares" /v "DisplayType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LanManServer/Parameters/NullSessionShares" /v "ValueType" /t REG_DWORD /d "7" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LanManServer/Parameters/RequireSecuritySignature" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59043" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LanManServer/Parameters/RequireSecuritySignature" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LanManServer/Parameters/RequireSecuritySignature" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LanManServer/Parameters/RestrictNullSessAccess" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59050" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LanManServer/Parameters/RestrictNullSessAccess" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LanManServer/Parameters/RestrictNullSessAccess" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LanManServer/Parameters/SmbServerNameHardeningLevel" /v "DisplayChoices" /t REG_MULTI_SZ /d "0|@wsecedit.dll,-59143\01|@wsecedit.dll,-59144\02|@wsecedit.dll,-59145" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LanManServer/Parameters/SmbServerNameHardeningLevel" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59142" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LanManServer/Parameters/SmbServerNameHardeningLevel" /v "DisplayType" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LanManServer/Parameters/SmbServerNameHardeningLevel" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LanmanWorkstation/Parameters/EnablePlainTextPassword" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59041" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LanmanWorkstation/Parameters/EnablePlainTextPassword" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LanmanWorkstation/Parameters/EnablePlainTextPassword" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LanmanWorkstation/Parameters/EnableSecuritySignature" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59040" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LanmanWorkstation/Parameters/EnableSecuritySignature" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LanmanWorkstation/Parameters/EnableSecuritySignature" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LanmanWorkstation/Parameters/RequireSecuritySignature" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59039" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LanmanWorkstation/Parameters/RequireSecuritySignature" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LanmanWorkstation/Parameters/RequireSecuritySignature" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LDAP/LDAPClientIntegrity" /v "DisplayChoices" /t REG_MULTI_SZ /d "0|@wsecedit.dll,-59073\01|@wsecedit.dll,-59074\02|@wsecedit.dll,-59075" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LDAP/LDAPClientIntegrity" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59072" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LDAP/LDAPClientIntegrity" /v "DisplayType" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/LDAP/LDAPClientIntegrity" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/Netlogon/Parameters/AuditNTLMInDomain" /v "DisplayChoices" /t REG_MULTI_SZ /d "0|@wsecedit.dll,-59137\01|@wsecedit.dll,-59138\03|@wsecedit.dll,-59139\05|@wsecedit.dll,-59140\07|@wsecedit.dll,-59141" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/Netlogon/Parameters/AuditNTLMInDomain" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59132" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/Netlogon/Parameters/AuditNTLMInDomain" /v "DisplayType" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/Netlogon/Parameters/AuditNTLMInDomain" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/Netlogon/Parameters/DCAllowedNTLMServers" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59119" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/Netlogon/Parameters/DCAllowedNTLMServers" /v "DisplayType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/Netlogon/Parameters/DCAllowedNTLMServers" /v "ValueType" /t REG_DWORD /d "7" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/Netlogon/Parameters/DisablePasswordChange" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59016" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/Netlogon/Parameters/DisablePasswordChange" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/Netlogon/Parameters/DisablePasswordChange" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/Netlogon/Parameters/MaximumPasswordAge" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59017" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/Netlogon/Parameters/MaximumPasswordAge" /v "DisplayType" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/Netlogon/Parameters/MaximumPasswordAge" /v "DisplayUnit" /t REG_SZ /d "@wsecedit.dll,-59093" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/Netlogon/Parameters/MaximumPasswordAge" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/Netlogon/Parameters/RefusePasswordChange" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59012" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/Netlogon/Parameters/RefusePasswordChange" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/Netlogon/Parameters/RefusePasswordChange" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/Netlogon/Parameters/RequireSignOrSeal" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59018" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/Netlogon/Parameters/RequireSignOrSeal" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/Netlogon/Parameters/RequireSignOrSeal" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/Netlogon/Parameters/RequireStrongKey" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59021" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/Netlogon/Parameters/RequireStrongKey" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/Netlogon/Parameters/RequireStrongKey" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/Netlogon/Parameters/RestrictNTLMInDomain" /v "DisplayChoices" /t REG_MULTI_SZ /d "0|@wsecedit.dll,-59113\01|@wsecedit.dll,-59114\03|@wsecedit.dll,-59115\05|@wsecedit.dll,-59116\07|@wsecedit.dll,-59117" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/Netlogon/Parameters/RestrictNTLMInDomain" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59112" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/Netlogon/Parameters/RestrictNTLMInDomain" /v "DisplayType" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/Netlogon/Parameters/RestrictNTLMInDomain" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/Netlogon/Parameters/SealSecureChannel" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59019" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/Netlogon/Parameters/SealSecureChannel" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/Netlogon/Parameters/SealSecureChannel" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/Netlogon/Parameters/SignSecureChannel" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59020" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/Netlogon/Parameters/SignSecureChannel" /v "DisplayType" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/Netlogon/Parameters/SignSecureChannel" /v "ValueType" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/NTDS/Parameters/LDAPServerIntegrity" /v "DisplayChoices" /t REG_MULTI_SZ /d "1|@wsecedit.dll,-59014\02|@wsecedit.dll,-59015" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/NTDS/Parameters/LDAPServerIntegrity" /v "DisplayName" /t REG_SZ /d "@wsecedit.dll,-59013" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/NTDS/Parameters/LDAPServerIntegrity" /v "DisplayType" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Reg Values\MACHINE/System/CurrentControlSet/Services/NTDS/Parameters/LDAPServerIntegrity" /v "ValueType" /t REG_DWORD /d "4" /f
REM ; Services
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SecEdit\Template Locations" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Alerter" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\ALG" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AppMgmt" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\BITS" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Browser" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\cisvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\ClipSrv" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\COMSysApp" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\cscsvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\defragsvc" /v "Start" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\dmadmin" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\dmserver" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "EnableAutoDoh" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxCacheTtl" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxNegativeCacheTtl" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\EntAppSvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\ERSvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\EventSystem" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\FastUserSwitchingCompatibility" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Fax" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\icssvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\helpsvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\HidServ" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\HbHost" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\lanmanserver" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation" /v "Start" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LmHosts" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\MapsBroker" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Messenger" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\mnmsrvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\MSDTC" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NetDDE" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NetDDEdsdm" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Netman" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Nla" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NtLmSsp" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NtmsSvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PeerDistSvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PhoneSvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PlugPlay" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PolicyAgent" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\RasAuto" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\RasMan" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\RDSessMgr" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\RemoteAccess" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\RemoteRegistry" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Retaildemo" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\RpcLocator" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\RSVP" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SCardDrv" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SCardSvr" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\seclogon" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SEMgrsvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SENS" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Smsrouter" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Snmptrap" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Spooler" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SSDPSRV" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SstpSvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stisvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SwPrv" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SysMain" /v "Start" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SysmonLog" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\TapiSrv" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\tcpip\parameters" /v "DisableReverseAddressRegistrations" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\tcpip\parameters" /v "EnableICMPRedirect" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\tcpip\parameters" /v "IGMPLevel" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\TermService" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\TlntSvr" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\TrkWks" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\uploadmgr" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\upnphost" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\UPS" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\VaultSvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\vmickvpexchange" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\vmicguestinterface" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\vmicheartbeat" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\vmicrdv" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\vmicshutdown" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\vmictimesync" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\vmicvmsession" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\vmicvss" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\VSS" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\W32Time" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WebClient" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\winrm" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WmdmPmSp" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Wmi" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WmiApSrv" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Wmpnetworksvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WSearch" /v "Start" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WwanSvc" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WZCSVC" /v "Start" /t REG_DWORD /d "4" /f
REM ; User policy
Reg.exe delete "HKCU\keycupoliciesmsvbasecurity" /v "loadcontrolsinforms" /f
Echo Y | Reg.exe add "HKCU\keycupoliciesmsvbasecurity" /f
Echo Y | Reg.exe add "HKCU\software\Adobe\Adobe Acrobat\2015\AVGeneral" /v "bFIPSMode" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\Adobe\Adobe Acrobat\2015\Security\cDigSig\cAdobeDownload" /v "bLoadSettingsFromURL" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\Adobe\Adobe Acrobat\2015\Security\cDigSig\cEUTLDownload" /v "bLoadSettingsFromURL" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\Adobe\Adobe Acrobat\DC\AVGeneral" /v "bFIPSMode" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\Adobe\Adobe Acrobat\DC\Security\cDigSig\cAdobeDownload" /v "bLoadSettingsFromURL" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\Adobe\Adobe Acrobat\DC\Security\cDigSig\cEUTLDownload" /v "bLoadSettingsFromURL" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "HideZoneInfoOnProperties" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "ScanWithAntiVirus" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKCU\software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInplaceSharing" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoPreviewPane" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoReadingPane" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\Microsoft\Windows\CurrentVersion\Policies\System" /v "NoDispScrSavPage" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\Assistance\Client\1.0" /v "NoExplicitFeedback" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\Assistance\Client\1.0" /v "NoImplicitFeedback" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\Internet Explorer\Control Panel" /v "FormSuggest" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\Internet Explorer\Control Panel" /v "FormSuggest Passwords" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\Internet Explorer\Main" /v "FormSuggest Passwords" /t REG_SZ /d "no" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\Internet Explorer\Main" /v "FormSuggest PW Ask" /t REG_SZ /d "no" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\Internet Explorer\Main" /v "Use FormSuggest" /t REG_SZ /d "no" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\access\internet" /v "donotunderlinehyperlinks" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\access\security" /v "modaltrustdecisiononly" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\access\security" /v "notbpromptunsignedaddin" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\access\security" /v "requireaddinsig" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\access\security" /v "vbawarnings" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\access\settings" /v "default file format" /t REG_DWORD /d "12" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\access\settings" /v "noconvertdialog" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\common" /v "qmenable" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\common" /v "updatereliabilitydata" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\common\broadcast" /v "disabledefaultservice" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\common\broadcast" /v "disableprogrammaticaccess" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\common\documentinformationpanel" /v "beaconing" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\common\drm" /v "disablecreation" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\common\drm" /v "includehtml" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\common\drm" /v "requireconnection" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\common\feedback" /v "enabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\common\feedback" /v "includescreenshot" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\common\fixedformat" /v "disablefixedformatdocproperties" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\common\general" /v "shownfirstrunoptin" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\common\general" /v "skydrivesigninoption" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\common\internet" /v "opendocumentsreadwritewhilebrowsing" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\common\internet" /v "relyonvml" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\common\internet" /v "useonlinecontent" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\common\mailsettings" /v "disablesignatures" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\common\mailsettings" /v "plainwraplen" /t REG_DWORD /d "132" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\common\portal" /v "linkpublishingdisabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\common\ptwatson" /v "ptwoptin" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\common\research\translation" /v "useonline" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\common\roaming" /v "roamingsettingsdisabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\common\security" /v "defaultencryption12" /t REG_SZ /d "Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\common\security" /v "disablehyperlinkwarning" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\common\security" /v "disablepasswordui" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\common\security" /v "drmencryptproperty" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\common\security" /v "encryptdocprops" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\common\security" /v "openxmlencryption" /t REG_SZ /d "Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\common\security" /v "openxmlencryptproperty" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\common\security\trusted locations" /v "allow user locations" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\common\services\fax" /v "nofax" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\common\signatures" /v "enablecreationofweakxpsignatures" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\common\signatures" /v "suppressextsigningsvcs" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\common\signin" /v "signinoptions" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\common\trustcenter" /v "trustbar" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\excel\internet" /v "donotloadpictures" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\excel\options" /v "autohyperlink" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\excel\options" /v "defaultformat" /t REG_DWORD /d "51" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\excel\options" /v "disableautorepublish" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\excel\options" /v "disableautorepublishwarning" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\excel\options" /v "extractdatadisableui" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\excel\options\binaryoptions" /v "fglobalsheet_37_1" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\excel\options\binaryoptions" /v "fupdateext_78_1" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\excel\security" /v "accessvbom" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\excel\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\excel\security" /v "excelbypassencryptedmacroscan" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\excel\security" /v "extensionhardening" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\excel\security" /v "notbpromptunsignedaddin" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\excel\security" /v "requireaddinsig" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\excel\security" /v "vbawarnings" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\excel\security" /v "webservicefunctionwarnings" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\excel\security\fileblock" /v "dbasefiles" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\excel\security\fileblock" /v "difandsylkfiles" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\excel\security\fileblock" /v "excel12betafilesfromconverters" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\excel\security\fileblock" /v "htmlandxmlssfiles" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\excel\security\fileblock" /v "openinprotectedview" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\excel\security\fileblock" /v "xl2macros" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\excel\security\fileblock" /v "xl2worksheets" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\excel\security\fileblock" /v "xl3macros" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\excel\security\fileblock" /v "xl3worksheets" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\excel\security\fileblock" /v "xl4macros" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\excel\security\fileblock" /v "xl4workbooks" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\excel\security\fileblock" /v "xl4worksheets" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\excel\security\fileblock" /v "xl9597workbooksandtemplates" /t REG_DWORD /d "5" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\excel\security\fileblock" /v "xl95workbooks" /t REG_DWORD /d "5" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\excel\security\filevalidation" /v "disableeditfrompv" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\excel\security\filevalidation" /v "enableonload" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\excel\security\filevalidation" /v "openinprotectedview" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\excel\security\protectedview" /v "disableattachmentsinpv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\excel\security\protectedview" /v "disableinternetfilesinpv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\excel\security\protectedview" /v "disableunsafelocationsinpv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\excel\security\trusted locations" /v "alllocationsdisabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\excel\security\trusted locations" /v "allownetworklocations" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\firstrun" /v "bootedrtm" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\firstrun" /v "disablemovie" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\gfx" /v "disablescreenshotautohyperlink" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\infopath" /v "disableinfopath2003emailforms" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\infopath\deployment" /v "cachemailxsn" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\infopath\deployment" /v "mailxsnwithxml" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\infopath\editor\offline" /v "cachedmodestatus" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\infopath\security" /v "allowinternetsolutions" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\infopath\security" /v "disallowattachmentcustomization" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\infopath\security" /v "editoractivexbeaconingui" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\infopath\security" /v "emailformsbeaconingui" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\infopath\security" /v "emailformsruncodeandscript" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\infopath\security" /v "enablefulltrustemailforms" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\infopath\security" /v "enableinternetemailforms" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\infopath\security" /v "enableintranetemailforms" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\infopath\security" /v "enablerestrictedemailforms" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\infopath\security" /v "gradualupgraderedirection" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\infopath\security" /v "infopathbeaconingui" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\infopath\security" /v "notbpromptunsignedaddin" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\infopath\security" /v "requireaddinsig" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\infopath\security" /v "runfulltrustsolutions" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\infopath\security" /v "runmanagedcodefrominternet" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\infopath\security" /v "signaturewarning" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\infopath\security\trusted locations" /v "alllocationsdisabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\meetings\profile" /v "serverui" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\ms project\security" /v "notbpromptunsignedaddin" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\ms project\security" /v "requireaddinsig" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\ms project\security" /v "trustwss" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\ms project\security" /v "vbawarnings" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\osm" /v "enablefileobfuscation" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\osm" /v "enablelogging" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\osm" /v "enableupload" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook" /v "disableantispam" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook" /v "disallowattachmentcustomization" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\options\autoformat" /v "pgrfafo_25_1" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\options\calendar" /v "disableweather" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\options\general" /v "check default client" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\options\general" /v "msgformat" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\options\mail" /v "blockextcontent" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\options\mail" /v "disableinfopathforms" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\options\mail" /v "editorpreference" /t REG_DWORD /d "65536" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\options\mail" /v "internet" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\options\mail" /v "intranet" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\options\mail" /v "junkmailenablelinks" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\options\mail" /v "junkmailtrustcontacts" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\options\mail" /v "junkmailtrustoutgoingrecipients" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\options\mail" /v "message plain format mime" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\options\mail" /v "message rtf format" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\options\mail" /v "readasplain" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\options\mail" /v "readsignedasplain" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\options\mail" /v "trustedzone" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\options\mail" /v "unblocksafezone" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\options\mail" /v "unblockspecificsenders" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\options\pubcal" /v "disabledav" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\options\pubcal" /v "disableofficeonline" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\options\pubcal" /v "publishcalendardetailspolicy" /t REG_DWORD /d "16384" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\options\pubcal" /v "restrictedaccessonly" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\options\pubcal" /v "singleuploadonly" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\options\rss" /v "disable" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\options\rss" /v "enableattachments" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\options\rss" /v "enablefulltexthtml" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\options\rss" /v "synctosyscfl" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\options\webcal" /v "disable" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\options\webcal" /v "enableattachments" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\rpc" /v "enablerpcencryption" /t REG_DWORD /d "1" /f
Reg.exe delete "HKCU\software\policies\microsoft\office\15.0\outlook\security" /v "fileextensionsremovelevel1" /f
Reg.exe delete "HKCU\software\policies\microsoft\office\15.0\outlook\security" /v "fileextensionsremovelevel2" /f
Reg.exe delete "HKCU\software\policies\microsoft\office\15.0\outlook\security" /v "outlooksecuretempfolder" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\security" /v "addintrust" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\security" /v "adminsecuritymode" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\security" /v "allowactivexoneoffforms" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\security" /v "allowuserstolowerattachments" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\security" /v "authenticationservice" /t REG_DWORD /d "9" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\security" /v "clearsign" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\security" /v "dontpromptlevel1attachclose" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\security" /v "dontpromptlevel1attachsend" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\security" /v "enableoneoffformscripts" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\security" /v "enablerememberpwd" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\security" /v "externalsmime" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\security" /v "fipsmode" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\security" /v "forcedefaultprofile" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\security" /v "level" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\security" /v "minenckey" /t REG_DWORD /d "168" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\security" /v "msgformats" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\security" /v "nocheckonsessionsecurity" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\security" /v "nondefaultstorescript" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\security" /v "promptoomaddressbookaccess" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\security" /v "promptoomaddressinformationaccess" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\security" /v "promptoomcustomaction" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\security" /v "promptoomformulaaccess" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\security" /v "promptoommeetingtaskrequestresponse" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\security" /v "promptoomsaveas" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\security" /v "promptoomsend" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\security" /v "publicfolderscript" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\security" /v "respondtoreceiptrequests" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\security" /v "sharedfolderscript" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\security" /v "showlevel1attach" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\security" /v "sigstatusnotrustdecision" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\security" /v "supressnamechecks" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\security" /v "usecrlchasing" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\outlook\security" /v "warnaboutinvalid" /t REG_DWORD /d "1" /f
Reg.exe delete "HKCU\software\policies\microsoft\office\15.0\outlook\security\trustedaddins" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\powerpoint\options" /v "defaultformat" /t REG_DWORD /d "27" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\powerpoint\options" /v "markupopensave" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\powerpoint\security" /v "accessvbom" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\powerpoint\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\powerpoint\security" /v "downloadimages" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\powerpoint\security" /v "notbpromptunsignedaddin" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\powerpoint\security" /v "powerpointbypassencryptedmacroscan" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\powerpoint\security" /v "requireaddinsig" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\powerpoint\security" /v "runprograms" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\powerpoint\security" /v "vbawarnings" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\powerpoint\security\fileblock" /v "openinprotectedview" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\powerpoint\security\fileblock" /v "powerpoint12betafilesfromconverters" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\powerpoint\security\filevalidation" /v "disableeditfrompv" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\powerpoint\security\filevalidation" /v "enableonload" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\powerpoint\security\filevalidation" /v "openinprotectedview" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\powerpoint\security\protectedview" /v "disableattachmentsinpv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\powerpoint\security\protectedview" /v "disableinternetfilesinpv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\powerpoint\security\protectedview" /v "disableunsafelocationsinpv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\powerpoint\security\trusted locations" /v "alllocationsdisabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\powerpoint\security\trusted locations" /v "allownetworklocations" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\powerpoint\slide libraries" /v "disableslideupdate" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\publisher" /v "promptforbadfiles" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\publisher\security" /v "notbpromptunsignedaddin" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\publisher\security" /v "requireaddinsig" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\publisher\security" /v "vbawarnings" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\visio\security" /v "notbpromptunsignedaddin" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\visio\security" /v "requireaddinsig" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\visio\security" /v "vbawarnings" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\wef\trustedcatalogs" /v "disableomexcatalogs" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\wef\trustedcatalogs" /v "requireserververification" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\word\options" /v "custommarkupwarning" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\word\options" /v "defaultformat" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\word\options" /v "dontupdatelinks" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\word\options" /v "warnrevisions" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\word\security" /v "accessvbom" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\word\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\word\security" /v "notbpromptunsignedaddin" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\word\security" /v "requireaddinsig" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\word\security" /v "vbawarnings" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\word\security" /v "wordbypassencryptedmacroscan" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\word\security\fileblock" /v "openinprotectedview" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\word\security\fileblock" /v "word2000files" /t REG_DWORD /d "5" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\word\security\fileblock" /v "word2files" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\word\security\fileblock" /v "word60files" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\word\security\fileblock" /v "word95files" /t REG_DWORD /d "5" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\word\security\fileblock" /v "word97files" /t REG_DWORD /d "5" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\word\security\fileblock" /v "wordxpfiles" /t REG_DWORD /d "5" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\word\security\filevalidation" /v "disableeditfrompv" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\word\security\filevalidation" /v "enableonload" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\word\security\filevalidation" /v "openinprotectedview" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\word\security\protectedview" /v "disableattachmentsinpv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\word\security\protectedview" /v "disableinternetfilesinpv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\word\security\protectedview" /v "disableunsafelocationsinpv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\word\security\trusted locations" /v "alllocationsdisabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\15.0\word\security\trusted locations" /v "allownetworklocations" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\access\internet" /v "donotunderlinehyperlinks" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\access\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\access\security" /v "modaltrustdecisiononly" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\access\security" /v "notbpromptunsignedaddin" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\access\security" /v "requireaddinsig" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\access\security" /v "vbadigsigtrustedpublishers" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\access\security" /v "vbarequiredigsigwithcodesigningeku" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\access\security" /v "vbarequirelmtrustedpublisher" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\access\security" /v "vbawarnings" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\access\security\trusted locations" /v "allownetworklocations" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\access\settings" /v "default file format" /t REG_DWORD /d "12" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\common" /v "fbabehavior" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\common" /v "fbaenabledhosts" /t REG_EXPAND_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\common" /v "sendcustomerdata" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\common\broadcast" /v "disabledefaultservice" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\common\broadcast" /v "disableprogrammaticaccess" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\common\drm" /v "requireconnection" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\common\feedback" /v "includescreenshot" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\common\fixedformat" /v "disablefixedformatdocproperties" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\common\portal" /v "linkpublishingdisabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\common\ptwatson" /v "ptwoptin" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\common\research\translation" /v "useonline" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\common\security" /v "defaultencryption12" /t REG_SZ /d "Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\common\security" /v "drmencryptproperty" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\common\security" /v "encryptdocprops" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\common\security" /v "macroruntimescanscope" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\common\security" /v "openxmlencryption" /t REG_SZ /d "Microsoft Enhanced RSA and AES Cryptographic Provider,AES 256,256" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\common\security" /v "openxmlencryptproperty" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\common\security\trusted locations" /v "allow user locations" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\common\toolbars\access" /v "noextensibilitycustomizationfromdocument" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\common\toolbars\excel" /v "noextensibilitycustomizationfromdocument" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\common\toolbars\infopath" /v "noextensibilitycustomizationfromdocument" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\common\toolbars\outlook" /v "noextensibilitycustomizationfromdocument" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\common\toolbars\powerpoint" /v "noextensibilitycustomizationfromdocument" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\common\toolbars\project" /v "noextensibilitycustomizationfromdocument" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\common\toolbars\publisher" /v "noextensibilitycustomizationfromdocument" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\common\toolbars\visio" /v "noextensibilitycustomizationfromdocument" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\common\toolbars\word" /v "noextensibilitycustomizationfromdocument" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\common\trustcenter" /v "trustbar" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\internet" /v "donotloadpictures" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\options" /v "defaultformat" /t REG_DWORD /d "51" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\options" /v "disableautorepublish" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\options" /v "disableautorepublishwarning" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\options" /v "extractdatadisableui" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\options\binaryoptions" /v "fglobalsheet_37_1" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\options\binaryoptions" /v "fupdateext_78_1" /t REG_DWORD /d "0" /f
Reg.exe delete "HKCU\software\policies\microsoft\office\16.0\excel\security" /v "excelbypassencryptedmacroscan" /f
Reg.exe delete "HKCU\software\policies\microsoft\office\16.0\excel\security" /v "webservicefunctionwarnings" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\security" /v "accessvbom" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\security" /v "extensionhardening" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\security" /v "notbpromptunsignedaddin" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\security" /v "requireaddinsig" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\security" /v "vbadigsigtrustedpublishers" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\security" /v "vbarequiredigsigwithcodesigningeku" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\security" /v "vbarequirelmtrustedpublisher" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\security" /v "vbawarnings" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\security\external content" /v "disableddeserverlaunch" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\security\external content" /v "disableddeserverlookup" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\security\external content" /v "enableblockunsecurequeryfiles" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\security\fileblock" /v "dbasefiles" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\security\fileblock" /v "difandsylkfiles" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\security\fileblock" /v "htmlandxmlssfiles" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\security\fileblock" /v "openinprotectedview" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\security\fileblock" /v "xl2macros" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\security\fileblock" /v "xl2worksheets" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\security\fileblock" /v "xl3macros" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\security\fileblock" /v "xl3worksheets" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\security\fileblock" /v "xl4macros" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\security\fileblock" /v "xl4workbooks" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\security\fileblock" /v "xl4worksheets" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\security\fileblock" /v "xl9597workbooksandtemplates" /t REG_DWORD /d "5" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\security\fileblock" /v "xl95workbooks" /t REG_DWORD /d "5" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\security\fileblock" /v "xl97workbooksandtemplates" /t REG_DWORD /d "2" /f
Reg.exe delete "HKCU\software\policies\microsoft\office\16.0\excel\security\filevalidation" /v "openinprotectedview" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\security\filevalidation" /v "disableeditfrompv" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\security\filevalidation" /v "enableonload" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\security\protectedview" /v "disableattachmentsinpv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\security\protectedview" /v "disableinternetfilesinpv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\security\protectedview" /v "disableintranetcheck" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\security\protectedview" /v "disableunsafelocationsinpv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\security\protectedview" /v "enabledatabasefileprotectedview" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\security\trusted locations" /v "alllocationsdisabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\excel\security\trusted locations" /v "allownetworklocations" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\meetings\profile" /v "serverui" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\ms project\security" /v "notbpromptunsignedaddin" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\ms project\security" /v "requireaddinsig" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\ms project\security" /v "trustwss" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\ms project\security" /v "vbawarnings" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\ms project\security\trusted locations" /v "allownetworklocations" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\osm" /v "enablefileobfuscation" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook" /v "disallowattachmentcustomization" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\options\general" /v "msgformat" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\options\mail" /v "blockextcontent" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\options\mail" /v "internet" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\options\mail" /v "intranet" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\options\mail" /v "junkmailenablelinks" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\options\mail" /v "junkmailprotection" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\options\mail" /v "trustedzone" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\options\mail" /v "unblocksafezone" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\options\mail" /v "unblockspecificsenders" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\options\pubcal" /v "disabledav" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\options\pubcal" /v "disableofficeonline" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\options\pubcal" /v "publishcalendardetailspolicy" /t REG_DWORD /d "16384" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\options\pubcal" /v "restrictedaccessonly" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\options\rss" /v "enableattachments" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\options\rss" /v "enablefulltexthtml" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\options\webcal" /v "disable" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\options\webcal" /v "enableattachments" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\rpc" /v "enablerpcencryption" /t REG_DWORD /d "1" /f
Reg.exe delete "HKCU\software\policies\microsoft\office\16.0\outlook\security" /v "fileextensionsremovelevel1" /f
Reg.exe delete "HKCU\software\policies\microsoft\office\16.0\outlook\security" /v "fileextensionsremovelevel2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\security" /v "addintrust" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\security" /v "adminsecuritymode" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\security" /v "allowactivexoneoffforms" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\security" /v "allowuserstolowerattachments" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\security" /v "authenticationservice" /t REG_DWORD /d "16" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\security" /v "clearsign" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\security" /v "enableoneoffformscripts" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\security" /v "enablerememberpwd" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\security" /v "externalsmime" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\security" /v "fipsmode" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\security" /v "forcedefaultprofile" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\security" /v "level" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\security" /v "minenckey" /t REG_DWORD /d "168" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\security" /v "msgformats" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\security" /v "nocheckonsessionsecurity" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\security" /v "promptoomaddressbookaccess" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\security" /v "promptoomaddressinformationaccess" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\security" /v "promptoomcustomaction" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\security" /v "promptoomformulaaccess" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\security" /v "promptoommeetingtaskrequestresponse" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\security" /v "promptoomsaveas" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\security" /v "promptoomsend" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\security" /v "publicfolderscript" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\security" /v "publishtogaldisabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\security" /v "respondtoreceiptrequests" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\security" /v "sharedfolderscript" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\security" /v "showlevel1attach" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\security" /v "supressnamechecks" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\security" /v "usecrlchasing" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\outlook\security" /v "warnaboutinvalid" /t REG_DWORD /d "1" /f
Reg.exe delete "HKCU\software\policies\microsoft\office\16.0\outlook\security\trustedaddins" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\powerpoint\options" /v "defaultformat" /t REG_DWORD /d "27" /f
Reg.exe delete "HKCU\software\policies\microsoft\office\16.0\powerpoint\security" /v "powerpointbypassencryptedmacroscan" /f
Reg.exe delete "HKCU\software\policies\microsoft\office\16.0\powerpoint\security" /v "runprograms" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\powerpoint\security" /v "accessvbom" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\powerpoint\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\powerpoint\security" /v "notbpromptunsignedaddin" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\powerpoint\security" /v "requireaddinsig" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\powerpoint\security" /v "vbadigsigtrustedpublishers" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\powerpoint\security" /v "vbarequiredigsigwithcodesigningeku" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\powerpoint\security" /v "vbarequirelmtrustedpublisher" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\powerpoint\security" /v "vbawarnings" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\powerpoint\security\fileblock" /v "binaryfiles" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\powerpoint\security\fileblock" /v "openinprotectedview" /t REG_DWORD /d "0" /f
Reg.exe delete "HKCU\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation" /v "openinprotectedview" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation" /v "disableeditfrompv" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation" /v "enableonload" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\powerpoint\security\protectedview" /v "disableattachmentsinpv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\powerpoint\security\protectedview" /v "disableinternetfilesinpv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\powerpoint\security\protectedview" /v "disableintranetcheck" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\powerpoint\security\protectedview" /v "disableunsafelocationsinpv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\powerpoint\security\trusted locations" /v "alllocationsdisabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\powerpoint\security\trusted locations" /v "allownetworklocations" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\publisher" /v "promptforbadfiles" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\publisher\security" /v "notbpromptunsignedaddin" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\publisher\security" /v "requireaddinsig" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\publisher\security" /v "vbadigsigtrustedpublishers" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\publisher\security" /v "vbarequiredigsigwithcodesigningeku" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\publisher\security" /v "vbarequirelmtrustedpublisher" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\publisher\security" /v "vbawarnings" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\visio\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\visio\security" /v "notbpromptunsignedaddin" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\visio\security" /v "requireaddinsig" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\visio\security" /v "vbadigsigtrustedpublishers" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\visio\security" /v "vbarequiredigsigwithcodesigningeku" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\visio\security" /v "vbarequirelmtrustedpublisher" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\visio\security" /v "vbawarnings" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\visio\security\fileblock" /v "visio2000files" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\visio\security\fileblock" /v "visio2003files" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\visio\security\fileblock" /v "visio50andearlierfiles" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\visio\security\trusted locations" /v "allownetworklocations" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\wef\trustedcatalogs" /v "requireserververification" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\word\options" /v "defaultformat" /t REG_SZ /d "" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\word\options" /v "dontupdatelinks" /t REG_DWORD /d "1" /f
Reg.exe delete "HKCU\software\policies\microsoft\office\16.0\word\security" /v "allowdde" /f
Reg.exe delete "HKCU\software\policies\microsoft\office\16.0\word\security" /v "wordbypassencryptedmacroscan" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\word\security" /v "accessvbom" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\word\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\word\security" /v "notbpromptunsignedaddin" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\word\security" /v "requireaddinsig" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\word\security" /v "vbadigsigtrustedpublishers" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\word\security" /v "vbarequiredigsigwithcodesigningeku" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\word\security" /v "vbarequirelmtrustedpublisher" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\word\security" /v "vbawarnings" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\word\security\fileblock" /v "openinprotectedview" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\word\security\fileblock" /v "word2000files" /t REG_DWORD /d "5" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\word\security\fileblock" /v "word2003files" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\word\security\fileblock" /v "word2007files" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\word\security\fileblock" /v "word2files" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\word\security\fileblock" /v "word60files" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\word\security\fileblock" /v "word95files" /t REG_DWORD /d "5" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\word\security\fileblock" /v "word97files" /t REG_DWORD /d "5" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\word\security\fileblock" /v "wordxpfiles" /t REG_DWORD /d "5" /f
Reg.exe delete "HKCU\software\policies\microsoft\office\16.0\word\security\filevalidation" /v "openinprotectedview" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\word\security\filevalidation" /v "disableeditfrompv" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\word\security\filevalidation" /v "enableonload" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\word\security\protectedview" /v "disableattachmentsinpv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\word\security\protectedview" /v "disableinternetfilesinpv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\word\security\protectedview" /v "disableintranetcheck" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\word\security\protectedview" /v "disableunsafelocationsinpv" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\word\security\trusted locations" /v "alllocationsdisabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\16.0\word\security\trusted locations" /v "allownetworklocations" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\common\blog" /v "disableblog" /t REG_DWORD /d "1" /f
Reg.exe delete "HKCU\software\policies\microsoft\office\common\security" /v "uficontrols" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\common\security" /v "automationsecurity" /t REG_DWORD /d "2" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\common\security" /v "automationsecuritypublisher" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\office\common\smart tag" /v "neverloadmanifests" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\OneDrive" /v "DisablePersonalSync" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\vba\security" /v "allowvbaintranetreferences" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\vba\security" /v "disablestrictvbarefssecurity" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\vba\security" /v "loadcontrolsinforms" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\Windows\CloudContent" /v "DisableThirdPartySuggestions" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\Windows\Control Panel\Desktop" /v "ScreenSaveActive" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\Windows\Control Panel\Desktop" /v "ScreenSaverIsSecure" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\Windows\Control Panel\Desktop" /v "SCRNSAVE.EXE" /t REG_SZ /d "scrnsave.scr" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\Windows\CurrentVersion\PushNotifications" /v "NoCloudApplicationNotification" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotificationOnLockScreen" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKCU\software\policies\microsoft\WindowsMediaPlayer" /v "PreventCodecDownload" /t REG_DWORD /d "1" /f
REM ; Worms Doors Cleaner
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Rpc\Internet" /v "UseInternetPorts" /t REG_SZ /d "N" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Ole" /v "EnableDCOM" /t REG_SZ /d "N" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\NetBT\Parameters" /v "SmbDeviceEnabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\NetBT" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Messenger" /v "Start" /t REG_DWORD /d "4" /f
Exit

:IsAdmin
Reg.exe query "HKU\S-1-5-19\Environment"
If Not %ERRORLEVEL% EQU 0 (
 Cls & Echo You must have administrator rights to continue ... 
 Pause & Exit
)
Cls
goto:eof
