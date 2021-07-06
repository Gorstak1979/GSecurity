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
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{F38BF404-1D43-42F2-9305-67DE0B28FC28}" /v "Description" /t REG_SZ /d "USB" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{F38BF404-1D43-42F2-9305-67DE0B28FC28}" /v "ItemData" /t REG_EXPAND_SZ /d "C:\Windows\System32\DriverStore\FileRepository\wpd*" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{F38BF404-1D43-42F2-9305-67DE0B28FC28}" /v "SaferFlags" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{F38BF404-1D43-42F2-9305-67DE0B28FC29}" /v "Description" /t REG_SZ /d "OEM" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{F38BF404-1D43-42F2-9305-67DE0B28FC29}" /v "ItemData" /t REG_EXPAND_SZ /d "C:\Windows\System32\DriverStore\FileRepository\oem*" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers\262144\Paths\{F38BF404-1D43-42F2-9305-67DE0B28FC29}" /v "SaferFlags" /t REG_DWORD /d "0" /f
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
Echo Y | Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NetBT" /v "Start" /t REG_DWORD /d "4" /f
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
REM ; Worms Doors Cleaner
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Rpc\Internet" /v "UseInternetPorts" /t REG_SZ /d "N" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Microsoft\Ole" /v "EnableDCOM" /t REG_SZ /d "N" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\NetBT\Parameters" /v "SmbDeviceEnabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\NetBT" /v "Start" /t REG_DWORD /d "4" /f
Echo Y | Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Messenger" /v "Start" /t REG_DWORD /d "4" /f
REM ; Pac file
Echo Y | Reg.exe add "HKU\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "AutoConfigURL" /t REG_SZ /d "https://www.proxynova.com/proxy.pac" /f
Echo Y | Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "AutoConfigURL" /t REG_SZ /d "https://www.proxynova.com/proxy.pac" /f
Echo Y | Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "EnableLegacyAutoProxyFeature" /t REG_DWORD /d "0" /f
Exit
REM ; Block cmd and powershell
Echo Y | Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /f
Echo Y | Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "1" /t REG_SZ /d "powershell.exe" /f
Echo Y | Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "2" /t REG_SZ /d "powershell_ise.exe" /f
Echo Y | Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "3" /t REG_SZ /d "conhost.exe" /f
Exit

:IsAdmin
Reg.exe query "HKU\S-1-5-19\Environment"
If Not %ERRORLEVEL% EQU 0 (
 Cls & Echo You must have administrator rights to continue ... 
 Pause & Exit
)
Cls
goto:eof
