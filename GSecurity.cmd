@echo off 
call :isAdmin
if %errorlevel% == 0 (
goto :run
) else (
echo Requesting administrative privileges...
goto :UACPrompt
)
goto:eof
:isAdmin
fsutil dirty query %systemdrive% >nul
goto:eof
:run
REM ; Make current folder active one
pushd %~dp0
REM ; Remove random reg keys (Startup/Privacy/Policies/Malware related)
Echo Y | Reg.exe delete "HKEY_CURRENT_USER\Software\Microsoft\Command Processor" /v "AutoRun" /f
Echo Y | Reg.exe delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /f
Echo Y | Reg.exe delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /f
Echo Y | Reg.exe delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved" /f
Echo Y | Reg.exe delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" /f
Echo Y | Reg.exe delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery" /f
Echo Y | Reg.exe delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\PackagedAppXDebug" /f
Echo Y | Reg.exe delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies" /f
Echo Y | Reg.exe delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /f
Echo Y | Reg.exe delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce" /f
Echo Y | Reg.exe delete "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v "Load" /f
Echo Y | Reg.exe delete "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /f
Echo Y | Reg.exe delete "HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell" /f
Echo Y | Reg.exe delete "HKEY_CURRENT_USER\Software\Policies" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Command Processor" /v "AutoRun" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Policies" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Tracing" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\AppModelUnlock" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Font Drivers" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v "AppInit_DLLs" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "VMApplet" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AlternateShells" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Taskman" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Policies" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\WOW6432Node\Microsoft\Policies" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\WOW6432Node\Microsoft\Tracing" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /v "AppInit_DLLs" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "VMApplet" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\AlternateShells" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\Taskman" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\WOW6432Node\Policies" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Keyboard Layout" /v "Scancode Map" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SafeBoot" /v "AlternateShell" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\winreg" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager" /v "BootExecute" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager" /v "Execute" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager" /v "SETUPEXECUTE" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server\Wds\rdpwd" /v "StartupPrograms" /f
REM ; Remove random files/folders
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
REM ; Restore essential startup entries
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
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /t REG_SZ /d "explorer.exe" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit" /t REG_SZ /d "C:\Windows\System32\userinit.exe," /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell" /t REG_SZ /d "explorer.exe" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager" /v "BootExecute" /t REG_MULTI_SZ /d "autocheck autochk *" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager" /v "SETUPEXECUTE" /t REG_MULTI_SZ /d "" /f
REM ; Remove user account
net user defaultuser0 /delete
REM ; Prevent files from being run/altered/recreated
takeown /f "%WINDIR%\System32\sethc.exe" /a
icacls "%WINDIR%\System32\sethc.exe" /remove "Administrators" "Authenticated Users" "Users" "System"
takeown /f "%WINDIR%\SysWOW64\sethc.exe" /a
icacls "%WINDIR%\SysWOW64\sethc.exe" /remove "Administrators" "Authenticated Users" "Users" "System"
takeown /f "%WINDIR%\System32\utilman.exe" /a
icacls "%WINDIR%\System32\utilman.exe" /remove "Administrators" "Authenticated Users" "Users" "System"
takeown /f "%WINDIR%\SysWOW64\utilman.exe" /a
icacls "%WINDIR%\SysWOW64\utilman.exe" /remove "Administrators" "Authenticated Users" "Users" "System"
REM ; Debloat
powershell "Get-AppxPackage -AllUsers | Where {($_.Name -notlike '*tore*')} | Where {($_.Name -notlike '*dge*')} | Where {($_.Name -notlike '*vidia*')} | Where {($_.Name -notlike '*dentity*')} | Where {($_.Name -notlike '*ost*')} | Where {($_.Name -notlike '*alc*')} | Where {($_.Name -notlike '*hotos*')} | Where {($_.Name -notlike '*hell*')} | Where {($_.Name -notlike '*ealtek*')} | Where {($_.Name -notlike '*olby*')} | Remove-AppxPackage"
powershell "Get-AppxProvisionedPackage -Online | Where {($_.Name -notlike '*tore*')} | Where {($_.Name -notlike '*dge*')} | Where {($_.Name -notlike '*vidia*')} | Where {($_.Name -notlike '*dentity*')} | Where {($_.Name -notlike '*ost*')} | Where {($_.Name -notlike '*alc*')} | Where {($_.Name -notlike '*hotos*')} | Where {($_.Name -notlike '*hell*')} | Where {($_.Name -notlike '*ealtek*')} | Where {($_.Name -notlike '*olby*')} | Remove-AppxProvisionedPackage -Online"
REM ; Take ownership of Desktop
takeown /s %computername% /u %username% /f "%SystemDrive%\Users\Public\Desktop" /r /d y
icacls "%SystemDrive%\Users\Public\Desktop" /grant:r %username%:(OI)(CI)F /t /l /q /c
takeown /s %computername% /u %username% /f "%USERPROFILE%\Desktop" /r /d y
icacls "%USERPROFILE%\Desktop" /grant:r %username%:(OI)(CI)F /t /l /q /c
REM ; Configure DNS
wmic nicconfig where (IPEnabled=TRUE) call SetDNSServerSearchOrder ("1.1.1.1", "8.8.8.8", "9.9.9.9")
:next
REM ; Autorun
rem 0 - Use Autoplay for all media and devices
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v "DisableAutoplay" /t REG_DWORD /d "1" /f 
rem Disable AutoPlay and AutoRun
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d "255" /f
REM ; Feedback and diagnostics
rem Diagnostic and usage data - Select how much data you send to Microsoft / 0 - Security (Not aplicable on Home/Pro, it resets to Basic) / 1 - Basic / 2 - Enhanced (Hidden) / 3 - Full
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Telemetry" /v "Enabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f
rem 1 - Let Microsoft provide more tailored experiences with relevant tips and recommendations by using your diagnostic data
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f
rem Feedback Frequency - Windows should ask for my feedback: 0 - Never / Removed - Automatically
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d "0" /f
REM ; Keyboard Tweaks
rem Language bar options - Advanced key settings - Change Key Sequence
rem 3 - Not assigned / 2 - CTRL+SHIFT / 1 - Left ALT+SHIFT
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Keyboard Layout\Toggle" /v "Language Hotkey" /t REG_SZ /d "3" /f
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Keyboard Layout\Toggle" /v "Hotkey" /t REG_SZ /d "3" /f
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Keyboard Layout\Toggle" /v "Layout Hotkey" /t REG_SZ /d "3" /f
rem 2 - Enable Num Lock on Sign-in Screen / 2147483648 - Disable
Echo Y | Reg.exe add "HKU\.DEFAULT\Control Panel\Keyboard" /v "InitialKeyboardIndicators" /t REG_SZ /d "2" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Input" /v "InputServiceEnabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Input" /v "InputServiceEnabledForCCI" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\InputPersonalization" /v "AllowInputPersonalization" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d "1" /f
rem Autocorrect misspelled words (Privacy)
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\TabletTip\1.7" /v "EnableAutocorrection" /t REG_DWORD /d "0" /f
rem Highlight misspelled words (Privacy)
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\TabletTip\1.7" /v "EnableSpellchecking" /t REG_DWORD /d "0" /f
rem Show text suggestions as I type on the software keyboard (Privacy)
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\TabletTip\1.7" /v "EnableTextPrediction" /t REG_DWORD /d "0" /f
rem Add a space after I choose a text suggestion (Privacy)
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\TabletTip\1.7" /v "EnablePredictionSpaceInsertion" /t REG_DWORD /d "0" /f
rem Add a period after I double-tap the Spacebar (Privacy)
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\TabletTip\1.7" /v "EnableDoubleTapSpace" /t REG_DWORD /d "0" /f
rem Show recommended app suggestions (Privacy)
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\PenWorkspace" /v "PenWorkspaceAppSuggestionsEnabled" /t REG_DWORD /d "0" /f
rem Sticky Keys / 26 - Disable All / 511 - Default
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "26" /f
rem Toggle Keys / 58 - Disable All / 63 - Default
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "58" /f
rem 1 - Disable Windows Key Hotkeys
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoWinKeys" /t REG_DWORD /d "1" /f
rem Disable specific Windows Key Hotkeys only (like R = Win+R)
rem Echo Y | Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisabledHotkeys" /t REG_EXPAND_SZ /d "R" /f
REM ; Radios
rem Let apps control radios / 0 - Default / 1 - Enabled / 2 - Disabled
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessRadios" /t REG_DWORD /d "2" /f
REM ; Networking Tweaks
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "autodisconnect" /t REG_DWORD /d "4294967295" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "Size" /t REG_DWORD /d "3" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "EnableOplocks" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "32" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationDelay" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationRetries" /t REG_DWORD /d "0" /f
REM ; Performance Tweaks
rem n - Disable Background disk defragmentation / y - Enable How long in milliseconds you want to have for a startup delay time for desktop apps that run at startup to load
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Dfrg\BootOptimizeFunction" /v "Enable" /t REG_SZ /d "n" /f
rem 0 - Disable Background auto-layout / Disable Optimize Hard Disk when idle
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\OptimalLayout" /v "EnableAutoLayout" /t REG_DWORD /d "0" /f
rem Disable Automatic Maintenance / Scheduled System Maintenance
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\ScheduledDiagnostics" /v "EnabledExecution" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\ScheduledDiagnostics" /v "EnabledExecution" /t REG_DWORD /d "0" /f
rem 0 - Enables 8dot3 name creation for all volumes on the system / 1 - Disables 8dot3 name creation for all volumes on the system / 2 - Sets 8dot3 name creation on a per volume basis / 3 - Disables 8dot3 name creation for all volumes except the system volume
rem fsutil 8dot3name scan c:\
fsutil behavior set disable8dot3 1
rem 1 - Disable the Encrypting File System (EFS)
fsutil behavior set disableencryption 1
rem 1 - When listing directories, NTFS does not update the last-access timestamp, and it does not record time stamp updates in the NTFS log
fsutil behavior set disablelastaccess 0
rem 5 - 5 secs / Delay Chkdsk startup time at OS Boot
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager" /v "AutoChkTimeout" /t REG_DWORD /d "5" /f
rem 0 - Establishes a standard size file-system cache of approximately 8 MB / 1 - Establishes a large system cache working set that can expand to physical memory, minus 4 MB, if needed
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "1" /f
rem 0 - Drivers and the kernel can be paged to disk as needed / 1 - Drivers and the kernel must remain in physical memory
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f
rem 0 - Disable Prefetch / 1 - Enable Prefetch when the application starts / 2 - Enable Prefetch when the device starts up / 3 - Enable Prefetch when the application or device starts up
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f
rem 0 - Disable SuperFetch / 1 - Enable SuperFetch when the application starts up / 2 - Enable SuperFetch when the device starts up / 3 - Enable SuperFetch when the application or device starts up
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "3" /f
rem 0 - Disable It / 1 - Default
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "SfTracingState" /t REG_DWORD /d "0" /f
rem 0 - Disable Fast Startup for a Full Shutdown / 1 - Enable Fast Startup (Hybrid Boot) for a Hybrid Shutdown
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem" /v "LongPathsEnabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsAllowExtendedCharacter8dot3Rename" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsDisable8dot3NameCreation" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "8" /f
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "ForegroundLockTimeout" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "8" /f
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PagingFiles" /t REG_MULTI_SZ /d "" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "ExistingPageFiles" /t REG_MULTI_SZ /d "" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Dfrg\BootOptimizeFunction" /v "Enable" /t REG_SZ /d "y" /f
REM ; Firewall
rem Block all inbound network traffic and all outbound except allowed apps
netsh advfirewall set DomainProfile firewallpolicy blockinboundalways,blockoutbound
netsh advfirewall set PrivateProfile firewallpolicy blockinboundalways,blockoutbound
netsh advfirewall set PublicProfile firewallpolicy blockinbound,allowoutbound
rem Remove All Windows Firewall Rules
netsh advfirewall firewall delete rule name=all
REM ; Logging
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\AppModel" /v "Start" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\Circular Kernel Context Logger" /v "Start" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\CShellCircular" /v "Start" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\CloudExperienceHostOobe" /v "Start" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\EventLog-Application" /v "Start" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\EventLog-Security" /v "Start" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\EventLog-System" /v "Start" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\DiagLog" /v "Start" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\FaceRecoTel" /v "Start" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\FaceUnlock" /v "Start" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\LwtNetLog" /v "Start" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\NetCore" /v "Start" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\NtfsLog" /v "Start" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\ReadyBoot" /v "Start" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\TileStore" /v "Start" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\Tpm" /v "Start" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\UBPM" /v "Start" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\WdiContextLog" /v "Start" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\WiFiDriverIHVSession" /v "Start" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\WiFiSession" /v "Start" /t REG_DWORD /d "0" /f
REM ; Error reporting
rem Disable Microsoft Support Diagnostic Tool MSDT
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /v "DisableQueryRemoteServer" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /v "EnableQueryRemoteServer" /t REG_DWORD /d "0" /f
rem Disable System Debugger (Dr. Watson)
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\AeDebug" /v "Auto" /t REG_SZ /d "0" /f
rem 1 - Disable Windows Error Reporting (WER)
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\PCHealth\ErrorReporting" /v "DoReport" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\PCHealth\ErrorReporting" /v "ShowUI" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
rem DefaultConsent / 1 - Always ask (default) / 2 - Parameters only / 3 - Parameters and safe data / 4 - All data
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultConsent" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultOverrideBehavior" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultConsent" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultOverrideBehavior" /t REG_DWORD /d "1" /f
rem 1 - Disable WER sending second-level data
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f
rem 1 - Disable WER crash dialogs, popups
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\PCHealth\ErrorReporting" /v "ShowUI" /t REG_DWORD /d "0" /f
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d "1" /f
rem 1 - Disable WER logging
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f
schtasks /Change /TN "Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable
rem Windows Error Reporting Service
sc config WerSvc start= disabled
rem Remove Windows Errror Reporting (to restore run "sfc /scannow")
takeown /f "%WinDir%\System32\WerFault.exe" /a
icacls "%WinDir%\System32\WerFault.exe" /grant:r Administrators:F /c
taskkill /im WerFault.exe /f
del "%WinDir%\System32\WerFault.exe" /s /f /q
REM ; Explorer advanced settings
rem 1 - Show hidden files, folders and drives
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d "1" /f
rem 0 - Show extensions for known file types
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d "0" /f
rem 0 - Hide protected operating system files 
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d "0" /f
rem 1 - Launch folder windows in a separate process
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "SeparateProcess" /t REG_DWORD /d "1" /f
rem 1 - Show Sync Provider Notifications in Windows Explorer (ADs)
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d "0" /f
rem 1 - Use Sharing Wizard
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "SharingWizardOn" /t REG_DWORD /d "0" /f
rem Navigation pane - 1 - Expand to open folder
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "NavPaneExpandToCurrentFolder" /t REG_DWORD /d "0" /f
rem 0 - All of the components of Windows Explorer run a single process / 1 - All instances of Windows Explorer run in one process and the Desktop and Taskbar run in a separate process
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "DesktopProcess" /t REG_DWORD /d "1" /f
rem Yes - Use Inline AutoComplete in File Explorer and Run Dialog / No
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete" /v "Append Completion" /t REG_SZ /d "No" /f
rem 0 - Do this for all current items checkbox / 1 - Disabled
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v "ConfirmationCheckBoxDoForAll" /t REG_DWORD /d "0" /f
rem 1 - Always show more details in copy dialog
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v "EnthusiastMode" /t REG_DWORD /d "0" /f
rem 1 - Display confirmation dialog when deleting files
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ConfirmFileDelete" /t REG_DWORD /d "1" /f
rem 1075839525 - Auto arrange icons and Align icons to grid on Desktop / 1075839520 / 1075839521 / 1075839524
Echo Y | Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Bags\1\Desktop" /v "FFlags" /t REG_DWORD /d "1075839525" /f
REM ; Priority Tweaks
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ8Priority" /t REG_DWORD /d "1" /f
REM ; SSRP
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\safer" /f
REM ; Pagefile
wmic computersystem where name="%computername%" set AutomaticManagedPagefile=False
wmic pagefileset where name="%SystemDrive%\\pagefile.sys" set InitialSize=0,MaximumSize=0
wmic pagefileset where name="%SystemDrive%\\pagefile.sys" delete
REM ; CPU Scheduling
rem 0 - Foreground and background applications equally responsive / 1 - Foreground application more responsive than background / 2 - Best foreground application response time (Default)
rem 38 - Adjust for best performance of Programs / 24 - Adjust for best performance of Background Services
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation " /t REG_DWORD /d "0" /f
REM ; System Restore
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableSR" /f
Echo Y | Reg.exe delete "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableConfig" /f
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\SPP\Clients" /v " {09F7EDC5-294E-4180-AF6A-FB0E6A0E9513}" /t REG_MULTI_SZ /d "1" /f
schtasks /Change /TN "Microsoft\Windows\SystemRestore\SR" /Enable
vssadmin Resize ShadowStorage /For=C: /On=C: /Maxsize=5GB
sc config wbengine start= demand
sc config swprv start= demand
sc config vds start= demand
sc config VSS start= demand
REM ; Reduce windows size
vssadmin delete shadows /all /quiet
dism /online /cleanup-image /startcomponentcleanup /resetbase
compact /compactos:always
REM ; File history
rem 1 - Disable File History (Creating previous versions of files/Windows Backup)
Echo Y | Reg.exe add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\FileHistory" /v "Disabled" /t REG_DWORD /d "1" /f
REM ; Tasks
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
REM ; Import registry
Reg.exe import GSecurity.reg
REM ; Exit
popd
exit /b
:UACPrompt
echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
echo UAC.ShellExecute "cmd.exe", "/c %~s0 %~1", "", "runas", 1 >> "%temp%\getadmin.vbs"
"%temp%\getadmin.vbs"
del "%temp%\getadmin.vbs"
goto:eof

