@Echo Off
cd %systemroot%\system32
call :IsAdmin
pushd %~dp0
takeown /F "%SystemDrive%" /r /d y
icacls "%SystemDrive%" /grant:r %username%:(OI)(CI)F /t /l /q /c
takeown /F "%USERPROFILE%" /r /d y
icacls "%USERPROFILE%" /grant:r %username%:(OI)(CI)F /t /l /q /c
Exit
:IsAdmin
Reg.exe query "HKU\S-1-5-19\Environment"
If Not %ERRORLEVEL% EQU 0 (
 Cls & Echo You must have administrator rights to continue ... 
 Pause & Exit
)
Cls
goto:eof
