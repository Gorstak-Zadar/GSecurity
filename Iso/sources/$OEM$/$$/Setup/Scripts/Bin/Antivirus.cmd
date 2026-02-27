@echo off

:: Step 1: Elevate
>nul 2>&1 fsutil dirty query %systemdrive% || echo CreateObject^("Shell.Application"^).ShellExecute "%~0", "ELEVATED", "", "runas", 1 > "%temp%\uac.vbs" && "%temp%\uac.vbs" && exit /b
DEL /F /Q "%temp%\uac.vbs"

:: Step 2: Initialize environment
setlocal EnableExtensions EnableDelayedExpansion

:: Step 3: Move to the script directory
cd /d %~dp0

:: Step 4: Execute PowerShell (.ps1) files with staggered delays to reduce CPU/RAM spikes
echo Executing PowerShell scripts with optimized startup delays...
set /a counter=0
for /f "tokens=*" %%A in ('dir /b /o:n *.ps1') do (
    if !counter! gtr 0 (
        echo Waiting 2 seconds before next module to reduce CPU/RAM spike...
        timeout /t 2 /nobreak >nul 2>&1
    )
    echo Running %%A...
    start "" /b powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -File "%%A"
    :: Stagger launches: 2 second delay between each module to prevent CPU/RAM spike at startup
    set /a counter+=1
)

exit

