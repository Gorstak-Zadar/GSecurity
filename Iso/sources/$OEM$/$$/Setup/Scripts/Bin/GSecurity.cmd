@echo off
SETLOCAL ENABLEDELAYEDEXPANSION

:: Script Metadata
set "SCRIPT_NAME=System Cleanup Utility"
set "SCRIPT_VERSION=1.0.0"
set "SCRIPT_UPDATED=2025-03-10"
set "AUTHOR=vocatus (consolidated by Grok/xAI)"

:: Configuration Variables
set "LOGPATH=%SystemDrive%\Logs"
set "LOGFILE=%COMPUTERNAME%_system_cleanup.log"
set "FORCE_CLOSE_PROCESSES=yes"
set "FORCE_CLOSE_PROCESSES_EXIT_CODE=1618"
set "LOG_MAX_SIZE=2097152"  :: 2MB

:: Process and GUID Lists
set "BROWSER_PROCESSES=battle chrome firefox flash iexplore iexplorer opera palemoon plugin-container skype steam yahoo"
set "VNC_PROCESSES=winvnc winvnc4 uvnc_service tvnserver"
set "FLASH_GUIDS_ACTIVE_X=cdf0cc64-4741-4e43-bf97-fef8fa1d6f1c ..."
set "FLASH_GUIDS_PLUGIN=F6E23569-A22A-4924-93A4-3F215BEF63D2 ..."

:: Initialize Environment
title %SCRIPT_NAME% v%SCRIPT_VERSION% (%SCRIPT_UPDATED%)
call :get_current_date
if not exist "%LOGPATH%" mkdir "%LOGPATH%" 2>NUL
pushd "%~dp0"
call :check_admin_rights
call :detect_os_version
call :handle_log_rotation

:: Main Execution
call :log "Starting system cleanup..."

:cleanup_flash
call :log "Cleaning Adobe Flash Player..."
if /i "%FORCE_CLOSE_PROCESSES%"=="yes" (call :force_close_flash) else (call :check_flash_processes)
call :remove_flash

:cleanup_vnc
call :log "Cleaning VNC installations..."
call :remove_vnc

:cleanup_temp
call :log "Cleaning temporary files..."
call :clean_temp_files

:cleanup_usb
call :log "Cleaning USB device registry..."
call :clean_usb_devices

:GSecurity
call :log "GSecurity..."
call :GSecurity
goto :complete

:complete
call :log "System cleanup complete."
goto :cleanup

:: Core Functions
:get_current_date
    for /f "tokens=1 delims=." %%a in ('wmic os get localdatetime ^| find "."') do set "DTS=%%a"
    set "CUR_DATE=!DTS:~0,4!-!DTS:~4,2!-!DTS:~6,2!"
    goto :eof

:log
    echo %CUR_DATE% %TIME%   %~1 >> "%LOGPATH%\%LOGFILE%"
    echo %CUR_DATE% %TIME%   %~1
    goto :eof

:check_admin_rights
    net session >nul 2>&1 || (
        call :log "ERROR: Administrative privileges required."
        goto :eof
    )
    goto :eof

:detect_os_version
    set "OS_VERSION=OTHER"
    ver | find /i "XP" >NUL && set "OS_VERSION=XP"
    for /f "tokens=3*" %%i in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName ^| find "ProductName"') do set "WIN_VER=%%i %%j"
    goto :eof

:handle_log_rotation
    if not exist "%LOGPATH%\%LOGFILE%" echo. > "%LOGPATH%\%LOGFILE%"
    for %%R in ("%LOGPATH%\%LOGFILE%") do if %%~zR GEQ %LOG_MAX_SIZE% (
        pushd "%LOGPATH%"
        del "%LOGFILE%.ancient" 2>NUL
        for %%s in (oldest older old) do if exist "%LOGFILE%.%%s" ren "%LOGFILE%.%%s" "%LOGFILE%.%%s.old" 2>NUL
        ren "%LOGFILE%" "%LOGFILE%.old" 2>NUL
        popd
    )
    goto :eof

:: Flash Cleanup Functions
:force_close_flash
    call :log "Closing Flash-related processes..."
    for %%i in (%BROWSER_PROCESSES%) do taskkill /F /IM "%%i*" /T >> "%LOGPATH%\%LOGFILE%" 2>NUL
    goto :eof

:check_flash_processes
    call :log "Checking for running Flash processes..."
    for %%i in (%BROWSER_PROCESSES%) do (
        for /f "delims=" %%a in ('tasklist ^| find /i "%%i"') do (
            if not "%%a"=="" (
                call :log "ERROR: Process '%%i' running, aborting."
                goto :eof
            )
        )
    )
    goto :eof

:remove_flash
    call :log "Removing Flash Player..."
    wmic product where "name like 'Adobe Flash Player%%'" uninstall /nointeractive >> "%LOGPATH%\%LOGFILE%" 2>NUL
    for %%g in (%FLASH_GUIDS_ACTIVE_X% %FLASH_GUIDS_PLUGIN%) do MsiExec.exe /uninstall {%%g} /quiet /norestart >> "%LOGPATH%\%LOGFILE%" 2>NUL
    goto :eof

:: VNC Cleanup Functions
:remove_vnc
    call :log "Stopping VNC services..."
    for %%s in (%VNC_PROCESSES%) do (
        net stop %%s >> "%LOGPATH%\%LOGFILE%" 2>NUL
        taskkill /F /IM %%s.exe >> "%LOGPATH%\%LOGFILE%" 2>NUL
        sc delete %%s >> "%LOGPATH%\%LOGFILE%" 2>NUL
    )
    call :log "Removing VNC registry entries..."
    for %%k in (UltraVNC ORL RealVNC TightVNC) do reg delete "HKLM\SOFTWARE\%%k" /f >> "%LOGPATH%\%LOGFILE%" 2>NUL
    call :log "Removing VNC files..."
    for %%d in (UltraVNC "uvnc bvba" RealVNC TightVNC) do (
        rd /s /q "%ProgramFiles%\%%d" 2>NUL
        rd /s /q "%ProgramFiles(x86)%\%%d" 2>NUL
    )
    goto :eof

:: Temp File Cleanup Functions
:clean_temp_files
    call :log "Cleaning user temp files..."
    del /F /S /Q "%TEMP%\*" >> "%LOGPATH%\%LOGFILE%" 2>NUL
    if /i "%WIN_VER:~0,9%"=="Microsoft" (
        for /D %%x in ("%SystemDrive%\Documents and Settings\*") do call :clean_user_xp "%%x"
    ) else (
        for /D %%x in ("%SystemDrive%\Users\*") do call :clean_user_vista "%%x"
    )
    call :log "Cleaning system temp files..."
    del /F /S /Q "%WINDIR%\TEMP\*" >> "%LOGPATH%\%LOGFILE%" 2>NUL
    for %%i in (NVIDIA ATI AMD Dell Intel HP) do rmdir /S /Q "%SystemDrive%\%%i" >> "%LOGPATH%\%LOGFILE%" 2>NUL
    goto :eof

:clean_user_xp
    del /F /Q "%~1\Local Settings\Temp\*" >> "%LOGPATH%\%LOGFILE%" 2>NUL
    del /F /Q "%~1\Recent\*" >> "%LOGPATH%\%LOGFILE%" 2>NUL
    goto :eof

:clean_user_vista
    del /F /S /Q "%~1\AppData\Local\Temp\*" >> "%LOGPATH%\%LOGFILE%" 2>NUL
    del /F /S /Q "%~1\AppData\Roaming\Macromedia\Flash Player\*" >> "%LOGPATH%\%LOGFILE%" 2>NUL
    goto :eof

:: USB Device Cleanup
:clean_usb_devices
    call :log "Cleaning USB device registry..."
    reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /f >> "%LOGPATH%\%LOGFILE%" 2>NUL
    reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2" /f >> "%LOGPATH%\%LOGFILE%" 2>NUL
    goto :eof

:GSecurity
set KEY=HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network
set SETACL=%~dp0SetACL.exe
set DEVCON=%~dp0devcon.exe
set LOGFILE=network_cleanup_log.txt

echo Starting network cleanup at %DATE% %TIME% > %LOGFILE%

:: Verify devcon.exe exists
if not exist %DEVCON% (
    echo Error: devcon.exe not found at %DEVCON%. Please download from Microsoft WDK or Support Tools. >> %LOGFILE%
    call :log "Error: devcon.exe not found, skipping device-related operations."
) else (
    :: List all network adapters
    echo Listing network adapters... >> %LOGFILE%
    netsh interface show interface >> %LOGFILE%
    %DEVCON% find *NET* >> %LOGFILE%

    :: Unbridge network adapters
    echo Checking for network bridges... >> %LOGFILE%
    netsh bridge show adapter >> %LOGFILE%
    echo Unbridging adapters... >> %LOGFILE%
    netsh bridge uninstall
    if %ERRORLEVEL% NEQ 0 (
        echo Failed to unbridge adapters! Continuing... >> %LOGFILE%
        call :log "Warning: Failed to unbridge network adapters."
    )

    :: Disable unauthorized adapters (placeholder - replace with actual adapter names)
    echo Disabling unauthorized adapters... >> %LOGFILE%
    :: Example: netsh interface set interface "TAP-Windows Adapter V9" disable
    :: netsh interface set interface "<AdapterName>" disable
    :: if %ERRORLEVEL% NEQ 0 (
    ::     echo Failed to disable adapter <AdapterName>! >> %LOGFILE%
    ::     call :log "Warning: Failed to disable adapter <AdapterName>."
    :: )

    :: Remove unauthorized adapters (placeholder - replace with actual DeviceIDs from devcon)
    echo Removing unauthorized adapters... >> %LOGFILE%
    :: Example: %DEVCON% remove @PCI\VEN_8086&DEV_...
    :: %DEVCON% remove @<DeviceID>
    :: if %ERRORLEVEL% NEQ 0 (
    ::     echo Failed to remove adapter <DeviceID>! >> %LOGFILE%
    ::     call :log "Warning: Failed to remove adapter <DeviceID>."
    :: )
)

:: Verify SetACL.exe exists
if not exist %SETACL% (
    echo Error: SetACL.exe not found at %SETACL%. >> %LOGFILE%
    call :log "Error: SetACL.exe not found, skipping registry permission changes."
) else (
    :: Backup registry permissions
    echo Backing up current registry permissions... >> %LOGFILE%
    %SETACL% -on "%KEY%" -ot reg -actn list -lst "f:sddl;w:dacl" -bckp "network_permissions_backup.txt"
    if %ERRORLEVEL% NEQ 0 (
        echo Backup failed! Continuing... >> %LOGFILE%
        call :log "Warning: Registry permission backup failed."
    )

    :: Remove Everyone group
    echo Removing Everyone group... >> %LOGFILE%
    %SETACL% -on "%KEY%" -ot reg -actn trustee -trst "n1:Everyone;ta:remtrst;w:dacl"
    if %ERRORLEVEL% NEQ 0 (
        echo Failed to remove Everyone! Continuing... >> %LOGFILE%
        call :log "Warning: Failed to remove Everyone group from registry permissions."
    )

    :: Set default permissions
    echo Setting default permissions... >> %LOGFILE%
    %SETACL% -on "%KEY%" -ot reg -actn ace -ace "n:Administrators;p:full" -rec cont_obj
    %SETACL% -on "%KEY%" -ot reg -actn ace -ace "n:SYSTEM;p:full" -rec cont_obj
    %SETACL% -on "%KEY%" -ot reg -actn ace -ace "n:Users;p:read" -rec cont_obj
    %SETACL% -on "%KEY%" -ot reg -actn ace -ace "n:CREATOR OWNER;p:full;i:so,sc" -rec cont_obj
    if %ERRORLEVEL% NEQ 0 (
        echo Failed to set permissions! Continuing... >> %LOGFILE%
        call :log "Warning: Failed to set registry permissions."
    )

    :: Set ownership to Administrators
    echo Setting ownership to Administrators... >> %LOGFILE%
    %SETACL% -on "%KEY%" -ot reg -actn setowner -ownr "n:Administrators" -rec cont_obj
    if %ERRORLEVEL% NEQ 0 (
        echo Failed to set ownership! Continuing... >> %LOGFILE%
        call :log "Warning: Failed to set registry ownership."
    )

    :: Enable inheritance
    echo Enabling inheritance... >> %LOGFILE%
    %SETACL% -on "%KEY%" -ot reg -actn setprot -op "dacl:np;sacl:np"
    if %ERRORLEVEL% NEQ 0 (
        echo Failed to enable inheritance! Continuing... >> %LOGFILE%
        call :log "Warning: Failed to enable registry inheritance."
    )

    :: Verify final state
    echo Verifying registry permissions... >> %LOGFILE%
    %SETACL% -on "%KEY%" -ot reg -actn list -lst "f:table;w:dacl" >> %LOGFILE%
)

:: Verify network adapters
echo Verifying network adapters... >> %LOGFILE%
net-Echo Verifying network adapters... >> %LOGFILE%
netsh interface show interface >> %LOGFILE%

:: User account cleanup (riddance)
call :log "Cleaning up user accounts..."
for /f "tokens=1,2*" %%x in ('whoami /user /fo list ^| findstr /i "name sid"') do (
    set "USERNAME=%%z"
    set "USERSID=%%y"
)
for /f "tokens=5 delims=-" %%r in ("!USERSID!") do set "RID=%%r"
for /f "tokens=*" %%u in ('net user ^| findstr /i /c:"User" ^| find /v "command completed successfully"') do (
    set "USERLINE=%%u"
    set "USERRID=!USERLINE:~-4!"
    if !USERRID! neq !RID! (
        echo Removing user: !USERLINE! >> %LOGFILE%
        net user !USERLINE! /delete
        if %ERRORLEVEL% NEQ 0 (
            call :log "Warning: Failed to delete user !USERLINE!."
        )
    )
)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to enable UAC via registry."
)

:: Services stop and disable
call :log "Stopping and disabling services..."
sc stop LanmanWorkstation
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to stop LanmanWorkstation service."
)
sc stop LanmanServer
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to stop LanmanServer service."
)
sc stop seclogon
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to stop seclogon service."
)
sc config LanmanWorkstation start= disabled
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to disable LanmanWorkstation service."
)
sc config LanmanServer start= disabled
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to disable LanmanServer service."
)
sc config seclogon start= disabled
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to disable seclogon service."
)

:: Install RamCleaner
call :log "Installing RamCleaner..."
mkdir %windir%\Setup\Scripts
mkdir %windir%\Setup\Scripts\Bin
copy /y emptystandbylist.exe %windir%\Setup\Scripts\Bin\emptystandbylist.exe
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to copy emptystandbylist.exe."
)
copy /y RamCleaner.bat %windir%\Setup\Scripts\Bin\RamCleaner.bat
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to copy RamCleaner.bat."
)
schtasks /create /tn "RamCleaner" /xml "RamCleaner.xml" /ru "SYSTEM"
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to create RamCleaner scheduled task."
)

:: EDR (commented out as it seems incomplete)
:: rem setup.exe /s /v"/qn"

:: Security Policy Import
call :log "Importing security policy..."
LGPO.exe /s GSecurity.inf
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to import security policy with LGPO.exe."
)

:: Install elam driver
call :log "Installing ELAM driver..."
pnputil /add-driver *.inf /subdirs /install
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to install ELAM driver."
)

:: Mini filter drivers
call :log "Removing mini filter drivers..."
fltmc unload bfs
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to unload bfs filter."
)
fltmc unload unionfs
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to unload unionfs filter."
)
takeown /f %windir%\system32\drivers\bfs.sys /A
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to take ownership of bfs.sys."
)
takeown /f %windir%\system32\drivers\unionfs.sys /A
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to take ownership of unionfs.sys."
)
icacls %windir%\system32\drivers\bfs.sys /reset
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to reset permissions on bfs.sys."
)
icacls %windir%\system32\drivers\unionfs.sys /reset
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to reset permissions on unionfs.sys."
)
icacls %windir%\system32\drivers\bfs.sys /inheritance:d
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to disable inheritance on bfs.sys."
)
icacls %windir%\system32\drivers\unionfs.sys /inheritance:d
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to disable inheritance on unionfs.sys."
)
del %windir%\system32\drivers\bfs.sys /Q
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to delete bfs.sys."
)
del %windir%\system32\drivers\unionfs.sys /Q
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to delete unionfs.sys."
)

:: BIOS tweaks
call :log "Applying BIOS tweaks..."
set bcd=%windir%\system32\bcdedit.exe
%bcd% /set nx AlwaysOff
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to set nx AlwaysOff."
)
%bcd% /set ems No
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to set ems No."
)
%bcd% /set bootems No
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to set bootems No."
)
%bcd% /set integrityservices disable
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to set integrityservices disable."
)
%bcd% /set tpmbootentropy ForceDisable
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to set tpmbootentropy ForceDisable."
)
%bcd% /set bootmenupolicy Legacy
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to set bootmenupolicy Legacy."
)
%bcd% /set debug No
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to set debug No."
)
%bcd% /set disableelamdrivers Yes
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to set disableelamdrivers Yes."
)
%bcd% /set isolatedcontext No
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to set isolatedcontext No."
)
%bcd% /set allowedinmemorysettings 0x0
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to set allowedinmemorysettings 0x0."
)
%bcd% /set vm No
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to set vm No."
)
%bcd% /set vsmlaunchtype Off
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to set vsmlaunchtype Off."
)
%bcd% /set configaccesspolicy Default
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to set configaccesspolicy Default."
)
%bcd% /set MSI Default
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to set MSI Default."
)
%bcd% /set usephysicaldestination No
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to set usephysicaldestination No."
)
%bcd% /set usefirmwarepcisettings No
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to set usefirmwarepcisettings No."
)
%bcd% /set sos No
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to set sos No."
)
%bcd% /set pae ForceDisable
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to set pae ForceDisable."
)
%bcd% /set tscsyncpolicy legacy
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to set tscsyncpolicy legacy."
)
%bcd% /set hypervisorlaunchtype off
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to set hypervisorlaunchtype off."
)
%bcd% /set useplatformclock false
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to set useplatformclock false."
)
%bcd% /set useplatformtick no
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to set useplatformtick no."
)
%bcd% /set disabledynamictick yes
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to set disabledynamictick yes."
)
%bcd% /set x2apicpolicy disable
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to set x2apicpolicy disable."
)
%bcd% /set uselegacyapicmode yes
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to set uselegacyapicmode yes."
)

:: Permissions
call :log "Setting file and folder permissions..."
takeown /f %windir%\System32\Oobe\useroobe.dll /A
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to take ownership of useroobe.dll."
)
icacls %windir%\System32\Oobe\useroobe.dll /inheritance:r
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to disable inheritance on useroobe.dll."
)
icacls "%systemdrive%\Users" /remove "Everyone"
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to remove Everyone from Users directory."
)
takeown /f "%USERPROFILE%\Desktop" /r /d y
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to take ownership of Desktop."
)
icacls "%USERPROFILE%\Desktop" /inheritance:r
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to disable inheritance on Desktop."
)
icacls "%USERPROFILE%\Desktop" /grant:r %username%:(OI)(CI)F /t /l /q /c
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to grant permissions to %username% on Desktop."
)
icacls "%USERPROFILE%\Desktop" /remove "System" /t /c /l
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to remove System from Desktop permissions."
)
icacls "%USERPROFILE%\Desktop" /remove "Administrators" /t /c /l
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to remove Administrators from Desktop permissions."
)
icacls "C:\Users\Public" /reset /T
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to reset permissions on C:\Users\Public."
)
takeown /f "C:\Users\Public\Desktop" /r /d y
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to take ownership of Public Desktop."
)
icacls "C:\Users\Public\Desktop" /inheritance:r
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to disable inheritance on Public Desktop."
)
icacls "C:\Users\Public\Desktop" /grant:r %username%:(OI)(CI)F /t /l /q /c
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to grant permissions to %username% on Public Desktop."
)
icacls "C:\Users\Public\Desktop" /remove "System" /t /c /l
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to remove System from Public Desktop permissions."
)
icacls "C:\Users\Public\Desktop" /remove "Administrators" /t /c /l
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to remove Administrators from Public Desktop permissions."
)

:: Consent
call :log "Configuring consent settings..."
takeown /f %windir%\system32\consent.exe /A
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to take ownership of consent.exe."
)
icacls %windir%\system32\consent.exe /inheritance:r /T /C
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to disable inheritance on consent.exe."
)
icacls %windir%\system32\consent.exe /grant:r "Console Logon":RX
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to grant Console Logon read/execute on consent.exe."
)
icacls %windir%\system32\consent.exe /remove "ALL APPLICATION PACKAGES"
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to remove ALL APPLICATION PACKAGES from consent.exe."
)
icacls %windir%\system32\consent.exe /remove "ALL RESTRICTED APPLICATION PACKAGES"
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to remove ALL RESTRICTED APPLICATION PACKAGES from consent.exe."
)
icacls %windir%\system32\consent.exe /remove "System"
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to remove System from consent.exe permissions."
)
icacls %windir%\system32\consent.exe /remove "Users"
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to remove Users from consent.exe permissions."
)
icacls %windir%\system32\consent.exe /remove "Authenticated Users"
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to remove Authenticated Users from consent.exe permissions."
)
icacls %windir%\system32\consent.exe /remove "Administrators"
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to remove Administrators from consent.exe permissions."
)
icacls %windir%\system32\consent.exe /remove "NT SERVICE\TrustedInstaller"
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to remove TrustedInstaller from consent.exe permissions."
)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "1" /f
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to set ConsentPromptBehaviorAdmin in HKLM."
)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d "1" /f
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to set ConsentPromptBehaviorUser in HKLM."
)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "1" /f
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to set ConsentPromptBehaviorAdmin in HKCU."
)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d "1" /f
if %ERRORLEVEL% NEQ 0 (
    call :log "Warning: Failed to set ConsentPromptBehaviorUser in HKCU."
)

echo Cleanup completed at %DATE% %TIME%. Check %LOGFILE% for details.
goto :eof

:cleanup
    popd
    goto :eof