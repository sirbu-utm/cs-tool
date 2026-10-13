@echo off
setlocal
chcp 65001 >nul
set "PYTHONUTF8=1"
pushd "%~dp0"

set "UV_EXE="

where uv >nul 2>nul
if not errorlevel 1 set "UV_EXE=uv"
if not defined UV_EXE (
    if exist "%USERPROFILE%\.local\bin\uv.exe" (
        set "UV_EXE=%USERPROFILE%\.local\bin\uv.exe"
    ) else if exist "%USERPROFILE%\.cargo\bin\uv.exe" (
        set "UV_EXE=%USERPROFILE%\.cargo\bin\uv.exe"
    ) else (
        echo [!] uv is not installed. Installing a pinned, checksum-verified uv...
        powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\install-uv.ps1"
        if exist "%USERPROFILE%\.local\bin\uv.exe" set "UV_EXE=%USERPROFILE%\.local\bin\uv.exe"
        if exist "%USERPROFILE%\.cargo\bin\uv.exe" set "UV_EXE=%USERPROFILE%\.cargo\bin\uv.exe"
    )
)

if not defined UV_EXE (
    echo [!] uv installation failed. Install uv and run this file again.
    popd
    exit /b 1
)

"%UV_EXE%" sync --extra dev --no-install-workspace --inexact
if errorlevel 1 (
    echo [!] Failed to install project dependencies.
    popd
    exit /b 1
)

rem With arguments (a command, a script, CI): run it right here, as before.
if not "%~1"=="" goto run_here

rem The interactive interface. Fetch any missing tool in this window first,
rem so the interface itself opens on a clean screen with nothing to install.
"%UV_EXE%" run --no-sync python -m cyberfw.cli prepare
if errorlevel 1 (
    echo [!] Could not prepare the tools.
    popd
    exit /b 1
)

rem Already inside Windows Terminal, or opted out with CYBERFW_NO_WT=1: stay in
rem this window - the interface clears the screen itself.
if defined WT_SESSION goto run_here
if defined CYBERFW_NO_WT goto run_here
where wt >nul 2>nul
if errorlevel 1 (
    echo [i] Tip: the interface looks best in Windows Terminal ^(winget install Microsoft.WindowsTerminal^).
    goto run_here
)

rem Open the interface in a new, clean Windows Terminal window; this one closes.
rem uv goes by full path: a new Terminal window may not inherit this PATH.
set "UV_FULL=%UV_EXE%"
if /i not "%UV_EXE%"=="uv" goto open_wt
for /f "delims=" %%U in ('where uv 2^>nul') do (
    set "UV_FULL=%%U"
    goto open_wt
)
:open_wt
wt -w new --size 120,36 --title "CS-TOOL" -d "%CD%\." "%UV_FULL%" run --directory "%CD%\." --no-sync python -m cyberfw.cli
if errorlevel 1 goto run_here
popd
exit /b 0

:run_here
"%UV_EXE%" run --no-sync python -m cyberfw.cli %*
set "EXIT_CODE=%errorlevel%"
popd
exit /b %EXIT_CODE%
