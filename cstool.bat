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
        echo [!] uv is not installed. Installing uv...
        powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
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

"%UV_EXE%" run --no-sync python -m cyberfw.cli %*
set "EXIT_CODE=%errorlevel%"
popd
exit /b %EXIT_CODE%
