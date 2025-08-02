@echo off
title CyberSec Assistant Portable - Windows Launcher

echo.
echo ╔══════════════════════════════════════════════════════════════════╗
echo ║                    🛡️  CYBERSEC ASSISTANT PORTABLE                 ║
echo ║                                                                  ║
echo ║              Comprehensive Portable Cybersecurity Toolkit       ║
echo ║                         Legal Use Only                          ║
echo ╚══════════════════════════════════════════════════════════════════╝
echo.

:: Set working directory to script location
cd /d "%~dp0"

:: Check if we're running from a portable drive
set "PORTABLE_DIR=%~dp0"
echo 📍 Portable Directory: %PORTABLE_DIR%

:: Check for Python
echo 🔍 Checking system requirements...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Python not found! Please install Python 3.8+ or use portable Python
    echo.
    echo 💡 Download Python from: https://www.python.org/downloads/
    echo    Or use WinPython for portable installation
    pause
    exit /b 1
)

:: Check for pip
python -m pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ pip not found! Python installation may be incomplete
    pause
    exit /b 1
)

echo ✅ Python found and ready

:: Install required packages if needed
echo 📦 Installing required packages...
python -m pip install requests >nul 2>&1

:: Run the portable launcher
echo 🚀 Starting CyberSec Assistant...
python start-portable.py

:: Handle exit
if %errorlevel% equ 0 (
    echo.
    echo ✅ Application completed successfully
) else (
    echo.
    echo ❌ Application encountered an error
)

echo.
echo Press any key to exit...
pause >nul