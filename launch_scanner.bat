@echo off
REM Complete Albion Online Dungeon Scanner Suite v4.0
REM Windows Launch Script

title Albion Scanner v4.0 Launcher

echo.
echo ===============================================================
echo    ALBION ONLINE DUNGEON SCANNER SUITE v4.0
echo    Windows Quick Launcher
echo ===============================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python is not installed or not in PATH
    echo 💡 Please install Python 3.8+ from https://python.org
    echo.
    pause
    exit /b 1
)

echo ✅ Python detected
python --version

REM Check if we're in the right directory
if not exist "albion_scanner_launcher.py" (
    echo.
    echo ❌ Launch script not found in current directory
    echo 💡 Please run this batch file from the scanner directory
    echo.
    pause
    exit /b 1
)

echo ✅ Scanner files detected

REM Check for dependencies
echo.
echo 📋 Checking dependencies...
python -c "import scapy, websockets" >nul 2>&1
if errorlevel 1 (
    echo ❌ Missing dependencies
    echo 💡 Installing required packages...
    pip install scapy websockets
    if errorlevel 1 (
        echo ❌ Failed to install dependencies
        echo 💡 Please run: pip install scapy websockets
        pause
        exit /b 1
    )
)

echo ✅ Dependencies satisfied

REM Check for admin privileges (needed for packet capture)
net session >nul 2>&1
if errorlevel 1 (
    echo.
    echo ⚠️  WARNING: Not running as Administrator
    echo 💡 Packet capture may not work without admin privileges
    echo 💡 Consider running as Administrator for best results
    echo.
    set /p continue="Continue anyway? (y/n): "
    if /i not "%continue%"=="y" (
        echo Operation cancelled
        pause
        exit /b 1
    )
)

REM Launch the scanner
echo.
echo 🚀 Launching Albion Scanner Suite...
echo.

python albion_scanner_launcher.py

REM Handle exit
echo.
echo 👋 Scanner session ended
pause