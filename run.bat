@echo off

title AI Security Operations Platform

cd /d "%~dp0"

echo ==========================================
echo   AI SECURITY OPERATIONS PLATFORM
echo ==========================================
echo.

start "Security Platform Server" /min cmd /c "python server.py"

timeout /t 1 /nobreak >nul

start "" "http://127.0.0.1:5001"

exit