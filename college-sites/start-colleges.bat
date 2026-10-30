@echo off
title CyberShield College Sites Launcher
color 0A
echo.
echo ============================================================
echo   CyberShield NEDI -- College Sites Launcher
echo ============================================================
echo.
echo  College A - South Campus (Chennai)    -> http://localhost:8082
echo  College E - Central Region (Bhopal)   -> http://localhost:8083
echo.
echo  CyberShield SOC Dashboard             -> http://localhost:8081/dashboard.html
echo.
echo  Make sure CyberShield backend is running first:
echo    cd .. ^&^& mvn spring-boot:run
echo.
echo ============================================================
echo.

:: Check if Python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found. Please install Python 3.x.
    echo         Download: https://www.python.org/downloads/
    pause
    exit /b 1
)

echo [INFO] Starting College A on port 8082...
start "College A - South Campus (8082)" cmd /k "cd /d "%~dp0college-a" && python -m http.server 8082"

timeout /t 2 /nobreak >nul

echo [INFO] Starting College E on port 8083...
start "College E - Central Region (8083)" cmd /k "cd /d "%~dp0college-e" && python -m http.server 8083"

timeout /t 2 /nobreak >nul

echo.
echo [SUCCESS] Both college sites are now running!
echo.
echo  -> College A: http://localhost:8082
echo  -> College E: http://localhost:8083
echo.
echo [INFO] Opening sites in browser...
timeout /t 2 /nobreak >nul
start http://localhost:8082
timeout /t 1 /nobreak >nul
start http://localhost:8083

echo.
echo [TIP] Now open the SOC Dashboard to see real-time alerts:
echo       http://localhost:8081/dashboard.html
echo.
echo [TIP] To simulate attacks, try these on the login pages:
echo       SQLi:        admin' OR '1'='1
echo       Brute Force: submit login form 4+ times rapidly
echo       Recon:       visit /admin.html or /erp.html pages
echo.
pause
