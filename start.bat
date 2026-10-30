@echo off
echo ============================================
echo  CyberShield Nexus - NEDI SOC Platform
echo ============================================
echo.
echo Port 8081 will be cleared if busy...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :8081 ^| findstr LISTENING') do (
    echo Killing old process [PID: %%a]
    taskkill /PID %%a /F >nul 2>&1
)
timeout /t 2 /nobreak >nul
echo.
echo Starting app... (keep this window open!)
echo Once started, open: http://localhost:8081/login.html
echo.
mvn spring-boot:run
pause

