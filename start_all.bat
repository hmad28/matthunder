@echo off
echo ========================================
echo Matthunder v2.0 - Full Stack Startup
echo ========================================
echo.
echo This will start both backend and frontend
echo.
echo Backend:  http://localhost:8000
echo Frontend: http://localhost:3000
echo.
echo Press any key to start...
pause >nul

echo.
echo Starting backend...
start "Matthunder Backend" cmd /k "cd /d "%~dp0backend" && start_backend.bat"

timeout /t 3 /nobreak >nul

echo Starting frontend...
start "Matthunder Frontend" cmd /k "cd /d "%~dp0frontend" && start_frontend.bat"

echo.
echo ========================================
echo Both services are starting...
echo.
echo Backend:  http://localhost:8000
echo Frontend: http://localhost:3000
echo API Docs: http://localhost:8000/docs
echo ========================================
echo.
echo Press any key to exit this window...
pause >nul
