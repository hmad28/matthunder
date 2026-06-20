@echo off
echo ========================================
echo Matthunder v2.0 - Frontend Startup
echo ========================================
echo.

cd /d "%~dp0"

echo Checking Node.js...
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Node.js not found! Please install Node.js 18+
    pause
    exit /b 1
)

echo Checking dependencies...
if not exist "node_modules" (
    echo Installing dependencies...
    call npm install
)

echo.
echo Starting frontend on http://localhost:3000
echo.
echo Press Ctrl+C to stop
echo.

call npm run dev

pause
