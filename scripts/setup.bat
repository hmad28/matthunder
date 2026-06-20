@echo off
REM Matthunder v2.0 - Setup Script for Windows

echo ⚡ Matthunder v2.0 - Setup
echo =========================
echo.

REM Check Docker
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Docker is not installed. Please install Docker Desktop first.
    echo    https://docs.docker.com/desktop/install/windows-install/
    pause
    exit /b 1
)

REM Check Docker Compose
docker-compose --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Docker Compose is not installed. Please install Docker Desktop first.
    echo    https://docs.docker.com/desktop/install/windows-install/
    pause
    exit /b 1
)

echo ✓ Docker and Docker Compose found
echo.

REM Create backend .env
if not exist backend\.env (
    echo Creating backend\.env from template...
    copy backend\.env.example backend\.env >nul
    echo ✓ Created backend\.env
    echo.
    echo ⚠️  IMPORTANT: Edit backend\.env and set your configuration:
    echo    - SECRET_KEY (change this!)
    echo    - AI provider API keys (optional)
    echo    - Acunetix settings (optional)
    echo.
) else (
    echo ✓ backend\.env already exists
)

REM Create necessary directories
echo Creating directories...
if not exist backend\scans mkdir backend\scans
if not exist backend\reports mkdir backend\reports
if not exist backend\uploads mkdir backend\uploads
echo ✓ Directories created
echo.

REM Pull Docker images
echo Pulling Docker images (this may take a few minutes)...
docker-compose pull
echo ✓ Images pulled
echo.

REM Build and start services
echo Building and starting services...
docker-compose up -d --build
echo ✓ Services started
echo.

REM Wait for services to be ready
echo Waiting for services to be ready...
timeout /t 10 /nobreak >nul

echo.
echo =========================
echo ✅ Setup complete!
echo.
echo Access the application:
echo   Frontend: http://localhost:3000
echo   Backend API: http://localhost:8000
echo   API Docs: http://localhost:8000/docs
echo.
echo Useful commands:
echo   View logs: docker-compose logs -f
echo   Stop services: docker-compose down
echo   Restart services: docker-compose restart
echo.
echo Next steps:
echo   1. Edit backend\.env with your configuration
echo   2. Restart services: docker-compose restart
echo   3. Open http://localhost:3000 in your browser
echo =========================
pause
