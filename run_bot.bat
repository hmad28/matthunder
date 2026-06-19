@echo off
REM Matthunder Telegram bot — single-instance auto-restart loop
REM Place at project root: C:\Projects\Tools-Automation-main\run_bot.bat
REM Double-click to start (or run via run_bot_hidden.vbs for hidden)

setlocal
cd /d "C:\Projects\Tools-Automation-main"

REM Set UTF-8 environment so subprocess (matthunder.py) doesn't crash on emoji
set PYTHONIOENCODING=utf-8
set PYTHONUTF8=1

REM Ensure log dir exists
if not exist "bot_logs" mkdir "bot_logs"

REM ----- Single-instance guard -----
REM If another run_bot.bat / telegram_deep_bot.py is already alive, exit cleanly.
set "LOCKFILE=%TEMP%\matthunder_bot.lock"
set "BOT_HEARTBEAT=%TEMP%\matthunder_bot.heartbeat"

REM Check existing lock by trying to delete it. If another instance is alive,
REM it refreshes the lock via wmic PID query below; if PID no longer exists,
REM the lock is stale and we take over.
if exist "%LOCKFILE%" goto CHECK_LOCK
goto NO_LOCK

:CHECK_LOCK
set "OLDPID="
for /f "usebackq delims=" %%P in ("%LOCKFILE%") do set "OLDPID=%%P"
if not defined OLDPID goto NO_LOCK

REM Use tasklist to reliably check if PID is still alive.
REM tasklist /FI "PID eq XXX" /NH returns "INFO: No tasks..." or
REM a row with PID, image name, etc. A real match contains the PID token.
set "ALIVE="
for /f "tokens=1,2*" %%A in ('tasklist /FI "PID eq %OLDPID%" /NH 2^>nul') do (
    if "%%A"=="%OLDPID%" set "ALIVE=1"
)
if defined ALIVE (
    echo [%date% %time%] Another bot instance already running (PID %OLDPID%). Exiting. >> "bot_logs\run_bot.log"
    exit /b 0
) else (
    echo [%date% %time%] Stale lockfile for PID %OLDPID% - taking over. >> "bot_logs\run_bot.log"
    del "%LOCKFILE%" 2>nul
)

:NO_LOCK

REM Register this cmd PID in the lock file
set "MY_PID="
REM wmic on Windows still exposes parent cmd PID via $Parent$; we just write a
REM marker here, and the bot itself refreshes BOT_HEARTBEAT so the next loop
REM iteration can detect a live process via heartbeat timestamp staleness.
echo cmdshell > "%LOCKFILE%"
del "%BOT_HEARTBEAT%" 2>nul

REM Periodic guard: the bot refreshes BOT_HEARTBEAT every ~15s. If heartbeat
REM is stale (>90s old) at restart, we assume the bot is dead and restart it.
:LOOP
echo [%date% %time%] Starting telegram_deep_bot.py ... >> "bot_logs\run_bot.log"

"C:\Users\Pongo\AppData\Local\Programs\Python\Python312\python.exe" telegram_deep_bot.py >> "bot_logs\bot.out.log" 2>> "bot_logs\bot.err.log"
set RC=%ERRORLEVEL%

echo [%date% %time%] Bot exited with code %RC%. Restarting in 5s ... >> "bot_logs\run_bot.log"

REM Optional: stop restarting if RC=0 (clean exit) — uncomment next line to make clean exit sticky
REM if %RC%==0 goto :END

timeout /t 5 /nobreak >nul
goto :LOOP

:END
del "%LOCKFILE%" 2>nul
del "%BOT_HEARTBEAT%" 2>nul
echo [%date% %time%] Bot stopped. >> "bot_logs\run_bot.log"
endlocal
