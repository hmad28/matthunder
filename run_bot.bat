@echo off
REM Matthunder Telegram bot — auto-restart loop
REM Place at project root: C:\Projects\Tools-Automation-main\run_bot.bat
REM Double-click to start (or run via run_bot_hidden.vbs for hidden)

setlocal
cd /d "C:\Projects\Tools-Automation-main"

REM Set UTF-8 environment so subprocess (matthunder.py) doesn't crash on emoji
set PYTHONIOENCODING=utf-8
set PYTHONUTF8=1

REM Ensure log dir exists
if not exist "bot_logs" mkdir "bot_logs"

REM Loop with restart on crash
:LOOP
echo [%date% %time%] Starting telegram_deep_bot.py ... >> "bot_logs\run_bot.log"

REM Run bot. If exits with non-zero, sleep then restart.
"C:\Users\Pongo\AppData\Local\Programs\Python\Python312\python.exe" telegram_deep_bot.py >> "bot_logs\bot.out.log" 2>> "bot_logs\bot.err.log"
set RC=%ERRORLEVEL%

echo [%date% %time%] Bot exited with code %RC%. Restarting in 5s ... >> "bot_logs\run_bot.log"

REM Optional: stop restarting if RC=0 (clean exit) — uncomment next line to make clean exit sticky
REM if %RC%==0 goto :END

timeout /t 5 /nobreak >nul
goto :LOOP

:END
echo [%date% %time%] Bot stopped. >> "bot_logs\run_bot.log"
endlocal
