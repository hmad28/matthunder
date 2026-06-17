' Matthunder Telegram bot — launch run_bot.bat hidden (no console window)
' Place at project root
' Run via:  wscript.exe run_bot_hidden.vbs
' Or schedule via Task Scheduler with this as the program.

Set WshShell = CreateObject("WScript.Shell")
WshShell.Run chr(34) & "C:\Projects\Tools-Automation-main\run_bot.bat" & chr(34), 0, False
Set WshShell = Nothing
