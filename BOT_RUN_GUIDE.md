# Matthunder Telegram Bot — Run Guide

Bot Telegram private yang jalanin matthunder scanner + Acunetix, plus AI assistant, langsung dari HP.

## Quick Start (paling cepet)

1. Edit `config.py` — set `BOT_TOKEN` + `CHAT_ID` lo
2. Double-click `run_bot.bat` (muncul console window) — buat test
3. Buka Telegram, chat `@MatthunderBot`, kirim `/start`

## Production Run (background + auto-restart + auto-start on logon)

Jalanin 3 step ini sekali, bot auto-start tiap logon + auto-restart kalo crash:

### 1. Edit `run_bot.bat`
Path python interpreter di-hardcode ke `C:\Users\Pongo\AppData\Local\Programs\Python\Python312\python.exe`. Kalo beda, edit baris pertama yang ada `python.exe`.

### 2. Register Task Scheduler (sekali)
Buka PowerShell **as Administrator**:
```powershell
$action = New-ScheduledTaskAction -Execute "wscript.exe" -Argument '"C:\Projects\Tools-Automation-main\run_bot_hidden.vbs"' -WorkingDirectory "C:\Projects\Tools-Automation-main"
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERNAME" -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Register-ScheduledTask -TaskName "MatthunderTelegramBot" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Matthunder Telegram bot with auto-restart"
```

### 3. Start sekarang (opsional, kalo ga mau nunggu logon)
```powershell
Start-ScheduledTask -TaskName "MatthunderTelegramBot"
```

## Commands

### Bot scan commands

Semua command scan di bawah sekarang lewat shared `matthunder_core` service layer:

```text
/deep example.com standard
/light example.com fast
/dark example.com standard
/blh example.com
/tpa example.com
/cred example.com
/takeover example.com
/sensitive example.com
```

| Perintah | Fungsi |
|----------|--------|
| `Start-ScheduledTask -TaskName "MatthunderTelegramBot"` | Start bot sekarang |
| `Stop-ScheduledTask -TaskName "MatthunderTelegramBot"` | Stop bot |
| `Get-ScheduledTask -TaskName "MatthunderTelegramBot"` | Cek status |
| `Unregister-ScheduledTask -TaskName "MatthunderTelegramBot"` | Hapus auto-start |
| `run_bot.bat` (double-click) | Run manual di foreground (debug) |
| `wscript.exe run_bot_hidden.vbs` | Run manual di background (no console) |

## Log Files

- `bot_logs/bot.out.log` — stdout bot
- `bot_logs/bot.err.log` — stderr bot
- `bot_logs/run_bot.log` — restart history (timestamp + exit code)
- `bot_logs/matthunder_banner.png` — cached banner image
- `bot_logs/deep_<target>_<ts>.log` — log per scan

## Configuration (via Telegram, no file edit)

Kirim `/setup` di bot → pilih menu:
- 🦅 Acunetix: URL + API key + TLS verify
- 🤖 AI Provider: OpenAI / Anthropic / Gemini / OpenRouter + API key + model

Disimpan di `user_config.json` (separate from `config.py`, ga keganggu).

## Customization

| Yang | File |
|------|------|
| Banner image (MATTHUNDER ASCII) | `matthunder_banner.py` |
| Banner font / size / color | `figlet_font`, `char_size`, `bg_color`, `fg_color` di `build_banner()` |
| Speed presets di Telegram | `matthunder_speed_keyboard()` di `telegram_deep_bot.py` |
| Quick mode nuclei tags | `matthunder.py` line ~1374 (cari `MATTHUNDER_QUICK_MODE`) |
| Auto-refresh interval scan | `_scan_autorefresh_and_notify(interval_s=30)` di `telegram_deep_bot.py` |
| Acunetix API | `/setup` di bot, atau manual di `user_config.json` |

## Troubleshoot

- **Bot ga respond**: Cek `bot_logs/bot.err.log`, mungkin ada error import. Jalanin `run_bot.bat` manual buat liat error.
- **Bot stuck / ga update status**: `Get-Process python` — kalo ada, kill. Auto-restart bakal start lagi dalam 5s.
- **Scheduled task ga jalan**: Buka Task Scheduler → cari "MatthunderTelegramBot" → Run manually buat test. Cek "Last Run Result" kolom.
- **Bot pake banner lama (cached di Telegram client)**: Tunggu 1-2 menit, atau restart bot biar cache invalid.
- **Scan lama banget**: Pakai mode "⚡ Quick (CVE only)" instead of full Deep Scan. Aktifin `MATTHUNDER_QUICK_MODE` env.
- **Acunetix error**: `/setup` → 🦅 Acunetix → 🧪 Test Connection buat debug.
