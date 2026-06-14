# OUSHH

```text
 ██████╗ ██╗   ██╗███████╗██╗  ██╗██╗  ██╗██╗  ██╗
██╔═══██╗██║   ██║██╔════╝██║  ██║██║  ██║██║  ██║
██║   ██║██║   ██║███████╗███████║███████║███████║
██║   ██║██║   ██║╚════██║██╔══██║██╔══██║██╔══██║
╚██████╔╝╚██████╔╝███████║██║  ██║██║  ██║██║  ██║
 ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
```

**Oushh** is an automation recon and Deep Scan toolkit with a private Telegram controller. It helps bug hunters run reconnaissance, monitor scan progress, view Nuclei findings, and receive ZIP reports directly from Telegram.

> Use only on targets you own or have explicit permission to test.

---

## Official Social

- Instagram: [@ouashxy](https://instagram.com/ouashxy)
- LinkedIn: [musa-hamonangan-lubis-a719b9282](https://www.linkedin.com/in/musa-hamonangan-lubis-a719b9282)
- GitHub: [2124600005-musa](https://github.com/2124600005-musa)

---

## Features

- Telegram Deep Scan bot controller.
- Button-based menu: start scan, status, latest report, clean output, stop scan, help.
- Status follows the real Oushh scan stages.
- Nuclei findings summary sent directly to Telegram.
- Full ZIP report sent after scan completes.
- Cleaning menu for output/cache/logs.
- Windows + Linux/macOS support.
- Kali/Debian-safe setup using local `.venv`.
- Tool resolver prefers Go-based recon tools to avoid wrong `httpx` binary.

---

## Scan Flow

Deep Scan stages follow the tool output, for example:

```text
[▶️] Starting process for example.com (DEEPSCAN)
[✓] Subfinder Found ... subdomains
[✓] Assetfinder Found ... subdomains
[✓] Successfully found ... subdomains
[✓] Httpx Found ... Subdomain active
[✓] Waybackurls Found ... URLs
[✓] Gau Found ... URLs
[+] Active subdomains ≥ 20, only using 20 active subdomains
[✓] Katana Found ... URLs
[✓] Httpx Found ... URL active
[✓] Successfully found ... URLs with parameter
[✓] Successfully found ... URLs .js
[⏱️] Successfully collected URLs from example.com for ...
[+] Nuclei (Basic scan)...
[+] Nuclei (JS scan)...
[+] Nuclei (DAST scan)...
[+] Nuclei (Takeover scan)...
```

---

## Requirements

- Python 3.10+
- Go/Golang
- Telegram bot token from BotFather
- Telegram numeric user ID for `CHAT_ID`

External tools installed by setup scripts:

- subfinder
- assetfinder
- httpx
- waybackurls
- gau
- katana
- nuclei

---

## Installation Using Git Clone

```bash
git clone https://github.com/2124600005-musa/Tools-Automation.git
cd Tools-Automation
```

---

## Windows Setup

Run:

```bat
setup.bat
```

Edit `config.py`:

```python
BOT_TOKEN = "YOUR_BOT_TOKEN_FROM_BOTFATHER"
CHAT_ID = "YOUR_TELEGRAM_USER_ID"
```

Start bot:

```bat
run_deep_bot.bat
```

Or manually:

```bat
python telegram_deep_bot.py
```

---

## Linux/macOS Setup

Run:

```bash
chmod +x setup.sh run_deep_bot.sh
./setup.sh
```

Edit `config.py`:

```bash
nano config.py
```

Fill:

```python
BOT_TOKEN = "YOUR_BOT_TOKEN_FROM_BOTFATHER"
CHAT_ID = "YOUR_TELEGRAM_USER_ID"
```

Start bot:

```bash
./run_deep_bot.sh
```

Or manually:

```bash
.venv/bin/python telegram_deep_bot.py
```

### Kali/Debian Note

Kali/Debian may block system-wide `pip install` with `externally-managed-environment`.

Oushh setup uses a local virtual environment:

```text
.venv/
```

So you do **not** need:

```bash
--break-system-packages
```

If venv support is missing:

```bash
sudo apt install python3-venv python3-pip
```

For Python 3.13:

```bash
sudo apt install python3.13-venv python3-pip
```

---

## Telegram Bot Usage

Start the bot:

```text
/start
```

Main menu:

```text
🧬 Start Deep Scan
📊 Status
📦 Latest Report
🧹 Clean Output
⛔ Stop Scan
🧭 Help
```

Button flow:

```text
/start → 🧬 Start Deep Scan → send target → choose speed → scan starts
```

Command fallback:

```text
/deep example.com standard
/status
/report
/stop
/help
```

---

## Output

Telegram output:

- Scan started card.
- Refreshable status card.
- Nuclei findings summary.
- Full ZIP report.

Local output folders:

```text
subdomain/
active/
crawled/
crawled_filtered/
nuclei/
take_over/
sensitive_data/
bot_logs/
bot_reports/
```

Example ZIP report contents:

```text
subdomain/example.com.txt
active/example.com.txt
crawled/wayback_example.com.txt
crawled/gau_example.com.txt
crawled/katana_example.com.txt
nuclei/nuc_active_example.com.txt
nuclei/nuc_exp_example.com.txt
nuclei/nuc_dast_example.com.txt
take_over/TOW_example.com.txt
bot_logs/deep_example.com_YYYYMMDD_HHMMSS.log
```

---

## Configuration

`config.example.py` format:

```python
# config.py
# Telegram Configuration
BOT_TOKEN = "YOUR_BOT_TOKEN_FROM_BOTFATHER"
CHAT_ID = "YOUR_TELEGRAM_USER_ID"

KATANA_LIMIT = 20

# Resume scan configuration
# Options: "ask" (always ask), "continue" (auto continue), "restart" (auto restart)
RESUME_SCAN_MODE = "ask"

# NOTE: DO NOT CHANGE ABOVE THIS!!!
# GitHub Configuration (for tool updates)
GITHUB_USER = "2124600005-musa"
GITHUB_REPO = "Tools-Automation"

SCAN_SPEED = "standard"
```

Do not commit real `config.py` with your bot token.

---

## Recommended `.gitignore`

```gitignore
config.py
.venv/
__pycache__/
*.pyc
bot_logs/
bot_reports/
subdomain/
active/
crawled/
crawled_filtered/
nuclei/
take_over/
sensitive_data/
output/
results/
reports/
```

---

## Tutorial Video

### Create Telegram Bot Token and Chat ID

Watch tutorial:

https://drive.google.com/file/d/12J-PEJcvJuv7PpX1DXBWQOCIQFcMIyeu/view?usp=drivesdk

### Optional: Gmail App Password

Only needed if you use features that require Gmail SMTP/app password.

https://drive.google.com/file/d/12F5cYBm8b5KVKkKmsa_1Yenfrqvcv5IG/view?usp=drivesdk

---

## Security Notice

This tool is for authorized security testing only. You are responsible for how you use it. Do not scan targets without permission.
