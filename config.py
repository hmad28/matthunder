# config.py
import os

# Telegram Configuration (optional — bot only used if --telegram flag set)
BOT_TOKEN = "8968634362:AAEsT_YB-suXpe75Udr4VXpt_r6kyH8B5_M"
CHAT_ID = "7118720621"

KATANA_LIMIT = 20

# Acunetix integration
# Set ACUNETIX_URL (e.g. https://acunetix.local:3443) and ACUNETIX_API_KEY
# Optional: ACUNETIX_VERIFY_SSL = False for self-signed certs
# ACUNETIX_URL = "https://localhost:3443"
# ACUNETIX_API_KEY = "your_api_key_here"
# ACUNETIX_VERIFY_SSL = False

# Resume scan configuration
# Options: "ask" (always ask), "continue" (auto continue), "restart" (auto restart)
RESUME_SCAN_MODE = "ask"

# NOTE: DO NOT CHANGE ABOVE THIS!!!
# GitHub Configuration (for tool updates)
GITHUB_USER = "hmad28"
GITHUB_REPO = "matthunder"

SCAN_SPEED = "standard"

# AI Parser (BYOK) — set ONE of these env vars, or hardcode below
# OPENAI_API_KEY = ""
# ANTHROPIC_API_KEY = ""
# GEMINI_API_KEY = ""
# OPENROUTER_API_KEY = ""

# Optional overrides
# MATTHUNDER_AI_PROVIDER = "openai"   # openai | anthropic | gemini | openrouter
# MATTHUNDER_AI_MODEL = "gpt-4o-mini"
