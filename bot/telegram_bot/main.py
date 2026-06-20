"""
matthunder Telegram Bot v2.0 - Upgraded with conversation handlers
"""
import os
import logging
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    CallbackQueryHandler,
    MessageHandler,
    ConversationHandler,
    filters,
    ContextTypes
)
import httpx

# Enable logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Configuration
BOT_TOKEN = os.getenv("MATTHUNDER_BOT_TOKEN", "")
OWNER_ID = int(os.getenv("MATTHUNDER_OWNER_ID", "0"))
API_URL = os.getenv("MATTHUNDER_API_URL", "http://localhost:8000")
API_TOKEN = os.getenv("MATTHUNDER_API_TOKEN", "")

# Conversation states
SELECTING_TARGET, SELECTING_SCAN_TYPE, SELECTING_SPEED, CONFIRMING = range(4)


def get_client() -> httpx.AsyncClient:
    """Get authenticated HTTP client"""
    headers = {}
    if API_TOKEN:
        headers["Authorization"] = f"Bearer {API_TOKEN}"
    return httpx.AsyncClient(base_url=API_URL, headers=headers, timeout=30.0)


def check_owner(func):
    """Decorator to check if user is owner"""
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
        if update.effective_user.id != OWNER_ID:
            await update.message.reply_text("⛔ Access denied. You are not the owner.")
            return ConversationHandler.END
        return await func(update, context)
    return wrapper


@check_owner
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Start command handler"""
    keyboard = [
        [
            InlineKeyboardButton("🎯 Targets", callback_data="targets"),
            InlineKeyboardButton("🔍 Scans", callback_data="scans")
        ],
        [
            InlineKeyboardButton("📊 Findings", callback_data="findings"),
            InlineKeyboardButton("🤖 AI Analysis", callback_data="ai")
        ],
        [
            InlineKeyboardButton("⚙️ Settings", callback_data="settings"),
            InlineKeyboardButton("ℹ️ Help", callback_data="help")
        ]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_text(
        "⚡ *matthunder Bot v2.0*\n\n"
        "AI-Powered Bug Hunting Platform\n\n"
        "Select an option:",
        reply_markup=reply_markup,
        parse_mode='Markdown'
    )


async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle inline keyboard buttons"""
    query = update.callback_query
    await query.answer()
    
    data = query.data
    
    if data == "targets":
        await show_targets(update, context)
    elif data == "scans":
        await show_scans(update, context)
    elif data == "findings":
        await show_findings(update, context)
    elif data == "ai":
        await query.message.reply_text("Send me a prompt for AI analysis:")
        return SELECTING_TARGET
    elif data == "settings":
        await show_settings(update, context)
    elif data == "help":
        await show_help(update, context)
    elif data.startswith("scan_target_"):
        target_id = data.replace("scan_target_", "")
        context.user_data["target_id"] = target_id
        await ask_scan_type(update, context)
        return SELECTING_SCAN_TYPE
    elif data.startswith("scan_type_"):
        scan_type = data.replace("scan_type_", "")
        context.user_data["scan_type"] = scan_type
        await ask_speed(update, context)
        return SELECTING_SPEED
    elif data.startswith("scan_speed_"):
        speed = data.replace("scan_speed_", "")
        context.user_data["speed"] = speed
        await confirm_scan(update, context)
        return CONFIRMING
    elif data == "confirm_yes":
        await start_scan(update, context)
        return ConversationHandler.END
    elif data == "confirm_no":
        await query.message.reply_text("Scan cancelled.")
        return ConversationHandler.END


@check_owner
async def show_targets(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show all targets"""
    try:
        async with get_client() as client:
            response = await client.get("/api/v1/targets")
            response.raise_for_status()
            targets = response.json()
        
        if not targets:
            await update.callback_query.message.reply_text("No targets found.")
            return
        
        message = "🎯 *Targets:*\n\n"
        for target in targets[:10]:  # Limit to 10
            message += f"• `{target['domain']}`\n  ID: `{target['id'][:8]}...`\n\n"
        
        # Add scan buttons
        keyboard = []
        for target in targets[:5]:  # Limit to 5 buttons
            keyboard.append([
                InlineKeyboardButton(
                    f"🔍 Scan {target['domain']}",
                    callback_data=f"scan_target_{target['id']}"
                )
            ])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        if update.callback_query:
            await update.callback_query.message.reply_text(
                message,
                reply_markup=reply_markup,
                parse_mode='Markdown'
            )
        else:
            await update.message.reply_text(
                message,
                reply_markup=reply_markup,
                parse_mode='Markdown'
            )
    except Exception as e:
        await update.callback_query.message.reply_text(f"Error: {e}")


@check_owner
async def show_scans(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show recent scans"""
    try:
        async with get_client() as client:
            response = await client.get("/api/v1/scans?limit=10")
            response.raise_for_status()
            scans = response.json()
        
        if not scans:
            await update.callback_query.message.reply_text("No scans found.")
            return
        
        message = "🔍 *Recent Scans:*\n\n"
        for scan in scans:
            status_emoji = {
                "completed": "✅",
                "running": "🔄",
                "failed": "❌",
                "pending": "⏳"
            }.get(scan["status"], "❓")
            
            message += f"{status_emoji} *{scan['scan_type']}* ({scan['speed']})\n"
            message += f"   Status: {scan['status']}\n"
            message += f"   ID: `{scan['id'][:8]}...`\n\n"
        
        if update.callback_query:
            await update.callback_query.message.reply_text(
                message,
                parse_mode='Markdown'
            )
        else:
            await update.message.reply_text(
                message,
                parse_mode='Markdown'
            )
    except Exception as e:
        await update.callback_query.message.reply_text(f"Error: {e}")


@check_owner
async def show_findings(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show recent findings"""
    try:
        async with get_client() as client:
            response = await client.get("/api/v1/findings?limit=10")
            response.raise_for_status()
            findings = response.json()
        
        if not findings:
            await update.callback_query.message.reply_text("No findings found.")
            return
        
        message = "📊 *Recent Findings:*\n\n"
        for finding in findings:
            severity_emoji = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🔵",
                "info": "⚪"
            }.get(finding.get("severity", ""), "❓")
            
            message += f"{severity_emoji} *{finding.get('severity', 'N/A').upper()}*\n"
            message += f"   Scanner: {finding.get('scanner', 'N/A')}\n"
            if finding.get('title'):
                message += f"   Title: {finding['title'][:50]}\n"
            message += "\n"
        
        if update.callback_query:
            await update.callback_query.message.reply_text(
                message,
                parse_mode='Markdown'
            )
        else:
            await update.message.reply_text(
                message,
                parse_mode='Markdown'
            )
    except Exception as e:
        await update.callback_query.message.reply_text(f"Error: {e}")


async def ask_scan_type(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Ask for scan type"""
    keyboard = [
        [
            InlineKeyboardButton("⚡ Light", callback_data="scan_type_light"),
            InlineKeyboardButton("🌑 Dark", callback_data="scan_type_dark")
        ],
        [
            InlineKeyboardButton("🔥 Deep", callback_data="scan_type_deep"),
            InlineKeyboardButton("🚀 Pipeline", callback_data="scan_type_pipeline")
        ]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.callback_query.message.reply_text(
        "Select scan type:",
        reply_markup=reply_markup
    )


async def ask_speed(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Ask for scan speed"""
    keyboard = [
        [
            InlineKeyboardButton("🐢 Low", callback_data="scan_speed_low"),
            InlineKeyboardButton("⚖️ Standard", callback_data="scan_speed_standard"),
            InlineKeyboardButton("🚀 Fast", callback_data="scan_speed_fast")
        ]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.callback_query.message.reply_text(
        "Select scan speed:",
        reply_markup=reply_markup
    )


async def confirm_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Confirm scan details"""
    target_id = context.user_data.get("target_id")
    scan_type = context.user_data.get("scan_type")
    speed = context.user_data.get("speed")
    
    keyboard = [
        [
            InlineKeyboardButton("✅ Yes", callback_data="confirm_yes"),
            InlineKeyboardButton("❌ No", callback_data="confirm_no")
        ]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.callback_query.message.reply_text(
        f"Start scan?\n\n"
        f"Target ID: `{target_id[:8]}...`\n"
        f"Type: {scan_type}\n"
        f"Speed: {speed}",
        reply_markup=reply_markup,
        parse_mode='Markdown'
    )


async def start_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Start the scan"""
    target_id = context.user_data.get("target_id")
    scan_type = context.user_data.get("scan_type")
    speed = context.user_data.get("speed")
    
    try:
        async with get_client() as client:
            response = await client.post("/api/v1/scans", json={
                "target_id": target_id,
                "scan_type": scan_type,
                "speed": speed
            })
            response.raise_for_status()
            scan = response.json()
        
        await update.callback_query.message.reply_text(
            f"✅ Scan started!\n\n"
            f"Scan ID: `{scan['id']}`\n"
            f"Type: {scan['scan_type']}\n"
            f"Status: {scan['status']}",
            parse_mode='Markdown'
        )
    except Exception as e:
        await update.callback_query.message.reply_text(f"❌ Error: {e}")


@check_owner
async def show_settings(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show settings"""
    try:
        async with get_client() as client:
            response = await client.get("/api/v1/config")
            response.raise_for_status()
            config = response.json()
        
        message = "⚙️ *Settings:*\n\n"
        for key, value in config.items():
            if isinstance(value, dict):
                value = ", ".join([f"{k}={'✓' if v else '✗'}" for k, v in value.items()])
            message += f"• *{key}*: `{value}`\n"
        
        if update.callback_query:
            await update.callback_query.message.reply_text(
                message,
                parse_mode='Markdown'
            )
        else:
            await update.message.reply_text(
                message,
                parse_mode='Markdown'
            )
    except Exception as e:
        await update.callback_query.message.reply_text(f"Error: {e}")


@check_owner
async def show_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show help message"""
    help_text = """
ℹ️ *matthunder Bot Help*

*Commands:*
/start - Show main menu
/targets - List all targets
/scans - Show recent scans
/findings - Show recent findings
/settings - View configuration
/help - Show this help message

*Features:*
• Start scans from target list
• View scan results
• AI-powered analysis
• Real-time notifications

*Security:*
• Bot only responds to owner
• All actions require authentication
• API token required for access
"""
    
    if update.callback_query:
        await update.callback_query.message.reply_text(
            help_text,
            parse_mode='Markdown'
        )
    else:
        await update.message.reply_text(
            help_text,
            parse_mode='Markdown'
        )


@check_owner
async def handle_ai_prompt(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle AI analysis prompt"""
    prompt = update.message.text
    
    try:
        async with get_client() as client:
            response = await client.post("/api/v1/ai/analyze", json={
                "prompt": prompt
            })
            response.raise_for_status()
            result = response.json()
        
        await update.message.reply_text(
            f"🤖 *AI Analysis Result:*\n\n"
            f"Provider: {result['provider']}\n"
            f"Model: {result['model']}\n\n"
            f"{result['response'].get('content', 'No content')[:2000]}...",
            parse_mode='Markdown'
        )
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {e}")
    
    return ConversationHandler.END


def main():
    """Start the bot"""
    if not BOT_TOKEN:
        logger.error("BOT_TOKEN not set!")
        return
    
    if not OWNER_ID:
        logger.error("OWNER_ID not set!")
        return
    
    # Create application
    application = Application.builder().token(BOT_TOKEN).build()
    
    # Add conversation handler for scan wizard
    scan_conv_handler = ConversationHandler(
        entry_points=[CallbackQueryHandler(button_handler, pattern="^scan_target_")],
        states={
            SELECTING_SCAN_TYPE: [CallbackQueryHandler(button_handler, pattern="^scan_type_")],
            SELECTING_SPEED: [CallbackQueryHandler(button_handler, pattern="^scan_speed_")],
            CONFIRMING: [CallbackQueryHandler(button_handler, pattern="^confirm_")],
        },
        fallbacks=[],
    )
    
    # Add conversation handler for AI analysis
    ai_conv_handler = ConversationHandler(
        entry_points=[CallbackQueryHandler(button_handler, pattern="^ai$")],
        states={
            SELECTING_TARGET: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_ai_prompt)],
        },
        fallbacks=[],
    )
    
    # Add handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("targets", show_targets))
    application.add_handler(CommandHandler("scans", show_scans))
    application.add_handler(CommandHandler("findings", show_findings))
    application.add_handler(CommandHandler("settings", show_settings))
    application.add_handler(CommandHandler("help", show_help))
    application.add_handler(CallbackQueryHandler(button_handler))
    application.add_handler(scan_conv_handler)
    application.add_handler(ai_conv_handler)
    
    # Start the bot
    logger.info("Starting bot...")
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
