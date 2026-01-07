"""
Telegram Relay Plugin for PyLink (Multi-channel)

Features:
- One fake IRC user per Telegram user
- Matterbridge-like nickname behavior
- Uses Telegram @username when available
- Fallback to full name without spaces
- Multi-channel Telegram <-> IRC bridge
- Uses the PyLink server (no extra IRC bots)
"""

import re
import time
import threading

from telegram import Update
from telegram.ext import (
    ApplicationBuilder,
    MessageHandler,
    ContextTypes,
    filters,
)

PLUGIN = "telegram"

telegram_users = {}   # telegram_user_id -> { user, last_seen }
bridge_map = {}       # telegram_chat_id -> bridge config


# ==================================================
# Plugin lifecycle
# ==================================================

def setup(irc):
    cfg = irc.config.get(PLUGIN)
    if not cfg or not cfg.get("enabled"):
        irc.log.info("[telegram] plugin disabled")
        return

    irc.telegram_cfg = cfg
    irc.log.info("[telegram] plugin loaded")

    build_bridge_map(cfg)

    # Hook IRC messages (IRC -> Telegram)
    irc.add_hook("PRIVMSG", on_irc_privmsg)

    # Start Telegram bot in a separate thread
    threading.Thread(
        target=start_telegram_bot,
        args=(irc,),
        daemon=True
    ).start()

    # Optional idle cleanup
    if cfg.get("cleanup", {}).get("idle_timeout", 0) > 0:
        start_cleanup_timer(irc)


def teardown(irc):
    irc.log.info("[telegram] plugin unloaded")
    for entry in telegram_users.values():
        irc.quit(entry["user"], "Telegram relay shutdown")


# ==================================================
# Telegram -> IRC
# ==================================================

async def on_telegram_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = update.message
    if not msg or not msg.text:
        return

    irc = context.application.irc
    cfg = irc.telegram_cfg

    chat_id = str(msg.chat_id)
    if chat_id not in bridge_map:
        return

    bridge = bridge_map[chat_id]
    channel = bridge["irc"]["channel"]

    user = get_or_create_irc_user(irc, msg.from_user)
    telegram_users[msg.from_user.id]["last_seen"] = time.time()

    text = msg.text[:cfg["limits"]["message_max"]]

    irc.send_privmsg(
        channel,
        text,
        source=user
    )


# ==================================================
# IRC -> Telegram
# ==================================================

def on_irc_privmsg(irc, source, target, message):
    cfg = irc.telegram_cfg

    # Anti-loop: ignore messages from Telegram fake users
    if source.ident == cfg["identity"]["ident"]:
        return

    for bridge in cfg["bridges"]:
        if target == bridge["irc"]["channel"]:
            text = f"<{source.nick}> {message}"
            irc.telegram_app.bot.send_message(
                chat_id=bridge["telegram"]["chat_id"],
                text=text
            )


# ==================================================
# Fake IRC user handling
# ==================================================

def get_or_create_irc_user(irc, tg_user):
    tg_id = tg_user.id

    if tg_id in telegram_users:
        return telegram_users[tg_id]["user"]

    cfg = irc.telegram_cfg
    nick = build_nick_from_telegram(tg_user, cfg)

    user = irc.create_user(
        nick=nick,
        ident=cfg["identity"]["ident"],
        host=cfg["identity"]["host"],
        realname=build_realname(tg_user)
    )

    # Join all configured IRC channels
    for bridge in cfg["bridges"]:
        irc.join(user, bridge["irc"]["channel"])

    telegram_users[tg_id] = {
        "user": user,
        "last_seen": time.time()
    }

    irc.log.info(f"[telegram] created IRC user: {nick}")
    return user


def build_nick_from_telegram(tg_user, cfg):
    """
    Matterbridge-like nickname rules
    """
    if tg_user.username:
        base = tg_user.username
    else:
        base = f"{tg_user.first_name or ''}{tg_user.last_name or ''}" or f"tg{tg_user.id}"

    base = sanitize_irc_name(base)
    nick = f"{base}/{cfg['identity']['suffix']}"

    return nick[:cfg["limits"]["nick_max"]]


def build_realname(tg_user):
    if tg_user.username:
        return f"Telegram @{tg_user.username}"
    return f"Telegram {tg_user.first_name or ''} {tg_user.last_name or ''}".strip()


def sanitize_irc_name(name):
    """
    Remove spaces, emojis and invalid IRC characters
    """
    name = re.sub(r"\s+", "", name)
    name = re.sub(r"[^A-Za-z0-9_\-\[\]\\`^{}]", "", name)
    return name or "TGUser"


# ==================================================
# Idle cleanup
# ==================================================

def start_cleanup_timer(irc):
    def loop():
        timeout = irc.telegram_cfg["cleanup"]["idle_timeout"]
        while True:
            time.sleep(60)
            now = time.time()
            for tg_id in list(telegram_users):
                entry = telegram_users[tg_id]
                if now - entry["last_seen"] > timeout:
                    irc.quit(entry["user"], "Telegram idle timeout")
                    del telegram_users[tg_id]

    threading.Thread(target=loop, daemon=True).start()


# ==================================================
# Helpers
# ==================================================

def build_bridge_map(cfg):
    for bridge in cfg["bridges"]:
        bridge_map[str(bridge["telegram"]["chat_id"])] = bridge


# ==================================================
# Telegram bootstrap
# ==================================================

def start_telegram_bot(irc):
    cfg = irc.telegram_cfg

    app = ApplicationBuilder().token(cfg["bot"]["token"]).build()
    app.irc = irc
    irc.telegram_app = app

    app.add_handler(
        MessageHandler(filters.TEXT & ~filters.COMMAND, on_telegram_message)
    )

    irc.log.info("[telegram] Telegram bot connected (multi-channel)")
    app.run_polling()
