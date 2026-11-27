# bot.py
import requests, os, datetime, time
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes
from config import BOT_TOKEN, ADMIN_IDS, SERVER_URL, ADMIN_TOKEN

HEADERS = {"X-Admin-Token": ADMIN_TOKEN}

def is_admin(uid): return uid in ADMIN_IDS

def ts(epoch):
    if not epoch: return "Never"
    return datetime.datetime.fromtimestamp(int(epoch)).strftime("%Y-%m-%d %H:%M:%S")

def fmt_bar(seconds: int) -> str:
    if seconds <= 0: return "🔴 EXPIRED"
    d  = seconds // 86400
    h  = (seconds % 86400) // 3600
    m  = (seconds % 3600) // 60
    s  = seconds % 60
    p  = []
    if d: p.append(f"{d}d")
    if h: p.append(f"{h}h")
    if m: p.append(f"{m}m")
    if s or not p: p.append(f"{s}s")
    return "🟢 " + " ".join(p)

def parse_duration(arg):
    arg = arg.strip().lower()
    if arg.endswith("h"):   return max(1, int(arg[:-1])) * 3600,  arg.upper()
    elif arg.endswith("d"): return max(1, int(arg[:-1])) * 86400, arg.upper()
    elif arg.endswith("m"): return max(1, int(arg[:-1])) * 60,    arg.upper()
    else:                   return max(1, int(arg)) * 86400,       f"{arg}D"

async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id): return
    await update.message.reply_text(
        "🔥 *APEX Admin Bot* | @APEX33Z\n\n"
        "`/genkey <duration> [note]`  — `1h` `6h` `12h` `7d` `30d`\n"
        "`/status <key>`              — Live countdown\n"
        "`/info <key>`                — Full key details\n"
        "`/revoke <key>`              — Revoke\n"
        "`/freeze <key>`              — Toggle freeze\n"
        "`/resethwid <key>`           — Reset HWID\n"
        "`/listkeys`                  — All keys\n"
        "`/ping`                      — Server health",
        parse_mode="Markdown"
    )

async def cmd_ping(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id): return
    try:
        r = requests.get(f"{SERVER_URL}/ping", timeout=8)
        await update.message.reply_text(f"✅ Online\n`{r.json()}`", parse_mode="Markdown")
    except Exception as e:
        await update.message.reply_text(f"❌ `{e}`", parse_mode="Markdown")

async def cmd_genkey(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id): return
    args = ctx.args or []
    if not args:
        await update.message.reply_text("Usage: `/genkey <duration> [note]`", parse_mode="Markdown")
        return
    try:
        secs, label = parse_duration(args[0])
    except Exception:
        await update.message.reply_text("❌ Bad duration. Use `6h`, `30d`, etc.", parse_mode="Markdown")
        return
    note = " ".join(args[1:]) if len(args) > 1 else ""
    post = {"note": note}
    if args[0].lower().endswith("h"): post["hours"] = str(max(1, secs // 3600))
    else:                             post["days"]  = str(max(1, secs // 86400))
    try:
        r   = requests.post(f"{SERVER_URL}/admin/genkey", data=post, headers=HEADERS, timeout=10)
        d   = r.json()
        exp = datetime.datetime.fromtimestamp(int(time.time()) + secs).strftime("%Y-%m-%d %H:%M:%S")
        await update.message.reply_text(
            f"✅ *Key Generated!*\n\n`{d['key']}`\n\n"
            f"⏳ Duration : *{label}*\n📅 Expires  : `{exp}`\n📝 Note: {note or '—'}",
            parse_mode="Markdown"
        )
    except Exception as e:
        await update.message.reply_text(f"❌ `{e}`", parse_mode="Markdown")

async def cmd_status(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id): return
    if not ctx.args:
        await update.message.reply_text("Usage: `/status <key>`", parse_mode="Markdown"); return
    try:
        r = requests.post(f"{SERVER_URL}/status", data={"key": ctx.args[0]},
                          headers=HEADERS, timeout=10)
        if r.status_code == 404:
            await update.message.reply_text("❌ Not found."); return
        d = r.json()
        emoji = {"active":"✅","expired":"⏳","revoked":"🚫","frozen":"❄️"}.get(d["status"],"❓")
        last  = "Never"
        if d.get("last_used"):
            diff = int(time.time()) - int(d["last_used"])
            last = fmt_bar(diff).replace("🟢","").strip() + " ago"
        await update.message.reply_text(
            f"📊 *Live Key Status*\n\n"
            f"🔑 `{d['key']}`\n"
            f"Status    : {emoji} `{d['status']}`\n"
            f"⏱ Remaining: `{d.get('remaining_fmt','N/A')}`\n"
            f"{fmt_bar(d.get('remaining_sec',0))}\n\n"
            f"📱 Device  : `{d.get('device_name') or 'Unbound'}`\n"
            f"🆔 HWID    : `{d.get('device_id') or '—'}`\n"
            f"📅 Expires : `{ts(d.get('expires_at'))}`\n"
            f"🔢 Uses    : `{d.get('usage_count',0)}`\n"
            f"🕐 Last    : `{last}`\n"
            f"📝 Note    : `{d.get('note') or '—'}`",
            parse_mode="Markdown"
        )
    except Exception as e:
        await update.message.reply_text(f"❌ `{e}`", parse_mode="Markdown")

async def cmd_info(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id): return
    if not ctx.args:
        await update.message.reply_text("Usage: `/info <key>`", parse_mode="Markdown"); return
    try:
        r = requests.post(f"{SERVER_URL}/admin/keyinfo", data={"key": ctx.args[0]},
                          headers=HEADERS, timeout=10)
        if r.status_code == 404:
            await update.message.reply_text("❌ Not found."); return
        d = r.json()
        emoji = {"active":"✅","expired":"⏳","revoked":"🚫","frozen":"❄️"}.get(d["status"],"❓")
        await update.message.reply_text(
            f"🔑 `{d['key']}`\n"
            f"Status    : {emoji} `{d['status']}`\n"
            f"⏱ Remaining: `{d.get('remaining_fmt','N/A')}`\n"
            f"📱 Device  : `{d['device_name'] or 'Unbound'}`\n"
            f"🆔 HWID    : `{d['device_id'] or '—'}`\n"
            f"📅 Expires : `{ts(d['expires_at'])}`\n"
            f"🔢 Uses    : `{d['usage_count']}`\n"
            f"📝 Note    : `{d['note'] or '—'}`",
            parse_mode="Markdown"
        )
    except Exception as e:
        await update.message.reply_text(f"❌ `{e}`", parse_mode="Markdown")

async def cmd_revoke(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id): return
    if not ctx.args:
        await update.message.reply_text("Usage: `/revoke <key>`", parse_mode="Markdown"); return
    try:
        requests.post(f"{SERVER_URL}/admin/revoke", data={"key": ctx.args[0]},
                      headers=HEADERS, timeout=10)
        await update.message.reply_text(f"🚫 Revoked: `{ctx.args[0]}`", parse_mode="Markdown")
    except Exception as e:
        await update.message.reply_text(f"❌ `{e}`", parse_mode="Markdown")

async def cmd_freeze(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id): return
    if not ctx.args:
        await update.message.reply_text("Usage: `/freeze <key>`", parse_mode="Markdown"); return
    try:
        r   = requests.post(f"{SERVER_URL}/admin/freeze", data={"key": ctx.args[0]},
                            headers=HEADERS, timeout=10)
        d   = r.json()
        e   = "❄️" if d["status"] == "frozen" else "✅"
        await update.message.reply_text(
            f"{e} Status: `{d['status']}`\n`{ctx.args[0]}`", parse_mode="Markdown"
        )
    except Exception as e:
        await update.message.reply_text(f"❌ `{e}`", parse_mode="Markdown")

async def cmd_resethwid(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id): return
    if not ctx.args:
        await update.message.reply_text("Usage: `/resethwid <key>`", parse_mode="Markdown"); return
    try:
        requests.post(f"{SERVER_URL}/admin/reset_hwid", data={"key": ctx.args[0]},
                      headers=HEADERS, timeout=10)
        await update.message.reply_text(f"♻️ HWID reset: `{ctx.args[0]}`", parse_mode="Markdown")
    except Exception as e:
        await update.message.reply_text(f"❌ `{e}`", parse_mode="Markdown")

async def cmd_listkeys(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id): return
    try:
        r    = requests.get(f"{SERVER_URL}/admin/listkeys", headers=HEADERS, timeout=10)
        keys = r.json()
        if not keys:
            await update.message.reply_text("No keys."); return
        em = {"active":"✅","expired":"⏳","revoked":"🚫","frozen":"❄️"}
        lines = ["📋 *All Keys (Latest 50)*\n"]
        for k in keys[:50]:
            e   = em.get(k["status"], "❓")
            exp = datetime.datetime.fromtimestamp(k["expires_at"]).strftime("%d/%m/%y %H:%M")
            lines.append(f"{e} `{k['key']}`\n   ⏱ {k.get('remaining_fmt','?')} | 📅 {exp} | 📱 {k['device_name'] or 'Unbound'}")
        msg = "\n".join(lines)
        if len(msg) > 4000: msg = msg[:3990] + "\n…(truncated)"
        await update.message.reply_text(msg, parse_mode="Markdown")
    except Exception as e:
        await update.message.reply_text(f"❌ `{e}`", parse_mode="Markdown")

def main():
    app = Application.builder().token(BOT_TOKEN).build()
    for name, fn in [
        ("start",     cmd_start),
        ("ping",      cmd_ping),
        ("genkey",    cmd_genkey),
        ("status",    cmd_status),
        ("info",      cmd_info),
        ("revoke",    cmd_revoke),
        ("freeze",    cmd_freeze),
        ("resethwid", cmd_resethwid),
        ("listkeys",  cmd_listkeys),
    ]:
        app.add_handler(CommandHandler(name, fn))
    print("[APEX BOT] Polling...")
    app.run_polling()

if __name__ == "__main__":
    main()