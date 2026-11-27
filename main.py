# main.py — APEX License Server + Admin Bot (single file)
# Developer : @APEX33Z | t.me/p20setuphai
# Deploy    : Render → Start Command: python main.py

import os, time, string, random, hashlib, struct, sqlite3, threading, datetime, requests
from flask import Flask, request, jsonify
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────

BOT_TOKEN          = os.environ.get("BOT_TOKEN",          "")
ADMIN_IDS          = [int(x) for x in os.environ.get("ADMIN_IDS", "").split(",") if x.strip()]
DB_PATH            = os.environ.get("DB_PATH",            "apex_keys.db")
ADMIN_TOKEN        = os.environ.get("ADMIN_TOKEN",        "APEX33Z_ADMIN_S3CR3T_2024")
SESSION_TTL        = int(os.environ.get("SESSION_TTL",    "120"))
SERVER_URL         = os.environ.get("SERVER_URL",         "https://p20-key.onrender.com")
BUILD_SIG_KEY      = os.environ.get("BUILD_SIG_KEY",      "APXBLD_FFI_2024")
EXPECTED_INTEGRITY = os.environ.get("EXPECTED_INTEGRITY", "6897")
PORT               = int(os.environ.get("PORT",           "5000"))

# ─────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.cursor().executescript("""
        CREATE TABLE IF NOT EXISTS keys (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            key         TEXT UNIQUE NOT NULL,
            device_id   TEXT DEFAULT NULL,
            device_name TEXT DEFAULT NULL,
            created_at  INTEGER NOT NULL,
            expires_at  INTEGER NOT NULL,
            status      TEXT DEFAULT 'active',
            usage_count INTEGER DEFAULT 0,
            last_used   INTEGER DEFAULT NULL,
            note        TEXT DEFAULT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            session_token TEXT UNIQUE NOT NULL,
            key_ref       TEXT NOT NULL,
            device_id     TEXT NOT NULL,
            created_at    INTEGER NOT NULL,
            expires_at    INTEGER NOT NULL,
            used          INTEGER DEFAULT 0
        );
    """)
    conn.commit()
    conn.close()

init_db()
db_lock = threading.Lock()

# ─────────────────────────────────────────────
# APEX CIPHER v1
# ─────────────────────────────────────────────

def apex_derive_key(session_token: str, nonce: str) -> list:
    sl  = len(session_token)
    nl  = len(nonce)
    key = []
    for i in range(32):
        sb = ord(session_token[i % sl])
        nb = ord(nonce[i % nl])
        key.append((sb ^ nb ^ ((i * 7) & 0xFF)) & 0xFF)
    return key

def apex_encode(data: bytes, session_token: str, nonce: str) -> str:
    BLOCK    = 16
    key      = apex_derive_key(session_token, nonce)
    orig_len = len(data)

    # Layer 1
    l1 = bytearray()
    for i, b in enumerate(data):
        rotated = (b + (i & 0xFF)) & 0xFF
        l1.append(rotated ^ key[i % 32])

    while len(l1) % BLOCK:
        l1.append(0x00)
    n_blocks = len(l1) // BLOCK
    blocks   = [l1[i * BLOCK:(i + 1) * BLOCK] for i in range(n_blocks)]

    # Layer 2
    l2 = bytearray(n_blocks * BLOCK)
    for b in range(n_blocks):
        for pos in range(BLOCK):
            l2[pos * n_blocks + b] = blocks[b][pos]

    l2p = bytearray(l2)
    while len(l2p) % 32:
        l2p.append(0x00)
    l3_chunks = len(l2p) // 32

    # Layer 3
    l3 = bytearray()
    for i in range(l3_chunks):
        chunk = l2p[i * 32:(i + 1) * 32]
        csum  = sum(chunk) & 0xFF
        l3.extend(chunk)
        l3.append(csum)

    header = struct.pack(">IHHI", orig_len, n_blocks, BLOCK, l3_chunks)
    return (bytes(header) + bytes(l3)).hex()

# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def gen_session_token() -> str:
    raw = f"{time.time()}{random.random()}{os.urandom(16).hex()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]

def gen_nonce() -> str:
    return os.urandom(8).hex()

def compute_expected_sig(device_id: str) -> str:
    key_b  = BUILD_SIG_KEY.encode()
    result = []
    for i, ch in enumerate(device_id.encode("utf-8")):
        result.append(f"{ch ^ key_b[i % len(key_b)]:02x}")
    return "".join(result)

def admin_ok() -> bool:
    return request.headers.get("X-Admin-Token") == ADMIN_TOKEN

def fmt_remaining(secs: int) -> str:
    if secs <= 0: return "EXPIRED"
    d = secs // 86400
    h = (secs % 86400) // 3600
    m = (secs % 3600)  // 60
    s = secs % 60
    parts = []
    if d: parts.append(f"{d}d")
    if h: parts.append(f"{h}h")
    if m: parts.append(f"{m}m")
    if s or not parts: parts.append(f"{s}s")
    return " ".join(parts)

def ts(epoch) -> str:
    if not epoch: return "Never"
    return datetime.datetime.fromtimestamp(int(epoch)).strftime("%Y-%m-%d %H:%M:%S")

def parse_duration(arg: str):
    arg = arg.strip().lower()
    if arg.endswith("h"):   return max(1, int(arg[:-1])) * 3600,  arg.upper()
    elif arg.endswith("d"): return max(1, int(arg[:-1])) * 86400, arg.upper()
    elif arg.endswith("m"): return max(1, int(arg[:-1])) * 60,    arg.upper()
    else:                   return max(1, int(arg)) * 86400,       f"{arg}D"

# ─────────────────────────────────────────────
# FLASK APP
# ─────────────────────────────────────────────

app = Flask(__name__)

@app.route("/ping", methods=["GET"])
def ping():
    return jsonify({"status": "online", "service": "APEX License Server", "dev": "@APEX33Z"})


@app.route("/validate", methods=["POST"])
def validate():
    key         = (request.form.get("key",         "") or "").strip()
    device_id   = (request.form.get("device_id",   "") or "").strip()
    device_name = (request.form.get("device_name", "Unknown") or "Unknown").strip()
    client_sig  = (request.form.get("sig",         "") or "").strip()
    integrity   = (request.form.get("integrity",   "") or "").strip()

    if not key or not device_id:
        return "INVALID", 200

    if integrity != EXPECTED_INTEGRITY:
        return "CRACKED", 200

    if client_sig != compute_expected_sig(device_id):
        return "CRACKED", 200

    with db_lock:
        conn = get_db()
        c    = conn.cursor()
        c.execute("SELECT * FROM keys WHERE key=?", (key,))
        row  = c.fetchone()

        if not row:
            conn.close()
            return "INVALID", 200
        if row["status"] == "revoked":
            conn.close()
            return "REVOKED", 200
        if row["status"] == "frozen":
            conn.close()
            return "FROZEN", 200
        if int(time.time()) > row["expires_at"]:
            c.execute("UPDATE keys SET status='expired' WHERE key=?", (key,))
            conn.commit()
            conn.close()
            return "EXPIRED", 200

        if row["device_id"] is None:
            c.execute(
                "UPDATE keys SET device_id=?, device_name=?, "
                "usage_count=usage_count+1, last_used=? WHERE key=?",
                (device_id, device_name, int(time.time()), key)
            )
        elif row["device_id"] != device_id:
            conn.close()
            return "DEVICE_MISMATCH", 200
        else:
            c.execute(
                "UPDATE keys SET usage_count=usage_count+1, last_used=? WHERE key=?",
                (int(time.time()), key)
            )

        token = gen_session_token()
        c.execute(
            "INSERT INTO sessions "
            "(session_token, key_ref, device_id, created_at, expires_at) "
            "VALUES (?,?,?,?,?)",
            (token, key, device_id, int(time.time()), int(time.time()) + SESSION_TTL)
        )
        conn.commit()
        conn.close()

    remaining = fmt_remaining(int(row["expires_at"]) - int(time.time()))
    return f"VALID:{token}:{remaining}", 200


@app.route("/payload", methods=["POST"])
def payload():
    token      = (request.form.get("token",     "") or "").strip()
    device_id  = (request.form.get("device_id", "") or "").strip()
    client_sig = (request.form.get("sig",       "") or "").strip()

    if not token or not device_id:
        return "DENIED", 200

    if client_sig != compute_expected_sig(device_id):
        return "CRACKED", 200

    with db_lock:
        conn = get_db()
        c    = conn.cursor()
        c.execute("SELECT * FROM sessions WHERE session_token=?", (token,))
        sess = c.fetchone()

        if not sess:
            conn.close()
            return "DENIED", 200
        if sess["used"]:
            conn.close()
            return "USED", 200
        if int(time.time()) > sess["expires_at"]:
            conn.close()
            return "EXPIRED", 200
        if sess["device_id"] != device_id:
            conn.close()
            return "DENIED", 200

        c.execute("UPDATE sessions SET used=1 WHERE session_token=?", (token,))
        conn.commit()
        conn.close()

    payload_path = os.path.join(os.path.dirname(__file__), "payloads", "crashfix.lua")
    try:
        with open(payload_path, "r", encoding="utf-8") as f:
            lua_code = f.read()
    except Exception:
        return "ERROR", 200

    nonce   = gen_nonce()
    encoded = apex_encode(lua_code.encode("utf-8"), token, nonce)
    return f"{nonce}:{encoded}", 200


@app.route("/status", methods=["POST"])
def key_status():
    if not admin_ok():
        return jsonify({"error": "unauthorized"}), 403
    key  = (request.form.get("key", "") or "").strip()
    with db_lock:
        conn = get_db()
        c    = conn.cursor()
        c.execute("SELECT * FROM keys WHERE key=?", (key,))
        row  = c.fetchone()
        conn.close()
    if not row:
        return jsonify({"error": "not found"}), 404
    now       = int(time.time())
    remaining = max(0, int(row["expires_at"]) - now)
    return jsonify({
        "key":           row["key"],
        "status":        row["status"],
        "device_name":   row["device_name"],
        "device_id":     row["device_id"],
        "created_at":    row["created_at"],
        "expires_at":    row["expires_at"],
        "remaining_sec": remaining,
        "remaining_fmt": fmt_remaining(remaining),
        "usage_count":   row["usage_count"],
        "last_used":     row["last_used"],
        "note":          row["note"],
    }), 200


@app.route("/admin/genkey", methods=["POST"])
def admin_genkey():
    if not admin_ok():
        return jsonify({"error": "unauthorized"}), 403
    hours_raw = request.form.get("hours")
    days_raw  = request.form.get("days", "30")
    note      = request.form.get("note", "")
    if hours_raw is not None:
        h          = max(1, int(hours_raw))
        expires_in = h * 3600
        label      = f"{h}h"
    else:
        d          = max(1, int(days_raw))
        expires_in = d * 86400
        label      = f"{d}d"
    pool    = string.ascii_uppercase + string.digits
    new_key = (
        "APEX-" + "".join(random.choices(pool, k=5))
        + "-"   + "".join(random.choices(pool, k=5))
        + "-"   + "".join(random.choices(pool, k=4))
    )
    now = int(time.time())
    with db_lock:
        conn = get_db()
        c    = conn.cursor()
        c.execute(
            "INSERT INTO keys (key, created_at, expires_at, note) VALUES (?,?,?,?)",
            (new_key, now, now + expires_in, note)
        )
        conn.commit()
        conn.close()
    return jsonify({"key": new_key, "expires": label, "note": note}), 200


@app.route("/admin/keyinfo", methods=["POST"])
def admin_keyinfo():
    if not admin_ok():
        return jsonify({"error": "unauthorized"}), 403
    key = request.form.get("key", "")
    with db_lock:
        conn = get_db()
        c    = conn.cursor()
        c.execute("SELECT * FROM keys WHERE key=?", (key,))
        row  = c.fetchone()
        conn.close()
    if not row:
        return jsonify({"error": "not found"}), 404
    d   = dict(row)
    rem = max(0, int(d["expires_at"]) - int(time.time()))
    d["remaining_fmt"] = fmt_remaining(rem)
    d["remaining_sec"] = rem
    return jsonify(d), 200


@app.route("/admin/revoke", methods=["POST"])
def admin_revoke():
    if not admin_ok():
        return jsonify({"error": "unauthorized"}), 403
    key = request.form.get("key", "")
    with db_lock:
        conn = get_db()
        conn.cursor().execute("UPDATE keys SET status='revoked' WHERE key=?", (key,))
        conn.commit()
        conn.close()
    return jsonify({"status": "revoked", "key": key}), 200


@app.route("/admin/freeze", methods=["POST"])
def admin_freeze():
    if not admin_ok():
        return jsonify({"error": "unauthorized"}), 403
    key = request.form.get("key", "")
    with db_lock:
        conn = get_db()
        c    = conn.cursor()
        c.execute("SELECT status FROM keys WHERE key=?", (key,))
        row  = c.fetchone()
        if not row:
            conn.close()
            return jsonify({"error": "not found"}), 404
        ns = "active" if row["status"] == "frozen" else "frozen"
        c.execute("UPDATE keys SET status=? WHERE key=?", (ns, key))
        conn.commit()
        conn.close()
    return jsonify({"status": ns, "key": key}), 200


@app.route("/admin/reset_hwid", methods=["POST"])
def admin_reset_hwid():
    if not admin_ok():
        return jsonify({"error": "unauthorized"}), 403
    key = request.form.get("key", "")
    with db_lock:
        conn = get_db()
        conn.cursor().execute(
            "UPDATE keys SET device_id=NULL, device_name=NULL WHERE key=?", (key,)
        )
        conn.commit()
        conn.close()
    return jsonify({"status": "hwid_reset", "key": key}), 200


@app.route("/admin/listkeys", methods=["GET"])
def admin_listkeys():
    if not admin_ok():
        return jsonify({"error": "unauthorized"}), 403
    with db_lock:
        conn = get_db()
        c    = conn.cursor()
        c.execute("SELECT * FROM keys ORDER BY created_at DESC LIMIT 100")
        now  = int(time.time())
        rows = []
        for r in c.fetchall():
            d   = dict(r)
            rem = max(0, int(d["expires_at"]) - now)
            d["remaining_fmt"] = fmt_remaining(rem)
            d["remaining_sec"] = rem
            rows.append(d)
        conn.close()
    return jsonify(rows), 200

# ─────────────────────────────────────────────
# TELEGRAM BOT
# ─────────────────────────────────────────────

HEADERS = {"X-Admin-Token": ADMIN_TOKEN}

def is_admin(uid): return uid in ADMIN_IDS

def fmt_bar(seconds: int) -> str:
    if seconds <= 0: return "🔴 EXPIRED"
    d  = seconds // 86400
    h  = (seconds % 86400) // 3600
    m  = (seconds % 3600)  // 60
    s  = seconds % 60
    p  = []
    if d: p.append(f"{d}d")
    if h: p.append(f"{h}h")
    if m: p.append(f"{m}m")
    if s or not p: p.append(f"{s}s")
    return "🟢 " + " ".join(p)

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
        await update.message.reply_text(
            "Usage: `/genkey <duration> [note]`\nExample: `/genkey 6h reseller`",
            parse_mode="Markdown"
        )
        return
    try:
        secs, label = parse_duration(args[0])
    except Exception:
        await update.message.reply_text("❌ Bad duration. Use `6h`, `30d`.", parse_mode="Markdown")
        return
    note = " ".join(args[1:]) if len(args) > 1 else ""
    post = {"note": note}
    if args[0].lower().endswith("h"): post["hours"] = str(max(1, secs // 3600))
    else:                             post["days"]  = str(max(1, secs // 86400))
    try:
        r   = requests.post(f"{SERVER_URL}/admin/genkey",
                            data=post, headers=HEADERS, timeout=10)
        d   = r.json()
        exp = datetime.datetime.fromtimestamp(int(time.time()) + secs).strftime("%Y-%m-%d %H:%M:%S")
        await update.message.reply_text(
            f"✅ *Key Generated!*\n\n`{d['key']}`\n\n"
            f"⏳ Duration : *{label}*\n"
            f"📅 Expires  : `{exp}`\n"
            f"📝 Note     : {note or '—'}",
            parse_mode="Markdown"
        )
    except Exception as e:
        await update.message.reply_text(f"❌ `{e}`", parse_mode="Markdown")

async def cmd_status(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id): return
    if not ctx.args:
        await update.message.reply_text("Usage: `/status <key>`", parse_mode="Markdown"); return
    try:
        r = requests.post(f"{SERVER_URL}/status",
                          data={"key": ctx.args[0]}, headers=HEADERS, timeout=10)
        if r.status_code == 404:
            await update.message.reply_text("❌ Not found."); return
        d     = r.json()
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
        r = requests.post(f"{SERVER_URL}/admin/keyinfo",
                          data={"key": ctx.args[0]}, headers=HEADERS, timeout=10)
        if r.status_code == 404:
            await update.message.reply_text("❌ Not found."); return
        d     = r.json()
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
        requests.post(f"{SERVER_URL}/admin/revoke",
                      data={"key": ctx.args[0]}, headers=HEADERS, timeout=10)
        await update.message.reply_text(f"🚫 Revoked: `{ctx.args[0]}`", parse_mode="Markdown")
    except Exception as e:
        await update.message.reply_text(f"❌ `{e}`", parse_mode="Markdown")

async def cmd_freeze(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id): return
    if not ctx.args:
        await update.message.reply_text("Usage: `/freeze <key>`", parse_mode="Markdown"); return
    try:
        r   = requests.post(f"{SERVER_URL}/admin/freeze",
                            data={"key": ctx.args[0]}, headers=HEADERS, timeout=10)
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
        requests.post(f"{SERVER_URL}/admin/reset_hwid",
                      data={"key": ctx.args[0]}, headers=HEADERS, timeout=10)
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
        em    = {"active":"✅","expired":"⏳","revoked":"🚫","frozen":"❄️"}
        lines = ["📋 *All Keys (Latest 50)*\n"]
        for k in keys[:50]:
            e   = em.get(k["status"], "❓")
            exp = datetime.datetime.fromtimestamp(k["expires_at"]).strftime("%d/%m/%y %H:%M")
            lines.append(
                f"{e} `{k['key']}`\n"
                f"   ⏱ {k.get('remaining_fmt','?')} | 📅 {exp} | 📱 {k['device_name'] or 'Unbound'}"
            )
        msg = "\n".join(lines)
        if len(msg) > 4000: msg = msg[:3990] + "\n…(truncated)"
        await update.message.reply_text(msg, parse_mode="Markdown")
    except Exception as e:
        await update.message.reply_text(f"❌ `{e}`", parse_mode="Markdown")

# ─────────────────────────────────────────────
# BOT THREAD
# ─────────────────────────────────────────────

def run_bot():
    if not BOT_TOKEN:
        print("[APEX BOT] BOT_TOKEN not set — bot disabled.")
        return
    import asyncio
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    application = Application.builder().token(BOT_TOKEN).build()
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
        application.add_handler(CommandHandler(name, fn))

    print("[APEX BOT] Polling started...")
    loop.run_until_complete(application.run_polling())

# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    # Bot ko background thread mein chalao
    bot_thread = threading.Thread(target=run_bot, daemon=True)
    bot_thread.start()

    # Flask foreground mein
    print(f"[APEX SERVER] Starting on port {PORT}...")
    app.run(host="0.0.0.0", port=PORT, debug=False, use_reloader=False)
