# main.py — APEX License Server v3.1
# Server: https://lua-server-apex.onrender.com
# Cipher: APEX GHOST v3 (custom) | Wire: token-derived
# @APEX33Z

import os, re, time, string, random, hashlib, hmac, struct, sqlite3
import threading, datetime, logging, asyncio, signal, sys
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] %(name)s — %(message)s")
log = logging.getLogger("APEX")

BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
ADMIN_IDS = [int(x) for x in os.environ.get("ADMIN_IDS", "").split(",") if x.strip()]
DB_PATH = os.environ.get("DB_PATH", "apex_keys.db")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "APEX33Z_ADMIN_S3CR3T_2024")
SESSION_TTL = int(os.environ.get("SESSION_TTL", "120"))
SERVER_URL = os.environ.get("SERVER_URL", "https://lua-server-apex.onrender.com").rstrip("/")
BUILD_SIG_KEY = os.environ.get("BUILD_SIG_KEY", "APXBLD_FFI_2024")
EXPECTED_INTEGRITY = os.environ.get("EXPECTED_INTEGRITY", "6897")
PORT = int(os.environ.get("PORT", "5000"))

# ✅ HARDCODED MASTER_HEX — env var ke bharose nahi
MASTER_HEX = os.environ.get(
    "MASTER_HEX",
    "9f3a7c1e5b8d2460a1c9e7f3d5b8a2460c1e9f7a3d5b8c2460e1f9a7c3d5b8e246a1c9f7e3d5b8a2460c1e9f7a3d5b8c2460e1f9a7c3d5b8e246a"
)

if not MASTER_HEX or len(MASTER_HEX) != 128:
    log.error("MASTER_HEX invalid — check hardcoded value")
MASTER = bytes.fromhex(MASTER_HEX)

MAGIC2 = 0xDEAD

def _ensure_dir(p):
    d = os.path.dirname(os.path.abspath(p))
    if d and not os.path.exists(d): os.makedirs(d, exist_ok=True)
_ensure_dir(DB_PATH)

def get_db():
    c = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    return c

def init_db():
    c = get_db()
    c.cursor().executescript("""
        CREATE TABLE IF NOT EXISTS keys (id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT UNIQUE NOT NULL, device_id TEXT DEFAULT NULL, device_name TEXT DEFAULT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, status TEXT DEFAULT 'active', usage_count INTEGER DEFAULT 0, last_used INTEGER DEFAULT NULL, note TEXT DEFAULT NULL);
        CREATE TABLE IF NOT EXISTS sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, session_token TEXT UNIQUE NOT NULL, key_ref TEXT NOT NULL, device_id TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, used INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, key_ref TEXT, actor TEXT, meta TEXT, ts INTEGER NOT NULL);
    """)
    c.commit(); c.close()
init_db()
db_lock = threading.Lock()

# ─────────────────────────────────────────────
# WIRE CIPHER — token-derived, client-computable
# ─────────────────────────────────────────────

def _wire_encrypt(data: bytes, token_hex: str) -> bytes:
    seed = bytes.fromhex(token_hex[:32])
    n = len(data)
    sl = len(seed)

    a = bytearray(n)
    for i in range(n):
        a[i] = data[i] ^ seed[i % sl] ^ ((i * 13) & 0xFF)

    b = bytearray(n)
    for i in range(n):
        rot = (seed[(i * 3) % sl] + i) % 8
        v = a[i]
        b[i] = ((v << rot) | (v >> (8 - rot))) & 0xFF

    c = bytearray(n)
    for i in range(0, n - 1, 2):
        c[i] = b[i + 1]
        c[i + 1] = b[i]
    if n % 2: c[n - 1] = b[n - 1]

    hdr = struct.pack('>I', n)
    out = bytearray(hdr)
    for i in range(0, n, 13):
        ch = c[i:i+13]
        out.extend(ch)
        s = 0
        for x in ch: s = (s ^ x) + 0x3C
        out.append(s & 0xFF)
    return bytes(out)

def _wire_decrypt(blob: bytes, token_hex: str) -> bytes:
    if len(blob) < 4: raise ValueError("short")
    n = struct.unpack('>I', blob[:4])[0]
    body = blob[4:]
    seed = bytes.fromhex(token_hex[:32])
    sl = len(seed)

    c = bytearray()
    i = 0
    while i < len(body):
        ch = body[i:i+13]
        if i + 13 < len(body):
            s = 0
            for x in ch: s = (s ^ x) + 0x3C
            if (s & 0xFF) != body[i + 13]:
                raise ValueError("csum")
            i += 14
        else:
            i += 13
        c.extend(ch)

    b = bytearray(len(c))
    for i in range(0, len(c) - 1, 2):
        b[i] = c[i + 1]
        b[i + 1] = c[i]
    if len(c) % 2: b[-1] = c[-1]

    a = bytearray(len(b))
    for i in range(len(b)):
        rot = (seed[(i * 3) % sl] + i) % 8
        v = b[i]
        a[i] = ((v >> rot) | (v << (8 - rot))) & 0xFF

    out = bytearray(len(a))
    for i in range(len(a)):
        out[i] = a[i] ^ seed[i % sl] ^ ((i * 13) & 0xFF)
    return bytes(out[:n])

_B62 = "Zq7yKx9Wp2Lm5Nv8Rt3Bc6Fj1Hg4Ds0AaEoIuYwQeTrUzXkOiP"
_B62_IDX = {c: i for i, c in enumerate(_B62)}

def _weird_encode(data: bytes) -> str:
    out = []
    pad = (3 - len(data) % 3) % 3
    data = data + b'\x00' * pad
    for i in range(0, len(data), 3):
        v = (data[i] << 16) | (data[i+1] << 8) | data[i+2]
        s = ""
        for _ in range(4):
            s = _B62[v % 62] + s
            v //= 62
        out.append(s)
    return "".join(out) + f".{pad}"

def _weird_decode(enc: str) -> bytes:
    if '.' not in enc: raise ValueError("no_dot")
    body, pad_s = enc.rsplit('.', 1)
    pad = int(pad_s)
    out = bytearray()
    for i in range(0, len(body), 4):
        ch = body[i:i+4]
        if len(ch) < 4: break
        v = 0
        for c in ch: v = v * 62 + _B62_IDX[c]
        out += bytes([(v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF])
    if pad: out = out[:-pad]
    return bytes(out)

# ─── helpers ───
KEY_RE = re.compile(r"^APEX-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{4}$")
def is_valid_key(k): return bool(KEY_RE.match(k))
def gen_token(): return hashlib.sha256(f"{time.time()}{os.urandom(32).hex()}".encode()).hexdigest()
def compute_sig(did):
    kb = BUILD_SIG_KEY.encode()
    return "".join(f"{ch ^ kb[i % len(kb)]:02x}" for i, ch in enumerate(did.encode()))
def admin_ok(): return hmac.compare_digest(request.headers.get("X-Admin-Token",""), ADMIN_TOKEN)

def audit(a, k=None, who="system", m=""):
    try:
        with db_lock:
            c = get_db(); c.cursor().execute("INSERT INTO audit_log (action,key_ref,actor,meta,ts) VALUES (?,?,?,?,?)",
                (a, k, who, m, int(time.time()))); c.commit(); c.close()
    except Exception as e: log.error(f"audit: {e}")

def fmt_rem(s):
    if s <= 0: return "EXPIRED"
    d, h, m, sec = s//86400, (s%86400)//3600, (s%3600)//60, s%60
    p = []
    if d: p.append(f"{d}d")
    if h: p.append(f"{h}h")
    if m: p.append(f"{m}m")
    if sec or not p: p.append(f"{sec}s")
    return " ".join(p)

def ts(e): return datetime.datetime.fromtimestamp(int(e)).strftime("%Y-%m-%d %H:%M:%S") if e else "Never"

def parse_dur(a):
    a = a.strip().lower()
    if a.endswith("h"): return max(1,int(a[:-1]))*3600, a.upper()
    if a.endswith("d"): return max(1,int(a[:-1]))*86400, a.upper()
    if a.endswith("m"): return max(1,int(a[:-1]))*60, a.upper()
    return max(1,int(a))*86400, f"{a}D"

# ─── FLASK ───
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64*1024
limiter = Limiter(get_remote_address, app=app, default_limits=["120 per minute"], storage_uri="memory://")

@app.route("/ping")
def ping(): return jsonify({"status":"online","v":"3.1","dev":"@APEX33Z"})

@app.route("/validate", methods=["POST"])
@limiter.limit("30 per minute")
def validate():
    key = (request.form.get("key","") or "").strip()
    did = (request.form.get("device_id","") or "").strip()
    dname = (request.form.get("device_name","Unknown") or "Unknown").strip()[:64]
    sig = (request.form.get("sig","") or "").strip()
    integ = (request.form.get("integrity","") or "").strip()

    if not key or not did: return "INVALID", 200
    if not is_valid_key(key): return "INVALID", 200
    if integ != EXPECTED_INTEGRITY: return "CRACKED", 200
    if not hmac.compare_digest(sig, compute_sig(did)): return "CRACKED", 200

    with db_lock:
        c = get_db(); cur = c.cursor()
        cur.execute("SELECT * FROM keys WHERE key=?", (key,)); row = cur.fetchone()
        if not row: c.close(); return "INVALID", 200
        if row["status"] == "revoked": c.close(); return "REVOKED", 200
        if row["status"] == "frozen": c.close(); return "FROZEN", 200
        if int(time.time()) > row["expires_at"]:
            cur.execute("UPDATE keys SET status='expired' WHERE key=?", (key,)); c.commit(); c.close()
            return "EXPIRED", 200
        if row["device_id"] and row["device_id"] != did: c.close(); return "DEVICE_MISMATCH", 200

        now = int(time.time())
        if not row["device_id"]:
            cur.execute("UPDATE keys SET device_id=?,device_name=?,usage_count=usage_count+1,last_used=? WHERE key=?",
                (did, dname, now, key))
        else:
            cur.execute("UPDATE keys SET usage_count=usage_count+1,last_used=? WHERE key=?", (now, key))
        token = gen_token()
        cur.execute("INSERT INTO sessions (session_token,key_ref,device_id,created_at,expires_at) VALUES (?,?,?,?,?)",
            (token, key, did, now, now + SESSION_TTL))
        c.commit(); c.close()

    rem = fmt_rem(int(row["expires_at"]) - int(time.time()))
    audit("validate_ok", key, did, "ok")
    return f"VALID:{token}:{rem}", 200

@app.route("/payload", methods=["POST"])
@limiter.limit("30 per minute")
def payload():
    token = (request.form.get("token","") or "").strip()
    did = (request.form.get("device_id","") or "").strip()
    sig = (request.form.get("sig","") or "").strip()

    if not token or not did: return "DENIED", 200
    if not hmac.compare_digest(sig, compute_sig(did)): return "CRACKED", 200

    with db_lock:
        c = get_db(); cur = c.cursor()
        cur.execute("SELECT * FROM sessions WHERE session_token=?", (token,)); s = cur.fetchone()
        if not s: c.close(); return "DENIED", 200
        if s["used"]: c.close(); return "USED", 200
        if int(time.time()) > s["expires_at"]: c.close(); return "EXPIRED", 200
        if s["device_id"] != did: c.close(); return "DENIED", 200
        cur.execute("UPDATE sessions SET used=1 WHERE session_token=?", (token,)); c.commit(); c.close()

    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "crashfix.lua")
    try:
        with open(path, "rb") as f: real = f.read()
        real.decode("utf-8")
    except Exception as e:
        log.error(f"payload fail: {e}")
        return "OK:" + _send_decoy(token), 200

    blob = _wire_encrypt(real, token)
    return "OK:" + _weird_encode(blob), 200

def _send_decoy(token_hex):
    decoy_src = (
        '-- CRACK DETECTED\n'
        'gg.alert("Madarchod, teri aukat nahi hai khud ka banane ki.\\n"'
        ' .. "Vastu yahi kar sakta hai — crack loader.\\n"'
        ' .. "Lauda pakad, kuch nahi milega!\\n\\n"'
        ' .. "[ APEX ANTI-CRACK FIRED ]\\n"'
        ' .. "Server ne tujhe pakad liya.\\n"'
        ' .. "Bypass ka koi rasta nahi.\\n"'
        ' .. "Ja ghar, khet mein kaam kar.\\n"'
        ' .. "[ @APEX33Z | t.me/p20setuphai ]")\n'
        'os.exit()\n'
    ).encode()
    blob = _wire_encrypt(decoy_src, token_hex)
    return _weird_encode(blob)

# ─── ADMIN ───
@app.route("/status", methods=["POST"])
@limiter.limit("60 per minute")
def key_status():
    if not admin_ok(): return jsonify({"error":"unauthorized"}), 403
    key = (request.form.get("key","") or "").strip()
    if not is_valid_key(key): return jsonify({"error":"bad"}), 400
    with db_lock:
        c = get_db(); cur = c.cursor(); cur.execute("SELECT * FROM keys WHERE key=?", (key,)); r = cur.fetchone(); c.close()
    if not r: return jsonify({"error":"not found"}), 404
    rem = max(0, int(r["expires_at"]) - int(time.time()))
    return jsonify({"key":r["key"],"status":r["status"],"device_name":r["device_name"],"device_id":r["device_id"],
        "created_at":r["created_at"],"expires_at":r["expires_at"],"remaining_sec":rem,"remaining_fmt":fmt_rem(rem),
        "usage_count":r["usage_count"],"last_used":r["last_used"],"note":r["note"]})

@app.route("/admin/genkey", methods=["POST"])
def admin_genkey():
    if not admin_ok(): return jsonify({"error":"unauthorized"}), 403
    hrs = request.form.get("hours"); dys = request.form.get("days","30"); note = request.form.get("note","")[:200]
    try:
        if hrs is not None: h = max(1, min(int(hrs), 24*365)); exp_in = h*3600; lbl = f"{h}h"
        else: d = max(1, min(int(dys), 365)); exp_in = d*86400; lbl = f"{d}d"
    except ValueError: return jsonify({"error":"bad duration"}), 400
    pool = string.ascii_uppercase + string.digits
    for _ in range(10):
        nk = "APEX-"+"".join(random.choices(pool,k=5))+"-"+"".join(random.choices(pool,k=5))+"-"+"".join(random.choices(pool,k=4))
        now = int(time.time())
        try:
            with db_lock:
                c = get_db(); c.cursor().execute("INSERT INTO keys (key,created_at,expires_at,note) VALUES (?,?,?,?)",
                    (nk, now, now+exp_in, note)); c.commit(); c.close()
            audit("genkey", nk, "admin", lbl)
            return jsonify({"key":nk,"expires":lbl,"note":note})
        except sqlite3.IntegrityError: continue
    return jsonify({"error":"gen fail"}), 500

@app.route("/admin/keyinfo", methods=["POST"])
def admin_keyinfo():
    if not admin_ok(): return jsonify({"error":"unauthorized"}), 403
    key = request.form.get("key","")
    with db_lock:
        c = get_db(); cur = c.cursor(); cur.execute("SELECT * FROM keys WHERE key=?", (key,)); r = cur.fetchone(); c.close()
    if not r: return jsonify({"error":"not found"}), 404
    d = dict(r); rem = max(0, int(d["expires_at"]) - int(time.time()))
    d["remaining_fmt"] = fmt_rem(rem); d["remaining_sec"] = rem
    return jsonify(d)

@app.route("/admin/revoke", methods=["POST"])
def admin_revoke():
    if not admin_ok(): return jsonify({"error":"unauthorized"}), 403
    key = request.form.get("key","")
    with db_lock:
        c = get_db(); c.cursor().execute("UPDATE keys SET status='revoked' WHERE key=?", (key,)); c.commit(); c.close()
    audit("revoke", key, "admin")
    return jsonify({"status":"revoked","key":key})

@app.route("/admin/freeze", methods=["POST"])
def admin_freeze():
    if not admin_ok(): return jsonify({"error":"unauthorized"}), 403
    key = request.form.get("key","")
    with db_lock:
        c = get_db(); cur = c.cursor(); cur.execute("SELECT status FROM keys WHERE key=?", (key,)); r = cur.fetchone()
        if not r: c.close(); return jsonify({"error":"not found"}), 404
        ns = "active" if r["status"]=="frozen" else "frozen"
        cur.execute("UPDATE keys SET status=? WHERE key=?", (ns, key)); c.commit(); c.close()
    audit("freeze", key, "admin", ns)
    return jsonify({"status":ns,"key":key})

@app.route("/admin/reset_hwid", methods=["POST"])
def admin_reset_hwid():
    if not admin_ok(): return jsonify({"error":"unauthorized"}), 403
    key = request.form.get("key","")
    with db_lock:
        c = get_db(); c.cursor().execute("UPDATE keys SET device_id=NULL,device_name=NULL WHERE key=?", (key,)); c.commit(); c.close()
    audit("reset_hwid", key, "admin")
    return jsonify({"status":"hwid_reset","key":key})

@app.route("/admin/listkeys")
@limiter.limit("30 per minute")
def admin_listkeys():
    if not admin_ok(): return jsonify({"error":"unauthorized"}), 403
    with db_lock:
        c = get_db(); cur = c.cursor(); cur.execute("SELECT * FROM keys ORDER BY created_at DESC LIMIT 100")
        now = int(time.time()); rows = []
        for r in cur.fetchall():
            d = dict(r); rem = max(0, int(d["expires_at"]) - now)
            d["remaining_fmt"] = fmt_rem(rem); d["remaining_sec"] = rem; rows.append(d)
        c.close()
    return jsonify(rows)

@app.route("/admin/audit")
def admin_audit():
    if not admin_ok(): return jsonify({"error":"unauthorized"}), 403
    lim = min(int(request.args.get("limit","100")), 500)
    with db_lock:
        c = get_db(); cur = c.cursor(); cur.execute("SELECT * FROM audit_log ORDER BY ts DESC LIMIT ?", (lim,))
        rows = [dict(r) for r in cur.fetchall()]; c.close()
    return jsonify(rows)

# ─── CLEANUP ───
_stop = threading.Event()
def cleanup():
    while not _stop.is_set():
        try:
            with db_lock:
                c = get_db(); cur = c.cursor(); now = int(time.time())
                cur.execute("DELETE FROM sessions WHERE expires_at < ?", (now-3600,))
                cur.execute("UPDATE keys SET status='expired' WHERE status='active' AND expires_at < ?", (now,))
                c.commit(); c.close()
        except Exception as e: log.error(f"cleanup: {e}")
        _stop.wait(3600)

# ─── BOT ───
bot_stop = threading.Event()
def run_bot():
    if not BOT_TOKEN: return
    from telegram import Update
    from telegram.ext import Application, CommandHandler, ContextTypes
    import httpx
    H = {"X-Admin-Token": ADMIN_TOKEN}
    def is_admin(u): return u in ADMIN_IDS
    async def _p(path, data):
        async with httpx.AsyncClient(timeout=15) as cl: return await cl.post(f"{SERVER_URL}{path}", data=data, headers=H)
    async def _g(path):
        async with httpx.AsyncClient(timeout=15) as cl: return await cl.get(f"{SERVER_URL}{path}", headers=H)
    def bar(s):
        if s <= 0: return "🔴 EXPIRED"
        d,h,m,sec = s//86400,(s%86400)//3600,(s%3600)//60,s%60
        p = []
        if d: p.append(f"{d}d")
        if h: p.append(f"{h}h")
        if m: p.append(f"{m}m")
        if sec or not p: p.append(f"{sec}s")
        return "🟢 "+" ".join(p)

    async def c_start(u,ctx):
        if not is_admin(u.effective_user.id): return
        await u.message.reply_text("🔥 *APEX Bot v3.1* | @APEX33Z\n\n`/genkey <dur> [note]`\n`/status <key>` | `/info <key>` | `/revoke <key>`\n`/freeze <key>` | `/resethwid <key>`\n`/listkeys` | `/audit` | `/ping`", parse_mode="Markdown")
    async def c_ping(u,ctx):
        if not is_admin(u.effective_user.id): return
        try: r = await _g("/ping"); await u.message.reply_text(f"✅ `{r.json()}`", parse_mode="Markdown")
        except Exception as e: await u.message.reply_text(f"❌ `{e}`")
    async def c_genkey(u,ctx):
        if not is_admin(u.effective_user.id): return
        args = ctx.args or []
        if not args: await u.message.reply_text("Usage: `/genkey <dur> [note]`", parse_mode="Markdown"); return
        try: secs, lbl = parse_dur(args[0])
        except: await u.message.reply_text("❌ Bad duration"); return
        note = " ".join(args[1:])[:200] if len(args)>1 else ""
        post = {"note":note}
        if args[0].lower().endswith("h"): post["hours"] = str(max(1, secs//3600))
        else: post["days"] = str(max(1, secs//86400))
        try:
            r = await _p("/admin/genkey", post); d = r.json()
            exp = datetime.datetime.fromtimestamp(int(time.time())+secs).strftime("%Y-%m-%d %H:%M:%S")
            await u.message.reply_text(f"✅ *Key*\n\n`{d['key']}`\n⏳ {lbl}\n📅 `{exp}`\n📝 {note or '—'}", parse_mode="Markdown")
        except Exception as e: await u.message.reply_text(f"❌ `{e}`")
    async def c_status(u,ctx):
        if not is_admin(u.effective_user.id): return
        if not ctx.args: await u.message.reply_text("Usage: `/status <key>`"); return
        try:
            r = await _p("/status", {"key":ctx.args[0]})
            if r.status_code == 404: await u.message.reply_text("❌ Not found"); return
            d = r.json(); em = {"active":"✅","expired":"⏳","revoked":"🚫","frozen":"❄️"}.get(d["status"],"❓")
            await u.message.reply_text(f"📊 *Status*\n🔑 `{d['key']}`\n{em} `{d['status']}`\n⏱ `{d.get('remaining_fmt','?')}`\n{bar(d.get('remaining_sec',0))}\n📱 `{d.get('device_name') or 'Unbound'}`\n🆔 `{d.get('device_id') or '—'}`\n📅 `{ts(d.get('expires_at'))}`\n🔢 `{d.get('usage_count',0)}`\n📝 `{d.get('note') or '—'}`", parse_mode="Markdown")
        except Exception as e: await u.message.reply_text(f"❌ `{e}`")
    async def c_info(u,ctx):
        if not is_admin(u.effective_user.id): return
        if not ctx.args: await u.message.reply_text("Usage: `/info <key>`"); return
        try:
            r = await _p("/admin/keyinfo", {"key":ctx.args[0]})
            if r.status_code == 404: await u.message.reply_text("❌ Not found"); return
            d = r.json(); em = {"active":"✅","expired":"⏳","revoked":"🚫","frozen":"❄️"}.get(d["status"],"❓")
            await u.message.reply_text(f"🔑 `{d['key']}`\n{em} `{d['status']}`\n⏱ `{d.get('remaining_fmt')}`\n📱 `{d['device_name'] or 'Unbound'}`\n🆔 `{d['device_id'] or '—'}`\n📅 `{ts(d['expires_at'])}`\n🔢 `{d['usage_count']}`\n📝 `{d['note'] or '—'}`", parse_mode="Markdown")
        except Exception as e: await u.message.reply_text(f"❌ `{e}`")
    async def c_revoke(u,ctx):
        if not is_admin(u.effective_user.id): return
        if not ctx.args: await u.message.reply_text("Usage: `/revoke <key>`"); return
        try: await _p("/admin/revoke", {"key":ctx.args[0]}); await u.message.reply_text(f"🚫 Revoked `{ctx.args[0]}`", parse_mode="Markdown")
        except Exception as e: await u.message.reply_text(f"❌ `{e}`")
    async def c_freeze(u,ctx):
        if not is_admin(u.effective_user.id): return
        if not ctx.args: await u.message.reply_text("Usage: `/freeze <key>`"); return
        try:
            r = await _p("/admin/freeze", {"key":ctx.args[0]}); d = r.json()
            e = "❄️" if d["status"]=="frozen" else "✅"
            await u.message.reply_text(f"{e} `{d['status']}` `{ctx.args[0]}`", parse_mode="Markdown")
        except Exception as e: await u.message.reply_text(f"❌ `{e}`")
    async def c_resethwid(u,ctx):
        if not is_admin(u.effective_user.id): return
        if not ctx.args: await u.message.reply_text("Usage: `/resethwid <key>`"); return
        try: await _p("/admin/reset_hwid", {"key":ctx.args[0]}); await u.message.reply_text(f"♻️ HWID reset `{ctx.args[0]}`", parse_mode="Markdown")
        except Exception as e: await u.message.reply_text(f"❌ `{e}`")
    async def c_listkeys(u,ctx):
        if not is_admin(u.effective_user.id): return
        try:
            r = await _g("/admin/listkeys"); keys = r.json()
            if not keys: await u.message.reply_text("No keys"); return
            em = {"active":"✅","expired":"⏳","revoked":"🚫","frozen":"❄️"}; lines = ["📋 *Keys*\n"]
            for k in keys[:50]:
                e = em.get(k["status"],"❓"); ex = datetime.datetime.fromtimestamp(k["expires_at"]).strftime("%d/%m %H:%M")
                lines.append(f"{e} `{k['key']}`\n   ⏱ {k.get('remaining_fmt','?')} | 📅 {ex} | 📱 {k['device_name'] or 'Unbound'}")
            await u.message.reply_text("\n".join(lines)[:4000], parse_mode="Markdown")
        except Exception as e: await u.message.reply_text(f"❌ `{e}`")
    async def c_audit(u,ctx):
        if not is_admin(u.effective_user.id): return
        try:
            r = await _g("/admin/audit?limit=30"); rows = r.json()
            if not rows: await u.message.reply_text("No audit"); return
            lines = ["📜 *Audit*\n"]
            for row in rows:
                t = datetime.datetime.fromtimestamp(row["ts"]).strftime("%d/%m %H:%M")
                lines.append(f"`{t}` {row['action']} | `{row.get('key_ref') or '—'}` | {row.get('meta') or ''}")
            await u.message.reply_text("\n".join(lines)[:4000], parse_mode="Markdown")
        except Exception as e: await u.message.reply_text(f"❌ `{e}`")

    async def start_bot():
        app_ = Application.builder().token(BOT_TOKEN).build()
        for n, f in [("start",c_start),("ping",c_ping),("genkey",c_genkey),("status",c_status),
                     ("info",c_info),("revoke",c_revoke),("freeze",c_freeze),
                     ("resethwid",c_resethwid),("listkeys",c_listkeys),("audit",c_audit)]:
            app_.add_handler(CommandHandler(n, f))
        log.info("[BOT] Polling")
        async with app_:
            await app_.start(); await app_.updater.start_polling(drop_pending_updates=True)
            while not bot_stop.is_set(): await asyncio.sleep(2)

    loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop)
    try: loop.run_until_complete(start_bot())
    except Exception as e: log.error(f"[BOT] {e}")

def _shutdown(s, f):
    _stop.set(); bot_stop.set(); sys.exit(0)
signal.signal(signal.SIGTERM, _shutdown)
signal.signal(signal.SIGINT, _shutdown)

if __name__ == "__main__":
    threading.Thread(target=cleanup, daemon=True).start()
    threading.Thread(target=run_bot, daemon=True).start()
    log.info(f"[APEX] port {PORT} | DB {DB_PATH} | URL {SERVER_URL}")
    log.info(f"[APEX] MASTER_HEX {'OK' if len(MASTER_HEX) == 128 else 'INVALID'}")
    app.run(host="0.0.0.0", port=PORT, debug=False, use_reloader=False)
