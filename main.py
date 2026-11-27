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
# PAYLOAD PATH AUTO-DETECT
# ─────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def find_payload():
    candidates = [
        os.path.join(BASE_DIR, "payloads", "crashfix.lua"),
        os.path.join(BASE_DIR, "crashfix.lua"),
        os.path.join(BASE_DIR, "payloads", "crashfix.LUA"),
    ]
    for p in candidates:
        if os.path.exists(p):
            return p
    return None

PAYLOAD_PATH = find_payload()

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

    l1 = bytearray()
    for i, b in enumerate(data):
        rotated = (b + (i & 0xFF)) & 0xFF
        l1.append(rotated ^ key[i % 32])

    while len(l1) % BLOCK:
        l1.append(0x00)
    n_blocks = len(l1) // BLOCK
    blocks   = [l1[i * BLOCK:(i + 1) * BLOCK] for i in range(n_blocks)]

    l2 = bytearray(n_blocks * BLOCK)
    for b in range(n_blocks):
        for pos in range(BLOCK):
            l2[pos * n_blocks + b] = blocks[b][pos]

    l2p = bytearray(l2)
    while len(l2p) % 32:
        l2p.append(0x00)
    l3_chunks = len(l2p) // 32

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
    return jsonify({
        "status": "online",
        "service": "APEX License Server",
        "dev": "@APEX33Z",
        "payload": "found" if PAYLOAD_PATH else "MISSING"
    })


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

    if not PAYLOAD_PATH:
        return "NO_PAYLOAD", 200

    try:
        with open(PAYLOAD_PATH, "r", encoding="utf-8") as f:
            lua_code = f.read()
    except Exception:
        return "ERROR", 200

    nonce   = gen_nonce()
    encoded = apex_encode(lua_code.encode("utf-8"), token, nonce)
    return f"{nonce}:{encoded}", 200


# ... (baaki admin endpoints same rahenge: /status, /admin/genkey, /admin/keyinfo, /admin/revoke, /admin/freeze, /admin/reset_hwid, /admin/listkeys)
