# app.py
from flask import Flask, request, jsonify
import sqlite3, os, time, string, random, hashlib, struct
from config import (DB_PATH, SESSION_TTL, ADMIN_TOKEN,
                    BUILD_SIG_KEY, EXPECTED_INTEGRITY)

app = Flask(__name__)

# ─────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
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

# ─────────────────────────────────────────────
# APEX CIPHER v1
# Proprietary encoding — all secrets server-side.
# Decode key derived from session_token + nonce,
# both one-time and server-issued. Never static in client.
# ─────────────────────────────────────────────

def apex_derive_key(session_token: str, nonce: str) -> list:
    """
    32-byte rolling key derivation.
    key[i] = (session_token[i%sl] XOR nonce[i%nl] XOR (i*7 & 0xFF)) & 0xFF
    Matches apex_derive_key() in apex_client.lua exactly.
    """
    sl  = len(session_token)
    nl  = len(nonce)
    key = []
    for i in range(32):
        sb = ord(session_token[i % sl])
        nb = ord(nonce[i % nl])
        key.append((sb ^ nb ^ ((i * 7) & 0xFF)) & 0xFF)
    return key


def apex_encode(data: bytes, session_token: str, nonce: str) -> str:
    """
    APEX Cipher v1 — 3-layer proprietary encode.

    Layer 1: Byte rotation + rolling key XOR
        encoded[i] = ((data[i] + (i & 0xFF)) & 0xFF) XOR key[i % 32]

    Layer 2: 16-byte block interleave
        Split l1 into 16-byte blocks.
        l2[pos * n_blocks + b] = block[b][pos]

    Layer 3: Checksum injection every 32 bytes
        Append 1-byte (sum of chunk) & 0xFF after each 32-byte group.

    Header (12 bytes, big-endian):
        orig_len  : uint32 — original payload byte length
        n_blocks  : uint16 — number of 16-byte blocks
        BLOCK     : uint16 — block size (16)
        l3_chunks : uint32 — number of 33-byte groups in l3

    Wire format: header_hex + l3_hex
    """
    BLOCK    = 16
    key      = apex_derive_key(session_token, nonce)
    orig_len = len(data)

    # Layer 1
    l1 = bytearray()
    for i, b in enumerate(data):
        rotated = (b + (i & 0xFF)) & 0xFF
        l1.append(rotated ^ key[i % 32])

    # Pad to multiple of BLOCK
    while len(l1) % BLOCK:
        l1.append(0x00)
    n_blocks = len(l1) // BLOCK
    blocks   = [l1[i * BLOCK:(i + 1) * BLOCK] for i in range(n_blocks)]

    # Layer 2: interleave
    # l2[pos * n_blocks + b] = blocks[b][pos]
    l2 = bytearray(n_blocks * BLOCK)
    for b in range(n_blocks):
        for pos in range(BLOCK):
            l2[pos * n_blocks + b] = blocks[b][pos]

    # Pad l2 to multiple of 32 for clean checksum groups
    l2p = bytearray(l2)
    while len(l2p) % 32:
        l2p.append(0x00)
    l3_chunks = len(l2p) // 32

    # Layer 3: checksum injection
    l3 = bytearray()
    for i in range(l3_chunks):
        chunk = l2p[i * 32:(i + 1) * 32]
        csum  = sum(chunk) & 0xFF
        l3.extend(chunk)
        l3.append(csum)

    # Header: I H H I = 4+2+2+4 = 12 bytes
    header = struct.pack(">IHHI", orig_len, n_blocks, BLOCK, l3_chunks)
    return (bytes(header) + bytes(l3)).hex()


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def gen_session_token() -> str:
    raw = f"{time.time()}{random.random()}{os.urandom(16).hex()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]

def gen_nonce() -> str:
    return os.urandom(8).hex()   # 16 hex chars, [0-9a-f] only

def compute_expected_sig(device_id: str) -> str:
    key_b  = BUILD_SIG_KEY.encode()
    result = []
    for i, ch in enumerate(device_id.encode("utf-8")):
        result.append(f"{ch ^ key_b[i % len(key_b)]:02x}")
    return "".join(result)

def admin_ok() -> bool:
    return request.headers.get("X-Admin-Token") == ADMIN_TOKEN

def fmt_remaining(secs: int) -> str:
    if secs <= 0:
        return "EXPIRED"
    d = secs // 86400
    h = (secs % 86400) // 3600
    m = (secs % 3600) // 60
    s = secs % 60
    parts = []
    if d: parts.append(f"{d}d")
    if h: parts.append(f"{h}h")
    if m: parts.append(f"{m}m")
    if s or not parts: parts.append(f"{s}s")
    return " ".join(parts)

# ─────────────────────────────────────────────
# PUBLIC ROUTES
# ─────────────────────────────────────────────

@app.route("/ping", methods=["GET"])
def ping():
    return jsonify({"status": "online", "service": "APEX License Server",
                    "dev": "@APEX33Z"})


@app.route("/validate", methods=["POST"])
def validate():
    key         = (request.form.get("key",         "") or "").strip()
    device_id   = (request.form.get("device_id",   "") or "").strip()
    device_name = (request.form.get("device_name", "Unknown") or "Unknown").strip()
    client_sig  = (request.form.get("sig",         "") or "").strip()
    integrity   = (request.form.get("integrity",   "") or "").strip()

    if not key or not device_id:
        return "INVALID", 200

    # Anti-tamper 1: script integrity fingerprint
    if integrity != EXPECTED_INTEGRITY:
        return "CRACKED", 200

    # Anti-tamper 2: client build signature
    if client_sig != compute_expected_sig(device_id):
        return "CRACKED", 200

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

    # HWID bind / verify
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

    # Sig check on payload request too
    if client_sig != compute_expected_sig(device_id):
        return "CRACKED", 200

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

    # Burn session — one-time use
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
    # Wire format: nonce_16hex:encoded_hex
    return f"{nonce}:{encoded}", 200


@app.route("/status", methods=["POST"])
def key_status():
    if not admin_ok():
        return jsonify({"error": "unauthorized"}), 403
    key  = (request.form.get("key", "") or "").strip()
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

# ─────────────────────────────────────────────
# ADMIN ROUTES
# ─────────────────────────────────────────────

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
    key  = request.form.get("key", "")
    conn = get_db()
    c    = conn.cursor()
    c.execute("SELECT * FROM keys WHERE key=?", (key,))
    row  = c.fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "not found"}), 404
    d = dict(row)
    rem = max(0, int(d["expires_at"]) - int(time.time()))
    d["remaining_fmt"] = fmt_remaining(rem)
    d["remaining_sec"] = rem
    return jsonify(d), 200


@app.route("/admin/revoke", methods=["POST"])
def admin_revoke():
    if not admin_ok():
        return jsonify({"error": "unauthorized"}), 403
    key  = request.form.get("key", "")
    conn = get_db()
    conn.cursor().execute("UPDATE keys SET status='revoked' WHERE key=?", (key,))
    conn.commit(); conn.close()
    return jsonify({"status": "revoked", "key": key}), 200


@app.route("/admin/freeze", methods=["POST"])
def admin_freeze():
    if not admin_ok():
        return jsonify({"error": "unauthorized"}), 403
    key  = request.form.get("key", "")
    conn = get_db()
    c    = conn.cursor()
    c.execute("SELECT status FROM keys WHERE key=?", (key,))
    row  = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "not found"}), 404
    ns = "active" if row["status"] == "frozen" else "frozen"
    c.execute("UPDATE keys SET status=? WHERE key=?", (ns, key))
    conn.commit(); conn.close()
    return jsonify({"status": ns, "key": key}), 200


@app.route("/admin/reset_hwid", methods=["POST"])
def admin_reset_hwid():
    if not admin_ok():
        return jsonify({"error": "unauthorized"}), 403
    key  = request.form.get("key", "")
    conn = get_db()
    conn.cursor().execute(
        "UPDATE keys SET device_id=NULL, device_name=NULL WHERE key=?", (key,)
    )
    conn.commit(); conn.close()
    return jsonify({"status": "hwid_reset", "key": key}), 200


@app.route("/admin/listkeys", methods=["GET"])
def admin_listkeys():
    if not admin_ok():
        return jsonify({"error": "unauthorized"}), 403
    conn = get_db()
    c    = conn.cursor()
    c.execute("SELECT * FROM keys ORDER BY created_at DESC LIMIT 100")
    now  = int(time.time())
    rows = []
    for r in c.fetchall():
        d = dict(r)
        rem = max(0, int(d["expires_at"]) - now)
        d["remaining_fmt"] = fmt_remaining(rem)
        d["remaining_sec"] = rem
        rows.append(d)
    conn.close()
    return jsonify(rows), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)