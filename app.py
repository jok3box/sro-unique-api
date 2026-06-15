import re
import json
import requests
import threading
import os
import psycopg2

DATABASE_URL = os.environ.get("DATABASE_URL")

def get_db():
    return psycopg2.connect(DATABASE_URL)

from datetime import datetime, timedelta
from collections import defaultdict
from flask import Flask, jsonify, request
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

ADMIN_SECRET = os.environ.get("ADMIN_SECRET")

def get_current_customer():
    token = request.cookies.get("session_token")
    if not token:
        return None
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT c.id, c.username, c.character_limit, c.discord_channel_id, c.expires_at, c.active
        FROM sessions s JOIN customers c ON s.customer_id = c.id
        WHERE s.token = %s AND s.expires_at > NOW()
        """,
        (token,)
    )
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row:
        return None
    return {
        "id": row[0], "username": row[1], "character_limit": row[2],
        "discord_channel_id": row[3], "expires_at": row[4].isoformat(), "active": row[5]
    }


@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    data = request.get_json(force=True)
    username = data.get("username", "")
    password = data.get("password", "")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, password_hash, expires_at, active FROM customers WHERE username = %s", (username,))
    row = cur.fetchone()

    if not row:
        cur.close()
        conn.close()
        return jsonify({"ok": False, "error": "Kullanici adi veya sifre hatali"}), 401

    customer_id, password_hash, expires_at, active = row

    if not check_password_hash(password_hash, password):
        cur.close()
        conn.close()
        return jsonify({"ok": False, "error": "Kullanici adi veya sifre hatali"}), 401

    if not active or expires_at < datetime.utcnow():
        cur.close()
        conn.close()
        return jsonify({"ok": False, "error": "Lisans suresi dolmus veya hesap pasif"}), 403

    token = secrets.token_urlsafe(32)
    session_expires = datetime.utcnow() + timedelta(days=7)
    cur.execute("INSERT INTO sessions (token, customer_id, expires_at) VALUES (%s, %s, %s)", (token, customer_id, session_expires))
    conn.commit()
    cur.close()
    conn.close()

    resp = jsonify({"ok": True})
    resp.set_cookie("session_token", token, httponly=True, secure=True, samesite="Lax", max_age=7 * 24 * 3600)
    return resp


@app.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    token = request.cookies.get("session_token")
    if token:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM sessions WHERE token = %s", (token,))
        conn.commit()
        cur.close()
        conn.close()
    resp = jsonify({"ok": True})
    resp.delete_cookie("session_token")
    return resp


@app.route("/api/auth/me")
def auth_me():
    customer = get_current_customer()
    if not customer:
        return jsonify({"ok": False, "error": "Oturum yok"}), 401
    return jsonify({"ok": True, "customer": customer})


@app.route("/api/admin/create_customer", methods=["POST"])
def create_customer():
    auth = request.headers.get("Authorization", "")
    if not ADMIN_SECRET or auth != f"Bearer {ADMIN_SECRET}":
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    data = request.get_json(force=True)
    username = data.get("username")
    password = data.get("password")
    character_limit = data.get("character_limit", 5)
    days = data.get("days", 30)

    if not username or not password:
        return jsonify({"ok": False, "error": "username ve password gerekli"}), 400

    license_key = secrets.token_hex(8).upper()
    client_secret = secrets.token_urlsafe(32)
    password_hash = generate_password_hash(password)
    expires_at = datetime.utcnow() + timedelta(days=days)

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO customers (license_key, client_secret, username, password_hash, character_limit, expires_at)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (license_key, client_secret, username, password_hash, character_limit, expires_at)
        )
        customer_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({
            "ok": True,
            "customer_id": customer_id,
            "license_key": license_key,
            "client_secret": client_secret,
            "username": username,
            "character_limit": character_limit,
            "expires_at": expires_at.isoformat()
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/db/init")
def db_init():
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS customers (
                id SERIAL PRIMARY KEY,
                license_key VARCHAR(64) UNIQUE NOT NULL,
                client_secret VARCHAR(128) NOT NULL,
                username VARCHAR(64) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                character_limit INTEGER NOT NULL DEFAULT 5,
                discord_channel_id VARCHAR(64),
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT NOW(),
                active BOOLEAN DEFAULT TRUE
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token VARCHAR(128) PRIMARY KEY,
                customer_id INTEGER REFERENCES customers(id) ON DELETE CASCADE,
                created_at TIMESTAMP DEFAULT NOW(),
                expires_at TIMESTAMP NOT NULL
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS commands (
                id SERIAL PRIMARY KEY,
                customer_id INTEGER REFERENCES customers(id) ON DELETE CASCADE,
                command TEXT NOT NULL,
                status VARCHAR(16) DEFAULT 'pending',
                result TEXT,
                created_at TIMESTAMP DEFAULT NOW(),
                completed_at TIMESTAMP
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS status_reports (
                customer_id INTEGER PRIMARY KEY REFERENCES customers(id) ON DELETE CASCADE,
                data JSONB,
                updated_at TIMESTAMP DEFAULT NOW()
            );
        """)
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"ok": True, "message": "Tablolar olusturuldu"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/api/db/debug")
def db_debug():
    keys = [k for k in os.environ.keys() if any(s in k.upper() for s in ["DATABASE", "POSTGRES", "PG"])]
    return jsonify({"matching_keys": keys, "DATABASE_URL_set": DATABASE_URL is not None})

@app.route("/api/db/test")
def db_test():
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT version();")
        version = cur.fetchone()[0]
        cur.close()
        conn.close()
        return jsonify({"ok": True, "version": version})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

SERVERS = {
    "knidos": 16,
    "nemrut": 19,
    "karya": 20,
    "lidya": 21
}

# Gamegami sunucusu Türkiye saatinde (UTC+3) veri veriyor
TR_OFFSET = timedelta(hours=3)

def fetch_gamegami(server_id: int) -> list:
    url = f"https://silkroad.gamegami.com/instantuniques.php?id={server_id}"
    try:
        r = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        html = r.text
        result = []
        rows = re.findall(r"<tr[^>]*>(.*?)</tr>", html, re.DOTALL)
        for row in rows:
            cells = re.findall(r"<td[^>]*>(.*?)</td>", row, re.DOTALL)
            cells = [re.sub(r"<[^>]+>", "", c).replace("&nbsp;", "").strip() for c in cells]
            if len(cells) < 5:
                continue
            name, spawn, kill, killer, region = cells[0], cells[1], cells[2], cells[3], cells[4]
            if not name or not spawn or len(name) > 50:
                continue
            if not re.match(r"\d{2}\.\d{2}\.\d{4}", spawn):
                continue
            result.append({
                "name": name,
                "spawn": spawn,
                "kill": kill,
                "killer": killer,
                "region": region
            })
        return result
    except Exception as e:
        return []

def analyze(records: list) -> list:
    by_unique = defaultdict(list)
    for r in records:
        by_unique[r["name"]].append(r)

    result = []

    for uname, entries in by_unique.items():
        entries_sorted = sorted(entries, key=lambda x: x["spawn"])
        if len(entries_sorted) < 2:
            continue

        intervals = []
        for i in range(1, len(entries_sorted)):
            try:
                # Spawn zamanları TR saatinde geliyor, interval hesabı için fark yeterli
                t1 = datetime.strptime(entries_sorted[i-1]["spawn"], "%d.%m.%Y %H:%M")
                t2 = datetime.strptime(entries_sorted[i]["spawn"], "%d.%m.%Y %H:%M")
                diff = abs((t2 - t1).total_seconds() / 60)
                if 10 < diff < 1440:
                    intervals.append(diff)
            except:
                continue

        if not intervals:
            continue

        avg = sum(intervals) / len(intervals)
        std = (sum((x - avg) ** 2 for x in intervals) / len(intervals)) ** 0.5 if len(intervals) > 1 else avg * 0.1

        try:
            # lastSpawn TR saatinde geliyor → UTC'ye çevir
            last_spawn_tr = datetime.strptime(entries_sorted[-1]["spawn"], "%d.%m.%Y %H:%M")
            last_spawn_utc = last_spawn_tr - TR_OFFSET

            # Hesaplamalar UTC üzerinden yap
            next_spawn_utc = last_spawn_utc + timedelta(minutes=avg)
            early_utc = last_spawn_utc + timedelta(minutes=max(0, avg - std))
            late_utc = last_spawn_utc + timedelta(minutes=avg + std)

            # earlySpawn / lateSpawn → TR saatinde göster (kullanıcı dostu)
            early_tr = early_utc + TR_OFFSET
            late_tr = late_utc + TR_OFFSET

        except:
            continue

        # Bölge istatistikleri - rotasyon ağırlığı
        regions = [e["region"] for e in entries_sorted if e.get("region")]
        region_counts = defaultdict(int)
        for reg in regions:
            region_counts[reg] += 1

        recent = [e["region"] for e in entries_sorted[-5:] if e.get("region")]
        recent_counts = defaultdict(int)
        for reg in recent:
            recent_counts[reg] += 1

        weighted = {}
        for reg in region_counts:
            total_freq = region_counts[reg] / len(regions)
            recency_penalty = 1 / (recent_counts.get(reg, 0) + 1)
            weighted[reg] = total_freq * recency_penalty

        total_w = sum(weighted.values())
        location_stats = sorted(
            [{"zone": r, "pct": int(v / total_w * 100)} for r, v in weighted.items()],
            key=lambda x: x["pct"], reverse=True
        ) if total_w > 0 else []

        last_entry = entries_sorted[-1]

        result.append({
            "name": uname,
            "avgIntervalMinutes": round(avg),
            "lastSpawn": last_entry["spawn"],       # TR saati (orijinal)
            "lastKill": last_entry["kill"],
            "lastKiller": last_entry.get("killer", ""),
            "lastZone": last_entry["region"],
            "nextSpawn": next_spawn_utc.strftime("%Y-%m-%dT%H:%M:%S.000Z"),  # UTC
            "earlySpawn": early_tr.strftime("%H:%M"),   # TR saati
            "lateSpawn": late_tr.strftime("%H:%M"),     # TR saati
            "recordCount": len(entries_sorted),
            "locationStats": location_stats[:3]
        })

    return sorted(result, key=lambda x: x["nextSpawn"])


# Cache
_cache = {}
_cache_time = {}
CACHE_SEC = 120

@app.route("/api/uniques/<server>")
def get_uniques(server):
    server = server.lower()
    if server not in SERVERS:
        return jsonify({"error": "Unknown server"}), 404

    import time
    now = time.time()
    if server in _cache and now - _cache_time.get(server, 0) < CACHE_SEC:
        return jsonify(_cache[server])

    server_id = SERVERS[server]
    records = fetch_gamegami(server_id)
    data = analyze(records)

    response = {
        "server": server,
        "data": data,
        "recordCount": len(records),
        "fetchedAt": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
    }
    _cache[server] = response
    _cache_time[server] = now
    return jsonify(response)

@app.route("/api/uniques")
def get_all_uniques():
    from flask import request
    server = request.args.get("server", "knidos")
    return get_uniques(server)

@app.route("/health")
def health():
    return jsonify({"status": "ok"})

_widget_lock = threading.Lock()
_widget_state = {"server": "knidos"}

@app.route("/api/widget/state")
def widget_state():
    with _widget_lock:
        return jsonify(dict(_widget_state))

@app.route("/api/widget/set/<server>")
def widget_set(server):
    server = server.lower()
    if server not in SERVERS:
        return jsonify({"error": "Unknown server", "valid": list(SERVERS.keys())}), 404
    with _widget_lock:
        _widget_state["server"] = server
    return jsonify({"ok": True, "server": server})

@app.route("/widget")
def widget_page():
    path = os.path.join(os.path.dirname(__file__), "widget.html")
    with open(path, "r", encoding="utf-8") as f:
        html = f.read()
    return html, 200, {"Content-Type": "text/html; charset=utf-8"}

if __name__ == "__main__":
    app.run(debug=True, port=5000)
