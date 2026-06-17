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
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# CORS'u sadece bilinen, guvenilir origin'lerle sinirliyoruz. Parametresiz
# CORS(app) TUM siteler icin acik kapi anlamina gelir (CSRF riski), bu
# yuzden acikca izin verilen adresleri listeliyoruz. Yeni bir domain
# eklenince (orn. www.jok3box.com canliya alindiginda) buraya eklenmeli.
ALLOWED_ORIGINS = [
    "https://sro-unique-api-production.up.railway.app",
    "https://jok3box.com",
    "https://www.jok3box.com",
]
CORS(app, origins=ALLOWED_ORIGINS, supports_credentials=True)

# Brute-force/asiri istek korumasi. Bellek-ici depolama kullaniyoruz (tek
# Railway instance'i icin yeterli); olcek buyurse Redis'e gecilebilir.
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per minute"],
    storage_uri="memory://",
)

ADMIN_SECRET = os.environ.get("ADMIN_SECRET")

# Discord musteri kanal otomasyonu - musteri lisans aktive ettiginde
# kendisine ozel, sadece kendisinin (ve kategori seviyesinde zaten
# yetkili rollerin) gorebilecegi bir Discord kanali otomatik acilir.
# Lisans suresi dolunca (asagidaki arka plan temizlik dongusu ile)
# kanal tamamen silinir.
DISCORD_BOT_TOKEN = os.environ.get("DISCORD_BOT_TOKEN")
DISCORD_GUILD_ID = os.environ.get("DISCORD_GUILD_ID")
DISCORD_CUSTOMER_CATEGORY_ID = os.environ.get("DISCORD_CUSTOMER_CATEGORY_ID")

DISCORD_API_BASE = "https://discord.com/api/v10"
_PERM_VIEW_CHANNEL = 1 << 10
_PERM_SEND_MESSAGES = 1 << 11
_PERM_READ_MESSAGE_HISTORY = 1 << 16
_CUSTOMER_ALLOW_PERMS = str(_PERM_VIEW_CHANNEL | _PERM_SEND_MESSAGES | _PERM_READ_MESSAGE_HISTORY)


def _sanitize_discord_channel_name(username: str) -> str:
    """Discord kanal adi kurallarina uygun hale getirir (kucuk harf, sadece
    harf/sayi/tire, bosluklar tireye donusur, 90 karakterle sinirlanir)."""
    name = f"musteri-{username}".lower()
    name = re.sub(r"[^a-z0-9\-]", "-", name)
    name = re.sub(r"-+", "-", name).strip("-")
    return name[:90] or "musteri"


def discord_create_customer_channel(username: str, discord_user_id: str):
    """Musteri icin Discord'da OZEL bir kanal olusturur. Kategori zaten
    sadece belirli rollerin gorebilecegi sekilde ayarlanmis - burada
    AYRICA @everyone'a acikca kanal-seviyesinde GORME izni reddedilir,
    ve sadece bu musterinin discord_user_id'sine ozel gorme/yazma izni
    verilir. Kategoriye erisimi olan diger roller (orn. admin) varsayilan
    davranisla (override edilmedigi icin) erisimini korur. Basarili
    olursa yeni kanalin ID'sini (str) doner, basarisiz olursa None doner."""
    if not (DISCORD_BOT_TOKEN and DISCORD_GUILD_ID):
        print("UYARI: DISCORD_BOT_TOKEN veya DISCORD_GUILD_ID tanimli degil, kanal olusturulamadi.")
        return None

    channel_name = _sanitize_discord_channel_name(username)
    payload = {
        "name": channel_name,
        "type": 0,
        "permission_overwrites": [
            {"id": DISCORD_GUILD_ID, "type": 0, "deny": str(_PERM_VIEW_CHANNEL)},
            {"id": str(discord_user_id), "type": 1, "allow": _CUSTOMER_ALLOW_PERMS},
        ],
    }
    if DISCORD_CUSTOMER_CATEGORY_ID:
        payload["parent_id"] = DISCORD_CUSTOMER_CATEGORY_ID

    headers = {
        "Authorization": f"Bot {DISCORD_BOT_TOKEN}",
        "Content-Type": "application/json",
    }
    try:
        resp = requests.post(
            f"{DISCORD_API_BASE}/guilds/{DISCORD_GUILD_ID}/channels",
            headers=headers, json=payload, timeout=10,
        )
        if resp.status_code in (200, 201):
            return str(resp.json()["id"])
        print(f"Discord kanal olusturma hatasi: {resp.status_code} {resp.text}")
        return None
    except Exception as e:
        print(f"Discord kanal olusturma istisnasi: {e}")
        return None


def discord_delete_channel(channel_id: str) -> bool:
    """Bir Discord kanalini tamamen siler. Kanal zaten silinmisse (404)
    bunu basarili sayar (idempotent)."""
    if not DISCORD_BOT_TOKEN or not channel_id:
        return False
    headers = {"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}
    try:
        resp = requests.delete(f"{DISCORD_API_BASE}/channels/{channel_id}", headers=headers, timeout=10)
        return resp.status_code in (200, 204, 404)
    except Exception as e:
        print(f"Discord kanal silme istisnasi: {e}")
        return False


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
@limiter.limit("10 per minute")
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


def get_customer_by_secret():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    secret = auth[len("Bearer "):]
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, character_limit FROM customers WHERE client_secret = %s AND active = TRUE", (secret,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row:
        return None
    return {"id": row[0], "character_limit": row[1]}


@app.route("/api/commands", methods=["POST"])
def submit_command():
    customer = get_current_customer()
    if not customer:
        return jsonify({"ok": False, "error": "Oturum yok"}), 401
    data = request.get_json(force=True)
    command = (data.get("command") or "").strip()
    if not command:
        return jsonify({"ok": False, "error": "Komut bos olamaz"}), 400
    conn = get_db()
    cur = conn.cursor()
    cur.execute("INSERT INTO commands (customer_id, command) VALUES (%s, %s) RETURNING id", (customer["id"], command))
    cmd_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"ok": True, "command_id": cmd_id})


@app.route("/api/commands/poll")
def poll_commands():
    customer = get_customer_by_secret()
    if not customer:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, command FROM commands WHERE customer_id = %s AND status = 'pending' ORDER BY id", (customer["id"],))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify({"ok": True, "commands": [{"id": r[0], "command": r[1]} for r in rows]})


@app.route("/api/commands/<int:cmd_id>/result", methods=["POST"])
def post_command_result(cmd_id):
    customer = get_customer_by_secret()
    if not customer:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    data = request.get_json(force=True)
    result = data.get("result", "")
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "UPDATE commands SET status='done', result=%s, completed_at=NOW() WHERE id=%s AND customer_id=%s",
        (result, cmd_id, customer["id"])
    )
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/commands/history")
def commands_history():
    customer = get_current_customer()
    if not customer:
        return jsonify({"ok": False, "error": "Oturum yok"}), 401
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, command, status, result, created_at, completed_at FROM commands WHERE customer_id=%s ORDER BY id DESC LIMIT 20",
        (customer["id"],)
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return jsonify({"ok": True, "commands": [
        {"id": r[0], "command": r[1], "status": r[2], "result": r[3],
         "created_at": r[4].isoformat(), "completed_at": r[5].isoformat() if r[5] else None}
        for r in rows
    ]})


@app.route("/api/status", methods=["POST"])
def post_status():
    customer = get_customer_by_secret()
    if not customer:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    data = request.get_json(force=True)

    # Lisans kisitlamasi: musteri kendi character_limit'inin uzerinde
    # karakter bildiremez. Bu, character_limit alaninin sadece veritabaninda
    # durmasini degil, gercekten uygulanan bir is kurali olmasini saglar.
    characters = data.get("characters")
    if isinstance(characters, list) and len(characters) > customer["character_limit"]:
        return jsonify({
            "ok": False,
            "error": f"Karakter limiti asildi: {len(characters)} karakter gonderildi, limit {customer['character_limit']}."
        }), 403

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO status_reports (customer_id, data, updated_at) VALUES (%s, %s::jsonb, NOW())
        ON CONFLICT (customer_id) DO UPDATE SET data = EXCLUDED.data, updated_at = NOW()
        """,
        (customer["id"], json.dumps(data))
    )
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/status")
def get_status():
    customer = get_current_customer()
    if not customer:
        return jsonify({"ok": False, "error": "Oturum yok"}), 401
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT data, updated_at FROM status_reports WHERE customer_id = %s", (customer["id"],))
    row = cur.fetchone()
    cur.close()
    conn.close()
    if not row:
        return jsonify({"ok": True, "data": None, "updated_at": None})
    return jsonify({"ok": True, "data": row[0], "updated_at": row[1].isoformat()})


@app.route("/api/notifications", methods=["POST"])
@limiter.limit("120 per minute")
def post_notification():
    """Discord bot'un gonderdigi otomatik bildirimleri (olum, drop, takilma,
    periyodik ozet) 'Son Komutlar' panelinde komutlarla AYNI kronolojik
    listede gostermek icin commands tablosuna tamamlanmis ('done') bir
    kayit olarak ekler."""
    customer = get_customer_by_secret()
    if not customer:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    data = request.get_json(force=True)
    label = (data.get("label") or "🔔 Bildirim").strip()
    text = (data.get("text") or "").strip()
    if not text:
        return jsonify({"ok": False, "error": "text gerekli"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO commands (customer_id, command, status, result, completed_at)
        VALUES (%s, %s, 'done', %s, NOW())
        """,
        (customer["id"], label, text)
    )
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"ok": True})


@app.route("/api/admin/create_customer", methods=["POST"])
@limiter.limit("20 per minute")
def create_customer():
    if not _check_admin_auth():
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


@app.route("/api/license/activate", methods=["POST"])
@limiter.limit("10 per minute")
def activate_license():
    """Musteri kurulum sihirbazindan lisans anahtarini gonderir. Discord
    kullanici ID'si İSTEĞE BAĞLIDIR - musteri Discord kullanmak istemiyorsa
    discord_user_id hic gonderilmez, kanal hic olusturulmaz, musteri sadece
    dashboard'u kullanir. Lisans gecerliyse (aktif + suresi dolmamis)
    client_secret + character_limit doner; discord_user_id VERILIRSE kanal
    henuz yoksa otomatik olusturur (varsa idempotent sekilde ayni kanali
    tekrar kullanir)."""
    data = request.get_json(force=True)
    license_key = (data.get("license_key") or "").strip()
    discord_user_id = (data.get("discord_user_id") or "").strip() or None

    if not license_key:
        return jsonify({"ok": False, "error": "license_key gerekli"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, username, client_secret, character_limit, discord_channel_id,
               discord_user_id, expires_at, active
        FROM customers WHERE license_key = %s
        """,
        (license_key,)
    )
    row = cur.fetchone()
    if not row:
        cur.close()
        conn.close()
        return jsonify({"ok": False, "error": "Lisans anahtari bulunamadi"}), 404

    (customer_id, username, client_secret, character_limit,
     discord_channel_id, stored_discord_user_id, expires_at, active) = row

    if not active:
        cur.close()
        conn.close()
        return jsonify({"ok": False, "error": "Lisans aktif degil"}), 403
    if expires_at < datetime.utcnow():
        cur.close()
        conn.close()
        return jsonify({"ok": False, "error": "Lisansin suresi dolmus"}), 403

    if discord_user_id:
        if not discord_channel_id:
            new_channel_id = discord_create_customer_channel(username, discord_user_id)
            if not new_channel_id:
                cur.close()
                conn.close()
                return jsonify({"ok": False, "error": "Discord kanali olusturulamadi, lutfen daha sonra tekrar deneyin"}), 502
            cur.execute(
                "UPDATE customers SET discord_channel_id = %s, discord_user_id = %s WHERE id = %s",
                (new_channel_id, discord_user_id, customer_id)
            )
            conn.commit()
            discord_channel_id = new_channel_id
        elif stored_discord_user_id != discord_user_id:
            cur.close()
            conn.close()
            return jsonify({"ok": False, "error": "Bu lisans farkli bir Discord hesabiyla aktive edilmis. Yardim icin destek ile iletisime gecin."}), 409

    cur.close()
    conn.close()
    return jsonify({
        "ok": True,
        "client_secret": client_secret,
        "character_limit": character_limit,
        "discord_channel_id": discord_channel_id,
        "expires_at": expires_at.isoformat(),
    })


def _check_admin_auth():
    """Admin-only uclar icin ortak yetkilendirme kontrolu.
    ADMIN_SECRET ortam degiskeni tanimli olmali ve dogru Bearer token gelmeli."""
    auth = request.headers.get("Authorization", "")
    return bool(ADMIN_SECRET) and auth == f"Bearer {ADMIN_SECRET}"


@app.route("/api/admin/update_customer", methods=["POST"])
@limiter.limit("20 per minute")
def update_customer():
    """Musterinin sifresini degistirir ve/veya aktif/pasif durumunu gunceller.
    Guvenlik: herhangi bir degisiklik sonrasi musterinin TUM mevcut session'lari
    iptal edilir - bu sayede sifre degisikliginde veya hesap askiya alindiginda
    eski/calinmis token'lar artik gecersiz olur."""
    if not _check_admin_auth():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    data = request.get_json(force=True)
    customer_id = data.get("customer_id")
    new_password = data.get("password")
    new_active = data.get("active")
    new_days = data.get("extend_days")

    if not customer_id:
        return jsonify({"ok": False, "error": "customer_id gerekli"}), 400
    if new_password is None and new_active is None and new_days is None:
        return jsonify({"ok": False, "error": "password, active veya extend_days alanlarindan en az biri gerekli"}), 400

    try:
        conn = get_db()
        cur = conn.cursor()

        if new_password is not None:
            cur.execute(
                "UPDATE customers SET password_hash=%s WHERE id=%s",
                (generate_password_hash(new_password), customer_id)
            )
        if new_active is not None:
            cur.execute(
                "UPDATE customers SET active=%s WHERE id=%s",
                (bool(new_active), customer_id)
            )
        if new_days is not None:
            cur.execute(
                "UPDATE customers SET expires_at = expires_at + (%s || ' days')::interval WHERE id=%s",
                (new_days, customer_id)
            )

        # Guvenlik: sifre veya aktiflik durumu degistiyse tum eski session'lari
        # gecersiz kil - calinmis bir token'in artik ise yaramamasini saglar.
        if new_password is not None or new_active is not None:
            cur.execute("DELETE FROM sessions WHERE customer_id=%s", (customer_id,))

        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"ok": True, "message": "Musteri guncellendi, eski oturumlar iptal edildi."})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/admin/run_cleanup_now", methods=["POST"])
@limiter.limit("10 per minute")
def run_cleanup_now():
    """Suresi dolmus/pasif musterilerin Discord kanallarini silme islemini
    15 dakika beklemeden ANINDA, senkron olarak calistirir - admin only.
    Test/teshis amacli."""
    if not _check_admin_auth():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    if not DISCORD_BOT_TOKEN:
        return jsonify({"ok": False, "error": "DISCORD_BOT_TOKEN tanimli degil"}), 500
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, discord_channel_id FROM customers
            WHERE discord_channel_id IS NOT NULL
              AND (expires_at < NOW() OR active = FALSE)
            """
        )
        rows = cur.fetchall()
        results = []
        for customer_id, channel_id in rows:
            deleted = discord_delete_channel(channel_id)
            results.append({"customer_id": customer_id, "channel_id": channel_id, "deleted": deleted})
            if deleted:
                cur.execute(
                    "UPDATE customers SET discord_channel_id = NULL WHERE id = %s",
                    (customer_id,)
                )
                conn.commit()
        cur.close()
        conn.close()
        return jsonify({"ok": True, "matched": len(rows), "results": results})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/admin/get_client_secret", methods=["POST"])
@limiter.limit("20 per minute")
def get_client_secret():
    """Bir musterinin client_secret'ini dondurur - admin only. Hesap kurulumu
    kaybedildiginde (orn. config dosyasi bozuldugunda) tekrar erisim icin."""
    if not _check_admin_auth():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    data = request.get_json(force=True)
    customer_id = data.get("customer_id")
    if not customer_id:
        return jsonify({"ok": False, "error": "customer_id gerekli"}), 400
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT username, client_secret FROM customers WHERE id=%s", (customer_id,))
        row = cur.fetchone()
        cur.close()
        conn.close()
        if not row:
            return jsonify({"ok": False, "error": "Musteri bulunamadi"}), 404
        return jsonify({"ok": True, "username": row[0], "client_secret": row[1]})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/admin/list_customers")
def list_customers():
    """Tum musterilerin temel bilgilerini (sifre haric) listeler - admin only."""
    if not _check_admin_auth():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT id, username, character_limit, expires_at, active FROM customers ORDER BY id")
        rows = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify({"ok": True, "customers": [
            {"id": r[0], "username": r[1], "character_limit": r[2],
             "expires_at": r[3].isoformat(), "active": r[4]}
            for r in rows
        ]})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/db/init")
def db_init():
    if not _check_admin_auth():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
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
            ALTER TABLE customers
            ADD COLUMN IF NOT EXISTS discord_user_id VARCHAR(32);
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
    if not _check_admin_auth():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    keys = [k for k in os.environ.keys() if any(s in k.upper() for s in ["DATABASE", "POSTGRES", "PG"])]
    return jsonify({"matching_keys": keys, "DATABASE_URL_set": DATABASE_URL is not None})

@app.route("/api/db/test")
def db_test():
    if not _check_admin_auth():
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
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

# Oyunun zamanlanmis etkinlik unique'leri - rastgele spawn etmedikleri icin
# Unique Radar tahmin listesine dahil edilmiyorlar.
EVENT_UNIQUES = {
    "beakyung the white viper",
}

def analyze(records: list) -> list:
    by_unique = defaultdict(list)
    for r in records:
        if r["name"].strip().lower() in EVENT_UNIQUES:
            continue
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

@app.route("/assets/<path:filename>")
def serve_asset(filename):
    from flask import send_from_directory
    assets_dir = os.path.join(os.path.dirname(__file__), "assets")
    return send_from_directory(assets_dir, filename)

@app.route("/dashboard")
def dashboard_page():
    path = os.path.join(os.path.dirname(__file__), "dashboard.html")
    with open(path, "r", encoding="utf-8") as f:
        html = f.read()
    return html, 200, {"Content-Type": "text/html; charset=utf-8"}

@app.route("/widget")
def widget_page():
    path = os.path.join(os.path.dirname(__file__), "widget.html")
    with open(path, "r", encoding="utf-8") as f:
        html = f.read()
    return html, 200, {"Content-Type": "text/html; charset=utf-8"}

def _expired_channel_cleanup_loop():
    """15 dakikada bir suresi dolmus veya pasif hale getirilmis musterilerin
    Discord kanallarini tarar ve tamamen siler (kullanicinin tercihi: kanal
    history'siyle birlikte tamamen kaldirilsin). Idempotent."""
    import time as _time
    while True:
        try:
            if DISCORD_BOT_TOKEN:
                conn = get_db()
                cur = conn.cursor()
                cur.execute(
                    """
                    SELECT id, discord_channel_id FROM customers
                    WHERE discord_channel_id IS NOT NULL
                      AND (expires_at < NOW() OR active = FALSE)
                    """
                )
                rows = cur.fetchall()
                for customer_id, channel_id in rows:
                    if discord_delete_channel(channel_id):
                        cur.execute(
                            "UPDATE customers SET discord_channel_id = NULL WHERE id = %s",
                            (customer_id,)
                        )
                        conn.commit()
                        print(f"Suresi dolan musteri (id={customer_id}) Discord kanali silindi.")
                cur.close()
                conn.close()
        except Exception as e:
            print(f"Kanal temizlik dongusu hatasi: {e}")
        _time.sleep(900)


_cleanup_thread_started = False


def _start_cleanup_thread():
    global _cleanup_thread_started
    if _cleanup_thread_started:
        return
    _cleanup_thread_started = True
    threading.Thread(target=_expired_channel_cleanup_loop, daemon=True).start()


_start_cleanup_thread()


if __name__ == "__main__":
    app.run(debug=True, port=5000)
