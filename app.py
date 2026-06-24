path = r"C:\phbot_monitor\api_server\sro-unique-api\app.py"

new_code = '''
# ============================================================
# JBOT LISANS SISTEMI
# ============================================================

@app.route("/api/jbot/create_license", methods=["POST"])
@limiter.limit("20 per minute")
def jbot_create_license():
    """JBOT icin yeni lisans olusturur. product: full/rocpickup/autotarget"""
    if not _check_admin_auth():
        return jsonify({"ok": False, "error": "Yetkisiz"}), 401

    data = request.get_json(force=True)
    product = (data.get("product") or "full").strip().lower()
    days = data.get("days", 30)
    note = (data.get("note") or "").strip()

    valid_products = ["full", "rocpickup", "autotarget", "rocpickup_autotarget"]
    if product not in valid_products:
        return jsonify({"ok": False, "error": f"Gecersiz product. Gecerli degerler: {valid_products}"}), 400

    license_key = "JBOT-" + "-".join([secrets.token_hex(4).upper() for _ in range(3)])
    expires_at = datetime.utcnow() + timedelta(days=days)

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO jbot_licenses (license_key, product, expires_at, note)
            VALUES (%s, %s, %s, %s)
            RETURNING id
        """, (license_key, product, expires_at, note))
        license_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({
            "ok": True,
            "id": license_id,
            "license_key": license_key,
            "product": product,
            "expires_at": expires_at.isoformat(),
            "note": note
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/jbot/verify", methods=["POST"])
@limiter.limit("60 per minute")
def jbot_verify():
    """JBOT acilisinda key + HWID dogrulama. Ilk kullanim: HWID kaydedilir.
    Sonraki kullanimlar: HWID eslesmeli."""
    data = request.get_json(force=True)
    license_key = (data.get("license_key") or "").strip()
    hwid = (data.get("hwid") or "").strip()
    product = (data.get("product") or "full").strip().lower()

    if not license_key or not hwid:
        return jsonify({"ok": False, "error": "license_key ve hwid gerekli"}), 400

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            SELECT id, product, expires_at, active, hwid
            FROM jbot_licenses WHERE license_key = %s
        """, (license_key,))
        row = cur.fetchone()

        if not row:
            cur.close()
            conn.close()
            return jsonify({"ok": False, "error": "Gecersiz lisans anahtari"}), 404

        lic_id, lic_product, expires_at, active, stored_hwid = row

        if not active:
            cur.close()
            conn.close()
            return jsonify({"ok": False, "error": "Lisans aktif degil"}), 403

        if expires_at < datetime.utcnow():
            cur.close()
            conn.close()
            return jsonify({"ok": False, "error": "Lisans suresi dolmus"}), 403

        # Urun kontrolu: full her seyi kapsiar, diger urunler sadece kendini
        allowed = (
            lic_product == "full" or
            lic_product == product or
            (lic_product == "rocpickup_autotarget" and product in ["rocpickup", "autotarget"])
        )
        if not allowed:
            cur.close()
            conn.close()
            return jsonify({"ok": False, "error": f"Bu lisans '{product}' urununu kapsamiyor"}), 403

        # HWID kontrolu
        if not stored_hwid:
            # Ilk aktivasyon - HWID kaydet
            cur.execute("UPDATE jbot_licenses SET hwid = %s WHERE id = %s", (hwid, lic_id))
            conn.commit()
        elif stored_hwid != hwid:
            cur.close()
            conn.close()
            return jsonify({"ok": False, "error": "Bu lisans baska bir bilgisayarda kayitli. Destek ile iletisime gecin."}), 409

        cur.close()
        conn.close()
        return jsonify({
            "ok": True,
            "product": lic_product,
            "expires_at": expires_at.isoformat()
        })

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/admin/jbot/list_licenses")
@limiter.limit("20 per minute")
def jbot_list_licenses():
    """Tum JBOT lisanslarini listeler - admin only."""
    if not _check_admin_auth():
        return jsonify({"ok": False, "error": "Yetkisiz"}), 401
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT id, license_key, product, hwid, expires_at, active, note, created_at FROM jbot_licenses ORDER BY id DESC")
        rows = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify({"ok": True, "licenses": [
            {"id": r[0], "license_key": r[1], "product": r[2],
             "hwid_set": bool(r[3]), "expires_at": r[4].isoformat(),
             "active": r[5], "note": r[6], "created_at": r[7].isoformat()}
            for r in rows
        ]})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/admin/jbot/reset_hwid", methods=["POST"])
@limiter.limit("20 per minute")
def jbot_reset_hwid():
    """JBOT lisansinin HWID kilidini sifirlar."""
    if not _check_admin_auth():
        return jsonify({"ok": False, "error": "Yetkisiz"}), 401
    data = request.get_json(force=True)
    license_id = data.get("license_id")
    if not license_id:
        return jsonify({"ok": False, "error": "license_id gerekli"}), 400
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("UPDATE jbot_licenses SET hwid = NULL WHERE id = %s", (license_id,))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"ok": True, "message": "HWID sifirlandi"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/admin/jbot/toggle_license", methods=["POST"])
@limiter.limit("20 per minute")
def jbot_toggle_license():
    """JBOT lisansini aktif/pasif yapar."""
    if not _check_admin_auth():
        return jsonify({"ok": False, "error": "Yetkisiz"}), 401
    data = request.get_json(force=True)
    license_id = data.get("license_id")
    active = data.get("active")
    if license_id is None or active is None:
        return jsonify({"ok": False, "error": "license_id ve active gerekli"}), 400
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("UPDATE jbot_licenses SET active = %s WHERE id = %s", (bool(active), license_id))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
'''

# app.py sonuna ekle (if __name__ satirindan once)
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

insert_before = '
@app.route("/api/db/init_jbot")
def db_init_jbot():
    if not _check_admin_auth():
        return jsonify({"ok": False, "error": "Yetkisiz"}), 401
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS jbot_licenses (
                id SERIAL PRIMARY KEY,
                license_key VARCHAR(64) UNIQUE NOT NULL,
                product VARCHAR(32) NOT NULL DEFAULT 'full',
                hwid VARCHAR(128),
                expires_at TIMESTAMP NOT NULL,
                active BOOLEAN DEFAULT TRUE,
                note TEXT,
                created_at TIMESTAMP DEFAULT NOW()
            );
        """)
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"ok": True, "message": "jbot_licenses tablosu olusturuldu"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

if __name__ == "__main__":'
if insert_before in content:
    if "/api/jbot/verify" in content:
        print("ZATEN EKLENMIS")
    else:
        content = content.replace(insert_before, new_code + "\n" + insert_before)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        print("OK - JBOT endpointleri eklendi")
else:
    print("HATA: insert noktasi bulunamadi")