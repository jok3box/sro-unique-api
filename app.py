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
from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

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
