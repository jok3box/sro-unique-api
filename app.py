
import re
import json
import requests
from datetime import datetime, timedelta
from collections import defaultdict
from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

SERVERS = {
    "knidos": 16,
    "nemrut": 19,
    "karya": 20,
    "lidya": 21
}

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
    now = datetime.utcnow()

    for uname, entries in by_unique.items():
        entries_sorted = sorted(entries, key=lambda x: x["spawn"])
        if len(entries_sorted) < 2:
            continue

        intervals = []
        for i in range(1, len(entries_sorted)):
            try:
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
        std = (sum((x-avg)**2 for x in intervals)/len(intervals))**0.5 if len(intervals) > 1 else avg*0.1

        try:
            last_spawn = datetime.strptime(entries_sorted[-1]["spawn"], "%d.%m.%Y %H:%M")
            next_spawn = last_spawn + timedelta(minutes=avg)
            early = last_spawn + timedelta(minutes=max(0, avg-std))
            late = last_spawn + timedelta(minutes=avg+std)
        except:
            continue

        # Bolge istatistikleri - rotasyon agirligi
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
            [{"zone": r, "pct": int(v/total_w*100)} for r, v in weighted.items()],
            key=lambda x: x["pct"], reverse=True
        ) if total_w > 0 else []

        last_entry = entries_sorted[-1]

        result.append({
            "name": uname,
            "avgIntervalMinutes": round(avg),
            "lastSpawn": last_entry["spawn"],
            "lastKill": last_entry["kill"],
            "lastKiller": last_entry.get("killer", ""),
            "lastZone": last_entry["region"],
            "nextSpawn": next_spawn.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "earlySpawn": early.strftime("%H:%M"),
            "lateSpawn": late.strftime("%H:%M"),
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

if __name__ == "__main__":
    app.run(debug=True, port=5000)
