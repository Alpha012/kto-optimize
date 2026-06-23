#!/usr/bin/env python3
import html
import json
import os
import re
import socket
import ssl
import sqlite3
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

COLLECTOR_BUILD = "v171"
CONFIG = os.environ.get("KTO_STATS_COLLECTOR_CONFIG", "/etc/kto-stats-collector.conf")


def load_config(path):
    data = {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                value = value.strip()
                if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
                    value = value[1:-1].replace('\\"', '"').replace("\\\\", "\\")
                data[key.strip()] = value
    except FileNotFoundError:
        pass
    return data


cfg = load_config(CONFIG)
LISTEN_HOST = cfg.get("KTO_COLLECTOR_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(cfg.get("KTO_COLLECTOR_LISTEN_PORT", "1337"))
SECRET = cfg.get("KTO_COLLECTOR_SECRET", "")
BOT_TOKEN = cfg.get("KTO_COLLECTOR_BOT_TOKEN", "")
CHAT_ID = cfg.get("KTO_COLLECTOR_CHAT_ID", "")
ALLOWED_USER_ID = str(cfg.get("KTO_COLLECTOR_ALLOWED_USER_ID", "646296998"))
STATE_DIR = cfg.get("KTO_COLLECTOR_STATE_DIR", "/var/lib/kto-stats-collector")
STALE_SEC = int(cfg.get("KTO_COLLECTOR_STALE_SEC", "60"))
CHECK_INTERVAL = int(cfg.get("KTO_COLLECTOR_CHECK_INTERVAL", "30"))
TZ_NAME = cfg.get("KTO_COLLECTOR_TZ", "Europe/Moscow")
DAILY_REPORT_TIME = cfg.get("KTO_COLLECTOR_DAILY_REPORT_TIME", "").strip()
try:
    EXPECTED_NODES = int(cfg.get("KTO_COLLECTOR_EXPECTED_NODES", "10") or "10")
except Exception:
    EXPECTED_NODES = 10
if EXPECTED_NODES < 1:
    EXPECTED_NODES = 10
try:
    SCAN_ALERT_DELTA = int(cfg.get("KTO_COLLECTOR_SCAN_ALERT_DELTA", "50") or "50")
except Exception:
    SCAN_ALERT_DELTA = 50
try:
    SCAN_ALERT_COOLDOWN = int(cfg.get("KTO_COLLECTOR_SCAN_ALERT_COOLDOWN", "600") or "600")
except Exception:
    SCAN_ALERT_COOLDOWN = 600
IP_LIMIT_ENABLED = str(cfg.get("KTO_COLLECTOR_IP_LIMIT_ENABLED", "0")).lower() in ("1", "yes", "true", "on", "enabled")
try:
    IP_LIMIT_MAX_IPS = int(cfg.get("KTO_COLLECTOR_IP_LIMIT_MAX_IPS", "1") or "1")
except Exception:
    IP_LIMIT_MAX_IPS = 1
if IP_LIMIT_MAX_IPS < 1:
    IP_LIMIT_MAX_IPS = 1
try:
    IP_LIMIT_MAX_EVENTS = int(cfg.get("KTO_COLLECTOR_IP_LIMIT_MAX_EVENTS", "10000") or "10000")
except Exception:
    IP_LIMIT_MAX_EVENTS = 10000
if IP_LIMIT_MAX_EVENTS < 100:
    IP_LIMIT_MAX_EVENTS = 100
if IP_LIMIT_MAX_EVENTS > 200000:
    IP_LIMIT_MAX_EVENTS = 200000
try:
    IP_LIMIT_WINDOW_SEC = int(cfg.get("KTO_COLLECTOR_IP_LIMIT_WINDOW_SEC", "600") or "600")
except Exception:
    IP_LIMIT_WINDOW_SEC = 600
if IP_LIMIT_WINDOW_SEC < 60:
    IP_LIMIT_WINDOW_SEC = 60
try:
    IP_LIMIT_ALERT_COOLDOWN = int(cfg.get("KTO_COLLECTOR_IP_LIMIT_ALERT_COOLDOWN", "600") or "600")
except Exception:
    IP_LIMIT_ALERT_COOLDOWN = 600
if IP_LIMIT_ALERT_COOLDOWN < 60:
    IP_LIMIT_ALERT_COOLDOWN = 60
IP_LIMIT_ENFORCE_ENABLED = str(cfg.get("KTO_COLLECTOR_IP_LIMIT_ENFORCE_ENABLED", "0")).lower() in ("1", "yes", "true", "on", "enabled")
try:
    IP_LIMIT_PENALTY_SEC = int(cfg.get("KTO_COLLECTOR_IP_LIMIT_PENALTY_SEC", "60") or "60")
except Exception:
    IP_LIMIT_PENALTY_SEC = 60
if IP_LIMIT_PENALTY_SEC < 10:
    IP_LIMIT_PENALTY_SEC = 10
REMNA_API_URL = str(cfg.get("KTO_COLLECTOR_REMNA_API_URL", "") or "").strip().rstrip("/")
REMNA_API_TOKEN = str(cfg.get("KTO_COLLECTOR_REMNA_API_TOKEN", "") or "").strip()
try:
    REMNA_API_CACHE_SEC = int(cfg.get("KTO_COLLECTOR_REMNA_API_CACHE_SEC", "300") or "300")
except Exception:
    REMNA_API_CACHE_SEC = 300
if REMNA_API_CACHE_SEC < 30:
    REMNA_API_CACHE_SEC = 30
try:
    REMNA_API_TIMEOUT_SEC = int(cfg.get("KTO_COLLECTOR_REMNA_API_TIMEOUT_SEC", "5") or "5")
except Exception:
    REMNA_API_TIMEOUT_SEC = 5
if REMNA_API_TIMEOUT_SEC < 1:
    REMNA_API_TIMEOUT_SEC = 1

NODES_FILE = os.path.join(STATE_DIR, "nodes.json")
FALLS_FILE = os.path.join(STATE_DIR, "falls.json")
OFFSET_FILE = os.path.join(STATE_DIR, "telegram_offset")
DAILY_FILE = os.path.join(STATE_DIR, "daily_report_date")
SSH_ALLOW_FILE = os.path.join(STATE_DIR, "ssh_allow_ips.json")
IP_LIMIT_FILE = os.path.join(STATE_DIR, "ip_limit.json")
IP_LIMIT_DB_FILE = os.path.join(STATE_DIR, "ip_limit.sqlite")
LOCK = threading.RLock()
NODES = {}
FALLS = {}
SSH_ALLOWED_IPS = []
IP_LIMIT_DB = None
REMNA_USER_CACHE = {}
ALERT_SEPARATOR = "➖" * 9
RESTORED_EMOJI = '<tg-emoji emoji-id="5449683594425410231">❇️</tg-emoji>'
LOST_EMOJI = '<tg-emoji emoji-id="5447183459602669338">🚨</tg-emoji>'

if TZ_NAME:
    os.environ["TZ"] = TZ_NAME
    try:
        time.tzset()
    except AttributeError:
        pass

_getaddrinfo = socket.getaddrinfo


def getaddrinfo_ipv4(host, port, family=0, socktype=0, proto=0, flags=0):
    return _getaddrinfo(host, port, socket.AF_INET, socktype, proto, flags)


socket.getaddrinfo = getaddrinfo_ipv4


def log(message):
    print(f"collector {COLLECTOR_BUILD}: {message}", flush=True)


def now_ts():
    return int(time.time())


def atomic_write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=os.path.dirname(path))
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(content)
    os.replace(tmp, path)


def load_nodes():
    global NODES
    os.makedirs(STATE_DIR, exist_ok=True)
    try:
        with open(NODES_FILE, "r", encoding="utf-8") as fh:
            loaded = json.load(fh)
            if isinstance(loaded, dict):
                NODES = loaded
    except Exception:
        NODES = {}


def save_nodes():
    atomic_write(NODES_FILE, json.dumps(NODES, ensure_ascii=False, indent=2, sort_keys=True))


def load_falls():
    global FALLS
    os.makedirs(STATE_DIR, exist_ok=True)
    try:
        with open(FALLS_FILE, "r", encoding="utf-8") as fh:
            loaded = json.load(fh)
            if isinstance(loaded, dict):
                FALLS = loaded
    except Exception:
        FALLS = {}


def save_falls():
    atomic_write(FALLS_FILE, json.dumps(FALLS, ensure_ascii=False, indent=2, sort_keys=True))


def valid_ipv4(value):
    parts = str(value or "").strip().split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        try:
            number = int(part)
        except Exception:
            return False
        if number < 0 or number > 255:
            return False
    return True


def normalize_ip(value):
    value = str(value or "").strip()
    if not valid_ipv4(value):
        raise ValueError("bad IPv4")
    return ".".join(str(int(part)) for part in value.split("."))


def load_ssh_allowed_ips():
    global SSH_ALLOWED_IPS
    os.makedirs(STATE_DIR, exist_ok=True)
    try:
        with open(SSH_ALLOW_FILE, "r", encoding="utf-8") as fh:
            loaded = json.load(fh)
        if isinstance(loaded, list):
            SSH_ALLOWED_IPS = sorted({normalize_ip(item) for item in loaded if valid_ipv4(item)})
    except Exception:
        SSH_ALLOWED_IPS = []


def save_ssh_allowed_ips():
    atomic_write(SSH_ALLOW_FILE, json.dumps(SSH_ALLOWED_IPS, ensure_ascii=False, indent=2))


def add_ssh_allowed_ip(ip):
    ip = normalize_ip(ip)
    with LOCK:
        exists = ip in SSH_ALLOWED_IPS
        if not exists:
            SSH_ALLOWED_IPS.append(ip)
            SSH_ALLOWED_IPS.sort(key=lambda value: tuple(int(part) for part in value.split(".")))
            save_ssh_allowed_ips()
        return ip, not exists, list(SSH_ALLOWED_IPS)


def ssh_allowed_ips_snapshot():
    with LOCK:
        return list(SSH_ALLOWED_IPS)


def ip_limit_db():
    global IP_LIMIT_DB
    if IP_LIMIT_DB is None:
        os.makedirs(STATE_DIR, exist_ok=True)
        IP_LIMIT_DB = sqlite3.connect(IP_LIMIT_DB_FILE, check_same_thread=False)
        IP_LIMIT_DB.row_factory = sqlite3.Row
        IP_LIMIT_DB.execute("PRAGMA journal_mode=WAL")
        IP_LIMIT_DB.execute("PRAGMA synchronous=NORMAL")
        IP_LIMIT_DB.execute("PRAGMA temp_store=MEMORY")
    return IP_LIMIT_DB


def init_ip_limit_db():
    db = ip_limit_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS ip_limit_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS ip_limit_events (
            user TEXT NOT NULL,
            ip TEXT NOT NULL,
            node TEXT NOT NULL,
            node_key TEXT NOT NULL DEFAULT '',
            last_seen INTEGER NOT NULL,
            PRIMARY KEY (user, ip, node)
        );
        CREATE INDEX IF NOT EXISTS idx_ip_limit_events_seen
            ON ip_limit_events(last_seen);
        CREATE INDEX IF NOT EXISTS idx_ip_limit_events_user_seen
            ON ip_limit_events(user, last_seen);
        CREATE INDEX IF NOT EXISTS idx_ip_limit_events_node_seen
            ON ip_limit_events(node_key, last_seen);
        CREATE TABLE IF NOT EXISTS ip_limit_alerts (
            user TEXT PRIMARY KEY,
            last_alert INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS ip_limit_limits (
            user TEXT PRIMARY KEY,
            limit_value INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS ip_limit_pending (
            key TEXT PRIMARY KEY,
            action TEXT NOT NULL,
            user TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS ip_limit_penalties (
            user TEXT PRIMARY KEY,
            uuid TEXT NOT NULL,
            disabled_at INTEGER NOT NULL,
            enable_at INTEGER NOT NULL,
            reason TEXT NOT NULL,
            last_error TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_ip_limit_penalties_enable
            ON ip_limit_penalties(enable_at);
        CREATE TABLE IF NOT EXISTS ip_limit_blocks (
            node_key TEXT NOT NULL,
            ip TEXT NOT NULL,
            user TEXT NOT NULL,
            node TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            PRIMARY KEY (node_key, ip)
        );
        CREATE INDEX IF NOT EXISTS idx_ip_limit_blocks_expires
            ON ip_limit_blocks(expires_at);
    """)
    try:
        db.execute("ALTER TABLE ip_limit_events ADD COLUMN node_key TEXT NOT NULL DEFAULT ''")
    except sqlite3.OperationalError as exc:
        if "duplicate column" not in str(exc).lower():
            raise
    rows = db.execute("SELECT user, ip, node FROM ip_limit_events WHERE node_key = ''").fetchall()
    for row in rows:
        db.execute(
            "UPDATE ip_limit_events SET node_key = ? WHERE user = ? AND ip = ? AND node = ?",
            (canonical_node_key(row["node"]), row["user"], row["ip"], row["node"]),
        )
    db.commit()


def ip_limit_meta_get(key):
    row = ip_limit_db().execute("SELECT value FROM ip_limit_meta WHERE key = ?", (str(key),)).fetchone()
    return str(row["value"]) if row else ""


def ip_limit_meta_set(key, value):
    ip_limit_db().execute(
        "INSERT INTO ip_limit_meta(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (str(key), str(value)),
    )


def load_ip_limit_legacy_json():
    try:
        with open(IP_LIMIT_FILE, "r", encoding="utf-8") as fh:
            loaded = json.load(fh)
        return loaded if isinstance(loaded, dict) else {}
    except Exception:
        return {}


def migrate_ip_limit_json_to_db():
    if ip_limit_meta_get("json_migrated") == "1":
        return
    loaded = load_ip_limit_legacy_json()
    if not loaded:
        ip_limit_meta_set("json_migrated", "1")
        ip_limit_db().commit()
        return
    db = ip_limit_db()
    users = loaded.get("users") if isinstance(loaded.get("users"), dict) else {}
    for user, ip_map in users.items():
        if not isinstance(ip_map, dict):
            continue
        for ip, entry in ip_map.items():
            if not valid_ipv4(ip) or not isinstance(entry, dict):
                continue
            last_seen = ip_limit_last_seen(entry)
            nodes = entry.get("nodes") if isinstance(entry.get("nodes"), dict) else {}
            if not nodes:
                nodes = {"-": last_seen}
            for node, node_seen in nodes.items():
                node = str(node or "-").strip()[:80] or "-"
                try:
                    seen = int(node_seen or last_seen or 0)
                except Exception:
                    seen = last_seen
                db.execute(
                    "INSERT INTO ip_limit_events(user, ip, node, node_key, last_seen) VALUES(?, ?, ?, ?, ?) "
                    "ON CONFLICT(user, ip, node) DO UPDATE SET node_key = excluded.node_key, last_seen = max(last_seen, excluded.last_seen)",
                    (str(user), normalize_ip(ip), node, canonical_node_key(node), max(seen, last_seen)),
                )
    alerts = loaded.get("alerts") if isinstance(loaded.get("alerts"), dict) else {}
    for user, ts in alerts.items():
        try:
            last_alert = int(ts or 0)
        except Exception:
            continue
        db.execute(
            "INSERT INTO ip_limit_alerts(user, last_alert) VALUES(?, ?) "
            "ON CONFLICT(user) DO UPDATE SET last_alert = excluded.last_alert",
            (str(user), last_alert),
        )
    limits = loaded.get("limits") if isinstance(loaded.get("limits"), dict) else {}
    for user, value in limits.items():
        try:
            limit_value = int(value)
        except Exception:
            continue
        db.execute(
            "INSERT INTO ip_limit_limits(user, limit_value) VALUES(?, ?) "
            "ON CONFLICT(user) DO UPDATE SET limit_value = excluded.limit_value",
            (str(user), limit_value),
        )
    pending = loaded.get("pending") if isinstance(loaded.get("pending"), dict) else {}
    for key, item in pending.items():
        if not isinstance(item, dict):
            continue
        action = str(item.get("action") or "").strip()
        user = str(item.get("user") or "").strip()
        if not action or not user:
            continue
        try:
            created_at = int(item.get("created_at") or 0)
        except Exception:
            created_at = 0
        db.execute(
            "INSERT INTO ip_limit_pending(key, action, user, created_at) VALUES(?, ?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET action = excluded.action, user = excluded.user, created_at = excluded.created_at",
            (str(key), action, user, created_at),
        )
    penalties = loaded.get("penalties") if isinstance(loaded.get("penalties"), dict) else {}
    for user, item in penalties.items():
        if not isinstance(item, dict):
            continue
        uuid = str(item.get("uuid") or "").strip()
        if not uuid:
            continue
        try:
            disabled_at = int(item.get("disabled_at") or 0)
            enable_at = int(item.get("enable_at") or 0)
        except Exception:
            continue
        db.execute(
            "INSERT INTO ip_limit_penalties(user, uuid, disabled_at, enable_at, reason, last_error) VALUES(?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(user) DO UPDATE SET uuid = excluded.uuid, disabled_at = excluded.disabled_at, enable_at = excluded.enable_at, reason = excluded.reason, last_error = excluded.last_error",
            (str(user), uuid, disabled_at, enable_at, str(item.get("reason") or "ip_limit"), str(item.get("last_error") or "")[:160]),
        )
    blocks = loaded.get("blocks") if isinstance(loaded.get("blocks"), dict) else {}
    for node_key, ip_map in blocks.items():
        if not isinstance(ip_map, dict):
            continue
        node_key = str(node_key or "").strip()
        if not node_key:
            continue
        for ip, item in ip_map.items():
            if not valid_ipv4(ip) or not isinstance(item, dict):
                continue
            try:
                expires_at = int(item.get("expires_at") or 0)
            except Exception:
                continue
            db.execute(
                "INSERT INTO ip_limit_blocks(node_key, ip, user, node, expires_at) VALUES(?, ?, ?, ?, ?) "
                "ON CONFLICT(node_key, ip) DO UPDATE SET user = excluded.user, node = excluded.node, expires_at = max(expires_at, excluded.expires_at)",
                (node_key, normalize_ip(ip), str(item.get("user") or ""), str(item.get("node") or node_key), expires_at),
            )
    ip_limit_meta_set("json_migrated", "1")
    db.commit()
    log("ip limit state migrated to sqlite")


def load_ip_limit_state():
    init_ip_limit_db()
    migrate_ip_limit_json_to_db()


def save_ip_limit_state():
    if IP_LIMIT_DB is not None:
        IP_LIMIT_DB.commit()


def normalize_scan_top(value):
    result = []
    if not isinstance(value, list):
        return result
    for item in value[:10]:
        if not isinstance(item, dict):
            continue
        ip = str(item.get("ip") or "").strip()
        if not valid_ipv4(ip):
            continue
        try:
            count = int(item.get("count") or 0)
        except Exception:
            count = 0
        try:
            rate = int(item.get("rate") or 0)
        except Exception:
            rate = 0
        if count > 0:
            result.append({"ip": normalize_ip(ip), "count": count, "rate": rate})
    return result


def today_key():
    return datetime.fromtimestamp(now_ts()).strftime("%Y-%m-%d")


def ensure_today_falls():
    day = today_key()
    if FALLS.get("date") != day:
        FALLS.clear()
        FALLS.update({"date": day, "total": 0, "downtime_sec": 0, "downtime_revoke_sec": 0, "nodes": {}})
    elif not isinstance(FALLS.get("nodes"), dict):
        FALLS["nodes"] = {}
    if "downtime_sec" not in FALLS:
        FALLS["downtime_sec"] = 0
    if "downtime_revoke_sec" not in FALLS:
        FALLS["downtime_revoke_sec"] = 0
    return FALLS


def record_fall(node):
    falls = ensure_today_falls()
    name = str(node.get("name") or node.get("id") or "unknown")
    falls["total"] = int(falls.get("total", 0) or 0) + 1
    nodes = falls.setdefault("nodes", {})
    nodes[name] = int(nodes.get(name, 0) or 0) + 1
    try:
        save_falls()
    except Exception as exc:
        log(f"save falls failed: {exc}")


def record_downtime(seconds):
    seconds = max(0, int(seconds or 0))
    if seconds <= 0:
        return
    falls = ensure_today_falls()
    falls["downtime_sec"] = int(falls.get("downtime_sec", 0) or 0) + seconds
    try:
        save_falls()
    except Exception as exc:
        log(f"save downtime failed: {exc}")


def revoke_downtime(seconds):
    seconds = max(0, int(seconds or 0))
    if seconds <= 0:
        return
    falls = ensure_today_falls()
    falls["downtime_revoke_sec"] = int(falls.get("downtime_revoke_sec", 0) or 0) + seconds
    try:
        save_falls()
    except Exception as exc:
        log(f"save downtime revoke failed: {exc}")


def reset_daily_falls(nodes, ts):
    active_downtime = 0
    for node in nodes:
        last_seen = int(node.get("last_seen", 0) or 0)
        age = ts - last_seen
        if age > STALE_SEC:
            offline_since = int(node.get("offline_since") or last_seen or ts)
            active_downtime += max(0, ts - offline_since)
    falls = ensure_today_falls()
    falls["total"] = 0
    falls["nodes"] = {}
    falls["downtime_sec"] = 0
    falls["downtime_revoke_sec"] = active_downtime
    try:
        save_falls()
    except Exception as exc:
        log(f"save full revoke failed: {exc}")


def format_bytes(value):
    try:
        value = float(value)
    except Exception:
        value = 0.0
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    idx = 0
    while value >= 1024 and idx < len(units) - 1:
        value /= 1024.0
        idx += 1
    if idx == 0:
        return f"{value:.0f} {units[idx]}"
    return f"{value:.1f} {units[idx]}"


def format_bytes_limit(value):
    try:
        value = float(value)
    except Exception:
        value = 0.0
    if value <= 0:
        return "∞"
    return format_bytes(value)


def format_percent(value):
    try:
        value = float(value)
    except Exception:
        value = 0.0
    if value <= 0:
        return "0%"
    if value < 0.1:
        return "<0.1%"
    if value >= 10:
        return f"{value:.0f}%"
    return f"{value:.1f}%"


def format_age(seconds):
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m"
    hours = minutes // 60
    return f"{hours}h {minutes % 60}m"


def plural_ru(value, one, few, many):
    value = abs(int(value))
    last_two = value % 100
    last = value % 10
    if 11 <= last_two <= 14:
        return many
    if last == 1:
        return one
    if 2 <= last <= 4:
        return few
    return many


def format_duration_ru(seconds):
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds} {plural_ru(seconds, 'секунда', 'секунды', 'секунд')}"
    minutes = seconds // 60
    rest_seconds = seconds % 60
    if minutes < 60:
        result = f"{minutes} {plural_ru(minutes, 'минута', 'минуты', 'минут')}"
        if rest_seconds:
            result += f" {rest_seconds} {plural_ru(rest_seconds, 'секунда', 'секунды', 'секунд')}"
        return result
    hours = minutes // 60
    rest_minutes = minutes % 60
    result = f"{hours} {plural_ru(hours, 'час', 'часа', 'часов')}"
    if rest_minutes:
        result += f" {rest_minutes} {plural_ru(rest_minutes, 'минута', 'минуты', 'минут')}"
    return result


def format_duration_ru_for(seconds):
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds} {plural_ru(seconds, 'секунду', 'секунды', 'секунд')}"
    minutes = seconds // 60
    rest_seconds = seconds % 60
    if minutes < 60 and rest_seconds == 0:
        return f"{minutes} {plural_ru(minutes, 'минуту', 'минуты', 'минут')}"
    return format_duration_ru(seconds)


def fmt_time(ts):
    try:
        return datetime.fromtimestamp(int(ts)).strftime("%d.%m.%Y %H:%M")
    except Exception:
        return "-"


def parse_iso_ts(value):
    value = str(value or "").strip()
    if not value:
        return 0
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return int(parsed.timestamp())
    except Exception:
        return 0


def fmt_iso_time(value):
    ts = parse_iso_ts(value)
    return fmt_time(ts) if ts > 0 else "-"


def natural_sort_key(value):
    text = str(value or "").casefold()
    key = []
    for part in re.split(r"(\d+)", text):
        if not part:
            continue
        if part.isdigit():
            key.append((1, int(part)))
        else:
            key.append((0, part))
    return key


def canonical_node_key(value):
    text = re.sub(r"[^\w]+", "", str(value or "").casefold(), flags=re.UNICODE)
    parts = []
    for part in re.split(r"(\d+)", text):
        if not part:
            continue
        if part.isdigit():
            parts.append(str(int(part)))
        else:
            parts.append(part)
    return "".join(parts)


def node_canonical_key(node):
    return canonical_node_key(node.get("name") or node.get("id") or "")


def tg_call(method, data=None, timeout=25):
    if not BOT_TOKEN:
        raise RuntimeError("telegram bot token is empty")
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/{method}"
    encoded = urllib.parse.urlencode(data or {}).encode("utf-8")
    req = urllib.request.Request(url, data=encoded, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", errors="replace")
    parsed = json.loads(body)
    if not parsed.get("ok"):
        raise RuntimeError(body[:700])
    return parsed


def send_message(text, reply_markup=None):
    if not CHAT_ID:
        log("telegram chat id is empty")
        return False
    try:
        payload = {
            "chat_id": CHAT_ID,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": "true",
        }
        if reply_markup is not None:
            payload["reply_markup"] = json.dumps(reply_markup, ensure_ascii=False)
        result = tg_call("sendMessage", payload)
        msg = result.get("result", {})
        log(f"telegram sent message_id={msg.get('message_id')} chat_id={msg.get('chat', {}).get('id')}")
        return True
    except Exception as exc:
        log(f"telegram send failed: {exc}")
        return False


def edit_message_text(chat_id, message_id, text, reply_markup=None):
    if not chat_id or not message_id:
        return False
    try:
        payload = {
            "chat_id": chat_id,
            "message_id": message_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": "true",
        }
        if reply_markup is not None:
            payload["reply_markup"] = json.dumps(reply_markup, ensure_ascii=False)
        tg_call("editMessageText", payload, timeout=15)
        log(f"telegram edited message_id={message_id} chat_id={chat_id}")
        return True
    except Exception as exc:
        if "message is not modified" in str(exc).lower():
            return True
        log(f"telegram edit failed: {exc}")
        return False


def answer_callback(callback_id, text=""):
    if not callback_id:
        return
    try:
        payload = {"callback_query_id": callback_id}
        if text:
            payload["text"] = text[:180]
        tg_call("answerCallbackQuery", payload, timeout=10)
    except Exception as exc:
        log(f"telegram callback answer failed: {exc}")


def remna_api_enabled():
    return bool(REMNA_API_URL and REMNA_API_TOKEN)


def remna_api_call(path, method="GET", payload=None):
    if not remna_api_enabled():
        return None
    url = f"{REMNA_API_URL}{path}"
    context = ssl._create_unverified_context() if url.lower().startswith("https://") else None
    body = None
    headers = {
        "Authorization": f"Bearer {REMNA_API_TOKEN}",
        "Accept": "application/json",
    }
    if payload is not None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(
        url,
        data=body,
        headers=headers,
        method=method,
    )
    with urllib.request.urlopen(req, timeout=REMNA_API_TIMEOUT_SEC, context=context) as resp:
        body = resp.read().decode("utf-8", errors="replace")
    return json.loads(body)


def remna_user_path(user_id):
    value = str(user_id or "").strip()
    if not value:
        return ""
    quoted = urllib.parse.quote(value, safe="")
    if value.isdigit():
        return f"/api/users/by-id/{quoted}"
    if re.fullmatch(r"[0-9a-fA-F-]{32,36}", value):
        return f"/api/users/{quoted}"
    return f"/api/users/by-username/{quoted}"


def remna_lookup_paths(query):
    value = str(query or "").strip()
    if not value:
        return []
    forced_tg = False
    if value.lower().startswith(("tg:", "telegram:")):
        value = value.split(":", 1)[1].strip()
        forced_tg = True
    quoted = urllib.parse.quote(value, safe="")
    if forced_tg and value:
        return [f"/api/users/by-telegram-id/{quoted}"]
    if value.isdigit():
        by_id = f"/api/users/by-id/{quoted}"
        by_tg = f"/api/users/by-telegram-id/{quoted}"
        if len(value) >= 7:
            return [by_tg, by_id]
        return [by_id, by_tg]
    if re.fullmatch(r"[0-9a-fA-F-]{32,36}", value):
        return [f"/api/users/{quoted}"]
    if "@" in value:
        return [f"/api/users/by-email/{quoted}", f"/api/users/by-username/{quoted}"]
    return [f"/api/users/by-username/{quoted}"]


def remna_extract_user(payload):
    candidates = []

    def collect(value):
        if isinstance(value, dict):
            candidates.append(value)
            for key in ("response", "user", "data", "items", "users"):
                collect(value.get(key))
        elif isinstance(value, list):
            for item in value:
                collect(item)

    collect(payload)
    user_keys = {"username", "email", "tag", "status", "expireAt", "trafficLimitBytes", "userTraffic"}
    for candidate in candidates:
        if any(key in candidate for key in user_keys):
            return candidate
    return None


def remna_user_cache_put(info):
    if not isinstance(info, dict):
        return
    aliases = []
    for key in ("id", "uuid", "username", "telegramId", "email", "tag"):
        value = str(info.get(key) or "").strip()
        if value:
            aliases.append(value)
            if key == "telegramId":
                aliases.append(f"tg:{value}")
    ts = now_ts()
    with LOCK:
        for alias in aliases:
            REMNA_USER_CACHE[alias] = {"fetched_at": ts, "data": info}


def remna_user_lookup(query):
    query = str(query or "").strip()
    if not query or not remna_api_enabled():
        return None
    ts = now_ts()
    with LOCK:
        cached = REMNA_USER_CACHE.get(query)
        if cached and ts - int(cached.get("fetched_at") or 0) < REMNA_API_CACHE_SEC:
            return cached.get("data")

    last_error = ""
    for path in remna_lookup_paths(query):
        try:
            payload = remna_api_call(path)
            data = remna_extract_user(payload)
            if data:
                remna_user_cache_put(data)
                with LOCK:
                    REMNA_USER_CACHE[query] = {"fetched_at": ts, "data": data}
                return data
        except urllib.error.HTTPError as exc:
            if exc.code != 404:
                last_error = f"http {exc.code}"
                log(f"remna user lookup failed query={query}: http {exc.code}")
        except Exception as exc:
            last_error = str(exc)
            log(f"remna user lookup failed query={query}: {exc}")
    if last_error:
        return None
    with LOCK:
        REMNA_USER_CACHE[query] = {"fetched_at": ts, "data": None}
    return None


def remna_user_info(user_id):
    user_id = str(user_id or "").strip()
    if not user_id or not remna_api_enabled():
        return None
    ts = now_ts()
    with LOCK:
        cached = REMNA_USER_CACHE.get(user_id)
        if cached and ts - int(cached.get("fetched_at") or 0) < REMNA_API_CACHE_SEC:
            return cached.get("data")

    data = None
    for path in remna_lookup_paths(user_id) or [remna_user_path(user_id)]:
        if not path:
            continue
        try:
            payload = remna_api_call(path)
            data = remna_extract_user(payload)
            if data:
                remna_user_cache_put(data)
                break
        except urllib.error.HTTPError as exc:
            if exc.code != 404:
                log(f"remna user lookup failed id={user_id}: http {exc.code}")
        except Exception as exc:
            log(f"remna user lookup failed id={user_id}: {exc}")

    with LOCK:
        REMNA_USER_CACHE[user_id] = {"fetched_at": ts, "data": data}
    return data


def remna_user_action(uuid_value, action):
    uuid_value = str(uuid_value or "").strip()
    action = str(action or "").strip()
    if not uuid_value or action not in ("disable", "enable"):
        raise ValueError("bad remna user action")
    quoted = urllib.parse.quote(uuid_value, safe="")
    payload = remna_api_call(f"/api/users/{quoted}/actions/{action}", method="POST", payload={})
    data = remna_extract_user(payload)
    if data:
        remna_user_cache_put(data)
    return data


def remna_user_name(info, fallback=""):
    if not isinstance(info, dict):
        return ""
    for key in ("username", "email", "tag"):
        value = str(info.get(key) or "").strip()
        if value and value != str(fallback):
            return value
    return ""


def remna_user_traffic(info):
    if not isinstance(info, dict):
        return ""
    traffic = info.get("userTraffic") if isinstance(info.get("userTraffic"), dict) else {}
    used = traffic.get("usedTrafficBytes") if traffic else 0
    limit = info.get("trafficLimitBytes") or 0
    if not used and not limit:
        return ""
    return f"{format_bytes(used)} / {format_bytes_limit(limit)}"


def remna_user_online(info):
    if not isinstance(info, dict):
        return ""
    traffic = info.get("userTraffic") if isinstance(info.get("userTraffic"), dict) else {}
    online_ts = parse_iso_ts(traffic.get("onlineAt") if traffic else "")
    if online_ts <= 0:
        return ""
    return f"{format_age(now_ts() - online_ts)} назад"


def remna_user_expire(info):
    if not isinstance(info, dict):
        return ""
    return fmt_iso_time(info.get("expireAt"))


def remna_detail_lines(user_id, info, include_hwid=False):
    lines = []
    name = remna_user_name(info, user_id)
    if name:
        lines.append(detail_line("Пользователь", name))
    status = str((info or {}).get("status") or "").strip()
    if status:
        lines.append(detail_line("Статус", status))
    traffic = remna_user_traffic(info)
    if traffic:
        lines.append(detail_line("Трафик", traffic))
    expire = remna_user_expire(info)
    if expire and expire != "-":
        lines.append(detail_line("Истекает", expire))
    online = remna_user_online(info)
    if online:
        lines.append(detail_line("Онлайн", online))
    if include_hwid:
        hwid = (info or {}).get("hwidDeviceLimit")
        if hwid is not None:
            lines.append(detail_line("HWID лимит", hwid))
    return lines


def remna_block_lines(user_id, info):
    result = []
    status = str((info or {}).get("status") or "").strip()
    traffic = remna_user_traffic(info)
    expire = remna_user_expire(info)
    online = remna_user_online(info)
    summary = []
    if status:
        summary.append(status)
    if traffic:
        summary.append(f"трафик {traffic}")
    if expire and expire != "-":
        summary.append(f"до {expire}")
    if online:
        summary.append(f"online {online}")
    if summary:
        result.append(html.escape(" | ".join(summary)))
    return result


def node_message(node, status=None):
    name = html.escape(str(node.get("name") or node.get("id") or "unknown"))
    ip = html.escape(str(node.get("ip") or "-"))
    uptime_sec = int(node.get("uptime_sec") or 0)
    uptime_text = format_duration_ru(uptime_sec) if uptime_sec > 0 else "-"
    error = str(node.get("error") or "")
    updated = node.get("updated_at") or node.get("last_seen") or 0
    metrics_ok = bool(node.get("metrics_ok"))
    status_text = html.escape(str(status or "OK"))
    footer = f"<i>Обновлено: {fmt_time(updated)} | Статус: {status_text}</i>"
    ram_line = "Забитость ОЗУ: ?% | ? / ?"
    cpu_line = "Нагруженность процессора: ?%"
    if metrics_ok:
        ram_line = f"Забитость ОЗУ: {int(node.get('ram_percent', 0) or 0)}% | {format_bytes(node.get('ram_used', 0))} / {format_bytes(node.get('ram_total', 0))}"
        cpu_line = f"Нагруженность процессора: {format_percent(node.get('cpu_percent', 0))}"
    scan_total = int(node.get("scan_wrong_sni_total") or 0)
    if scan_total > 0:
        scan_sources = int(node.get("scan_wrong_sni_sources") or 0)
        cpu_line = f"{cpu_line}\nWrong SNI: {scan_total} / {scan_sources} IP"
    lines = [f"<blockquote><b>{name}</b>\nIP: {ip}\nАптайм: {uptime_text}</blockquote>", ""]
    if error:
        lines += [
            "I/O: - | -",
            "<b>Сегодня: ошибка | Вчера: - | Месяц: ошибка</b>",
            "",
            f"<b><i>{ram_line}",
            f"{cpu_line}</i></b>",
            "",
            f"Ошибка: {html.escape(error)[:800]}",
            "",
            footer,
        ]
        return "\n".join(lines)
    lines += [
        f"<b>I/O: {format_bytes(node.get('day_rx', 0))} | {format_bytes(node.get('day_tx', 0))}</b>",
        f"<b>Сегодня: {format_bytes(node.get('day_total', 0))} | Вчера: {format_bytes(node.get('yesterday_total', 0))} | Месяц: {format_bytes(node.get('month_total', 0))}</b>",
        "",
        f"<b><i>{ram_line}",
        f"{cpu_line}</i></b>",
        "",
        footer,
    ]
    return "\n".join(lines)


def downtime_totals(nodes, ts):
    dead_items = []
    active_downtime = 0
    for node in nodes:
        last_seen = int(node.get("last_seen", 0) or 0)
        age = ts - last_seen
        if age > STALE_SEC:
            dead_items.append((node, age))
            offline_since = int(node.get("offline_since") or last_seen or ts)
            active_downtime += max(0, ts - offline_since)
    with LOCK:
        falls = dict(ensure_today_falls())
        falls_nodes = dict(falls.get("nodes") or {})
    completed_downtime = int(falls.get("downtime_sec", 0) or 0)
    revoked_downtime = int(falls.get("downtime_revoke_sec", 0) or 0)
    total_downtime = max(0, completed_downtime + active_downtime - revoked_downtime)
    return dead_items, falls, falls_nodes, total_downtime


def dedupe_nodes(values):
    deduped = {}
    for node in values:
        key = node_canonical_key(node)
        current = deduped.get(key)
        if current is None or int(node.get("last_seen", 0) or 0) > int(current.get("last_seen", 0) or 0):
            deduped[key] = node
    return list(deduped.values())


def status_summary(nodes, ts):
    expected_total = max(EXPECTED_NODES, len(nodes), 1)
    live_count = 0
    for node in nodes:
        last_seen = int(node.get("last_seen", 0) or 0)
        age = ts - last_seen
        if age <= STALE_SEC:
            live_count += 1
    dead_items, falls, falls_nodes, total_downtime = downtime_totals(nodes, ts)

    lines = [
        "",
        "<blockquote>На данный момент:</blockquote>",
        f"<b>Живо: {live_count}/{expected_total}</b>",
        "<b>Мертво:</b>",
    ]
    if dead_items:
        dead_items.sort(key=lambda item: natural_sort_key(item[0].get("name") or item[0].get("id") or ""))
        for node, age in dead_items:
            name = html.escape(str(node.get("name") or node.get("id") or "unknown"))
            ip = html.escape(str(node.get("ip") or "-"))
            uptime_sec = int(node.get("uptime_sec") or 0)
            uptime_text = format_duration_ru(uptime_sec) if uptime_sec > 0 else "-"
            last_seen = int(node.get("last_seen", 0) or 0)
            lines += [
                f"<blockquote><b>{name}</b>",
                f"IP: {ip}",
                f"Аптайм: {uptime_text}",
                f"Последнее удачное обновление: {fmt_time(last_seen)}",
                f"В даунтайме: {format_duration_ru(age)}</blockquote>",
            ]
    else:
        lines.append("нет")

    total_falls = int(falls.get("total", 0) or 0)
    lines += [
        "",
        f"<b>Общее кол-во падений за сегодня: {total_falls}</b>",
        f"<b>Общее время даунтайма за сегодня: {format_duration_ru(total_downtime)}</b>",
    ]
    if falls_nodes:
        lines.append("<b>Топ лист машин которые падали:</b>")
        top_lines = []
        for name, count in sorted(falls_nodes.items(), key=lambda item: (-int(item[1]), natural_sort_key(item[0]))):
            top_lines.append(f"{html.escape(str(name))}: {int(count)} раз")
        lines.append(f"<blockquote>{chr(10).join(top_lines)}</blockquote>")
    else:
        lines.append("<b>Топ лист машин которые падали:</b> нет")
    return "\n".join(lines)


def aggregate_message():
    with LOCK:
        nodes = dedupe_nodes(NODES.values())
    ts = now_ts()
    if not nodes:
        return "<b>Статистика обходов</b>\n\nНет данных от машин."
    nodes.sort(key=lambda item: natural_sort_key(item.get("name") or item.get("id") or ""))
    parts = ["<b>Статистика обходов</b>"]
    for node in nodes:
        age = ts - int(node.get("last_seen", 0) or 0)
        status = "OK" if age <= STALE_SEC else f"OFFLINE {format_age(age)}"
        parts.append("")
        parts.append(node_message(node, status))
    parts.append(status_summary(nodes, ts))
    return "\n".join(parts)


def code_value(value):
    if value is None or value == "":
        value = "-"
    value = str(value).replace("№", "#")
    return f"<code>{html.escape(value)}</code>"


def detail_line(label, value):
    return f"<b>{label}:</b> {code_value(value)}"


def node_display_name(node, fallback="unknown"):
    return str(node.get("name") or node.get("id") or node.get("hostname") or fallback)


def node_display_ip(node):
    return str(node.get("ip") or "-")


def find_node(query):
    needle = canonical_node_key(query)
    if not needle:
        return None
    with LOCK:
        for node in NODES.values():
            candidates = [
                node.get("id"),
                node.get("name"),
                node.get("hostname"),
            ]
            if any(canonical_node_key(value) == needle for value in candidates):
                return dict(node)
    return None


def node_alert_message(kind, node_id, node, reason="-"):
    name = node_display_name(node, node_id)
    ip = node_display_ip(node)
    if kind == "up":
        lines = [
            f"{RESTORED_EMOJI} #nodeConnectionRestored",
            "<b>Подключение к серверу восстановлено</b>",
            ALERT_SEPARATOR,
            detail_line("Название", name),
            detail_line("Адрес", ip),
        ]
    else:
        updated = fmt_time(node.get("last_seen") or node.get("updated_at") or 0)
        lines = [
            f"{LOST_EMOJI} #nodeConnectionLost",
            "<b>Подключение к серверу потеряно</b>",
            ALERT_SEPARATOR,
            detail_line("Название", name),
            detail_line("Причина", reason),
            detail_line("Последнее обновление", updated),
            detail_line("Адрес", ip),
        ]
    return "\n".join(lines)


def alert_offline(node_id, node, age):
    return send_message(node_alert_message("down", node_id, node, f"Нет push {format_age(age)}"))


def alert_online(node_id, node):
    return send_message(node_alert_message("up", node_id, node))


def alert_scan_spike(node, delta):
    name = html.escape(str(node.get("name") or node.get("id") or "unknown"))
    ip = html.escape(str(node.get("ip") or "-"))
    top = node.get("scan_wrong_sni_top") or []
    top_lines = []
    for item in top[:5]:
        src = html.escape(str(item.get("ip") or "-"))
        count = int(item.get("count") or 0)
        rate = int(item.get("rate") or 0)
        suffix = f", rate {rate}/10s" if rate > 0 else ""
        top_lines.append(f"{src}: {count}{suffix}")
    if not top_lines:
        top_lines.append("нет топа")
    return send_message(
        "<b>Подозрительный wrong SNI шум</b>\n\n"
        f"<blockquote><b>{name}</b>\nIP: {ip}</blockquote>\n"
        f"Прирост: +{int(delta)}\n"
        f"Всего в окне HAProxy: {int(node.get('scan_wrong_sni_total') or 0)}\n\n"
        f"<blockquote>{chr(10).join(top_lines)}</blockquote>"
    )


def normalize_ip_limit_user(value):
    value = re.sub(r"\s+", " ", str(value or "").strip())
    if not value or len(value) > 160:
        return ""
    return value


def normalize_ip_limit_event(raw, fallback_node, ts):
    if not isinstance(raw, dict):
        return None
    user = normalize_ip_limit_user(raw.get("user"))
    ip = str(raw.get("ip") or "").strip()
    if not user or not valid_ipv4(ip):
        return None
    node = str(raw.get("node") or fallback_node or "-").strip() or "-"
    try:
        seen_at = int(raw.get("seen_at") or ts)
    except Exception:
        seen_at = ts
    if seen_at <= 0 or seen_at > ts + 300:
        seen_at = ts
    return {"user": user, "ip": normalize_ip(ip), "node": node[:80], "seen_at": seen_at}


def ip_limit_last_seen(entry):
    try:
        return int((entry or {}).get("last_seen") or 0)
    except Exception:
        return 0


def purge_ip_limit_state(ts):
    cutoff = ts - IP_LIMIT_WINDOW_SEC
    ip_limit_db().execute("DELETE FROM ip_limit_events WHERE last_seen < ?", (cutoff,))


def active_ip_limit_entries(user, ts):
    cutoff = ts - IP_LIMIT_WINDOW_SEC
    rows = ip_limit_db().execute(
        "SELECT ip, max(last_seen) AS last_seen, group_concat(node, '\n') AS nodes "
        "FROM ip_limit_events WHERE user = ? AND last_seen >= ? "
        "GROUP BY ip ORDER BY last_seen DESC, ip ASC",
        (str(user), cutoff),
    ).fetchall()
    result = []
    for row in rows:
        nodes = sorted({node for node in str(row["nodes"] or "").split("\n") if node}, key=natural_sort_key)
        result.append({"ip": str(row["ip"]), "last_seen": int(row["last_seen"] or 0), "nodes": nodes})
    return result


def remna_user_id(info, fallback=""):
    if isinstance(info, dict):
        value = str(info.get("id") or "").strip()
        if value:
            return value
    return str(fallback or "").strip()


def remna_user_uuid(info):
    if not isinstance(info, dict):
        return ""
    return str(info.get("uuid") or "").strip()


def ip_limit_user_keys(user, info=None):
    keys = []

    def add(value):
        value = str(value or "").strip()
        if value and value not in keys:
            keys.append(value)

    add(user)
    if isinstance(info, dict):
        for key in ("id", "uuid", "username", "telegramId", "email", "tag"):
            value = str(info.get(key) or "").strip()
            if value:
                add(value)
                if key == "telegramId":
                    add(f"tg:{value}")
    return keys


def ip_limit_primary_key(user, info=None):
    if isinstance(info, dict):
        value = str(info.get("id") or "").strip()
        if value:
            return value
    keys = ip_limit_user_keys(user, info)
    return keys[0] if keys else str(user or "").strip()


def ip_limit_effective_limit(user, info=None):
    with LOCK:
        for key in ip_limit_user_keys(user, info):
            row = ip_limit_db().execute("SELECT limit_value FROM ip_limit_limits WHERE user = ?", (str(key),)).fetchone()
            if not row:
                continue
            value = int(row["limit_value"])
            if value <= 0:
                return 0, "personal"
            return value, "personal"
    return IP_LIMIT_MAX_IPS, "global"


def set_ip_limit_override(user, info, value):
    key = ip_limit_primary_key(user, info)
    if not key:
        raise ValueError("empty user key")
    value = int(value)
    with LOCK:
        ip_limit_db().execute(
            "INSERT INTO ip_limit_limits(user, limit_value) VALUES(?, ?) "
            "ON CONFLICT(user) DO UPDATE SET limit_value = excluded.limit_value",
            (str(key), value),
        )
        save_ip_limit_state()
    return key


def clear_ip_limit_cache(info):
    if not isinstance(info, dict):
        return
    with LOCK:
        for key in ip_limit_user_keys("", info):
            REMNA_USER_CACHE.pop(key, None)


def active_ip_limit_entries_for_user(user, info, ts):
    merged = {}
    with LOCK:
        for key in ip_limit_user_keys(user, info):
            for item in active_ip_limit_entries(key, ts):
                ip = item.get("ip")
                if not ip:
                    continue
                current = merged.setdefault(ip, {"ip": ip, "last_seen": 0, "nodes": set()})
                current["last_seen"] = max(int(current["last_seen"] or 0), int(item.get("last_seen") or 0))
                current["nodes"].update(str(node) for node in item.get("nodes") or [] if str(node).strip())
    result = []
    for item in merged.values():
        result.append({"ip": item["ip"], "last_seen": item["last_seen"], "nodes": sorted(item["nodes"], key=natural_sort_key)})
    result.sort(key=lambda row: (-row["last_seen"], row["ip"]))
    return result


def purge_ip_limit_blocks(ts):
    cur = ip_limit_db().execute("DELETE FROM ip_limit_blocks WHERE expires_at <= ?", (int(ts),))
    return cur.rowcount > 0


def node_alias_keys(node):
    aliases = set()
    if isinstance(node, dict):
        for key in ("id", "name", "hostname"):
            alias = canonical_node_key(node.get(key))
            if alias:
                aliases.add(alias)
    else:
        alias = canonical_node_key(node)
        if alias:
            aliases.add(alias)
    return aliases


def schedule_ip_limit_blocks(user, entries, info, expires_at):
    user_key = ip_limit_primary_key(user, info)
    if not user_key:
        user_key = str(user or "").strip()
    scheduled = 0
    with LOCK:
        for item in entries:
            ip = str(item.get("ip") or "").strip()
            if not valid_ipv4(ip):
                continue
            node_names = [str(node or "").strip() for node in item.get("nodes") or [] if str(node or "").strip()]
            for node_name in node_names:
                node_key = canonical_node_key(node_name)
                if not node_key:
                    continue
                ip_limit_db().execute(
                    "INSERT INTO ip_limit_blocks(node_key, ip, user, node, expires_at) VALUES(?, ?, ?, ?, ?) "
                    "ON CONFLICT(node_key, ip) DO UPDATE SET user = excluded.user, node = excluded.node, expires_at = max(expires_at, excluded.expires_at)",
                    (node_key, normalize_ip(ip), user_key, node_name, int(expires_at)),
                )
                scheduled += 1
        if scheduled > 0:
            save_ip_limit_state()
    return scheduled


def ip_limit_blocks_for_node(node, ts):
    aliases = list(node_alias_keys(node))
    if not aliases:
        return []
    with LOCK:
        changed = purge_ip_limit_blocks(ts)
        placeholders = ",".join("?" for _ in aliases)
        rows = ip_limit_db().execute(
            f"SELECT ip, user, max(expires_at) AS expires_at FROM ip_limit_blocks "
            f"WHERE node_key IN ({placeholders}) AND expires_at > ? GROUP BY ip, user",
            tuple(aliases) + (int(ts),),
        ).fetchall()
        if changed:
            save_ip_limit_state()
    result = [{"ip": str(row["ip"]), "user": str(row["user"] or ""), "expires_at": int(row["expires_at"] or 0)} for row in rows]
    return sorted(result, key=lambda item: (item["expires_at"], item["ip"]))


def ip_limit_snapshot(ts, node_query=""):
    cutoff = ts - IP_LIMIT_WINDOW_SEC
    node_key = canonical_node_key(node_query)
    with LOCK:
        purge_ip_limit_state(ts)
        if node_key:
            rows = ip_limit_db().execute(
                "SELECT user, ip, max(last_seen) AS last_seen, group_concat(node, '\n') AS nodes "
                "FROM ip_limit_events WHERE last_seen >= ? AND node_key = ? GROUP BY user, ip "
                "ORDER BY last_seen DESC, user ASC, ip ASC",
                (cutoff, node_key),
            ).fetchall()
        else:
            rows = ip_limit_db().execute(
                "SELECT user, ip, max(last_seen) AS last_seen, group_concat(node, '\n') AS nodes "
                "FROM ip_limit_events WHERE last_seen >= ? GROUP BY user, ip "
                "ORDER BY last_seen DESC, user ASC, ip ASC",
                (cutoff,),
            ).fetchall()
    result = []
    for row in rows:
        nodes = sorted({node for node in str(row["nodes"] or "").split("\n") if node.strip()}, key=natural_sort_key)
        result.append({
            "user": str(row["user"]),
            "ip": str(row["ip"]),
            "last_seen": int(row["last_seen"] or 0),
            "nodes": nodes,
        })
    result.sort(key=lambda item: (-item["last_seen"], natural_sort_key(item["user"]), item["ip"]))
    return result


def ip_limit_active_node_names(rows):
    names = set()
    for row in rows:
        for node in row.get("nodes") or []:
            node = str(node or "").strip()
            if node:
                names.add(node)
    return sorted(names, key=natural_sort_key)


def ip_limit_row_matches_node(row, node_query):
    needle = canonical_node_key(node_query)
    if not needle:
        return False
    for node in row.get("nodes") or []:
        if canonical_node_key(node) == needle:
            return True
    return False


def ip_limit_group_rows(rows):
    grouped = {}
    for row in rows:
        grouped.setdefault(row["user"], []).append(row)
    return sorted(
        grouped.items(),
        key=lambda item: (-len(item[1]), -max(row["last_seen"] for row in item[1]), natural_sort_key(item[0])),
    )


def ip_limit_user_block(user, rows, ts):
    info = remna_user_info(user)
    name = remna_user_name(info, user)
    limit, _ = ip_limit_effective_limit(user, info)
    limit_text = f"{limit} IP" if limit > 0 else "без лимита"
    title = f"<b>ID {html.escape(str(user))}</b>"
    if name:
        title += f" | {html.escape(name)}"
    lines = [f"{title} — {len(rows)}/{html.escape(limit_text)}"]
    lines.extend(remna_block_lines(user, info))
    for row in rows[:8]:
        nodes = ", ".join(row.get("nodes") or []) or "-"
        age = format_age(ts - int(row.get("last_seen") or 0))
        lines.append(f"{html.escape(row['ip'])} — {html.escape(nodes)} — {html.escape(age)} назад")
    if len(rows) > 8:
        lines.append(f"... ещё {len(rows) - 8}")
    return "<blockquote>" + "\n".join(lines) + "</blockquote>"


def ip_limit_report(query=""):
    query = str(query or "").strip()
    ts = now_ts()
    if not query:
        snapshot = ip_limit_snapshot(ts)
        node_names = ip_limit_active_node_names(snapshot)
        lines = [
            "<b>IP лимит</b>",
            ALERT_SEPARATOR,
            "<b>Пример:</b> <code>/ip Нидерланды</code>",
        ]
        if node_names:
            lines += ["", "<b>Активные машины:</b>"]
            lines.extend(f"<code>{html.escape(name)}</code>" for name in node_names[:20])
            if len(node_names) > 20:
                lines.append(f"<i>Ещё машин: {len(node_names) - 20}</i>")
        else:
            lines.append("")
            lines.append("Активных IP-записей пока нет.")
        return "\n".join(lines)

    rows = ip_limit_snapshot(ts, query)
    if not rows:
        node_names = ip_limit_active_node_names(ip_limit_snapshot(ts))
        lines = [
            "<b>IP лимит</b>",
            ALERT_SEPARATOR,
            f"{detail_line('Машина', query)}",
            f"{detail_line('Активных записей', 0)}",
            "",
            "<i>Команда ищет только по названию машины.</i>",
        ]
        if node_names:
            lines += ["", "<b>Активные машины:</b>"]
            lines.extend(f"<code>{html.escape(name)}</code>" for name in node_names[:20])
        return "\n".join(lines)

    grouped = ip_limit_group_rows(rows)
    total_ips = len({row["ip"] for row in rows})
    header = [
        "<b>IP лимит</b>",
        ALERT_SEPARATOR,
        detail_line("Машина", query),
        detail_line("Окно", format_duration_ru(IP_LIMIT_WINDOW_SEC)),
        detail_line("Лимит", f"{IP_LIMIT_MAX_IPS} IP"),
        detail_line("IP", total_ips),
    ]

    blocks = [ip_limit_user_block(user, user_rows, ts) for user, user_rows in grouped[:12]]
    if len(grouped) > 12:
        blocks.append(f"<i>Ещё подписок: {len(grouped) - 12}</i>")
    return "\n".join(header + [""] + blocks)


def ip_limit_limit_text(limit, source):
    if limit <= 0:
        return "без лимита"
    suffix = "персональный" if source == "personal" else "глобальный"
    return f"{limit} IP ({suffix})"


def ip_limit_user_card(query):
    query = str(query or "").strip()
    if not query:
        text = (
            "<b>IP лимит пользователя</b>\n"
            f"{ALERT_SEPARATOR}\n"
            "<b>Пример:</b> <code>/ip_limit 3</code>\n"
            "<b>Telegram ID:</b> <code>/ip_limit tg:646296998</code>"
        )
        return text, None
    info = remna_user_lookup(query)
    if not isinstance(info, dict):
        text = (
            "<b>Не нашёл пользователя</b>\n"
            f"{ALERT_SEPARATOR}\n"
            f"{detail_line('Запрос', query)}\n"
            "<i>Можно Remna ID, Telegram ID через tg:, username или uuid.</i>"
        )
        return text, None
    key = ip_limit_primary_key(query, info)
    ts = now_ts()
    entries = active_ip_limit_entries_for_user(query, info, ts)
    limit, source = ip_limit_effective_limit(query, info)
    active_text = f"{len(entries)}/{limit}" if limit > 0 else f"{len(entries)}/без лимита"
    lines = [
        "<b>IP лимит пользователя</b>",
        ALERT_SEPARATOR,
        detail_line("ID", remna_user_id(info, key)),
    ]
    telegram_id = str(info.get("telegramId") or "").strip()
    if telegram_id:
        lines.append(detail_line("Telegram ID", telegram_id))
    lines.extend(remna_detail_lines(key, info, include_hwid=True))
    lines.extend([
        detail_line("Лимит", ip_limit_limit_text(limit, source)),
        detail_line("Окно", format_duration_ru(IP_LIMIT_WINDOW_SEC)),
        detail_line("Активных IP", active_text),
    ])
    with LOCK:
        penalty = ip_limit_db().execute("SELECT enable_at FROM ip_limit_penalties WHERE user = ?", (key,)).fetchone()
        if penalty and int(penalty["enable_at"] or 0) > ts:
            lines.append(detail_line("Отключен до", fmt_time(penalty["enable_at"])))
    ip_lines = []
    for item in entries[:12]:
        nodes = ", ".join(item.get("nodes") or []) or "-"
        age = format_age(ts - int(item.get("last_seen") or 0))
        ip_lines.append(f"{html.escape(item['ip'])} — {html.escape(nodes)} — {html.escape(age)} назад")
    if len(entries) > 12:
        ip_lines.append(f"... ещё {len(entries) - 12}")
    if ip_lines:
        lines.append("<blockquote>" + "\n".join(ip_lines) + "</blockquote>")
    else:
        lines.append("<blockquote>Активных IP сейчас нет.</blockquote>")
    markup = {
        "inline_keyboard": [
            [
                {"text": "Убрать лимит", "callback_data": f"ipl:off:{key}"},
                {"text": "Повысить лимит", "callback_data": f"ipl:raise:{key}"},
            ],
            [{"text": "Обновить", "callback_data": f"ipl:show:{key}"}],
        ]
    }
    return "\n".join(lines), markup


def alert_ip_limit_exceeded(user, entries, info=None):
    ip_lines = []
    for item in entries[:12]:
        nodes = ", ".join(item.get("nodes") or []) or "-"
        ip_lines.append(f"{html.escape(item['ip'])} — {html.escape(nodes)}")
    if len(entries) > 12:
        ip_lines.append(f"... ещё {len(entries) - 12}")

    if not isinstance(info, dict):
        info = remna_user_info(user)
    limit, _ = ip_limit_effective_limit(user, info)
    lines = [
        f"{LOST_EMOJI} #ipLimitExceeded",
        "<b>IP лимит превышен</b>",
        ALERT_SEPARATOR,
        detail_line("ID", user),
    ]
    lines.extend(remna_detail_lines(user, info, include_hwid=True))
    lines.extend([
        detail_line("Активных IP", f"{len(entries)}/{limit if limit > 0 else 'без лимита'}"),
        detail_line("Окно", format_duration_ru(IP_LIMIT_WINDOW_SEC)),
        f"<blockquote>{chr(10).join(ip_lines)}</blockquote>",
    ])
    enforcement = enforce_ip_limit(user, entries, limit, info)
    if enforcement:
        lines.insert(-1, detail_line("Действие", enforcement))
    return send_message("\n".join(lines))


def enforce_ip_limit(user, entries, limit, info=None):
    if not IP_LIMIT_ENFORCE_ENABLED:
        return ""
    if limit <= 0 or len(entries) <= limit:
        return ""
    if not isinstance(info, dict):
        info = remna_user_info(user)
    ts = now_ts()
    enable_at = ts + IP_LIMIT_PENALTY_SEC
    penalty_text = format_duration_ru_for(IP_LIMIT_PENALTY_SEC)
    scheduled_blocks = schedule_ip_limit_blocks(user, entries, info, enable_at)
    block_text = f"Все айпи были дропнуты с ноды на {penalty_text}." if scheduled_blocks > 0 else ""
    if not remna_api_enabled():
        return block_text or "Remna API не настроен"
    if not isinstance(info, dict):
        return block_text or "юзер не найден в Remna API"
    uuid_value = remna_user_uuid(info)
    if not uuid_value:
        return block_text or "у юзера нет uuid"
    status = str(info.get("status") or "").strip().upper()
    if status and status != "ACTIVE":
        if block_text:
            return f"{block_text} Подписка уже {status}."
        return f"не отключал, статус {status}"
    key = ip_limit_primary_key(user, info)
    with LOCK:
        current = ip_limit_db().execute(
            "SELECT enable_at FROM ip_limit_penalties WHERE user = ?",
            (key,),
        ).fetchone()
        if current and int(current["enable_at"] or 0) > ts:
            if block_text:
                return f"{block_text} Подписка уже отключена до {fmt_time(current['enable_at'])}."
            return f"уже отключён до {fmt_time(current['enable_at'])}"
    try:
        remna_user_action(uuid_value, "disable")
        clear_ip_limit_cache(info)
    except Exception as exc:
        log(f"ip limit disable failed user={user} uuid={uuid_value}: {exc}")
        if block_text:
            return f"{block_text} Remna disable не сработал."
        return "ошибка disable в Remna API"
    with LOCK:
        ip_limit_db().execute(
            "INSERT INTO ip_limit_penalties(user, uuid, disabled_at, enable_at, reason, last_error) VALUES(?, ?, ?, ?, ?, '') "
            "ON CONFLICT(user) DO UPDATE SET uuid = excluded.uuid, disabled_at = excluded.disabled_at, enable_at = excluded.enable_at, reason = excluded.reason, last_error = ''",
            (key, uuid_value, ts, enable_at, "ip_limit"),
        )
        save_ip_limit_state()
    if block_text:
        return f"Подписка отключена на {penalty_text}. Все айпи были дропнуты с ноды."
    return f"Подписка отключена на {penalty_text}."


def ip_limit_penalty_loop():
    while True:
        try:
            time.sleep(5)
            ts = now_ts()
            due = []
            with LOCK:
                rows = ip_limit_db().execute(
                    "SELECT user, uuid, disabled_at, enable_at, reason, last_error FROM ip_limit_penalties WHERE enable_at <= ?",
                    (ts,),
                ).fetchall()
                due = [(str(row["user"]), dict(row)) for row in rows]
            for key, item in due:
                uuid_value = str(item.get("uuid") or "").strip()
                if not uuid_value:
                    with LOCK:
                        ip_limit_db().execute("DELETE FROM ip_limit_penalties WHERE user = ?", (key,))
                        save_ip_limit_state()
                    continue
                try:
                    remna_user_action(uuid_value, "enable")
                    with LOCK:
                        ip_limit_db().execute("DELETE FROM ip_limit_penalties WHERE user = ?", (key,))
                        save_ip_limit_state()
                    log(f"ip limit penalty lifted: user={key} uuid={uuid_value}")
                    send_message(
                        f"{RESTORED_EMOJI} #ipLimitLifted\n"
                        "<b>IP лимит снят</b>\n"
                        f"{ALERT_SEPARATOR}\n"
                        f"{detail_line('ID', key)}\n"
                        f"{detail_line('Действие', 'доступ восстановлен')}"
                    )
                except Exception as exc:
                    log(f"ip limit enable failed user={key} uuid={uuid_value}: {exc}")
                    with LOCK:
                        ip_limit_db().execute(
                            "UPDATE ip_limit_penalties SET enable_at = ?, last_error = ? WHERE user = ?",
                            (now_ts() + 30, str(exc)[:160], key),
                        )
                        save_ip_limit_state()
        except Exception as exc:
            log(f"ip limit penalty loop failed: {exc}")
            time.sleep(10)


def process_ip_limit_events(events, fallback_node, ts):
    if not IP_LIMIT_ENABLED or not isinstance(events, list):
        return

    touched = set()
    normalized = []
    with LOCK:
        purge_ip_limit_state(ts)
        for raw in events[:IP_LIMIT_MAX_EVENTS]:
            event = normalize_ip_limit_event(raw, fallback_node, ts)
            if not event:
                continue
            touched.add(event["user"])
            normalized.append((event["user"], event["ip"], event["node"], canonical_node_key(event["node"]), event["seen_at"]))
        if normalized:
            ip_limit_db().executemany(
                "INSERT INTO ip_limit_events(user, ip, node, node_key, last_seen) VALUES(?, ?, ?, ?, ?) "
                "ON CONFLICT(user, ip, node) DO UPDATE SET node_key = excluded.node_key, last_seen = max(last_seen, excluded.last_seen)",
                normalized,
            )
            save_ip_limit_state()

    for user in sorted(touched, key=natural_sort_key):
        info = None
        with LOCK:
            purge_ip_limit_state(ts)
            entries = active_ip_limit_entries(user, ts)
            limit, _ = ip_limit_effective_limit(user, None)
            if limit <= 0 or len(entries) <= limit:
                continue
        info = remna_user_info(user)
        with LOCK:
            purge_ip_limit_state(ts)
            entries = active_ip_limit_entries_for_user(user, info, ts)
            limit, _ = ip_limit_effective_limit(user, info)
            if limit <= 0 or len(entries) <= limit:
                continue
            alert_key = ip_limit_primary_key(user, info)
            row = ip_limit_db().execute("SELECT last_alert FROM ip_limit_alerts WHERE user = ?", (alert_key,)).fetchone()
            last_alert = int(row["last_alert"] or 0) if row else 0
            if ts - last_alert < IP_LIMIT_ALERT_COOLDOWN:
                continue
            ip_limit_db().execute(
                "INSERT INTO ip_limit_alerts(user, last_alert) VALUES(?, ?) "
                "ON CONFLICT(user) DO UPDATE SET last_alert = excluded.last_alert",
                (alert_key, ts),
            )
            save_ip_limit_state()
        log(f"ip limit exceeded: user={user} active_ips={len(entries)} limit={limit}")
        alert_ip_limit_exceeded(user, entries, info)


def update_node(payload, remote_ip=""):
    node_id = str(payload.get("id") or payload.get("name") or payload.get("hostname") or "").strip()
    if not node_id:
        raise ValueError("id/name is required")
    current = now_ts()
    scan_alert_node = None
    scan_alert_delta = 0
    record = {
        "id": node_id,
        "name": str(payload.get("name") or node_id),
        "ip": str(remote_ip or payload.get("ip") or ""),
        "uptime_sec": int(payload.get("uptime_sec") or 0),
        "iface": str(payload.get("iface") or ""),
        "hostname": str(payload.get("hostname") or ""),
        "day_total": int(payload.get("day_total") or 0),
        "day_rx": int(payload.get("day_rx") or 0),
        "day_tx": int(payload.get("day_tx") or 0),
        "yesterday_total": int(payload.get("yesterday_total") or 0),
        "yesterday_rx": int(payload.get("yesterday_rx") or 0),
        "yesterday_tx": int(payload.get("yesterday_tx") or 0),
        "month_total": int(payload.get("month_total") or 0),
        "month_rx": int(payload.get("month_rx") or 0),
        "month_tx": int(payload.get("month_tx") or 0),
        "ram_total": int(payload.get("ram_total") or 0),
        "ram_used": int(payload.get("ram_used") or 0),
        "ram_percent": int(payload.get("ram_percent") or 0),
        "cpu_percent": float(payload.get("cpu_percent") or 0),
        "metrics_ok": bool(payload.get("metrics_ok")),
        "scan_wrong_sni_total": int(payload.get("scan_wrong_sni_total") or 0),
        "scan_wrong_sni_sources": int(payload.get("scan_wrong_sni_sources") or 0),
        "scan_wrong_sni_top": normalize_scan_top(payload.get("scan_wrong_sni_top")),
        "error": str(payload.get("error") or ""),
        "updated_at": int(payload.get("updated_at") or current),
        "last_seen": current,
        "offline_alerted": False,
    }
    with LOCK:
        old = NODES.get(node_id, {})
        was_offline = bool(old.get("offline_alerted"))
        if was_offline:
            offline_since = int(old.get("offline_since") or old.get("last_seen") or current)
            record_downtime(current - offline_since)
        scan_alerted_at = int(old.get("scan_alerted_at") or 0)
        record["scan_alerted_at"] = scan_alerted_at
        if old and "scan_wrong_sni_total" in old and SCAN_ALERT_DELTA > 0:
            old_scan_total = int(old.get("scan_wrong_sni_total") or 0)
            scan_delta = record["scan_wrong_sni_total"] - old_scan_total
            if scan_delta >= SCAN_ALERT_DELTA and current - scan_alerted_at >= SCAN_ALERT_COOLDOWN:
                record["scan_alerted_at"] = current
                scan_alert_node = dict(record)
                scan_alert_delta = scan_delta
        canonical = node_canonical_key(record)
        removed = []
        for existing_id, existing_node in list(NODES.items()):
            if existing_id != node_id and node_canonical_key(existing_node) == canonical:
                del NODES[existing_id]
                removed.append(existing_id)
        NODES[node_id] = record
        save_nodes()
    if removed:
        log(f"removed duplicate node records for {node_id}: {', '.join(removed)}")
    if was_offline:
        log(f"node online: {node_id}")
        alert_online(node_id, record)
    if scan_alert_node:
        log(f"scan spike: {node_id} delta={scan_alert_delta}")
        alert_scan_spike(scan_alert_node, scan_alert_delta)
    process_ip_limit_events(payload.get("ip_limit_events"), record.get("name") or node_id, current)
    return record


def authorized(headers):
    if not SECRET:
        return False
    value = headers.get("Authorization", "")
    return value == f"Bearer {SECRET}" or value == SECRET


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        log(fmt % args)

    def send_json(self, code, data):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == "/health":
            self.send_json(200, {"ok": True, "build": COLLECTOR_BUILD})
            return
        if path == "/nodes":
            if not authorized(self.headers):
                self.send_json(401, {"ok": False, "error": "unauthorized"})
                return
            with LOCK:
                self.send_json(200, {"ok": True, "nodes": NODES})
            return
        self.send_json(404, {"ok": False, "error": "not found"})

    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path
        if path != "/push":
            self.send_json(404, {"ok": False, "error": "not found"})
            return
        if not authorized(self.headers):
            self.send_json(401, {"ok": False, "error": "unauthorized"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 65536:
                raise ValueError("bad content length")
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            remote_ip = self.client_address[0] if self.client_address else ""
            node = update_node(payload, remote_ip)
            self.send_json(200, {
                "ok": True,
                "id": node["id"],
                "last_seen": node["last_seen"],
                "ssh_allowed_ips": ssh_allowed_ips_snapshot(),
                "ip_limit_blocks": ip_limit_blocks_for_node(node, now_ts()),
            })
        except Exception as exc:
            self.send_json(400, {"ok": False, "error": str(exc)})


def offline_loop():
    while True:
        try:
            time.sleep(CHECK_INTERVAL)
            current = now_ts()
            changed = False
            alerts = []
            with LOCK:
                for node_id, node in NODES.items():
                    age = current - int(node.get("last_seen", 0) or 0)
                    if age > STALE_SEC and not node.get("offline_alerted"):
                        node["offline_alerted"] = True
                        node["offline_since"] = current
                        record_fall(node)
                        alerts.append((node_id, dict(node), age))
                        changed = True
                if changed:
                    save_nodes()
            for node_id, node, age in alerts:
                log(f"node offline: {node_id} age={age}s")
                alert_offline(node_id, node, age)
        except Exception as exc:
            log(f"offline loop failed: {exc}")
            time.sleep(5)


def load_offset():
    try:
        with open(OFFSET_FILE, "r", encoding="utf-8") as fh:
            return int(fh.read().strip())
    except Exception:
        return None


def save_offset(offset):
    atomic_write(OFFSET_FILE, str(offset))


def load_daily_date():
    try:
        with open(DAILY_FILE, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except Exception:
        return ""


def save_daily_date(value):
    atomic_write(DAILY_FILE, value)


def daily_report_loop():
    last_sent = load_daily_date()
    log(f"daily report time={DAILY_REPORT_TIME} tz={TZ_NAME}")
    while True:
        try:
            current = datetime.now()
            today = current.strftime("%Y-%m-%d")
            if current.strftime("%H:%M") == DAILY_REPORT_TIME and last_sent != today:
                if send_message(aggregate_message()):
                    last_sent = today
                    save_daily_date(today)
                time.sleep(70)
            else:
                time.sleep(20)
        except Exception as exc:
            log(f"daily report failed: {exc}")
            time.sleep(20)


def parse_duration_arg(value):
    text = re.sub(r"\s+", "", str(value or "").lower())
    if not text:
        raise ValueError("empty duration")
    units = {
        "d": 86400, "day": 86400, "days": 86400, "д": 86400, "день": 86400, "дня": 86400, "дней": 86400,
        "h": 3600, "hr": 3600, "hrs": 3600, "hour": 3600, "hours": 3600, "ч": 3600, "час": 3600, "часа": 3600, "часов": 3600,
        "m": 60, "min": 60, "mins": 60, "minute": 60, "minutes": 60, "м": 60, "мин": 60, "минута": 60, "минуты": 60, "минут": 60,
        "s": 1, "sec": 1, "secs": 1, "second": 1, "seconds": 1, "с": 1, "сек": 1, "секунда": 1, "секунды": 1, "секунд": 1,
    }
    total = 0
    pos = 0
    for match in re.finditer(r"(\d+)([a-zа-я]+)", text):
        if match.start() != pos:
            raise ValueError("bad duration")
        amount = int(match.group(1))
        unit = match.group(2)
        if unit not in units:
            raise ValueError("bad unit")
        total += amount * units[unit]
        pos = match.end()
    if pos != len(text) or total <= 0:
        raise ValueError("bad duration")
    return total


def handle_statsrevoke(text):
    parts = text.split(maxsplit=1)
    if len(parts) < 2:
        send_message("<b>Пример:</b> /statsrevoke 50h\nМожно: 90m, 30s, 1h30m, 2ч, full")
        return
    arg = parts[1].strip().lower()
    if arg == "full":
        ts = now_ts()
        with LOCK:
            nodes = dedupe_nodes(NODES.values())
            reset_daily_falls(nodes, ts)
        send_message(
            "<b>Стата за сегодня сброшена</b>\n\n"
            "Downtime: 0 секунд\n"
            "Падений: 0\n"
            "Топ машин: пусто"
        )
        return
    try:
        seconds = parse_duration_arg(arg)
    except Exception:
        send_message("<b>Не понял время.</b>\nПример: /statsrevoke 50h\nМожно: 90m, 30s, 1h30m, 2ч, full")
        return
    with LOCK:
        revoke_downtime(seconds)
        nodes = dedupe_nodes(NODES.values())
    _, _, _, total_downtime = downtime_totals(nodes, now_ts())
    send_message(
        "<b>Downtime скорректирован</b>\n\n"
        f"Вычел: {format_duration_ru(seconds)}\n"
        f"Теперь за сегодня: {format_duration_ru(total_downtime)}"
    )


def delete_node_records(query):
    query = str(query or "").strip()
    needle = canonical_node_key(query)
    if not needle:
        return [], [], 0

    deleted = []
    removed_fall_names = []
    removed_falls = 0
    with LOCK:
        aliases = {needle}
        for node_id, node in list(NODES.items()):
            candidates = [
                node_id,
                node.get("id"),
                node.get("name"),
                node.get("hostname"),
            ]
            if any(canonical_node_key(value) == needle for value in candidates):
                deleted.append((node_id, dict(node)))
                aliases.update(canonical_node_key(value) for value in candidates if value)
                del NODES[node_id]

        if deleted:
            save_nodes()

        falls = ensure_today_falls()
        falls_nodes = falls.setdefault("nodes", {})
        for name in list(falls_nodes.keys()):
            if canonical_node_key(name) in aliases:
                try:
                    removed_falls += int(falls_nodes.get(name, 0) or 0)
                except Exception:
                    pass
                removed_fall_names.append(name)
                del falls_nodes[name]
        if removed_falls:
            falls["total"] = max(0, int(falls.get("total", 0) or 0) - removed_falls)
        if deleted or removed_fall_names:
            save_falls()

    return deleted, removed_fall_names, removed_falls


def handle_delete(text):
    parts = text.split(maxsplit=1)
    if len(parts) < 2 or not parts[1].strip():
        send_message("<b>Пример:</b> /delete Обход №8")
        return

    query = parts[1].strip()
    deleted, removed_fall_names, removed_falls = delete_node_records(query)
    if not deleted and not removed_fall_names:
        send_message(
            "<b>Не нашёл такой обход</b>\n\n"
            f"Запрос: <code>{html.escape(query)}</code>\n"
            "Пиши точное название, например: <code>/delete Обход №8</code>"
        )
        return

    lines = ["<b>Обход удалён</b>", ""]
    if deleted:
        for node_id, node in deleted:
            name = html.escape(str(node.get("name") or node_id))
            ip = html.escape(str(node.get("ip") or "-"))
            lines.append(f"<blockquote>{name}\nIP: {ip}</blockquote>")
    else:
        lines.append("Активной записи уже не было.")
    if removed_fall_names:
        lines += [
            "",
            f"Падений за сегодня вычистил: {removed_falls}",
            "Топ падений: очищен по этому обходу",
        ]
    lines += [
        "",
        "<i>Если машина продолжает пушить стату, она появится снова.</i>",
    ]
    send_message("\n".join(lines))


def handle_add_ip(text):
    parts = text.split(maxsplit=1)
    if len(parts) < 2 or not parts[1].strip():
        send_message("<b>Пример:</b> /add_ip 1.2.3.4")
        return

    raw_ip = parts[1].split()[0].strip()
    try:
        ip, added, all_ips = add_ssh_allowed_ip(raw_ip)
    except Exception:
        send_message(
            "<b>Не понял IP.</b>\n\n"
            "Нужен IPv4, пример: <code>/add_ip 1.2.3.4</code>"
        )
        return

    status = "добавлен" if added else "уже был в списке"
    send_message(
        f"<b>SSH IP {status}</b>\n\n"
        f"<code>{html.escape(ip)}</code>\n\n"
        f"Всего дополнительных IP: {len(all_ips)}\n"
        "<i>Whitelist-машины применят правило при ближайшем push.</i>"
    )


def handle_ip(text):
    parts = text.split(maxsplit=1)
    query = parts[1].strip() if len(parts) > 1 else ""
    send_message(ip_limit_report(query))


def handle_ip_limit(text):
    parts = text.split(maxsplit=1)
    query = parts[1].strip() if len(parts) > 1 else ""
    body, markup = ip_limit_user_card(query)
    send_message(body, reply_markup=markup)


def pending_key(chat_id, from_id):
    return f"{chat_id}:{from_id}"


def set_pending_ip_limit(chat_id, from_id, user_key):
    with LOCK:
        ip_limit_db().execute(
            "INSERT INTO ip_limit_pending(key, action, user, created_at) VALUES(?, ?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET action = excluded.action, user = excluded.user, created_at = excluded.created_at",
            (pending_key(chat_id, from_id), "set_ip_limit", str(user_key), now_ts()),
        )
        save_ip_limit_state()


def pop_pending_ip_limit(chat_id, from_id):
    with LOCK:
        key = pending_key(chat_id, from_id)
        row = ip_limit_db().execute("SELECT action, user, created_at FROM ip_limit_pending WHERE key = ?", (key,)).fetchone()
        if row is not None:
            ip_limit_db().execute("DELETE FROM ip_limit_pending WHERE key = ?", (key,))
            save_ip_limit_state()
            return {"action": str(row["action"]), "user": str(row["user"]), "created_at": int(row["created_at"] or 0)}
        return None


def peek_pending_ip_limit(chat_id, from_id):
    with LOCK:
        key = pending_key(chat_id, from_id)
        row = ip_limit_db().execute("SELECT action, user, created_at FROM ip_limit_pending WHERE key = ?", (key,)).fetchone()
        if not row:
            return None
        item = {"action": str(row["action"]), "user": str(row["user"]), "created_at": int(row["created_at"] or 0)}
        if now_ts() - int(item.get("created_at") or 0) > 600:
            ip_limit_db().execute("DELETE FROM ip_limit_pending WHERE key = ?", (key,))
            save_ip_limit_state()
            return None
        return item


def handle_pending_ip_limit(chat_id, from_id, text):
    pending = peek_pending_ip_limit(chat_id, from_id)
    if not pending or pending.get("action") != "set_ip_limit":
        return False
    value = str(text or "").strip()
    if not re.fullmatch(r"\d{1,3}", value):
        send_message("<b>Нужна цифра.</b>\n\nНапример: <code>5</code>\nОтмена: <code>/cancel</code>")
        return True
    limit = int(value)
    if limit < 1 or limit > 999:
        send_message("<b>Лимит должен быть от 1 до 999.</b>")
        return True
    item = pop_pending_ip_limit(chat_id, from_id)
    user_key = str((item or {}).get("user") or pending.get("user") or "").strip()
    info = remna_user_lookup(user_key)
    set_ip_limit_override(user_key, info, limit)
    body, markup = ip_limit_user_card(user_key)
    send_message(f"<b>IP лимит обновлён</b>\n\n{body}", reply_markup=markup)
    return True


def handle_ip_limit_callback(callback):
    callback_id = str(callback.get("id") or "")
    data = str(callback.get("data") or "")
    from_id = str((callback.get("from") or {}).get("id") or "")
    message = callback.get("message") or {}
    chat_id = str((message.get("chat") or {}).get("id") or CHAT_ID)
    message_id = str(message.get("message_id") or "")
    if chat_id != str(CHAT_ID) or from_id != ALLOWED_USER_ID:
        answer_callback(callback_id, "нет доступа")
        return
    parts = data.split(":", 2)
    if len(parts) != 3 or parts[0] != "ipl":
        answer_callback(callback_id)
        return
    action, user_key = parts[1], parts[2].strip()
    if not user_key:
        answer_callback(callback_id, "пустой юзер")
        return
    info = remna_user_lookup(user_key)
    if action == "off":
        key = set_ip_limit_override(user_key, info, 0)
        answer_callback(callback_id, "лимит убран")
        body, markup = ip_limit_user_card(key)
        if not edit_message_text(chat_id, message_id, body, reply_markup=markup):
            send_message(body, reply_markup=markup)
        return
    if action == "raise":
        set_pending_ip_limit(chat_id, from_id, user_key)
        answer_callback(callback_id, "ответь числом")
        send_message(
            "<b>Новый IP лимит</b>\n\n"
            f"{detail_line('ID', user_key)}\n"
            "Ответь одним числом, например: <code>5</code>\n"
            "Отмена: <code>/cancel</code>"
        )
        return
    if action == "show":
        answer_callback(callback_id, "обновляю")
        body, markup = ip_limit_user_card(user_key)
        if not edit_message_text(chat_id, message_id, body, reply_markup=markup):
            send_message(body, reply_markup=markup)
        return
    answer_callback(callback_id)


def handle_test_alert(text, kind):
    parts = text.split(maxsplit=1)
    if len(parts) < 2 or not parts[1].strip():
        command = "/up" if kind == "up" else "/down"
        send_message(f"<b>Пример:</b> {command} Обход №8")
        return

    query = parts[1].strip()
    node = find_node(query)
    if node is None:
        node = {"id": query, "name": query, "ip": "-", "last_seen": now_ts()}
    if kind == "up":
        send_message(node_alert_message("up", query, node))
    else:
        send_message(node_alert_message("down", query, node, "Тестовая проверка"))


def utf16_slice(text, offset, length):
    try:
        raw = str(text or "").encode("utf-16-le")
        return raw[offset * 2:(offset + length) * 2].decode("utf-16-le", errors="ignore")
    except Exception:
        return ""


def collect_custom_emoji_ids(message):
    result = []
    seen = set()

    def scan(source):
        for text_key, entities_key in (("text", "entities"), ("caption", "caption_entities")):
            text = str(source.get(text_key) or "")
            entities = source.get(entities_key) or []
            for entity in entities:
                if entity.get("type") != "custom_emoji":
                    continue
                emoji_id = str(entity.get("custom_emoji_id") or "").strip()
                if not emoji_id or emoji_id in seen:
                    continue
                seen.add(emoji_id)
                fallback = utf16_slice(text, int(entity.get("offset") or 0), int(entity.get("length") or 0))
                result.append((emoji_id, fallback or "🙂"))

    scan(message)
    reply = message.get("reply_to_message")
    if isinstance(reply, dict):
        scan(reply)
    return result


def handle_emoji(message):
    emojis = collect_custom_emoji_ids(message)
    if not emojis:
        send_message(
            "<b>Не нашёл premium emoji.</b>\n\n"
            "Пример: <code>/emoji 🔥</code>\n"
            "Можно ответить командой <code>/emoji</code> на сообщение с premium emoji."
        )
        return

    lines = ["<b>Custom emoji id:</b>"]
    for emoji_id, fallback in emojis:
        fallback = html.escape(fallback)
        lines += [
            "",
            f"<code>{html.escape(emoji_id)}</code>",
            f"<code>&lt;tg-emoji emoji-id=\"{html.escape(emoji_id)}\"&gt;{fallback}&lt;/tg-emoji&gt;</code>",
        ]
    send_message("\n".join(lines))


def bot_loop():
    offset = load_offset()
    try:
        info = tg_call("getWebhookInfo")
        webhook_url = info.get("result", {}).get("url") or ""
        if webhook_url:
            log(f"deleteWebhook: {webhook_url}")
            tg_call("deleteWebhook", {"drop_pending_updates": "false"})
    except Exception as exc:
        log(f"webhook check failed: {exc}")
    if offset is None:
        try:
            recent = tg_call("getUpdates", {"timeout": 0, "limit": 1, "offset": -1})
            result = recent.get("result") or []
            if result:
                offset = int(result[-1]["update_id"]) + 1
                save_offset(offset)
        except Exception as exc:
            log(f"initial getUpdates failed: {exc}")
    while True:
        try:
            params = {"timeout": 25, "limit": 20, "allowed_updates": json.dumps(["message", "callback_query"])}
            if offset is not None:
                params["offset"] = offset
            updates = tg_call("getUpdates", params, timeout=35).get("result") or []
            for item in updates:
                update_id = int(item.get("update_id", 0))
                offset = update_id + 1
                save_offset(offset)
                callback = item.get("callback_query")
                if isinstance(callback, dict):
                    handle_ip_limit_callback(callback)
                    continue
                message = item.get("message") or {}
                chat_id = str((message.get("chat") or {}).get("id", ""))
                from_id = str((message.get("from") or {}).get("id", ""))
                text = str(message.get("text") or "")
                command = text.split()[0].split("@", 1)[0].lower() if text.split() else ""
                if chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/cancel":
                    pop_pending_ip_limit(chat_id, from_id)
                    send_message("<b>Отменил.</b>")
                    continue
                if chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and not command.startswith("/"):
                    if handle_pending_ip_limit(chat_id, from_id, text):
                        continue
                if chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/stats":
                    send_message(aggregate_message())
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/statsrevoke":
                    handle_statsrevoke(text)
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/delete":
                    handle_delete(text)
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/add_ip":
                    handle_add_ip(text)
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/ip":
                    handle_ip(text)
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/ip_limit":
                    handle_ip_limit(text)
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/down":
                    handle_test_alert(text, "down")
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/up":
                    handle_test_alert(text, "up")
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/emoji":
                    handle_emoji(message)
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/statstest":
                    send_message("<b>Проверка алертов</b>\n\nКоллектор жив, Telegram отправка работает.")
        except Exception as exc:
            log(f"bot loop failed: {exc}")
            time.sleep(5)


def main():
    if not SECRET:
        raise SystemExit("KTO_COLLECTOR_SECRET is empty")
    os.makedirs(STATE_DIR, exist_ok=True)
    load_nodes()
    load_falls()
    load_ssh_allowed_ips()
    load_ip_limit_state()
    threading.Thread(target=offline_loop, daemon=True).start()
    threading.Thread(target=ip_limit_penalty_loop, daemon=True).start()
    threading.Thread(target=bot_loop, daemon=True).start()
    if DAILY_REPORT_TIME:
        threading.Thread(target=daily_report_loop, daemon=True).start()
    server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    log(f"listening http://{LISTEN_HOST}:{LISTEN_PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
