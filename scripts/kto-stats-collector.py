#!/usr/bin/env python3
import html
import hashlib
import hmac
import ipaddress
import json
import math
import os
import queue
import re
import shlex
import socket
import ssl
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

COLLECTOR_BUILD = "v329"
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
                    value = (
                        value[1:-1]
                        .replace('\\"', '"')
                        .replace("\\$", "$")
                        .replace("\\`", "`")
                        .replace("\\\\", "\\")
                    )
                data[key.strip()] = value
    except FileNotFoundError:
        pass
    return data


cfg = load_config(CONFIG)
SSH_BASE_ALLOWED_IPS_DEFAULT = (
    "85.192.48.122",
    "46.28.64.183",
    "146.19.248.67",
    "85.93.9.35",
    "185.31.243.221",
    "94.247.129.92",
    "83.228.242.53",
    "167.254.243.181",
    "5.34.176.116",
    "5.34.178.234",
    "84.38.185.15",
    "193.23.195.222",
)


def parse_ipv4_list(value):
    result = set()
    for item in re.split(r"[\s,;]+", str(value or "").strip()):
        if not item:
            continue
        try:
            address = ipaddress.ip_address(item)
        except ValueError:
            continue
        if address.version == 4:
            result.add(str(address))
    return sorted(result, key=lambda item: tuple(int(part) for part in item.split(".")))


SSH_BASE_ALLOWED_IPS = parse_ipv4_list(
    cfg.get("KTO_COLLECTOR_SSH_BASE_ALLOWED_IPS", " ".join(SSH_BASE_ALLOWED_IPS_DEFAULT))
)
RAW_BASE = cfg.get("KTO_RAW_BASE", "https://raw.githubusercontent.com/Alpha012/kto-optimize/main").rstrip("/")
ALLOW_INSECURE_UPDATE_URL = str(cfg.get("KTO_ALLOW_INSECURE_UPDATE_URL", "0")).lower() in ("1", "yes", "true", "on", "enabled")
LISTEN_HOST = cfg.get("KTO_COLLECTOR_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(cfg.get("KTO_COLLECTOR_LISTEN_PORT", "1337"))
SECRET = cfg.get("KTO_COLLECTOR_SECRET", "")
BOT_TOKEN = cfg.get("KTO_COLLECTOR_BOT_TOKEN", "")
CHAT_ID = cfg.get("KTO_COLLECTOR_CHAT_ID", "")
ALLOWED_USER_ID = str(cfg.get("KTO_COLLECTOR_ALLOWED_USER_ID", "646296998"))
STATE_DIR = cfg.get("KTO_COLLECTOR_STATE_DIR", "/var/lib/kto-stats-collector")
RICH_STATS_ENABLED = str(cfg.get("KTO_COLLECTOR_RICH_STATS_ENABLED", "0")).strip().lower() in ("1", "true", "yes", "on")
STALE_SEC = int(cfg.get("KTO_COLLECTOR_STALE_SEC", "60"))
CHECK_INTERVAL = int(cfg.get("KTO_COLLECTOR_CHECK_INTERVAL", "30"))
try:
    WL_OFFLINE_CONFIRM_SEC = int(cfg.get("KTO_COLLECTOR_WL_OFFLINE_CONFIRM_SEC", "15") or "15")
except Exception:
    WL_OFFLINE_CONFIRM_SEC = 15
WL_OFFLINE_CONFIRM_SEC = max(0, min(WL_OFFLINE_CONFIRM_SEC, 120))
try:
    AUTH_MAX_SKEW_SEC = int(cfg.get("KTO_COLLECTOR_AUTH_MAX_SKEW_SEC", "300") or "300")
except Exception:
    AUTH_MAX_SKEW_SEC = 300
AUTH_MAX_SKEW_SEC = max(30, min(AUTH_MAX_SKEW_SEC, 3600))
try:
    NODES_FLUSH_SEC = float(cfg.get("KTO_COLLECTOR_NODES_FLUSH_SEC", "5") or "5")
except Exception:
    NODES_FLUSH_SEC = 5.0
NODES_FLUSH_SEC = max(1.0, min(NODES_FLUSH_SEC, 60.0))
try:
    BL_STALE_SEC = int(cfg.get("KTO_COLLECTOR_BL_STALE_SEC", "30") or "30")
except Exception:
    BL_STALE_SEC = 30
if BL_STALE_SEC < 5:
    BL_STALE_SEC = 5
try:
    BL_OFFLINE_CONFIRM_SEC = int(cfg.get("KTO_COLLECTOR_BL_OFFLINE_CONFIRM_SEC", "15") or "15")
except Exception:
    BL_OFFLINE_CONFIRM_SEC = 15
if BL_OFFLINE_CONFIRM_SEC < 0:
    BL_OFFLINE_CONFIRM_SEC = 0
if BL_OFFLINE_CONFIRM_SEC > 60:
    BL_OFFLINE_CONFIRM_SEC = 60
try:
    BL_STALE_FALLBACK_SEC = int(cfg.get("KTO_COLLECTOR_BL_STALE_FALLBACK_SEC", "90") or "90")
except Exception:
    BL_STALE_FALLBACK_SEC = 90
if BL_STALE_FALLBACK_SEC < BL_STALE_SEC:
    BL_STALE_FALLBACK_SEC = BL_STALE_SEC
try:
    BL_PUSH_INTERVAL_SEC = int(cfg.get("KTO_COLLECTOR_BL_PUSH_INTERVAL_SEC", "2") or "2")
except Exception:
    BL_PUSH_INTERVAL_SEC = 2
if BL_PUSH_INTERVAL_SEC < 1:
    BL_PUSH_INTERVAL_SEC = 1
if BL_PUSH_INTERVAL_SEC > 3600:
    BL_PUSH_INTERVAL_SEC = 3600
try:
    PUSH_MISS_WINDOW_SEC = int(cfg.get("KTO_COLLECTOR_PUSH_MISS_WINDOW_SEC", "60") or "60")
except Exception:
    PUSH_MISS_WINDOW_SEC = 60
if PUSH_MISS_WINDOW_SEC < 10:
    PUSH_MISS_WINDOW_SEC = 10
if PUSH_MISS_WINDOW_SEC > 3600:
    PUSH_MISS_WINDOW_SEC = 3600
try:
    PUSH_MISS_THRESHOLD = int(cfg.get("KTO_COLLECTOR_PUSH_MISS_THRESHOLD", "15") or "15")
except Exception:
    PUSH_MISS_THRESHOLD = 15
if PUSH_MISS_THRESHOLD < 1:
    PUSH_MISS_THRESHOLD = 1
try:
    PUSH_MISS_ALERT_COOLDOWN = int(cfg.get("KTO_COLLECTOR_PUSH_MISS_ALERT_COOLDOWN", "300") or "300")
except Exception:
    PUSH_MISS_ALERT_COOLDOWN = 300
if PUSH_MISS_ALERT_COOLDOWN < 0:
    PUSH_MISS_ALERT_COOLDOWN = 0
OFFLINE_LOOP_SEC = max(1, min(5, CHECK_INTERVAL))
TZ_NAME = cfg.get("KTO_COLLECTOR_TZ", "Europe/Moscow")
DAILY_REPORT_TIME = cfg.get("KTO_COLLECTOR_DAILY_REPORT_TIME", "").strip()
try:
    EXPECTED_NODES = int(cfg.get("KTO_COLLECTOR_EXPECTED_NODES", "10") or "10")
except Exception:
    EXPECTED_NODES = 10
if EXPECTED_NODES < 1:
    EXPECTED_NODES = 10
try:
    SCAN_ALERT_DELTA = int(cfg.get("KTO_COLLECTOR_SCAN_ALERT_DELTA", "0") or "0")
except Exception:
    SCAN_ALERT_DELTA = 0
try:
    SCAN_ALERT_COOLDOWN = int(cfg.get("KTO_COLLECTOR_SCAN_ALERT_COOLDOWN", "600") or "600")
except Exception:
    SCAN_ALERT_COOLDOWN = 600
IP_LIMIT_ENABLED = str(cfg.get("KTO_COLLECTOR_IP_LIMIT_ENABLED", "0")).lower() in ("1", "yes", "true", "on", "enabled")
IP_LIMIT_SOURCE = str(cfg.get("KTO_COLLECTOR_IP_LIMIT_SOURCE", "remna") or "remna").strip().lower()
if IP_LIMIT_SOURCE not in ("remna", "push", "both"):
    IP_LIMIT_SOURCE = "remna"
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
    IP_LIMIT_WINDOW_SEC = int(cfg.get("KTO_COLLECTOR_IP_LIMIT_WINDOW_SEC", "60") or "60")
except Exception:
    IP_LIMIT_WINDOW_SEC = 60
if IP_LIMIT_WINDOW_SEC < 60:
    IP_LIMIT_WINDOW_SEC = 60
try:
    IP_LIMIT_ALERT_COOLDOWN = int(cfg.get("KTO_COLLECTOR_IP_LIMIT_ALERT_COOLDOWN", "600") or "600")
except Exception:
    IP_LIMIT_ALERT_COOLDOWN = 600
if IP_LIMIT_ALERT_COOLDOWN < 60:
    IP_LIMIT_ALERT_COOLDOWN = 60
try:
    IP_LIMIT_SCAN_SEC = int(cfg.get("KTO_COLLECTOR_IP_LIMIT_SCAN_SEC", "60") or "60")
except Exception:
    IP_LIMIT_SCAN_SEC = 60
if IP_LIMIT_SCAN_SEC < 10:
    IP_LIMIT_SCAN_SEC = 10
if IP_LIMIT_SCAN_SEC > 3600:
    IP_LIMIT_SCAN_SEC = 3600
try:
    IP_LIMIT_ALERT_THRESHOLD = int(cfg.get("KTO_COLLECTOR_IP_LIMIT_ALERT_THRESHOLD", "20") or "20")
except Exception:
    IP_LIMIT_ALERT_THRESHOLD = 20
if IP_LIMIT_ALERT_THRESHOLD < 1:
    IP_LIMIT_ALERT_THRESHOLD = 1
if IP_LIMIT_ALERT_THRESHOLD > 10000:
    IP_LIMIT_ALERT_THRESHOLD = 10000
try:
    IP_LIMIT_ALERT_TOP = int(cfg.get("KTO_COLLECTOR_IP_LIMIT_ALERT_TOP", "20") or "20")
except Exception:
    IP_LIMIT_ALERT_TOP = 20
if IP_LIMIT_ALERT_TOP < 1:
    IP_LIMIT_ALERT_TOP = 1
if IP_LIMIT_ALERT_TOP > 100:
    IP_LIMIT_ALERT_TOP = 100
REMNA_API_URL = str(cfg.get("KTO_COLLECTOR_REMNA_API_URL", "") or "").strip().rstrip("/")
REMNA_API_TOKEN = str(cfg.get("KTO_COLLECTOR_REMNA_API_TOKEN", "") or "").strip()
REMNA_API_INSECURE = str(cfg.get("KTO_COLLECTOR_REMNA_API_INSECURE", "0")).lower() in ("1", "yes", "true", "on", "enabled")
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
REMNA_NODE_ALERT_ENABLED = str(cfg.get("KTO_COLLECTOR_REMNA_NODE_ALERT_ENABLED", "1")).lower() in ("1", "yes", "true", "on", "enabled")
try:
    REMNA_NODE_POLL_SEC = int(cfg.get("KTO_COLLECTOR_REMNA_NODE_POLL_SEC", "15") or "15")
except Exception:
    REMNA_NODE_POLL_SEC = 15
if REMNA_NODE_POLL_SEC < 5:
    REMNA_NODE_POLL_SEC = 5
if REMNA_NODE_POLL_SEC > 300:
    REMNA_NODE_POLL_SEC = 300
REMNA_OFFLINE_GUARD_ENABLED = str(cfg.get("KTO_COLLECTOR_REMNA_OFFLINE_GUARD_ENABLED", "1")).lower() in ("1", "yes", "true", "on", "enabled")
try:
    REMNA_OFFLINE_STATE_MAX_AGE_SEC = int(cfg.get("KTO_COLLECTOR_REMNA_OFFLINE_STATE_MAX_AGE_SEC", "60") or "60")
except Exception:
    REMNA_OFFLINE_STATE_MAX_AGE_SEC = 60
if REMNA_OFFLINE_STATE_MAX_AGE_SEC < REMNA_NODE_POLL_SEC:
    REMNA_OFFLINE_STATE_MAX_AGE_SEC = REMNA_NODE_POLL_SEC
if REMNA_OFFLINE_STATE_MAX_AGE_SEC > 600:
    REMNA_OFFLINE_STATE_MAX_AGE_SEC = 600
try:
    REMNA_OFFLINE_LOG_GRACE_SEC = int(cfg.get("KTO_COLLECTOR_REMNA_OFFLINE_LOG_GRACE_SEC", "30") or "30")
except Exception:
    REMNA_OFFLINE_LOG_GRACE_SEC = 30
if REMNA_OFFLINE_LOG_GRACE_SEC < 0:
    REMNA_OFFLINE_LOG_GRACE_SEC = 0
if REMNA_OFFLINE_LOG_GRACE_SEC > 600:
    REMNA_OFFLINE_LOG_GRACE_SEC = 600
try:
    REMNA_TOP_IP_JOB_TIMEOUT_SEC = int(cfg.get("KTO_COLLECTOR_REMNA_TOP_IP_JOB_TIMEOUT_SEC", "25") or "25")
except Exception:
    REMNA_TOP_IP_JOB_TIMEOUT_SEC = 25
if REMNA_TOP_IP_JOB_TIMEOUT_SEC < 5:
    REMNA_TOP_IP_JOB_TIMEOUT_SEC = 5
if REMNA_TOP_IP_JOB_TIMEOUT_SEC > 120:
    REMNA_TOP_IP_JOB_TIMEOUT_SEC = 120
try:
    REMNA_TOP_IP_POLL_SEC = float(cfg.get("KTO_COLLECTOR_REMNA_TOP_IP_POLL_SEC", "0.8") or "0.8")
except Exception:
    REMNA_TOP_IP_POLL_SEC = 0.8
if REMNA_TOP_IP_POLL_SEC < 0.2:
    REMNA_TOP_IP_POLL_SEC = 0.2
if REMNA_TOP_IP_POLL_SEC > 5:
    REMNA_TOP_IP_POLL_SEC = 5
try:
    REMNA_TOP_IP_ACTIVE_SEC = int(cfg.get("KTO_COLLECTOR_REMNA_TOP_IP_ACTIVE_SEC", "60") or "60")
except Exception:
    REMNA_TOP_IP_ACTIVE_SEC = 60
if REMNA_TOP_IP_ACTIVE_SEC < 10:
    REMNA_TOP_IP_ACTIVE_SEC = 10
if REMNA_TOP_IP_ACTIVE_SEC > 3600:
    REMNA_TOP_IP_ACTIVE_SEC = 3600
ASN_LOOKUP_ENABLED = str(cfg.get("KTO_COLLECTOR_ASN_LOOKUP_ENABLED", "1")).lower() in ("1", "yes", "true", "on", "enabled")
ASN_LOOKUP_URL = str(
    cfg.get(
        "KTO_COLLECTOR_ASN_LOOKUP_URL",
        "http://ip-api.com/json/{ip}?fields=status,message,as,isp,org,country,query",
    )
    or ""
).strip()
try:
    ASN_CACHE_SEC = int(cfg.get("KTO_COLLECTOR_ASN_CACHE_SEC", "604800") or "604800")
except Exception:
    ASN_CACHE_SEC = 604800
if ASN_CACHE_SEC < 3600:
    ASN_CACHE_SEC = 3600
try:
    ASN_TIMEOUT_SEC = int(cfg.get("KTO_COLLECTOR_ASN_TIMEOUT_SEC", "2") or "2")
except Exception:
    ASN_TIMEOUT_SEC = 2
if ASN_TIMEOUT_SEC < 1:
    ASN_TIMEOUT_SEC = 1

NODES_FILE = os.path.join(STATE_DIR, "nodes.json")
FALLS_FILE = os.path.join(STATE_DIR, "falls.json")
OFFSET_FILE = os.path.join(STATE_DIR, "telegram_offset")
DAILY_FILE = os.path.join(STATE_DIR, "daily_report_date")
SSH_ALLOW_FILE = os.path.join(STATE_DIR, "ssh_allow_ips.json")
SSH_FIREWALL_FILE = os.path.join(STATE_DIR, "ssh_firewall.json")
SNI_ALLOW_FILE = os.path.join(STATE_DIR, "sni_allow.json")
HAPROXY_CONTROL_FILE = os.path.join(STATE_DIR, "haproxy_control.json")
NODE_NAMES_FILE = os.path.join(STATE_DIR, "node_names.json")
BL_GROUPS_FILE = os.path.join(STATE_DIR, "bl_groups.json")
STATS_OFF_FILE = os.path.join(STATE_DIR, "stats_off.json")
ALERTS_OFF_FILE = os.path.join(STATE_DIR, "connection_alerts_off.json")
REMNA_NODES_FILE = os.path.join(STATE_DIR, "remna_nodes.json")
IP_LIMIT_FILE = os.path.join(STATE_DIR, "ip_limit.json")
IP_LIMIT_DB_FILE = os.path.join(STATE_DIR, "ip_limit.sqlite")
NETWORK_RATE_DB_FILE = os.path.join(STATE_DIR, "network_rate.sqlite")
IP_NOTES_FILE = os.path.join(STATE_DIR, "ip_notes.json")
UPDATE_STATE_FILE = os.path.join(STATE_DIR, "update_state.json")
REMOTE_CONTROL_FILE = os.path.join(STATE_DIR, "remote_control.json")
LOCK = threading.RLock()
NODES = {}
FALLS = {}
SSH_ALLOWED_IPS = []
SSH_FIREWALL_STATE = {"nodes": {}}
SNI_STATE = {"nodes": {}, "pending": {}}
HAPROXY_STATE = {"nodes": {}, "sessions": {}, "pending": {}}
NODE_NAME_STATE = {"nodes": {}, "pending": {}}
BL_GROUP_STATE = {"groups": {}, "pending": {}}
STATS_OFF_STATE = {"nodes": {}}
ALERTS_OFF_STATE = {"nodes": {}}
REMNA_NODE_STATE = {"nodes": {}}
UPDATE_STATE = {"current": {}, "results": {}, "local": {}, "retry_tokens": {}, "pending": {}}
IP_NOTE_STATE = {"notes": {}, "pending": {}}
REMOTE_CONTROL_STATE = {"paused": False, "paused_at": 0, "paused_by": ""}
IP_LIMIT_DB = None
NETWORK_RATE_DB = None
NETWORK_RATE_LAST_PURGE_MINUTE = 0
REMNA_USER_CACHE = {}
EVENT_QUEUE = queue.Queue(maxsize=10000)
NODES_DIRTY = False
AUTH_NONCES = {}
AUTH_NONCE_LAST_PURGE = 0
ALERT_SEPARATOR = "➖" * 9
IP_NOTE_MAX_LENGTH = 160
IP_NOTE_PENDING_TTL = 600
HAPROXY_SESSION_TTL = 1800
HAPROXY_MAX_ROUTES = 128
HAPROXY_MAX_TARGETS = 64
HAPROXY_MAX_SNI = 64
HAPROXY_SNI_ANY = "any"
HAPROXY_BACKEND_MAXCONN = "auto"
HAPROXY_LEGACY_BACKEND_MAXCONN = 25_000
HAPROXY_MAX_BANDWIDTH_LIMITS = 64
HAPROXY_MAX_BANDWIDTH_MBIT = 100000
HAPROXY_MACHINE_PAGE_SIZE = 20
HAPROXY_MAX_MACHINE_CHOICES = 1024
NETWORK_RATE_BUCKET_SEC = 60
NETWORK_RATE_RETENTION_SEC = 60 * 60
NETWORK_RATE_MAX_SAMPLE_MS = 5 * 60 * 1000
NETWORK_RATE_MAX_BPS = 100_000_000_000_000
NETWORK_RATE_LINK_TOLERANCE_BPS = 250_000_000
NETWORK_RATE_LINK_TOLERANCE_PERCENT = 25
NETWORK_RATE_SCHEMA_VERSION = 3
RESTORED_EMOJI = '<tg-emoji emoji-id="5449683594425410231">❇️</tg-emoji>'
LOST_EMOJI = '<tg-emoji emoji-id="5447183459602669338">🚨</tg-emoji>'
BL_NODE_ORDER = [
    "финляндия",
    "германия",
    "нидерланды",
    "латвия",
    "латвияhysteria",
    "эстония",
    "швейцария",
    "сингапур",
    "япония",
    "сшамайами",
    "россиясанктпетербург",
    "россияновосибирск",
]
BL_NODE_ORDER_INDEX = {name: index for index, name in enumerate(BL_NODE_ORDER)}

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


def enqueue_event(callback, *args, **kwargs):
    try:
        EVENT_QUEUE.put_nowait((callback, args, kwargs))
        return True
    except queue.Full:
        log(f"event queue full, dropped={getattr(callback, '__name__', 'unknown')}")
        return False


def event_worker_loop():
    while True:
        callback, args, kwargs = EVENT_QUEUE.get()
        try:
            callback(*args, **kwargs)
        except Exception as exc:
            log(f"event worker failed callback={getattr(callback, '__name__', 'unknown')}: {exc}")
        finally:
            EVENT_QUEUE.task_done()


def atomic_write(path, content, keep_backup=False):
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    if keep_backup and os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as current:
                previous = current.read()
            if not isinstance(json.loads(previous), dict):
                raise ValueError("state is not an object")
            atomic_write(f"{path}.bak", previous)
        except Exception as exc:
            log(f"state backup failed path={path}: {exc}")
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        try:
            dir_fd = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def load_nodes():
    global NODES
    os.makedirs(STATE_DIR, exist_ok=True)
    for candidate in (NODES_FILE, f"{NODES_FILE}.bak"):
        try:
            with open(candidate, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            if isinstance(loaded, dict):
                NODES = loaded
                if candidate != NODES_FILE:
                    log(f"nodes state recovered from backup: {candidate}")
                return
        except FileNotFoundError:
            continue
        except Exception as exc:
            log(f"nodes state load failed path={candidate}: {exc}")
    NODES = {}


def save_nodes():
    global NODES_DIRTY
    atomic_write(NODES_FILE, json.dumps(NODES, ensure_ascii=False, indent=2, sort_keys=True), keep_backup=True)
    NODES_DIRTY = False


def schedule_nodes_save():
    global NODES_DIRTY
    NODES_DIRTY = True


def nodes_flush_loop():
    while True:
        try:
            time.sleep(NODES_FLUSH_SEC)
            with LOCK:
                if NODES_DIRTY:
                    save_nodes()
        except Exception as exc:
            log(f"nodes flush failed: {exc}")
            time.sleep(1)


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


def normalize_haproxy_target(value):
    value = re.sub(r"\s+", "", str(value or ""))
    if not value:
        raise ValueError("bad haproxy target")
    if ":" in value:
        parts = value.rsplit(":", 1)
        if len(parts) != 2:
            raise ValueError("bad haproxy target")
        ip, port_text = parts
    else:
        ip, port_text = value, "443"
    ip = normalize_ip(ip)
    if not port_text.isdigit():
        raise ValueError("bad haproxy port")
    port = int(port_text)
    if port < 1 or port > 65535:
        raise ValueError("bad haproxy port")
    return f"{ip}:{port}"


def normalize_haproxy_target_or_empty(value):
    try:
        return normalize_haproxy_target(value)
    except Exception:
        return ""


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
        return sorted(
            set(SSH_BASE_ALLOWED_IPS) | set(SSH_ALLOWED_IPS),
            key=lambda value: tuple(int(part) for part in value.split(".")),
        )


def ssh_allowed_ips_for_node(node):
    return ssh_allowed_ips_snapshot() if node_is_wl(node) else []


def load_ssh_firewall_state():
    global SSH_FIREWALL_STATE
    os.makedirs(STATE_DIR, exist_ok=True)
    try:
        with open(SSH_FIREWALL_FILE, "r", encoding="utf-8") as fh:
            loaded = json.load(fh)
        raw_nodes = loaded.get("nodes") if isinstance(loaded, dict) else {}
        if not isinstance(raw_nodes, dict):
            raw_nodes = {}
        clean_nodes = {}
        for key, item in raw_nodes.items():
            if not isinstance(item, dict) or not bool(item.get("open", True)):
                continue
            node_key = canonical_node_key(key)
            if not node_key:
                continue
            name = clean_display_text(item.get("name") or node_key)[:120] or node_key
            record_key = canonical_node_key(item.get("record_key") or node_key)
            clean_nodes[node_key] = {
                "name": name,
                "record_key": record_key or node_key,
                "open": True,
                "updated_at": int(item.get("updated_at") or 0),
            }
        SSH_FIREWALL_STATE = {"nodes": clean_nodes}
    except Exception:
        SSH_FIREWALL_STATE = {"nodes": {}}


def save_ssh_firewall_state():
    atomic_write(SSH_FIREWALL_FILE, json.dumps(SSH_FIREWALL_STATE, ensure_ascii=False, indent=2, sort_keys=True))


def normalize_sni(value):
    value = str(value or "").strip().lower().rstrip(".")
    value = value.replace("，", ",").replace(";", " ").strip()
    if not value or len(value) > 253:
        raise ValueError("bad sni")
    if value.startswith("*."):
        tail = value[2:]
        wildcard = True
    else:
        tail = value
        wildcard = False
    labels = tail.split(".")
    if len(labels) < 2:
        raise ValueError("bad sni")
    label_re = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    for label in labels:
        if not label_re.fullmatch(label):
            raise ValueError("bad sni")
    return f"*.{tail}" if wildcard else tail


def normalize_sni_list(values):
    result = []
    if isinstance(values, str):
        raw_values = re.split(r"[\s,]+", values)
    elif isinstance(values, list):
        raw_values = values
    else:
        raw_values = []
    for value in raw_values:
        try:
            item = normalize_sni(value)
        except Exception:
            continue
        if item not in result:
            result.append(item)
    return sorted(result, key=natural_sort_key)


def normalize_haproxy_sni_list(values):
    if isinstance(values, str):
        raw_values = re.split(r"[\s,;]+", values.strip()) if values.strip() else []
    elif isinstance(values, list):
        raw_values = [value for value in values if str(value or "").strip()]
    else:
        raw_values = []
    if not raw_values:
        return [HAPROXY_SNI_ANY]

    result = []
    for value in raw_values:
        raw = str(value or "").strip().lower()
        if raw in ("*", "any", "all"):
            if len(raw_values) != 1:
                raise ValueError("any sni cannot be mixed with allow-list")
            return [HAPROXY_SNI_ANY]
        item = normalize_sni(raw)
        if item not in result:
            result.append(item)
    if not result or len(result) > HAPROXY_MAX_SNI:
        raise ValueError("bad haproxy sni count")
    return sorted(result, key=natural_sort_key)


def haproxy_sni_display_values(values):
    normalized = normalize_haproxy_sni_list(values)
    return ["любой"] if normalized == [HAPROXY_SNI_ANY] else normalized


def normalize_haproxy_targets(values):
    if isinstance(values, str):
        raw_values = re.split(r"[\s,;]+", values)
    elif isinstance(values, list):
        raw_values = values
    else:
        raise ValueError("bad haproxy targets")
    result = []
    for value in raw_values:
        if value is None or str(value).strip() == "":
            continue
        target = normalize_haproxy_target(value)
        if target not in result:
            result.append(target)
    if not result or len(result) > HAPROXY_MAX_TARGETS:
        raise ValueError("bad haproxy target count")
    return result


def normalize_haproxy_listen_ip(value):
    value = str(value or "*").strip().lower()
    if value in ("", "*", "any", "all", "default", "0.0.0.0"):
        return "*"
    return normalize_ip(value)


def normalize_haproxy_source_ip(value):
    value = str(value or "default").strip().lower()
    if value in ("", "auto", "default"):
        return "default"
    return normalize_ip(value)


def normalize_haproxy_server_maxconn(value):
    value = str(value if value is not None else "default").strip().lower()
    if value in ("", "0", "auto", "default", "none"):
        return HAPROXY_BACKEND_MAXCONN
    if not value.isdigit():
        raise ValueError("bad haproxy maxconn")
    number = int(value)
    if number < 1 or number > 10_000_000:
        raise ValueError("bad haproxy maxconn")
    if number == HAPROXY_LEGACY_BACKEND_MAXCONN:
        return HAPROXY_BACKEND_MAXCONN
    return number


def haproxy_server_maxconn_label(value):
    normalized = normalize_haproxy_server_maxconn(value)
    if normalized == HAPROXY_BACKEND_MAXCONN:
        return "авто от global и размера пула"
    return f"потолок {normalized} на backend"


def normalize_haproxy_send_proxy_v2(value):
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    text = str(value).strip().lower()
    if text in ("", "0", "n", "no", "off", "false"):
        return False
    if text in ("1", "y", "yes", "on", "true"):
        return True
    raise ValueError("bad haproxy send-proxy-v2")


def normalize_haproxy_route(value):
    if not isinstance(value, dict):
        raise ValueError("bad haproxy route")
    port_text = str(value.get("port") or "").strip()
    if not port_text.isdigit():
        raise ValueError("bad haproxy route port")
    port = int(port_text)
    if port < 1 or port > 65535:
        raise ValueError("bad haproxy route port")
    targets = normalize_haproxy_targets(value.get("targets"))
    if "sni" not in value:
        raise ValueError("missing haproxy sni mode")
    sni = normalize_haproxy_sni_list(value.get("sni"))
    listen_ip = normalize_haproxy_listen_ip(value.get("listen_ip"))
    source_ip = normalize_haproxy_source_ip(value.get("source_ip"))
    if listen_ip != "*":
        source_ip = listen_ip
    elif source_ip != "default":
        listen_ip = source_ip
    return {
        "listen_ip": listen_ip,
        "port": port,
        "targets": targets,
        "sni": sni,
        "source_ip": source_ip,
        "server_maxconn": normalize_haproxy_server_maxconn(value.get("server_maxconn")),
        "send_proxy_v2": normalize_haproxy_send_proxy_v2(value.get("send_proxy_v2")),
    }


def haproxy_route_sort_key(route):
    listen_ip = str(route.get("listen_ip") or "*")
    ip_key = (-1,) if listen_ip == "*" else tuple(int(part) for part in listen_ip.split("."))
    return (ip_key, int(route.get("port") or 0), tuple(route.get("targets") or []))


def normalize_haproxy_routes(values, strict=False):
    if not isinstance(values, list):
        if strict:
            raise ValueError("bad haproxy routes")
        return []
    if len(values) > HAPROXY_MAX_ROUTES:
        if strict:
            raise ValueError("too many haproxy routes")
        values = values[:HAPROXY_MAX_ROUTES]
    result = []
    seen_endpoints = set()
    ports_with_wildcard = set()
    ports_with_exact = set()
    for value in values:
        try:
            route = normalize_haproxy_route(value)
            endpoint = (route["listen_ip"], route["port"])
            if endpoint in seen_endpoints:
                raise ValueError("duplicate haproxy endpoint")
            if route["listen_ip"] == "*":
                if route["port"] in ports_with_exact:
                    raise ValueError("wildcard haproxy conflict")
                ports_with_wildcard.add(route["port"])
            else:
                if route["port"] in ports_with_wildcard:
                    raise ValueError("wildcard haproxy conflict")
                ports_with_exact.add(route["port"])
            seen_endpoints.add(endpoint)
            result.append(route)
        except Exception:
            if strict:
                raise
    return sorted(result, key=haproxy_route_sort_key)


def haproxy_routes_equal(left, right):
    return normalize_haproxy_routes(left) == normalize_haproxy_routes(right)


def haproxy_routes_fingerprint(values):
    normalized = normalize_haproxy_routes(values)
    return hashlib.sha256(
        json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def clean_haproxy_base_hashes(values):
    result = []
    for value in values if isinstance(values, list) else []:
        value = str(value or "").strip().lower()
        if re.fullmatch(r"[0-9a-f]{64}", value) and value not in result:
            result.append(value)
        if len(result) >= 8:
            break
    return result


def normalize_haproxy_apply_result(value):
    if not isinstance(value, dict):
        return {}
    status = str(value.get("status") or "").strip().lower()
    if status not in ("ok", "error"):
        return {}
    try:
        routes = max(0, min(int(value.get("routes") or 0), HAPROXY_MAX_ROUTES))
        updated_at = max(0, int(value.get("updated_at") or 0))
    except Exception:
        routes = 0
        updated_at = 0
    message = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", str(value.get("message") or ""))
    return {
        "status": status,
        "message": clean_display_text(message)[:500],
        "build": clean_display_text(value.get("build") or "")[:40],
        "routes": routes,
        "updated_at": updated_at,
        "command_id": clean_haproxy_command_id(value.get("command_id")),
    }


def normalize_haproxy_bandwidth_limits(values, strict=False):
    if not isinstance(values, list):
        if strict:
            raise ValueError("bad haproxy bandwidth limits")
        return []
    if len(values) > HAPROXY_MAX_BANDWIDTH_LIMITS:
        if strict:
            raise ValueError("too many haproxy bandwidth limits")
        values = values[:HAPROXY_MAX_BANDWIDTH_LIMITS]
    result = {}
    for value in values:
        try:
            if not isinstance(value, dict):
                raise ValueError("bad haproxy bandwidth limit")
            ip_text = normalize_ip(value.get("ip"))
            if not valid_ipv4(ip_text):
                raise ValueError("bad haproxy bandwidth ip")
            rate_text = str(value.get("rate_mbit") if value.get("rate_mbit") is not None else "").strip()
            if not rate_text.isdigit():
                raise ValueError("bad haproxy bandwidth rate")
            rate_mbit = int(rate_text)
            if rate_mbit < 1 or rate_mbit > HAPROXY_MAX_BANDWIDTH_MBIT:
                raise ValueError("bad haproxy bandwidth rate")
            if ip_text in result and result[ip_text] != rate_mbit:
                raise ValueError("duplicate haproxy bandwidth ip")
            result[ip_text] = rate_mbit
        except Exception:
            if strict:
                raise
    return [
        {"ip": ip_text, "rate_mbit": result[ip_text]}
        for ip_text in sorted(result, key=lambda item: int(ipaddress.ip_address(item)))
    ]


def haproxy_bandwidth_limits_equal(left, right):
    return normalize_haproxy_bandwidth_limits(left) == normalize_haproxy_bandwidth_limits(right)


def haproxy_bandwidth_fingerprint(values):
    normalized = normalize_haproxy_bandwidth_limits(values)
    return hashlib.sha256(
        json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def normalize_haproxy_bandwidth_apply_result(value):
    if not isinstance(value, dict):
        return {}
    status = str(value.get("status") or "").strip().lower()
    if status not in ("ok", "error"):
        return {}
    try:
        limits = max(0, min(int(value.get("limits") or 0), HAPROXY_MAX_BANDWIDTH_LIMITS))
        updated_at = max(0, int(value.get("updated_at") or 0))
    except Exception:
        limits = 0
        updated_at = 0
    message = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", str(value.get("message") or ""))
    return {
        "status": status,
        "message": clean_display_text(message)[:500],
        "build": clean_display_text(value.get("build") or "")[:40],
        "limits": limits,
        "updated_at": updated_at,
        "command_id": clean_haproxy_command_id(value.get("command_id")),
    }


def clean_haproxy_command_id(value):
    value = str(value or "").strip().lower()
    return value if re.fullmatch(r"[0-9a-f]{16,64}", value) else ""


def new_haproxy_command_id():
    return uuid.uuid4().hex


def haproxy_apply_result_fingerprint(value):
    if not isinstance(value, dict) or str(value.get("status") or "").lower() != "error":
        return ""
    normalized = {
        "status": "error",
        "message": clean_display_text(value.get("message") or "")[:500],
        "build": clean_display_text(value.get("build") or "")[:40],
        "updated_at": max(0, int(value.get("updated_at") or 0)),
        "command_id": clean_haproxy_command_id(value.get("command_id")),
    }
    return hashlib.sha256(
        json.dumps(normalized, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()


def load_sni_state():
    global SNI_STATE
    os.makedirs(STATE_DIR, exist_ok=True)
    try:
        with open(SNI_ALLOW_FILE, "r", encoding="utf-8") as fh:
            loaded = json.load(fh)
        nodes = loaded.get("nodes") if isinstance(loaded, dict) else {}
        pending = loaded.get("pending") if isinstance(loaded, dict) else {}
        if not isinstance(nodes, dict):
            nodes = {}
        if not isinstance(pending, dict):
            pending = {}
        clean_nodes = {}
        for key, item in nodes.items():
            key = str(key or "").strip()
            if not key or not isinstance(item, dict):
                continue
            values = normalize_sni_list(item.get("values"))
            target = normalize_haproxy_target_or_empty(item.get("target") or item.get("haproxy_target"))
            if values or target:
                clean_item = {
                    "name": str(item.get("name") or key).strip()[:120],
                    "updated_at": int(item.get("updated_at") or 0),
                }
                if values:
                    clean_item["values"] = values
                if target:
                    clean_item["target"] = target
                clean_nodes[key] = clean_item
        SNI_STATE = {"nodes": clean_nodes, "pending": pending}
    except Exception:
        SNI_STATE = {"nodes": {}, "pending": {}}


def save_sni_state():
    atomic_write(SNI_ALLOW_FILE, json.dumps(SNI_STATE, ensure_ascii=False, indent=2, sort_keys=True))


def load_haproxy_state():
    global HAPROXY_STATE
    os.makedirs(STATE_DIR, exist_ok=True)
    try:
        with open(HAPROXY_CONTROL_FILE, "r", encoding="utf-8") as fh:
            loaded = json.load(fh)
    except Exception:
        loaded = {}
    raw_nodes = loaded.get("nodes") if isinstance(loaded, dict) else {}
    raw_sessions = loaded.get("sessions") if isinstance(loaded, dict) else {}
    raw_pending = loaded.get("pending") if isinstance(loaded, dict) else {}
    clean_nodes = {}
    clean_sessions = {}
    clean_pending = {}
    discarded_legacy_commands = 0
    current = now_ts()
    if isinstance(raw_nodes, dict):
        for key, item in raw_nodes.items():
            if not isinstance(item, dict):
                continue
            node_key = str(key or "").strip()[:200]
            routes = normalize_haproxy_routes(item.get("routes"))
            route_base_hashes = clean_haproxy_base_hashes(item.get("routes_base_hashes"))
            if routes and not route_base_hashes:
                routes = []
                discarded_legacy_commands += 1
            has_bandwidth_limits = isinstance(item.get("bandwidth_limits"), list)
            bandwidth_limits = []
            bandwidth_base_hashes = clean_haproxy_base_hashes(item.get("bandwidth_base_hashes"))
            if has_bandwidth_limits:
                try:
                    bandwidth_limits = normalize_haproxy_bandwidth_limits(item.get("bandwidth_limits"), strict=True)
                except Exception:
                    has_bandwidth_limits = False
            if has_bandwidth_limits and not bandwidth_base_hashes:
                has_bandwidth_limits = False
                discarded_legacy_commands += 1
            if not node_key or (not routes and not has_bandwidth_limits):
                continue
            clean_item = {
                "name": clean_display_text(item.get("name") or node_key)[:120],
                "updated_at": int(item.get("updated_at") or 0),
            }
            if routes:
                clean_item["routes"] = routes
                clean_item["routes_command_id"] = (
                    clean_haproxy_command_id(item.get("routes_command_id")) or new_haproxy_command_id()
                )
                clean_item["routes_base_hashes"] = route_base_hashes
                clean_item["routes_error_baseline"] = clean_haproxy_command_id(
                    item.get("routes_error_baseline")
                )
            if has_bandwidth_limits:
                clean_item["bandwidth_limits"] = bandwidth_limits
                clean_item["bandwidth_updated_at"] = int(item.get("bandwidth_updated_at") or 0)
                clean_item["bandwidth_command_id"] = (
                    clean_haproxy_command_id(item.get("bandwidth_command_id")) or new_haproxy_command_id()
                )
                clean_item["bandwidth_base_hashes"] = bandwidth_base_hashes
                clean_item["bandwidth_error_baseline"] = clean_haproxy_command_id(
                    item.get("bandwidth_error_baseline")
                )
            clean_nodes[node_key] = clean_item
    if isinstance(raw_sessions, dict):
        for token, item in raw_sessions.items():
            if not re.fullmatch(r"[0-9a-f]{8,16}", str(token or "")) or not isinstance(item, dict):
                continue
            created_at = int(item.get("created_at") or 0)
            if current - created_at > HAPROXY_SESSION_TTL:
                continue
            node_choices = []
            for value in item.get("node_choices") if isinstance(item.get("node_choices"), list) else []:
                node_key = str(value or "").strip()[:200]
                if node_key and node_key not in node_choices:
                    node_choices.append(node_key)
                if len(node_choices) >= HAPROXY_MAX_MACHINE_CHOICES:
                    break
            try:
                page = max(0, min(int(item.get("page") or 0), 10000))
            except Exception:
                page = 0
            clean_sessions[str(token)] = {
                "node_key": str(item.get("node_key") or "")[:200],
                "node_name": clean_display_text(item.get("node_name") or "")[:120],
                "node_choices": node_choices,
                "page": page,
                "selected_ip": str(item.get("selected_ip") or "")[:64],
                "chat_id": str(item.get("chat_id") or "")[:64],
                "message_id": str(item.get("message_id") or "")[:64],
                "created_at": created_at,
            }
    if isinstance(raw_pending, dict):
        for key, item in raw_pending.items():
            if not isinstance(item, dict):
                continue
            created_at = int(item.get("created_at") or 0)
            if current - created_at <= HAPROXY_SESSION_TTL:
                clean_pending[str(key)[:160]] = item
    HAPROXY_STATE = {"nodes": clean_nodes, "sessions": clean_sessions, "pending": clean_pending}
    if discarded_legacy_commands:
        log(f"discarded legacy HAProxy command(s) without baseline: {discarded_legacy_commands}")
        atomic_write(
            HAPROXY_CONTROL_FILE,
            json.dumps(HAPROXY_STATE, ensure_ascii=False, indent=2, sort_keys=True),
        )


def save_haproxy_state():
    atomic_write(HAPROXY_CONTROL_FILE, json.dumps(HAPROXY_STATE, ensure_ascii=False, indent=2, sort_keys=True))


def normalize_node_name(value):
    name = clean_display_text(value)
    if not name:
        raise ValueError("empty name")
    if len(name) > 120:
        raise ValueError("too long")
    if re.search(r'["\\$`]', name):
        raise ValueError("bad chars")
    return name


def load_node_name_state():
    global NODE_NAME_STATE
    os.makedirs(STATE_DIR, exist_ok=True)
    try:
        with open(NODE_NAMES_FILE, "r", encoding="utf-8") as fh:
            loaded = json.load(fh)
        nodes = loaded.get("nodes") if isinstance(loaded, dict) else {}
        pending = loaded.get("pending") if isinstance(loaded, dict) else {}
        if not isinstance(nodes, dict):
            nodes = {}
        if not isinstance(pending, dict):
            pending = {}
        clean_nodes = {}
        for key, item in nodes.items():
            key = str(key or "").strip()
            if not key:
                continue
            if isinstance(item, str):
                raw_name = item
                raw_aliases = [key]
                target = ""
                updated_at = 0
            elif isinstance(item, dict):
                raw_name = item.get("name")
                raw_aliases = item.get("aliases") if isinstance(item.get("aliases"), list) else []
                target = canonical_node_key(item.get("target") or "")
                updated_at = int(item.get("updated_at") or 0)
            else:
                continue
            try:
                name = normalize_node_name(raw_name)
            except Exception:
                continue
            name_key = canonical_node_key(name)
            aliases = {canonical_node_key(key)}
            for alias in raw_aliases:
                alias = canonical_node_key(alias)
                if alias and alias != name_key:
                    aliases.add(alias)
            key_uuid = normalize_node_uuid(key[5:]) if key.casefold().startswith("uuid_") else ""
            if key_uuid:
                # Old builds stored hostname/name aliases beside UUID. Shared
                # hostnames made a single rename apply to unrelated machines.
                aliases = {target}
            aliases.discard("")
            clean_item = {
                "name": name,
                "aliases": sorted(aliases, key=natural_sort_key),
                "updated_at": updated_at,
            }
            if target:
                clean_item["target"] = target
            clean_nodes[key] = clean_item
        clean_pending = pending if isinstance(pending, dict) else {}
        NODE_NAME_STATE = {"nodes": clean_nodes, "pending": clean_pending}
    except Exception:
        NODE_NAME_STATE = {"nodes": {}, "pending": {}}


def save_node_name_state():
    atomic_write(NODE_NAMES_FILE, json.dumps(NODE_NAME_STATE, ensure_ascii=False, indent=2, sort_keys=True))


def normalize_bl_group_name(value):
    return normalize_node_name(value)


def bl_group_id_for_name(name):
    base = canonical_node_key(name)
    digest = hashlib.sha1(str(name or "").encode("utf-8", errors="ignore")).hexdigest()[:10]
    if base and re.fullmatch(r"[a-z0-9_]{1,32}", base):
        return f"{base[:32]}{digest}"[:42]
    return f"g{digest}"


def load_bl_group_state():
    global BL_GROUP_STATE
    os.makedirs(STATE_DIR, exist_ok=True)
    try:
        with open(BL_GROUPS_FILE, "r", encoding="utf-8") as fh:
            loaded = json.load(fh)
        raw_groups = loaded.get("groups") if isinstance(loaded, dict) else {}
        raw_pending = loaded.get("pending") if isinstance(loaded, dict) else {}
        if not isinstance(raw_groups, dict):
            raw_groups = {}
        if not isinstance(raw_pending, dict):
            raw_pending = {}
        clean_groups = {}
        seen_names = set()
        for raw_gid, item in raw_groups.items():
            if not isinstance(item, dict):
                continue
            try:
                name = normalize_bl_group_name(item.get("name"))
            except Exception:
                continue
            name_key = canonical_node_key(name)
            if not name_key or name_key in seen_names:
                continue
            gid = str(raw_gid or "").strip()
            if not re.fullmatch(r"[A-Za-z0-9_:-]{1,48}", gid):
                gid = bl_group_id_for_name(name)
            nodes = {}
            raw_nodes = item.get("nodes") if isinstance(item.get("nodes"), dict) else {}
            for key, value in raw_nodes.items():
                node_key = canonical_node_key(key)
                if not node_key:
                    continue
                nodes[node_key] = clean_display_text(value or node_key)[:120] or node_key
            try:
                created_at = int(item.get("created_at") or 0)
            except Exception:
                created_at = 0
            try:
                updated_at = int(item.get("updated_at") or created_at)
            except Exception:
                updated_at = created_at
            clean_groups[gid] = {
                "name": name,
                "nodes": nodes,
                "created_at": created_at,
                "updated_at": updated_at,
            }
            seen_names.add(name_key)
        clean_pending = raw_pending if isinstance(raw_pending, dict) else {}
        BL_GROUP_STATE = {"groups": clean_groups, "pending": clean_pending}
    except Exception:
        BL_GROUP_STATE = {"groups": {}, "pending": {}}


def save_bl_group_state():
    atomic_write(BL_GROUPS_FILE, json.dumps(BL_GROUP_STATE, ensure_ascii=False, indent=2))


def load_stats_off_state():
    global STATS_OFF_STATE
    os.makedirs(STATE_DIR, exist_ok=True)
    try:
        with open(STATS_OFF_FILE, "r", encoding="utf-8") as fh:
            loaded = json.load(fh)
        raw_nodes = loaded.get("nodes") if isinstance(loaded, dict) else {}
        if not isinstance(raw_nodes, dict):
            raw_nodes = {}
        clean_nodes = {}
        for key, item in raw_nodes.items():
            node_key = canonical_node_key(key)
            if not node_key:
                continue
            if isinstance(item, dict):
                name = clean_display_text(item.get("name") or node_key)[:120] or node_key
                raw_aliases = item.get("aliases") if isinstance(item.get("aliases"), list) else []
                updated_at = int(item.get("updated_at") or 0)
            else:
                name = clean_display_text(item or node_key)[:120] or node_key
                raw_aliases = []
                updated_at = 0
            aliases = {node_key, canonical_node_key(name)}
            for alias in raw_aliases:
                alias = canonical_node_key(alias)
                if alias:
                    aliases.add(alias)
            aliases.discard("")
            clean_nodes[node_key] = {
                "name": name,
                "aliases": sorted(aliases, key=natural_sort_key),
                "updated_at": updated_at,
            }
        STATS_OFF_STATE = {"nodes": clean_nodes}
    except Exception:
        STATS_OFF_STATE = {"nodes": {}}


def save_stats_off_state():
    atomic_write(STATS_OFF_FILE, json.dumps(STATS_OFF_STATE, ensure_ascii=False, indent=2, sort_keys=True))


def load_alerts_off_state():
    global ALERTS_OFF_STATE
    os.makedirs(STATE_DIR, exist_ok=True)
    try:
        with open(ALERTS_OFF_FILE, "r", encoding="utf-8") as fh:
            loaded = json.load(fh)
        raw_nodes = loaded.get("nodes") if isinstance(loaded, dict) else {}
        if not isinstance(raw_nodes, dict):
            raw_nodes = {}
        clean_nodes = {}
        for key, item in raw_nodes.items():
            node_key = canonical_node_key(key)
            if not node_key:
                continue
            if isinstance(item, dict):
                name = clean_display_text(item.get("name") or node_key)[:120] or node_key
                record_key = canonical_node_key(item.get("record_key") or node_key)
                updated_at = int(item.get("updated_at") or 0)
            else:
                name = clean_display_text(item or node_key)[:120] or node_key
                record_key = node_key
                updated_at = 0
            clean_nodes[node_key] = {
                "name": name,
                "record_key": record_key or node_key,
                "updated_at": updated_at,
            }
        ALERTS_OFF_STATE = {"nodes": clean_nodes}
    except Exception:
        ALERTS_OFF_STATE = {"nodes": {}}


def save_alerts_off_state():
    atomic_write(ALERTS_OFF_FILE, json.dumps(ALERTS_OFF_STATE, ensure_ascii=False, indent=2, sort_keys=True))


def load_remna_node_state():
    global REMNA_NODE_STATE
    os.makedirs(STATE_DIR, exist_ok=True)
    try:
        with open(REMNA_NODES_FILE, "r", encoding="utf-8") as fh:
            loaded = json.load(fh)
        raw_nodes = loaded.get("nodes") if isinstance(loaded, dict) else {}
        if not isinstance(raw_nodes, dict):
            raw_nodes = {}
        clean_nodes = {}
        for key, item in raw_nodes.items():
            if not isinstance(item, dict):
                continue
            node_key = str(key or "").strip()[:120]
            if not node_key:
                continue
            clean_nodes[node_key] = {
                "name": clean_display_text(item.get("name") or node_key)[:120],
                "address": clean_display_text(item.get("address") or "")[:160],
                "disabled": bool(item.get("disabled")),
                "connected": bool(item.get("connected")),
                "seen_at": int(item.get("seen_at") or 0),
                "alerted_at": int(item.get("alerted_at") or 0),
            }
        REMNA_NODE_STATE = {"nodes": clean_nodes}
    except Exception:
        REMNA_NODE_STATE = {"nodes": {}}


def save_remna_node_state():
    atomic_write(REMNA_NODES_FILE, json.dumps(REMNA_NODE_STATE, ensure_ascii=False, indent=2, sort_keys=True))


def clean_update_result(item):
    if not isinstance(item, dict):
        return {}
    job_id = str(item.get("id") or item.get("job_id") or "").strip()[:80]
    status = str(item.get("status") or "").strip().lower()[:24]
    if status not in ("queued", "running", "ok", "error"):
        status = ""
    try:
        updated_at = int(item.get("updated_at") or 0)
    except Exception:
        updated_at = 0
    result = {
        "id": job_id,
        "status": status,
        "build": str(item.get("build") or "").strip()[:40],
        "message": str(item.get("message") or "").strip()[:240],
        "updated_at": updated_at,
    }
    details_text = str(item.get("details_text") or "").strip()
    if details_text:
        result["details_text"] = details_text[:4000]
    details = clean_update_details(item.get("details"))
    top_status_rows = clean_status_panel_rows(item.get("status_rows"))
    if top_status_rows:
        if not details:
            details = {
                "kind": "optimize",
                "mode": "status",
                "source": "kto_status_panel",
                "before": [],
                "after": [],
                "status_rows": top_status_rows,
                "status_fail_count": sum(1 for row in top_status_rows if row.get("status") == "fail"),
                "missing_before": [],
                "fixed_count": 0,
                "remaining_count": 0,
            }
        else:
            details["status_rows"] = top_status_rows
            details["status_fail_count"] = sum(1 for row in top_status_rows if row.get("status") == "fail")
    if details:
        result["details"] = details
    return result


def clean_optimize_rows(value):
    if not isinstance(value, list):
        return []
    rows = []
    for item in value[:30]:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status") or "").strip().lower()[:12]
        if status not in ("ok", "miss", "skip", "error"):
            status = "miss"
        rows.append({
            "id": str(item.get("id") or "").strip()[:80],
            "name": clean_display_text(item.get("name") or item.get("id") or "-")[:80],
            "status": status,
            "current": clean_display_text(item.get("current") or "-")[:160],
            "desired": clean_display_text(item.get("desired") or "-")[:160],
        })
    return rows


def clean_status_panel_rows(value):
    if not isinstance(value, list):
        return []
    rows = []
    for item in value[:80]:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status") or "info").strip().lower()[:12]
        if status not in ("ok", "fail", "info", "warn"):
            status = "info"
        rows.append({
            "section": clean_display_text(item.get("section") or "-")[:80],
            "name": clean_display_text(item.get("name") or "-")[:80],
            "value": clean_display_text(item.get("value") or "-")[:200],
            "status": status,
        })
    return rows


def clean_update_details(value):
    if not isinstance(value, dict):
        return {}
    kind = str(value.get("kind") or "").strip().lower()[:40]
    if kind != "optimize":
        return {}
    mode = str(value.get("mode") or "").strip().lower()[:24]
    if mode not in ("apply", "status"):
        mode = "status"
    before = clean_optimize_rows(value.get("before"))
    after = clean_optimize_rows(value.get("after"))
    status_rows = clean_status_panel_rows(value.get("status_rows"))
    missing_before = []
    raw_missing = value.get("missing_before")
    if isinstance(raw_missing, list):
        for item in raw_missing[:20]:
            name = clean_display_text(item)[:80]
            if name:
                missing_before.append(name)
    if not missing_before:
        missing_before = [row["name"] for row in before if row.get("status") == "miss"][:20]
    remaining_default = sum(1 for row in after if row.get("status") == "miss")
    fixed_default = max(0, len(missing_before) - remaining_default)
    try:
        fixed_count = int(value.get("fixed_count")) if value.get("fixed_count") not in (None, "") else fixed_default
    except Exception:
        fixed_count = fixed_default
    try:
        remaining_count = int(value.get("remaining_count")) if value.get("remaining_count") not in (None, "") else remaining_default
    except Exception:
        remaining_count = remaining_default
    return {
        "kind": "optimize",
        "mode": mode,
        "source": clean_display_text(value.get("source") or "")[:80],
        "before": before,
        "after": after,
        "status_rows": status_rows,
        "status_fail_count": sum(1 for row in status_rows if row.get("status") == "fail"),
        "missing_before": missing_before,
        "fixed_count": fixed_count,
        "remaining_count": remaining_count,
    }


def clean_update_retry_tokens(value):
    if not isinstance(value, dict):
        return {}
    current = now_ts()
    items = []
    for compound, item in value.items():
        if not isinstance(item, dict):
            continue
        compound = str(compound or "").strip()[:80]
        action = str(item.get("action") or "").strip()[:40]
        token = str(item.get("token") or "").strip()[:24]
        key = str(item.get("key") or "").strip()[:120]
        name = clean_display_text(item.get("name") or key)[:120]
        try:
            created_at = int(item.get("created_at") or 0)
        except Exception:
            created_at = 0
        if not compound or not action or not token or not key:
            continue
        if created_at and current - created_at > 7 * 86400:
            continue
        items.append((created_at, compound, {
            "action": action,
            "token": token,
            "key": key,
            "name": name or key,
            "created_at": created_at or current,
        }))
    items.sort(key=lambda row: row[0], reverse=True)
    return {compound: item for _, compound, item in items[:300]}


def clean_update_pending(value):
    if not isinstance(value, dict):
        return {}
    current = now_ts()
    clean = {}
    for key, item in value.items():
        if not isinstance(item, dict):
            continue
        key = str(key or "").strip()[:160]
        action = str(item.get("action") or "").strip()[:40]
        try:
            created_at = int(item.get("created_at") or 0)
        except Exception:
            created_at = 0
        if not key or action != "update_node_list":
            continue
        if created_at and current - created_at > 1800:
            continue
        clean[key] = {"action": action, "created_at": created_at or current}
    return clean


def load_update_state():
    global UPDATE_STATE
    os.makedirs(STATE_DIR, exist_ok=True)
    try:
        with open(UPDATE_STATE_FILE, "r", encoding="utf-8") as fh:
            loaded = json.load(fh)
        if not isinstance(loaded, dict):
            raise ValueError("bad update state")
        current = loaded.get("current") if isinstance(loaded.get("current"), dict) else {}
        current_id = str(current.get("id") or "").strip()[:80]
        clean_current = {}
        if current_id:
            targets = {}
            raw_targets = current.get("targets")
            if isinstance(raw_targets, dict):
                for key, name in raw_targets.items():
                    key = str(key or "").strip()[:120]
                    name = clean_display_text(name or key)[:120]
                    if key:
                        targets[key] = name or key
            elif isinstance(raw_targets, list):
                for item in raw_targets:
                    key = str(item or "").strip()[:120]
                    if key:
                        targets[key] = key
            clean_current = {
                "id": current_id,
                "created_at": int(current.get("created_at") or 0),
                "requested_by": str(current.get("requested_by") or "").strip()[:80],
                "raw_base": str(current.get("raw_base") or RAW_BASE).strip().rstrip("/")[:300],
                "action": str(current.get("action") or "push_update").strip()[:40],
                "scope": str(current.get("scope") or "all").strip()[:40],
                "local_required": bool(current.get("local_required", True)),
                "targets": targets,
                "notified_at": int(current.get("notified_at") or 0),
                "notify_chat_id": str(current.get("notify_chat_id") or "").strip()[:80],
                "notify_message_id": str(current.get("notify_message_id") or "").strip()[:80],
                "quiet_done": bool(current.get("quiet_done", False)),
                "live_targets": bool(current.get("live_targets", False)),
            }
        results = {}
        raw_results = loaded.get("results") if isinstance(loaded.get("results"), dict) else {}
        for key, item in raw_results.items():
            key = str(key or "").strip()[:120]
            result = clean_update_result(item)
            if key and result.get("id") and result.get("status"):
                result["node"] = str(item.get("node") or key).strip()[:120] if isinstance(item, dict) else key
                results[key] = result
        local = clean_update_result(loaded.get("local"))
        retry_tokens = clean_update_retry_tokens(loaded.get("retry_tokens"))
        pending = clean_update_pending(loaded.get("pending"))
        UPDATE_STATE = {"current": clean_current, "results": results, "local": local, "retry_tokens": retry_tokens, "pending": pending}
    except Exception:
        UPDATE_STATE = {"current": {}, "results": {}, "local": {}, "retry_tokens": {}, "pending": {}}


def save_update_state():
    atomic_write(UPDATE_STATE_FILE, json.dumps(UPDATE_STATE, ensure_ascii=False, indent=2, sort_keys=True))


def load_remote_control_state():
    global REMOTE_CONTROL_STATE
    os.makedirs(STATE_DIR, exist_ok=True)
    try:
        with open(REMOTE_CONTROL_FILE, "r", encoding="utf-8") as fh:
            loaded = json.load(fh)
        if not isinstance(loaded, dict):
            raise ValueError("bad remote control state")
        REMOTE_CONTROL_STATE = {
            "paused": loaded.get("paused") is True,
            "paused_at": max(0, int(loaded.get("paused_at") or 0)),
            "paused_by": str(loaded.get("paused_by") or "").strip()[:80],
        }
    except Exception:
        REMOTE_CONTROL_STATE = {"paused": False, "paused_at": 0, "paused_by": ""}


def save_remote_control_state():
    atomic_write(
        REMOTE_CONTROL_FILE,
        json.dumps(REMOTE_CONTROL_STATE, ensure_ascii=False, indent=2, sort_keys=True),
    )


def remote_commands_paused():
    with LOCK:
        return REMOTE_CONTROL_STATE.get("paused") is True


def remote_control_snapshot():
    with LOCK:
        return {
            "paused": REMOTE_CONTROL_STATE.get("paused") is True,
            "paused_at": max(0, int(REMOTE_CONTROL_STATE.get("paused_at") or 0)),
            "paused_by": str(REMOTE_CONTROL_STATE.get("paused_by") or "").strip()[:80],
        }


def discard_remote_command_queues_unlocked():
    haproxy_nodes = HAPROXY_STATE.setdefault("nodes", {})
    haproxy_sessions = HAPROXY_STATE.setdefault("sessions", {})
    haproxy_pending = HAPROXY_STATE.setdefault("pending", {})
    sni_nodes = SNI_STATE.setdefault("nodes", {})
    sni_pending = SNI_STATE.setdefault("pending", {})
    rename_pending = NODE_NAME_STATE.setdefault("pending", {})
    update_current = UPDATE_STATE.get("current") if isinstance(UPDATE_STATE.get("current"), dict) else {}
    update_results = UPDATE_STATE.get("results") if isinstance(UPDATE_STATE.get("results"), dict) else {}
    update_retry = UPDATE_STATE.get("retry_tokens") if isinstance(UPDATE_STATE.get("retry_tokens"), dict) else {}
    update_pending = UPDATE_STATE.get("pending") if isinstance(UPDATE_STATE.get("pending"), dict) else {}

    counts = {
        "haproxy": len(haproxy_nodes),
        "dialogs": len(haproxy_sessions) + len(haproxy_pending) + len(sni_pending) + len(rename_pending) + len(update_pending),
        "sni": len(sni_nodes),
        "updates": (1 if str(update_current.get("id") or "") else 0) + len(update_retry),
        "results": len(update_results),
        "ip_limit_dialogs": 0,
    }

    HAPROXY_STATE["nodes"] = {}
    HAPROXY_STATE["sessions"] = {}
    HAPROXY_STATE["pending"] = {}
    SNI_STATE["nodes"] = {}
    SNI_STATE["pending"] = {}
    NODE_NAME_STATE["pending"] = {}
    UPDATE_STATE["current"] = {}
    UPDATE_STATE["results"] = {}
    UPDATE_STATE["local"] = {}
    UPDATE_STATE["retry_tokens"] = {}
    UPDATE_STATE["pending"] = {}

    db = ip_limit_db()
    row = db.execute("SELECT COUNT(*) AS value FROM ip_limit_pending").fetchone()
    counts["ip_limit_dialogs"] = int(row["value"] if row else 0)
    db.execute("DELETE FROM ip_limit_pending")

    save_haproxy_state()
    save_sni_state()
    save_node_name_state()
    save_update_state()
    save_ip_limit_state()
    counts["total"] = sum(counts.values())
    return counts


def pause_remote_commands(requested_by=""):
    with LOCK:
        cleared = discard_remote_command_queues_unlocked()
        REMOTE_CONTROL_STATE.clear()
        REMOTE_CONTROL_STATE.update({
            "paused": True,
            "paused_at": now_ts(),
            "paused_by": str(requested_by or "").strip()[:80],
        })
        save_remote_control_state()
        return cleared


def resume_remote_commands(requested_by=""):
    with LOCK:
        was_paused = REMOTE_CONTROL_STATE.get("paused") is True
        REMOTE_CONTROL_STATE.clear()
        REMOTE_CONTROL_STATE.update({"paused": False, "paused_at": 0, "paused_by": ""})
        save_remote_control_state()
        return was_paused


def clean_all_active_unlocked():
    current = UPDATE_STATE.get("current") if isinstance(UPDATE_STATE.get("current"), dict) else {}
    return bool(
        str(current.get("id") or "")
        and str(current.get("action") or "") == "push_delete"
        and bool(current.get("live_targets"))
    )


def clean_all_active():
    with LOCK:
        return clean_all_active_unlocked()


def node_scope_matches(node, scope):
    scope = str(scope or "all").strip().lower()
    if scope in ("all", "*"):
        return True
    if scope in ("panel", "collector"):
        return False
    if scope in ("wl", "whitelist"):
        return node_is_wl(node)
    if scope in ("bl", "blacklist", "other", "others"):
        return not node_is_wl(node)
    return True


def current_update_targets(scope="all"):
    targets = {}
    for node in dedupe_nodes(NODES.values()):
        if not node_scope_matches(node, scope):
            continue
        key = node_record_key(node) or node_canonical_key(node)
        if key:
            targets[key] = node_display_name(node, key)[:120]
    return targets


def queue_update_task(requested_by, action="push_update", scope="all", targets=None, local_required=True, notify=None, quiet_done=False, live_targets=False):
    ts = now_ts()
    action = str(action or "push_update").strip()
    if action not in ("push_update", "node_update", "optimize", "optimize_status", "push_delete"):
        action = "push_update"
    scope = str(scope or "all").strip().lower()
    with LOCK:
        selected_targets = targets if isinstance(targets, dict) else current_update_targets(scope)
        job = {
            "id": uuid.uuid4().hex,
            "created_at": ts,
            "requested_by": str(requested_by or "").strip()[:80],
            "raw_base": RAW_BASE,
            "action": action,
            "scope": scope,
            "local_required": bool(local_required),
            "targets": selected_targets,
            "notified_at": 0,
            "notify_chat_id": str((notify or {}).get("chat_id") or "").strip()[:80] if isinstance(notify, dict) else "",
            "notify_message_id": str((notify or {}).get("message_id") or "").strip()[:80] if isinstance(notify, dict) else "",
            "quiet_done": bool(quiet_done),
            "live_targets": bool(live_targets),
        }
        UPDATE_STATE["current"] = job
        UPDATE_STATE["results"] = {}
        if local_required:
            UPDATE_STATE["local"] = {"id": job["id"], "status": "queued", "build": COLLECTOR_BUILD, "message": "", "updated_at": ts}
        else:
            UPDATE_STATE["local"] = {"id": job["id"], "status": "ok", "build": COLLECTOR_BUILD, "message": "collector skipped", "updated_at": ts}
        save_update_state()
    return dict(job)


def update_target_key_for_node(node, targets):
    if not isinstance(targets, dict) or not targets:
        return node_record_key(node) or node_canonical_key(node)
    node_key = node_record_key(node) or node_canonical_key(node)
    if node_key in targets:
        return node_key
    aliases = node_alias_keys(node)
    for target_key, target_name in targets.items():
        if canonical_node_key(target_key) in aliases or canonical_node_key(target_name) in aliases:
            return str(target_key)
    return ""


def update_task_for_node(node):
    if remote_commands_paused():
        return None
    node_key = node_record_key(node) or node_canonical_key(node)
    if not node_key:
        return None
    with LOCK:
        current = UPDATE_STATE.get("current") if isinstance(UPDATE_STATE.get("current"), dict) else {}
        job_id = str(current.get("id") or "")
        if not job_id:
            return None
        scope = str(current.get("scope") or "all").strip().lower()
        live_targets = bool(current.get("live_targets"))
        targets = current.get("targets") if isinstance(current.get("targets"), dict) else {}
        if scope in ("panel", "collector"):
            return None
        if not targets and not live_targets:
            return None
        target_key = update_target_key_for_node(node, targets)
        if targets and not target_key:
            return None
        state_key = target_key or node_key
        result = UPDATE_STATE.setdefault("results", {}).get(state_key)
        action = str(current.get("action") or "push_update")
        if action == "push_delete":
            result_message = clean_display_text((result or {}).get("message") or "") if isinstance(result, dict) else ""
            if isinstance(result, dict) and result.get("id") == job_id and result.get("status") in ("ok", "error") and result_message in ("push delete sent", "push deleted"):
                return None
            task_action = "push_delete"
            if build_number((node or {}).get("push_build")) < 212 and build_number((result or {}).get("build") if isinstance(result, dict) else "") < 212:
                task_action = "push_update"
            task_id = job_id
            if task_action == "push_update":
                task_id = f"{job_id}:bootstrap"
                if isinstance(result, dict) and result.get("id") == task_id and result.get("status") == "error":
                    task_id = f"{task_id}:{now_ts() // 60}"
            if task_action == "push_delete":
                UPDATE_STATE.setdefault("results", {})[state_key] = {
                    "id": job_id,
                    "status": "ok",
                    "build": COLLECTOR_BUILD,
                    "message": "push delete sent",
                    "updated_at": now_ts(),
                    "node": node_display_name(node, node_key)[:120],
                }
                save_update_state()
            return {
                "id": task_id,
                "action": task_action,
                "raw_base": str(current.get("raw_base") or RAW_BASE).rstrip("/"),
                "collector_build": COLLECTOR_BUILD,
            }
        if isinstance(result, dict) and result.get("id") == job_id and result.get("status") in ("ok", "error"):
            return None
        return {
            "id": job_id,
            "action": action,
            "raw_base": str(current.get("raw_base") or RAW_BASE).rstrip("/"),
            "collector_build": COLLECTOR_BUILD,
        }


def process_update_result(raw, node, ts):
    result = clean_update_result(raw)
    if not result.get("id") or not result.get("status"):
        return
    node_key = node_record_key(node) or node_canonical_key(node)
    if not node_key:
        return
    result["node"] = node_display_name(node, node_key)[:120]
    if not result.get("updated_at"):
        result["updated_at"] = ts
    should_check_done = False
    with LOCK:
        current = UPDATE_STATE.get("current") if isinstance(UPDATE_STATE.get("current"), dict) else {}
        current_id = str(current.get("id") or "")
        result_id = str(result.get("id") or "")
        action = str(current.get("action") or "")
        valid_result = result_id == current_id
        if action == "push_delete" and result_id.startswith(f"{current_id}:bootstrap"):
            valid_result = True
        if not current_id or not valid_result:
            log(f"ignored stale update result node={node_key} result={result_id} current={current_id or '-'}")
            return
        scope = str(current.get("scope") or "all").strip().lower()
        live_targets = bool(current.get("live_targets"))
        targets = current.get("targets") if isinstance(current.get("targets"), dict) else {}
        if scope in ("panel", "collector") or (not targets and not live_targets):
            return
        target_key = update_target_key_for_node(node, targets)
        if targets and not target_key:
            return
        state_key = target_key or node_key
        existing = UPDATE_STATE.setdefault("results", {}).get(state_key)
        if isinstance(existing, dict) and existing == result:
            return
        UPDATE_STATE["results"][state_key] = result
        save_update_state()
        should_check_done = True
    if should_check_done:
        enqueue_event(maybe_send_update_done_notification)


def set_local_update_result(job_id, status, message=""):
    with LOCK:
        UPDATE_STATE["local"] = {
            "id": str(job_id or "")[:80],
            "status": str(status or "")[:24],
            "build": COLLECTOR_BUILD,
            "message": str(message or "")[:240],
            "updated_at": now_ts(),
        }
        save_update_state()
    maybe_send_update_done_notification()


def local_collector_update(job):
    job_id = str(job.get("id") or "")
    raw_base = str(job.get("raw_base") or RAW_BASE).rstrip("/")
    if not raw_base.startswith("https://") and not ALLOW_INSECURE_UPDATE_URL:
        set_local_update_result(job_id, "error", "insecure update URL rejected")
        return
    set_local_update_result(job_id, "running", "collector update started")
    script = f"""
set -eu
tmp="$(mktemp)"
cleanup() {{ rm -f "$tmp"; }}
trap cleanup EXIT
curl -fsSL {shlex.quote(raw_base)}/scripts/kto-stats-collector.py -o "$tmp"
[ "$(wc -c < "$tmp")" -ge 10000 ]
[ "$(wc -c < "$tmp")" -le 2097152 ]
[ "$(head -n 1 "$tmp")" = '#!/usr/bin/env python3' ]
grep -Eq '^COLLECTOR_BUILD = "v[0-9]+"$' "$tmp"
python3 -c 'import pathlib, sys; p = pathlib.Path(sys.argv[1]); compile(p.read_text(encoding="utf-8"), str(p), "exec")' "$tmp"
[ ! -f /usr/local/bin/kto-stats-collector ] || cp -f /usr/local/bin/kto-stats-collector /usr/local/bin/kto-stats-collector.prev
install -m 0755 "$tmp" /usr/local/bin/kto-stats-collector
(sleep 1; systemctl restart kto-stats-collector.service) >/dev/null 2>&1 &
"""
    try:
        completed = subprocess.run(["/bin/sh", "-c", script], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=90)
        if completed.returncode == 0:
            set_local_update_result(job_id, "ok", "collector updated, restart scheduled")
            log(f"local collector update queued restart for job={job_id}")
        else:
            message = (completed.stderr or completed.stdout or f"rc={completed.returncode}").replace("\n", " ")[:220]
            set_local_update_result(job_id, "error", message)
            log(f"local collector update failed job={job_id}: {message}")
    except Exception as exc:
        message = str(exc).replace("\n", " ")[:220]
        set_local_update_result(job_id, "error", message)
        log(f"local collector update exception job={job_id}: {message}")


def start_local_collector_update(job):
    threading.Thread(target=local_collector_update, args=(dict(job),), daemon=True).start()


def network_rate_db():
    global NETWORK_RATE_DB
    if NETWORK_RATE_DB is None:
        os.makedirs(STATE_DIR, exist_ok=True)
        NETWORK_RATE_DB = sqlite3.connect(NETWORK_RATE_DB_FILE, check_same_thread=False)
        NETWORK_RATE_DB.row_factory = sqlite3.Row
        NETWORK_RATE_DB.execute("PRAGMA journal_mode=WAL")
        NETWORK_RATE_DB.execute("PRAGMA synchronous=NORMAL")
        NETWORK_RATE_DB.execute("PRAGMA temp_store=MEMORY")
    return NETWORK_RATE_DB


def init_network_rate_db():
    db = network_rate_db()
    version_row = db.execute("PRAGMA user_version").fetchone()
    version = int(version_row[0] if version_row else 0)
    reset_history = version < NETWORK_RATE_SCHEMA_VERSION
    if reset_history:
        db.executescript("""
            DROP TABLE IF EXISTS network_rate_minute;
            DROP TABLE IF EXISTS cpu_minute;
        """)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS network_rate_minute (
            node_key TEXT NOT NULL,
            series_key TEXT NOT NULL,
            iface TEXT NOT NULL DEFAULT '',
            ip TEXT NOT NULL DEFAULT '',
            minute INTEGER NOT NULL,
            rx_bps_ms REAL NOT NULL DEFAULT 0,
            tx_bps_ms REAL NOT NULL DEFAULT 0,
            sample_ms INTEGER NOT NULL DEFAULT 0,
            sample_count INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (node_key, series_key, minute)
        );
        CREATE INDEX IF NOT EXISTS idx_network_rate_minute_time
            ON network_rate_minute(minute);
        CREATE INDEX IF NOT EXISTS idx_network_rate_minute_node
            ON network_rate_minute(node_key, minute);
        CREATE TABLE IF NOT EXISTS cpu_minute (
            node_key TEXT NOT NULL,
            minute INTEGER NOT NULL,
            sample_sum REAL NOT NULL DEFAULT 0,
            sample_count INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (node_key, minute)
        );
        CREATE INDEX IF NOT EXISTS idx_cpu_minute_time
            ON cpu_minute(minute);
        CREATE INDEX IF NOT EXISTS idx_cpu_minute_node
            ON cpu_minute(node_key, minute);
    """)
    if reset_history:
        db.execute(f"PRAGMA user_version = {NETWORK_RATE_SCHEMA_VERSION}")
    db.commit()
    return reset_history


def clear_loaded_network_rate_fields():
    cleared = 0
    fields = (
        "rate_rx_bps",
        "rate_tx_bps",
        "rate_sample_ms",
        "avg_rx_bps_1h",
        "avg_tx_bps_1h",
        "rate_samples_1h",
        "cpu_avg_1h",
        "cpu_samples_1h",
        "peak_rx_bps_24h",
        "peak_tx_bps_24h",
        "rate_samples_24h",
        "cpu_avg_24h",
        "cpu_samples_24h",
    )
    for node in NODES.values():
        if not isinstance(node, dict):
            continue
        for field in fields:
            if node.pop(field, None) is not None:
                cleared += 1
        ip_stats = node.get("ip_stats") if isinstance(node.get("ip_stats"), list) else []
        for entry in ip_stats:
            if not isinstance(entry, dict):
                continue
            for field in fields:
                if entry.pop(field, None) is not None:
                    cleared += 1
    return cleared


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
        CREATE TABLE IF NOT EXISTS ip_limit_nodes (
            node_key TEXT PRIMARY KEY,
            node TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 0,
            enforce INTEGER NOT NULL DEFAULT 0,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS ip_asn_cache (
            ip TEXT PRIMARY KEY,
            updated_at INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT '',
            asn TEXT NOT NULL DEFAULT '',
            isp TEXT NOT NULL DEFAULT '',
            org TEXT NOT NULL DEFAULT '',
            country TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_ip_asn_cache_updated
            ON ip_asn_cache(updated_at);
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
    ip_limit_meta_set("json_migrated", "1")
    db.commit()
    log("ip limit state migrated to sqlite")


def load_ip_limit_state():
    init_ip_limit_db()
    migrate_ip_limit_json_to_db()


def disable_ip_limit_actions_runtime():
    with LOCK:
        db = ip_limit_db()
        blocks = db.execute("SELECT COUNT(*) AS value FROM ip_limit_blocks").fetchone()
        penalties = db.execute("SELECT COUNT(*) AS value FROM ip_limit_penalties").fetchone()
        db.execute("DELETE FROM ip_limit_blocks")
        db.execute("UPDATE ip_limit_nodes SET enforce = 0 WHERE enforce != 0")
        db.execute(
            "UPDATE ip_limit_penalties SET enable_at = 0, reason = 'ip_limit_recovery' "
            "WHERE reason IN ('ip_limit', 'ip_limit_recovery')"
        )
        save_ip_limit_state()
    log(
        "ip limit alert-only recovery: "
        f"blocks={int(blocks['value'] if blocks else 0)} "
        f"penalties={int(penalties['value'] if penalties else 0)}"
    )


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


def normalize_scan_sni_top(value):
    result = []
    if not isinstance(value, list):
        return result
    seen = set()
    for item in value[:20]:
        if not isinstance(item, dict):
            continue
        raw_sni = str(item.get("sni") or "").strip().lower().rstrip(".")
        if not raw_sni or raw_sni in seen or len(raw_sni) > 253:
            continue
        try:
            sni = normalize_sni(raw_sni)
        except Exception:
            continue
        try:
            count = int(item.get("count") or 0)
        except Exception:
            count = 0
        if count > 0:
            seen.add(sni)
            result.append({"sni": sni, "count": count})
    result.sort(key=lambda item: (-int(item.get("count") or 0), natural_sort_key(item.get("sni"))))
    return result[:10]


def normalize_remna_info(item):
    if not isinstance(item, dict):
        return {}
    try:
        restarts = int(item.get("restarts") or 0)
    except Exception:
        restarts = 0
    try:
        error_count = int(item.get("error_count") or 0)
    except Exception:
        error_count = 0
    return {
        "status": clean_display_text(item.get("status") or "")[:80],
        "restarts": max(0, restarts),
        "error_count": max(0, error_count),
        "last_error": clean_display_text(item.get("last_error") or "")[:500],
        "compose_dir": clean_display_text(item.get("compose_dir") or "")[:240],
    }


def asn_info_from_row(row):
    if not row or str(row["status"] or "") != "success":
        return None
    return {
        "asn": str(row["asn"] or "").strip(),
        "isp": str(row["isp"] or "").strip(),
        "org": str(row["org"] or "").strip(),
        "country": str(row["country"] or "").strip(),
    }


def cache_asn_info(ip, status="", asn="", isp="", org="", country=""):
    with LOCK:
        ip_limit_db().execute(
            "INSERT INTO ip_asn_cache(ip, updated_at, status, asn, isp, org, country) VALUES(?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(ip) DO UPDATE SET updated_at = excluded.updated_at, status = excluded.status, "
            "asn = excluded.asn, isp = excluded.isp, org = excluded.org, country = excluded.country",
            (
                normalize_ip(ip),
                now_ts(),
                str(status or "")[:32],
                str(asn or "")[:160],
                str(isp or "")[:160],
                str(org or "")[:160],
                str(country or "")[:80],
            ),
        )
        save_ip_limit_state()


def lookup_asn_info(ip, fetch=True):
    if not ASN_LOOKUP_ENABLED or not ASN_LOOKUP_URL or not valid_ipv4(ip):
        return None
    ip = normalize_ip(ip)
    ts = now_ts()
    stale_row = None
    with LOCK:
        row = ip_limit_db().execute(
            "SELECT updated_at, status, asn, isp, org, country FROM ip_asn_cache WHERE ip = ?",
            (ip,),
        ).fetchone()
        if row:
            if ts - int(row["updated_at"] or 0) < ASN_CACHE_SEC:
                return asn_info_from_row(row)
            stale_row = row
    if not fetch:
        return asn_info_from_row(stale_row)
    try:
        url = ASN_LOOKUP_URL.replace("{ip}", urllib.parse.quote(ip, safe=""))
        req = urllib.request.Request(url, headers={"User-Agent": f"kto-stats/{COLLECTOR_BUILD}"})
        with urllib.request.urlopen(req, timeout=ASN_TIMEOUT_SEC) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="replace"))
        status = str(payload.get("status") or "").strip()
        if status == "success":
            info = {
                "asn": str(payload.get("as") or "").strip(),
                "isp": str(payload.get("isp") or "").strip(),
                "org": str(payload.get("org") or "").strip(),
                "country": str(payload.get("country") or "").strip(),
            }
            cache_asn_info(ip, status="success", **info)
            return info
        cache_asn_info(ip, status=status or "fail")
    except Exception as exc:
        log(f"asn lookup failed ip={ip}: {exc}")
    return asn_info_from_row(stale_row)


def asn_info_text(ip, fetch=True):
    info = lookup_asn_info(ip, fetch=fetch)
    if not info:
        return ""
    parts = []
    seen = set()

    def add(value, prefix=""):
        value = str(value or "").strip()
        if not value:
            return
        text = f"{prefix}{value}" if prefix else value
        key = text.casefold()
        if key not in seen:
            seen.add(key)
            parts.append(text)

    add(info.get("asn"))
    add(info.get("isp"), "ISP: ")
    org = str(info.get("org") or "").strip()
    if org and org.casefold() != str(info.get("isp") or "").strip().casefold():
        add(org, "Org: ")
    return " | ".join(parts)[:220]


def today_key():
    return datetime.fromtimestamp(now_ts()).strftime("%Y-%m-%d")


def ensure_today_falls():
    day = today_key()
    if FALLS.get("date") != day:
        FALLS.clear()
        FALLS.update({
            "date": day,
            "total": 0,
            "downtime_sec": 0,
            "downtime_revoke_sec": 0,
            "nodes": {},
            "downtime_nodes": {},
        })
    elif not isinstance(FALLS.get("nodes"), dict):
        FALLS["nodes"] = {}
    if not isinstance(FALLS.get("downtime_nodes"), dict):
        FALLS["downtime_nodes"] = {}
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


def revoke_fall(node):
    falls = ensure_today_falls()
    name = str(node.get("name") or node.get("id") or "unknown")
    falls["total"] = max(0, int(falls.get("total", 0) or 0) - 1)
    nodes = falls.setdefault("nodes", {})
    if name in nodes:
        value = max(0, int(nodes.get(name, 0) or 0) - 1)
        if value > 0:
            nodes[name] = value
        else:
            nodes.pop(name, None)
    try:
        save_falls()
    except Exception as exc:
        log(f"save falls revoke failed: {exc}")


def record_downtime(seconds, node=None):
    seconds = max(0, int(seconds or 0))
    if seconds <= 0:
        return
    falls = ensure_today_falls()
    falls["downtime_sec"] = int(falls.get("downtime_sec", 0) or 0) + seconds
    if isinstance(node, dict):
        name = str(node.get("name") or node.get("id") or "unknown")
        downtime_nodes = falls.setdefault("downtime_nodes", {})
        downtime_nodes[name] = int(downtime_nodes.get(name, 0) or 0) + seconds
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
        if age > node_stale_sec(node):
            offline_since = int(node.get("offline_since") or last_seen or ts)
            active_downtime += max(0, ts - offline_since)
    falls = ensure_today_falls()
    falls["total"] = 0
    falls["nodes"] = {}
    falls["downtime_nodes"] = {}
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


def normalize_cpu_percent(value):
    try:
        value = float(value)
    except Exception:
        return 0.0
    if not math.isfinite(value) or value < 0:
        return 0.0
    return min(value, 100_000.0)


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


def day_start_ts(ts):
    try:
        current = datetime.fromtimestamp(int(ts))
        return int(datetime(current.year, current.month, current.day).timestamp())
    except Exception:
        return int(ts) - 1


def format_sla_percent(total_downtime, expected_total, ts):
    elapsed = max(1, int(ts) - day_start_ts(ts))
    budget = max(1, int(expected_total or 1)) * elapsed
    percent = 100.0 - ((max(0, int(total_downtime or 0)) * 100.0) / budget)
    if percent < 0:
        percent = 0.0
    if percent > 100:
        percent = 100.0
    if percent >= 99.995:
        return "100%"
    if percent >= 99:
        return f"{percent:.2f}%"
    if percent >= 95:
        return f"{percent:.1f}%"
    return f"{percent:.0f}%"


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


def clean_display_text(value):
    text = str(value or "")
    text = text.replace("\ufeff", "").replace("\ufffd", "")
    text = re.sub(r"[\u200b-\u200f\u202a-\u202e\u2060]", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    text = text.replace("Санкрт-Петербург", "Санкт-Петербург")
    text = text.replace("санкрт-петербург", "санкт-петербург")
    return text


def normalize_note_ip(value):
    text = str(value or "").strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1].strip()
    address = ipaddress.ip_address(text)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return address.compressed


def normalize_ip_note_text(value):
    note = clean_display_text(value)
    if not note:
        raise ValueError("empty note")
    if len(note) > IP_NOTE_MAX_LENGTH:
        raise ValueError("note too long")
    return note


def load_ip_note_state():
    global IP_NOTE_STATE
    os.makedirs(STATE_DIR, exist_ok=True)
    for candidate in (IP_NOTES_FILE, f"{IP_NOTES_FILE}.bak"):
        try:
            with open(candidate, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            if not isinstance(loaded, dict):
                raise ValueError("state is not an object")
            raw_notes = loaded.get("notes")
            raw_pending = loaded.get("pending")
            if not isinstance(raw_notes, dict):
                raw_notes = {}
            if not isinstance(raw_pending, dict):
                raw_pending = {}

            notes = {}
            for raw_ip, raw_item in raw_notes.items():
                try:
                    ip = normalize_note_ip(raw_ip)
                    item = raw_item if isinstance(raw_item, dict) else {"text": raw_item}
                    note = normalize_ip_note_text(item.get("text"))
                    notes[ip] = {
                        "text": note,
                        "updated_at": max(0, int(item.get("updated_at") or 0)),
                    }
                except (TypeError, ValueError):
                    continue

            pending = {}
            ts = now_ts()
            for key, raw_item in raw_pending.items():
                if not isinstance(raw_item, dict):
                    continue
                try:
                    ip = normalize_note_ip(raw_item.get("ip"))
                    created_at = int(raw_item.get("created_at") or 0)
                except (TypeError, ValueError):
                    continue
                if not key or created_at <= 0 or ts - created_at > IP_NOTE_PENDING_TTL:
                    continue
                pending[str(key)] = {"ip": ip, "created_at": created_at}

            IP_NOTE_STATE = {"notes": notes, "pending": pending}
            if candidate != IP_NOTES_FILE:
                log(f"ip notes recovered from backup: {candidate}")
            return
        except FileNotFoundError:
            continue
        except Exception as exc:
            log(f"ip notes load failed path={candidate}: {exc}")
    IP_NOTE_STATE = {"notes": {}, "pending": {}}


def save_ip_note_state():
    atomic_write(
        IP_NOTES_FILE,
        json.dumps(IP_NOTE_STATE, ensure_ascii=False, indent=2, sort_keys=True),
        keep_backup=True,
    )


def ip_note_text(value):
    try:
        ip = normalize_note_ip(value)
    except ValueError:
        return ""
    with LOCK:
        item = IP_NOTE_STATE.setdefault("notes", {}).get(ip)
        if isinstance(item, dict):
            return clean_display_text(item.get("text"))
        return clean_display_text(item)


def ip_with_note_html(value):
    display_ip = clean_display_text(value) or "-"
    note = ip_note_text(display_ip)
    result = html.escape(display_ip)
    if note:
        result += f" | {html.escape(note)}"
    return result


def natural_sort_key(value):
    text = clean_display_text(value).casefold()
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
    text = re.sub(r"[^\w]+", "", clean_display_text(value).casefold(), flags=re.UNICODE)
    parts = []
    for part in re.split(r"(\d+)", text):
        if not part:
            continue
        if part.isdigit():
            parts.append(str(int(part)))
        else:
            parts.append(part)
    return "".join(parts)


def normalize_node_uuid(value):
    try:
        return str(uuid.UUID(str(value or "").strip()))
    except (ValueError, TypeError, AttributeError):
        return ""


def node_canonical_key(node):
    return canonical_node_key(node.get("name") or node.get("id") or "")


def node_group_key(node):
    return canonical_node_key(node_record_key(node) or node_canonical_key(node))


def exact_bypass_record_key(value):
    key = canonical_node_key(value)
    if re.fullmatch(r"обход\d+", key or ""):
        return f"bypass_{key}"
    return ""


def human_name_record_key(node):
    if not isinstance(node, dict):
        return ""
    name = canonical_node_key(node.get("name"))
    if not name or name in ("unknown", "localhost", "none", "null"):
        return ""
    ip = canonical_node_key(node.get("ip"))
    if ip:
        return f"name_{name}_ip_{ip}"
    host = canonical_node_key(node.get("hostname"))
    if host and host not in ("unknown", "localhost", "none", "null") and host != name:
        return f"name_{name}_host_{host}"
    node_id = canonical_node_key(node.get("id"))
    if node_id and node_id not in ("unknown", "localhost", "none", "null") and node_id != name:
        return f"name_{name}_id_{node_id}"
    for field in ("hostname", "id"):
        other = canonical_node_key(node.get(field))
        if other and name == other:
            return ""
    return f"name_{name}"


def node_record_key(node):
    if not isinstance(node, dict):
        return canonical_node_key(node)
    node_uuid = normalize_node_uuid(node.get("node_uuid"))
    if node_uuid:
        return f"uuid_{node_uuid}"
    for field in ("name", "id", "hostname"):
        key = exact_bypass_record_key(node.get(field))
        if key:
            return key
    key = human_name_record_key(node)
    if key:
        return key
    for prefix, field in (("host", "hostname"), ("ip", "ip"), ("id", "id"), ("name", "name")):
        value = canonical_node_key(node.get(field))
        if value and value not in ("unknown", "localhost", "none", "null"):
            return f"{prefix}_{value}"
    return ""


def build_number(value):
    match = re.search(r"(\d+)", str(value or ""))
    if not match:
        return 0
    try:
        return int(match.group(1))
    except Exception:
        return 0


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
        return msg or True
    except Exception as exc:
        log(f"telegram send failed: {exc}")
        return False


def send_rich_message(rich_html, reply_markup=None):
    if not CHAT_ID:
        log("telegram chat id is empty")
        return False
    try:
        payload = {
            "chat_id": CHAT_ID,
            "rich_message": json.dumps({"html": rich_html}, ensure_ascii=False),
        }
        if reply_markup is not None:
            payload["reply_markup"] = json.dumps(reply_markup, ensure_ascii=False)
        result = tg_call("sendRichMessage", payload)
        msg = result.get("result", {})
        log(f"telegram sent rich message_id={msg.get('message_id')} chat_id={msg.get('chat', {}).get('id')}")
        return msg or True
    except Exception as exc:
        log(f"telegram rich send failed: {exc}")
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


def edit_rich_message_text(chat_id, message_id, rich_html, reply_markup=None):
    if not chat_id or not message_id:
        return False
    try:
        payload = {
            "chat_id": chat_id,
            "message_id": message_id,
            "rich_message": json.dumps({"html": rich_html}, ensure_ascii=False),
        }
        if reply_markup is not None:
            payload["reply_markup"] = json.dumps(reply_markup, ensure_ascii=False)
        tg_call("editMessageText", payload, timeout=15)
        log(f"telegram edited rich message_id={message_id} chat_id={chat_id}")
        return True
    except Exception as exc:
        if "message is not modified" in str(exc).lower():
            return True
        log(f"telegram rich edit failed: {exc}")
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
    context = ssl._create_unverified_context() if REMNA_API_INSECURE and url.lower().startswith("https://") else None
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


def remna_dicts(value):
    result = []

    def collect(item):
        if isinstance(item, dict):
            result.append(item)
            for child in item.values():
                collect(child)
        elif isinstance(item, list):
            for child in item:
                collect(child)

    collect(value)
    return result


def remna_list_payload(payload):
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        return []
    for key in ("response", "data", "items", "nodes", "users", "result"):
        value = payload.get(key)
        if isinstance(value, list):
            return value
        if isinstance(value, dict):
            nested = remna_list_payload(value)
            if nested:
                return nested
    return []


def remna_bool(value):
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in ("1", "yes", "true", "on", "enabled")


def remna_get_nodes():
    payload = remna_api_call("/api/nodes")
    items = remna_list_payload(payload)
    nodes = []
    seen = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        uuid_value = str(item.get("uuid") or item.get("id") or "").strip()
        if not uuid_value or uuid_value in seen:
            continue
        seen.add(uuid_value)
        nodes.append(item)
    return nodes


def remna_node_value(item, keys):
    if not isinstance(item, dict):
        return ""
    for key in keys:
        value = item.get(key)
        if value is None or value == "":
            continue
        value = clean_display_text(value)
        if value:
            return value
    return ""


def remna_node_key(item):
    return remna_node_value(item, ("uuid", "id", "nodeUuid", "node_uuid"))


def remna_node_name(item):
    return remna_node_value(item, ("name", "remark", "tag", "nodeName", "node_name"))


def remna_node_address(item):
    value = remna_node_value(item, ("address", "ip", "host", "hostname", "domain", "nodeAddress", "node_address"))
    if "://" in value:
        try:
            parsed = urllib.parse.urlparse(value)
            value = parsed.hostname or value
        except Exception:
            pass
    return value.strip("[]")


def remna_node_is_disabled(item):
    if not isinstance(item, dict):
        return False
    for key in ("isDisabled", "is_disabled", "disabled"):
        if key in item:
            return remna_bool(item.get(key))
    status = str(item.get("status") or item.get("state") or "").strip().lower()
    return status in ("disabled", "disable", "inactive", "off")


def remna_node_is_connected(item):
    if not isinstance(item, dict):
        return False
    for key in ("isConnected", "is_connected", "connected"):
        if key in item:
            return remna_bool(item.get(key))
    return not remna_node_is_disabled(item)


def normalize_remna_node(item, ts=None):
    ts = int(ts or now_ts())
    node_key = remna_node_key(item)
    name = remna_node_name(item)
    address = remna_node_address(item)
    if not node_key:
        seed = name or address
        if not seed:
            return {}
        node_key = canonical_node_key(seed)
    if not name:
        name = address or node_key
    return {
        "key": str(node_key or "")[:120],
        "name": clean_display_text(name or node_key)[:120],
        "address": clean_display_text(address or "")[:160],
        "disabled": remna_node_is_disabled(item),
        "connected": remna_node_is_connected(item),
        "seen_at": ts,
    }


def remna_local_node(info):
    if not isinstance(info, dict):
        return None
    keys = {
        canonical_node_key(info.get("name")),
        canonical_node_key(info.get("address")),
        canonical_node_key(info.get("key")),
    }
    keys.discard("")
    if not keys:
        return None
    with LOCK:
        for node in NODES.values():
            if not isinstance(node, dict):
                continue
            aliases = node_alias_keys(node)
            aliases.add(canonical_node_key(node.get("ip")))
            aliases.add(canonical_node_key(node.get("hostname")))
            aliases.add(canonical_node_key(node.get("id")))
            aliases.discard("")
            if keys.intersection(aliases):
                return dict(node)
    return None


def remna_node_alert_message(kind, info):
    info = info if isinstance(info, dict) else {}
    local = remna_local_node(info)
    if local:
        name = node_display_name(local, info.get("name") or info.get("key") or "unknown")
        address = node_display_ip(local)
    else:
        name = clean_display_text(info.get("name") or info.get("key") or "unknown")
        address = clean_display_text(info.get("address") or "-")
    if kind == "enabled":
        lines = [
            f"{RESTORED_EMOJI} #remnawaveNodeEnabled",
            "<b>Нода включена в Remnawave</b>",
            ALERT_SEPARATOR,
            detail_line("Название", name),
            detail_line("Адрес", address),
        ]
    else:
        lines = [
            f"{LOST_EMOJI} #remnawaveNodeDisabled",
            "<b>Нода отключена в Remnawave</b>",
            ALERT_SEPARATOR,
            detail_line("Название", name),
            detail_line("Причина", "Отключена в панели Remnawave"),
            detail_line("Адрес", address),
        ]
    return "\n".join(lines)


def alert_remna_node(kind, info):
    return send_message(remna_node_alert_message(kind, info))


def remna_job_id(payload):
    for item in remna_dicts(payload):
        for key in ("jobId", "job_id"):
            value = str(item.get(key) or "").strip()
            if value:
                return value
    return ""


def remna_fetch_users_ips_state(payload):
    for item in remna_dicts(payload):
        if "isCompleted" in item or "is_completed" in item or "isFailed" in item or "is_failed" in item:
            return item
    return payload if isinstance(payload, dict) else {}


def remna_fetch_users_ips_result(payload):
    state = remna_fetch_users_ips_state(payload)
    if not isinstance(state, dict):
        return False, False, None
    completed = remna_bool(state.get("isCompleted", state.get("is_completed")))
    failed = remna_bool(state.get("isFailed", state.get("is_failed")))
    result = state.get("result") if isinstance(state.get("result"), dict) else None
    if result is None and isinstance(state.get("data"), dict):
        result = state.get("data")
    if result is None and "users" in state:
        result = state
    return completed, failed, result


def remna_user_ip_items(user_item):
    if not isinstance(user_item, dict):
        return []
    ips = user_item.get("ips")
    if isinstance(ips, list):
        return ips
    ip = user_item.get("ip")
    return [ip] if ip else []


def remna_user_item_id(user_item):
    if not isinstance(user_item, dict):
        return ""
    for key in ("userId", "user_id", "id", "uuid", "userUuid", "user_uuid", "username"):
        value = str(user_item.get(key) or "").strip()
        if value:
            return value
    user = user_item.get("user")
    if isinstance(user, dict):
        for key in ("id", "uuid", "username", "email", "tag"):
            value = str(user.get(key) or "").strip()
            if value:
                return value
    return ""


def remna_user_item_info(user_item):
    if not isinstance(user_item, dict):
        return {}
    user = user_item.get("user")
    if isinstance(user, dict):
        return user
    user_keys = {
        "id", "uuid", "username", "email", "tag", "telegramId", "status",
        "expireAt", "trafficLimitBytes", "userTraffic", "hwidDeviceLimit",
        "hwidLimit", "deviceLimit", "devicesLimit", "hwidDevicesLimit",
        "hwidDeviceCount", "deviceCount",
    }
    if any(key in user_item for key in user_keys):
        return user_item
    return {}


def remna_ip_item_value(ip_item):
    if isinstance(ip_item, str):
        return ip_item
    if not isinstance(ip_item, dict):
        return ""
    for key in ("ip", "clientIp", "client_ip", "address"):
        value = str(ip_item.get(key) or "").strip()
        if value:
            return value
    return ""


def remna_epoch_sec(value, fallback=0):
    try:
        numeric = int(float(value))
    except Exception:
        return int(fallback or 0)
    if numeric > 10_000_000_000:
        numeric = numeric // 1000
    return numeric


def remna_ip_item_last_seen(ip_item, fallback_ts):
    if not isinstance(ip_item, dict):
        return fallback_ts
    for key in ("lastSeen", "last_seen", "seenAt", "seen_at", "connectedAt", "connected_at"):
        value = ip_item.get(key)
        if value is None or value == "":
            continue
        try:
            if isinstance(value, (int, float)):
                return remna_epoch_sec(value, fallback_ts)
            parsed = parse_iso_ts(value)
            if parsed > 0:
                return parsed
        except Exception:
            continue
    return fallback_ts


def remna_active_user_ips_from_result(result, node, ts):
    if not isinstance(result, dict):
        return []
    users = result.get("users") if isinstance(result.get("users"), list) else []
    node_name = str(node.get("name") or result.get("nodeName") or result.get("node_name") or node.get("address") or node.get("uuid") or "-").strip()
    rows = []
    for user_item in users:
        user_id = remna_user_item_id(user_item)
        if not user_id:
            continue
        user_info = remna_user_item_info(user_item)
        if user_info:
            remna_user_cache_put(user_info)
            user_id = ip_limit_primary_key(user_id, user_info) or user_id
        for ip_item in remna_user_ip_items(user_item):
            ip = remna_ip_item_value(ip_item)
            if ip.startswith("::ffff:"):
                ip = ip.rsplit(":", 1)[-1]
            if not valid_ipv4(ip):
                continue
            rows.append({
                "user": user_id,
                "ip": normalize_ip(ip),
                "node": node_name[:80] or "-",
                "last_seen": remna_ip_item_last_seen(ip_item, ts),
                "user_info": user_info,
            })
    return rows


def remna_fetch_active_user_ips():
    if not remna_api_enabled():
        raise RuntimeError("Remnawave API не настроен")
    nodes = remna_get_nodes()
    runnable = []
    skipped = 0
    for node in nodes:
        if remna_bool(node.get("isDisabled")):
            skipped += 1
            continue
        if "isConnected" in node and not remna_bool(node.get("isConnected")):
            skipped += 1
            continue
        uuid_value = str(node.get("uuid") or node.get("id") or "").strip()
        if not uuid_value:
            skipped += 1
            continue
        runnable.append(node)

    jobs = {}
    errors = []
    for node in runnable:
        uuid_value = str(node.get("uuid") or node.get("id") or "").strip()
        quoted = urllib.parse.quote(uuid_value, safe="")
        try:
            payload = remna_api_call(f"/api/ip-control/fetch-users-ips/{quoted}", method="POST")
            job_id = remna_job_id(payload)
            if job_id:
                jobs[job_id] = node
            else:
                errors.append(f"{node.get('name') or uuid_value}: нет jobId")
        except Exception as exc:
            errors.append(f"{node.get('name') or uuid_value}: {exc}")

    deadline = time.monotonic() + REMNA_TOP_IP_JOB_TIMEOUT_SEC
    pending = dict(jobs)
    rows = []
    failed = 0
    while pending and time.monotonic() < deadline:
        completed_jobs = []
        for job_id, node in list(pending.items()):
            quoted_job = urllib.parse.quote(str(job_id), safe="")
            try:
                payload = remna_api_call(f"/api/ip-control/fetch-users-ips/result/{quoted_job}")
                completed, is_failed, result = remna_fetch_users_ips_result(payload)
                if is_failed:
                    failed += 1
                    completed_jobs.append(job_id)
                    continue
                if completed:
                    rows.extend(remna_active_user_ips_from_result(result, node, now_ts()))
                    completed_jobs.append(job_id)
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    continue
                failed += 1
                completed_jobs.append(job_id)
                errors.append(f"{node.get('name') or job_id}: http {exc.code}")
            except Exception as exc:
                failed += 1
                completed_jobs.append(job_id)
                errors.append(f"{node.get('name') or job_id}: {exc}")
        for job_id in completed_jobs:
            pending.pop(job_id, None)
        if pending:
            time.sleep(REMNA_TOP_IP_POLL_SEC)

    return {
        "rows": rows,
        "collected_at": now_ts(),
        "nodes_total": len(nodes),
        "nodes_polled": len(jobs),
        "nodes_skipped": skipped,
        "jobs_pending": len(pending),
        "jobs_failed": failed,
        "errors": errors[:5],
    }


def remna_top_ip_rows(rows, active_after=0):
    grouped = {}
    for row in rows:
        user = str(row.get("user") or "").strip()
        ip = str(row.get("ip") or "").strip()
        if not user or not valid_ipv4(ip):
            continue
        last_seen = remna_epoch_sec(row.get("last_seen"), 0)
        if active_after and last_seen > 0 and last_seen < active_after:
            continue
        entry = grouped.setdefault(user, {"user": user, "ips": {}, "last_seen": 0})
        if isinstance(row.get("user_info"), dict) and row.get("user_info") and not isinstance(entry.get("user_info"), dict):
            entry["user_info"] = row.get("user_info")
        ip_entry = entry["ips"].setdefault(ip, {"ip": ip, "nodes": set(), "last_seen": 0})
        node = str(row.get("node") or "").strip()
        if node:
            ip_entry["nodes"].add(node)
        if last_seen > ip_entry["last_seen"]:
            ip_entry["last_seen"] = last_seen
        if last_seen > entry["last_seen"]:
            entry["last_seen"] = last_seen
    result = []
    for entry in grouped.values():
        ips = []
        for item in entry["ips"].values():
            ips.append({
                "ip": item["ip"],
                "nodes": sorted(item["nodes"], key=natural_sort_key),
                "last_seen": item["last_seen"],
            })
        ips.sort(key=lambda item: (-int(item.get("last_seen") or 0), item.get("ip") or ""))
        result.append({
            "user": entry["user"],
            "ips": ips,
            "last_seen": entry["last_seen"],
            "user_info": entry.get("user_info") if isinstance(entry.get("user_info"), dict) else {},
        })
    result.sort(key=lambda item: (-len(item["ips"]), -int(item.get("last_seen") or 0), natural_sort_key(item["user"])))
    return result


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


def remna_user_hwid_limit(info):
    if not isinstance(info, dict):
        return None
    for key in (
        "hwidDeviceLimit", "hwidDevicesLimit", "hwidLimit", "hwid_limit",
        "deviceLimit", "device_limit", "devicesLimit", "devices_limit",
        "maxDevices", "max_devices",
    ):
        if key not in info:
            continue
        value = info.get(key)
        if value is None or value == "":
            continue
        try:
            return max(0, int(value))
        except Exception:
            continue
    return None


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
        hwid = remna_user_hwid_limit(info)
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


def top_wrong_sni_label(node):
    top = node.get("scan_wrong_sni_names") or []
    if not isinstance(top, list) or not top:
        return ""
    item = top[0] if isinstance(top[0], dict) else {}
    sni = str(item.get("sni") or "").strip()
    if not sni:
        return ""
    try:
        count = int(item.get("count") or 0)
    except Exception:
        count = 0
    if count > 0:
        return f"{sni} x{count}"
    return sni


def wrong_sni_html_line(node):
    scan_total = int(node.get("scan_wrong_sni_total") or 0)
    if scan_total <= 0:
        return ""
    scan_sources = int(node.get("scan_wrong_sni_sources") or 0)
    scan_line = f"Wrong SNI: {scan_total} / {scan_sources} IP"
    top_sni = top_wrong_sni_label(node)
    if top_sni:
        scan_line = f"{scan_line} | {top_sni}"
    return html.escape(scan_line)


def remna_html_line(node):
    remna = node.get("remna") if isinstance(node, dict) else {}
    if not isinstance(remna, dict):
        return ""
    status = clean_display_text(remna.get("status") or "")
    restarts = int(remna.get("restarts") or 0)
    error_count = int(remna.get("error_count") or 0)
    last_error = clean_display_text(remna.get("last_error") or "")
    parts = []
    if status and status != "running":
        parts.append(f"status {status}")
    if restarts > 0:
        parts.append(f"restarts {restarts}")
    if error_count > 0:
        parts.append(f"errors {error_count}")
    if not parts:
        return ""
    line = "Remnawave: " + ", ".join(parts)
    if last_error:
        line = f"{line} | {last_error[:180]}"
    return html.escape(line)


def node_message(node, status=None, compact=False):
    name = html.escape(clean_display_text(node.get("name") or node.get("id") or "unknown"))
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
    wrong_sni_line = wrong_sni_html_line(node)
    if wrong_sni_line:
        cpu_line = f"{cpu_line}\n{wrong_sni_line}"
    remna_line = remna_html_line(node)
    if remna_line:
        cpu_line = f"{cpu_line}\n{remna_line}"
    average_rate = node_average_rate_table_text(node)
    if compact:
        lines = [f"<blockquote><b>{name}</b>\nIP: {ip}</blockquote>", ""]
        if error:
            lines += [
                "<b>Сегодня: ошибка | Вчера: - | Месяц: ошибка</b>",
                "",
                f"Ошибка: {html.escape(error)[:800]}",
                "",
                footer,
            ]
            return "\n".join(lines)
        lines += [
            f"<b>Сегодня: {format_bytes(node.get('day_total', 0))} | Вчера: {format_bytes(node.get('yesterday_total', 0))} | Месяц: {format_bytes(node.get('month_total', 0))}</b>",
        ]
        if average_rate != "-":
            lines.append(f"<b>Средняя ↑/↓ за 1ч: {average_rate}</b>")
        if wrong_sni_line:
            lines += ["", f"<b><i>{wrong_sni_line}</i></b>"]
        if remna_line:
            lines += ["", f"<b><i>{remna_line}</i></b>"]
        lines += ["", footer]
        return "\n".join(lines)
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
    ]
    if average_rate != "-":
        lines.append(f"<b>Средняя ↑/↓ за 1ч: {average_rate}</b>")
    lines += ["", f"<b><i>{ram_line}", f"{cpu_line}</i></b>", "", footer]
    return "\n".join(lines)


def node_name_keys(nodes):
    keys = set()
    for node in nodes:
        for value in (node.get("name"), node.get("id"), node.get("hostname")):
            key = canonical_node_key(value)
            if key:
                keys.add(key)
    return keys


def filter_named_counter(counter, keys):
    if not keys:
        return {}
    result = {}
    for name, value in (counter or {}).items():
        if canonical_node_key(name) in keys:
            result[str(name)] = value
    return result


def downtime_totals(nodes, ts, filtered=False):
    dead_items = []
    active_downtime = 0
    for node in nodes:
        last_seen = int(node.get("last_seen", 0) or 0)
        age = ts - last_seen
        if age > node_stale_sec(node):
            dead_items.append((node, age))
            offline_since = int(node.get("offline_since") or last_seen or ts)
            active_downtime += max(0, ts - offline_since)
    with LOCK:
        falls = dict(ensure_today_falls())
        all_falls_nodes = dict(falls.get("nodes") or {})
        all_downtime_nodes = dict(falls.get("downtime_nodes") or {})
    if filtered:
        keys = node_name_keys(nodes)
        falls_nodes = filter_named_counter(all_falls_nodes, keys)
        downtime_nodes = filter_named_counter(all_downtime_nodes, keys)
        falls["nodes"] = falls_nodes
        falls["total"] = sum(int(value or 0) for value in falls_nodes.values())
        completed_downtime = sum(int(value or 0) for value in downtime_nodes.values())
        revoked_downtime = 0
    else:
        falls_nodes = all_falls_nodes
        completed_downtime = int(falls.get("downtime_sec", 0) or 0)
        revoked_downtime = int(falls.get("downtime_revoke_sec", 0) or 0)
    total_downtime = max(0, completed_downtime + active_downtime - revoked_downtime)
    return dead_items, falls, falls_nodes, total_downtime


def dedupe_nodes(values):
    deduped = {}
    for node in values:
        key = node_record_key(node) or node_canonical_key(node)
        current = deduped.get(key)
        if current is None or int(node.get("last_seen", 0) or 0) > int(current.get("last_seen", 0) or 0):
            deduped[key] = node
    return list(deduped.values())


TRAFFIC_COUNTER_FIELDS = (
    "day_rx",
    "day_tx",
    "day_total",
    "yesterday_rx",
    "yesterday_tx",
    "yesterday_total",
    "month_rx",
    "month_tx",
    "month_total",
)


def normalize_traffic_counter(value):
    try:
        parsed = int(value or 0)
    except Exception:
        parsed = 0
    return max(0, min(parsed, 2**63 - 1))


def normalize_network_counter(value):
    try:
        parsed = int(value or 0)
    except Exception:
        parsed = 0
    return max(0, min(parsed, 2**64 - 1))


def normalize_network_rate(value):
    try:
        parsed = int(value or 0)
    except Exception:
        parsed = 0
    return max(0, min(parsed, NETWORK_RATE_MAX_BPS))


def normalize_network_rate_source(value):
    source = str(value or "").strip().lower()
    if source == "haproxy":
        return "haproxy"
    return "interface"


def normalize_ipv4_text(value):
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return ""
    if address.version == 4:
        return str(address)
    if address.ipv4_mapped is not None:
        return str(address.ipv4_mapped)
    return ""


def normalized_traffic_entry(raw, fallback_iface="", fallback_ip=""):
    raw = raw if isinstance(raw, dict) else {}
    iface = clean_display_text(raw.get("iface") or fallback_iface or "").strip()[:80]
    ip_text = normalize_ipv4_text(raw.get("ip") or fallback_ip)
    entry = {
        "iface": iface,
        "ip": ip_text,
        "error": clean_display_text(raw.get("error") or "").strip()[:300],
        "rate_source": normalize_network_rate_source(raw.get("rate_source")),
        "counter_generation": clean_display_text(raw.get("counter_generation") or "").strip()[:160],
        "counter_rx_bytes": normalize_network_counter(raw.get("counter_rx_bytes")),
        "counter_tx_bytes": normalize_network_counter(raw.get("counter_tx_bytes")),
        "counter_sample_ms": normalize_traffic_counter(raw.get("counter_sample_ms")),
        "link_counter_rx_bytes": normalize_network_counter(raw.get("link_counter_rx_bytes")),
        "link_counter_tx_bytes": normalize_network_counter(raw.get("link_counter_tx_bytes")),
        "link_counter_sample_ms": normalize_traffic_counter(raw.get("link_counter_sample_ms")),
        "rate_rx_bps": normalize_network_rate(raw.get("rate_rx_bps")),
        "rate_tx_bps": normalize_network_rate(raw.get("rate_tx_bps")),
        "rate_sample_ms": normalize_traffic_counter(raw.get("rate_sample_ms")),
        "avg_rx_bps_1h": normalize_network_rate(raw.get("avg_rx_bps_1h")),
        "avg_tx_bps_1h": normalize_network_rate(raw.get("avg_tx_bps_1h")),
        "rate_samples_1h": normalize_traffic_counter(raw.get("rate_samples_1h")),
    }
    for prefix in ("day", "yesterday", "month"):
        rx = normalize_traffic_counter(raw.get(f"{prefix}_rx"))
        tx = normalize_traffic_counter(raw.get(f"{prefix}_tx"))
        supplied_total = normalize_traffic_counter(raw.get(f"{prefix}_total"))
        calculated_total = rx + tx
        entry[f"{prefix}_rx"] = rx
        entry[f"{prefix}_tx"] = tx
        entry[f"{prefix}_total"] = calculated_total if calculated_total > 0 or supplied_total <= 0 else supplied_total
    return entry


def normalize_ip_stats(value, fallback_ip="", fallback_iface="", fallback_record=None):
    fallback_record = fallback_record if isinstance(fallback_record, dict) else {}
    normalized = []
    seen_interfaces = set()
    if isinstance(value, list):
        for raw in value[:64]:
            if not isinstance(raw, dict):
                continue
            entry = normalized_traffic_entry(raw)
            iface_key = entry["iface"].casefold()
            dedupe_key = f"iface:{iface_key}" if iface_key else f"ip:{entry['ip']}"
            if not entry["iface"] and not entry["ip"]:
                continue
            if dedupe_key in seen_interfaces:
                continue
            seen_interfaces.add(dedupe_key)
            normalized.append(entry)

    valid_fallback_ip = normalize_ipv4_text(fallback_ip)
    clean_fallback_iface = clean_display_text(fallback_iface or "").strip()[:80]
    if normalized:
        if valid_fallback_ip:
            filled = False
            for entry in normalized:
                if not entry["ip"] and clean_fallback_iface and entry["iface"] == clean_fallback_iface:
                    entry["ip"] = valid_fallback_ip
                    filled = True
                    break
            if not filled and not normalized[0]["ip"]:
                normalized[0]["ip"] = valid_fallback_ip
        return normalized

    return [normalized_traffic_entry(fallback_record, clean_fallback_iface, valid_fallback_ip)]


def node_ip_stats(node):
    if not isinstance(node, dict):
        return []
    return normalize_ip_stats(node.get("ip_stats"), node.get("ip"), node.get("iface"), node)


def node_ip_stats_by_traffic(node):
    return sorted(
        node_ip_stats(node),
        key=lambda entry: (
            -normalize_traffic_counter(entry.get("day_total")),
            -normalize_traffic_counter(entry.get("month_total")),
            -normalize_traffic_counter(entry.get("yesterday_total")),
            natural_sort_key(entry.get("iface") or ""),
            natural_sort_key(entry.get("ip") or ""),
        ),
    )


def network_rate_series_key(entry):
    if not isinstance(entry, dict):
        return ""
    iface = clean_display_text(entry.get("iface") or "").strip().casefold()[:80]
    ip_text = normalize_ipv4_text(entry.get("ip"))
    source = normalize_network_rate_source(entry.get("rate_source"))
    if iface and ip_text:
        return f"source:{source}|iface:{iface}|ip:{ip_text}"
    if iface:
        return f"source:{source}|iface:{iface}"
    if ip_text:
        return f"source:{source}|ip:{ip_text}"
    return ""


def calculate_counter_rate_sample(entry, previous, rx_field, tx_field, sample_field):
    current_ms = normalize_traffic_counter(entry.get(sample_field))
    previous_ms = normalize_traffic_counter(previous.get(sample_field))
    elapsed_ms = current_ms - previous_ms
    if elapsed_ms < 250 or elapsed_ms > NETWORK_RATE_MAX_SAMPLE_MS:
        return None
    rx_delta = normalize_network_counter(entry.get(rx_field)) - normalize_network_counter(previous.get(rx_field))
    tx_delta = normalize_network_counter(entry.get(tx_field)) - normalize_network_counter(previous.get(tx_field))
    if rx_delta < 0 or tx_delta < 0:
        return None
    return {
        "rx_bps": normalize_network_rate((rx_delta * 8000) // elapsed_ms),
        "tx_bps": normalize_network_rate((tx_delta * 8000) // elapsed_ms),
        "elapsed_ms": elapsed_ms,
    }


def calculate_network_rate_sample(entry, previous):
    if not isinstance(entry, dict) or not isinstance(previous, dict):
        return None
    source = normalize_network_rate_source(entry.get("rate_source"))
    if source != normalize_network_rate_source(previous.get("rate_source")):
        return None
    if source == "haproxy":
        generation = clean_display_text(entry.get("counter_generation") or "").strip()
        previous_generation = clean_display_text(previous.get("counter_generation") or "").strip()
        if not generation or generation != previous_generation:
            return None
    sample = calculate_counter_rate_sample(
        entry,
        previous,
        "counter_rx_bytes",
        "counter_tx_bytes",
        "counter_sample_ms",
    )
    if sample is None:
        return None
    if source == "haproxy":
        link_sample = calculate_counter_rate_sample(
            entry,
            previous,
            "link_counter_rx_bytes",
            "link_counter_tx_bytes",
            "link_counter_sample_ms",
        )
        if link_sample is None:
            return None
        rx_tolerance = max(
            NETWORK_RATE_LINK_TOLERANCE_BPS,
            (link_sample["rx_bps"] * NETWORK_RATE_LINK_TOLERANCE_PERCENT) // 100,
        )
        tx_tolerance = max(
            NETWORK_RATE_LINK_TOLERANCE_BPS,
            (link_sample["tx_bps"] * NETWORK_RATE_LINK_TOLERANCE_PERCENT) // 100,
        )
        if (
            sample["rx_bps"] > link_sample["rx_bps"] + rx_tolerance
            or sample["tx_bps"] > link_sample["tx_bps"] + tx_tolerance
        ):
            return None
    return sample


def purge_metric_history(db, minute):
    global NETWORK_RATE_LAST_PURGE_MINUTE
    if NETWORK_RATE_LAST_PURGE_MINUTE == minute:
        return
    oldest_minute = minute - NETWORK_RATE_RETENTION_SEC + NETWORK_RATE_BUCKET_SEC
    db.execute("DELETE FROM network_rate_minute WHERE minute < ?", (oldest_minute,))
    db.execute("DELETE FROM cpu_minute WHERE minute < ?", (oldest_minute,))
    NETWORK_RATE_LAST_PURGE_MINUTE = minute


def enrich_network_rate_stats(node_key, entries, previous_entries, current):
    node_key = str(node_key or "").strip()[:200]
    if not node_key or not isinstance(entries, list):
        return entries
    previous_map = {}
    for previous in previous_entries if isinstance(previous_entries, list) else []:
        series_key = network_rate_series_key(previous)
        if series_key:
            previous_map[series_key] = previous

    minute = (int(current) // NETWORK_RATE_BUCKET_SEC) * NETWORK_RATE_BUCKET_SEC
    oldest_minute = minute - NETWORK_RATE_RETENTION_SEC + NETWORK_RATE_BUCKET_SEC
    db = network_rate_db()
    series_keys = []
    for entry in entries:
        series_key = network_rate_series_key(entry)
        if not series_key:
            continue
        series_keys.append(series_key)
        sample = calculate_network_rate_sample(entry, previous_map.get(series_key))
        if sample is None:
            entry["rate_rx_bps"] = 0
            entry["rate_tx_bps"] = 0
            entry["rate_sample_ms"] = 0
            continue
        entry["rate_rx_bps"] = sample["rx_bps"]
        entry["rate_tx_bps"] = sample["tx_bps"]
        entry["rate_sample_ms"] = sample["elapsed_ms"]
        db.execute(
            "INSERT INTO network_rate_minute"
            "(node_key, series_key, iface, ip, minute, rx_bps_ms, tx_bps_ms, sample_ms, sample_count) "
            "VALUES(?, ?, ?, ?, ?, ?, ?, ?, 1) "
            "ON CONFLICT(node_key, series_key, minute) DO UPDATE SET "
            "iface = excluded.iface, ip = excluded.ip, "
            "rx_bps_ms = network_rate_minute.rx_bps_ms + excluded.rx_bps_ms, "
            "tx_bps_ms = network_rate_minute.tx_bps_ms + excluded.tx_bps_ms, "
            "sample_ms = network_rate_minute.sample_ms + excluded.sample_ms, "
            "sample_count = network_rate_minute.sample_count + 1",
            (
                node_key,
                series_key,
                str(entry.get("iface") or "")[:80],
                str(entry.get("ip") or "")[:45],
                minute,
                float(sample["rx_bps"] * sample["elapsed_ms"]),
                float(sample["tx_bps"] * sample["elapsed_ms"]),
                sample["elapsed_ms"],
            ),
        )

    purge_metric_history(db, minute)
    db.commit()

    averages = {}
    if series_keys:
        placeholders = ",".join("?" for _ in series_keys)
        rows = db.execute(
            f"SELECT series_key, sum(rx_bps_ms) / sum(sample_ms) AS avg_rx_bps, "
            f"sum(tx_bps_ms) / sum(sample_ms) AS avg_tx_bps, "
            f"sum(sample_count) AS sample_count "
            f"FROM network_rate_minute WHERE node_key = ? AND minute >= ? "
            f"AND sample_ms > 0 AND series_key IN ({placeholders}) GROUP BY series_key",
            (node_key, oldest_minute, *series_keys),
        ).fetchall()
        averages = {str(row["series_key"]): row for row in rows}

    for entry in entries:
        row = averages.get(network_rate_series_key(entry))
        entry["avg_rx_bps_1h"] = normalize_network_rate(row["avg_rx_bps"] if row else 0)
        entry["avg_tx_bps_1h"] = normalize_network_rate(row["avg_tx_bps"] if row else 0)
        entry["rate_samples_1h"] = int(row["sample_count"] if row else 0)
    return entries


def enrich_cpu_average(node_key, cpu_percent, metrics_ok, current):
    node_key = str(node_key or "").strip()[:200]
    if not node_key:
        return 0.0, 0
    minute = (int(current) // NETWORK_RATE_BUCKET_SEC) * NETWORK_RATE_BUCKET_SEC
    oldest_minute = minute - NETWORK_RATE_RETENTION_SEC + NETWORK_RATE_BUCKET_SEC
    db = network_rate_db()
    if metrics_ok:
        sample = normalize_cpu_percent(cpu_percent)
        db.execute(
            "INSERT INTO cpu_minute(node_key, minute, sample_sum, sample_count) VALUES(?, ?, ?, 1) "
            "ON CONFLICT(node_key, minute) DO UPDATE SET "
            "sample_sum = cpu_minute.sample_sum + excluded.sample_sum, "
            "sample_count = cpu_minute.sample_count + 1",
            (node_key, minute, sample),
        )
    purge_metric_history(db, minute)
    db.commit()
    row = db.execute(
        "SELECT avg(sample_sum / sample_count) AS avg_cpu, "
        "sum(sample_count) AS sample_count FROM cpu_minute "
        "WHERE node_key = ? AND minute >= ? AND sample_count > 0",
        (node_key, oldest_minute),
    ).fetchone()
    if not row or row["avg_cpu"] is None:
        return 0.0, 0
    return normalize_cpu_percent(row["avg_cpu"]), int(row["sample_count"] or 0)


def traffic_stats_total(stats, field):
    if field not in TRAFFIC_COUNTER_FIELDS:
        return 0
    return sum(normalize_traffic_counter(entry.get(field)) for entry in stats if isinstance(entry, dict))


def nodes_day_traffic(nodes):
    total = 0
    for node in nodes:
        try:
            value = int(node.get("day_total") or 0)
        except Exception:
            value = 0
        if value <= 0:
            try:
                value = int(node.get("day_rx") or 0) + int(node.get("day_tx") or 0)
            except Exception:
                value = 0
        total += max(0, value)
    return total


def status_summary(nodes, ts, expected_total=None, filtered=False):
    expected_total = max(int(expected_total or EXPECTED_NODES), len(nodes), 1)
    live_count = live_node_count(nodes, ts)
    dead_items, falls, falls_nodes, total_downtime = downtime_totals(nodes, ts, filtered=filtered)

    lines = [
        "",
        "<blockquote>На данный момент:</blockquote>",
        f"<b>Живо: {live_count}/{expected_total}</b>",
        f"<b>SLA за сегодня: {format_sla_percent(total_downtime, expected_total, ts)}</b>",
        f"<b>Объем трафика: {format_bytes(nodes_day_traffic(nodes))}</b>",
        "",
        f"<b>Общее кол-во падений за сегодня: {int(falls.get('total', 0) or 0)}</b>",
        f"<b>Общее время даунтайма за сегодня: {format_duration_ru(total_downtime)}</b>",
        "<b>Мертво:</b>",
    ]
    if dead_items:
        dead_items.sort(key=lambda item: natural_sort_key(item[0].get("name") or item[0].get("id") or ""))
        for node, age in dead_items:
            name = html.escape(clean_display_text(node.get("name") or node.get("id") or "unknown"))
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

    if falls_nodes:
        lines.append("")
        lines.append("<b>Топ лист машин которые падали:</b>")
        top_lines = []
        for name, count in sorted(falls_nodes.items(), key=lambda item: (-int(item[1]), natural_sort_key(item[0]))):
            top_lines.append(f"{html.escape(clean_display_text(name))}: {int(count)} раз")
        lines.append(f"<blockquote>{chr(10).join(top_lines)}</blockquote>")
    return "\n".join(lines)


def node_is_wl(node):
    if isinstance(node, dict):
        node_kind = str(node.get("node_kind") or "").strip().lower()
        if node_kind in ("wl", "whitelist", "bypass"):
            return True
        if node_kind in ("bl", "other", "node"):
            return False
    values = [
        node.get("name") if isinstance(node, dict) else "",
        node.get("id") if isinstance(node, dict) else "",
        node.get("hostname") if isinstance(node, dict) else "",
    ]
    for value in values:
        text = canonical_node_key(value)
        if text.startswith("обход") or "whitelist" in text or "haproxy" in text:
            return True
    return False


def node_stale_sec(node):
    try:
        if node_is_wl(node):
            return STALE_SEC
        try:
            push_interval = int((node or {}).get("push_interval_sec") or 0)
        except Exception:
            push_interval = 0
        if push_interval <= 0:
            return max(BL_STALE_SEC, BL_STALE_FALLBACK_SEC)
        if push_interval <= 2:
            return max(BL_STALE_SEC, push_interval * 10)
        return max(BL_STALE_SEC, push_interval * 6)
    except Exception:
        return STALE_SEC


def node_offline_confirm_sec(node):
    try:
        return WL_OFFLINE_CONFIRM_SEC if node_is_wl(node) else BL_OFFLINE_CONFIRM_SEC
    except Exception:
        return WL_OFFLINE_CONFIRM_SEC


def desired_push_interval_sec(node):
    try:
        if node_is_wl(node):
            return 0
        return BL_PUSH_INTERVAL_SEC
    except Exception:
        return 0


def node_push_interval_sec(node):
    try:
        interval = int((node or {}).get("push_interval_sec") or 0)
    except Exception:
        interval = 0
    if interval <= 0:
        interval = desired_push_interval_sec(node)
    if interval <= 0:
        return 0
    return max(1, min(3600, int(interval)))


def push_history_limit(interval):
    interval = max(1, int(interval or 1))
    window = max(PUSH_MISS_WINDOW_SEC * 2, 120)
    return max(120, int(window / interval) + 20)


def clean_push_history(values, current, interval):
    cutoff = int(current) - max(PUSH_MISS_WINDOW_SEC * 2, 120)
    result = []
    if isinstance(values, list):
        for raw in values:
            try:
                seen = int(raw)
            except Exception:
                continue
            if cutoff <= seen <= int(current):
                result.append(seen)
    result.append(int(current))
    result = sorted(set(result))
    limit = push_history_limit(interval)
    if len(result) > limit:
        result = result[-limit:]
    return result


def node_push_miss_stats(node, current=None):
    current = int(current or now_ts())
    interval = node_push_interval_sec(node)
    if interval <= 0:
        return {"enabled": False}
    window = PUSH_MISS_WINDOW_SEC
    expected = max(1, int(window / interval))
    all_history = []
    window_history = []
    for raw in (node or {}).get("push_history") or []:
        try:
            seen = int(raw)
        except Exception:
            continue
        if seen <= current:
            all_history.append(seen)
        if current - window < seen <= current:
            window_history.append(seen)
    all_history.sort()
    window_history.sort()
    first_seen = all_history[0] if all_history else int((node or {}).get("last_seen") or 0)
    actual = len(window_history)
    ready = (first_seen > 0 and current - first_seen >= window) or actual >= expected
    missed = max(0, expected - actual)
    return {
        "enabled": True,
        "ready": ready,
        "window": window,
        "interval": interval,
        "expected": expected,
        "actual": actual,
        "missed": missed,
    }


def node_push_miss_blocks_alert(node, current):
    if node_is_wl(node):
        return False
    if node_push_interval_sec(node) > 2:
        return False
    stats = node_push_miss_stats(node, current)
    if int(stats.get("expected") or 0) <= PUSH_MISS_THRESHOLD:
        return False
    if not stats.get("enabled"):
        return False
    if not stats.get("ready"):
        return True
    return int(stats.get("missed") or 0) <= PUSH_MISS_THRESHOLD


def node_push_miss_exceeded(node, current):
    if node_push_interval_sec(node) > 2:
        return False
    stats = node_push_miss_stats(node, current)
    if int(stats.get("expected") or 0) <= PUSH_MISS_THRESHOLD:
        return False
    return bool(stats.get("ready")) and int(stats.get("missed") or 0) > PUSH_MISS_THRESHOLD


def remnawave_state_for_node(node):
    if not isinstance(node, dict):
        return None
    keys = set(node_alias_keys(node))
    for value in (node.get("ip"), node.get("hostname"), node.get("id"), node.get("name")):
        key = canonical_node_key(value)
        if key:
            keys.add(key)
    if not keys:
        return None
    with LOCK:
        state_nodes = REMNA_NODE_STATE.setdefault("nodes", {})
        for item in state_nodes.values():
            if not isinstance(item, dict):
                continue
            item_keys = {
                canonical_node_key(item.get("key")),
                canonical_node_key(item.get("name")),
                canonical_node_key(item.get("address")),
            }
            item_keys.discard("")
            if keys.intersection(item_keys):
                return dict(item)
    return None


def remnawave_log_guard_reason(node, current, age, stale_sec):
    remna = node.get("remna") if isinstance(node, dict) else {}
    if not isinstance(remna, dict):
        return ""
    status = clean_display_text(remna.get("status") or "").strip().lower()
    try:
        error_count = int(remna.get("error_count") or 0)
    except Exception:
        error_count = 0
    last_error = clean_display_text(remna.get("last_error") or "").strip()
    if not status and error_count <= 0 and not last_error:
        return ""
    if status and status != "running":
        return ""
    if error_count > 0 or last_error:
        return ""
    if age <= stale_sec + REMNA_OFFLINE_LOG_GRACE_SEC:
        return "Remnawave diagnostics are clean"
    return ""


def remnawave_offline_guard_reason(node, current, age, stale_sec):
    if not REMNA_OFFLINE_GUARD_ENABLED or node_is_wl(node):
        return ""
    state = remnawave_state_for_node(node)
    if isinstance(state, dict):
        seen_at = int(state.get("seen_at") or 0)
        state_age = current - seen_at if seen_at > 0 else REMNA_OFFLINE_STATE_MAX_AGE_SEC + 1
        if state_age <= REMNA_OFFLINE_STATE_MAX_AGE_SEC:
            if bool(state.get("disabled")):
                return "disabled in Remnawave"
            if bool(state.get("connected")):
                return "Remnawave still sees node connected"
            return ""
    return remnawave_log_guard_reason(node, current, age, stale_sec)


def node_is_exact_bypass(node):
    values = [
        node.get("name") if isinstance(node, dict) else "",
        node.get("id") if isinstance(node, dict) else "",
        node.get("hostname") if isinstance(node, dict) else "",
    ]
    for value in values:
        if re.fullmatch(r"обход\d+", canonical_node_key(value) or ""):
            return True
    return False


def live_node_count(nodes, ts):
    live_count = 0
    for node in nodes:
        last_seen = int(node.get("last_seen", 0) or 0)
        if ts - last_seen <= node_stale_sec(node):
            live_count += 1
    return live_count


def node_sort_text(node):
    if not isinstance(node, dict):
        return ""
    return node_display_name(node, "")


def node_natural_sort_key(node):
    return natural_sort_key(node_sort_text(node))


def wl_other_node_sort_key(node):
    text = node_sort_text(node)
    folded = text.casefold()
    if re.search(r"(?<!\w)(?:resell|reseller|реселл|ресейл)(?!\w)", folded):
        variant_order = 0
    elif re.search(r"(?<!\w)(?:private|приват)(?!\w)", folded):
        variant_order = 1
    else:
        variant_order = 2
    bypass_match = re.search(r"обход\s*(?:[№#]\s*)?(\d+)", folded)
    bypass_number = int(bypass_match.group(1)) if bypass_match else 2**63 - 1
    return (variant_order, bypass_number, natural_sort_key(text))


def bl_node_sort_key(node):
    text = node_sort_text(node)
    canonical = canonical_node_key(text)
    order = BL_NODE_ORDER_INDEX.get(canonical)
    if order is None:
        order = len(BL_NODE_ORDER_INDEX) + 1
    return (order, natural_sort_key(text))


def aggregate_message(scope="all"):
    with LOCK:
        all_nodes = [node for node in dedupe_nodes(NODES.values()) if not node_stats_disabled(node)]
    ts = now_ts()
    scope = str(scope or "all").strip().lower()
    expected_total = None
    filtered = False
    compact = False
    other_nodes = []
    title = "Статистика обходов"
    if scope in ("wl", "wl_full"):
        wl_nodes = [node for node in all_nodes if node_is_wl(node)]
        nodes = [node for node in wl_nodes if node_is_exact_bypass(node)]
        other_nodes = [node for node in wl_nodes if not node_is_exact_bypass(node)]
        expected_total = max(EXPECTED_NODES, len(nodes), 1)
        filtered = True
        compact = scope == "wl"
    elif scope == "bl":
        nodes = [node for node in all_nodes if not node_is_wl(node)]
        expected_total = max(len(nodes), 1)
        filtered = True
        title = "Статистика других машин"
    else:
        nodes = all_nodes
        expected_total = max(EXPECTED_NODES, len(nodes), 1)
    if not nodes and not other_nodes:
        return f"<b>{title}</b>\n\nНет данных от машин."
    if scope == "bl":
        nodes.sort(key=bl_node_sort_key)
    else:
        nodes.sort(key=node_natural_sort_key)
    other_nodes.sort(key=wl_other_node_sort_key)
    parts = [f"<b>{title}</b>"]
    for node in nodes:
        age = ts - int(node.get("last_seen", 0) or 0)
        status = "OK" if age <= node_stale_sec(node) else f"OFFLINE {format_age(age)}"
        parts.append("")
        parts.append(node_message(node, status, compact=compact))
    parts.append(status_summary(nodes, ts, expected_total=expected_total, filtered=filtered))
    if other_nodes:
        parts.append("")
        parts.append(f"<blockquote><b>Другие: {live_node_count(other_nodes, ts)}/{len(other_nodes)}</b></blockquote>")
        for node in other_nodes:
            age = ts - int(node.get("last_seen", 0) or 0)
            status = "OK" if age <= node_stale_sec(node) else f"OFFLINE {format_age(age)}"
            parts.append("")
            parts.append(node_message(node, status, compact=compact))
    return "\n".join(parts)


def aggregate_summary_message(scope="bl"):
    with LOCK:
        all_nodes = [node for node in dedupe_nodes(NODES.values()) if not node_stats_disabled(node)]
    ts = now_ts()
    scope = str(scope or "bl").strip().lower()
    if scope == "bl":
        nodes = [node for node in all_nodes if not node_is_wl(node)]
        title = "Статистика других машин"
    elif scope == "wl":
        nodes = [node for node in all_nodes if node_is_wl(node)]
        title = "Статистика обходов"
    else:
        nodes = all_nodes
        title = "Статистика машин"
    expected_total = max(len(nodes), 1)
    if not nodes:
        return f"<b>{title}</b>\n\nНет данных от машин."
    return f"<b>{title}</b>\n{status_summary(nodes, ts, expected_total=expected_total, filtered=True)}"


def rich_text(value):
    return html.escape(clean_display_text(value if value is not None else "-"))


def rich_cell(value, header=False, align="left", rowspan=1, colspan=1, valign=""):
    tag = "th" if header else "td"
    attrs = []
    if align in ("left", "center", "right"):
        attrs.append(f'align="{align}"')
    if valign in ("top", "middle", "bottom"):
        attrs.append(f'valign="{valign}"')
    try:
        rowspan = max(1, min(int(rowspan or 1), 64))
    except Exception:
        rowspan = 1
    try:
        colspan = max(1, min(int(colspan or 1), 20))
    except Exception:
        colspan = 1
    if rowspan > 1:
        attrs.append(f'rowspan="{rowspan}"')
    if colspan > 1:
        attrs.append(f'colspan="{colspan}"')
    attrs_text = f" {' '.join(attrs)}" if attrs else ""
    return f"<{tag}{attrs_text}>{rich_text(value)}</{tag}>"


def rich_table(headers, rows, caption="", footer=""):
    if not rows:
        return ""
    parts = ["<table bordered striped>"]
    if caption:
        parts.append(f"<caption>{rich_text(caption)}</caption>")
    parts.append("<tr>" + "".join(rich_cell(header, header=True, align="center") for header in headers) + "</tr>")
    for row in rows:
        cells = []
        for cell in row:
            if isinstance(cell, dict):
                cells.append(
                    rich_cell(
                        cell.get("value"),
                        align=cell.get("align", "left"),
                        rowspan=cell.get("rowspan", 1),
                        colspan=cell.get("colspan", 1),
                        valign=cell.get("valign", ""),
                    )
                )
            else:
                value, align = cell
                cells.append(rich_cell(value, align=align))
        parts.append("<tr>" + "".join(cells) + "</tr>")
    if footer:
        colspan = max(1, min(len(headers), 20))
        parts.append(
            f'<tr><td align="center" colspan="{colspan}"><b>{rich_text(footer)}</b></td></tr>'
        )
    parts.append("</table>")
    return "".join(parts)


def format_mbit_rate(value):
    mbps = normalize_network_rate(value) / 1_000_000
    if mbps >= 100:
        return f"{mbps:.0f}"
    if mbps >= 10:
        return f"{mbps:.1f}".rstrip("0").rstrip(".")
    return f"{mbps:.2f}".rstrip("0").rstrip(".") or "0"


def average_rate_table_text(entry):
    if not isinstance(entry, dict) or normalize_traffic_counter(entry.get("rate_samples_1h")) <= 0:
        return "-"
    upload = format_mbit_rate(entry.get("avg_tx_bps_1h"))
    download = format_mbit_rate(entry.get("avg_rx_bps_1h"))
    return f"{upload} | {download} Mbit/s"


def node_average_rate_table_text(node):
    entries = [
        entry for entry in node_ip_stats(node)
        if normalize_traffic_counter(entry.get("rate_samples_1h")) > 0
    ]
    if not entries:
        return "-"
    return average_rate_table_text({
        "avg_tx_bps_1h": sum(normalize_network_rate(entry.get("avg_tx_bps_1h")) for entry in entries),
        "avg_rx_bps_1h": sum(normalize_network_rate(entry.get("avg_rx_bps_1h")) for entry in entries),
        "rate_samples_1h": sum(normalize_traffic_counter(entry.get("rate_samples_1h")) for entry in entries),
    })


def cpu_average_table_text(node):
    if not isinstance(node, dict) or int(node.get("cpu_samples_1h") or 0) <= 0:
        return "-"
    return format_percent(normalize_cpu_percent(node.get("cpu_avg_1h")))


def wrong_sni_table_text(node):
    total = int(node.get("scan_wrong_sni_total") or 0)
    if total <= 0:
        return "-"
    sources = int(node.get("scan_wrong_sni_sources") or 0)
    text = f"{total}/{sources} IP"
    top = top_wrong_sni_label(node)
    if top:
        text = f"{text} | {top}"
    return text


def node_status_text(node, ts):
    if clean_display_text(node.get("error") or ""):
        return "ERR"
    age = ts - int(node.get("last_seen", 0) or 0)
    if age <= node_stale_sec(node):
        return "OK"
    return f"OFF {format_age(age)}"


def rich_wl_rows(nodes, ts):
    rows = []
    for node in nodes:
        traffic_rows = node_ip_stats_by_traffic(node)
        if not traffic_rows:
            traffic_rows = [normalized_traffic_entry(node, node.get("iface"), node.get("ip"))]
        rowspan = len(traffic_rows)
        node_error = clean_display_text(node.get("error") or "")
        sni = "-" if node_error else wrong_sni_table_text(node)
        status = node_status_text(node, ts)
        if status == "OK" and any(clean_display_text(entry.get("error") or "") for entry in traffic_rows):
            status = "WARN"
        shared = {
            "rowspan": rowspan,
            "valign": "middle",
        }
        for index, entry in enumerate(traffic_rows):
            entry_error = node_error or clean_display_text(entry.get("error") or "")
            if entry_error:
                today = "ошибка"
                yesterday = "-"
                month = "ошибка"
            else:
                today = format_bytes(entry.get("day_total", 0))
                yesterday = format_bytes(entry.get("yesterday_total", 0))
                month = format_bytes(entry.get("month_total", 0))
            row = []
            if index == 0:
                row.append({
                    **shared,
                    "value": node_display_name(node, "unknown").replace("№", "#"),
                    "align": "left",
                })
            row.extend([
                (str(entry.get("ip") or "-"), "left"),
                (today, "right"),
                (yesterday, "right"),
                (month, "right"),
            ])
            if index == 0:
                row.extend([
                    {**shared, "value": sni, "align": "left"},
                    {**shared, "value": status, "align": "center"},
                ])
            rows.append(row)
    return rows


def rich_status_summary(nodes, ts, expected_total):
    expected_total = max(int(expected_total or EXPECTED_NODES), len(nodes), 1)
    live_count = live_node_count(nodes, ts)
    dead_items, falls, falls_nodes, total_downtime = downtime_totals(nodes, ts, filtered=True)
    parts = [
        "<h4>На данный момент</h4>",
        f"<p><b>Живо:</b> {rich_text(f'{live_count}/{expected_total}')}</p>",
        f"<p><b>SLA за сегодня:</b> {rich_text(format_sla_percent(total_downtime, expected_total, ts))}</p>",
        f"<p><b>Общее кол-во падений за сегодня:</b> {rich_text(int(falls.get('total', 0) or 0))}</p>",
        f"<p><b>Общее время даунтайма за сегодня:</b> {rich_text(format_duration_ru(total_downtime))}</p>",
    ]
    if dead_items:
        dead_lines = []
        dead_items.sort(key=lambda item: natural_sort_key(item[0].get("name") or item[0].get("id") or ""))
        for node, age in dead_items:
            name = node_display_name(node, "unknown")
            ip = str(node.get("ip") or "-")
            dead_lines.append(f"{name} ({ip}) - {format_duration_ru(age)}")
        parts.append("<blockquote>" + "<br/>".join(rich_text(line) for line in dead_lines) + "</blockquote>")
    else:
        parts.append("<p><b>Мертво:</b> нет</p>")
    if falls_nodes:
        top_lines = []
        for name, count in sorted(falls_nodes.items(), key=lambda item: (-int(item[1]), natural_sort_key(item[0]))):
            top_lines.append(f"{clean_display_text(name)}: {int(count)} раз")
        parts.append("<details><summary>Топ падений</summary>" + "<br/>".join(rich_text(line) for line in top_lines) + "</details>")
    return "".join(parts)


def rich_traffic_total_text(nodes):
    return f"Общий трафик: {format_bytes(nodes_day_traffic(nodes))}"


def aggregate_wl_rich_message():
    with LOCK:
        all_nodes = [node for node in dedupe_nodes(NODES.values()) if not node_stats_disabled(node)]
    ts = now_ts()
    wl_nodes = [node for node in all_nodes if node_is_wl(node)]
    nodes = [node for node in wl_nodes if node_is_exact_bypass(node)]
    other_nodes = [node for node in wl_nodes if not node_is_exact_bypass(node)]
    expected_total = max(EXPECTED_NODES, len(nodes), 1)
    if not nodes and not other_nodes:
        return "<h3>Статистика обходов</h3><p>Нет данных от машин.</p>"
    nodes.sort(key=node_natural_sort_key)
    other_nodes.sort(key=wl_other_node_sort_key)
    headers = ["Обход", "IP", "Сегодня", "Вчера", "Месяц", "SNI", "Статус"]
    parts = [
        "<h3>Статистика обходов</h3>",
        rich_table(headers, rich_wl_rows(nodes, ts), footer=rich_traffic_total_text(nodes)),
        rich_status_summary(nodes, ts, expected_total),
    ]
    if other_nodes:
        other_caption = f"Другие: {live_node_count(other_nodes, ts)}/{len(other_nodes)}"
        parts.append(
            rich_table(
                headers,
                rich_wl_rows(other_nodes, ts),
                caption=other_caption,
                footer=rich_traffic_total_text(other_nodes),
            )
        )
    return "".join(part for part in parts if part)


def send_stats_wl(use_rich=True):
    if use_rich or RICH_STATS_ENABLED:
        rich_html = aggregate_wl_rich_message()
        if send_rich_message(rich_html):
            return True
    return bool(send_message(aggregate_message("wl")))


def remna_table_text(node):
    remna = node.get("remna") if isinstance(node, dict) else {}
    if not isinstance(remna, dict):
        return "-"
    status = clean_display_text(remna.get("status") or "")
    restarts = int(remna.get("restarts") or 0)
    error_count = int(remna.get("error_count") or 0)
    last_error = clean_display_text(remna.get("last_error") or "")
    parts = []
    if status and status != "running":
        parts.append(status)
    if restarts > 0:
        parts.append(f"restarts {restarts}")
    if error_count > 0:
        parts.append(f"errors {error_count}")
    if last_error:
        parts.append(last_error[:80])
    return ", ".join(parts) if parts else "-"


def rich_bl_rows(nodes, ts):
    rows = []
    for node in nodes:
        traffic_rows = node_ip_stats_by_traffic(node)
        if not traffic_rows:
            traffic_rows = [normalized_traffic_entry(node, node.get("iface"), node.get("ip"))]
        rowspan = len(traffic_rows)
        node_error = clean_display_text(node.get("error") or "")
        metrics_ok = bool(node.get("metrics_ok"))
        ram = f"{int(node.get('ram_percent', 0) or 0)}%" if metrics_ok else "-"
        status = node_status_text(node, ts)
        if status == "OK" and any(clean_display_text(entry.get("error") or "") for entry in traffic_rows):
            status = "WARN"
        shared = {"rowspan": rowspan, "valign": "middle"}
        for index, entry in enumerate(traffic_rows):
            entry_error = node_error or clean_display_text(entry.get("error") or "")
            if entry_error:
                today = "ошибка"
                yesterday = "-"
                month = "ошибка"
            else:
                today = format_bytes(entry.get("day_total", 0))
                yesterday = format_bytes(entry.get("yesterday_total", 0))
                month = format_bytes(entry.get("month_total", 0))
            row = []
            if index == 0:
                row.append({
                    **shared,
                    "value": node_display_name(node, "unknown").replace("№", "#"),
                    "align": "left",
                })
            row.extend([
                (str(entry.get("ip") or "-"), "left"),
                (today, "right"),
                (yesterday, "right"),
                (month, "right"),
            ])
            if index == 0:
                row.extend([
                    {**shared, "value": ram, "align": "right"},
                    {**shared, "value": remna_table_text(node), "align": "left"},
                    {**shared, "value": status, "align": "center"},
                ])
            rows.append(row)
    return rows


def bl_group_rich_context(group_id=None, ungrouped=False):
    nodes = current_bl_nodes()
    if ungrouped:
        group_nodes = bl_ungrouped_nodes(nodes, bl_group_list())
        group_name = "Без группы"
        group_found = True
    else:
        group = bl_group_by_id(group_id)
        if group is None:
            return "", [], False
        group_nodes = bl_group_nodes(group, nodes)
        group_name = group.get("name") or "Группа"
        group_found = True
    return group_name, group_nodes, group_found


def bl_group_stats_rich_message(group_id=None, ungrouped=False):
    group_name, group_nodes, group_found = bl_group_rich_context(group_id, ungrouped=ungrouped)
    if not group_found:
        return "<h3>Статистика других машин</h3><p>Группа не найдена.</p>"

    return "<h3>Статистика других машин</h3>" + bl_nodes_rich_section(group_name, group_nodes)


def bl_nodes_rich_section(group_name, group_nodes, ts=None):
    if not group_nodes:
        return f"<h4>{rich_text(group_name)}</h4><p>Нет машин в группе.</p>"
    ts = now_ts() if ts is None else int(ts)
    headers = ["Машина", "IP", "Сегодня", "Вчера", "Месяц", "RAM", "Remnawave", "Статус"]
    parts = [
        f"<h4>{rich_text(group_name)}</h4>",
        rich_table(headers, rich_bl_rows(group_nodes, ts), footer=rich_traffic_total_text(group_nodes)),
        rich_status_summary(group_nodes, ts, max(len(group_nodes), 1)),
    ]
    return "".join(part for part in parts if part)


def edit_or_send_bl_group_stats(chat_id, message_id, group_id=None, ungrouped=False):
    markup = bl_group_action_markup(group_id, ungrouped=ungrouped)
    if RICH_STATS_ENABLED:
        rich_html = bl_group_stats_rich_message(group_id, ungrouped=ungrouped)
        if edit_rich_message_text(chat_id, message_id, rich_html, reply_markup=markup):
            return
    body = bl_group_stats_message(group_id, ungrouped=ungrouped)
    if not edit_message_text(chat_id, message_id, body, reply_markup=markup):
        send_message(body, reply_markup=markup)


def code_value(value):
    if value is None or value == "":
        value = "-"
    value = clean_display_text(value).replace("№", "#")
    return f"<code>{html.escape(value)}</code>"


def detail_line(label, value):
    return f"<b>{label}:</b> {code_value(value)}"


def node_base_aliases(node):
    aliases = set()
    if isinstance(node, dict):
        record_key = canonical_node_key(node_record_key(node))
        if record_key:
            aliases.add(record_key)
        fields = ("node_uuid", "id", "name", "hostname")
        if not normalize_node_uuid(node.get("node_uuid")):
            fields += ("ip",)
        for key in fields:
            alias = canonical_node_key(node.get(key))
            if alias:
                aliases.add(alias)
    else:
        alias = canonical_node_key(node)
        if alias:
            aliases.add(alias)
    return aliases


def node_name_identity_aliases(node):
    if not isinstance(node, dict):
        return node_base_aliases(node)
    node_uuid = normalize_node_uuid(node.get("node_uuid"))
    if not node_uuid:
        return node_base_aliases(node)
    return {
        canonical_node_key(node_uuid),
        canonical_node_key(f"uuid_{node_uuid}"),
    }


def node_name_state_target(key, item):
    if isinstance(item, dict):
        return canonical_node_key(item.get("target") or key)
    return canonical_node_key(key)


def exact_node_name_override_unlocked(node):
    target = canonical_node_key(node_record_key(node))
    if not target:
        return ""
    matches = []
    for key, item in NODE_NAME_STATE.setdefault("nodes", {}).items():
        if not isinstance(item, dict):
            continue
        if target not in (node_name_state_target(key, item), canonical_node_key(key)):
            continue
        name = clean_display_text(item.get("name") or "")
        if name:
            matches.append((int(item.get("updated_at") or 0), name))
    if not matches:
        return ""
    return max(matches, key=lambda row: row[0])[1]


def node_name_override_for_node(node):
    aliases = node_base_aliases(node)
    if not aliases:
        return ""
    with LOCK:
        nodes = NODE_NAME_STATE.setdefault("nodes", {})
        exact = exact_node_name_override_unlocked(node)
        if exact:
            return exact
        # UUID is the authoritative identity. Falling back to hostname/name here
        # lets one common hostname (for example "kto") rename every modern node.
        if isinstance(node, dict) and normalize_node_uuid(node.get("node_uuid")):
            return ""
        for key in aliases:
            item = nodes.get(key)
            if isinstance(item, dict):
                name = clean_display_text(item.get("name") or "")
                if name:
                    return name
        for item in nodes.values():
            if not isinstance(item, dict):
                continue
            name_key = canonical_node_key(item.get("name") or "")
            item_aliases = {canonical_node_key(value) for value in item.get("aliases") or []}
            item_aliases.discard(name_key)
            if aliases.intersection(item_aliases):
                name = clean_display_text(item.get("name") or "")
                if name:
                    return name
    return ""


def node_name_recovery_value(node, reported_name=None):
    if not isinstance(node, dict) or not normalize_node_uuid(node.get("node_uuid")):
        return ""
    if node_name_override_for_node(node):
        return ""
    reported = clean_display_text(node.get("name") if reported_name is None else reported_name)
    reported_key = canonical_node_key(reported)
    if not reported_key:
        return ""
    target = canonical_node_key(node_record_key(node))
    foreign_override = False
    with LOCK:
        for key, item in NODE_NAME_STATE.setdefault("nodes", {}).items():
            if not isinstance(item, dict) or canonical_node_key(item.get("name") or "") != reported_key:
                continue
            if target not in (node_name_state_target(key, item), canonical_node_key(key)):
                foreign_override = True
                break
    if not foreign_override:
        return ""
    for field in ("id", "hostname"):
        candidate = clean_display_text(node.get(field) or "")[:120]
        candidate_key = canonical_node_key(candidate)
        if candidate_key and candidate_key != reported_key and candidate_key not in ("unknown", "localhost", "none", "null"):
            return candidate
    return ""


def node_name_sync_value(node, reported_name=None):
    return node_name_override_for_node(node) or node_name_recovery_value(node, reported_name)


def node_display_name(node, fallback="unknown"):
    synced_name = node_name_sync_value(node)
    if synced_name:
        return synced_name
    return clean_display_text(node.get("name") or node.get("id") or node.get("hostname") or fallback)


def repair_loaded_node_names():
    repaired = 0
    with LOCK:
        for node in NODES.values():
            if not isinstance(node, dict):
                continue
            recovered = node_name_recovery_value(node)
            if recovered and recovered != clean_display_text(node.get("name") or ""):
                node["name"] = recovered
                repaired += 1
        if repaired:
            save_nodes()
    if repaired:
        log(f"repaired leaked rename on {repaired} node(s)")
    return repaired


def node_display_ip(node):
    return str(node.get("ip") or "-")


def find_nodes(query):
    needle = canonical_node_key(query)
    if not needle:
        return []
    matches = []
    seen = set()
    with LOCK:
        for node in NODES.values():
            candidates = [
                node_record_key(node),
                node.get("id"),
                node.get("name"),
                node.get("hostname"),
                node.get("ip"),
                node_name_override_for_node(node),
            ]
            aliases = node_alias_keys(node)
            if needle in aliases or any(canonical_node_key(value) == needle for value in candidates):
                item = dict(node)
                key = node_record_key(item) or node_canonical_key(item)
                if key and key in seen:
                    continue
                seen.add(key)
                matches.append(item)
    matches.sort(key=lambda node: int(node.get("last_seen", 0) or 0), reverse=True)
    return matches


def find_node(query):
    matches = find_nodes(query)
    if matches:
        return matches[0]
    return None


def sni_node_aliases(node):
    return node_base_aliases(node)


def sni_override_for_node(node):
    aliases = sni_node_aliases(node)
    if not aliases:
        return None
    with LOCK:
        nodes = SNI_STATE.setdefault("nodes", {})
        for key in aliases:
            item = nodes.get(key)
            if not isinstance(item, dict):
                continue
            values = normalize_sni_list(item.get("values"))
            if values:
                return values
    return None


def haproxy_target_override_for_node(node):
    aliases = sni_node_aliases(node)
    if not aliases:
        return None
    with LOCK:
        nodes = SNI_STATE.setdefault("nodes", {})
        for key in aliases:
            item = nodes.get(key)
            if not isinstance(item, dict):
                continue
            target = normalize_haproxy_target_or_empty(item.get("target") or item.get("haproxy_target"))
            if target:
                return target
    return None


def reported_sni_for_node(node):
    if not isinstance(node, dict):
        return []
    return normalize_sni_list(node.get("haproxy_allowed_sni"))


def reported_haproxy_target_for_node(node):
    if not isinstance(node, dict):
        return ""
    return normalize_haproxy_target_or_empty(node.get("haproxy_backend_target"))


def effective_sni_for_node(node):
    override = sni_override_for_node(node)
    if override is not None:
        return override, "telegram"
    return reported_sni_for_node(node), "node"


def effective_haproxy_target_for_node(node):
    override = haproxy_target_override_for_node(node)
    if override:
        return override, "telegram"
    return reported_haproxy_target_for_node(node), "node"


def sni_list_text(values):
    values = normalize_sni_list(values)
    if not values:
        return "<i>Список пуст.</i>"
    return "<blockquote>" + "\n".join(f"<code>{html.escape(item)}</code>" for item in values) + "</blockquote>"


def set_sni_override_for_node(node, values):
    key = node_canonical_key(node)
    if not key:
        raise ValueError("empty node key")
    values = normalize_sni_list(values)
    if not values:
        raise ValueError("empty sni list")
    with LOCK:
        nodes = SNI_STATE.setdefault("nodes", {})
        existing = nodes.get(key) if isinstance(nodes.get(key), dict) else {}
        target = normalize_haproxy_target_or_empty(existing.get("target") or existing.get("haproxy_target"))
        item = {
            "name": node_display_name(node, key)[:120],
            "values": values,
            "updated_at": now_ts(),
        }
        if target:
            item["target"] = target
        nodes[key] = item
        save_sni_state()
    return values


def set_haproxy_override_for_node(node, target, values):
    key = node_canonical_key(node)
    if not key:
        raise ValueError("empty node key")
    target = normalize_haproxy_target(target)
    values = normalize_sni_list(values)
    if not values:
        raise ValueError("empty sni list")
    with LOCK:
        SNI_STATE.setdefault("nodes", {})[key] = {
            "name": node_display_name(node, key)[:120],
            "target": target,
            "values": values,
            "updated_at": now_ts(),
        }
        save_sni_state()
    return target, values


def set_pending_sni(chat_id, from_id, action, node, extra=None):
    key = pending_key(chat_id, from_id)
    node_key = node_canonical_key(node)
    with LOCK:
        item = {
            "action": action,
            "node_key": node_key,
            "node_name": node_display_name(node, node_key),
            "created_at": now_ts(),
        }
        if isinstance(extra, dict):
            item.update(extra)
        SNI_STATE.setdefault("pending", {})[key] = item
        save_sni_state()


def pop_pending_sni(chat_id, from_id):
    key = pending_key(chat_id, from_id)
    with LOCK:
        item = SNI_STATE.setdefault("pending", {}).pop(key, None)
        if item is not None:
            save_sni_state()
        return item if isinstance(item, dict) else None


def peek_pending_sni(chat_id, from_id):
    key = pending_key(chat_id, from_id)
    with LOCK:
        item = SNI_STATE.setdefault("pending", {}).get(key)
        if not isinstance(item, dict):
            return None
        if now_ts() - int(item.get("created_at") or 0) > 600:
            SNI_STATE.setdefault("pending", {}).pop(key, None)
            save_sni_state()
            return None
        return dict(item)


def sni_command_intro(command, node, values, source):
    name = node_display_name(node)
    source_text = "Telegram override" if source == "telegram" else "последний HAProxy config"
    action_text = "Напиши SNI ответом, и я добавлю его в allow-list." if command == "allow_sni" else "Напиши SNI ответом, и я удалю его из allow-list."
    lines = [
        "<b>SNI allow-list</b>",
        ALERT_SEPARATOR,
        detail_line("Машина", name),
        detail_line("Источник", source_text),
        "",
        "<b>Сейчас разрешены:</b>",
        sni_list_text(values),
        "",
        action_text,
        "Отмена: <code>/cancel</code>",
    ]
    return "\n".join(lines)


def haproxy_command_intro(node, target, target_source, values, sni_source):
    name = node_display_name(node)
    target_source_text = "Telegram override" if target_source == "telegram" else "последний HAProxy config"
    sni_source_text = "Telegram override" if sni_source == "telegram" else "последний HAProxy config"
    lines = [
        "<b>HAProxy</b>",
        ALERT_SEPARATOR,
        detail_line("Машина", name),
        detail_line("Backend", target or "-"),
        detail_line("Источник backend", target_source_text),
        detail_line("Источник SNI", sni_source_text),
        "",
        "<b>Сейчас разрешены:</b>",
        sni_list_text(values),
        "",
        "Напиши backend ответом: <code>1.2.3.4</code> или <code>1.2.3.4:8443</code>",
        "Отмена: <code>/cancel</code>",
    ]
    return "\n".join(lines)


def haproxy_state_key(node):
    return str(node_record_key(node) or node_canonical_key(node) or "").strip()


def haproxy_state_item_for_node(node):
    key = haproxy_state_key(node)
    aliases = node_alias_keys(node)
    with LOCK:
        nodes = HAPROXY_STATE.setdefault("nodes", {})
        item = nodes.get(key)
        if isinstance(item, dict):
            return dict(item)
        for stored_key, stored_item in nodes.items():
            if canonical_node_key(stored_key) in aliases and isinstance(stored_item, dict):
                return dict(stored_item)
    return None


def reported_haproxy_routes_for_node(node):
    if not isinstance(node, dict):
        return []
    return normalize_haproxy_routes(node.get("haproxy_routes"))


def desired_haproxy_routes_for_node(node):
    item = haproxy_state_item_for_node(node)
    if not isinstance(item, dict):
        return None
    routes = normalize_haproxy_routes(item.get("routes"))
    return routes or None


def effective_haproxy_routes_for_node(node):
    desired = desired_haproxy_routes_for_node(node)
    if desired is not None:
        return desired, "telegram"
    return reported_haproxy_routes_for_node(node), "node"


def set_haproxy_routes_for_node(node, routes):
    routes = normalize_haproxy_routes(routes, strict=True)
    if not routes:
        raise ValueError("empty haproxy routes")
    key = haproxy_state_key(node)
    if not key:
        raise ValueError("empty node key")
    aliases = node_alias_keys(node)
    with LOCK:
        nodes = HAPROXY_STATE.setdefault("nodes", {})
        preserved = dict(nodes.get(key)) if isinstance(nodes.get(key), dict) else {}
        for stored_key in list(nodes):
            if stored_key != key and canonical_node_key(stored_key) in aliases:
                if not preserved and isinstance(nodes.get(stored_key), dict):
                    preserved = dict(nodes[stored_key])
                del nodes[stored_key]
        base_hashes = clean_haproxy_base_hashes(preserved.get("routes_base_hashes"))
        if bool(node.get("haproxy_routes_supported")):
            base_hashes.append(haproxy_routes_fingerprint(reported_haproxy_routes_for_node(node)))
        if isinstance(preserved.get("routes"), list):
            base_hashes.append(haproxy_routes_fingerprint(preserved.get("routes")))
        base_hashes = list(dict.fromkeys(base_hashes))[-8:]
        preserved.update({
            "name": node_display_name(node, key)[:120],
            "routes": routes,
            "updated_at": now_ts(),
            "routes_command_id": new_haproxy_command_id(),
            "routes_base_hashes": base_hashes,
            "routes_error_baseline": haproxy_apply_result_fingerprint(node.get("haproxy_apply_result")),
        })
        nodes[key] = preserved
        save_haproxy_state()
    return routes


def reported_haproxy_bandwidth_limits_for_node(node):
    if not isinstance(node, dict) or not bool(node.get("haproxy_bandwidth_supported")):
        return []
    return normalize_haproxy_bandwidth_limits(node.get("haproxy_bandwidth_limits"))


def desired_haproxy_bandwidth_limits_for_node(node):
    item = haproxy_state_item_for_node(node)
    if not isinstance(item, dict) or "bandwidth_limits" not in item:
        return None
    return normalize_haproxy_bandwidth_limits(item.get("bandwidth_limits"))


def effective_haproxy_bandwidth_limits_for_node(node):
    desired = desired_haproxy_bandwidth_limits_for_node(node)
    if desired is not None:
        return desired, "telegram"
    return reported_haproxy_bandwidth_limits_for_node(node), "node"


def set_haproxy_bandwidth_limits_for_node(node, limits):
    limits = normalize_haproxy_bandwidth_limits(limits, strict=True)
    key = haproxy_state_key(node)
    if not key:
        raise ValueError("empty node key")
    aliases = node_alias_keys(node)
    with LOCK:
        nodes = HAPROXY_STATE.setdefault("nodes", {})
        preserved = dict(nodes.get(key)) if isinstance(nodes.get(key), dict) else {}
        for stored_key in list(nodes):
            if stored_key != key and canonical_node_key(stored_key) in aliases:
                if not preserved and isinstance(nodes.get(stored_key), dict):
                    preserved = dict(nodes[stored_key])
                del nodes[stored_key]
        base_hashes = clean_haproxy_base_hashes(preserved.get("bandwidth_base_hashes"))
        if bool(node.get("haproxy_bandwidth_supported")):
            base_hashes.append(
                haproxy_bandwidth_fingerprint(reported_haproxy_bandwidth_limits_for_node(node))
            )
        if isinstance(preserved.get("bandwidth_limits"), list):
            base_hashes.append(haproxy_bandwidth_fingerprint(preserved.get("bandwidth_limits")))
        base_hashes = list(dict.fromkeys(base_hashes))[-8:]
        preserved.update({
            "name": node_display_name(node, key)[:120],
            "bandwidth_limits": limits,
            "bandwidth_updated_at": now_ts(),
            "bandwidth_command_id": new_haproxy_command_id(),
            "bandwidth_base_hashes": base_hashes,
            "bandwidth_error_baseline": haproxy_apply_result_fingerprint(
                node.get("haproxy_bandwidth_apply_result")
            ),
        })
        nodes[key] = preserved
        save_haproxy_state()
    return limits


def acknowledge_haproxy_desired_state(node):
    if not isinstance(node, dict):
        return []
    key = haproxy_state_key(node)
    aliases = node_alias_keys(node)
    routes_supported = bool(node.get("haproxy_routes_supported"))
    bandwidth_supported = bool(node.get("haproxy_bandwidth_supported"))
    reported_routes = reported_haproxy_routes_for_node(node) if routes_supported else []
    reported_limits = reported_haproxy_bandwidth_limits_for_node(node) if bandwidth_supported else []
    acknowledged = []

    with LOCK:
        nodes = HAPROXY_STATE.setdefault("nodes", {})
        stored_key = key if isinstance(nodes.get(key), dict) else ""
        if not stored_key:
            for candidate, value in nodes.items():
                if canonical_node_key(candidate) in aliases and isinstance(value, dict):
                    stored_key = candidate
                    break
        if not stored_key:
            return []

        item = dict(nodes[stored_key])
        if routes_supported and "routes" in item:
            desired_routes = normalize_haproxy_routes(item.get("routes"))
            command_id = clean_haproxy_command_id(item.get("routes_command_id"))
            apply_result = normalize_haproxy_apply_result(node.get("haproxy_apply_result"))
            result_matches = bool(
                command_id
                and apply_result.get("command_id") == command_id
                and apply_result.get("status") in ("ok", "error")
            )
            applied = result_matches and apply_result.get("status") == "ok"
            failed = result_matches and apply_result.get("status") == "error"
            base_hashes = clean_haproxy_base_hashes(item.get("routes_base_hashes"))
            reported_hash = haproxy_routes_fingerprint(reported_routes)
            local_change = bool(
                desired_routes
                and reported_routes
                and base_hashes
                and reported_hash not in base_hashes
                and not haproxy_routes_equal(desired_routes, reported_routes)
                and not failed
            )
            if desired_routes and (applied or haproxy_routes_equal(desired_routes, reported_routes) or local_change):
                item.pop("routes", None)
                item.pop("updated_at", None)
                item.pop("routes_command_id", None)
                item.pop("routes_base_hashes", None)
                item.pop("routes_error_baseline", None)
                acknowledged.append("routes_local" if local_change and not applied else "routes")
        if bandwidth_supported and "bandwidth_limits" in item:
            desired_limits = normalize_haproxy_bandwidth_limits(item.get("bandwidth_limits"))
            command_id = clean_haproxy_command_id(item.get("bandwidth_command_id"))
            apply_result = normalize_haproxy_bandwidth_apply_result(
                node.get("haproxy_bandwidth_apply_result")
            )
            result_matches = bool(
                command_id
                and apply_result.get("command_id") == command_id
                and apply_result.get("status") in ("ok", "error")
            )
            applied = result_matches and apply_result.get("status") == "ok"
            failed = result_matches and apply_result.get("status") == "error"
            base_hashes = clean_haproxy_base_hashes(item.get("bandwidth_base_hashes"))
            reported_hash = haproxy_bandwidth_fingerprint(reported_limits)
            local_change = bool(
                base_hashes
                and reported_hash not in base_hashes
                and not haproxy_bandwidth_limits_equal(desired_limits, reported_limits)
                and not failed
            )
            if applied or haproxy_bandwidth_limits_equal(desired_limits, reported_limits) or local_change:
                item.pop("bandwidth_limits", None)
                item.pop("bandwidth_updated_at", None)
                item.pop("bandwidth_command_id", None)
                item.pop("bandwidth_base_hashes", None)
                item.pop("bandwidth_error_baseline", None)
                acknowledged.append("bandwidth_local" if local_change and not applied else "bandwidth")

        if not acknowledged:
            return []
        if "routes" not in item and "bandwidth_limits" not in item:
            nodes.pop(stored_key, None)
        else:
            nodes[stored_key] = item
        save_haproxy_state()

    log(f"haproxy command acknowledged node={key or stored_key}: {','.join(acknowledged)}")
    return acknowledged


def haproxy_desired_apply_error(node, kind, desired_item=None):
    item = dict(desired_item) if isinstance(desired_item, dict) else (haproxy_state_item_for_node(node) or {})
    if kind == "routes":
        desired_field = "routes"
        command_field = "routes_command_id"
        baseline_field = "routes_error_baseline"
        result = node.get("haproxy_apply_result")
    elif kind == "bandwidth":
        desired_field = "bandwidth_limits"
        command_field = "bandwidth_command_id"
        baseline_field = "bandwidth_error_baseline"
        result = node.get("haproxy_bandwidth_apply_result")
    else:
        return ""
    if desired_field not in item or not isinstance(result, dict):
        return ""
    if str(result.get("status") or "").lower() != "error":
        return ""
    desired_command_id = clean_haproxy_command_id(item.get(command_field))
    result_command_id = clean_haproxy_command_id(result.get("command_id"))
    if desired_command_id and result_command_id and desired_command_id != result_command_id:
        return ""
    result_fingerprint = haproxy_apply_result_fingerprint(result)
    if result_fingerprint and result_fingerprint == clean_haproxy_command_id(item.get(baseline_field)):
        return ""
    return clean_display_text(result.get("message") or "ошибка применения")[:160]


def retry_haproxy_desired_state(node, kind):
    key = haproxy_state_key(node)
    aliases = node_alias_keys(node)
    if kind == "routes":
        desired_field = "routes"
        desired_time_field = "updated_at"
        command_field = "routes_command_id"
        baseline_field = "routes_error_baseline"
        result = node.get("haproxy_apply_result")
    elif kind == "bandwidth":
        desired_field = "bandwidth_limits"
        desired_time_field = "bandwidth_updated_at"
        command_field = "bandwidth_command_id"
        baseline_field = "bandwidth_error_baseline"
        result = node.get("haproxy_bandwidth_apply_result")
    else:
        return False
    result_time = int((result or {}).get("updated_at") or 0) if isinstance(result, dict) else 0
    with LOCK:
        nodes = HAPROXY_STATE.setdefault("nodes", {})
        stored_key = key if isinstance(nodes.get(key), dict) else ""
        if not stored_key:
            for candidate, value in nodes.items():
                if canonical_node_key(candidate) in aliases and isinstance(value, dict):
                    stored_key = candidate
                    break
        if not stored_key or desired_field not in nodes[stored_key]:
            return False
        item = dict(nodes[stored_key])
        item[desired_time_field] = max(
            now_ts(),
            int(item.get(desired_time_field) or 0) + 1,
            result_time + 1,
        )
        item[command_field] = new_haproxy_command_id()
        item[baseline_field] = haproxy_apply_result_fingerprint(result)
        nodes[stored_key] = item
        save_haproxy_state()
    return True


def cleanup_haproxy_sessions_unlocked(current=None):
    current = int(current or now_ts())
    changed = False
    sessions = HAPROXY_STATE.setdefault("sessions", {})
    for token, item in list(sessions.items()):
        if not isinstance(item, dict) or current - int(item.get("created_at") or 0) > HAPROXY_SESSION_TTL:
            del sessions[token]
            changed = True
    pending = HAPROXY_STATE.setdefault("pending", {})
    for key, item in list(pending.items()):
        if not isinstance(item, dict) or current - int(item.get("created_at") or 0) > HAPROXY_SESSION_TTL:
            del pending[key]
            changed = True
    return changed


def normalize_haproxy_machine_choices(values):
    result = []
    for value in values if isinstance(values, (list, tuple)) else []:
        node_key = node_record_key(value) if isinstance(value, dict) else str(value or "").strip()
        node_key = str(node_key or "")[:200]
        if node_key and node_key not in result:
            result.append(node_key)
        if len(result) >= HAPROXY_MAX_MACHINE_CHOICES:
            break
    return result


def haproxy_machine_nodes():
    with LOCK:
        nodes = [dict(node) for node in dedupe_nodes(NODES.values()) if isinstance(node, dict)]
    return sorted(nodes, key=node_natural_sort_key)


def create_haproxy_session(node, chat_id, message_id="", node_choices=None):
    with LOCK:
        cleanup_haproxy_sessions_unlocked()
        token = ""
        while not token or token in HAPROXY_STATE.setdefault("sessions", {}):
            token = uuid.uuid4().hex[:10]
        HAPROXY_STATE["sessions"][token] = {
            "node_key": haproxy_state_key(node) if isinstance(node, dict) else "",
            "node_name": node_display_name(node) if isinstance(node, dict) else "",
            "node_choices": normalize_haproxy_machine_choices(node_choices),
            "page": 0,
            "selected_ip": "",
            "chat_id": str(chat_id),
            "message_id": str(message_id or ""),
            "created_at": now_ts(),
        }
        save_haproxy_state()
    return token


def create_haproxy_machine_session(chat_id, message_id=""):
    return create_haproxy_session(
        None,
        chat_id,
        message_id,
        node_choices=haproxy_machine_nodes(),
    )


def get_haproxy_session(token):
    token = str(token or "")
    with LOCK:
        changed = cleanup_haproxy_sessions_unlocked()
        item = HAPROXY_STATE.setdefault("sessions", {}).get(token)
        if changed:
            save_haproxy_state()
        return dict(item) if isinstance(item, dict) else None


def update_haproxy_session(token, **changes):
    with LOCK:
        item = HAPROXY_STATE.setdefault("sessions", {}).get(str(token or ""))
        if not isinstance(item, dict):
            return None
        for key, limit in (("node_key", 200), ("node_name", 120), ("selected_ip", 64), ("chat_id", 64), ("message_id", 64)):
            if key in changes:
                item[key] = str(changes[key] or "")[:limit]
        if "page" in changes:
            try:
                item["page"] = max(0, min(int(changes["page"] or 0), 10000))
            except Exception:
                item["page"] = 0
        item["created_at"] = now_ts()
        save_haproxy_state()
        return dict(item)


def set_pending_haproxy(chat_id, from_id, action, token, **extra):
    key = pending_key(chat_id, from_id)
    with LOCK:
        item = {
            "action": str(action),
            "token": str(token),
            "created_at": now_ts(),
        }
        item.update(extra)
        HAPROXY_STATE.setdefault("pending", {})[key] = item
        save_haproxy_state()


def peek_pending_haproxy(chat_id, from_id):
    key = pending_key(chat_id, from_id)
    with LOCK:
        changed = cleanup_haproxy_sessions_unlocked()
        item = HAPROXY_STATE.setdefault("pending", {}).get(key)
        if changed:
            save_haproxy_state()
        return dict(item) if isinstance(item, dict) else None


def pop_pending_haproxy(chat_id, from_id):
    key = pending_key(chat_id, from_id)
    with LOCK:
        item = HAPROXY_STATE.setdefault("pending", {}).pop(key, None)
        if item is not None:
            save_haproxy_state()
        return dict(item) if isinstance(item, dict) else None


def haproxy_session_node(session):
    if not isinstance(session, dict):
        return None
    return find_node(session.get("node_key")) or find_node(session.get("node_name"))


def haproxy_node_ips(node, routes):
    result = []
    for entry in node_ip_stats(node):
        ip_text = normalize_ipv4_text(entry.get("ip"))
        if ip_text and ip_text not in result:
            result.append(ip_text)
    fallback = normalize_ipv4_text(node.get("ip"))
    if fallback and fallback not in result:
        result.append(fallback)
    for route in routes:
        listen_ip = route.get("listen_ip")
        if valid_ipv4(listen_ip) and listen_ip not in result:
            result.append(listen_ip)
    route_counts = {}
    for route in routes:
        listen_ip = str(route.get("listen_ip") or "")
        route_counts[listen_ip] = route_counts.get(listen_ip, 0) + 1

    def sort_key(ip_text):
        route_count = route_counts.get(ip_text, 0)
        if ip_text == "*":
            return (-route_count, -1)
        try:
            numeric_ip = int(ipaddress.ip_address(ip_text))
        except ValueError:
            numeric_ip = (1 << 32)
        return (-route_count, numeric_ip)

    return sorted(result, key=sort_key)


def haproxy_routes_for_ip(routes, listen_ip):
    return [route for route in routes if route.get("listen_ip") == listen_ip]


def haproxy_route_for_endpoint(routes, listen_ip, port):
    for route in routes:
        if route.get("listen_ip") == listen_ip and int(route.get("port") or 0) == int(port):
            return route
    return None


def replace_haproxy_route(routes, current_listen_ip, current_port, **changes):
    updated = [dict(route) for route in routes]
    for index, route in enumerate(updated):
        if route.get("listen_ip") == current_listen_ip and int(route.get("port") or 0) == int(current_port):
            changed = dict(route)
            changed.update(changes)
            updated[index] = changed
            return updated, changed
    raise ValueError("haproxy route not found")


def haproxy_apply_status_text(node, desired, reported):
    if desired is None:
        return "текущий config машины"
    if haproxy_routes_equal(desired, reported):
        return "применено"
    message = haproxy_desired_apply_error(node, "routes")
    if message:
        return f"ошибка: {message[:120]}"
    return "ожидает ближайший push"


def haproxy_bandwidth_rate_for_ip(limits, ip_text):
    for item in normalize_haproxy_bandwidth_limits(limits):
        if item.get("ip") == ip_text:
            return int(item.get("rate_mbit") or 0)
    return 0


def haproxy_bandwidth_apply_status_text(node, desired, reported):
    if desired is None:
        return "текущий config машины"
    if haproxy_bandwidth_limits_equal(desired, reported):
        return "применено"
    message = haproxy_desired_apply_error(node, "bandwidth")
    if message:
        return f"ошибка: {message[:120]}"
    return "ожидает ближайший push"


def haproxy_primary_node_ip(node):
    local_ips = []
    for entry in node_ip_stats(node):
        ip_text = normalize_ipv4_text(entry.get("ip"))
        if ip_text and ip_text not in local_ips:
            local_ips.append(ip_text)
    remote_ip = normalize_ipv4_text(node.get("ip"))
    if remote_ip and remote_ip in local_ips:
        return remote_ip
    if local_ips:
        return local_ips[0]
    return remote_ip


def build_haproxy_source_pinned_routes(node, routes):
    routes = normalize_haproxy_routes(routes, strict=True)
    default_ip = haproxy_primary_node_ip(node)
    exact_endpoints = {
        (route["listen_ip"], int(route["port"]))
        for route in routes
        if route.get("listen_ip") != "*"
    }
    emitted_endpoints = set()
    updated = []
    preview = []
    for route in routes:
        changed = dict(route)
        listen_ip = route.get("listen_ip")
        if listen_ip == "*":
            target_ip = route.get("source_ip")
            if target_ip == "default":
                target_ip = default_ip
            target_ip = normalize_ipv4_text(target_ip)
            if not target_ip:
                raise ValueError(f"не удалось определить IP для *:{int(route['port'])}")
            endpoint = (target_ip, int(route["port"]))
            if endpoint in exact_endpoints or endpoint in emitted_endpoints:
                raise ValueError(f"точечный listener {target_ip}:{int(route['port'])} уже существует")
            changed["listen_ip"] = target_ip
            changed["source_ip"] = target_ip
            preview.append((int(route["port"]), target_ip))
        else:
            changed["source_ip"] = listen_ip
        changed["server_maxconn"] = HAPROXY_BACKEND_MAXCONN
        endpoint = (changed["listen_ip"], int(changed["port"]))
        if endpoint in emitted_endpoints:
            raise ValueError(f"listener {endpoint[0]}:{endpoint[1]} повторяется")
        emitted_endpoints.add(endpoint)
        updated.append(changed)
    return normalize_haproxy_routes(updated, strict=True), preview


def haproxy_machine_selector_payload(token, page=None):
    session = get_haproxy_session(token) or {}
    choices = normalize_haproxy_machine_choices(session.get("node_choices"))
    available = []
    for choice_index, node_key in enumerate(choices):
        node = find_node(node_key)
        if node is not None:
            available.append((choice_index, node))
    try:
        requested_page = int(session.get("page") or 0) if page is None else int(page)
    except Exception:
        requested_page = 0
    page_count = max(1, (len(available) + HAPROXY_MACHINE_PAGE_SIZE - 1) // HAPROXY_MACHINE_PAGE_SIZE)
    current_page = max(0, min(requested_page, page_count - 1))
    start = current_page * HAPROXY_MACHINE_PAGE_SIZE
    page_items = available[start:start + HAPROXY_MACHINE_PAGE_SIZE]
    lines = [
        "<b>HAProxy</b>",
        ALERT_SEPARATOR,
        detail_line("Машин", len(available)),
        "",
        "<b>Выбери машину:</b>",
    ]
    if not available:
        lines += ["", "<i>Collector пока не получил данные от машин.</i>"]
    buttons = []
    for choice_index, node in page_items:
        label = node_display_name(node, "Без названия")[:64]
        buttons.append({"text": label, "callback_data": f"hpx:n:{token}:{choice_index}"})
    rows = [buttons[index:index + 2] for index in range(0, len(buttons), 2)]
    if page_count > 1:
        navigation = []
        if current_page > 0:
            navigation.append({"text": "Назад", "callback_data": f"hpx:g:{token}:{current_page - 1}"})
        navigation.append({"text": f"{current_page + 1}/{page_count}", "callback_data": f"hpx:g:{token}:{current_page}"})
        if current_page + 1 < page_count:
            navigation.append({"text": "Дальше", "callback_data": f"hpx:g:{token}:{current_page + 1}"})
        rows.append(navigation)
    return "\n".join(lines), {"inline_keyboard": rows} if rows else None


def haproxy_ip_selector_payload(node, token):
    routes, source = effective_haproxy_routes_for_node(node)
    reported = reported_haproxy_routes_for_node(node)
    desired = routes if source == "telegram" else None
    bandwidth_limits, _ = effective_haproxy_bandwidth_limits_for_node(node)
    routes_error = haproxy_desired_apply_error(node, "routes")
    bandwidth_error = haproxy_desired_apply_error(node, "bandwidth")
    ips = haproxy_node_ips(node, routes)
    status = haproxy_apply_status_text(node, desired, reported)
    wildcard_count = sum(1 for route in routes if route.get("listen_ip") == "*")
    lines = [
        "<b>HAProxy</b>",
        ALERT_SEPARATOR,
        detail_line("Машина", node_display_name(node)),
        detail_line("Статус", status),
        detail_line("FULL-бинды", wildcard_count),
        "",
        "<b>Выбери входной IP:</b>",
    ]
    if not ips:
        lines += ["", "<i>Машина пока не прислала ни одного IPv4.</i>"]
    buttons = []
    for ip_text in ips:
        count = len(haproxy_routes_for_ip(routes, ip_text))
        label = "Все IP (*)" if ip_text == "*" else ip_text
        buttons.append({"text": f"{label} · {count}", "callback_data": f"hpx:i:{token}:{ip_text}"})
    rows = [buttons[index:index + 2] for index in range(0, len(buttons), 2)]
    if wildcard_count:
        rows.append([{"text": "FULL → точечные бинды", "callback_data": f"hpx:p:{token}"}])
    if routes_error:
        rows.append([{"text": "Повторить применение маршрутов", "callback_data": f"hpx:R:{token}"}])
    if bandwidth_error:
        rows.append([{"text": "Повторить применение лимитов", "callback_data": f"hpx:L:{token}"}])
    if bandwidth_limits:
        rows.append([{"text": "Снять все лимиты скорости", "callback_data": f"hpx:C:{token}"}])
    footer = []
    if (get_haproxy_session(token) or {}).get("node_choices"):
        footer.append({"text": "К списку машин", "callback_data": f"hpx:m:{token}"})
    footer.append({"text": "Обновить", "callback_data": f"hpx:r:{token}"})
    rows.append(footer)
    return "\n".join(lines), {"inline_keyboard": rows}


def haproxy_target_summary(route):
    targets = list(route.get("targets") or [])
    if len(targets) == 1:
        return targets[0]
    return f"пул {len(targets)} backend ({targets[0]})" if targets else "-"


def haproxy_route_values_block(values, limit=8, max_chars=900):
    items = [str(value) for value in values or []]
    lines = []
    used_chars = 0
    for value in items:
        escaped = html.escape(value)
        if len(lines) >= limit or (lines and used_chars + len(escaped) > max_chars):
            break
        lines.append(f"<code>{escaped}</code>")
        used_chars += len(escaped)
    if len(items) > len(lines):
        lines.append(f"и ещё {len(items) - len(lines)}")
    return "<blockquote>" + "\n".join(lines or ["-"]) + "</blockquote>"


def haproxy_sni_values_block(values):
    return haproxy_route_values_block(haproxy_sni_display_values(values))


def haproxy_route_editor_payload(node, token, selected_ip, port):
    routes, source = effective_haproxy_routes_for_node(node)
    reported = reported_haproxy_routes_for_node(node)
    desired = routes if source == "telegram" else None
    route = haproxy_route_for_endpoint(routes, selected_ip, port)
    if route is None:
        return None, None
    listen_label = "Все IP (*)" if selected_ip == "*" else selected_ip
    proxy_v2_enabled = bool(route.get("send_proxy_v2"))
    lines = [
        "<b>HAProxy маршрут</b>",
        ALERT_SEPARATOR,
        detail_line("Машина", node_display_name(node)),
        detail_line("IP", listen_label),
        detail_line("Порт", f"{int(route['port'])}/tcp"),
        detail_line("Backend maxconn", haproxy_server_maxconn_label(route.get("server_maxconn"))),
        detail_line("PROXY protocol v2", "Включён" if proxy_v2_enabled else "Выключен"),
        detail_line("Статус", haproxy_apply_status_text(node, desired, reported)),
        "",
        "<b>Backend:</b>",
        haproxy_route_values_block(route.get("targets") or []),
        "<b>SNI:</b>",
        haproxy_sni_values_block(route.get("sni") or []),
        "",
        "<i>Включай PROXY v2 только если backend ожидает PROXY protocol v2.</i>",
    ]
    rows = [
        [
            {"text": "Backend", "callback_data": f"hpx:k:{token}:{int(route['port'])}"},
            {"text": "SNI", "callback_data": f"hpx:c:{token}:{int(route['port'])}"},
        ],
        [
            {"text": "IP", "callback_data": f"hpx:o:{token}:{int(route['port'])}"},
            {"text": "Входной порт", "callback_data": f"hpx:w:{token}:{int(route['port'])}"},
        ],
        [{
            "text": f"PROXY v2: {'ON' if proxy_v2_enabled else 'OFF'}",
            "callback_data": f"hpx:t:{token}:{int(route['port'])}",
        }],
        [{"text": "Удалить маршрут", "callback_data": f"hpx:q:{token}:{int(route['port'])}"}],
        [
            {"text": "К маршрутам", "callback_data": f"hpx:s:{token}"},
            {"text": "Обновить", "callback_data": f"hpx:v:{token}:{int(route['port'])}"},
        ],
    ]
    return "\n".join(lines), {"inline_keyboard": rows}


def haproxy_route_ip_choices(node, route, field=None):
    values = []
    current = str(route.get("listen_ip") or "")
    routes, _ = effective_haproxy_routes_for_node(node)
    for ip_text in haproxy_node_ips(node, routes):
        if valid_ipv4(ip_text) and ip_text not in values:
            values.append(ip_text)
    if valid_ipv4(current) and current not in values:
        values.append(current)
    return values


def haproxy_route_ip_selector_payload(node, token, route, field):
    current = str(route.get("listen_ip") or "")
    title = "Новый IP маршрута"
    current_label = current or "не определён"
    lines = [
        f"<b>{title}</b>",
        ALERT_SEPARATOR,
        detail_line("Машина", node_display_name(node)),
        detail_line("Маршрут", f"{route.get('listen_ip')}:{int(route['port'])}/tcp"),
        detail_line("Сейчас", current_label),
        "",
        "<b>Выбери IP:</b>",
    ]
    buttons = []
    for value in haproxy_route_ip_choices(node, route, field):
        label = value
        if value == current:
            label += " · сейчас"
        buttons.append({
            "text": label,
            "callback_data": f"hpx:h:{token}:{int(route['port'])}|{value}",
        })
    rows = [buttons[index:index + 2] for index in range(0, len(buttons), 2)]
    rows.append([{"text": "Назад", "callback_data": f"hpx:v:{token}:{int(route['port'])}"}])
    return "\n".join(lines), {"inline_keyboard": rows}


def haproxy_selected_ip_payload(node, token, selected_ip):
    routes, source = effective_haproxy_routes_for_node(node)
    reported = reported_haproxy_routes_for_node(node)
    desired = routes if source == "telegram" else None
    selected_routes = haproxy_routes_for_ip(routes, selected_ip)
    label = "Все IP (*)" if selected_ip == "*" else selected_ip
    bandwidth_limits, bandwidth_source = effective_haproxy_bandwidth_limits_for_node(node)
    reported_bandwidth = reported_haproxy_bandwidth_limits_for_node(node)
    desired_bandwidth = bandwidth_limits if bandwidth_source == "telegram" else None
    bandwidth_rate = haproxy_bandwidth_rate_for_ip(bandwidth_limits, selected_ip) if selected_ip != "*" else 0
    lines = [
        "<b>HAProxy маршруты</b>",
        ALERT_SEPARATOR,
        detail_line("Машина", node_display_name(node)),
        detail_line("Входной IP", label),
        detail_line("Статус", haproxy_apply_status_text(node, desired, reported)),
    ]
    if selected_ip != "*":
        if bool(node.get("haproxy_bandwidth_supported")):
            speed_text = f"{bandwidth_rate} Mbit/s на RX и TX" if bandwidth_rate else "без ограничения"
            lines.append(detail_line("Скорость", speed_text))
            if desired_bandwidth is not None:
                lines.append(detail_line("Статус скорости", haproxy_bandwidth_apply_status_text(node, desired_bandwidth, reported_bandwidth)))
        else:
            lines.append(detail_line("Скорость", "нужно обновить push"))
    lines.append("")
    if not selected_routes:
        lines.append("<i>На этом IP маршрутов пока нет.</i>")
    else:
        lines.append("<b>Маршруты:</b>")
        route_lines = []
        for route in selected_routes:
            sni_values = list(route.get("sni") or [])
            sni_text = " ".join(sni_values[:3])
            if len(sni_values) > 3:
                sni_text += f" +{len(sni_values) - 3}"
            route_lines.append(
                f"<b>{int(route['port'])}/tcp</b> → {html.escape(haproxy_target_summary(route))}\n"
                f"SNI: <code>{html.escape(sni_text)}</code>"
            )
        lines.append("<blockquote>" + "\n\n".join(route_lines) + "</blockquote>")
        lines += ["", "<b>Выбери маршрут для настройки:</b>"]
    rows = []
    if selected_routes:
        route_buttons = [
            {"text": f"{int(route['port'])}/tcp", "callback_data": f"hpx:v:{token}:{int(route['port'])}"}
            for route in selected_routes
        ]
        rows += [route_buttons[index:index + 2] for index in range(0, len(route_buttons), 2)]
    rows.append([{"text": "Добавить порт", "callback_data": f"hpx:a:{token}"}])
    if selected_ip != "*" and bool(node.get("haproxy_bandwidth_supported")):
        speed_button = "Изменить скорость" if bandwidth_rate else "Ограничить скорость"
        rows.append([{"text": speed_button, "callback_data": f"hpx:l:{token}"}])
    rows.append([
        {"text": "К списку IP", "callback_data": f"hpx:b:{token}"},
        {"text": "Обновить", "callback_data": f"hpx:r:{token}"},
    ])
    return "\n".join(lines), {"inline_keyboard": rows}


def haproxy_route_selector_payload(node, token, selected_ip, action):
    routes, _ = effective_haproxy_routes_for_node(node)
    selected_routes = haproxy_routes_for_ip(routes, selected_ip)
    title = "Какой маршрут изменить?" if action == "edit" else "Какой маршрут удалить?"
    lines = [
        f"<b>{title}</b>",
        ALERT_SEPARATOR,
        detail_line("Машина", node_display_name(node)),
        detail_line("Входной IP", "Все IP (*)" if selected_ip == "*" else selected_ip),
    ]
    callback_action = "x" if action == "edit" else "q"
    buttons = [
        {"text": f"{int(route['port'])}/tcp", "callback_data": f"hpx:{callback_action}:{token}:{int(route['port'])}"}
        for route in selected_routes
    ]
    rows = [buttons[index:index + 2] for index in range(0, len(buttons), 2)]
    rows.append([{"text": "Назад", "callback_data": f"hpx:s:{token}"}])
    return "\n".join(lines), {"inline_keyboard": rows}


def edit_haproxy_session_message(token, text, reply_markup=None):
    session = get_haproxy_session(token)
    if not session:
        return False
    if edit_message_text(session.get("chat_id"), session.get("message_id"), text, reply_markup=reply_markup):
        return True
    sent = send_message(text, reply_markup=reply_markup)
    if isinstance(sent, dict):
        update_haproxy_session(token, message_id=sent.get("message_id"), chat_id=(sent.get("chat") or {}).get("id"))
        return True
    return False


def show_haproxy_machine_selector(token, page=None):
    session = get_haproxy_session(token)
    if not session:
        return False
    if page is not None:
        session = update_haproxy_session(token, page=page) or session
    body, markup = haproxy_machine_selector_payload(token, session.get("page") or 0)
    return edit_haproxy_session_message(token, body, markup)


def show_haproxy_ip_selector(token):
    session = get_haproxy_session(token)
    node = haproxy_session_node(session)
    if not session or node is None:
        return False
    body, markup = haproxy_ip_selector_payload(node, token)
    return edit_haproxy_session_message(token, body, markup)


def show_haproxy_selected_ip(token):
    session = get_haproxy_session(token)
    node = haproxy_session_node(session)
    selected_ip = str((session or {}).get("selected_ip") or "")
    if not session or node is None or not selected_ip:
        return False
    body, markup = haproxy_selected_ip_payload(node, token, selected_ip)
    return edit_haproxy_session_message(token, body, markup)


def show_haproxy_route_editor(token, port):
    session = get_haproxy_session(token)
    node = haproxy_session_node(session)
    selected_ip = str((session or {}).get("selected_ip") or "")
    if not session or node is None or not selected_ip:
        return False
    body, markup = haproxy_route_editor_payload(node, token, selected_ip, port)
    if body is None:
        return show_haproxy_selected_ip(token)
    return edit_haproxy_session_message(token, body, markup)


def haproxy_node_menu_error(node):
    if not bool(node.get("haproxy_routes_supported")):
        return (
            "<b>Нужен новый push на машине</b>\n"
            f"{ALERT_SEPARATOR}\n"
            f"{detail_line('Машина', node_display_name(node))}\n\n"
            "Обнови push через <code>/update_collector_wl</code> или <code>/update_collector_bl</code>, "
            "дождись следующего push и повтори команду."
        )
    if not bool(node.get("haproxy_routes_managed")):
        return (
            "<b>Удалённое изменение заблокировано</b>\n"
            f"{ALERT_SEPARATOR}\n"
            f"{detail_line('Машина', node_display_name(node))}\n\n"
            "Текущий <code>haproxy.cfg</code> не помечен как управляемый kto. "
            "Я не буду целиком перезаписывать сторонний config. Сначала импортируй или пересоздай его через HAProxy-меню на машине."
        )
    return ""


def handle_haproxy_command(text, chat_id, from_id):
    parts = text.split(maxsplit=1)
    if len(parts) < 2 or not parts[1].strip():
        pop_pending_haproxy(chat_id, from_id)
        pop_pending_sni(chat_id, from_id)
        token = create_haproxy_machine_session(chat_id)
        body, markup = haproxy_machine_selector_payload(token)
        sent = send_message(body, reply_markup=markup)
        if isinstance(sent, dict):
            update_haproxy_session(
                token,
                chat_id=(sent.get("chat") or {}).get("id") or chat_id,
                message_id=sent.get("message_id"),
            )
        return
    query = parts[1].strip()
    node = find_node(query)
    if node is None:
        send_message(
            "<b>Не нашёл такую машину</b>\n\n"
            f"{detail_line('Запрос', query)}\n"
            f"Сначала проверь название через <code>/stats</code>."
        )
        return
    error_text = haproxy_node_menu_error(node)
    if error_text:
        send_message(error_text)
        return
    pop_pending_haproxy(chat_id, from_id)
    pop_pending_sni(chat_id, from_id)
    token = create_haproxy_session(node, chat_id)
    body, markup = haproxy_ip_selector_payload(node, token)
    sent = send_message(body, reply_markup=markup)
    if isinstance(sent, dict):
        update_haproxy_session(
            token,
            chat_id=(sent.get("chat") or {}).get("id") or chat_id,
            message_id=sent.get("message_id"),
        )


def handle_sni_command(text, action, chat_id, from_id):
    parts = text.split(maxsplit=1)
    command = "/allow_sni" if action == "allow_sni" else "/delete_sni"
    if len(parts) < 2 or not parts[1].strip():
        send_message(f"<b>Пример:</b> <code>{command} Обход #8</code>")
        return
    query = parts[1].strip()
    node = find_node(query)
    if node is None:
        send_message(
            "<b>Не нашёл такой обход</b>\n\n"
            f"{detail_line('Запрос', query)}\n"
            f"Сначала проверь название через <code>/stats</code>."
        )
        return
    values, source = effective_sni_for_node(node)
    if action == "delete_sni" and not values:
        send_message(
            "<b>SNI allow-list пуст</b>\n\n"
            f"{detail_line('Машина', node_display_name(node))}"
        )
        return
    set_pending_sni(chat_id, from_id, action, node)
    send_message(sni_command_intro(action, node, values, source))


def handle_pending_sni(chat_id, from_id, text):
    pending = peek_pending_sni(chat_id, from_id)
    if not pending or pending.get("action") not in ("allow_sni", "delete_sni", "haproxy_target", "haproxy_sni"):
        return False
    node = find_node(pending.get("node_key")) or find_node(pending.get("node_name"))
    if node is None:
        pop_pending_sni(chat_id, from_id)
        send_message("<b>Обход больше не найден.</b>")
        return True
    action = pending.get("action")
    if action == "haproxy_target":
        raw_target = text.split()[0] if str(text or "").split() else ""
        try:
            target = normalize_haproxy_target(raw_target)
        except Exception:
            send_message("<b>Не понял backend.</b>\n\nПример: <code>1.2.3.4</code> или <code>1.2.3.4:8443</code>")
            return True
        current, _ = effective_sni_for_node(node)
        set_pending_sni(chat_id, from_id, "haproxy_sni", node, {"target": target})
        send_message(
            "<b>Backend принят</b>\n"
            f"{ALERT_SEPARATOR}\n"
            f"{detail_line('Машина', node_display_name(node))}\n"
            f"{detail_line('Backend', target)}\n\n"
            "<b>Сейчас разрешены:</b>\n"
            f"{sni_list_text(current)}\n\n"
            "Теперь напиши SNI для allow-list.\n"
            "Пример: <code>example.com</code> или <code>*.example.com</code>"
        )
        return True
    try:
        sni = normalize_sni(text.split()[0] if str(text or "").split() else "")
    except Exception:
        send_message("<b>Не понял SNI.</b>\n\nПример: <code>example.com</code> или <code>*.example.com</code>")
        return True
    if action == "haproxy_sni":
        target = normalize_haproxy_target_or_empty(pending.get("target"))
        if not target:
            pop_pending_sni(chat_id, from_id)
            send_message("<b>Backend потерялся.</b>\n\nЗапусти <code>/haproxy</code> заново.")
            return True
        target, updated = set_haproxy_override_for_node(node, target, [sni])
        pop_pending_sni(chat_id, from_id)
        send_message(
            "<b>HAProxy обновление сохранено</b>\n"
            f"{ALERT_SEPARATOR}\n"
            f"{detail_line('Машина', node_display_name(node))}\n"
            f"{detail_line('Backend', target)}\n"
            f"{detail_line('SNI', sni)}\n\n"
            "<b>Теперь разрешены:</b>\n"
            f"{sni_list_text(updated)}\n"
            "<i>Машина применит HAProxy config при ближайшем push.</i>"
        )
        return True
    current, _ = effective_sni_for_node(node)
    if action == "allow_sni":
        updated = normalize_sni_list(current + [sni])
        added = sni not in current
        set_sni_override_for_node(node, updated)
        pop_pending_sni(chat_id, from_id)
        status = "добавлен" if added else "уже был в списке"
        send_message(
            f"<b>SNI {status}</b>\n"
            f"{ALERT_SEPARATOR}\n"
            f"{detail_line('Машина', node_display_name(node))}\n"
            f"{detail_line('SNI', sni)}\n\n"
            "<b>Теперь разрешены:</b>\n"
            f"{sni_list_text(updated)}\n"
            "<i>Машина применит список при ближайшем push.</i>"
        )
        return True
    if sni not in current:
        send_message(
            "<b>Такого SNI нет в списке.</b>\n\n"
            f"{detail_line('SNI', sni)}\n\n"
            "<b>Сейчас разрешены:</b>\n"
            f"{sni_list_text(current)}"
        )
        return True
    updated = [item for item in current if item != sni]
    if not updated:
        send_message("<b>Последний SNI удалять нельзя.</b>\n\nТак можно случайно закрыть весь обход.")
        return True
    set_sni_override_for_node(node, updated)
    pop_pending_sni(chat_id, from_id)
    send_message(
        "<b>SNI удалён</b>\n"
        f"{ALERT_SEPARATOR}\n"
        f"{detail_line('Машина', node_display_name(node))}\n"
        f"{detail_line('SNI', sni)}\n\n"
        "<b>Теперь разрешены:</b>\n"
        f"{sni_list_text(updated)}\n"
        "<i>Машина применит список при ближайшем push.</i>"
    )
    return True


def parse_haproxy_sni_input(value):
    return normalize_haproxy_sni_list(value)


def haproxy_targets_prompt(node, token, route=None, adding=False):
    selected_ip = (get_haproxy_session(token) or {}).get("selected_ip") or "*"
    lines = [
        "<b>Новый backend</b>" if not adding else "<b>Backend нового маршрута</b>",
        ALERT_SEPARATOR,
        detail_line("Машина", node_display_name(node)),
        detail_line("Вход", f"{selected_ip}:{int((route or {}).get('port') or 0)}"),
    ]
    if route:
        lines += [
            "",
            "<b>Сейчас:</b>",
            "<blockquote>" + "\n".join(f"<code>{html.escape(item)}</code>" for item in route.get("targets") or []) + "</blockquote>",
        ]
    lines += [
        "",
        "Ответь одним или несколькими backend: <code>IP:порт</code>.",
        "Для пула перечисли их через пробел, запятую или с новой строки.",
    ]
    if route:
        lines.append("Ответ <code>=</code> оставит backend без изменений.")
    lines.append("Отмена: <code>/cancel</code>")
    return "\n".join(lines)


def haproxy_sni_prompt(node, token, route=None, adding=False):
    selected_ip = (get_haproxy_session(token) or {}).get("selected_ip") or "*"
    lines = [
        "<b>SNI нового маршрута</b>" if adding else "<b>Новый SNI allow-list</b>",
        ALERT_SEPARATOR,
        detail_line("Машина", node_display_name(node)),
        detail_line("Вход", f"{selected_ip}:{int((route or {}).get('port') or 0)}"),
    ]
    if route:
        lines += ["", "<b>Сейчас:</b>", haproxy_sni_values_block(route.get("sni") or [])]
    lines += [
        "",
        "Ответь SNI через пробел, запятую или с новой строки.",
        "Поддомены поддерживаются: <code>*.example.com</code>.",
        "Чтобы пропускать любой SNI, ответь <code>any</code> или <code>*</code>.",
    ]
    if route:
        lines.append("Ответ <code>=</code> оставит SNI без изменений.")
    lines.append("Отмена: <code>/cancel</code>")
    return "\n".join(lines)


def haproxy_pending_context(chat_id, from_id):
    pending = peek_pending_haproxy(chat_id, from_id)
    if not pending:
        return None, None, None
    session = get_haproxy_session(pending.get("token"))
    node = haproxy_session_node(session)
    if not session or node is None:
        pop_pending_haproxy(chat_id, from_id)
        return pending, None, None
    return pending, session, node


def handle_pending_haproxy(chat_id, from_id, text):
    pending, session, node = haproxy_pending_context(chat_id, from_id)
    if not pending:
        return False
    token = pending.get("token")
    if not session or node is None:
        send_message("<b>HAProxy-сессия устарела.</b>\n\nЗапусти <code>/haproxy</code> заново.")
        return True
    action = str(pending.get("action") or "")
    selected_ip = str(session.get("selected_ip") or "")
    routes, _ = effective_haproxy_routes_for_node(node)
    if action == "bandwidth_rate":
        if not valid_ipv4(selected_ip) or not bool(node.get("haproxy_bandwidth_supported")):
            pop_pending_haproxy(chat_id, from_id)
            edit_haproxy_session_message(token, "<b>Управление скоростью для этого IP недоступно.</b>\n\nОбнови меню и выбери конкретный IPv4.")
            return True
        rate_text = str(text or "").strip().lower()
        if rate_text in ("off", "none", "без лимита", "без ограничения", "убрать"):
            rate_text = "0"
        if not rate_text.isdigit() or not 0 <= int(rate_text) <= HAPROXY_MAX_BANDWIDTH_MBIT:
            edit_haproxy_session_message(
                token,
                "<b>Не понял скорость.</b>\n\n"
                f"Ответь числом от <code>1</code> до <code>{HAPROXY_MAX_BANDWIDTH_MBIT}</code> Mbit/s.\n"
                "<code>0</code> уберёт ограничение.\nОтмена: <code>/cancel</code>",
            )
            return True
        rate_mbit = int(rate_text)
        limits, _ = effective_haproxy_bandwidth_limits_for_node(node)
        updated_limits = [item for item in limits if item.get("ip") != selected_ip]
        if rate_mbit > 0:
            updated_limits.append({"ip": selected_ip, "rate_mbit": rate_mbit})
        try:
            set_haproxy_bandwidth_limits_for_node(node, updated_limits)
        except Exception as exc:
            log(f"haproxy bandwidth save failed node={haproxy_state_key(node)}: {exc}")
            edit_haproxy_session_message(token, "<b>Лимит скорости не сохранён.</b>\n\nПроверка отклонила IP или значение скорости.")
            return True
        pop_pending_haproxy(chat_id, from_id)
        show_haproxy_selected_ip(token)
        return True
    if action == "add_port":
        port_text = str(text or "").strip()
        if not port_text.isdigit() or not 1 <= int(port_text) <= 65535:
            edit_haproxy_session_message(
                token,
                "<b>Не понял порт.</b>\n\nОтветь числом от <code>1</code> до <code>65535</code>.\nОтмена: <code>/cancel</code>",
            )
            return True
        port = int(port_text)
        if haproxy_route_for_endpoint(routes, selected_ip, port):
            edit_haproxy_session_message(
                token,
                f"<b>Маршрут уже существует</b>\n\n{detail_line('Вход', f'{selected_ip}:{port}')}\n"
                "Выбери другой порт или отмени: <code>/cancel</code>",
            )
            return True
        if selected_ip == "*" and any(int(route.get("port") or 0) == port for route in routes):
            edit_haproxy_session_message(token, "<b>Этот порт уже занят точечным bind.</b>\n\nWildcard <code>*:порт</code> с ним несовместим.")
            return True
        if selected_ip != "*" and haproxy_route_for_endpoint(routes, "*", port):
            edit_haproxy_session_message(
                token,
                "<b>Этот порт занят FULL-bind.</b>\n\nСначала перенеси <code>*:порт</code> на конкретный IP через консольное HAProxy-меню.",
            )
            return True
        route = {"port": port}
        set_pending_haproxy(chat_id, from_id, "add_targets", token, port=port)
        edit_haproxy_session_message(token, haproxy_targets_prompt(node, token, route=route, adding=True))
        return True

    port = int(pending.get("port") or 0)
    pending_listen_ip = str(pending.get("listen_ip") or selected_ip)
    current_route = haproxy_route_for_endpoint(routes, pending_listen_ip, port)
    route_field_actions = {"route_targets", "route_sni", "route_port"}
    if action in route_field_actions:
        if current_route is None:
            pop_pending_haproxy(chat_id, from_id)
            edit_haproxy_session_message(token, "<b>Маршрут уже изменился.</b>\n\nВернись к списку и выбери его заново.")
            return True
        raw_text = str(text or "").strip()
        changes = {}
        if action == "route_targets":
            if raw_text == "=":
                changes["targets"] = list(current_route.get("targets") or [])
            else:
                try:
                    changes["targets"] = normalize_haproxy_targets(raw_text)
                except Exception:
                    edit_haproxy_session_message(
                        token,
                        "<b>Не понял backend.</b>\n\nПример: <code>1.2.3.4:443</code>\n"
                        "Пул: <code>1.2.3.4:443 5.6.7.8:443</code>\nОтмена: <code>/cancel</code>",
                    )
                    return True
        elif action == "route_sni":
            if raw_text == "=":
                changes["sni"] = list(current_route.get("sni") or [])
            else:
                try:
                    changes["sni"] = parse_haproxy_sni_input(raw_text)
                except Exception:
                    edit_haproxy_session_message(
                        token,
                        "<b>Не понял SNI.</b>\n\nПример: <code>example.com *.example.net</code>\nОтмена: <code>/cancel</code>",
                    )
                    return True
        elif action == "route_port":
            if not raw_text.isdigit() or not 1 <= int(raw_text) <= 65535:
                edit_haproxy_session_message(
                    token,
                    "<b>Не понял порт.</b>\n\nОтветь числом от <code>1</code> до <code>65535</code>.\nОтмена: <code>/cancel</code>",
                )
                return True
            changes["port"] = int(raw_text)
        try:
            updated, changed_route = replace_haproxy_route(routes, pending_listen_ip, port, **changes)
            set_haproxy_routes_for_node(node, updated)
        except Exception as exc:
            log(f"haproxy route field save failed node={haproxy_state_key(node)}: {exc}")
            edit_haproxy_session_message(
                token,
                "<b>Маршрут не изменён.</b>\n\nПроверка нашла конфликт входного IP или порта. Введи другое значение или отмени: <code>/cancel</code>",
            )
            return True
        pop_pending_haproxy(chat_id, from_id)
        update_haproxy_session(token, selected_ip=str(changed_route.get("listen_ip") or pending_listen_ip))
        show_haproxy_route_editor(token, int(changed_route.get("port") or port))
        return True

    if action.startswith("edit_") and current_route is None:
        pop_pending_haproxy(chat_id, from_id)
        edit_haproxy_session_message(token, "<b>Маршрут уже изменился.</b>\n\nНажми «Обновить» и выбери его заново.")
        return True

    if action in ("add_targets", "edit_targets"):
        if str(text or "").strip() == "=" and current_route is not None:
            targets = list(current_route.get("targets") or [])
        else:
            try:
                targets = normalize_haproxy_targets(text)
            except Exception:
                edit_haproxy_session_message(
                    token,
                    "<b>Не понял backend.</b>\n\nПример: <code>1.2.3.4:443</code>\n"
                    "Пул: <code>1.2.3.4:443 5.6.7.8:443</code>\nОтмена: <code>/cancel</code>",
                )
                return True
        next_action = "add_sni" if action == "add_targets" else "edit_sni"
        set_pending_haproxy(chat_id, from_id, next_action, token, port=port, targets=targets)
        route_for_prompt = current_route or {"port": port}
        edit_haproxy_session_message(
            token,
            haproxy_sni_prompt(node, token, route=route_for_prompt, adding=action == "add_targets"),
        )
        return True

    if action not in ("add_sni", "edit_sni"):
        pop_pending_haproxy(chat_id, from_id)
        return False
    if str(text or "").strip() == "=" and current_route is not None:
        sni = list(current_route.get("sni") or [])
    else:
        try:
            sni = parse_haproxy_sni_input(text)
        except Exception:
            edit_haproxy_session_message(
                token,
                "<b>Не понял SNI.</b>\n\nПример: <code>example.com *.example.net</code>\nОтмена: <code>/cancel</code>",
            )
            return True
    targets = normalize_haproxy_targets(pending.get("targets"))
    updated = [dict(route) for route in routes]
    if action == "edit_sni":
        for index, route in enumerate(updated):
            if route.get("listen_ip") == selected_ip and int(route.get("port") or 0) == port:
                changed_route = dict(route)
                changed_route["targets"] = targets
                changed_route["sni"] = sni
                updated[index] = changed_route
                break
        else:
            pop_pending_haproxy(chat_id, from_id)
            edit_haproxy_session_message(token, "<b>Маршрут уже исчез.</b>\n\nНажми «Обновить».")
            return True
    else:
        updated.append({
            "listen_ip": selected_ip,
            "port": port,
            "targets": targets,
            "sni": sni,
            "source_ip": selected_ip if selected_ip != "*" else "default",
            "server_maxconn": HAPROXY_BACKEND_MAXCONN,
            "send_proxy_v2": False,
        })
    try:
        set_haproxy_routes_for_node(node, updated)
    except Exception as exc:
        log(f"haproxy route save failed node={haproxy_state_key(node)}: {exc}")
        edit_haproxy_session_message(token, "<b>Маршрут не сохранён.</b>\n\nПроверка нашла конфликт входного IP или порта.")
        return True
    pop_pending_haproxy(chat_id, from_id)
    if action == "add_sni":
        show_haproxy_route_editor(token, port)
    else:
        show_haproxy_selected_ip(token)
    return True


def handle_haproxy_callback(callback):
    callback_id = str(callback.get("id") or "")
    data = str(callback.get("data") or "")
    if not data.startswith("hpx:"):
        return False
    from_id = str((callback.get("from") or {}).get("id") or "")
    message = callback.get("message") or {}
    chat_id = str((message.get("chat") or {}).get("id") or CHAT_ID)
    message_id = str(message.get("message_id") or "")
    if chat_id != str(CHAT_ID) or from_id != ALLOWED_USER_ID:
        answer_callback(callback_id, "нет доступа")
        return True
    parts = data.split(":", 3)
    if len(parts) < 3:
        answer_callback(callback_id)
        return True
    action = parts[1]
    token = parts[2]
    value = parts[3] if len(parts) == 4 else ""
    session = get_haproxy_session(token)
    if not session:
        answer_callback(callback_id, "меню устарело")
        return True
    session = update_haproxy_session(token, chat_id=chat_id, message_id=message_id) or session

    if action == "g":
        if not value.isdigit():
            answer_callback(callback_id, "неверная страница")
            return True
        answer_callback(callback_id)
        show_haproxy_machine_selector(token, int(value))
        return True
    if action == "m":
        if not session.get("node_choices"):
            answer_callback(callback_id, "запусти /haproxy заново")
            return True
        pop_pending_haproxy(chat_id, from_id)
        pop_pending_sni(chat_id, from_id)
        update_haproxy_session(token, node_key="", node_name="", selected_ip="")
        answer_callback(callback_id, "список машин")
        show_haproxy_machine_selector(token)
        return True
    if action == "n":
        choices = normalize_haproxy_machine_choices(session.get("node_choices"))
        if not value.isdigit() or int(value) >= len(choices):
            answer_callback(callback_id, "машина больше не найдена")
            show_haproxy_machine_selector(token)
            return True
        node = find_node(choices[int(value)])
        if node is None:
            answer_callback(callback_id, "машина больше не найдена")
            show_haproxy_machine_selector(token)
            return True
        pop_pending_haproxy(chat_id, from_id)
        pop_pending_sni(chat_id, from_id)
        update_haproxy_session(
            token,
            node_key=haproxy_state_key(node),
            node_name=node_display_name(node),
            selected_ip="",
        )
        error_text = haproxy_node_menu_error(node)
        if error_text:
            answer_callback(callback_id, "управление недоступно")
            markup = {"inline_keyboard": [[{"text": "К списку машин", "callback_data": f"hpx:m:{token}"}]]}
            edit_haproxy_session_message(token, error_text, markup)
            return True
        answer_callback(callback_id, "список IP")
        show_haproxy_ip_selector(token)
        return True

    node = haproxy_session_node(session)
    if node is None:
        if session.get("node_choices"):
            answer_callback(callback_id, "сначала выбери машину")
            show_haproxy_machine_selector(token)
        else:
            answer_callback(callback_id, "меню устарело")
        return True
    routes, _ = effective_haproxy_routes_for_node(node)
    selected_ip = str(session.get("selected_ip") or "")

    if action == "i":
        if value not in haproxy_node_ips(node, routes):
            answer_callback(callback_id, "IP больше не найден")
            show_haproxy_ip_selector(token)
            return True
        pop_pending_haproxy(chat_id, from_id)
        update_haproxy_session(token, selected_ip=value)
        answer_callback(callback_id, "маршруты")
        show_haproxy_selected_ip(token)
        return True
    if action == "b":
        pop_pending_haproxy(chat_id, from_id)
        update_haproxy_session(token, selected_ip="")
        answer_callback(callback_id, "список IP")
        show_haproxy_ip_selector(token)
        return True
    if action == "r":
        answer_callback(callback_id, "обновляю")
        if selected_ip:
            show_haproxy_selected_ip(token)
        else:
            show_haproxy_ip_selector(token)
        return True
    if action in ("R", "L"):
        kind = "routes" if action == "R" else "bandwidth"
        if retry_haproxy_desired_state(node, kind):
            answer_callback(callback_id, "повторю при ближайшем push")
        else:
            answer_callback(callback_id, "нет команды для повтора")
        show_haproxy_ip_selector(token)
        return True
    if action == "C":
        limits, _ = effective_haproxy_bandwidth_limits_for_node(node)
        if not limits:
            answer_callback(callback_id, "лимитов уже нет")
            show_haproxy_ip_selector(token)
            return True
        answer_callback(callback_id)
        body = (
            "<b>Снять все лимиты скорости?</b>\n"
            f"{ALERT_SEPARATOR}\n"
            f"{detail_line('Машина', node_display_name(node))}\n"
            f"{detail_line('Ограниченных IP', len(limits))}\n\n"
            "Маршруты, backend и SNI не изменятся. При ближайшем push будут удалены только kernel-фильтры скорости."
        )
        markup = {"inline_keyboard": [[
            {"text": "Снять все лимиты", "callback_data": f"hpx:D:{token}"},
            {"text": "Отмена", "callback_data": f"hpx:r:{token}"},
        ]]}
        edit_haproxy_session_message(token, body, markup)
        return True
    if action == "D":
        try:
            set_haproxy_bandwidth_limits_for_node(node, [])
        except Exception as exc:
            log(f"haproxy bandwidth clear failed node={haproxy_state_key(node)}: {exc}")
            answer_callback(callback_id, "не удалось сохранить")
            return True
        answer_callback(callback_id, "лимиты будут сняты")
        show_haproxy_ip_selector(token)
        return True
    if action == "s":
        answer_callback(callback_id)
        show_haproxy_selected_ip(token)
        return True
    if action in ("p", "z"):
        try:
            pinned_routes, preview = build_haproxy_source_pinned_routes(node, routes)
        except Exception as exc:
            answer_callback(callback_id, "перенос не подготовлен")
            body = (
                "<b>FULL-бинды не изменены</b>\n"
                f"{ALERT_SEPARATOR}\n"
                f"{detail_line('Машина', node_display_name(node))}\n"
                f"{detail_line('Причина', clean_display_text(exc)[:160])}"
            )
            markup = {"inline_keyboard": [[{"text": "К списку IP", "callback_data": f"hpx:b:{token}"}]]}
            edit_haproxy_session_message(token, body, markup)
            return True
        if not preview:
            answer_callback(callback_id, "FULL-биндов нет")
            show_haproxy_ip_selector(token)
            return True
        if action == "p":
            answer_callback(callback_id)
            preview_lines = [f"<code>*:{port}</code> → <code>{html.escape(ip_text)}:{port}</code>" for port, ip_text in preview]
            if len(preview_lines) > 16:
                preview_lines = preview_lines[:16] + [f"и ещё {len(preview) - 16}"]
            body = (
                "<b>Перенести FULL-бинды?</b>\n"
                f"{ALERT_SEPARATOR}\n"
                f"{detail_line('Машина', node_display_name(node))}\n"
                f"{detail_line('Маршрутов', len(preview))}\n\n"
                "<blockquote>" + "\n".join(preview_lines) + "</blockquote>\n\n"
                "Каждый <code>*:порт</code> будет закреплён за настроенным выходным IP. "
                "Конфиг применится с проверкой и автоматическим откатом при ошибке."
            )
            markup = {"inline_keyboard": [[
                {"text": "Перенести", "callback_data": f"hpx:z:{token}"},
                {"text": "Отмена", "callback_data": f"hpx:b:{token}"},
            ]]}
            edit_haproxy_session_message(token, body, markup)
            return True
        try:
            set_haproxy_routes_for_node(node, pinned_routes)
        except Exception as exc:
            log(f"haproxy full bind save failed node={haproxy_state_key(node)}: {exc}")
            answer_callback(callback_id, "перенос не сохранён")
            return True
        pop_pending_haproxy(chat_id, from_id)
        update_haproxy_session(token, selected_ip="")
        answer_callback(callback_id, "ожидает ближайший push")
        show_haproxy_ip_selector(token)
        return True
    if not selected_ip:
        answer_callback(callback_id, "сначала выбери IP")
        show_haproxy_ip_selector(token)
        return True
    selected_routes = haproxy_routes_for_ip(routes, selected_ip)
    if action in ("h", "u"):
        route_value = value.split("|", 1)
        if len(route_value) != 2 or not route_value[0].isdigit():
            answer_callback(callback_id, "неверный маршрут")
            return True
        port = int(route_value[0])
        route = haproxy_route_for_endpoint(routes, selected_ip, port)
        if route is None:
            answer_callback(callback_id, "маршрут уже изменился")
            show_haproxy_selected_ip(token)
            return True
        try:
            new_value = normalize_ip(route_value[1])
        except Exception:
            answer_callback(callback_id, "неверный IP")
            return True
        if new_value not in haproxy_route_ip_choices(node, route):
            answer_callback(callback_id, "этого IP нет на машине")
            return True
        if new_value == route.get("listen_ip") and new_value == route.get("source_ip"):
            answer_callback(callback_id, "без изменений")
            show_haproxy_route_editor(token, port)
            return True
        try:
            updated, changed_route = replace_haproxy_route(
                routes,
                selected_ip,
                port,
                listen_ip=new_value,
                source_ip=new_value,
                server_maxconn=HAPROXY_BACKEND_MAXCONN,
            )
            set_haproxy_routes_for_node(node, updated)
        except Exception as exc:
            log(f"haproxy route ip save failed node={haproxy_state_key(node)}: {exc}")
            answer_callback(callback_id, "IP или порт уже занят")
            return True
        pop_pending_haproxy(chat_id, from_id)
        selected_ip = str(changed_route.get("listen_ip") or selected_ip)
        update_haproxy_session(token, selected_ip=selected_ip)
        answer_callback(callback_id, "ожидает ближайший push")
        show_haproxy_route_editor(token, int(changed_route.get("port") or port))
        return True
    if action in ("v", "k", "c", "o", "w", "f", "j", "t"):
        if not value.isdigit():
            answer_callback(callback_id, "неверный порт")
            return True
        port = int(value)
        route = haproxy_route_for_endpoint(routes, selected_ip, port)
        if route is None:
            answer_callback(callback_id, "маршрут уже изменился")
            show_haproxy_selected_ip(token)
            return True
        pop_pending_haproxy(chat_id, from_id)
        if action == "v":
            answer_callback(callback_id, "маршрут")
            show_haproxy_route_editor(token, port)
            return True
        if action == "t":
            enabled = not bool(route.get("send_proxy_v2"))
            try:
                updated, changed_route = replace_haproxy_route(
                    routes,
                    selected_ip,
                    port,
                    send_proxy_v2=enabled,
                )
                set_haproxy_routes_for_node(node, updated)
            except Exception as exc:
                log(f"haproxy proxy-v2 save failed node={haproxy_state_key(node)}: {exc}")
                answer_callback(callback_id, "не удалось сохранить")
                return True
            answer_callback(callback_id, "PROXY v2 включён" if enabled else "PROXY v2 выключен")
            show_haproxy_route_editor(token, int(changed_route.get("port") or port))
            return True
        if action == "k":
            set_pending_haproxy(chat_id, from_id, "route_targets", token, listen_ip=selected_ip, port=port)
            answer_callback(callback_id, "жду backend")
            edit_haproxy_session_message(token, haproxy_targets_prompt(node, token, route=route))
            return True
        if action == "c":
            set_pending_haproxy(chat_id, from_id, "route_sni", token, listen_ip=selected_ip, port=port)
            answer_callback(callback_id, "жду SNI")
            edit_haproxy_session_message(token, haproxy_sni_prompt(node, token, route=route))
            return True
        if action in ("o", "f"):
            answer_callback(callback_id)
            body, markup = haproxy_route_ip_selector_payload(
                node,
                token,
                route,
                "listen_ip",
            )
            edit_haproxy_session_message(token, body, markup)
            return True
        if action == "w":
            set_pending_haproxy(chat_id, from_id, "route_port", token, listen_ip=selected_ip, port=port)
            answer_callback(callback_id, "жду порт")
            edit_haproxy_session_message(
                token,
                "<b>Новый входной порт</b>\n"
                f"{ALERT_SEPARATOR}\n"
                f"{detail_line('Машина', node_display_name(node))}\n"
                f"{detail_line('Сейчас', f'{selected_ip}:{port}/tcp')}\n\n"
                "Ответь числом от <code>1</code> до <code>65535</code>.\nОтмена: <code>/cancel</code>",
            )
            return True
        answer_callback(callback_id, "maxconn: auto от global и размера пула")
        show_haproxy_route_editor(token, port)
        return True
    if action == "l":
        if selected_ip == "*" or not valid_ipv4(selected_ip) or not bool(node.get("haproxy_bandwidth_supported")):
            answer_callback(callback_id, "выбери конкретный IPv4")
            return True
        limits, _ = effective_haproxy_bandwidth_limits_for_node(node)
        current_rate = haproxy_bandwidth_rate_for_ip(limits, selected_ip)
        set_pending_haproxy(chat_id, from_id, "bandwidth_rate", token)
        answer_callback(callback_id, "жду скорость")
        edit_haproxy_session_message(
            token,
            "<b>Лимит скорости HAProxy</b>\n"
            f"{ALERT_SEPARATOR}\n"
            f"{detail_line('Машина', node_display_name(node))}\n"
            f"{detail_line('Входной IP', selected_ip)}\n"
            f"{detail_line('Сейчас', f'{current_rate} Mbit/s на RX и TX' if current_rate else 'без ограничения')}\n\n"
            f"Ответь числом от <code>1</code> до <code>{HAPROXY_MAX_BANDWIDTH_MBIT}</code> Mbit/s.\n"
            "Лимит применяется отдельно к RX и TX только для HAProxy на этом IP.\n"
            "<code>0</code> уберёт ограничение.\nОтмена: <code>/cancel</code>",
        )
        return True
    if action in ("e", "d"):
        if not selected_routes:
            answer_callback(callback_id, "маршрутов нет")
            return True
        answer_callback(callback_id)
        body, markup = haproxy_route_selector_payload(node, token, selected_ip, "edit" if action == "e" else "delete")
        edit_haproxy_session_message(token, body, markup)
        return True
    if action == "a":
        set_pending_haproxy(chat_id, from_id, "add_port", token)
        answer_callback(callback_id, "жду порт")
        edit_haproxy_session_message(
            token,
            "<b>Новый HAProxy-порт</b>\n"
            f"{ALERT_SEPARATOR}\n"
            f"{detail_line('Машина', node_display_name(node))}\n"
            f"{detail_line('Входной IP', 'Все IP (*)' if selected_ip == '*' else selected_ip)}\n\n"
            "Ответь номером порта, например: <code>8443</code>\n"
            "Отмена: <code>/cancel</code>",
        )
        return True
    if action in ("x", "q", "y"):
        if not value.isdigit():
            answer_callback(callback_id, "неверный порт")
            return True
        port = int(value)
        route = haproxy_route_for_endpoint(routes, selected_ip, port)
        if route is None:
            answer_callback(callback_id, "маршрут уже изменился")
            show_haproxy_selected_ip(token)
            return True
        if action == "x":
            set_pending_haproxy(chat_id, from_id, "edit_targets", token, port=port)
            answer_callback(callback_id, "жду backend")
            edit_haproxy_session_message(token, haproxy_targets_prompt(node, token, route=route))
            return True
        if action == "q":
            answer_callback(callback_id)
            body = (
                "<b>Удалить HAProxy-маршрут?</b>\n"
                f"{ALERT_SEPARATOR}\n"
                f"{detail_line('Вход', f'{selected_ip}:{port}')}\n"
                f"{detail_line('Backend', haproxy_target_summary(route))}\n\n"
                "Конфиг применится с проверкой и автоматическим откатом при ошибке."
            )
            markup = {"inline_keyboard": [[
                {"text": "Удалить", "callback_data": f"hpx:y:{token}:{port}"},
                {"text": "Отмена", "callback_data": f"hpx:s:{token}"},
            ]]}
            edit_haproxy_session_message(token, body, markup)
            return True
        if len(routes) <= 1:
            answer_callback(callback_id, "последний маршрут удалять нельзя")
            show_haproxy_selected_ip(token)
            return True
        updated = [
            item for item in routes
            if not (item.get("listen_ip") == selected_ip and int(item.get("port") or 0) == port)
        ]
        try:
            set_haproxy_routes_for_node(node, updated)
        except Exception:
            answer_callback(callback_id, "удаление не сохранено")
            return True
        pop_pending_haproxy(chat_id, from_id)
        answer_callback(callback_id, "маршрут удалён")
        show_haproxy_selected_ip(token)
        return True
    answer_callback(callback_id)
    return True


def set_pending_rename(chat_id, from_id, node):
    key = pending_key(chat_id, from_id)
    node_key = node_record_key(node) or node_canonical_key(node)
    with LOCK:
        NODE_NAME_STATE.setdefault("pending", {})[key] = {
            "action": "rename",
            "node_key": node_key,
            "node_name": node_display_name(node, node_key),
            "created_at": now_ts(),
        }
        save_node_name_state()


def pop_pending_rename(chat_id, from_id):
    key = pending_key(chat_id, from_id)
    with LOCK:
        item = NODE_NAME_STATE.setdefault("pending", {}).pop(key, None)
        if item is not None:
            save_node_name_state()
        return item if isinstance(item, dict) else None


def peek_pending_rename(chat_id, from_id):
    key = pending_key(chat_id, from_id)
    with LOCK:
        item = NODE_NAME_STATE.setdefault("pending", {}).get(key)
        if not isinstance(item, dict):
            return None
        if now_ts() - int(item.get("created_at") or 0) > 600:
            NODE_NAME_STATE.setdefault("pending", {}).pop(key, None)
            save_node_name_state()
            return None
        return dict(item)


def move_ip_limit_policy_on_rename(aliases, new_key, new_name):
    if not aliases or not new_key:
        return
    init_ip_limit_db()
    with LOCK:
        placeholders = ",".join("?" for _ in aliases)
        row = ip_limit_db().execute(
            f"SELECT node_key, enabled, enforce, updated_at FROM ip_limit_nodes WHERE node_key IN ({placeholders}) "
            "ORDER BY updated_at DESC LIMIT 1",
            tuple(aliases),
        ).fetchone()
        if not row:
            return
        ip_limit_db().execute(f"DELETE FROM ip_limit_nodes WHERE node_key IN ({placeholders})", tuple(aliases))
        ip_limit_db().execute(
            "INSERT INTO ip_limit_nodes(node_key, node, enabled, enforce, updated_at) VALUES(?, ?, ?, ?, ?) "
            "ON CONFLICT(node_key) DO UPDATE SET node = excluded.node, enabled = excluded.enabled, "
            "enforce = excluded.enforce, updated_at = excluded.updated_at",
            (new_key, new_name[:120], int(row["enabled"] or 0), int(row["enforce"] or 0), now_ts()),
        )
        save_ip_limit_state()


def rename_fall_counters(aliases, new_name):
    changed = False
    falls = ensure_today_falls()
    for field in ("nodes", "downtime_nodes"):
        counter = falls.setdefault(field, {})
        total = 0
        for name in list(counter.keys()):
            if canonical_node_key(name) in aliases and name != new_name:
                total += int(counter.pop(name, 0) or 0)
                changed = True
        if total > 0:
            counter[new_name] = int(counter.get(new_name, 0) or 0) + total
            changed = True
    if changed:
        save_falls()


def set_node_name_override(node, new_name):
    new_name = normalize_node_name(new_name)
    old_aliases = node_base_aliases(node)
    old_key = node_record_key(node) or node_canonical_key(node)
    previous_name = node_display_name(node, old_key)
    new_key = canonical_node_key(new_name)
    if not old_key or not new_key:
        raise ValueError("empty node key")
    target_key = canonical_node_key(old_key)
    stable_identity = node_name_identity_aliases(node)
    node_uuid = normalize_node_uuid(node.get("node_uuid"))
    aliases = set(stable_identity if node_uuid else old_aliases)
    if node_uuid:
        for value in (node.get("id"), node.get("name"), previous_name):
            alias = canonical_node_key(value)
            if alias:
                aliases.add(alias)
    aliases.add(target_key)
    aliases.discard(new_key)
    stored_aliases = set(stable_identity if node_uuid else aliases)
    stored_aliases.discard(new_key)
    with LOCK:
        for key, item in list(NODE_NAME_STATE.setdefault("nodes", {}).items()):
            item_aliases = {canonical_node_key(value) for value in (item.get("aliases") or [])} if isinstance(item, dict) else {canonical_node_key(key)}
            same_target = target_key in (node_name_state_target(key, item), canonical_node_key(key))
            legacy_match = not node_uuid and (
                aliases.intersection(item_aliases) or canonical_node_key(key) in aliases
            )
            if same_target or legacy_match:
                NODE_NAME_STATE["nodes"].pop(key, None)
        NODE_NAME_STATE.setdefault("nodes", {})[old_key] = {
            "name": new_name,
            "aliases": sorted(stored_aliases, key=natural_sort_key),
            "target": target_key,
            "updated_at": now_ts(),
        }
        save_node_name_state()

        for key, item in SNI_STATE.setdefault("nodes", {}).items():
            if isinstance(item, dict) and (
                canonical_node_key(key) in {canonical_node_key(node.get("name")), canonical_node_key(node.get("id"))}
                or canonical_node_key(item.get("name")) == canonical_node_key(previous_name)
            ):
                item["name"] = new_name[:120]
        save_sni_state()

        move_bl_group_nodes_on_rename(aliases, old_key, new_name)
        rename_fall_counters(aliases, new_name)
    move_ip_limit_policy_on_rename(aliases, new_key, new_name)
    return new_name, old_key, new_key


def handle_rename_command(text, chat_id, from_id):
    parts = text.split(maxsplit=1)
    if len(parts) < 2 or not parts[1].strip():
        send_message("<b>Пример:</b> <code>/rename Германия</code>")
        return
    query = parts[1].strip()
    node = find_node(query)
    if node is None:
        send_message(
            "<b>Не нашёл такую машину</b>\n"
            f"{ALERT_SEPARATOR}\n"
            f"{detail_line('Запрос', query)}\n"
            "Проверь название через <code>/stats</code>."
        )
        return
    set_pending_rename(chat_id, from_id, node)
    send_message(
        "<b>Переименование машины</b>\n"
        f"{ALERT_SEPARATOR}\n"
        f"{detail_line('Сейчас', node_display_name(node))}\n\n"
        "Ответь новым названием.\n"
        "Отмена: <code>/cancel</code>"
    )


def handle_pending_rename(chat_id, from_id, text):
    pending = peek_pending_rename(chat_id, from_id)
    if not pending or pending.get("action") != "rename":
        return False
    try:
        new_name = normalize_node_name(text)
    except Exception:
        send_message(
            "<b>Не понял название.</b>\n\n"
            "Нельзя пустое, слишком длинное, а ещё нельзя символы <code>\" \\ $ `</code>."
        )
        return True
    node = find_node(pending.get("node_key")) or find_node(pending.get("node_name"))
    if node is None:
        pop_pending_rename(chat_id, from_id)
        send_message("<b>Машина больше не найдена.</b>")
        return True
    existing_matches = find_nodes(new_name)
    target_key = node_record_key(node) or node_canonical_key(node)
    busy = [item for item in existing_matches if (node_record_key(item) or node_canonical_key(item)) != target_key]
    if busy:
        examples = []
        for item in busy[:5]:
            examples.append(f"{node_display_name(item)} / {node_display_ip(item)}")
        send_message(
            "<b>Такое имя уже занято.</b>\n\n"
            f"{detail_line('Название', new_name)}\n"
            "<blockquote>" + "\n".join(html.escape(line) for line in examples) + "</blockquote>"
        )
        return True
    old_name = node_display_name(node)
    new_name, _, _ = set_node_name_override(node, new_name)
    pop_pending_rename(chat_id, from_id)
    send_message(
        "<b>Машина переименована</b>\n"
        f"{ALERT_SEPARATOR}\n"
        f"{detail_line('Было', old_name)}\n"
        f"{detail_line('Стало', new_name)}\n\n"
        "<i>Нода перепишет имя в push-конфиге при ближайшем push.</i>"
    )
    return True


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
    reason = f"Нет push {format_age(age)}"
    stats = node_push_miss_stats(node, now_ts())
    if stats.get("ready") and int(stats.get("missed") or 0) > PUSH_MISS_THRESHOLD:
        reason = (
            f"Нет push {format_age(age)}; "
            f"пропущено {int(stats.get('missed') or 0)}/{int(stats.get('expected') or 0)} "
            f"за {format_duration_ru(int(stats.get('window') or 0))}"
        )
    return send_message(node_alert_message("down", node_id, node, reason))


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
    sni_lines = []
    for item in (node.get("scan_wrong_sni_names") or [])[:5]:
        sni = html.escape(str(item.get("sni") or "-"))
        count = int(item.get("count") or 0)
        if sni and count > 0:
            sni_lines.append(f"{sni}: {count}")
    sni_block = ""
    if sni_lines:
        sni_block = f"\n\n<b>Топ wrong SNI:</b>\n<blockquote>{chr(10).join(sni_lines)}</blockquote>"
    return send_message(
        "<b>Подозрительный wrong SNI шум</b>\n\n"
        f"<blockquote><b>{name}</b>\nIP: {ip}</blockquote>\n"
        f"Прирост: +{int(delta)}\n"
        f"Всего в окне HAProxy: {int(node.get('scan_wrong_sni_total') or 0)}\n\n"
        f"<blockquote>{chr(10).join(top_lines)}</blockquote>"
        f"{sni_block}"
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
        seen_at = remna_epoch_sec(raw.get("seen_at", raw.get("last_seen")), ts)
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


def store_ip_limit_events(events, fallback_node="", ts=None, max_events=None):
    if not isinstance(events, list):
        return set()
    if ts is None:
        ts = now_ts()
    if max_events is None:
        max_events = IP_LIMIT_MAX_EVENTS
    touched = set()
    normalized = []
    for raw in events[:max_events]:
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
    return touched


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


def ip_limit_total_limit():
    with LOCK:
        raw = ip_limit_meta_get("total_limit")
    if raw == "":
        return None
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None
    if value < 0 or value > 10000:
        return None
    return value


def ip_limit_effective_limit(user, info=None):
    total_limit = ip_limit_total_limit()
    if total_limit is not None:
        return total_limit, "total"
    with LOCK:
        for key in ip_limit_user_keys(user, info):
            row = ip_limit_db().execute("SELECT limit_value FROM ip_limit_limits WHERE user = ?", (str(key),)).fetchone()
            if not row:
                continue
            value = int(row["limit_value"])
            if value <= 0:
                return 0, "personal"
            return value, "personal"
    hwid_limit = remna_user_hwid_limit(info)
    if hwid_limit is not None:
        if hwid_limit <= 0:
            return 0, "hwid"
        return hwid_limit, "hwid"
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
    aliases = node_base_aliases(node)
    override = node_name_override_for_node(node)
    alias = canonical_node_key(override)
    if alias:
        aliases.add(alias)
    with LOCK:
        nodes = NODE_NAME_STATE.setdefault("nodes", {})
        for item in nodes.values():
            if not isinstance(item, dict):
                continue
            item_aliases = {canonical_node_key(value) for value in item.get("aliases") or []}
            if aliases.intersection(item_aliases):
                aliases.update(alias for alias in item_aliases if alias)
    return aliases


def node_identity_keys(node):
    keys = set()
    if not isinstance(node, dict):
        key = canonical_node_key(node)
        return {key} if key else set()
    node_uuid = normalize_node_uuid(node.get("node_uuid"))
    if node_uuid:
        return {f"uuid_{node_uuid}"}
    record_key = canonical_node_key(node_record_key(node) or "")
    if record_key:
        keys.add(record_key)
    node_id = canonical_node_key(node.get("id"))
    if node_id and node_id not in ("unknown", "localhost", "none", "null"):
        keys.add(f"id_{node_id}")
    return keys


def node_same_identity(left, right):
    left_keys = node_identity_keys(left)
    right_keys = node_identity_keys(right)
    if not left_keys or not right_keys:
        return False
    return bool(left_keys.intersection(right_keys))


def node_migrates_legacy_identity(existing, incoming):
    if not isinstance(existing, dict) or not isinstance(incoming, dict):
        return False
    if normalize_node_uuid(existing.get("node_uuid")) or not normalize_node_uuid(incoming.get("node_uuid")):
        return False
    existing_id = canonical_node_key(existing.get("id"))
    incoming_id = canonical_node_key(incoming.get("id"))
    if existing_id and incoming_id and existing_id == incoming_id:
        return True
    existing_name = canonical_node_key(existing.get("name"))
    incoming_name = canonical_node_key(incoming.get("name"))
    existing_ip = str(existing.get("ip") or "").strip()
    incoming_ip = str(incoming.get("ip") or "").strip()
    return bool(existing_name and existing_name == incoming_name and existing_ip and existing_ip == incoming_ip)


def node_in_alias_state(node, state):
    aliases = node_alias_keys(node)
    if not aliases:
        return False
    with LOCK:
        nodes = state.setdefault("nodes", {})
        for key, item in nodes.items():
            item_aliases = {canonical_node_key(key)}
            if isinstance(item, dict):
                item_aliases.update(canonical_node_key(value) for value in item.get("aliases") or [])
                item_aliases.add(canonical_node_key(item.get("name")))
            item_aliases.discard("")
            if aliases.intersection(item_aliases):
                return True
    return False


def node_in_record_state(node, state):
    record_key = canonical_node_key(node_record_key(node) or node_canonical_key(node))
    if not record_key:
        return False
    with LOCK:
        for key, item in state.setdefault("nodes", {}).items():
            item_keys = {canonical_node_key(key)}
            if isinstance(item, dict):
                item_keys.add(canonical_node_key(item.get("record_key")))
            item_keys.discard("")
            if record_key in item_keys:
                return True
    return False


def node_stats_disabled(node):
    return node_in_alias_state(node, STATS_OFF_STATE)


def node_connection_alerts_disabled(node):
    return node_in_record_state(node, ALERTS_OFF_STATE)


def ssh_firewall_open_for_node(node):
    return bool(node_is_wl(node) and node_in_record_state(node, SSH_FIREWALL_STATE))


def current_bl_nodes():
    with LOCK:
        nodes = [dict(node) for node in dedupe_nodes(NODES.values()) if not node_is_wl(node) and not node_stats_disabled(node)]
    return nodes


def bl_groups_snapshot():
    with LOCK:
        groups = BL_GROUP_STATE.setdefault("groups", {})
        result = {}
        for gid, group in groups.items():
            if not isinstance(group, dict):
                continue
            result[str(gid)] = {
                "id": str(gid),
                "name": clean_display_text(group.get("name") or str(gid))[:120],
                "nodes": dict(group.get("nodes") if isinstance(group.get("nodes"), dict) else {}),
                "created_at": int(group.get("created_at") or 0),
                "updated_at": int(group.get("updated_at") or 0),
            }
    return result


def bl_group_list():
    groups = list(bl_groups_snapshot().values())
    groups.sort(key=lambda item: (int(item.get("created_at") or 0), natural_sort_key(item.get("name") or "")))
    return groups


def bl_group_by_id(group_id):
    group_id = str(group_id or "").strip()
    if not group_id:
        return None
    with LOCK:
        group = BL_GROUP_STATE.setdefault("groups", {}).get(group_id)
        if not isinstance(group, dict):
            return None
        return {
            "id": group_id,
            "name": clean_display_text(group.get("name") or group_id)[:120],
            "nodes": dict(group.get("nodes") if isinstance(group.get("nodes"), dict) else {}),
            "created_at": int(group.get("created_at") or 0),
            "updated_at": int(group.get("updated_at") or 0),
        }


def bl_node_lookup(nodes=None):
    lookup = {}
    for node in (nodes if nodes is not None else current_bl_nodes()):
        for key in node_alias_keys(node):
            if key:
                lookup.setdefault(key, node)
    return lookup


def bl_group_nodes(group, nodes=None):
    if not isinstance(group, dict):
        return []
    lookup = bl_node_lookup(nodes)
    result = []
    seen = set()
    for key in (group.get("nodes") or {}).keys():
        node = lookup.get(canonical_node_key(key))
        if not node:
            continue
        node_key = node_group_key(node)
        if node_key in seen:
            continue
        seen.add(node_key)
        result.append(node)
    return result


def bl_node_in_group(node, group):
    if not isinstance(node, dict) or not isinstance(group, dict):
        return False
    aliases = node_alias_keys(node)
    if not aliases:
        return False
    raw_nodes = group.get("nodes") if isinstance(group.get("nodes"), dict) else {}
    for key in raw_nodes.keys():
        if canonical_node_key(key) in aliases:
            return True
    return False


def reorder_bl_group_nodes(group_id, ordered_nodes):
    group_id = str(group_id or "").strip()
    prepared = []
    for node in ordered_nodes:
        if not isinstance(node, dict):
            continue
        key = node_group_key(node)
        if not key:
            continue
        prepared.append((key, node_display_name(node, key)[:120], node_alias_keys(node)))
    if not prepared:
        return {"ordered": [], "appended": []}
    ordered = []
    appended = []
    with LOCK:
        groups = BL_GROUP_STATE.setdefault("groups", {})
        group = groups.get(group_id)
        if not isinstance(group, dict):
            raise ValueError("group not found")
        group_nodes = group.setdefault("nodes", {})
        if not isinstance(group_nodes, dict):
            group_nodes = {}
            group["nodes"] = group_nodes
        old_items = list(group_nodes.items())
        new_nodes = {}
        used = set()
        for key, name, aliases in prepared:
            matched_key = None
            for existing_key in group_nodes.keys():
                existing_canon = canonical_node_key(existing_key)
                if existing_canon and existing_canon in aliases:
                    matched_key = existing_key
                    break
            if matched_key is None:
                continue
            canonical_key = canonical_node_key(matched_key) or canonical_node_key(key)
            if not canonical_key or canonical_key in used:
                continue
            display = clean_display_text(group_nodes.get(matched_key) or name or canonical_key)[:120] or canonical_key
            new_nodes[canonical_key] = display
            used.add(canonical_key)
            ordered.append(display)
        for existing_key, existing_name in old_items:
            canonical_key = canonical_node_key(existing_key)
            if not canonical_key or canonical_key in used:
                continue
            display = clean_display_text(existing_name or canonical_key)[:120] or canonical_key
            new_nodes[canonical_key] = display
            appended.append(display)
        if ordered:
            group["nodes"] = new_nodes
            group["updated_at"] = now_ts()
            save_bl_group_state()
    return {"ordered": ordered, "appended": appended}


def bl_assigned_node_aliases(groups=None):
    aliases = set()
    for group in (groups if groups is not None else bl_group_list()):
        raw_nodes = group.get("nodes") if isinstance(group.get("nodes"), dict) else {}
        for key in raw_nodes.keys():
            key = canonical_node_key(key)
            if key:
                aliases.add(key)
    return aliases


def bl_ungrouped_nodes(nodes=None, groups=None):
    nodes = list(nodes if nodes is not None else current_bl_nodes())
    assigned = bl_assigned_node_aliases(groups)
    result = []
    for node in nodes:
        if node_alias_keys(node).isdisjoint(assigned):
            result.append(node)
    result.sort(key=bl_node_sort_key)
    return result


def bl_group_node_count(group, nodes=None):
    group_nodes = bl_group_nodes(group, nodes)
    ts = now_ts()
    return live_node_count(group_nodes, ts), len(group_nodes)


def create_bl_group(name):
    name = normalize_bl_group_name(name)
    name_key = canonical_node_key(name)
    if not name_key:
        raise ValueError("empty group name")
    with LOCK:
        for group in BL_GROUP_STATE.setdefault("groups", {}).values():
            if isinstance(group, dict) and canonical_node_key(group.get("name")) == name_key:
                raise ValueError("duplicate group name")
        group_id = bl_group_id_for_name(name)
        if group_id in BL_GROUP_STATE["groups"]:
            group_id = f"g{hashlib.sha1((name + str(now_ts())).encode('utf-8', errors='ignore')).hexdigest()[:12]}"
        ts = now_ts()
        BL_GROUP_STATE["groups"][group_id] = {
            "name": name,
            "nodes": {},
            "created_at": ts,
            "updated_at": ts,
        }
        save_bl_group_state()
    return bl_group_by_id(group_id)


def find_bl_node_exact(query):
    needle = canonical_node_key(query)
    if not needle:
        return None
    matches = []
    for node in current_bl_nodes():
        candidates = node_alias_keys(node)
        for value in (node.get("id"), node.get("name"), node.get("hostname"), node_display_name(node)):
            key = canonical_node_key(value)
            if key:
                candidates.add(key)
        if needle in candidates:
            matches.append(node)
    if not matches:
        return None
    matches.sort(key=lambda node: int(node.get("last_seen", 0) or 0), reverse=True)
    return matches[0]


def add_nodes_to_bl_group(group_id, nodes):
    group_id = str(group_id or "").strip()
    prepared = []
    for node in nodes:
        key = node_group_key(node)
        if not key:
            continue
        prepared.append((key, node_display_name(node, key)[:120], node_alias_keys(node)))
    added = []
    already = []
    moved = []
    with LOCK:
        groups = BL_GROUP_STATE.setdefault("groups", {})
        group = groups.get(group_id)
        if not isinstance(group, dict):
            raise ValueError("group not found")
        group_nodes = group.setdefault("nodes", {})
        for key, name, aliases in prepared:
            was_here = any(canonical_node_key(existing) in aliases for existing in group_nodes.keys())
            was_elsewhere = False
            for other_id, other_group in groups.items():
                if not isinstance(other_group, dict):
                    continue
                other_nodes = other_group.setdefault("nodes", {})
                for existing in list(other_nodes.keys()):
                    if canonical_node_key(existing) in aliases and (other_id != group_id or canonical_node_key(existing) != key):
                        other_nodes.pop(existing, None)
                        if other_id != group_id:
                            was_elsewhere = True
            group_nodes[key] = name
            if was_here:
                already.append(name)
            elif was_elsewhere:
                moved.append(name)
            else:
                added.append(name)
        if prepared:
            group["updated_at"] = now_ts()
            save_bl_group_state()
    return {"added": added, "already": already, "moved": moved}


def move_bl_group_nodes_on_rename(aliases, new_key, new_name):
    aliases = {canonical_node_key(item) for item in aliases if canonical_node_key(item)}
    new_key = canonical_node_key(new_key)
    if not aliases or not new_key:
        return
    changed = False
    with LOCK:
        for group in BL_GROUP_STATE.setdefault("groups", {}).values():
            if not isinstance(group, dict):
                continue
            nodes = group.setdefault("nodes", {})
            found = False
            for key in list(nodes.keys()):
                if canonical_node_key(key) in aliases:
                    nodes.pop(key, None)
                    found = True
            if found:
                nodes[new_key] = clean_display_text(new_name or new_key)[:120] or new_key
                group["updated_at"] = now_ts()
                changed = True
        if changed:
            save_bl_group_state()


def remove_bl_group_nodes_by_aliases(aliases):
    aliases = {canonical_node_key(item) for item in aliases if canonical_node_key(item)}
    if not aliases:
        return
    changed = False
    with LOCK:
        for group in BL_GROUP_STATE.setdefault("groups", {}).values():
            if not isinstance(group, dict):
                continue
            nodes = group.setdefault("nodes", {})
            for key in list(nodes.keys()):
                if canonical_node_key(key) in aliases:
                    nodes.pop(key, None)
                    group["updated_at"] = now_ts()
                    changed = True
        if changed:
            save_bl_group_state()


def bl_group_selector_payload():
    groups = bl_group_list()
    nodes = current_bl_nodes()
    lines = [
        "<b>Статистика других машин</b>",
        ALERT_SEPARATOR,
        "Выберите группу:",
    ]
    rows = []
    if not groups:
        lines += ["", "<i>Групп пока нет.</i>"]
    for group in groups:
        live_count, total_count = bl_group_node_count(group, nodes)
        label = f"{group.get('name')} ({live_count}/{total_count})"
        rows.append([{"text": label[:60], "callback_data": f"blg:s:{group.get('id')}"}])
    ungrouped = bl_ungrouped_nodes(nodes, groups)
    if ungrouped:
        rows.append([{"text": f"Без группы ({live_node_count(ungrouped, now_ts())}/{len(ungrouped)})", "callback_data": "blg:u"}])
    rows.append([{"text": "Создать группу", "callback_data": "blg:c"}])
    return "\n".join(lines), {"inline_keyboard": rows}


def bl_group_stats_message(group_id=None, ungrouped=False):
    nodes = current_bl_nodes()
    if ungrouped:
        group_nodes = bl_ungrouped_nodes(nodes, bl_group_list())
        group_name = "Без группы"
    else:
        group = bl_group_by_id(group_id)
        if group is None:
            return "<b>Группа не найдена.</b>"
        group_nodes = bl_group_nodes(group, nodes)
        group_name = group.get("name") or "Группа"
    ts = now_ts()
    parts = [
        "<b>Статистика других машин</b>",
        "",
        f"<blockquote><b>{html.escape(clean_display_text(group_name))}:</b></blockquote>",
    ]
    if not group_nodes:
        parts += ["", "Нет машин в группе."]
        return "\n".join(parts)
    for node in group_nodes:
        age = ts - int(node.get("last_seen", 0) or 0)
        status = "OK" if age <= node_stale_sec(node) else f"OFFLINE {format_age(age)}"
        parts.append("")
        parts.append(node_message(node, status, compact=False))
    parts.append(status_summary(group_nodes, ts, expected_total=max(len(group_nodes), 1), filtered=True))
    return "\n".join(parts)


def bl_group_action_markup(group_id=None, ungrouped=False):
    rows = []
    if not ungrouped and group_id:
        rows.append([{"text": "Добавить сюда машины", "callback_data": f"blg:a:{group_id}"}])
        rows.append([{"text": "Редактировать вид списка", "callback_data": f"blg:o:{group_id}"}])
        rows.append([{"text": "Обновить", "callback_data": f"blg:s:{group_id}"}])
    elif ungrouped:
        rows.append([{"text": "Обновить", "callback_data": "blg:u"}])
    rows.append([{"text": "К списку групп", "callback_data": "blg:l"}])
    rows.append([{"text": "Создать группу", "callback_data": "blg:c"}])
    return {"inline_keyboard": rows}


def aggregate_grouped_bl_summary_message():
    groups = bl_group_list()
    if not groups:
        return aggregate_summary_message("bl")
    nodes = current_bl_nodes()
    parts = ["<b>Статистика других машин</b>"]
    rendered = 0
    for group in groups:
        group_nodes = bl_group_nodes(group, nodes)
        if not group_nodes:
            continue
        parts += [
            "",
            f"<blockquote><b>{html.escape(clean_display_text(group.get('name') or 'Группа'))}:</b></blockquote>",
            status_summary(group_nodes, now_ts(), expected_total=max(len(group_nodes), 1), filtered=True),
        ]
        rendered += 1
    ungrouped = bl_ungrouped_nodes(nodes, groups)
    if ungrouped:
        parts += [
            "",
            "<blockquote><b>Без группы:</b></blockquote>",
            status_summary(ungrouped, now_ts(), expected_total=max(len(ungrouped), 1), filtered=True),
        ]
        rendered += 1
    if not rendered:
        return "<b>Статистика других машин</b>\n\nНет данных от машин."
    return "\n".join(parts)


def aggregate_grouped_bl_rich_message():
    groups = bl_group_list()
    nodes = current_bl_nodes()
    ts = now_ts()
    parts = ["<h3>Статистика других машин</h3>"]
    rendered = 0

    if not groups:
        if not nodes:
            return "<h3>Статистика других машин</h3><p>Нет данных от машин.</p>"
        parts.append(bl_nodes_rich_section("Все машины", nodes, ts))
        return "".join(parts)

    for group in groups:
        group_nodes = bl_group_nodes(group, nodes)
        if not group_nodes:
            continue
        parts.append(bl_nodes_rich_section(group.get("name") or "Группа", group_nodes, ts))
        rendered += 1

    ungrouped = bl_ungrouped_nodes(nodes, groups)
    if ungrouped:
        parts.append(bl_nodes_rich_section("Без группы", ungrouped, ts))
        rendered += 1

    if not rendered:
        return "<h3>Статистика других машин</h3><p>Нет данных от машин.</p>"
    return "".join(parts)


def send_grouped_bl_stats(use_rich=True):
    if use_rich or RICH_STATS_ENABLED:
        if send_rich_message(aggregate_grouped_bl_rich_message()):
            return True
    return bool(send_message(aggregate_grouped_bl_summary_message()))


def ip_limit_node_policy(node):
    aliases = list(node_alias_keys(node))
    if not aliases:
        return None
    with LOCK:
        placeholders = ",".join("?" for _ in aliases)
        rows = ip_limit_db().execute(
            f"SELECT node_key, node, enabled, enforce, updated_at FROM ip_limit_nodes WHERE node_key IN ({placeholders}) "
            "ORDER BY updated_at DESC LIMIT 1",
            tuple(aliases),
        ).fetchall()
    if not rows:
        return None
    row = rows[0]
    return {
        "node_key": str(row["node_key"] or ""),
        "node": str(row["node"] or ""),
        "enabled": bool(int(row["enabled"] or 0)),
        "enforce": bool(int(row["enforce"] or 0)),
        "updated_at": int(row["updated_at"] or 0),
    }


def ip_limit_enabled_node_keys():
    with LOCK:
        rows = ip_limit_db().execute("SELECT node_key FROM ip_limit_nodes WHERE enabled = 1").fetchall()
    return {str(row["node_key"] or "") for row in rows if str(row["node_key"] or "").strip()}


def ip_limit_remna_monitor_enabled():
    if IP_LIMIT_SOURCE not in ("remna", "both"):
        return False
    if not remna_api_enabled():
        return False
    total_limit = ip_limit_total_limit()
    if total_limit is not None:
        return total_limit > 0
    if IP_LIMIT_ENABLED:
        return True
    return bool(ip_limit_enabled_node_keys())


def remna_ip_limit_allowed_rows(rows, enabled_node_keys):
    allowed = []
    active_after = now_ts() - REMNA_TOP_IP_ACTIVE_SEC
    total_limit = ip_limit_total_limit()
    for row in rows or []:
        last_seen = remna_epoch_sec(row.get("last_seen"), 0)
        if last_seen > 0 and last_seen < active_after:
            continue
        node_keys = node_alias_keys(row.get("node"))
        if total_limit is None and not IP_LIMIT_ENABLED and enabled_node_keys and not node_keys.intersection(enabled_node_keys):
            continue
        allowed.append({
            "user": row.get("user"),
            "ip": row.get("ip"),
            "node": row.get("node"),
            "last_seen": last_seen or now_ts(),
            "seen_at": last_seen or now_ts(),
        })
    return allowed


def set_ip_limit_node_policy(node, enabled=True, enforce=False):
    key = node_canonical_key(node)
    if not key:
        raise ValueError("empty node key")
    name = node_display_name(node, key)
    enabled_value = 1 if enabled else 0
    enforce_value = 1 if enforce else 0
    with LOCK:
        ip_limit_db().execute(
            "INSERT INTO ip_limit_nodes(node_key, node, enabled, enforce, updated_at) VALUES(?, ?, ?, ?, ?) "
            "ON CONFLICT(node_key) DO UPDATE SET node = excluded.node, enabled = excluded.enabled, "
            "enforce = excluded.enforce, updated_at = excluded.updated_at",
            (key, name[:120], enabled_value, enforce_value, now_ts()),
        )
        save_ip_limit_state()
    return {
        "node_key": key,
        "node": name,
        "enabled": bool(enabled_value),
        "enforce": bool(enforce_value),
    }


def ip_limit_processing_enabled_for_node(node_name):
    total_limit = ip_limit_total_limit()
    if total_limit is not None:
        return total_limit > 0
    if IP_LIMIT_ENABLED:
        return True
    policy = ip_limit_node_policy(node_name)
    return bool(policy and policy.get("enabled"))


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
        lines.append(f"{ip_with_note_html(row['ip'])} — {html.escape(nodes)} — {html.escape(age)} назад")
    if len(rows) > 8:
        lines.append(f"... ещё {len(rows) - 8}")
    return "<blockquote>" + "\n".join(lines) + "</blockquote>"


def ip_limit_entry_detail_line(item, ts):
    ip = str(item.get("ip") or "-")
    nodes = ", ".join(item.get("nodes") or []) or "-"
    age = format_age(ts - int(item.get("last_seen") or 0))
    parts = [ip_with_note_html(ip), html.escape(nodes), html.escape(f"{age} назад")]
    asn = asn_info_text(ip, fetch=False)
    if asn:
        parts.append(html.escape(asn))
    return " — ".join(parts)


def ip_limit_report(query=""):
    query = str(query or "").strip()
    ts = now_ts()
    if not query:
        snapshot = ip_limit_snapshot(ts)
        node_names = ip_limit_active_node_names(snapshot)
        lines = [
            "<b>IP лимит</b>",
            ALERT_SEPARATOR,
            "<b>По машине:</b> <code>/ip Нидерланды</code>",
            "<b>Заметка для IP:</b> <code>/ip 203.0.113.10</code>",
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
    total_limit = ip_limit_total_limit()
    report_limit = total_limit if total_limit is not None else IP_LIMIT_MAX_IPS
    report_limit_text = f"{report_limit} IP" if report_limit > 0 else "без лимита"
    header = [
        "<b>IP лимит</b>",
        ALERT_SEPARATOR,
        detail_line("Машина", query),
        detail_line("Окно", format_duration_ru(IP_LIMIT_WINDOW_SEC)),
        detail_line("Лимит", report_limit_text),
        detail_line("IP", total_ips),
    ]

    blocks = [ip_limit_user_block(user, user_rows, ts) for user, user_rows in grouped[:12]]
    if len(grouped) > 12:
        blocks.append(f"<i>Ещё подписок: {len(grouped) - 12}</i>")
    return "\n".join(header + [""] + blocks)


def top_ip_user_line(index, row):
    user = str(row.get("user") or "").strip()
    info = row.get("user_info") if isinstance(row.get("user_info"), dict) and row.get("user_info") else remna_user_info(user)
    telegram_id = "-"
    if isinstance(info, dict):
        telegram_id = str(info.get("telegramId") or "-").strip() or "-"
        user = remna_user_id(info, user) or user
    count = len(row.get("ips") or [])
    return (
        f"{index}. <b>ID:</b> <code>{html.escape(user)}</code> | "
        f"<b>IP:</b> <code>{count}</code> | "
        f"<b>TG:</b> <code>{html.escape(telegram_id)}</code>"
    )


def top_ip_report(limit=20):
    if not remna_api_enabled():
        return (
            "<b>Топ активных IP</b>\n"
            f"{ALERT_SEPARATOR}\n"
            "<b>Remnawave API:</b> <code>не настроен</code>"
        )
    try:
        limit = int(limit)
    except Exception:
        limit = 20
    if limit < 1:
        limit = 20
    if limit > 100:
        limit = 100
    try:
        snapshot = remna_fetch_active_user_ips()
    except Exception as exc:
        log(f"top_ip failed: {exc}")
        return (
            "<b>Топ активных IP</b>\n"
            f"{ALERT_SEPARATOR}\n"
            f"{detail_line('Ошибка', str(exc)[:160])}"
        )
    active_after = int(snapshot.get("collected_at") or now_ts()) - REMNA_TOP_IP_ACTIVE_SEC
    rows = remna_top_ip_rows(snapshot.get("rows") or [], active_after=active_after)
    shown = rows[:limit]
    lines = [
        "<b>Топ активных IP</b>",
        ALERT_SEPARATOR,
        detail_line("Ноды", f"{snapshot.get('nodes_polled', 0)}/{snapshot.get('nodes_total', 0)}"),
        detail_line("Окно", format_duration_ru(REMNA_TOP_IP_ACTIVE_SEC)),
        detail_line("Показано", f"{len(shown)}/{len(rows)}"),
    ]
    problems = []
    if int(snapshot.get("nodes_skipped") or 0) > 0:
        problems.append(f"пропущено нод: {int(snapshot.get('nodes_skipped') or 0)}")
    if int(snapshot.get("jobs_pending") or 0) > 0:
        problems.append(f"не успело jobs: {int(snapshot.get('jobs_pending') or 0)}")
    if int(snapshot.get("jobs_failed") or 0) > 0:
        problems.append(f"упало jobs: {int(snapshot.get('jobs_failed') or 0)}")
    if problems:
        lines.append(detail_line("Замечания", ", ".join(problems)))
    if not shown:
        lines += ["", "<blockquote>Активных IP сейчас не нашёл.</blockquote>"]
    else:
        lines.append("")
        for index, row in enumerate(shown, 1):
            lines.append(top_ip_user_line(index, row))
    errors = snapshot.get("errors") or []
    if errors:
        lines += ["", "<blockquote>" + "\n".join(html.escape(str(item)) for item in errors[:5]) + "</blockquote>"]
    return "\n".join(lines)


def remna_ip_limit_alert_rows(rows, ts):
    top_rows = remna_top_ip_rows(rows, active_after=ts - REMNA_TOP_IP_ACTIVE_SEC)
    result = []
    for row in top_rows:
        user = str(row.get("user") or "").strip()
        active_ips = len(row.get("ips") or [])
        if active_ips <= IP_LIMIT_ALERT_THRESHOLD:
            continue
        info = row.get("user_info") if isinstance(row.get("user_info"), dict) and row.get("user_info") else remna_user_info(user)
        limit, source = ip_limit_effective_limit(user, info)
        if not ip_limit_telegram_alert_allowed(limit, source) or active_ips <= limit:
            continue
        item = dict(row)
        if isinstance(info, dict) and info:
            item["user"] = ip_limit_primary_key(user, info) or user
            item["user_info"] = info
        item["effective_limit"] = limit
        item["limit_source"] = source
        result.append(item)
    return result


def ip_limit_telegram_alert_allowed(limit, source=""):
    value = int(limit or 0)
    if source == "total":
        return value > 0
    return 0 < value <= IP_LIMIT_ALERT_THRESHOLD


def remna_ip_limit_top_message(top_rows, snapshot):
    shown = top_rows[:IP_LIMIT_ALERT_TOP]
    max_ips = len(top_rows[0].get("ips") or []) if top_rows else 0
    lines = [
        f"{LOST_EMOJI} #ipLimitTop",
        "<b>Много активных IP</b>",
        ALERT_SEPARATOR,
        detail_line("Порог", f">{IP_LIMIT_ALERT_THRESHOLD} IP и выше действующего лимита"),
        detail_line("Максимум", f"{max_ips} IP"),
        detail_line("Окно", format_duration_ru(REMNA_TOP_IP_ACTIVE_SEC)),
        detail_line("Ноды", f"{snapshot.get('nodes_polled', 0)}/{snapshot.get('nodes_total', 0)}"),
        detail_line("Показано", f"{len(shown)}/{len(top_rows)}"),
    ]
    problems = []
    if int(snapshot.get("nodes_skipped") or 0) > 0:
        problems.append(f"пропущено нод: {int(snapshot.get('nodes_skipped') or 0)}")
    if int(snapshot.get("jobs_pending") or 0) > 0:
        problems.append(f"не успело jobs: {int(snapshot.get('jobs_pending') or 0)}")
    if int(snapshot.get("jobs_failed") or 0) > 0:
        problems.append(f"упало jobs: {int(snapshot.get('jobs_failed') or 0)}")
    if problems:
        lines.append(detail_line("Замечания", ", ".join(problems)))
    lines.append("")
    if shown:
        for index, row in enumerate(shown, 1):
            lines.append(top_ip_user_line(index, row))
    else:
        lines.append("<blockquote>Активных IP сейчас не нашёл.</blockquote>")
    errors = snapshot.get("errors") or []
    if errors:
        lines += ["", "<blockquote>" + "\n".join(html.escape(str(item)) for item in errors[:5]) + "</blockquote>"]
    return "\n".join(lines)


def maybe_alert_remna_ip_limit_top(rows, snapshot, ts):
    top_rows = remna_ip_limit_alert_rows(rows, ts)
    if not top_rows:
        return
    max_ips = len(top_rows[0].get("ips") or [])
    if max_ips <= IP_LIMIT_ALERT_THRESHOLD:
        return
    with LOCK:
        last_alert = int(ip_limit_meta_get("remna_top_alert_last") or 0)
        if ts - last_alert < IP_LIMIT_ALERT_COOLDOWN:
            return
        ip_limit_meta_set("remna_top_alert_last", str(ts))
        save_ip_limit_state()
    log(f"remna ip top alert: max_ips={max_ips} threshold={IP_LIMIT_ALERT_THRESHOLD}")
    send_message(remna_ip_limit_top_message(top_rows, snapshot))


def ip_limit_limit_text(limit, source):
    if limit <= 0:
        return "без лимита"
    suffix_map = {
        "total": "общий для всех",
        "personal": "персональный",
        "hwid": "HWID",
        "global": "глобальный",
    }
    suffix = suffix_map.get(source, source or "глобальный")
    return f"{limit} IP ({suffix})"


def ip_limit_user_card(query):
    query = str(query or "").strip()
    if not query:
        text = (
            "<b>IP лимит пользователя</b>\n"
            f"{ALERT_SEPARATOR}\n"
            "<b>Пример:</b> <code>/limit_ip 3</code>\n"
            "<b>Алиас:</b> <code>/ip_limit 3</code>\n"
            "<b>Telegram ID:</b> <code>/limit_ip tg:646296998</code>"
        )
        return text, None
    info = remna_user_lookup(query)
    if not isinstance(info, dict):
        text = (
            "<b>Не нашёл пользователя</b>\n"
            f"{ALERT_SEPARATOR}\n"
            f"{detail_line('Запрос', query)}\n"
            "<i>Можно Remnawave ID, Telegram ID через tg:, username или uuid.</i>"
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
    if source == "total":
        lines.append("<i>Персональные и HWID-лимиты сейчас игнорируются.</i>")
    with LOCK:
        penalty = ip_limit_db().execute("SELECT enable_at FROM ip_limit_penalties WHERE user = ?", (key,)).fetchone()
        if penalty and int(penalty["enable_at"] or 0) > ts:
            lines.append(detail_line("Отключен до", fmt_time(penalty["enable_at"])))
    ip_lines = []
    for item in entries[:12]:
        ip_lines.append(ip_limit_entry_detail_line(item, ts))
    if len(entries) > 12:
        ip_lines.append(f"... ещё {len(entries) - 12}")
    if ip_lines:
        lines.append("<blockquote>" + "\n".join(ip_lines) + "</blockquote>")
    else:
        lines.append("<blockquote>Активных IP сейчас нет.</blockquote>")
    markup_rows = []
    if source != "total":
        markup_rows.append([
            {"text": "Убрать лимит", "callback_data": f"ipl:off:{key}"},
            {"text": "Повысить лимит", "callback_data": f"ipl:raise:{key}"},
        ])
    markup_rows.append([{"text": "Обновить", "callback_data": f"ipl:show:{key}"}])
    markup = {"inline_keyboard": markup_rows}
    return "\n".join(lines), markup


def ip_limit_entry_alert_line(item):
    ip = str(item.get("ip") or "-")
    nodes = ", ".join(item.get("nodes") or []) or "-"
    parts = [ip_with_note_html(ip), html.escape(nodes)]
    asn = asn_info_text(ip)
    if asn:
        parts.append(html.escape(asn))
    return " — ".join(parts)


def alert_ip_limit_exceeded(user, entries, info=None):
    ip_lines = []
    for item in entries[:12]:
        ip_lines.append(ip_limit_entry_alert_line(item))
    if len(entries) > 12:
        ip_lines.append(f"... ещё {len(entries) - 12}")

    if not isinstance(info, dict):
        info = remna_user_info(user)
    limit, source = ip_limit_effective_limit(user, info)
    lines = [
        f"{LOST_EMOJI} #ipLimitExceeded",
        "<b>IP лимит превышен</b>",
        ALERT_SEPARATOR,
        detail_line("ID", user),
    ]
    lines.extend(remna_detail_lines(user, info, include_hwid=True))
    lines.extend([
        detail_line("Лимит", ip_limit_limit_text(limit, source)),
        detail_line("Активных IP", f"{len(entries)}/{limit if limit > 0 else 'без лимита'}"),
        detail_line("Окно", format_duration_ru(IP_LIMIT_WINDOW_SEC)),
        f"<blockquote>{chr(10).join(ip_lines)}</blockquote>",
    ])
    return send_message("\n".join(lines))


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
                    with LOCK:
                        REMNA_USER_CACHE.pop(uuid_value, None)
                        REMNA_USER_CACHE.pop(key, None)
                    info = remna_user_lookup(uuid_value)
                    if not isinstance(info, dict):
                        raise RuntimeError("user state unavailable")
                    status = str(info.get("status") or "").strip().upper()
                    if status == "ACTIVE":
                        with LOCK:
                            ip_limit_db().execute("DELETE FROM ip_limit_penalties WHERE user = ?", (key,))
                            save_ip_limit_state()
                        log(f"ip limit penalty already lifted: user={key} uuid={uuid_value}")
                        continue
                    if status != "DISABLED":
                        with LOCK:
                            ip_limit_db().execute("DELETE FROM ip_limit_penalties WHERE user = ?", (key,))
                            save_ip_limit_state()
                        log(f"ip limit penalty not lifted due to status={status or '-'}: user={key} uuid={uuid_value}")
                        continue
                    remna_user_action(uuid_value, "enable")
                    with LOCK:
                        ip_limit_db().execute("DELETE FROM ip_limit_penalties WHERE user = ?", (key,))
                        save_ip_limit_state()
                    log(f"ip limit penalty lifted: user={key} uuid={uuid_value}")
                    if str(item.get("reason") or "") != "ip_limit_recovery":
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
    if not isinstance(events, list):
        return
    if IP_LIMIT_SOURCE not in ("push", "both"):
        return
    if not ip_limit_processing_enabled_for_node(fallback_node):
        return

    with LOCK:
        purge_ip_limit_state(ts)
        touched = store_ip_limit_events(events, fallback_node, ts)
        if touched:
            save_ip_limit_state()

    for user in sorted(touched, key=natural_sort_key):
        with LOCK:
            purge_ip_limit_state(ts)
            entries = active_ip_limit_entries(user, ts)
            if len(entries) <= 1:
                continue
        info = remna_user_info(user)
        with LOCK:
            purge_ip_limit_state(ts)
            entries = active_ip_limit_entries_for_user(user, info, ts)
            limit, source = ip_limit_effective_limit(user, info)
            if not ip_limit_telegram_alert_allowed(limit, source) or len(entries) <= limit:
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


def process_remna_ip_limit_alerts(ts):
    grouped = ip_limit_group_rows(ip_limit_snapshot(ts))
    for user, raw_entries in grouped:
        if len(raw_entries) <= 1:
            continue
        info = remna_user_info(user)
        entries = active_ip_limit_entries_for_user(user, info, ts)
        limit, source = ip_limit_effective_limit(user, info)
        if limit <= 0 or len(entries) <= limit:
            continue
        if not ip_limit_telegram_alert_allowed(limit, source):
            continue
        alert_key = ip_limit_primary_key(user, info)
        with LOCK:
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
        log(f"remna ip limit alert: user={user} active_ips={len(entries)} limit={limit}")
        alert_ip_limit_exceeded(user, entries, info)


def remna_ip_limit_poll_once():
    ts = now_ts()
    total_limit = ip_limit_total_limit()
    enabled_node_keys = ip_limit_enabled_node_keys()
    if total_limit == 0 or (total_limit is None and not IP_LIMIT_ENABLED and not enabled_node_keys):
        return {"ok": True, "disabled": True}
    snapshot = remna_fetch_active_user_ips()
    rows = remna_ip_limit_allowed_rows(snapshot.get("rows") or [], enabled_node_keys)
    with LOCK:
        purge_ip_limit_state(ts)
        store_ip_limit_events(rows, "", ts, max_events=len(rows))
        save_ip_limit_state()
    process_remna_ip_limit_alerts(ts)
    maybe_alert_remna_ip_limit_top(rows, snapshot, ts)
    return {"ok": True, "rows": len(rows), "nodes": snapshot.get("nodes_polled", 0)}


def remna_ip_limit_loop():
    while True:
        try:
            if ip_limit_remna_monitor_enabled():
                result = remna_ip_limit_poll_once()
                if result.get("rows", 0) > 0:
                    log(f"remna ip monitor: rows={result.get('rows')} nodes={result.get('nodes')}")
            time.sleep(IP_LIMIT_SCAN_SEC)
        except Exception as exc:
            log(f"remna ip monitor failed: {exc}")
            time.sleep(max(10, min(IP_LIMIT_SCAN_SEC, 60)))


def remna_node_monitor_enabled():
    return bool(REMNA_NODE_ALERT_ENABLED and remna_api_enabled())


def remna_node_poll_once():
    ts = now_ts()
    raw_nodes = remna_get_nodes()
    current = {}
    alerts = []
    with LOCK:
        state_nodes = REMNA_NODE_STATE.setdefault("nodes", {})
        for raw in raw_nodes:
            info = normalize_remna_node(raw, ts)
            node_key = str(info.get("key") or "").strip()
            if not node_key:
                continue
            old = state_nodes.get(node_key)
            if isinstance(old, dict):
                old_disabled = bool(old.get("disabled"))
                if old_disabled != bool(info.get("disabled")):
                    kind = "disabled" if info.get("disabled") else "enabled"
                    info["alerted_at"] = ts
                    alerts.append((kind, dict(info)))
                else:
                    info["alerted_at"] = int(old.get("alerted_at") or 0)
            else:
                info["alerted_at"] = 0
            state_nodes[node_key] = info
            current[node_key] = True
        for node_key in list(state_nodes.keys()):
            if node_key not in current:
                state_nodes.pop(node_key, None)
        save_remna_node_state()
    for kind, info in alerts:
        log(f"remna node {kind}: {info.get('name') or info.get('key')}")
        alert_remna_node(kind, info)
    return {"nodes": len(current), "alerts": len(alerts)}


def remna_node_loop():
    while True:
        try:
            if remna_node_monitor_enabled():
                remna_node_poll_once()
            time.sleep(REMNA_NODE_POLL_SEC)
        except Exception as exc:
            log(f"remna node monitor failed: {exc}")
            time.sleep(max(10, min(REMNA_NODE_POLL_SEC, 60)))


def update_node(payload, remote_ip=""):
    raw_id = clean_display_text(payload.get("id") or "")[:160]
    hostname_value = clean_display_text(payload.get("hostname") or "")[:255]
    remote_ip_value = str(remote_ip or payload.get("ip") or "")
    node_name = clean_display_text(payload.get("name") or raw_id or hostname_value or "")[:160]
    node_id = raw_id or hostname_value or node_name
    node_uuid = normalize_node_uuid(payload.get("node_uuid"))
    node_kind = str(payload.get("node_kind") or "").strip().lower()
    if node_kind not in ("wl", "bl"):
        node_kind = ""
    identity = {
        "id": raw_id,
        "name": node_name,
        "node_uuid": node_uuid,
        "hostname": hostname_value,
        "ip": remote_ip_value,
    }
    synced_name = node_name_sync_value(identity, node_name)
    if synced_name:
        node_name = synced_name
    if not node_id:
        raise ValueError("id/name is required")
    current = now_ts()
    scan_alert_node = None
    scan_alert_delta = 0
    try:
        push_interval_sec = int(payload.get("push_interval_sec") or 0)
    except Exception:
        push_interval_sec = 0
    iface_value = clean_display_text(payload.get("iface") or "").strip()[:80]
    ip_stats = normalize_ip_stats(payload.get("ip_stats"), remote_ip_value, iface_value, payload)
    haproxy_routes_supported = bool(payload.get("haproxy_routes_supported")) and isinstance(payload.get("haproxy_routes"), list)
    haproxy_routes = normalize_haproxy_routes(payload.get("haproxy_routes")) if haproxy_routes_supported else []
    haproxy_bandwidth_supported = bool(payload.get("haproxy_bandwidth_supported")) and isinstance(payload.get("haproxy_bandwidth_limits"), list)
    haproxy_bandwidth_limits = normalize_haproxy_bandwidth_limits(payload.get("haproxy_bandwidth_limits")) if haproxy_bandwidth_supported else []
    record = {
        "id": node_id,
        "name": node_name or node_id,
        "node_uuid": node_uuid,
        "node_kind": node_kind,
        "push_build": clean_display_text(payload.get("push_build") or payload.get("build") or ""),
        "ip": remote_ip_value,
        "uptime_sec": int(payload.get("uptime_sec") or 0),
        "iface": iface_value,
        "hostname": hostname_value,
        "ip_stats": ip_stats,
        "day_total": traffic_stats_total(ip_stats, "day_total"),
        "day_rx": traffic_stats_total(ip_stats, "day_rx"),
        "day_tx": traffic_stats_total(ip_stats, "day_tx"),
        "yesterday_total": traffic_stats_total(ip_stats, "yesterday_total"),
        "yesterday_rx": traffic_stats_total(ip_stats, "yesterday_rx"),
        "yesterday_tx": traffic_stats_total(ip_stats, "yesterday_tx"),
        "month_total": traffic_stats_total(ip_stats, "month_total"),
        "month_rx": traffic_stats_total(ip_stats, "month_rx"),
        "month_tx": traffic_stats_total(ip_stats, "month_tx"),
        "ram_total": int(payload.get("ram_total") or 0),
        "ram_used": int(payload.get("ram_used") or 0),
        "ram_percent": int(payload.get("ram_percent") or 0),
        "cpu_percent": normalize_cpu_percent(payload.get("cpu_percent")),
        "metrics_ok": bool(payload.get("metrics_ok")),
        "push_interval_sec": max(0, min(3600, push_interval_sec)),
        "haproxy_allowed_sni": normalize_sni_list(payload.get("haproxy_allowed_sni")),
        "haproxy_backend_target": normalize_haproxy_target_or_empty(payload.get("haproxy_backend_target")),
        "haproxy_routes_supported": haproxy_routes_supported,
        "haproxy_routes_managed": bool(payload.get("haproxy_routes_managed")) if haproxy_routes_supported else False,
        "haproxy_routes": haproxy_routes,
        "haproxy_apply_result": normalize_haproxy_apply_result(payload.get("haproxy_apply_result")),
        "haproxy_bandwidth_supported": haproxy_bandwidth_supported,
        "haproxy_bandwidth_limits": haproxy_bandwidth_limits,
        "haproxy_bandwidth_apply_result": normalize_haproxy_bandwidth_apply_result(payload.get("haproxy_bandwidth_apply_result")),
        "scan_wrong_sni_total": int(payload.get("scan_wrong_sni_total") or 0),
        "scan_wrong_sni_sources": int(payload.get("scan_wrong_sni_sources") or 0),
        "scan_wrong_sni_top": normalize_scan_top(payload.get("scan_wrong_sni_top")),
        "scan_wrong_sni_names": normalize_scan_sni_top(payload.get("scan_wrong_sni_names")),
        "remna": normalize_remna_info(payload.get("remna")),
        "error": clean_display_text(payload.get("error") or "")[:1000],
        "updated_at": int(payload.get("updated_at") or current),
        "last_seen": current,
        "offline_alerted": False,
    }
    with LOCK:
        suppress_runtime_stats = clean_all_active_unlocked()
        record_key = node_record_key(record) or node_canonical_key(record) or node_id
        old = NODES.get(record_key, {})
        if not old:
            for existing_id, existing_node in NODES.items():
                if existing_id != record_key and (
                    (node_record_key(existing_node) or node_canonical_key(existing_node)) == record_key
                    or node_same_identity(existing_node, record)
                    or node_migrates_legacy_identity(existing_node, record)
                ):
                    old = existing_node
                    break
        if old and not record.get("haproxy_routes_supported") and old.get("haproxy_routes_supported"):
            record["haproxy_routes_supported"] = True
            record["haproxy_routes_managed"] = bool(old.get("haproxy_routes_managed"))
            record["haproxy_routes"] = normalize_haproxy_routes(old.get("haproxy_routes"))
        if old and not record.get("haproxy_apply_result") and isinstance(old.get("haproxy_apply_result"), dict):
            record["haproxy_apply_result"] = dict(old.get("haproxy_apply_result"))
        if old and not record.get("haproxy_bandwidth_supported") and old.get("haproxy_bandwidth_supported"):
            record["haproxy_bandwidth_supported"] = True
            record["haproxy_bandwidth_limits"] = normalize_haproxy_bandwidth_limits(old.get("haproxy_bandwidth_limits"))
        if old and not record.get("haproxy_bandwidth_apply_result") and isinstance(old.get("haproxy_bandwidth_apply_result"), dict):
            record["haproxy_bandwidth_apply_result"] = dict(old.get("haproxy_bandwidth_apply_result"))
        removed = []
        if suppress_runtime_stats:
            for existing_id, existing_node in list(NODES.items()):
                if existing_id == record_key or (node_record_key(existing_node) or node_canonical_key(existing_node)) == record_key or node_same_identity(existing_node, record) or node_migrates_legacy_identity(existing_node, record):
                    del NODES[existing_id]
                    removed.append(existing_id)
            if removed:
                schedule_nodes_save()
            was_offline = False
        else:
            try:
                enrich_network_rate_stats(record_key, record["ip_stats"], old.get("ip_stats"), current)
            except Exception as exc:
                log(f"network rate sample failed node={record_key}: {exc}")
                try:
                    network_rate_db().rollback()
                except Exception:
                    pass
            try:
                cpu_average, cpu_samples = enrich_cpu_average(
                    record_key,
                    record["cpu_percent"],
                    record["metrics_ok"],
                    current,
                )
                record["cpu_avg_1h"] = cpu_average
                record["cpu_samples_1h"] = cpu_samples
            except Exception as exc:
                log(f"cpu average sample failed node={record_key}: {exc}")
                try:
                    network_rate_db().rollback()
                except Exception:
                    pass
                record["cpu_avg_1h"] = normalize_cpu_percent(old.get("cpu_avg_1h"))
                record["cpu_samples_1h"] = int(old.get("cpu_samples_1h") or 0)
            record["avg_rx_bps_1h"] = sum(
                normalize_network_rate(entry.get("avg_rx_bps_1h")) for entry in record["ip_stats"]
            )
            record["avg_tx_bps_1h"] = sum(
                normalize_network_rate(entry.get("avg_tx_bps_1h")) for entry in record["ip_stats"]
            )
            was_offline = bool(old.get("offline_alerted")) and bool(old.get("offline_confirmed", True))
            if node_stats_disabled(record):
                if was_offline:
                    revoke_fall(record)
                was_offline = False
            elif was_offline:
                offline_since = int(old.get("offline_since") or old.get("last_seen") or current)
                record_downtime(current - offline_since, record)
            scan_alerted_at = int(old.get("scan_alerted_at") or 0)
            record["scan_alerted_at"] = scan_alerted_at
            record["push_miss_alerted_at"] = int(old.get("push_miss_alerted_at") or 0)
            record["push_history"] = clean_push_history(old.get("push_history"), current, node_push_interval_sec(record) or BL_PUSH_INTERVAL_SEC)
            if old and "scan_wrong_sni_total" in old and SCAN_ALERT_DELTA > 0:
                old_scan_total = int(old.get("scan_wrong_sni_total") or 0)
                scan_delta = record["scan_wrong_sni_total"] - old_scan_total
                if scan_delta >= SCAN_ALERT_DELTA and current - scan_alerted_at >= SCAN_ALERT_COOLDOWN:
                    record["scan_alerted_at"] = current
                    scan_alert_node = dict(record)
                    scan_alert_delta = scan_delta
            for existing_id, existing_node in list(NODES.items()):
                if existing_id != record_key and (
                    (node_record_key(existing_node) or node_canonical_key(existing_node)) == record_key
                    or node_same_identity(existing_node, record)
                    or node_migrates_legacy_identity(existing_node, record)
                ):
                    del NODES[existing_id]
                    removed.append(existing_id)
            NODES[record_key] = record
            schedule_nodes_save()
    if removed:
        log(f"removed duplicate node records for {record_key}: {', '.join(removed)}")
    if was_offline:
        log(f"node online: {record_key}")
        if node_connection_alerts_disabled(record):
            log(f"node online alert muted: {record_key}")
        else:
            enqueue_event(alert_online, record_key, dict(record))
    if scan_alert_node:
        log(f"scan spike: {record_key} delta={scan_alert_delta}")
        enqueue_event(alert_scan_spike, dict(scan_alert_node), scan_alert_delta)
    process_update_result(payload.get("update_result"), record, current)
    ip_events = payload.get("ip_limit_events")
    if not suppress_runtime_stats and isinstance(ip_events, list) and ip_events:
        enqueue_event(process_ip_limit_events, ip_events, record.get("name") or node_id, current)
    return record


def authorized(headers):
    if not SECRET:
        return False
    value = headers.get("Authorization", "")
    return hmac.compare_digest(value, f"Bearer {SECRET}") or hmac.compare_digest(value, SECRET)


def hmac_sha256_hex(secret, value):
    return hmac.new(str(secret).encode("utf-8"), value, hashlib.sha256).hexdigest()


def request_signature_payload(timestamp, nonce, body):
    digest = hashlib.sha256(body).hexdigest()
    return f"kto-v2\n{timestamp}\n{nonce}\n{digest}".encode("utf-8")


def response_signature_payload(nonce, body):
    digest = hashlib.sha256(body).hexdigest()
    return f"kto-v2\n{nonce}\n{digest}".encode("utf-8")


def authenticate_push(headers, body, current=None):
    global AUTH_NONCE_LAST_PURGE
    if not SECRET:
        return None
    signature = str(headers.get("X-KTO-Signature", "") or "").strip().lower()
    timestamp_text = str(headers.get("X-KTO-Timestamp", "") or "").strip()
    nonce = str(headers.get("X-KTO-Nonce", "") or "").strip().lower()
    if signature or timestamp_text or nonce:
        if not re.fullmatch(r"[0-9a-f]{64}", signature):
            return None
        if not re.fullmatch(r"[0-9a-f]{16,64}", nonce):
            return None
        try:
            timestamp = int(timestamp_text)
        except (TypeError, ValueError):
            return None
        current = int(current or now_ts())
        if abs(current - timestamp) > AUTH_MAX_SKEW_SEC:
            return None
        expected = hmac_sha256_hex(SECRET, request_signature_payload(timestamp, nonce, body))
        if not hmac.compare_digest(signature, expected):
            return None
        with LOCK:
            if current - AUTH_NONCE_LAST_PURGE >= min(60, AUTH_MAX_SKEW_SEC):
                cutoff = current - AUTH_MAX_SKEW_SEC
                for old_nonce, seen_at in list(AUTH_NONCES.items()):
                    if seen_at < cutoff:
                        del AUTH_NONCES[old_nonce]
                AUTH_NONCE_LAST_PURGE = current
            if nonce in AUTH_NONCES:
                return None
            AUTH_NONCES[nonce] = current
        return {"mode": "hmac-sha256", "nonce": nonce, "timestamp": timestamp}
    if authorized(headers):
        return {"mode": "legacy", "nonce": "", "timestamp": 0}
    return None


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(20)

    def log_message(self, fmt, *args):
        log(fmt % args)

    def send_json(self, code, data, auth_context=None):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if isinstance(auth_context, dict) and auth_context.get("mode") == "hmac-sha256":
            nonce = str(auth_context.get("nonce") or "")
            signature = hmac_sha256_hex(SECRET, response_signature_payload(nonce, body))
            self.send_header("X-KTO-Auth", "hmac-sha256")
            self.send_header("X-KTO-Nonce", nonce)
            self.send_header("X-KTO-Response-Signature", signature)
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
                nodes = {key: dict(value) for key, value in NODES.items()}
            self.send_json(200, {"ok": True, "nodes": nodes})
            return
        self.send_json(404, {"ok": False, "error": "not found"})

    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path
        if path != "/push":
            self.send_json(404, {"ok": False, "error": "not found"})
            return
        auth_context = None
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 1048576:
                raise ValueError("bad content length")
            body = self.rfile.read(length)
            auth_context = authenticate_push(self.headers, body)
            if auth_context is None:
                self.send_json(401, {"ok": False, "error": "unauthorized"})
                return
            payload = json.loads(body.decode("utf-8"))
            remote_ip = self.client_address[0] if self.client_address else ""
            node = update_node(payload, remote_ip)
            acknowledge_haproxy_desired_state(node)
            response = {
                "ok": True,
                "id": node["id"],
                "last_seen": node["last_seen"],
            }
            if remote_commands_paused():
                response.update({
                    "remote_commands_paused": True,
                    "ip_limit_blocks": [],
                    "ip_limit_clear_blocks": True,
                })
                self.send_json(200, response, auth_context=auth_context)
                return
            response.update({
                "ssh_allowed_ips": ssh_allowed_ips_for_node(node),
                "ssh_firewall_open": ssh_firewall_open_for_node(node),
                "ip_limit_blocks": [],
                "ip_limit_clear_blocks": True,
            })
            total_limit = ip_limit_total_limit()
            ip_policy = ip_limit_node_policy(node)
            if total_limit is not None:
                response["ip_limit_enabled"] = total_limit > 0
            elif ip_policy is not None:
                response["ip_limit_enabled"] = bool(ip_policy.get("enabled"))
            else:
                response["ip_limit_enabled"] = bool(IP_LIMIT_ENABLED)
            desired_item = haproxy_state_item_for_node(node) or {}
            desired_haproxy_routes = (
                normalize_haproxy_routes(desired_item.get("routes"))
                if "routes" in desired_item
                else None
            )
            if desired_haproxy_routes is not None:
                if not haproxy_desired_apply_error(node, "routes", desired_item):
                    response["haproxy_routes"] = desired_haproxy_routes
                    response["haproxy_routes_command_id"] = clean_haproxy_command_id(
                        desired_item.get("routes_command_id")
                    )
            else:
                sni_override = sni_override_for_node(node)
                if sni_override is not None:
                    response["allowed_sni"] = sni_override
                haproxy_target = haproxy_target_override_for_node(node)
                if haproxy_target:
                    response["haproxy_target"] = haproxy_target
            desired_haproxy_bandwidth = (
                normalize_haproxy_bandwidth_limits(desired_item.get("bandwidth_limits"))
                if "bandwidth_limits" in desired_item
                else None
            )
            if desired_haproxy_bandwidth is not None and not haproxy_desired_apply_error(
                node, "bandwidth", desired_item
            ):
                response["haproxy_bandwidth_limits"] = desired_haproxy_bandwidth
                response["haproxy_bandwidth_command_id"] = clean_haproxy_command_id(
                    desired_item.get("bandwidth_command_id")
                )
            node_name_sync = node_name_sync_value(node, payload.get("name"))
            if node_name_sync:
                response["node_name"] = node_name_sync
            desired_interval = desired_push_interval_sec(node)
            if desired_interval > 0:
                response["push_interval_sec"] = desired_interval
            update_task = update_task_for_node(node)
            if update_task:
                response["update_task"] = update_task
            self.send_json(200, response, auth_context=auth_context)
        except Exception as exc:
            self.send_json(400, {"ok": False, "error": str(exc)}, auth_context=auth_context)


def offline_loop():
    while True:
        try:
            time.sleep(OFFLINE_LOOP_SEC)
            current = now_ts()
            changed = False
            alerts = []
            with LOCK:
                for node_id, node in NODES.items():
                    if node_stats_disabled(node):
                        if node.pop("offline_pending_since", None) is not None:
                            changed = True
                        if node.get("offline_alerted"):
                            node["offline_alerted"] = False
                            node.pop("offline_confirmed", None)
                            node.pop("offline_since", None)
                            node.pop("offline_guard_reason", None)
                            revoke_fall(node)
                            changed = True
                        continue
                    age = current - int(node.get("last_seen", 0) or 0)
                    stale_sec = node_stale_sec(node)
                    guard_reason = remnawave_offline_guard_reason(node, current, age, stale_sec)
                    if age <= stale_sec:
                        if node.pop("offline_pending_since", None) is not None:
                            changed = True
                        if node.get("offline_alerted") and not node_is_wl(node):
                            node["offline_alerted"] = False
                            node.pop("offline_confirmed", None)
                            node.pop("offline_since", None)
                            node.pop("offline_guard_reason", None)
                            revoke_fall(node)
                            changed = True
                        continue
                    if guard_reason:
                        if node.pop("offline_pending_since", None) is not None:
                            changed = True
                        if node.get("offline_alerted") and not node_is_wl(node):
                            node["offline_alerted"] = False
                            node.pop("offline_confirmed", None)
                            node.pop("offline_since", None)
                            revoke_fall(node)
                            changed = True
                        if node.get("offline_guard_reason") != guard_reason:
                            node["offline_guard_reason"] = guard_reason
                            changed = True
                        continue
                    if node.get("offline_alerted"):
                        continue
                    if node_push_miss_blocks_alert(node, current):
                        continue
                    if node_push_miss_exceeded(node, current):
                        last_miss_alert = int(node.get("push_miss_alerted_at") or 0)
                        if PUSH_MISS_ALERT_COOLDOWN > 0 and current - last_miss_alert < PUSH_MISS_ALERT_COOLDOWN:
                            continue
                    confirm_sec = node_offline_confirm_sec(node)
                    pending_since = int(node.get("offline_pending_since") or 0)
                    if confirm_sec > 0:
                        if pending_since <= 0:
                            node["offline_pending_since"] = current
                            changed = True
                            continue
                        if current - pending_since < confirm_sec:
                            continue
                    node["offline_alerted"] = True
                    node["offline_confirmed"] = True
                    node["offline_since"] = pending_since or current
                    if node_push_miss_exceeded(node, current):
                        node["push_miss_alerted_at"] = current
                    node.pop("offline_pending_since", None)
                    node.pop("offline_guard_reason", None)
                    record_fall(node)
                    if node_connection_alerts_disabled(node):
                        log(f"node offline alert muted: {node_id}")
                    else:
                        alerts.append((node_id, dict(node), age))
                    changed = True
                if changed:
                    save_nodes()
            for node_id, node, age in alerts:
                log(f"node offline: {node_id} age={age}s stale={node_stale_sec(node)}s confirm={node_offline_confirm_sec(node)}s")
                alert_offline(node_id, node, age)
        except Exception as exc:
            log(f"offline loop failed: {exc}")
            time.sleep(5)


class CollectorHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128


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
                wl_sent = send_stats_wl(use_rich=True)
                bl_sent = False
                if wl_sent:
                    bl_sent = send_grouped_bl_stats(use_rich=True)
                if wl_sent and bl_sent:
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
        if deleted:
            remove_bl_group_nodes_by_aliases(aliases)

    return deleted, removed_fall_names, removed_falls


def handle_delete(text):
    parts = text.split(maxsplit=1)
    if len(parts) < 2 or not parts[1].strip():
        send_message("<b>Пример:</b> /delete Россия, Санкт-Петербург")
        return

    query = parts[1].strip()
    deleted, removed_fall_names, removed_falls = delete_node_records(query)
    if not deleted and not removed_fall_names:
        send_message(
            "<b>Не нашёл такую машину</b>\n\n"
            f"Запрос: <code>{html.escape(clean_display_text(query))}</code>\n"
            "Пиши точное название, например: <code>/delete Россия, Санкт-Петербург</code>"
        )
        return

    lines = ["<b>Машина удалена</b>", ""]
    if deleted:
        for node_id, node in deleted:
            name = html.escape(clean_display_text(node.get("name") or node_id))
            ip = html.escape(str(node.get("ip") or "-"))
            lines.append(f"<blockquote>{name}\nIP: {ip}</blockquote>")
    else:
        lines.append("Активной записи уже не было.")
    if removed_fall_names:
        lines += [
            "",
            f"Падений за сегодня вычистил: {removed_falls}",
            "Топ падений: очищен по этой машине",
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


def update_progress_snapshot_unlocked():
    current = dict(UPDATE_STATE.get("current") or {})
    local = dict(UPDATE_STATE.get("local") or {})
    results = dict(UPDATE_STATE.get("results") or {})
    targets = current.get("targets") if isinstance(current.get("targets"), dict) else {}
    targets = {str(key): clean_display_text(value or key) for key, value in targets.items() if key}
    job_id = str(current.get("id") or "")
    action = str(current.get("action") or "push_update")
    scope = str(current.get("scope") or "all")
    local_required = bool(current.get("local_required", True))
    live_targets = bool(current.get("live_targets", False))
    if live_targets and not targets and job_id:
        for key, item in results.items():
            if isinstance(item, dict) and item.get("id") == job_id:
                targets[str(key)] = clean_display_text(item.get("node") or key)
    ok_count = 0
    error_count = 0
    running_count = 0
    wait_count = 0
    errors = []
    ok_items = []
    running_items = []
    wait_items = []
    for key in targets:
        item = results.get(key)
        if not isinstance(item, dict) or item.get("id") != job_id:
            wait_count += 1
            wait_items.append({
                "key": key,
                "node": targets.get(key) or key,
                "status": "wait",
                "message": "ждёт ближайший push",
            })
            continue
        item = dict(item)
        item["key"] = key
        item["node"] = clean_display_text(item.get("node") or targets.get(key) or key)
        status = item.get("status")
        if status == "ok":
            ok_count += 1
            ok_items.append(item)
        elif status == "error":
            error_count += 1
            errors.append(item)
        elif status == "running":
            running_count += 1
            running_items.append(item)
        else:
            wait_count += 1
            wait_items.append(item)
    local_status = local.get("status") if local.get("id") == job_id else "wait"
    if not local_required and local_status == "wait":
        local_status = "ok"
    if local_status == "error":
        local_error = dict(local)
        local_error["node"] = "collector"
        errors.insert(0, local_error)
    done = bool(job_id) and not live_targets and local_status in ("ok", "error") and wait_count == 0 and running_count == 0
    return {
        "job_id": job_id,
        "action": action,
        "scope": scope,
        "local_required": local_required,
        "live_targets": live_targets,
        "local_status": local_status or "wait",
        "ok_count": ok_count,
        "error_count": error_count,
        "running_count": running_count,
        "wait_count": wait_count,
        "ok_items": ok_items,
        "running_items": running_items,
        "wait_items": wait_items,
        "errors": errors,
        "done": done,
        "notified_at": int(current.get("notified_at") or 0),
    }


def update_action_label(action):
    action = str(action or "push_update")
    if action == "node_update":
        return "remnanode compose"
    if action == "optimize":
        return "system optimize"
    if action == "optimize_status":
        return "system optimize check"
    if action == "push_delete":
        return "push self-delete"
    return "push script"


def update_scope_label(scope):
    scope = str(scope or "all").lower()
    if scope in ("panel", "collector"):
        return "панель"
    if scope == "wl":
        return "WL"
    if scope == "bl":
        return "BL"
    if scope == "single":
        return "1 машина"
    if scope == "list":
        return "список"
    if scope == "live":
        return "любой push"
    return "все"


def update_retry_token(node_key):
    return hashlib.sha1(str(node_key or "").encode("utf-8", errors="ignore")).hexdigest()[:12]


def update_retry_compound(action, token):
    return f"{str(action or '').strip()[:40]}:{str(token or '').strip()[:24]}"


def register_update_retry_token(action, key, name):
    action = str(action or "push_update").strip()[:40]
    key = str(key or "").strip()[:120]
    if not key:
        return ""
    token = update_retry_token(key)
    compound = update_retry_compound(action, token)
    current = now_ts()
    with LOCK:
        tokens = UPDATE_STATE.setdefault("retry_tokens", {})
        tokens[compound] = {
            "action": action,
            "token": token,
            "key": key,
            "name": clean_display_text(name or key)[:120] or key,
            "created_at": current,
        }
        if len(tokens) > 300:
            ordered = sorted(
                tokens.items(),
                key=lambda row: int((row[1] if isinstance(row[1], dict) else {}).get("created_at") or 0),
                reverse=True,
            )
            UPDATE_STATE["retry_tokens"] = dict(ordered[:300])
        save_update_state()
    return token


def lookup_update_retry_token(action, token):
    compound = update_retry_compound(action, token)
    with LOCK:
        tokens = UPDATE_STATE.get("retry_tokens") if isinstance(UPDATE_STATE.get("retry_tokens"), dict) else {}
        item = tokens.get(compound)
        if not isinstance(item, dict):
            return None
        try:
            created_at = int(item.get("created_at") or 0)
        except Exception:
            created_at = 0
        if created_at and now_ts() - created_at > 7 * 86400:
            tokens.pop(compound, None)
            save_update_state()
            return None
        return {
            "key": str(item.get("key") or "").strip()[:120],
            "name": clean_display_text(item.get("name") or item.get("key") or "")[:120],
            "action": str(item.get("action") or action).strip()[:40],
        }


def update_retry_markup(snapshot):
    errors = snapshot.get("errors") if isinstance(snapshot.get("errors"), list) else []
    rows = []
    action = str(snapshot.get("action") or "push_update")
    for item in errors:
        key = str(item.get("key") or "")
        if not key:
            continue
        name = clean_display_text(item.get("node") or key)[:40]
        token = register_update_retry_token(action, key, name or key)
        rows.append([{"text": name or key, "callback_data": f"upd:r:{action}:{token}"}])
        if len(rows) >= 10:
            break
    return {"inline_keyboard": rows} if rows else None


def update_status_message_from_snapshot(snapshot, title="Update status"):
    job_id = str(snapshot.get("job_id") or "")
    if not job_id:
        return "<b>Update-задачи нет.</b>"
    collector_status = snapshot.get("local_status") or "-"
    node_status = f"ok {snapshot.get('ok_count', 0)} / error {snapshot.get('error_count', 0)} / running {snapshot.get('running_count', 0)} / wait {snapshot.get('wait_count', 0)}"
    if not snapshot.get("local_required", True):
        collector_status = "skip"
    if str(snapshot.get("scope") or "").lower() in ("panel", "collector"):
        node_status = "skip"
    lines = [
        f"<b>{title}</b>",
        ALERT_SEPARATOR,
        detail_line("Job", job_id),
        detail_line("Тип", update_action_label(snapshot.get("action"))),
        detail_line("Группа", update_scope_label(snapshot.get("scope"))),
        detail_line("Collector", collector_status),
        detail_line("Ноды", node_status),
    ]
    errors = snapshot.get("errors") if isinstance(snapshot.get("errors"), list) else []
    if errors:
        lines.append("")
        lines.append("<b>Ошибки:</b>")
        for item in errors[:10]:
            node = html.escape(clean_display_text(item.get("node") or "-"))
            message = html.escape(clean_display_text(item.get("message") or "-"))
            lines.append(f"<blockquote>{node}: {message}</blockquote>")
    return "\n".join(lines)


def friendly_update_message(message, status=""):
    text = clean_display_text(message)
    lower = text.lower()
    if lower in ("ok", "skip"):
        return "готово"
    if lower == "wait":
        return "ждёт"
    if lower == "running":
        return "выполняется"
    if lower == "error":
        return "ошибка"
    if lower == "node update started":
        return "docker compose pull/up"
    if lower == "node updated":
        return "готово"
    if lower == "push update started":
        return "скачивает и ставит push-скрипт"
    if lower == "push script updated":
        return "push-скрипт обновлён"
    if lower == "collector update started":
        return "collector обновляется"
    if lower == "collector skipped":
        return "collector не трогаем"
    if lower == "docker not found":
        return "docker не найден"
    if lower == "docker compose not found":
        return "docker compose не найден"
    if lower == "compose dir not found":
        return "папка compose не найдена"
    if lower.startswith("curl failed"):
        return "не смог скачать скрипт"
    if lower.startswith("install /usr/local/bin/kto-stats-push failed"):
        return "не смог поставить push-скрипт"
    if text:
        return text
    if status == "wait":
        return "ждёт ближайший push"
    if status == "running":
        return "выполняется"
    if status == "ok":
        return "готово"
    if status == "error":
        return "ошибка"
    return "-"


def friendly_update_item_lines(items, empty_text="нет", max_items=60):
    items = items if isinstance(items, list) else []
    if not items:
        return f"<blockquote>{html.escape(empty_text)}</blockquote>"
    lines = []
    for item in items[:max_items]:
        if not isinstance(item, dict):
            continue
        node = clean_display_text(item.get("node") or item.get("key") or "-")
        status = str(item.get("status") or "")
        stage = friendly_update_message(item.get("message") or "", status=status)
        lines.append(f"{html.escape(node)} — {html.escape(stage)}")
    if len(items) > max_items:
        lines.append(f"... ещё {len(items) - max_items}")
    return "<blockquote>" + "\n".join(lines or [html.escape(empty_text)]) + "</blockquote>"


def friendly_update_status_message(snapshot):
    job_id = str(snapshot.get("job_id") or "")
    if not job_id:
        return "<b>Update-задачи нет.</b>"
    action = snapshot.get("action")
    local_status = snapshot.get("local_status") or "-"
    summary = (
        f"готово {int(snapshot.get('ok_count') or 0)} / "
        f"ошибки {int(snapshot.get('error_count') or 0)} / "
        f"на апдейте {int(snapshot.get('running_count') or 0)} / "
        f"ждут {int(snapshot.get('wait_count') or 0)}"
    )
    lines = [
        "<b>Статус апдейта нод</b>",
        ALERT_SEPARATOR,
        detail_line("Job", job_id),
        detail_line("Тип", update_action_label(action)),
        detail_line("Группа", update_scope_label(snapshot.get("scope"))),
        detail_line("Итог", summary),
    ]
    if snapshot.get("local_required", True):
        lines.append(detail_line("Collector", friendly_update_message(local_status, status=local_status)))
    lines += [
        "",
        "<b>На апдейте:</b>",
        friendly_update_item_lines(snapshot.get("running_items"), empty_text="нет"),
        "<b>Ждут push:</b>",
        friendly_update_item_lines(snapshot.get("wait_items"), empty_text="нет"),
        "<b>Выполнено:</b>",
        friendly_update_item_lines(snapshot.get("ok_items"), empty_text="нет"),
        "<b>Не выполнено:</b>",
        friendly_update_item_lines(snapshot.get("errors"), empty_text="нет"),
    ]
    return "\n".join(lines)


def update_status_payload():
    with LOCK:
        snapshot = update_progress_snapshot_unlocked()
    return update_status_message_from_snapshot(snapshot), update_retry_markup(snapshot)


def update_status_message():
    body, _ = update_status_payload()
    return body


def optimize_status_label(status):
    status = str(status or "").lower()
    if status == "ok":
        return "OK"
    if status == "skip":
        return "SKIP"
    if status == "error":
        return "ERROR"
    return "НЕТ"


def status_panel_label(status):
    status = str(status or "info").lower()
    if status == "ok":
        return "OK"
    if status == "fail":
        return "FAIL"
    if status == "warn":
        return "WARN"
    return "-"


def fit_cell(value, width):
    text = clean_display_text(value)
    if len(text) <= width:
        return text.ljust(width)
    if width <= 1:
        return text[:width]
    return (text[: width - 1] + "…").ljust(width)


def optimize_text_table(rows):
    if not rows:
        return ""
    lines = [
        f"{fit_cell('Проверка', 18)} {fit_cell('Статус', 6)} {fit_cell('Сейчас', 24)} Нужно",
        f"{'-' * 18} {'-' * 6} {'-' * 24} {'-' * 24}",
    ]
    for row in rows[:30]:
        if not isinstance(row, dict):
            continue
        lines.append(
            f"{fit_cell(row.get('name') or '-', 18)} "
            f"{fit_cell(optimize_status_label(row.get('status')), 6)} "
            f"{fit_cell(row.get('current') or '-', 24)} "
            f"{clean_display_text(row.get('desired') or '-')}"
        )
    return "\n".join(lines)


def optimize_result_payload(result, title="Optimize status"):
    result = result if isinstance(result, dict) else {}
    details = result.get("details") if isinstance(result.get("details"), dict) else {}
    mode = str(details.get("mode") or "status")
    status_rows = details.get("status_rows") if isinstance(details.get("status_rows"), list) else []
    rows = details.get("after") if isinstance(details.get("after"), list) else []
    if not rows:
        rows = details.get("before") if isinstance(details.get("before"), list) else []
    missing_before = details.get("missing_before") if isinstance(details.get("missing_before"), list) else []
    missing_before = [clean_display_text(item) for item in missing_before if clean_display_text(item)]
    node_name = clean_display_text(result.get("node") or "-")
    message = clean_display_text(result.get("message") or "")
    details_text = str(result.get("details_text") or "").strip()
    status = str(result.get("status") or "-")
    rich_lines = [
        f"<b>{html.escape(title)}</b>",
        ALERT_SEPARATOR,
        detail_line("Машина", node_name),
        detail_line("Режим", "fix" if mode == "apply" else "check"),
        detail_line("Статус", status),
    ]
    if result.get("build"):
        rich_lines.append(detail_line("Build", result.get("build")))
    if mode == "apply":
        rich_lines.append(detail_line("Исправлено", details.get("fixed_count", 0)))
        rich_lines.append(detail_line("Осталось", details.get("remaining_count", 0)))
        if missing_before:
            rich_lines += [
                "",
                "<b>Не было до фикса:</b>",
                "<blockquote>" + "\n".join(html.escape(item) for item in missing_before[:20]) + "</blockquote>",
            ]
        else:
            rich_lines.append(detail_line("До фикса", "всё уже было OK"))
    if message:
        rich_lines.append(detail_line("Сообщение", message))

    if status_rows:
        ok_count = sum(1 for row in status_rows if isinstance(row, dict) and row.get("status") == "ok")
        fail_count = sum(1 for row in status_rows if isinstance(row, dict) and row.get("status") == "fail")
        warn_count = sum(1 for row in status_rows if isinstance(row, dict) and row.get("status") == "warn")
        info_count = sum(1 for row in status_rows if isinstance(row, dict) and row.get("status") == "info")
        panel_title = "Панель состояния" if mode == "status" else "Панель состояния после оптимизации"
        build = clean_display_text(result.get("build") or "-")
        rich_lines = [
            f"<h3>{rich_text(panel_title)}</h3>",
            f"<p><b>Машина:</b> {rich_text(node_name)}</p>",
            f"<p><b>OK:</b> {rich_text(str(ok_count))} · <b>FAIL:</b> {rich_text(str(fail_count))} · <b>INFO:</b> {rich_text(str(info_count))}"
            + (f" · <b>WARN:</b> {rich_text(str(warn_count))}" if warn_count else "")
            + f" · <b>Build:</b> {rich_text(build)}</p>",
        ]
        if fail_count:
            rich_lines.append(f"<p><b>Требует внимания:</b> {rich_text(str(fail_count))}</p>")
        table_rows = []
        for row in status_rows:
            if not isinstance(row, dict):
                continue
            table_rows.append([
                (row.get("section") or "-", "left"),
                (row.get("name") or "-", "left"),
                (row.get("value") or "-", "left"),
                (status_panel_label(row.get("status")), "center"),
            ])
        rich_html = "\n".join(rich_lines)
        rich_html += "\n" + rich_table(["Раздел", "Проверка", "Значение", "Статус"], table_rows)
        text_lines = [
            f"<b>{html.escape(panel_title)}</b>",
            ALERT_SEPARATOR,
            detail_line("Машина", node_name),
            detail_line("OK / FAIL / INFO", f"{ok_count} / {fail_count} / {info_count}"),
            detail_line("Build", build),
        ]
        if fail_count:
            text_lines.append(detail_line("Требует внимания", fail_count))
        text_rows = []
        for row in status_rows:
            if not isinstance(row, dict):
                continue
            text_rows.append({
                "name": f"{row.get('section') or '-'} / {row.get('name') or '-'}",
                "status": "ok" if row.get("status") == "ok" else "miss" if row.get("status") == "fail" else "skip",
                "current": row.get("value") or "-",
                "desired": status_panel_label(row.get("status")),
            })
        text_lines += ["", "<b>Панель состояния:</b>", f"<pre>{html.escape(optimize_text_table(text_rows))}</pre>"]
        return rich_html, "\n".join(text_lines)

    table_rows = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        table_rows.append([
            (row.get("name") or "-", "left"),
            (optimize_status_label(row.get("status")), "center"),
            (row.get("current") or "-", "left"),
            (row.get("desired") or "-", "left"),
        ])
    table_html = rich_table(["Проверка", "Статус", "Сейчас", "Нужно"], table_rows)
    rich_html = "\n".join(rich_lines)
    if table_html:
        rich_html += "\n" + table_html
    elif not rows:
        rich_html = ""

    text_lines = list(rich_lines)
    if rows:
        text_lines += ["", "<b>Проверки:</b>", f"<pre>{html.escape(optimize_text_table(rows))}</pre>"]
    elif details_text:
        text_lines += ["", "<b>Проверки:</b>", f"<pre>{html.escape(details_text)}</pre>"]
    else:
        text_lines += [
            "",
            "<b>Проверки:</b>",
            "<blockquote>Нода вернула итог без строк панели состояния. Обнови push на этой машине до v207 и повтори команду.</blockquote>",
        ]
    return rich_html, "\n".join(text_lines)


def optimize_done_payload_unlocked(snapshot, title):
    current = UPDATE_STATE.get("current") if isinstance(UPDATE_STATE.get("current"), dict) else {}
    results = UPDATE_STATE.get("results") if isinstance(UPDATE_STATE.get("results"), dict) else {}
    targets = current.get("targets") if isinstance(current.get("targets"), dict) else {}
    job_id = str(snapshot.get("job_id") or "")
    for key, node_name in targets.items():
        item = results.get(key)
        if isinstance(item, dict) and item.get("id") == job_id:
            result = dict(item)
            result["node"] = clean_display_text(result.get("node") or node_name or key)
            return optimize_result_payload(result, title=title)
    return "", update_status_message_from_snapshot(snapshot, title=title)


def maybe_send_update_done_notification():
    message = ""
    rich_message = ""
    notify_chat_id = ""
    notify_message_id = ""
    with LOCK:
        snapshot = update_progress_snapshot_unlocked()
        current = UPDATE_STATE.get("current") if isinstance(UPDATE_STATE.get("current"), dict) else {}
        if not snapshot.get("done") or snapshot.get("notified_at"):
            return
        notify_chat_id = str(current.get("notify_chat_id") or "")
        notify_message_id = str(current.get("notify_message_id") or "")
        current["notified_at"] = now_ts()
        UPDATE_STATE["current"] = current
        save_update_state()
        success = snapshot.get("error_count", 0) == 0 and snapshot.get("local_status") == "ok"
        title = "Update завершён" if success else "Update завершён с ошибками"
        if str(snapshot.get("action") or "") in ("optimize", "optimize_status"):
            title = "Optimize завершён" if success else "Optimize завершён с ошибками"
            rich_message, message = optimize_done_payload_unlocked(snapshot, title)
        else:
            message = update_status_message_from_snapshot(snapshot, title=title)
        markup = update_retry_markup(snapshot)
    if message:
        if notify_chat_id and notify_message_id:
            if rich_message and edit_rich_message_text(notify_chat_id, notify_message_id, rich_message, reply_markup=markup):
                return
            if edit_message_text(notify_chat_id, notify_message_id, message, reply_markup=markup):
                return
        if rich_message and send_rich_message(rich_message, reply_markup=markup):
            return
        send_message(message, reply_markup=markup)


def update_start_title(action, scope, retry=False):
    if retry:
        return "Update retry запущен"
    if action == "node_update":
        if str(scope or "").lower() == "list":
            return "Update node list запущен"
        if str(scope or "").lower() == "single":
            return "Update node запущен"
        return "Update nodes запущен"
    if action == "optimize":
        return "Optimize запущен"
    if action == "optimize_status":
        return "Optimize status запущен"
    if action == "push_delete":
        return "Clean all запущен"
    if scope == "wl":
        return "Update WL запущен"
    if scope == "bl":
        return "Update BL запущен"
    if str(scope or "").lower() in ("panel", "collector"):
        return "Update collector запущен"
    return "Update запущен"


def update_status_command(action):
    if action == "node_update":
        return "/update_node_status"
    if action == "push_delete":
        return "/clean_all status"
    return "/update_collector status"


def start_update_job(action, scope, requested_by, local_required=True, targets=None, retry=False, live_targets=False):
    job = queue_update_task(requested_by, action=action, scope=scope, targets=targets, local_required=local_required, live_targets=live_targets)
    total_nodes = len(job.get("targets") if isinstance(job.get("targets"), dict) else {})
    lines = [
        f"<b>{update_start_title(action, scope, retry=retry)}</b>",
        ALERT_SEPARATOR,
        detail_line("Job", job.get("id")),
        detail_line("Тип", update_action_label(action)),
        detail_line("Группа", update_scope_label(scope)),
    ]
    if live_targets:
        lines.append(detail_line("Режим", "любой будущий push"))
    elif str(scope or "").lower() not in ("panel", "collector"):
        lines.append(detail_line("Машин в очереди", total_nodes))
    if action == "push_update":
        lines.append(detail_line("Raw", job.get("raw_base")))
        if str(scope or "").lower() in ("panel", "collector"):
            lines += [
                "",
                "<i>Обновится только collector на панели. Ноды не трогаю.</i>",
                f"<i>Статус: <code>{update_status_command(action)}</code></i>",
            ]
        else:
            lines += [
                "",
                "<i>Collector обновится локально. Ноды применят update при ближайшем push.</i>" if local_required else "<i>Нода применит update при ближайшем push.</i>",
                f"<i>Статус: <code>{update_status_command(action)}</code></i>",
            ]
    elif action == "node_update":
        lines += [
            "",
            "<i>Ноды выполнят docker compose pull/up при ближайшем push.</i>",
            f"<i>Статус: <code>{update_status_command(action)}</code></i>",
        ]
    elif action == "optimize":
        lines += [
            "",
            "<i>Машина сначала проверит оптимизацию, потом применит недостающее при ближайшем push.</i>",
            f"<i>Статус: <code>{update_status_command(action)}</code></i>",
        ]
    elif action == "optimize_status":
        lines += [
            "",
            "<i>Машина только проверит оптимизацию при ближайшем push, без правок.</i>",
            f"<i>Статус: <code>{update_status_command(action)}</code></i>",
        ]
    elif action == "push_delete":
        lines += [
            "",
            "<i>Любая машина, которая ещё пришлёт push, получит команду удалить свой push/timer/config.</i>",
            "<i>Задача останется активной, пока её не заменит следующая update-команда.</i>",
            "<i>Остановить: <code>/clean_all stop</code></i>",
            f"<i>Статус: <code>{update_status_command(action)}</code></i>",
        ]
    send_message("\n".join(lines))
    if action == "push_update" and local_required:
        start_local_collector_update(job)
    maybe_send_update_done_notification()
    return job


def handle_update_collector(text, chat_id, from_id, scope="panel"):
    parts = text.split()
    if len(parts) > 1 and parts[1].lower() in ("status", "статус"):
        body, markup = update_status_payload()
        send_message(body, reply_markup=markup)
        return
    start_update_job("push_update", scope, from_id, local_required=True)


def handle_update_nodes(text, chat_id, from_id):
    parts = text.split()
    if len(parts) > 1 and parts[1].lower() in ("status", "статус"):
        body, markup = update_status_payload()
        send_message(body, reply_markup=markup)
        return
    start_update_job("node_update", "all", from_id, local_required=False)


def clear_collector_runtime_stats():
    cleared = {}
    with LOCK:
        cleared["nodes"] = len(NODES)
        NODES.clear()
        save_nodes()

        fall_nodes = FALLS.get("nodes") if isinstance(FALLS.get("nodes"), dict) else {}
        cleared["falls"] = sum(int(item.get("count") or 0) for item in fall_nodes.values() if isinstance(item, dict))
        FALLS.clear()
        save_falls()

        remna_nodes = REMNA_NODE_STATE.get("nodes") if isinstance(REMNA_NODE_STATE.get("nodes"), dict) else {}
        cleared["remna_nodes"] = len(remna_nodes)
        REMNA_NODE_STATE["nodes"] = {}
        save_remna_node_state()

        db = ip_limit_db()
        for table in ("ip_limit_events", "ip_limit_alerts", "ip_limit_blocks", "ip_limit_penalties", "ip_limit_pending"):
            row = db.execute(f"SELECT COUNT(*) AS value FROM {table}").fetchone()
            cleared[table] = int(row["value"] if row else 0)
            db.execute(f"DELETE FROM {table}")
        db.execute("DELETE FROM ip_limit_meta WHERE key = ?", ("remna_top_alert_last",))
        save_ip_limit_state()

        rate_db = network_rate_db()
        row = rate_db.execute("SELECT COUNT(*) AS value FROM network_rate_minute").fetchone()
        cleared["network_rate_minutes"] = int(row["value"] if row else 0)
        rate_db.execute("DELETE FROM network_rate_minute")
        row = rate_db.execute("SELECT COUNT(*) AS value FROM cpu_minute").fetchone()
        cleared["cpu_minutes"] = int(row["value"] if row else 0)
        rate_db.execute("DELETE FROM cpu_minute")
        rate_db.commit()
    return cleared


def clean_all_cleared_message(cleared):
    ip_rows = sum(int(cleared.get(table) or 0) for table in ("ip_limit_events", "ip_limit_alerts", "ip_limit_blocks", "ip_limit_penalties", "ip_limit_pending"))
    return "\n".join([
        "<b>Локальная стата очищена</b>",
        ALERT_SEPARATOR,
        detail_line("Машины", cleared.get("nodes", 0)),
        detail_line("Падения", cleared.get("falls", 0)),
        detail_line("Remnawave ноды", cleared.get("remna_nodes", 0)),
        detail_line("IP-limit runtime", ip_rows),
        detail_line("Минутные пики скорости", cleared.get("network_rate_minutes", 0)),
        detail_line("Минутные CPU-семплы", cleared.get("cpu_minutes", 0)),
        "",
        "<i>Настройки групп, rename, SNI и лимиты пользователей не трогал.</i>",
    ])


def stop_clean_all():
    with LOCK:
        active = clean_all_active_unlocked()
        if active:
            UPDATE_STATE["current"] = {}
            UPDATE_STATE["results"] = {}
            UPDATE_STATE["local"] = {}
            save_update_state()
        return active


def handle_clean_all(text, chat_id, from_id):
    parts = text.split()
    action = parts[1].lower() if len(parts) > 1 else ""
    if action in ("status", "статус"):
        body, markup = update_status_payload()
        send_message(body, reply_markup=markup)
        return
    if action in ("stop", "off", "cancel", "disable", "стоп", "выкл", "отмена"):
        if stop_clean_all():
            send_message(
                "<b>Clean all остановлен</b>\n"
                f"{ALERT_SEPARATOR}\n"
                "<i>Новые push больше не будут получать self-delete и снова будут писаться в стату.</i>"
            )
        else:
            send_message(
                "<b>Clean all не активен</b>\n"
                f"{ALERT_SEPARATOR}\n"
                "<i>Self-delete задача сейчас не висит.</i>"
            )
        return
    start_update_job("push_delete", "live", from_id, local_required=False, targets={}, live_targets=True)
    send_message(clean_all_cleared_message(clear_collector_runtime_stats()))


def handle_update_node_status(text, chat_id, from_id):
    with LOCK:
        snapshot = update_progress_snapshot_unlocked()
    send_message(friendly_update_status_message(snapshot), reply_markup=update_retry_markup(snapshot))


def handle_update_node(text, chat_id, from_id):
    parts = text.split(maxsplit=1)
    if len(parts) < 2 or not parts[1].strip():
        send_message("<b>Пример:</b> <code>/update_node Германия</code>")
        return
    query = parts[1].strip()
    node = find_node(query)
    if node is None:
        send_message(
            "<b>Не нашёл такую машину</b>\n"
            f"{ALERT_SEPARATOR}\n"
            f"{detail_line('Запрос', query)}\n"
            "Проверь название через <code>/stats</code>."
        )
        return
    node_key = node_canonical_key(node)
    node_name = node_display_name(node, node_key)
    if not node_key:
        send_message("<b>Не смог получить ключ машины.</b>")
        return
    start_update_job(
        "node_update",
        "single",
        from_id,
        local_required=False,
        targets={node_key: node_name},
    )


def set_pending_update_node_list(chat_id, from_id):
    key = pending_key(chat_id, from_id)
    with LOCK:
        UPDATE_STATE.setdefault("pending", {})[key] = {
            "action": "update_node_list",
            "created_at": now_ts(),
        }
        save_update_state()


def pop_pending_update_node_list(chat_id, from_id):
    key = pending_key(chat_id, from_id)
    with LOCK:
        item = UPDATE_STATE.setdefault("pending", {}).pop(key, None)
        if item is not None:
            save_update_state()
        return item if isinstance(item, dict) else None


def peek_pending_update_node_list(chat_id, from_id):
    key = pending_key(chat_id, from_id)
    with LOCK:
        item = UPDATE_STATE.setdefault("pending", {}).get(key)
        if not isinstance(item, dict) or item.get("action") != "update_node_list":
            return None
        if now_ts() - int(item.get("created_at") or 0) > 1800:
            UPDATE_STATE.setdefault("pending", {}).pop(key, None)
            save_update_state()
            return None
        return dict(item)


def normalize_update_node_query(line):
    text = clean_display_text(line)
    text = re.sub(r"^\s*(?:[-*]+|\d+[.)])\s*", "", text)
    return text.strip()


def resolve_update_node_list(text):
    targets = {}
    found = []
    missing = []
    seen_queries = set()
    for raw_line in str(text or "").splitlines():
        query = normalize_update_node_query(raw_line)
        if not query:
            continue
        query_key = canonical_node_key(query)
        if not query_key or query_key in seen_queries:
            continue
        seen_queries.add(query_key)
        node = find_node(query)
        if node is None:
            missing.append(query)
            continue
        node_key = node_canonical_key(node)
        node_name = node_display_name(node, node_key)
        if node_key and node_key not in targets:
            targets[node_key] = node_name
            found.append(node_name)
    return targets, found, missing


def handle_update_node_list_text(chat_id, from_id, text):
    targets, found, missing = resolve_update_node_list(text)
    if not targets and not missing:
        send_message(
            "<b>Список пустой.</b>\n"
            "Напиши названия нод построчно, например:\n"
            "<blockquote>Германия\nШвейцария\nОбход #3</blockquote>"
        )
        return True
    if missing:
        lines = [
            "<b>Не нашёл часть нод</b>",
            ALERT_SEPARATOR,
            "<i>Апдейт не запускал, чтобы не обновить неполный список.</i>",
            "",
            "<b>Не найдены:</b>",
            "<blockquote>" + "\n".join(html.escape(item) for item in missing[:40]) + "</blockquote>",
        ]
        if found:
            lines += [
                "<b>Нашёл:</b>",
                "<blockquote>" + "\n".join(html.escape(item) for item in found[:40]) + "</blockquote>",
            ]
        send_message("\n".join(lines))
        return True
    pop_pending_update_node_list(chat_id, from_id)
    start_update_job(
        "node_update",
        "list",
        from_id,
        local_required=False,
        targets=targets,
    )
    return True


def handle_pending_update_node_list(chat_id, from_id, text):
    pending = peek_pending_update_node_list(chat_id, from_id)
    if not pending:
        return False
    return handle_update_node_list_text(chat_id, from_id, text)


def handle_update_node_list(text, chat_id, from_id):
    parts = text.split(maxsplit=1)
    set_pending_update_node_list(chat_id, from_id)
    if len(parts) > 1 and parts[1].strip():
        handle_update_node_list_text(chat_id, from_id, parts[1])
        return
    send_message(
        "<b>Напишите список нод</b>\n"
        f"{ALERT_SEPARATOR}\n"
        "Каждая нода с новой строки. Апдейт стартанёт только если нашёл все названия.\n\n"
        "<blockquote>Германия\nШвейцария\nОбход #3</blockquote>\n"
        "<i>Отмена: <code>/cancel</code></i>"
    )


def handle_optimize_command(text, chat_id, from_id, action):
    parts = text.split(maxsplit=1)
    command_name = "/optimize" if action == "optimize" else "/optimize_status"
    if len(parts) < 2 or not parts[1].strip():
        send_message(f"<b>Пример:</b> <code>{command_name} Германия</code>")
        return
    query = parts[1].strip()
    node = find_node(query)
    if node is None:
        send_message(
            "<b>Не нашёл такую машину</b>\n"
            f"{ALERT_SEPARATOR}\n"
            f"{detail_line('Запрос', query)}\n"
            "Проверь название через <code>/stats</code>."
        )
        return
    node_key = node_canonical_key(node)
    node_name = node_display_name(node, node_key)
    if not node_key:
        send_message("<b>Не смог получить ключ машины.</b>")
        return
    verb = "Оптимизирую" if action == "optimize" else "Проверяю оптимизацию"
    placeholder = send_message(
        f"<b>{verb}</b>\n"
        f"{ALERT_SEPARATOR}\n"
        f"{detail_line('Машина', node_name)}\n"
        "<i>Жду ближайший push от машины.</i>"
    )
    notify = {}
    if isinstance(placeholder, dict):
        notify = {
            "chat_id": str((placeholder.get("chat") or {}).get("id") or chat_id),
            "message_id": str(placeholder.get("message_id") or ""),
        }
    queue_update_task(
        from_id,
        action,
        scope="single",
        local_required=False,
        targets={node_key: node_name},
        notify=notify,
        quiet_done=True,
    )


def handle_stats_bl(text=None):
    body, markup = bl_group_selector_payload()
    send_message(body, reply_markup=markup)


def stats_toggle_queries(text):
    parts = str(text or "").split(maxsplit=1)
    if len(parts) < 2:
        return []
    raw = parts[1]
    result = []
    for line in raw.splitlines():
        for item in re.split(r"\s*\|\s*", line):
            item = clean_display_text(item)
            if item:
                result.append(item)
    return result


def handle_stats_monitoring(text, enabled):
    queries = stats_toggle_queries(text)
    command = "/stats_on" if enabled else "/stats_off"
    if not queries:
        send_message(
            f"<b>Пример:</b> <code>{command} Германия</code>\n"
            "Можно списком, каждая машина с новой строки."
        )
        return
    changed = []
    already = []
    missing = []
    ts = now_ts()
    with LOCK:
        nodes_state = STATS_OFF_STATE.setdefault("nodes", {})
        for query in queries:
            node = find_node(query)
            if node is None:
                missing.append(query)
                continue
            node_key = node_canonical_key(node)
            node_name = node_display_name(node, node_key)
            aliases = node_alias_keys(node)
            if not node_key:
                missing.append(query)
                continue
            if enabled:
                removed = False
                for key, item in list(nodes_state.items()):
                    disabled_aliases = {canonical_node_key(key)}
                    if isinstance(item, dict):
                        disabled_aliases.update(canonical_node_key(value) for value in item.get("aliases") or [])
                        disabled_aliases.add(canonical_node_key(item.get("name")))
                    disabled_aliases.discard("")
                    if aliases.intersection(disabled_aliases):
                        nodes_state.pop(key, None)
                        removed = True
                if removed:
                    changed.append(node_name)
                else:
                    already.append(node_name)
            else:
                item = {
                    "name": node_name[:120],
                    "aliases": sorted({alias for alias in aliases if alias}, key=natural_sort_key),
                    "updated_at": ts,
                }
                if node_stats_disabled(node):
                    already.append(node_name)
                else:
                    nodes_state[node_key] = item
                    changed.append(node_name)
        if changed:
            save_stats_off_state()
    title = "Стата включена" if enabled else "Стата выключена"
    lines = [f"<b>{title}</b>", ALERT_SEPARATOR]
    if changed:
        lines += ["<b>Изменено:</b>", "<blockquote>" + "\n".join(html.escape(name) for name in changed) + "</blockquote>"]
    if already:
        lines += ["", "<b>Уже было так:</b>", "<blockquote>" + "\n".join(html.escape(name) for name in already) + "</blockquote>"]
    if missing:
        lines += ["", "<b>Не нашёл:</b>", "<blockquote>" + "\n".join(html.escape(name) for name in missing[:30]) + "</blockquote>"]
    send_message("\n".join(lines))


def set_connection_alert_notifications(queries, enabled):
    changed = []
    already = []
    missing = []
    ambiguous = []
    ts = now_ts()
    with LOCK:
        nodes_state = ALERTS_OFF_STATE.setdefault("nodes", {})
        for query in queries:
            matches = find_nodes(query)
            if not matches:
                missing.append(query)
                continue
            if len(matches) > 1:
                ambiguous.append(query)
                continue
            node = matches[0]
            node_key = node_record_key(node) or node_canonical_key(node)
            exact_key = canonical_node_key(node_key)
            node_name = node_display_name(node, node_key)
            if not node_key or not exact_key:
                missing.append(query)
                continue
            if enabled:
                removed = False
                for key, item in list(nodes_state.items()):
                    item_keys = {canonical_node_key(key)}
                    if isinstance(item, dict):
                        item_keys.add(canonical_node_key(item.get("record_key")))
                    item_keys.discard("")
                    if exact_key in item_keys:
                        nodes_state.pop(key, None)
                        removed = True
                if removed:
                    changed.append(node_name)
                else:
                    already.append(node_name)
            else:
                if node_connection_alerts_disabled(node):
                    already.append(node_name)
                    continue
                nodes_state[node_key] = {
                    "name": node_name[:120],
                    "record_key": exact_key,
                    "updated_at": ts,
                }
                changed.append(node_name)
        if changed:
            save_alerts_off_state()
    return {
        "changed": changed,
        "already": already,
        "missing": missing,
        "ambiguous": ambiguous,
    }


def handle_push_notifications(text, enabled):
    queries = stats_toggle_queries(text)
    command = "/enable_push" if enabled else "/disable_push"
    if not queries:
        send_message(f"<b>Пример:</b> <code>{command} Германия</code>")
        return
    result = set_connection_alert_notifications(queries, enabled)
    changed = result["changed"]
    already = result["already"]
    missing = result["missing"]
    ambiguous = result["ambiguous"]
    title = "Уведомления включены" if enabled else "Уведомления отключены"
    lines = [f"<b>{title}</b>", ALERT_SEPARATOR]
    if changed:
        lines += ["<b>Изменено:</b>", "<blockquote>" + "\n".join(html.escape(name) for name in changed) + "</blockquote>"]
    if already:
        lines += ["", "<b>Уже было так:</b>", "<blockquote>" + "\n".join(html.escape(name) for name in already) + "</blockquote>"]
    if missing:
        lines += ["", "<b>Не нашёл:</b>", "<blockquote>" + "\n".join(html.escape(name) for name in missing[:30]) + "</blockquote>"]
    if ambiguous:
        lines += ["", "<b>Несколько совпадений:</b>", "<blockquote>" + "\n".join(html.escape(name) for name in ambiguous[:30]) + "</blockquote>"]
    if not enabled:
        lines += ["", "<i>Push, статистика, SLA и downtime продолжают работать. Отключены только lost/restored уведомления.</i>"]
    else:
        lines += ["", "<i>Lost/restored уведомления снова будут приходить.</i>"]
    send_message("\n".join(lines))


def set_ssh_firewall_mode(queries, opened):
    changed = []
    already = []
    missing = []
    ambiguous = []
    unsupported = []
    ts = now_ts()
    with LOCK:
        nodes_state = SSH_FIREWALL_STATE.setdefault("nodes", {})
        for query in queries:
            matches = find_nodes(query)
            if not matches:
                missing.append(query)
                continue
            if len(matches) > 1:
                ambiguous.append(query)
                continue
            node = matches[0]
            node_key = node_record_key(node) or node_canonical_key(node)
            exact_key = canonical_node_key(node_key)
            node_name = node_display_name(node, node_key)
            if not node_key or not exact_key:
                missing.append(query)
                continue
            if not node_is_wl(node):
                unsupported.append(node_name)
                continue
            is_open = ssh_firewall_open_for_node(node)
            if opened:
                if is_open:
                    already.append(node_name)
                    continue
                nodes_state[node_key] = {
                    "name": node_name[:120],
                    "record_key": exact_key,
                    "open": True,
                    "updated_at": ts,
                }
                changed.append(node_name)
                continue

            removed = False
            for key, item in list(nodes_state.items()):
                item_keys = {canonical_node_key(key)}
                if isinstance(item, dict):
                    item_keys.add(canonical_node_key(item.get("record_key")))
                item_keys.discard("")
                if exact_key in item_keys:
                    nodes_state.pop(key, None)
                    removed = True
            if removed:
                changed.append(node_name)
            else:
                already.append(node_name)
        if changed:
            save_ssh_firewall_state()
    return {
        "changed": changed,
        "already": already,
        "missing": missing,
        "ambiguous": ambiguous,
        "unsupported": unsupported,
    }


def handle_ssh_firewall(text, opened):
    queries = stats_toggle_queries(text)
    command = "/ssh_firewall_off" if opened else "/ssh_firewall_on"
    if not queries:
        send_message(
            f"<b>Пример:</b> <code>{command} Обход №1</code>\n"
            "Можно списком, каждая машина с новой строки."
        )
        return

    result = set_ssh_firewall_mode(queries, opened)
    title = "SSH-фильтр отключён" if opened else "SSH-фильтр включён"
    lines = [f"<b>{title}</b>", ALERT_SEPARATOR]
    if result["changed"]:
        lines += [
            "<b>Изменено:</b>",
            "<blockquote>" + "\n".join(html.escape(name) for name in result["changed"]) + "</blockquote>",
        ]
    if result["already"]:
        lines += [
            "",
            "<b>Уже было так:</b>",
            "<blockquote>" + "\n".join(html.escape(name) for name in result["already"]) + "</blockquote>",
        ]
    if result["missing"]:
        lines += [
            "",
            "<b>Не нашёл:</b>",
            "<blockquote>" + "\n".join(html.escape(name) for name in result["missing"][:30]) + "</blockquote>",
        ]
    if result["ambiguous"]:
        lines += [
            "",
            "<b>Несколько совпадений:</b>",
            "<blockquote>" + "\n".join(html.escape(name) for name in result["ambiguous"][:30]) + "</blockquote>",
        ]
    if result["unsupported"]:
        lines += [
            "",
            "<b>Не обходы:</b>",
            "<blockquote>" + "\n".join(html.escape(name) for name in result["unsupported"][:30]) + "</blockquote>",
        ]
    if opened:
        lines += [
            "",
            "<i>При ближайшем push SSH откроется для любого IP. UFW, остальные порты и Fail2ban продолжат работать.</i>",
        ]
    else:
        lines += [
            "",
            "<i>При ближайшем push SSH снова останется только для базового списка и IP из /add_ip.</i>",
        ]
    send_message("\n".join(lines))


def connection_alerts_off_names():
    with LOCK:
        names = []
        for key, item in ALERTS_OFF_STATE.setdefault("nodes", {}).items():
            if isinstance(item, dict):
                name = clean_display_text(item.get("name") or key)
            else:
                name = clean_display_text(item or key)
            if name:
                names.append(name[:120])
    return sorted(set(names), key=natural_sort_key)


def connection_alert_state_matches(query):
    query_key = canonical_node_key(query)
    if not query_key:
        return []
    matches = []
    with LOCK:
        for key, item in ALERTS_OFF_STATE.setdefault("nodes", {}).items():
            item_keys = {canonical_node_key(key)}
            if isinstance(item, dict):
                item_keys.add(canonical_node_key(item.get("record_key")))
                item_keys.add(canonical_node_key(item.get("name")))
                name = clean_display_text(item.get("name") or key)[:120]
            else:
                item_keys.add(canonical_node_key(item))
                name = clean_display_text(item or key)[:120]
            item_keys.discard("")
            if query_key in item_keys:
                matches.append((key, name or clean_display_text(key)[:120]))
    return matches


def connection_alerts_cli(argv):
    if not argv or argv[0] not in ("--connection-alerts-list", "--connection-alerts-toggle"):
        return None
    if argv[0] == "--connection-alerts-list":
        load_alerts_off_state()
        for name in connection_alerts_off_names():
            print(name)
        return 0

    query = clean_display_text(" ".join(argv[1:]))
    if not query:
        print("error\tНазвание машины не указано")
        return 2
    load_alerts_off_state()
    muted_matches = connection_alert_state_matches(query)
    if len(muted_matches) == 1:
        key, name = muted_matches[0]
        with LOCK:
            ALERTS_OFF_STATE.setdefault("nodes", {}).pop(key, None)
            save_alerts_off_state()
        print(f"enabled\t{name}")
        return 0
    if len(muted_matches) > 1:
        names = ", ".join(name for _, name in muted_matches[:10])
        print(f"error\tНесколько отключённых машин совпали: {names}")
        return 4

    load_nodes()
    matches = find_nodes(query)
    if not matches:
        print(f"error\tМашина не найдена: {query}")
        return 3
    if len(matches) > 1:
        names = ", ".join(node_display_name(node) for node in matches[:10])
        print(f"error\tНесколько совпадений: {names}")
        return 4

    node = matches[0]
    enable = node_connection_alerts_disabled(node)
    result = set_connection_alert_notifications([query], enable)
    if result["missing"] or result["ambiguous"] or not (result["changed"] or result["already"]):
        print(f"error\tНе удалось изменить уведомления: {query}")
        return 5
    action = "enabled" if enable else "disabled"
    print(f"{action}\t{node_display_name(node)}")
    return 0


def set_pending_bl_group(chat_id, from_id, action, group_id=""):
    key = pending_key(chat_id, from_id)
    with LOCK:
        BL_GROUP_STATE.setdefault("pending", {})[key] = {
            "action": str(action or "").strip(),
            "group_id": str(group_id or "").strip(),
            "created_at": now_ts(),
        }
        save_bl_group_state()


def pop_pending_bl_group(chat_id, from_id):
    key = pending_key(chat_id, from_id)
    with LOCK:
        item = BL_GROUP_STATE.setdefault("pending", {}).pop(key, None)
        if item is not None:
            save_bl_group_state()
        return item if isinstance(item, dict) else None


def peek_pending_bl_group(chat_id, from_id):
    key = pending_key(chat_id, from_id)
    with LOCK:
        item = BL_GROUP_STATE.setdefault("pending", {}).get(key)
        if not isinstance(item, dict):
            return None
        if now_ts() - int(item.get("created_at") or 0) > 600:
            BL_GROUP_STATE.setdefault("pending", {}).pop(key, None)
            save_bl_group_state()
            return None
        return dict(item)


def bl_group_add_prompt(group):
    name = clean_display_text((group or {}).get("name") or "Группа")
    current_nodes = bl_group_nodes(group)
    lines = [
        "<b>Добавление машин в группу</b>",
        ALERT_SEPARATOR,
        detail_line("Группа", name),
        "",
    ]
    if current_nodes:
        lines += [
            "<b>Сейчас в группе:</b>",
            "<blockquote>" + "\n".join(html.escape(node_display_name(node)) for node in current_nodes) + "</blockquote>",
            "",
        ]
    lines += [
        "Напиши список машин, каждая с новой строки.",
        "Пример:",
        "<code>Латвия\nГермания</code>",
        "Отмена: <code>/cancel</code>",
    ]
    return "\n".join(lines)


def bl_group_order_prompt(group):
    name = clean_display_text((group or {}).get("name") or "Группа")
    current_nodes = bl_group_nodes(group)
    lines = [
        "<b>Редактирование вида списка</b>",
        ALERT_SEPARATOR,
        detail_line("Группа", name),
        "",
    ]
    if current_nodes:
        lines += [
            "<b>Текущий порядок:</b>",
            "<blockquote>" + "\n".join(html.escape(node_display_name(node)) for node in current_nodes) + "</blockquote>",
            "",
        ]
    lines += [
        "Ответь списком машин в нужном порядке, каждая с новой строки.",
        "Неуказанные машины останутся внизу в старом порядке.",
        "Отмена: <code>/cancel</code>",
    ]
    return "\n".join(lines)


def handle_pending_bl_group(chat_id, from_id, text):
    pending = peek_pending_bl_group(chat_id, from_id)
    if not pending:
        return False
    action = str(pending.get("action") or "")
    if action == "create":
        try:
            group = create_bl_group(text)
        except ValueError as exc:
            if "duplicate" in str(exc):
                send_message("<b>Такая группа уже есть.</b>\n\nНапиши другое название или <code>/cancel</code>.")
            else:
                send_message("<b>Не понял название группы.</b>\n\nНапример: <code>kto VPN</code>\nОтмена: <code>/cancel</code>")
            return True
        pop_pending_bl_group(chat_id, from_id)
        body = (
            "<b>Группа создана</b>\n"
            f"{ALERT_SEPARATOR}\n"
            f"{detail_line('Название', group.get('name'))}\n\n"
            "Теперь можно добавить сюда машины."
        )
        send_message(body, reply_markup=bl_group_action_markup(group.get("id")))
        return True
    if action == "add":
        group_id = str(pending.get("group_id") or "").strip()
        group = bl_group_by_id(group_id)
        if group is None:
            pop_pending_bl_group(chat_id, from_id)
            send_message("<b>Группа больше не найдена.</b>")
            return True
        raw_lines = [line.strip() for line in str(text or "").splitlines()]
        raw_lines = [line for line in raw_lines if line]
        if not raw_lines:
            send_message("<b>Список пуст.</b>\n\nНапиши названия машин строками.\nОтмена: <code>/cancel</code>")
            return True
        found = []
        missing = []
        seen = set()
        for line in raw_lines:
            node = find_bl_node_exact(line)
            if node is None:
                missing.append(line)
                continue
            node_key = node_canonical_key(node)
            if node_key in seen:
                continue
            seen.add(node_key)
            found.append(node)
        if not found:
            send_message(
                "<b>Не нашёл ни одной машины exact-match.</b>\n\n"
                "Пиши название ровно как в <code>/stats_bl</code>.\n"
                f"<blockquote>{html.escape(chr(10).join(missing[:20]))}</blockquote>\n"
                "Отмена: <code>/cancel</code>"
            )
            return True
        result = add_nodes_to_bl_group(group_id, found)
        pop_pending_bl_group(chat_id, from_id)
        group = bl_group_by_id(group_id)
        lines = [
            "<b>Группа обновлена</b>",
            ALERT_SEPARATOR,
            detail_line("Группа", (group or {}).get("name") or group_id),
        ]
        if result.get("added"):
            lines += ["", "<b>Добавлено:</b>", "<blockquote>" + "\n".join(html.escape(item) for item in result["added"]) + "</blockquote>"]
        if result.get("moved"):
            lines += ["", "<b>Перенесено из других групп:</b>", "<blockquote>" + "\n".join(html.escape(item) for item in result["moved"]) + "</blockquote>"]
        if result.get("already"):
            lines += ["", "<b>Уже были тут:</b>", "<blockquote>" + "\n".join(html.escape(item) for item in result["already"]) + "</blockquote>"]
        if missing:
            lines += ["", "<b>Не нашёл:</b>", "<blockquote>" + "\n".join(html.escape(item) for item in missing[:20]) + "</blockquote>"]
        send_message("\n".join(lines), reply_markup=bl_group_action_markup(group_id))
        return True
    if action == "order":
        group_id = str(pending.get("group_id") or "").strip()
        group = bl_group_by_id(group_id)
        if group is None:
            pop_pending_bl_group(chat_id, from_id)
            send_message("<b>Группа больше не найдена.</b>")
            return True
        raw_lines = [line.strip() for line in str(text or "").splitlines()]
        raw_lines = [line for line in raw_lines if line]
        if not raw_lines:
            send_message("<b>Список пуст.</b>\n\nНапиши названия машин строками.\nОтмена: <code>/cancel</code>")
            return True
        found = []
        missing = []
        outside = []
        seen = set()
        for line in raw_lines:
            node = find_bl_node_exact(line)
            if node is None:
                missing.append(line)
                continue
            node_key = node_canonical_key(node)
            if node_key in seen:
                continue
            seen.add(node_key)
            if not bl_node_in_group(node, group):
                outside.append(line)
                continue
            found.append(node)
        if not found:
            lines = [
                "<b>Не нашёл машин из этой группы.</b>",
                "",
                "Пиши названия ровно как в текущем списке группы.",
                "Отмена: <code>/cancel</code>",
            ]
            if missing:
                lines += ["", "<b>Не нашёл:</b>", "<blockquote>" + "\n".join(html.escape(item) for item in missing[:20]) + "</blockquote>"]
            if outside:
                lines += ["", "<b>Не в этой группе:</b>", "<blockquote>" + "\n".join(html.escape(item) for item in outside[:20]) + "</blockquote>"]
            send_message("\n".join(lines))
            return True
        result = reorder_bl_group_nodes(group_id, found)
        pop_pending_bl_group(chat_id, from_id)
        group = bl_group_by_id(group_id)
        lines = [
            "<b>Порядок списка обновлён</b>",
            ALERT_SEPARATOR,
            detail_line("Группа", (group or {}).get("name") or group_id),
        ]
        if result.get("ordered"):
            lines += ["", "<b>Новый верх списка:</b>", "<blockquote>" + "\n".join(html.escape(item) for item in result["ordered"]) + "</blockquote>"]
        if result.get("appended"):
            lines += ["", "<b>Остались внизу:</b>", "<blockquote>" + "\n".join(html.escape(item) for item in result["appended"]) + "</blockquote>"]
        if missing:
            lines += ["", "<b>Не нашёл:</b>", "<blockquote>" + "\n".join(html.escape(item) for item in missing[:20]) + "</blockquote>"]
        if outside:
            lines += ["", "<b>Не в этой группе:</b>", "<blockquote>" + "\n".join(html.escape(item) for item in outside[:20]) + "</blockquote>"]
        send_message("\n".join(lines), reply_markup=bl_group_action_markup(group_id))
        return True
    return False


def handle_bl_group_callback(callback):
    callback_id = str(callback.get("id") or "")
    data = str(callback.get("data") or "")
    from_id = str((callback.get("from") or {}).get("id") or "")
    message = callback.get("message") or {}
    chat_id = str((message.get("chat") or {}).get("id") or CHAT_ID)
    message_id = str(message.get("message_id") or "")
    if not data.startswith("blg:"):
        return False
    if chat_id != str(CHAT_ID) or from_id != ALLOWED_USER_ID:
        answer_callback(callback_id, "нет доступа")
        return True
    if data == "blg:c":
        set_pending_bl_group(chat_id, from_id, "create")
        answer_callback(callback_id, "напиши название")
        send_message(
            "<b>Новая группа обычных машин</b>\n\n"
            "Ответь названием группы.\n"
            "Пример: <code>kto VPN</code>\n"
            "Отмена: <code>/cancel</code>"
        )
        return True
    if data == "blg:l":
        answer_callback(callback_id, "список групп")
        body, markup = bl_group_selector_payload()
        if not edit_message_text(chat_id, message_id, body, reply_markup=markup):
            send_message(body, reply_markup=markup)
        return True
    if data == "blg:u":
        answer_callback(callback_id, "обновляю")
        edit_or_send_bl_group_stats(chat_id, message_id, ungrouped=True)
        return True
    parts = data.split(":", 2)
    if len(parts) != 3:
        answer_callback(callback_id)
        return True
    action, group_id = parts[1], parts[2].strip()
    group = bl_group_by_id(group_id)
    if group is None:
        answer_callback(callback_id, "группа не найдена")
        body, markup = bl_group_selector_payload()
        if not edit_message_text(chat_id, message_id, body, reply_markup=markup):
            send_message(body, reply_markup=markup)
        return True
    if action == "s":
        answer_callback(callback_id, "обновляю")
        edit_or_send_bl_group_stats(chat_id, message_id, group_id)
        return True
    if action == "a":
        set_pending_bl_group(chat_id, from_id, "add", group_id)
        answer_callback(callback_id, "жду список")
        send_message(bl_group_add_prompt(group))
        return True
    if action == "o":
        set_pending_bl_group(chat_id, from_id, "order", group_id)
        answer_callback(callback_id, "жду порядок")
        send_message(bl_group_order_prompt(group))
        return True
    answer_callback(callback_id)
    return True


def update_retry_button_text(callback, data):
    message = callback.get("message") if isinstance(callback, dict) else {}
    markup = message.get("reply_markup") if isinstance(message, dict) else {}
    rows = markup.get("inline_keyboard") if isinstance(markup, dict) else []
    if not isinstance(rows, list):
        return ""
    for row in rows:
        if not isinstance(row, list):
            continue
        for button in row:
            if not isinstance(button, dict):
                continue
            if str(button.get("callback_data") or "") == data:
                return clean_display_text(button.get("text") or "")
    return ""


def handle_update_callback(callback):
    callback_id = str(callback.get("id") or "")
    data = str(callback.get("data") or "")
    from_id = str((callback.get("from") or {}).get("id") or "")
    message = callback.get("message") or {}
    chat_id = str((message.get("chat") or {}).get("id") or CHAT_ID)
    if not data.startswith("upd:"):
        return False
    if chat_id != str(CHAT_ID) or from_id != ALLOWED_USER_ID:
        answer_callback(callback_id, "нет доступа")
        return True
    parts = data.split(":", 3)
    if len(parts) != 4 or parts[1] != "r":
        answer_callback(callback_id)
        return True
    action = parts[2].strip()
    token = parts[3].strip()
    selected_key = ""
    selected_name = ""
    with LOCK:
        current = UPDATE_STATE.get("current") if isinstance(UPDATE_STATE.get("current"), dict) else {}
        if action == str(current.get("action") or "push_update"):
            targets = current.get("targets") if isinstance(current.get("targets"), dict) else {}
            for key, name in targets.items():
                if update_retry_token(key) == token:
                    selected_key = str(key)
                    selected_name = clean_display_text(name or key)
                    break
    if not selected_key:
        retry_item = lookup_update_retry_token(action, token)
        if retry_item:
            selected_key = retry_item.get("key") or ""
            selected_name = retry_item.get("name") or selected_key
    if not selected_key:
        button_text = update_retry_button_text(callback, data)
        if button_text:
            node = find_node(button_text)
            if node is not None:
                selected_key = node_canonical_key(node)
                selected_name = node_display_name(node, selected_key)
    if not selected_key:
        answer_callback(callback_id, "retry устарел")
        return True
    answer_callback(callback_id, "запустил retry")
    start_update_job(
        action,
        "single",
        from_id,
        local_required=False,
        targets={selected_key: selected_name or selected_key},
        retry=True,
    )
    return True


def set_pending_ip_note(chat_id, from_id, value):
    ip = normalize_note_ip(value)
    with LOCK:
        IP_NOTE_STATE.setdefault("pending", {})[pending_key(chat_id, from_id)] = {
            "ip": ip,
            "created_at": now_ts(),
        }
        save_ip_note_state()
    return ip


def pop_pending_ip_note(chat_id, from_id):
    key = pending_key(chat_id, from_id)
    with LOCK:
        item = IP_NOTE_STATE.setdefault("pending", {}).pop(key, None)
        if item is not None:
            save_ip_note_state()
        return dict(item) if isinstance(item, dict) else None


def peek_pending_ip_note(chat_id, from_id):
    key = pending_key(chat_id, from_id)
    with LOCK:
        item = IP_NOTE_STATE.setdefault("pending", {}).get(key)
        if not isinstance(item, dict):
            return None
        if now_ts() - int(item.get("created_at") or 0) > IP_NOTE_PENDING_TTL:
            IP_NOTE_STATE.setdefault("pending", {}).pop(key, None)
            save_ip_note_state()
            return None
        return dict(item)


def clear_ip_note_dialog_conflicts(chat_id, from_id):
    for popper in (
        pop_pending_ip_limit,
        pop_pending_sni,
        pop_pending_rename,
        pop_pending_bl_group,
        pop_pending_update_node_list,
    ):
        try:
            popper(chat_id, from_id)
        except Exception as exc:
            log(f"pending dialog cleanup failed handler={popper.__name__}: {exc}")


def ip_note_prompt(ip):
    lines = [
        "<b>Заметка для IP</b>",
        ALERT_SEPARATOR,
        detail_line("IP", ip),
    ]
    current = ip_note_text(ip)
    if current:
        lines.append(detail_line("Сейчас", current))
    lines += [
        "",
        "Напиши заметку следующим сообщением.",
        f"Максимум: <code>{IP_NOTE_MAX_LENGTH}</code> символов.",
        "Удалить заметку: <code>-</code>",
        "Отмена: <code>/cancel</code>",
    ]
    return "\n".join(lines)


def handle_ip(text, chat_id="", from_id=""):
    parts = text.split(maxsplit=1)
    query = parts[1].strip() if len(parts) > 1 else ""
    try:
        ip = normalize_note_ip(query)
    except ValueError:
        if chat_id and from_id:
            pop_pending_ip_note(chat_id, from_id)
        send_message(ip_limit_report(query))
        return
    clear_ip_note_dialog_conflicts(chat_id, from_id)
    set_pending_ip_note(chat_id, from_id, ip)
    send_message(ip_note_prompt(ip))


def handle_pending_ip_note(chat_id, from_id, text):
    pending = peek_pending_ip_note(chat_id, from_id)
    if not pending:
        return False
    ip = str(pending.get("ip") or "")
    value = clean_display_text(text)
    if value != "-":
        if not value:
            send_message("<b>Заметка пустая.</b>\n\nНапиши текст или отправь <code>-</code> для удаления.")
            return True
        if len(value) > IP_NOTE_MAX_LENGTH:
            send_message(
                f"<b>Слишком длинная заметка.</b>\n\n"
                f"Максимум: <code>{IP_NOTE_MAX_LENGTH}</code> символов. Сейчас: <code>{len(value)}</code>."
            )
            return True

    key = pending_key(chat_id, from_id)
    with LOCK:
        current = IP_NOTE_STATE.setdefault("pending", {}).get(key)
        if not isinstance(current, dict) or str(current.get("ip") or "") != ip:
            return False
        IP_NOTE_STATE["pending"].pop(key, None)
        if value == "-":
            removed = IP_NOTE_STATE.setdefault("notes", {}).pop(ip, None) is not None
        else:
            value = normalize_ip_note_text(value)
            IP_NOTE_STATE.setdefault("notes", {})[ip] = {
                "text": value,
                "updated_at": now_ts(),
            }
            removed = False
        save_ip_note_state()

    if value == "-":
        title = "Заметка удалена" if removed else "Заметки для IP не было"
        send_message(f"<b>{title}</b>\n{ALERT_SEPARATOR}\n{detail_line('IP', ip)}")
    else:
        send_message(
            "<b>Заметка сохранена</b>\n"
            f"{ALERT_SEPARATOR}\n"
            f"<blockquote>{ip_with_note_html(ip)}</blockquote>"
        )
    return True


def handle_top_ip(text):
    parts = text.split()
    limit = 20
    if len(parts) > 1:
        value = parts[1].strip()
        if not re.fullmatch(r"\d{1,3}", value):
            send_message("<b>Пример:</b> <code>/top_ip 50</code>")
            return
        limit = int(value)
    message = send_message("Собираю информацию...")
    body = top_ip_report(limit)
    if isinstance(message, dict):
        chat_id = str((message.get("chat") or {}).get("id") or CHAT_ID)
        message_id = str(message.get("message_id") or "")
        if edit_message_text(chat_id, message_id, body):
            return
    send_message(body)


def push_debug_kind(node):
    hidden = node_stats_disabled(node)
    if node_is_wl(node):
        kind = "WL exact" if node_is_exact_bypass(node) else "WL other"
    else:
        kind = "BL"
    if hidden:
        kind = f"{kind}, hidden"
    return kind


def push_debug_message(text):
    parts = text.split(maxsplit=1)
    query = canonical_node_key(parts[1]) if len(parts) > 1 and parts[1].strip() else ""
    ts = now_ts()
    with LOCK:
        nodes = [dict(node) for node in dedupe_nodes(NODES.values())]
        clean_active = clean_all_active_unlocked()
    if query:
        nodes = [
            node for node in nodes
            if query in {canonical_node_key(node.get("name")), canonical_node_key(node.get("id")), canonical_node_key(node.get("hostname")), canonical_node_key(node.get("ip"))}
            or query in canonical_node_key(node.get("name"))
        ]
    nodes.sort(key=lambda node: int(node.get("last_seen") or 0), reverse=True)
    visible = [node for node in nodes if not node_stats_disabled(node)]
    hidden_count = len(nodes) - len(visible)
    wl_exact = [node for node in visible if node_is_wl(node) and node_is_exact_bypass(node)]
    wl_other = [node for node in visible if node_is_wl(node) and not node_is_exact_bypass(node)]
    bl_nodes = [node for node in visible if not node_is_wl(node)]
    lines = [
        "<b>Push debug</b>",
        ALERT_SEPARATOR,
        detail_line("Clean all", "ACTIVE" if clean_active else "off"),
        detail_line("Всего в collector", len(nodes)),
        detail_line("WL exact", len(wl_exact)),
        detail_line("WL other", len(wl_other)),
        detail_line("BL", len(bl_nodes)),
        detail_line("Hidden stats_off", hidden_count),
    ]
    if query:
        lines.append(detail_line("Фильтр", parts[1].strip()))
    if clean_active:
        lines += ["", "<b>Внимание:</b> <code>/clean_all stop</code> сначала, иначе новые push будут гаситься."]
    lines.append("")
    if not nodes:
        lines.append("<blockquote>Collector сейчас не видит таких push-записей.</blockquote>")
        return "\n".join(lines)
    rows = []
    for node in nodes[:40]:
        name = clean_display_text(node.get("name") or node.get("id") or node.get("hostname") or "-")
        age = format_age(ts - int(node.get("last_seen") or 0)) if int(node.get("last_seen") or 0) > 0 else "-"
        build = clean_display_text(node.get("push_build") or "-")
        ip = clean_display_text(node.get("ip") or "-")
        rows.append(f"{html.escape(name)} | {html.escape(push_debug_kind(node))} | {html.escape(age)} | {html.escape(build)} | {html.escape(ip)}")
    if len(nodes) > 40:
        rows.append(f"... ещё {len(nodes) - 40}")
    lines.append("<blockquote>" + "\n".join(rows) + "</blockquote>")
    return "\n".join(lines)


def handle_push_debug(text):
    send_message(push_debug_message(text))


def handle_ip_limit(text):
    parts = text.split(maxsplit=1)
    query = parts[1].strip() if len(parts) > 1 else ""
    body, markup = ip_limit_user_card(query)
    send_message(body, reply_markup=markup)


def handle_ip_limit_total(text):
    parts = text.split(maxsplit=1)
    value_text = parts[1].strip().lower() if len(parts) > 1 else ""
    current = ip_limit_total_limit()
    if not value_text:
        current_text = "auto: персональный → HWID → fallback" if current is None else ip_limit_limit_text(current, "total")
        send_message(
            "<b>Общий IP лимит</b>\n"
            f"{ALERT_SEPARATOR}\n"
            f"{detail_line('Сейчас', current_text)}\n\n"
            "<b>Установить:</b> <code>/limit_ip_total 5</code>\n"
            "<b>Выключить IP-алерты:</b> <code>/limit_ip_total 0</code>\n"
            "<b>Вернуть HWID-логику:</b> <code>/limit_ip_total auto</code>"
        )
        return
    if value_text in ("auto", "reset", "default"):
        with LOCK:
            ip_limit_db().execute("DELETE FROM ip_limit_meta WHERE key = 'total_limit'")
            save_ip_limit_state()
        send_message(
            "<b>Общий IP лимит сброшен</b>\n"
            f"{ALERT_SEPARATOR}\n"
            f"{detail_line('Логика', 'персональный → HWID → fallback')}\n"
            "<i>Применилось сразу, рестарт не нужен.</i>"
        )
        return
    if not re.fullmatch(r"\d{1,5}", value_text):
        send_message("<b>Нужно число от 0 до 10000.</b>\n\nПример: <code>/limit_ip_total 5</code>")
        return
    limit = int(value_text)
    if limit > 10000:
        send_message("<b>Лимит должен быть от 0 до 10000.</b>")
        return
    with LOCK:
        ip_limit_meta_set("total_limit", str(limit))
        ip_limit_db().execute("DELETE FROM ip_limit_pending")
        save_ip_limit_state()
    if limit == 0:
        send_message(
            "<b>IP-limit алерты выключены</b>\n"
            f"{ALERT_SEPARATOR}\n"
            f"{detail_line('Общий лимит', 'без лимита')}\n"
            "<i>Статистика и остальные алерты продолжают работать. Рестарт не нужен.</i>"
        )
        return
    send_message(
        "<b>Общий IP лимит установлен</b>\n"
        f"{ALERT_SEPARATOR}\n"
        f"{detail_line('Лимит', f'{limit} IP для каждого')}\n"
        f"{detail_line('Приоритет', 'выше персонального и HWID')}\n"
        f"{detail_line('Режим', 'только алерты, без ограничений')}\n"
        "<i>Применилось сразу, рестарт не нужен.</i>"
    )
    if ip_limit_remna_monitor_enabled():
        enqueue_event(remna_ip_limit_poll_once)


def handle_ip_enable(text, force=False):
    parts = text.split(maxsplit=1)
    command = "/ip_enable_force" if force else "/ip_enable"
    if len(parts) < 2 or not parts[1].strip():
        send_message(f"<b>Пример:</b> <code>{command} Обход #8</code>")
        return
    query = parts[1].strip()
    node = find_node(query)
    if node is None:
        send_message(
            "<b>Не нашёл такую машину</b>\n"
            f"{ALERT_SEPARATOR}\n"
            f"{detail_line('Запрос', query)}\n"
            "Проверь название через <code>/stats</code>."
        )
        return
    policy = set_ip_limit_node_policy(node, enabled=True, enforce=False)
    mode = "только сбор и алерты"
    remna_state = "настроен" if remna_api_enabled() else "не настроен"
    lines = [
        "<b>IP лимит включён</b>",
        ALERT_SEPARATOR,
        detail_line("Машина", policy.get("node") or query),
        detail_line("Режим", mode),
        detail_line("Remnawave API", remna_state),
        "",
        "<i>Машина применит флаг при ближайшем push.</i>",
    ]
    if force:
        lines += ["", "<i>Force-режим отключён: IP limit работает только как мониторинг.</i>"]
    send_message("\n".join(lines))


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
    if ip_limit_total_limit() is not None:
        pop_pending_ip_limit(chat_id, from_id)
        send_message("<b>Действует общий IP лимит.</b>\n\nПерсональные лимиты сейчас не применяются.")
        return True
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
    if action in ("off", "raise") and ip_limit_total_limit() is not None:
        answer_callback(callback_id, "действует общий лимит")
        body, markup = ip_limit_user_card(user_key)
        if not edit_message_text(chat_id, message_id, body, reply_markup=markup):
            send_message(body, reply_markup=markup)
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


REMOTE_MUTATION_COMMANDS = {
    "/add_ip",
    "/allow_sni",
    "/clean_all",
    "/delete_sni",
    "/haproxy",
    "/ip_enable",
    "/ip_enable_force",
    "/optimize",
    "/optimize_status",
    "/rename",
    "/ssh_firewall_off",
    "/ssh_firewall_on",
    "/update_collector_bl",
    "/update_collector_full",
    "/update_collector_wl",
    "/update_node",
    "/update_node_list",
    "/update_nodes",
}


def remote_control_status_message(title="Режим push-команд"):
    state = remote_control_snapshot()
    if state.get("paused"):
        paused_at = int(state.get("paused_at") or 0)
        paused_text = datetime.fromtimestamp(paused_at).strftime("%d.%m.%Y %H:%M:%S") if paused_at else "-"
        return "\n".join([
            f"<b>{html.escape(title)}</b>",
            ALERT_SEPARATOR,
            detail_line("Режим", "stats-only"),
            detail_line("Поставлен", paused_text),
            "",
            "<i>Статистика, SLA и алерты продолжают работать. Управляющие команды нодам не выдаются.</i>",
            "<i>Вернуть управление: <code>/push_resume</code></i>",
        ])
    return "\n".join([
        f"<b>{html.escape(title)}</b>",
        ALERT_SEPARATOR,
        detail_line("Режим", "управление включено"),
        "",
        "<i>Ноды могут получать только новые команды, созданные после последнего сброса.</i>",
    ])


def handle_push_pause(from_id):
    cleared = pause_remote_commands(from_id)
    send_message("\n".join([
        "<b>Push-команды остановлены</b>",
        ALERT_SEPARATOR,
        detail_line("Режим", "stats-only"),
        detail_line("Очищено записей", cleared.get("total", 0)),
        detail_line("HAProxy", cleared.get("haproxy", 0)),
        detail_line("SNI", cleared.get("sni", 0)),
        detail_line("Update", cleared.get("updates", 0)),
        detail_line("Диалоги", cleared.get("dialogs", 0) + cleared.get("ip_limit_dialogs", 0)),
        "",
        "<i>Push продолжает передавать статистику, но collector не возвращает нодам управляющие поля.</i>",
        "<i>Уже запущенный на ноде процесс остановить задним числом нельзя. Старая очередь после resume не восстановится.</i>",
        "<i>Вернуть управление: <code>/push_resume</code></i>",
    ]))


def handle_push_resume(from_id):
    was_paused = resume_remote_commands(from_id)
    title = "Push-команды включены" if was_paused else "Push-команды уже включены"
    send_message("\n".join([
        f"<b>{title}</b>",
        ALERT_SEPARATOR,
        detail_line("Режим", "управление включено"),
        "",
        "<i>Очищенная очередь не восстановлена. Ноды получат только команды, созданные после включения.</i>",
    ]))


def handle_paused_remote_callback(callback):
    if not remote_commands_paused():
        return False
    data = str(callback.get("data") or "")
    if not data.startswith(("hpx:", "upd:")):
        return False
    callback_id = str(callback.get("id") or "")
    from_id = str((callback.get("from") or {}).get("id") or "")
    message = callback.get("message") or {}
    chat_id = str((message.get("chat") or {}).get("id") or CHAT_ID)
    if chat_id != str(CHAT_ID) or from_id != ALLOWED_USER_ID:
        answer_callback(callback_id, "нет доступа")
    else:
        answer_callback(callback_id, "push-команды на паузе")
    return True


def remote_mutation_blocked_message(command):
    return "\n".join([
        "<b>Push-команды на паузе</b>",
        ALERT_SEPARATOR,
        detail_line("Команда", command or "-"),
        "",
        "<i>Статистика продолжает работать. Сначала включи управление: <code>/push_resume</code></i>",
    ])


BOT_HELP_SECTIONS = (
    ("Статистика", (
        ("/help", "Показать все актуальные команды."),
        ("/stats", "Показать полную статистику всех машин."),
        ("/stats_wl", "Показать таблицу обходов с трафиком по IP."),
        ("/stats_wl_table", "Принудительно отправить rich-таблицу обходов."),
        ("/stats_wl_full", "Показать расширенную статистику обходов с ресурсами."),
        ("/stats_bl", "Открыть статистику обычных машин по группам."),
        ("/stats_off <машина|список>", "Исключить машины из статистики, SLA и downtime."),
        ("/stats_on <машина|список>", "Вернуть машины в статистику, SLA и downtime."),
        ("/statsrevoke <время|full>", "Скорректировать или сбросить downtime за сегодня."),
        ("/push_debug [машина]", "Показать push-записи, которые видит collector."),
    )),
    ("Машины и уведомления", (
        ("/disable_push <машина|список>", "Отключить только lost/restored уведомления."),
        ("/enable_push <машина|список>", "Включить lost/restored уведомления обратно."),
        ("/ssh_firewall_off <машина|список>", "Открыть SSH обхода для любого IP."),
        ("/ssh_firewall_on <машина|список>", "Вернуть SSH whitelist на обходе."),
        ("/delete <машина>", "Удалить машину и её падения из collector."),
        ("/rename <машина>", "Переименовать машину через ответное сообщение."),
        ("/add_ip <IPv4>", "Добавить IP в SSH whitelist обходов."),
        ("/haproxy [машина]", "Выбрать машину кнопкой и управлять маршрутами HAProxy."),
        ("/allow_sni <машина>", "Добавить SNI в allow-list машины."),
        ("/delete_sni <машина>", "Удалить SNI из allow-list машины."),
    )),
    ("Обновление и оптимизация", (
        ("/push_pause", "Очистить старую очередь и оставить push только для статистики."),
        ("/push_resume", "Разрешить новые управляющие команды нодам."),
        ("/push_status", "Показать текущий режим push-команд."),
        ("/update_collector", "Обновить только collector на панели."),
        ("/update_collector_full", "Обновить collector и push на всех машинах."),
        ("/update_collector_wl", "Обновить collector и push только на обходах."),
        ("/update_collector_bl", "Обновить collector и push только на обычных машинах."),
        ("/update_node <машина>", "Обновить Remnawave-контейнеры одной ноды."),
        ("/update_node_list", "Обновить Remnawave на указанном списке нод."),
        ("/update_nodes", "Обновить Remnawave-контейнеры всех нод."),
        ("/update_node_status", "Показать ход последнего обновления нод."),
        ("/optimize <машина>", "Проверить и применить недостающую оптимизацию."),
        ("/optimize_status <машина>", "Только проверить оптимизацию без изменений."),
        ("/clean_all [status|stop]", "Очистить collector и удалить push со всех машин."),
    )),
    ("IP limit", (
        ("/ip <машина|IP>", "Показать IP-limit по машине или записать заметку для IP."),
        ("/top_ip [N]", "Показать топ пользователей по активным IP."),
        ("/ip_limit <Remna/TG ID>", "Открыть пользователя и его персональный IP лимит."),
        ("/limit_ip <Remna/TG ID>", "Алиас команды /ip_limit."),
        ("/limit_ip_total <N|0|auto>", "Задать общий лимит алертов для всех пользователей."),
        ("/ip_enable <машина>", "Включить сбор IP и алерты на машине."),
        ("/ip_enable_force <машина>", "То же, что /ip_enable; блокировки отключены."),
    )),
    ("Проверка и диалоги", (
        ("/down <машина>", "Отправить тестовый lost-алерт."),
        ("/up <машина>", "Отправить тестовый restored-алерт."),
        ("/emoji <premium emoji>", "Получить ID premium emoji и готовый тег."),
        ("/statstest", "Проверить связь collector с Telegram."),
        ("/cancel", "Отменить текущий диалог с ботом."),
    )),
)


def bot_help_command_names():
    return {
        syntax.split(maxsplit=1)[0]
        for _section, commands in BOT_HELP_SECTIONS
        for syntax, _description in commands
    }


def bot_help_message():
    lines = ["<b>Команды бота</b>", ALERT_SEPARATOR]
    for section, commands in BOT_HELP_SECTIONS:
        lines += ["", f"<b>{html.escape(section)}</b>"]
        for syntax, description in commands:
            lines.append(f"<code>{html.escape(syntax)}</code> — {html.escape(description)}")
    return "\n".join(lines)


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
                    if handle_paused_remote_callback(callback):
                        continue
                    if handle_haproxy_callback(callback):
                        continue
                    if handle_update_callback(callback):
                        continue
                    if handle_bl_group_callback(callback):
                        continue
                    handle_ip_limit_callback(callback)
                    continue
                message = item.get("message") or {}
                chat_id = str((message.get("chat") or {}).get("id", ""))
                from_id = str((message.get("from") or {}).get("id", ""))
                text = str(message.get("text") or "")
                command = text.split()[0].split("@", 1)[0].lower() if text.split() else ""
                if chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/cancel":
                    pop_pending_ip_note(chat_id, from_id)
                    pop_pending_ip_limit(chat_id, from_id)
                    pop_pending_haproxy(chat_id, from_id)
                    pop_pending_sni(chat_id, from_id)
                    pop_pending_rename(chat_id, from_id)
                    pop_pending_bl_group(chat_id, from_id)
                    pop_pending_update_node_list(chat_id, from_id)
                    send_message("<b>Отменил.</b>")
                    continue
                if chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/push_pause":
                    handle_push_pause(from_id)
                    continue
                if chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/push_resume":
                    handle_push_resume(from_id)
                    continue
                if chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/push_status":
                    send_message(remote_control_status_message())
                    continue
                if (
                    chat_id == str(CHAT_ID)
                    and from_id == ALLOWED_USER_ID
                    and remote_commands_paused()
                    and command in REMOTE_MUTATION_COMMANDS
                ):
                    send_message(remote_mutation_blocked_message(command))
                    continue
                if (
                    chat_id == str(CHAT_ID)
                    and from_id == ALLOWED_USER_ID
                    and command.startswith("/")
                    and command not in ("/cancel", "/ip")
                ):
                    pop_pending_ip_note(chat_id, from_id)
                if chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and not command.startswith("/"):
                    if handle_pending_ip_note(chat_id, from_id, text):
                        continue
                    if handle_pending_haproxy(chat_id, from_id, text):
                        continue
                    if handle_pending_update_node_list(chat_id, from_id, text):
                        continue
                    if handle_pending_bl_group(chat_id, from_id, text):
                        continue
                    if handle_pending_rename(chat_id, from_id, text):
                        continue
                    if handle_pending_sni(chat_id, from_id, text):
                        continue
                    if handle_pending_ip_limit(chat_id, from_id, text):
                        continue
                if chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/help":
                    send_message(bot_help_message())
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/stats":
                    send_message(aggregate_message())
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/stats_wl":
                    send_stats_wl()
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/stats_wl_table":
                    send_stats_wl(use_rich=True)
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/stats_wl_full":
                    send_message(aggregate_message("wl_full"))
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/stats_bl":
                    handle_stats_bl(text)
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/stats_off":
                    handle_stats_monitoring(text, enabled=False)
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/stats_on":
                    handle_stats_monitoring(text, enabled=True)
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/disable_push":
                    handle_push_notifications(text, enabled=False)
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/enable_push":
                    handle_push_notifications(text, enabled=True)
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/ssh_firewall_off":
                    handle_ssh_firewall(text, opened=True)
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/ssh_firewall_on":
                    handle_ssh_firewall(text, opened=False)
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/statsrevoke":
                    handle_statsrevoke(text)
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/delete":
                    handle_delete(text)
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/rename":
                    handle_rename_command(text, chat_id, from_id)
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/add_ip":
                    handle_add_ip(text)
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/update_collector":
                    handle_update_collector(text, chat_id, from_id)
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/update_collector_full":
                    handle_update_collector(text, chat_id, from_id, scope="all")
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/update_collector_wl":
                    handle_update_collector(text, chat_id, from_id, scope="wl")
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/update_collector_bl":
                    handle_update_collector(text, chat_id, from_id, scope="bl")
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/update_node":
                    handle_update_node(text, chat_id, from_id)
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/update_node_list":
                    handle_update_node_list(text, chat_id, from_id)
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/update_node_status":
                    handle_update_node_status(text, chat_id, from_id)
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/update_nodes":
                    handle_update_nodes(text, chat_id, from_id)
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/clean_all":
                    handle_clean_all(text, chat_id, from_id)
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/optimize":
                    handle_optimize_command(text, chat_id, from_id, "optimize")
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/optimize_status":
                    handle_optimize_command(text, chat_id, from_id, "optimize_status")
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/haproxy":
                    handle_haproxy_command(text, chat_id, from_id)
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/allow_sni":
                    handle_sni_command(text, "allow_sni", chat_id, from_id)
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/delete_sni":
                    handle_sni_command(text, "delete_sni", chat_id, from_id)
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/ip":
                    handle_ip(text, chat_id, from_id)
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/top_ip":
                    handle_top_ip(text)
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/push_debug":
                    handle_push_debug(text)
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command in ("/ip_limit", "/limit_ip"):
                    handle_ip_limit(text)
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/limit_ip_total":
                    handle_ip_limit_total(text)
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/ip_enable":
                    handle_ip_enable(text, force=False)
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/ip_enable_force":
                    handle_ip_enable(text, force=True)
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
    network_rate_history_reset = init_network_rate_db()
    load_nodes()
    if network_rate_history_reset:
        cleared = clear_loaded_network_rate_fields()
        if cleared:
            save_nodes()
        log(f"network rate history reset schema={NETWORK_RATE_SCHEMA_VERSION} fields={cleared}")
    load_falls()
    load_ssh_allowed_ips()
    load_ssh_firewall_state()
    load_sni_state()
    load_haproxy_state()
    load_node_name_state()
    repair_loaded_node_names()
    load_bl_group_state()
    load_stats_off_state()
    load_alerts_off_state()
    load_remna_node_state()
    load_update_state()
    load_remote_control_state()
    load_ip_note_state()
    load_ip_limit_state()
    if remote_commands_paused():
        with LOCK:
            discarded = discard_remote_command_queues_unlocked()
        log(f"remote commands paused, discarded={discarded.get('total', 0)}")
    disable_ip_limit_actions_runtime()
    threading.Thread(target=event_worker_loop, daemon=True).start()
    threading.Thread(target=nodes_flush_loop, daemon=True).start()
    threading.Thread(target=offline_loop, daemon=True).start()
    threading.Thread(target=ip_limit_penalty_loop, daemon=True).start()
    threading.Thread(target=remna_node_loop, daemon=True).start()
    threading.Thread(target=remna_ip_limit_loop, daemon=True).start()
    threading.Thread(target=bot_loop, daemon=True).start()
    if DAILY_REPORT_TIME:
        threading.Thread(target=daily_report_loop, daemon=True).start()
    server = CollectorHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    log(f"listening http://{LISTEN_HOST}:{LISTEN_PORT}")
    server.serve_forever()


if __name__ == "__main__":
    cli_status = connection_alerts_cli(sys.argv[1:])
    if cli_status is None:
        main()
    else:
        raise SystemExit(cli_status)
