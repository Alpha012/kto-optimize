#!/usr/bin/env python3
import html
import json
import os
import re
import socket
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

COLLECTOR_BUILD = "v155"
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

NODES_FILE = os.path.join(STATE_DIR, "nodes.json")
FALLS_FILE = os.path.join(STATE_DIR, "falls.json")
OFFSET_FILE = os.path.join(STATE_DIR, "telegram_offset")
DAILY_FILE = os.path.join(STATE_DIR, "daily_report_date")
SSH_ALLOW_FILE = os.path.join(STATE_DIR, "ssh_allow_ips.json")
LOCK = threading.RLock()
NODES = {}
FALLS = {}
SSH_ALLOWED_IPS = []
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


def fmt_time(ts):
    try:
        return datetime.fromtimestamp(int(ts)).strftime("%d.%m.%Y %H:%M")
    except Exception:
        return "-"


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


def send_message(text):
    if not CHAT_ID:
        log("telegram chat id is empty")
        return False
    try:
        result = tg_call("sendMessage", {
            "chat_id": CHAT_ID,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": "true",
        })
        msg = result.get("result", {})
        log(f"telegram sent message_id={msg.get('message_id')} chat_id={msg.get('chat', {}).get('id')}")
        return True
    except Exception as exc:
        log(f"telegram send failed: {exc}")
        return False


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
    value = str(value or "-").replace("№", "#")
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
            params = {"timeout": 25, "limit": 20, "allowed_updates": json.dumps(["message"])}
            if offset is not None:
                params["offset"] = offset
            updates = tg_call("getUpdates", params, timeout=35).get("result") or []
            for item in updates:
                update_id = int(item.get("update_id", 0))
                offset = update_id + 1
                save_offset(offset)
                message = item.get("message") or {}
                chat_id = str((message.get("chat") or {}).get("id", ""))
                from_id = str((message.get("from") or {}).get("id", ""))
                text = str(message.get("text") or "")
                command = text.split()[0].split("@", 1)[0].lower() if text.split() else ""
                if chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/stats":
                    send_message(aggregate_message())
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/statsrevoke":
                    handle_statsrevoke(text)
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/delete":
                    handle_delete(text)
                elif chat_id == str(CHAT_ID) and from_id == ALLOWED_USER_ID and command == "/add_ip":
                    handle_add_ip(text)
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
    threading.Thread(target=offline_loop, daemon=True).start()
    threading.Thread(target=bot_loop, daemon=True).start()
    if DAILY_REPORT_TIME:
        threading.Thread(target=daily_report_loop, daemon=True).start()
    server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    log(f"listening http://{LISTEN_HOST}:{LISTEN_PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
