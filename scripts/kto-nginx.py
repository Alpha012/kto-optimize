#!/usr/bin/env python3
"""Interactive, scoped Nginx WS/TLS provisioning for Debian and Ubuntu."""

from __future__ import annotations

import argparse
import base64
import configparser
import contextlib
import dataclasses
import datetime as dt
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import uuid


MANAGED = "# Managed by kto-nginx. Use the Nginx menu to edit."
NGINX = Path("/etc/nginx/nginx.conf")
DEFAULT_SITE = Path("/etc/nginx/sites-available/default")
CONF = Path("/etc/nginx/conf.d")
STATE = Path("/etc/kto-nginx")
BACKUPS = Path("/var/backups/kto-nginx")
WEBROOT = Path("/var/www/kto-nginx-acme")
LOGS = Path("/var/log/nginx/kto")
LOG = Path("/var/log/kto-nginx.log")
ROTATE = Path("/etc/logrotate.d/kto-nginx")
UNIT = Path("/etc/systemd/system/kto-nginx-logrotate.service")
TIMER = Path("/etc/systemd/system/kto-nginx-logrotate.timer")
HOOK = Path("/etc/letsencrypt/renewal-hooks/deploy/50-kto-nginx")
LE = Path("/etc/letsencrypt")
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
CA_PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory"
CA_STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory"


class SetupError(RuntimeError):
    pass


def say(message: str, kind: str = "..") -> None:
    colors = {"OK": "32", "!": "33", "STOP": "31", "..": "36"}
    label = f"[{kind}]"
    if sys.stdout.isatty():
        label = f"\033[{colors.get(kind, '36')}m{label}\033[0m"
    print(f"{label} {message}", flush=True)


def ask(label: str, default: str = "") -> str:
    value = input(f"{label}{f' [{default}]' if default else ''}: ").strip()
    return value or default


def confirm(label: str, default: bool = False) -> bool:
    value = ask(label, "Y/n" if default else "y/N").lower()
    return value in ("y", "yes", "д", "да") or (default and value == "y/n")


def domain_name(value: str) -> str:
    try:
        value = value.strip().rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise SetupError("Некорректный домен") from exc
    if len(value) > 253 or not re.fullmatch(
        r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?", value
    ):
        raise SetupError("Нужен домен без https://, пути, порта и wildcard")
    return value


def ipv4(value: str) -> str:
    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError as exc:
        raise SetupError(f"Некорректный IPv4: {value}") from exc


def port_number(value: str | int) -> int:
    if not re.fullmatch(r"[0-9]{1,5}", str(value)) or not 1 <= int(value) <= 65535:
        raise SetupError("Порт должен быть от 1 до 65535")
    return int(value)


def ws_path(value: str) -> str:
    if not re.fullmatch(r"/[A-Za-z0-9_./~%-]*", value) or len(value) > 512:
        raise SetupError("WS-путь должен начинаться с /, без пробелов, query и спецсимволов Nginx")
    if "//" in value or any(part in (".", "..") for part in value.split("/")) or "%" in value:
        raise SetupError("Укажи обычный WS-путь без двойных /, .. и percent-encoding")
    if value.startswith("/.well-known/"):
        raise SetupError("/.well-known/ зарезервирован для сертификатов")
    return value


def cert_path(value: str) -> str:
    if not re.fullmatch(r"/[A-Za-z0-9_./-]+", value) or ".." in Path(value).parts:
        raise SetupError("Нужен абсолютный путь к PEM без пробелов и спецсимволов")
    return value


@dataclasses.dataclass
class Site:
    domain: str
    ips: list[str]
    backend: str
    backend_port: int = 9080
    source: str = "auto"
    path: str = "/de3ws"
    port: int = 443
    tls_mode: str = "http"
    email: str = ""
    cert: str = ""
    key: str = ""
    http_listens: list[str] = dataclasses.field(default_factory=list)
    tls_listens: list[str] = dataclasses.field(default_factory=list)
    status: str = "draft"
    webroot: str = dataclasses.field(default_factory=lambda: WEBROOT.as_posix())
    health_token: str = ""

    def validate(self) -> Site:
        self.domain = domain_name(self.domain)
        self.ips = list(dict.fromkeys(ipv4(x) for x in self.ips))
        if not self.ips or len(self.ips) > 16:
            raise SetupError("Выбери от 1 до 16 входных IPv4")
        self.backend = ipv4(self.backend)
        self.backend_port = port_number(self.backend_port)
        self.port = port_number(self.port)
        if self.port == 80:
            raise SetupError("Входной TLS-порт не может совпадать с HTTP :80")
        if self.source != "auto":
            self.source = ipv4(self.source)
        self.path = ws_path(self.path)
        if self.tls_mode not in ("http", "dns", "existing"):
            raise SetupError("Неизвестный способ получения сертификата")
        if self.email and not re.fullmatch(r"[A-Za-z0-9_.+%-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", self.email):
            raise SetupError("Некорректный email")
        if self.cert:
            self.cert = cert_path(self.cert)
        if self.key:
            self.key = cert_path(self.key)
        self.webroot = cert_path(self.webroot)
        if self.health_token and not re.fullmatch(r"[a-f0-9]{32}", self.health_token):
            raise SetupError("Некорректный маркер проверки config")
        for values, expected_port, allowed_options in ((self.http_listens, 80, []),
                                                       (self.tls_listens, self.port, ["http2"])):
            if not isinstance(values, list):
                raise SetupError("Некорректный список listen в сохранённом маршруте")
            for value in values:
                parts = value.split()
                address = listen_address(parts[0]) if parts else None
                if (not address or address[0] not in ["0.0.0.0", *self.ips] or address[1] != expected_port
                        or any(option not in allowed_options for option in parts[1:])):
                    raise SetupError("Некорректный listen в сохранённом маршруте")
        return self

    @property
    def config(self) -> Path:
        return CONF / f"kto-wss-{self.domain}.conf"

    @property
    def state(self) -> Path:
        return STATE / "sites" / f"{self.domain}.json"

    @property
    def draft(self) -> Path:
        return STATE / "drafts" / f"{self.domain}.json"

    @property
    def cert_name(self) -> str:
        return f"kto-{self.domain}"


def atomic_write(path: Path, text: str | bytes, mode: int = 0o644) -> None:
    if path.is_symlink():
        raise SetupError(f"Не перезаписываю symlink: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    previous = path.stat() if path.exists() else None
    fd, name = tempfile.mkstemp(prefix=".kto-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(text.encode("utf-8") if isinstance(text, str) else text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(name, mode)
        if previous and hasattr(os, "chown"):
            os.chown(name, previous.st_uid, previous.st_gid)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


class Transaction:
    """Keep original bytes and modes; never copy certificate private keys."""

    def __init__(self, root: Path | None = None):
        root = root or BACKUPS
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(root, 0o700)
        self.folder = Path(tempfile.mkdtemp(prefix=dt.datetime.now().strftime("%Y%m%d-%H%M%S-"), dir=root))
        self.originals: dict[Path, tuple[bytes, int] | None] = {}
        say(f"Backup: {self.folder}")

    def remember(self, path: Path) -> None:
        if path in self.originals:
            return
        if path.is_symlink():
            raise SetupError(f"Не меняю symlink автоматически: {path}")
        self.originals[path] = (path.read_bytes(), path.stat().st_mode & 0o777) if path.exists() else None
        old = self.originals[path]
        if old:
            atomic_write(self.folder / f"{len(self.originals)}.bak", old[0], 0o600)
        manifest = [{"path": str(p), "backup": f"{i}.bak" if item else None,
                     "mode": item[1] if item else None}
                    for i, (p, item) in enumerate(self.originals.items(), 1)]
        atomic_write(self.folder / "manifest.json", json.dumps(manifest, indent=2), 0o600)

    def write(self, path: Path, text: str, mode: int | None = None) -> None:
        self.remember(path)
        previous = self.originals[path]
        atomic_write(path, text, mode if mode is not None else (previous[1] if previous else 0o644))

    def remove(self, path: Path) -> None:
        self.remember(path)
        path.unlink(missing_ok=True)

    def restore(self) -> None:
        for path, old in reversed(list(self.originals.items())):
            if old is None:
                path.unlink(missing_ok=True)
            else:
                atomic_write(path, old[0], old[1])


def nginx_directives(text: str):
    lexer = shlex.shlex(text, posix=True, punctuation_chars=";{}")
    lexer.whitespace_split = True
    lexer.commenters = "#"
    context: list[str] = []
    words: list[str] = []
    for token in lexer:
        tokens = list(token) if token and set(token) <= set(";{}") else [token]
        for part in tokens:
            if part == "{":
                context.append(words[0] if words else "?")
                words = []
            elif part == "}":
                if context:
                    context.pop()
                words = []
            elif part == ";":
                if words:
                    yield tuple(context), words[0], words[1:]
                words = []
            else:
                words.append(part)


def tune_capacity(text: str) -> str:
    directives = list(nginx_directives(text))
    connections = next((int(args[0]) for ctx, key, args in directives
                        if key == "worker_connections" and len(args) == 1 and args[0].isdigit()), 8192)
    nofile = max(65536, connections + 1024)
    for name, context, minimum in (("worker_connections", ("events",), 8192),
                                   ("worker_rlimit_nofile", (), nofile)):
        found = [(ctx, args) for ctx, key, args in directives if key == name]
        if not found and name == "worker_rlimit_nofile":
            text += f"\nworker_rlimit_nofile {nofile};\n"
            continue
        if len(found) != 1 or found[0][0] != context or len(found[0][1]) != 1 or not found[0][1][0].isdigit():
            raise SetupError(f"Необычная структура {name}: настрой её вручную, существующий config сохранён")
        pattern = rf"(?m)^(\s*{name}\s+)(\d+)(\s*;)"
        if len(re.findall(pattern, text)) != 1:
            raise SetupError(f"{name} должен быть отдельной строкой в nginx.conf")
        text = re.sub(pattern, lambda m: f"{m[1]}{max(int(m[2]), minimum)}{m[3]}", text)
    return text


def config_sections(dump: str) -> dict[str, str]:
    sections: dict[str, str] = {}
    current = ""
    for line in dump.splitlines():
        match = re.fullmatch(r"# configuration file (.+):", line)
        if match:
            current = match[1]
            sections[current] = ""
        elif current:
            sections[current] += line + "\n"
    return sections


def listen_address(value: str) -> tuple[str, int] | None:
    if value.isdigit():
        return "0.0.0.0", int(value)
    match = re.fullmatch(r"(\d+\.\d+\.\d+\.\d+|\*):(\d+)", value)
    if match:
        return ("0.0.0.0" if match[1] == "*" else match[1]), int(match[2])
    return None


def choose_listens(site: Site, dump: str, sockets: str) -> tuple[list[str], list[str]]:
    declared: dict[int, list[tuple[str, tuple[str, ...]]]] = {}
    for filename, text in config_sections(dump).items():
        for context, name, args in nginx_directives(text):
            if name == "server_name" and site.domain in [x.lower() for x in args] and filename != str(site.config):
                raise SetupError(f"Домен уже настроен в {filename}. Чужой vhost не перезаписываю; нужен перенос вручную")
            if name == "listen" and args and (parsed := listen_address(args[0])):
                if context[:1] != ("http",) and filename == str(NGINX):
                    continue
                declared.setdefault(parsed[1], []).append((parsed[0], tuple(args[1:])))
    result = []
    for port in (80, site.port):
        wildcard = False
        skip_http = False
        for line in sockets.splitlines():
            fields = line.split()
            if len(fields) < 4:
                continue
            endpoint = fields[3]
            parsed = listen_address(endpoint)
            if endpoint in (f"[::]:{port}", f"*:{port}") and '"nginx"' not in line:
                if port == 80 and site.tls_mode != "http":
                    skip_http = True
                    continue
                raise SetupError(f"Порт {port} занят другим процессом: {line.strip()}")
            if not parsed or parsed[1] != port or parsed[0] not in ["0.0.0.0", *site.ips]:
                continue
            if '"nginx"' not in line:
                if port == 80 and site.tls_mode != "http":
                    skip_http = True
                    continue
                raise SetupError(f"Конфликт порта {endpoint}: {line.strip()}. HAProxy/SSH не останавливаю")
            if parsed[0] == "0.0.0.0":
                wildcard = True
                if not any(ip == "0.0.0.0" for ip, _ in declared.get(port, [])):
                    raise SetupError(f"Runtime Nginx слушает *:{port}, но такого listen нет в config. Сначала исправь расхождение")
        if skip_http:
            result.append([])
            continue
        wildcard = wildcard or any(ip == "0.0.0.0" for ip, _ in declared.get(port, []))
        chosen = ["0.0.0.0"] if wildcard else site.ips
        for ip, options in declared.get(port, []):
            if ip not in chosen:
                continue
            if "proxy_protocol" in options:
                raise SetupError(f"Nginx {ip}:{port} ожидает PROXY protocol; этот мастер его не использует")
            if port == 80 and "ssl" in options:
                raise SetupError("Существующий :80 использует TLS, автоматическая замена запрещена")
            if port == site.port and "ssl" not in options:
                raise SetupError(f"Существующий Nginx :{port} не TLS; выбери свободный входной порт")
        result.append([(str(port) if ip == "0.0.0.0" else f"{ip}:{port}") +
                       (" http2" if port == site.port and any(address == ip and "http2" in opts
                                                              for address, opts in declared.get(port, [])) else "")
                       for ip in chosen])
    return result[0], result[1]


def render_site(site: Site, tls: bool) -> str:
    site.validate()
    allowed = "|".join(re.escape(ip) for ip in site.ips)
    guard = f'    if ($server_addr !~ "^({allowed})$") {{ return 444; }}\n'
    http = "\n".join(f"    listen {ip};" for ip in site.http_listens)
    location = f"    location ^~ /.well-known/acme-challenge/ {{ root {site.webroot}; }}\n"
    redirect_port = "" if site.port == 443 else f":{site.port}"
    http_body = (f"    location / {{ return 301 https://{site.domain}{redirect_port}$request_uri; }}\n"
                 if tls else '    location / { default_type text/plain; return 200 "TLS setup pending\\n"; }\n')
    text = f"{MANAGED}\n"
    if site.http_listens:
        text += (f"server {{\n{http}\n    server_name {site.domain};\n"
                 f"    access_log {LOGS}/{site.domain}.access.log combined buffer=32k flush=5s;\n"
                 f"    error_log {LOGS}/{site.domain}.error.log warn;\n{guard}{location}{http_body}}}\n")
    if not tls:
        return text
    if not site.cert or not site.key or site.source == "auto" or not site.health_token or not site.tls_listens:
        raise SetupError("TLS config нельзя создавать без сертификата, ключа и выбранного source IP")
    listens = "\n".join(f"    listen {ip} ssl;" for ip in site.tls_listens)
    # Local root probes verify that the new generation, rather than an old worker, is serving.
    text += f"""server {{
{listens}
    server_name {site.domain};
{guard}    ssl_certificate {site.cert};
    ssl_certificate_key {site.key};
    ssl_protocols TLSv1.2 TLSv1.3;
    access_log {LOGS}/{site.domain}.access.log combined buffer=32k flush=5s;
    error_log {LOGS}/{site.domain}.error.log warn;
    location = {site.path} {{
        if ($http_upgrade !~* "^websocket$") {{ return 404; }}
        proxy_pass http://{site.backend}:{site.backend_port};
        proxy_bind {site.source};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_buffering off;
        proxy_connect_timeout 5s;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }}
    location / {{ default_type text/plain; return 200 "KTO {site.domain} {site.health_token} OK\\n"; }}
}}
"""
    return text


def probe_http(ip: str, port: int, host: str, path: str = "/", *, tls: bool = False,
               websocket: bool = False, source: str | None = None, timeout: float = 7) -> tuple[int, str]:
    with socket.create_connection((ip, port), timeout, (source, 0) if source else None) as raw:
        conn = ssl.create_default_context().wrap_socket(raw, server_hostname=host) if tls else raw
        with contextlib.closing(conn):
            key = base64.b64encode(os.urandom(16)).decode()
            headers = [f"GET {path} HTTP/1.1", f"Host: {host}", "User-Agent: kto-nginx-check"]
            if websocket:
                headers += ["Connection: Upgrade", "Upgrade: websocket", "Sec-WebSocket-Version: 13",
                            f"Sec-WebSocket-Key: {key}"]
            else:
                headers += ["Connection: close"]
            conn.sendall(("\r\n".join(headers) + "\r\n\r\n").encode("ascii"))
            response = http.client.HTTPResponse(conn)
            response.begin()
            try:
                if websocket and response.status == 101:
                    accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
                    if (response.getheader("Sec-WebSocket-Accept") != accept or
                            response.getheader("Upgrade", "").lower() != "websocket" or
                            "upgrade" not in [part.strip().lower() for part in response.getheader("Connection", "").split(",")]):
                        raise SetupError("Ответ 101 получен, но WebSocket handshake некорректен")
                    return 101, "WebSocket handshake OK (VLESS UUID этим тестом не проверяется)"
                if websocket:
                    return response.status, response.reason
                return response.status, response.read(1024).decode("utf-8", "replace")
            finally:
                response.close()


def certificate_error(text: str) -> str:
    value = text.lower()
    if "too many" in value or "rate limit" in value or "rate-limit" in value:
        return "Лимит CA: не повторяй выпуск сейчас; смотри retry-after в выводе Certbot"
    if "nxdomain" in value:
        return "DNS-запись не найдена. Проверь A/AAAA или TXT и дождись распространения"
    if "404" in value or "unauthorized" in value:
        return "CA не получила правильный challenge: проверь DNS, CDN и vhost на всех A/AAAA"
    if "timeout" in value or "connection" in value or "validation data" in value:
        return "Недоступна CA или HTTP :80 снаружи. Проверь firewall провайдера/маршрут; альтернатива: DNS-01"
    return "Certbot не завершил выпуск. Полная причина в /var/log/letsencrypt/letsencrypt.log"


class Manager:
    def __init__(self):
        self.step = 0
        self.last_output = ""
        self.fresh_default = False
        self.log_failed = False

    def log(self, text: str) -> None:
        try:
            if LOG.exists() and LOG.stat().st_size > 8 * 1024 * 1024:
                os.replace(LOG, LOG.with_suffix(".log.1"))
            with LOG.open("a", encoding="utf-8") as handle:
                os.chmod(LOG, 0o600)
                handle.write(f"{dt.datetime.now().isoformat(timespec='seconds')} {text}\n")
        except OSError as exc:
            if not self.log_failed:
                say(f"Не могу записать лог {LOG}: {exc}", "!")
                self.log_failed = True

    def stage(self, text: str) -> None:
        self.step += 1
        say(f"{self.step}/8  {text}")
        self.log(text)

    def run(self, args: list[str], timeout: int = 30, *, check: bool = True,
            interactive: bool = False) -> subprocess.CompletedProcess:
        self.log("$ " + shlex.join(args))
        started = time.monotonic()
        with tempfile.TemporaryFile() as output:
            proc = subprocess.Popen(args, stdout=None if interactive else output,
                                    stderr=None if interactive else subprocess.STDOUT, start_new_session=True)
            next_update = started + 5
            try:
                while proc.poll() is None:
                    now = time.monotonic()
                    if now - started > timeout:
                        raise SetupError(f"Превышено ожидание {timeout} с: {args[0]}")
                    if not interactive and now >= next_update:
                        say(f"{args[0]}: выполняется {int(now - started)} с")
                        next_update = now + 5
                    time.sleep(0.15)
            except BaseException:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
                size = output.tell()
                output.seek(max(0, size - 65536))
                self.log(output.read().decode("utf-8", "replace"))
                raise
            size = output.tell()
            output.seek(max(0, size - 2 * 1024 * 1024))
            text = output.read().decode("utf-8", "replace")
        self.last_output = text
        self.log(text)
        if check and proc.returncode:
            raise SetupError(f"{args[0]} завершился с кодом {proc.returncode}:\n" + "\n".join(text.splitlines()[-16:]))
        return subprocess.CompletedProcess(args, proc.returncode, text)

    def active(self, unit: str) -> bool:
        return self.run(["systemctl", "is-active", "--quiet", unit], check=False).returncode == 0

    def storage(self) -> None:
        space = shutil.disk_usage("/")
        inodes = os.statvfs("/").f_favail
        say(f"Диск: свободно {space.free // 1024**2} МБ; свободных inode: {inodes}")
        if space.free < 256 * 1024**2 or inodes < 2048:
            raise SetupError("Недостаточно места/inode. Сначала раздел очистки диска; логи и данные без согласия не удаляются")

    def dependencies(self) -> None:
        if not shutil.which("apt-get") or not shutil.which("systemctl"):
            raise SetupError("Этот мастер рассчитан на Debian/Ubuntu с systemd")
        self.fresh_default = not shutil.which("nginx") and not DEFAULT_SITE.exists()
        packages = {"nginx": "nginx", "certbot": "certbot", "dig": "dnsutils", "ip": "iproute2",
                    "ss": "iproute2", "openssl": "openssl", "logrotate": "logrotate", "ps": "procps"}
        missing = sorted({package for command, package in packages.items() if not shutil.which(command)})
        if not Path("/etc/ssl/certs/ca-certificates.crt").is_file():
            missing.append("ca-certificates")
        if not missing:
            return
        # Prevent package installation from starting a wildcard Nginx over existing listeners.
        policy = Path("/usr/sbin/policy-rc.d")
        temporary_policy = not policy.exists() and not policy.is_symlink()
        if temporary_policy:
            atomic_write(policy, '#!/bin/sh\ncase "$1" in nginx|nginx.service) exit 101;; esac\nexit 0\n', 0o755)
        try:
            apt_options = ["-o", "DPkg::Lock::Timeout=60", "-o", "Acquire::ForceIPv4=true", "-o", "Acquire::Retries=2"]
            updated = self.run(["apt-get", *apt_options, "update"], 180, check=False)
            if updated.returncode:
                say("apt update не завершился; пробую установку из существующего кэша пакетов", "!")
            self.run(["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "-o", "DPkg::Lock::Timeout=60",
                      "-o", "Acquire::ForceIPv4=true", "-o", "Acquire::Retries=2", "install", "-y", *missing], 480)
        finally:
            if temporary_policy:
                policy.unlink(missing_ok=True)

    def addresses(self) -> dict[str, str]:
        data = json.loads(self.run(["ip", "-j", "-4", "addr", "show"], 10).stdout)
        return {addr["local"]: link["ifname"] for link in data
                for addr in link.get("addr_info", []) if addr.get("scope") == "global"}

    def source_check(self, site: Site, local: dict[str, str]) -> bool:
        sources = [site.source] if site.source != "auto" else list(dict.fromkeys([*site.ips, *local]))[:16]
        for source in sources:
            if source not in local:
                raise SetupError(f"Source IP {source} не назначен машине")
            route = self.run(["ip", "-4", "route", "get", site.backend, "from", source], check=False).stdout.strip()
            say(f"Выход {source}: {route or 'маршрут не найден'}")
            success = 0
            for _ in range(2):
                try:
                    with socket.create_connection((site.backend, site.backend_port), 3, (source, 0)):
                        success += 1
                except OSError as exc:
                    say(f"TCP {source} -> {site.backend}:{site.backend_port}: {exc}", "!")
            if success == 2:
                site.source = source
                say(f"Выход закреплён за {source}; TCP 2/2", "OK")
                return True
        if site.source == "auto":
            site.source = site.ips[0]
        return False

    def dns(self, site: Site) -> bool:
        records = {}
        for kind in ("A", "AAAA"):
            result = self.run(["dig", "+time=2", "+tries=1", "+short", site.domain, kind], 6, check=False)
            values = []
            for line in result.stdout.splitlines():
                with contextlib.suppress(ValueError):
                    values.append(str(ipaddress.ip_address(line.strip())))
            records[kind] = values
            say(f"DNS {kind}: {', '.join(values) or '-'}")
        valid = bool(records["A"]) and set(records["A"]) <= set(site.ips) and not records["AAAA"]
        if not valid:
            say("Для HTTP-01 все A должны вести на выбранные IP. IPv6 этот мастер не настраивает: проверь/убери AAAA или выбери DNS-01", "!")
        return valid

    def certificate_valid(self, site: Site) -> bool:
        if not site.cert or not site.key or not Path(site.cert).is_file() or not Path(site.key).is_file():
            return False
        host = self.run(["openssl", "x509", "-in", site.cert, "-noout", "-checkhost", site.domain], check=False)
        if host.returncode or "does match certificate" not in host.stdout:
            return False
        if self.run(["openssl", "x509", "-in", site.cert, "-noout", "-checkend", "604800"], check=False).returncode:
            return False
        try:
            ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(site.cert, site.key)
        except (ssl.SSLError, OSError):
            return False
        return True

    def find_certificate(self, site: Site) -> bool:
        if self.certificate_valid(site):
            return True
        if site.tls_mode == "existing":
            return False
        for name in (site.cert_name, site.domain):
            site.cert = str(LE / "live" / name / "fullchain.pem")
            site.key = str(LE / "live" / name / "privkey.pem")
            if self.certificate_valid(site):
                return True
        site.cert = site.key = ""
        return False

    def renewal_info(self, site: Site) -> tuple[str, str]:
        path = LE / "renewal" / (Path(site.cert).parent.name + ".conf")
        parser = configparser.ConfigParser(interpolation=None)
        try:
            parser.read(path)
            auth = parser.get("renewalparams", "authenticator", fallback="unknown")
            root = ""
            for section in ("webroot_map", "[webroot_map]"):
                root = parser.get(section, site.domain, fallback="") or root
            if not root:
                raw = parser.get("renewalparams", "webroot_path", fallback="")
                roots = [part.strip() for part in raw.split(",") if part.strip()]
                if len(roots) == 1:
                    root = roots[0]
            return auth, cert_path(root) if root else ""
        except (configparser.Error, OSError) as exc:
            raise SetupError(f"Не удалось проверить способ продления {path}: {exc}") from exc

    def certificate(self, site: Site) -> None:
        base = ["certbot", "certonly", "--config", "/dev/null", "--cert-name", site.cert_name,
                "-d", site.domain, "--agree-tos"]
        base += ["-m", site.email] if site.email else ["--register-unsafely-without-email"]
        if site.tls_mode == "dns":
            say("Certbot покажет TXT. Добавь его в DNS и дождись распространения ДО Enter. Автопродления без DNS API не будет", "!")
            result = self.run([*base, "--server", CA_PRODUCTION, "--manual", "--preferred-challenges", "dns"],
                              1800, check=False, interactive=True)
        else:
            args = [*base, "--webroot", "-w", site.webroot, "--non-interactive"]
            say("Проверка HTTP-01 через staging CA; production только после успешной проверки")
            test = self.run([*args, "--server", CA_STAGING, "--dry-run"], 180, check=False)
            if test.returncode:
                raise SetupError(certificate_error(test.stdout) + "\n" + "\n".join(test.stdout.splitlines()[-16:]))
            result = self.run([*args, "--server", CA_PRODUCTION, "--keep-until-expiring"], 180, check=False)
        if result.returncode:
            raise SetupError(certificate_error(result.stdout) + "\n" + "\n".join(result.stdout.splitlines()[-16:]))
        site.cert = str(LE / "live" / site.cert_name / "fullchain.pem")
        site.key = str(LE / "live" / site.cert_name / "privkey.pem")
        if not self.certificate_valid(site):
            raise SetupError("Certbot завершился, но подходящая пара certificate/key не найдена")

    def apply_runtime(self) -> None:
        self.run(["nginx", "-t"], 20)
        self.run(["systemctl", "reload" if self.active("nginx") else "start", "nginx"], 30)
        if not self.active("nginx"):
            raise SetupError("Nginx не стал active; смотри journalctl -u nginx")

    def runtime_capacity(self) -> None:
        master = self.run(["systemctl", "show", "nginx", "-p", "MainPID", "--value"]).stdout.strip()
        if not master.isdigit() or int(master) == 0:
            raise SetupError("Не найден активный master Nginx")
        workers = self.run(["ps", "--ppid", master, "-o", "pid=,args="]).stdout
        pids = re.findall(r"(?m)^\s*(\d+)\s+nginx: worker process\s*$", workers)
        if not pids:
            raise SetupError("Не найдены новые рабочие процессы Nginx")
        for pid in pids:
            limits = Path(f"/proc/{pid}/limits").read_text()
            match = re.search(r"Max open files\s+(\d+|unlimited)\s+", limits)
            if not match or (match[1] != "unlimited" and int(match[1]) < 65536):
                raise SetupError(f"Worker {pid}: лимит файлов не поднялся. Проверь LimitNOFILE/capabilities в systemd; restart автоматически не выполняется")
        say(f"Активных workers: {len(pids)}; лимит файлов каждого не меньше 65536", "OK")

    def prune_backups(self, current: Path) -> None:
        candidates = sorted((path for path in BACKUPS.iterdir() if path.is_dir() and not path.is_symlink()
                             and re.fullmatch(r"\d{8}-\d{6}-[A-Za-z0-9_-]+", path.name)
                             and (path / "manifest.json").is_file() and path != current), reverse=True)
        for path in candidates[9:]:
            if path.resolve().parent == BACKUPS.resolve():
                shutil.rmtree(path)

    def firewall(self, site: Site) -> None:
        if not shutil.which("ufw"):
            say("UFW отсутствует. Firewall провайдера и nftables автоматически не меняются", "!")
            return
        status = self.run(["env", "LC_ALL=C", "ufw", "status"], check=False).stdout
        if "Status: active" not in status:
            say("UFW не активен; включать его не буду")
            return
        if not confirm(f"Разрешить в UFW вход на выбранные IP, TCP 80/{site.port}?", True):
            say("UFW оставлен без изменений; доступ снаружи нужно разрешить самостоятельно", "!")
            return
        for ip in site.ips:
            for port in (80, site.port):
                self.run(["ufw", "insert", "1", "allow", "in", "proto", "tcp", "to", ip, "port", str(port),
                          "comment", "kto-nginx"], 20)

    def protections(self, tx: Transaction) -> None:
        for path in (ROTATE, UNIT, TIMER, HOOK):
            if path.exists() and MANAGED not in path.read_text()[:256]:
                raise SetupError(f"{path} не принадлежит этому мастеру; перезапись отменена")
        tx.write(ROTATE, f"""{MANAGED}
{LOGS}/*.log {{
    daily
    maxsize 50M
    rotate 4
    missingok
    notifempty
    compress
    delaycompress
    create 0640 root adm
    sharedscripts
    postrotate
        if /usr/bin/systemctl is-active --quiet nginx; then
            /usr/bin/systemctl kill --kill-who=main --signal=USR1 nginx.service
        fi
    endscript
}}
""")
        self.run(["logrotate", "--debug", str(ROTATE)], 20)
        tx.write(UNIT, MANAGED + "\n[Unit]\nDescription=KTO Nginx log rotation\n[Service]\nType=oneshot\n"
                 "ExecStart=/usr/sbin/logrotate /etc/logrotate.d/kto-nginx\nSuccessExitStatus=3\n")
        tx.write(TIMER, MANAGED + "\n[Unit]\nDescription=KTO Nginx log size check\n[Timer]\nOnBootSec=5min\n"
                 "OnUnitActiveSec=5min\nAccuracySec=30s\n[Install]\nWantedBy=timers.target\n")
        tx.write(HOOK, "#!/bin/sh\n" + MANAGED + "\nset -e\nif systemctl is-active --quiet nginx; then\n"
                 "    nginx -t\n    systemctl reload nginx\nfi\n", 0o755)
        self.run(["systemctl", "daemon-reload"])
        self.run(["systemctl", "enable", "--now", TIMER.name])
        self.run(["systemctl", "start", UNIT.name])
        if self.run(["systemctl", "cat", "certbot.timer"], check=False).returncode == 0:
            self.run(["systemctl", "enable", "--now", "certbot.timer"])
        elif not Path("/etc/cron.d/certbot").exists():
            raise SetupError("Не найден планировщик Certbot: настрой автоматическое продление")

    def check_http_token(self, site: Site) -> None:
        token = "kto-" + uuid.uuid4().hex
        target = Path(site.webroot) / ".well-known/acme-challenge" / token
        target.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(target, token)
        try:
            for ip in site.ips:
                for attempt in range(3):
                    try:
                        code, body = probe_http(ip, 80, site.domain, f"/.well-known/acme-challenge/{token}")
                        if code == 200 and body == token:
                            break
                    except (OSError, http.client.HTTPException):
                        pass
                    if attempt == 2:
                        raise SetupError(f"ACME-файл не отдаётся через {ip}:80. Возможны старый worker, чужой vhost или bind-конфликт; смотри error.log")
                    time.sleep(1)
                say(f"ACME {ip}:80 -> 200", "OK")
        finally:
            target.unlink(missing_ok=True)
        say("Локальная проверка не доказывает доступность :80 для CA из интернета")

    def verify(self, site: Site) -> bool:
        ready = True
        for ip in site.ips:
            healthy = False
            reason = "не получен ответ нового vhost"
            for _ in range(3):
                try:
                    code, body = probe_http(ip, site.port, site.domain, tls=True,
                                            path="/" if site.path != "/" else "/kto-health")
                    healthy = code == 200 and body == f"KTO {site.domain} {site.health_token} OK\n"
                    if not healthy:
                        reason = f"HTTP {code}, ответ не соответствует новому config"
                except (OSError, http.client.HTTPException) as exc:
                    self.log(str(exc))
                    reason = str(exc)
                if healthy:
                    break
                time.sleep(1)
            if not healthy:
                raise SetupError(f"{ip}:{site.port}: HTTPS-проверка не прошла: {reason}. Изменения будут отменены")
            say(f"{ip}: HTTPS 200, сертификат проверен", "OK")
            try:
                code, _ = probe_http(ip, site.port, site.domain, site.path, tls=True, websocket=True)
                if code != 101:
                    raise SetupError(f"HTTP {code}")
                say(f"{ip}: WS 101", "OK")
            except (OSError, http.client.HTTPException, SetupError) as exc:
                ready = False
                say(f"{ip}: WS не готов ({exc}); проверь {site.backend}:{site.backend_port}, путь и firewall бэкенда", "!")
        return ready

    def deploy(self, site: Site) -> None:
        site.validate()
        self.step = 0
        atomic_write(site.draft, json.dumps(dataclasses.asdict(site), ensure_ascii=False, indent=2), 0o600)
        self.stage("Место на диске и пакеты")
        self.storage()
        self.dependencies()
        self.stage("Локальные IP, DNS, конфликты портов")
        local = self.addresses()
        if not set(site.ips) <= set(local):
            raise SetupError("Выбранные входные IP отсутствуют в ip addr. Сначала пункт дополнительных IP")
        if site.backend in local and site.backend_port == site.port:
            raise SetupError("Backend совпадает с локальным TLS listener: возможна петля")
        dump = self.run(["nginx", "-T"], 20).stdout
        if str(site.config) not in config_sections(dump) and site.config.exists():
            raise SetupError(f"{site.config} существует, но Nginx его не включает")
        if site.config.exists() and not site.config.read_text().startswith(MANAGED):
            raise SetupError(f"Файл {site.config} не принадлежит этому мастеру")
        if not any(key == "include" and args == [str(CONF / "*.conf")]
                   for context, key, args in nginx_directives(NGINX.read_text()) if context == ("http",)):
            raise SetupError("В http {} nginx.conf нет include /etc/nginx/conf.d/*.conf; автоматически чужую структуру не перестраиваю")
        sockets = self.run(["ss", "-Hlnpt"], 10).stdout
        if self.fresh_default:
            dump = "\n".join(f"# configuration file {name}:\n{text}" for name, text in config_sections(dump).items()
                             if name != "/etc/nginx/sites-enabled/default")
        site.http_listens, site.tls_listens = choose_listens(site, dump, sockets)
        dns_ok = self.dns(site)
        existing = self.find_certificate(site)
        if existing:
            auth, root = self.renewal_info(site)
            if auth == "webroot":
                if not root or not site.http_listens:
                    raise SetupError("Существующий сертификат продлевается через webroot, но каталог или HTTP :80 недоступен")
                site.webroot = root
                say(f"Сохраняю каталог продления сертификата: {root}")
        if not existing and site.tls_mode == "existing":
            raise SetupError("Сертификат/ключ не подходят домену, истекают меньше чем через 7 дней или не читаются")
        if not existing and site.tls_mode == "http" and not dns_ok:
            raise SetupError("HTTP-01 остановлен до обращения в CA. Исправь A/AAAA или выбери DNS-01 / готовый сертификат")
        self.stage("Проверка бэкенда и выбор исходящего IP")
        backend_ok = self.source_check(site, local)
        if not backend_ok and not confirm("Бэкенд недоступен. Подготовить фронт заранее со статусом ОЖИДАЕТ БЭКЕНД?"):
            raise SetupError("Бэкенд недоступен; конфигурация Nginx не менялась")
        self.stage("Firewall и резервная копия")
        self.firewall(site)
        was_active = self.active("nginx")
        timer_active = self.active(TIMER.name)
        timer_enabled = self.run(["systemctl", "is-enabled", "--quiet", TIMER.name], check=False).returncode == 0
        tx = Transaction()
        try:
            LOGS.mkdir(parents=True, exist_ok=True)
            Path(site.webroot).mkdir(parents=True, exist_ok=True)
            if self.fresh_default and DEFAULT_SITE.exists():
                tx.write(DEFAULT_SITE, MANAGED + "\n# Packaged default disabled on first installation.\n")
            tx.write(NGINX, tune_capacity(NGINX.read_text()))
            site.health_token = uuid.uuid4().hex
            self.stage("HTTP challenge и сертификат")
            if not existing:
                if site.tls_mode == "http":
                    tx.write(site.config, render_site(site, False))
                    self.apply_runtime()
                    self.check_http_token(site)
                self.certificate(site)
            else:
                say(f"Использую действующий сертификат: {site.cert}", "OK")
            self.stage("TLS + WebSocket, применение без restart")
            tx.write(site.config, render_site(site, True))
            self.apply_runtime()
            self.stage("Проверка HTTPS / WS через каждый IP")
            ready = self.verify(site)
            self.runtime_capacity()
            if not ready and site.state.exists() and backend_ok and not confirm("WS-проверка не прошла. Всё равно заменить существующий маршрут?"):
                raise SetupError("WS не готов: возвращаю прежний маршрут")
            self.stage("Ротация, продление и сохранение маршрута")
            self.protections(tx)
            site.status = "ready" if ready else "backend-pending"
            tx.write(site.state, json.dumps(dataclasses.asdict(site), ensure_ascii=False, indent=2), 0o600)
            self.run(["systemctl", "enable", "nginx"])
        except BaseException:
            say("Возвращаю прежние файлы Nginx", "!")
            if not timer_enabled:
                self.run(["systemctl", "disable", TIMER.name], check=False)
            if not timer_active:
                self.run(["systemctl", "stop", TIMER.name], check=False)
            tx.restore()
            self.run(["systemctl", "daemon-reload"], check=False)
            if timer_enabled:
                self.run(["systemctl", "enable", TIMER.name], check=False)
            if timer_active:
                self.run(["systemctl", "start", TIMER.name], check=False)
            if was_active:
                with contextlib.suppress(SetupError):
                    self.apply_runtime()
            else:
                self.run(["systemctl", "stop", "nginx"], check=False)
            say(f"Черновик сохранён. Пакеты, выданный сертификат и разрешённые UFW-правила не удалялись. Backup: {tx.folder}", "!")
            raise
        site.draft.unlink(missing_ok=True)
        try:
            self.prune_backups(tx.folder)
        except OSError as exc:
            say(f"Не удалось ограничить старые backup: {exc}", "!")
        self.summary(site)

    def summary(self, site: Site) -> None:
        print("\n" + "=" * 64)
        say("Фронт готов" if site.status == "ready" else "TLS готов, WS / бэкенд требует проверки",
            "OK" if site.status == "ready" else "!")
        print(f"Домен / SNI / Host: {site.domain}\nВход: {', '.join(site.ips)}:{site.port}\n"
              f"Backend: {site.backend}:{site.backend_port}{site.path}\nИсходящий IP: {site.source}\n"
              f"Клиент: VLESS, WS, TLS, ALPN http/1.1, путь {site.path}, flow пустой\n"
              "UUID берётся у владельца бэкенда. PROXY protocol не используется.\n"
              "Проверка с этой машины не заменяет внешний тест клиента и передачу трафика.")
        auth, _ = self.renewal_info(site)
        if auth == "webroot":
            say("Certbot: webroot-продление; сохраняй доступность HTTP :80 и правильные A/AAAA")
        elif auth == "manual":
            say("Сертификат manual DNS: автоматического продления нет, TXT потребуется снова до истечения", "!")
        else:
            say("Продление существующего сертификата зависит от его первоначального ACME-клиента; проверь расписание", "!")
        print(f"Config: {site.config}\nЛоги: {LOGS}/{site.domain}.error.log\nМастер: {LOG}")

    def diagnose(self, site: Site) -> None:
        try:
            self.storage()
        except SetupError as exc:
            say(str(exc), "!")
        self.run(["nginx", "-t"])
        self.dns(site)
        route = ["ip", "-4", "route", "get", site.backend]
        if site.source != "auto":
            route += ["from", site.source]
        print(self.run(route, check=False).stdout)
        for ip in site.ips:
            for ws in (False, True):
                try:
                    path = site.path if ws else ("/kto-health" if site.path == "/" else "/")
                    code, _ = probe_http(ip, site.port, site.domain, path, tls=True, websocket=ws)
                    say(f"{ip}: {'WS' if ws else 'HTTPS'} HTTP {code}", "OK" if code == (101 if ws else 200) else "!")
                except (OSError, http.client.HTTPException, SetupError) as exc:
                    say(f"{ip}: {exc}", "!")
        if site.source != "auto":
            try:
                code, _ = probe_http(site.backend, site.backend_port, site.domain, site.path, websocket=True, source=site.source)
                say(f"Прямой WS с {site.source}: HTTP {code}", "OK" if code == 101 else "!")
            except (OSError, http.client.HTTPException, SetupError) as exc:
                say(f"Бэкенд напрямую: {exc}", "!")
        print(self.run(["systemctl", "list-timers", "--all", "--no-pager", TIMER.name, "certbot.timer"], check=False).stdout)
        log = LOGS / f"{site.domain}.error.log"
        if log.exists():
            print(self.run(["tail", "-n", "15", str(log)]).stdout)
        say("101 не проверяет UUID/трафик VLESS. Для потерь нужны внешний клиент и замеры под нагрузкой")

    def remove(self, site: Site) -> None:
        if not confirm(f"Удалить только маршрут {site.domain}? Его активные WS завершатся естественно после reload"):
            return
        if not site.config.exists() and not site.state.exists():
            site.draft.unlink(missing_ok=True)
            say("Черновик удалён", "OK")
            return
        if not site.config.read_text().startswith(MANAGED):
            raise SetupError("Нельзя удалять чужой config")
        tx = Transaction()
        try:
            tx.remove(site.config)
            tx.remove(site.state)
            tx.remove(site.draft)
            self.apply_runtime()
        except BaseException:
            tx.restore()
            self.apply_runtime()
            raise
        say("Маршрут удалён. Nginx, HAProxy, сертификат, firewall и остальные сайты сохранены", "OK")

    def repair(self, site: Site) -> None:
        checked = self.run(["nginx", "-t"], 20, check=False)
        if checked.returncode:
            if not site.state.exists() or not site.config.exists() or not site.config.read_text().startswith(MANAGED):
                raise SetupError("Config невалиден, но нет сохранённого управляемого маршрута для восстановления:\n" + checked.stdout)
            saved = load_site(site.state)
            tx = Transaction()
            try:
                tx.write(saved.config, render_site(saved, True))
                self.run(["nginx", "-t"], 20)
            except BaseException:
                tx.restore()
                raise
            say(f"Синтаксис управляемого vhost восстановлен из state. Backup повреждённого файла: {tx.folder}", "OK")
            say("Файл восстановлен; далее проверка сети/TLS и применение. Другие configs не менялись")
            site = saved
        self.deploy(site)


def load_site(path: Path) -> Site:
    try:
        site = Site(**json.loads(path.read_text())).validate()
        if path.stem != site.domain:
            raise SetupError("Имя файла не совпадает с доменом")
        return site
    except (OSError, TypeError, ValueError) as exc:
        raise SetupError(f"Не удалось прочитать {path}: {exc}") from exc


def sites() -> list[Site]:
    found: dict[str, Site] = {}
    for folder in ("sites", "drafts"):
        for path in sorted((STATE / folder).glob("*.json")):
            site = load_site(path)
            found[site.domain] = site
    return list(found.values())


def select_site() -> Site:
    choices = sites()
    if not choices:
        raise SetupError("Пока нет маршрутов этого мастера. Сначала создай маршрут")
    for i, site in enumerate(choices, 1):
        print(f"{i}. {site.domain:35} {site.status}")
    value = ask("Номер маршрута", "1")
    if not value.isdigit() or not 1 <= int(value) <= len(choices):
        raise SetupError("Некорректный номер")
    return choices[int(value) - 1]


def wizard(manager: Manager, old: Site | None = None) -> Site:
    print("\n=== NGINX / WEBSOCKET + TLS ===")
    print("Бэкенд должен принимать обычный WS без TLS и PROXY protocol.")
    domain = domain_name(ask("Домен", old.domain if old else ""))
    if old and domain != old.domain:
        raise SetupError("Для другого домена создай новый фронт; существующий домен остаётся без изменений")
    if not old and (STATE / "sites" / f"{domain}.json").exists():
        raise SetupError("Маршрут уже существует: выбери изменение маршрута")
    local = manager.addresses()
    for index, (ip, iface) in enumerate(local.items(), 1):
        print(f"  {index:2}. {ip:16} {iface}")
    selected = ask("Входные IP или номера через запятую", ",".join(old.ips) if old else "1")
    ips = []
    for value in selected.split(","):
        value = value.strip()
        if value.isdigit() and 1 <= int(value) <= len(local):
            value = list(local)[int(value) - 1]
        if value not in local:
            raise SetupError(f"IP {value} не назначен этой машине")
        ips.append(value)
    backend = ask("Backend IPv4:порт", f"{old.backend}:{old.backend_port}" if old else "")
    host, separator, port = backend.partition(":")
    site = Site(domain, ips, ipv4(host), port_number(port if separator else "9080"))
    site.path = ask("WS-путь", old.path if old else "/de3ws")
    site.port = port_number(ask("Входной TLS-порт", str(old.port) if old else "443"))
    site.source = ask("Исходящий IP Nginx к бэкенду (auto = найти рабочий)", old.source if old else "auto")
    print("Сертификат: 1. HTTP-01 автоматически  2. DNS TXT вручную  3. Готовые PEM")
    modes = {"1": "http", "2": "dns", "3": "existing"}
    choice = ask("Способ", {"http": "1", "dns": "2", "existing": "3"}.get(old.tls_mode if old else "http", "1"))
    if choice not in modes:
        raise SetupError("Неверный способ сертификата")
    site.tls_mode = modes[choice]
    if old and old.domain == domain:
        site.cert, site.key = old.cert, old.key
    if site.tls_mode == "existing":
        site.cert = cert_path(ask("fullchain.pem", site.cert))
        site.key = cert_path(ask("privkey.pem", site.key))
    else:
        site.email = ask("Email для Let's Encrypt (Enter = без email)", old.email if old else "")
        if site.tls_mode == "dns":
            say("DNS TXT вручную требует участия при каждом продлении; таймер сам TXT не создаст", "!")
    site.validate()
    print(f"\n{site.domain}: {', '.join(site.ips)}:{site.port} -> {site.backend}:{site.backend_port}{site.path}")
    print("Будут установлены пакеты, лимиты Nginx и ротация его новых логов.")
    print("HAProxy, SSH, системные маршруты и DNS-записи не меняются. Чужие vhost не удаляются.")
    if site.tls_mode != "existing":
        print("При выпуске сертификата принимаются условия Let's Encrypt: https://letsencrypt.org/repository/")
    if not confirm("Применить настройки?"):
        raise SetupError("Отменено; настройки не менялись")
    return site


def main() -> int:
    parser = argparse.ArgumentParser(description="KTO Nginx WS/TLS manager")
    parser.add_argument("action", choices=("menu", "diagnose"), nargs="?", default="menu")
    args = parser.parse_args()
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        print("Запусти мастер от root на Debian/Ubuntu", file=sys.stderr)
        return 1
    os.umask(0o022)
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(STATE, 0o700)
    LOG.parent.mkdir(parents=True, exist_ok=True)
    LOG.touch(mode=0o600, exist_ok=True)
    manager = Manager()
    # One writer avoids races between certificate, config and rollback stages.
    import fcntl
    with (STATE / "manager.lock").open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            say("Другой мастер Nginx уже работает", "STOP")
            return 1
        if args.action == "diagnose":
            manager.diagnose(select_site())
            return 0
        while True:
            print("\n" + "=" * 64 + "\n  NGINX / WS + TLS\n" + "=" * 64)
            for site in sites():
                print(f"  {site.domain:32} {site.status:16} {site.backend}:{site.backend_port}")
            print("\n1. Поднять новый фронт\n2. Изменить / продолжить настройку\n"
                  "3. Диагностика маршрута\n4. Проверить и восстановить настройки\n"
                  "5. Удалить маршрут\n0. Назад")
            try:
                choice = ask("Выбор", "0")
                if choice == "0":
                    return 0
                if choice == "1":
                    manager.deploy(wizard(manager))
                elif choice == "2":
                    manager.deploy(wizard(manager, select_site()))
                elif choice == "3":
                    manager.diagnose(select_site())
                elif choice == "4":
                    site = select_site()
                    if confirm(f"Проверить и повторно применить {site.domain} с backup и откатом?"):
                        manager.repair(site)
                elif choice == "5":
                    manager.remove(select_site())
                else:
                    say("Неверный пункт", "!")
            except (SetupError, OSError, ValueError) as exc:
                say(str(exc), "STOP")
                manager.log(str(exc))
                say(f"Лог: {LOG}. Исправь причину и выбери продолжение настройки", "!")
            except (KeyboardInterrupt, EOFError):
                print("\nОтменено")
                return 130


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (SetupError, OSError, ValueError) as error:
        say(str(error), "STOP")
        raise SystemExit(1)
    except (KeyboardInterrupt, EOFError):
        raise SystemExit(130)
