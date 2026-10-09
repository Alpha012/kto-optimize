#!/usr/bin/env python3
"""Enable a generated root SSH password without replacing keys or changing ports."""

from __future__ import annotations

import contextlib
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import stat
import string
import subprocess
import sys
import tempfile


CONFIG = Path("/etc/ssh/sshd_config")
MARKER = Path("/etc/kto-ssh-password.enabled")
BACKUPS = Path("/var/backups/kto-ssh-password")
LOCK = Path("/run/lock/kto-ssh-password.lock")
BEGIN = "# BEGIN KTO ROOT PASSWORD"
END = "# END KTO ROOT PASSWORD"
AUTH = {"permitrootlogin": ["yes"], "pubkeyauthentication": ["yes"],
        "passwordauthentication": ["yes"], "authenticationmethods": ["any"]}
BLOCK = f"""{BEGIN}
Match User root
    PermitRootLogin yes
    PubkeyAuthentication yes
    PasswordAuthentication yes
    AuthenticationMethods any
Match all
{END}
"""


class PasswordError(RuntimeError):
    pass


class Runner:
    def run(self, args, *, data=None, secret=False, check=True):
        try:
            result = subprocess.run(args, input=data, capture_output=True, text=True,
                                    errors="replace", env=dict(os.environ, LC_ALL="C"), timeout=30)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise PasswordError(f"Не удалось выполнить {args[0]}" + ("" if secret else f": {exc}")) from None
        if check and result.returncode:
            raise PasswordError(f"Ошибка {args[0]}" + ("" if secret else f": {result.stderr.strip()}"))
        return result


def generate_password() -> str:
    groups = (string.ascii_lowercase, string.ascii_uppercase, string.digits, "!@%+=_-.")
    alphabet = "".join(groups)
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(28))
        if all(any(char in group for char in password) for group in groups):
            return password


def candidate_config(original: str) -> str:
    lines = original.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if line.strip() == BEGIN]
    ends = [i for i, line in enumerate(lines) if line.strip() == END]
    if starts or ends:
        if len(starts) != 1 or len(ends) != 1 or ends[0] <= starts[0]:
            raise PasswordError("Повреждён блок KTO ROOT PASSWORD; конфиг не изменён")
        if "".join(lines[ends[0] + 1:]).strip():
            raise PasswordError("После блока KTO появились другие настройки. Нужна ручная проверка Match.")
        original = "".join(lines[:starts[0]])
    # A Match block goes last: global-only options (Port, ListenAddress, etc.) must stay outside it.
    return original.rstrip("\r\n") + "\n\n" + BLOCK


def contexts(connection: str) -> list[str]:
    result = ["host=localhost,addr=127.0.0.1", "host=192.0.2.1,addr=192.0.2.1"]
    if connection:
        fields = connection.split()
        if len(fields) != 4:
            raise PasswordError("Некорректный SSH_CONNECTION")
        peer, peer_port, local, local_port = fields
        for address in (peer, local):
            ipaddress.ip_address(address)
        if not all(port.isdigit() and 1 <= int(port) <= 65535 for port in (peer_port, local_port)):
            raise PasswordError("Некорректный порт SSH_CONNECTION")
        result.append(f"host={peer},addr={peer},laddr={local},lport={local_port}")
    return result


def effective(runner, sshd, config, user, context):
    output = runner.run([sshd, "-T", "-f", str(config), "-C", f"user={user},{context}"]).stdout
    result = {}
    for line in output.splitlines():
        key, _, value = line.partition(" ")
        result.setdefault(key, []).append(value.strip())
    if not all(key in result for key in AUTH) or "port" not in result:
        raise PasswordError("Не удалось прочитать эффективный конфиг sshd")
    return result


def validate_candidate(before, after, *, root):
    if root:
        for key, value in AUTH.items():
            if after.get(key) != value:
                raise PasswordError(f"{key} перекрыт другим Match/Include. SSH и пароль не изменены.")
        allowed = set(AUTH)
    else:
        allowed = set()
    changed = [key for key in before.keys() | after.keys()
               if key not in allowed and before.get(key) != after.get(key)]
    if changed:
        raise PasswordError("Меняются посторонние параметры SSH: " + ", ".join(sorted(changed)))


def atomic_write(path: Path, data: bytes, mode=0o600):
    fd, temporary = tempfile.mkstemp(prefix=".kto-password-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.chmod(temporary, mode)
            os.fsync(out.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def account_snapshot(runner):
    passwd = runner.run(["getent", "passwd", "root"]).stdout.strip().split(":")
    if len(passwd) != 7 or passwd[0] != "root" or passwd[2] != "0":
        raise PasswordError("Не найден локальный root с UID 0")
    if passwd[6].endswith(("/nologin", "/false")):
        raise PasswordError("Shell root запрещает вход; автоматически его не меняю")
    shadow = runner.run(["getent", "shadow", "root"], secret=True).stdout.strip().split(":")
    if len(shadow) != 9 or shadow[0] != "root":
        raise PasswordError("Не удалось сохранить прежнее состояние пароля root")
    today = (dt.datetime.now(dt.timezone.utc).date() - dt.date(1970, 1, 1)).days
    if shadow[7] and int(shadow[7]) >= 0 and int(shadow[7]) <= today:
        raise PasswordError("Учётная запись root просрочена; срок действия автоматически не меняю")
    return shadow


def active_service(runner):
    for service in ("ssh.service", "sshd.service"):
        if runner.run(["systemctl", "is-active", "--quiet", service], check=False).returncode == 0:
            if runner.run(["systemctl", "show", service, "-p", "CanReload", "--value"]).stdout.strip() != "yes":
                raise PasswordError("SSH не поддерживает reload. Автоматический restart не выполняется.")
            return service
    raise PasswordError("Активный SSH service не найден. Socket и сервис автоматически не запускаю.")


def check_daemon_options(runner, service):
    pid = runner.run(["systemctl", "show", service, "-p", "MainPID", "--value"]).stdout.strip()
    if not pid.isdigit() or int(pid) < 1:
        raise PasswordError("Не удалось найти работающий процесс sshd")
    command = (Path("/proc") / pid / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
    if "sshd" not in command or re.search(r"(?:^|\s)-(?:f|o)", command):
        raise PasswordError("SSH запущен с нестандартным конфигом/опциями. Нужна ручная проверка -f/-o.")


def check_file(path, *, optional=False):
    if path.parent.resolve() != path.parent or path.is_symlink():
        raise PasswordError(f"Не изменяю путь с symlink: {path}")
    if optional and not path.exists():
        return
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise PasswordError(f"Нужен обычный root-owned файл без записи для группы/остальных: {path}")


@contextlib.contextmanager
def operation_lock():
    import fcntl
    with LOCK.open("a") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise PasswordError("Уже выполняется другая смена SSH-пароля") from None
        yield


def enable(runner, connection=""):
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise PasswordError("Нужен интерактивный терминал без перенаправления stdout: пароль не должен попасть в лог")
    with operation_lock():
        print("[1/5] Проверяю SSH и root. Порт, ключи, firewall и прочие пользователи не меняются.", flush=True)
        for name in ("sshd", "chpasswd", "chage", "getent", "systemctl"):
            if not shutil.which(name):
                raise PasswordError(f"Не найдена команда {name}. Автоматической установки пакетов нет.")
        sshd = shutil.which("sshd")
        check_file(CONFIG)
        check_file(MARKER, optional=True)
        service = active_service(runner)
        check_daemon_options(runner, service)
        runner.run([sshd, "-t", "-f", str(CONFIG)])
        shadow = account_snapshot(runner)
        probes = contexts(connection)
        before = {(user, context): effective(runner, sshd, CONFIG, user, context)
                  for user in ("root", "nobody") for context in probes}
        for (user, _), config in before.items():
            if user == "root" and any(key in config for key in ("allowusers", "denyusers", "allowgroups", "denygroups")):
                raise PasswordError("Есть AllowUsers/DenyUsers/AllowGroups/DenyGroups. Сначала проверь доступ root вручную.")
        original = CONFIG.read_bytes()
        mode = stat.S_IMODE(CONFIG.stat().st_mode)
        old_marker = MARKER.read_bytes() if MARKER.exists() else None
        candidate = candidate_config(original.decode("utf-8"))
        print("[!] Прежний пароль root будет заменён случайным. Вход: пароль ИЛИ ключ, без обязательного сочетания.")
        print("[!] Не закрывай эту сессию, пока не проверишь новый вход. Доступные IP и Fail2ban остаются как были.")
        if input("Включить? Введи ENABLE (Enter = отмена): ").strip() != "ENABLE":
            print("[OK] Отменено, настройки и пароль не изменены.")
            return
        if BACKUPS.is_symlink() or BACKUPS.parent.resolve() != BACKUPS.parent:
            raise PasswordError("Небезопасный каталог backup")
        BACKUPS.mkdir(mode=0o700, parents=True, exist_ok=True)
        BACKUPS.chmod(0o700)
        backup = Path(tempfile.mkdtemp(prefix=dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ-"), dir=BACKUPS))
        atomic_write(backup / "sshd_config", original)
        atomic_write(backup / "root-shadow", (":".join(shadow) + "\n").encode())
        if old_marker is not None:
            atomic_write(backup / "previous-mode", old_marker)
        staging = backup / "candidate.conf"
        atomic_write(staging, candidate.encode())
        print(f"[2/5] Backup: {backup}. Проверяю кандидат через sshd -t и sshd -T.", flush=True)
        runner.run([sshd, "-t", "-f", str(staging)])
        for (user, context), old in before.items():
            validate_candidate(old, effective(runner, sshd, staging, user, context), root=user == "root")
        current_marker = MARKER.read_bytes() if MARKER.exists() else None
        if CONFIG.read_bytes() != original or account_snapshot(runner) != shadow or current_marker != old_marker:
            raise PasswordError("Конфиг или пароль изменён другим процессом. Повтори операцию.")
        password = generate_password()
        config_touched = password_touched = marker_touched = False
        try:
            print("[3/5] Применяю root-only конфиг и устанавливаю случайный пароль.", flush=True)
            config_touched = True
            atomic_write(CONFIG, candidate.encode(), mode)
            password_touched = True
            runner.run(["chpasswd"], data=f"root:{password}\n", secret=True)
            updated = account_snapshot(runner)
            if not updated[1] or updated[1].startswith(("!", "*")) or updated[1] == shadow[1]:
                raise PasswordError("Не подтверждена установка нового пароля")
            print("[4/5] Reload SSH без restart; действующая сессия остаётся открытой.", flush=True)
            runner.run(["systemctl", "reload", service])
            runner.run(["systemctl", "is-active", "--quiet", service])
            for (user, context), old in before.items():
                validate_candidate(old, effective(runner, sshd, CONFIG, user, context), root=user == "root")
            marker_touched = True
            atomic_write(MARKER, (json.dumps({"mode": "root-password-and-key", "backup": str(backup)}) + "\n").encode())
        except BaseException:
            errors = []
            with contextlib.suppress(OSError):
                print(f"[STOP] Выполняю откат. Backup: {backup}", flush=True)
            if password_touched:
                try:
                    runner.run(["chpasswd", "-e"], data=f"root:{shadow[1]}\n", secret=True)
                    runner.run(["chage", "-d", shadow[2] or "-1", "root"], secret=True)
                except (PasswordError, OSError) as exc:
                    errors.append(str(exc))
            if config_touched:
                try:
                    atomic_write(CONFIG, original, mode)
                    runner.run([sshd, "-t", "-f", str(CONFIG)])
                    runner.run(["systemctl", "reload", service])
                except (PasswordError, OSError) as exc:
                    errors.append(str(exc))
            if marker_touched:
                try:
                    if old_marker is None:
                        MARKER.unlink(missing_ok=True)
                    else:
                        atomic_write(MARKER, old_marker)
                except OSError as exc:
                    errors.append(str(exc))
            with contextlib.suppress(OSError):
                if errors:
                    print("[STOP] Откат неполный, НЕ закрывай сессию: " + "; ".join(errors), flush=True)
                else:
                    print("[OK] Прежние конфиг и состояние пароля восстановлены.", flush=True)
            raise
        print("[5/5] Готово. Вход root по паролю и ключу включён; ключевые файлы не изменялись.")
        print("Пароль показан только здесь, в файлах KTO не сохраняется:")
        print(f"root: {password}", flush=True)
        print("Проверь ИЗ НОВОГО окна, подставив IP сервера:")
        port = before[("root", probes[-1])]["port"][0]
        if connection:
            port = connection.split()[3]
        print(f"ssh -p {port} -o PubkeyAuthentication=no -o PreferredAuthentications=password root@IP")
        print("Также проверь прежний вход по ключу. Повторный запуск создаст новый пароль.")


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--connection", default=os.environ.get("SSH_CONNECTION", ""))
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        print("[STOP] Запусти от root")
        return 1
    os.umask(0o077)

    def interrupted(number, _frame):
        raise PasswordError(f"Операция прервана сигналом {number}")

    for name in ("SIGTERM", "SIGHUP"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), interrupted)
    try:
        enable(Runner(), args.connection)
    except (PasswordError, OSError, ValueError) as exc:
        with contextlib.suppress(OSError):
            print(f"[STOP] {exc}", flush=True)
        return 1
    except (KeyboardInterrupt, EOFError):
        with contextlib.suppress(OSError):
            print("[STOP] Прервано", flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
