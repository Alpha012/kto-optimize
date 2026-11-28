#!/usr/bin/env python3
"""Full root SSH & account recovery wizard for kto."""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import getpass
import json
import os
from pathlib import Path
try:
    import pwd
except ImportError:  # pragma: no cover - Windows unit test runner
    pwd = None
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time


RETURN_ROOT_BUILD = "v355"

SSHD_CONFIG = Path("/etc/ssh/sshd_config")
SSHD_CONFIG_D = Path("/etc/ssh/sshd_config.d")
DROPIN_NAME = "00-kto-return-root.conf"
DROPIN_PATH = SSHD_CONFIG_D / DROPIN_NAME
MARKER_PATH = Path("/etc/kto-ssh-password.enabled")
BACKUPS_DIR = Path("/var/backups/kto-return-root")
LOCK_PATH = Path("/run/lock/kto-return-root.lock")
SUDOERS_DIR = Path("/etc/sudoers.d")
ROOT_SSH_DIR = Path("/root/.ssh")
ROOT_AUTH_KEYS = ROOT_SSH_DIR / "authorized_keys"

KEY_TYPE_RE = re.compile(
    r"^(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp(?:256|384|521)|"
    r"sk-(?:ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)$"
)
BLOCKED_SHELLS = ("/nologin", "/false")
REQUIRED_EFFECTIVE = {
    "permitrootlogin": "yes",
    "pubkeyauthentication": "yes",
    "passwordauthentication": "yes",
    "authenticationmethods": "any",
}

PASS_LOWER = "abcdefghjkmnpqrstuvwxyz"
PASS_UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"
PASS_DIGITS = "23456789"


class ReturnRootError(RuntimeError):
    pass


class Runner:
    def run(self, args, *, data=None, secret=False, check=True, timeout=60):
        try:
            result = subprocess.run(
                args,
                input=data,
                capture_output=True,
                text=True,
                errors="replace",
                env=dict(os.environ, LC_ALL="C", DEBIAN_FRONTEND="noninteractive"),
                timeout=timeout,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ReturnRootError(
                f"Не удалось выполнить {args[0]}" + ("" if secret else f": {exc}")
            ) from None
        if check and result.returncode != 0:
            detail = "" if secret else f": {(result.stderr or result.stdout).strip()}"
            raise ReturnRootError(f"Ошибка {args[0]}{detail}")
        return result


def generate_password(length: int = 20) -> str:
    if length < 12:
        length = 12
    alphabet = PASS_LOWER + PASS_UPPER + PASS_DIGITS
    while True:
        chars = [secrets.choice(alphabet) for _ in range(length)]
        password = "".join(chars)
        if (
            sum(c in PASS_LOWER for c in password) >= 2
            and sum(c in PASS_UPPER for c in password) >= 2
            and sum(c in PASS_DIGITS for c in password) >= 2
        ):
            return password


def validate_custom_password(password: str) -> str:
    if not password:
        raise ReturnRootError("Пароль не может быть пустым")
    if any(ch in password for ch in ("\n", "\r", "\0")):
        raise ReturnRootError("Пароль не должен содержать перевод строки или NUL")
    if len(password) < 6:
        raise ReturnRootError("Пароль слишком короткий (минимум 6 символов)")
    return password


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".kto-rr-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.chmod(tmp_name, mode)
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            with contextlib.suppress(OSError):
                os.unlink(tmp_name)


def safe_chown_root(path: Path) -> None:
    if hasattr(os, "chown"):
        with contextlib.suppress(OSError):
            os.chown(path, 0, 0)


def extract_clean_ssh_key(line: str) -> tuple[tuple[str, str], str] | None:
    raw = line.strip()
    if not raw or raw.startswith("#"):
        return None
    parts = raw.split()
    key_idx = None
    for idx, token in enumerate(parts):
        if KEY_TYPE_RE.match(token):
            key_idx = idx
            break
    if key_idx is None or key_idx + 1 >= len(parts):
        return None
    key_type = parts[key_idx]
    key_blob = parts[key_idx + 1]
    if len(key_blob) < 32:
        return None
    prefix = " ".join(parts[:key_idx])
    is_cloud_wrapper = bool(
        prefix
        and (
            "please login as the user" in prefix.lower()
            or "rather than the user" in prefix.lower()
            or ("command=" in prefix.lower() and "exit " in prefix.lower())
        )
    )
    if is_cloud_wrapper:
        cleaned = " ".join(parts[key_idx:])
    else:
        cleaned = raw
    return (key_type, key_blob), cleaned


def merge_authorized_keys(sources: list[str]) -> tuple[str, int, int]:
    """Merge and deduplicate SSH public keys; strip cloud-init root lockout wrappers."""
    seen: set[tuple[str, str]] = set()
    kept: list[str] = []
    unwrapped = 0
    for text in sources:
        for line in text.splitlines():
            parsed = extract_clean_ssh_key(line)
            if not parsed:
                continue
            identity, cleaned = parsed
            if cleaned != line.strip():
                unwrapped += 1
            if identity not in seen:
                seen.add(identity)
                kept.append(cleaned)
    rendered = ("\n".join(kept) + "\n") if kept else ""
    return rendered, len(kept), unwrapped


def render_dropin(*, include_kbd_interactive: bool) -> str:
    lines = [
        "# Managed by kto return-root",
        "PermitRootLogin yes",
        "PubkeyAuthentication yes",
        "PasswordAuthentication yes",
    ]
    if include_kbd_interactive:
        lines.append("KbdInteractiveAuthentication yes")
    lines.extend([
        "AuthenticationMethods any",
        "UsePAM yes",
    ])
    return "\n".join(lines) + "\n"


def prepend_include(sshd_config_text: str, dropin_path: Path) -> str:
    directive = f"Include {dropin_path}"
    lines = sshd_config_text.splitlines(keepends=True)
    filtered = [
        line for line in lines
        if line.strip().lower() != directive.lower()
    ]
    body = "".join(filtered)
    if body and not body.endswith("\n"):
        body += "\n"
    return directive + "\n" + body


def fix_access_control_directives(text: str) -> tuple[str, bool]:
    """Ensure AllowUsers/DenyUsers/AllowGroups/DenyGroups do not block root."""
    changed = False
    out_lines: list[str] = []
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            out_lines.append(line)
            continue
        eol = "\n"
        if line.endswith("\r\n"):
            eol = "\r\n"
        elif not line.endswith("\n"):
            eol = ""
        leading = line[: len(line) - len(line.lstrip(" \t"))]
        tokens = stripped.split()
        key = tokens[0].lower()
        values = tokens[1:]
        if key in ("denyusers", "denygroups"):
            remaining = [
                v for v in values
                if v != "root" and not v.startswith("root@")
            ]
            if len(remaining) != len(values):
                changed = True
                if remaining:
                    out_lines.append(f"{leading}{tokens[0]} {' '.join(remaining)}{eol}")
                else:
                    out_lines.append(f"{leading}# Disabled by kto return-root: {stripped}{eol}")
                continue
        elif key in ("allowusers", "allowgroups"):
            has_root = any(v == "root" or v.startswith("root@") for v in values)
            if values and not has_root:
                changed = True
                out_lines.append(f"{leading}{tokens[0]} {' '.join(values)} root{eol}")
                continue
        out_lines.append(line)
    return "".join(out_lines), changed


def parse_sshd_effective(output: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for line in output.splitlines():
        key, sep, value = line.partition(" ")
        if sep:
            result.setdefault(key.strip().lower(), []).append(value.strip())
    return result


def get_effective_root_config(runner: Runner, sshd_bin: str, config_path: Path) -> dict[str, list[str]]:
    proc = runner.run(
        [sshd_bin, "-T", "-f", str(config_path), "-C", "user=root,host=localhost,addr=127.0.0.1"]
    )
    return parse_sshd_effective(proc.stdout)


def root_is_blocked_by_acl(effective: dict[str, list[str]]) -> list[str]:
    issues: list[str] = []
    deny_users = " ".join(effective.get("denyusers", [])).split()
    if any(u == "root" or u.startswith("root@") for u in deny_users):
        issues.append("denyusers")
    allow_users = " ".join(effective.get("allowusers", [])).split()
    if allow_users and not any(u == "root" or u.startswith("root@") for u in allow_users):
        issues.append("allowusers")
    deny_groups = " ".join(effective.get("denygroups", [])).split()
    if "root" in deny_groups:
        issues.append("denygroups")
    allow_groups = " ".join(effective.get("allowgroups", [])).split()
    if allow_groups and "root" not in allow_groups:
        issues.append("allowgroups")
    return issues


def verify_effective_root(effective: dict[str, list[str]]) -> list[str]:
    problems: list[str] = []
    for key, expected in REQUIRED_EFFECTIVE.items():
        actual = effective.get(key, [])
        if expected not in actual:
            problems.append(f"{key}={' '.join(actual) or 'unset'} (ожидалось {expected})")
    for acl in root_is_blocked_by_acl(effective):
        problems.append(f"root заблокирован директивой {acl}")
    return problems


def ensure_openssh_installed(runner: Runner) -> str:
    sshd = shutil.which("sshd") or ("/usr/sbin/sshd" if Path("/usr/sbin/sshd").is_file() else None)
    if sshd:
        return sshd
    if not shutil.which("apt-get"):
        raise ReturnRootError("OpenSSH server (sshd) не установлен и apt-get не найден")
    print("[!] OpenSSH server не найден — устанавливаю openssh-server...", flush=True)
    runner.run(["apt-get", "update", "-qq"], timeout=120)
    runner.run(["apt-get", "install", "-y", "-qq", "openssh-server"], timeout=180)
    sshd = shutil.which("sshd") or ("/usr/sbin/sshd" if Path("/usr/sbin/sshd").is_file() else None)
    if not sshd:
        raise ReturnRootError("Не удалось найти sshd после установки openssh-server")
    return sshd


def ensure_ssh_runtime_and_hostkeys(runner: Runner) -> list[str]:
    actions: list[str] = []
    run_sshd = Path("/run/sshd")
    if not run_sshd.is_dir():
        run_sshd.mkdir(mode=0o755, parents=True, exist_ok=True)
        safe_chown_root(run_sshd)
        actions.append("создан /run/sshd")

    ssh_dir = SSHD_CONFIG.parent
    has_host_keys = any(ssh_dir.glob("ssh_host_*_key"))
    if not has_host_keys and shutil.which("ssh-keygen"):
        runner.run(["ssh-keygen", "-A"])
        actions.append("сгенерированы host-ключи SSH")
    return actions


def repair_root_account(runner: Runner, password: str) -> list[str]:
    actions: list[str] = []
    passwd_line = runner.run(["getent", "passwd", "root"]).stdout.strip().split(":")
    if len(passwd_line) != 7 or passwd_line[0] != "root" or passwd_line[2] != "0":
        raise ReturnRootError("Локальная учётная запись root (UID 0) не найдена")

    shell = passwd_line[6]
    if any(shell.endswith(bad) for bad in BLOCKED_SHELLS) or not shell:
        target_shell = "/bin/bash" if Path("/bin/bash").is_file() else "/bin/sh"
        runner.run(["usermod", "-s", target_shell, "root"])
        actions.append(f"shell root изменён на {target_shell}")

    shadow_before = runner.run(["getent", "shadow", "root"], secret=True).stdout.strip().split(":")
    if len(shadow_before) >= 2 and shadow_before[1].startswith(("!", "*")):
        if shutil.which("usermod"):
            runner.run(["usermod", "-U", "root"], check=False)
        elif shutil.which("passwd"):
            runner.run(["passwd", "-u", "root"], check=False)
        actions.append("снята блокировка учётной записи root")

    if shutil.which("chage"):
        runner.run(["chage", "-E", "-1", "-M", "99999", "-I", "-1", "-m", "0", "root"], check=False)

    runner.run(["chpasswd"], data=f"root:{password}\n", secret=True)
    shadow_after = runner.run(["getent", "shadow", "root"], secret=True).stdout.strip().split(":")
    if len(shadow_after) < 2 or not shadow_after[1] or shadow_after[1].startswith(("!", "*")):
        raise ReturnRootError("Не удалось подтвердить установку пароля root в /etc/shadow")
    actions.append("пароль root установлен и проверен")
    return actions


def repair_root_ssh_keys(caller_user: str, base_key: str) -> list[str]:
    sources: list[str] = []
    if ROOT_AUTH_KEYS.is_file():
        with contextlib.suppress(OSError):
            sources.append(ROOT_AUTH_KEYS.read_text(encoding="utf-8", errors="replace"))

    if caller_user and caller_user != "root":
        caller_home = Path("/home") / caller_user
        if pwd is not None:
            with contextlib.suppress(KeyError):
                caller_home = Path(pwd.getpwnam(caller_user).pw_dir)
        caller_keys = caller_home / ".ssh" / "authorized_keys"
        if caller_keys.is_file():
            with contextlib.suppress(OSError):
                sources.append(caller_keys.read_text(encoding="utf-8", errors="replace"))

    if base_key.strip():
        sources.append(base_key.strip())

    merged, count, unwrapped = merge_authorized_keys(sources)
    if not count:
        return []

    ROOT_SSH_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(ROOT_SSH_DIR, 0o700)
    safe_chown_root(ROOT_SSH_DIR)
    atomic_write(ROOT_AUTH_KEYS, merged.encode("utf-8"), 0o600)
    safe_chown_root(ROOT_AUTH_KEYS)

    notes = [f"SSH-ключи root: {count} шт."]
    if unwrapped:
        notes.append(f"убрано cloud-init заглушек: {unwrapped}")
    return notes


def detect_ssh_service(runner: Runner) -> str:
    for svc in ("ssh.service", "sshd.service"):
        if runner.run(["systemctl", "is-active", "--quiet", svc], check=False).returncode == 0:
            return svc
    for svc in ("ssh.service", "sshd.service"):
        probe = runner.run(["systemctl", "cat", svc], check=False)
        if probe.returncode == 0:
            return svc
    return "ssh.service"


def port_is_listening(runner: Runner, port: int) -> bool:
    if shutil.which("ss"):
        out = runner.run(["ss", "-tlnH"], check=False).stdout
        pattern = re.compile(rf"(?:^|\s)\S*:{port}(?:\s|$)")
        return any(pattern.search(line) for line in out.splitlines())
    return True


def reload_or_start_ssh(runner: Runner, service: str, port: int) -> str:
    was_active = runner.run(["systemctl", "is-active", "--quiet", service], check=False).returncode == 0
    if was_active:
        rel = runner.run(["systemctl", "reload", service], check=False)
        if rel.returncode == 0 and runner.run(["systemctl", "is-active", "--quiet", service], check=False).returncode == 0:
            return f"{service} перезагружен (reload, текущая сессия сохранена)"

    runner.run(["systemctl", "reset-failed", service], check=False)
    # Ubuntu 24.04 socket activation may conflict or stay inactive; ensure the service itself is active.
    if runner.run(["systemctl", "is-active", "--quiet", "ssh.socket"], check=False).returncode == 0:
        runner.run(["systemctl", "disable", "--now", "ssh.socket"], check=False)
    runner.run(["systemctl", "enable", service], check=False)
    runner.run(["systemctl", "restart", service])

    for _ in range(16):
        active = runner.run(["systemctl", "is-active", "--quiet", service], check=False).returncode == 0
        if active and port_is_listening(runner, port):
            return f"{service} запущен и слушает порт {port}/tcp"
        time.sleep(0.25)

    active = runner.run(["systemctl", "is-active", "--quiet", service], check=False).returncode == 0
    if not active:
        raise ReturnRootError(f"Служба {service} не перешла в состояние active после перезапуска")
    return f"{service} запущен (порт {port}/tcp)"


def ensure_firewall_and_fail2ban(runner: Runner, port: int, connection: str) -> list[str]:
    notes: list[str] = []
    if shutil.which("ufw"):
        status = runner.run(["ufw", "status"], check=False).stdout
        if "Status: active" in status:
            if not re.search(rf"\b{port}/tcp\b.*\bALLOW\b", status):
                runner.run(["ufw", "allow", f"{port}/tcp"], check=False)
                notes.append(f"UFW: открыт порт {port}/tcp")

    peer_ip = ""
    if connection:
        parts = connection.split()
        if parts:
            peer_ip = parts[0]

    if peer_ip and shutil.which("fail2ban-client"):
        active = runner.run(["systemctl", "is-active", "--quiet", "fail2ban"], check=False).returncode == 0
        if active:
            runner.run(["fail2ban-client", "set", "sshd", "unbanip", peer_ip], check=False)
            notes.append(f"Fail2ban: проверен/разбанен IP {peer_ip}")
    return notes


def configure_caller_nopasswd(runner: Runner, caller_user: str) -> str | None:
    if not caller_user or caller_user == "root":
        return None
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", caller_user):
        return None
    if not SUDOERS_DIR.is_dir():
        return None

    target = SUDOERS_DIR / f"90-kto-nopasswd-{caller_user}"
    content = f"{caller_user} ALL=(ALL) NOPASSWD:ALL\n"
    fd, tmp_name = tempfile.mkstemp(prefix=".kto-sudoers-", dir=SUDOERS_DIR)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
        os.chmod(tmp_name, 0o440)
        safe_chown_root(Path(tmp_name))
        if shutil.which("visudo"):
            check = runner.run(["visudo", "-cf", tmp_name], check=False)
            if check.returncode != 0:
                return None
        os.replace(tmp_name, target)
        return f"sudo NOPASSWD включён для {caller_user}"
    finally:
        if os.path.exists(tmp_name):
            with contextlib.suppress(OSError):
                os.unlink(tmp_name)


def detect_server_ip(runner: Runner, connection: str) -> str:
    if connection:
        parts = connection.split()
        if len(parts) >= 3 and parts[2] not in ("127.0.0.1", "::1"):
            return parts[2]
    if shutil.which("ip"):
        out = runner.run(["ip", "-4", "route", "get", "1.1.1.1"], check=False).stdout
        match = re.search(r"\bsrc\s+(\d+\.\d+\.\d+\.\d+)\b", out)
        if match:
            return match.group(1)
    if shutil.which("hostname"):
        ips = runner.run(["hostname", "-I"], check=False).stdout.split()
        for ip in ips:
            if "." in ip and not ip.startswith("127."):
                return ip
    return "<IP>"


def choose_password_interactive(*, auto: bool) -> tuple[str, bool]:
    if auto or not (sys.stdin.isatty() and sys.stdout.isatty()):
        return generate_password(), True

    print("Выбери пароль для root:")
    print("  1) Сгенерировать автоматически (рекомендуется) [Enter]")
    print("  2) Ввести свой пароль вручную")
    choice = input("Выбор [1]: ").strip()
    if choice == "2":
        while True:
            first = getpass.getpass("Новый пароль для root: ")
            try:
                validate_custom_password(first)
            except ReturnRootError as exc:
                print(f"[!] {exc}")
                continue
            second = getpass.getpass("Повтори пароль: ")
            if first != second:
                print("[!] Пароли не совпадают, попробуй ещё раз.")
                continue
            return first, False
    return generate_password(), True


@contextlib.contextmanager
def operation_lock():
    import fcntl

    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOCK_PATH.open("a") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ReturnRootError("Уже выполняется другая операция возвращения root") from None
        yield


def return_root(
    runner: Runner,
    *,
    connection: str = "",
    caller_user: str = "",
    base_key: str = "",
    auto: bool = False,
) -> dict:
    with operation_lock():
        print("==========================================", flush=True)
        print("            ВОЗВРАЩЕНИЕ ROOT              ", flush=True)
        print("==========================================", flush=True)

        password, was_generated = choose_password_interactive(auto=auto)

        print("[1/6] Проверяю OpenSSH, /run/sshd и host-ключи...", flush=True)
        sshd_bin = ensure_openssh_installed(runner)
        runtime_notes = ensure_ssh_runtime_and_hostkeys(runner)

        BACKUPS_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(BACKUPS_DIR, 0o700)
        backup_dir = Path(
            tempfile.mkdtemp(
                prefix=dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ-"),
                dir=BACKUPS_DIR,
            )
        )
        os.chmod(backup_dir, 0o700)

        original_sshd_config = SSHD_CONFIG.read_bytes() if SSHD_CONFIG.exists() else None
        original_sshd_mode = stat.S_IMODE(SSHD_CONFIG.stat().st_mode) if SSHD_CONFIG.exists() else 0o644
        original_dropin = DROPIN_PATH.read_bytes() if DROPIN_PATH.exists() else None
        original_marker = MARKER_PATH.read_bytes() if MARKER_PATH.exists() else None
        shadow_before_proc = runner.run(["getent", "shadow", "root"], secret=True, check=False)
        original_shadow = (
            shadow_before_proc.stdout.strip().split(":")
            if shadow_before_proc.returncode == 0 and ":" in shadow_before_proc.stdout
            else None
        )

        if original_sshd_config is not None:
            atomic_write(backup_dir / "sshd_config", original_sshd_config)
        if original_dropin is not None:
            atomic_write(backup_dir / DROPIN_NAME, original_dropin)
        if original_shadow is not None:
            atomic_write(backup_dir / "root-shadow", (":".join(original_shadow) + "\n").encode("utf-8"))
        if ROOT_AUTH_KEYS.is_file():
            with contextlib.suppress(OSError):
                atomic_write(backup_dir / "authorized_keys", ROOT_AUTH_KEYS.read_bytes())

        print("[2/6] Разблокирую учётную запись root и ставлю пароль...", flush=True)
        account_notes = repair_root_account(runner, password)
        password_changed = True

        print("[3/6] Проверяю SSH-ключи root (чищу cloud-init заглушки)...", flush=True)
        key_notes = repair_root_ssh_keys(caller_user, base_key)

        print("[4/6] Настраиваю sshd_config для входа root по паролю и ключу...", flush=True)
        SSHD_CONFIG_D.mkdir(mode=0o755, parents=True, exist_ok=True)

        # Probe current effective config to check KbdInteractiveAuthentication support
        include_kbd = False
        if SSHD_CONFIG.exists():
            probe = runner.run([sshd_bin, "-T", "-f", str(SSHD_CONFIG)], check=False)
            if probe.returncode == 0 and "kbdinteractiveauthentication " in probe.stdout.lower():
                include_kbd = True

        modified_extra_files: dict[Path, tuple[bytes, int]] = {}
        try:
            dropin_text = render_dropin(include_kbd_interactive=include_kbd)
            atomic_write(DROPIN_PATH, dropin_text.encode("utf-8"), 0o644)
            safe_chown_root(DROPIN_PATH)

            base_text = (
                original_sshd_config.decode("utf-8", errors="replace")
                if original_sshd_config is not None
                else ""
            )
            new_main_text = prepend_include(base_text, DROPIN_PATH)
            new_main_text, main_acl_fixed = fix_access_control_directives(new_main_text)
            atomic_write(SSHD_CONFIG, new_main_text.encode("utf-8"), original_sshd_mode)
            safe_chown_root(SSHD_CONFIG)

            # Check effective root config and fix any AllowUsers/DenyUsers in sshd_config.d
            effective = get_effective_root_config(runner, sshd_bin, SSHD_CONFIG)
            acl_issues = root_is_blocked_by_acl(effective)
            if acl_issues:
                for conf_file in sorted(SSHD_CONFIG_D.glob("*.conf")):
                    if conf_file == DROPIN_PATH or not conf_file.is_file():
                        continue
                    raw_bytes = conf_file.read_bytes()
                    fixed_text, changed = fix_access_control_directives(
                        raw_bytes.decode("utf-8", errors="replace")
                    )
                    if changed:
                        file_mode = stat.S_IMODE(conf_file.stat().st_mode)
                        modified_extra_files[conf_file] = (raw_bytes, file_mode)
                        atomic_write(backup_dir / f"dropin-{conf_file.name}", raw_bytes)
                        atomic_write(conf_file, fixed_text.encode("utf-8"), file_mode)
                        safe_chown_root(conf_file)
                effective = get_effective_root_config(runner, sshd_bin, SSHD_CONFIG)

            runner.run([sshd_bin, "-t", "-f", str(SSHD_CONFIG)])
            problems = verify_effective_root(effective)
            if problems:
                raise ReturnRootError(
                    "Эффективный конфиг sshd не подтвердил доступ root: " + "; ".join(problems)
                )

            ports = effective.get("port", ["22"])
            ssh_port = int(ports[0]) if ports and ports[0].isdigit() else 22

            print("[5/6] Перезагружаю SSH, проверяю UFW/Fail2ban и права sudo...", flush=True)
            service = detect_ssh_service(runner)
            service_note = reload_or_start_ssh(runner, service, ssh_port)

            marker_payload = json.dumps(
                {
                    "mode": "root-password-and-key",
                    "source": "return-root",
                    "build": RETURN_ROOT_BUILD,
                    "backup": str(backup_dir),
                },
                ensure_ascii=False,
            ) + "\n"
            atomic_write(MARKER_PATH, marker_payload.encode("utf-8"), 0o600)
            safe_chown_root(MARKER_PATH)
        except BaseException:
            with contextlib.suppress(OSError):
                print(f"[STOP] Ошибка при настройке SSH — откатываю конфиг (backup: {backup_dir})", flush=True)
            if password_changed and original_shadow is not None and len(original_shadow) >= 3:
                with contextlib.suppress(ReturnRootError, OSError):
                    runner.run(["chpasswd", "-e"], data=f"root:{original_shadow[1]}\n", secret=True, check=False)
                    if shutil.which("chage"):
                        runner.run(["chage", "-d", original_shadow[2] or "-1", "root"], secret=True, check=False)
            for path, (old_bytes, old_mode) in modified_extra_files.items():
                with contextlib.suppress(OSError):
                    atomic_write(path, old_bytes, old_mode)
            if original_sshd_config is not None:
                with contextlib.suppress(OSError):
                    atomic_write(SSHD_CONFIG, original_sshd_config, original_sshd_mode)
            if original_dropin is None:
                with contextlib.suppress(OSError):
                    DROPIN_PATH.unlink(missing_ok=True)
            else:
                with contextlib.suppress(OSError):
                    atomic_write(DROPIN_PATH, original_dropin, 0o644)
            if original_marker is None:
                with contextlib.suppress(OSError):
                    MARKER_PATH.unlink(missing_ok=True)
            else:
                with contextlib.suppress(OSError):
                    atomic_write(MARKER_PATH, original_marker, 0o600)
            raise

        net_notes = ensure_firewall_and_fail2ban(runner, ssh_port, connection)
        sudo_note = configure_caller_nopasswd(runner, caller_user)

        server_ip = detect_server_ip(runner, connection)
        ssh_cmd = f"ssh root@{server_ip}" if ssh_port == 22 else f"ssh -p {ssh_port} root@{server_ip}"

        print("[6/6] Готово!", flush=True)
        print("", flush=True)
        print("==========================================", flush=True)
        print("         ВОЗВРАЩЕНИЕ ROOT: ГОТОВО         ", flush=True)
        print("==========================================", flush=True)
        print("Логин:       root", flush=True)
        print(f"Пароль:      {password}", flush=True)
        print(f"SSH-порт:    {ssh_port}/tcp", flush=True)
        print(f"IP сервера:  {server_ip}", flush=True)
        print("Режим входа: пароль + SSH-ключ", flush=True)
        print(f"Команда SSH: {ssh_cmd}", flush=True)
        print(f"Backup:      {backup_dir}", flush=True)
        print("==========================================", flush=True)

        summary_items = runtime_notes + account_notes + key_notes + [service_note] + net_notes
        if sudo_note:
            summary_items.append(sudo_note)
        for item in summary_items:
            print(f"  [OK] {item}", flush=True)

        print("", flush=True)
        if was_generated:
            print("[!] Сохрани пароль — в файлы и логи kto он НЕ записывается.", flush=True)
        print("[!] Проверь вход под root ИЗ НОВОГО ОКНА, прежде чем закрывать эту сессию.", flush=True)

        return {
            "password": password,
            "port": ssh_port,
            "ip": server_ip,
            "ssh_cmd": ssh_cmd,
            "backup": str(backup_dir),
            "summary": summary_items,
        }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--connection", default=os.environ.get("SSH_CONNECTION", ""))
    parser.add_argument("--caller-user", default=os.environ.get("SUDO_USER", ""))
    parser.add_argument("--base-key", default="")
    parser.add_argument("--auto", action="store_true", help="Сгенерировать пароль без интерактивного запроса")
    args = parser.parse_args(argv)

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("[STOP] Запусти от root или через sudo", flush=True)
        return 1
    os.umask(0o077)

    def interrupted(sig_num, _frame):
        raise ReturnRootError(f"Операция прервана сигналом {sig_num}")

    for sig_name in ("SIGTERM", "SIGHUP"):
        if hasattr(signal, sig_name):
            signal.signal(getattr(signal, sig_name), interrupted)

    try:
        return_root(
            Runner(),
            connection=args.connection,
            caller_user=args.caller_user,
            base_key=args.base_key,
            auto=args.auto,
        )
    except (ReturnRootError, OSError, ValueError) as exc:
        with contextlib.suppress(OSError):
            print(f"[STOP] {exc}", flush=True)
        return 1
    except (KeyboardInterrupt, EOFError):
        with contextlib.suppress(OSError):
            print("[STOP] Прервано пользователем", flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
