#!/usr/bin/env python3
"""Scoped removal of proxy packages; never a reset of the host or SSH access."""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile


BACKUPS = Path("/var/backups/kto-server-cleanup")
LOCK = Path("/run/lock/kto-server-cleanup.lock")
MAX_BACKUP_BYTES = 512 * 1024 * 1024
PRESERVED = (
    "SSH, пароли и authorized_keys; UFW и Fail2ban; IP, DNS и маршруты; "
    "ядро/GRUB и sysctl; сертификаты, сайты /var/www, логи и данные Docker."
)
PACKAGE_PATTERNS = {
    "haproxy": re.compile(r"haproxy(?:-doc)?"),
    "nginx": re.compile(r"(?:nginx(?:-[a-z0-9+.-]+)?|libnginx-mod-[a-z0-9+.-]+)"),
    "docker": re.compile(r"(?:docker-ce(?:-cli|-rootless-extras)?|docker\.io|docker-cli|"
                         r"docker-compose(?:-v2|-plugin)?|docker-buildx(?:-plugin)?|"
                         r"docker-model-plugin|containerd(?:\.io)?)"),
}
UNITS = {
    "haproxy": (
        "kto-haproxy-guard.timer", "kto-haproxy-guard.service",
        "kto-haproxy-firewall.service", "kto-haproxy-bandwidth.service", "haproxy.service",
    ),
    "nginx": ("kto-nginx-logrotate.timer", "kto-nginx-logrotate.service", "nginx.service"),
    "docker": ("docker.socket", "docker.service", "containerd.service"),
}
PATHS = {
    "haproxy": (
        "/etc/haproxy", "/etc/systemd/system/haproxy.service.d",
        "/usr/local/sbin/kto-haproxy-guard", "/usr/local/sbin/kto-haproxy-firewall",
        "/usr/local/sbin/kto-haproxy-bandwidth", "/etc/kto-haproxy-bandwidth.conf",
    ),
    "nginx": (
        "/etc/nginx", "/etc/kto-nginx", "/etc/systemd/system/nginx.service.d",
        "/usr/local/sbin/kto-nginx", "/etc/logrotate.d/kto-nginx",
        "/etc/letsencrypt/renewal-hooks/deploy/50-kto-nginx",
    ),
    "docker": ("/etc/docker", "/etc/containerd", "/etc/systemd/system/docker.service.d",
               "/etc/systemd/system/docker.socket.d", "/etc/systemd/system/containerd.service.d"),
}
MARKERS = (Path("/etc/kto-haproxy-guard.disabled"), Path("/etc/kto-haproxy-routes.disabled"))
PROTECTED = (
    Path("/etc/ssh"), Path("/root/.ssh/authorized_keys"), Path("/etc/passwd"), Path("/etc/shadow"),
    Path("/etc/netplan"), Path("/etc/systemd/network"), Path("/etc/ufw"), Path("/etc/fail2ban"),
)
CORE_SERVICES = ("ssh.service", "sshd.service", "ssh.socket", "fail2ban.service", "ufw.service",
                 "kto-additional-ip-routes.timer", "kto-primary-egress.timer")
PROC_NAMES = {"haproxy": {"haproxy"}, "nginx": {"nginx"}, "docker": {"dockerd", "containerd"}}


class CleanupError(RuntimeError):
    pass


def say(text: str, kind: str = "..") -> None:
    print(f"[{kind}] {text}", flush=True)


class Runner:
    def __init__(self) -> None:
        self.log: Path | None = None

    def record(self, text: str) -> None:
        if self.log:
            with self.log.open("a", encoding="utf-8") as out:
                out.write(text + "\n")

    def run(self, args: list[str], *, check: bool = True, timeout: int = 30) -> subprocess.CompletedProcess:
        env = dict(os.environ, LC_ALL="C")
        for key in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"):
            env.pop(key, None)
        self.record("$ " + " ".join(args))
        try:
            result = subprocess.run(args, capture_output=True, text=True, errors="replace", env=env, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise CleanupError(f"Не удалось выполнить {args[0]}: {exc}") from exc
        self.record(result.stdout + result.stderr)
        if check and result.returncode:
            raise CleanupError(f"{' '.join(args)}\n{result.stdout}{result.stderr}")
        return result

    def purge(self, packages: list[str]) -> None:
        # Do not time out dpkg in the middle of a transaction.
        args = apt_command(packages, simulate=False)
        self.record("$ " + " ".join(args))
        say("Удаление пакетов APT. Не прерывай эту операцию.")
        with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              text=True, errors="replace", env=dict(os.environ, LC_ALL="C", NEEDRESTART_MODE="l")) as proc:
            for line in proc.stdout:
                print(line, end="", flush=True)
                self.record(line.rstrip())
            if proc.wait():
                raise CleanupError("APT завершился с ошибкой; смотри operation.log в резервной копии")


def package_component(name: str) -> str | None:
    if not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*(?::[a-z0-9][a-z0-9-]*)?", name):
        return None
    base = name.split(":", 1)[0]
    return next((group for group, pattern in PACKAGE_PATTERNS.items() if pattern.fullmatch(base)), None)


def installed_packages(runner: Runner, components: tuple[str, ...]) -> list[str]:
    result = runner.run(["dpkg-query", "-W", "-f=${binary:Package}\t${db:Status-Status}\n"])
    packages = []
    for line in result.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) != 2:
            raise CleanupError("Не удалось разобрать список пакетов dpkg-query")
        name, state = fields
        if package_component(name) in components and state not in ("not-installed", "unknown"):
            packages.append(name)
    return sorted(packages)


def apt_command(packages: list[str], *, simulate: bool) -> list[str]:
    return ["apt-get", "-s" if simulate else "-y", "-o", "APT::Get::AutomaticRemove=false",
            "-o", "DPkg::Lock::Timeout=30", "purge", *packages]


def validate_apt_plan(output: str, packages: list[str]) -> None:
    allowed = set(packages) | {p.split(":", 1)[0] for p in packages}
    seen = set()
    for line in output.splitlines():
        fields = line.split()
        if not fields:
            continue
        if fields[0] in ("Inst", "Conf"):
            raise CleanupError(f"STOP: APT собирается устанавливать/настраивать пакеты: {line}")
        if fields[0] in ("Remv", "Purg"):
            if len(fields) < 2 or fields[1] not in allowed or package_component(fields[1]) is None:
                raise CleanupError(f"STOP: APT хочет удалить пакет вне выбранного набора: {line}")
            seen.add(fields[1].split(":", 1)[0])
    if any(p.split(":", 1)[0] not in seen for p in packages):
        raise CleanupError("STOP: APT не подтвердил удаление всех выбранных пакетов")


def unit_states(runner: Runner, units: tuple[str, ...]) -> dict[str, dict[str, str]]:
    states = {}
    for unit in units:
        result = runner.run(["systemctl", "show", unit, "--no-pager", "-p", "LoadState",
                             "-p", "ActiveState", "-p", "UnitFileState"], check=False)
        data = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        if not data.get("LoadState"):
            raise CleanupError(f"Не удалось прочитать состояние {unit}: {result.stderr}")
        states[unit] = data
    return states


def process_rows(runner: Runner) -> list[tuple[int, str]]:
    rows = []
    for line in runner.run(["ps", "-eo", "uid=,comm="]).stdout.splitlines():
        fields = line.split(None, 1)
        if len(fields) != 2 or not fields[0].isdigit():
            raise CleanupError("Не удалось прочитать список процессов")
        rows.append((int(fields[0]), fields[1]))
    return rows


def check_managed_processes(runner: Runner, components: tuple[str, ...], states: dict) -> None:
    names = set().union(*(PROC_NAMES[c] for c in components))
    for uid, name in process_rows(runner):
        if "docker" in components and uid != 0 and (name == "dockerd" or name.startswith("dockerd-rootless")):
            raise CleanupError("Обнаружен rootless Docker. Нужен отдельный аудит перед удалением.")
        if name in names:
            service = ("docker" if name == "dockerd" else name) + ".service"
            if states.get(service, {}).get("ActiveState") != "active":
                raise CleanupError(f"Есть процесс {name} вне активного {service}. "
                                   "Не трогаю конфиги ручной установки; сначала проверь её отдельно.")


def has_data(path: Path) -> bool:
    return path.exists() and (not path.is_dir() or next(path.iterdir(), None) is not None)


def docker_preflight(runner: Runner, packages: list[str], states: dict) -> None:
    docker_needed = any(package_component(p) == "docker" for p in packages) or any(
        v.get("ActiveState") in ("active", "activating") for k, v in states.items() if k in UNITS["docker"])
    if not docker_needed:
        return
    if any(uid != 0 and (name == "dockerd" or name.startswith("dockerd-rootless"))
           for uid, name in process_rows(runner)):
        raise CleanupError("Обнаружен rootless Docker. Сначала останови и проверь его отдельно.")
    if shutil.which("docker"):
        if states.get("docker.service", {}).get("ActiveState") != "active":
            raise CleanupError("Docker не запущен. Не активирую его через docker.socket без разрешения. "
                               "Проверь Docker отдельно или выбери удаление только прокси.")
        result = runner.run(["docker", "--host", "unix:///var/run/docker.sock", "ps", "-a",
                             "--format", "{{json .}}"], check=False, timeout=15)
        if result.returncode:
            raise CleanupError("Docker API недоступен: нельзя подтвердить отсутствие контейнеров. "
                               "Выбери удаление только HAProxy/Nginx или сначала проверь Docker.\n" + result.stderr)
        containers = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        if any(not isinstance(container, dict) for container in containers):
            raise CleanupError("Не удалось разобрать список контейнеров Docker; удаление остановлено")
        if containers:
            names = ", ".join(str(c.get("Names", c.get("ID", "?"))) for c in containers)
            raise CleanupError("Docker содержит контейнеры (включая остановленные): " + names +
                               ". Они НЕ удалены. Перенеси/удали их самостоятельно или выбери только прокси.")
    elif has_data(Path("/var/lib/docker")) or states.get("docker.service", {}).get("ActiveState") == "active":
        raise CleanupError("Есть данные/сервис Docker, но нет docker CLI. Нужен ручной аудит.")
    if states.get("containerd.service", {}).get("ActiveState") == "active":
        result = runner.run(["ctr", "--address", "/run/containerd/containerd.sock", "namespaces", "list", "--quiet"])
        foreign = [line for line in result.stdout.splitlines() if line.strip() not in ("", "moby")]
        if foreign:
            raise CleanupError("containerd используется вне Docker: " + ", ".join(foreign))
        if "moby" in result.stdout.splitlines():
            tasks = runner.run(["ctr", "--address", "/run/containerd/containerd.sock", "--namespace", "moby",
                                "tasks", "list", "--quiet"])
            if tasks.stdout.strip():
                raise CleanupError("В containerd остались активные задачи moby; Docker пока не удаляется")
    elif has_data(Path("/var/lib/containerd")):
        raise CleanupError("containerd остановлен, но содержит данные. Нельзя исключить другие нагрузки.")


def selected_paths(components: tuple[str, ...]) -> list[Path]:
    result = [Path(p) for group in components for p in PATHS[group]]
    for group in components:
        for unit in UNITS[group]:
            # Keep vendor unit files under /usr/lib owned by dpkg; quarantine local overrides only.
            result += [Path("/etc/systemd/system") / unit,
                       Path("/etc/systemd/system") / (unit + ".d")]
    return sorted(set(result), key=str)


def tree_entries(path: Path):
    if not path.exists() and not path.is_symlink():
        return
    yield path
    if path.is_dir() and not path.is_symlink():
        for child in sorted(path.iterdir()):
            yield from tree_entries(child)


def mount_points() -> set[str]:
    points = set()
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        if len(fields) < 6:
            raise CleanupError("Не удалось прочитать /proc/self/mountinfo")
        points.add(re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), fields[4]))
    return points


def check_paths(paths: list[Path]) -> int:
    mounts = mount_points()
    total = 0
    for root in paths:
        # Do not move a bind mount, a mounted child, or traverse a symlink in a parent.
        if root.parent.resolve() != root.parent:
            raise CleanupError(f"Родительский каталог перенаправлен symlink: {root}")
        if any(Path(point) == root or root in Path(point).parents for point in mounts):
            raise CleanupError(f"В конфиге есть отдельное монтирование: {root}; нужен ручной перенос")
        for entry in tree_entries(root):
            mode = entry.lstat().st_mode
            if stat.S_ISREG(mode):
                total += entry.lstat().st_size
            elif not (stat.S_ISDIR(mode) or stat.S_ISLNK(mode)):
                raise CleanupError(f"Необычный файл в конфигурации: {entry}")
            if total > MAX_BACKUP_BYTES:
                raise CleanupError("Конфигурации больше 512 MiB. Нужен отдельный backup перед удалением.")
    return total


def fingerprint(paths=None) -> dict[str, str]:
    paths = PROTECTED if paths is None else paths
    result = {}
    for root in paths:
        entries = list(tree_entries(root))
        if not entries:
            result[str(root)] = "absent"
        for entry in entries:
            info = entry.lstat()
            meta = f"{info.st_mode}:{info.st_uid}:{info.st_gid}:"
            if entry.is_symlink():
                value = "link:" + os.readlink(entry)
            elif entry.is_file():
                value = hashlib.sha256(entry.read_bytes()).hexdigest()
            else:
                value = "directory"
            result[str(entry)] = meta + value
    return result


@dataclasses.dataclass
class Plan:
    components: tuple[str, ...]
    packages: list[str]
    units: dict[str, dict[str, str]]
    paths: list[Path]
    apt_output: str


def preflight(runner: Runner, components: tuple[str, ...]) -> Plan:
    audit = runner.run(["dpkg", "--audit"])
    if audit.stdout.strip() or audit.stderr.strip():
        raise CleanupError("Есть незавершённые пакеты. Ничего не отключено. Сначала исправь APT отдельно:\n" +
                           audit.stdout + audit.stderr + "\nДля просмотра плана: apt-get -s --fix-broken install")
    packages = installed_packages(runner, components)
    units = unit_states(runner, tuple(u for group in components for u in UNITS[group]))
    check_managed_processes(runner, components, units)
    if "docker" in components:
        docker_preflight(runner, packages, units)
    output = ""
    if packages:
        result = runner.run(apt_command(packages, simulate=True), timeout=90, check=False)
        if result.returncode:
            raise CleanupError("Проверка APT не прошла; сервисы ещё не отключены:\n" + result.stdout + result.stderr)
        output = result.stdout
        validate_apt_plan(output, packages)
    paths = selected_paths(components)
    size = check_paths(paths)
    if shutil.disk_usage("/var/backups").free < max(64 * 1024 * 1024, size * 2 + 16 * 1024 * 1024):
        raise CleanupError("Не хватает места в /var/backups для конфигураций. Автоочистка не запускается.")
    return Plan(components, packages, units, paths, output)


def print_plan(plan: Plan) -> None:
    say(f"Сервер: {socket.gethostname()}; выбрано: {', '.join(plan.components)}")
    say("Пакеты: " + (", ".join(plan.packages) or "не установлены"))
    for unit, state in plan.units.items():
        print(f"  {unit:38s} {state.get('ActiveState', '?')}")
    existing = [str(p) for p in plan.paths if p.exists() or p.is_symlink()]
    if existing:
        say("Конфигурации/локальные unit-файлы будут перенесены в backup:")
        print("\n".join("  " + p for p in existing))
    say("СОХРАНЯЮТСЯ: " + PRESERVED)
    if "haproxy" in plan.components:
        say("Штатный stop kto-haproxy-bandwidth снимает его лимиты tc; IP и маршруты не меняются.")
    if "docker" in plan.components:
        say("Удаление Docker отключит его сеть; данные /var/lib/docker и /var/lib/containerd останутся.")


def write_manifest(backup: Path, manifest: dict) -> None:
    path = backup / "manifest.json.tmp"
    path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)
    path.replace(backup / "manifest.json")


def backup_configs(plan: Plan, runner: Runner) -> Path:
    if BACKUPS.is_symlink() or BACKUPS.parent.resolve() != BACKUPS.parent:
        raise CleanupError("Каталог резервных копий не должен быть symlink")
    BACKUPS.mkdir(mode=0o700, parents=True, exist_ok=True)
    BACKUPS.chmod(0o700)
    backup = Path(tempfile.mkdtemp(prefix=dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ-"), dir=BACKUPS))
    runner.log = backup / "operation.log"
    runner.record("Backup: " + str(backup))
    (backup / "apt-plan.txt").write_text(plan.apt_output, encoding="utf-8")
    with tarfile.open(backup / "configs.tar", "w", dereference=False) as archive:
        seen = set()
        for root in plan.paths:
            for entry in tree_entries(root):
                if str(entry) not in seen:
                    archive.add(entry, arcname=entry.relative_to(entry.anchor).as_posix(), recursive=False)
                    seen.add(str(entry))
    return backup


@contextlib.contextmanager
def cleanup_lock():
    import fcntl
    LOCK.parent.mkdir(parents=True, exist_ok=True)
    with LOCK.open("a") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise CleanupError("Другой процесс очистки уже работает") from exc
        yield


def verify(runner: Runner, plan: Plan, before: dict, core: dict) -> None:
    if fingerprint() != before:
        raise CleanupError("Изменились защищённые файлы SSH/паролей/сети. Автоматический откат чужих изменений не выполняется.")
    current = unit_states(runner, CORE_SERVICES)
    for unit, state in core.items():
        if state.get("ActiveState") == "active" and current[unit].get("ActiveState") != "active":
            raise CleanupError(f"Защищённый сервис больше не активен: {unit}")
    remaining = installed_packages(runner, plan.components)
    if remaining:
        raise CleanupError("Остались пакеты: " + ", ".join(remaining))
    audit = runner.run(["dpkg", "--audit"])
    if audit.stdout.strip() or audit.stderr.strip():
        raise CleanupError("После удаления dpkg требует внимания:\n" + audit.stdout + audit.stderr)
    names = set().union(*(PROC_NAMES[c] for c in plan.components))
    remaining_processes = [name for _, name in process_rows(runner) if name in names]
    if remaining_processes:
        raise CleanupError("Остались процессы (возможно, ручная установка): " + ", ".join(remaining_processes))
    for unit, state in unit_states(runner, tuple(plan.units)).items():
        if state.get("ActiveState") in ("active", "activating", "deactivating"):
            raise CleanupError(f"Сервис не остановлен: {unit}")


def remove(runner: Runner, components: tuple[str, ...]) -> None:
    runner.log = None
    with cleanup_lock():
        say("1/6 Проверяю пакеты, APT, контейнеры и место для backup")
        plan = preflight(runner, components)
        print_plan(plan)
        if not sys.stdin.isatty():
            raise CleanupError("Удаление требует интерактивного терминала и подтверждения DELETE")
        say("Сайты и прокси выбранных сервисов перестанут работать. Это не сброс Ubuntu.", "!")
        if input("Для удаления введи DELETE (Enter = отмена): ").strip() != "DELETE":
            say("Отменено. Сервисы и пакеты не изменены.")
            return
        # Recheck after the user has had time to review; do not act on a stale package/container list.
        fresh = preflight(runner, components)
        if fresh.packages != plan.packages:
            raise CleanupError("Набор пакетов изменился. Запусти проверку заново.")
        plan = fresh
        before = fingerprint()
        core = unit_states(runner, CORE_SERVICES)
        say("2/6 Сохраняю конфигурации и состояния сервисов")
        backup = backup_configs(plan, runner)
        manifest = {"status": "prepared", "components": components, "packages": plan.packages,
                    "units_before": plan.units, "preserved": PRESERVED, "moved": []}
        write_manifest(backup, manifest)
        say(f"Backup: {backup}", "OK")
        try:
            say("3/6 Останавливаю только выбранные сервисы и их KTO-таймеры")
            manifest["status"] = "stopping"
            write_manifest(backup, manifest)
            for unit, state in plan.units.items():
                if state.get("LoadState") == "not-found":
                    continue
                runner.run(["systemctl", "stop", unit])
                runner.run(["systemctl", "disable", unit])
            if "haproxy" in components:
                for marker in MARKERS:
                    if marker.is_symlink():
                        raise CleanupError(f"Не перезаписываю symlink: {marker}")
                    marker.write_text("Disabled by KTO server cleanup.\n", encoding="ascii")
            say("4/6 Удаляю выбранные пакеты без autoremove")
            manifest["status"] = "purging"
            write_manifest(backup, manifest)
            if plan.packages:
                runner.purge(plan.packages)
            say("5/6 Переношу оставшиеся конфигурации в backup")
            check_paths(plan.paths)
            for path in plan.paths:
                if not path.exists() and not path.is_symlink():
                    continue
                target = backup / "residual" / path.relative_to(path.anchor)
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                shutil.move(str(path), str(target))
                manifest["moved"].append(str(path))
                write_manifest(backup, manifest)
            runner.run(["systemctl", "daemon-reload"])
            say("6/6 Проверяю удаление и сохранность доступа")
            verify(runner, plan, before, core)
            manifest["status"] = "complete"
            write_manifest(backup, manifest)
        except BaseException as exc:
            manifest["status"] = "partial"
            manifest["error"] = str(exc)
            try:
                write_manifest(backup, manifest)
            except OSError as write_error:
                say(f"Не удалось записать итог операции: {write_error}", "!")
            say(f"Очистка НЕ завершена. Сервисы могли быть остановлены; автоматического возврата пакетов нет. Backup: {backup}", "STOP")
            raise
        say("Удаление завершено. Пароль и настройки SSH не менялись; ключи сохранены.", "OK")
        say(f"Backup: {backup}. Данные Docker, сертификаты и системные оптимизации оставлены.")


def audit(runner: Runner) -> None:
    runner.log = None
    say(f"Сервер: {socket.gethostname()}")
    say("Установленные пакеты / остаточные конфиги пакетов:")
    print("\n".join(installed_packages(runner, tuple(PACKAGE_PATTERNS))) or "  не найдены")
    all_units = tuple(u for group in UNITS.values() for u in group) + CORE_SERVICES
    for unit, state in unit_states(runner, all_units).items():
        print(f"  {unit:38s} {state.get('ActiveState', '?'):12s} {state.get('UnitFileState', '')}")
    say("Слушающие TCP-порты:")
    print(runner.run(["ss", "-Hlnpt"]).stdout)
    say("Незавершённые пакеты:")
    result = runner.run(["dpkg", "--audit"], check=False)
    print(result.stdout + result.stderr or "  нет")
    say("Сохраняются: " + PRESERVED)


def menu(runner: Runner) -> None:
    choices = {"2": ("haproxy", "nginx", "docker"), "3": ("haproxy", "nginx"),
               "4": ("haproxy",), "5": ("nginx",), "6": ("docker",)}
    while True:
        print("\n[ УДАЛЕНИЕ СЕРВИСОВ ]\n1) Проверить сервер\n2) Удалить HAProxy + Nginx + Docker\n"
              "3) Удалить HAProxy + Nginx (Docker оставить)\n4) Удалить только HAProxy\n"
              "5) Удалить только Nginx\n6) Удалить только Docker/containerd\n0) Назад")
        print("Пароли, SSH-ключи и маршруты не меняются. Docker с контейнерами не удаляется.")
        value = input("> ").strip()
        if value == "0":
            return
        try:
            if value == "1":
                audit(runner)
            elif value in choices:
                remove(runner, choices[value])
            else:
                say("Неверный пункт", "!")
        except (CleanupError, OSError, ValueError) as exc:
            say(str(exc), "STOP")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("menu", "audit", "remove"), nargs="?", default="menu")
    parser.add_argument("components", choices=tuple(PACKAGE_PATTERNS), nargs="*")
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        say("Запусти от root: sudo python3 kto-server-cleanup.py", "STOP")
        return 1
    os.umask(0o077)
    runner = Runner()
    try:
        if args.action == "audit":
            audit(runner)
        elif args.action == "remove":
            remove(runner, tuple(dict.fromkeys(args.components)) or tuple(PACKAGE_PATTERNS))
        elif not sys.stdin.isatty():
            raise CleanupError("Для меню нужен интерактивный терминал; для аудита используй audit")
        else:
            menu(runner)
    except (CleanupError, OSError, ValueError) as exc:
        say(str(exc), "STOP")
        return 1
    except (KeyboardInterrupt, EOFError):
        say("Прервано. При прерывании APT проверь dpkg --audit перед следующей попыткой.", "!")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
