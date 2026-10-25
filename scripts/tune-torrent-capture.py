#!/usr/bin/env python3
"""Retune an existing KTO torrent observer without rebuilding nDPId or Xray."""

import configparser
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request


PREFIX = Path("/opt/kto-torrent-guard")
CONFIG = Path("/etc/kto-torrent-guard.json")
UNIT = Path("/etc/systemd/system/kto-torrent-capture@.service")
STATUS = Path("/run/kto-torrent-guard/status.json")
HELPER_URL = "https://raw.githubusercontent.com/Alpha012/kto-optimize/main/scripts/kto-torrent-guard.py"
HELPER_SHA256 = "858c5b7b86f10b951fd681f775738df8d96c9bc97cdac63dea43a3ecdeee576b"


def profile(total_kib):
    return (65536, "1536M", "2G") if total_kib >= 16777216 else (32768, "768M", "1G")


def capture_config(text, flow_limit):
    parser = configparser.ConfigParser(interpolation=None)
    parser.read_string(text)
    if not parser.has_section("general") or not parser.has_section("tuning"):
        raise ValueError("capture config has no general/tuning sections")
    if parser.getint("tuning", "max-reader-threads") not in (1, 2):
        raise ValueError("nonstandard thread count; review memory sizing before tuning")
    for key, value in {
        "max-flows-per-thread": flow_limit,
        "max-idle-flows-per-thread": 1024,
        "flow-scan-interval": 5000000,
        "tcp-max-idle-time": 60000000,
        "udp-max-idle-time": 30000000,
        "tcp-max-post-end-flow-time": 10000000,
    }.items():
        parser.set("tuning", key, str(value))
    output = io.StringIO()
    parser.write(output)
    return output.getvalue()


def capture_unit(text, high, maximum):
    if "Description=KTO nDPId capture on %i" not in text:
        raise ValueError("capture service is not the expected KTO unit")
    for key, value in (("MemoryHigh", high), ("MemoryMax", maximum)):
        text, count = re.subn(rf"(?m)^{key}=[^\r\n]*", f"{key}={value}", text)
        if count != 1:
            raise ValueError(f"expected exactly one {key} setting")
    return text


def write_atomic(path, content, mode):
    fd, temporary = tempfile.mkstemp(prefix=".kto-tune-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def apply_files(plan, backup, activate, verify):
    originals = []
    for index, (path, _content) in enumerate(plan):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"refusing to replace symlink/non-file: {path}")
        old = path.read_bytes()
        mode = stat.S_IMODE(path.stat().st_mode)
        originals.append((path, old, mode))
        (backup / f"{index:02d}-{path.name}").write_bytes(old)
    (backup / "paths.json").write_text(json.dumps([str(p) for p, _, _ in originals]), encoding="utf-8")
    changed = []
    try:
        for (path, content), (_, old, mode) in zip(plan, originals):
            changed.append((path, old, mode))
            write_atomic(path, content, mode)
        activate()
        verify()
    except BaseException:
        for path, content, mode in reversed(changed):
            write_atomic(path, content, mode)
        try:
            activate()
        except Exception as rollback_error:
            print(f"[ERROR] Files restored, but service recovery failed: {rollback_error}", file=sys.stderr)
        raise


def restart_observer():
    subprocess.run(["systemctl", "daemon-reload"], check=True, timeout=30)
    subprocess.run(["systemctl", "restart", "kto-torrent-guard.service"], check=True, timeout=90)


def main():
    if os.geteuid() != 0:
        raise ValueError("Run with sudo python3.")
    if (PREFIX / ".owner").read_text().strip() != "kto-torrent-guard-v1":
        raise ValueError("existing KTO torrent guard was not found")
    settings = json.loads(CONFIG.read_text())
    if settings.get("mode") != "observe":
        raise ValueError("Run sudo kto-torrent observe before tuning. No files were changed.")
    interfaces = settings.get("interfaces", [])
    if not interfaces or any(not isinstance(name, str) or
                             not re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}", name) for name in interfaces):
        raise ValueError("invalid capture interface list")
    mem = dict((line.split()[0].rstrip(":"), int(line.split()[1]))
               for line in Path("/proc/meminfo").read_text().splitlines() if len(line.split()) >= 2)
    if mem["MemAvailable"] < 2097152:
        raise ValueError("less than 2 GiB available; do not increase observer capacity yet")
    limit, high, maximum = profile(mem["MemTotal"])
    plan = []
    for name in interfaces:
        path = PREFIX / "capture" / f"{name}.conf"
        plan.append((path, capture_config(path.read_text(), limit).encode()))
    plan.append((UNIT, capture_unit(UNIT.read_text(), high, maximum).encode()))

    print("[..] Downloading hash-pinned observer with classification diagnostics", flush=True)
    with urllib.request.urlopen(HELPER_URL, timeout=30) as response:
        helper = response.read(512001)
    if hashlib.sha256(helper).hexdigest() != HELPER_SHA256:
        raise ValueError("observer checksum mismatch; no files were changed")
    compile(helper, "guard.py", "exec")
    plan.append((PREFIX / "guard.py", helper))
    if json.loads(CONFIG.read_text()) != settings:
        raise ValueError("settings changed during preparation; retry after reviewing them")

    backup = Path(tempfile.mkdtemp(prefix="capture-backup-", dir=PREFIX))
    print(f"[..] Backup: {backup}", flush=True)
    print(f"[..] {limit} flows/thread, MemoryHigh={high}, MemoryMax={maximum} per capture", flush=True)
    print("[..] Restarting only the KTO observer/captures; Xray and SSH stay running", flush=True)
    restarted_at = 0

    def activate():
        nonlocal restarted_at
        restarted_at = time.time()
        restart_observer()

    def verify():
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            try:
                status = json.loads(STATUS.read_text())
                expected = {f"kto-{name}" for name in interfaces}
                if (status["mode"] == "observe" and status["started"] >= restarted_at
                        and 0 <= time.time() - status["updated"] < 10
                        and set(status["captures"]) == expected):
                    return
            except (OSError, ValueError, KeyError):
                pass
            time.sleep(1)
        raise RuntimeError("captures did not become healthy; restoring previous files")

    apply_files(plan, backup, activate, verify)
    print("[OK] Updated without rebuilding nDPId. Mode remains observe.")
    print("Check fresh logs: journalctl -u kto-torrent-guard --since '2 minutes ago' --no-pager")
    print("Watch observer CPU/RAM: systemctl status 'kto-torrent-capture@*' --no-pager")
    print("Do not enable enforcement until suspected false positives have been checked.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"[STOP] {error}", file=sys.stderr)
        sys.exit(1)
