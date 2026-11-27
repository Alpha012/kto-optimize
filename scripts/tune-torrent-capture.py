#!/usr/bin/env python3
"""Update an existing KTO torrent guard installation without rebuilding nDPId or Xray."""

import argparse
import configparser
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request


PREFIX = Path("/opt/kto-torrent-guard")
CONFIG = Path("/etc/kto-torrent-guard.json")
GUARD_UNIT = Path("/etc/systemd/system/kto-torrent-guard.service")
UNIT = Path("/etc/systemd/system/kto-torrent-capture@.service")
STATUS = Path("/run/kto-torrent-guard/status.json")
RAW_BASE = os.environ.get("KTO_RAW_BASE", "https://raw.githubusercontent.com/Alpha012/kto-optimize/main").rstrip("/")
HELPER_URL = f"{RAW_BASE}/scripts/kto-torrent-guard.py"
HELPER_SHA256 = "03ecb6d92892fd23b08f1802120128b407eae799af08acecb2eec949e5b86c5f"
MAX_BACKUPS = 3


def profile(total_kib):
    if total_kib >= 16777216:
        return (65536, "1536M", "2G")
    if total_kib >= 4194304:
        return (32768, "768M", "1G")
    return (16384, "384M", "512M")


def capture_config(text, flow_limit):
    parser = configparser.ConfigParser(interpolation=None)
    parser.read_string(text)
    if not parser.has_section("general") or not parser.has_section("tuning"):
        raise ValueError("capture config has no general/tuning sections")
    if parser.getint("tuning", "max-reader-threads") not in (1, 2):
        raise ValueError("nonstandard thread count; review memory sizing before tuning")
    parser.remove_option("general", "pidfile")
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


def guard_unit(text):
    if "ExecStart=/usr/bin/python3 /opt/kto-torrent-guard/guard.py daemon" not in text:
        raise ValueError("guard service is not the expected KTO unit")
    text, count = re.subn(
        r"(?m)^CapabilityBoundingSet=[^\r\n]*",
        "CapabilityBoundingSet=CAP_NET_ADMIN CAP_DAC_READ_SEARCH CAP_SYS_PTRACE",
        text,
    )
    if count != 1:
        raise ValueError("expected exactly one CapabilityBoundingSet setting")
    return text


def migrate_config(settings, *, has_ndpi):
    updated = dict(settings)
    if "engine" not in updated:
        updated["engine"] = "hybrid" if has_ndpi else "kernel"
    updated.setdefault("ttl", 600)
    updated.setdefault("block_encrypted_cache", True)
    updated.setdefault("protected_udp", [])
    updated.setdefault("exempt_ips", [])
    updated.setdefault("interfaces", [])
    return updated


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


def prune_old_backups(prefix, keep=MAX_BACKUPS):
    backups = sorted(
        (p for p in prefix.glob("capture-backup-*") if p.is_dir() and not p.is_symlink()),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    for stale in backups[keep:]:
        shutil.rmtree(stale, ignore_errors=True)


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


def check_helper(helper):
    with tempfile.TemporaryDirectory(prefix="kto-torrent-preflight-") as directory:
        path = Path(directory) / "guard.py"
        path.write_bytes(helper)
        subprocess.run(["unshare", "--net", sys.executable, str(path), "check-nft"],
                       check=True, timeout=60)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local-guard", help="Use a local guard.py file instead of downloading")
    args = parser.parse_args()

    if os.geteuid() != 0:
        raise ValueError("Run with sudo python3.")
    if (PREFIX / ".owner").read_text(encoding="utf-8").strip() != "kto-torrent-guard-v1":
        raise ValueError("existing KTO torrent guard was not found")
    settings = json.loads(CONFIG.read_text(encoding="utf-8"))
    if settings.get("mode") != "observe":
        raise ValueError("Run sudo kto-torrent observe before tuning. No files were changed.")

    has_ndpi = (PREFIX / "nDPId").is_file() and UNIT.is_file() and bool(list((PREFIX / "capture").glob("*.conf")))
    migrated = migrate_config(settings, has_ndpi=has_ndpi)
    engine = migrated["engine"]
    interfaces = migrated.get("interfaces", [])
    if engine == "hybrid":
        if not interfaces or any(not isinstance(name, str) or
                                 not re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}", name) for name in interfaces):
            raise ValueError("invalid capture interface list")

    mem = dict((line.split()[0].rstrip(":"), int(line.split()[1]))
               for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines() if len(line.split()) >= 2)
    limit, high, maximum = profile(mem["MemTotal"])

    plan = []
    if migrated != settings:
        plan.append((CONFIG, (json.dumps(migrated) + "\n").encode("utf-8")))
    if GUARD_UNIT.is_file():
        plan.append((GUARD_UNIT, guard_unit(GUARD_UNIT.read_text(encoding="utf-8")).encode("utf-8")))
    if engine == "hybrid":
        for name in interfaces:
            path = PREFIX / "capture" / f"{name}.conf"
            plan.append((path, capture_config(path.read_text(encoding="utf-8"), limit).encode("utf-8")))
        plan.append((UNIT, capture_unit(UNIT.read_text(encoding="utf-8"), high, maximum).encode("utf-8")))

    if args.local_guard:
        print("[..] Loading hash-verified torrent guard from local path", flush=True)
        helper = Path(args.local_guard).read_bytes()
    else:
        print("[..] Downloading hash-pinned torrent guard v3", flush=True)
        with urllib.request.urlopen(HELPER_URL, timeout=30) as response:
            helper = response.read(512001)
    if hashlib.sha256(helper).hexdigest() != HELPER_SHA256:
        raise ValueError("observer checksum mismatch; no files were changed")
    compile(helper, "guard.py", "exec")
    print("[..] Testing kernel signatures and selective TCP/UDP blocking in isolated namespaces", flush=True)
    check_helper(helper)
    plan.append((PREFIX / "guard.py", helper))
    if json.loads(CONFIG.read_text(encoding="utf-8")) != settings:
        raise ValueError("settings changed during preparation; retry after reviewing them")

    backup = Path(tempfile.mkdtemp(prefix="capture-backup-", dir=PREFIX))
    print(f"[..] Backup: {backup}", flush=True)
    if engine == "hybrid":
        print(f"[..] Hybrid mode: {limit} flows/thread, MemoryHigh={high}, MemoryMax={maximum} per capture", flush=True)
    else:
        print("[..] Kernel mode: zero-RAM nftables engine", flush=True)
    print("[..] Restarting only KTO torrent guard; Xray and SSH stay running", flush=True)
    restarted_mono = 0.0
    restarted_wall = 0.0

    def activate():
        nonlocal restarted_mono, restarted_wall
        restarted_mono = time.monotonic()
        restarted_wall = time.time()
        restart_observer()

    def verify():
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            try:
                status = json.loads(STATUS.read_text(encoding="utf-8"))
                started_ok = (
                    (isinstance(status.get("started_mono"), (int, float)) and status["started_mono"] >= restarted_mono - 1) or
                    (isinstance(status.get("started"), (int, float)) and status["started"] >= restarted_wall - 2)
                )
                fresh_ok = (
                    (isinstance(status.get("updated_mono"), (int, float)) and 0 <= time.monotonic() - status["updated_mono"] < 12) or
                    (isinstance(status.get("updated"), (int, float)) and -5 <= time.time() - status["updated"] < 12)
                )
                captures_ok = (
                    engine != "hybrid" or set(status.get("captures", [])) == {f"kto-{name}" for name in interfaces}
                )
                if (status.get("mode") == "observe" and status.get("version") == 3
                        and status.get("engine") == engine
                        and started_ok and fresh_ok and captures_ok):
                    return
            except (OSError, ValueError, KeyError):
                pass
            time.sleep(1)
        raise RuntimeError("torrent guard did not become healthy; restoring previous files")

    apply_files(plan, backup, activate, verify)
    prune_old_backups(PREFIX)
    print(f"[OK] KTO Torrent Guard v3 updated (engine={engine}). Mode remains observe.")
    print("Check status: sudo kto-torrent status")
    print("Enable blocking: sudo kto-torrent enforce")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"[STOP] {error}", file=sys.stderr)
        sys.exit(1)
