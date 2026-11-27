import configparser
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("torrent_tuning", ROOT / "scripts/tune-torrent-capture.py")
tuning = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tuning)

CAPTURE = """[general]
netif = eth0
alias = kto-eth0
collector = /run/kto-torrent-guard/collector.sock
pidfile = /tmp/kto-torrent-capture-eth0.pid
bpf = (tcp or udp) and not net 127.0.0.0/8 and not host ::1
[tuning]
max-reader-threads = 2
max-flows-per-thread = 16384
max-idle-flows-per-thread = 256
max-packets-per-flow-to-send = 0
tcp-max-idle-time = 180000000
udp-max-idle-time = 120000000
[ndpi]
fpc = disable
dpi.guess_on_giveup = 0
"""

UNIT = """[Unit]
Description=KTO nDPId capture on %i
PartOf=kto-torrent-guard.service
[Service]
ExecStart=/opt/kto-torrent-guard/nDPId -l -f /opt/kto-torrent-guard/capture/%i.conf
MemoryHigh=768M
MemoryMax=1G
Nice=5
"""

GUARD_UNIT = """[Unit]
Description=KTO BitTorrent connection guard
[Service]
ExecStart=/usr/bin/python3 /opt/kto-torrent-guard/guard.py daemon
CapabilityBoundingSet=CAP_NET_ADMIN
"""


class TorrentCaptureTuningTests(unittest.TestCase):
    def test_profiles_adapt_for_small_medium_and_large_hosts(self):
        self.assertEqual(tuning.profile(1 * 1024 * 1024), (16384, "384M", "512M"))
        self.assertEqual(tuning.profile(4 * 1024 * 1024 - 1), (16384, "384M", "512M"))
        self.assertEqual(tuning.profile(4 * 1024 * 1024), (32768, "768M", "1G"))
        self.assertEqual(tuning.profile(16 * 1024 * 1024 - 1), (32768, "768M", "1G"))
        self.assertEqual(tuning.profile(16 * 1024 * 1024), (65536, "1536M", "2G"))
        self.assertEqual(tuning.profile(32 * 1024 * 1024), (65536, "1536M", "2G"))

    def test_capture_config_preserves_scope_and_drops_obsolete_pidfile(self):
        old = configparser.ConfigParser(interpolation=None)
        old.read_string(CAPTURE)
        new = configparser.ConfigParser(interpolation=None)
        new.read_string(tuning.capture_config(CAPTURE, 65536))
        self.assertNotIn("pidfile", new["general"])
        self.assertEqual(new["general"]["netif"], old["general"]["netif"])
        self.assertEqual(dict(old["ndpi"]), dict(new["ndpi"]))
        self.assertEqual(new.getint("tuning", "max-reader-threads"), 2)
        self.assertEqual(new.getint("tuning", "max-packets-per-flow-to-send"), 0)
        for key, value in {
            "max-flows-per-thread": 65536,
            "max-idle-flows-per-thread": 1024,
            "flow-scan-interval": 5000000,
            "tcp-max-idle-time": 60000000,
            "udp-max-idle-time": 30000000,
            "tcp-max-post-end-flow-time": 10000000,
        }.items():
            self.assertEqual(new.getint("tuning", key), value)

    def test_unknown_capture_shape_is_rejected(self):
        for text in (CAPTURE.replace("max-reader-threads = 2", "max-reader-threads = 8"),
                     CAPTURE.replace("[general]", "[other]"),
                     CAPTURE.replace("[tuning]", "[other]")):
            with self.subTest(text=text), self.assertRaises(ValueError):
                tuning.capture_config(text, 65536)

    def test_unit_changes_only_memory_limits_and_guard_unit_adds_proc_caps(self):
        expected = UNIT.replace("MemoryHigh=768M", "MemoryHigh=1536M").replace("MemoryMax=1G", "MemoryMax=2G")
        self.assertEqual(tuning.capture_unit(UNIT, "1536M", "2G"), expected)
        for text in (UNIT.replace("KTO nDPId", "Another"),
                     UNIT.replace("MemoryMax=1G\n", ""), UNIT + "MemoryMax=4G\n"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                tuning.capture_unit(text, "1536M", "2G")
        updated_guard = tuning.guard_unit(GUARD_UNIT)
        self.assertIn("CapabilityBoundingSet=CAP_NET_ADMIN CAP_DAC_READ_SEARCH CAP_SYS_PTRACE", updated_guard)

    def test_migrate_config_detects_hybrid_vs_kernel_and_preserves_settings(self):
        v2 = {"mode": "observe", "ttl": 300, "interfaces": ["eth0"], "protected_udp": [8443]}
        self.assertEqual(tuning.migrate_config(v2, has_ndpi=True)["engine"], "hybrid")
        self.assertEqual(tuning.migrate_config(v2, has_ndpi=False)["engine"], "kernel")
        self.assertEqual(tuning.migrate_config(v2, has_ndpi=True)["ttl"], 300)
        self.assertTrue(tuning.migrate_config(v2, has_ndpi=True)["block_encrypted_cache"])

    def test_prune_old_backups_keeps_only_latest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for idx in range(5):
                d = root / f"capture-backup-{idx}"
                d.mkdir()
                (d / "x").write_text("ok", encoding="utf-8")
                ts = 1000 + idx * 10
                import os
                os.utime(d, (ts, ts))
            tuning.prune_old_backups(root, keep=3)
            remaining = sorted(p.name for p in root.glob("capture-backup-*"))
            self.assertEqual(remaining, ["capture-backup-2", "capture-backup-3", "capture-backup-4"])

    def test_download_is_pinned_to_current_helper(self):
        helper = ROOT / "scripts/kto-torrent-guard.py"
        self.assertEqual(hashlib.sha256(helper.read_bytes()).hexdigest(), tuning.HELPER_SHA256)
        self.assertTrue(tuning.HELPER_URL.startswith("https://raw.githubusercontent.com/Alpha012/"))

    def test_preflight_uses_a_disposable_namespace_and_does_not_restart_services(self):
        with patch.object(tuning.subprocess, "run") as run:
            tuning.check_helper(b"# fixture, never executed by this unit test\n")
        args = run.call_args.args[0]
        self.assertEqual(args[:2], ["unshare", "--net"])
        self.assertEqual(args[-1], "check-nft")
        self.assertEqual(run.call_args.kwargs, {"check": True, "timeout": 60})

    def test_success_backups_and_activation_order(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, second, backup = root / "capture.conf", root / "unit", root / "backup"
            first.write_bytes(b"old capture")
            second.write_bytes(b"old unit")
            backup.mkdir()
            calls = []

            def activate():
                self.assertEqual(first.read_bytes(), b"new capture")
                self.assertEqual(second.read_bytes(), b"new unit")
                calls.append("activate")

            tuning.apply_files([(first, b"new capture"), (second, b"new unit")], backup,
                               activate, lambda: calls.append("verify"))
            self.assertEqual(calls, ["activate", "verify"])
            self.assertEqual((backup / "00-capture.conf").read_bytes(), b"old capture")
            self.assertEqual((backup / "01-unit").read_bytes(), b"old unit")
            self.assertEqual(json.loads((backup / "paths.json").read_text()), [str(first), str(second)])

    def test_failed_health_check_restores_files_and_reactivates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, backup = root / "capture.conf", root / "backup"
            path.write_bytes(b"old")
            backup.mkdir()
            states = []

            def fail():
                raise RuntimeError("unhealthy capture")

            with self.assertRaisesRegex(RuntimeError, "unhealthy capture"):
                tuning.apply_files([(path, b"new")], backup,
                                   lambda: states.append(path.read_bytes()), fail)
            self.assertEqual(states, [b"new", b"old"])
            self.assertEqual(path.read_bytes(), b"old")

    def test_activation_failure_rolls_back(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, backup = root / "unit", root / "backup"
            path.write_bytes(b"old")
            backup.mkdir()
            attempts = []

            def activate():
                attempts.append(path.read_bytes())
                if len(attempts) == 1:
                    raise RuntimeError("restart failed")

            with self.assertRaisesRegex(RuntimeError, "restart failed"):
                tuning.apply_files([(path, b"new")], backup, activate,
                                   lambda: self.fail("verification must not run"))
            self.assertEqual(attempts, [b"new", b"old"])

    def test_missing_destination_never_applies_partial_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, backup = root / "capture.conf", root / "backup"
            path.write_bytes(b"old")
            backup.mkdir()
            with self.assertRaises(ValueError):
                tuning.apply_files([(path, b"new"), (root / "missing", b"new")], backup,
                                   lambda: self.fail("must not activate"), lambda: None)
            self.assertEqual(path.read_bytes(), b"old")

    def test_enforcing_installation_is_not_changed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".owner").write_text("kto-torrent-guard-v1")
            config = root / "config.json"
            config.write_text('{"mode":"enforce","interfaces":["eth0"]}')
            with patch.object(tuning, "PREFIX", root), patch.object(tuning, "CONFIG", config), \
                    patch.object(tuning.os, "geteuid", return_value=0, create=True), \
                    patch.object(tuning.urllib.request, "urlopen") as download, \
                    patch.object(tuning, "restart_observer") as restart, \
                    patch.object(tuning.sys, "argv", ["tune-torrent-capture.py"]):
                with self.assertRaisesRegex(ValueError, "observe before tuning"):
                    tuning.main()
                download.assert_not_called()
                restart.assert_not_called()
            self.assertEqual(json.loads(config.read_text())["mode"], "enforce")


if __name__ == "__main__":
    unittest.main()
