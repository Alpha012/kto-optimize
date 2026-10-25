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
ExecStart=/opt/kto-torrent-guard/nDPId -c /opt/kto-torrent-guard/capture/%i.conf
MemoryHigh=768M
MemoryMax=1G
Nice=5
"""


class TorrentCaptureTuningTests(unittest.TestCase):
    def test_profiles_respect_upstream_flow_limit_and_bound_memory(self):
        self.assertEqual(tuning.profile(8 * 1024 * 1024), (32768, "768M", "1G"))
        self.assertEqual(tuning.profile(16 * 1024 * 1024 - 1), (32768, "768M", "1G"))
        self.assertEqual(tuning.profile(16 * 1024 * 1024), (65536, "1536M", "2G"))
        self.assertEqual(tuning.profile(32 * 1024 * 1024), (65536, "1536M", "2G"))

    def test_capture_config_preserves_scope_and_privacy_settings(self):
        old = configparser.ConfigParser(interpolation=None)
        old.read_string(CAPTURE)
        new = configparser.ConfigParser(interpolation=None)
        new.read_string(tuning.capture_config(CAPTURE, 65536))
        self.assertEqual(dict(old["general"]), dict(new["general"]))
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

    def test_unit_changes_only_memory_limits(self):
        expected = UNIT.replace("MemoryHigh=768M", "MemoryHigh=1536M").replace("MemoryMax=1G", "MemoryMax=2G")
        self.assertEqual(tuning.capture_unit(UNIT, "1536M", "2G"), expected)
        for text in (UNIT.replace("KTO nDPId", "Another"),
                     UNIT.replace("MemoryMax=1G\n", ""), UNIT + "MemoryMax=4G\n"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                tuning.capture_unit(text, "1536M", "2G")

    def test_download_is_pinned_to_current_helper(self):
        helper = ROOT / "scripts/kto-torrent-guard.py"
        self.assertEqual(hashlib.sha256(helper.read_bytes()).hexdigest(), tuning.HELPER_SHA256)
        self.assertTrue(tuning.HELPER_URL.startswith("https://raw.githubusercontent.com/Alpha012/"))

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
                    patch.object(tuning, "restart_observer") as restart:
                with self.assertRaisesRegex(ValueError, "observe before tuning"):
                    tuning.main()
                download.assert_not_called()
                restart.assert_not_called()
            self.assertEqual(json.loads(config.read_text())["mode"], "enforce")


if __name__ == "__main__":
    unittest.main()
