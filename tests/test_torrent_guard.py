import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "kto-torrent-guard.py"
INSTALLER = ROOT / "scripts" / "install-torrent-guard.sh"
spec = importlib.util.spec_from_file_location("torrent_guard", HELPER)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


def event(**values):
    result = {
        "alias": "kto-eth0", "flow_event_name": "detected", "l4_proto": "tcp",
        "thread_id": 0, "flow_id": 1, "flow_first_seen": 1000,
        "src_ip": "5.34.179.103", "src_port": 55432,
        "dst_ip": "93.184.216.34", "dst_port": 49999,
        "ndpi": {"proto": "BitTorrent", "confidence": {"6": "DPI"}},
    }
    result.update(values)
    return result


class TorrentGuardTests(unittest.TestCase):
    def setUp(self):
        self.local = {"5.34.179.103", "172.16.0.2", "2606:4700:110:8765::2"}
        self.ports = {"tcp": {22, 443, 1488}, "udp": {2408}}
        self.settings = {
            "engine": "hybrid", "mode": "observe", "ttl": 600, "exempt_ips": [],
            "interfaces": ["eth0", "warp"], "protected_udp": [],
            "block_encrypted_cache": True,
        }

    def peer(self, data, **kwargs):
        return guard.torrent_flow(data, self.local, self.ports, set(), self.settings["interfaces"], **kwargs)

    def frame(self, data):
        payload = json.dumps(data).encode() + b"\n"
        return f"{len(payload):05d}".encode() + payload

    def test_split_and_coalesced_frames(self):
        decoder = guard.Frames()
        first = self.frame(event())
        self.assertEqual(decoder.feed(first[:3]), [])
        self.assertEqual(decoder.feed(first[3:20]), [])
        self.assertEqual(decoder.feed(first[20:] + self.frame({"alias": "kto-warp"})),
                         [event(), {"alias": "kto-warp"}])

    def test_bad_frames_rejected(self):
        for data in (b"hello{}", b"99999", b"00000", b"00002[]", b"00003bad"):
            with self.subTest(data=data), self.assertRaises(ValueError):
                guard.Frames().feed(data)

    def test_tcp_peer(self):
        self.assertEqual(self.peer(event()), (4, "eth0", "5.34.179.103", 55432, "93.184.216.34", 49999, "tcp"))

    def test_warp_and_udp(self):
        self.assertEqual(self.peer(event(alias="kto-warp", src_ip="172.16.0.2", l4_proto="udp")),
                         (4, "warp", "172.16.0.2", 55432, "93.184.216.34", 49999, "udp"))

    def test_ipv6_peer(self):
        self.assertEqual(self.peer(event(src_ip="2606:4700:110:8765::2", dst_ip="2001:4860:4860::8888")),
                         (6, "eth0", "2606:4700:110:8765::2", 55432, "2001:4860:4860::8888", 49999, "tcp"))

    def test_reverse_direction(self):
        self.assertEqual(self.peer(event(src_ip="93.184.216.34", dst_ip="5.34.179.103",
                                        src_port=49999, dst_port=55432)),
                         (4, "eth0", "5.34.179.103", 55432, "93.184.216.34", 49999, "tcp"))

    def test_listening_ports_protect_fronts_and_ssh(self):
        for port in self.ports["tcp"]:
            self.assertIsNone(self.peer(event(src_port=port)))
            self.assertIsNone(self.peer(event(src_ip="93.184.216.34", dst_ip="5.34.179.103",
                                             dst_port=port)))
        self.assertIsNone(self.peer(event(l4_proto="udp", src_port=2408)))

    def test_only_bittorrent_protocol(self):
        for proto in ("TLS", "HTTP", "QUIC", "FileSharing", "notbittorrent", "BitTorrent-Evil"):
            self.assertIsNone(self.peer(event(ndpi={"proto": proto, "confidence": {"6": "DPI"}})))
        self.assertIsNotNone(self.peer(event(ndpi={"proto": "TLS.BitTorrent", "confidence": {"6": "DPI"}})))

    def test_accepts_dpi_and_dpi_cache_by_label_not_port_or_ip_guesses(self):
        # Accepts DPI regardless of numeric enum key, and accepts DPI (cache) for MSE/PE.
        self.assertIsNotNone(self.peer(event(ndpi={"proto": "BitTorrent", "confidence": {"99": "DPI"}})))
        self.assertIsNotNone(self.peer(event(ndpi={"proto": "BitTorrent", "confidence": {"5": "DPI (cache)"}})))
        self.assertIsNone(self.peer(event(ndpi={"proto": "BitTorrent", "confidence": {"5": "DPI (cache)"}}),
                                    allow_cache=False))
        for confidence in ({"1": "Match by port"}, {"7": "Match by IP"}, {},
                           {"8": "DPI (aggressive)"}, {"6": "Match by port"},
                           {"3": "DPI (partial)"}, {"4": "DPI (partial cache)"}):
            self.assertIsNone(self.peer(event(ndpi={"proto": "BitTorrent", "confidence": confidence})))
        self.assertIsNone(self.peer(event(flow_event_name="guessed")))

    def test_private_local_and_foreign_traffic_ignored(self):
        for ip in ("127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.2", "5.34.179.103"):
            self.assertIsNone(self.peer(event(dst_ip=ip)))
        self.assertIsNone(self.peer(event(src_ip="8.8.8.8")))
        self.assertIsNone(guard.torrent_flow(event(), self.local, self.ports, {"93.184.216.34"}, ["eth0"]))

    def test_untrusted_values_cannot_become_nft_commands(self):
        for values in ({"src_port": "55432"}, {"dst_port": True}, {"dst_port": 65536},
                       {"dst_ip": "8.8.8.8; flush ruleset"}, {"src_ip": None},
                       {"l4_proto": "tcp; flush ruleset"}, {"ndpi": []},
                       {"alias": 'kto-eth0"; flush ruleset'}, {"flow_id": True},
                       {"flow_first_seen": -1}, {"thread_id": 32}, {"flow_id": "1"}):
            self.assertIsNone(self.peer(event(**values)))

    def test_parse_ipv4_ipv6_and_auto_protect_hysteria_and_daemons(self):
        text = (
            'tcp LISTEN 0 128 0.0.0.0:26195 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n'
            'tcp LISTEN 0 128 [::]:443 [::]:* users:(("xray",pid=2,fd=4))\n'
            'udp UNCONN 0 0 *:55432 *:* users:(("xray",pid=2,fd=12))\n'
            'udp UNCONN 0 0 [::]:8443 [::]:* users:(("xray",pid=2,fd=13))\n'
            'udp UNCONN 0 0 *:443 *:* users:(("caddy",pid=3,fd=5))\n'
            'udp UNCONN 0 0 *:12345 *:* users:(("hysteria",pid=4,fd=6))\n'
        )
        ports = guard.protected_ports(text, [9443], "warp\t52198\n")
        self.assertEqual(ports["tcp"], {26195, 443})
        # Protects Hysteria2/Xray inbound (<10000), known daemons, WireGuard, and explicit ports;
        # does NOT blindly exempt Xray high-port ephemeral UDP egress socket 55432!
        self.assertEqual(ports["udp"], {443, 8443, 9443, 12345, 52198})
        self.assertNotIn(55432, ports["udp"])

    def test_nft_kernel_and_hybrid_rules_include_signatures_rst_and_safety(self):
        kernel_rules = guard.nft_table(self.ports, 600, [], engine="kernel")
        self.assertIn('comment "kto-torrent-guard-v1"', kernel_rules)
        self.assertIn("hook output priority 0; policy accept", kernel_rules)
        self.assertIn("hook prerouting priority -101; policy accept", kernel_rules)
        self.assertIn("hook postrouting priority 101; policy accept", kernel_rules)
        self.assertIn("reject with tcp reset", kernel_rules)
        self.assertIn("0x13426974546f7272", kernel_rules)  # BitTorrent TCP handshake
        self.assertIn("0x474554202f616e6e", kernel_rules)  # HTTP /announce?
        self.assertIn("0x0000041727101980", kernel_rules)  # UDP tracker BEP 15
        self.assertIn("0x64313a6164323a69", kernel_rules)  # DHT BEP 5
        self.assertIn("flags dynamic,timeout; timeout 600s", kernel_rules)
        self.assertIn("th dport != 80 th dport != 443 add @bt_peers4_tcp", kernel_rules)
        self.assertIn("th dport != 53 th dport != 443 th dport != 853 add @bt_peers4_udp", kernel_rules)
        self.assertIn("set private_v4", kernel_rules)
        self.assertIn("set private_v6", kernel_rules)
        self.assertNotIn("flows4_", kernel_rules)
        self.assertNotIn("flush ruleset", kernel_rules)

        hybrid_rules = guard.nft_table(self.ports, 600, ["eth0", "warp"],
                                       exempt_ips=["203.0.113.9"], engine="hybrid")
        self.assertIn("set exempt_v4", hybrid_rules)
        self.assertIn('oifname "eth0" meta l4proto { tcp, udp } ip saddr . th sport . ip daddr . th dport . meta l4proto @flows4_65746830 counter drop comment "kto:ndpi_flow"', hybrid_rules)
        self.assertIn('iifname "warp" meta l4proto { tcp, udp } ip6 daddr . th dport . ip6 saddr . th sport . meta l4proto @flows6_77617270 counter drop comment "kto:ndpi_flow"', hybrid_rules)

    def test_socket_selftest_refuses_the_host_network(self):
        with patch.object(guard.os, "stat") as stat, patch.object(guard, "command") as run:
            stat.return_value.st_ino = 123
            with self.assertRaisesRegex(RuntimeError, "refusing to touch the host firewall"):
                guard.check_nft()
            run.assert_not_called()

    def test_firewall_errors_include_stderr(self):
        result = subprocess.CompletedProcess([], 1, "", "unsupported nft syntax")
        with patch.object(guard.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(RuntimeError, "unsupported nft syntax"):
                guard.command(["nft", "-f", "-"], input="fixture")
            self.assertEqual(guard.command(["nft"], check=False), result)

    def test_expired_set_element_deletion_is_compatible_with_ubuntu_24(self):
        rules = guard.nft_remove(self.peer(event()))
        self.assertTrue(rules.startswith("add element"))
        self.assertIn("\ndelete element", rules)
        self.assertNotIn("destroy element", rules)

    def test_table_ownership(self):
        result = subprocess.CompletedProcess([], 0, json.dumps({"nftables": [
            {"table": {"name": guard.TABLE, "comment": guard.OWNER}}]}), "")
        with patch.object(guard, "command", return_value=result):
            self.assertTrue(guard.owns_table())
        result.stdout = json.dumps({"nftables": [{"table": {"name": guard.TABLE}}]})
        with patch.object(guard, "command", return_value=result), self.assertRaises(RuntimeError):
            guard.cleanup()

    def test_absent_table_and_permission_error_are_different(self):
        result = subprocess.CompletedProcess([], 1, "", "Error: No such file or directory")
        with patch.object(guard, "command", return_value=result) as run:
            guard.cleanup()
            self.assertEqual(run.call_count, 1)
        result.stderr = "Operation not permitted"
        with patch.object(guard, "command", return_value=result), self.assertRaises(RuntimeError):
            guard.cleanup()

    def make_guard(self, mode, engine="hybrid"):
        self.settings["mode"] = mode
        self.settings["engine"] = engine
        with patch.object(guard, "config", return_value=copy.deepcopy(self.settings)):
            obj = guard.Guard()
        obj.addresses = self.local
        obj.protected = self.ports
        obj.local_updated = guard.time.monotonic()
        obj.active_mode = mode
        obj.applied_signature = obj._table_signature(obj.settings)
        return obj

    def test_observe_never_adds_firewall_rules(self):
        obj = self.make_guard("observe")
        with patch.object(guard, "command") as run:
            obj.handle(event())
            obj.flush(force=True)
            run.assert_not_called()
        self.assertEqual(obj.detections, 1)

    def test_enforce_bans_peer_port_for_torrent_ports_and_5tuple_only_for_shared_web_ports(self):
        obj = self.make_guard("enforce")
        with patch.object(guard, "command") as run:
            # Non-shared port 49999 -> strict peer:port ban (covers reconnects & MSE)
            obj.handle(event(dst_port=49999))
            obj.handle(event(src_port=55433, dst_port=49999))  # duplicate peer:port -> deduped
            # Shared HTTPS port 443 -> only 5-tuple connection drop (never bans whole ip:443)
            obj.handle(event(src_port=55434, dst_port=443, flow_id=2))
            obj.flush(force=True)
            self.assertEqual(run.call_count, 1)
            rules = run.call_args.kwargs["input"]
            self.assertIn("bt_peers4_tcp { 93.184.216.34 . 49999 timeout 600s }", rules)
            self.assertIn("flows4_65746830 { 5.34.179.103 . 55434 . 93.184.216.34 . 443 . tcp timeout 600s }", rules)
            self.assertNotIn("bt_peers4_tcp { 93.184.216.34 . 443", rules)

    def test_idle_and_end_events_do_not_self_unban_live_torrents(self):
        obj = self.make_guard("enforce")
        with patch.object(guard, "command") as run:
            # Shared port 443 uses 5-tuple set; non-shared port 49999 uses peer:port set
            obj.handle(event(dst_port=443))
            obj.handle(event(dst_port=49999, flow_id=2))
            obj.flush(force=True)
            run.reset_mock()
            for name in ("idle", "end"):
                obj.handle(event(flow_event_name=name, dst_port=443))
                obj.handle(event(flow_event_name=name, dst_port=49999, flow_id=2))
            obj.flush(force=True)
            run.assert_not_called()
            self.assertEqual(len(obj.blocked), 1)
            self.assertEqual(len(obj.blocked_peers), 1)

    def test_reused_tuple_on_new_flow_is_removed_before_new_detection_is_added(self):
        obj = self.make_guard("enforce")
        with patch.object(guard, "command") as run:
            obj.handle(event(dst_port=443))
            obj.flush(force=True)
            obj.handle(event(flow_event_name="new", dst_port=443, flow_id=2, flow_first_seen=2000))
            obj.handle(event(dst_port=443, flow_id=2, flow_first_seen=2000))
            obj.flush(force=True)
        rules = run.call_args.kwargs["input"]
        self.assertLess(rules.index("delete element"), rules.rindex("add element"))
        self.assertEqual(len(obj.blocked), 1)

    def test_flush_batches_rapid_events_instead_of_forking_nft_per_event(self):
        obj = self.make_guard("enforce")
        t = 100.0
        with patch.object(guard, "command") as run, patch.object(guard.time, "monotonic", side_effect=lambda: t):
            obj.last_flush = t
            obj.handle(event(dst_port=50001))
            obj.flush()  # Within FLUSH_INTERVAL_SEC -> batched, not forked yet
            run.assert_not_called()
            t += guard.FLUSH_INTERVAL_SEC + 0.05
            obj.flush()
            self.assertEqual(run.call_count, 1)

    def test_set_mode_reloads_nft_table_when_config_changes_in_enforce(self):
        obj = self.make_guard("enforce", engine="kernel")
        updated = copy.deepcopy(self.settings)
        updated["mode"] = "enforce"
        updated["engine"] = "kernel"
        updated["ttl"] = 900
        with patch.object(guard, "config", return_value=updated), \
                patch.object(guard, "owns_table", return_value=True), \
                patch.object(guard, "command") as run:
            changed = obj.set_mode()
        self.assertTrue(changed)
        self.assertEqual(run.call_count, 2)  # --check + apply
        self.assertIn("timeout 900s", run.call_args.kwargs["input"])

    def test_status_freshness_tolerates_ntp_wall_clock_step_using_monotonic(self):
        mono = 5000.0
        # Wall clock stepped backward by 60s, but monotonic age is 3s -> still fresh!
        raw = {"updated": 1000.0, "updated_mono": mono - 3.0}
        self.assertTrue(guard.status_is_fresh(raw, now_wall=940.0, now_mono=mono))
        self.assertFalse(guard.status_is_fresh({"updated": 1000.0, "updated_mono": mono - 20.0},
                                               now_wall=940.0, now_mono=mono))

    def test_interface_set_names_cannot_collide_or_become_nft_syntax(self):
        names = [guard.nft_set(4, name) for name in ("wan.test-1", "wan_test_1", "eth0", "warp")]
        self.assertEqual(len(set(names)), 4)
        self.assertTrue(all(re.fullmatch(r"flows4_[a-f0-9]+", name) for name in names))

    def test_limits_do_not_allow_nft_set_overflow(self):
        obj = self.make_guard("enforce")
        with patch.object(guard, "MAX_PEER_BANS", 1), patch.object(guard, "command") as run:
            obj.handle(event(dst_port=49999))
            obj.handle(event(dst_port=49998, flow_id=2))
            obj.flush(force=True)
        self.assertEqual(run.call_args.kwargs["input"].count("add element"), 1)
        self.assertEqual(len(obj.blocked_peers), 1)

    def test_stale_local_snapshot_never_adds_bans(self):
        obj = self.make_guard("enforce")
        obj.local_updated = guard.time.monotonic() - 61
        obj.handle(event())
        self.assertEqual(obj.pending_peers, set())
        self.assertEqual(obj.pending, set())

    def test_detection_log_has_diagnostics_without_logging_torrent_hash(self):
        obj = self.make_guard("observe")
        data = event()
        data["ndpi"]["bittorrent"] = {"hash": "private-infohash-value"}
        with patch("builtins.print") as output:
            obj.handle(data)
        line = output.call_args.args[0]
        self.assertIn('capture="kto-eth0"', line)
        self.assertIn('confidence={"6":"DPI"}', line)
        self.assertIn("hash_present=True", line)
        self.assertNotIn("private-infohash-value", line)

    def test_enforce_to_observe_removes_only_owned_table(self):
        obj = self.make_guard("enforce")
        obj.pending_peers.add((4, "93.184.216.34", 49999, "tcp"))
        self.settings["mode"] = "observe"
        with patch.object(guard, "config", return_value=self.settings), patch.object(guard, "cleanup") as clean:
            obj.set_mode()
            clean.assert_called_once_with()
            self.assertEqual(obj.pending_peers, set())

    def test_configuration_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps(self.settings), encoding="utf-8")
            self.assertEqual(guard.config(path)["ttl"], 600)
            # Kernel engine allows empty interfaces list
            path.write_text(json.dumps({"engine": "kernel", "mode": "observe", "interfaces": []}), encoding="utf-8")
            self.assertEqual(guard.config(path)["engine"], "kernel")
            for values in ({"mode": "drop_all"}, {"engine": "magic"}, {"ttl": True}, {"ttl": 0},
                           {"block_encrypted_cache": "yes"}, {"exempt_ips": ["bad"]},
                           {"engine": "hybrid", "interfaces": []}, {"interfaces": ["lo"]},
                           {"interfaces": ["eth0;flush"]}, {"interfaces": ["eth0", "eth0"]},
                           {"protected_udp": [True]}):
                path.write_text(json.dumps({**self.settings, **values}), encoding="utf-8")
                with self.assertRaises(ValueError):
                    guard.config(path)

    def test_installer_download_is_hash_pinned_and_supports_kernel_and_hybrid(self):
        content = INSTALLER.read_text(encoding="utf-8")
        digest = hashlib.sha256(HELPER.read_bytes()).hexdigest()
        self.assertIn(f"GUARD_SHA256={digest}", content)
        self.assertIn('sha256sum -c -', content)
        self.assertIn("ENGINE=kernel", content)
        self.assertIn("--engine", content)
        self.assertIn("--add-ndpi", content)
        self.assertIn("remove-ndpi)", content)
        self.assertIn("ubuntu|debian)", content)
        self.assertIn("x86_64|aarch64|arm64)", content)
        self.assertNotIn("flush ruleset", content)
        self.assertNotIn("iptables -F", content)
        self.assertNotIn("systemctl restart remnanode", content)
        self.assertNotIn("linux-headers", content)
        self.assertNotIn("modprobe", content)
        self.assertIn("NDPID_REF=b1ef7a62e57b6902098053809bbeb69eb6017c99", content)
        self.assertIn("NDPI_REF=c8443f9747efa204fe8673f1fae99f462267d1f5", content)

    def run_version_probe(self, output, status):
        bash = shutil.which("bash")
        if not bash:
            self.skipTest("bash is not available")
        source = INSTALLER.read_text(encoding="utf-8")
        function = re.search(r"(?ms)^probe_ndpid_version\(\) \{\n.*?^\}", source)
        self.assertIsNotNone(function)
        script = ("set -e\n"
                  "die() { printf '%s\\n' \"$*\" >&2; exit 1; }\n" +
                  function.group() + "\n" +
                  "fake_ndpid() { printf '%s\\n' \"$PROBE_OUTPUT\"; return \"$PROBE_STATUS\"; }\n"
                  "probe_ndpid_version fake_ndpid\n"
                  "printf 'NEXT_INSTALL_STAGE\\n'\n")
        env = {**os.environ, "PROBE_OUTPUT": output, "PROBE_STATUS": str(status)}
        return subprocess.run([bash, "-c", script], env=env, capture_output=True,
                              text=True, timeout=10)

    def test_upstream_version_exit_one_does_not_abort_install(self):
        banner = "nDPId version 1.7.0-release\nnDPI version...: 6.1.0-1-c8443f9"
        for status in (0, 1):
            with self.subTest(status=status):
                result = self.run_version_probe(banner, status)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("NEXT_INSTALL_STAGE", result.stdout)

    def test_broken_binary_or_invalid_banner_still_aborts_install(self):
        banner = "nDPId version 1.7.0-release\nnDPI version...: 6.1.0-1-c8443f9"
        for output, status in (("", 1), ("missing shared library", 1),
                               ("wrong program", 0), (banner, 2), (banner, 132)):
            with self.subTest(output=output, status=status):
                result = self.run_version_probe(output, status)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("NEXT_INSTALL_STAGE", result.stdout)


if __name__ == "__main__":
    unittest.main()
