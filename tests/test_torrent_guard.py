import copy
import hashlib
import importlib.util
import json
from pathlib import Path
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
        self.settings = {"mode": "observe", "ttl": 600, "exempt_ips": [],
                         "interfaces": ["eth0", "warp"], "protected_udp": []}

    def peer(self, data):
        return guard.torrent_peer(data, self.local, self.ports, set())

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
        self.assertEqual(self.peer(event()), (4, "93.184.216.34", 49999, "tcp"))

    def test_warp_and_udp(self):
        self.assertEqual(self.peer(event(src_ip="172.16.0.2", l4_proto="udp")),
                         (4, "93.184.216.34", 49999, "udp"))

    def test_ipv6_peer(self):
        self.assertEqual(self.peer(event(src_ip="2606:4700:110:8765::2", dst_ip="2001:4860:4860::8888")),
                         (6, "2001:4860:4860::8888", 49999, "tcp"))

    def test_reverse_direction(self):
        self.assertEqual(self.peer(event(src_ip="93.184.216.34", dst_ip="5.34.179.103",
                                        src_port=49999, dst_port=55432)),
                         (4, "93.184.216.34", 49999, "tcp"))

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

    def test_only_dpi_not_ip_or_port_guesses(self):
        for confidence in ({"1": "Match by port"}, {"7": "Match by IP"}, {},
                           {"8": "DPI (aggressive)"}, {"6": "Match by port"}):
            self.assertIsNone(self.peer(event(ndpi={"proto": "BitTorrent", "confidence": confidence})))
        for key, value in (("3", "DPI (partial)"), ("4", "DPI (partial cache)"), ("5", "DPI (cache)")):
            self.assertIsNotNone(self.peer(event(ndpi={"proto": "BitTorrent", "confidence": {key: value}})))
        self.assertIsNone(self.peer(event(flow_event_name="guessed")))

    def test_private_local_and_foreign_traffic_ignored(self):
        for ip in ("127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.2", "5.34.179.103"):
            self.assertIsNone(self.peer(event(dst_ip=ip)))
        self.assertIsNone(self.peer(event(src_ip="8.8.8.8")))
        self.assertIsNone(guard.torrent_peer(event(), self.local, self.ports, {"93.184.216.34"}))

    def test_untrusted_values_cannot_become_nft_commands(self):
        for values in ({"src_port": "55432"}, {"dst_port": True}, {"dst_port": 65536},
                       {"dst_ip": "8.8.8.8; flush ruleset"}, {"src_ip": None},
                       {"l4_proto": "tcp; flush ruleset"}, {"ndpi": []}):
            self.assertIsNone(self.peer(event(**values)))

    def test_parse_ipv4_ipv6_and_wildcard_listeners(self):
        ports = guard.listening_ports(
            "tcp LISTEN 0 128 0.0.0.0:26195 0.0.0.0:*\n"
            "tcp LISTEN 0 128 [::]:443 [::]:*\n"
            "udp UNCONN 0 0 *:2408 *:*\n")
        self.assertEqual(ports, {"tcp": {26195, 443}, "udp": {2408}})

    def test_udp_egress_sockets_are_not_treated_as_inbound_servers(self):
        text = ("tcp LISTEN 0 128 [::]:443 [::]:*\n"
                "udp UNCONN 0 0 *:55432 *:*\n"
                "udp UNCONN 0 0 *:443 *:*\n")
        ports = guard.protected_ports(text, [8443], "warp\t52198\n")
        self.assertEqual(ports["udp"], {443, 8443, 52198})
        self.assertNotIn(55432, ports["udp"])

    def test_nft_scope_and_safety(self):
        rules = guard.nft_table(self.ports, 600)
        self.assertIn('comment "kto-torrent-guard-v1"', rules)
        self.assertIn("hook output priority -20; policy accept", rules)
        self.assertIn("hook input priority -20; policy accept", rules)
        self.assertIn("tcp sport @protect_tcp return", rules)
        self.assertIn("tcp dport @protect_tcp return", rules)
        self.assertIn("ip daddr . th dport . meta l4proto @peers4 counter drop", rules)
        self.assertIn("ip6 saddr . th sport . meta l4proto @peers6 counter drop", rules)
        self.assertNotIn("flush ruleset", rules)
        self.assertNotIn("hook forward", rules)

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

    def make_guard(self, mode):
        self.settings["mode"] = mode
        with patch.object(guard, "config", return_value=copy.deepcopy(self.settings)):
            obj = guard.Guard()
        obj.addresses = self.local
        obj.protected = self.ports
        obj.local_updated = guard.time.monotonic()
        obj.active_mode = mode
        return obj

    def test_observe_never_adds_firewall_rules(self):
        obj = self.make_guard("observe")
        with patch.object(guard, "command") as run:
            obj.handle(event())
            obj.flush()
            run.assert_not_called()
        self.assertEqual(obj.detections, 1)

    def test_enforce_batches_and_deduplicates_endpoints(self):
        obj = self.make_guard("enforce")
        with patch.object(guard, "command") as run:
            obj.handle(event())
            obj.handle(event(src_port=55433))
            obj.flush()
            self.assertEqual(run.call_count, 1)
            rules = run.call_args.kwargs["input"]
            self.assertEqual(rules.count("add element"), 1)
            self.assertIn("93.184.216.34 . 49999 . tcp timeout 600s", rules)
            obj.handle(event())
            obj.flush()
            self.assertEqual(run.call_count, 1)

    def test_expired_lease_can_be_added_again(self):
        obj = self.make_guard("enforce")
        peer = self.peer(event())
        obj.blocked[peer] = guard.time.monotonic() - 1
        with patch.object(guard, "command") as run:
            obj.handle(event())
            obj.flush()
            self.assertEqual(run.call_count, 1)

    def test_stale_local_snapshot_never_adds_bans(self):
        obj = self.make_guard("enforce")
        obj.local_updated = 0
        obj.handle(event())
        self.assertEqual(obj.pending, set())

    def test_capture_errors_are_counted_without_becoming_bans(self):
        obj = self.make_guard("enforce")
        obj.handle({"error_event_name": "Max flows to track reached"})
        self.assertEqual(obj.errors, 1)
        self.assertEqual(obj.pending, set())

    def test_enforce_to_observe_removes_only_owned_table(self):
        obj = self.make_guard("enforce")
        obj.pending.add(self.peer(event()))
        self.settings["mode"] = "observe"
        with patch.object(guard, "config", return_value=self.settings), patch.object(guard, "cleanup") as clean:
            obj.set_mode()
            clean.assert_called_once_with()
            self.assertEqual(obj.pending, set())

    def test_configuration_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps(self.settings), encoding="utf-8")
            self.assertEqual(guard.config(path)["ttl"], 600)
            for values in ({"mode": "drop_all"}, {"ttl": True}, {"ttl": 0},
                           {"exempt_ips": ["bad"]}, {"interfaces": []}, {"protected_udp": [True]}):
                path.write_text(json.dumps({**self.settings, **values}), encoding="utf-8")
                with self.assertRaises(ValueError):
                    guard.config(path)

    def test_installer_download_is_hash_pinned(self):
        content = INSTALLER.read_text(encoding="utf-8")
        digest = hashlib.sha256(HELPER.read_bytes()).hexdigest()
        self.assertIn(f"GUARD_SHA256={digest}", content)
        self.assertIn('sha256sum -c -', content)
        self.assertIn("NDPID_REF=b1ef7a62e57b6902098053809bbeb69eb6017c99", content)
        self.assertIn("NDPI_REF=c8443f9747efa204fe8673f1fae99f462267d1f5", content)

    def test_installer_does_not_modify_core_or_existing_firewall(self):
        content = INSTALLER.read_text(encoding="utf-8")
        self.assertIn("MODE=observe", content)
        self.assertIn("--interface", content)
        self.assertNotIn("flush ruleset", content)
        self.assertNotIn("iptables -F", content)
        self.assertNotIn("systemctl restart remnanode", content)
        self.assertNotIn("linux-headers", content)
        self.assertNotIn("modprobe", content)
        self.assertIn("max-packets-per-flow-to-send = 0", content)
        self.assertIn("MemoryMax=1G", content)


if __name__ == "__main__":
    unittest.main()
