import contextlib
import importlib.util
import inspect
import io
import json
import os
import re
import tempfile
import threading
import time
import unittest
import urllib.request
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
IMPORT_STATE = tempfile.TemporaryDirectory()
CONFIG = Path(IMPORT_STATE.name) / "collector.conf"
CONFIG.write_text(
    f'KTO_COLLECTOR_SECRET="test-secret"\nKTO_COLLECTOR_STATE_DIR="{IMPORT_STATE.name}"\n',
    encoding="utf-8",
)
os.environ["KTO_STATS_COLLECTOR_CONFIG"] = str(CONFIG)
SPEC = importlib.util.spec_from_file_location("kto_stats_collector", ROOT / "scripts" / "kto-stats-collector.py")
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)


class CollectorRegressionTests(unittest.TestCase):
    def setUp(self):
        self.state = tempfile.TemporaryDirectory()
        collector.STATE_DIR = self.state.name
        collector.NODES_FILE = os.path.join(self.state.name, "nodes.json")
        collector.FALLS_FILE = os.path.join(self.state.name, "falls.json")
        collector.SNI_ALLOW_FILE = os.path.join(self.state.name, "sni_allow.json")
        collector.HAPROXY_CONTROL_FILE = os.path.join(self.state.name, "haproxy_control.json")
        collector.NODE_NAMES_FILE = os.path.join(self.state.name, "node_names.json")
        collector.BL_GROUPS_FILE = os.path.join(self.state.name, "bl_groups.json")
        collector.IP_LIMIT_FILE = os.path.join(self.state.name, "ip_limit.json")
        collector.UPDATE_STATE_FILE = os.path.join(self.state.name, "update_state.json")
        collector.REMOTE_CONTROL_FILE = os.path.join(self.state.name, "remote_control.json")
        collector.SSH_ALLOW_FILE = os.path.join(self.state.name, "ssh_allow_ips.json")
        collector.SSH_FIREWALL_FILE = os.path.join(self.state.name, "ssh_firewall.json")
        collector.ALERTS_OFF_FILE = os.path.join(self.state.name, "connection_alerts_off.json")
        collector.IP_LIMIT_DB_FILE = os.path.join(self.state.name, "ip_limit.sqlite")
        collector.NETWORK_RATE_DB_FILE = os.path.join(self.state.name, "network_rate.sqlite")
        collector.IP_NOTES_FILE = os.path.join(self.state.name, "ip_notes.json")
        if collector.IP_LIMIT_DB is not None:
            collector.IP_LIMIT_DB.close()
        collector.IP_LIMIT_DB = None
        if collector.NETWORK_RATE_DB is not None:
            collector.NETWORK_RATE_DB.close()
        collector.NETWORK_RATE_DB = None
        collector.NETWORK_RATE_LAST_PURGE_MINUTE = 0
        collector.NODES = {}
        collector.FALLS = {}
        collector.SNI_STATE = {"nodes": {}, "pending": {}}
        collector.HAPROXY_STATE = {"nodes": {}, "sessions": {}, "pending": {}}
        collector.NODE_NAME_STATE = {"nodes": {}, "pending": {}}
        collector.STATS_OFF_STATE = {"nodes": {}}
        collector.ALERTS_OFF_STATE = {"nodes": {}}
        collector.SSH_FIREWALL_STATE = {"nodes": {}}
        collector.BL_GROUP_STATE = {"groups": {}, "pending": {}}
        collector.UPDATE_STATE = {"current": {}, "results": {}, "local": {}, "retry_tokens": {}, "pending": {}}
        collector.IP_NOTE_STATE = {"notes": {}, "pending": {}}
        collector.REMOTE_CONTROL_STATE = {"paused": False, "paused_at": 0, "paused_by": ""}
        collector.AUTH_NONCES = {}
        collector.NODES_DIRTY = False
        collector.SSH_ALLOWED_IPS = []
        collector.SSH_BASE_ALLOWED_IPS = list(collector.SSH_BASE_ALLOWED_IPS_DEFAULT)
        collector.init_ip_limit_db()
        collector.init_network_rate_db()
        self.original_enqueue = collector.enqueue_event
        collector.enqueue_event = lambda *_args, **_kwargs: True

    def tearDown(self):
        collector.enqueue_event = self.original_enqueue
        if collector.IP_LIMIT_DB is not None:
            collector.IP_LIMIT_DB.close()
        collector.IP_LIMIT_DB = None
        if collector.NETWORK_RATE_DB is not None:
            collector.NETWORK_RATE_DB.close()
        collector.NETWORK_RATE_DB = None
        self.state.cleanup()

    @staticmethod
    def payload(name, node_uuid="", node_kind=""):
        return {
            "id": name,
            "name": name,
            "node_uuid": node_uuid,
            "node_kind": node_kind,
            "hostname": f"{collector.canonical_node_key(name)}.example",
            "metrics_ok": True,
            "updated_at": int(time.time()),
        }

    def test_legacy_nodes_behind_same_ip_do_not_collapse(self):
        collector.update_node(self.payload("Германия"), "203.0.113.10")
        collector.update_node(self.payload("Нидерланды"), "203.0.113.10")
        self.assertEqual(2, len(collector.NODES))

    def test_uuid_migrates_matching_legacy_record(self):
        collector.update_node(self.payload("Обход №10"), "203.0.113.20")
        node_uuid = str(uuid.uuid4())
        collector.update_node(self.payload("Обход №10", node_uuid, "wl"), "203.0.113.20")
        self.assertEqual([f"uuid_{node_uuid}"], list(collector.NODES))

    def test_distinct_uuids_keep_distinct_records_with_same_name(self):
        first = str(uuid.uuid4())
        second = str(uuid.uuid4())
        collector.update_node(self.payload("Тест", first, "bl"), "203.0.113.30")
        collector.update_node(self.payload("Тест", second, "bl"), "203.0.113.30")
        self.assertEqual(2, len(collector.NODES))

    def test_rename_is_scoped_by_uuid_and_repairs_shared_hostname_leak(self):
        identities = [
            ("Обход №1", str(uuid.uuid4()), "203.0.113.31"),
            ("Обход №2", str(uuid.uuid4()), "203.0.113.32"),
            ("Обход №3", str(uuid.uuid4()), "203.0.113.33"),
        ]
        for name, node_uuid, address in identities:
            payload = self.payload(name, node_uuid, "wl")
            payload["hostname"] = "kto"
            collector.update_node(payload, address)

        first = collector.find_node("Обход №1")
        collector.set_node_name_override(first, "Обход №10")
        self.assertEqual("Обход №10", collector.node_display_name(collector.find_node("Обход №1")))
        self.assertEqual("Обход №2", collector.node_display_name(collector.find_node("Обход №2")))
        self.assertEqual("Обход №3", collector.node_display_name(collector.find_node("Обход №3")))

        first_state = next(iter(collector.NODE_NAME_STATE["nodes"].values()))
        first_state["aliases"].extend(["kto", "Обход №2"])
        collector.save_node_name_state()
        collector.NODE_NAME_STATE = {"nodes": {}, "pending": {}}
        collector.load_node_name_state()
        loaded_aliases = next(iter(collector.NODE_NAME_STATE["nodes"].values()))["aliases"]
        self.assertNotIn("kto", loaded_aliases)
        self.assertNotIn(collector.canonical_node_key("Обход №2"), loaded_aliases)

        second = collector.find_node("Обход №2")
        collector.set_node_name_override(second, "Обход №20")
        self.assertEqual(2, len(collector.NODE_NAME_STATE["nodes"]))
        self.assertEqual("Обход №10", collector.node_display_name(collector.find_node("Обход №1")))
        self.assertEqual("Обход №20", collector.node_display_name(collector.find_node("Обход №2")))
        self.assertEqual("Обход №3", collector.node_display_name(collector.find_node("Обход №3")))

        leaked = self.payload("Обход №10", identities[2][1], "wl")
        leaked["id"] = "Обход №3"
        leaked["hostname"] = "kto"
        repaired = collector.update_node(leaked, identities[2][2])
        self.assertEqual("Обход №3", repaired["name"])
        self.assertEqual("Обход №3", collector.node_name_sync_value(repaired, "Обход №10"))

        repaired["name"] = "Обход №20"
        self.assertEqual(1, collector.repair_loaded_node_names())
        self.assertEqual("Обход №3", repaired["name"])

        rich = collector.aggregate_wl_rich_message()
        for name in ("Обход #10", "Обход #20", "Обход #3"):
            self.assertEqual(1, rich.count(name))

    def test_nodes_state_recovers_from_last_valid_backup(self):
        collector.NODES = {"first": {"name": "Первая"}}
        collector.save_nodes()
        collector.NODES = {"second": {"name": "Вторая"}}
        collector.save_nodes()
        Path(collector.NODES_FILE).write_text("{broken", encoding="utf-8")
        collector.NODES = {}
        collector.load_nodes()
        self.assertEqual({"first": {"name": "Первая"}}, collector.NODES)

    def test_explicit_node_kind_wins_over_name_heuristic(self):
        self.assertFalse(collector.node_is_wl(self.payload("Обход №1", str(uuid.uuid4()), "bl")))
        self.assertTrue(collector.node_is_wl(self.payload("Обычная машина", str(uuid.uuid4()), "wl")))

    def test_ssh_snapshot_combines_base_and_telegram_ips(self):
        collector.SSH_BASE_ALLOWED_IPS = ["203.0.113.10", "203.0.113.20"]
        collector.SSH_ALLOWED_IPS = ["198.51.100.7", "203.0.113.10"]
        self.assertEqual(
            ["198.51.100.7", "203.0.113.10", "203.0.113.20"],
            collector.ssh_allowed_ips_snapshot(),
        )
        self.assertEqual(
            collector.ssh_allowed_ips_snapshot(),
            collector.ssh_allowed_ips_for_node(self.payload("Обход", str(uuid.uuid4()), "wl")),
        )
        self.assertEqual(
            [],
            collector.ssh_allowed_ips_for_node(self.payload("Нода", str(uuid.uuid4()), "bl")),
        )

    def test_ssh_firewall_mode_is_wl_only_and_follows_node_uuid(self):
        node_uuid = str(uuid.uuid4())
        collector.update_node(self.payload("Обход №1", node_uuid, "wl"), "203.0.113.50")
        result = collector.set_ssh_firewall_mode(["Обход №1"], opened=True)
        self.assertEqual(["Обход №1"], result["changed"])
        self.assertTrue(collector.ssh_firewall_open_for_node(collector.find_node("Обход №1")))

        collector.SSH_FIREWALL_STATE = {"nodes": {}}
        collector.load_ssh_firewall_state()
        renamed = self.payload("Обход №20", node_uuid, "wl")
        collector.update_node(renamed, "203.0.113.50")
        self.assertTrue(collector.ssh_firewall_open_for_node(collector.find_node("Обход №20")))

        result = collector.set_ssh_firewall_mode(["Обход №20"], opened=False)
        self.assertEqual(["Обход №20"], result["changed"])
        self.assertFalse(collector.ssh_firewall_open_for_node(collector.find_node("Обход №20")))

        collector.update_node(self.payload("Германия", str(uuid.uuid4()), "bl"), "203.0.113.51")
        result = collector.set_ssh_firewall_mode(["Германия"], opened=True)
        self.assertEqual(["Германия"], result["unsupported"])
        self.assertFalse(collector.ssh_firewall_open_for_node(collector.find_node("Германия")))

    def test_parse_ipv4_list_deduplicates_and_rejects_bad_values(self):
        self.assertEqual(
            ["192.0.2.2", "192.0.2.10"],
            collector.parse_ipv4_list("192.0.2.10, bad; 192.0.2.2 192.0.2.10 2001:db8::1"),
        )

    def test_wl_other_nodes_sort_resell_then_private_then_the_rest(self):
        names = [
            "Обход №3 (Private)",
            "Обход №3 (resell)",
            "Обход, но не обход (DNS)",
            "Обход №1 (Private)",
            "Обход №2 (resell)",
            "Обход №1 (resell)",
        ]
        nodes = [{"name": name} for name in names]
        ordered = [node["name"] for node in sorted(nodes, key=collector.wl_other_node_sort_key)]
        self.assertEqual(
            [
                "Обход №1 (resell)",
                "Обход №2 (resell)",
                "Обход №3 (resell)",
                "Обход №1 (Private)",
                "Обход №3 (Private)",
                "Обход, но не обход (DNS)",
            ],
            ordered,
        )

    def test_wl_rich_and_plain_reports_use_variant_order(self):
        names = [
            "Обход №3 (Private)",
            "Обход №2 (resell)",
            "Обход №1 (Private)",
            "Обход №1 (resell)",
        ]
        for index, name in enumerate(names, start=1):
            collector.update_node(
                self.payload(name, str(uuid.uuid4()), "wl"),
                f"203.0.113.{index}",
            )
        expected = [
            "Обход №1 (resell)",
            "Обход №2 (resell)",
            "Обход №1 (Private)",
            "Обход №3 (Private)",
        ]
        plain = collector.aggregate_message("wl")
        rich = collector.aggregate_wl_rich_message()
        self.assertEqual(sorted(plain.index(name) for name in expected), [plain.index(name) for name in expected])
        rich_names = [name.replace("№", "#") for name in expected]
        self.assertEqual(sorted(rich.index(name) for name in rich_names), [rich.index(name) for name in rich_names])

    def test_wl_rich_report_groups_per_interface_ip_rows(self):
        payload = self.payload("Обход №4", str(uuid.uuid4()), "wl")
        payload.update(
            {
                "iface": "ens3",
                "day_total": 999999,
                "ip_stats": [
                    {
                        "iface": "ens3",
                        "ip": "217.19.122.109",
                        "day_rx": 100,
                        "day_tx": 200,
                        "yesterday_rx": 300,
                        "yesterday_tx": 400,
                        "month_rx": 500,
                        "month_tx": 600,
                    },
                    {
                        "iface": "wan2",
                        "ip": "185.141.227.93",
                        "day_rx": 1000,
                        "day_tx": 2000,
                        "yesterday_rx": 3000,
                        "yesterday_tx": 4000,
                        "month_rx": 5000,
                        "month_tx": 6000,
                    },
                    {
                        "iface": "wan2",
                        "ip": "185.141.227.94",
                        "day_total": 999999,
                    },
                ],
            }
        )

        node = collector.update_node(payload, "217.19.122.109")
        rich = collector.aggregate_wl_rich_message()

        self.assertEqual(3300, node["day_total"])
        self.assertEqual(2, len(node["ip_stats"]))
        self.assertEqual(1, rich.count("Обход #4"))
        self.assertIn('valign="middle" rowspan="2">Обход #4</td>', rich)
        self.assertIn("217.19.122.109", rich)
        self.assertIn("185.141.227.93", rich)
        self.assertNotIn("185.141.227.94", rich)
        self.assertLess(rich.index("185.141.227.93"), rich.index("217.19.122.109"))
        self.assertIn(
            f'colspan="9"><b>Общий трафик: {collector.format_bytes(3300)}</b></td>',
            rich,
        )

    def test_ip_rows_sort_by_today_then_month_then_yesterday_traffic(self):
        node = {
            "ip_stats": [
                {"iface": "wan1", "ip": "203.0.113.10", "day_total": 100, "month_total": 100, "yesterday_total": 500},
                {"iface": "wan2", "ip": "203.0.113.11", "day_total": 100, "month_total": 200, "yesterday_total": 100},
                {"iface": "wan3", "ip": "203.0.113.12", "day_total": 200, "month_total": 50, "yesterday_total": 50},
                {"iface": "wan4", "ip": "203.0.113.13", "day_total": 0, "month_total": 900, "yesterday_total": 900},
            ]
        }
        ordered = [entry["ip"] for entry in collector.node_ip_stats_by_traffic(node)]
        self.assertEqual(
            ["203.0.113.12", "203.0.113.11", "203.0.113.10", "203.0.113.13"],
            ordered,
        )

    def test_network_peak_is_per_ip_and_rolls_over_after_24_hours(self):
        node_uuid = str(uuid.uuid4())
        base_time = 1_800_000_000
        original_now = collector.now_ts

        def rate_payload(counter_rx, counter_tx, sample_ms):
            payload = self.payload("Обход №8", node_uuid, "wl")
            payload["ip_stats"] = [{
                "iface": "ens3",
                "ip": "203.0.113.80",
                "counter_rx_bytes": counter_rx,
                "counter_tx_bytes": counter_tx,
                "counter_sample_ms": sample_ms,
            }]
            return payload

        try:
            collector.now_ts = lambda: base_time
            first = collector.update_node(rate_payload(1_000_000_000, 2_000_000_000, 10_000), "203.0.113.80")
            self.assertEqual("-", collector.peak_rate_table_text(first["ip_stats"][0]))

            collector.now_ts = lambda: base_time + 5
            second = collector.update_node(rate_payload(1_100_000_000, 2_050_000_000, 15_000), "203.0.113.80")
            entry = second["ip_stats"][0]
            self.assertEqual(160_000_000, entry["peak_rx_bps_24h"])
            self.assertEqual(80_000_000, entry["peak_tx_bps_24h"])
            self.assertEqual("80 | 160 Mbit/s", collector.peak_rate_table_text(entry))
            rich = collector.aggregate_wl_rich_message()
            self.assertIn("Пик ↑/↓ (24ч)", rich)
            self.assertIn("80 | 160 Mbit/s", rich)

            collector.now_ts = lambda: base_time + 10
            third = collector.update_node(rate_payload(1_110_000_000, 2_055_000_000, 20_000), "203.0.113.80")
            self.assertEqual(160_000_000, third["ip_stats"][0]["peak_rx_bps_24h"])
            self.assertEqual(80_000_000, third["ip_stats"][0]["peak_tx_bps_24h"])

            collector.now_ts = lambda: base_time + collector.NETWORK_RATE_RETENTION_SEC + 61
            expired = collector.update_node(
                rate_payload(1_110_000_000, 2_055_000_000, 86_471_000),
                "203.0.113.80",
            )
            self.assertEqual("-", collector.peak_rate_table_text(expired["ip_stats"][0]))
        finally:
            collector.now_ts = original_now

    def test_cpu_average_uses_minute_buckets_and_rolls_over_after_24_hours(self):
        node_uuid = str(uuid.uuid4())
        base_time = 1_800_000_000
        original_now = collector.now_ts

        def cpu_payload(value):
            payload = self.payload("Обход №9", node_uuid, "wl")
            payload["cpu_percent"] = value
            return payload

        try:
            collector.now_ts = lambda: base_time
            first = collector.update_node(cpu_payload(20), "203.0.113.90")
            self.assertEqual(20.0, first["cpu_avg_24h"])
            self.assertEqual(1, first["cpu_samples_24h"])

            collector.now_ts = lambda: base_time + 10
            same_minute = collector.update_node(cpu_payload(40), "203.0.113.90")
            self.assertEqual(30.0, same_minute["cpu_avg_24h"])
            self.assertEqual(2, same_minute["cpu_samples_24h"])

            collector.now_ts = lambda: base_time + 60
            next_minute = collector.update_node(cpu_payload(60), "203.0.113.90")
            self.assertEqual(45.0, next_minute["cpu_avg_24h"])
            rich = collector.aggregate_wl_rich_message()
            self.assertIn("CPU ср. (24ч)", rich)
            self.assertIn("45%", rich)

            collector.now_ts = lambda: base_time + collector.NETWORK_RATE_RETENTION_SEC + 61
            expired = collector.update_node(cpu_payload(80), "203.0.113.90")
            self.assertEqual(80.0, expired["cpu_avg_24h"])
            self.assertEqual(1, expired["cpu_samples_24h"])
        finally:
            collector.now_ts = original_now

    def test_bl_rich_report_groups_additional_ip_rows(self):
        payload = self.payload("Германия", str(uuid.uuid4()), "bl")
        payload["ip_stats"] = [
            {"iface": "ens3", "ip": "203.0.113.31", "day_rx": 100, "day_tx": 200},
            {"iface": "wan2", "ip": "203.0.113.32", "day_rx": 300, "day_tx": 400},
        ]
        node = collector.update_node(payload, "203.0.113.31")
        rich = collector.bl_nodes_rich_section("kto VPN", [node])

        self.assertEqual(1, rich.count("Германия"))
        self.assertIn('valign="middle" rowspan="2">Германия</td>', rich)
        self.assertIn("203.0.113.31", rich)
        self.assertIn("203.0.113.32", rich)
        self.assertLess(rich.index("203.0.113.32"), rich.index("203.0.113.31"))
        self.assertIn("CPU ср. (24ч)", rich)
        self.assertIn('colspan="11"', rich)

    def test_rich_tables_show_separate_centered_traffic_totals(self):
        exact_payload = self.payload("Обход №2", str(uuid.uuid4()), "wl")
        exact_payload.update({"day_rx": 100, "day_tx": 200})
        other_payload = self.payload("Обход №2 (resell)", str(uuid.uuid4()), "wl")
        other_payload.update({"day_rx": 400, "day_tx": 500})
        bl_payload = self.payload("Германия", str(uuid.uuid4()), "bl")
        bl_payload.update({"day_rx": 1000, "day_tx": 2000})

        collector.update_node(exact_payload, "203.0.113.21")
        collector.update_node(other_payload, "203.0.113.22")
        bl_node = collector.update_node(bl_payload, "203.0.113.23")

        wl_rich = collector.aggregate_wl_rich_message()
        bl_rich = collector.bl_nodes_rich_section("kto VPN", [bl_node])

        self.assertEqual(2, wl_rich.count("Общий трафик:"))
        self.assertIn(
            f'align="center" colspan="9"><b>Общий трафик: {collector.format_bytes(300)}</b>',
            wl_rich,
        )
        self.assertIn(
            f'align="center" colspan="9"><b>Общий трафик: {collector.format_bytes(900)}</b>',
            wl_rich,
        )
        self.assertIn(
            f'align="center" colspan="11"><b>Общий трафик: {collector.format_bytes(3000)}</b>',
            bl_rich,
        )
        self.assertNotIn("Объем трафика:", wl_rich + bl_rich)

    def test_daily_report_uses_same_rich_table_senders_as_manual_stats(self):
        loop_source = inspect.getsource(collector.daily_report_loop)
        self.assertIn("send_stats_wl(use_rich=True)", loop_source)
        self.assertIn("send_grouped_bl_stats(use_rich=True)", loop_source)
        self.assertNotIn('send_message(aggregate_message("wl"))', loop_source)
        self.assertNotIn("send_message(aggregate_grouped_bl_summary_message())", loop_source)

    def test_help_lists_every_routed_bot_command(self):
        loop_source = inspect.getsource(collector.bot_loop)
        routed_commands = set(re.findall(r'"(/[a-z_]+)"', loop_source))
        help_commands = collector.bot_help_command_names()
        message = collector.bot_help_message()

        self.assertEqual(routed_commands, help_commands)
        self.assertLessEqual(len(message), 4096)
        self.assertIn("<code>/help</code> — Показать все актуальные команды.", message)
        self.assertIn("<code>/ip_enable_force &lt;машина&gt;</code> — То же, что /ip_enable; блокировки отключены.", message)

    def test_ip_command_preserves_machine_report_and_starts_note_dialog_for_ip(self):
        messages = []
        original_send = collector.send_message
        original_report = collector.ip_limit_report
        collector.send_message = lambda text, **_kwargs: messages.append(text)
        collector.ip_limit_report = lambda query="": f"machine-report:{query}"
        try:
            collector.handle_ip("/ip Нидерланды", "chat", "user")
            self.assertEqual("machine-report:Нидерланды", messages[-1])
            self.assertIsNone(collector.peek_pending_ip_note("chat", "user"))

            collector.handle_ip("/ip 203.0.113.010", "chat", "user")
            self.assertEqual("machine-report:203.0.113.010", messages[-1])

            collector.handle_ip("/ip 203.0.113.10", "chat", "user")
            pending = collector.peek_pending_ip_note("chat", "user")
            self.assertEqual("203.0.113.10", pending["ip"])
            self.assertIn("Заметка для IP", messages[-1])
            self.assertIn("203.0.113.10", messages[-1])
        finally:
            collector.send_message = original_send
            collector.ip_limit_report = original_report

    def test_ip_note_is_persistent_escaped_rendered_and_deletable(self):
        messages = []
        original_send = collector.send_message
        original_asn = collector.asn_info_text
        collector.send_message = lambda text, **_kwargs: messages.append(text)
        collector.asn_info_text = lambda _ip, **_kwargs: ""
        try:
            collector.handle_ip("/ip 198.51.100.7", "chat", "user")
            self.assertTrue(collector.handle_pending_ip_note("chat", "user", "дом <офис> & резерв"))
            self.assertIsNone(collector.peek_pending_ip_note("chat", "user"))
            self.assertEqual("дом <офис> & резерв", collector.ip_note_text("198.51.100.7"))
            self.assertIn("198.51.100.7 | дом &lt;офис&gt; &amp; резерв", messages[-1])

            stored = json.loads(Path(collector.IP_NOTES_FILE).read_text(encoding="utf-8"))
            self.assertEqual("дом <офис> & резерв", stored["notes"]["198.51.100.7"]["text"])
            collector.IP_NOTE_STATE = {"notes": {}, "pending": {}}
            collector.load_ip_note_state()
            self.assertEqual("дом <офис> & резерв", collector.ip_note_text("198.51.100.7"))

            detail = collector.ip_limit_entry_detail_line(
                {"ip": "198.51.100.7", "nodes": ["Нидерланды"], "last_seen": int(time.time())},
                int(time.time()),
            )
            alert = collector.ip_limit_entry_alert_line({"ip": "198.51.100.7", "nodes": ["Нидерланды"]})
            self.assertIn("198.51.100.7 | дом &lt;офис&gt; &amp; резерв", detail)
            self.assertIn("198.51.100.7 | дом &lt;офис&gt; &amp; резерв", alert)

            collector.handle_ip("/ip 198.51.100.7", "chat", "user")
            self.assertIn("Сейчас", messages[-1])
            self.assertTrue(collector.handle_pending_ip_note("chat", "user", "-"))
            self.assertEqual("", collector.ip_note_text("198.51.100.7"))
            self.assertIn("Заметка удалена", messages[-1])
        finally:
            collector.send_message = original_send
            collector.asn_info_text = original_asn

    def test_ip_note_rejects_overlong_text_without_losing_dialog(self):
        messages = []
        original_send = collector.send_message
        collector.send_message = lambda text, **_kwargs: messages.append(text)
        try:
            collector.handle_ip("/ip 2001:db8::1", "chat", "user")
            self.assertTrue(
                collector.handle_pending_ip_note(
                    "chat",
                    "user",
                    "x" * (collector.IP_NOTE_MAX_LENGTH + 1),
                )
            )
            self.assertIsNotNone(collector.peek_pending_ip_note("chat", "user"))
            self.assertEqual("", collector.ip_note_text("2001:db8::1"))
            self.assertIn("Слишком длинная", messages[-1])
        finally:
            collector.send_message = original_send

    def test_grouped_daily_bl_report_contains_manual_rich_tables(self):
        first_uuid = str(uuid.uuid4())
        second_uuid = str(uuid.uuid4())
        first = collector.update_node(self.payload("Германия", first_uuid, "bl"), "203.0.113.51")
        second = collector.update_node(self.payload("Швейцария", second_uuid, "bl"), "203.0.113.52")
        first_key = collector.node_group_key(first)
        second_key = collector.node_group_key(second)
        collector.BL_GROUP_STATE = {
            "groups": {
                "vpn": {
                    "id": "vpn",
                    "name": "kto VPN",
                    "nodes": {first_key: "Германия", second_key: "Швейцария"},
                    "created_at": 1,
                    "updated_at": 1,
                }
            },
            "pending": {},
        }

        daily = collector.aggregate_grouped_bl_rich_message()
        manual = collector.bl_group_stats_rich_message("vpn")
        manual_section = manual.removeprefix("<h3>Статистика других машин</h3>")

        self.assertIn("<table bordered striped>", daily)
        self.assertIn("<th align=\"center\">Машина</th>", daily)
        self.assertIn("<h4>kto VPN</h4>", daily)
        self.assertIn("Германия", daily)
        self.assertIn("Швейцария", daily)
        self.assertIn(manual_section, daily)

    def test_update_job_ids_are_unique(self):
        first = collector.queue_update_task("test", local_required=False)
        second = collector.queue_update_task("test", local_required=False)
        self.assertNotEqual(first["id"], second["id"])

    def test_panel_and_empty_snapshot_updates_never_dispatch_to_nodes(self):
        node = collector.update_node(
            self.payload("Германия", str(uuid.uuid4()), "bl"),
            "203.0.113.39",
        )
        node["push_build"] = "v307"

        collector.queue_update_task("test", scope="panel", local_required=True)
        self.assertIsNone(collector.update_task_for_node(node))

        collector.queue_update_task("test", scope="all", targets={}, local_required=False)
        self.assertIsNone(collector.update_task_for_node(node))

        live = collector.queue_update_task(
            "test",
            action="push_delete",
            scope="live",
            targets={},
            local_required=False,
            live_targets=True,
        )
        task = collector.update_task_for_node(node)
        self.assertEqual(live["id"], task["id"])
        self.assertEqual("push_delete", task["action"])

    def test_push_pause_discards_remote_queues_and_persists_stats_only_mode(self):
        node = collector.update_node(
            self.payload("Обход №1", str(uuid.uuid4()), "wl"),
            "203.0.113.41",
        )
        node_key = collector.node_record_key(node)
        collector.HAPROXY_STATE = {
            "nodes": {node_key: {"name": "Обход №1", "routes": []}},
            "sessions": {"session": {"created_at": int(time.time())}},
            "pending": {"chat:user": {"created_at": int(time.time())}},
        }
        collector.SNI_STATE = {
            "nodes": {node_key: {"name": "Обход №1", "allowed": ["example.com"]}},
            "pending": {"chat:user": {"created_at": int(time.time())}},
        }
        collector.NODE_NAME_STATE = {
            "nodes": {node_key: {"name": "Сохранённое имя", "aliases": [], "updated_at": 1}},
            "pending": {"chat:user": {"action": "rename", "created_at": int(time.time())}},
        }
        collector.UPDATE_STATE = {
            "current": {"id": "job", "targets": {node_key: "Обход №1"}},
            "results": {node_key: {"id": "job", "status": "running"}},
            "local": {"id": "job", "status": "running"},
            "retry_tokens": {"token": {"key": node_key}},
            "pending": {"chat:user": {"action": "update_node_list", "created_at": int(time.time())}},
        }
        collector.ip_limit_db().execute(
            "INSERT INTO ip_limit_pending(key, action, user, created_at) VALUES(?, ?, ?, ?)",
            ("chat:user", "set_ip_limit", "3", int(time.time())),
        )
        collector.ip_limit_db().commit()

        cleared = collector.pause_remote_commands("tester")

        self.assertTrue(collector.remote_commands_paused())
        self.assertGreater(cleared["total"], 0)
        self.assertEqual({}, collector.HAPROXY_STATE["nodes"])
        self.assertEqual({}, collector.HAPROXY_STATE["sessions"])
        self.assertEqual({}, collector.SNI_STATE["nodes"])
        self.assertEqual({}, collector.UPDATE_STATE["current"])
        self.assertEqual({}, collector.UPDATE_STATE["results"])
        self.assertEqual({}, collector.NODE_NAME_STATE["pending"])
        self.assertEqual("Сохранённое имя", collector.NODE_NAME_STATE["nodes"][node_key]["name"])
        self.assertEqual(1, len(collector.NODES))
        self.assertEqual(0, collector.ip_limit_db().execute("SELECT COUNT(*) FROM ip_limit_pending").fetchone()[0])

        collector.REMOTE_CONTROL_STATE = {"paused": False, "paused_at": 0, "paused_by": ""}
        collector.load_remote_control_state()
        self.assertTrue(collector.remote_commands_paused())
        self.assertTrue(collector.resume_remote_commands("tester"))
        self.assertFalse(collector.remote_commands_paused())
        self.assertEqual({}, collector.HAPROXY_STATE["nodes"])
        self.assertEqual({}, collector.UPDATE_STATE["current"])

    def test_stale_update_result_cannot_replace_current_job(self):
        node_uuid = str(uuid.uuid4())
        node = collector.update_node(self.payload("Германия", node_uuid, "bl"), "203.0.113.40")
        current = collector.queue_update_task(
            "test",
            targets={collector.node_record_key(node): "Германия"},
            local_required=False,
        )
        collector.process_update_result(
            {"id": "old-job", "status": "error", "message": "late"},
            node,
            int(time.time()),
        )
        self.assertEqual({}, collector.UPDATE_STATE["results"])
        collector.process_update_result(
            {"id": current["id"], "status": "ok", "message": "done"},
            node,
            int(time.time()),
        )
        self.assertEqual(current["id"], collector.UPDATE_STATE["results"][collector.node_record_key(node)]["id"])

    def test_running_job_survives_legacy_to_uuid_migration(self):
        legacy = collector.update_node(self.payload("Обход №7"), "203.0.113.47")
        legacy_key = collector.node_record_key(legacy)
        job = collector.queue_update_task(
            "test",
            targets={legacy_key: "Обход №7"},
            local_required=False,
        )
        migrated = collector.update_node(
            self.payload("Обход №7", str(uuid.uuid4()), "wl"),
            "203.0.113.47",
        )
        task = collector.update_task_for_node(migrated)
        self.assertEqual(job["id"], task["id"])
        collector.process_update_result(
            {"id": job["id"], "status": "ok", "message": "done"},
            migrated,
            int(time.time()),
        )
        self.assertEqual(job["id"], collector.UPDATE_STATE["results"][legacy_key]["id"])

    def test_hmac_authentication_rejects_replay(self):
        body = b'{"name":"test"}'
        timestamp = int(time.time())
        nonce = "0123456789abcdef0123456789abcdef"
        signature = collector.hmac_sha256_hex(
            collector.SECRET,
            collector.request_signature_payload(timestamp, nonce, body),
        )
        headers = {
            "X-KTO-Timestamp": str(timestamp),
            "X-KTO-Nonce": nonce,
            "X-KTO-Signature": signature,
        }
        self.assertIsNotNone(collector.authenticate_push(headers, body, current=timestamp))
        self.assertIsNone(collector.authenticate_push(headers, body, current=timestamp))

    def test_config_loader_unescapes_shell_safe_values(self):
        path = Path(self.state.name) / "safe.conf"
        path.write_text('VALUE="a\\$b\\`c\\\\d\\\"e"\n', encoding="utf-8")
        self.assertEqual('a$b`c\\d"e', collector.load_config(path)["VALUE"])

    def test_response_signature_covers_exact_body(self):
        body = b'{"ok": true}'
        nonce = "fedcba9876543210fedcba9876543210"
        signature = collector.hmac_sha256_hex(
            collector.SECRET,
            collector.response_signature_payload(nonce, body),
        )
        changed = collector.hmac_sha256_hex(
            collector.SECRET,
            collector.response_signature_payload(nonce, body + b" "),
        )
        self.assertEqual(64, len(signature))
        self.assertNotEqual(signature, changed)

    def test_signed_http_push_returns_verifiable_response(self):
        with collector.LOCK:
            collector.ip_limit_meta_set("total_limit", "5")
            collector.save_ip_limit_state()
        body = json.dumps(
            self.payload("HTTP нода", str(uuid.uuid4()), "bl"),
            ensure_ascii=False,
        ).encode("utf-8")
        timestamp = int(time.time())
        nonce = uuid.uuid4().hex
        signature = collector.hmac_sha256_hex(
            collector.SECRET,
            collector.request_signature_payload(timestamp, nonce, body),
        )
        server = collector.CollectorHTTPServer(("127.0.0.1", 0), collector.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{server.server_port}/push",
                data=body,
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "X-KTO-Timestamp": str(timestamp),
                    "X-KTO-Nonce": nonce,
                    "X-KTO-Signature": signature,
                },
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                response_body = response.read()
                response_signature = response.headers["X-KTO-Response-Signature"]
                self.assertEqual(nonce, response.headers["X-KTO-Nonce"])
            expected = collector.hmac_sha256_hex(
                collector.SECRET,
                collector.response_signature_payload(nonce, response_body),
            )
            self.assertEqual(expected, response_signature)
            payload = json.loads(response_body)
            self.assertTrue(payload["ok"])
            self.assertEqual([], payload["ssh_allowed_ips"])
            self.assertFalse(payload["ssh_firewall_open"])
            self.assertEqual([], payload["ip_limit_blocks"])
            self.assertTrue(payload["ip_limit_clear_blocks"])
            self.assertTrue(payload["ip_limit_enabled"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_stats_only_push_response_contains_no_remote_commands(self):
        collector.REMOTE_CONTROL_STATE = {
            "paused": True,
            "paused_at": int(time.time()),
            "paused_by": "tester",
        }
        body = json.dumps(
            self.payload("Stats only", str(uuid.uuid4()), "bl"),
            ensure_ascii=False,
        ).encode("utf-8")
        timestamp = int(time.time())
        nonce = uuid.uuid4().hex
        signature = collector.hmac_sha256_hex(
            collector.SECRET,
            collector.request_signature_payload(timestamp, nonce, body),
        )
        server = collector.CollectorHTTPServer(("127.0.0.1", 0), collector.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{server.server_port}/push",
                data=body,
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "X-KTO-Timestamp": str(timestamp),
                    "X-KTO-Nonce": nonce,
                    "X-KTO-Signature": signature,
                },
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                payload = json.loads(response.read())
            self.assertTrue(payload["ok"])
            self.assertTrue(payload["remote_commands_paused"])
            self.assertEqual([], payload["ip_limit_blocks"])
            self.assertTrue(payload["ip_limit_clear_blocks"])
            for field in (
                "ssh_allowed_ips",
                "ssh_firewall_open",
                "ip_limit_enabled",
                "haproxy_routes",
                "haproxy_bandwidth_limits",
                "allowed_sni",
                "haproxy_target",
                "node_name",
                "push_interval_sec",
                "update_task",
            ):
                self.assertNotIn(field, payload)
            self.assertIsNotNone(collector.find_node("Stats only"))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_remna_top_alert_skips_unlimited_and_limits_above_threshold(self):
        now = int(time.time())

        def rows(user, info):
            return [
                {
                    "user": user,
                    "ip": f"198.51.100.{index}",
                    "node": "Нидерланды",
                    "last_seen": now,
                    "user_info": info,
                }
                for index in range(1, 23)
            ]

        unlimited = {"id": 1, "uuid": str(uuid.uuid4()), "hwidDeviceLimit": 0}
        high_limit = {"id": 2, "uuid": str(uuid.uuid4()), "hwidDeviceLimit": 25}
        limited = {"id": 3, "uuid": str(uuid.uuid4()), "hwidDeviceLimit": 2}
        self.assertEqual([], collector.remna_ip_limit_alert_rows(rows("1", unlimited), now))
        self.assertEqual([], collector.remna_ip_limit_alert_rows(rows("2", high_limit), now))
        self.assertEqual(1, len(collector.remna_ip_limit_alert_rows(rows("3", limited), now)))
        self.assertFalse(collector.ip_limit_telegram_alert_allowed(0))
        self.assertTrue(collector.ip_limit_telegram_alert_allowed(20))
        self.assertFalse(collector.ip_limit_telegram_alert_allowed(21))
        self.assertTrue(collector.ip_limit_telegram_alert_allowed(25, "total"))

    def test_total_ip_limit_overrides_personal_and_hwid_immediately(self):
        info = {"id": 3, "uuid": str(uuid.uuid4()), "hwidDeviceLimit": 1}
        collector.set_ip_limit_override("3", info, 2)
        self.assertEqual((2, "personal"), collector.ip_limit_effective_limit("3", info))
        messages = []
        original_send = collector.send_message
        collector.send_message = lambda text, **_kwargs: messages.append(text)
        try:
            collector.handle_ip_limit_total("/limit_ip_total 5")
            self.assertEqual((5, "total"), collector.ip_limit_effective_limit("3", info))
            self.assertTrue(collector.ip_limit_processing_enabled_for_node("Любая нода"))
            self.assertIn("5 IP для каждого", messages[-1])
            collector.handle_ip_limit_total("/limit_ip_total 0")
            self.assertEqual((0, "total"), collector.ip_limit_effective_limit("3", info))
            self.assertFalse(collector.ip_limit_processing_enabled_for_node("Любая нода"))
            collector.handle_ip_limit_total("/limit_ip_total auto")
            self.assertIsNone(collector.ip_limit_total_limit())
            self.assertEqual((2, "personal"), collector.ip_limit_effective_limit("3", info))
        finally:
            collector.send_message = original_send

    def test_ip_limit_is_alert_only_and_recovers_old_actions(self):
        now = int(time.time())
        db = collector.ip_limit_db()
        db.execute(
            "INSERT INTO ip_limit_nodes(node_key, node, enabled, enforce, updated_at) VALUES(?, ?, 1, 1, ?)",
            ("нидерланды", "Нидерланды", now),
        )
        db.execute(
            "INSERT INTO ip_limit_blocks(node_key, ip, user, node, expires_at) VALUES(?, ?, ?, ?, ?)",
            ("нидерланды", "198.51.100.10", "3", "Нидерланды", now + 60),
        )
        db.execute(
            "INSERT INTO ip_limit_penalties(user, uuid, disabled_at, enable_at, reason, last_error) VALUES(?, ?, ?, ?, ?, '')",
            ("3", str(uuid.uuid4()), now, now + 60, "ip_limit"),
        )
        db.commit()
        collector.disable_ip_limit_actions_runtime()
        self.assertEqual(0, db.execute("SELECT COUNT(*) FROM ip_limit_blocks").fetchone()[0])
        self.assertEqual(0, db.execute("SELECT enforce FROM ip_limit_nodes").fetchone()[0])
        penalty = db.execute("SELECT enable_at, reason FROM ip_limit_penalties").fetchone()
        self.assertEqual(0, penalty["enable_at"])
        self.assertEqual("ip_limit_recovery", penalty["reason"])

    def test_remna_ip_limit_sends_alert_without_actions(self):
        now = int(time.time())
        db = collector.ip_limit_db()
        for index in range(1, 3):
            db.execute(
                "INSERT INTO ip_limit_events(user, ip, node, node_key, last_seen) VALUES(?, ?, ?, ?, ?)",
                ("3", f"198.51.100.{index}", "Нидерланды", "нидерланды", now),
            )
        db.commit()
        messages = []
        user_info = {"id": 3, "uuid": str(uuid.uuid4()), "hwidDeviceLimit": 1, "status": "ACTIVE"}
        original_info = collector.remna_user_info
        original_send = collector.send_message
        original_asn = collector.asn_info_text
        original_action = collector.remna_user_action
        collector.remna_user_info = lambda _user: user_info
        collector.send_message = lambda text, **_kwargs: messages.append(text)
        collector.asn_info_text = lambda _ip: ""
        collector.remna_user_action = lambda *_args, **_kwargs: self.fail("IP limit attempted a Remnawave action")
        try:
            collector.process_remna_ip_limit_alerts(now)
        finally:
            collector.remna_user_info = original_info
            collector.send_message = original_send
            collector.asn_info_text = original_asn
            collector.remna_user_action = original_action
        self.assertEqual(1, len(messages))
        self.assertIn("#ipLimitExceeded", messages[0])
        self.assertNotIn("Действие", messages[0])
        self.assertEqual(0, db.execute("SELECT COUNT(*) FROM ip_limit_blocks").fetchone()[0])
        self.assertEqual(0, db.execute("SELECT COUNT(*) FROM ip_limit_penalties").fetchone()[0])

    def test_disable_push_mutes_only_connection_alerts(self):
        node = collector.update_node(
            self.payload("Германия", str(uuid.uuid4()), "bl"),
            "203.0.113.90",
        )
        messages = []
        original_send = collector.send_message
        collector.send_message = lambda text, **_kwargs: messages.append(text)
        try:
            collector.handle_push_notifications("/disable_push Германия", enabled=False)
            self.assertTrue(collector.node_connection_alerts_disabled(node))
            self.assertFalse(collector.node_stats_disabled(node))
            self.assertIn("Push, статистика, SLA и downtime продолжают работать", messages[-1])
            node_key = collector.node_record_key(node)
            collector.NODES[node_key]["offline_alerted"] = True
            collector.NODES[node_key]["offline_confirmed"] = True
            collector.NODES[node_key]["offline_since"] = int(time.time()) - 30
            queued = []
            collector.enqueue_event = lambda callback, *_args, **_kwargs: queued.append(callback.__name__)
            collector.update_node(
                self.payload("Германия", node["node_uuid"], "bl"),
                "203.0.113.90",
            )
            self.assertNotIn("alert_online", queued)
            collector.handle_push_notifications("/enable_push Германия", enabled=True)
            self.assertFalse(collector.node_connection_alerts_disabled(node))
        finally:
            collector.send_message = original_send

    def test_disable_push_uses_exact_uuid_not_shared_aliases(self):
        first_payload = self.payload("Обход №1 (Private)", str(uuid.uuid4()), "wl")
        second_payload = self.payload("Обход №1 (resell)", str(uuid.uuid4()), "wl")
        first_payload["hostname"] = "shared.example"
        second_payload["hostname"] = "shared.example"
        first = collector.update_node(first_payload, "203.0.113.91")
        second = collector.update_node(second_payload, "203.0.113.92")
        original_send = collector.send_message
        collector.send_message = lambda *_args, **_kwargs: None
        try:
            collector.handle_push_notifications("/disable_push Обход #1 (Private)", enabled=False)
            self.assertTrue(collector.node_connection_alerts_disabled(first))
            first_state = next(iter(collector.ALERTS_OFF_STATE["nodes"].values()))
            first_state["aliases"] = ["sharedexample", collector.canonical_node_key(second["name"])]
            self.assertFalse(collector.node_connection_alerts_disabled(second))
            collector.handle_push_notifications("/disable_push Обход #1 (resell)", enabled=False)
            self.assertTrue(collector.node_connection_alerts_disabled(second))
            self.assertEqual(2, len(collector.ALERTS_OFF_STATE["nodes"]))
        finally:
            collector.send_message = original_send

    def test_console_toggle_uses_same_connection_alert_state(self):
        node = collector.update_node(
            self.payload("Обход №3 (Private)", str(uuid.uuid4()), "wl"),
            "203.0.113.93",
        )
        collector.save_nodes()

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = collector.connection_alerts_cli(
                ["--connection-alerts-toggle", "Обход #3 (Private)"]
            )
        self.assertEqual(0, status)
        self.assertIn("disabled\tОбход №3 (Private)", output.getvalue())
        self.assertTrue(collector.node_connection_alerts_disabled(node))
        self.assertFalse(collector.node_stats_disabled(node))

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = collector.connection_alerts_cli(["--connection-alerts-list"])
        self.assertEqual(0, status)
        self.assertEqual("Обход №3 (Private)", output.getvalue().strip())

        collector.NODES = {}
        collector.save_nodes()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = collector.connection_alerts_cli(
                ["--connection-alerts-toggle", "Обход №3 (Private)"]
            )
        self.assertEqual(0, status)
        self.assertIn("enabled\tОбход №3 (Private)", output.getvalue())
        self.assertFalse(collector.node_connection_alerts_disabled(node))


if __name__ == "__main__":
    unittest.main()
