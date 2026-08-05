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
        collector.UPDATE_STATE_FILE = os.path.join(self.state.name, "update_state.json")
        collector.ALERTS_OFF_FILE = os.path.join(self.state.name, "connection_alerts_off.json")
        collector.IP_LIMIT_DB_FILE = os.path.join(self.state.name, "ip_limit.sqlite")
        if collector.IP_LIMIT_DB is not None:
            collector.IP_LIMIT_DB.close()
        collector.IP_LIMIT_DB = None
        collector.NODES = {}
        collector.FALLS = {}
        collector.NODE_NAME_STATE = {"nodes": {}, "pending": {}}
        collector.STATS_OFF_STATE = {"nodes": {}}
        collector.ALERTS_OFF_STATE = {"nodes": {}}
        collector.BL_GROUP_STATE = {"groups": {}, "pending": {}}
        collector.UPDATE_STATE = {"current": {}, "results": {}, "local": {}, "retry_tokens": {}, "pending": {}}
        collector.AUTH_NONCES = {}
        collector.NODES_DIRTY = False
        collector.init_ip_limit_db()
        self.original_enqueue = collector.enqueue_event
        collector.enqueue_event = lambda *_args, **_kwargs: True

    def tearDown(self):
        collector.enqueue_event = self.original_enqueue
        if collector.IP_LIMIT_DB is not None:
            collector.IP_LIMIT_DB.close()
        collector.IP_LIMIT_DB = None
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
            self.assertEqual([], payload["ip_limit_blocks"])
            self.assertTrue(payload["ip_limit_clear_blocks"])
            self.assertTrue(payload["ip_limit_enabled"])
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
