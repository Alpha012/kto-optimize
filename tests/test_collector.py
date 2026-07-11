import importlib.util
import json
import os
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
        collector.IP_LIMIT_DB_FILE = os.path.join(self.state.name, "ip_limit.sqlite")
        if collector.IP_LIMIT_DB is not None:
            collector.IP_LIMIT_DB.close()
        collector.IP_LIMIT_DB = None
        collector.NODES = {}
        collector.FALLS = {}
        collector.NODE_NAME_STATE = {"nodes": {}, "pending": {}}
        collector.STATS_OFF_STATE = {"nodes": {}}
        collector.UPDATE_STATE = {"current": {}, "results": {}, "local": {}, "retry_tokens": {}, "pending": {}}
        collector.AUTH_NONCES = {}
        collector.NODES_DIRTY = False
        collector.init_ip_limit_db()
        self.original_enqueue = collector.enqueue_event
        self.original_drop_enabled = collector.IP_LIMIT_DROP_ENABLED
        collector.enqueue_event = lambda *_args, **_kwargs: True

    def tearDown(self):
        collector.enqueue_event = self.original_enqueue
        collector.IP_LIMIT_DROP_ENABLED = self.original_drop_enabled
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
            self.assertTrue(json.loads(response_body)["ok"])
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

    def test_shared_ip_is_never_scheduled_for_source_drop(self):
        collector.IP_LIMIT_DROP_ENABLED = True
        now = int(time.time())
        db = collector.ip_limit_db()
        db.execute(
            "INSERT INTO ip_limit_events(user, ip, node, node_key, last_seen) VALUES(?, ?, ?, ?, ?)",
            ("1", "198.51.100.77", "Нидерланды", "нидерланды", now),
        )
        db.execute(
            "INSERT INTO ip_limit_events(user, ip, node, node_key, last_seen) VALUES(?, ?, ?, ?, ?)",
            ("2", "198.51.100.77", "Нидерланды", "нидерланды", now),
        )
        db.commit()
        scheduled = collector.schedule_ip_limit_blocks(
            "1",
            [{"ip": "198.51.100.77", "nodes": ["Нидерланды"]}],
            {"id": 1, "uuid": str(uuid.uuid4())},
            now + 60,
        )
        self.assertEqual(0, scheduled)


if __name__ == "__main__":
    unittest.main()
