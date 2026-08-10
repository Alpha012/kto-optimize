import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COLLECTOR_PATH = ROOT / "scripts" / "kto-stats-collector.py"


def load_collector():
    spec = importlib.util.spec_from_file_location("kto_stats_collector_haproxy_tests", COLLECTOR_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TelegramHaproxyTests(unittest.TestCase):
    def setUp(self):
        self.collector = load_collector()
        self.temp = tempfile.TemporaryDirectory()
        self.collector.HAPROXY_CONTROL_FILE = str(Path(self.temp.name) / "haproxy.json")
        self.collector.HAPROXY_STATE = {"nodes": {}, "sessions": {}, "pending": {}}
        self.collector.NODES = {}
        self.collector.CHAT_ID = "100"
        self.collector.edit_haproxy_session_message = lambda *args, **kwargs: True
        self.collector.show_haproxy_selected_ip = lambda *args, **kwargs: True
        self.collector.show_haproxy_ip_selector = lambda *args, **kwargs: True
        self.collector.send_message = lambda *args, **kwargs: True
        self.collector.answer_callback = lambda *args, **kwargs: None
        self.node = {
            "id": "Bypass old",
            "name": "Bypass old",
            "node_uuid": "12345678-1234-1234-1234-123456789abc",
            "ip": "10.0.0.2",
            "ip_stats": [
                {"ip": "10.0.0.2", "iface": "ens3"},
                {"ip": "10.0.0.3", "iface": "wan2"},
                {"ip": "10.0.0.4", "iface": "wan3"},
            ],
            "haproxy_routes_supported": True,
            "haproxy_routes_managed": True,
            "haproxy_routes": [
                {
                    "listen_ip": "10.0.0.2",
                    "port": 443,
                    "targets": ["1.1.1.1:443"],
                    "sni": ["base.example.com"],
                    "source_ip": "10.0.0.2",
                    "server_maxconn": "default",
                },
                {
                    "listen_ip": "10.0.0.2",
                    "port": 8443,
                    "targets": ["2.2.2.2:443"],
                    "sni": ["extra.example.com"],
                    "source_ip": "10.0.0.2",
                    "server_maxconn": 10000,
                },
            ],
        }
        key = self.collector.node_record_key(self.node)
        self.collector.NODES[key] = dict(self.node)
        self.chat_id = "100"
        self.from_id = self.collector.ALLOWED_USER_ID
        self.token = self.collector.create_haproxy_session(self.node, self.chat_id, "77")
        self.collector.update_haproxy_session(self.token, selected_ip="10.0.0.2")

    def tearDown(self):
        self.temp.cleanup()

    def test_ip_buttons_are_two_columns_and_include_route_counts(self):
        body, markup = self.collector.haproxy_ip_selector_payload(self.node, self.token)
        self.assertIn("Выбери входной IP", body)
        rows = markup["inline_keyboard"]
        self.assertEqual(len(rows[0]), 2)
        self.assertEqual(rows[0][0]["text"], "10.0.0.2 · 2")
        self.assertEqual(rows[0][1]["text"], "10.0.0.3 · 0")
        self.assertEqual(rows[1][0]["text"], "10.0.0.4 · 0")

    def test_route_state_follows_uuid_after_rename(self):
        routes = self.collector.reported_haproxy_routes_for_node(self.node)
        self.collector.set_haproxy_routes_for_node(self.node, routes)
        renamed = dict(self.node, id="New name", name="New name")
        self.assertEqual(self.collector.desired_haproxy_routes_for_node(renamed), routes)

    def test_edit_targets_additional_port_only(self):
        self.collector.set_pending_haproxy(
            self.chat_id,
            self.from_id,
            "edit_targets",
            self.token,
            port=8443,
        )
        self.assertTrue(
            self.collector.handle_pending_haproxy(
                self.chat_id,
                self.from_id,
                "3.3.3.3:443 4.4.4.4:7443",
            )
        )
        pending = self.collector.peek_pending_haproxy(self.chat_id, self.from_id)
        self.assertEqual(pending["action"], "edit_sni")
        self.assertTrue(
            self.collector.handle_pending_haproxy(
                self.chat_id,
                self.from_id,
                "new.example.com *.new.example.com",
            )
        )
        routes = self.collector.desired_haproxy_routes_for_node(self.node)
        base = self.collector.haproxy_route_for_endpoint(routes, "10.0.0.2", 443)
        extra = self.collector.haproxy_route_for_endpoint(routes, "10.0.0.2", 8443)
        self.assertEqual(base["targets"], ["1.1.1.1:443"])
        self.assertEqual(extra["targets"], ["3.3.3.3:443", "4.4.4.4:7443"])
        self.assertEqual(extra["sni"], ["*.new.example.com", "new.example.com"])
        self.assertEqual(extra["server_maxconn"], 10000)

    def test_add_port_uses_selected_ip_for_input_and_output(self):
        self.collector.update_haproxy_session(self.token, selected_ip="10.0.0.3")
        self.collector.set_pending_haproxy(self.chat_id, self.from_id, "add_port", self.token)
        self.collector.handle_pending_haproxy(self.chat_id, self.from_id, "9443")
        self.collector.handle_pending_haproxy(self.chat_id, self.from_id, "5.5.5.5:443")
        self.collector.handle_pending_haproxy(self.chat_id, self.from_id, "bridge.example.com")
        routes = self.collector.desired_haproxy_routes_for_node(self.node)
        added = self.collector.haproxy_route_for_endpoint(routes, "10.0.0.3", 9443)
        self.assertIsNotNone(added)
        self.assertEqual(added["source_ip"], "10.0.0.3")

    def test_wildcard_and_exact_same_port_are_rejected(self):
        with self.assertRaises(ValueError):
            self.collector.normalize_haproxy_routes(
                [
                    {
                        "listen_ip": "*",
                        "port": 443,
                        "targets": ["1.1.1.1:443"],
                        "sni": ["one.example.com"],
                    },
                    {
                        "listen_ip": "10.0.0.2",
                        "port": 443,
                        "targets": ["2.2.2.2:443"],
                        "sni": ["two.example.com"],
                    },
                ],
                strict=True,
            )

    def test_delete_callback_removes_only_selected_extra_port(self):
        self.collector.set_haproxy_routes_for_node(
            self.node,
            self.collector.reported_haproxy_routes_for_node(self.node),
        )
        callback = {
            "id": "callback-1",
            "data": f"hpx:y:{self.token}:8443",
            "from": {"id": self.from_id},
            "message": {"message_id": 77, "chat": {"id": self.chat_id}},
        }
        self.assertTrue(self.collector.handle_haproxy_callback(callback))
        routes = self.collector.desired_haproxy_routes_for_node(self.node)
        self.assertIsNotNone(self.collector.haproxy_route_for_endpoint(routes, "10.0.0.2", 443))
        self.assertIsNone(self.collector.haproxy_route_for_endpoint(routes, "10.0.0.2", 8443))


class HaproxyTransportContractTests(unittest.TestCase):
    def test_push_and_node_helper_use_full_route_contract(self):
        push = (ROOT / "scripts" / "kto-stats-push.sh").read_text(encoding="utf-8")
        kto = (ROOT / "kto.sh").read_text(encoding="utf-8")
        collector = COLLECTOR_PATH.read_text(encoding="utf-8")
        self.assertIn("read_haproxy_routes", push)
        self.assertIn("haproxy_routes: $haproxy_routes", push)
        self.assertIn("apply_collector_haproxy_routes", push)
        self.assertIn("haproxy-remote-apply", kto)
        self.assertIn('apply_haproxy_routes_config "$routes_file"', kto)
        self.assertIn('response["haproxy_routes"] = desired_haproxy_routes', collector)


if __name__ == "__main__":
    unittest.main()
