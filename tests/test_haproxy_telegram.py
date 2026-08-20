import importlib.util
import json
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
            "haproxy_bandwidth_supported": True,
            "haproxy_bandwidth_limits": [
                {"ip": "10.0.0.2", "rate_mbit": 2000},
            ],
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
                    "server_maxconn": 25000,
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

    def make_node(self, name, number, **changes):
        node = dict(
            self.node,
            id=name,
            name=name,
            node_uuid=f"12345678-1234-1234-1234-{number:012x}",
        )
        node.update(changes)
        return node

    def test_haproxy_without_name_shows_all_machines_in_two_columns(self):
        nodes = [
            self.make_node("Обход №10", 10),
            self.make_node("Германия", 11),
            self.make_node("Обход №2", 12),
        ]
        self.collector.NODES = {self.collector.node_record_key(node): node for node in nodes}
        sent = []

        def send_message(body, reply_markup=None):
            sent.append((body, reply_markup))
            return {"message_id": 501, "chat": {"id": self.chat_id}}

        self.collector.send_message = send_message
        self.collector.handle_haproxy_command("/haproxy", self.chat_id, self.from_id)

        self.assertEqual(len(sent), 1)
        body, markup = sent[0]
        self.assertIn("Выбери машину", body)
        machine_rows = [
            row for row in markup["inline_keyboard"]
            if row and all(button["callback_data"].startswith("hpx:n:") for button in row)
        ]
        self.assertTrue(machine_rows)
        self.assertTrue(all(1 <= len(row) <= 2 for row in machine_rows))
        labels = [button["text"] for row in machine_rows for button in row]
        self.assertEqual(labels, ["Германия", "Обход №2", "Обход №10"])
        token = machine_rows[0][0]["callback_data"].split(":")[2]
        session = self.collector.get_haproxy_session(token)
        self.assertEqual(len(session["node_choices"]), 3)
        self.assertEqual(session["message_id"], "501")

    def test_machine_button_selects_exact_node_and_opens_ip_menu(self):
        first = self.make_node("Обход №1", 21)
        target = self.make_node("Обход №2", 22)
        self.collector.NODES = {
            self.collector.node_record_key(first): first,
            self.collector.node_record_key(target): target,
        }
        token = self.collector.create_haproxy_machine_session(self.chat_id, "77")
        _body, markup = self.collector.haproxy_machine_selector_payload(token)
        target_button = next(
            button
            for row in markup["inline_keyboard"]
            for button in row
            if button["text"] == "Обход №2"
        )
        shown = []
        self.collector.show_haproxy_ip_selector = lambda selected_token: shown.append(selected_token) or True
        callback = {
            "id": "select-node",
            "data": target_button["callback_data"],
            "from": {"id": self.from_id},
            "message": {"message_id": 77, "chat": {"id": self.chat_id}},
        }

        self.assertTrue(self.collector.handle_haproxy_callback(callback))
        session = self.collector.get_haproxy_session(token)
        self.assertEqual(session["node_key"], self.collector.node_record_key(target))
        self.assertEqual(session["node_name"], "Обход №2")
        self.assertEqual(shown, [token])
        _body, ip_markup = self.collector.haproxy_ip_selector_payload(target, token)
        self.assertTrue(
            any(button["text"] == "К списку машин" for row in ip_markup["inline_keyboard"] for button in row)
        )

    def test_machine_choices_survive_state_reload(self):
        nodes = [self.make_node("Обход №1", 31), self.make_node("Обход №2", 32)]
        self.collector.NODES = {self.collector.node_record_key(node): node for node in nodes}
        token = self.collector.create_haproxy_machine_session(self.chat_id, "88")
        expected = self.collector.get_haproxy_session(token)["node_choices"]

        self.collector.HAPROXY_STATE = {"nodes": {}, "sessions": {}, "pending": {}}
        self.collector.load_haproxy_state()

        session = self.collector.get_haproxy_session(token)
        self.assertEqual(session["node_choices"], expected)
        self.assertEqual(session["page"], 0)

    def test_ip_buttons_are_two_columns_and_include_route_counts(self):
        body, markup = self.collector.haproxy_ip_selector_payload(self.node, self.token)
        self.assertIn("Выбери входной IP", body)
        rows = markup["inline_keyboard"]
        self.assertEqual(len(rows[0]), 2)
        self.assertEqual(rows[0][0]["text"], "10.0.0.2 · 2")
        self.assertEqual(rows[0][1]["text"], "10.0.0.3 · 0")
        self.assertEqual(rows[1][0]["text"], "10.0.0.4 · 0")
        self.assertFalse(any(button["text"] == "FULL → точечные бинды" for row in rows for button in row))

    def test_ip_buttons_sort_by_route_count_then_numeric_address(self):
        node = dict(
            self.node,
            ip_stats=[
                {"ip": "78.159.245.250", "iface": "ens3"},
                {"ip": "217.19.122.39", "iface": "wan2"},
                {"ip": "5.34.176.116", "iface": "wan3"},
                {"ip": "37.18.15.228", "iface": "wan4"},
                {"ip": "3.3.3.3", "iface": "wan5"},
                {"ip": "10.0.0.3", "iface": "wan6"},
                {"ip": "10.0.0.4", "iface": "wan7"},
            ],
            haproxy_routes=[
                *self.node["haproxy_routes"],
                {
                    "listen_ip": "217.19.122.39",
                    "port": 443,
                    "targets": ["3.3.3.3:443"],
                    "sni": ["one.example.com"],
                    "source_ip": "217.19.122.39",
                    "server_maxconn": "default",
                },
            ],
        )
        _body, markup = self.collector.haproxy_ip_selector_payload(node, self.token)
        labels = [
            button["text"]
            for row in markup["inline_keyboard"]
            for button in row
            if button["callback_data"].startswith("hpx:i:")
        ]
        self.assertEqual(
            labels,
            [
                "10.0.0.2 · 2",
                "217.19.122.39 · 1",
                "3.3.3.3 · 0",
                "5.34.176.116 · 0",
                "10.0.0.3 · 0",
                "10.0.0.4 · 0",
                "37.18.15.228 · 0",
                "78.159.245.250 · 0",
            ],
        )

    def test_route_state_follows_uuid_after_rename(self):
        routes = self.collector.reported_haproxy_routes_for_node(self.node)
        self.collector.set_haproxy_routes_for_node(self.node, routes)
        renamed = dict(self.node, id="New name", name="New name")
        self.assertEqual(self.collector.desired_haproxy_routes_for_node(renamed), routes)

    def test_acknowledged_route_command_does_not_restore_later_local_delete(self):
        routes = self.collector.reported_haproxy_routes_for_node(self.node)
        self.collector.set_haproxy_routes_for_node(self.node, routes)

        self.assertEqual(self.collector.acknowledge_haproxy_desired_state(self.node), ["routes"])
        self.assertIsNone(self.collector.desired_haproxy_routes_for_node(self.node))

        locally_changed = dict(self.node, haproxy_routes=[routes[0]])
        effective, source = self.collector.effective_haproxy_routes_for_node(locally_changed)
        self.assertEqual(source, "node")
        self.assertEqual(effective, [routes[0]])

    def test_successful_command_id_does_not_restore_route_after_local_ip_change(self):
        routes = self.collector.reported_haproxy_routes_for_node(self.node)
        desired, _ = self.collector.replace_haproxy_route(
            routes,
            "10.0.0.2",
            443,
            listen_ip="10.0.0.3",
        )
        self.collector.set_haproxy_routes_for_node(self.node, desired)
        command_id = self.collector.haproxy_state_item_for_node(self.node)["routes_command_id"]
        locally_changed, _ = self.collector.replace_haproxy_route(
            desired,
            "10.0.0.3",
            443,
            listen_ip="10.0.0.4",
        )
        reported = dict(
            self.node,
            haproxy_routes=locally_changed,
            haproxy_apply_result={
                "status": "ok",
                "message": "routes applied",
                "build": "v309",
                "routes": len(desired),
                "updated_at": 10,
                "command_id": command_id,
            },
        )

        self.assertEqual(self.collector.acknowledge_haproxy_desired_state(reported), ["routes"])
        self.assertIsNone(self.collector.desired_haproxy_routes_for_node(reported))
        effective, source = self.collector.effective_haproxy_routes_for_node(reported)
        self.assertEqual("node", source)
        self.assertTrue(self.collector.haproxy_routes_equal(locally_changed, effective))

    def test_newer_local_route_change_discards_undelivered_telegram_state(self):
        routes = self.collector.reported_haproxy_routes_for_node(self.node)
        desired, _ = self.collector.replace_haproxy_route(
            routes,
            "10.0.0.2",
            443,
            listen_ip="10.0.0.3",
        )
        self.collector.set_haproxy_routes_for_node(self.node, desired)
        locally_changed, _ = self.collector.replace_haproxy_route(
            routes,
            "10.0.0.2",
            443,
            listen_ip="10.0.0.4",
        )
        reported = dict(self.node, haproxy_routes=locally_changed)

        self.assertEqual(
            self.collector.acknowledge_haproxy_desired_state(reported),
            ["routes_local"],
        )
        self.assertIsNone(self.collector.desired_haproxy_routes_for_node(reported))
        effective, source = self.collector.effective_haproxy_routes_for_node(reported)
        self.assertEqual("node", source)
        self.assertTrue(self.collector.haproxy_routes_equal(locally_changed, effective))

    def test_empty_route_report_does_not_discard_pending_telegram_state(self):
        desired = self.collector.reported_haproxy_routes_for_node(self.node)[:1]
        self.collector.set_haproxy_routes_for_node(self.node, desired)
        reported = dict(self.node, haproxy_routes=[])

        self.assertEqual([], self.collector.acknowledge_haproxy_desired_state(reported))
        self.assertTrue(
            self.collector.haproxy_routes_equal(
                desired,
                self.collector.desired_haproxy_routes_for_node(reported),
            )
        )

    def test_follow_up_telegram_edit_accepts_previous_desired_state_as_baseline(self):
        routes = self.collector.reported_haproxy_routes_for_node(self.node)
        first, _ = self.collector.replace_haproxy_route(
            routes,
            "10.0.0.2",
            443,
            listen_ip="10.0.0.3",
        )
        self.collector.set_haproxy_routes_for_node(self.node, first)
        second, _ = self.collector.replace_haproxy_route(
            first,
            "10.0.0.3",
            443,
            listen_ip="10.0.0.4",
        )
        self.collector.set_haproxy_routes_for_node(self.node, second)
        reported = dict(self.node, haproxy_routes=first)

        self.assertEqual([], self.collector.acknowledge_haproxy_desired_state(reported))
        self.assertTrue(
            self.collector.haproxy_routes_equal(
                second,
                self.collector.desired_haproxy_routes_for_node(reported),
            )
        )

    def test_legacy_pending_route_without_baseline_is_discarded_on_reload(self):
        routes = self.collector.reported_haproxy_routes_for_node(self.node)
        Path(self.collector.HAPROXY_CONTROL_FILE).write_text(
            json.dumps({
                "nodes": {
                    self.collector.node_record_key(self.node): {
                        "name": self.node["name"],
                        "routes": routes,
                        "routes_command_id": "a" * 32,
                    }
                },
                "sessions": {},
                "pending": {},
            }),
            encoding="utf-8",
        )
        self.collector.HAPROXY_STATE = {"nodes": {}, "sessions": {}, "pending": {}}

        self.collector.load_haproxy_state()

        self.assertIsNone(self.collector.desired_haproxy_routes_for_node(self.node))
        persisted = json.loads(Path(self.collector.HAPROXY_CONTROL_FILE).read_text(encoding="utf-8"))
        self.assertEqual({}, persisted["nodes"])

    def test_unapplied_route_command_stays_pending(self):
        desired = self.collector.reported_haproxy_routes_for_node(self.node)[:1]
        self.collector.set_haproxy_routes_for_node(self.node, desired)

        self.assertEqual(self.collector.acknowledge_haproxy_desired_state(self.node), [])
        self.assertEqual(self.collector.desired_haproxy_routes_for_node(self.node), desired)

    def test_failed_route_command_is_paused_until_explicit_retry(self):
        desired = self.collector.reported_haproxy_routes_for_node(self.node)[:1]
        desired[0] = dict(desired[0], targets=["9.9.9.9:443"])
        self.collector.set_haproxy_routes_for_node(self.node, desired)
        state_before = self.collector.haproxy_state_item_for_node(self.node)
        failed = dict(
            self.node,
            haproxy_apply_result={
                "status": "error",
                "message": "reload failed",
                "build": "v306",
                "routes": 1,
                "updated_at": 1,
                "command_id": state_before["routes_command_id"],
            },
        )
        self.collector.NODES[self.collector.node_record_key(failed)] = failed

        self.assertEqual(self.collector.haproxy_desired_apply_error(failed, "routes"), "reload failed")
        _body, markup = self.collector.haproxy_ip_selector_payload(failed, self.token)
        retry_button = next(
            button
            for row in markup["inline_keyboard"]
            for button in row
            if button["callback_data"].startswith("hpx:R:")
        )
        callback = {
            "id": "retry-routes",
            "data": retry_button["callback_data"],
            "from": {"id": self.from_id},
            "message": {"message_id": 77, "chat": {"id": self.chat_id}},
        }
        self.assertTrue(self.collector.handle_haproxy_callback(callback))
        state_after = self.collector.haproxy_state_item_for_node(failed)
        self.assertNotEqual(state_after["routes_command_id"], state_before["routes_command_id"])
        self.assertEqual(self.collector.haproxy_desired_apply_error(failed, "routes"), "")

    def test_stale_apply_error_does_not_block_a_new_route_command(self):
        stale = dict(
            self.node,
            haproxy_apply_result={
                "status": "error",
                "message": "old failure",
                "build": "v305",
                "routes": 2,
                "updated_at": 123,
            },
        )
        desired = self.collector.reported_haproxy_routes_for_node(stale)[:1]
        self.collector.set_haproxy_routes_for_node(stale, desired)
        self.assertEqual(self.collector.haproxy_desired_apply_error(stale, "routes"), "")

        changed_error = dict(stale["haproxy_apply_result"], updated_at=124)
        failed = dict(stale, haproxy_apply_result=changed_error)
        self.assertEqual(self.collector.haproxy_desired_apply_error(failed, "routes"), "old failure")

    def test_route_ack_preserves_pending_bandwidth_command(self):
        routes = self.collector.reported_haproxy_routes_for_node(self.node)
        desired_limits = [{"ip": "10.0.0.2", "rate_mbit": 1500}]
        self.collector.set_haproxy_routes_for_node(self.node, routes)
        self.collector.set_haproxy_bandwidth_limits_for_node(self.node, desired_limits)

        self.assertEqual(self.collector.acknowledge_haproxy_desired_state(self.node), ["routes"])
        self.assertIsNone(self.collector.desired_haproxy_routes_for_node(self.node))
        self.assertEqual(self.collector.desired_haproxy_bandwidth_limits_for_node(self.node), desired_limits)

        updated = dict(self.node, haproxy_bandwidth_limits=desired_limits)
        self.assertEqual(self.collector.acknowledge_haproxy_desired_state(updated), ["bandwidth"])
        self.assertIsNone(self.collector.desired_haproxy_bandwidth_limits_for_node(updated))

    def test_bandwidth_change_preserves_routes_and_other_limits(self):
        self.collector.set_pending_haproxy(
            self.chat_id,
            self.from_id,
            "bandwidth_rate",
            self.token,
        )
        self.assertTrue(self.collector.handle_pending_haproxy(self.chat_id, self.from_id, "1500"))
        limits = self.collector.desired_haproxy_bandwidth_limits_for_node(self.node)
        self.assertEqual(limits, [{"ip": "10.0.0.2", "rate_mbit": 1500}])
        self.assertIsNone(self.collector.desired_haproxy_routes_for_node(self.node))

        routes = self.collector.reported_haproxy_routes_for_node(self.node)
        self.collector.set_haproxy_routes_for_node(self.node, routes)
        self.assertEqual(self.collector.desired_haproxy_bandwidth_limits_for_node(self.node), limits)
        self.assertEqual(self.collector.desired_haproxy_routes_for_node(self.node), routes)

    def test_zero_bandwidth_removes_only_selected_ip_limit(self):
        self.node["haproxy_bandwidth_limits"] = [
            {"ip": "10.0.0.2", "rate_mbit": 2000},
            {"ip": "10.0.0.3", "rate_mbit": 3000},
        ]
        self.collector.NODES[self.collector.node_record_key(self.node)] = dict(self.node)
        self.collector.set_pending_haproxy(self.chat_id, self.from_id, "bandwidth_rate", self.token)
        self.collector.handle_pending_haproxy(self.chat_id, self.from_id, "0")
        self.assertEqual(
            self.collector.desired_haproxy_bandwidth_limits_for_node(self.node),
            [{"ip": "10.0.0.3", "rate_mbit": 3000}],
        )

    def test_empty_bandwidth_desire_survives_state_reload(self):
        self.collector.set_haproxy_bandwidth_limits_for_node(self.node, [])
        self.collector.HAPROXY_STATE = {"nodes": {}, "sessions": {}, "pending": {}}
        self.collector.load_haproxy_state()
        self.assertEqual(self.collector.desired_haproxy_bandwidth_limits_for_node(self.node), [])

    def test_clear_all_bandwidth_button_preserves_routes(self):
        edited = []
        self.collector.edit_haproxy_session_message = lambda *args: edited.append(args) or True
        callback = {
            "id": "clear-limits",
            "data": f"hpx:C:{self.token}",
            "from": {"id": self.from_id},
            "message": {"message_id": 77, "chat": {"id": self.chat_id}},
        }
        self.assertTrue(self.collector.handle_haproxy_callback(callback))
        self.assertTrue(edited)
        self.assertIn("Снять все лимиты скорости", edited[-1][1])

        callback["id"] = "confirm-clear-limits"
        callback["data"] = f"hpx:D:{self.token}"
        self.assertTrue(self.collector.handle_haproxy_callback(callback))
        self.assertEqual(self.collector.desired_haproxy_bandwidth_limits_for_node(self.node), [])
        self.assertIsNone(self.collector.desired_haproxy_routes_for_node(self.node))

    def test_selected_ip_shows_bandwidth_and_control_button(self):
        body, markup = self.collector.haproxy_selected_ip_payload(self.node, self.token, "10.0.0.2")
        self.assertIn("2000 Mbit/s на RX и TX", body)
        self.assertTrue(any(button["text"] == "Изменить скорость" for row in markup["inline_keyboard"] for button in row))

    def test_each_route_has_direct_button_and_full_editor(self):
        body, markup = self.collector.haproxy_selected_ip_payload(self.node, self.token, "10.0.0.2")
        self.assertIn("Выбери маршрут для настройки", body)
        route_buttons = [
            button
            for row in markup["inline_keyboard"]
            for button in row
            if button["callback_data"].startswith("hpx:v:")
        ]
        self.assertEqual([button["text"] for button in route_buttons], ["443/tcp", "8443/tcp"])

        editor_body, editor_markup = self.collector.haproxy_route_editor_payload(
            self.node,
            self.token,
            "10.0.0.2",
            8443,
        )
        self.assertIn("<b>IP:</b> <code>10.0.0.2</code>", editor_body)
        self.assertIn("<b>Порт:</b> <code>8443/tcp</code>", editor_body)
        self.assertIn("<b>Backend maxconn:</b> <code>авто, до 25000</code>", editor_body)
        self.assertIn("PROXY protocol v2", editor_body)
        self.assertIn("Выключен", editor_body)
        labels = {button["text"] for row in editor_markup["inline_keyboard"] for button in row}
        self.assertTrue(
            {"Backend", "SNI", "IP", "Входной порт", "PROXY v2: OFF", "Удалить маршрут"}.issubset(labels)
        )
        self.assertNotIn("Выходной IP", labels)
        self.assertNotIn("Maxconn", labels)

    def test_proxy_v2_button_toggles_only_selected_route(self):
        callback = {
            "id": "toggle-proxy-v2",
            "data": f"hpx:t:{self.token}:8443",
            "from": {"id": self.from_id},
            "message": {"message_id": 77, "chat": {"id": self.chat_id}},
        }

        self.assertTrue(self.collector.handle_haproxy_callback(callback))
        routes = self.collector.desired_haproxy_routes_for_node(self.node)
        changed = self.collector.haproxy_route_for_endpoint(routes, "10.0.0.2", 8443)
        base = self.collector.haproxy_route_for_endpoint(routes, "10.0.0.2", 443)
        self.assertTrue(changed["send_proxy_v2"])
        self.assertFalse(base["send_proxy_v2"])

        self.assertTrue(self.collector.handle_haproxy_callback(callback))
        routes = self.collector.desired_haproxy_routes_for_node(self.node)
        changed = self.collector.haproxy_route_for_endpoint(routes, "10.0.0.2", 8443)
        self.assertFalse(changed["send_proxy_v2"])

    def test_proxy_v2_normalization_defaults_off_and_rejects_unknown_values(self):
        route = self.collector.normalize_haproxy_route(self.node["haproxy_routes"][0])
        self.assertFalse(route["send_proxy_v2"])
        enabled = self.collector.normalize_haproxy_route({
            **self.node["haproxy_routes"][0],
            "send_proxy_v2": "yes",
        })
        self.assertTrue(enabled["send_proxy_v2"])
        with self.assertRaises(ValueError):
            self.collector.normalize_haproxy_route({
                **self.node["haproxy_routes"][0],
                "send_proxy_v2": "maybe",
            })

    def test_backend_only_edit_preserves_sni_and_endpoint(self):
        self.collector.set_pending_haproxy(
            self.chat_id,
            self.from_id,
            "route_targets",
            self.token,
            listen_ip="10.0.0.2",
            port=8443,
        )
        self.assertTrue(self.collector.handle_pending_haproxy(self.chat_id, self.from_id, "3.3.3.3:443 4.4.4.4:7443"))
        routes = self.collector.desired_haproxy_routes_for_node(self.node)
        changed = self.collector.haproxy_route_for_endpoint(routes, "10.0.0.2", 8443)
        base = self.collector.haproxy_route_for_endpoint(routes, "10.0.0.2", 443)
        self.assertEqual(changed["targets"], ["3.3.3.3:443", "4.4.4.4:7443"])
        self.assertEqual(changed["sni"], ["extra.example.com"])
        self.assertEqual(base["targets"], ["1.1.1.1:443"])

    def test_route_backend_button_targets_clicked_port(self):
        callback = {
            "id": "edit-backend",
            "data": f"hpx:k:{self.token}:8443",
            "from": {"id": self.from_id},
            "message": {"message_id": 77, "chat": {"id": self.chat_id}},
        }
        self.assertTrue(self.collector.handle_haproxy_callback(callback))
        pending = self.collector.peek_pending_haproxy(self.chat_id, self.from_id)
        self.assertEqual(pending["action"], "route_targets")
        self.assertEqual(pending["listen_ip"], "10.0.0.2")
        self.assertEqual(pending["port"], 8443)

    def test_sni_only_edit_preserves_backend(self):
        self.collector.set_pending_haproxy(
            self.chat_id,
            self.from_id,
            "route_sni",
            self.token,
            listen_ip="10.0.0.2",
            port=8443,
        )
        self.assertTrue(self.collector.handle_pending_haproxy(self.chat_id, self.from_id, "new.example.com *.new.example.com"))
        routes = self.collector.desired_haproxy_routes_for_node(self.node)
        changed = self.collector.haproxy_route_for_endpoint(routes, "10.0.0.2", 8443)
        self.assertEqual(changed["targets"], ["2.2.2.2:443"])
        self.assertEqual(changed["sni"], ["*.new.example.com", "new.example.com"])

    def test_route_port_edit_moves_only_selected_endpoint(self):
        self.collector.set_pending_haproxy(
            self.chat_id,
            self.from_id,
            "route_port",
            self.token,
            listen_ip="10.0.0.2",
            port=8443,
        )
        self.assertTrue(self.collector.handle_pending_haproxy(self.chat_id, self.from_id, "9443"))
        routes = self.collector.desired_haproxy_routes_for_node(self.node)
        self.assertIsNone(self.collector.haproxy_route_for_endpoint(routes, "10.0.0.2", 8443))
        changed = self.collector.haproxy_route_for_endpoint(routes, "10.0.0.2", 9443)
        self.assertEqual(changed["targets"], ["2.2.2.2:443"])
        self.assertIsNotNone(self.collector.haproxy_route_for_endpoint(routes, "10.0.0.2", 443))

    def test_route_port_conflict_keeps_original_route(self):
        self.collector.set_pending_haproxy(
            self.chat_id,
            self.from_id,
            "route_port",
            self.token,
            listen_ip="10.0.0.2",
            port=8443,
        )
        self.assertTrue(self.collector.handle_pending_haproxy(self.chat_id, self.from_id, "443"))
        self.assertIsNone(self.collector.desired_haproxy_routes_for_node(self.node))
        pending = self.collector.peek_pending_haproxy(self.chat_id, self.from_id)
        self.assertEqual(pending["action"], "route_port")

    def test_route_ip_button_moves_input_and_output_atomically(self):
        callback = {
            "id": "move-input",
            "data": f"hpx:h:{self.token}:8443|10.0.0.3",
            "from": {"id": self.from_id},
            "message": {"message_id": 77, "chat": {"id": self.chat_id}},
        }
        self.assertTrue(self.collector.handle_haproxy_callback(callback))
        routes = self.collector.desired_haproxy_routes_for_node(self.node)
        self.assertIsNone(self.collector.haproxy_route_for_endpoint(routes, "10.0.0.2", 8443))
        changed = self.collector.haproxy_route_for_endpoint(routes, "10.0.0.3", 8443)
        self.assertEqual(changed["source_ip"], "10.0.0.3")
        self.assertEqual(changed["server_maxconn"], 25000)
        self.assertEqual(self.collector.get_haproxy_session(self.token)["selected_ip"], "10.0.0.3")

    def test_legacy_output_ip_callback_also_moves_both_sides(self):
        callback = {
            "id": "move-output",
            "data": f"hpx:u:{self.token}:8443|10.0.0.3",
            "from": {"id": self.from_id},
            "message": {"message_id": 77, "chat": {"id": self.chat_id}},
        }
        self.assertTrue(self.collector.handle_haproxy_callback(callback))
        routes = self.collector.desired_haproxy_routes_for_node(self.node)
        self.assertIsNone(self.collector.haproxy_route_for_endpoint(routes, "10.0.0.2", 8443))
        changed = self.collector.haproxy_route_for_endpoint(routes, "10.0.0.3", 8443)
        self.assertEqual(changed["source_ip"], "10.0.0.3")
        self.assertEqual(changed["targets"], ["2.2.2.2:443"])

    def test_route_maxconn_is_fixed_during_normalization(self):
        legacy = {**self.node["haproxy_routes"][1], "server_maxconn": 10000}
        changed = self.collector.normalize_haproxy_route(legacy)
        self.assertEqual(changed["server_maxconn"], 25000)
        self.assertEqual(changed["sni"], ["extra.example.com"])

    def test_full_binds_pin_to_route_source_or_primary_ip(self):
        wildcard_routes = [
            {
                "listen_ip": "*",
                "port": 443,
                "targets": ["1.1.1.1:443"],
                "sni": ["one.example.com"],
                "source_ip": "10.0.0.3",
                "server_maxconn": "default",
            },
            {
                "listen_ip": "*",
                "port": 8443,
                "targets": ["2.2.2.2:443"],
                "sni": ["two.example.com"],
                "source_ip": "default",
                "server_maxconn": 10000,
            },
        ]
        pinned, preview = self.collector.build_haproxy_source_pinned_routes(self.node, wildcard_routes)
        self.assertEqual(preview, [(8443, "10.0.0.2")])
        self.assertIsNotNone(self.collector.haproxy_route_for_endpoint(pinned, "10.0.0.3", 443))
        self.assertIsNotNone(self.collector.haproxy_route_for_endpoint(pinned, "10.0.0.2", 8443))
        self.assertTrue(all(route["server_maxconn"] == 25000 for route in pinned))

    def test_full_bind_confirm_callback_saves_exact_routes(self):
        wildcard = dict(
            self.node,
            haproxy_routes=[
                {
                    "listen_ip": "*",
                    "port": 443,
                    "targets": ["1.1.1.1:443"],
                    "sni": ["one.example.com"],
                    "source_ip": "default",
                    "server_maxconn": "default",
                }
            ],
        )
        self.collector.NODES[self.collector.node_record_key(wildcard)] = wildcard
        callback = {
            "id": "callback-pin",
            "data": f"hpx:z:{self.token}",
            "from": {"id": self.from_id},
            "message": {"message_id": 77, "chat": {"id": self.chat_id}},
        }
        self.assertTrue(self.collector.handle_haproxy_callback(callback))
        routes = self.collector.desired_haproxy_routes_for_node(wildcard)
        self.assertIsNotNone(self.collector.haproxy_route_for_endpoint(routes, "10.0.0.2", 443))

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
        self.assertEqual(extra["server_maxconn"], 25000)

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
        self.assertIn("apply_collector_haproxy_bandwidth_limits", push)
        self.assertIn("haproxy_bandwidth_limits: $haproxy_bandwidth_limits", push)
        self.assertIn("haproxy-remote-apply", kto)
        self.assertIn("haproxy-bandwidth-remote-apply", kto)
        self.assertIn('apply_haproxy_routes_config "$routes_file"', kto)
        self.assertIn('send-proxy-v2', kto)
        self.assertIn('send_proxy_v2: (.send_proxy_v2 == true)', push)
        self.assertIn("acknowledge_haproxy_desired_state(node)", collector)
        self.assertIn('response["haproxy_routes"] = desired_haproxy_routes', collector)
        self.assertIn('response["haproxy_bandwidth_limits"] = desired_haproxy_bandwidth', collector)
        self.assertIn('response["haproxy_routes_command_id"]', collector)
        self.assertIn('response["haproxy_bandwidth_command_id"]', collector)
        self.assertIn('"${previous_command_id,,}" == "$command_id"', push)
        self.assertGreaterEqual(
            push.count('( "$previous_status" == "ok" || "$previous_status" == "error" )'),
            2,
        )


if __name__ == "__main__":
    unittest.main()
