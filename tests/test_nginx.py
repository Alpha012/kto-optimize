import base64
import contextlib
import dataclasses
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("kto_nginx", ROOT / "scripts/kto-nginx.py")
ng = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ng
SPEC.loader.exec_module(ng)


def site(**changes):
    values = dict(domain="test.example.com", ips=["192.0.2.10", "192.0.2.11"], backend="198.51.100.10",
                  source="192.0.2.11", cert="/etc/letsencrypt/live/test/fullchain.pem",
                  key="/etc/letsencrypt/live/test/privkey.pem", health_token="a" * 32,
                  http_listens=["80"], tls_listens=["192.0.2.10:443", "192.0.2.11:443"])
    values.update(changes)
    return ng.Site(**values)


class NginxPureTests(unittest.TestCase):
    def test_validation_rejects_config_shell_path_and_header_injection(self):
        for value in ("a.com;", "x.com\nlisten 22", "a.com/a", "*.example.com", "-x.com", "x..com"):
            with self.subTest(domain=value), self.assertRaises(ng.SetupError):
                ng.domain_name(value)
        for value in ("/a;", "/a b", "/a\nX: 1", "/../test", "/%2f", "/$uri", "/.well-known/a", "/a?b=1"):
            with self.subTest(path=value), self.assertRaises(ng.SetupError):
                ng.ws_path(value)
        for value in ("/a.pem;", "/a/../b.pem", "relative.pem", "/key$(id)"):
            with self.subTest(cert=value), self.assertRaises(ng.SetupError):
                ng.cert_path(value)
        for value in ("0", "65536", "--help", "True", "1; rm"):
            with self.subTest(port=value), self.assertRaises(ng.SetupError):
                ng.port_number(value)
        self.assertEqual(ng.domain_name(" EXAMPLE.com. "), "example.com")
        self.assertEqual(ng.ws_path("/de3ws"), "/de3ws")

    def test_render_keeps_source_ws_headers_no_proxy_protocol_and_scoped_logs(self):
        text = ng.render_site(site(), True)
        for expected in ("proxy_bind 192.0.2.11;", "proxy_pass http://198.51.100.10:9080;",
                         "location = /de3ws", "proxy_http_version 1.1;", "proxy_set_header Upgrade $http_upgrade;",
                         'proxy_set_header Connection "upgrade";', "proxy_buffering off;",
                         "listen 192.0.2.10:443 ssl;", "listen 192.0.2.11:443 ssl;",
                         "location ^~ /.well-known/acme-challenge/", "proxy_connect_timeout 5s;",
                         "proxy_read_timeout 3600s;", 'a' * 32):
            self.assertIn(expected, text)
        self.assertNotIn("proxy_protocol", text)
        self.assertNotIn("listen 443 ssl;", text)
        self.assertIn('if ($server_addr !~', text)
        self.assertIn(str(ng.LOGS), text)

    def test_bootstrap_never_references_a_nonexistent_certificate(self):
        text = ng.render_site(site(cert="", key="", source="auto"), False)
        self.assertNotIn("ssl_certificate", text)
        self.assertNotIn("9080", text)
        self.assertIn("TLS setup pending", text)
        with self.assertRaises(ng.SetupError):
            ng.render_site(site(cert="", key=""), True)

    def test_dns_mode_can_have_tls_only_and_custom_redirect_port(self):
        text = ng.render_site(site(http_listens=[], tls_mode="dns"), True)
        self.assertEqual(text.count("server {"), 1)
        self.assertNotIn("listen 80;", text)
        self.assertIn("https://test.example.com:8443$request_uri", ng.render_site(
            site(port=8443, tls_listens=["192.0.2.10:8443", "192.0.2.11:8443"]), True))

    def test_capacity_idempotent_and_preserves_higher_values_and_other_settings(self):
        original = "user www-data;\nworker_processes auto;\nevents {\n worker_connections 768; # old\n}\nhttp { }\n"
        result = ng.tune_capacity(original)
        self.assertIn("worker_connections 8192; # old", result)
        self.assertIn("worker_rlimit_nofile 65536;", result)
        self.assertIn("worker_processes auto;", result)
        self.assertEqual(ng.tune_capacity(result), result)
        high = result.replace("8192", "32000").replace("65536", "131072")
        self.assertEqual(ng.tune_capacity(high), high)
        very_high = ng.tune_capacity(original.replace("768", "100000"))
        self.assertIn("worker_connections 100000", very_high)
        self.assertIn("worker_rlimit_nofile 101024;", very_high)
        for value in ("events { include custom; }", original + "worker_connections 1;\n",
                      original.replace("768", "$number"), original.replace("events", "http")):
            with self.assertRaises(ng.SetupError):
                ng.tune_capacity(value)

    def test_listens_share_existing_wildcard_and_leave_other_ips_and_ports_alone(self):
        dump = "# configuration file /etc/nginx/sites-enabled/default:\nserver { listen 80 default_server; server_name _; }\n"
        sockets = 'LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=1,fd=3))\n'
        sockets += 'LISTEN 0 511 192.0.2.20:443 0.0.0.0:* users:(("haproxy",pid=2,fd=4))\n'
        sockets += 'LISTEN 0 511 0.0.0.0:7443 0.0.0.0:* users:(("haproxy",pid=2,fd=4))\n'
        self.assertEqual(ng.choose_listens(site(), dump, sockets), (["80"], ["192.0.2.10:443", "192.0.2.11:443"]))

    def test_conflicts_do_not_stop_haproxy_or_accept_unknown_old_runtime(self):
        for endpoint in ("0.0.0.0:443", "192.0.2.11:443", "[::]:443", "*:443"):
            with self.subTest(endpoint=endpoint), self.assertRaises(ng.SetupError):
                ng.choose_listens(site(), "", f'LISTEN 0 511 {endpoint} *:* users:(("haproxy",pid=2,fd=4))')
        with self.assertRaisesRegex(ng.SetupError, "Runtime"):
            ng.choose_listens(site(), "", 'LISTEN 0 511 0.0.0.0:80 *:* users:(("nginx",pid=1,fd=3))')
        dump = "# configuration file /etc/nginx/sites-enabled/foreign:\nserver { listen 443 ssl; server_name test.example.com; }"
        with self.assertRaisesRegex(ng.SetupError, "уже настроен"):
            ng.choose_listens(site(), dump, "")

    def test_conflict_on_port_80_allows_dns_challenge_but_not_http(self):
        sockets = 'LISTEN 0 511 0.0.0.0:80 *:* users:(("haproxy",pid=2,fd=4))'
        self.assertEqual(ng.choose_listens(site(tls_mode="dns"), "", sockets)[0], [])
        with self.assertRaises(ng.SetupError):
            ng.choose_listens(site(), "", sockets)

    def test_shared_plaintext_or_proxy_protocol_tls_port_is_rejected(self):
        for options in ("", "ssl proxy_protocol"):
            dump = f"# configuration file /etc/nginx/conf.d/other:\nserver {{ listen 443 {options}; server_name other.example.com; }}"
            with self.assertRaises(ng.SetupError):
                ng.choose_listens(site(), dump, "")

    def test_error_messages_distinguish_dns_rate_limit_and_validation(self):
        for raw, expected in (("too many failed authorizations", "Лимит CA"), ("NXDOMAIN", "DNS-запись"),
                              ("HTTP 404 unauthorized", "challenge"), ("Timeout during connect", "firewall")):
            self.assertIn(expected, ng.certificate_error(raw))

    def test_main_menu_places_nginx_directly_under_haproxy(self):
        source = (ROOT / "kto.sh").read_text(encoding="utf-8")
        for label in ("HAProxy", "HAProxy (мост, 8443/tcp)"):
            self.assertIn(f'labels+=("{label}")\n        actions+=("haproxy")\n'
                          '        labels+=("Nginx (WS + TLS)")\n        actions+=("nginx")', source)
        self.assertIn('nginx|nginx-ws|install-nginx) nginx_menu', source)
        self.assertIn('install_asset_file scripts/kto-nginx.py "$NGINX_MANAGER" 0755 bounded', source)


class TransactionTests(unittest.TestCase):
    def test_failed_apply_restores_old_files_and_removes_only_new_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old, new, untouched = root / "old", root / "new", root / "other"
            old.write_bytes(b"original\x00")
            untouched.write_text("HAProxy")
            with contextlib.redirect_stdout(io.StringIO()):
                tx = ng.Transaction(root / "backups")
                tx.write(old, "edited")
                tx.write(old, "edited again")
                tx.write(new, "new")
                tx.restore()
            self.assertEqual(old.read_bytes(), b"original\x00")
            self.assertFalse(new.exists())
            self.assertEqual(untouched.read_text(), "HAProxy")
            self.assertTrue((tx.folder / "manifest.json").exists())

    def test_refuses_to_overwrite_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original, alias = root / "original", root / "alias"
            original.write_text("leave me")
            try:
                alias.symlink_to(original)
            except OSError:
                self.skipTest("symlinks unavailable")
            with self.assertRaises(ng.SetupError):
                ng.atomic_write(alias, "bad")
            self.assertEqual(original.read_text(), "leave me")


class ProbeTests(unittest.TestCase):
    def test_ws_probe_validates_accept_and_returns_without_waiting_for_ws_payload(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(101)
                self.send_header("Upgrade", "websocket")
                self.send_header("Connection", "Upgrade")
                key = self.headers["Sec-WebSocket-Key"]
                accept = base64.b64encode(hashlib.sha1((key + ng.WS_GUID).encode()).digest()).decode()
                self.send_header("Sec-WebSocket-Accept", "bad" if self.path == "/bad" else accept)
                self.end_headers()

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            self.assertEqual(ng.probe_http("127.0.0.1", server.server_port, "test.example.com",
                                         "/ok", websocket=True, source="127.0.0.1")[0], 101)
            with self.assertRaises(ng.SetupError):
                ng.probe_http("127.0.0.1", server.server_port, "test.example.com", "/bad", websocket=True)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_http_certificate_failure_never_reaches_production(self):
        manager = ng.Manager()
        def run(args, *a, **kw):
            return subprocess.CompletedProcess(args, 1, "Timeout during connect")
        with mock.patch.object(manager, "run", side_effect=run) as runner, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(ng.SetupError, "firewall"):
                manager.certificate(site())
        self.assertEqual(runner.call_count, 1)
        args = runner.call_args.args[0]
        self.assertIn(ng.CA_STAGING, args)
        self.assertIn("--dry-run", args)
        self.assertNotIn(ng.CA_PRODUCTION, args)

    def test_http_certificate_issues_once_after_successful_staging(self):
        manager = ng.Manager()
        with mock.patch.object(manager, "run", side_effect=lambda args, *a, **kw: subprocess.CompletedProcess(args, 0, "ok")) as runner, \
                mock.patch.object(manager, "certificate_valid", return_value=True), contextlib.redirect_stdout(io.StringIO()):
            manager.certificate(site())
        self.assertEqual(runner.call_count, 2)
        self.assertIn(ng.CA_STAGING, runner.call_args_list[0].args[0])
        self.assertIn(ng.CA_PRODUCTION, runner.call_args_list[1].args[0])
        self.assertNotIn("--force-renewal", str(runner.call_args_list))


class FakeManager(ng.Manager):
    def __init__(self):
        super().__init__()
        self.calls = []
        self.verify_fail = False
        self.ws_ready = True
        self.has_certificate = True
        self.ca_fail = False
        self.dns_ok = True
        self.runtime_count = 0

    def log(self, text):
        self.calls.append(text)

    def storage(self):
        pass

    def dependencies(self):
        pass

    def addresses(self):
        return {"192.0.2.10": "ens3", "192.0.2.11": "wan2"}

    def active(self, unit):
        return unit == "nginx"

    def run(self, args, timeout=30, **kwargs):
        self.calls.append(args)
        out = ""
        rc = 0
        if args[:2] == ["nginx", "-T"]:
            out = f"# configuration file {ng.NGINX}:\n" + ng.NGINX.read_text()
            for path in ng.CONF.glob("*.conf"):
                out += f"\n# configuration file {path}:\n" + path.read_text()
        elif "is-enabled" in args:
            rc = 1
        return subprocess.CompletedProcess(args, rc, out)

    def dns(self, site):
        return self.dns_ok

    def source_check(self, site, local):
        site.source = "192.0.2.11"
        return True

    def find_certificate(self, site):
        return self.has_certificate

    def renewal_info(self, site):
        return "webroot", site.webroot

    def firewall(self, site):
        pass

    def check_http_token(self, site):
        pass

    def certificate(self, site):
        if self.ca_fail:
            raise ng.SetupError("CA timeout")
        site.cert, site.key = "/cert.pem", "/key.pem"

    def apply_runtime(self):
        self.runtime_count += 1

    def verify(self, site):
        if self.verify_fail:
            raise ng.SetupError("TLS verification failed")
        return self.ws_ready

    def runtime_capacity(self):
        pass


class DeployTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        mapping = dict(NGINX="nginx/nginx.conf", CONF="nginx/conf.d", STATE="state", BACKUPS="backups",
                       WEBROOT="webroot", LOGS="logs", LOG="manager.log", ROTATE="rotate/nginx",
                       UNIT="units/kto-nginx-logrotate.service", TIMER="units/kto-nginx-logrotate.timer",
                       HOOK="hooks/deploy", LE="letsencrypt", DEFAULT_SITE="nginx/default")
        for name, value in mapping.items():
            self.stack.enter_context(mock.patch.object(ng, name, self.root / value))
        ng.NGINX.parent.mkdir(parents=True)
        ng.CONF.mkdir(parents=True)
        self.original = ('user www-data;\nworker_processes auto;\nevents {\n worker_connections 768;\n}\n'
                         f'http {{ include {json.dumps(str(ng.CONF / "*.conf"))}; }}\n')
        ng.NGINX.write_text(self.original)
        self.current = site(webroot=str(ng.WEBROOT))
        # Only Windows test fixture paths bypass the production POSIX path validator.
        validate_path = ng.cert_path
        self.stack.enter_context(mock.patch.object(ng, "cert_path", side_effect=lambda s: s if s.startswith(str(self.root)) else validate_path(s)))
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.manager = FakeManager()

    def test_success_writes_only_scoped_config_and_protections(self):
        unrelated = ng.CONF / "unrelated.conf"
        unrelated.write_text("# untouched")
        self.manager.deploy(self.current)
        saved = ng.load_site(self.current.state)
        self.assertEqual(saved.status, "ready")
        self.assertEqual(saved.source, "192.0.2.11")
        self.assertIn(saved.health_token, saved.config.read_text())
        self.assertEqual(unrelated.read_text(), "# untouched")
        self.assertFalse(saved.draft.exists())
        self.assertIn("8192", ng.NGINX.read_text())
        self.assertIn("maxsize 50M", ng.ROTATE.read_text())
        self.assertIn("OnUnitActiveSec=5min", ng.TIMER.read_text())
        self.assertIn("systemctl reload nginx", ng.HOOK.read_text())
        commands = [call for call in self.manager.calls if isinstance(call, list)]
        self.assertNotIn("restart", str(commands))
        self.assertNotIn("haproxy", str(commands))

    def test_repeated_deploy_keeps_exactly_one_managed_vhost_and_existing_webroot(self):
        self.manager.deploy(self.current)
        previous = self.current.health_token
        self.manager.deploy(self.current)
        self.assertEqual(len(list(ng.CONF.glob("kto-wss-*.conf"))), 1)
        self.assertNotEqual(self.current.health_token, previous)
        self.assertEqual(ng.NGINX.read_text().count("worker_rlimit_nofile"), 1)
        self.assertEqual(ng.load_site(self.current.state).webroot, str(ng.WEBROOT))

    def test_fresh_packaged_default_is_disabled_without_touching_existing_sites(self):
        ng.DEFAULT_SITE.write_text("server { listen 80 default_server; server_name _; }")
        def dependencies():
            self.manager.fresh_default = True
        with mock.patch.object(self.manager, "dependencies", side_effect=dependencies):
            self.manager.deploy(self.current)
        self.assertIn("Packaged default disabled", ng.DEFAULT_SITE.read_text())
        self.assertTrue(any(path.read_text().startswith("server {") for path in ng.BACKUPS.glob("*/*.bak")))

    def test_failed_tls_verification_rolls_back_configuration_and_preserves_draft(self):
        self.manager.verify_fail = True
        with self.assertRaisesRegex(ng.SetupError, "TLS verification"):
            self.manager.deploy(self.current)
        self.assertEqual(ng.NGINX.read_text(), self.original)
        self.assertFalse(self.current.config.exists())
        self.assertFalse(self.current.state.exists())
        self.assertTrue(self.current.draft.exists())
        self.assertGreaterEqual(self.manager.runtime_count, 2)

    def test_ca_failure_restores_existing_route_without_deleting_certificate(self):
        self.current.config.write_text(ng.MANAGED + "\n# original config\n")
        original = self.current.config.read_text()
        self.manager.has_certificate = False
        self.manager.ca_fail = True
        with self.assertRaisesRegex(ng.SetupError, "CA timeout"):
            self.manager.deploy(self.current)
        self.assertEqual(self.current.config.read_text(), original)
        self.assertEqual(ng.NGINX.read_text(), self.original)
        self.assertNotIn("delete", str(self.manager.calls))

    def test_bad_dns_aborts_before_runtime_or_certificate_request(self):
        self.manager.has_certificate = False
        self.manager.dns_ok = False
        with self.assertRaisesRegex(ng.SetupError, "HTTP-01"):
            self.manager.deploy(self.current)
        self.assertEqual(self.manager.runtime_count, 0)
        self.assertEqual(ng.NGINX.read_text(), self.original)

    def test_new_front_with_ws_failure_is_not_marked_ready(self):
        self.manager.ws_ready = False
        self.manager.deploy(self.current)
        self.assertEqual(ng.load_site(self.current.state).status, "backend-pending")

    def test_updating_working_site_rolls_back_when_ws_fails_and_user_does_not_override(self):
        self.manager.deploy(self.current)
        before = self.current.config.read_text()
        self.manager.ws_ready = False
        with mock.patch.object(ng, "confirm", return_value=False), self.assertRaises(ng.SetupError):
            self.manager.deploy(self.current)
        self.assertEqual(self.current.config.read_text(), before)
        self.assertEqual(ng.load_site(self.current.state).status, "ready")

    def test_support_file_failure_rolls_back_site_and_capacity(self):
        ng.ROTATE.parent.mkdir(parents=True)
        ng.ROTATE.write_text("# belongs to someone else")
        with self.assertRaisesRegex(ng.SetupError, "не принадлежит"):
            self.manager.deploy(self.current)
        self.assertEqual(ng.ROTATE.read_text(), "# belongs to someone else")
        self.assertEqual(ng.NGINX.read_text(), self.original)
        self.assertFalse(self.current.config.exists())

    def test_renewal_keeps_existing_webroot_mapping(self):
        renewal = ng.LE / "renewal"
        renewal.mkdir(parents=True)
        (renewal / "test.conf").write_text("[renewalparams]\nauthenticator = webroot\nwebroot_path = /fallback,\n"
                                          "[[webroot_map]]\ntest.example.com = /var/www/original\n")
        self.assertEqual(ng.Manager.renewal_info(self.manager, self.current), ("webroot", "/var/www/original"))

    def test_draft_takes_precedence_for_resume_and_removal_is_scoped(self):
        self.manager.deploy(self.current)
        draft = dataclasses.replace(self.current, backend_port=9081, status="draft")
        ng.atomic_write(draft.draft, json.dumps(dataclasses.asdict(draft)))
        self.assertEqual(ng.sites()[0].backend_port, 9081)
        with mock.patch.object(ng, "confirm", return_value=True):
            self.manager.remove(draft)
        self.assertFalse(draft.config.exists())
        self.assertFalse(draft.state.exists())
        self.assertFalse(draft.draft.exists())
        self.assertTrue(ng.ROTATE.exists())

    def test_repair_restores_only_its_broken_vhost_from_saved_state(self):
        self.manager.deploy(self.current)
        self.current.config.write_text(ng.MANAGED + "\nBROKEN\n")
        runner = self.manager.run
        def run(args, *a, **kw):
            if args == ["nginx", "-t"] and "BROKEN" in self.current.config.read_text():
                return subprocess.CompletedProcess(args, 1, "syntax error in owned site")
            return runner(args, *a, **kw)
        with mock.patch.object(self.manager, "run", side_effect=run):
            self.manager.repair(self.current)
        self.assertNotIn("BROKEN", self.current.config.read_text())
        self.assertEqual(ng.load_site(self.current.state).status, "ready")

    def test_repair_cannot_claim_or_replace_a_foreign_broken_vhost(self):
        self.manager.deploy(self.current)
        self.current.config.write_text("# not managed\nBROKEN")
        with mock.patch.object(self.manager, "run", return_value=subprocess.CompletedProcess([], 1, "syntax error")):
            with self.assertRaises(ng.SetupError):
                self.manager.repair(self.current)
        self.assertEqual(self.current.config.read_text(), "# not managed\nBROKEN")


if __name__ == "__main__":
    unittest.main()
