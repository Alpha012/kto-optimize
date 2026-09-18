import importlib.util
import re
import shlex
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
KTO = (ROOT / "kto.sh").read_text(encoding="utf-8")
PUSH = (ROOT / "scripts/kto-stats-push.sh").read_text(encoding="utf-8")


def function(source, name):
    match = re.search(rf"(?m)^{name}\(\) \{{", source)
    if match is None:
        raise AssertionError(name)
    end = re.search(r"\n[a-zA-Z_][a-zA-Z0-9_]*\(\) \{", source[match.end():])
    return source[match.start():match.end() + end.start()] if end else source[match.start():]


class HaproxyDnsTests(unittest.TestCase):
    def shell(self, script):
        bash = shutil.which("bash") or r"C:\Program Files\Git\bin\bash.exe"
        if not Path(bash).is_file():
            self.skipTest("bash is unavailable")
        result = subprocess.run([bash, "-lc", "set -euo pipefail\n" + script], cwd=ROOT,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

    def collector(self):
        spec = importlib.util.spec_from_file_location("dns_test_collector", ROOT / "scripts/kto-stats-collector.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_target_validation_agrees_in_menu_push_and_collector(self):
        valid = {
            "hetz.cdnvideo.work": "hetz.cdnvideo.work:443",
            " HETZ.CDNVIDEO.WORK.:0443 ": "hetz.cdnvideo.work:443",
            "backend.example.com:8443": "backend.example.com:8443",
            "xn--e1afmkfd.xn--p1ai:9080": "xn--e1afmkfd.xn--p1ai:9080",
            "a.b:1": "a.b:1",
            "192.0.2.7": "192.0.2.7:443",
            "192.0.2.7:65535": "192.0.2.7:65535",
        }
        invalid = ["", "https://backend.example.com", "backend.example.com/path", "xray",
                   "*.example.com", "-bad.example.com", "bad-.example.com", "bad..example.com",
                   "bad_name.example.com", "a.example.com..", "a.example.com:443:8443",
                   "192.0.2.7:443:8443", "256.1.2.3", "999.999.999.999", "[::1]:443",
                   "a.example.com:0", "a.example.com:65536", "a.example.com:-1", "a.example.com:",
                   "a.example.com:18446744073709552059", "a.example.com:４４３",
                   "a.example.com check", "a.example.com\ncheck", "a.example.com;check",
                   "a.example.com#comment", "$(id).example.com", "a" * 64 + ".com",
                   ".".join(["a" * 63] * 4)]
        collector = self.collector()
        for raw, expected in valid.items():
            with self.subTest(raw=raw):
                self.assertEqual(collector.normalize_haproxy_target(raw), expected)
        for raw in invalid:
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    collector.normalize_haproxy_target(raw)
        for source in (KTO, PUSH):
            harness = function(KTO, "validate_domain") + "\n"
            harness += function(source, "validate_ipv4") + "\n" + function(source, "normalize_haproxy_target")
            for raw, expected in valid.items():
                harness += f'\n[[ "$(normalize_haproxy_target {shlex.quote(raw)})" == {shlex.quote(expected)} ]]'
            for raw in invalid:
                harness += f'\nif normalize_haproxy_target {shlex.quote(raw)}; then echo invalid-accepted; exit 1; fi'
            self.shell(harness)

    def test_mixed_pool_and_dns_round_trip_preserves_route_options(self):
        self.shell(r'''
source <(sed '/^main /d' kto.sh)
SUDO=()
KTO_HAPROXY_MAXCONN=100000
KTO_HAPROXY_NBTHREAD=2
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
pool=$(normalize_haproxy_target_pool 'HETZ.CDNVIDEO.WORK,192.0.2.7:8443;hetz.cdnvideo.work.:443 hetz.cdnvideo.work:9080')
[[ "$pool" == 'hetz.cdnvideo.work:443,192.0.2.7:8443,hetz.cdnvideo.work:9080' ]]
print_haproxy_route 2001 "$pool" 'client.example.com' 198.51.100.5 default 198.51.100.5 1 > "$root/routes"
render_haproxy_routes_config "$root/routes" "$root/config"
[[ "$(grep -c '^resolvers kto_dns$' "$root/config")" == 1 ]]
grep -q '^    parse-resolv-conf$' "$root/config"
grep -q '^    hold valid 10s$' "$root/config"
grep -Fqx '    server xray1 hetz.cdnvideo.work:443 check weight 10 source 198.51.100.5 send-proxy-v2 maxconn 15000 resolvers kto_dns resolve-prefer ipv4 resolve-opts allow-dup-ip init-addr last,none' "$root/config"
grep -Fqx '    server xray2 192.0.2.7:8443 check weight 10 source 198.51.100.5 send-proxy-v2 maxconn 15000' "$root/config"
grep -Fqx '    server xray3 hetz.cdnvideo.work:9080 check weight 10 source 198.51.100.5 send-proxy-v2 maxconn 15000 resolvers kto_dns resolve-prefer ipv4 resolve-opts allow-dup-ip init-addr last,none' "$root/config"
grep -Fqx '    acl allowed_sni req.ssl_sni -i client.example.com' "$root/config"
! grep -q 'init-addr .*libc' "$root/config"
extract_haproxy_routes "$root/config" > "$root/parsed"
haproxy_routes_round_trip_equal "$root/routes" "$root/parsed"
render_haproxy_routes_config "$root/parsed" "$root/config2"
cmp "$root/config" "$root/config2"
''')

    def test_ip_only_config_does_not_require_dns(self):
        self.shell(r'''
source <(sed '/^main /d' kto.sh)
SUDO=()
KTO_HAPROXY_MAXCONN=100000
KTO_HAPROXY_NBTHREAD=2
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
print_haproxy_route 443 192.0.2.7 any default > "$root/routes"
render_haproxy_routes_config "$root/routes" "$root/config"
! grep -q 'resolvers\|resolve-prefer\|init-addr\|parse-resolv-conf' "$root/config"
grep -Fqx '    server xray1 192.0.2.7:443 check weight 10 maxconn 15000' "$root/config"
''')

    def test_domain_route_survives_collector_normalization(self):
        collector = self.collector()
        route = collector.normalize_haproxy_route({
            "port": 2001, "targets": ["HETZ.CDNVIDEO.WORK", "192.0.2.7:8443"],
            "sni": ["any"], "listen_ip": "198.51.100.5", "source_ip": "198.51.100.5",
            "server_maxconn": 15000, "send_proxy_v2": True,
        })
        self.assertEqual(route["targets"], ["hetz.cdnvideo.work:443", "192.0.2.7:8443"])
        self.assertEqual(route["source_ip"], "198.51.100.5")
        self.assertTrue(route["send_proxy_v2"])
        self.assertEqual(collector.normalize_haproxy_targets("HETZ.CDNVIDEO.WORK,hetz.cdnvideo.work.:443"),
                         ["hetz.cdnvideo.work:443"])

    def test_legacy_push_adds_dns_once_and_preserves_other_servers(self):
        helpers = "\n".join(function(PUSH, name) for name in (
            "validate_ipv4", "normalize_haproxy_target", "render_haproxy_dns_resolvers", "rewrite_haproxy_backend_target"))
        self.shell(helpers + r'''
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
printf 'backend vless_pool\n    server xray1 192.0.2.7:443 check source 198.51.100.5 send-proxy-v2 maxconn 15000 # note\n    server xray2 192.0.2.8:443 check\n' > "$root/a"
rewrite_haproxy_backend_target "$root/a" xray1 hetz.cdnvideo.work "$root/b"
grep -Fqx '    server xray1 hetz.cdnvideo.work:443 check source 198.51.100.5 send-proxy-v2 maxconn 15000 resolvers kto_dns resolve-prefer ipv4 resolve-opts allow-dup-ip init-addr last,none' "$root/b"
grep -Fqx '    server xray2 192.0.2.8:443 check' "$root/b"
rewrite_haproxy_backend_target "$root/b" xray1 other.example.com:8443 "$root/c"
[[ "$(grep -c '^resolvers kto_dns$' "$root/c")" == 1 ]]
[[ "$(grep -o 'resolvers kto_dns' "$root/c" | wc -l)" == 2 ]]
grep -q 'server xray1 other.example.com:8443' "$root/c"
! rewrite_haproxy_backend_target "$root/c" missing other.example.com "$root/d"
! rewrite_haproxy_backend_target "$root/c" xray1 'https://example.com' "$root/d"
''')

    def test_dns_blocks_and_ui_descriptions_remain_consistent(self):
        self.assertEqual(function(KTO, "render_haproxy_dns_resolvers"), function(PUSH, "render_haproxy_dns_resolvers"))
        self.assertIn("IP/домен[:порт]", function(KTO, "ask_haproxy_target_pool_default"))
        self.assertIn('rewrite_haproxy_backend_target "$tmp_cfg"', function(PUSH, "apply_collector_haproxy_config"))


if __name__ == "__main__":
    unittest.main()
