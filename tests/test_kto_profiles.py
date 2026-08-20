import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
KTO = (ROOT / "kto.sh").read_text(encoding="utf-8")
PUSH = (ROOT / "scripts" / "kto-stats-push.sh").read_text(encoding="utf-8")
COLLECTOR = (ROOT / "scripts" / "kto-stats-collector.py").read_text(encoding="utf-8")
MOBILE443 = (ROOT / "scripts" / "kto-mobile443.sh").read_text(encoding="utf-8")
ADDITIONAL_IPS = (ROOT / "scripts" / "kto-additional-ips.sh").read_text(encoding="utf-8")
REMNA_EGRESS = (ROOT / "scripts" / "kto-remnawave-egress.sh").read_text(encoding="utf-8")
HAPROXY_BANDWIDTH = (ROOT / "scripts" / "kto-haproxy-bandwidth.sh").read_text(encoding="utf-8")
DPI_PREFLIGHT_PATH = ROOT / "scripts" / "kto-dpi-preflight.py"
DPI_PREFLIGHT = DPI_PREFLIGHT_PATH.read_text(encoding="utf-8")


def bash_executable():
    candidates = [
        shutil.which("bash"),
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files (x86)\Git\bin\bash.exe",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return str(candidate)
    return None


def function_body(source, name):
    function = re.search(rf"(?m)^{re.escape(name)}\(\) \{{", source)
    if function is None:
        raise ValueError(f"function not found: {name}")
    start = function.start()
    next_function = re.search(r"\n[a-zA-Z_][a-zA-Z0-9_]*\(\) \{", source[start + 1 :])
    if next_function is None:
        return source[start:]
    return source[start : start + 1 + next_function.start()]


class CombinedNodeProfileTests(unittest.TestCase):
    def test_build_markers_stay_in_sync(self):
        self.assertIn('SCRIPT_BUILD="v330"', KTO)
        self.assertIn('PUSH_BUILD="v330"', PUSH)
        self.assertIn('COLLECTOR_BUILD = "v330"', COLLECTOR)
        self.assertIn('MOBILE443_BUILD="v330"', MOBILE443)
        self.assertIn('ADDITIONAL_IP_BUILD="v330"', ADDITIONAL_IPS)
        self.assertIn('REMNA_EGRESS_BUILD="v330"', REMNA_EGRESS)
        self.assertIn('HAPROXY_BANDWIDTH_BUILD="v330"', HAPROXY_BANDWIDTH)
        self.assertIn('DPI_PREFLIGHT_BUILD = "v330"', DPI_PREFLIGHT)

    def test_remote_haproxy_bandwidth_control_is_transactional(self):
        report = function_body(KTO, "haproxy_bandwidth_remote_report_json")
        apply_limits = function_body(KTO, "haproxy_bandwidth_remote_apply_json")
        self.assertIn('load_haproxy_bandwidth_config "$limits_file"', report)
        self.assertIn('length <= 64', apply_limits)
        self.assertIn('haproxy_input_ip_available "$ip"', apply_limits)
        self.assertIn('commit_haproxy_bandwidth_config "$previous_file" "$next_file" "$had_config"', apply_limits)
        self.assertIn('haproxy-bandwidth-remote-report', KTO)
        self.assertIn('haproxy-bandwidth-remote-apply', KTO)

    def test_stats_push_discovers_and_reports_per_interface_traffic(self):
        self.assertIn("list_public_ipv4_interfaces()", PUSH)
        self.assertIn("ensure_vnstat_interfaces", PUSH)
        self.assertIn("ip_stats: $ip_stats", PUSH)
        self.assertIn("counter_rx_bytes: $counter_rx_bytes", PUSH)
        self.assertIn("counter_tx_bytes: $counter_tx_bytes", PUSH)
        self.assertIn("counter_sample_ms: $counter_sample_ms", PUSH)
        self.assertIn('rate_source: "interface"', PUSH)
        self.assertIn('read_haproxy_traffic_counters', PUSH)
        self.assertIn('apply_haproxy_traffic_counters "$ip_stats"', PUSH)
        self.assertIn("counter_generation", PUSH)
        self.assertIn("link_counter_rx_bytes", PUSH)
        self.assertIn("list_haproxy_additional_source_ips | awk", KTO)

    def test_stats_push_uses_haproxy_frontend_bytes_for_rate_counters(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
set -Eeuo pipefail
source <(awk '/^haproxy_frontend_bindings_tsv\(\)/ { keep=1 } /^load_haproxy_apply_result\(\)/ { exit } keep' scripts/kto-stats-push.sh)
config=$(mktemp)
bindings=$(mktemp)
counters=$(mktemp)
trap 'rm -f "$config" "$bindings" "$counters"' EXIT
cat > "$config" <<'EOF'
global
    stats socket /run/haproxy/admin.sock
frontend vless_in
    bind 203.0.113.10:443
    default_backend vless_pool
frontend vless_in_8443
    bind 203.0.113.10:8443
    default_backend vless_pool_8443
frontend vless_in_9443
    bind *:9443
    default_backend vless_pool_9443
frontend unrelated
    bind 198.51.100.20:9000
    default_backend unrelated_pool
frontend ambiguous
    bind 203.0.113.10:10000
    bind 198.51.100.20:10000
    default_backend ambiguous_pool
EOF
haproxy_frontend_bindings_tsv "$config" > "$bindings"
grep -Fqx $'vless_in\t203.0.113.10\t443' "$bindings"
grep -Fqx $'vless_in_8443\t203.0.113.10\t8443' "$bindings"
grep -Fqx $'vless_in_9443\t*\t9443' "$bindings"
! grep -Fq $'ambiguous\t' "$bindings"

haproxy_frontend_counters_tsv > "$counters" <<'EOF'
# svname,bout,pxname,bin,status
FRONTEND,2000,vless_in,1000,OPEN
FRONTEND,4000,vless_in_8443,3000,OPEN
FRONTEND,7000,vless_in_9443,5000,OPEN
FRONTEND,9000,unrelated,8000,OPEN
FRONTEND,broken,vless_broken,not-a-counter,OPEN
BACKEND,2000,vless_pool,1000,UP
EOF
grep -Fqx $'vless_in\t1000\t2000' "$counters"
grep -Fqx $'vless_in_8443\t3000\t4000' "$counters"
grep -Fqx $'vless_in_9443\t5000\t7000' "$counters"
! grep -Fq $'vless_pool\t' "$counters"
! grep -Fq $'vless_broken\t' "$counters"
command -v jq >/dev/null 2>&1 || exit 0
routes='[
  {"listen_ip":"203.0.113.10","port":443},
  {"listen_ip":"203.0.113.10","port":8443},
  {"listen_ip":"*","port":9443}
]'
links='[{"ip":"203.0.113.10","rx":900000,"tx":800000,"sample_ms":123460}]'
result=$(build_haproxy_traffic_counters_json \
  "$bindings" "$counters" "$routes" 123456 203.0.113.10 generation-a "$links")
jq -e '. == [{
    "ip":"203.0.113.10",
    "rate_source":"haproxy",
    "counter_generation":"generation-a",
    "counter_rx_bytes":9000,
    "counter_tx_bytes":13000,
    "counter_sample_ms":123456,
    "link_counter_rx_bytes":900000,
    "link_counter_tx_bytes":800000,
    "link_counter_sample_ms":123460
}]' <<< "$result" >/dev/null

haproxy_traffic_enabled=true
haproxy_traffic_counters="$result"
merged=$(apply_haproxy_traffic_counters '[
  {"iface":"ens3","ip":"203.0.113.10","counter_rx_bytes":999999,"counter_tx_bytes":999999,"counter_sample_ms":10},
  {"iface":"wan2","ip":"198.51.100.20","counter_rx_bytes":888888,"counter_tx_bytes":888888,"counter_sample_ms":10}
]')
jq -e '.[0].rate_source == "haproxy"
    and .[0].counter_rx_bytes == 9000
    and .[0].counter_tx_bytes == 13000
    and .[0].counter_sample_ms == 123456
    and .[0].counter_generation == "generation-a"
    and .[0].link_counter_rx_bytes == 900000
    and .[0].link_counter_tx_bytes == 800000
    and .[0].link_counter_sample_ms == 123460
    and .[1].rate_source == "haproxy"
    and .[1].counter_generation == ""
    and .[1].counter_rx_bytes == 0
    and .[1].counter_tx_bytes == 0
    and .[1].counter_sample_ms == 0
    and .[1].link_counter_rx_bytes == 888888
    and .[1].link_counter_tx_bytes == 888888
    and .[1].link_counter_sample_ms == 10' <<< "$merged" >/dev/null
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_combined_profile_exposes_both_capabilities(self):
        valid = function_body(KTO, "valid_node_profile")
        label = function_body(KTO, "node_profile_label")
        reality = function_body(KTO, "node_profile_includes_reality")
        hysteria = function_body(KTO, "node_profile_includes_hysteria2")

        self.assertIn('"reality_hysteria2"', valid)
        self.assertIn('reality_hysteria2) echo "Reality + Hysteria2"', label)
        self.assertIn('"reality_hysteria2"', reality)
        self.assertIn('"reality_hysteria2"', hysteria)

    def test_combined_install_orders_ssl_before_node_and_selfsteal(self):
        body = function_body(KTO, "install_common_stack")
        combo = body[body.index('elif [[ "$NODE_PROFILE" == "reality_hysteria2" ]]') :]
        steps = [
            'do_issue_ssl_certificate "$domain"',
            'do_install_remnawave_node "$secret"',
            'do_install_selfsteal "$domain"',
            "do_install_warp_native",
        ]
        positions = [combo.index(step) for step in steps]
        self.assertEqual(positions, sorted(positions))

    def test_existing_profile_install_flows_are_unchanged(self):
        body = function_body(KTO, "install_common_stack")
        reality = body[
            body.index('if [[ "$NODE_PROFILE" == "reality" ]]') :
            body.index('elif [[ "$NODE_PROFILE" == "hysteria2" ]]')
        ]
        hysteria = body[
            body.index('elif [[ "$NODE_PROFILE" == "hysteria2" ]]') :
            body.index('elif [[ "$NODE_PROFILE" == "reality_hysteria2" ]]')
        ]

        self.assertIn("do_install_selfsteal", reality)
        self.assertNotIn("do_issue_ssl_certificate", reality)
        self.assertIn("do_issue_ssl_certificate", hysteria)
        self.assertNotIn("do_install_selfsteal", hysteria)

    def test_selfsteal_caddy_timeouts_are_safe_and_idempotent(self):
        install_selfsteal = function_body(KTO, "do_install_selfsteal")
        harden = function_body(KTO, "harden_selfsteal_caddy")

        self.assertIn("harden_selfsteal_caddy", install_selfsteal)
        self.assertIn("# kto-selfsteal-timeouts-v1", harden)
        self.assertIn('read_header 5s', harden)
        self.assertIn('idle 15s', harden)
        self.assertIn('max_header_size 64KB', harden)
        self.assertNotIn('read_body', harden)
        self.assertNotIn('write 15s', harden)
        self.assertNotIn('fallback_policy', harden)
        self.assertIn('caddy validate --config /etc/caddy/Caddyfile', harden)
        self.assertIn('docker restart --time 3', harden)
        self.assertIn('selfsteal-harden|selfsteal-timeouts', KTO)

        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
SUDO=()
LOG_FILE=$(mktemp)
work=$(mktemp -d)
events="$work/events"
KTO_SELFSTEAL_CADDYFILE="$work/Caddyfile"
KTO_SELFSTEAL_CADDY_CONTAINER=caddy-selfsteal
trap 'rm -rf "$work" "$LOG_FILE"' EXIT
cat > "$KTO_SELFSTEAL_CADDYFILE" <<'EOF'
{
    https_port 9443
    default_bind 127.0.0.1
    servers {
        protocols h1 h2
        listener_wrappers {
            proxy_protocol {
                allow 127.0.0.1/32
            }
            tls
        }
    }
    admin off
}
:9443 {
    tls internal
    respond 204
}
EOF
docker() {
    { printf '%s|' "$@"; printf '\n'; } >> "$events"
    case "${1:-}" in
        inspect|exec|restart) return 0 ;;
    esac
    return 1
}
harden_selfsteal_caddy
harden_selfsteal_caddy
[[ "$(grep -Fc '# kto-selfsteal-timeouts-v1' "$KTO_SELFSTEAL_CADDYFILE")" == 1 ]]
grep -q 'read_header 5s' "$KTO_SELFSTEAL_CADDYFILE"
grep -q 'idle 15s' "$KTO_SELFSTEAL_CADDYFILE"
grep -q 'max_header_size 64KB' "$KTO_SELFSTEAL_CADDYFILE"
[[ "$(grep -c '^exec|' "$events")" == 1 ]]
[[ "$(grep -c '^restart|--time|3|caddy-selfsteal|' "$events")" == 1 ]]
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_combined_profile_mounts_certificates_and_opens_udp(self):
        node_install = function_body(KTO, "do_install_remnawave_node")
        firewall = function_body(KTO, "opt_firewall")
        firewall_check = function_body(KTO, "system_check_firewall")

        self.assertIn("if node_profile_includes_hysteria2; then", node_install)
        self.assertIn("- /opt/remnawave:/opt/remnawave:ro", node_install)
        self.assertIn('if [[ "$MACHINE_MODE" == "node" ]]', firewall)
        self.assertIn('ufw allow 443/udp', firewall)
        self.assertIn('ufw_rule_allowed "443/udp"', firewall_check)

    def test_menu_and_remote_status_show_combined_features(self):
        menu = function_body(KTO, "menu")
        status = function_body(PUSH, "status_panel_rows_json")

        self.assertIn("node_profile_includes_reality", menu)
        self.assertIn("node_profile_includes_hysteria2", menu)
        self.assertIn('reality_hysteria2) profile_label="Reality + Hysteria2"', status)
        self.assertIn('section="SSL"', status)
        self.assertIn('cert_dir="/opt/remnawave"', status)

    def test_vps_warp_installer_is_unattended_and_verified(self):
        install = function_body(KTO, "do_install_warp_native")

        self.assertIn("tagashi666/vps-warp/main/warp_install.sh", KTO)
        self.assertIn('bash -n "$script"', install)
        self.assertIn("printf '2\\n\\n'", install)
        self.assertIn("setsid --wait", install)
        self.assertIn("/etc/wireguard/warp.conf", install)
        self.assertIn("/usr/local/bin/vps-warp", install)
        self.assertIn("systemctl is-active --quiet wg-quick@warp", install)

    def test_speedtest_installer_uses_verified_non_snap_fallbacks(self):
        fetch = function_body(KTO, "speedtest_fetch_url")
        archive = function_body(KTO, "speedtest_install_static_archive")
        package = function_body(KTO, "speedtest_install_packagecloud_deb")
        install = function_body(KTO, "install_speedtest")

        self.assertNotIn("snap install speedtest", KTO)
        self.assertIn("curl -fL", fetch)
        self.assertIn("curl -4 -fL", fetch)
        self.assertIn("wget -4", fetch)
        self.assertIn("speedtest_verify_sha256", archive)
        self.assertIn("speedtest_verify_sha256", package)
        self.assertIn('dpkg-deb -f "$package_file" Package', package)
        self.assertIn('apt-get -o DPkg::Lock::Timeout=600 install -y "$package_file"', package)
        self.assertIn("speedtest_install_static_archive", install)
        self.assertIn("speedtest_install_packagecloud_deb", install)
        self.assertLess(
            install.index("speedtest_install_packagecloud_deb"),
            install.index("speedtest_install_static_archive"),
        )
        self.assertIn("Проверены официальный Packagecloud и статический архив", install)

    def test_speedtest_download_retries_with_ipv4_and_wget(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
target=$(mktemp)
output=$(mktemp)
trap 'rm -f "$target" "$output"' EXIT
RUN_CALLS=()
stage() { :; }
warn() { :; }
ok() { :; }
command_exists() { [[ "$1" == "curl" || "$1" == "wget" || "$1" == "timeout" ]]; }
run_live_capture_timeout() {
    RUN_CALLS+=("$3:${4:-}")
    if (( ${#RUN_CALLS[@]} == 3 )); then
        printf 'downloaded\n' > "$target"
        return 0
    fi
    return 1
}
speedtest_fetch_url test https://example.invalid/speedtest "$target" "$output"
[[ "${#RUN_CALLS[@]}" == 3 ]]
[[ "${RUN_CALLS[0]}" == "curl:-fL" ]]
[[ "${RUN_CALLS[1]}" == "curl:-4" ]]
[[ "${RUN_CALLS[2]}" == "wget:-4" ]]
[[ -s "$target" ]]
profile=$(speedtest_platform_profile x86_64)
IFS=$'\t' read -r archive_url archive_hash deb_url deb_hash deb_arch <<< "$profile"
[[ "$archive_url" == *install.speedtest.net* ]]
[[ "$deb_url" == *packagecloud.io* ]]
[[ "$archive_hash" == "$SPEEDTEST_X86_64_ARCHIVE_SHA256" ]]
[[ "$deb_hash" == "$SPEEDTEST_AMD64_DEB_SHA256" ]]
[[ "$deb_arch" == amd64 ]]
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_speedtest_ru_binds_all_test_traffic_to_requested_ip(self):
        speedtest_ru = function_body(KTO, "speedtest_ru")
        download_bench = function_body(KTO, "download_speedtest_ru_bench")
        main = function_body(KTO, "main")

        self.assertIn(
            'SPEEDTEST_RU_URL="${KTO_SPEEDTEST_RU_URL:-https://bench.tlab.pw/bench.sh}"',
            KTO,
        )
        self.assertIn('local source_ip="${1:-}"', speedtest_ru)
        self.assertIn('ip -4 route get 1.1.1.1 from "$source_ip"', speedtest_ru)
        self.assertIn('download_speedtest_ru_bench "$bench_script" "$source_ip"', speedtest_ru)
        self.assertIn('"--bind-address=${source_ip}"', download_bench)
        self.assertIn('--interface "$source_ip"', download_bench)
        self.assertIn('"$bind_dir/iperf3" "$real_iperf3" -B "$source_ip"', speedtest_ru)
        self.assertIn('"$bind_dir/ping" "$real_ping" -I "$source_ip"', speedtest_ru)
        self.assertIn('"--bind-address=${source_ip}"', speedtest_ru)
        self.assertIn('--interface "$source_ip"', speedtest_ru)
        self.assertIn('PATH="${bind_dir}:${PATH}" bash "$bench_script"', speedtest_ru)
        self.assertIn('speedtest_ru "${2:-}"', main)

        bash = bash_executable()
        if bash is None:
            return
        harness = r'''
source <(sed '/^main /d' kto.sh)
wrapper=$(mktemp)
trap 'rm -f "$wrapper"' EXIT
write_speedtest_ru_bind_wrapper "$wrapper" /bin/echo -B 217.19.122.109
[[ "$("$wrapper" hello)" == '-B 217.19.122.109 hello' ]]
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_ip_dependent_tests_select_and_bind_the_source_ipv4(self):
        listing = function_body(KTO, "list_test_source_ipv4s")
        selector = function_body(KTO, "select_test_source_ipv4")
        speedtest = function_body(KTO, "install_speedtest")
        speedtest_ru = function_body(KTO, "speedtest_ru")
        network = function_body(KTO, "network_test")
        network_resolve = function_body(KTO, "network_test_resolve")
        network_tcp = function_body(KTO, "network_test_tcp")
        network_https = function_body(KTO, "network_test_https")
        network_raw = function_body(KTO, "network_test_raw_ip")
        network_ping = function_body(KTO, "network_test_ping")
        network_mtr = function_body(KTO, "network_test_mtr")
        ipcheck_place = function_body(KTO, "ipcheck_place")
        ipcheck_region = function_body(KTO, "ipcheck_region")
        downloader = function_body(KTO, "download_ip_test_script")

        self.assertIn('ip -4 route get 1.1.1.1 from "$source_ip"', listing)
        self.assertIn('[[ "$route_interface" == "$interface" ]]', listing)
        self.assertIn('if (( ${#rows[@]} == 1 )); then', selector)
        self.assertIn('Выберите IP', selector)
        self.assertIn('select_test_source_ipv4 "$requested_source_ip"', speedtest)
        self.assertIn('--ip="$source_ip"', speedtest)
        self.assertIn('select_test_source_ipv4 "$source_ip"', speedtest_ru)
        self.assertIn('select_test_source_ipv4 "$requested_source_ip"', network)
        self.assertIn('from "$NETTEST_SOURCE_IP"', network)
        self.assertIn('dig -4 -b "$NETTEST_SOURCE_IP" "$host" A', network_resolve)
        self.assertIn('sock.bind((source_ip, 0))', network_tcp)
        self.assertIn('--interface "$NETTEST_SOURCE_IP"', network_https)
        self.assertIn('--interface "$NETTEST_SOURCE_IP"', network_raw)
        self.assertIn('-I "$NETTEST_SOURCE_IP"', network_ping)
        self.assertIn('-a "$NETTEST_SOURCE_IP"', network_mtr)
        self.assertIn('select_test_source_ipv4 "$source_ip"', ipcheck_place)
        self.assertIn('bash "$script" -4 -i "$source_ip" -l en', ipcheck_place)
        self.assertIn('select_test_source_ipv4 "$source_ip"', ipcheck_region)
        self.assertIn('bash "$script" --ipv4 --interface "$source_ip"', ipcheck_region)
        self.assertIn('--interface "$source_ip"', downloader)
        self.assertIn('"--bind-address=${source_ip}"', downloader)

        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
fail() { return 1; }
ip() {
    if [[ "${1:-}" == -4 && "${2:-}" == route && "${3:-}" == get ]]; then
        case "${6:-}" in
            203.0.113.20) echo '1.1.1.1 from 203.0.113.20 via 203.0.113.1 dev wan2 table 102' ;;
            172.17.0.1) echo '1.1.1.1 from 172.17.0.1 via 198.51.100.1 dev ens3' ;;
            *) echo '1.1.1.1 via 198.51.100.1 dev ens3 src 198.51.100.10' ;;
        esac
        return 0
    fi
    if [[ "${1:-}" == -4 && "${2:-}" == -o && "${3:-}" == address ]]; then
        cat <<'EOF'
2: ens3    inet 198.51.100.10/24 scope global ens3
3: wan2    inet 203.0.113.20/24 scope global wan2
4: docker0 inet 172.17.0.1/16 scope global docker0
EOF
        return 0
    fi
    return 1
}
mapfile -t rows < <(list_test_source_ipv4s)
[[ "${#rows[@]}" == 2 ]]
[[ "${rows[0]}" == $'198.51.100.10\tens3\tосновной' ]]
[[ "${rows[1]}" == $'203.0.113.20\twan2\tдополнительный' ]]
select_test_source_ipv4 <<< '2' >/dev/null
[[ "$TEST_SOURCE_IP" == 203.0.113.20 ]]
[[ "$TEST_SOURCE_INTERFACE" == wan2 ]]
list_test_source_ipv4s() { printf '198.51.100.10\tens3\tосновной\n'; }
select_test_source_ipv4 </dev/null
[[ "$TEST_SOURCE_IP" == 198.51.100.10 ]]
[[ "$TEST_SOURCE_INTERFACE" == ens3 ]]
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_network_ping_marks_partial_packet_loss_as_warning(self):
        main = function_body(KTO, "main")
        self.assertIn('network_test "$@" || true', main)

        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
NETTEST_SOURCE_IP=198.51.100.10
NETTEST_PING_BAD=0
ping() {
    [[ "$*" == *'-c 10 -i 0.2'* ]]
    cat <<'EOF'
10 packets transmitted, 8 received, 20% packet loss, time 1800ms
rtt min/avg/max/mdev = 0.400/0.500/0.600/0.050 ms
EOF
    return 0
}
network_test_row() { printf '%s|%s|%s\n' "$1" "$2" "$3"; }
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
network_test_ping 1.1.1.1 cloudflare > "$tmp"
output="$(cat "$tmp")"
grep -q 'ping cloudflare|loss=20% avg=0.500 ms|warn' <<< "$output"
[[ "$NETTEST_PING_BAD" == 1 ]]
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_conntrack_capacity_scales_with_ram_and_network_test_detects_full_table(self):
        capacity = function_body(KTO, "conntrack_capacity_values")
        configure = function_body(KTO, "configure_conntrack_capacity")
        network_conntrack = function_body(KTO, "network_test_conntrack")
        system_check = function_body(KTO, "system_check_network_limits")
        main = function_body(KTO, "main")

        self.assertIn("target_max=2097152", capacity)
        self.assertIn('net.netfilter.nf_conntrack_max = ${target_max}', configure)
        self.assertIn("nf_conntrack_tcp_timeout_established = 10800", configure)
        self.assertIn("nf_conntrack_tcp_timeout_time_wait = 30", configure)
        self.assertIn('options nf_conntrack hashsize=${target_buckets}', configure)
        self.assertNotIn("conntrack -F", configure)
        self.assertNotIn("systemctl restart", configure)
        self.assertIn("count >= maximum || percent >= 95", network_conntrack)
        self.assertIn("nf_conntrack: table full, dropping packet", network_conntrack)
        self.assertIn('system_check_row miss "conntrack"', system_check)
        self.assertIn("conntrack-fix|fix-conntrack|conntrack-optimize", main)

        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
memory_total_mb() { printf '16000\n'; }
sysctl() {
    if [[ "${1:-}" == -n && "${2:-}" == net.netfilter.nf_conntrack_max ]]; then
        printf '262144\n'
    elif [[ "${1:-}" == -n && "${2:-}" == net.netfilter.nf_conntrack_buckets ]]; then
        printf '65536\n'
    elif [[ "${1:-}" == -n && "${2:-}" == net.netfilter.nf_conntrack_count ]]; then
        printf '262144\n'
    else
        return 1
    fi
}
IFS=$'\t' read -r maximum buckets < <(conntrack_capacity_values)
[[ "$maximum" == 2097152 ]]
[[ "$buckets" == 524288 ]]

NETTEST_CONNTRACK_BAD=0
NETTEST_WARN=0
dmesg() { printf 'nf_conntrack: table full, dropping packet\n'; }
network_test_row() { printf '%s|%s|%s\n' "$1" "$2" "$3"; }
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
network_test_conntrack > "$tmp"
grep -q 'conntrack|262144/262144 (100%)|fail' "$tmp"
grep -q 'conntrack drops|в последних kernel-сообщениях был table full|warn' "$tmp"
[[ "$NETTEST_CONNTRACK_BAD" == 1 ]]
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_conntrack_capacity_applies_live_without_flushing_connections(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
KTO_CONNTRACK_SYSCTL_CONF="$work/conntrack.conf"
KTO_CONNTRACK_MODPROBE_CONF="$work/nf_conntrack.conf"
LOG_FILE="$work/log"
SUDO=()
printf '262144\n' > "$work/max"
printf '65536\n' > "$work/buckets"
memory_total_mb() { printf '16000\n'; }
modprobe() { return 0; }
sysctl() {
    if [[ "${1:-}" == -n ]]; then
        case "${2:-}" in
            net.netfilter.nf_conntrack_count) printf '262144\n' ;;
            net.netfilter.nf_conntrack_max) cat "$work/max" ;;
            net.netfilter.nf_conntrack_buckets) cat "$work/buckets" ;;
            *) return 1 ;;
        esac
    elif [[ "${1:-}" == -p ]]; then
        awk -F= '/nf_conntrack_max/ { gsub(/[[:space:]]/, "", $2); print $2 }' "$2" > "$work/max"
    elif [[ "${1:-}" == -w && "${2:-}" == net.netfilter.nf_conntrack_buckets=* ]]; then
        printf '%s\n' "${2#*=}" > "$work/buckets"
    else
        return 1
    fi
}
output="$(configure_conntrack_capacity)"
[[ "$(cat "$work/max")" == 2097152 ]]
[[ "$(cat "$work/buckets")" == 524288 ]]
grep -q '^net.netfilter.nf_conntrack_max = 2097152$' "$KTO_CONNTRACK_SYSCTL_CONF"
grep -q '^net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30$' "$KTO_CONNTRACK_SYSCTL_CONF"
grep -q '^options nf_conntrack hashsize=524288$' "$KTO_CONNTRACK_MODPROBE_CONF"
grep -q 'Conntrack: 262144/2097152 (12%), buckets=524288' <<< "$output"
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_tspu_ip_probe_targets_one_ip_through_the_selected_source(self):
        menu = function_body(KTO, "menu")
        runner = function_body(KTO, "run_tspu_ip_test")
        tcp_probe = function_body(KTO, "tspu_ip_tcp_probe")
        http_probe = function_body(KTO, "tspu_ip_http_probe")
        mtu_probe = function_body(KTO, "tspu_ip_path_mtu_probe")
        trace = function_body(KTO, "tspu_ip_trace")
        main = function_body(KTO, "main")

        self.assertIn('labels+=("Проверка ТСПУ (IP)")', menu)
        self.assertIn('actions+=("dpi-ip-test")', menu)
        self.assertIn('dpi-ip-test) run_tspu_ip_test', menu)
        self.assertIn('select_test_source_ipv4 "$requested_source_ip"', runner)
        self.assertIn('ask_text "Целевой IPv4 или IPv4:порт"', runner)
        self.assertLess(
            runner.index('select_test_source_ipv4 "$requested_source_ip"'),
            runner.index('ask_text "Целевой IPv4 или IPv4:порт"'),
        )
        self.assertIn('parse_tspu_ipv4_target "$target_input"', runner)
        self.assertIn('ip -4 route get "$target_ip" from "$source_ip"', runner)
        self.assertIn('[[ "$route_interface" != "$source_interface"', runner)
        self.assertIn('network_test_ping "$target_ip" "$target_ip"', runner)
        self.assertIn('tspu_ip_tcp_probe "$source_ip" "$target_ip" 80', runner)
        self.assertIn('tspu_ip_tcp_probe "$source_ip" "$target_ip" 443', runner)
        self.assertIn('tspu_ip_http_probe "$source_ip" "$target_ip" http 80', runner)
        self.assertIn('tspu_ip_http_probe "$source_ip" "$target_ip" https 443', runner)
        self.assertIn('tspu_ip_path_mtu_probe "$source_ip" "$target_ip"', runner)
        self.assertIn('tspu_ip_trace "$source_ip" "$target_ip" "$trace_port"', runner)
        self.assertIn('sock.bind((source_ip, 0))', tcp_probe)
        self.assertIn('--interface "$source_ip"', http_probe)
        self.assertIn('-I "$source_ip"', mtu_probe)
        self.assertIn('-a "$source_ip"', trace)
        self.assertIn('Один замер не доказывает ТСПУ', runner)
        self.assertIn('dpi-ip-test|dpi-ip|tspu-ip-test|tspu-ip', main)

        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
MACHINE_MODE=whitelist
LOG_FILE=$(mktemp)
events=$(mktemp)
trap 'rm -f "$LOG_FILE" "$events"' EXIT
header() { :; }
need_root() { :; }
must() { return 0; }
command_exists() { return 0; }
select_test_source_ipv4() {
    printf 'select=%s\n' "${1:-}" >> "$events"
    TEST_SOURCE_IP=203.0.113.20
    TEST_SOURCE_INTERFACE=wan2
}
ip() {
    printf '198.51.100.30 from 203.0.113.20 via 203.0.113.1 dev wan2 table 102\n'
}
network_test_ping() { printf 'ping=%s|source=%s\n' "$1" "$NETTEST_SOURCE_IP" >> "$events"; }
tspu_ip_tcp_probe() { printf 'tcp=%s|%s|%s\n' "$1" "$2" "$3" >> "$events"; return 0; }
tspu_ip_http_probe() { printf 'http=%s|%s|%s|%s\n' "$1" "$2" "$3" "$4" >> "$events"; return 0; }
tspu_ip_path_mtu_probe() { printf 'mtu=%s|%s\n' "$1" "$2" >> "$events"; }
tspu_ip_trace() { printf 'trace=%s|%s|%s\n' "$1" "$2" "$3" >> "$events"; }
run_tspu_ip_test 203.0.113.20 198.51.100.30 >/dev/null
grep -Fqx 'select=203.0.113.20' "$events"
grep -Fqx 'ping=198.51.100.30|source=203.0.113.20' "$events"
grep -Fqx 'tcp=203.0.113.20|198.51.100.30|80' "$events"
grep -Fqx 'tcp=203.0.113.20|198.51.100.30|443' "$events"
grep -Fqx 'http=203.0.113.20|198.51.100.30|http|80' "$events"
grep -Fqx 'http=203.0.113.20|198.51.100.30|https|443' "$events"
grep -Fqx 'mtu=203.0.113.20|198.51.100.30' "$events"
grep -Fqx 'trace=203.0.113.20|198.51.100.30|443' "$events"

: > "$events"
run_tspu_ip_test 203.0.113.20 198.51.100.30:8443 >/dev/null
grep -Fqx 'ping=198.51.100.30|source=203.0.113.20' "$events"
grep -Fqx 'tcp=203.0.113.20|198.51.100.30|8443' "$events"
grep -Fqx 'http=203.0.113.20|198.51.100.30|http|8443' "$events"
grep -Fqx 'http=203.0.113.20|198.51.100.30|https|8443' "$events"
grep -Fqx 'mtu=203.0.113.20|198.51.100.30' "$events"
grep -Fqx 'trace=203.0.113.20|198.51.100.30|8443' "$events"
! grep -Fq '|80' "$events"
! grep -Fq '|443' "$events"

parse_tspu_ipv4_target '198.51.100.30:65535'
[[ "$TSPU_TARGET_IP" == 198.51.100.30 ]]
[[ "$TSPU_TARGET_PORT" == 65535 ]]
[[ "$TSPU_TARGET_HAS_PORT" == 1 ]]
! parse_tspu_ipv4_target '198.51.100.30:0'
! parse_tspu_ipv4_target '198.51.100.30:65536'
! parse_tspu_ipv4_target '198.51.100.30:abc'
! parse_tspu_ipv4_target '198.51.100.30:999999999999999999999'
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_batch_tcp_mtr_parses_groups_and_uses_each_target_port(self):
        menu = function_body(KTO, "menu")
        parser = function_body(KTO, "parse_mtr_batch_targets")
        runner = function_body(KTO, "run_mtr_batch")
        target_runner = function_body(KTO, "run_mtr_batch_target")
        main = function_body(KTO, "main")

        self.assertIn('labels+=("Пакетный TCP-MTR")', menu)
        self.assertIn('actions+=("mtr-batch")', menu)
        self.assertIn('mtr-batch) run_mtr_batch || true', menu)
        self.assertIn('parse_tspu_ipv4_target "$token"', parser)
        self.assertIn('KTO_MTR_BATCH_MAX_TARGETS', parser)
        self.assertIn('KTO_MTR_BATCH_PARALLEL', runner)
        self.assertIn('pids+=("$!")', runner)
        self.assertIn('wait "${pids[0]}" || true', runner)
        self.assertIn('-a "$source_ip"', target_runner)
        self.assertIn('-T -P "$target_port"', target_runner)
        self.assertIn('mtr-batch|batch-mtr|multi-mtr|tcp-mtr-batch', main)

        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
raw="$work/input.txt"
parsed="$work/targets.tsv"
cat > "$raw" <<'EOF'
95.85.252.203:443 - клиент 1
5.42.114.188:443 - клиент 2
94.26.90.182:443 - клиент 3
185.23.19.215:8443 - клиент 4

клиент 5:
82.27.0.247:8443
5.255.113.251:8443
5.255.127.33:8443
82.27.0.175:8443

клиент 6:
84.32.64.14:19272
84.32.96.215:19272
84.32.101.85:19272
84.32.102.204:19272
EOF
parse_mtr_batch_targets "$raw" "$parsed"
[[ "$MTR_BATCH_TARGET_COUNT" == 12 ]]
[[ "$MTR_BATCH_INVALID_COUNT" == 0 ]]
[[ "$MTR_BATCH_DUPLICATE_COUNT" == 0 ]]
grep -Fqx $'клиент 1\t95.85.252.203\t443' "$parsed"
grep -Fqx $'клиент 5\t82.27.0.247\t8443' "$parsed"
grep -Fqx $'клиент 6\t84.32.102.204\t19272' "$parsed"

printf '198.51.100.20:443\n198.51.100.20:443\n' > "$raw"
parse_mtr_batch_targets "$raw" "$parsed"
[[ "$MTR_BATCH_TARGET_COUNT" == 1 ]]
[[ "$MTR_BATCH_DUPLICATE_COUNT" == 1 ]]

printf '198.51.100.20:70000\n' > "$raw"
! parse_mtr_batch_targets "$raw" "$parsed"

SUDO=()
run_bounded_command() { shift; "$@"; }
ip() { printf '198.51.100.30 from 203.0.113.20 via 203.0.113.1 dev ens3 table 100\n'; }
mtr() {
    printf 'ARGS'
    printf ' <%s>' "$@"
    printf '\n'
}
mkdir -p "$work/results"
run_mtr_batch_target 1 'клиент тест' 203.0.113.20 ens3 \
    198.51.100.30 8443 10 0.2 30 20 "$work/results"
[[ "$(cat "$work/results/001.status")" == 0 ]]
grep -Fq '===== клиент тест | 198.51.100.30:8443 =====' "$work/results/001.txt"
grep -Fq '<-a> <203.0.113.20>' "$work/results/001.txt"
grep -Fq '<-T> <-P> <8443>' "$work/results/001.txt"
grep -Fq '<198.51.100.30>' "$work/results/001.txt"

MACHINE_MODE=whitelist
TMPDIR="$work"
header() { :; }
select_test_source_ipv4() {
    TEST_SOURCE_IP=203.0.113.20
    TEST_SOURCE_INTERFACE=ens3
}
need_root() { :; }
apt_install_with_update_if_missing() { :; }
must() { shift; "$@"; }
network_test_row() { :; }
stage() { :; }
KTO_MTR_BATCH_CYCLES=10
KTO_MTR_BATCH_PARALLEL=2
run_mtr_batch \
    '198.51.100.1:443 - one' \
    '198.51.100.2:8443 - two' \
    'group:' \
    '198.51.100.3:19272' \
    '198.51.100.4:443' \
    '198.51.100.5:443' > "$work/batch-output"
result_dir=$(find "$work" -maxdepth 1 -type d -name 'kto-mtr-batch.*' | head -n 1)
[[ -n "$result_dir" ]]
[[ "$(find "$result_dir" -name '*.status' | wc -l | tr -d ' ')" == 5 ]]
grep -Fq 'TCP-MTR завершён для 5 целей' "$work/batch-output"
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_whitelist_btop_selects_ip_and_uses_temporary_interface_config(self):
        menu = function_body(KTO, "menu")
        runner = function_body(KTO, "run_btop_for_ip")
        writer = function_body(KTO, "write_btop_interface_config")
        launcher = function_body(KTO, "run_btop_with_config")
        main = function_body(KTO, "main")

        self.assertIn('labels+=("btop")', menu)
        self.assertIn('actions+=("btop")', menu)
        self.assertIn('btop) run_btop_for_ip || true', menu)
        self.assertIn('require_whitelist_mode', runner)
        self.assertIn('select_test_source_ipv4 "$requested_ip"', runner)
        self.assertIn('source_interface="$TEST_SOURCE_INTERFACE"', runner)
        self.assertIn('apt_install_with_update_if_missing btop', runner)
        self.assertIn('write_btop_interface_config "$user_config" "$temp_config" "$source_interface"', runner)
        self.assertIn('run_btop_with_config "$temp_config" "$temp_dir"', runner)
        self.assertIn('btop --config "$config_file"', launcher)
        self.assertIn('btop -c "$config_file"', launcher)
        self.assertIn('XDG_CONFIG_HOME="$isolated_config_home" btop', launcher)
        self.assertIn('btop|btop-ip|monitor-ip) run_btop_for_ip "${2:-}"', main)
        self.assertIn('net_iface =', writer)
        self.assertIn('shown_boxes =', writer)

        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
source_config=$(mktemp)
original=$(mktemp)
output_config=$(mktemp)
minimal_config=$(mktemp)
events=$(mktemp)
trap 'rm -f "$source_config" "$original" "$output_config" "$minimal_config" "$events"' EXIT
cat > "$source_config" <<'EOF'
color_theme = "Default"
shown_boxes = "cpu mem proc"
net_iface = "ens3"
net_auto = true
EOF
cp "$source_config" "$original"
write_btop_interface_config "$source_config" "$output_config" wan2
cmp -s "$source_config" "$original"
grep -Fqx 'shown_boxes = "cpu mem proc net"' "$output_config"
grep -Fqx 'net_iface = "wan2"' "$output_config"
[[ "$(grep -c '^shown_boxes[[:space:]]*=' "$output_config")" == 1 ]]
[[ "$(grep -c '^net_iface[[:space:]]*=' "$output_config")" == 1 ]]
write_btop_interface_config /missing/btop.conf "$minimal_config" wan3
grep -Fqx 'shown_boxes = "cpu mem net proc"' "$minimal_config"
grep -Fqx 'net_iface = "wan3"' "$minimal_config"
! write_btop_interface_config "$source_config" "$minimal_config" 'bad interface'

btop() {
    if [[ "${1:-}" == "--help" ]]; then
        case "$btop_test_mode" in
            long) printf '%s\n' '  -c, --config <file>  Path to config file' ;;
            short) printf '%s\n' '  -c FILE  Path to configuration file' ;;
            legacy) printf '%s\n' '  -h  Show help' ;;
        esac
        return 0
    fi
    printf 'arg1=%s|arg2=%s|xdg=%s\n' "${1:-}" "${2:-}" "${XDG_CONFIG_HOME:-}" >> "$events"
}

btop_test_mode=long
run_btop_with_config /tmp/kto-btop.conf /tmp/kto-btop-xdg
grep -Fqx 'arg1=--config|arg2=/tmp/kto-btop.conf|xdg=' "$events"

: > "$events"
btop_test_mode=short
run_btop_with_config /tmp/kto-btop.conf /tmp/kto-btop-xdg
grep -Fqx 'arg1=-c|arg2=/tmp/kto-btop.conf|xdg=' "$events"

: > "$events"
btop_test_mode=legacy
run_btop_with_config /tmp/kto-btop.conf /tmp/kto-btop-xdg
grep -Fqx 'arg1=|arg2=|xdg=/tmp/kto-btop-xdg' "$events"
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("regexp escape sequence", result.stderr)

    def test_dpi_detector_is_one_shot_hardened_and_source_routed(self):
        menu = function_body(KTO, "menu")
        runner = function_body(KTO, "run_dpi_detector")
        image_prepare = function_body(KTO, "dpi_detector_prepare_image")
        image_pull = function_body(KTO, "dpi_detector_pull_image")
        dns_prepare = function_body(KTO, "dpi_detector_prepare_registry_dns")
        policy = function_body(KTO, "dpi_detector_prepare_source_policy")
        cleanup = function_body(KTO, "dpi_detector_cleanup")
        preflight = function_body(KTO, "dpi_detector_prepare_targets")
        probe = function_body(KTO, "dpi_detector_probe_targets")
        main = function_body(KTO, "main")

        self.assertIn(
            'DPI_DETECTOR_IMAGE="${KTO_DPI_DETECTOR_IMAGE:-ghcr.io/runnin4ik/dpi-detector:3.3.0}"',
            KTO,
        )
        self.assertIn('labels+=("Проверка ТСПУ")', menu)
        self.assertIn('actions+=("dpi-test")', menu)
        self.assertIn('[[ "$MACHINE_MODE" != "panel" ]]', menu)
        self.assertIn('[[ "$MACHINE_MODE" == "panel" ]]', runner)
        self.assertIn('select_test_source_ipv4 "$requested_source_ip"', runner)
        self.assertIn('dpi_detector_prepare_image', runner)
        self.assertIn('dpi_detector_restore_resolver || true', runner)
        self.assertIn('ensure_hostname_hosts_entry', image_prepare)
        self.assertIn('dpi_detector_prepare_registry_dns ghcr.io', image_prepare)
        self.assertIn('run_bounded_command "$timeout_sec"', image_pull)
        self.assertIn('docker pull "$DPI_DETECTOR_IMAGE"', image_pull)
        self.assertIn('dpi_detector_image_cached', image_pull)
        self.assertIn('dpi_detector_use_resolved_upstream', dns_prepare)
        self.assertIn('dpi_detector_use_public_resolver', dns_prepare)
        self.assertIn('run --rm --name "$container_name"', runner)
        self.assertIn('--network host', runner)
        self.assertIn('--user "${uid}:${uid}"', runner)
        self.assertIn('--cap-drop ALL', runner)
        self.assertIn('--security-opt no-new-privileges:true', runner)
        self.assertIn('--read-only', runner)
        self.assertIn('--tmpfs "/tmp:rw,nosuid,nodev,noexec,size=128m"', runner)
        self.assertIn('detector_args=(--batch)', runner)
        self.assertIn('detector_args=(-t 123 --batch)', runner)
        self.assertIn('dpi_detector_prepare_targets "$preflight_dir"', runner)
        self.assertIn('--volume "${DPI_PREFLIGHT_TARGET_FILE}:/app/tcp16.json:ro"', runner)
        self.assertIn('ensure_dpi_preflight_helper', preflight)
        self.assertIn('dpi_detector_probe_targets "$original_file" "$selected_file"', preflight)
        self.assertIn('dpi_detector_probe_targets "$original_file" "$reference_file" "$reference_uid"', preflight)
        self.assertIn('--network host', probe)
        self.assertIn('--user "${uid}:${uid}"', probe)
        self.assertIn("trap 'dpi_detector_cleanup", runner)
        self.assertIn('uidrange "${uid}-${uid}"', policy)
        self.assertIn('src "$source_ip"', policy)
        self.assertIn('route get 1.1.1.1 uid "$uid"', policy)
        self.assertIn('ip -4 rule del priority "$priority"', cleanup)
        self.assertIn('ip -4 route flush table "$table"', cleanup)
        self.assertIn('dpi-test|dpi-detector|tspu-test|tspu', main)

        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
SUDO=()
LOG_FILE=$(mktemp)
events=$(mktemp)
trap 'rm -f "$LOG_FILE" "$events"' EXIT
ip() {
    { printf '%s|' "$@"; printf '\n'; } >> "$events"
    if [[ "${1:-}" == -4 && "${2:-}" == rule && "${3:-}" == help ]]; then
        printf 'uidrange\n'
        return 2
    fi
    if [[ "${1:-}" == -4 && "${2:-}" == route && "${3:-}" == get && "${5:-}" == from ]]; then
        printf '1.1.1.1 from 203.0.113.20 via 203.0.113.1 dev wan2 table 102\n'
        return 0
    fi
    if [[ "${1:-}" == -4 && "${2:-}" == route && "${3:-}" == get && "${5:-}" == uid ]]; then
        printf '1.1.1.1 via 203.0.113.1 dev wan2 src 203.0.113.20 uid 61000\n'
        return 0
    fi
    return 0
}
dpi_detector_prepare_source_policy 203.0.113.20 wan2 61000 61000 21000
dpi_detector_cleanup '' 61000 21000
grep -Fq -- '-4|route|add|table|61000|default|via|203.0.113.1|dev|wan2|onlink|src|203.0.113.20|' "$events"
grep -Fq -- '-4|rule|add|priority|21000|uidrange|61000-61000|lookup|61000|' "$events"
grep -Fq -- '-4|route|get|1.1.1.1|uid|61000|' "$events"
grep -Fq -- '-4|rule|del|priority|21000|' "$events"
grep -Fq -- '-4|route|flush|table|61000|' "$events"
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_dpi_preflight_keeps_route_differences_and_drops_only_double_failures(self):
        targets = [
            {"id": "A-01", "asn": "64500", "provider": "Alpha", "ip": "192.0.2.10", "port": 443},
            {"id": "B-01", "asn": "64501", "provider": "Beta", "ip": "198.51.100.20", ",port": 80},
            {"id": "C-01", "asn": "64500", "provider": "Alpha 2", "ip": "203.0.113.30", "port": 443},
            {"id": "D-01", "asn": "64502", "provider": "Delta", "ip": "203.0.113.40", "port": 443},
        ]

        def report(statuses):
            results = []
            for index, (item, status) in enumerate(zip(targets, statuses, strict=True)):
                ok, reason = status
                port = item.get("port", item.get(",port", 443))
                results.append(
                    {
                        "index": index,
                        "ip": item["ip"],
                        "port": port,
                        "ok": ok,
                        "reason": reason,
                        "latency_ms": 1.0 if ok else None,
                    }
                )
            return {"schema": 1, "build": "v319", "results": results}

        selected = report(
            [(True, "open"), (False, "timeout"), (False, "refused"), (False, "timeout")]
        )
        reference = report(
            [(False, "timeout"), (True, "open"), (False, "timeout"), (False, "timeout")]
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            input_path = root / "targets.json"
            selected_path = root / "selected.json"
            reference_path = root / "reference.json"
            output_path = root / "filtered.json"
            input_path.write_text(json.dumps(targets), encoding="utf-8")
            selected_path.write_text(json.dumps(selected), encoding="utf-8")
            reference_path.write_text(json.dumps(reference), encoding="utf-8")

            result = subprocess.run(
                [
                    sys.executable,
                    str(DPI_PREFLIGHT_PATH),
                    "combine",
                    "--input",
                    str(input_path),
                    "--selected",
                    str(selected_path),
                    "--reference",
                    str(reference_path),
                    "--output",
                    str(output_path),
                    "--min-kept",
                    "1",
                    "--min-kept-ratio",
                    "0.1",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            filtered = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual([item["id"] for item in filtered], ["A-01", "B-01", "D-01"])
            self.assertEqual(filtered[1]["port"], 80)
            self.assertNotIn(",port", filtered[1])
            self.assertIn("KEPT\t3", result.stdout)
            self.assertIn("SKIPPED\t1", result.stdout)
            self.assertIn("DIFFERENTIAL\t1", result.stdout)
            self.assertIn("UNVERIFIED\t1", result.stdout)
            self.assertIn("SKIP\tC-01\tAlpha 2\t203.0.113.30\t443", result.stdout)
            self.assertIn("UNVERIFIED_TARGET\tD-01\tDelta\t203.0.113.40\t443", result.stdout)

    def test_dpi_detector_preflight_restores_resolver_and_uses_cached_image(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
SUDO=()
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
LOG_FILE="$root/kto.log"
DPI_RESOLV_CONF_FILE="$root/resolv.conf"
DPI_RESOLVED_UPSTREAM_FILE="$root/upstream.conf"
original="$root/original.conf"
printf 'nameserver 127.0.0.53\noptions edns0 trust-ad\n' > "$original"
printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > "$DPI_RESOLVED_UPSTREAM_FILE"
cp "$original" "$DPI_RESOLV_CONF_FILE"

dns_host_resolves() { return 1; }
systemd_resolved_available() { return 0; }
run_systemctl_bounded() { return 0; }
command_exists() { [[ "$1" != resolvectl ]]; }
wait_for_dns_host() {
    cmp -s "$DPI_RESOLV_CONF_FILE" "$DPI_RESOLVED_UPSTREAM_FILE"
}
dpi_detector_prepare_registry_dns ghcr.io
[[ "$DPI_RESOLV_CHANGED" == 1 ]]
cmp -s "$DPI_RESOLV_CONF_FILE" "$DPI_RESOLVED_UPSTREAM_FILE"
snapshot="$DPI_RESOLV_SNAPSHOT_DIR"
[[ -d "$snapshot" ]]
dpi_detector_restore_resolver
cmp -s "$DPI_RESOLV_CONF_FILE" "$original"
[[ ! -e "$snapshot" ]]

wait_for_dns_host() { return 1; }
! dpi_detector_prepare_registry_dns ghcr.io
cmp -s "$DPI_RESOLV_CONF_FILE" "$original"
[[ -z "$DPI_RESOLV_SNAPSHOT_DIR" && "$DPI_RESOLV_CHANGED" == 0 ]]

run_bounded_command() { shift; "$@"; }
cached=1
docker() {
    if [[ "${1:-}" == pull ]]; then
        printf 'dial tcp: lookup ghcr.io on 127.0.0.53:53: operation not permitted\n'
        return 1
    fi
    if [[ "${1:-}" == image && "${2:-}" == inspect ]]; then
        [[ "$cached" == 1 ]]
        return
    fi
    return 0
}
KTO_DPI_PULL_TIMEOUT=30
dpi_detector_pull_image
cached=0
! dpi_detector_pull_image
grep -q 'cached image selected' "$LOG_FILE"
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_hostname_guard_is_backed_up_and_idempotent(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
SUDO=()
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
LOG_FILE="$root/kto.log"
HOSTS_FILE="$root/hosts"
HOSTS_BACKUP_FILE="$root/hosts.kto-backup"
printf '127.0.0.1\tlocalhost\n' > "$HOSTS_FILE"
cp "$HOSTS_FILE" "$root/original"
hostname() { printf 'kto-test\n'; }
getent() { return 2; }
run_bounded_command() { shift; "$@"; }
ensure_hostname_hosts_entry
cmp -s "$HOSTS_BACKUP_FILE" "$root/original"
grep -Fqx $'127.0.1.1\tkto-test' "$HOSTS_FILE"
ensure_hostname_hosts_entry
[[ "$(grep -c 'kto-test' "$HOSTS_FILE")" == 1 ]]
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_additional_ip_menu_uses_openstack_ports_and_source_routing(self):
        menu = function_body(KTO, "menu")
        wrapper = function_body(KTO, "setup_additional_ips")
        optimizer_wrapper = function_body(KTO, "optimize_additional_ip_networks")
        setup = function_body(ADDITIONAL_IPS, "setup_additional_ips")
        optimizer = function_body(ADDITIONAL_IPS, "optimize_all_ip_networks")
        apply_netplan = function_body(ADDITIONAL_IPS, "apply_managed_netplan")
        render = function_body(ADDITIONAL_IPS, "render_netplan")

        self.assertIn('labels+=("Проверить и завести дополнительные IP")', menu)
        self.assertIn('actions+=("additional-ips")', menu)
        self.assertIn('labels+=("Оптимизировать сеть всех IP")', menu)
        self.assertIn('actions+=("additional-ips-optimize")', menu)
        self.assertIn('ensure_additional_ip_manager', wrapper)
        self.assertIn('ensure_additional_ip_manager', optimizer_wrapper)
        self.assertIn('"$ADDITIONAL_IP_MANAGER" optimize', optimizer_wrapper)
        self.assertIn('fetch_openstack_metadata "$metadata_file"', setup)
        self.assertIn('setup_existing_source_routes', setup)
        self.assertIn('openstack_ipv4_port_macs "$metadata_file"', setup)
        self.assertIn('wait_for_dhcp "${names[@]}"', setup)
        self.assertIn('remove_duplicate_primary_addresses', setup)
        self.assertIn('write_multiwan_sysctl', setup)
        self.assertIn('install_source_route_manager "$final_state"', setup)
        self.assertIn('discover_existing_extra_state', optimizer)
        self.assertIn('install_source_route_manager "$state_file"', optimizer)
        self.assertNotIn('netplan apply', optimizer)
        self.assertIn('main_route_healthy', apply_netplan)
        self.assertIn('restore_managed_netplan', apply_netplan)
        self.assertIn('routing-policy:', render)
        self.assertIn('on-link: true', render)
        self.assertIn('table: ${table}', render)

    def test_reality_profiles_expose_remnawave_egress_manager(self):
        menu = function_body(KTO, "menu")
        wrapper = function_body(KTO, "configure_remnawave_egress")

        self.assertIn('labels+=("Исходящий IP Remnawave")', menu)
        self.assertIn('actions+=("remnawave-egress")', menu)
        self.assertIn('node_profile_includes_reality', menu)
        self.assertIn('node_profile_includes_reality', wrapper)
        self.assertIn('ensure_remna_api_config', wrapper)
        self.assertIn('ensure_remna_egress_manager', wrapper)
        self.assertIn('KTO_NODE_PROFILE="$NODE_PROFILE"', wrapper)

    def test_remnawave_egress_rewrites_only_selected_freedom_outbound(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")
        jq_check = subprocess.run(
            [bash, "-lc", "command -v jq"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if jq_check.returncode != 0:
            self.skipTest("jq is unavailable in bash environment")

        harness = r'''
source <(sed '/^main "$@"$/d' scripts/kto-remnawave-egress.sh)
profile=$(mktemp)
origin=$(mktemp)
fixed=$(mktemp)
reset=$(mktemp)
trap 'rm -f "$profile" "$origin" "$fixed" "$reset"' EXIT
cat > "$profile" <<'JSON'
{
  "response": {
    "config": {
      "outbounds": [
        {"protocol":"freedom","tag":"DIRECT"},
        {"protocol":"freedom","tag":"OTHER","sendThrough":"10.0.0.2"},
        {"protocol":"blackhole","tag":"BLOCK"}
      ]
    }
  }
}
JSON
rewrite_profile_config "$profile" 0 origin "$origin"
jq -e '.outbounds[0].sendThrough == "origin"' "$origin" >/dev/null
jq -e '.outbounds[1].sendThrough == "10.0.0.2"' "$origin" >/dev/null

jq -n --slurpfile config "$origin" '{response:{config:$config[0]}}' > "$profile"
rewrite_profile_config "$profile" 0 185.141.227.93 "$fixed"
jq -e '.outbounds[0].sendThrough == "185.141.227.93"' "$fixed" >/dev/null

jq -n --slurpfile config "$fixed" '{response:{config:$config[0]}}' > "$profile"
rewrite_profile_config "$profile" 0 default "$reset"
jq -e '(.outbounds[0] | has("sendThrough") | not)' "$reset" >/dev/null
jq -e '.outbounds[1].sendThrough == "10.0.0.2"' "$reset" >/dev/null
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_additional_ip_non_openstack_fallback_discovers_existing_interfaces(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' scripts/kto-additional-ips.sh)
LOG_FILE=/dev/null
ip() {
    if [[ "${1:-}" == "-4" && "${2:-}" == "-o" && "${3:-}" == "address" && "${4:-}" == "show" ]]; then
        printf '%s\n' \
            '2: ens3 inet 78.159.250.112/24 brd 78.159.250.255 scope global ens3' \
            '3: wan2 inet 185.141.227.93/26 brd 185.141.227.127 scope global wan2' \
            '4: wan3 inet 217.19.122.48/24 brd 217.19.122.255 scope global wan3' \
            '5: docker0 inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0'
        return 0
    fi
    return 1
}
interface_gateway() {
    case "$1" in
        ens3) printf '78.159.250.1\n' ;;
        wan2) printf '185.141.227.65\n' ;;
        wan3) printf '217.19.122.1\n' ;;
    esac
}
interface_mac() { printf 'fa:16:3e:00:00:02\n'; }
network_for_cidr() {
    case "$1" in
        185.*) printf '185.141.227.64/26\n' ;;
        217.*) printf '217.19.122.0/24\n' ;;
    esac
}
state=$(mktemp)
runner=$(mktemp)
trap 'rm -f "$state" "$runner"' EXIT
discover_existing_extra_state ens3 78.159.250.112 "$state"
[[ "$DISCOVERED_EXTRA_COUNT" == 2 ]]
[[ "$DISCOVERED_SKIPPED_COUNT" == 0 ]]
grep -q '^wan2|.*|185.141.227.93/26|185.141.227.65|185.141.227.64/26|102|10200$' "$state"
grep -q '^wan3|.*|217.19.122.48/24|217.19.122.1|217.19.122.0/24|103|10300$' "$state"
! grep -q 'docker0' "$state"
MANAGED_ROUTE_STATE_FILE=/etc/kto-additional-ip-routes.conf
render_source_route_script "$runner"
bash -n "$runner"
grep -q 'route replace.*scope link table' "$runner"
grep -q 'route replace default via.*onlink table' "$runner"
grep -q 'rule add from.*table.*priority' "$runner"
grep -q 'source_rule_count' "$runner"
grep -q 'rule_count.*!=.*1' "$runner"
! grep -q 'route flush table' "$runner"
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_additional_ip_self_heal_is_idempotent_and_timed(self):
        install_manager = function_body(ADDITIONAL_IPS, "install_source_route_manager")
        restore_manager = function_body(ADDITIONAL_IPS, "restore_source_route_manager")
        self.assertNotIn('remove_source_routes_from_state "$MANAGED_ROUTE_STATE_FILE"', install_manager)
        self.assertIn('remove_obsolete_source_routes', install_manager)
        self.assertIn('if (( had_state == 1 )); then', restore_manager)
        self.assertIn('Runtime source routes оставлены рабочими', restore_manager)

        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' scripts/kto-additional-ips.sh)
unit=$(mktemp)
timer=$(mktemp)
trap 'rm -f "$unit" "$timer"' EXIT
ROUTE_HEAL_INTERVAL_SEC=75
render_source_route_unit "$unit"
render_source_route_timer "$timer"
grep -q '^Type=oneshot$' "$unit"
grep -q '^TimeoutStartSec=45$' "$unit"
! grep -q '^RemainAfterExit=yes$' "$unit"
grep -q '^OnUnitActiveSec=75s$' "$timer"
grep -q '^Unit=kto-additional-ip-routes.service$' "$timer"
grep -q '^Persistent=true$' "$timer"
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_additional_ip_self_heal_does_not_recreate_healthy_rule(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' scripts/kto-additional-ips.sh)
state=$(mktemp)
runner=$(mktemp)
events=$(mktemp)
trap 'rm -f "$state" "$runner" "$events"' EXIT
printf 'wan2|aa|500|185.141.227.93/26|185.141.227.65|185.141.227.64/26|102|10200\n' > "$state"
MANAGED_ROUTE_STATE_FILE="$state"
render_source_route_script "$runner"
rule_mode=present
route_mode=present
ip() {
    if [[ "${1:-}" == -4 && "${2:-}" == -o && "${3:-}" == address && "${4:-}" == show ]]; then
        printf '2: wan2 inet 185.141.227.93/26 scope global wan2\n'
    elif [[ "${1:-}" == -4 && "${2:-}" == rule && "${3:-}" == show ]]; then
        [[ "$rule_mode" == present ]] && printf '10200: from 185.141.227.93 lookup 102\n'
    elif [[ "${1:-}" == -4 && "${2:-}" == route && "${3:-}" == show ]]; then
        if [[ "$route_mode" == present && "${6:-}" == default ]]; then
            printf 'default via 185.141.227.65 dev wan2 onlink\n'
        elif [[ "$route_mode" == present ]]; then
            printf '185.141.227.64/26 dev wan2 scope link src 185.141.227.93\n'
        fi
    elif [[ "${1:-}" == -4 && "${2:-}" == route && "${3:-}" == replace ]]; then
        printf 'route-replace\n' >> "$events"
    elif [[ "${1:-}" == -4 && "${2:-}" == rule && "${3:-}" == del ]]; then
        printf 'rule-del\n' >> "$events"
        return 1
    elif [[ "${1:-}" == -4 && "${2:-}" == rule && "${3:-}" == add ]]; then
        printf 'rule-add\n' >> "$events"
    elif [[ "${1:-}" == -4 && "${2:-}" == route && "${3:-}" == flush ]]; then
        :
    else
        return 1
    fi
}
sleep() { :; }
( set +e; set +o pipefail; source "$runner" )
! grep -q '^route-replace$' "$events"
! grep -q '^rule-del$' "$events"
! grep -q '^rule-add$' "$events"
: > "$events"
rule_mode=missing
route_mode=missing
( set +e; set +o pipefail; source "$runner" )
grep -q '^route-replace$' "$events"
grep -q '^rule-del$' "$events"
grep -q '^rule-add$' "$events"
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_multiwan_sysctl_covers_physical_interfaces_only(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' scripts/kto-additional-ips.sh)
root=$(mktemp -d)
config=$(mktemp)
trap 'rm -rf "$root" "$config"' EXIT
mkdir -p "$root/ens3" "$root/wan2" "$root/docker0" "$root/wg0"
IPV4_CONF_ROOT="$root"
MANAGED_SYSCTL_FILE="$config"
LOG_FILE=/dev/null
sysctl() { :; }
write_multiwan_sysctl
grep -q '^net.ipv4.conf.ens3.rp_filter=2$' "$config"
grep -q '^net.ipv4.conf.ens3.arp_notify=1$' "$config"
grep -q '^net.ipv4.conf.wan2.arp_filter=1$' "$config"
grep -q '^net.ipv4.conf.wan2.arp_announce=2$' "$config"
! grep -q 'docker0' "$config"
! grep -q 'wg0' "$config"
printf 'old-config\n' > "$config"
sysctl_calls=0
sysctl() {
    sysctl_calls=$((sysctl_calls + 1))
    (( sysctl_calls > 1 ))
}
if write_multiwan_sysctl; then
    exit 1
fi
grep -qx 'old-config' "$config"
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_fixed_remnawave_egress_refuses_shared_profile(self):
        apply_egress = function_body(REMNA_EGRESS, "apply_send_through")

        self.assertIn('[[ "$mode" == "fixed" && "$node_count" -gt 1 ]]', apply_egress)
        self.assertIn('отдельный Config Profile', apply_egress)
        self.assertIn('api_call PATCH /api/config-profiles', apply_egress)
        self.assertIn('rewrite_profile_config', apply_egress)
        self.assertIn('backup_file=', apply_egress)

    def test_remnawave_node_detection_keeps_local_ips_when_public_probe_fails(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main "$@"$/d' scripts/kto-remnawave-egress.sh)
ip() {
    printf '%s\n' \
        '2: ens3 inet 78.159.250.112/24 scope global ens3' \
        '3: wan2 inet 185.141.227.93/26 scope global wan2'
}
curl() { return 28; }
output="$(local_ipv4s)"
grep -qx '78.159.250.112' <<< "$output"
grep -qx '185.141.227.93' <<< "$output"
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_origin_mode_documents_udp_limit(self):
        status = function_body(REMNA_EGRESS, "show_status")
        origin = function_body(REMNA_EGRESS, "configure_origin")

        self.assertIn('origin работает для Reality/TCP', status)
        self.assertIn('Hysteria2/UDP', status)
        self.assertIn('Hysteria2/UDP продолжит использовать системный маршрут', origin)

    def test_additional_ip_metadata_parser_and_netplan_renderer(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' scripts/kto-additional-ips.sh)
python3() { python "$@"; }
metadata=$(mktemp)
state=$(mktemp)
netplan=$(mktemp)
trap 'rm -f "$metadata" "$state" "$netplan"' EXIT
cat > "$metadata" <<'JSON'
{
  "links": [
    {"id":"primary","ethernet_mac_address":"fa:16:3e:00:00:01"},
    {"id":"extra-a","ethernet_mac_address":"FA:16:3E:00:00:02"},
    {"id":"extra-b","ethernet_mac_address":"fa:16:3e:00:00:03"}
  ],
  "networks": [
    {"type":"ipv4_dhcp","link":"primary"},
    {"type":"ipv4_dhcp","link":"extra-a"},
    {"type":"ipv6_dhcpv6-stateful","link":"extra-a"},
    {"type":"ipv4_dhcp","link":"extra-a"},
    {"type":"ipv4_dhcp","link":"extra-b"}
  ]
}
JSON
actual=$(openstack_ipv4_port_macs "$metadata" | tr -d '\r')
expected=$'fa:16:3e:00:00:01\nfa:16:3e:00:00:02\nfa:16:3e:00:00:03'
[[ "$actual" == "$expected" ]]
printf 'wan2|fa:16:3e:00:00:02|500|185.141.227.93/26|185.141.227.65|185.141.227.64/26|102|10200\n' > "$state"
render_netplan "$state" "$netplan"
grep -q '^    wan2:$' "$netplan"
grep -q '^        macaddress: "fa:16:3e:00:00:02"$' "$netplan"
grep -q '^        - to: 185.141.227.64/26$' "$netplan"
grep -q '^          via: 185.141.227.65$' "$netplan"
grep -q '^        - from: 185.141.227.93/32$' "$netplan"
grep -q '^          table: 102$' "$netplan"
grep -q '^          priority: 10200$' "$netplan"
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_additional_ip_setup_is_idempotent_two_phase_configuration(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' scripts/kto-additional-ips.sh)
require_root() { :; }
require_commands() { :; }
init_log() { LOG_FILE=$(mktemp); }
primary_interface() { printf 'ens3\n'; }
primary_ipv4() { printf '78.159.250.112\n'; }
primary_route_metric() { printf '100\n'; }
interface_mac() { printf 'fa:16:3e:00:00:01\n'; }
fetch_openstack_metadata() { printf '{}\n' > "$1"; }
openstack_ipv4_port_macs() {
    printf '%s\n' fa:16:3e:00:00:01 fa:16:3e:00:00:02 fa:16:3e:00:00:03
}
rescan_network_links() { :; }
interface_for_mac() { return 1; }
apply_count=0
first=$(mktemp)
second=$(mktemp)
trap 'rm -f "$first" "$second" "${LOG_FILE:-}"' EXIT
apply_managed_netplan() {
    apply_count=$((apply_count + 1))
    if (( apply_count == 1 )); then cp "$1" "$first"; else cp "$1" "$second"; fi
}
renew_interfaces() { :; }
wait_for_dhcp() { :; }
interface_ipv4_cidr() {
    if [[ "$1" == wan2 ]]; then printf '185.141.227.93/26\n'; else printf '217.19.122.48/24\n'; fi
}
interface_gateway() {
    if [[ "$1" == wan2 ]]; then printf '185.141.227.65\n'; else printf '217.19.122.1\n'; fi
}
network_for_cidr() {
    if [[ "$1" == 185.* ]]; then printf '185.141.227.64/26\n'; else printf '217.19.122.0/24\n'; fi
}
disable_legacy_alias_file() { :; }
remove_duplicate_primary_addresses() { :; }
write_multiwan_sysctl() { :; }
install_count=0
install_source_route_manager() { install_count=$((install_count + 1)); }
sleep() { :; }
print_result_table() { :; }
setup_additional_ips
[[ "$apply_count" == 2 ]]
[[ "$install_count" == 1 ]]
grep -q '^    wan2:$' "$first"
! grep -q 'routing-policy:' "$first"
grep -q '^    wan2:$' "$second"
grep -q '^    wan3:$' "$second"
grep -q 'routing-policy:' "$second"
grep -q 'table: 102' "$second"
grep -q 'table: 103' "$second"
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_additional_ip_check_bypasses_proxies_and_reports_nat_as_working(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        self.assertIn("curl -q -4 --noproxy '*' --interface", ADDITIONAL_IPS)
        harness = r'''
source <(sed '/^main /d' scripts/kto-additional-ips.sh)
state=$(mktemp)
trap 'rm -f "$state"' EXIT
printf 'wan2|fa:16:3e:00:00:02|500|185.141.227.93/26|185.141.227.65|185.141.227.64/26|102|10200\n' > "$state"
bound_public_ip() {
    case "$1" in
        78.159.250.112) printf '78.159.250.112\n' ;;
        185.141.227.93) printf '46.243.235.141\n' ;;
    esac
}
ip() {
    printf '1.1.1.1 from 185.141.227.93 via 185.141.227.65 dev wan2 table 102\n'
}
output=$(print_result_table ens3 78.159.250.112 "$state" 2>&1)
grep -q '185.141.227.93.*46.243.235.141.*NAT' <<< "$output"
grep -q 'Дополнительные IP имеют доступ в интернет: 1/1' <<< "$output"
grep -q 'через NAT/прокси: 1' <<< "$output"
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_additional_ip_parallel_probe_keeps_rows_aligned_and_checks_primary(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' scripts/kto-additional-ips.sh)
state=$(mktemp)
probes=$(mktemp -d)
trap 'rm -rf "$state" "$probes"' EXIT
printf '%s\n' \
  'wan2|aa|500||||102|10200' \
  'wan3|bb|501|217.19.122.48/24|217.19.122.1|217.19.122.0/24|103|10300' > "$state"
bound_public_ip() {
    case "$1" in
        217.19.122.48) printf '217.19.122.48\n' ;;
        *) return 1 ;;
    esac
}
PROBE_CONCURRENCY=2
collect_bound_public_ip_probes 78.159.250.112 "$state" "$probes"
[[ ! -s "$probes/0" ]]
[[ ! -s "$probes/1" ]]
grep -qx '217.19.122.48' "$probes/2"
ip() { printf '1.1.1.1 from 217.19.122.48 via 217.19.122.1 dev wan3 table 103\n'; }
output=$(print_result_table ens3 78.159.250.112 <(tail -n 1 "$state") 2>&1) && exit 1
grep -q 'Основной IP не прошёл HTTPS-проверку' <<< "$output"
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_multiport_menu_keeps_legacy_443_names_and_unified_route_flow(self):
        render = function_body(KTO, "render_haproxy_routes_config")
        haproxy_menu = function_body(KTO, "haproxy_menu")
        main_menu = function_body(KTO, "menu")

        self.assertIn('if (( port == 443 ))', render)
        self.assertIn('frontend_name="vless_in"', render)
        self.assertIn('backend_name="vless_pool"', render)
        self.assertIn('server_name="xray1"', render)
        self.assertIn('frontend_name="vless_in_${port}"', render)
        self.assertIn('backend_name="vless_pool_${port}"', render)
        self.assertIn('2) Добавить маршрут (входной IP = выходному IP)', haproxy_menu)
        self.assertIn('3) Удалить маршрут', haproxy_menu)
        self.assertIn('4) Заменить SNI у всех маршрутов', haproxy_menu)
        self.assertIn('5) Обновить HAProxy, сохранив маршруты', haproxy_menu)
        self.assertIn('6) Добавить или заменить backend-пул', haproxy_menu)
        self.assertIn('7) Массово добавить backend по следующим портам', haproxy_menu)
        self.assertIn('8) Ограничить скорость по входному IP', haproxy_menu)
        self.assertIn('9) Восстановить HAProxy backup', haproxy_menu)
        self.assertIn('10) Проверить бинды', haproxy_menu)
        self.assertIn('11) Полная диагностика HAProxy', haproxy_menu)
        self.assertIn('12) Аварийно стабилизировать HAProxy', haproxy_menu)
        self.assertIn('add_haproxy_route "$routes_file"', haproxy_menu)
        self.assertNotIn('Добавить маршрут через основной', haproxy_menu)
        self.assertNotIn('Добавить маршрут через другой', haproxy_menu)
        self.assertIn('replace_all_haproxy_sni "$routes_file"', haproxy_menu)
        self.assertIn('haproxy_bandwidth_menu', haproxy_menu)
        self.assertIn('restore_haproxy_backup "$routes_file"', haproxy_menu)
        self.assertIn('check_haproxy_bindings "$routes_file"', haproxy_menu)
        self.assertIn('diagnose_haproxy', haproxy_menu)
        self.assertIn('haproxy-diagnose|haproxy-diagnostic|haproxy-diag|haproxy-status', KTO)
        self.assertNotIn('labels+=("Обновить HAProxy")', main_menu)

    def test_haproxy_route_list_uses_compact_input_backend_sni_format(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
routes=$(mktemp)
trap 'rm -f "$routes"' EXIT
printf '443\t144.31.128.40:443\t*.rog-self.co.uk\tdefault\n8443\t5.34.179.144:443\tbridge.example.com\t217.19.122.48\tdefault\t217.19.122.48\n' > "$routes"
haproxy_default_source_ip() { printf '78.159.245.250\n'; }
output=$(print_haproxy_routes "$routes")
grep -Fq '*:443 -> 144.31.128.40:443 | SNI: *.rog-self.co.uk | Выход: 78.159.245.250 (default)' <<< "$output"
grep -Fq '217.19.122.48:8443 -> 5.34.179.144:443 | SNI: bridge.example.com | Выход: 217.19.122.48' <<< "$output"
! grep -Fq 'Вход:' <<< "$output"
! grep -Fq '/tcp' <<< "$output"
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_binding_check_distinguishes_wildcard_and_specific_ip(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
routes=$(mktemp)
trap 'rm -f "$routes"' EXIT
printf '443\t144.31.128.40:443\ta.example.com\tdefault\n8443\t5.34.179.144:443\tb.example.com\tdefault\tdefault\t217.19.122.48\n9443\t5.34.179.145:443\tc.example.com\tdefault\tdefault\t185.141.227.93\n' > "$routes"
command_exists() { [[ "$1" == ss ]]; }
haproxy_tcp_listener_endpoints() {
    printf '*\t443\n217.19.122.48\t8443\n*\t9443\n'
}
rc=0
output=$(check_haproxy_bindings "$routes") || rc=$?
[[ "$rc" == 1 ]]
grep -Fq '*:443 — FULL: занимает 443/tcp на всех IP | Runtime: OK' <<< "$output"
grep -Fq '217.19.122.48:8443 — ТОЧЕЧНЫЙ: только IP 217.19.122.48 | Runtime: OK' <<< "$output"
grep -Fq '185.141.227.93:9443 — ТОЧЕЧНЫЙ: только IP 185.141.227.93 | Runtime: ОШИБКА: HAProxy реально слушает *:9443 на всех IP' <<< "$output"
grep -Fq 'Проверено: 3 | OK: 2 | Проблем: 1' <<< "$output"
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_backend_diagnostic_parses_dynamic_stats_header(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
report=$(haproxy_backend_health_report <<'EOF'
# pxname,svname,status,check_status
vless_pool,BACKEND,UP,
vless_pool,xray1,UP,L4OK
vless_pool,xray2,DOWN,L4TOUT
EOF
)
grep -Fq $'S\t1\t0\t2\t1\t1\t0' <<< "$report"
grep -Fq $'D\tvless_pool/xray2\tDOWN\tL4TOUT' <<< "$report"
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_bandwidth_limit_is_scoped_to_selected_input_ip(self):
        apply_limits = function_body(HAPROXY_BANDWIDTH, "apply_limits")
        add_ingress = function_body(HAPROXY_BANDWIDTH, "add_ingress_redirect_filter")
        add_egress = function_body(HAPROXY_BANDWIDTH, "add_egress_class_filter")
        setup_ifb = function_body(HAPROXY_BANDWIDTH, "setup_ifb_shaper")
        setup_root = function_body(HAPROXY_BANDWIDTH, "setup_egress_root")
        ensure_clsact = function_body(HAPROXY_BANDWIDTH, "ensure_clsact")
        active_filters = function_body(HAPROXY_BANDWIDTH, "active_filter_count")
        active_layout = function_body(HAPROXY_BANDWIDTH, "state_layout_active")
        cleanup = function_body(HAPROXY_BANDWIDTH, "cleanup_state_file")
        set_limit = function_body(KTO, "set_haproxy_input_bandwidth_limit")
        commit = function_body(KTO, "commit_haproxy_bandwidth_config")
        apply_routes = function_body(KTO, "apply_haproxy_routes_config")
        reapply = function_body(KTO, "reapply_haproxy_bandwidth_limits")
        apply_cli = function_body(KTO, "apply_haproxy_bandwidth_limits_cli")

        self.assertIn('tc_logged qdisc add dev "$interface" clsact', ensure_clsact)
        self.assertNotIn(' root ', ensure_clsact)
        self.assertIn('dst_ip "$ip" dst_port "$port"', add_ingress)
        self.assertIn('action mirred egress redirect dev "$ifb"', add_ingress)
        self.assertIn('src_ip "$ip" src_port "$port" classid "$classid"', add_egress)
        self.assertIn('flowid "$classid"', add_egress)
        self.assertIn('handle "${IFB_ROOT_MAJOR}:" htb', setup_ifb)
        self.assertIn('add_fq_codel "$ifb"', setup_ifb)
        self.assertIn('handle "${ROOT_MAJOR}:" htb', setup_root)
        self.assertNotIn('action police rate', HAPROXY_BANDWIDTH)
        self.assertIn('cleanup_orphaned_legacy_tc', apply_limits)
        self.assertIn('tc actions delete action police index', cleanup)
        self.assertIn("trap 'rc=$?; trap - EXIT;", apply_limits)
        self.assertNotIn("RETURN", apply_limits)
        self.assertIn('state_filter_snapshot "$interface" "$direction"', active_filters)
        self.assertIn('tc class show dev "$ifb"', active_layout)
        self.assertIn('tc class show dev "$interface"', active_layout)
        self.assertIn('desired_state_signature', apply_limits)
        self.assertIn('Shaper HAProxy уже актуален', apply_limits)
        self.assertIn('haproxy_input_ip_available "$input_ip"', set_limit)
        self.assertIn('Возвращаю предыдущие лимиты', commit)
        self.assertIn('reapply_haproxy_bandwidth_limits', apply_routes)
        self.assertIn('skip_bandwidth_reapply', apply_routes)
        self.assertIn('require_local_haproxy_bandwidth_manager', reapply)
        self.assertNotIn('ensure_haproxy_bandwidth_manager', reapply)
        self.assertIn('ensure_haproxy_bandwidth_manager', apply_cli)
        self.assertIn('reapply_haproxy_bandwidth_limits', apply_cli)
        self.assertIn('haproxy-limit|haproxy-bandwidth-limit', KTO)
        self.assertIn('haproxy-limit-off|haproxy-bandwidth-off', KTO)
        self.assertIn('haproxy-limit-apply|haproxy-bandwidth-apply', KTO)
        self.assertIn('haproxy-limit-status|haproxy-bandwidth-status', KTO)

        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
set -Eeuo pipefail
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export KTO_HAPROXY_BANDWIDTH_CONFIG="$work/limits"
export KTO_HAPROXY_CONFIG="$work/haproxy.cfg"
export KTO_HAPROXY_BANDWIDTH_STATE="$work/state"
export KTO_HAPROXY_BANDWIDTH_LOG="$work/log"
export KTO_HAPROXY_BANDWIDTH_LOCK="$work/lock"
source <(sed '/^main /d' scripts/kto-haproxy-bandwidth.sh)
printf '217.19.122.109\t2000\n' > "$LIMITS_CONFIG"
cat > "$HAPROXY_CONFIG" <<'EOF'
global
    maxconn 10000
defaults
    mode tcp
frontend vless_in_8443
    bind 217.19.122.109:8443 backlog 65535
    default_backend vless_pool_8443
frontend vless_in_8444
    bind 198.51.100.44:8444 backlog 65535
    default_backend vless_pool_8444
frontend vless_in_9443
    bind *:9443 backlog 65535
    default_backend vless_pool_9443
backend vless_pool_8443
    server xray1 1.1.1.1:443
backend vless_pool_8444
    server xray2 2.2.2.2:443
backend vless_pool_9443
    server xray3 3.3.3.3:443
EOF
printf 'A\t3900001\nF\tens3\tingress\t42001\t3900001\nF\tens3\tegress\t42002\t3900001\n' > "$STATE_FILE"
: > "$LOG_FILE"
ip() {
    if [[ "${1:-}" == -4 && "${2:-}" == -o && "${3:-}" == address &&
        "${4:-}" == show && "${5:-}" == scope && "${6:-}" == global ]]; then
        printf '2: ens3    inet 217.19.122.109/24 brd 217.19.122.255 scope global ens3\n'
        return 0
    fi
    if [[ "${1:-}" == link && "${2:-}" == show ]]; then
        return 1
    fi
    return 0
}
tc() {
    printf '%s ' "$@" >> "$work/events"
    printf '\n' >> "$work/events"
    if [[ "${1:-}" == qdisc && "${2:-}" == show ]]; then
        printf 'qdisc mq 0: root\n'
        printf 'qdisc clsact ffff: parent ffff:fff1\n'
    elif [[ "${1:-}" == filter && "${2:-}" == show ]]; then
        printf 'filter protocol ip pref 42001 flower\n'
        printf 'filter protocol ip pref 42002 flower\n'
    elif [[ "${1:-}" == actions && "${2:-}" == ls ]]; then
        printf 'index 3900001 ref 1 bind 1\n'
    fi
    return 0
}
install() {
    [[ "$1" == -m ]]
    cp "$3" "$4"
    chmod "$2" "$4"
}
preflight_shaper() { return 0; }
state_layout_active() { return 0; }
run_apply() { apply_limits; }
run_apply
[[ -z "$(trap -p RETURN)" ]]
grep -q '^actions delete action police index 3900001 ' "$work/events"
! grep -q 'action police rate' "$work/events"
grep -q '^qdisc replace dev ktoifb.* root handle 7b00: htb ' "$work/events"
grep -q '^qdisc replace dev ens3 root handle 7a00: htb ' "$work/events"
grep -q '^qdisc replace dev ktoifb.* fq_codel ' "$work/events"
grep -q '^qdisc replace dev ens3 parent 7a00:101 .* fq_codel ' "$work/events"
[[ "$(grep -c '^filter add dev ens3 ' "$work/events")" == 4 ]]
grep -q 'ingress protocol ip .* dst_ip 217.19.122.109 dst_port 8443 action mirred egress redirect dev ktoifb' "$work/events"
grep -q 'parent 7a00: protocol ip .* src_ip 217.19.122.109 src_port 8443 classid 7a00:101' "$work/events"
grep -q 'ingress protocol ip .* dst_ip 217.19.122.109 dst_port 9443 action mirred egress redirect dev ktoifb' "$work/events"
grep -q 'parent 7a00: protocol ip .* src_ip 217.19.122.109 src_port 9443 classid 7a00:101' "$work/events"
! grep -q 'dst_port 8444' "$work/events"
! grep -q 'src_port 8444' "$work/events"
[[ "$(grep -c $'^F\t' "$STATE_FILE")" == 4 ]]
[[ "$(grep -c $'^A\t' "$STATE_FILE" || true)" == 0 ]]
[[ "$(grep -c $'^S\t' "$STATE_FILE")" == 1 ]]
[[ "$(grep -c $'^V\t3$' "$STATE_FILE")" == 1 ]]
[[ "$(grep -c $'^R\tens3\tmq$' "$STATE_FILE")" == 1 ]]
[[ "$(grep -c $'^I\t' "$STATE_FILE")" == 1 ]]
grep -q $'^L\t217.19.122.109\t2000\tens3\t.*\t7a00:101\t8443,9443$' "$STATE_FILE"
: > "$work/events"
second_output="$(run_apply)"
grep -q 'Shaper HAProxy уже актуален: 1 IP, 4 точных фильтров' <<< "$second_output"
! grep -Eq '^(qdisc (add|replace|delete)|class (add|replace|delete)|filter (add|delete)|actions delete)' "$work/events"
[[ -z "$(trap -p RETURN)" ]]
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_bandwidth_shaper_falls_back_to_u32_when_flower_is_unavailable(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
set -Eeuo pipefail
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export KTO_HAPROXY_BANDWIDTH_CONFIG="$work/limits"
export KTO_HAPROXY_CONFIG="$work/haproxy.cfg"
export KTO_HAPROXY_BANDWIDTH_STATE="$work/state"
export KTO_HAPROXY_BANDWIDTH_LOG="$work/log"
export KTO_HAPROXY_BANDWIDTH_LOCK="$work/lock"
source <(sed '/^main /d' scripts/kto-haproxy-bandwidth.sh)
printf '217.19.122.109\t2000\n' > "$LIMITS_CONFIG"
cat > "$HAPROXY_CONFIG" <<'EOF'
global
    maxconn 10000
defaults
    mode tcp
frontend vless_in
    bind *:443 backlog 65535
    default_backend vless_pool
backend vless_pool
    server xray1 1.1.1.1:443
EOF
: > "$LOG_FILE"
ip() {
    if [[ "${1:-}" == -4 && "${2:-}" == -o && "${3:-}" == address &&
        "${4:-}" == show && "${5:-}" == scope && "${6:-}" == global ]]; then
        printf '2: ens3    inet 217.19.122.109/24 brd 217.19.122.255 scope global ens3\n'
        return 0
    fi
    if [[ "${1:-}" == link && "${2:-}" == show ]]; then
        return 1
    fi
    return 0
}
tc() {
    local argument
    printf '%s ' "$@" >> "$work/events"
    printf '\n' >> "$work/events"
    if [[ "${1:-}" == filter && "${2:-}" == add ]]; then
        for argument in "$@"; do
            if [[ "$argument" == flower ]]; then
                printf "Unknown filter 'flower'\n" >&2
                return 2
            fi
        done
    elif [[ "${1:-}" == qdisc && "${2:-}" == show ]]; then
        printf 'qdisc fq 0: root\n'
        printf 'qdisc clsact ffff: parent ffff:fff1\n'
    fi
    return 0
}
install() {
    [[ "$1" == -m ]]
    cp "$3" "$4"
    chmod "$2" "$4"
}
preflight_shaper() { return 0; }
outer() { apply_limits; }
outer
[[ -z "$(trap -p RETURN)" ]]
[[ "$(grep -c '^filter add dev ens3 .* flower ' "$work/events")" == 1 ]]
[[ "$(grep -c '^filter add dev ens3 .* u32 ' "$work/events")" == 2 ]]
grep -q 'u32 .* match ip dst 217.19.122.109/32 match ip dport 443 .* action mirred egress redirect dev ktoifb' "$work/events"
grep -q 'parent 7a00: protocol ip .* u32 .* match ip src 217.19.122.109/32 match ip sport 443 .* flowid 7a00:101' "$work/events"
! grep -q 'action police rate' "$work/events"
[[ "$(grep -c $'^F\t' "$STATE_FILE")" == 2 ]]
[[ "$(grep -c $'^A\t' "$STATE_FILE" || true)" == 0 ]]
[[ "$(grep -c $'^R\tens3\tfq$' "$STATE_FILE")" == 1 ]]
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_bandwidth_shaper_groups_multiple_ips_on_one_interface(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
set -Eeuo pipefail
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export KTO_HAPROXY_BANDWIDTH_CONFIG="$work/limits"
export KTO_HAPROXY_CONFIG="$work/haproxy.cfg"
export KTO_HAPROXY_BANDWIDTH_STATE="$work/state"
export KTO_HAPROXY_BANDWIDTH_LOG="$work/log"
export KTO_HAPROXY_BANDWIDTH_LOCK="$work/lock"
source <(sed '/^main /d' scripts/kto-haproxy-bandwidth.sh)
printf '217.19.122.109\t2000\n217.19.122.148\t1000\n' > "$LIMITS_CONFIG"
cat > "$HAPROXY_CONFIG" <<'EOF'
global
    maxconn 10000
defaults
    mode tcp
frontend vless_a
    bind 217.19.122.109:443
    default_backend pool_a
frontend vless_b
    bind 217.19.122.148:443
    default_backend pool_b
frontend vless_shared
    bind *:8443
    default_backend pool_shared
backend pool_a
    server a 1.1.1.1:443
backend pool_b
    server b 2.2.2.2:443
backend pool_shared
    server c 3.3.3.3:443
EOF
: > "$LOG_FILE"
ip() {
    if [[ "${1:-}" == -4 && "${2:-}" == -o && "${3:-}" == address ]]; then
        printf '2: ens3 inet 217.19.122.109/24 scope global ens3\n'
        printf '2: ens3 inet 217.19.122.148/24 scope global secondary ens3\n'
        return 0
    fi
    [[ "${1:-}" == link && "${2:-}" == show ]] && return 1
    return 0
}
tc() {
    printf '%s ' "$@" >> "$work/events"
    printf '\n' >> "$work/events"
    if [[ "${1:-}" == qdisc && "${2:-}" == show ]]; then
        printf 'qdisc fq 0: root\nqdisc clsact ffff: parent ffff:fff1\n'
    fi
    return 0
}
install() {
    [[ "$1" == -m ]]
    cp "$3" "$4"
    chmod "$2" "$4"
}
preflight_shaper() { return 0; }
apply_limits
[[ "$(grep -c '^qdisc replace dev ens3 root handle 7a00: htb ' "$work/events")" == 1 ]]
[[ "$(grep -c '^qdisc replace dev ktoifb.* root handle 7b00: htb ' "$work/events")" == 2 ]]
grep -q '^class replace dev ens3 parent 7a00:1 classid 7a00:101 htb rate 2000mbit ' "$work/events"
grep -q '^class replace dev ens3 parent 7a00:1 classid 7a00:102 htb rate 1000mbit ' "$work/events"
[[ "$(grep -c '^filter add dev ens3 ' "$work/events")" == 8 ]]
[[ "$(grep -c $'^R\tens3\tfq$' "$STATE_FILE")" == 1 ]]
[[ "$(grep -c $'^I\t' "$STATE_FILE")" == 2 ]]
[[ "$(grep -c $'^L\t' "$STATE_FILE")" == 2 ]]
[[ "$(grep -c $'^F\t' "$STATE_FILE")" == 8 ]]
grep -q $'^L\t217.19.122.109\t2000\tens3\t.*\t7a00:101\t443,8443$' "$STATE_FILE"
grep -q $'^L\t217.19.122.148\t1000\tens3\t.*\t7a00:102\t443,8443$' "$STATE_FILE"
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_bandwidth_shaper_rolls_back_partial_apply(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
set -Eeuo pipefail
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export KTO_HAPROXY_BANDWIDTH_CONFIG="$work/limits"
export KTO_HAPROXY_CONFIG="$work/haproxy.cfg"
export KTO_HAPROXY_BANDWIDTH_STATE="$work/state"
export KTO_HAPROXY_BANDWIDTH_LOG="$work/log"
export KTO_HAPROXY_BANDWIDTH_LOCK="$work/lock"
source <(sed '/^main /d' scripts/kto-haproxy-bandwidth.sh)
printf '217.19.122.109\t2000\n' > "$LIMITS_CONFIG"
cat > "$HAPROXY_CONFIG" <<'EOF'
global
defaults
    mode tcp
frontend vless_in
    bind 217.19.122.109:443
    default_backend pool
backend pool
    server xray 1.1.1.1:443
EOF
: > "$LOG_FILE"
ip() {
    if [[ "${1:-}" == -4 && "${2:-}" == -o && "${3:-}" == address ]]; then
        printf '2: ens3 inet 217.19.122.109/24 scope global ens3\n'
        return 0
    fi
    if [[ "${1:-}" == link && "${2:-}" == show ]]; then
        [[ -e "$work/ifb-up" ]]
        return
    fi
    if [[ "${1:-}" == link && "${2:-}" == add ]]; then
        : > "$work/ifb-up"
    elif [[ "${1:-}" == link && "${2:-}" == delete ]]; then
        rm -f "$work/ifb-up"
    fi
    printf 'ip:' >> "$work/events"
    printf '%s ' "$@" >> "$work/events"
    printf '\n' >> "$work/events"
    return 0
}
tc() {
    printf '%s ' "$@" >> "$work/events"
    printf '\n' >> "$work/events"
    if [[ "${1:-}" == qdisc && "${2:-}" == show && "${4:-}" == ens3 ]]; then
        if [[ -e "$work/root-owned" ]]; then
            printf 'qdisc htb 7a00: root\n'
        else
            printf 'qdisc fq 0: root\n'
        fi
        printf 'qdisc clsact ffff: parent ffff:fff1\n'
    elif [[ "${1:-}" == qdisc && "${2:-}" == replace && "${4:-}" == ens3 &&
        "${5:-}" == root && "${6:-}" == handle && "${7:-}" == 7a00: ]]; then
        : > "$work/root-owned"
    elif [[ "${1:-}" == qdisc && "${2:-}" == delete && "${4:-}" == ens3 && "${5:-}" == root ]]; then
        rm -f "$work/root-owned"
    elif [[ "${1:-}" == filter && "${2:-}" == add && "${5:-}" == parent && "${6:-}" == 7a00: ]]; then
        printf 'simulated egress classifier failure\n' >&2
        return 2
    fi
    return 0
}
install() {
    [[ "$1" == -m ]]
    cp "$3" "$4"
    chmod "$2" "$4"
}
preflight_shaper() { return 0; }
if apply_limits; then
    echo 'apply unexpectedly succeeded' >&2
    exit 1
fi
[[ ! -e "$work/root-owned" ]]
[[ ! -e "$work/ifb-up" ]]
[[ ! -e "$STATE_FILE" ]]
grep -q '^filter delete dev ens3 ingress protocol ip pref 42001 ' "$work/events"
grep -q '^qdisc delete dev ens3 root ' "$work/events"
grep -q '^ip:link delete dev ktoifb' "$work/events"
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_route_reapply_uses_only_local_bandwidth_manager(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
set -Eeuo pipefail
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export EVENTS="$work/events"
export KTO_HAPROXY_BANDWIDTH_MANAGER="$work/manager"
export KTO_HAPROXY_BANDWIDTH_SERVICE="manager.service"
source <(sed '/^main /d' kto.sh)
SUDO=()
cat > "$HAPROXY_BANDWIDTH_MANAGER" <<'EOF'
#!/usr/bin/env bash
printf 'manager:%s\n' "$*" >> "$EVENTS"
EOF
chmod +x "$HAPROXY_BANDWIDTH_MANAGER"
ensure_haproxy_bandwidth_manager() {
    printf 'network-install\n' >> "$EVENTS"
    return 99
}
require_local_haproxy_bandwidth_manager() {
    printf 'local-check\n' >> "$EVENTS"
}
run_bounded_command() {
    shift
    "$@"
}
run_systemctl_bounded() { return 1; }
reapply_haproxy_bandwidth_limits
grep -Fqx 'local-check' "$EVENTS"
grep -Fqx 'manager:apply' "$EVENTS"
! grep -q '^network-install$' "$EVENTS"
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_bandwidth_config_rolls_back_on_apply_failure(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
set -Eeuo pipefail
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export KTO_HAPROXY_CONFIG="$work/haproxy.cfg"
export KTO_HAPROXY_BANDWIDTH_CONFIG="$work/limits"
export KTO_HAPROXY_BANDWIDTH_MANAGER="$work/manager"
export KTO_HAPROXY_BANDWIDTH_UNIT="$work/manager.service"
source <(sed '/^main /d' kto.sh)
SUDO=()
LOG_FILE="$work/log"
: > "$LOG_FILE"
printf 'global\n' > "$HAPROXY_CONFIG_FILE"
cat > "$HAPROXY_BANDWIDTH_MANAGER" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$HAPROXY_BANDWIDTH_MANAGER"
ip() {
    if [[ "${1:-}" == -4 && "${2:-}" == route && "${3:-}" == get ]]; then
        printf '1.1.1.1 via 217.19.122.1 dev ens3 src 217.19.122.109\n'
        return 0
    fi
    if [[ "${1:-}" == -4 && "${2:-}" == -o && "${3:-}" == address ]]; then
        printf '2: ens3    inet 217.19.122.109/24 brd 217.19.122.255 scope global ens3\n'
        return 0
    fi
    return 1
}
write_root_file_mode() {
    local mode="$1" path="$2"
    cat > "$path"
    chmod "$mode" "$path"
}
ensure_haproxy_bandwidth_manager() { :; }
REAPPLY_FAIL=0
reapply_haproxy_bandwidth_limits() { (( REAPPLY_FAIL == 0 )); }

set_haproxy_input_bandwidth_limit 217.19.122.109 2000
grep -qx $'217.19.122.109\t2000' "$HAPROXY_BANDWIDTH_CONFIG"

REAPPLY_FAIL=1
! set_haproxy_input_bandwidth_limit 217.19.122.109 3000
grep -qx $'217.19.122.109\t2000' "$HAPROXY_BANDWIDTH_CONFIG"
! grep -q $'\t3000$' "$HAPROXY_BANDWIDTH_CONFIG"

REAPPLY_FAIL=0
remove_haproxy_input_bandwidth_limit 217.19.122.109
[[ ! -s "$HAPROXY_BANDWIDTH_CONFIG" ]]
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_reality_profiles_expose_haproxy_bridge_on_8443(self):
        supported = function_body(KTO, "haproxy_mode_supported")
        base_port = function_body(KTO, "haproxy_base_port")
        configure = function_body(KTO, "configure_haproxy_backend")
        haproxy_menu = function_body(KTO, "haproxy_menu")
        settings_menu = function_body(KTO, "settings_menu")
        main_menu = function_body(KTO, "menu")

        self.assertIn('[[ "$MACHINE_MODE" == "whitelist" ]]', supported)
        self.assertIn('node_profile_includes_reality', supported)
        self.assertIn('echo "8443"', base_port)
        self.assertIn('echo "443"', base_port)
        self.assertIn('require_haproxy_mode', configure)
        self.assertIn('base_port="$(haproxy_base_port)"', configure)
        self.assertIn('haproxy_tcp_port_listening "$base_port" "$listen_ip"', configure)
        self.assertIn('source_ip="$(select_haproxy_route_source_ip)"', configure)
        self.assertIn('listen_ip="$(haproxy_route_ip_for_source "$source_ip")"', configure)
        self.assertIn('print_haproxy_route "$base_port"', configure)
        self.assertIn('sync_haproxy_firewall "$routes_file" "$previous_routes_file"', configure)
        self.assertIn('require_haproxy_mode', haproxy_menu)
        self.assertIn('if haproxy_mode_supported; then', settings_menu)
        self.assertIn('labels+=("HAProxy (мост, 8443/tcp)")', main_menu)

    def test_new_haproxy_routes_default_to_an_exact_input_ip(self):
        default_bind = function_body(KTO, "haproxy_default_listen_ip_for_source")
        configure = function_body(KTO, "configure_haproxy_backend")
        add_route = function_body(KTO, "add_haproxy_route_with_source")
        add_pool = function_body(KTO, "add_haproxy_pool_route")
        add_sequential = function_body(KTO, "add_haproxy_sequential_routes")
        pool_cli = function_body(KTO, "set_haproxy_pool_route_cli")
        sequential_cli = function_body(KTO, "set_haproxy_sequential_routes_cli")

        self.assertIn('haproxy_route_ip_for_source "${1:-default}"', default_bind)
        self.assertIn('select_haproxy_route_source_ip', configure)
        self.assertIn('listen_ip="$(haproxy_route_ip_for_source "$source_ip")"', configure)
        self.assertIn('listen_ip="$(haproxy_route_ip_for_source "$source_ip"', add_route)
        self.assertIn('listen_ip="$(haproxy_route_ip_for_source "$source_ip")"', add_pool)
        self.assertIn('listen_ip="$(haproxy_route_ip_for_source "$source_ip")"', add_sequential)
        self.assertIn('normalized_listen_ip="$(haproxy_route_ip_for_source "$source_ip"', pool_cli)
        self.assertIn('Раздельные входной и выходной IP больше не поддерживаются', pool_cli)
        self.assertIn('listen_ip="$(haproxy_default_listen_ip_for_source "$source_ip")"', sequential_cli)
        self.assertIn('"$target_pool" "$listen_ip"', sequential_cli)

        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
haproxy_default_source_ip() { printf '198.51.100.10\n'; }
haproxy_input_ip_available() {
    [[ "$1" == 198.51.100.10 || "$1" == 203.0.113.20 ]]
}
ip() { return 0; }
[[ "$(haproxy_default_listen_ip_for_source default)" == 198.51.100.10 ]]
[[ "$(haproxy_default_listen_ip_for_source 203.0.113.20)" == 203.0.113.20 ]]
! haproxy_default_listen_ip_for_source 192.0.2.99
haproxy_input_ip_available() { return 1; }
! haproxy_default_listen_ip_for_source default
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_reality_haproxy_does_not_reclassify_push_as_whitelist(self):
        identity = function_body(PUSH, "ensure_node_identity")
        node_branch = identity.index('elif [[ "$machine_mode" == "node" ]]')
        haproxy_fallback = identity.index('elif [[ -r /etc/haproxy/haproxy.cfg ]]')

        self.assertLess(node_branch, haproxy_fallback)
        self.assertIn('inferred_kind="bl"', identity[node_branch:haproxy_fallback])

    def test_push_manages_reality_haproxy_base_route(self):
        frontend = function_body(PUSH, "haproxy_base_frontend_name")
        server = function_body(PUSH, "haproxy_base_server_name")
        read_sni = function_body(PUSH, "read_haproxy_allowed_sni")
        read_target = function_body(PUSH, "read_haproxy_backend_target")
        apply_config = function_body(PUSH, "apply_collector_haproxy_config")

        self.assertIn('/^vless_in_[0-9]+$/', frontend)
        self.assertIn('/^xray_[0-9]+$/', server)
        self.assertIn('base_frontend="$(haproxy_base_frontend_name)"', read_sni)
        self.assertIn('base_server="$(haproxy_base_server_name)"', read_target)
        self.assertIn('server_name="$base_server"', apply_config)
        self.assertIn('frontend_name="$base_frontend"', apply_config)

        bash = bash_executable()
        if bash is None:
            return

        harness = r'''
source <(awk '/^haproxy_base_frontend_name\(\)/ { keep=1 } /^read_haproxy_allowed_sni\(\)/ { exit } keep' scripts/kto-stats-push.sh)
config=$(mktemp)
trap 'rm -f "$config"' EXIT
cat > "$config" <<'EOF'
frontend vless_in_8443
    bind *:8443
    default_backend vless_pool_8443
backend vless_pool_8443
    server xray_8443 5.34.179.144:443 check weight 10
EOF
[[ "$(haproxy_base_frontend_name "$config")" == vless_in_8443 ]]
[[ "$(haproxy_base_server_name "$config")" == xray_8443 ]]
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_base_port_matches_machine_profile(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
MACHINE_MODE=whitelist
NODE_PROFILE=
haproxy_mode_supported
[[ "$(haproxy_base_port)" == 443 ]]
MACHINE_MODE=node
NODE_PROFILE=reality
haproxy_mode_supported
[[ "$(haproxy_base_port)" == 8443 ]]
NODE_PROFILE=reality_hysteria2
haproxy_mode_supported
[[ "$(haproxy_base_port)" == 8443 ]]
NODE_PROFILE=hysteria2
! haproxy_mode_supported
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_wildcard_sni_and_ssh_defaults_are_managed(self):
        render_sni = function_body(KTO, "render_haproxy_sni_acl_lines")
        extract = function_body(KTO, "extract_haproxy_routes")
        read_sni = function_body(PUSH, "read_haproxy_allowed_sni")
        apply_haproxy = function_body(PUSH, "apply_collector_haproxy_config")

        self.assertIn('req.ssl_sni -m end -i %s', render_sni)
        self.assertIn('value = "*" value', extract)
        self.assertIn('value = "*" value', read_sni)
        self.assertIn('current_sni_block', apply_haproxy)
        self.assertIn('if (replaced == 0)', apply_haproxy)
        self.assertIn('line = line " " $i', apply_haproxy)
        self.assertIn(
            'WHITELIST_SSH_ALLOWED_IPS_DEFAULT="85.192.48.122 46.28.64.183 146.19.248.67 '
            '85.93.9.35 185.31.243.221 94.247.129.92 83.228.242.53 167.254.243.181 '
            '5.34.176.116 5.34.178.234 84.38.185.15 193.23.195.222"',
            KTO,
        )

    def test_xanmod_x64v3_install_is_guarded_and_bootable(self):
        repository = function_body(KTO, "configure_xanmod_repository")
        release_probe = function_body(KTO, "xanmod_release_available")
        cpu_check = function_body(KTO, "xanmod_x64v3_supported")
        install = function_body(KTO, "opt_xanmod_kernel")
        grub = function_body(KTO, "select_xanmod_grub_entry")
        grub_state = function_body(KTO, "prepare_xanmod_grub_state")

        self.assertIn('XANMOD_PACKAGE="${KTO_XANMOD_PACKAGE:-linux-xanmod-x64v3}"', KTO)
        self.assertIn('https://dl.xanmod.org/archive.key', KTO)
        self.assertIn('https://deb.xanmod.org', KTO)
        self.assertIn('x86-64-v3[[:space:]]+\\(supported', cpu_check)
        for flag in ("avx", "avx2", "bmi1", "bmi2", "f16c", "fma", "movbe", "xsave"):
            self.assertIn(flag, cpu_check)
        self.assertIn('gpg --batch --show-keys --with-colons', repository)
        self.assertIn('signed-by=${XANMOD_KEYRING}', repository)
        self.assertIn('/dists/${codename}/InRelease', release_probe)
        self.assertIn('curl -fsSIL --retry 2', release_probe)
        self.assertIn('wget -q --spider', release_probe)
        self.assertIn('secure_boot_enabled', install)
        self.assertIn('free_mb < 300', install)
        self.assertIn('root_free_mb < 1500', install)
        self.assertIn('for attempt in 1 2 3', install)
        self.assertIn('dpkg --configure -a', install)
        self.assertIn('apt-cache show "$XANMOD_PACKAGE"', install)
        self.assertIn('xanmod_release_available "$codename"', install)
        self.assertLess(install.index('if xanmod_installed; then'), install.index('xanmod_release_available "$codename"'))
        self.assertIn('select_xanmod_grub_entry', install)
        self.assertIn('mkdir -p /boot/grub', grub_state)
        self.assertIn('$2 == "/boot"', grub_state)
        self.assertIn('mount /boot', grub_state)
        self.assertIn('grub-editenv /boot/grub/grubenv create', grub_state)
        self.assertIn('prepare_xanmod_grub_state', grub)
        self.assertLess(grub.index('prepare_xanmod_grub_state'), grub.index('update-initramfs'))
        self.assertIn('update-initramfs', grub)
        self.assertIn('GRUB_DEFAULT=saved', grub)
        self.assertIn('update-grub', grub)
        self.assertIn('grub-set-default', grub)
        self.assertIn('progress_step "Ставлю XanMod x64v3" opt_xanmod_kernel', KTO)
        self.assertIn('progress_step "Проверяю kernel" opt_kernel_final_check', KTO)

    def test_root_ssh_migration_opens_firewall_before_restart_and_can_rollback(self):
        choose_port = function_body(KTO, "choose_managed_ssh_port")
        merge_keys = function_body(KTO, "merge_root_authorized_keys")
        migrate = function_body(KTO, "opt_ssh_root_access")
        rollback = function_body(KTO, "rollback_ssh_migration")

        self.assertIn('KTO_SSH_PORT_MIN="${KTO_SSH_PORT_MIN:-20000}"', KTO)
        self.assertIn('KTO_SSH_PORT_MAX="${KTO_SSH_PORT_MAX:-29999}"', KTO)
        self.assertIn('KTO_ROOT_BASE_PUBLIC_KEY="ssh-rsa AAAAB3NzaC1yc2E', KTO)
        self.assertIn('marker="$(managed_ssh_port || true)"', choose_port)
        self.assertIn('RANDOM * 32768 + RANDOM', choose_port)
        self.assertIn('/root/.ssh/authorized_keys', merge_keys)
        self.assertIn('getent passwd', merge_keys)
        self.assertIn('/etc/ssh/authorized_keys.d/${user}', merge_keys)
        self.assertIn('printf \'%s\\n\' "$KTO_ROOT_BASE_PUBLIC_KEY" > "$output_file"', merge_keys)
        self.assertIn('ssh-keygen -lf "$output_file"', merge_keys)
        self.assertNotIn('fail "SSH:', merge_keys)
        self.assertIn('public key не найден; текущие порт, UFW и параметры входа оставлены без изменений', migrate)
        self.assertIn('PermitRootLogin prohibit-password', migrate)
        self.assertIn('PasswordAuthentication no', migrate)
        self.assertIn('awk -v managed_include="$KTO_SSH_MANAGED_CONFIG"', migrate)
        self.assertNotIn('awk -v include=', migrate)
        self.assertIn('sshd -t', migrate)
        self.assertIn('sshd -T -C user=root', migrate)
        self.assertIn('rollback_ssh_migration', migrate)
        self.assertLess(
            migrate.index('ensure_global_ssh_ufw_rule "$new_port"'),
            migrate.index('restart "$service"'),
        )
        self.assertLess(
            migrate.index('ssh_port_is_listening "$new_port"'),
            migrate.index('write_root_file_mode 0600 "$KTO_SSH_PORT_FILE"'),
        )
        self.assertIn('restore_optional_ssh_file', rollback)
        self.assertIn('remove_ufw_allow_rules_for_port "$new_port"', rollback)
        optimize = function_body(KTO, "optimize_system")
        self.assertIn('ok "SSH-порт: ${ssh_port}/tcp"', optimize)
        self.assertIn('ok "Подключение: ssh -p ${ssh_port} root@IP"', optimize)

    def test_root_ssh_without_public_key_is_a_safe_noop(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
set -Eeuo pipefail
source <(sed '/^main /d' kto.sh)
SUDO=()
LOG_FILE=/dev/null
command_exists() { return 0; }
ssh_service_name() { printf 'ssh\n'; }
merge_root_authorized_keys() { : > "$1"; return 1; }
output="$(opt_ssh_root_access 2>&1)"
grep -Fq 'public key не найден' <<< "$output"
grep -Fq 'оставлены без изменений' <<< "$output"
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_managed_root_ssh_stays_global_during_haproxy_firewall_sync(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
events="$(mktemp)"
trap 'rm -f "$events"' EXIT
SUDO=()
whitelist_ssh_allowed_ips() { printf '192.0.2.10\n'; }
managed_ssh_port() { printf '23456\n'; }
ensure_global_ssh_ufw_rule() { printf 'global %s\n' "$1" >> "$events"; }
ufw() { printf 'ufw %s\n' "$*" >> "$events"; return 1; }

apply_whitelist_ssh_rules 23456
grep -qx 'global 23456' "$events"
! grep -q 'delete allow 23456/tcp' "$events"
! grep -q 'insert 1 allow proto tcp from' "$events"
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_ssh_allowlist_is_prioritized_and_ignored_by_fail2ban(self):
        apply_rules = function_body(KTO, "apply_whitelist_ssh_rules")
        fail2ban = function_body(KTO, "opt_fail2ban")
        push_apply = function_body(PUSH, "apply_collector_ssh_ips")
        push_sync = function_body(PUSH, "sync_fail2ban_ssh_allowlist")
        push_mode = function_body(PUSH, "apply_collector_ssh_firewall_mode")

        self.assertIn('ufw insert 1 allow proto tcp from "$ip"', apply_rules)
        self.assertIn('managed_port="$(managed_ssh_port 2>/dev/null || true)"', apply_rules)
        self.assertIn('ensure_global_ssh_ufw_rule "$ssh_port"', apply_rules)
        self.assertIn("write_whitelist_fail2ban_allowlist", fail2ban)
        self.assertIn("unban_whitelist_ssh_ips", fail2ban)
        self.assertIn("ufw insert 1 allow proto tcp from \"\\$trusted_ip\"", KTO)
        self.assertIn('[[ "$KTO_PUSH_NODE_KIND" == "wl" ]] || return 0', push_apply)
        self.assertIn('ufw insert 1 allow proto tcp from "$ip"', push_apply)
        self.assertIn("fail2ban-client set sshd addignoreip", push_sync)
        self.assertIn("fail2ban-client set sshd unbanip", push_sync)
        self.assertIn('[[ "$KTO_PUSH_NODE_KIND" == "wl" ]] || return 0', push_mode)
        self.assertIn("ssh_firewall_open", push_mode)
        self.assertIn("kto-ssh-open", push_mode)
        self.assertIn("/ssh_firewall_off", COLLECTOR)
        self.assertIn("/ssh_firewall_on", COLLECTOR)

        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = "\n".join(
            [
                "set -Eeuo pipefail",
                function_body(PUSH, "validate_ipv4"),
                function_body(PUSH, "managed_ssh_port_enabled"),
                function_body(PUSH, "ufw_ssh_open_rule_numbers"),
                function_body(PUSH, "ufw_ssh_open_rule_exists"),
                function_body(PUSH, "remove_ufw_ssh_open_rules"),
                function_body(PUSH, "collector_ssh_allowed_ips"),
                function_body(PUSH, "ufw_kto_ssh_allowed_ips"),
                function_body(PUSH, "sync_fail2ban_ssh_allowlist"),
                function_body(PUSH, "apply_collector_ssh_ips"),
                function_body(PUSH, "apply_collector_ssh_firewall_mode"),
                r'''
root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT
events="$root/events"
open_state="$root/open"
KTO_SSH_PORT_FILE="$root/managed-ssh-port"
KTO_FAIL2BAN_SSH_ALLOWLIST_CONF="$root/allowlist.local"
KTO_PUSH_NODE_KIND=wl
PUSH_BUILD=vtest

jq() {
    input="$(cat)"
    if [[ "$*" == *ssh_firewall_open* ]]; then
        case "$input" in
            *'"ssh_firewall_open":true'*) printf 'open\n' ;;
            *'"ssh_firewall_open":false'*) printf 'whitelist\n' ;;
            *) printf 'unchanged\n' ;;
        esac
    else
        printf '%s\n' 85.192.48.122 203.0.113.77
    fi
}
ufw_active() { return 0; }
detect_ssh_port() { printf '22\n'; }
ufw_ssh_rule_exists() { return 1; }
ufw() {
    if [[ "${1:-}" == "status" && "${2:-}" == "numbered" ]]; then
        [[ ! -e "$open_state" ]] || printf '[ 1] 22/tcp ALLOW IN Anywhere # kto-ssh-open\n'
        return 0
    fi
    printf 'ufw %s\n' "$*" >> "$events"
    if [[ "$*" == *"comment kto-ssh-open"* ]]; then
        : > "$open_state"
    elif [[ "${1:-}" == "--force" && "${2:-}" == "delete" && "${3:-}" == "1" ]]; then
        rm -f "$open_state"
    fi
}
systemctl() { [[ "${1:-}" == "is-active" ]]; }
fail2ban-client() { printf 'f2b %s\n' "$*" >> "$events"; }

apply_collector_ssh_ips '{}'
grep -q '^ufw insert 1 allow proto tcp from 85.192.48.122 to any port 22 comment kto-ssh$' "$events"
grep -q '^f2b set sshd addignoreip 203.0.113.77$' "$events"
grep -q '^f2b set sshd unbanip 203.0.113.77$' "$events"
grep -q '^ignoreip = 127.0.0.1/8 ::1 203.0.113.77 85.192.48.122$' "$KTO_FAIL2BAN_SSH_ALLOWLIST_CONF"

apply_collector_ssh_firewall_mode '{"ssh_firewall_open":true}'
[[ -e "$open_state" ]]
grep -q '^ufw insert 1 allow proto tcp to any port 22 comment kto-ssh-open$' "$events"
apply_collector_ssh_firewall_mode '{"ssh_firewall_open":false}'
[[ ! -e "$open_state" ]]
grep -q '^ufw --force delete 1$' "$events"

before="$(wc -l < "$events")"
KTO_PUSH_NODE_KIND=bl
apply_collector_ssh_ips '{}'
apply_collector_ssh_firewall_mode '{"ssh_firewall_open":true}'
after="$(wc -l < "$events")"
[[ "$before" == "$after" ]]
''',
            ]
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            harness_path = Path(tmpdir) / "ssh-firewall-test.sh"
            harness_path.write_text(harness, encoding="utf-8", newline="\n")
            result = subprocess.run(
                [bash, str(harness_path)],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_updates_are_transactional_and_preserve_routes(self):
        apply_routes = function_body(KTO, "apply_haproxy_routes_config")
        update = function_body(KTO, "update_haproxy_existing_config")

        self.assertIn('haproxy -c -f "$tmp_config"', apply_routes)
        self.assertIn('${config}.kto.bak', apply_routes)
        self.assertIn('${config}.kto.failed', apply_routes)
        self.assertIn('extract_haproxy_routes "$backup" > "$backup_routes"', apply_routes)
        self.assertIn('create_haproxy_persistent_backup "before-apply"', apply_routes)
        self.assertIn('reserve_haproxy_route_ports "$routes_file"', apply_routes)
        self.assertIn('reload_haproxy_gracefully "$routes_file"', apply_routes)
        self.assertIn('возвращаю предыдущий', apply_routes)
        self.assertIn('install -m 0644 "$backup" "$config"', apply_routes)
        self.assertIn('start_haproxy_cleanly "$backup_routes"', apply_routes)
        self.assertIn('write_root_file_if_changed', apply_routes)
        self.assertIn('capacity_updated == 1', apply_routes)
        self.assertIn('cmp -s "$tmp_config" "$backup"', apply_routes)
        self.assertIn('reload не требуется', apply_routes)
        self.assertIn('force_clean_start', apply_routes)
        self.assertIn('extract_haproxy_routes > "$routes_file"', update)
        self.assertIn('upgrade_haproxy_routes_transaction "$routes_file"', update)
        upgrade = function_body(KTO, "upgrade_haproxy_routes_transaction")
        self.assertIn('маршруты сохранены', upgrade)
        self.assertIn('haproxy_routes_round_trip_equal', upgrade)

    def test_haproxy_stability_controls_are_bounded_and_preserve_routes(self):
        render = function_body(KTO, "render_haproxy_routes_config")
        stabilize = function_body(KTO, "stabilize_haproxy")
        clear_limits = function_body(KTO, "clear_all_haproxy_bandwidth_limits")
        diagnose = function_body(KTO, "diagnose_haproxy")

        self.assertIn("option splice-auto", render)
        self.assertIn("option splice-request", render)
        self.assertIn("option splice-response", render)
        self.assertIn("option redispatch", render)
        self.assertIn("retries 2", render)
        self.assertIn("timeout connect 4s", render)
        self.assertIn("timeout queue 4s", render)
        self.assertIn("timeout check 3s", render)
        self.assertIn("default-server inter 10s fastinter 2s downinter 10s fall 3 rise 2", render)
        self.assertIn("spread-checks 5", render)
        self.assertNotIn("hard-stop-after", render)
        self.assertNotIn("tune.maxaccept", render)
        self.assertNotIn("tune.bufsize", render)
        self.assertIn('extract_haproxy_routes > "$routes_file"', stabilize)
        self.assertIn('apply_haproxy_routes_config "$routes_file" 1 1', stabilize)
        self.assertIn('run_bounded_command 20', clear_limits)
        self.assertIn('"$HAPROXY_BANDWIDTH_MANAGER" clear', clear_limits)
        self.assertIn('rm -f "$HAPROXY_BANDWIDTH_CONFIG"', clear_limits)
        self.assertIn('ps -C haproxy', diagnose)
        self.assertIn('haproxy-limit-clear|haproxy-bandwidth-clear', KTO)
        self.assertIn('haproxy-stabilize|haproxy-recover', KTO)

    def test_root_file_writer_reports_only_real_content_changes(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
SUDO=()
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
LOG_FILE="$root/kto.log"
target="$root/capacity.conf"
write_root_file_if_changed "$target" <<'EOF'
alpha
EOF
[[ "$ROOT_FILE_UPDATED" == 1 ]]
write_root_file_if_changed "$target" <<'EOF'
alpha
EOF
[[ "$ROOT_FILE_UPDATED" == 0 ]]
write_root_file_if_changed "$target" <<'EOF'
beta
EOF
[[ "$ROOT_FILE_UPDATED" == 1 ]]
grep -Fqx beta "$target"
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_capacity_respects_descriptor_budget(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
memory_total_mb() { printf '%s\n' "${TEST_MEMORY_MB:-16384}"; }
cpu_count() { printf '%s\n' "${TEST_CPU_COUNT:-16}"; }
sysctl() {
    if [[ "${1:-}" == -n && "${2:-}" == net.netfilter.nf_conntrack_max ]]; then
        printf '%s\n' "${TEST_CONNTRACK_MAX:-2097152}"
        return 0
    fi
    return 1
}
KTO_HAPROXY_NOFILE_LIMIT=1048576
KTO_HAPROXY_FDS_PER_CONNECTION=3
KTO_HAPROXY_FD_RESERVE=8192
unset KTO_HAPROXY_MAXCONN
[[ "$(recommended_haproxy_maxconn)" == 32000 ]]
KTO_HAPROXY_MAXCONN=invalid
[[ "$(recommended_haproxy_maxconn)" == 32000 ]]
KTO_HAPROXY_MAXCONN=500000
[[ "$(recommended_haproxy_maxconn)" == 346000 ]]
KTO_HAPROXY_MAXCONN=200000
[[ "$(recommended_haproxy_maxconn)" == 200000 ]]
TEST_CONNTRACK_MAX=524288
KTO_HAPROXY_NOFILE_LIMIT=1048576
KTO_HAPROXY_MAXCONN=500000
[[ "$(recommended_haproxy_maxconn)" == 196000 ]]
TEST_CONNTRACK_MAX=2097152
KTO_HAPROXY_NOFILE_LIMIT=65536
unset KTO_HAPROXY_MAXCONN
[[ "$(recommended_haproxy_maxconn)" == 19000 ]]
KTO_HAPROXY_NOFILE_LIMIT=1048576
TEST_MEMORY_MB=65536
TEST_CPU_COUNT=2
[[ "$(recommended_haproxy_maxconn)" == 4000 ]]
TEST_CPU_COUNT=4
[[ "$(recommended_haproxy_maxconn)" == 8000 ]]
TEST_CPU_COUNT=8
[[ "$(recommended_haproxy_maxconn)" == 16000 ]]
TEST_CPU_COUNT=16
[[ "$(recommended_haproxy_maxconn)" == 32000 ]]
TEST_CPU_COUNT=32
[[ "$(recommended_haproxy_maxconn)" == 64000 ]]
KTO_HAPROXY_CONNECTIONS_PER_CPU=invalid
[[ "$(recommended_haproxy_maxconn)" == 64000 ]]
unset KTO_HAPROXY_CONNECTIONS_PER_CPU
[[ "$(haproxy_pool_server_maxconn 64000 1 auto)" == 64000 ]]
[[ "$(haproxy_pool_server_maxconn 64000 21 auto)" == 3048 ]]
[[ "$(haproxy_pool_server_maxconn 64000 1 25000)" == 25000 ]]
[[ "$(haproxy_pool_server_maxconn 4000 1 auto)" == 4000 ]]
unset KTO_HAPROXY_NBTHREAD
TEST_CPU_COUNT=16
[[ "$(haproxy_thread_count)" == 16 ]]
TEST_CPU_COUNT=32
[[ "$(haproxy_thread_count)" == 32 ]]
KTO_HAPROXY_AUTO_THREADS_MAX=8
[[ "$(haproxy_thread_count)" == 8 ]]
KTO_HAPROXY_NBTHREAD=8
[[ "$(haproxy_thread_count)" == 8 ]]
KTO_HAPROXY_NBTHREAD=0
[[ "$(haproxy_thread_count)" == 8 ]]
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_activation_checks_every_listener(self):
        wait_for_routes = function_body(KTO, "wait_for_haproxy_routes")
        missing_listeners = function_body(KTO, "haproxy_missing_listener_ports")
        reload = function_body(KTO, "reload_haproxy_gracefully")
        clean_start = function_body(KTO, "start_haproxy_cleanly")
        bounded_systemctl = function_body(KTO, "run_systemctl_bounded")
        bounded_command = function_body(KTO, "run_bounded_command")
        stale_listeners = function_body(KTO, "kill_stale_haproxy_route_listeners")
        socket_details = function_body(KTO, "haproxy_tcp_port_socket_details")
        socket_probe = function_body(KTO, "haproxy_tcp_port_has_socket")
        failure_details = function_body(KTO, "print_haproxy_failure_details")
        package = function_body(KTO, "ensure_haproxy_package")

        self.assertIn('haproxy_missing_listener_ports "$routes_file"', wait_for_routes)
        self.assertIn('run_systemctl_bounded 3 is-active --quiet haproxy', wait_for_routes)
        self.assertIn('haproxy_tcp_listener_endpoints', missing_listeners)
        self.assertNotIn('ss -H -ltnp', missing_listeners)
        self.assertNotIn('haproxy_tcp_port_owned_by_haproxy', missing_listeners)
        self.assertIn('wait_for_haproxy_routes "$routes_file"', reload)
        self.assertIn('start_haproxy_cleanly "$routes_file"', reload)
        self.assertIn('print_haproxy_failure_details', reload)
        self.assertIn('run_systemctl_bounded 15 restart haproxy', reload)
        self.assertIn('run_bounded_command "$timeout_sec" "${SUDO[@]}" systemctl', bounded_systemctl)
        self.assertIn('timeout --foreground --signal=TERM --kill-after=3s', bounded_command)
        self.assertIn('run_systemctl_bounded 10 --no-block stop haproxy', clean_start)
        self.assertIn('reserve_haproxy_route_ports "$routes_file"', clean_start)
        self.assertIn('wait_for_haproxy_stopped_and_ports_free', clean_start)
        self.assertIn('wait_for_haproxy_stopped_and_ports_free "$routes_file" 5', clean_start)
        self.assertIn('deadline=$(( SECONDS + max_wait_sec ))', wait_for_routes)
        self.assertIn('run_systemctl_bounded 10 kill --kill-who=all --signal=KILL', clean_start)
        self.assertIn('run_systemctl_bounded 10 reset-failed haproxy', clean_start)
        self.assertIn('run_systemctl_bounded 10 --no-block start haproxy', clean_start)
        self.assertIn('grep -vi haproxy', stale_listeners)
        self.assertIn('kill "-${signal}" "$pid"', stale_listeners)
        self.assertIn('ss -K state connected', stale_listeners)
        self.assertIn('ss -H -tanp', socket_details)
        self.assertIn('sport = :${wanted}', socket_details)
        self.assertIn('run_bounded_command 3', socket_probe)
        self.assertIn('return 0', socket_probe)
        self.assertIn('journalctl -u haproxy -n 40', failure_details)
        self.assertIn('ss -H -ltn', failure_details)
        self.assertNotIn('ss -H -ltnp', failure_details)
        self.assertIn('run_systemctl_bounded 5 show haproxy -p LimitNOFILE', failure_details)
        self.assertIn('haproxy socat iproute2', package)
        self.assertIn('command_exists haproxy && command_exists ss', package)
        self.assertNotIn('command_exists haproxy && command_exists socat', package)

        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
SUDO=()
KTO_HAPROXY_STARTUP_ATTEMPTS=1
routes=$(mktemp)
events=$(mktemp)
trap 'rm -f "$routes" "$events"' EXIT
printf '8443\t65.108.1.173:443\tfaq.cdnvideo.work\tdefault\n8444\t65.108.1.174:443\tfaq.cdnvideo.work\tdefault\n' > "$routes"
systemctl() { return 0; }
run_systemctl_bounded() {
    shift
    systemctl "$@"
}
sleep() { return 0; }
MODE=partial
ss() {
    printf 'call\n' >> "$events"
    printf '%s\n' 'LISTEN 0 4096 0.0.0.0:8443 0.0.0.0:* users:(("haproxy",pid=10,fd=4))'
    if [[ "$MODE" == all ]]; then
        printf '%s\n' 'LISTEN 0 4096 0.0.0.0:8444 0.0.0.0:* users:(("haproxy",pid=10,fd=5))'
    fi
}
! wait_for_haproxy_routes "$routes"
[[ "$(wc -l < "$events")" == 2 ]]
: > "$events"
MODE=all
wait_for_haproxy_routes "$routes"
[[ "$(wc -l < "$events")" == 1 ]]
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_clean_start_waits_and_kills_only_stale_haproxy(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
SUDO=()
LOG_FILE=$(mktemp)
routes=$(mktemp)
events=$(mktemp)
trap 'rm -f "$LOG_FILE" "$routes" "$events"' EXIT
printf '8443\t65.108.1.173:443\tfaq.cdnvideo.work\tdefault\n' > "$routes"
systemctl() {
    printf '%s|' "$@" >> "$events"
    printf '\n' >> "$events"
    if [[ "${1:-}" == show ]]; then
        printf 'ActiveState=inactive\nMainPID=0\n'
    fi
    return 0
}
run_systemctl_bounded() {
    shift
    systemctl "$@"
}
port_checks=0
haproxy_route_ports_are_free() {
    port_checks=$((port_checks + 1))
    return 0
}
wait_for_haproxy_routes() { return 0; }
reserve_haproxy_route_ports() { return 0; }
start_haproxy_cleanly "$routes"
[[ "$port_checks" == 1 ]]
grep -q -- '--no-block|stop|haproxy|' "$events"
grep -q 'reset-failed|haproxy|' "$events"
grep -q -- '--no-block|start|haproxy|' "$events"

MODE=haproxy
haproxy_tcp_port_socket_details() {
    case "$MODE" in
        haproxy)
            printf '%s\n' 'LISTEN 0 4096 0.0.0.0:8443 0.0.0.0:* users:(("haproxy",pid=123,fd=4))'
            ;;
        foreign)
            printf '%s\n' 'LISTEN 0 4096 0.0.0.0:8443 0.0.0.0:* users:(("xray",pid=456,fd=4))'
            ;;
        connected)
            printf '%s\n' 'ESTAB 0 0 127.0.0.1:8443 127.0.0.1:9443 users:(("rw-core",pid=789,fd=5))'
            ;;
    esac
}
cat() { printf 'haproxy\n'; }
kill() { printf 'kill:%s:%s\n' "$1" "$2" >> "$events"; }
ss() { { printf 'ss:'; printf '%s|' "$@"; printf '\n'; } >> "$events"; }
kill_stale_haproxy_route_listeners "$routes" KILL
grep -q 'kill:-KILL:123' "$events"
before=$(grep -c '^kill:' "$events")
MODE=foreign
! kill_stale_haproxy_route_listeners "$routes" KILL
after=$(grep -c '^kill:' "$events")
[[ "$before" == "$after" ]]
MODE=connected
kill_stale_haproxy_route_listeners "$routes" KILL
grep -q 'ss:-K|state|connected|' "$events"

state_checks=0
port_checks=0
SECONDS=0
sleep() { return 0; }
haproxy_service_is_stopped() {
    state_checks=$((state_checks + 1))
    SECONDS=$((SECONDS + 3))
    return 1
}
haproxy_route_ports_are_free() {
    port_checks=$((port_checks + 1))
    return 0
}
! wait_for_haproxy_stopped_and_ports_free "$routes" 5
[[ "$state_checks" == 2 ]]
[[ "$port_checks" == 0 ]]
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_ports_are_reserved_and_ephemeral_range_avoids_service_ports(self):
        self.assertIn("net.ipv4.ip_local_port_range = 10000 65535", KTO)
        self.assertIn("net.ipv4.ip_local_port_range = 10000 65535", PUSH)
        self.assertNotIn("net.ipv4.ip_local_port_range = 1024 65535", KTO)
        self.assertNotIn("net.ipv4.ip_local_port_range = 1024 65535", PUSH)

        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
SUDO=()
LOG_FILE=$(mktemp)
HAPROXY_RESERVED_PORTS_SYSCTL_CONF=$(mktemp)
routes=$(mktemp)
events=$(mktemp)
trap 'rm -f "$LOG_FILE" "$HAPROXY_RESERVED_PORTS_SYSCTL_CONF" "$routes" "$events"' EXIT
printf '8443\t65.108.1.173:443\ta.example\tdefault\n8444\t65.108.1.174:443\tb.example\tdefault\n' > "$routes"
[[ "$(merge_reserved_port_list '22,8000-8400' 8443)" == '22,8000-8400,8443' ]]
[[ "$(merge_reserved_port_list '22,8000-9000' 8443)" == '22,8000-9000' ]]
sysctl() {
    if [[ "${1:-}" == -n ]]; then
        printf '22,8000-8400\n'
    elif [[ "${1:-}" == -w ]]; then
        printf '%s\n' "${2:-}" >> "$events"
    fi
}
reserve_haproxy_route_ports "$routes"
grep -q '^net.ipv4.ip_local_reserved_ports = 22,8000-8400,8443,8444$' "$HAPROXY_RESERVED_PORTS_SYSCTL_CONF"
grep -q '^net.ipv4.ip_local_reserved_ports=22,8000-8400,8443,8444$' "$events"
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_firewall_and_wrong_sni_cover_extra_ports(self):
        firewall = function_body(KTO, "sync_haproxy_firewall")
        optimize_firewall = function_body(KTO, "opt_firewall")
        check_firewall = function_body(KTO, "system_check_firewall")
        scan = function_body(PUSH, "read_haproxy_scan_stats")

        self.assertIn('repair_haproxy_firewall_rules "$routes_file"', firewall)
        self.assertIn('ufw --force delete allow "${port}/tcp"', firewall)
        self.assertIn('haproxy_listener_ports "$routes_file" > "$ports_file"', optimize_firewall)
        self.assertIn('ufw allow "${port}/tcp"', optimize_firewall)
        self.assertIn('haproxy_listener_ports "$routes_file" > "$ports_file"', check_firewall)
        self.assertIn('ufw_status_rule_open_to_any "${port}/tcp"', check_firewall)
        self.assertIn('/^vless_in_[0-9_]+$/', scan)
        self.assertIn("count[$1] += $2", scan)
        self.assertIn("show table %s", scan)

    def test_reality_haproxy_firewall_does_not_apply_whitelist_ssh_rules(self):
        firewall = function_body(KTO, "sync_haproxy_firewall")
        self.assertIn('[[ "$MACHINE_MODE" == "whitelist" && "$previous_known" == "0" ]]', firewall)
        self.assertIn('apply_whitelist_ssh_rules "$ssh_port"', firewall)
        self.assertIn('repair_haproxy_firewall_rules "$routes_file"', firewall)
        self.assertIn('"$port" == "443" || "$port" == "$NODE_PORT"', firewall)

        bash = bash_executable()
        if bash is None:
            return

        harness = r'''
source <(sed '/^main /d' kto.sh)
MACHINE_MODE=node
NODE_PROFILE=reality
SUDO=()
routes=$(mktemp)
previous=$(mktemp)
events=$(mktemp)
trap 'rm -f "$routes" "$previous" "$events"' EXIT
printf '8443\t5.34.179.144:443\tbridge.example.com\tdefault\n' > "$routes"
printf '443\t89.144.8.3:443\told.example.com\tdefault\n' > "$previous"
command_exists() { [[ "$1" == ufw ]]; }
ufw_active() { return 0; }
ufw_rule_open_to_any() {
    [[ "$1" == '443/tcp' ]] || grep -Fq "ufw allow ${1} comment kto-haproxy" "$events"
}
repair_haproxy_firewall_rules() {
    cmd ufw allow 8443/tcp comment kto-haproxy
}
apply_whitelist_ssh_rules() { printf 'ssh-filter\n' >> "$events"; }
cmd() { local IFS=' '; printf '%s\n' "$*" >> "$events"; }
sync_haproxy_firewall "$routes" "$previous"
grep -q 'ufw allow 8443/tcp' "$events"
! grep -q 'ssh-filter' "$events"
! grep -q 'delete allow 443/tcp' "$events"
! grep -q 'delete allow 443/udp' "$events"
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_firewall_route_edit_applies_only_port_delta(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
MACHINE_MODE=whitelist
SUDO=()
routes=$(mktemp)
previous=$(mktemp)
events=$(mktemp)
trap 'rm -f "$routes" "$previous" "$events"' EXIT
printf '443\t89.144.8.3:443\ta.example.com\tdefault\n8443\t5.34.179.144:443\tb.example.com\tdefault\n' > "$routes"
printf '443\t89.144.8.3:443\ta.example.com\tdefault\n8444\t5.34.179.145:443\tc.example.com\tdefault\n' > "$previous"
command_exists() { [[ "$1" == ufw ]]; }
ufw_active() { return 0; }
ufw_rule_open_to_any() {
    [[ "$1" == '443/tcp' ]] || grep -Fq "ufw allow ${1} comment kto-haproxy" "$events"
}
repair_haproxy_firewall_rules() {
    cmd ufw allow 8443/tcp comment kto-haproxy
}
apply_whitelist_ssh_rules() { printf 'ssh-filter\n' >> "$events"; }
cmd() { local IFS=' '; printf '%s\n' "$*" >> "$events"; }
sync_haproxy_firewall "$routes" "$previous"
grep -Fqx 'ufw allow 8443/tcp comment kto-haproxy' "$events"
grep -Fqx 'ufw --force delete allow 8444/tcp' "$events"
! grep -q 'ufw allow 443/tcp' "$events"
! grep -q 'ssh-filter' "$events"
[[ "$(wc -l < "$events")" == 2 ]]
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_ufw_helpers_distinguish_ipv4_global_rules_from_ipv6_and_restricted_rules(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
SUDO=()
command_exists() { [[ "$1" == ufw ]]; }
ufw() {
    [[ "${1:-}" == status ]] || return 1
    printf 'Status: active\n\nTo Action From\n'
    case "$UFW_CASE" in
        v6)
            printf '443/tcp (v6) ALLOW IN Anywhere (v6)\n'
            ;;
        out)
            printf '443/tcp ALLOW OUT Anywhere\n'
            ;;
        restricted)
            printf '443/tcp ALLOW IN 94.247.129.92\n'
            ;;
        global)
            printf '443/tcp ALLOW IN Anywhere\n'
            ;;
    esac
}
UFW_CASE=v6
! ufw_rule_allowed '443/tcp'
! ufw_rule_open_to_any '443/tcp'
! ufw_global_allow_exists_for_port 443
UFW_CASE=out
! ufw_rule_allowed '443/tcp'
! ufw_rule_open_to_any '443/tcp'
! ufw_global_allow_exists_for_port 443
UFW_CASE=restricted
ufw_rule_allowed '443/tcp'
ufw_rule_from_allowed '443/tcp' '94.247.129.92'
! ufw_rule_open_to_any '443/tcp'
! ufw_global_allow_exists_for_port 443
UFW_CASE=global
ufw_rule_allowed '443/tcp'
ufw_rule_open_to_any '443/tcp'
ufw_global_allow_exists_for_port 443
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_listener_ports_include_all_external_frontend_binds(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
SUDO=()
config=$(mktemp)
routes=$(mktemp)
trap 'rm -f "$config" "$routes"' EXIT
cat > "$config" <<'EOF'
global
    maxconn 1000
defaults
    mode tcp
frontend managed
    bind *:443 backlog 65535
    default_backend pool_a
frontend exact
    bind 217.19.122.54:8443
    default_backend pool_a
frontend multiple
    bind 37.18.15.228:9443,[::]:9443
    default_backend pool_a
frontend local_admin
    bind 127.0.0.1:8404
listen stats
    bind *:9000
backend pool_a
    server xray 1.1.1.1:443
EOF
printf '10443\t2.2.2.2:443\tany\tdefault\n' > "$routes"
expected=$'443\n8443\n9443\n10443'
[[ "$(haproxy_listener_ports "$routes" "$config")" == "$expected" ]]
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_firewall_repair_restores_every_missing_ipv4_listener(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
SUDO=()
HAPROXY_CONFIG_FILE=$(mktemp)
state=$(mktemp)
events=$(mktemp)
trap 'rm -f "$HAPROXY_CONFIG_FILE" "$state" "$events"' EXIT
cat > "$HAPROXY_CONFIG_FILE" <<'EOF'
frontend first
    bind 81.94.148.126:443
frontend second
    bind 81.94.148.126:8443
frontend third
    bind 81.94.148.126:9443
EOF
cat > "$state" <<'EOF'
Status: active
443/tcp (v6) ALLOW IN Anywhere (v6)
8443/tcp ALLOW IN 94.247.129.92
9443/tcp ALLOW IN Anywhere
EOF
command_exists() { [[ "$1" == ufw ]]; }
ufw() {
    [[ "${1:-}" == status ]] || return 1
    cat "$state"
}
cmd() {
    local IFS=' '
    printf '%s\n' "$*" >> "$events"
    if [[ "${1:-}" == ufw && "${2:-}" == allow ]]; then
        printf '%s ALLOW IN Anywhere\n' "$3" >> "$state"
    fi
}
repair_haproxy_firewall_rules
grep -Fqx 'ufw allow 443/tcp comment kto-haproxy' "$events"
grep -Fqx 'ufw allow 8443/tcp comment kto-haproxy' "$events"
! grep -q 'ufw allow 9443/tcp' "$events"
[[ "$(wc -l < "$events")" == 2 ]]
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_optimize_rechecks_haproxy_firewall_after_antiscanner(self):
        optimize = function_body(KTO, "optimize_system")

        self.assertLess(
            optimize.index('progress_step "Подключаю AntiScanner" opt_antiscanner'),
            optimize.index('progress_step "Проверяю HAProxy firewall" opt_haproxy_firewall_final_check'),
        )
        self.assertIn('KTO_HAPROXY_FIREWALL_BUILD="v330"', KTO)
        self.assertIn('After=network-online.target ufw.service haproxy.service antiscanner-update.service', KTO)
        self.assertIn('failed to restore HAProxy UFW rules', KTO)

    def test_haproxy_firewall_guard_runs_as_a_standalone_repair(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
SUDO=()
LOG_FILE="$root/kto.log"
HAPROXY_CONFIG_FILE="$root/haproxy.cfg"
HAPROXY_FIREWALL_MANAGER="$root/kto-haproxy-firewall"
HAPROXY_FIREWALL_UNIT="$root/kto-haproxy-firewall.service"
HAPROXY_FIREWALL_SERVICE=kto-haproxy-firewall.service
cat > "$HAPROXY_CONFIG_FILE" <<'EOF'
frontend one
    bind 81.94.148.126:443
frontend two
    bind 81.94.148.126:8443
EOF
write_root_file() {
    local path="$1"
    cat > "$path"
}
systemctl() {
    [[ "${1:-}" == is-enabled ]] && return 1
    return 0
}
cmd() {
    if [[ "${1:-}" == chmod ]]; then
        command chmod "$2" "$3"
    fi
    return 0
}
ensure_haproxy_firewall_guard
bash -n "$HAPROXY_FIREWALL_MANAGER"
grep -Fq "ExecStart=$HAPROXY_FIREWALL_MANAGER" "$HAPROXY_FIREWALL_UNIT"
mkdir -p "$root/bin"
cat > "$root/bin/ufw" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
case "${1:-}" in
    status)
        cat "$FAKE_UFW_STATE"
        ;;
    allow)
        printf '%s ALLOW IN Anywhere\n' "$2" >> "$FAKE_UFW_STATE"
        ;;
    *)
        exit 1
        ;;
esac
EOF
chmod +x "$root/bin/ufw"
cat > "$root/ufw.state" <<'EOF'
Status: active
443/tcp (v6) ALLOW IN Anywhere (v6)
8443/tcp ALLOW IN Anywhere
EOF
PATH="$root/bin:$PATH" FAKE_UFW_STATE="$root/ufw.state" \
    KTO_HAPROXY_CONFIG="$HAPROXY_CONFIG_FILE" "$HAPROXY_FIREWALL_MANAGER"
grep -Fqx '443/tcp ALLOW IN Anywhere' "$root/ufw.state"
[[ "$(grep -Fc '8443/tcp ALLOW IN Anywhere' "$root/ufw.state")" == 1 ]]
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_firewall_repairs_missing_ipv4_rule_for_existing_route(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
MACHINE_MODE=whitelist
SUDO=()
routes=$(mktemp)
previous=$(mktemp)
events=$(mktemp)
trap 'rm -f "$routes" "$previous" "$events"' EXIT
printf '443\t89.144.8.3:443\ta.example.com\t37.18.15.213\n' > "$routes"
cp "$routes" "$previous"
command_exists() { [[ "$1" == ufw ]]; }
ufw_active() { return 0; }
ufw_rule_open_to_any() {
    grep -Fq "ufw allow ${1} comment kto-haproxy" "$events"
}
repair_haproxy_firewall_rules() {
    cmd ufw allow 443/tcp comment kto-haproxy
}
apply_whitelist_ssh_rules() { printf 'ssh-filter\n' >> "$events"; }
cmd() { local IFS=' '; printf '%s\n' "$*" >> "$events"; }
sync_haproxy_firewall "$routes" "$previous"
grep -Fqx 'ufw allow 443/tcp comment kto-haproxy' "$events"
! grep -q 'ssh-filter' "$events"
[[ "$(wc -l < "$events")" == 1 ]]
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_multiport_config_round_trip(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
SUDO=()
KTO_HAPROXY_MAXCONN=100000
KTO_HAPROXY_NBTHREAD=4
routes=$(mktemp)
config=$(mktemp)
trap 'rm -f "$routes" "$config"' EXIT
printf '443\t89.144.8.3:443\tbase.example.com *.rog-self.co.uk\tdefault\n8443\t5.34.179.144:443\textra.example.com *.other.example.com\t185.141.227.93\n' > "$routes"
render_haproxy_routes_config "$routes" "$config"
grep -q '^    maxconn 100000$' "$config"
grep -q '^    nbthread 4$' "$config"
grep -q '^    spread-checks 5$' "$config"
! grep -q '^    maxpipes ' "$config"
! grep -q '^    nosplice$' "$config"
! grep -q '^    hard-stop-after ' "$config"
grep -q '^    option splice-auto$' "$config"
grep -q '^    option splice-request$' "$config"
grep -q '^    option splice-response$' "$config"
grep -q '^    option redispatch$' "$config"
grep -q '^    retries 2$' "$config"
grep -q '^    timeout connect 4s$' "$config"
grep -q '^    timeout queue 4s$' "$config"
grep -q '^    timeout client 1m$' "$config"
grep -q '^    timeout server 1m$' "$config"
grep -q '^    timeout tunnel 15m$' "$config"
grep -q '^    timeout client-fin 30s$' "$config"
grep -q '^    timeout server-fin 30s$' "$config"
grep -q '^    timeout check 3s$' "$config"
grep -q '^    default-server inter 10s fastinter 2s downinter 10s fall 3 rise 2$' "$config"
! grep -q '^    tune.maxaccept ' "$config"
! grep -q '^    tune.bufsize ' "$config"
grep -q '^frontend vless_in$' "$config"
grep -q '^frontend vless_in_8443$' "$config"
[[ "$(grep -c '^    tcp-request connection track-sc0 src$' "$config")" == 2 ]]
[[ "$(grep -c '^    stick-table type ip size 100k expire 5m store gpc0,conn_rate(10s)$' "$config")" == 2 ]]
[[ "$(grep -c '^    tcp-request connection silent-drop if { src_get_gpc0 gt 500 }$' "$config")" == 2 ]]
[[ "$(grep -c '^    tcp-request connection silent-drop if { src_conn_rate gt 5000 }$' "$config")" == 2 ]]
grep -q '^    server xray1 89.144.8.3:443 check weight 10 maxconn 100000$' "$config"
grep -q '^    server xray_8443 5.34.179.144:443 check weight 10 source 185.141.227.93 maxconn 100000$' "$config"
grep -q '^    acl allowed_sni req.ssl_sni -i base.example.com$' "$config"
grep -q '^    acl allowed_sni req.ssl_sni -m end -i \.rog-self.co.uk$' "$config"
actual=$(extract_haproxy_routes "$config")
expected=$'443\t89.144.8.3:443\tbase.example.com *.rog-self.co.uk\tdefault\tauto\n8443\t5.34.179.144:443\textra.example.com *.other.example.com\t185.141.227.93\tauto\t185.141.227.93'
[[ "$actual" == "$expected" ]]
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_send_proxy_v2_is_per_route_and_defaults_off(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
set -u
SUDO=()
KTO_HAPROXY_MAXCONN=100000
routes=$(mktemp)
config=$(mktemp)
parsed=$(mktemp)
trap 'rm -f "$routes" "$config" "$parsed"' EXIT
printf '443\t89.144.8.3:443\tbase.example.com\tdefault\n8443\t5.34.179.144:443,5.34.179.145:443\textra.example.com\t185.141.227.93\t10000\t78.159.250.112\t1\n' > "$routes"
render_haproxy_routes_config "$routes" "$config"
grep -q '^    server xray1 89.144.8.3:443 check weight 10 maxconn 100000$' "$config"
grep -q '^    server xray1 5.34.179.144:443 check weight 10 source 78.159.250.112 send-proxy-v2 maxconn 10000$' "$config"
grep -q '^    server xray2 5.34.179.145:443 check weight 10 source 78.159.250.112 send-proxy-v2 maxconn 10000$' "$config"
extract_haproxy_routes "$config" > "$parsed"
haproxy_routes_round_trip_equal "$routes" "$parsed"
[[ "$(tail -n 1 "$parsed")" == $'8443\t5.34.179.144:443,5.34.179.145:443\textra.example.com\t78.159.250.112\t10000\t78.159.250.112\t1' ]]
[[ "$(print_haproxy_route 9443 1.2.3.4:443 any default default '*' 1)" == $'9443\t1.2.3.4:443\tany\tdefault\tauto\t*\t1' ]]
[[ "$(ask_haproxy_send_proxy_v2 0 <<< '')" == 0 ]]
[[ "$(ask_haproxy_send_proxy_v2 0 <<< 'y')" == 1 ]]
[[ "$(ask_haproxy_send_proxy_v2 1 <<< '')" == 1 ]]
! normalize_haproxy_send_proxy_v2 maybe
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_blank_sni_means_any_and_round_trips(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
set -u
SUDO=()
routes=$(mktemp)
config=$(mktemp)
trap 'rm -f "$routes" "$config"' EXIT
printf '443\t89.144.8.3:443\tany\tdefault\n8443\t5.34.179.144:443\tstrict.example.com\tdefault\n' > "$routes"
render_haproxy_routes_config "$routes" "$config"
any_block=$(awk '$1 == "frontend" { active = ($2 == "vless_in") } active { print } active && $1 == "default_backend" { exit }' "$config")
strict_block=$(awk '$1 == "frontend" { active = ($2 == "vless_in_8443") } active { print } active && $1 == "default_backend" { exit }' "$config")
grep -Fq '# kto-sni-mode any' <<< "$any_block"
grep -Fq 'tcp-request content accept if clienthello' <<< "$any_block"
! grep -Fq 'allowed_sni' <<< "$any_block"
grep -Fq 'tcp-request connection track-sc0 src' <<< "$any_block"
! grep -Fq 'tcp-request content track-sc1' <<< "$any_block"
grep -Fq '# kto-sni-mode allow-list' <<< "$strict_block"
grep -Fq 'acl allowed_sni req.ssl_sni -i strict.example.com' <<< "$strict_block"
actual=$(extract_haproxy_routes "$config")
expected=$'443\t89.144.8.3:443\tany\tdefault\tauto\n8443\t5.34.179.144:443\tstrict.example.com\tdefault\tauto'
[[ "$actual" == "$expected" ]]
[[ "$(normalize_haproxy_sni_list '')" == any ]]
[[ "$(normalize_haproxy_sni_list '*')" == any ]]
! normalize_haproxy_sni_list 'any strict.example.com'
[[ "$(print_haproxy_route 9443 1.2.3.4:443 '' default)" == $'9443\t1.2.3.4:443\tany\tdefault\tauto' ]]
[[ "$(ask_haproxy_sni_list SNI <<< '')" == any ]]
[[ "$(ask_haproxy_sni_list SNI old.example.com <<< '')" == any ]]
[[ "$(ask_haproxy_sni_list SNI old.example.com <<< '=')" == old.example.com ]]
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        remote_apply = function_body(KTO, "haproxy_remote_apply_json")
        self.assertIn('if length == 0 then "any" else join(" ") end', remote_apply)
        self.assertIn('(.sni | length <= 64)', remote_apply)
        self.assertIn('apply_haproxy_routes_config "$routes_file" 1', remote_apply)
        self.assertIn(
            'reconcile_haproxy_bandwidth_after_route_change "$routes_file" "$previous_routes_file"',
            remote_apply,
        )
        self.assertIn('HAPROXY_SNI_ANY = "any"', COLLECTOR)
        self.assertIn('def parse_haproxy_sni_input(value):\n    return normalize_haproxy_sni_list(value)', COLLECTOR)
        self.assertIn('ответь <code>any</code> или <code>*</code>', COLLECTOR)

    def test_haproxy_same_port_on_distinct_input_ips_round_trip(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
SUDO=()
KTO_HAPROXY_MAXCONN=42000
routes=$(mktemp)
config=$(mktemp)
conflict=$(mktemp)
trap 'rm -f "$routes" "$config" "$conflict"' EXIT
printf '443\t89.144.8.3:443\ta.example.com\tdefault\tdefault\t78.159.250.112\n443\t5.34.179.144:443\tb.example.com\t217.19.122.48\tdefault\t217.19.122.48\n' > "$routes"
render_haproxy_routes_config "$routes" "$config"
grep -q '^frontend vless_in$' "$config"
grep -q '^    bind 78.159.250.112:443 backlog 65535$' "$config"
grep -q '^frontend vless_in_443_217_19_122_48$' "$config"
grep -q '^    bind 217.19.122.48:443 backlog 65535$' "$config"
grep -q '^    server xray1 5.34.179.144:443 check weight 10 source 217.19.122.48 maxconn 42000$' "$config"
actual=$(extract_haproxy_routes "$config")
expected=$'443\t89.144.8.3:443\ta.example.com\t78.159.250.112\tauto\t78.159.250.112\n443\t5.34.179.144:443\tb.example.com\t217.19.122.48\tauto\t217.19.122.48'
[[ "$actual" == "$expected" ]]
haproxy_route_file_has_endpoint "$routes" 443 78.159.250.112
haproxy_route_file_has_endpoint "$routes" 443 217.19.122.48
! haproxy_route_file_conflicts_endpoint "$routes" 443 185.141.227.93

printf '443\t89.144.8.3:443\ta.example.com\tdefault\n443\t5.34.179.144:443\tb.example.com\tdefault\tdefault\t217.19.122.48\n' > "$conflict"
! render_haproxy_routes_config "$conflict" "$config"
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_same_port_edit_and_delete_are_endpoint_scoped(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
routes=$(mktemp)
trap 'rm -f "$routes"' EXIT
printf '443\t89.144.8.3:443\ta.example.com\tdefault\tdefault\t78.159.250.112\n443\t5.34.179.144:443\tb.example.com\t217.19.122.48\tdefault\t217.19.122.48\n' > "$routes"
select_haproxy_route() { printf '443\t217.19.122.48\n'; }
select_haproxy_route_for_delete() { printf '443\t217.19.122.48\n'; }
select_haproxy_route_source_ip() { printf '217.19.122.48\n'; }
haproxy_route_ip_for_source() { printf '%s\n' "$1"; }
ask_haproxy_target_pool_default() { printf '5.34.179.145:443\n'; }
ask_haproxy_sni_list() { printf 'changed.example.com\n'; }
ask_haproxy_send_proxy_v2() { printf '0\n'; }
apply_haproxy_routes_config() { return 0; }
sync_haproxy_firewall() { return 0; }
haproxy_bandwidth_current_rate() { return 0; }
edit_haproxy_route "$routes"
grep -Fqx $'443\t89.144.8.3:443\ta.example.com\t78.159.250.112\tauto\t78.159.250.112' "$routes"
grep -Fqx $'443\t5.34.179.145:443\tchanged.example.com\t217.19.122.48\tauto\t217.19.122.48' "$routes"
delete_haproxy_route "$routes" <<< 'y'
[[ "$(wc -l < "$routes")" == 1 ]]
grep -Fqx $'443\t89.144.8.3:443\ta.example.com\t78.159.250.112\tauto\t78.159.250.112' "$routes"
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_route_delete_selects_input_ip_then_port(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
SUDO=()
routes=$(mktemp)
applied=$(mktemp)
events=$(mktemp)
output=$(mktemp)
export HAPROXY_BANDWIDTH_CONFIG="$routes.limits"
trap 'rm -f "$routes" "$routes.limits" "$applied" "$events" "$output"' EXIT
printf '443\t89.144.8.3:443\ta.example.com\tdefault\tdefault\t78.159.250.112\n443\t5.34.179.143:443\tb.example.com\t217.19.122.48\tdefault\t217.19.122.48\n8443\t5.34.179.144:443\tc.example.com\t217.19.122.48\tdefault\t217.19.122.48\n8444\t5.34.179.145:443\td.example.com\t217.19.122.48\tdefault\t217.19.122.48\n' > "$routes"
printf '217.19.122.48\t2000\n' > "$HAPROXY_BANDWIDTH_CONFIG"
apply_haproxy_routes_config() { cp "$1" "$applied"; printf 'route-apply:%s\n' "${2:-0}" >> "$events"; }
sync_haproxy_firewall() { printf 'sync\n' >> "$events"; }
haproxy_bandwidth_current_rate() { return 0; }
remove_haproxy_input_bandwidth_limit() { printf 'limit-removed:%s\n' "$1" >> "$events"; }
reapply_haproxy_bandwidth_limits() { printf 'tc-reapply\n' >> "$events"; }
require_local_haproxy_bandwidth_manager() { return 0; }
delete_haproxy_route "$routes" <<< $'2\n2\ny' > "$output" 2>&1
grep -q 'Выберите входной IP маршрута:' "$output"
grep -q '217.19.122.48 | портов: 443, 8443, 8444' "$output"
grep -q 'Выберите порт для 217.19.122.48:' "$output"
grep -q 'Будет удалён маршрут 217.19.122.48:8443/tcp' "$output"
grep -Fqx $'443\t89.144.8.3:443\ta.example.com\tdefault\tdefault\t78.159.250.112' "$routes"
grep -Fqx $'443\t5.34.179.143:443\tb.example.com\t217.19.122.48\tdefault\t217.19.122.48' "$routes"
grep -Fqx $'8444\t5.34.179.145:443\td.example.com\t217.19.122.48\tdefault\t217.19.122.48' "$routes"
! grep -q $'^8443\t' "$routes"
cmp -s "$routes" "$applied"
grep -Fqx 'sync' "$events"
grep -Fqx 'route-apply:1' "$events"
[[ "$(grep -c '^tc-reapply$' "$events")" == 1 ]]
! grep -q '^limit-removed:' "$events"
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_route_delete_protects_last_route_and_cleans_unused_ip_limit(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
SUDO=()
routes=$(mktemp)
events=$(mktemp)
output=$(mktemp)
export HAPROXY_BANDWIDTH_CONFIG="$routes.limits"
trap 'rm -f "$routes" "$routes.limits" "$events" "$output"' EXIT
printf '443\t89.144.8.3:443\ta.example.com\tdefault\tdefault\t78.159.250.112\n443\t5.34.179.144:443\tb.example.com\t217.19.122.48\tdefault\t217.19.122.48\n' > "$routes"
printf '217.19.122.48\t2000\n' > "$HAPROXY_BANDWIDTH_CONFIG"
apply_haproxy_routes_config() { printf 'route-apply:%s\n' "${2:-0}" >> "$events"; }
sync_haproxy_firewall() { printf 'sync\n' >> "$events"; }
haproxy_bandwidth_current_rate() {
    if [[ "$1" == '217.19.122.48' ]]; then
        printf '2000\n'
    fi
    return 0
}
remove_haproxy_input_bandwidth_limit() { printf 'limit-removed:%s:%s\n' "$1" "${2:-latest}" >> "$events"; }
require_local_haproxy_bandwidth_manager() { return 0; }
commit_haproxy_bandwidth_config() {
    cp "$2" "$HAPROXY_BANDWIDTH_CONFIG"
    printf 'limits-commit\n' >> "$events"
}
cp "$routes" "$routes.cancelled"
delete_haproxy_route "$routes" <<< $'2\nn' > "$output" 2>&1
cmp -s "$routes" "$routes.cancelled"
[[ ! -s "$events" ]]
rm -f "$routes.cancelled"
delete_haproxy_route "$routes" <<< $'2\ny' > "$output" 2>&1
[[ "$(wc -l < "$routes")" == 1 ]]
grep -Fqx 'route-apply:1' "$events"
grep -Fqx 'limits-commit' "$events"
! grep -q '^217\.19\.122\.48' "$HAPROXY_BANDWIDTH_CONFIG"
[[ "$(grep -c '^limits-commit$' "$events")" == 1 ]]
cp "$routes" "$routes.before"
if delete_haproxy_route "$routes" > "$output" 2>&1; then
    exit 1
fi
cmp -s "$routes" "$routes.before"
grep -q 'Нельзя удалить последний HAProxy-маршрут' "$output"
rm -f "$routes.before"
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_route_delete_shared_port_skips_tc_rebuild(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
SUDO=()
routes=$(mktemp)
events=$(mktemp)
output=$(mktemp)
export HAPROXY_BANDWIDTH_CONFIG="$routes.limits"
trap 'rm -f "$routes" "$routes.limits" "$events" "$output"' EXIT
printf '443\t89.144.8.3:443\ta.example.com\tdefault\tdefault\t78.159.250.112\n443\t5.34.179.143:443\tb.example.com\tdefault\tdefault\t217.19.122.48\n8444\t5.34.179.145:443\td.example.com\tdefault\tdefault\t217.19.122.48\n' > "$routes"
printf '217.19.122.48\t2000\n' > "$HAPROXY_BANDWIDTH_CONFIG"
select_haproxy_route_for_delete() { printf '443\t78.159.250.112\n'; }
apply_haproxy_routes_config() { printf 'route-apply:%s\n' "${2:-0}" >> "$events"; }
sync_haproxy_firewall() { printf 'sync\n' >> "$events"; }
reapply_haproxy_bandwidth_limits() { printf 'tc-reapply\n' >> "$events"; }
require_local_haproxy_bandwidth_manager() { printf 'manager-check\n' >> "$events"; }
delete_haproxy_route "$routes" <<< 'y' > "$output" 2>&1
[[ "$(wc -l < "$routes")" == 2 ]]
grep -Fqx 'route-apply:1' "$events"
grep -Fqx 'sync' "$events"
! grep -q '^tc-reapply$' "$events"
! grep -q '^manager-check$' "$events"
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_pool_cli_supports_exact_listener_and_wildcard_migration(self):
        cli = function_body(KTO, "set_haproxy_pool_route_cli")
        migration = function_body(KTO, "retarget_haproxy_wildcard_route")

        self.assertIn("[--listen-ip IP]", cli)
        self.assertIn('--listen-ip)', cli)
        self.assertIn('--listen-ip=*)', cli)
        self.assertIn(
            'retarget_haproxy_wildcard_route "$routes_file" "$port" "$listen_ip"',
            cli,
        )
        self.assertIn('if [[ "$listen_ip" != "*" ]] &&', cli)
        self.assertNotIn('listen_ip_explicit == 1 )) && [[ "$listen_ip" != "*" ]]', cli)
        self.assertIn('"$server_maxconn" "$target_pool" "$listen_ip"', cli)
        self.assertIn('current_listen="$listen_ip"', migration)

        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
KTO_HAPROXY_MAXCONN=50000
routes=$(mktemp)
config=$(mktemp)
trap 'rm -f "$routes" "$config"' EXIT
pool='31.59.140.66:7443,31.77.154.79:7443'
printf '443\t144.31.128.40:443\t*.rog-self.co.uk\tdefault\n9449\t%s\tdex-yandex.sbs *.dex-yandex.sbs\t78.159.240.211\t10000\n' "$pool" > "$routes"
before_443=$(grep $'^443\t' "$routes")
retarget_haproxy_wildcard_route "$routes" 9449 78.159.240.211
grep -Fqx $'443\t144.31.128.40:443\t*.rog-self.co.uk\tdefault\tauto' "$routes"
grep -Fqx $'9449\t31.59.140.66:7443,31.77.154.79:7443\tdex-yandex.sbs *.dex-yandex.sbs\t78.159.240.211\t10000\t78.159.240.211' "$routes"
! haproxy_route_file_has_endpoint "$routes" 9449 '*'
haproxy_route_file_has_endpoint "$routes" 9449 78.159.240.211
render_haproxy_routes_config "$routes" "$config"
grep -Fqx '    bind 78.159.240.211:9449 backlog 65535' "$config"
grep -Fqx '    server xray1 31.59.140.66:7443 check weight 10 source 78.159.240.211 maxconn 10000' "$config"
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_listener_checks_are_input_ip_scoped(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
SUDO=()
command_exists() { [[ "$1" == ss ]]; }
ss() {
    printf '%s\n' \
        'LISTEN 0 4096 78.159.250.112:443 0.0.0.0:* users:(("haproxy",pid=10,fd=4))' \
        'LISTEN 0 4096 217.19.122.48:443 0.0.0.0:* users:(("xray",pid=11,fd=4))' \
        'LISTEN 0 4096 0.0.0.0:8443 0.0.0.0:* users:(("haproxy",pid=10,fd=5))'
}
haproxy_tcp_port_owned_by_haproxy 443 78.159.250.112
! haproxy_tcp_port_owned_by_haproxy 443 217.19.122.48
! haproxy_tcp_port_owned_by_haproxy 443 '*'
haproxy_tcp_port_owned_by_haproxy 8443 '*'
grep -q haproxy < <(haproxy_tcp_port_socket_details 443 78.159.250.112)
grep -q xray < <(haproxy_tcp_port_socket_details 443 217.19.122.48)
! haproxy_tcp_port_socket_details 443 185.141.227.93
haproxy_tcp_port_socket_details 8443 185.141.227.93 >/dev/null
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_persistent_backup_has_verified_checksum(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
SUDO=()
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
HAPROXY_CONFIG_FILE="$root/haproxy.cfg"
HAPROXY_BACKUP_DIR="$root/backups"
LOG_FILE="$root/kto.log"
printf 'global\n    maxconn 1000\n' > "$HAPROXY_CONFIG_FILE"
create_haproxy_persistent_backup test "$HAPROXY_CONFIG_FILE"
[[ -s "$HAPROXY_LAST_BACKUP" ]]
[[ -s "${HAPROXY_LAST_BACKUP}.sha256" ]]
verify_haproxy_backup "$HAPROXY_LAST_BACKUP"
[[ "$(list_haproxy_backups)" == "$HAPROXY_LAST_BACKUP" ]]
printf '# tampered\n' >> "$HAPROXY_LAST_BACKUP"
! verify_haproxy_backup "$HAPROXY_LAST_BACKUP"
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_prepare_expands_wildcard_only_after_confirmation(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
SUDO=()
root=$(mktemp -d)
routes="$root/routes"
snapshot="$root/snapshot"
config="$root/haproxy.cfg"
applied="$root/applied"
conflict="$root/conflict"
conflict_out="$root/conflict.out"
trap 'rm -rf "$root"' EXIT
LOG_FILE="$root/kto.log"
HAPROXY_CONFIG_FILE="$config"
printf '443\t89.144.8.3:443\tbase.example.com\t217.19.122.48\t10000\n' > "$routes"
cp "$routes" "$snapshot"
render_haproxy_routes_config "$routes" "$config"
list_haproxy_preparable_input_ips() {
    printf '78.159.250.112\tens3\n217.19.122.48\twan2\n'
}
ensure_haproxy_package() { return 0; }
haproxy() { return 0; }
apply_haproxy_routes_config() { cp "$1" "$applied"; return 0; }
sync_haproxy_firewall() { return 0; }
prepare_haproxy_multi_ip_config "$routes" <<< 'n'
cmp -s "$routes" "$snapshot"
[[ ! -e "$applied" ]]
prepare_haproxy_multi_ip_config "$routes" <<< 'y'
[[ "$(wc -l < "$routes")" == 2 ]]
grep -Fqx $'443\t89.144.8.3:443\tbase.example.com\t78.159.250.112\t10000\t78.159.250.112' "$routes"
grep -Fqx $'443\t89.144.8.3:443\tbase.example.com\t217.19.122.48\t10000\t217.19.122.48' "$routes"
cmp -s "$routes" "$applied"
[[ "$HAPROXY_PREPARE_WILDCARDS" == 1 ]]
[[ "$HAPROXY_PREPARE_ROUTES_BEFORE" == 1 ]]
[[ "$HAPROXY_PREPARE_ROUTES_AFTER" == 2 ]]
printf '443\t89.144.8.3:443\tbase.example.com\tdefault\n443\t5.34.179.144:443\tother.example.com\tdefault\tdefault\t217.19.122.48\n' > "$conflict"
! build_haproxy_multi_ip_routes "$conflict" "$conflict_out"
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_full_binds_pin_to_each_route_source_ip_transactionally(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
SUDO=()
root=$(mktemp -d)
routes="$root/routes"
snapshot="$root/snapshot"
candidate="$root/candidate"
applied="$root/applied"
config="$root/haproxy.cfg"
collision="$root/collision"
collision_out="$root/collision.out"
semantic_a="$root/semantic-a"
semantic_b="$root/semantic-b"
semantic_bad="$root/semantic-bad"
trap 'rm -rf "$root"' EXIT
LOG_FILE="$root/kto.log"
HAPROXY_CONFIG_FILE="$config"
printf '8443\t5.34.179.144:443\t*.bridge.example.com bridge.example.com\t217.19.122.48\t10000\n443\t144.31.128.40:443\tbase.example.com\tdefault\n8444\t5.34.179.145:443\texact.example.com\t185.141.227.93\tdefault\t185.141.227.93\n' > "$routes"
cp "$routes" "$snapshot"
haproxy_default_source_ip() { printf '78.159.250.112\n'; }
list_haproxy_input_ips() {
    printf '78.159.250.112\tens3\n217.19.122.48\twan2\n185.141.227.93\twan3\n'
}
ensure_haproxy_package() { return 0; }
haproxy() { return 0; }
apply_haproxy_routes_config() { cp "$1" "$applied"; return 0; }
sync_haproxy_firewall() { return 0; }
check_haproxy_bindings() { return 0; }

build_haproxy_source_pinned_routes "$routes" "$candidate"
grep -Fqx $'443\t144.31.128.40:443\tbase.example.com\t78.159.250.112\tauto\t78.159.250.112' "$candidate"
grep -Fqx $'8443\t5.34.179.144:443\t*.bridge.example.com bridge.example.com\t217.19.122.48\t10000\t217.19.122.48' "$candidate"
grep -Fqx $'8444\t5.34.179.145:443\texact.example.com\t185.141.227.93\tauto\t185.141.227.93' "$candidate"
[[ "$HAPROXY_PIN_WILDCARDS" == 2 ]]
grep -Fq '*:443 -> 78.159.250.112:443' <<< "$HAPROXY_PIN_PREVIEW"
grep -Fq '*:8443 -> 217.19.122.48:8443' <<< "$HAPROXY_PIN_PREVIEW"

pin_haproxy_wildcards_to_source_ips "$routes" <<< 'n'
cmp -s "$routes" "$snapshot"
[[ ! -e "$applied" ]]
pin_haproxy_wildcards_to_source_ips "$routes" <<< 'y'
cmp -s "$routes" "$applied"
grep -Fqx $'443\t144.31.128.40:443\tbase.example.com\t78.159.250.112\tauto\t78.159.250.112' "$routes"
grep -Fqx $'8443\t5.34.179.144:443\t*.bridge.example.com bridge.example.com\t217.19.122.48\t10000\t217.19.122.48' "$routes"

printf '443\t144.31.128.40:443\tbase.example.com\tdefault\n443\t5.34.179.144:443\texact.example.com\tdefault\tdefault\t78.159.250.112\n' > "$collision"
! build_haproxy_source_pinned_routes "$collision" "$collision_out"

printf '9449\t31.59.140.66:7443,31.77.154.79:7443\t*.dev-yandex.sbs dev-yandex.sbs\t37.18.15.124\t10000\t37.18.15.124\n443\t144.31.128.40:443\tbase.example.com\tdefault\tdefault\t78.159.250.112\n' > "$semantic_a"
printf '443\t144.31.128.40:443\tbase.example.com\tdefault\tdefault\t78.159.250.112\n9449\t31.59.140.66:7443,31.77.154.79:7443\tdev-yandex.sbs *.dev-yandex.sbs\t37.18.15.124\t10000\t37.18.15.124\n' > "$semantic_b"
printf '443\t144.31.128.41:443\tbase.example.com\tdefault\tdefault\t78.159.250.112\n9449\t31.59.140.66:7443,31.77.154.79:7443\tdev-yandex.sbs *.dev-yandex.sbs\t37.18.15.124\t10000\t37.18.15.124\n' > "$semantic_bad"
haproxy_routes_round_trip_equal "$semantic_a" "$semantic_b"
! haproxy_routes_round_trip_equal "$semantic_a" "$semantic_bad"
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_restore_failure_returns_exact_previous_config(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
SUDO=()
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
LOG_FILE="$root/kto.log"
HAPROXY_CONFIG_FILE="$root/haproxy.cfg"
HAPROXY_BACKUP_DIR="$root/backups"
current_routes="$root/current.routes"
old_routes="$root/old.routes"
menu_routes="$root/menu.routes"
current_snapshot="$root/current.snapshot"
backup="$HAPROXY_BACKUP_DIR/haproxy-20260807-120000-test-1.cfg"
mkdir -p "$HAPROXY_BACKUP_DIR"
printf '443\t89.144.8.3:443\tcurrent.example.com\tdefault\n' > "$current_routes"
printf '443\t5.34.179.144:443\told.example.com\tdefault\n' > "$old_routes"
render_haproxy_routes_config "$current_routes" "$HAPROXY_CONFIG_FILE"
render_haproxy_routes_config "$old_routes" "$backup"
hash=$(sha256sum "$backup" | awk '{print $1}')
printf '%s  %s\n' "$hash" "$(basename "$backup")" > "${backup}.sha256"
cp "$HAPROXY_CONFIG_FILE" "$current_snapshot"
cp "$current_routes" "$menu_routes"
ensure_haproxy_package() { return 0; }
haproxy() { return 0; }
reserve_haproxy_route_ports() { return 0; }
reload_haproxy_gracefully() { return 1; }
start_haproxy_cleanly() { return 0; }
sync_haproxy_firewall() { return 99; }
if restore_haproxy_backup "$menu_routes" <<< $'1\ny'; then
    exit 1
fi
cmp -s "$HAPROXY_CONFIG_FILE" "$current_snapshot"
cmp -s "$menu_routes" "$current_routes"
[[ -s "${HAPROXY_CONFIG_FILE}.kto.failed-restore" ]]
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_restore_success_installs_exact_backup(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
SUDO=()
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
LOG_FILE="$root/kto.log"
HAPROXY_CONFIG_FILE="$root/haproxy.cfg"
HAPROXY_BACKUP_DIR="$root/backups"
current_routes="$root/current.routes"
old_routes="$root/old.routes"
menu_routes="$root/menu.routes"
backup="$HAPROXY_BACKUP_DIR/haproxy-20260807-120000-test-1.cfg"
mkdir -p "$HAPROXY_BACKUP_DIR"
printf '443\t89.144.8.3:443\tcurrent.example.com\tdefault\n' > "$current_routes"
printf '443\t5.34.179.144:443\told.example.com\tdefault\n' > "$old_routes"
render_haproxy_routes_config "$current_routes" "$HAPROXY_CONFIG_FILE"
render_haproxy_routes_config "$old_routes" "$backup"
hash=$(sha256sum "$backup" | awk '{print $1}')
printf '%s  %s\n' "$hash" "$(basename "$backup")" > "${backup}.sha256"
cp "$current_routes" "$menu_routes"
ensure_haproxy_package() { return 0; }
haproxy() { return 0; }
reserve_haproxy_route_ports() { return 0; }
reload_haproxy_gracefully() { return 0; }
sync_haproxy_firewall() { printf 'sync\n' >> "$root/events"; }
restore_haproxy_backup "$menu_routes" <<< $'1\ny'
cmp -s "$HAPROXY_CONFIG_FILE" "$backup"
extract_haproxy_routes "$backup" > "$root/expected-restored.routes"
cmp -s "$menu_routes" "$root/expected-restored.routes"
grep -q '^sync$' "$root/events"
[[ -n "$HAPROXY_LAST_BACKUP" && -s "$HAPROXY_LAST_BACKUP" ]]
verify_haproxy_backup "$HAPROXY_LAST_BACKUP"
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_legacy_routes_default_source_and_additional_ips_are_routable(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
SUDO=()
KTO_HAPROXY_MAXCONN=100000
routes=$(mktemp)
config=$(mktemp)
trap 'rm -f "$routes" "$config"' EXIT
printf '443\t89.144.8.3:443\tbase.example.com\n' > "$routes"
render_haproxy_routes_config "$routes" "$config"
grep -q '^    server xray1 89.144.8.3:443 check weight 10 maxconn 100000$' "$config"
[[ "$(extract_haproxy_routes "$config")" == $'443\t89.144.8.3:443\tbase.example.com\tdefault\tauto' ]]

ip() {
    local args
    args="$(printf '%s ' "$@")"
    args="${args% }"
    case "$args" in
        '-4 route get 1.1.1.1')
            printf '1.1.1.1 via 78.159.250.1 dev ens3 src 78.159.250.112\n'
            ;;
        '-4 -o address show scope global')
            printf '%s\n' \
                '2: ens3 inet 78.159.250.112/24 scope global ens3' \
                '3: wan2 inet 185.141.227.93/26 scope global wan2' \
                '4: wan3 inet 217.19.122.48/24 scope global wan3' \
                '5: wan4 inet 217.19.122.49/24 scope global wan4' \
                '6: docker0 inet 172.17.0.1/16 scope global docker0'
            ;;
        '-4 route get 1.1.1.1 from 185.141.227.93')
            printf '1.1.1.1 from 185.141.227.93 via 185.141.227.65 dev wan2 table 102\n'
            ;;
        '-4 route get 1.1.1.1 from 217.19.122.48')
            printf '1.1.1.1 from 217.19.122.48 via 217.19.122.1 dev wan3 table 103\n'
            ;;
        '-4 route get 1.1.1.1 from 217.19.122.49')
            printf '1.1.1.1 from 217.19.122.49 via 217.19.122.1 dev wan4 table 104\n'
            ;;
        '-4 route get 1.1.1.1 from 172.17.0.1')
            printf '1.1.1.1 from 172.17.0.1 via 78.159.250.1 dev ens3\n'
            ;;
    esac
}
actual=$(list_haproxy_additional_source_ips)
expected=$'185.141.227.93\twan2\n217.19.122.48\twan3\n217.19.122.49\twan4'
[[ "$actual" == "$expected" ]]
printf '443\t89.144.8.3:443\tbase.example.com\tdefault\n8443\t5.34.179.144:443\textra.example.com\t185.141.227.93\n8444\t5.34.179.145:443\textra2.example.com\t217.19.122.48\n' > "$routes"
list_haproxy_additional_source_ips() { printf '185.141.227.93\twan2\n217.19.122.48\twan3\n217.19.122.49\twan4\n'; }
[[ "$(printf '1\n' | select_haproxy_additional_source_ip "$routes")" == '185.141.227.93' ]]
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_backend_pool_round_trip_preserves_all_servers(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
SUDO=()
KTO_HAPROXY_MAXCONN=42000
routes=$(mktemp)
config=$(mktemp)
config2=$(mktemp)
routes2=$(mktemp)
trap 'rm -f "$routes" "$config" "$config2" "$routes2"' EXIT
pool='31.59.140.66:7443,31.77.154.79:7443,31.76.113.188:7443,31.76.113.189:7443,31.76.113.190:7443,144.31.94.40:7443,144.31.94.156:7443,144.31.94.135:7443,144.31.94.233:7443,144.31.94.107:7443,144.31.94.36:7443,144.31.94.153:7443,144.31.2.44:7443,144.31.130.226:7443,144.31.131.232:7443,144.31.129.206:7443,144.31.129.69:7443,144.31.131.228:7443,144.31.131.93:7443,13.143.134.143:7443,117.55.203.106:7443'
printf '443\t89.144.8.3:443\tbase.example.com\tdefault\n8450\t%s\tdev-yandex.sbs\t217.19.122.109\t10000\n' "$pool" > "$routes"
render_haproxy_routes_config "$routes" "$config"
[[ "$(awk '$1 == "backend" { active = ($2 == "vless_pool_8450"); next } active && $1 == "server" { count++ } END { print count + 0 }' "$config")" == 21 ]]
grep -q '^    server xray1 31.59.140.66:7443 check weight 10 source 217.19.122.109 maxconn 2000$' "$config"
grep -q '^    server xray21 117.55.203.106:7443 check weight 10 source 217.19.122.109 maxconn 2000$' "$config"
extract_haproxy_routes "$config" > "$routes2"
expected=$'443\t89.144.8.3:443\tbase.example.com\tdefault\tauto\n8450\t'"$pool"$'\tdev-yandex.sbs\t217.19.122.109\t10000\t217.19.122.109'
[[ "$(cat "$routes2")" == "$expected" ]]
render_haproxy_routes_config "$routes2" "$config2"
cmp -s "$config" "$config2"
cat > "$config2" <<'EOF'
frontend vless_in_8450
    bind *:8450
    acl allowed_sni req.ssl_sni -i dev-yandex.sbs
    default_backend vless_pool_8450
backend vless_pool_8450
    server xray1 31.59.140.66:7443 check weight 10 maxconn 10000 source 217.19.122.109
    server xray2 31.77.154.79:7443 check weight 10 maxconn 10000 source 217.19.122.110
EOF
[[ -z "$(extract_haproxy_routes "$config2")" ]]
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_bulk_routes_reuse_source_ip_and_are_idempotent(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
routes=$(mktemp)
snapshot=$(mktemp)
trap 'rm -f "$routes" "$snapshot"' EXIT
printf '443\t89.144.8.3:443\tbase.example.com\t78.159.245.250\t25000\t78.159.245.250\n8450\t1.1.1.1:7443\told.example.com\t217.19.122.109\t25000\t217.19.122.109\n' > "$routes"
haproxy_default_source_ip() { printf '78.159.245.250\n'; }
haproxy_input_ip_available() { [[ "$1" == '78.159.245.250' || "$1" == '217.19.122.109' ]]; }
ip() { return 0; }
haproxy_tcp_port_listening() { return 1; }
apply_haproxy_routes_config() { return 0; }
sync_haproxy_firewall() { return 0; }
haproxy_source_label() { printf '%s\n' "$1"; }
pool='31.59.140.66:7443,31.77.154.79:7443,31.76.113.188:7443,31.76.113.189:7443,31.76.113.190:7443,144.31.94.40:7443,144.31.94.156:7443,144.31.94.135:7443,144.31.94.233:7443,144.31.94.107:7443,144.31.94.36:7443,144.31.94.153:7443,144.31.2.44:7443,144.31.130.226:7443,144.31.131.232:7443,144.31.129.206:7443,144.31.129.69:7443,144.31.131.228:7443,144.31.131.93:7443,13.143.134.143:7443,117.55.203.106:7443'
set_haproxy_sequential_routes "$routes" 8450 217.19.122.109 dev-yandex.sbs 10000 "$pool"
[[ "$(awk -F '\t' '$1 >= 8450 && $1 <= 8470 { count++ } END { print count + 0 }' "$routes")" == 21 ]]
grep -qx $'8450\t31.59.140.66:7443\tdev-yandex.sbs\t217.19.122.109\t10000\t217.19.122.109' "$routes"
grep -qx $'8470\t117.55.203.106:7443\tdev-yandex.sbs\t217.19.122.109\t10000\t217.19.122.109' "$routes"
cp "$routes" "$snapshot"
set_haproxy_sequential_routes "$routes" 8450 217.19.122.109 dev-yandex.sbs 10000 "$pool"
cmp -s "$routes" "$snapshot"
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_pool_accepts_explicit_primary_source_ip(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
routes=$(mktemp)
trap 'rm -f "$routes"' EXIT
printf '443\t1.1.1.1:443\tany\tdefault\tdefault\t81.94.148.126\n' > "$routes"
haproxy_default_source_ip() { printf '81.94.148.126\n'; }
haproxy_additional_source_ip_available() { return 1; }
haproxy_input_ip_available() { [[ "$1" == '81.94.148.126' ]]; }
ip() { return 0; }
haproxy_tcp_port_listening() { return 1; }
apply_haproxy_routes_config() { return 0; }
sync_haproxy_firewall() { return 0; }
pool='31.59.140.66:7443,31.77.154.79:7443'
set_haproxy_pool_route "$routes" 8450 81.94.148.126 '*.dev-yandex.sbs' 10000 "$pool" 81.94.148.126
grep -Fqx $'8450\t31.59.140.66:7443,31.77.154.79:7443\t*.dev-yandex.sbs\t81.94.148.126\t10000\t81.94.148.126' "$routes"
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_port_range_collapses_to_one_balanced_pool(self):
        main = function_body(KTO, "main")
        self.assertIn('haproxy-pool-collapse|haproxy-collapse-pool', main)

        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
routes=$(mktemp)
trap 'rm -f "$routes"' EXIT
printf '443\t89.144.8.3:443\tbase.example.com\tdefault\n8450\t31.59.140.66:7443\told.example.com\t217.19.122.109\t10000\n8451\t31.77.154.79:7443\told.example.com\t217.19.122.109\t10000\n8452\t31.76.113.188:7443\told.example.com\t217.19.122.109\t10000\n9000\t5.34.179.144:443\tkeep.example.com\tdefault\n' > "$routes"
haproxy_default_source_ip() { printf '78.159.245.250\n'; }
haproxy_input_ip_available() { [[ "$1" == '78.159.245.250' || "$1" == '217.19.122.109' ]]; }
ip() { return 0; }
apply_haproxy_routes_config() { return 0; }
sync_haproxy_firewall() { SYNC_CALLS=$((SYNC_CALLS + 1)); }
haproxy_source_label() { printf '%s\n' "$1"; }
SYNC_CALLS=0
pool='31.59.140.66:7443,31.77.154.79:7443,31.76.113.188:7443'
collapse_haproxy_routes_to_pool "$routes" 8450 8470 217.19.122.109 'dev-yandex.sbs *.dev-yandex.sbs' 10000 "$pool"
grep -Fqx $'8450\t31.59.140.66:7443,31.77.154.79:7443,31.76.113.188:7443\tdev-yandex.sbs *.dev-yandex.sbs\t217.19.122.109\t10000\t217.19.122.109' "$routes"
! awk -F '\t' '$1 >= 8451 && $1 <= 8470 { found = 1 } END { exit found ? 0 : 1 }' "$routes"
grep -q $'^9000\t' "$routes"
[[ "$SYNC_CALLS" == 2 ]]
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_add_source_route_saves_selected_ip(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
routes=$(mktemp)
trap 'rm -f "$routes"' EXIT
printf '443\t89.144.8.3:443\tbase.example.com\tdefault\n' > "$routes"
select_haproxy_route_source_ip() { printf '185.141.227.93\n'; }
haproxy_route_ip_for_source() { printf '185.141.227.93\n'; }
ask_int() { printf '8443\n'; }
haproxy_tcp_port_listening() { return 1; }
ask_haproxy_target_default() { printf '5.34.179.144:443\n'; }
ask_haproxy_sni_list() { printf 'extra.example.com\n'; }
ask_haproxy_send_proxy_v2() { printf '0\n'; }
apply_haproxy_routes_config() { return 0; }
sync_haproxy_firewall() { return 0; }
add_haproxy_source_route "$routes"
grep -qx $'8443\t5.34.179.144:443\textra.example.com\t185.141.227.93\tauto\t185.141.227.93' "$routes"
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_haproxy_bulk_sni_replace_preserves_ports_and_targets(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
SUDO=()
routes=$(mktemp)
trap 'rm -f "$routes"' EXIT
printf '443\t89.144.8.3:443\told.example.com\tdefault\n8443\t5.34.179.144:443\tother.example.com\t185.141.227.93\n8450\t31.59.140.66:7443,31.77.154.79:7443\tpool.example.com\t217.19.122.109\t10000\n' > "$routes"
ask_haproxy_sni_list() { printf '%s\n' '*.rog-self.co.uk'; }
apply_haproxy_routes_config() { return 0; }
sync_haproxy_firewall() { return 0; }
replace_all_haproxy_sni "$routes"
expected=$'443\t89.144.8.3:443\t*.rog-self.co.uk\tdefault\n8443\t5.34.179.144:443\t*.rog-self.co.uk\t185.141.227.93\n8450\t31.59.140.66:7443,31.77.154.79:7443\t*.rog-self.co.uk\t217.19.122.109\t10000'
actual=$(cat "$routes")
[[ "$actual" == "$expected" ]]
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_panel_menu_manages_connection_alert_mutes(self):
        panel_menu = function_body(KTO, "menu")
        alerts_menu = function_body(KTO, "stats_collector_alerts_menu")

        self.assertIn('labels+=("Не получать push-уведомления")', panel_menu)
        self.assertIn('stats-collector-alerts) stats_collector_alerts_menu', panel_menu)
        self.assertIn('--connection-alerts-list', alerts_menu)
        self.assertIn('--connection-alerts-toggle "$query"', alerts_menu)
        self.assertIn('systemctl stop "$STATS_COLLECTOR_SERVICE"', alerts_menu)
        self.assertIn('systemctl start "$STATS_COLLECTOR_SERVICE"', alerts_menu)
        self.assertIn('Статистика, SLA и downtime продолжат работать', alerts_menu)
        self.assertIn('query="$(trim_whitespace "$query")"', alerts_menu)
        self.assertNotIn('query="$(trim "$query")"', alerts_menu)

    def test_collector_alert_menu_trims_zero_and_machine_names(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
SUDO=()
STATS_COLLECTOR_CONFIG=$(mktemp)
LOG_FILE=$(mktemp)
trap 'rm -f "$STATS_COLLECTOR_CONFIG" "$LOG_FILE"' EXIT
printf 'configured\n' > "$STATS_COLLECTOR_CONFIG"
STATS_COLLECTOR_SCRIPT=/bin/true
header() { :; }
require_panel_mode() { :; }
need_root() { :; }
write_stats_collector_script() { :; }
[[ "$(trim_whitespace '  Обход №1 (Private)  ')" == 'Обход №1 (Private)' ]]
stats_collector_alerts_menu <<< '  0  ' >/dev/null
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_whitelist_mobile443_mode_is_minimal_pinned_and_fail_open(self):
        main_menu = function_body(KTO, "menu")
        lte_menu = function_body(KTO, "mobile443_lte_menu")
        enable = function_body(KTO, "enable_mobile443_lte")
        disable = function_body(KTO, "disable_mobile443_lte")
        status = function_body(KTO, "print_mobile443_lte_status")
        config = function_body(MOBILE443, "write_config")
        download = function_body(MOBILE443, "download_upstream")
        fail_open = function_body(MOBILE443, "fail_open")
        manager_enable = function_body(MOBILE443, "enable_lte")
        manager_status = function_body(MOBILE443, "show_status")

        self.assertIn('labels+=("Включение режима \\"Только LTE\\"")', main_menu)
        self.assertIn('actions+=("mobile443-lte")', main_menu)
        self.assertIn('labels+=("Статус режима \\"Только LTE\\"")', main_menu)
        self.assertIn('actions+=("mobile443-lte-status")', main_menu)
        self.assertIn('enable_mobile443_lte || true', lte_menu)
        self.assertIn('extract_haproxy_routes > "$routes_file"', enable)
        self.assertIn('whitelist_ipv6_disabled', enable)
        self.assertIn('opt_ipv6_mode_guard', enable)
        self.assertIn('"$MOBILE443_MANAGER" enable "$ports"', enable)
        self.assertIn('ensure_mobile443_manager', disable)
        self.assertNotIn('KTO_MOBILE443_LOG_FILE', enable + disable + status)
        self.assertIn('bash "$script" update full', manager_enable)
        self.assertIn('fail_open "$ports"', manager_enable)
        self.assertIn('show_status', manager_enable)
        self.assertIn('Списки загружены. Проверяю ipset, iptables и systemd.', manager_enable)
        self.assertIn('Итог: %s', manager_status)
        self.assertIn('Правила INPUT:', manager_status)
        self.assertIn('NextElapseUSecRealtime', manager_status)
        self.assertIn('ExecMainStatus', manager_status)
        self.assertIn('tail -n 15 "$LOG_FILE"', manager_status)
        self.assertIn('ENABLE_TRAF_GUARD="false"', config)
        self.assertIn('ENABLE_MOBILE_ALLOW="${enabled}"', config)
        self.assertIn('ENABLE_TELEGRAM="false"', config)
        self.assertIn('sha256sum "$destination"', download)
        self.assertIn('remove_jumps', fail_open)
        self.assertIn('MOBILE443_REF="${KTO_MOBILE443_REF:-43d0065e983d1d518421b781298f8130125738b4}"', MOBILE443)
        self.assertIn('MOBILE443_ASN_SHA256="${KTO_MOBILE443_ASN_SHA256:-505184e6e859871d64a379a05954ccba648bae97ba672f2e6c7575ba969befaf}"', MOBILE443)

    def test_mobile443_uses_all_unique_haproxy_ports(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
routes=$(mktemp)
trap 'rm -f "$routes"' EXIT
printf '8443\ttarget-a:443\ta.example\n443\ttarget-b:443\tb.example\n8443\ttarget-c:443\tc.example\n' > "$routes"
[[ "$(mobile443_lte_ports_from_routes "$routes")" == '443 8443' ]]
require_whitelist_mode() { :; }
need_root() { :; }
mobile443_lte_configured() { return 1; }
enable_mobile443_lte() { return 1; }
mobile443_lte_menu
KTO_MOBILE443_LOG_FILE=/tmp/must-not-be-used
source <(sed '/^require_root$/,$d' scripts/kto-mobile443.sh)
[[ "$LOG_FILE" == '/var/log/kto-mobile443.log' ]]
[[ "$(normalize_ports '08443,443 8443')" == '443 8443' ]]
events=$(mktemp)
systemctl() { return 0; }
remove_jumps() { printf 'jumps-removed\n' >> "$events"; }
write_config() { printf 'config:%s:%s\n' "$1" "$2" >> "$events"; }
fail_open '443 8443'
grep -qx 'jumps-removed' "$events"
grep -qx 'config:443 8443:false' "$events"
rm -f "$events"
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_mobile443_status_reports_real_rules_and_timer(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^require_root$/,$d' scripts/kto-mobile443.sh)
config_ports() { printf '443 8443\n'; }
config_enabled() { return 0; }
prefix_count() { printf '2500\n'; }
healthy() { return 0; }
iptables() {
    if [[ "$1" == "-nL" || "$1" == "-C" ]]; then
        return 0
    fi
    return 1
}
ipset() { return 0; }
systemctl() {
    if [[ "$1" == "is-active" ]]; then
        printf 'active\n'
    elif [[ "$1" == "is-enabled" ]]; then
        printf 'enabled\n'
    elif [[ "$1" == "show" ]]; then
        case "$4" in
            NextElapseUSecRealtime) printf 'Tue 2026-07-29 00:00:00 UTC\n' ;;
            ExecMainExitTimestamp) printf 'Mon 2026-07-28 00:01:00 UTC\n' ;;
            Result) printf 'success\n' ;;
            ExecMainStatus) printf '0\n' ;;
            *) printf '\n' ;;
        esac
    fi
}
output="$(show_status)"
grep -q '^Итог: РАБОТАЕТ$' <<< "$output"
grep -q '^443/tcp: OK | 443/udp: OK$' <<< "$output"
grep -q '^8443/tcp: OK | 8443/udp: OK$' <<< "$output"
grep -q '^Allowlist ipset: OK, IPv4-сетей: 2500$' <<< "$output"
grep -q '^Автообновление: active / enabled$' <<< "$output"
'''
        result = subprocess.run(
            [bash, "-lc", harness],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
