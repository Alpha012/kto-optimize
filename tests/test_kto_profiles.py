import re
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
KTO = (ROOT / "kto.sh").read_text(encoding="utf-8")
PUSH = (ROOT / "scripts" / "kto-stats-push.sh").read_text(encoding="utf-8")
COLLECTOR = (ROOT / "scripts" / "kto-stats-collector.py").read_text(encoding="utf-8")
MOBILE443 = (ROOT / "scripts" / "kto-mobile443.sh").read_text(encoding="utf-8")
ADDITIONAL_IPS = (ROOT / "scripts" / "kto-additional-ips.sh").read_text(encoding="utf-8")


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
        self.assertIn('SCRIPT_BUILD="v250"', KTO)
        self.assertIn('PUSH_BUILD="v250"', PUSH)
        self.assertIn('COLLECTOR_BUILD = "v250"', COLLECTOR)
        self.assertIn('MOBILE443_BUILD="v250"', MOBILE443)
        self.assertIn('ADDITIONAL_IP_BUILD="v250"', ADDITIONAL_IPS)

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

    def test_additional_ip_menu_uses_openstack_ports_and_source_routing(self):
        menu = function_body(KTO, "menu")
        wrapper = function_body(KTO, "setup_additional_ips")
        setup = function_body(ADDITIONAL_IPS, "setup_additional_ips")
        apply_netplan = function_body(ADDITIONAL_IPS, "apply_managed_netplan")
        render = function_body(ADDITIONAL_IPS, "render_netplan")

        self.assertIn('labels+=("Проверить и завести дополнительные IP")', menu)
        self.assertIn('actions+=("additional-ips")', menu)
        self.assertIn('ensure_additional_ip_manager', wrapper)
        self.assertIn('fetch_openstack_metadata "$metadata_file"', setup)
        self.assertIn('openstack_ipv4_port_macs "$metadata_file"', setup)
        self.assertIn('wait_for_dhcp "${names[@]}"', setup)
        self.assertIn('remove_duplicate_primary_addresses', setup)
        self.assertIn('write_multiwan_sysctl', setup)
        self.assertIn('main_route_healthy', apply_netplan)
        self.assertIn('restore_managed_netplan', apply_netplan)
        self.assertIn('routing-policy:', render)
        self.assertIn('on-link: true', render)
        self.assertIn('table: ${table}', render)

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
sleep() { :; }
print_result_table() { :; }
setup_additional_ips
[[ "$apply_count" == 2 ]]
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

    def test_haproxy_multiport_menu_keeps_legacy_443_names(self):
        render = function_body(KTO, "render_haproxy_routes_config")
        haproxy_menu = function_body(KTO, "haproxy_menu")
        main_menu = function_body(KTO, "menu")

        self.assertIn('if (( port == 443 ))', render)
        self.assertIn('frontend_name="vless_in"', render)
        self.assertIn('backend_name="vless_pool"', render)
        self.assertIn('server_name="xray1"', render)
        self.assertIn('frontend_name="vless_in_${port}"', render)
        self.assertIn('backend_name="vless_pool_${port}"', render)
        self.assertIn('2) Добавить порт', haproxy_menu)
        self.assertIn('3) Удалить дополнительный порт', haproxy_menu)
        self.assertIn('4) Заменить SNI у всех маршрутов', haproxy_menu)
        self.assertIn('5) Обновить HAProxy, сохранив маршруты', haproxy_menu)
        self.assertIn('replace_all_haproxy_sni "$routes_file"', haproxy_menu)
        self.assertNotIn('labels+=("Обновить HAProxy")', main_menu)

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
        self.assertIn(
            'WHITELIST_SSH_ALLOWED_IPS_DEFAULT="85.192.48.122 46.28.64.183 146.19.248.67 '
            '85.93.9.35 185.31.243.221 94.247.129.92 83.228.242.53 167.254.243.181 '
            '5.34.176.116 5.34.178.234 84.38.185.15 193.23.195.222"',
            KTO,
        )

    def test_haproxy_updates_are_transactional_and_preserve_routes(self):
        apply_routes = function_body(KTO, "apply_haproxy_routes_config")
        update = function_body(KTO, "update_haproxy_existing_config")

        self.assertIn('haproxy -c -f "$tmp_config"', apply_routes)
        self.assertIn('${config}.kto.bak', apply_routes)
        self.assertIn('возвращаю предыдущий', apply_routes)
        self.assertIn('install -m 0644 "$backup" "$config"', apply_routes)
        self.assertIn('extract_haproxy_routes > "$routes_file"', update)
        self.assertIn('маршруты сохранены', update)

    def test_haproxy_firewall_and_wrong_sni_cover_extra_ports(self):
        firewall = function_body(KTO, "harden_whitelist_haproxy_firewall")
        optimize_firewall = function_body(KTO, "opt_firewall")
        check_firewall = function_body(KTO, "system_check_firewall")
        scan = function_body(PUSH, "read_haproxy_scan_stats")

        self.assertIn('ufw allow "${port}/tcp"', firewall)
        self.assertIn('ufw --force delete allow "${port}/tcp"', firewall)
        self.assertIn('extract_haproxy_routes > "$routes_file"', optimize_firewall)
        self.assertIn('ufw allow "${port}/tcp"', optimize_firewall)
        self.assertIn('extract_haproxy_routes > "$routes_file"', check_firewall)
        self.assertIn('ufw_rule_allowed "${port}/tcp"', check_firewall)
        self.assertIn('/^vless_in_[0-9]+$/', scan)
        self.assertIn("count[$1] += $2", scan)
        self.assertIn("show table %s", scan)

    def test_haproxy_multiport_config_round_trip(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
SUDO=()
routes=$(mktemp)
config=$(mktemp)
trap 'rm -f "$routes" "$config"' EXIT
printf '443\t89.144.8.3:443\tbase.example.com *.rog-self.co.uk\n8443\t5.34.179.144:443\textra.example.com *.other.example.com\n' > "$routes"
render_haproxy_routes_config "$routes" "$config"
grep -q '^frontend vless_in$' "$config"
grep -q '^frontend vless_in_8443$' "$config"
grep -q '^    server xray1 89.144.8.3:443 check weight 10$' "$config"
grep -q '^    server xray_8443 5.34.179.144:443 check weight 10$' "$config"
grep -q '^    acl allowed_sni req.ssl_sni -i base.example.com$' "$config"
grep -q '^    acl allowed_sni req.ssl_sni -m end -i \.rog-self.co.uk$' "$config"
actual=$(extract_haproxy_routes "$config")
expected=$'443\t89.144.8.3:443\tbase.example.com *.rog-self.co.uk\n8443\t5.34.179.144:443\textra.example.com *.other.example.com'
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

    def test_haproxy_bulk_sni_replace_preserves_ports_and_targets(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
SUDO=()
routes=$(mktemp)
trap 'rm -f "$routes"' EXIT
printf '443\t89.144.8.3:443\told.example.com\n8443\t5.34.179.144:443\tother.example.com\n' > "$routes"
ask_haproxy_sni_list() { printf '%s\n' '*.rog-self.co.uk'; }
apply_haproxy_routes_config() { return 0; }
harden_whitelist_haproxy_firewall() { return 0; }
replace_all_haproxy_sni "$routes"
expected=$'443\t89.144.8.3:443\t*.rog-self.co.uk\n8443\t5.34.179.144:443\t*.rog-self.co.uk'
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
