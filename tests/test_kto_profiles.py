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
REMNA_EGRESS = (ROOT / "scripts" / "kto-remnawave-egress.sh").read_text(encoding="utf-8")


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
        self.assertIn('SCRIPT_BUILD="v262"', KTO)
        self.assertIn('PUSH_BUILD="v262"', PUSH)
        self.assertIn('COLLECTOR_BUILD = "v262"', COLLECTOR)
        self.assertIn('MOBILE443_BUILD="v262"', MOBILE443)
        self.assertIn('ADDITIONAL_IP_BUILD="v262"', ADDITIONAL_IPS)
        self.assertIn('REMNA_EGRESS_BUILD="v262"', REMNA_EGRESS)

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
        self.assertIn('setup_existing_source_routes', setup)
        self.assertIn('openstack_ipv4_port_macs "$metadata_file"', setup)
        self.assertIn('wait_for_dhcp "${names[@]}"', setup)
        self.assertIn('remove_duplicate_primary_addresses', setup)
        self.assertIn('write_multiwan_sysctl', setup)
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
grep -q '^wan2|.*|185.141.227.93/26|185.141.227.65|185.141.227.64/26|5201|15201$' "$state"
grep -q '^wan3|.*|217.19.122.48/24|217.19.122.1|217.19.122.0/24|5202|15202$' "$state"
! grep -q 'docker0' "$state"
MANAGED_ROUTE_STATE_FILE=/etc/kto-additional-ip-routes.conf
render_source_route_script "$runner"
bash -n "$runner"
grep -q 'route replace.*scope link table' "$runner"
grep -q 'route replace default via.*onlink table' "$runner"
grep -q 'rule add from.*table.*priority' "$runner"
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
        self.assertIn('2) Добавить порт через основной выходной IP', haproxy_menu)
        self.assertIn('3) Добавить конфиг для другого выходного IP', haproxy_menu)
        self.assertIn('4) Удалить дополнительный порт', haproxy_menu)
        self.assertIn('5) Заменить SNI у всех маршрутов', haproxy_menu)
        self.assertIn('6) Обновить HAProxy, сохранив маршруты', haproxy_menu)
        self.assertIn('add_haproxy_source_route "$routes_file"', haproxy_menu)
        self.assertIn('replace_all_haproxy_sni "$routes_file"', haproxy_menu)
        self.assertNotIn('labels+=("Обновить HAProxy")', main_menu)

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
        self.assertIn('haproxy_tcp_port_listening "$base_port"', configure)
        self.assertIn("printf '%s\\t%s\\t%s\\tdefault\\n'", configure)
        self.assertIn('sync_haproxy_firewall "$routes_file" "$previous_routes_file"', configure)
        self.assertIn('require_haproxy_mode', haproxy_menu)
        self.assertIn('if haproxy_mode_supported; then', settings_menu)
        self.assertIn('labels+=("HAProxy (мост, 8443/tcp)")', main_menu)

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

    def test_haproxy_updates_are_transactional_and_preserve_routes(self):
        apply_routes = function_body(KTO, "apply_haproxy_routes_config")
        update = function_body(KTO, "update_haproxy_existing_config")

        self.assertIn('haproxy -c -f "$tmp_config"', apply_routes)
        self.assertIn('${config}.kto.bak', apply_routes)
        self.assertIn('${config}.kto.failed', apply_routes)
        self.assertIn('extract_haproxy_routes "$backup" > "$backup_routes"', apply_routes)
        self.assertIn('reserve_haproxy_route_ports "$routes_file"', apply_routes)
        self.assertIn('reload_haproxy_gracefully "$routes_file"', apply_routes)
        self.assertIn('возвращаю предыдущий', apply_routes)
        self.assertIn('install -m 0644 "$backup" "$config"', apply_routes)
        self.assertIn('start_haproxy_cleanly "$backup_routes"', apply_routes)
        self.assertIn('extract_haproxy_routes > "$routes_file"', update)
        self.assertIn('маршруты сохранены', update)

    def test_haproxy_capacity_respects_descriptor_budget(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
memory_total_mb() { printf '32768\n'; }
KTO_HAPROXY_NOFILE_LIMIT=1048576
KTO_HAPROXY_FDS_PER_CONNECTION=3
KTO_HAPROXY_FD_RESERVE=8192
unset KTO_HAPROXY_MAXCONN
[[ "$(recommended_haproxy_maxconn)" == 346000 ]]
KTO_HAPROXY_MAXCONN=500000
[[ "$(recommended_haproxy_maxconn)" == 346000 ]]
KTO_HAPROXY_MAXCONN=200000
[[ "$(recommended_haproxy_maxconn)" == 200000 ]]
KTO_HAPROXY_NOFILE_LIMIT=65536
unset KTO_HAPROXY_MAXCONN
[[ "$(recommended_haproxy_maxconn)" == 19000 ]]
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
        reload = function_body(KTO, "reload_haproxy_gracefully")
        clean_start = function_body(KTO, "start_haproxy_cleanly")
        bounded_systemctl = function_body(KTO, "run_systemctl_bounded")
        bounded_command = function_body(KTO, "run_bounded_command")
        stale_listeners = function_body(KTO, "kill_stale_haproxy_route_listeners")
        socket_details = function_body(KTO, "haproxy_tcp_port_socket_details")
        failure_details = function_body(KTO, "print_haproxy_failure_details")
        package = function_body(KTO, "ensure_haproxy_package")

        self.assertIn('haproxy_missing_listener_ports "$routes_file"', wait_for_routes)
        self.assertIn('run_systemctl_bounded 3 is-active --quiet haproxy', wait_for_routes)
        self.assertIn('wait_for_haproxy_routes "$routes_file"', reload)
        self.assertIn('start_haproxy_cleanly "$routes_file"', reload)
        self.assertIn('print_haproxy_failure_details', reload)
        self.assertIn('run_systemctl_bounded 15 restart haproxy', reload)
        self.assertIn('run_bounded_command "$timeout_sec" "${SUDO[@]}" systemctl', bounded_systemctl)
        self.assertIn('timeout --foreground --signal=TERM --kill-after=3s', bounded_command)
        self.assertIn('run_systemctl_bounded 10 --no-block stop haproxy', clean_start)
        self.assertIn('reserve_haproxy_route_ports "$routes_file"', clean_start)
        self.assertIn('wait_for_haproxy_stopped_and_ports_free', clean_start)
        self.assertIn('run_systemctl_bounded 10 kill --kill-who=all --signal=KILL', clean_start)
        self.assertIn('run_systemctl_bounded 10 reset-failed haproxy', clean_start)
        self.assertIn('run_systemctl_bounded 10 --no-block start haproxy', clean_start)
        self.assertIn('grep -vi haproxy', stale_listeners)
        self.assertIn('kill "-${signal}" "$pid"', stale_listeners)
        self.assertIn('ss -K state connected', stale_listeners)
        self.assertIn('ss -H -tanp', socket_details)
        self.assertIn('journalctl -u haproxy -n 40', failure_details)
        self.assertIn('run_systemctl_bounded 5 show haproxy -p LimitNOFILE', failure_details)
        self.assertIn('haproxy socat iproute2', package)

        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
SUDO=()
KTO_HAPROXY_STARTUP_ATTEMPTS=1
routes=$(mktemp)
trap 'rm -f "$routes"' EXIT
printf '8443\t65.108.1.173:443\tfaq.cdnvideo.work\tdefault\n8444\t65.108.1.174:443\tfaq.cdnvideo.work\tdefault\n' > "$routes"
systemctl() { return 0; }
run_systemctl_bounded() {
    shift
    systemctl "$@"
}
sleep() { return 0; }
haproxy_tcp_port_owned_by_haproxy() { [[ "$1" == 8443 ]]; }
! wait_for_haproxy_routes "$routes"
haproxy_tcp_port_owned_by_haproxy() { return 0; }
wait_for_haproxy_routes "$routes"
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
    if [[ "${1:-}" == show && "${4:-}" == ActiveState ]]; then
        printf 'inactive\n'
    elif [[ "${1:-}" == show && "${4:-}" == MainPID ]]; then
        printf '0\n'
    fi
    return 0
}
run_systemctl_bounded() {
    shift
    systemctl "$@"
}
haproxy_route_ports_are_free() { return 0; }
wait_for_haproxy_routes() { return 0; }
reserve_haproxy_route_ports() { return 0; }
start_haproxy_cleanly "$routes"
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

        self.assertIn('ufw allow "${port}/tcp"', firewall)
        self.assertIn('ufw --force delete allow "${port}/tcp"', firewall)
        self.assertIn('extract_haproxy_routes > "$routes_file"', optimize_firewall)
        self.assertIn('ufw allow "${port}/tcp"', optimize_firewall)
        self.assertIn('extract_haproxy_routes > "$routes_file"', check_firewall)
        self.assertIn('ufw_rule_allowed "${port}/tcp"', check_firewall)
        self.assertIn('/^vless_in_[0-9]+$/', scan)
        self.assertIn("count[$1] += $2", scan)
        self.assertIn("show table %s", scan)

    def test_reality_haproxy_firewall_does_not_apply_whitelist_ssh_rules(self):
        firewall = function_body(KTO, "sync_haproxy_firewall")
        self.assertIn('if [[ "$MACHINE_MODE" == "whitelist" ]]', firewall)
        self.assertIn('apply_whitelist_ssh_rules "$ssh_port"', firewall)
        self.assertIn('ufw allow "${port}/tcp"', firewall)
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
printf '443\t89.144.8.3:443\tbase.example.com *.rog-self.co.uk\tdefault\n8443\t5.34.179.144:443\textra.example.com *.other.example.com\t185.141.227.93\n' > "$routes"
render_haproxy_routes_config "$routes" "$config"
grep -q '^    maxpipes 0$' "$config"
grep -q '^    nosplice$' "$config"
! grep -q 'option splice-' "$config"
grep -q '^frontend vless_in$' "$config"
grep -q '^frontend vless_in_8443$' "$config"
grep -q '^    server xray1 89.144.8.3:443 check weight 10$' "$config"
grep -q '^    server xray_8443 5.34.179.144:443 check weight 10 source 185.141.227.93$' "$config"
grep -q '^    acl allowed_sni req.ssl_sni -i base.example.com$' "$config"
grep -q '^    acl allowed_sni req.ssl_sni -m end -i \.rog-self.co.uk$' "$config"
actual=$(extract_haproxy_routes "$config")
expected=$'443\t89.144.8.3:443\tbase.example.com *.rog-self.co.uk\tdefault\n8443\t5.34.179.144:443\textra.example.com *.other.example.com\t185.141.227.93'
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

    def test_haproxy_legacy_routes_default_source_and_additional_ips_are_routable(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("bash is unavailable")

        harness = r'''
source <(sed '/^main /d' kto.sh)
SUDO=()
routes=$(mktemp)
config=$(mktemp)
trap 'rm -f "$routes" "$config"' EXIT
printf '443\t89.144.8.3:443\tbase.example.com\n' > "$routes"
render_haproxy_routes_config "$routes" "$config"
grep -q '^    server xray1 89.144.8.3:443 check weight 10$' "$config"
[[ "$(extract_haproxy_routes "$config")" == $'443\t89.144.8.3:443\tbase.example.com\tdefault' ]]

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
[[ "$(select_haproxy_additional_source_ip "$routes")" == '217.19.122.49' ]]
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
select_haproxy_additional_source_ip() { printf '185.141.227.93\n'; }
haproxy_additional_source_ip_available() { [[ "$1" == '185.141.227.93' ]]; }
ask_int() { printf '8443\n'; }
haproxy_tcp_port_listening() { return 1; }
ask_haproxy_target_default() { printf '5.34.179.144:443\n'; }
ask_haproxy_sni_list() { printf 'extra.example.com\n'; }
apply_haproxy_routes_config() { return 0; }
sync_haproxy_firewall() { return 0; }
add_haproxy_source_route "$routes"
grep -qx $'8443\t5.34.179.144:443\textra.example.com\t185.141.227.93' "$routes"
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
printf '443\t89.144.8.3:443\told.example.com\tdefault\n8443\t5.34.179.144:443\tother.example.com\t185.141.227.93\n' > "$routes"
ask_haproxy_sni_list() { printf '%s\n' '*.rog-self.co.uk'; }
apply_haproxy_routes_config() { return 0; }
sync_haproxy_firewall() { return 0; }
replace_all_haproxy_sni "$routes"
expected=$'443\t89.144.8.3:443\t*.rog-self.co.uk\tdefault\n8443\t5.34.179.144:443\t*.rog-self.co.uk\t185.141.227.93'
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
