import os
import subprocess
import unittest

from test_kto_profiles import KTO, ROOT, bash_executable, function_body


class GCloudSafetyTests(unittest.TestCase):
    def run_bash(self, names, harness):
        bash = os.environ.get("KTO_TEST_BASH") or bash_executable()
        if not bash:
            self.skipTest("bash is unavailable")
        definitions = "\n".join(function_body(KTO, name) for name in names)
        source = r"""
set -Eeuo pipefail
IFS=$'\n\t'
LOG_FILE=/dev/null
SUDO=()
ok() { printf '%s\n' "$*"; }
warn() { printf '%s\n' "$*"; }
fail() { printf '%s\n' "$*"; }
expect_failure() {
    if "$@"; then
        printf 'Expected failure: %s\n' "$*" >&2
        exit 99
    fi
}
""" + definitions + "\n" + harness
        result = subprocess.run(
            [bash, "-s"], input=source, cwd=ROOT,
            capture_output=True, encoding="utf-8", timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

    def test_detection_uses_kernel_or_local_markers_without_network(self):
        self.run_bash(["google_cloud_detected"], r'''
uname() { printf '%s\n' "$release"; }
cat() { printf '%s\n' "$test_markers"; return 1; }
curl() { exit 90; }
test_markers=''
for release in 6.8.0-1015-gcp 6.14.0-1001-gcp-64k 6.8.0-1001-gke; do
    google_cloud_detected
done
release=6.18.1-x64v3-xanmod1
for test_markers in 'Google Compute Engine' 'Google' 'DataSourceGCE [net,ver=2]'; do
    google_cloud_detected
done
test_markers=OpenStack
expect_failure google_cloud_detected
release=6.8.0-51-generic
expect_failure google_cloud_detected
test_markers=''
expect_failure google_cloud_detected
''')

    def test_stale_boot_selection_and_unfinished_packages_are_detected(self):
        self.run_bash(["xanmod_boot_changes_present"], r'''
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
XANMOD_GRUB_DEFAULT_FILE="$tmp/override.cfg"
release=6.8.0-1015-gcp
state='deinstall ok config-files'
uname() { printf '%s\n' "$release"; }
dpkg-query() { printf '%s\n' "$state"; }
expect_failure xanmod_boot_changes_present
for state in 'install ok installed' 'install ok unpacked' \
    'install reinstreq half-installed' 'install ok half-configured' \
    'install ok triggers-awaited' 'install ok triggers-pending'; do
    xanmod_boot_changes_present
done
state=''
expect_failure xanmod_boot_changes_present
touch "$XANMOD_GRUB_DEFAULT_FILE"
xanmod_boot_changes_present
rm "$XANMOD_GRUB_DEFAULT_FILE"
release=6.18.1-x64v3-xanmod1
xanmod_boot_changes_present
''')

    def test_kernel_install_and_final_retry_do_not_touch_boot_on_gcloud(self):
        self.run_bash([
            "opt_cloud_boot_preflight", "opt_xanmod_kernel", "opt_kernel_final_check",
            "configure_xanmod_repository", "prepare_xanmod_grub_state",
            "select_xanmod_grub_entry",
        ], r'''
google_cloud_detected() { return 0; }
xanmod_boot_changes_present() { return 1; }
cmd() { exit 91; }
write_root_file() { exit 92; }
xanmod_installed() { exit 93; }
xanmod_latest_version() { exit 94; }
apt_install_quiet() { exit 95; }
opt_xanmod_kernel
opt_kernel_final_check
expect_failure configure_xanmod_repository
expect_failure prepare_xanmod_grub_state
expect_failure select_xanmod_grub_entry
xanmod_boot_changes_present() { return 0; }
expect_failure opt_xanmod_kernel
expect_failure opt_kernel_final_check
''')

    def test_dirty_gcloud_boot_stops_all_optimization_entrypoints_before_mutation(self):
        self.run_bash([
            "opt_cloud_boot_preflight", "optimize_system",
            "system_check_apply_missing", "opt_prepare_system",
        ], r'''
google_cloud_detected() { return 0; }
xanmod_boot_changes_present() { return 0; }
header() { :; }
need_root() { :; }
cmd() { exit 91; }
progress_start() { exit 92; }
detect_ssh_port() { exit 93; }
expect_failure optimize_system
expect_failure system_check_apply_missing 22
expect_failure opt_prepare_system
''')

    def test_cloud_kernel_audit_never_requests_xanmod_or_a_reboot(self):
        output = self.run_bash(["system_check_kernel"], r'''
google_cloud_detected() { return 0; }
uname() { echo 6.8.0-1015-gcp; }
xanmod_boot_changes_present() { return "$dirty"; }
xanmod_installed() { exit 91; }
system_check_row() { printf '%s|%s|%s\n' "$1" "$2" "$3"; }
for dirty in 0 1; do
    SYSTEM_CHECK_NEEDS_KERNEL=1
    system_check_kernel
    [[ "$SYSTEM_CHECK_NEEDS_KERNEL" == 0 ]]
done
''')
        self.assertIn("warn|GCloud kernel|", output)
        self.assertIn("ok|GCloud kernel|", output)
        self.assertNotIn("нужен reboot", output)

    def test_dns_ipv6_and_ssh_are_preserved_even_in_whitelist_mode(self):
        self.run_bash([
            "managed_ssh_changes_enabled", "opt_dns_guard", "opt_ipv6_mode_guard",
            "opt_ssh_root_access", "opt_fail2ban", "opt_haproxy_firewall_final_check",
        ], r'''
google_cloud_detected() { return 0; }
cmd() { exit 91; }
write_root_file() { exit 92; }
ensure_hostname_hosts_entry() { exit 93; }
ensure_haproxy_firewall_guard() { exit 94; }
ufw_active() { return 1; }
KTO_FORCE_DNS_GUARD=1
for MACHINE_MODE in node whitelist panel; do
    expect_failure managed_ssh_changes_enabled
    opt_dns_guard
    opt_ipv6_mode_guard
    opt_ssh_root_access
    opt_fail2ban
    opt_haproxy_firewall_final_check
done
google_cloud_detected() { return 1; }
MACHINE_MODE=node
expect_failure managed_ssh_changes_enabled
MACHINE_MODE=whitelist
managed_ssh_changes_enabled
MACHINE_MODE=panel
managed_ssh_changes_enabled
''')

    def test_full_cloud_optimization_keeps_non_kernel_steps_without_reboot_advice(self):
        output = self.run_bash([
            "optimize_system", "opt_cloud_boot_preflight", "managed_ssh_changes_enabled",
            "opt_kernel_network_memory_parallel", "opt_xanmod_kernel", "opt_kernel_final_check",
            "opt_dns_guard", "opt_ipv6_mode_guard",
        ], r'''
google_cloud_detected() { return 0; }
xanmod_boot_changes_present() { return 1; }
header() { :; }
need_root() { :; }
detect_ssh_port() { echo 22; }
progress_start() { [[ "$1" == 9 ]]; }
progress_step() { shift; "$@"; }
parallel_run_tasks() { while (( $# )); do shift; "$1"; shift; done; }
opt_prepare_system() { opt_cloud_boot_preflight; }
opt_install_fast_packages() { echo 'PACKAGES'; }
opt_network_limits() { opt_dns_guard; opt_ipv6_mode_guard; echo 'NETWORK'; }
opt_memory_guard() { echo 'MEMORY'; }
opt_storage_guard() { echo 'STORAGE'; }
upgrade_haproxy_if_configured() { echo 'HAPROXY'; }
opt_firewall() { echo 'FIREWALL'; }
opt_antiscanner() { echo 'ANTISCANNER'; }
opt_haproxy_firewall_final_check() { :; }
format_duration() { echo 0; }
opt_ssh_root_access() { exit 91; }
opt_fail2ban() { exit 92; }
select_xanmod_grub_entry() { exit 93; }
apt_install_quiet() { exit 94; }
MACHINE_MODE=whitelist
optimize_system
''')
        for step in ("PACKAGES", "NETWORK", "MEMORY", "STORAGE", "HAPROXY", "FIREWALL", "ANTISCANNER"):
            self.assertIn(step, output)
        self.assertIn("SSH сохранён без изменений", output)
        self.assertNotIn("sudo reboot", output)

    def test_boot_preflight_precedes_package_hooks_in_both_workflows(self):
        for name, action in (
            ("optimize_system", "progress_start"),
            ("system_check_apply_missing", "progress_start"),
            ("opt_prepare_system", "dpkg --configure -a"),
        ):
            with self.subTest(name=name):
                body = function_body(KTO, name)
                self.assertLess(body.index("opt_cloud_boot_preflight"), body.index(action))

    def test_local_status_accepts_preserved_google_kernel(self):
        output = self.run_bash(["print_kernel_status"], r'''
BOLD='' PURPLE='' NC=''
google_cloud_detected() { return 0; }
print_row() { printf '%s|%s|%s\n' "$1" "$2" "$3"; }
print_kernel_status 6.8.0-1015-gcp
''')
        self.assertIn("kernel|6.8.0-1015-gcp (GCloud: сохраняется)|1", output)


if __name__ == "__main__":
    unittest.main()

