import os
import subprocess
import unittest

from test_kto_profiles import KTO, ROOT, bash_executable, function_body


HARNESS = r'''
set -Eeuo pipefail
IFS=$'\n\t'
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
export TMPDIR="$tmp"
LOG_FILE="$tmp/install.log"
events="$tmp/events"
: > "$LOG_FILE"
: > "$events"
WARP_INSTALL_URL=https://raw.githubusercontent.com/tagashi666/vps-warp/main/warp_install.sh
SUDO=(root_cmd)
SYSTEMD_RC=0
APT_RC=0
DOWNLOAD_RC=0
INSTALL_RC=0
MISSING_TOOL=''
INVALID_SCRIPT=0
EMPTY_SCRIPT=0
MISSING_CONFIG=0
MISSING_CLI=0
INACTIVE_SERVICE=''
TRACE_RC=0
TRACE_VALUE=on

stage() { printf '%s\n' "$*"; }
ok() { printf 'OK: %s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*"; }
command_exists() { [[ "$1" != "$MISSING_TOOL" ]]; }
must() { shift; "$@" >> "$LOG_FILE" 2>&1; }
apt_install_with_update_if_missing() {
    printf 'deps:%s\n' "$*" >> "$events"
    [[ "${NEEDRESTART_MODE:-}" == l ]] || return 90
    if read -r unexpected; then return 91; fi
    return "$APT_RC"
}
run_systemctl_bounded() {
    { printf 'systemctl:'; printf '%s|' "$@"; printf '\n'; } >> "$events"
    [[ "$1" == 10 ]] || return 92
    shift
    case "$1" in
        show-environment) return "$SYSTEMD_RC" ;;
        is-active) [[ "$3" != "$INACTIVE_SERVICE" ]] ;;
        status) return 0 ;;
        *) return 93 ;;
    esac
}
root_cmd() {
    case "$1" in
        env)
            shift
            local -a environment=()
            while [[ "$1" == *=* ]]; do
                environment+=("$1")
                shift
            done
            [[ "$1" == setsid && "$2" == --wait && "$3" == timeout ]] || return 94
            [[ "$4" == --signal=TERM && "$5" == --kill-after=15s && "$6" == 900s ]] || return 95
            [[ "$7" == bash && -s "$8" ]] || return 96
            printf 'installer:%s\n' "$8" >> "$events"
            command env "${environment[@]}" FAKE_INSTALL_RC="$INSTALL_RC" bash "$8"
            ;;
        test)
            case "$3" in
                /etc/wireguard/warp.conf) [[ "$MISSING_CONFIG" == 0 ]] ;;
                /usr/local/bin/vps-warp) [[ "$MISSING_CLI" == 0 ]] ;;
                *) return 97 ;;
            esac
            ;;
        curl) shift; curl "$@" ;;
        *) return 98 ;;
    esac
}
curl() {
    local target='' previous='' arg
    for arg in "$@"; do
        [[ "$previous" != -o ]] || target="$arg"
        previous="$arg"
    done
    if [[ -n "$target" ]]; then
        printf 'download:%s\n' "$target" >> "$events"
        if [[ "$EMPTY_SCRIPT" == 1 ]]; then
            : > "$target"
        elif [[ "$INVALID_SCRIPT" == 1 ]]; then
            printf '%s\n' 'if then' > "$target"
        else
            printf '%s\n' \
                '#!/usr/bin/env bash' \
                'set -eu' \
                'read -r language; [[ "$language" == 2 ]]' \
                'read -r license; [[ -z "$license" ]]' \
                'if read -r unexpected; then exit 99; fi' \
                '[[ "$HOME" == /root && "$DEBIAN_FRONTEND" == noninteractive && "$NEEDRESTART_MODE" == l ]]' \
                'echo upstream-progress' \
                'exit "$FAKE_INSTALL_RC"' > "$target"
        fi
        return "$DOWNLOAD_RC"
    fi
    printf 'trace\n' >> "$events"
    [[ "$*" == *'--interface'* && "$*" == *warp* && "$*" == *'--noproxy'* ]] || return 89
    printf 'warp=%s\r\n' "$TRACE_VALUE"
    return "$TRACE_RC"
}
expect_failure() {
    if do_install_warp_native; then
        echo 'Unexpected install success' >&2
        exit 88
    fi
}
assert_temporary_script_removed() {
    local kind path
    while IFS=: read -r kind path; do
        [[ "$kind" != download ]] || [[ ! -e "$path" ]]
    done < "$events"
}
'''


class WarpInstallTests(unittest.TestCase):
    def run_bash(self, scenario):
        bash = os.environ.get("KTO_TEST_BASH") or bash_executable()
        if not bash:
            self.skipTest("bash is unavailable")
        source = HARNESS + "\n" + function_body(KTO, "do_install_warp_native")
        source += "\n" + scenario + "\nassert_temporary_script_removed\n"
        result = subprocess.run(
            [bash, "-s"], input=source, cwd=ROOT,
            capture_output=True, encoding="utf-8", timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

    def test_unattended_answers_live_output_and_menu_stdin_isolation(self):
        output = self.run_bash(r'''
{
    do_install_warp_native
    read -r next_action
    [[ "$next_action" == next-menu-action ]]
} <<< next-menu-action
grep -q upstream-progress "$LOG_FILE"
[[ "$(grep -c '^installer:' "$events")" == 1 ]]
[[ "$(grep -c '^trace$' "$events")" == 1 ]]
''')
        self.assertIn("upstream-progress", output)
        self.assertIn("sockopt.mark=255", output)

    def test_missing_systemd_stops_before_packages_or_download(self):
        self.run_bash(r'''
SYSTEMD_RC=1
expect_failure
! grep -qE '^(deps|download|installer):' "$events"
''')

    def test_dependency_failure_never_launches_installer(self):
        self.run_bash(r'''
APT_RC=1
expect_failure
! grep -qE '^(download|installer):' "$events"
''')

    def test_required_tools_are_checked_after_dependency_installation(self):
        for tool in ("setsid", "timeout", "wg-quick", "ip", "iptables", "ping", "curl", "wget"):
            with self.subTest(tool=tool):
                self.run_bash(f"MISSING_TOOL={tool}\nexpect_failure\n! grep -q '^download:' \"$events\"")

    def test_download_failure_cleans_partial_file_without_execution(self):
        self.run_bash(r'''
DOWNLOAD_RC=28
expect_failure
! grep -q '^installer:' "$events"
''')

    def test_empty_and_invalid_downloads_are_not_executed(self):
        for setting in ("EMPTY_SCRIPT", "INVALID_SCRIPT"):
            with self.subTest(setting=setting):
                self.run_bash(f"{setting}=1\nexpect_failure\n! grep -q '^installer:' \"$events\"")

    def test_upstream_failure_is_not_hidden_by_successful_tee(self):
        output = self.run_bash(r'''
INSTALL_RC=23
expect_failure
! grep -q '^trace$' "$events"
''')
        self.assertIn("код 23", output)

    def test_timeout_has_specific_error_and_skips_success_checks(self):
        for code in (124, 137):
            with self.subTest(code=code):
                output = self.run_bash(f"INSTALL_RC={code}\nexpect_failure\n! grep -q '^trace$' \"$events\"")
                self.assertIn("15 минут" if code == 124 else "SIGKILL", output)

    def test_config_cli_tunnel_and_watchdog_are_required(self):
        for setting in ("MISSING_CONFIG=1", "MISSING_CLI=1",
                        "INACTIVE_SERVICE=wg-quick@warp", "INACTIVE_SERVICE=warp-watchdog.timer"):
            with self.subTest(setting=setting):
                self.run_bash(setting + r'''
expect_failure
! grep -q '^trace$' "$events"
grep -q 'systemctl:10.*status' "$events"
''')

    def test_active_service_without_warp_connectivity_is_not_success(self):
        for setting in ("TRACE_RC=28", "TRACE_VALUE=off", "TRACE_VALUE=''"):
            with self.subTest(setting=setting):
                output = self.run_bash(setting + "\nexpect_failure")
                self.assertNotIn("OK:", output)
                self.assertIn("vps-warp rotate", output)

    def test_warp_plus_trace_is_accepted(self):
        self.run_bash("TRACE_VALUE=plus\ndo_install_warp_native")

    def test_download_and_process_tree_have_time_limits(self):
        install = function_body(KTO, "do_install_warp_native")
        self.assertIn("--connect-timeout 10 --max-time 90", install)
        self.assertIn("--proto '=https' --proto-redir '=https'", install)
        self.assertIn("setsid --wait timeout --signal=TERM --kill-after=15s 900s", install)
        self.assertIn("wireguard-tools", install)
        self.assertNotIn("apt_install_quiet wireguard\n", install)

    def test_needrestart_setting_reaches_apt_through_sudo(self):
        self.run_bash(function_body(KTO, "apt_install_quiet") + r'''
package_installed() { return 1; }
wait_for_apt_locks() { return 0; }
root_cmd() {
    [[ "$1" == env && "$2" == DEBIAN_FRONTEND=noninteractive ]]
    shift 2
    if [[ "$expected_mode" == l ]]; then
        [[ "$1" == NEEDRESTART_MODE=l ]]
        shift
    fi
    [[ "$1" == apt-get ]]
    [[ "$*" == *--force-confold* ]]
}
expected_mode=l
NEEDRESTART_MODE=l apt_install_quiet wireguard-tools
expected_mode=default
unset NEEDRESTART_MODE
apt_install_quiet wireguard-tools
''')


if __name__ == "__main__":
    unittest.main()
