import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASH = next((str(path) for path in (
    Path(shutil.which("bash") or "missing-bash"),
    Path(r"C:\Program Files\Git\bin\bash.exe"),
) if path.is_file()), None)

HARNESS = r'''
set -Eeuo pipefail
source <(sed '/^main /d' kto.sh)
root=$(mktemp -d)
trap 'rc=$?; if (( rc != 0 )); then cat "$root/worker.log" "$root/events" >&2; fi; rm -rf "$root"' EXIT
SUDO=()
LOG_FILE="$root/main.log"
ANTISCANNER_SCRIPT="$root/update.sh"
ANTISCANNER_CACHE_FILE="$root/cache.list"
ANTISCANNER_LOG_FILE="$root/worker.log"
KTO_UFW_LOCK_FILE="$root/ufw.lock"
KTO_SSH_FIREWALL_GUARD="$root/ssh-guard"
HAPROXY_FIREWALL_MANAGER="$root/haproxy-guard"
export KTO_ANTISCANNER_UFW_DIR="$root/ufw"
mkdir -p "$KTO_ANTISCANNER_UFW_DIR"
printf 'keep-this-rule\n' > "$KTO_ANTISCANNER_UFW_DIR/user.rules"
events="$root/events"
: > "$events"
feed="$root/feed"
printf '192.0.2.0/25\n192.0.2.128/25\n192.0.2.1\n# comment\n2001:db8::/32\n' > "$feed"
existing=1
service_state=inactive
queue_result=0
curl_result=0
insert_result=0
status_rules=0
managed_ssh_changes_enabled() { return 1; }
python3() { "$KTO_TEST_PYTHON" "$@"; }
antiscanner_rules_count() { printf '%s\n' "$existing"; }
package_installed() { return 1; }
apt_install_quiet() { :; }
cmd() {
    local IFS=' '
    printf 'cmd %s\n' "$*" >> "$events"
    [[ "${1:-}" != "$ANTISCANNER_SCRIPT" ]]
}
write_root_file() {
    if [[ "$1" == "$ANTISCANNER_SCRIPT" ]]; then
        cat > "$1"
    else
        cat > /dev/null
    fi
}
run_systemctl_bounded() {
    local IFS=' '
    printf 'systemctl %s\n' "$*" >> "$events"
    if [[ "${2:-}" == show ]]; then
        printf '%s\n' "$service_state"
    elif [[ "${2:-}" == --no-block ]]; then
        return "$queue_result"
    else
        return 1
    fi
}
curl() {
    local target='' IFS=' '
    printf 'curl %s\n' "$*" >> "$events"
    (( curl_result == 0 )) || return "$curl_result"
    while (( $# )); do
        if [[ "$1" == -o ]]; then target="$2"; shift 2; else shift; fi
    done
    cp "$feed" "$target"
}
ufw() {
    local IFS=' '
    printf 'ufw %s\n' "$*" >> "$events"
    if [[ "$1" == status ]]; then
        for ((n=0; n<status_rules; n++)); do
            printf 'DENY IN Anywhere # AntiScanner-Block\n'
        done
    elif [[ "$1" == insert ]]; then
        return "$insert_result"
    fi
}
flock() {
    local IFS=' '
    printf 'flock %s\n' "$*" >> "$events"
}
install_antiscanner background >/dev/null
bash -n "$ANTISCANNER_SCRIPT"
'''


@unittest.skipUnless(BASH, "bash is unavailable")
class OptimizationLatencyTests(unittest.TestCase):
    def run_harness(self, fragment):
        environment = os.environ.copy()
        environment["KTO_TEST_PYTHON"] = sys.executable.replace("\\", "/")
        result = subprocess.run(
            [BASH, "-lc", HARNESS + "\n" + fragment], cwd=ROOT,
            capture_output=True, text=True, timeout=30, env=environment,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_first_install_queues_service_without_running_worker_in_foreground(self):
        self.run_harness(r'''
existing=0
install_antiscanner background >/dev/null
grep -Fxq 'systemctl 10 --no-block restart antiscanner-update.service' "$events"
! grep -Fq "cmd $ANTISCANNER_SCRIPT" "$events"
! grep -Fq 'apt-get purge' "$events"
''')

    def test_running_update_is_not_restarted(self):
        self.run_harness(r'''
: > "$events"
existing=0
service_state=activating
chmod +x "$ANTISCANNER_SCRIPT"
before=$(cksum "$ANTISCANNER_SCRIPT")
install_antiscanner background >/dev/null
[[ "$before" == "$(cksum "$ANTISCANNER_SCRIPT")" ]]
! grep -q '^cmd ' "$events"
! grep -Fq -- '--no-block restart' "$events"
! grep -Fq "cmd $ANTISCANNER_SCRIPT" "$events"
''')

    def test_queue_failure_is_reported_without_synchronous_fallback(self):
        self.run_harness(r'''
existing=0
queue_result=1
if install_antiscanner background >/dev/null; then exit 1; fi
! grep -Fq "cmd $ANTISCANNER_SCRIPT" "$events"
''')

    def test_failed_download_does_not_take_firewall_lock_or_change_rules(self):
        self.run_harness(r'''
: > "$events"
curl_result=28
if ( source "$ANTISCANNER_SCRIPT" ); then exit 1; fi
grep -Fq -- '--connect-timeout 5 --max-time 30' "$events"
! grep -q '^flock ' "$events"
! grep -q '^ufw ' "$events"
grep -Fxq 'keep-this-rule' "$KTO_ANTISCANNER_UFW_DIR/user.rules"
grep -Fq 'existing rules preserved' "$ANTISCANNER_LOG_FILE"
''')

    def test_invalid_or_empty_feed_preserves_existing_rules(self):
        for value in ("not-an-ip", "# empty", "0.0.0.0/0", "0.0.0.0/1\n128.0.0.0/1"):
            with self.subTest(value=value):
                self.run_harness(r'''
: > "$events"
printf '%s\n' "''' + value + r'''" > "$feed"
if ( source "$ANTISCANNER_SCRIPT" ); then exit 1; fi
! grep -q '^flock ' "$events"
! grep -q '^ufw ' "$events"
grep -Fxq 'keep-this-rule' "$KTO_ANTISCANNER_UFW_DIR/user.rules"
''')

    def test_collapsed_feed_is_applied_once_and_cached_updates_skip_writes(self):
        self.run_harness(r'''
: > "$events"
( source "$ANTISCANNER_SCRIPT" )
[[ "$(grep -c '^ufw insert ' "$events")" == 2 ]]
grep -Fxq '192.0.2.0/24' "$ANTISCANNER_CACHE_FILE"
grep -Fxq '2001:db8::/32' "$ANTISCANNER_CACHE_FILE"
grep -Fq '[PROGRESS] 2/2 rules; failed=0' "$ANTISCANNER_LOG_FILE"
grep -Fq '[SUCCESS]' "$ANTISCANNER_LOG_FILE"
: > "$events"
status_rules=2
( source "$ANTISCANNER_SCRIPT" )
! grep -q '^ufw insert ' "$events"
! grep -q '^ufw reload' "$events"
grep -Fq '[SKIP] blacklist unchanged' "$ANTISCANNER_LOG_FILE"
''')

    def test_failed_rule_is_reported_and_not_saved_as_successful_cache(self):
        self.run_harness(r'''
insert_result=1
if ( source "$ANTISCANNER_SCRIPT" ); then exit 1; fi
[[ ! -e "$ANTISCANNER_CACHE_FILE" ]]
grep -Fq '[ERROR] failed to apply 2/2 rules' "$ANTISCANNER_LOG_FILE"
! grep -Fq '[SUCCESS]' "$ANTISCANNER_LOG_FILE"
''')

    def test_cached_update_still_restores_managed_ssh_priority_under_lock(self):
        self.run_harness(r'''
KTO_SSH_PORT_FILE="$root/ssh-port"
printf '23456\n' > "$KTO_SSH_PORT_FILE"
printf '192.0.2.0/24\n2001:db8::/32\n' > "$ANTISCANNER_CACHE_FILE"
ssh_state="$root/ssh-state"
printf '2\n' > "$ssh_state"
managed_ssh_changes_enabled() { return 0; }
install_ssh_firewall_guard() { :; }
ufw() {
    local IFS=' '
    printf 'ufw %s\n' "$*" >> "$events"
    case "$*" in
        'status numbered')
            printf '[%s] 23456/tcp ALLOW IN Anywhere # kto-ssh-open\n' "$(cat "$ssh_state")"
            ;;
        status)
            printf '23456/tcp ALLOW IN Anywhere # kto-ssh-open\n'
            printf 'DENY IN Anywhere # AntiScanner-Block\n%.0s' 1 2
            ;;
        '--force delete 2') : ;;
        'prepend allow proto tcp to any port 23456 comment kto-ssh-open')
            printf '1\n' > "$ssh_state"
            ;;
        *) return 1 ;;
    esac
}
install_antiscanner background >/dev/null
: > "$events"
( source "$ANTISCANNER_SCRIPT" )
[[ "$(cat "$ssh_state")" == 1 ]]
lock_line=$(grep -n '^flock -w ' "$events" | cut -d: -f1)
write_line=$(grep -n '^ufw --force delete ' "$events" | cut -d: -f1)
(( lock_line < write_line ))
! grep -q '^ufw insert .* deny ' "$events"
grep -Fq '[SKIP] blacklist unchanged' "$ANTISCANNER_LOG_FILE"
''')


if __name__ == "__main__":
    unittest.main()
