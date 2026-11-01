import shutil
import subprocess
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
trap 'rm -rf "$root"' EXIT
SUDO=()
LOG_FILE="$root/kto.log"
KTO_SSH_PASSWORD_MODE_FILE="$root/no-password-mode"
events="$root/events"
: > "$events"
active_state=active
restart_result=0
changed=1
cmd() {
    local IFS=' '
    printf 'cmd %s\n' "$*" >> "$events"
    if [[ "${1:-}" == install && "${2:-}" == -d && "${*: -1}" == /run/sshd ]]; then
        touch "$root/runtime"
    fi
}
write_root_file_if_changed() {
    printf 'drop-in %s\n' "$1" >> "$events"
    cat > "$root/drop-in"
    ROOT_FILE_UPDATED="$changed"
}
run_systemctl_bounded() {
    local IFS=' '
    printf 'systemctl %s\n' "$*" >> "$events"
    case "${2:-}" in
        show) printf '%s\n' "$active_state" ;;
        restart)
            rm -f "$root/runtime"
            return "$restart_result"
            ;;
    esac
}
restore_optional_ssh_file() {
    printf 'restore %s\n' "$2" >> "$events"
}
remove_ufw_allow_rules_for_port() {
    printf 'ufw-remove %s\n' "$1" >> "$events"
}
'''


@unittest.skipUnless(BASH, "bash is unavailable")
class SshRuntimeRecoveryTests(unittest.TestCase):
    def run_harness(self, fragment):
        result = subprocess.run(
            [BASH, "-lc", HARNESS + "\n" + fragment], cwd=ROOT,
            capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_runtime_directory_is_root_owned_and_preserved_by_systemd(self):
        self.run_harness(r'''
ensure_ssh_runtime_directory ssh.service
[[ -e "$root/runtime" ]]
grep -Fxq 'RuntimeDirectoryPreserve=yes' "$root/drop-in"
grep -Fxq 'drop-in /etc/systemd/system/ssh.service.d/99-kto-runtime.conf' "$events"
grep -Fxq 'cmd install -d -o root -g root -m 0755 /run/sshd' "$events"
grep -Fxq 'systemctl 15 daemon-reload' "$events"
''')

    def test_unchanged_drop_in_does_not_reload_systemd(self):
        self.run_harness(r'''
changed=0
ensure_ssh_runtime_directory ssh
[[ -e "$root/runtime" ]]
! grep -q '^systemctl ' "$events"
''')

    def test_failed_rollback_restart_recreates_privsep_directory(self):
        self.run_harness(r'''
restart_result=1
rollback_ssh_migration "$root/backup" 1 0 1 0 ssh 0 0 21392 0
[[ -e "$root/runtime" ]]
[[ "$(grep -c '^restore ' "$events")" == 4 ]]
grep -Fxq 'systemctl 15 restart ssh' "$events"
grep -Fxq 'ufw-remove 21392' "$events"
last_runtime=$(grep -n '^cmd install -d ' "$events" | tail -1 | cut -d: -f1)
restart=$(grep -n '^systemctl 15 restart ' "$events" | cut -d: -f1)
(( last_runtime > restart ))
''')

    def test_already_failed_service_is_not_migrated_again(self):
        self.run_harness(r'''
active_state=failed
managed_ssh_changes_enabled() { return 0; }
command_exists() { [[ "$1" == sshd || "$1" == ssh-keygen ]]; }
ssh_service_name() { printf 'ssh\n'; }
print_ssh_failure_details() { printf 'diagnostics\n' >> "$events"; }
merge_root_authorized_keys() { : > "$1"; }
choose_managed_ssh_port() { printf 'port-changed\n' >> "$events"; }
if opt_ssh_root_access; then exit 1; fi
[[ -e "$root/runtime" ]]
grep -Fxq diagnostics "$events"
! grep -q '^keys-changed\|^port-changed\|^systemctl .*restart' "$events"
''')

    def test_failed_runtime_preparation_aborts_before_ssh_changes(self):
        self.run_harness(r'''
managed_ssh_changes_enabled() { return 0; }
command_exists() { [[ "$1" == sshd || "$1" == ssh-keygen ]]; }
ssh_service_name() { printf 'ssh\n'; }
write_root_file_if_changed() { cat >/dev/null; return 1; }
merge_root_authorized_keys() { : > "$1"; }
if opt_ssh_root_access; then exit 1; fi
! grep -q '^keys-changed\|^systemctl ' "$events"
''')


if __name__ == "__main__":
    unittest.main()
