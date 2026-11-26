import os
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
KTO = (ROOT / "kto.sh").read_text(encoding="utf-8")
CHECK_SH = (ROOT / "scripts" / "check.sh").read_text(encoding="utf-8")
BASH = next(
    (
        str(path)
        for path in (
            Path(shutil.which("bash") or "missing-bash"),
            Path(r"C:\Program Files\Git\bin\bash.exe"),
            Path(r"C:\Program Files (x86)\Git\bin\bash.exe"),
        )
        if path.is_file()
    ),
    None,
)


def run_kto_bash(snippet: str, *, timeout: int = 30) -> subprocess.CompletedProcess:
    assert BASH is not None
    env = os.environ.copy()
    env["KTO_TEST_PYTHON"] = sys.executable.replace("\\", "/")
    script = "set -Eeuo pipefail\nsource <(sed '/^main /d' kto.sh)\n" + snippet
    return subprocess.run(
        [BASH, "-lc", script],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
        check=False,
    )


class CleanupFixesTests(unittest.TestCase):
    def test_version_pinned_and_build_v351_synced(self):
        self.assertIn('SCRIPT_VERSION="1.4.8.8"', KTO)
        self.assertNotIn("1.4.8.10", KTO)
        self.assertIn('SCRIPT_BUILD="v351"', KTO)
        self.assertIn('KTO_HAPROXY_FIREWALL_BUILD="v351"', KTO)
        self.assertNotIn("v349", KTO)
        self.assertNotIn("v350", KTO)

    def test_check_sh_covers_all_shell_and_python_scripts(self):
        self.assertIn("for script in scripts/*.sh; do", CHECK_SH)
        self.assertIn('Path("scripts").glob("*.py")', CHECK_SH)

    def test_init_log_does_not_chmod_world_writable(self):
        self.assertNotIn("chmod 0666", KTO)

    @unittest.skipUnless(BASH, "bash is unavailable")
    def test_ssl_failure_restores_stopped_containers_and_closes_port_80(self):
        res = run_kto_bash(
            r'''
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
SUDO=()
LOG_FILE="$root/kto.log"
CERT_DIR="$root/certs"
events="$root/events"
: > "$events"

apt_update_quiet() { :; }
apt_install_quiet() { :; }
command_exists() { [[ "$1" == ufw || "$1" == docker ]]; }
container_running() { [[ "$1" == remnanode || "$1" == caddy-selfsteal ]]; }
test() {
    if [[ "${1:-}" == -x && "${2:-}" == /root/.acme.sh/acme.sh ]]; then
        return 0
    fi
    builtin test "$@"
}
systemctl() { :; }
ufw() {
    local IFS=' '
    printf 'ufw %s\n' "$*" >> "$events"
    if [[ "$1" == status ]]; then
        printf 'Status: active\n443/tcp ALLOW IN Anywhere\n'
    fi
}
docker() {
    local IFS=' '
    printf 'docker %s\n' "$*" >> "$events"
}
env() {
    local IFS=' '
    if [[ "$*" == *"--issue"* ]]; then
        printf 'acme issue fail\n' >> "$events"
        return 1
    fi
    printf 'env %s\n' "$*" >> "$events"
    return 0
}

if do_issue_ssl_certificate example.com >/dev/null 2>&1; then
    echo "expected failure" >&2
    exit 1
fi

grep -Fxq 'ufw allow 80/tcp' "$events"
grep -Fxq 'docker stop remnanode' "$events"
grep -Fxq 'docker stop caddy-selfsteal' "$events"
grep -Fxq 'docker start remnanode' "$events"
grep -Fxq 'docker start caddy-selfsteal' "$events"
grep -Fxq 'ufw --force delete allow 80/tcp' "$events"
! grep -Eq '^docker start[[:space:]]*$' "$events"
'''
        )
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    @unittest.skipUnless(BASH, "bash is unavailable")
    def test_ssl_success_with_no_running_containers_does_not_call_empty_docker_start(self):
        res = run_kto_bash(
            r'''
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
SUDO=()
LOG_FILE="$root/kto.log"
CERT_DIR="$root/certs"
events="$root/events"
: > "$events"

apt_update_quiet() { :; }
apt_install_quiet() { :; }
command_exists() { [[ "$1" == docker ]]; }
container_running() { return 1; }
test() {
    if [[ "${1:-}" == -x && "${2:-}" == /root/.acme.sh/acme.sh ]]; then
        return 0
    fi
    builtin test "$@"
}
systemctl() { :; }
docker() {
    local IFS=' '
    printf 'docker %s\n' "$*" >> "$events"
}
env() { return 0; }

do_issue_ssl_certificate example.com >/dev/null 2>&1
! grep -q '^docker start' "$events"
'''
        )
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    @unittest.skipUnless(BASH, "bash is unavailable")
    def test_parallel_run_tasks_fails_on_critical_and_allows_optional(self):
        res = run_kto_bash(
            r'''
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
LOG_FILE="$root/kto.log"
ok_task() { echo "ok"; }
bad_task() { echo "boom"; return 7; }

# Critical failure must propagate non-zero exit code.
if parallel_run_tasks "good" ok_task "network limits" bad_task >/dev/null 2>&1; then
    echo "expected critical parallel failure" >&2
    exit 1
fi
grep -Fq '[ERROR] parallel block failed in critical tasks:' "$LOG_FILE"

# Allowed optional failure (kernel) must succeed with warning.
: > "$LOG_FILE"
KTO_PARALLEL_ALLOW_FAIL="kernel" parallel_run_tasks "kernel" bad_task "network limits" ok_task >/dev/null 2>&1
grep -Fq '[WARN] parallel block finished with non-critical errors:' "$LOG_FILE"
'''
        )
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    @unittest.skipUnless(BASH, "bash is unavailable")
    def test_haproxy_remote_apply_reports_missing_source_route_specifically(self):
        res = run_kto_bash(
            r'''
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
SUDO=()
LOG_FILE="$root/kto.log"
HAPROXY_CONFIG_FILE="$root/haproxy.cfg"
need_root() { :; }
command_exists() { [[ "$1" == jq ]] || command -v "$1" >/dev/null 2>&1; }
jq() {
    case "${1:-}" in
        -e) return 0 ;;
        -r)
            if [[ "${2:-}" == length ]]; then
                printf '1\n'
            else
                printf '443\t192.0.2.10:443\texample.com\t198.51.100.5\tdefault\t*\t0\n'
            fi
            ;;
        *) return 0 ;;
    esac
}
haproxy_route_ip_for_source() { return 1; }
canonicalize_haproxy_runtime_source_ip() { printf '%s\n' "$1"; }

err=$(printf '[{"port":443,"targets":["192.0.2.10:443"],"sni":["example.com"],"source_ip":"198.51.100.5"}]\n' \
    | haproxy_remote_apply_json 2>&1 >/dev/null || true)
grep -Fq 'Для выходного IP 198.51.100.5 нет рабочего локального source-route' <<< "$err"
'''
        )
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    @unittest.skipUnless(BASH, "bash is unavailable")
    def test_stats_collector_status_respects_tls_verify_setting(self):
        res = run_kto_bash(
            r'''
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
SUDO=()
LOG_FILE="$root/kto.log"
STATS_COLLECTOR_CONFIG="$root/collector.conf"
STATS_COLLECTOR_STATE_DIR="$root/state"
STATS_COLLECTOR_SCRIPT="$root/collector.py"
mkdir -p "$STATS_COLLECTOR_STATE_DIR"
cat > "$STATS_COLLECTOR_SCRIPT" <<'SH'
#!/usr/bin/env bash
echo "tok123"
SH
chmod +x "$STATS_COLLECTOR_SCRIPT"

"$KTO_TEST_PYTHON" - "$STATS_COLLECTOR_STATE_DIR/ip_limit.sqlite" <<'PY'
import sqlite3, sys
conn = sqlite3.connect(sys.argv[1])
conn.execute("CREATE TABLE ip_limit_events (user TEXT, last_seen INTEGER)")
conn.execute("INSERT INTO ip_limit_events VALUES ('42', 1000)")
conn.commit()
conn.close()
PY

header() { :; }
require_panel_mode() { :; }
need_root() { :; }
service_ok() { echo 1; }
command_exists() { [[ "$1" == curl ]]; }
python3() { "$KTO_TEST_PYTHON" "$@"; }

curl_log="$root/curl.log"
curl() {
    local IFS=' '
    printf '%s\n' "$*" >> "$curl_log"
    if [[ "$*" == *"/health"* ]]; then
        printf '{"ok":true}'
        return 0
    fi
    local out=""
    local -a args=("$@")
    for ((i=0; i<${#args[@]}; i++)); do
        if [[ "${args[$i]}" == -o ]]; then out="${args[$((i+1))]}"; fi
    done
    [[ -n "$out" ]] && printf '{"username":"alice","status":"ACTIVE"}' > "$out"
    printf '200'
}

cat > "$STATS_COLLECTOR_CONFIG" <<EOF
KTO_COLLECTOR_LISTEN_HOST="127.0.0.1"
KTO_COLLECTOR_LISTEN_PORT="1337"
KTO_COLLECTOR_REMNA_API_URL="https://panel.example.com"
KTO_COLLECTOR_REMNA_API_TOKEN="secret-token"
KTO_COLLECTOR_REMNA_API_INSECURE="0"
EOF
: > "$curl_log"
stats_collector_status >/dev/null
grep -Fq 'https://panel.example.com/api/users/by-id/42' "$curl_log"
! grep -Fq ' -k ' "$curl_log"

cat > "$STATS_COLLECTOR_CONFIG" <<EOF
KTO_COLLECTOR_LISTEN_HOST="127.0.0.1"
KTO_COLLECTOR_LISTEN_PORT="1337"
KTO_COLLECTOR_REMNA_API_URL="https://panel.example.com"
KTO_COLLECTOR_REMNA_API_TOKEN="secret-token"
KTO_COLLECTOR_REMNA_API_INSECURE="1"
EOF
: > "$curl_log"
stats_collector_status >/dev/null
grep -Fq ' -k ' "$curl_log"
'''
        )
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)


if __name__ == "__main__":
    unittest.main()
