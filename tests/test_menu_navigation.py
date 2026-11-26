import os
import re
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which("bash")


def run_kto_bash(snippet: str, stdin_bytes: bytes = b"", env_extra=None, timeout: int = 20):
    env = os.environ.copy()
    env.setdefault("PYTHONUTF8", "1")
    if env_extra:
        env.update(env_extra)
    script = "set -Eeuo pipefail\nsource <(sed '/^main /d' kto.sh)\n" + snippet + "\n"
    return subprocess.run(
        [BASH, "-c", script],
        cwd=ROOT,
        input=stdin_bytes,
        capture_output=True,
        timeout=timeout,
        env=env,
        check=False,
    )


@unittest.skipUnless(BASH, "bash is unavailable")
class MenuNavigationTests(unittest.TestCase):
    def test_all_menus_have_at_most_nine_items_in_every_mode_and_profile(self):
        snippet = r'''
header() { :; }
need_root() { :; }
require_haproxy_mode() { :; }
require_whitelist_mode() { :; }
print_haproxy_routes() { echo "ROUTES"; }
print_haproxy_bandwidth_limits() { echo "BW"; }
print_mobile443_lte_status() { echo "LTE"; }
mobile443_lte_configured() { return 0; }
torrent_guard_installed() { return 0; }
SUDO=()
HAPROXY_CONFIG_FILE=/nonexistent
HAPROXY_GUARD_MANAGER=/nonexistent
BOLD= DIM= PURPLE= GREEN= YELLOW= RED= NC=

check_menu_limit() {
    local name="$1"
    local out count
    shift
    out="$("$@" <<< $'0\n')"
    count="$(printf '%s\n' "$out" | grep -cE '^[1-9]\) ' || true)"
    printf '%s=%s\n' "$name" "$count"
    (( count >= 1 && count <= 9 ))
    ! printf '%s\n' "$out" | grep -qE '^[1-9][0-9]+\) '
}

for mode_profile in "node:reality" "node:hysteria2" "node:reality_hysteria2" "whitelist:" "panel:"; do
    MACHINE_MODE="${mode_profile%%:*}"
    NODE_PROFILE="${mode_profile#*:}"
    check_menu_limit "root_${MACHINE_MODE}_${NODE_PROFILE}" menu
    check_menu_limit "settings_${MACHINE_MODE}_${NODE_PROFILE}" settings_menu
    if [[ "$MACHINE_MODE" == "node" ]]; then
        check_menu_limit "node_stack_${NODE_PROFILE}" node_stack_menu
    fi
    if [[ "$MACHINE_MODE" != "panel" ]]; then
        check_menu_limit "proxy_${MACHINE_MODE}_${NODE_PROFILE}" proxy_menu
        check_menu_limit "net_${MACHINE_MODE}_${NODE_PROFILE}" network_diag_menu
        check_menu_limit "ip_${MACHINE_MODE}_${NODE_PROFILE}" additional_ip_menu
    else
        check_menu_limit "panel_collector" panel_collector_menu
    fi
done

MACHINE_MODE="whitelist"
NODE_PROFILE=""
routes_file="$(mktemp)"
trap 'rm -f "$routes_file"' EXIT
check_menu_limit "haproxy_root" haproxy_menu
check_menu_limit "haproxy_bulk" haproxy_routes_bulk_menu "$routes_file"
check_menu_limit "haproxy_maint" haproxy_maintenance_menu "$routes_file"
check_menu_limit "haproxy_bw" haproxy_bandwidth_menu
check_menu_limit "haproxy_guard" haproxy_guard_menu
check_menu_limit "stats_push" stats_push_menu
check_menu_limit "torrent_guard" torrent_guard_menu
check_menu_limit "mobile443_lte" mobile443_lte_menu
'''
        res = run_kto_bash(snippet)
        out = res.stdout.decode("utf-8", errors="replace")
        err = res.stderr.decode("utf-8", errors="replace")
        self.assertEqual(res.returncode, 0, out + err)
        counts = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
        self.assertEqual(counts["root_node_reality"], "8")
        self.assertEqual(counts["root_whitelist_"], "8")
        self.assertEqual(counts["root_panel_"], "4")
        self.assertEqual(counts["haproxy_root"], "6")
        self.assertEqual(counts["haproxy_bulk"], "4")
        self.assertEqual(counts["haproxy_maint"], "6")
        self.assertEqual(counts["net_node_reality"], "8")

    def test_interactive_instant_digit_selection_requires_no_enter(self):
        snippet = r'''
header() { :; }
BOLD= DIM= PURPLE= GREEN= YELLOW= RED= NC=
MENU_LABELS=("First" "Second" "Third")
MENU_ACTIONS=("one" "two" "three")
# Press out-of-range '9' (ignored), then '2' with NO trailing newline/Enter
menu_select "TEST" "Назад"
printf 'ACTION=%s INDEX=%s\n' "$MENU_SELECTED_ACTION" "$MENU_SELECTED_INDEX"
'''
        res = run_kto_bash(snippet, stdin_bytes=b"92", env_extra={"KTO_MENU_INTERACTIVE": "1"})
        out = res.stdout.decode("utf-8", errors="replace")
        err = res.stderr.decode("utf-8", errors="replace")
        self.assertEqual(res.returncode, 0, out + err)
        self.assertIn("ACTION=two INDEX=1", out)

    def test_interactive_arrow_keys_wrap_and_confirm_with_enter(self):
        snippet = r'''
header() { :; }
BOLD= DIM= PURPLE= GREEN= YELLOW= RED= NC=
MENU_LABELS=("First" "Second" "Third")
MENU_ACTIONS=("one" "two" "three")
menu_select "TEST" "Назад"
printf 'A1=%s\n' "$MENU_SELECTED_ACTION"
menu_select "TEST" "Назад"
printf 'A2=%s\n' "$MENU_SELECTED_ACTION"
menu_select "TEST" "Назад"
printf 'A3=%s\n' "$MENU_SELECTED_ACTION"
'''
        # 1) Down, Down, Enter -> "three"
        # 2) Up (wraps to 0/Back), Enter -> "__back__"
        # 3) PgUp (\x1b[5~ must be drained and NOT trigger digit 5!), Right arrow -> "one"
        stream = b"\x1b[B\x1b[B\r" + b"\x1b[A\r" + b"\x1b[5~\x1b[C"
        res = run_kto_bash(snippet, stdin_bytes=stream, env_extra={"KTO_MENU_INTERACTIVE": "1"})
        out = res.stdout.decode("utf-8", errors="replace")
        err = res.stderr.decode("utf-8", errors="replace")
        self.assertEqual(res.returncode, 0, out + err)
        self.assertIn("A1=three", out)
        self.assertIn("A2=__back__", out)
        self.assertIn("A3=one", out)

    def test_interactive_escape_q_left_arrow_and_zero_go_back(self):
        snippet = r'''
header() { :; }
BOLD= DIM= PURPLE= GREEN= YELLOW= RED= NC=
MENU_LABELS=("Only" "Two")
MENU_ACTIONS=("a" "b")
for i in 1 2 3 4; do
    menu_select "TEST" "Назад"
    printf 'R%d=%s\n' "$i" "$MENU_SELECTED_ACTION"
done
'''
        # q, 0, Left arrow (\x1b[D), plain Esc (\x1b at EOF)
        res = run_kto_bash(snippet, stdin_bytes=b"q0\x1b[D\x1b", env_extra={"KTO_MENU_INTERACTIVE": "1"})
        out = res.stdout.decode("utf-8", errors="replace")
        err = res.stderr.decode("utf-8", errors="replace")
        self.assertEqual(res.returncode, 0, out + err)
        for i in range(1, 5):
            self.assertIn(f"R{i}=__back__", out)

    def test_interactive_branch_traversal_in_node_and_haproxy_menus(self):
        snippet = r'''
header() { :; }
need_root() { :; }
require_haproxy_mode() { :; }
print_haproxy_routes() { echo "ROUTES"; }
SUDO=()
HAPROXY_CONFIG_FILE=/nonexistent
BOLD= DIM= PURPLE= GREEN= YELLOW= RED= NC=
MACHINE_MODE="node"
NODE_PROFILE="reality_hysteria2"
issue_ssl_certificate() { echo "CALLED:ssl"; }
run_mtr_batch() { echo "CALLED:mtr-batch"; }
enable_ssh_password() { echo "CALLED:ssh-password"; }
add_haproxy_pool_route() { echo "CALLED:haproxy-pool"; }
diagnose_haproxy() { echo "CALLED:haproxy-diagnose"; }

# Stream:
# - '3' (Стек ноды) -> '4' (SSL, paused with 'x') -> 'q' (back to root)
# - '5' (Сеть и диагностика) -> '4' (TCP-MTR, paused with 'x') -> '0' (back to root)
# - '8' (Система и SSH) -> '3' (SSH password, paused with 'x') -> 'q' (back to root)
# - '4' (Прокси и фильтры) -> '1' (HAProxy) -> '4' (bulk) -> '1' (pool, paused with 'x')
#   -> 'q' (back to haproxy) -> '6' (maintenance) -> '2' (diagnose, paused with 'x')
#   -> 'q' (back to haproxy) -> '0' (back to proxy) -> 'q' (back to root) -> '0' (exit)
menu
'''
        stream = b"34xq54x083xq4141xq62xq0q0"
        res = run_kto_bash(snippet, stdin_bytes=stream, env_extra={"KTO_MENU_INTERACTIVE": "1"})
        out = res.stdout.decode("utf-8", errors="replace")
        err = res.stderr.decode("utf-8", errors="replace")
        self.assertEqual(res.returncode, 0, out + err)
        for marker in (
            "CALLED:ssl",
            "CALLED:mtr-batch",
            "CALLED:ssh-password",
            "CALLED:haproxy-pool",
            "CALLED:haproxy-diagnose",
        ):
            self.assertIn(marker, out)

    def test_non_tty_pipeline_navigation_and_select_legacy_aliases(self):
        snippet = r'''
header() { :; }
need_root() { :; }
save_machine_mode() { :; }
BOLD= DIM= PURPLE= GREEN= YELLOW= RED= NC=

select_machine_mode <<< $'node\nhybrid\n'
printf 'MODE=%s PROFILE=%s\n' "$MACHINE_MODE" "$NODE_PROFILE"

MACHINE_MODE="panel"
NODE_PROFILE=""
stats_collector_status() { echo "CALLED:collector-status"; }
network_test() { echo "CALLED:net-test"; }
# In panel: 2 (Коллектор статистики) -> 2 (Статус коллектора) -> 0 (назад) -> 3 (Тест сети) -> 0 (выход)
menu <<< $'2\n2\n0\n3\n0\n'
'''
        res = run_kto_bash(snippet)
        out = res.stdout.decode("utf-8", errors="replace")
        err = res.stderr.decode("utf-8", errors="replace")
        self.assertEqual(res.returncode, 0, out + err)
        self.assertIn("MODE=node PROFILE=reality_hysteria2", out)
        self.assertIn("CALLED:collector-status", out)
        self.assertIn("CALLED:net-test", out)

    def test_interactive_inline_choice_accepts_only_valid_digits_and_escape(self):
        snippet = r'''
menu_read_inline_choice "12"
printf 'C1=%s\n' "$MENU_INLINE_CHOICE"
menu_read_inline_choice "12"
printf 'C2=%s\n' "$MENU_INLINE_CHOICE"
'''
        # First call: '9' (invalid, ignored), '3' (invalid, ignored), '2' (valid)
        # Second call: 'q' -> '0'
        res = run_kto_bash(snippet, stdin_bytes=b"932q", env_extra={"KTO_MENU_INTERACTIVE": "1"})
        out = res.stdout.decode("utf-8", errors="replace")
        err = res.stderr.decode("utf-8", errors="replace")
        self.assertEqual(res.returncode, 0, out + err)
        self.assertIn("C1=2", out)
        self.assertIn("C2=0", out)


if __name__ == "__main__":
    unittest.main()
