import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
KTO = (ROOT / "kto.sh").read_text(encoding="utf-8")
MENU_ENGINE = KTO[KTO.index("MENU_LABELS=()"):KTO.index("stage() {")]
FUNCTIONS = MENU_ENGINE + "\n" + KTO[KTO.index("torrent_guard_installed() {"):KTO.index("server_cleanup_menu() {")]


class TorrentMenuTests(unittest.TestCase):
    def setUp(self):
        self.bash = shutil.which("bash")
        if not self.bash:
            self.skipTest("bash unavailable")
        self.temporary = tempfile.TemporaryDirectory(prefix="kto-torrent-menu-")
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name)
        self.trace = self.path / "trace"
        self.prefix = self.path / "guard"
        self.config = self.path / "config.json"
        self.status = self.path / "status.json"
        self.settings = {"mode": "enforce", "interfaces": ["eth0"], "ttl": 600,
                         "protected_udp": [8443], "exempt_ips": ["192.0.2.1"]}
        self.cli = self.path / "cli"
        self.cli.write_text("""#!/usr/bin/env bash
printf 'CLI %s\n' "$1" >> "$TEST_TRACE"
case "$1" in
    enforce) exit "${TEST_ENFORCE_RC:-0}" ;;
    observe)
        if [[ "${TEST_OBSERVE_ONCE:-0}" == 1 ]] && (( $(grep -c '^CLI observe$' "$TEST_TRACE") > 1 )); then
            exit 1
        fi
        exit "${TEST_OBSERVE_RC:-0}"
        ;;
    status) exit "${TEST_STATUS_RC:-0}" ;;
esac
""", encoding="utf-8")
        self.cli.chmod(0o755)
        (self.path / "installer").write_text("""#!/usr/bin/env bash
printf 'INSTALL %s\n' "$*" >> "$TEST_TRACE"
printf 'SSH %s\n' "$SSH_CONNECTION" >> "$TEST_TRACE"
exit "${TEST_INSTALL_RC:-0}"
""", encoding="utf-8")
        (self.path / "updater").write_text("""import os
import sys
with open(os.environ['TEST_TRACE'], 'a', encoding='utf-8') as output:
    output.write('UPDATE\\n')
sys.exit(int(os.environ.get('TEST_UPDATE_RC', '0')))
""", encoding="utf-8")
        self.env = dict(os.environ, TEST_ROOT=self.path.as_posix(), TEST_TRACE=self.trace.as_posix(),
                        TEST_PYTHON=Path(sys.executable).as_posix(), PYTHONUTF8="1")

    def installed(self, mode="enforce", version=2):
        (self.prefix / "capture").mkdir(parents=True)
        (self.prefix / ".owner").write_text("kto-torrent-guard-v1\n", encoding="utf-8")
        (self.prefix / "guard.py").write_text("# test helper\n", encoding="utf-8")
        (self.prefix / "capture/eth0.conf").write_text("# capture\n", encoding="utf-8")
        self.settings["mode"] = mode
        self.config.write_text(json.dumps(self.settings), encoding="utf-8")
        self.status.write_text(json.dumps({"version": version, "block_scope": "connection"}), encoding="utf-8")

    def run_bash(self, command, input_text="", expected=0, extra=""):
        harness = r'''
set -Eeuo pipefail
SUDO=()
TORRENT_GUARD_PREFIX="$TEST_ROOT/guard"
TORRENT_GUARD_CONFIG="$TEST_ROOT/config.json"
TORRENT_GUARD_CLI="$TEST_ROOT/cli"
TORRENT_GUARD_STATUS="$TEST_ROOT/status.json"
SSH_CONNECTION='192.0.2.1 12345 198.51.100.1 22'
BOLD= DIM= PURPLE= GREEN= NC=
header() { :; }
need_root() { :; }
stage() { printf 'STAGE %s\n' "$*"; }
warn() { printf 'WARN %s\n' "$*"; }
fail() { printf 'FAIL %s\n' "$*"; }
ok() { printf 'OK %s\n' "$*"; }
sleep() { :; }
python3() { "$TEST_PYTHON" "$@"; }
run_bounded_command() { shift; "$@"; }
run_systemctl_bounded() {
    printf 'SYSTEMCTL %s\n' "$*" >> "$TEST_TRACE"
    if [[ "$2" == is-active ]]; then return "${TEST_ACTIVE_RC:-0}"; fi
    return "${TEST_SYSTEMCTL_RC:-0}"
}
install_asset_file() {
    printf 'FETCH %s %s\n' "$1" "$4" >> "$TEST_TRACE"
    printf '%s\n' "$2" > "$TEST_ROOT/asset-path"
    [[ "${TEST_FETCH_RC:-0}" == 0 ]] || return 1
    if [[ "$1" == *.py ]]; then
        cp "$TEST_ROOT/updater" "$2"
    else
        cp "$TEST_ROOT/installer" "$2"
    fi
}
''' + FUNCTIONS + "\n" + extra + "\n" + command
        path = self.path / "harness.sh"
        path.write_text(harness, encoding="utf-8", newline="\n")
        run = subprocess.run([self.bash, path.as_posix()], input=input_text.encode("utf-8"), env=self.env,
                             cwd=ROOT, capture_output=True, timeout=25)
        run.stdout = run.stdout.decode("utf-8", errors="replace")
        run.stderr = run.stderr.decode("utf-8", errors="replace")
        self.assertEqual(run.returncode, expected, run.stdout + run.stderr)
        return run

    def trace_lines(self):
        return self.trace.read_text(encoding="utf-8").splitlines() if self.trace.exists() else []

    def test_main_menu_and_direct_entrypoint(self):
        self.assertIn('labels+=("Торрент-блокер (nDPI, выходная нода)")', KTO)
        self.assertIn('torrent-guard) torrent_guard_menu || true', KTO)
        main = KTO[KTO.index("main() {"):]
        self.assertLess(main.index("torrent-guard|torrent-blocker)"), main.index("prepare_runtime_tmpdir"))
        self.assertIn('torrent_guard_menu "${2:-menu}"', main)
        optimize = KTO[KTO.index("optimize_system() {"):].split("\n}\n", 1)[0]
        self.assertNotIn("torrent_guard_setup", optimize)

    def test_direct_entrypoint_skips_other_startup_mutations(self):
        main = KTO[KTO.index("main() {"):].removesuffix('main "$@"\n')
        self.run_bash("main torrent-guard status", extra=main + r'''
init_log() { :; }
ensure_utf8_locale() { :; }
torrent_guard_menu() { [[ "$1" == status ]]; }
prepare_runtime_tmpdir() { exit 91; }
startup_storage_preflight() { exit 92; }
''')

    def test_main_menu_item_selects_guard_in_node_and_whitelist_modes(self):
        menu = re.search(r"(?ms)^menu\(\) \{.*?(?=^main\(\) \{)", KTO).group(0)
        extra = menu + r'''
header() { :; }
node_profile_label() { echo combined; }
node_profile_includes_reality() { return 0; }
node_profile_includes_hysteria2() { return 0; }
mobile443_lte_configured() { return 1; }
torrent_guard_menu() { echo SELECTED-GUARD; }
BOLD= DIM= PURPLE= GREEN= NC=
MACHINE_MODE=$TEST_MODE
'''
        for mode in ("node", "whitelist", "panel"):
            with self.subTest(mode=mode):
                self.env["TEST_MODE"] = mode
                run = self.run_bash("menu", "0\n", extra=extra)
                proxy_branch = re.search(r"(?m)^(\d+)\) Прокси и фильтры", run.stdout)
                if mode == "panel":
                    self.assertIsNone(proxy_branch)
                    self.assertNotIn("Торрент-блокер", run.stdout)
                else:
                    self.assertIsNotNone(proxy_branch)
                    branch_run = self.run_bash("menu", f"{proxy_branch.group(1)}\n0\n0\n", extra=extra)
                    guard_choice = re.search(r"(?m)^(\d+)\) Торрент-блокер", branch_run.stdout)
                    self.assertIsNotNone(guard_choice)
                    selected = self.run_bash(
                        "menu",
                        f"{proxy_branch.group(1)}\n{guard_choice.group(1)}\n0\n0\n",
                        extra=extra,
                    )
                    self.assertIn("SELECTED-GUARD", selected.stdout)

    def test_owner_marker_is_required(self):
        self.installed()
        (self.prefix / ".owner").write_text("other-program\n", encoding="utf-8")
        self.run_bash("torrent_guard_menu stop", expected=1)
        self.assertEqual(self.trace_lines(), [])

    def test_status_works_without_downloading_anything(self):
        self.installed()
        self.run_bash("torrent_guard_menu status")
        self.assertEqual(self.trace_lines(), ["CLI status"])

    def test_fresh_install_passes_interfaces_udp_and_ssh_context(self):
        self.run_bash("torrent_guard_menu install", "eth0,warp\n8443 9443\n")
        trace = self.trace_lines()
        self.assertIn("FETCH scripts/install-torrent-guard.sh bounded", trace)
        self.assertIn("INSTALL --mode observe --interface eth0 --interface warp --protect-udp 8443 --protect-udp 9443", trace)
        self.assertIn("SSH 192.0.2.1 12345 198.51.100.1 22", trace)
        self.assertNotIn("CLI enforce", trace)
        self.run_bash('[[ ! -e "$(cat "$TEST_ROOT/asset-path")" ]]')

    def test_empty_inputs_keep_installer_auto_detection(self):
        self.run_bash("torrent_guard_menu install", "\n\n")
        self.assertIn("INSTALL --mode observe", self.trace_lines())

    def test_invalid_wizard_inputs_never_download_or_execute(self):
        for text in ("lo\n\n", "eth0;reboot\n\n", "eth0\n0\n", "eth0\n65536\n", "eth0\n--help\n"):
            with self.subTest(text=text):
                self.run_bash("torrent_guard_menu install", text, expected=1)
                self.assertEqual(self.trace_lines(), [])

    def test_cancel_enforcement_before_download_or_changes(self):
        self.run_bash("torrent_guard_menu setup", "n\n")
        self.assertEqual(self.trace_lines(), [])

    def test_install_failure_does_not_enable(self):
        self.env["TEST_INSTALL_RC"] = "1"
        self.run_bash("torrent_guard_menu setup", "y\n\n\n", expected=1)
        self.assertNotIn("CLI enforce", self.trace_lines())

    def test_fresh_setup_enables_only_after_the_installer(self):
        self.run_bash("torrent_guard_menu setup", "y\n\n\n", extra=r'''
torrent_guard_enable() { printf 'ENABLE\n' >> "$TEST_TRACE"; }
''')
        trace = self.trace_lines()
        self.assertLess(trace.index("INSTALL --mode observe"), trace.index("ENABLE"))

    def test_download_failure_does_not_disable_running_guard(self):
        self.installed()
        self.env["TEST_FETCH_RC"] = "1"
        self.run_bash("torrent_guard_menu setup", "y\n", expected=1)
        self.assertEqual(self.trace_lines(), ["FETCH scripts/tune-torrent-capture.py bounded"])

    def test_invalid_update_syntax_does_not_change_mode(self):
        self.installed()
        (self.path / "updater").write_text("not python @@@\n", encoding="utf-8")
        self.run_bash("torrent_guard_menu update", expected=1)
        self.assertEqual(self.trace_lines(), ["FETCH scripts/tune-torrent-capture.py bounded"])

    def test_update_disables_first_and_only_enables_after_success(self):
        self.installed()
        self.run_bash("torrent_guard_menu setup", "y\n")
        trace = self.trace_lines()
        self.assertLess(trace.index("CLI observe"), trace.index("UPDATE"))
        self.assertLess(trace.index("UPDATE"), trace.index("CLI enforce"))
        self.assertNotIn("FETCH scripts/install-torrent-guard.sh bounded", trace)

    def test_failed_update_never_reenables(self):
        self.installed()
        self.env["TEST_UPDATE_RC"] = "1"
        self.run_bash("torrent_guard_menu setup", "y\n", expected=1)
        trace = self.trace_lines()
        self.assertIn("CLI observe", trace)
        self.assertIn("UPDATE", trace)
        self.assertNotIn("CLI enforce", trace)

    def test_unacknowledged_observe_aborts_before_update(self):
        self.installed()
        self.env["TEST_OBSERVE_RC"] = "1"
        self.run_bash("torrent_guard_menu setup", "y\n", expected=1)
        self.assertNotIn("UPDATE", self.trace_lines())
        self.assertNotIn("CLI enforce", self.trace_lines())

    def test_stopped_guard_is_set_to_observe_and_other_config_is_preserved(self):
        self.installed()
        self.env["TEST_ACTIVE_RC"] = "3"
        self.run_bash("torrent_guard_menu observe")
        expected = dict(self.settings, mode="observe")
        self.assertEqual(json.loads(self.config.read_text(encoding="utf-8")), expected)
        self.assertIn("SYSTEMCTL 40 enable --now kto-torrent-guard.service", self.trace_lines())
        self.assertIn("SYSTEMCTL 40 enable --now kto-torrent-capture@eth0.service", self.trace_lines())

    def test_failed_capture_start_prevents_enforce(self):
        self.installed()
        self.env["TEST_SYSTEMCTL_RC"] = "1"
        self.run_bash("torrent_guard_menu enforce", "y\n", expected=1)
        self.assertNotIn("CLI enforce", self.trace_lines())

    def test_old_peer_guard_cannot_be_enabled_without_update(self):
        self.installed(version=1)
        self.run_bash("torrent_guard_menu enforce", "y\n", expected=1)
        self.assertIn("CLI observe", self.trace_lines())
        self.assertNotIn("CLI enforce", self.trace_lines())

    def test_scope_is_checked_after_resuming_the_observer(self):
        self.installed()
        self.run_bash("torrent_guard_menu enforce", "y\n", expected=1, extra=r'''
torrent_guard_observe() {
    printf '{"version": 1, "block_scope": "peer"}\n' > "$TORRENT_GUARD_STATUS"
}
''')
        self.assertNotIn("CLI enforce", self.trace_lines())

    def test_failed_enforce_falls_back_to_observe(self):
        self.installed()
        self.env["TEST_ENFORCE_RC"] = "1"
        self.run_bash("torrent_guard_menu enforce", "y\n", expected=1)
        trace = self.trace_lines()
        self.assertEqual(trace[-2:], ["CLI enforce", "CLI observe"])

    def test_failed_enforce_and_failed_recovery_request_a_stop(self):
        self.installed()
        self.env.update(TEST_ENFORCE_RC="1", TEST_OBSERVE_ONCE="1")
        self.run_bash("torrent_guard_menu enforce", "y\n", expected=1)
        self.assertEqual(self.trace_lines()[-3:], ["CLI enforce", "CLI observe", "CLI stop"])

    def test_removal_needs_confirmation_and_installed_owner(self):
        self.installed()
        self.run_bash("torrent_guard_menu uninstall", "n\n")
        self.assertEqual(self.trace_lines(), [])
        self.run_bash("torrent_guard_menu uninstall", "y\n")
        self.assertEqual(self.trace_lines(), ["CLI uninstall"])

    def test_eof_leaves_menu_without_side_effects(self):
        self.run_bash("torrent_guard_menu", "")
        self.assertEqual(self.trace_lines(), [])

    def test_numbered_actions_stay_in_sync(self):
        menu = FUNCTIONS[FUNCTIONS.index("torrent_guard_menu() {"):]
        self.assertIn(
            'MENU_ACTIONS=("install" "setup" "enforce" "observe" "status" "logs" "stop" "uninstall")',
            menu,
        )
        for action in ("install", "setup", "enforce", "observe", "status", "logs", "stop", "uninstall"):
            self.assertRegex(menu, rf"{re.escape(action)}\) torrent_guard_menu {re.escape(action)} \|\| true")


if __name__ == "__main__":
    unittest.main()
