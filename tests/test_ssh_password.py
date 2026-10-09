import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from test_kto_profiles import KTO, ROOT, bash_executable, function_body


SPEC = importlib.util.spec_from_file_location("kto_ssh_password", ROOT / "scripts/kto-ssh-password.py")
pw = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = pw
SPEC.loader.exec_module(pw)


def result(stdout="", rc=0, stderr=""):
    return subprocess.CompletedProcess([], rc, stdout, stderr)


def config(root=False):
    values = {"port": ["26195"], "listenaddress": ["0.0.0.0:26195", "[::]:26195"],
              "authorizedkeysfile": [".ssh/authorized_keys"], "usepam": ["yes"],
              "permitrootlogin": ["without-password"], "passwordauthentication": ["no"],
              "pubkeyauthentication": ["yes"], "authenticationmethods": ["any"]}
    if root:
        values.update(copy.deepcopy(pw.AUTH))
    return values


class FakeRunner:
    def __init__(self):
        self.calls = []
        self.shadow = ["root", "$y$old-hash", "20100", "0", "99999", "7", "", "", ""]
        self.old_shadow = list(self.shadow)
        self.fail_reload = self.fail_password = self.fail_syntax = False
        self.conflict = self.changed_port = self.locked_password = False
        self.password_input = None

    def run(self, args, *, data=None, secret=False, check=True):
        self.calls.append((args, data, secret))
        if args[:2] == ["getent", "passwd"]:
            return result("root:x:0:0:root:/root:/bin/bash\n")
        if args[:2] == ["getent", "shadow"]:
            return result(":".join(self.shadow) + "\n")
        if args[0] == "sshd":
            path = Path(args[args.index("-f") + 1])
            modified = pw.BEGIN in path.read_text()
            if "-t" in args:
                if modified and self.fail_syntax:
                    raise pw.PasswordError("bad candidate syntax")
                return result()
            user = args[-1].split(",")[0].split("=")[1]
            values = config(modified and user == "root" and not self.conflict)
            if modified and self.changed_port:
                values["port"] = ["22"]
            return result("\n".join(f"{key} {value}" for key, items in values.items() for value in items))
        if args[0] == "systemctl":
            if args[1] == "show":
                return result("yes\n")
            if args[1] == "reload" and self.fail_reload:
                self.fail_reload = False
                raise pw.PasswordError("reload failed")
            return result()
        if args[0] == "chpasswd":
            if "-e" in args:
                self.shadow[1] = data.strip().split(":", 1)[1]
            else:
                self.password_input = data
                self.shadow[1] = "!locked" if self.locked_password else "$y$new-hash"
                if self.fail_password:
                    raise pw.PasswordError("password failed")
            self.shadow[2] = "22222"
            return result()
        if args[0] == "chage":
            self.shadow[2] = args[2]
            return result()
        raise AssertionError(args)


class PureTests(unittest.TestCase):
    def test_password_entropy_and_stdin_safety(self):
        values = {pw.generate_password() for _ in range(100)}
        self.assertEqual(len(values), 100)
        for value in values:
            self.assertEqual(len(value), 28)
            self.assertTrue(any(c.islower() for c in value))
            self.assertTrue(any(c.isupper() for c in value))
            self.assertTrue(any(c.isdigit() for c in value))
            self.assertTrue(any(c in "!@%+=_-." for c in value))
            self.assertNotIn(":", value)
            self.assertNotIn("\n", value)

    def test_root_match_is_last_and_preserves_existing_global_config(self):
        original = "Port 26195\nInclude /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication no\n"
        rendered = pw.candidate_config(original)
        self.assertTrue(rendered.startswith(original))
        self.assertLess(rendered.index("Port 26195"), rendered.index("Match User root"))
        self.assertEqual(rendered.count("Match User root"), 1)
        self.assertEqual(rendered, pw.candidate_config(rendered))

    def test_malformed_or_nonfinal_managed_block_rejected(self):
        for source in (pw.BEGIN, pw.END, pw.END + "\n" + pw.BEGIN,
                       pw.BLOCK + "Port 22\n", pw.BLOCK + pw.BLOCK):
            with self.subTest(source=source), self.assertRaises(pw.PasswordError):
                pw.candidate_config(source)

    def test_existing_match_not_rewritten(self):
        source = "Port 22\nMatch User backup\n    ForceCommand internal-sftp\n"
        self.assertTrue(pw.candidate_config(source).startswith(source))

    def test_effective_root_auth_and_key_locations_preserved(self):
        pw.validate_candidate(config(), config(True), root=True)
        pw.validate_candidate(config(), config(), root=False)
        for key, value in (("passwordauthentication", ["no"]), ("pubkeyauthentication", ["no"]),
                           ("authenticationmethods", ["publickey,password"]),
                           ("authorizedkeysfile", ["none"]), ("port", ["22"])):
            changed = config(True)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(pw.PasswordError):
                pw.validate_candidate(config(), changed, root=True)

    def test_other_user_auth_cannot_change(self):
        with self.assertRaises(pw.PasswordError):
            pw.validate_candidate(config(), config(True), root=False)

    def test_connection_context_validates_ipv4_ipv6_and_ports(self):
        self.assertIn("lport=26195", pw.contexts("192.0.2.5 54321 198.51.100.5 26195")[-1])
        self.assertIn("addr=2001:db8::1", pw.contexts("2001:db8::1 54321 2001:db8::2 22")[-1])
        for value in ("one", "bad 44 198.51.100.1 22", "192.0.2.1 4 198.51.100.1 999999"):
            with self.assertRaises((pw.PasswordError, ValueError)):
                pw.contexts(value)

    def test_secret_error_does_not_leak_stdin_or_stderr(self):
        with mock.patch.object(pw.subprocess, "run", return_value=result(rc=1, stderr="SECRET")) as run:
            with self.assertRaises(pw.PasswordError) as caught:
                pw.Runner().run(["chpasswd"], data="root:SECRET\n", secret=True)
            self.assertNotIn("SECRET", str(caught.exception))
            self.assertEqual(run.call_args.args[0], ["chpasswd"])
            self.assertEqual(run.call_args.kwargs["input"], "root:SECRET\n")

    def test_expired_account_is_not_unlocked(self):
        runner = FakeRunner()
        runner.shadow[7] = "1"
        with self.assertRaisesRegex(pw.PasswordError, "просрочена"):
            pw.account_snapshot(runner)
        self.assertFalse(any(args[0] == "chpasswd" for args, _, _ in runner.calls))

    def test_reload_support_is_required(self):
        runner = mock.Mock()
        runner.run.side_effect = [result(), result("no\n")]
        with self.assertRaisesRegex(pw.PasswordError, "restart"):
            pw.active_service(runner)

    def test_custom_daemon_config_is_rejected(self):
        runner = mock.Mock()
        runner.run.return_value = result("123\n")
        for args in (b"/usr/sbin/sshd\0-D\0-f/etc/ssh/other.conf", b"sshd: /usr/sbin/sshd -D -o PasswordAuthentication=no"):
            with mock.patch.object(pw.Path, "read_bytes", return_value=args), self.assertRaises(pw.PasswordError):
                pw.check_daemon_options(runner, "ssh.service")
        with mock.patch.object(pw.Path, "read_bytes", return_value=b"sshd: /usr/sbin/sshd -D [listener]"):
            pw.check_daemon_options(runner, "ssh.service")


class TransactionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.config = self.base / "sshd_config"
        self.config.write_text("Port 26195\nPasswordAuthentication no\n")
        self.original = self.config.read_bytes()
        self.marker = self.base / "mode"
        self.backups = self.base / "backups"
        self.runner = FakeRunner()
        self.output = io.StringIO()
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(contextlib.redirect_stdout(self.output))
        patches = [mock.patch.object(pw, "CONFIG", self.config), mock.patch.object(pw, "MARKER", self.marker),
                   mock.patch.object(pw, "BACKUPS", self.backups), mock.patch.object(pw, "check_file"),
                   mock.patch.object(pw, "check_daemon_options"),
                   mock.patch.object(pw, "operation_lock", side_effect=contextlib.nullcontext),
                   mock.patch.object(pw.shutil, "which", side_effect=lambda name: name),
                   mock.patch.object(pw.sys.stdin, "isatty", return_value=True),
                   mock.patch.object(pw.sys.stdout, "isatty", return_value=True),
                   mock.patch("builtins.input", return_value="ENABLE"),
                   mock.patch.object(pw, "generate_password", return_value="SAFE-test-secret-123!")]
        for patch in patches:
            self.stack.enter_context(patch)

    def apply(self):
        pw.enable(self.runner, "192.0.2.8 53000 198.51.100.8 26195")

    def assert_unchanged(self):
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertEqual(self.runner.shadow, self.runner.old_shadow)
        self.assertFalse(self.marker.exists())

    def test_cancel_does_not_change_files_or_password(self):
        with mock.patch("builtins.input", return_value=""):
            self.apply()
        self.assert_unchanged()
        self.assertFalse(self.backups.exists())

    def test_noninteractive_rejected(self):
        with mock.patch.object(pw.sys.stdout, "isatty", return_value=False), self.assertRaises(pw.PasswordError):
            self.apply()
        self.assertEqual(self.runner.calls, [])

    def test_success_changes_only_root_auth_and_prints_password_once(self):
        self.apply()
        self.assertEqual(self.runner.password_input, "root:SAFE-test-secret-123!\n")
        self.assertEqual(self.output.getvalue().count("SAFE-test-secret-123!"), 1)
        self.assertEqual(self.config.read_text().count(pw.BEGIN), 1)
        self.assertEqual(json.loads(self.marker.read_text())["mode"], "root-password-and-key")
        for path in self.base.rglob("*"):
            if path.is_file():
                self.assertNotIn(b"SAFE-test-secret-123!", path.read_bytes(), str(path))
        for args, data, secret in self.runner.calls:
            self.assertNotIn("restart", args)
            self.assertNotIn("SAFE-test-secret-123!", " ".join(args))
            if args[0] == "chpasswd":
                self.assertTrue(secret)

    def test_syntax_failure_never_changes_password(self):
        self.runner.fail_syntax = True
        with self.assertRaises(pw.PasswordError):
            self.apply()
        self.assert_unchanged()
        self.assertIsNone(self.runner.password_input)

    def test_conflicting_match_aborts_before_changes(self):
        self.runner.conflict = True
        with self.assertRaisesRegex(pw.PasswordError, "перекрыт"):
            self.apply()
        self.assert_unchanged()

    def test_changed_port_aborts_before_changes(self):
        self.runner.changed_port = True
        with self.assertRaisesRegex(pw.PasswordError, "посторонние"):
            self.apply()
        self.assert_unchanged()

    def test_password_failure_restores_old_hash_and_age(self):
        self.runner.fail_password = True
        with self.assertRaisesRegex(pw.PasswordError, "password failed"):
            self.apply()
        self.assert_unchanged()
        self.assertNotIn("SAFE-test-secret-123!", self.output.getvalue())

    def test_locked_new_password_is_rejected_and_rolled_back(self):
        self.runner.locked_password = True
        with self.assertRaises(pw.PasswordError):
            self.apply()
        self.assert_unchanged()

    def test_reload_failure_restores_old_hash_config_and_mode(self):
        self.marker.write_text("old-mode")
        self.runner.fail_reload = True
        with self.assertRaisesRegex(pw.PasswordError, "reload failed"):
            self.apply()
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertEqual(self.runner.shadow, self.runner.old_shadow)
        self.assertEqual(self.marker.read_text(), "old-mode")
        self.assertNotIn("SAFE-test-secret-123!", self.output.getvalue())

    def test_marker_write_failure_rolls_back(self):
        write = pw.atomic_write

        def fail_marker(path, *args):
            if path == self.marker:
                raise OSError("disk full")
            return write(path, *args)

        with mock.patch.object(pw, "atomic_write", side_effect=fail_marker), self.assertRaises(OSError):
            self.apply()
        self.assert_unchanged()

    def test_broken_terminal_cannot_interrupt_rollback(self):
        self.runner.fail_reload = True
        original_print = print

        def broken(message, **kwargs):
            if message.startswith("[STOP]") or message.startswith("[OK]"):
                raise BrokenPipeError("terminal disconnected")
            original_print(message, **kwargs)

        with mock.patch("builtins.print", side_effect=broken), self.assertRaisesRegex(pw.PasswordError, "reload failed"):
            self.apply()
        self.assert_unchanged()

    def test_repeat_does_not_duplicate_match(self):
        self.apply()
        self.runner.shadow[1] = "$y$previous-generation"
        self.apply()
        self.assertEqual(self.config.read_text().count(pw.BEGIN), 1)
        self.assertEqual(len(list(self.backups.iterdir())), 2)


class IntegrationTests(unittest.TestCase):
    def test_direct_entrypoint_and_menu(self):
        main = function_body(KTO, "main")
        self.assertLess(main.index("ssh-password|root-password)"), main.index("startup_storage_preflight"))
        self.assertIn('actions+=("ssh-password")', function_body(KTO, "menu"))
        wrapper = function_body(KTO, "enable_ssh_password")
        self.assertIn('scripts/kto-ssh-password.py', wrapper)
        self.assertIn('--connection "${SSH_CONNECTION:-}"', wrapper)
        self.assertNotIn('apt_install', wrapper)
        self.assertNotIn('>> "$LOG_FILE"', wrapper)

    def test_future_optimization_respects_explicit_password_mode(self):
        bash = bash_executable()
        if not bash:
            self.skipTest("bash unavailable")
        source = r'''
set -Eeuo pipefail
SUDO=()
KTO_SSH_PASSWORD_MODE_FILE=$(mktemp)
trap 'rm -f "$KTO_SSH_PASSWORD_MODE_FILE"' EXIT
managed_ssh_changes_enabled() { return 0; }
ok() { printf '%s\n' "$*"; }
command_exists() { exit 91; }
''' + function_body(KTO, "opt_ssh_root_access") + "\nopt_ssh_root_access\n"
        run = subprocess.run([bash, "-s"], input=source, capture_output=True, encoding="utf-8", timeout=15)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn("не переопределяет", run.stdout)

    def test_helper_has_no_key_port_network_or_package_mutations(self):
        source = (ROOT / "scripts/kto-ssh-password.py").read_text(encoding="utf-8")
        for command in ('"apt-get"', '"ufw"', '"iptables"', '"netplan"', '"restart"', '"ssh-keygen"'):
            self.assertNotIn(command, source)
        self.assertNotIn("/root/.ssh/authorized_keys", source)

    def test_status_checks_running_service_and_listener_without_resetting_auth(self):
        bash = bash_executable()
        if not bash:
            self.skipTest("bash unavailable")
        source = r'''
set -Eeuo pipefail
SUDO=()
KTO_SSH_PASSWORD_MODE_FILE=$(mktemp)
trap 'rm -f "$KTO_SSH_PASSWORD_MODE_FILE"' EXIT
SYSTEM_CHECK_NEEDS_SSH=0
managed_ssh_changes_enabled() { return 0; }
detect_ssh_port() { printf '26195\n'; }
ssh_service_name() { printf 'ssh\n'; }
run_systemctl_bounded() { return "$service_rc"; }
ssh_port_is_listening() { return "$listener_rc"; }
sshd() { printf '%s\n' 'permitrootlogin yes' 'pubkeyauthentication yes' 'passwordauthentication yes' 'authenticationmethods any'; }
system_check_row() { printf '%s\n' "$1"; }
''' + function_body(KTO, "system_check_ssh_root_access") + r'''
service_rc=0
listener_rc=0
[[ $(system_check_ssh_root_access) == ok ]]
service_rc=1
[[ $(system_check_ssh_root_access) == warn ]]
service_rc=0
listener_rc=1
[[ $(system_check_ssh_root_access) == warn ]]
[[ $SYSTEM_CHECK_NEEDS_SSH == 0 ]]
'''
        run = subprocess.run([bash, "-s"], input=source, capture_output=True, encoding="utf-8", timeout=15)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)


@unittest.skipUnless(os.name == "posix" and shutil.which("sshd") and shutil.which("ssh-keygen"),
                     "local Linux sshd/ssh-keygen unavailable")
class OpenSshParserTests(unittest.TestCase):
    def test_real_root_match_preserves_key_paths_ports_and_other_users(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            key = base / "hostkey"
            subprocess.run([shutil.which("ssh-keygen"), "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
            original = base / "before.conf"
            candidate = base / "after.conf"
            original.write_text(f"HostKey {key}\nPort 26195\nPermitRootLogin prohibit-password\n"
                                "PasswordAuthentication no\nPubkeyAuthentication yes\n")
            candidate.write_text(pw.candidate_config(original.read_text()))
            sshd = shutil.which("sshd")
            probe = subprocess.run([sshd, "-t", "-f", str(candidate)], capture_output=True, text=True)
            if "Missing privilege separation directory" in probe.stderr:
                self.skipTest("sshd runtime directory unavailable")
            self.assertEqual(probe.returncode, 0, probe.stderr)
            for user in ("root", "nobody"):
                context = "host=localhost,addr=127.0.0.1"
                before = pw.effective(pw.Runner(), sshd, original, user, context)
                after = pw.effective(pw.Runner(), sshd, candidate, user, context)
                pw.validate_candidate(before, after, root=user == "root")


if __name__ == "__main__":
    unittest.main()
