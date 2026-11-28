import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from test_kto_profiles import KTO, ROOT, bash_executable, function_body


SPEC = importlib.util.spec_from_file_location("kto_return_root", ROOT / "scripts/kto-return-root.py")
rr = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = rr
SPEC.loader.exec_module(rr)


def proc(stdout="", rc=0, stderr=""):
    return subprocess.CompletedProcess([], rc, stdout, stderr)


SAMPLE_KEY_1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl user@laptop"
SAMPLE_KEY_2 = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8Drz6C97zQtb5mA5u6uVWccuWgRAWmfp5pwbQV9kf+L8V+7FrMQ9mmwMbwFKXuopKj95cy base@nova"


class FakeRunner:
    def __init__(self, sshd_config: Path, dropin: Path, extra_dropin: Path | None = None):
        self.sshd_config = sshd_config
        self.dropin = dropin
        self.extra_dropin = extra_dropin
        self.calls = []
        self.passwd_shell = "/usr/sbin/nologin"
        self.shadow = ["root", "!locked", "20100", "0", "99999", "7", "", "", ""]
        self.old_shadow = list(self.shadow)
        self.ssh_active = False
        self.socket_active = True
        self.fail_syntax = False
        self.port = 22
        self.password_written = None
        self.ufw_active = True
        self.fail2ban_active = True

    def _effective_text(self, path: Path) -> str:
        text = path.read_text(encoding="utf-8") if path.exists() else ""
        dropin_text = self.dropin.read_text(encoding="utf-8") if self.dropin.exists() else ""
        extra_text = self.extra_dropin.read_text(encoding="utf-8") if (self.extra_dropin and self.extra_dropin.exists()) else ""
        has_include = f"Include {self.dropin}" in text
        has_yes = has_include and "PermitRootLogin yes" in dropin_text
        lines = [
            f"port {self.port}",
            f"permitrootlogin {'yes' if has_yes else 'prohibit-password'}",
            f"passwordauthentication {'yes' if has_yes else 'no'}",
            "pubkeyauthentication yes",
            "authenticationmethods any",
            "kbdinteractiveauthentication yes",
        ]
        active_lines = [
            ln.strip()
            for ln in (text + "\n" + extra_text).splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        if any(ln == "DenyUsers root" for ln in active_lines):
            lines.append("denyusers root")
        return "\n".join(lines) + "\n"

    def run(self, args, *, data=None, secret=False, check=True, timeout=60):
        self.calls.append((list(args), data, secret))
        cmd = args[0]
        if args[:2] == ["getent", "passwd"]:
            return proc(f"root:x:0:0:root:/root:{self.passwd_shell}\n")
        if args[:2] == ["getent", "shadow"]:
            return proc(":".join(self.shadow) + "\n")
        if cmd == "usermod":
            if "-s" in args:
                self.passwd_shell = args[args.index("-s") + 1]
            if "-U" in args and self.shadow[1].startswith("!"):
                self.shadow[1] = self.shadow[1].lstrip("!")
            return proc()
        if cmd == "chage":
            if "-d" in args:
                self.shadow[2] = args[args.index("-d") + 1]
            return proc()
        if cmd == "chpasswd":
            if "-e" in args:
                self.shadow[1] = data.strip().split(":", 1)[1]
            else:
                self.password_written = data
                self.shadow[1] = "$y$new-hash"
            return proc()
        if cmd == "ssh-keygen":
            (self.sshd_config.parent / "ssh_host_ed25519_key").write_text("dummy", encoding="utf-8")
            return proc()
        if cmd == "sshd":
            cfg_path = Path(args[args.index("-f") + 1])
            if "-t" in args:
                if self.fail_syntax:
                    if check:
                        raise rr.ReturnRootError("sshd -t failed")
                    return proc(rc=1, stderr="bad syntax")
                return proc()
            if "-T" in args:
                return proc(self._effective_text(cfg_path))
        if cmd == "systemctl":
            action = args[1]
            unit = args[-1]
            if action == "is-active":
                if unit == "ssh.service":
                    return proc(rc=0 if self.ssh_active else 3)
                if unit == "ssh.socket":
                    return proc(rc=0 if self.socket_active else 3)
                if unit == "fail2ban":
                    return proc(rc=0 if self.fail2ban_active else 3)
                return proc(rc=3)
            if action == "cat":
                return proc(rc=0 if unit == "ssh.service" else 1)
            if action == "disable" and unit == "ssh.socket":
                self.socket_active = False
                return proc()
            if action in ("restart", "reload"):
                self.ssh_active = True
                return proc()
            return proc()
        if cmd == "ss":
            return proc(f"LISTEN 0 128 0.0.0.0:{self.port} 0.0.0.0:*\n")
        if cmd == "ufw":
            if args[1] == "status":
                return proc("Status: active\n443/tcp ALLOW Anywhere\n" if self.ufw_active else "Status: inactive\n")
            return proc()
        if cmd == "fail2ban-client":
            return proc()
        if cmd == "visudo":
            return proc()
        if cmd == "ip":
            return proc("1.1.1.1 via 195.123.211.1 dev ens3 src 185.100.10.20 uid 0\n")
        return proc()


class PureReturnRootTests(unittest.TestCase):
    def test_generated_password_is_strong_and_vnc_safe(self):
        seen = {rr.generate_password() for _ in range(100)}
        self.assertEqual(len(seen), 100)
        for pwd in seen:
            self.assertEqual(len(pwd), 20)
            self.assertGreaterEqual(sum(c in rr.PASS_LOWER for c in pwd), 2)
            self.assertGreaterEqual(sum(c in rr.PASS_UPPER for c in pwd), 2)
            self.assertGreaterEqual(sum(c in rr.PASS_DIGITS for c in pwd), 2)
            for ambiguous in ("0", "O", "1", "l", "I", ":", "\n", "'", '"', "\\"):
                self.assertNotIn(ambiguous, pwd)

    def test_validate_custom_password_rejects_invalid(self):
        for bad in ("", "12345", "abc\ndef", "abc\rdef"):
            with self.assertRaises(rr.ReturnRootError):
                rr.validate_custom_password(bad)
        self.assertEqual(rr.validate_custom_password("MyPass123"), "MyPass123")

    def test_merge_authorized_keys_unwraps_cloud_init_lockout_and_deduplicates(self):
        wrapped = (
            'no-port-forwarding,no-agent-forwarding,no-X11-forwarding,'
            'command="echo \'Please login as the user \\"ubuntu\\" rather than the user \\"root\\".\';echo;sleep 10;exit 142" '
            + SAMPLE_KEY_1
        )
        merged, count, unwrapped = rr.merge_authorized_keys([wrapped, SAMPLE_KEY_1, SAMPLE_KEY_2])
        self.assertEqual(count, 2)
        self.assertEqual(unwrapped, 1)
        self.assertNotIn("Please login as the user", merged)
        self.assertIn(SAMPLE_KEY_1, merged)
        self.assertIn(SAMPLE_KEY_2, merged)

    def test_prepend_include_is_line_one_and_idempotent(self):
        src = "Include /etc/ssh/sshd_config.d/00-kto-managed.conf\nPort 22\n"
        dropin = Path("/etc/ssh/sshd_config.d/00-kto-return-root.conf")
        first = rr.prepend_include(src, dropin)
        self.assertTrue(first.startswith(f"Include {dropin}\n"))
        self.assertEqual(first, rr.prepend_include(first, dropin))

    def test_fix_access_control_directives_unblocks_root(self):
        src = "AllowUsers ubuntu admin\nDenyUsers root guest\nDenyGroups root\n"
        fixed, changed = rr.fix_access_control_directives(src)
        self.assertTrue(changed)
        self.assertIn("AllowUsers ubuntu admin root\n", fixed)
        self.assertIn("DenyUsers guest\n", fixed)
        self.assertIn("# Disabled by kto return-root: DenyGroups root\n", fixed)


class TransactionReturnRootTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.ssh_dir = self.base / "etc_ssh"
        self.ssh_d = self.ssh_dir / "sshd_config.d"
        self.ssh_d.mkdir(parents=True)
        self.sshd_config = self.ssh_dir / "sshd_config"
        self.sshd_config.write_text(
            "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin prohibit-password\nPasswordAuthentication no\n",
            encoding="utf-8",
        )
        self.extra_dropin = self.ssh_d / "50-cloud-init.conf"
        self.extra_dropin.write_text("PasswordAuthentication no\nDenyUsers root\n", encoding="utf-8")
        self.dropin = self.ssh_d / rr.DROPIN_NAME
        self.marker = self.base / "kto-ssh-password.enabled"
        self.backups = self.base / "backups"
        self.sudoers = self.base / "sudoers.d"
        self.sudoers.mkdir()
        self.root_ssh = self.base / "root_ssh"
        self.root_ssh.mkdir()
        self.root_keys = self.root_ssh / "authorized_keys"
        self.root_keys.write_text(
            'command="echo \'Please login as the user \\"ubuntu\\" rather than the user \\"root\\".\';exit 142" '
            + SAMPLE_KEY_1 + "\n",
            encoding="utf-8",
        )
        self.runner = FakeRunner(self.sshd_config, self.dropin, self.extra_dropin)
        self.output = io.StringIO()
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(contextlib.redirect_stdout(self.output))
        patches = [
            mock.patch.object(rr, "SSHD_CONFIG", self.sshd_config),
            mock.patch.object(rr, "SSHD_CONFIG_D", self.ssh_d),
            mock.patch.object(rr, "DROPIN_PATH", self.dropin),
            mock.patch.object(rr, "MARKER_PATH", self.marker),
            mock.patch.object(rr, "BACKUPS_DIR", self.backups),
            mock.patch.object(rr, "SUDOERS_DIR", self.sudoers),
            mock.patch.object(rr, "ROOT_SSH_DIR", self.root_ssh),
            mock.patch.object(rr, "ROOT_AUTH_KEYS", self.root_keys),
            mock.patch.object(rr, "operation_lock", side_effect=contextlib.nullcontext),
            mock.patch.object(rr, "ensure_ssh_runtime_and_hostkeys", return_value=["создан /run/sshd"]),
            mock.patch.object(rr.shutil, "which", side_effect=lambda name: name),
            mock.patch.object(rr, "generate_password", return_value="SafeTestPass2026AbCd"),
        ]
        for p in patches:
            self.stack.enter_context(p)

    def test_full_recovery_fixes_account_keys_acl_socket_ufw_fail2ban_and_sudoers(self):
        info = rr.return_root(
            self.runner,
            connection="85.192.48.122 51234 185.100.10.20 22",
            caller_user="kto",
            base_key=SAMPLE_KEY_2,
            auto=True,
        )
        out = self.output.getvalue()
        self.assertEqual(info["password"], "SafeTestPass2026AbCd")
        self.assertEqual(info["ssh_cmd"], "ssh root@185.100.10.20")
        self.assertIn("Пароль:      SafeTestPass2026AbCd", out)
        self.assertEqual(self.runner.password_written, "root:SafeTestPass2026AbCd\n")
        self.assertIn("/bin/", self.runner.passwd_shell)
        self.assertFalse(self.runner.socket_active)
        self.assertTrue(self.runner.ssh_active)

        # Line-1 Include + drop-in + fixed DenyUsers + marker
        self.assertTrue(self.sshd_config.read_text(encoding="utf-8").startswith(f"Include {self.dropin}\n"))
        self.assertIn("PermitRootLogin yes", self.dropin.read_text(encoding="utf-8"))
        self.assertIn("AuthenticationMethods any", self.dropin.read_text(encoding="utf-8"))
        self.assertIn("# Disabled by kto return-root: DenyUsers root", self.extra_dropin.read_text(encoding="utf-8"))
        marker_data = json.loads(self.marker.read_text(encoding="utf-8"))
        self.assertEqual(marker_data["mode"], "root-password-and-key")
        self.assertEqual(marker_data["source"], "return-root")

        # Keys unwrapped + base key added
        keys_text = self.root_keys.read_text(encoding="utf-8")
        self.assertNotIn("Please login as the user", keys_text)
        self.assertIn(SAMPLE_KEY_1, keys_text)
        self.assertIn(SAMPLE_KEY_2, keys_text)

        # NOPASSWD sudoers created for caller user
        sudoers_file = self.sudoers / "90-kto-nopasswd-kto"
        self.assertTrue(sudoers_file.is_file())
        self.assertEqual(sudoers_file.read_text(encoding="utf-8"), "kto ALL=(ALL) NOPASSWD:ALL\n")

        # UFW allow + fail2ban unban invoked
        called_cmds = [c[0] for c in self.runner.calls]
        self.assertIn(["ufw", "allow", "22/tcp"], called_cmds)
        self.assertIn(["fail2ban-client", "set", "sshd", "unbanip", "85.192.48.122"], called_cmds)

        # Password never stored in any file or argv
        for path in self.base.rglob("*"):
            if path.is_file():
                self.assertNotIn(b"SafeTestPass2026AbCd", path.read_bytes(), str(path))
        for args, _data, _secret in self.runner.calls:
            self.assertNotIn("SafeTestPass2026AbCd", " ".join(args))

    def test_syntax_failure_rolls_back_config_dropins_marker_and_shadow(self):
        orig_main = self.sshd_config.read_bytes()
        orig_extra = self.extra_dropin.read_bytes()
        self.runner.fail_syntax = True
        with self.assertRaises(rr.ReturnRootError):
            rr.return_root(self.runner, auto=True)
        self.assertEqual(self.sshd_config.read_bytes(), orig_main)
        self.assertEqual(self.extra_dropin.read_bytes(), orig_extra)
        self.assertFalse(self.dropin.exists())
        self.assertFalse(self.marker.exists())
        self.assertEqual(self.runner.shadow, self.runner.old_shadow)


class KtoIntegrationReturnRootTests(unittest.TestCase):
    def test_menu_cli_wrapper_and_build_sync(self):
        self.assertIn('SCRIPT_BUILD="v355"', KTO)
        self.assertEqual(rr.RETURN_ROOT_BUILD, "v355")
        main_body = function_body(KTO, "main")
        self.assertLess(
            main_body.index("return-root|restore-root|root-restore|fix-root|root)"),
            main_body.index("startup_storage_preflight"),
        )
        settings_body = function_body(KTO, "settings_menu")
        self.assertIn('"Возвращение root"', settings_body)
        self.assertIn('"return-root"', settings_body)
        wrapper = function_body(KTO, "return_root_access")
        self.assertIn("scripts/kto-return-root.py", wrapper)
        self.assertIn("--caller-user", wrapper)
        self.assertIn("--base-key", wrapper)
        self.assertNotIn('>> "$LOG_FILE"', wrapper)

    def test_menu_digit_selection_triggers_return_root(self):
        bash = bash_executable()
        if not bash:
            self.skipTest("bash unavailable")
        snippet = r'''
set -Eeuo pipefail
source <(sed '/^main /d' kto.sh)
header() { :; }
need_root() { :; }
SUDO=()
BOLD= DIM= PURPLE= GREEN= YELLOW= RED= NC=
MACHINE_MODE="node"
NODE_PROFILE="reality"
return_root_access() { echo "CALLED:return-root"; }
menu
'''
        # 8 (Система и SSH) -> 4 (Возвращение root, pause with x) -> q (back) -> 0 (exit)
        res = subprocess.run(
            [bash, "-c", snippet],
            cwd=ROOT,
            input=b"84xq0",
            capture_output=True,
            timeout=20,
            env=dict(os.environ, KTO_MENU_INTERACTIVE="1"),
            check=False,
        )
        out = res.stdout.decode("utf-8", errors="replace")
        err = res.stderr.decode("utf-8", errors="replace")
        self.assertEqual(res.returncode, 0, out + err)
        self.assertIn("CALLED:return-root", out)


if __name__ == "__main__":
    unittest.main()
