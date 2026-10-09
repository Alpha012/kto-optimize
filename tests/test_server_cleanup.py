import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("kto_server_cleanup", ROOT / "scripts/kto-server-cleanup.py")
cl = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = cl
SPEC.loader.exec_module(cl)


def result(output="", rc=0, error=""):
    return subprocess.CompletedProcess([], rc, output, error)


def unit(active="inactive", load="loaded"):
    return {"LoadState": load, "ActiveState": active, "UnitFileState": "enabled"}


class PackageSafetyTests(unittest.TestCase):
    def test_allowlist(self):
        for name, component in (("haproxy", "haproxy"), ("nginx-common", "nginx"),
                                ("libnginx-mod-http-js:amd64", "nginx"), ("nginx-full", "nginx"),
                                ("docker-ce-rootless-extras", "docker"), ("docker.io", "docker"),
                                ("containerd.io:amd64", "docker"), ("docker-compose-v2", "docker")):
            self.assertEqual(cl.package_component(name), component)
        for name in ("openssh-server", "ufw", "fail2ban", "linux-virtual", "linux-image-generic",
                     "caddy", "xray", "runc", "remnawave", "python3-docker", "docker-ce-unknown",
                     "nginx;reboot", "nginx\nssh", "--help", "nginx:amd64:arm64"):
            self.assertIsNone(cl.package_component(name), name)

    def test_installed_and_config_files_but_not_uninstalled(self):
        runner = mock.Mock()
        runner.run.return_value = result("nginx\tinstalled\nhaproxy\tconfig-files\n"
                                         "docker.io\tnot-installed\nopenssh-server\tinstalled\n")
        self.assertEqual(cl.installed_packages(runner, ("nginx", "haproxy", "docker")), ["haproxy", "nginx"])
        self.assertEqual(cl.installed_packages(runner, ("docker",)), [])

    def test_malformed_inventory_fails_closed(self):
        runner = mock.Mock()
        runner.run.return_value = result("unexpected format")
        with self.assertRaises(cl.CleanupError):
            cl.installed_packages(runner, ("nginx",))

    def test_safe_simulation(self):
        cl.validate_apt_plan("Purg nginx [1]\nRemv haproxy:amd64 [2]\n", ["nginx", "haproxy:amd64"])

    def test_simulation_rejects_extra_removals_installs_and_pending_configuration(self):
        for action in ("Remv openssh-server [1]", "Purg linux-virtual [1]", "Remv docker-ce [1]",
                       "Inst linux-headers [1]", "Conf linux-image [1]", "Purg", "Purg nginx:arm64 [1]"):
            with self.subTest(action=action), self.assertRaises(cl.CleanupError):
                cl.validate_apt_plan("Purg nginx [1]\n" + action, ["nginx"])

    def test_empty_or_incomplete_plan_is_not_confirmation(self):
        for text in ("", "Reading packages...", "Remv nginx [1]"):
            with self.assertRaises(cl.CleanupError):
                cl.validate_apt_plan(text, ["nginx", "haproxy"])

    def test_no_autoremove_force_repair_or_upgrade_flags(self):
        command = cl.apt_command(["nginx"], simulate=False)
        self.assertEqual(command[-2:], ["purge", "nginx"])
        self.assertIn("APT::Get::AutomaticRemove=false", command)
        for bad in ("autoremove", "upgrade", "--fix-broken", "--allow-remove-essential", "--allow-change-held-packages"):
            self.assertNotIn(bad, command)

    def test_pending_kernel_blocks_before_any_other_work(self):
        runner = mock.Mock()
        runner.run.return_value = result("linux-image-generic is not configured")
        with self.assertRaisesRegex(cl.CleanupError, "Ничего не отключено"):
            cl.preflight(runner, ("nginx",))
        runner.run.assert_called_once_with(["dpkg", "--audit"])
        runner.purge.assert_not_called()

    def test_apt_failure_keeps_error_visible_and_does_not_stop_services(self):
        runner = mock.Mock()
        runner.run.side_effect = [result(), result("nginx\tinstalled\n"),
                                  result("unmet linux-headers dependency", 100, "E: broken")]
        with mock.patch.object(cl, "unit_states", return_value={}), \
                mock.patch.object(cl, "process_rows", return_value=[]), self.assertRaisesRegex(cl.CleanupError, "unmet linux"):
            cl.preflight(runner, ("nginx",))
        self.assertFalse(any(call.args[0][:2] == ["systemctl", "stop"] for call in runner.run.call_args_list))

    def test_manually_started_nginx_blocks_before_config_changes(self):
        with mock.patch.object(cl, "process_rows", return_value=[(0, "nginx")]), \
                self.assertRaisesRegex(cl.CleanupError, "ручной установки"):
            cl.check_managed_processes(mock.Mock(), ("nginx",), {"nginx.service": unit()})

    def test_unselected_processes_do_not_block_proxy_only_cleanup(self):
        with mock.patch.object(cl, "process_rows", return_value=[(0, "nginx"), (1000, "dockerd")]):
            cl.check_managed_processes(mock.Mock(), ("nginx",), {"nginx.service": unit("active")})


class DockerSafetyTests(unittest.TestCase):
    def setUp(self):
        self.runner = mock.Mock()
        self.states = {"docker.service": unit("active"), "containerd.service": unit("active")}
        self.which = mock.patch.object(cl.shutil, "which", return_value="/usr/bin/docker")
        self.processes = mock.patch.object(cl, "process_rows", return_value=[])
        self.which.start()
        self.processes.start()
        self.addCleanup(self.which.stop)
        self.addCleanup(self.processes.stop)

    def test_existing_containers_block_without_removal(self):
        self.runner.run.return_value = result('{"Names":"remnanode","ID":"abc"}\n')
        with self.assertRaisesRegex(cl.CleanupError, "remnanode"):
            cl.docker_preflight(self.runner, ["docker-ce"], self.states)
        self.runner.run.assert_called_once()
        self.assertIn("unix:///var/run/docker.sock", self.runner.run.call_args.args[0])

    def test_api_error_is_not_empty_container_list(self):
        self.runner.run.return_value = result(rc=1, error="permission denied")
        with self.assertRaisesRegex(cl.CleanupError, "недоступен"):
            cl.docker_preflight(self.runner, ["docker-ce"], self.states)

    def test_unexpected_json_cannot_confirm_empty_docker(self):
        self.runner.run.return_value = result('[]\n')
        with self.assertRaisesRegex(cl.CleanupError, "разобрать"):
            cl.docker_preflight(self.runner, ["docker-ce"], self.states)

    def test_inactive_docker_never_activates_socket(self):
        self.states["docker.service"] = unit()
        self.states["docker.socket"] = unit("active")
        with self.assertRaisesRegex(cl.CleanupError, "Не активирую"):
            cl.docker_preflight(self.runner, ["docker-ce"], self.states)
        self.runner.run.assert_not_called()

    def test_foreign_containerd_namespace_blocks(self):
        self.runner.run.side_effect = [result(), result("moby\nk8s.io\n")]
        with self.assertRaisesRegex(cl.CleanupError, "k8s.io"):
            cl.docker_preflight(self.runner, ["docker-ce"], self.states)

    def test_orphan_containerd_tasks_block(self):
        self.runner.run.side_effect = [result(), result("moby\n"), result("orphan-task\n")]
        with self.assertRaisesRegex(cl.CleanupError, "задачи"):
            cl.docker_preflight(self.runner, ["docker-ce"], self.states)

    def test_empty_local_docker_is_accepted(self):
        self.runner.run.side_effect = [result(), result("moby\n"), result()]
        cl.docker_preflight(self.runner, ["docker-ce"], self.states)
        self.assertEqual(self.runner.run.call_count, 3)

    def test_rootless_daemon_is_protected(self):
        with mock.patch.object(cl, "process_rows", return_value=[(1000, "dockerd")]), self.assertRaisesRegex(cl.CleanupError, "rootless"):
            cl.docker_preflight(self.runner, ["docker-ce"], self.states)

    def test_no_docker_packages_or_runtime_does_not_touch_stored_data(self):
        cl.docker_preflight(self.runner, [], {"docker.service": unit(load="not-found")})
        self.runner.run.assert_not_called()

    def test_runner_ignores_remote_docker_environment(self):
        with mock.patch.dict(os.environ, {"DOCKER_HOST": "tcp://remote:2375", "DOCKER_CONTEXT": "remote"}), \
                mock.patch.object(cl.subprocess, "run", return_value=result()) as call:
            cl.Runner().run(["docker", "--host", "unix:///var/run/docker.sock", "ps"])
        self.assertNotIn("DOCKER_HOST", call.call_args.kwargs["env"])
        self.assertNotIn("DOCKER_CONTEXT", call.call_args.kwargs["env"])


class FileSafetyTests(unittest.TestCase):
    def test_selected_paths_never_cover_access_network_docker_data_or_other_nodes(self):
        paths = [str(p).replace("\\", "/") for p in cl.selected_paths(tuple(cl.PACKAGE_PATTERNS))]
        for protected in ("/etc/ssh", "/root/.ssh", "/etc/netplan", "/etc/ufw", "/etc/fail2ban", "/opt/remnawave",
                          "/etc/caddy", "/var/lib/docker", "/var/lib/containerd", "/etc/default/grub", "/etc/sysctl.d",
                          "/etc/letsencrypt/live", "/var/www", "/var/log"):
            self.assertFalse(any(p == protected or p.startswith(protected + "/") for p in paths), protected)
        self.assertNotIn("kto-additional-ip-routes.timer", sum(cl.UNITS.values(), ()))
        self.assertNotIn("ssh.service", sum(cl.UNITS.values(), ()))

    def test_mounted_config_is_not_moved(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nginx"
            path.mkdir()
            with mock.patch.object(cl, "mount_points", return_value={str(path / "mounted")}):
                with self.assertRaisesRegex(cl.CleanupError, "монтирование"):
                    cl.check_paths([path])

    def test_config_backup_size_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nginx"
            path.write_bytes(b"large")
            with mock.patch.object(cl, "mount_points", return_value=set()), mock.patch.object(cl, "MAX_BACKUP_BYTES", 4):
                with self.assertRaisesRegex(cl.CleanupError, "512 MiB"):
                    cl.check_paths([path])

    def test_fingerprint_detects_password_and_key_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "authorized_keys"
            path.write_text("old")
            before = cl.fingerprint([path])
            path.write_text("new")
            self.assertNotEqual(cl.fingerprint([path]), before)
            self.assertNotIn("old", json.dumps(before))

    def test_archive_does_not_follow_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            config, secret = base / "config", base / "secret"
            config.mkdir()
            secret.write_text("DO NOT ARCHIVE")
            link = config / "outside"
            try:
                link.symlink_to(secret)
            except OSError:
                self.skipTest("symlink creation unavailable")
            plan = cl.Plan(("nginx",), [], {}, [config], "")
            with mock.patch.object(cl, "BACKUPS", base / "backups"):
                backup = cl.backup_configs(plan, cl.Runner())
            with tarfile.open(backup / "configs.tar") as archive:
                self.assertTrue(any(member.issym() for member in archive.getmembers()))
                self.assertFalse(any(member.isfile() for member in archive.getmembers()))


class RemovalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.config = self.base / "nginx.conf"
        self.config.write_text("config")
        self.plan = cl.Plan(("nginx",), ["nginx"], {"nginx.service": unit("active")}, [self.config], "Purg nginx [1]")
        self.runner = mock.Mock(spec=cl.Runner)
        self.runner.run.return_value = result()
        patches = [
            mock.patch.object(cl, "BACKUPS", self.base / "backups"),
            mock.patch.object(cl, "cleanup_lock", side_effect=contextlib.nullcontext),
            mock.patch.object(cl, "preflight", return_value=self.plan),
            mock.patch.object(cl, "fingerprint", return_value={"protected": "unchanged"}),
            mock.patch.object(cl, "unit_states", return_value={"ssh.service": unit("active")}),
            mock.patch.object(cl, "check_paths", return_value=0),
            mock.patch.object(cl, "verify"),
            mock.patch.object(cl.sys.stdin, "isatty", return_value=True),
        ]
        self.mocks = [patch.start() for patch in patches]
        for patch in patches:
            self.addCleanup(patch.stop)
        self.output = contextlib.redirect_stdout(io.StringIO())
        self.output.__enter__()
        self.addCleanup(self.output.__exit__, None, None, None)

    def test_cancel_changes_no_services_or_files(self):
        with mock.patch("builtins.input", return_value="no"):
            cl.remove(self.runner, ("nginx",))
        self.runner.run.assert_not_called()
        self.runner.purge.assert_not_called()
        self.assertTrue(self.config.exists())
        self.assertFalse((self.base / "backups").exists())

    def test_confirmation_is_required_without_tty(self):
        with mock.patch.object(cl.sys.stdin, "isatty", return_value=False), self.assertRaises(cl.CleanupError):
            cl.remove(self.runner, ("nginx",))
        self.runner.run.assert_not_called()

    def test_stale_package_plan_stops_before_changes(self):
        changed = cl.Plan(("nginx",), ["nginx", "nginx-common"], {}, [], "")
        self.mocks[2].side_effect = [self.plan, changed]
        with mock.patch("builtins.input", return_value="DELETE"), self.assertRaisesRegex(cl.CleanupError, "изменился"):
            cl.remove(self.runner, ("nginx",))
        self.runner.run.assert_not_called()

    def test_removal_preserves_access_and_stores_configs(self):
        with mock.patch("builtins.input", return_value="DELETE"):
            cl.remove(self.runner, ("nginx",))
        self.runner.purge.assert_called_once_with(["nginx"])
        commands = [call.args[0] for call in self.runner.run.call_args_list]
        self.assertEqual(commands, [["systemctl", "stop", "nginx.service"],
                                    ["systemctl", "disable", "nginx.service"], ["systemctl", "daemon-reload"]])
        backup = next((self.base / "backups").iterdir())
        manifest = json.loads((backup / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["status"], "complete")
        self.assertTrue((backup / "configs.tar").is_file())
        self.assertFalse(self.config.exists())
        self.assertIn(str(self.config), manifest["moved"])

    def test_failed_stop_does_not_purge(self):
        self.runner.run.side_effect = cl.CleanupError("stop failed")
        with mock.patch("builtins.input", return_value="DELETE"), self.assertRaises(cl.CleanupError):
            cl.remove(self.runner, ("nginx",))
        self.runner.purge.assert_not_called()
        self.assertTrue(self.config.exists())
        backup = next((self.base / "backups").iterdir())
        self.assertEqual(json.loads((backup / "manifest.json").read_text())["status"], "partial")

    def test_failed_purge_retains_configs_and_reports_partial(self):
        self.runner.purge.side_effect = cl.CleanupError("dpkg failed")
        with mock.patch("builtins.input", return_value="DELETE"), self.assertRaises(cl.CleanupError):
            cl.remove(self.runner, ("nginx",))
        self.assertTrue(self.config.exists())
        backup = next((self.base / "backups").iterdir())
        self.assertEqual(json.loads((backup / "manifest.json").read_text())["status"], "partial")
        self.assertFalse(any(call.args[0][:2] == ["systemctl", "start"] for call in self.runner.run.call_args_list))

    def test_no_installed_packages_is_repeatable(self):
        self.plan.packages = []
        self.plan.units = {"nginx.service": unit(load="not-found")}
        with mock.patch("builtins.input", return_value="DELETE"):
            cl.remove(self.runner, ("nginx",))
            cl.remove(self.runner, ("nginx",))
        self.runner.purge.assert_not_called()
        self.assertEqual(len(list((self.base / "backups").iterdir())), 2)

    def test_disk_error_cannot_hide_failed_removal(self):
        self.runner.purge.side_effect = cl.CleanupError("dpkg failed")
        original_write = cl.write_manifest

        def write(backup, manifest):
            if manifest["status"] == "partial":
                raise OSError("No space left")
            original_write(backup, manifest)

        with mock.patch("builtins.input", return_value="DELETE"), \
                mock.patch.object(cl, "write_manifest", side_effect=write), \
                self.assertRaisesRegex(cl.CleanupError, "dpkg failed"):
            cl.remove(self.runner, ("nginx",))
        backup = next((self.base / "backups").iterdir())
        self.assertEqual(json.loads((backup / "manifest.json").read_text())["status"], "purging")
        self.assertTrue(self.config.exists())


class IntegrationTests(unittest.TestCase):
    def test_menu_and_early_cli_dispatch(self):
        source = (ROOT / "kto.sh").read_text(encoding="utf-8")
        self.assertIn('labels+=("Удалить HAProxy / Nginx / Docker")', source)
        self.assertIn('server-cleanup) server_cleanup_menu || true', source)
        main = source.split("\nmain() {", 1)[1]
        self.assertLess(main.index("cleanup|server-cleanup|uninstall-proxies)"), main.index("startup_storage_preflight"))
        self.assertLess(main.index("cleanup-audit|server-cleanup-audit)"), main.index("migrate_superseded_kto_state"))
        wrapper = source.split("\nserver_cleanup_menu() {", 1)[1].split("\n}\n", 1)[0]
        self.assertNotIn("apt_install", wrapper)
        self.assertIn("scripts/kto-server-cleanup.py", wrapper)

    def test_no_password_key_firewall_route_kernel_mutations(self):
        source = (ROOT / "scripts/kto-server-cleanup.py").read_text(encoding="utf-8")
        for command in ("chpasswd", "usermod", "netplan apply", "iptables -F", "ufw reset", "update-grub", "sysctl -w"):
            self.assertNotIn(command, source)
        self.assertNotIn('"--fix-broken", "install"', source)
        self.assertNotIn("shutil.rmtree", source)


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.plan = cl.Plan(("nginx",), ["nginx"], {"nginx.service": unit("active")}, [], "")
        self.runner = mock.Mock()
        self.runner.run.return_value = result()
        self.before = {"key": "unchanged"}
        self.core = {"ssh.service": unit("active")}
        patches = [
            mock.patch.object(cl, "fingerprint", return_value=self.before),
            mock.patch.object(cl, "unit_states", side_effect=[self.core, {"nginx.service": unit(load="not-found")}]),
            mock.patch.object(cl, "installed_packages", return_value=[]),
            mock.patch.object(cl, "process_rows", return_value=[]),
        ]
        self.mocks = [patch.start() for patch in patches]
        for patch in patches:
            self.addCleanup(patch.stop)

    def test_success(self):
        cl.verify(self.runner, self.plan, self.before, self.core)

    def test_changed_protected_files(self):
        self.mocks[0].return_value = {"key": "changed"}
        with self.assertRaisesRegex(cl.CleanupError, "защищённые файлы"):
            cl.verify(self.runner, self.plan, self.before, self.core)

    def test_inactive_ssh_is_not_success(self):
        self.mocks[1].side_effect = [{"ssh.service": unit()}]
        with self.assertRaisesRegex(cl.CleanupError, "ssh.service"):
            cl.verify(self.runner, self.plan, self.before, self.core)

    def test_remaining_packages(self):
        self.mocks[2].return_value = ["nginx-common"]
        with self.assertRaisesRegex(cl.CleanupError, "nginx-common"):
            cl.verify(self.runner, self.plan, self.before, self.core)

    def test_remaining_processes(self):
        self.mocks[3].return_value = [(0, "nginx")]
        with self.assertRaisesRegex(cl.CleanupError, "Остались процессы"):
            cl.verify(self.runner, self.plan, self.before, self.core)

    def test_remaining_units(self):
        self.mocks[1].side_effect = [self.core, {"nginx.service": unit("activating")}]
        with self.assertRaisesRegex(cl.CleanupError, "не остановлен"):
            cl.verify(self.runner, self.plan, self.before, self.core)

    def test_new_pending_packages(self):
        self.runner.run.return_value = result("package requires configuration")
        with self.assertRaisesRegex(cl.CleanupError, "dpkg требует"):
            cl.verify(self.runner, self.plan, self.before, self.core)


class CliTests(unittest.TestCase):
    def setUp(self):
        patches = [mock.patch.object(cl.os, "geteuid", return_value=0, create=True),
                   mock.patch.object(cl.os, "umask"), mock.patch.object(cl, "audit"),
                   mock.patch.object(cl, "remove"), mock.patch.object(cl, "menu"),
                   mock.patch.object(cl.sys.stdin, "isatty", return_value=True)]
        self.mocks = [patch.start() for patch in patches]
        for patch in patches:
            self.addCleanup(patch.stop)
        self.output = contextlib.redirect_stdout(io.StringIO())
        self.output.__enter__()
        self.addCleanup(self.output.__exit__, None, None, None)

    def test_audit_without_components(self):
        self.assertEqual(cl.main(["audit"]), 0)
        self.mocks[2].assert_called_once()
        self.mocks[3].assert_not_called()

    def test_default_menu(self):
        self.assertEqual(cl.main([]), 0)
        self.mocks[4].assert_called_once()

    def test_select_components(self):
        self.assertEqual(cl.main(["remove", "nginx", "haproxy", "nginx"]), 0)
        self.assertEqual(self.mocks[3].call_args.args[1], ("nginx", "haproxy"))

    def test_nonroot_is_rejected(self):
        self.mocks[0].return_value = 1000
        self.assertEqual(cl.main(["remove"]), 1)
        self.mocks[3].assert_not_called()

    def test_menu_interrupt_returns_without_traceback(self):
        self.mocks[4].side_effect = EOFError
        self.assertEqual(cl.main([]), 1)


if __name__ == "__main__":
    unittest.main()
