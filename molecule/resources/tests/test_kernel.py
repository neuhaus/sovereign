"""Kernel settings and blocked modules (kernel role)."""

import pathlib

import pytest
import yaml

testinfra_hosts = ["mail"]

DEFAULTS = yaml.safe_load((pathlib.Path(__file__).parents[3] / "roles/kernel/defaults/main.yml").read_text())


def in_container(host):
    return host.run("systemd-detect-virt --container --quiet").rc == 0


def test_kernel_settings_in_effect(host):
    if in_container(host):
        pytest.skip("a container shares the host's kernel settings")
    keys = list(DEFAULTS["kernel_sysctl"])
    actual = dict(zip(keys, host.check_output("sysctl -n %s", " ".join(keys)).splitlines()))
    assert actual == {key: str(value) for key, value in DEFAULTS["kernel_sysctl"].items()}


@pytest.mark.parametrize("module", DEFAULTS["kernel_blocked_modules"])
def test_module_cannot_be_loaded(host, module):
    # modprobe -n shows what it would do: run /bin/false instead of loading.
    assert "/bin/false" in host.check_output("modprobe --dry-run --verbose %s 2>&1 || true", module)


def test_unprivileged_users_cannot_create_user_namespaces(host):
    if in_container(host):
        pytest.skip("a container shares the host's kernel settings")
    assert host.run("runuser -u nobody -- unshare --user true").rc != 0


def test_processes_cannot_read_each_others_memory(host):
    # ptrace_scope 2: not even the same user may attach to a process.
    if in_container(host):
        pytest.skip("a container shares the host's kernel settings")
    script = "import subprocess; p = subprocess.Popen(['sleep', '30']); open('/proc/%d/mem' % p.pid, 'rb'); p.kill()"
    result = host.run("runuser -u nobody -- python3 -c %s", script)
    assert result.rc != 0 and "PermissionError" in result.stderr, result.stderr
