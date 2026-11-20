"""Shared helpers for the Molecule testinfra tests."""

import base64
import json
import os
import pathlib
import plistlib
import subprocess
import tempfile

import pytest
import testinfra
import testinfra.backend
import testinfra.utils.ansible_runner
from testinfra.backend import base


class IncusBackend(base.BaseBackend):
    """Run commands with incus exec, as the incus connection plugin does.

    testinfra doesn't know community.general.incus and falls back to starting
    a whole ansible process per command: 0.8 s each, against 0.03 s here.
    """

    NAME = "incus"

    def __init__(self, name, *args, **kwargs):
        self.name = name
        super().__init__(name, *args, **kwargs)

    def run(self, command, *args, **kwargs):
        cmd = self.get_command(command, *args)
        out = self.run_local("incus exec --force-noninteractive %s -- /bin/sh -c %s", self.name, cmd)
        out.command = self.encode(cmd)
        return out


testinfra.backend.BACKENDS["incus"] = "conftest.IncusBackend"
_get_ansible_host = testinfra.utils.ansible_runner.get_ansible_host


def _get_ansible_host_incus(config, inventory, host, **kwargs):
    hostvars = inventory.get("_meta", {}).get("hostvars", {}).get(host, {})
    if hostvars.get("ansible_connection") == "community.general.incus":
        return testinfra.get_host("incus://" + hostvars.get("ansible_host", host))
    return _get_ansible_host(config, inventory, host, **kwargs)


testinfra.utils.ansible_runner.get_ansible_host = _get_ansible_host_incus

# Connects to ip:port from the probing instance and prints the outcome:
# "open" (accepted and listening), "refused" (accepted by the firewall, nothing
# listening) or "timeout" (dropped by the firewall).
PROBE = """
import socket, sys
s = socket.socket()
s.settimeout(3)
try:
    s.connect((sys.argv[1], int(sys.argv[2])))
    print("open")
except ConnectionRefusedError:
    print("refused")
except (socket.timeout, TimeoutError):
    print("timeout")
"""


@pytest.fixture(scope="module")
def sovtest_vars(host):
    """Inventory variables of the instance under test, NOT templated.

    Values that contain Jinja (e.g. "mail.{{ sovtest_domain }}") come back
    literally; use the `ansible_var` fixture for those.
    """
    return host.ansible.get_variables()


# In a container, incus generates /run/systemd/system/service.d/
# zzz-lxc-service.conf, which overrides these for every service; on a VM or
# a real server our drop-ins apply. Sandbox tests leave them out there.
CONTAINER_OVERRIDES = {
    "NoNewPrivileges", "PrivateNetwork", "ProtectProc", "ProcSubset", "ProtectControlGroups", "ProtectKernelTunables",
}


def in_container(host):
    return host.run("systemd-detect-virt --container --quiet").rc == 0


def sandbox_props(host, unit, names):
    """systemctl show values of a unit, without those a container overrides."""
    shown = dict(line.split("=", 1) for line in host.check_output("systemctl show -p %s %s", ",".join(names), unit).splitlines())
    if in_container(host):
        shown = {k: v for k, v in shown.items() if k not in CONTAINER_OVERRIDES}
    return shown


def without_restic(sovtest_vars):
    """Whether the scenario leaves out the restic role (sovtest_without_restic).

    Debian Testing has no restic package at times; see docs/STATUS.md.
    """
    return bool(sovtest_vars.get("sovtest_without_restic", False))


def skip_without_restic(sovtest_vars):
    if without_restic(sovtest_vars):
        pytest.skip("restic role left out: no restic package in this release (docs/STATUS.md)")


@pytest.fixture(scope="module")
def ansible_var(host):
    """Return a fully templated inventory variable of the instance under test."""

    def get(name):
        return host.ansible("ansible.builtin.debug", "var=" + name)[name]

    return get


@pytest.fixture(scope="module")
def peer(host):
    """Return a testinfra host for another instance of the same scenario."""

    def get(name):
        return testinfra.get_host(
            f"ansible://{name}", ansible_inventory=host.backend.ansible_inventory
        )

    return get


def probe(client, ip, port):
    """TCP connect from `client` to ip:port; returns open, refused or timeout."""
    return client.check_output("python3 -c %s %s %s", PROBE, ip, str(port))


def mail_client(instance):
    """Copy mailclient.py to an instance; returns a function running its commands."""
    code = base64.b64encode((pathlib.Path(__file__).parent / "mailclient.py").read_bytes()).decode()
    instance.check_output("echo %s | base64 -d > /tmp/mailclient.py", code)

    def run(*args):
        return json.loads(instance.check_output("python3 /tmp/mailclient.py " + " ".join(["%s"] * len(args)), *args))

    return run


# The tests run about 45 playbooks; each gathered the same facts again, a few
# seconds over incus every time. Kept for the session only.
FACT_CACHE = tempfile.mkdtemp(prefix="sovtest-facts-")


def run_playbook(host, playbook, variables, extra_inventory=None, limit=None, expect_failure=False):
    """Run a playbook with the scenario's inventory.

    Returns the changed count of the last host, or the output if it must fail.
    """
    tests = pathlib.Path(__file__).parent
    command = ["ansible-playbook", "-i", host.backend.ansible_inventory]
    if extra_inventory:
        command += ["-i", str(extra_inventory)]
    if limit:
        command += ["--limit", limit]
    with tempfile.NamedTemporaryFile("w", suffix=".json") as extra_vars:
        json.dump(variables, extra_vars)
        extra_vars.flush()
        result = subprocess.run(
            command + ["-e", "@" + extra_vars.name, str(playbook)],
            # Without colour: the recap below is parsed (CI forces colour on).
            env={
                **os.environ,
                "ANSIBLE_ROLES_PATH": str(tests.parents[2] / "roles"),
                "ANSIBLE_FORCE_COLOR": "0",
                "PY_COLORS": "0",
                "ANSIBLE_GATHERING": "smart",
                "ANSIBLE_CACHE_PLUGIN": "jsonfile",
                "ANSIBLE_CACHE_PLUGIN_CONNECTION": FACT_CACHE,
                "ANSIBLE_CACHE_PLUGIN_TIMEOUT": "86400",
                "ANSIBLE_PIPELINING": "True",
            },
            capture_output=True,
            text=True,
            check=False,
        )
    if expect_failure:
        assert result.returncode != 0, result.stdout[-2000:]
        return result.stdout + result.stderr
    assert result.returncode == 0, result.stdout[-4000:] + result.stderr[-2000:]
    recap = [line for line in result.stdout.splitlines() if "changed=" in line and "unreachable=" in line]
    assert recap, result.stdout[-2000:]
    return int(recap[-1].split("changed=")[1].split()[0])


def apple_profile(host, name):
    """Fetches https://<name>/mail.mobileconfig on the mail instance and
    checks its signature against the system trust store (Pebble's root in
    Molecule). Returns the content type, the profile as a dict and the SHA-256
    fingerprint of the signing certificate. The certificate is a TLS server
    certificate, hence -purpose any."""
    work = "/tmp/sovtest-mobileconfig"
    host.check_output("rm -rf %s && mkdir -p %s", work, work)
    content_type = host.check_output(
        "curl -fsS --resolve %s:443:127.0.0.1 -o %s/signed -w '%%{content_type}' https://%s/mail.mobileconfig",
        name, work, name,
    )
    host.check_output(
        "openssl cms -verify -binary -inform DER -purpose any -in %s/signed -signer %s/signer.pem -out %s/profile",
        work, work, work,
    )
    profile = plistlib.loads(host.file(work + "/profile").content)
    signer = host.check_output("openssl x509 -in %s/signer.pem -noout -fingerprint -sha256", work)
    return content_type, profile, signer
