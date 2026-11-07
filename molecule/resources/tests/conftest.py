"""Shared helpers for the Molecule testinfra tests."""

import base64
import json
import os
import pathlib
import subprocess
import tempfile

import pytest
import testinfra

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
            env={**os.environ, "ANSIBLE_ROLES_PATH": str(tests.parents[2] / "roles"), "ANSIBLE_FORCE_COLOR": "0", "PY_COLORS": "0"},
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
