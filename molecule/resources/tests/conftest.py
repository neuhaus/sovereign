"""Shared helpers for the Molecule testinfra tests."""

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
