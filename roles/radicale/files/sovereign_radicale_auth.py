"""Radicale authentication against Dovecot's auth socket (Sovereign radicale role).

Replaces Radicale's built-in "dovecot" type and python3-radicale-dovecot-auth:

- Both send no client address and no "no-penalty". Dovecot then keeps one shared
  auth penalty for all of them: a single wrong password delays every user's next
  login by up to 15 seconds, so anybody could lock out all CalDAV users. Brute
  force is handled by Radicale's login delay and the fail2ban jail instead.
- Both use the process ID as CPID, which must be unique per connection, although
  Radicale handles requests in parallel threads.
- The built-in type reads Dovecot 2.4's handshake with a timing-dependent single
  recv(), and the one in Debian 13 does not know that protocol version at all.
"""

import base64
import socket
import threading

from radicale import auth
from radicale.log import logger

# Dovecot delays failed logins by auth_failure_delay (2 seconds by default).
TIMEOUT = 15


class Auth(auth.BaseAuth):
    def __init__(self, configuration):
        super().__init__(configuration)
        self._socket = configuration.get("auth", "dovecot_socket")

    def _login(self, login, password):
        if not login or not password or "\0" in login or "\0" in password:
            return ""
        token = base64.b64encode(b"\0%b\0%b" % (login.encode(), password.encode()))
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(TIMEOUT)
                sock.connect(self._socket)
                with sock.makefile("rwb") as dovecot:
                    dovecot.write(b"VERSION\t1\t1\nCPID\t%d\n" % threading.get_native_id())
                    dovecot.flush()
                    while True:
                        line = dovecot.readline()
                        if not line:
                            raise OSError("connection closed during the handshake")
                        if line.startswith(b"DONE"):
                            break
                    dovecot.write(b"AUTH\t1\tPLAIN\tservice=radicale\tno-penalty\tresp=%b\n" % token)
                    dovecot.flush()
                    reply = dovecot.readline().split(b"\t")
        except OSError as error:
            logger.error("Dovecot authentication failed: %s", error)
            return ""
        return login if reply[:2] == [b"OK", b"1"] else ""
