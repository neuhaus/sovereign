"""Mail client helper, copied to and run on another instance by the tests.

Each command prints one JSON object. Certificates are not verified here (the
Pebble root is trusted on mail only); test_mailflow.py checks the certificate
on the mail instance itself.

Usage: python3 mailclient.py <command> [args...]
"""

import imaplib
import json
import smtplib
import socket
import ssl
import sys


def ctx(version=None):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    if version:
        c.set_ciphers("ALL:@SECLEVEL=0")
        v = getattr(ssl.TLSVersion, version)
        c.minimum_version = c.maximum_version = v
    return c


def out(**kw):
    print(json.dumps(kw))


def message(frm, to, subject):
    return (
        f"From: {frm}\r\nTo: {to}\r\nSubject: {subject}\r\n"
        f"Message-ID: <{subject}@sovtest>\r\n\r\nBody {subject}\r\n"
    )


def cmd_submission_plain(host):
    s = smtplib.SMTP(host, 587, timeout=15)
    s.ehlo("client.sovtest")
    starttls, auth = s.has_extn("starttls"), s.has_extn("auth")
    code, _ = s.mail("alice@sovereign.test")
    s.close()
    out(starttls=starttls, auth_before_tls=auth, mail_code=code)


def cmd_submit(host, user, password, frm, to, subject):
    s = smtplib.SMTP(host, 587, timeout=15)
    s.starttls(context=ctx())
    try:
        s.login(user, password)
    except smtplib.SMTPAuthenticationError as exc:
        out(ok=False, stage="auth", error=str(exc))
        return
    try:
        s.sendmail(frm, [to], message(frm, to, subject))
        out(ok=True)
    except smtplib.SMTPException as exc:
        out(ok=False, stage="send", error=str(exc))
    finally:
        s.quit()


def cmd_smtp(host, frm, to, subject):
    s = smtplib.SMTP(host, 25, timeout=15)
    s.ehlo("sender.sovtest")
    info = {"starttls": s.has_extn("starttls"), "auth": s.has_extn("auth")}
    s.starttls(context=ctx())
    s.ehlo("sender.sovtest")
    try:
        s.sendmail(frm, [to], message(frm, to, subject))
        out(ok=True, **info)
    except smtplib.SMTPException as exc:
        out(ok=False, error=str(exc), **info)
    finally:
        s.quit()


def cmd_imap_count(host, user, password, subject):
    imap = imaplib.IMAP4_SSL(host, 993, ssl_context=ctx())
    imap.login(user, password)
    imap.select("INBOX")
    _, data = imap.search(None, "SUBJECT", subject)
    imap.logout()
    out(count=len(data[0].split()))


def cmd_imap_login(host, port, user, password):
    try:
        if port == "993":
            imap = imaplib.IMAP4_SSL(host, 993, ssl_context=ctx())
        else:
            imap = imaplib.IMAP4(host, 143)
            imap.starttls(ssl_context=ctx())
        imap.login(user, password)
        imap.logout()
        out(ok=True)
    except imaplib.IMAP4.error as exc:
        out(ok=False, error=str(exc))


def cmd_imap_plain(host, user, password):
    imap = imaplib.IMAP4(host, 143)
    caps = list(imap.capabilities)
    try:
        imap.login(user, password)
        login = True
    except imaplib.IMAP4.error:
        login = False
    out(capabilities=caps, login_without_tls=login)


def cmd_tls(host, port, version, mode):
    port = int(port)
    try:
        raw = socket.create_connection((host, port), timeout=10)
        if mode == "smtp":
            f = raw.makefile("rwb")
            f.readline()
            f.write(b"EHLO client.sovtest\r\n")
            f.flush()
            while not f.readline().startswith(b"250 "):
                pass
            f.write(b"STARTTLS\r\n")
            f.flush()
            if not f.readline().startswith(b"220"):
                raise OSError("STARTTLS refused")
        elif mode == "imap":
            f = raw.makefile("rwb")
            f.readline()
            f.write(b"a STARTTLS\r\n")
            f.flush()
            if not f.readline().startswith(b"a OK"):
                raise OSError("STARTTLS refused")
        with ctx(version).wrap_socket(raw) as s:
            out(ok=True, version=s.version(), cipher=s.cipher()[0])
    except (ssl.SSLError, OSError) as exc:
        out(ok=False, error=str(exc))


def cmd_sieve(host):
    with socket.create_connection((host, 4190), timeout=10) as s:
        greeting = b""
        while b"\r\nOK" not in greeting and not greeting.startswith(b"OK"):
            chunk = s.recv(4096)
            if not chunk:
                break
            greeting += chunk
    out(starttls=b'"STARTTLS"' in greeting, greeting=greeting.decode(errors="replace")[:300])


def cmd_sink(port, outfile):
    """Minimal SMTP server recording envelopes as JSON lines (plays a foreign MX)."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", int(port)))
    srv.listen()
    while True:
        conn, _ = srv.accept()
        f = conn.makefile("rwb")
        env = {"rcpt": []}

        def say(line):
            f.write(line.encode() + b"\r\n")
            f.flush()

        say("220 sink.sovtest ESMTP")
        while True:
            line = f.readline().decode(errors="replace").strip()
            if not line:
                break
            upper = line.upper()
            if upper.startswith(("EHLO", "HELO")):
                say("250 sink.sovtest")
            elif upper.startswith("MAIL FROM:"):
                env["from"] = line[10:].strip().split()[0].strip("<>")
                say("250 ok")
            elif upper.startswith("RCPT TO:"):
                env["rcpt"].append(line[8:].strip().split()[0].strip("<>"))
                say("250 ok")
            elif upper == "DATA":
                say("354 go ahead")
                while f.readline().rstrip(b"\r\n") != b".":
                    pass
                with open(outfile, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(env) + "\n")
                env = {"rcpt": []}
                say("250 queued")
            elif upper == "QUIT":
                say("221 bye")
                break
            else:
                say("250 ok")
        conn.close()


COMMANDS = {
    "submission-plain": cmd_submission_plain,
    "submit": cmd_submit,
    "smtp": cmd_smtp,
    "imap-count": cmd_imap_count,
    "imap-login": cmd_imap_login,
    "imap-plain": cmd_imap_plain,
    "tls": cmd_tls,
    "sieve": cmd_sieve,
    "sink": cmd_sink,
}

if __name__ == "__main__":
    COMMANDS[sys.argv[1]](*sys.argv[2:])
