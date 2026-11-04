"""Mail client helper, copied to and run on another instance by the tests.

Each command prints one JSON object. Certificates are not verified here (the
Pebble root is trusted on mail only); test_mailflow.py checks the certificate
on the mail instance itself.

Usage: python3 mailclient.py <command> [args...]
"""

import base64
import email
import email.policy
import email.utils
import imaplib
import io
import json
import smtplib
import socket
import ssl
import sys
import zipfile
from email.message import EmailMessage


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


def message(frm, to, subject, kind="plain"):
    """Build a test message. kind: plain, long (enough tokens for Bayes), exe, zip-exe."""
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = frm, to, subject
    m["Message-ID"] = f"<{subject}@sovtest.example>"
    m["Date"] = email.utils.formatdate()
    if kind == "long":
        m.set_content(" ".join(f"{subject} offer{i} discount cheap pills buy now limited" for i in range(40)))
    else:
        m.set_content(f"Body {subject}\n")
    exe = b"MZ\x90\x00" + b"\x00" * 200
    if kind == "exe":
        m.add_attachment(exe, maintype="application", subtype="octet-stream", filename="setup.exe")
    elif kind == "zip-exe":
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("setup.exe", exe)
        m.add_attachment(buf.getvalue(), maintype="application", subtype="zip", filename="documents.zip")
    return m.as_bytes(policy=email.policy.SMTP)  # CRLF line endings


def cmd_submission_plain(host):
    s = smtplib.SMTP(host, 587, timeout=15)
    s.ehlo("client.sovtest")
    starttls, auth = s.has_extn("starttls"), s.has_extn("auth")
    code, _ = s.mail("alice@sovereign.test")
    s.close()
    out(starttls=starttls, auth_before_tls=auth, mail_code=code)


def cmd_submit(host, user, password, frm, to, subject, kind="plain"):
    s = smtplib.SMTP(host, 587, timeout=15)
    s.starttls(context=ctx())
    try:
        s.login(user, password)
    except smtplib.SMTPAuthenticationError as exc:
        out(ok=False, stage="auth", error=str(exc))
        return
    try:
        s.sendmail(frm, [to], message(frm, to, subject, kind))
        out(ok=True)
    except smtplib.SMTPException as exc:
        out(ok=False, stage="send", error=str(exc))
    finally:
        s.quit()


def cmd_smtp(host, frm, to, subject, kind="plain"):
    s = smtplib.SMTP(host, 25, timeout=15)
    s.ehlo("sender.sovtest")
    info = {"starttls": s.has_extn("starttls"), "auth": s.has_extn("auth")}
    s.starttls(context=ctx())
    s.ehlo("sender.sovtest")
    try:
        s.sendmail(frm, [to], message(frm, to, subject, kind))
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


def cmd_imap_headers(host, user, password, subject, mailbox="INBOX"):
    """Headers of the first message with this subject, as a list of [name, value]."""
    imap = imaplib.IMAP4_SSL(host, 993, ssl_context=ctx())
    imap.login(user, password)
    imap.select(mailbox, readonly=True)
    _, data = imap.search(None, "SUBJECT", subject)
    ids = data[0].split()
    headers = []
    if ids:
        _, msg = imap.fetch(ids[0], "(BODY.PEEK[HEADER])")
        parsed = email.message_from_bytes(msg[0][1])
        headers = [[k, str(v)] for k, v in parsed.items()]
    imap.logout()
    out(found=bool(ids), headers=headers)


def cmd_imap_move(host, user, password, subject, target):
    """Move the message with this subject from INBOX to target (IMAP MOVE)."""
    imap = imaplib.IMAP4_SSL(host, 993, ssl_context=ctx())
    imap.login(user, password)
    imap.select("INBOX")
    _, data = imap.search(None, "SUBJECT", subject)
    ids = data[0].split()
    result = None
    if ids:
        result = imap._simple_command("MOVE", ids[0].decode(), target)[0]
    imap.logout()
    out(found=bool(ids), result=result)


def cmd_dkim_verify(message_b64, txt_record):
    """Verify the DKIM signature of a message against the given TXT record."""
    import dkim  # python3-dkim (dkimpy)

    raw = base64.b64decode(message_b64)
    record = txt_record.encode()
    ok = dkim.verify(raw, dnsfunc=lambda name, timeout=5: record)
    out(ok=bool(ok))


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
                lines = []
                while True:
                    data_line = f.readline()
                    if data_line.rstrip(b"\r\n") == b".":
                        break
                    lines.append(data_line[1:] if data_line.startswith(b"..") else data_line)
                env["data"] = base64.b64encode(b"".join(lines)).decode()
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
    "imap-headers": cmd_imap_headers,
    "imap-move": cmd_imap_move,
    "dkim-verify": cmd_dkim_verify,
    "tls": cmd_tls,
    "sieve": cmd_sieve,
    "sink": cmd_sink,
}

if __name__ == "__main__":
    COMMANDS[sys.argv[1]](*sys.argv[2:])
