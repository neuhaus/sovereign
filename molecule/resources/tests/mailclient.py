"""Mail client helper, copied to and run on another instance by the tests.

Each command prints one JSON object. Certificates are not verified here (the
Pebble root is trusted on mail only); test_mailflow.py checks the certificate
on the mail instance itself.

Usage: python3 mailclient.py <command> [args...]
"""

import base64
import concurrent.futures
import email
import email.policy
import email.utils
import http.client
import imaplib
import io
import json
import re
import smtplib
import socket
import ssl
import sys
import time
import urllib.parse
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


def cmd_imap_hold(host, user, password, seconds):
    """Stay logged in; prints whether the server ended the session."""
    imap = imaplib.IMAP4_SSL(host, 993, ssl_context=ctx())
    imap.login(user, password)
    try:
        for _ in range(int(seconds)):
            imap.noop()
            time.sleep(1)
    except (imaplib.IMAP4.abort, OSError) as exc:
        out(disconnected=True, error=str(exc))
        return
    imap.logout()
    out(disconnected=False)


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


def cmd_sieve_login(host, user, password):
    """ManageSieve: STARTTLS, then PLAIN authentication."""

    def read_response(f):
        while True:
            line = f.readline()
            if not line or line.startswith((b"OK", b"NO", b"BYE")):
                return line.decode(errors="replace").strip()

    with socket.create_connection((host, 4190), timeout=15) as raw:
        f = raw.makefile("rwb")
        read_response(f)
        f.write(b"STARTTLS\r\n")
        f.flush()
        starttls = read_response(f)
        with ctx().wrap_socket(raw) as s:
            f = s.makefile("rwb")
            read_response(f)  # capabilities again after STARTTLS
            token = base64.b64encode(f"\0{user}\0{password}".encode()).decode()
            f.write(f'AUTHENTICATE "PLAIN" "{token}"\r\n'.encode())
            f.flush()
            auth = read_response(f)
    out(starttls=starttls, auth=auth, ok=auth.startswith("OK"))


def basic_auth(user, password):
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


# Basic auth in front of the webmail (roundcube_basic_auth_users in Molecule).
WEBMAIL_AUTH = basic_auth("webmail", "sovtest-webmail-pass")


class Web:
    """Minimal browser for one HTTPS virtual host: keeps cookies, no redirects."""

    def __init__(self, ip, vhost):
        self.ip, self.vhost, self.cookies, self.token = ip, vhost, {}, None

    def request(self, method, path, fields=None, headers=None):
        conn = http.client.HTTPSConnection(self.ip, 443, context=ctx(), timeout=60)
        all_headers = {"Host": self.vhost, "Authorization": WEBMAIL_AUTH, **(headers or {})}
        if self.cookies:
            all_headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        body = None
        if fields is not None:
            body = urllib.parse.urlencode(fields)
            all_headers["Content-Type"] = "application/x-www-form-urlencoded"
        conn.request(method, path, body, all_headers)
        resp = conn.getresponse()
        text = resp.read().decode(errors="replace")
        for name, value in resp.getheaders():
            if name.lower() == "set-cookie":
                key, _, val = value.split(";", 1)[0].partition("=")
                self.cookies[key] = val
        conn.close()
        match = re.search(r'"request_token":"([^"]+)"', text) or re.search(r'name="_token" value="([^"]+)"', text)
        if match:
            self.token = match.group(1)
        return resp, text

    def login(self, user, password):
        """Roundcube login; True when it redirects into the mailbox."""
        self.request("GET", "/")
        resp, _ = self.request(
            "POST",
            "/?_task=login",
            {"_token": self.token, "_task": "login", "_action": "login", "_timezone": "UTC", "_url": "", "_user": user, "_pass": password},
        )
        if resp.status != 302:
            return False
        self.request("GET", resp.getheader("Location"))
        return True


def cmd_web_login(ip, vhost, user, password):
    out(ok=Web(ip, vhost).login(user, password))


def cmd_web_basic(ip, vhost, path, user="", password=""):
    """Request without or with other basic auth credentials; prints the status."""
    conn = http.client.HTTPSConnection(ip, 443, context=ctx(), timeout=30)
    headers = {"Host": vhost}
    if user:
        headers["Authorization"] = basic_auth(user, password)
    conn.request("GET", path, headers=headers)
    resp = conn.getresponse()
    body = resp.read().decode(errors="replace")
    out(status=resp.status, roundcube="rcmail" in body or "roundcube" in body.lower())


def cmd_web_assets(ip, vhost):
    """Fetch the login page and everything static it references."""
    web = Web(ip, vhost)
    resp, page = web.request("GET", "/")
    links = sorted(set(re.findall(r'(?:src|href)="(\.?/?(?:skins|plugins|program)/[^"?]+)', page)))
    failed = {}
    for link in links:
        status = web.request("GET", "/" + link.lstrip("./"))[0].status
        if status != 200:
            failed[link] = status
    out(status=resp.status, elastic="skins/elastic" in page, assets=len(links), failed=failed)


def cmd_web_password(ip, vhost, user, current, new):
    web = Web(ip, vhost)
    if not web.login(user, current):
        out(ok=False, stage="login")
        return
    web.request("GET", "/?_task=settings&_action=plugin.password")
    _, page = web.request(
        "POST",
        "/?_task=settings&_action=plugin.password-save",
        {"_token": web.token, "_curpasswd": current, "_newpasswd": new, "_confpasswd": new},
    )
    match = re.search(r'display_message\("([^"]*)","(\w+)"', page)
    message = match.groups() if match else (None, None)
    out(ok=message[1] == "confirmation", message=message[0], kind=message[1])


def cmd_web_send(ip, vhost, user, password, to, subject):
    """Send a mail through the compose form, as the browser would."""
    web = Web(ip, vhost)
    if not web.login(user, password):
        out(ok=False, stage="login")
        return
    resp, page = web.request("GET", "/?_task=mail&_action=compose")
    if resp.status == 302:
        resp, page = web.request("GET", resp.getheader("Location"))
    compose_id = re.search(r'"compose_id":"([^"]+)"', page).group(1)
    identity = re.search(r'<select name="_from"[^>]*>\s*<option value="(\d+)"', page).group(1)
    _, result = web.request(
        "POST",
        "/?_task=mail&_action=send",
        {"_token": web.token, "_task": "mail", "_action": "send", "_id": compose_id, "_attachments": "", "_from": identity,
         "_to": to, "_cc": "", "_bcc": "", "_replyto": "", "_followupto": "", "_subject": subject, "_draft": "",
         "_store_target": "Sent", "_is_html": "0", "_framed": "1", "_message": "Sent through the webmail\n"},
    )
    errors = re.findall(r'display_message\("([^"]*)","error"', result)
    out(ok="sent_successfully" in result, errors=errors, response=result[-300:] if "sent_successfully" not in result else "")


def cmd_web_sieve(ip, vhost, user, password):
    """Open the filter settings; Roundcube talks to ManageSieve for them."""
    web = Web(ip, vhost)
    if not web.login(user, password):
        out(ok=False, stage="login")
        return
    resp, page = web.request("GET", "/?_task=settings&_action=plugin.managesieve")
    errors = re.findall(r'display_message\("([^"]*)","error"', page)
    out(ok=resp.status == 200 and "filtersetslist" in page and not errors, status=resp.status, errors=errors)


PROPFIND = '<?xml version="1.0"?><propfind xmlns="DAV:"><prop><displayname/><resourcetype/></prop></propfind>'


def cmd_dav(ip, vhost, method, path, user="", password="", body=""):
    """One WebDAV request; prints status and response body."""
    conn = http.client.HTTPSConnection(ip, 443, context=ctx(), timeout=30)
    headers = {"Host": vhost, "Depth": "0", "Content-Type": "text/calendar" if method == "PUT" else "application/xml"}
    if user:
        headers["Authorization"] = basic_auth(user, password)
    conn.request(method, path, body or (PROPFIND if method == "PROPFIND" else None), headers)
    resp = conn.getresponse()
    text = resp.read().decode(errors="replace")
    out(status=resp.status, location=resp.getheader("Location"), body=text[:2000])


def cmd_dav_parallel(ip, vhost, path, user, password, count):
    """The same PROPFIND several times at once; prints all statuses."""

    def propfind(_):
        conn = http.client.HTTPSConnection(ip, 443, context=ctx(), timeout=60)
        headers = {"Host": vhost, "Depth": "0", "Content-Type": "application/xml", "Authorization": basic_auth(user, password)}
        conn.request("PROPFIND", path, PROPFIND, headers)
        return conn.getresponse().status

    with concurrent.futures.ThreadPoolExecutor(int(count)) as pool:
        out(statuses=list(pool.map(propfind, range(int(count)))))


def sink_session(conn, outfile, tls):
    """One SMTP session; returns when the client is done."""
    f = conn.makefile("rwb")
    env = {"rcpt": [], "tls": False}

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
            if tls and not env["tls"]:
                say("250-sink.sovtest")
                say("250 STARTTLS")
            else:
                say("250 sink.sovtest")
        elif upper == "STARTTLS" and tls:
            say("220 go ahead")
            conn = tls.wrap_socket(conn, server_side=True)
            f = conn.makefile("rwb")
            env["tls"] = True
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
            env = {"rcpt": [], "tls": env["tls"]}
            say("250 queued")
        elif upper == "QUIT":
            say("221 bye")
            break
        else:
            say("250 ok")


def cmd_sink(port, outfile, certfile=None, keyfile=None):
    """Minimal SMTP server recording envelopes as JSON lines (plays a foreign MX).

    With a certificate it offers STARTTLS, without any verification of its own.
    """
    tls = None
    if certfile:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(certfile, keyfile)
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", int(port)))
    srv.listen()
    while True:
        conn, _ = srv.accept()
        try:
            sink_session(conn, outfile, tls)
        except OSError:  # includes ssl.SSLError: clients may abort after the handshake
            pass
        finally:
            conn.close()


COMMANDS = {
    "submission-plain": cmd_submission_plain,
    "submit": cmd_submit,
    "smtp": cmd_smtp,
    "imap-count": cmd_imap_count,
    "imap-login": cmd_imap_login,
    "imap-hold": cmd_imap_hold,
    "imap-plain": cmd_imap_plain,
    "imap-headers": cmd_imap_headers,
    "imap-move": cmd_imap_move,
    "dkim-verify": cmd_dkim_verify,
    "tls": cmd_tls,
    "sieve": cmd_sieve,
    "sieve-login": cmd_sieve_login,
    "web-login": cmd_web_login,
    "web-basic": cmd_web_basic,
    "web-assets": cmd_web_assets,
    "web-password": cmd_web_password,
    "web-send": cmd_web_send,
    "web-sieve": cmd_web_sieve,
    "dav": cmd_dav,
    "dav-parallel": cmd_dav_parallel,
    "sink": cmd_sink,
}

if __name__ == "__main__":
    COMMANDS[sys.argv[1]](*sys.argv[2:])
