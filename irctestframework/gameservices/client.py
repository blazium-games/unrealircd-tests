"""Clients and mock-API helpers for the gameservices suites."""

import asyncore
import base64
import json
import os
import random
import re
import socket
import string
import sys
import time
import urllib.request
import uuid

import irctestframework.ircclient

CONTROL = os.environ.get("GS_MOCK_CONTROL", "http://127.0.0.1:5801")
PORTS = {"c1": 5661, "c2": 5662, "c3": 5663}
COLORS = {"c1": 31, "c2": 32, "c3": 33}
SERVERS = {"c1": "irc1.test.net", "c2": "irc2.test.net", "c3": "irc3.test.net"}
# Clients from this address are not covered by gameservices::exempt.
NON_EXEMPT = "127.0.0.2"
GS_CAPS = "blazium.games/tags blazium.games/commands blazium.games/membership"
SERVICE_NICK = "blazium"


def control(path, body=None, timeout=10):
    data = None
    if body is not None:
        data = json.dumps(body).encode()
    req = urllib.request.Request(CONTROL + path, data=data, method="POST" if data is not None else "GET")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read() or b"{}")


def new_uid():
    return str(uuid.uuid4())


def new_token_id():
    return "".join(random.choice("0123456789abcdef") for _ in range(24))


def username(prefix):
    """A unique Blazium-style account name (lowercase, digits, dashes)."""
    prefix = re.sub("[^a-z0-9-]", "", prefix.lower())[:12] or "gs"
    return prefix + "-" + "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(7))


def token(user, token_id):
    return "gs.%s.%s" % (user, token_id)


def asset(name=None, listed=True, guests=False, owners=(), licensed=(), banned=(), suspended=(), uid=None):
    """Registers a listing with the mock API. Returns (uid, channel)."""
    uid = uid or new_uid()
    res = control("/__mock/asset", {
        "uid": uid, "name": name or ("Game " + uid[:8]), "listed": listed, "guests": guests,
        "owners": list(owners), "licensed": list(licensed), "banned": list(banned),
        "suspended": list(suspended),
    })
    return uid, res["channel"]


def update_asset(uid, **fields):
    body = {"uid": uid}
    for k, v in fields.items():
        body[k] = list(v) if isinstance(v, (tuple, set)) else v
    return control("/__mock/asset", body)


def revoke(user, token_id="*"):
    control("/__mock/revoke", {"username": user, "token_id": token_id})


def unrevoke(user, token_id="*"):
    control("/__mock/unrevoke", {"username": user, "token_id": token_id})


def fail(match, status=503, delay=0, count=-1):
    control("/__mock/fail", {"match": match, "status": status, "delay": delay, "count": count})


def unfail(match):
    control("/__mock/unfail", {"match": match})


def api_log(match, since=0):
    return control("/__mock/log?match=" + urllib.request.quote(match) + "&since=" + str(since))["requests"]


def conduit_push(op):
    return control("/__mock/conduit", op)


def conduit_state():
    return control("/__mock/conduit/state")


class GSClient(irctestframework.ircclient.IrcClient):
    """IrcClient that can bind a source address, request the gameservices
    caps, and log in with SASL PLAIN or GAMEAUTH before registering."""

    def __init__(self, name, syncchan, bind=None, caps=None, sasl=None, gameauth=None):
        self.bind_ip = bind
        self.gs_caps = caps
        self.gs_sasl = sasl
        self.gs_gameauth = gameauth
        self.sasl_result = None
        prefix = name[:2]
        irctestframework.ircclient.IrcClient.__init__(self, ("127.0.0.1", PORTS[prefix]), name, COLORS[prefix], syncchan)

    def connect(self, address):
        if self.bind_ip:
            self.socket.bind((self.bind_ip, 0))
        return asyncore.dispatcher.connect(self, address)

    def handle_connect(self):
        if self.gs_gameauth:
            self.out("GAMEAUTH " + self.gs_gameauth)
        self.out("CAP LS 302")
        self.out("CAP REQ :message-tags account-tag")
        if self.gs_caps:
            self.out("CAP REQ :" + self.gs_caps)
        if self.gs_sasl:
            self.out("CAP REQ :sasl")
        else:
            self.out("CAP END")
        self.out("USER username x x :Test framework")
        self.out("NICK " + self.nick)

    def found_terminator(self):
        line = self.data_in
        if self.gs_sasl and self.sasl_result is None:
            bare = line.split(" ", 1)[1] if line.startswith("@") else line
            if re.search(r"^:\S+ CAP \S+ ACK :.*\bsasl\b", bare):
                self.out("AUTHENTICATE PLAIN")
            elif bare.startswith("AUTHENTICATE +"):
                user, password = self.gs_sasl
                payload = base64.b64encode(("\0" + user + "\0" + password).encode()).decode()
                self.out("AUTHENTICATE " + payload)
            elif re.search(r"^:\S+ 903 ", bare):
                self.sasl_result = "903"
                self.out("CAP END")
            elif re.search(r"^:\S+ (902|904|905|906|908) ", bare):
                self.sasl_result = bare.split(" ")[1]
                self.out("CAP END")
            elif re.search(r"^:\S+ CAP \S+ NAK :.*\bsasl\b", bare):
                self.sasl_result = "NAK"
                self.out("CAP END")
        irctestframework.ircclient.IrcClient.found_terminator(self)


def new_client(m, name, bind=None, caps=None, sasl=None, gameauth=None):
    if name in m.clients:
        raise Exception("client already exists: " + name)
    obj = GSClient(name, m.syncchan, bind=bind, caps=caps, sasl=sasl, gameauth=gameauth)
    obj.disable_logging = m.disable_logging
    obj.disable_message_tags_check = m.disable_message_tags_check
    m.clients[name] = obj
    return obj


def require_module(m, client):
    """Exits 0 (skip) unless third/gameservices is loaded on the network."""
    client.out("VERSION")
    deadline = time.time() + 6
    seen_end = None
    while time.time() < deadline:
        for line in client.all_lines:
            if re.search(r" 005 .*GAMESERVICES=", line):
                print("\u2714 gameservices module is loaded")
                try:
                    control("/__mock/health")
                except Exception as e:
                    raise Exception("gameservices is loaded but the mock API is not reachable: %s" % e)
                return
            if re.search(r" 351 ", line) and seen_end is None:
                seen_end = time.time()
        if seen_end and time.time() - seen_end > 1:
            break
        asyncore.loop(count=1, timeout=0.1)
    print("SKIP: third/gameservices is not loaded (run irctestframework/gameservices/run-suite)")
    sys.exit(0)


def login(m, client, user, token_id=None):
    """GAMEAUTH on an already registered (exempt) client. Returns the token id."""
    tid = token_id or new_token_id()
    m.sync = 0
    client.out("GAMEAUTH " + token(user, tid))
    m.expect(client, "GAMEAUTH logged in as " + user, r" 1800 \S+ " + re.escape(user) + " ", timeout=10)
    m.expect(client, "nick forced to " + user, r" NICK :?" + re.escape(user) + "$", timeout=10)
    m.sync = 1
    m.multisync()
    return tid


def gamejoin(m, client, uid, numeric="1801", spectate=False):
    client.out(("LFGSUB " if spectate else "GAMEJOIN ") + uid)
    line = wait_for(m, client, r" %s .*%s" % (numeric, re.escape(uid)), timeout=10, what="joined game chat " + uid)
    m.multisync()
    return line


def wait_for(m, client, regex, timeout=10, what=None):
    """Like m.expect with a timeout, but returns the matching line."""
    m.expect(client, what or regex, regex, timeout=timeout)
    return client.expect(what or regex, m.replacestr(client, regex))


def wait_until(m, fn, timeout=10, what="condition"):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if fn():
            print("\u2714 Test passed: " + what)
            return True
        m.wait(0.2)
    raise Exception("timed out waiting for " + what)


class RawClient:
    """Blocking client for handshakes the framework cannot model (failed
    logins, pre-registration commands, disconnects)."""

    def __init__(self, server="c1", bind=NON_EXEMPT, timeout=15):
        self.sock = socket.create_connection(("127.0.0.1", PORTS[server]), timeout=timeout,
                                             source_address=(bind, 0) if bind else None)
        self.sock.settimeout(0.2)
        self.buf = b""
        self.lines = []
        self.closed = False
        self.nick = "gsraw" + "".join(random.choice(string.ascii_lowercase) for _ in range(6))

    def send(self, line):
        print("raw>> " + line)
        try:
            self.sock.sendall((line + "\r\n").encode())
        except OSError:
            self.closed = True

    def pump(self, seconds):
        deadline = time.time() + seconds
        while time.time() < deadline and not self.closed:
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                self.closed = True
                break
            if not chunk:
                self.closed = True
                break
            self.buf += chunk
            while b"\r\n" in self.buf:
                raw, self.buf = self.buf.split(b"\r\n", 1)
                line = raw.decode("utf-8", "replace")
                print("<<raw " + line)
                self.lines.append(line)
                bare = line.split(" ", 1)[1] if line.startswith("@") else line
                if bare.startswith("PING "):
                    self.send("PONG " + bare[5:])

    def expect(self, regex, timeout=10, what=None):
        deadline = time.time() + timeout
        while True:
            for line in self.lines:
                if re.search(regex, line):
                    print("\u2714 Test passed: " + (what or regex))
                    return line
            if time.time() >= deadline or self.closed:
                for line in self.lines:
                    if re.search(regex, line):
                        print("\u2714 Test passed: " + (what or regex))
                        return line
                print("Lines:")
                for line in self.lines:
                    print("  " + line)
                raise Exception("raw client: expected %s (%s)" % (what or regex, "closed" if self.closed else "timeout"))
            self.pump(0.3)

    def not_expect(self, regex, timeout=0, what=None):
        if timeout:
            self.pump(timeout)
        for line in self.lines:
            if re.search(regex, line):
                raise Exception("raw client: unexpected %s: %s" % (what or regex, line))
        print("\u2714 Test passed: " + (what or ("no " + regex)))

    def expect_closed(self, timeout=10, what="connection closed"):
        deadline = time.time() + timeout
        while not self.closed and time.time() < deadline:
            self.pump(0.3)
        if not self.closed:
            raise Exception("raw client: expected the server to close the link")
        print("\u2714 Test passed: " + what)

    def register(self):
        self.send("USER username x x :raw")
        self.send("NICK " + self.nick)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass
        self.closed = True
