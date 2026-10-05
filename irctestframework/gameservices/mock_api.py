#!/usr/bin/env python3
"""Mock of the games API used by third/gameservices and conduit.

API (HTTPS, Bearer key):
  POST /api/v1/internal/irc/verify          {token} -> {username, token_id}
  POST /api/v1/internal/irc/join            {username, asset_uid} -> {allow, channel, mode}
  POST /api/v1/internal/irc/access          same as join
  POST /api/v1/internal/irc/sessions        {sessions:[{username, token_id}]} -> {revoke:[...]}
  POST /api/v1/internal/irc/games           {} -> {games:[{asset_uid, name, channel}]}
  POST /api/v1/internal/irc/service-token   {} -> {username, token, host}
  GET  /api/v1/internal/irc/channels        -> {channels:[{asset_uid, channel}]}
  GET  /api/v1/internal/irc/conduit         websocket (subprotocol blazium.conduit)

Tokens are stateless: "gs.<username>.<token_id>". Assets are registered by the
tests over the plain-HTTP control port:
  POST /__mock/asset     {uid, name, listed, guests, owners, licensed, banned, suspended}
  POST /__mock/revoke    {username, token_id}   token_id "*" ends every session
  POST /__mock/unrevoke  {username, token_id}
  POST /__mock/fail      {match, status, delay, count}   match is a substring of path+body
                         status 0 drops the connection, 200 answers success:false,
                         -1 only delays the normal answer
  POST /__mock/unfail    {match}
  POST /__mock/conduit   {op, ...}   pushed to every connected conduit websocket
  GET  /__mock/conduit/state
  GET  /__mock/log?match=...
  GET  /__mock/health
"""

import argparse
import base64
import hashlib
import json
import os
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
SERVICE_NICK = "blazium"


def channel_for(uid):
    return "#g" + hashlib.sha256(uid.encode()).hexdigest()[:16]


class State:
    def __init__(self, key):
        self.key = key
        self.lock = threading.Lock()
        self.assets = {}
        self.revoked = set()
        self.failures = []
        self.requests = []
        self.conduits = []
        self.conduit_received = []
        self.conduit_connects = 0

    def log_request(self, path, body):
        with self.lock:
            self.requests.append({"t": time.time(), "path": path, "body": body})
            if len(self.requests) > 20000:
                self.requests = self.requests[-10000:]

    def failure_for(self, path, body):
        hay = path + " " + body
        with self.lock:
            for f in self.failures:
                if f["match"] in hay and f["count"] != 0:
                    if f["count"] > 0:
                        f["count"] -= 1
                    return dict(f)
        return None

    def is_revoked(self, username, token_id):
        with self.lock:
            return (username, token_id) in self.revoked or (username, "*") in self.revoked


def parse_token(token):
    if not isinstance(token, str) or not token.startswith("gs."):
        return None, None
    parts = token.split(".")
    if len(parts) != 3 or not parts[1] or not parts[2]:
        return None, None
    return parts[1], parts[2]


def decide(asset, username):
    if username == SERVICE_NICK:
        return True, "o"
    if username in asset.get("owners", []):
        return True, "o"
    if username in asset.get("banned", []):
        return False, ""
    if username in asset.get("licensed", []):
        if username in asset.get("suspended", []):
            return True, ""
        return True, "v"
    if asset.get("guests"):
        return True, ""
    return False, ""


def make_handler(state):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            if os.environ.get("GS_MOCK_VERBOSE"):
                sys.stderr.write("mock: " + (fmt % args) + "\n")

        def reply(self, status, obj):
            raw = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def ok(self, data):
            self.reply(200, {"success": True, "data": data})

        def err(self, status, message):
            self.reply(status, {"success": False, "error": {"message": message}})

        def body(self):
            n = int(self.headers.get("Content-Length") or 0)
            return self.rfile.read(n).decode("utf-8", "replace") if n else ""

        def authed(self):
            return self.headers.get("Authorization", "") == "Bearer " + state.key

        def do_GET(self):
            path = urllib.parse.urlparse(self.path).path
            state.log_request(path, "")
            if path == "/api/v1/internal/irc/conduit":
                return self.conduit()
            if path == "/api/v1/internal/irc/channels":
                if not self.authed():
                    return self.err(401, "unauthorized")
                f = state.failure_for(path, "")
                if f:
                    time.sleep(f.get("delay", 0))
                    return self.err(f.get("status", 503), "injected")
                with state.lock:
                    rows = [{"asset_uid": u, "channel": channel_for(u)}
                            for u, a in state.assets.items() if a.get("listed", True)]
                return self.ok({"channels": rows})
            return self.err(404, "not found")

        def do_POST(self):
            path = urllib.parse.urlparse(self.path).path
            raw = self.body()
            state.log_request(path, raw)
            if not self.authed():
                return self.err(401, "unauthorized")
            f = state.failure_for(path, raw)
            if f:
                time.sleep(f.get("delay", 0))
                status = f.get("status", 503)
            if f and status != -1:
                if status == 0:
                    self.close_connection = True
                    self.connection.shutdown(socket.SHUT_RDWR)
                    return
                if status == 200:
                    return self.reply(200, {"success": False})
                return self.err(status, "injected")
            try:
                body = json.loads(raw) if raw else {}
            except ValueError:
                return self.err(400, "bad json")
            if path == "/api/v1/internal/irc/verify":
                username, token_id = parse_token(body.get("token"))
                if not username or state.is_revoked(username, token_id):
                    return self.err(401, "Invalid or expired token")
                return self.ok({"username": username, "token_id": token_id})
            if path in ("/api/v1/internal/irc/join", "/api/v1/internal/irc/access"):
                username = body.get("username", "")
                uid = body.get("asset_uid", "")
                with state.lock:
                    asset = state.assets.get(uid)
                    asset = dict(asset) if asset else None
                if not asset:
                    return self.err(404, "Game not found")
                allow, mode = decide(asset, username)
                return self.ok({"username": username, "allow": allow,
                                "channel": channel_for(uid) if allow else "", "mode": mode})
            if path == "/api/v1/internal/irc/sessions":
                revoke = []
                for row in body.get("sessions", []):
                    if state.is_revoked(row.get("username"), row.get("token_id")):
                        revoke.append({"username": row.get("username"), "token_id": row.get("token_id")})
                return self.ok({"revoke": revoke})
            if path == "/api/v1/internal/irc/games":
                with state.lock:
                    games = [{"asset_uid": u, "name": a.get("name", u), "channel": channel_for(u)}
                             for u, a in state.assets.items() if a.get("listed", True)]
                return self.ok({"games": games})
            if path == "/api/v1/internal/irc/service-token":
                return self.ok({"username": SERVICE_NICK, "token": "gs.%s.web" % SERVICE_NICK,
                                "host": os.environ.get("GS_MOCK_IRC_HOST", "localhost")})
            return self.err(404, "not found")

        def conduit(self):
            if not self.authed():
                return self.err(401, "unauthorized")
            if self.headers.get("Upgrade", "").lower() != "websocket":
                return self.err(400, "websocket required")
            key = self.headers.get("Sec-WebSocket-Key", "")
            accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
            self.send_response(101)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept)
            if "blazium.conduit" in self.headers.get("Sec-WebSocket-Protocol", ""):
                self.send_header("Sec-WebSocket-Protocol", "blazium.conduit")
            self.end_headers()
            self.wfile.flush()
            sock = self.connection
            wlock = threading.Lock()
            alive = {"ok": True}

            def send(text):
                payload = text.encode()
                hdr = bytearray([0x81])
                n = len(payload)
                if n < 126:
                    hdr.append(n)
                elif n < 65536:
                    hdr.append(126)
                    hdr += struct.pack("!H", n)
                else:
                    hdr.append(127)
                    hdr += struct.pack("!Q", n)
                with wlock:
                    sock.sendall(bytes(hdr) + payload)

            entry = {"send": send, "alive": alive}
            with state.lock:
                state.conduits.append(entry)
                state.conduit_connects += 1
            try:
                while True:
                    frame = read_frame(self.rfile)
                    if frame is None:
                        break
                    opcode, data = frame
                    if opcode == 8:
                        break
                    if opcode == 9:
                        with wlock:
                            sock.sendall(bytes([0x8A, len(data)]) + data)
                        continue
                    if opcode == 1:
                        with state.lock:
                            state.conduit_received.append(data.decode("utf-8", "replace"))
            finally:
                alive["ok"] = False
                with state.lock:
                    if entry in state.conduits:
                        state.conduits.remove(entry)
                self.close_connection = True

    return Handler


def read_exact(f, n):
    buf = b""
    while len(buf) < n:
        chunk = f.read(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def read_frame(f):
    hdr = read_exact(f, 2)
    if hdr is None:
        return None
    opcode = hdr[0] & 0x0F
    masked = hdr[1] & 0x80
    n = hdr[1] & 0x7F
    if n == 126:
        ext = read_exact(f, 2)
        if ext is None:
            return None
        n = struct.unpack("!H", ext)[0]
    elif n == 127:
        ext = read_exact(f, 8)
        if ext is None:
            return None
        n = struct.unpack("!Q", ext)[0]
    mask = read_exact(f, 4) if masked else b"\0\0\0\0"
    if mask is None:
        return None
    data = read_exact(f, n) if n else b""
    if data is None:
        return None
    if masked:
        data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
    return opcode, data


def make_control(state):
    class Control(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            pass

        def reply(self, status, obj):
            raw = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            u = urllib.parse.urlparse(self.path)
            q = urllib.parse.parse_qs(u.query)
            if u.path == "/__mock/health":
                return self.reply(200, {"ok": True})
            if u.path == "/__mock/log":
                match = q.get("match", [""])[0]
                since = float(q.get("since", ["0"])[0])
                with state.lock:
                    rows = [r for r in state.requests
                            if r["t"] >= since and match in (r["path"] + " " + r["body"])]
                return self.reply(200, {"requests": rows})
            if u.path == "/__mock/conduit/state":
                with state.lock:
                    return self.reply(200, {"connected": len(state.conduits),
                                            "connects": state.conduit_connects,
                                            "received": list(state.conduit_received[-200:])})
            return self.reply(404, {"error": "not found"})

        def do_POST(self):
            u = urllib.parse.urlparse(self.path)
            n = int(self.headers.get("Content-Length") or 0)
            try:
                body = json.loads(self.rfile.read(n) or b"{}")
            except ValueError:
                return self.reply(400, {"error": "bad json"})
            with state.lock:
                if u.path == "/__mock/asset":
                    uid = body["uid"]
                    asset = state.assets.get(uid, {})
                    asset.update({k: v for k, v in body.items() if k != "uid"})
                    asset.setdefault("listed", True)
                    asset.setdefault("name", uid)
                    state.assets[uid] = asset
                    return self.reply(200, {"channel": channel_for(uid)})
                if u.path == "/__mock/revoke":
                    state.revoked.add((body["username"], body.get("token_id", "*")))
                    return self.reply(200, {"ok": True})
                if u.path == "/__mock/unrevoke":
                    state.revoked.discard((body["username"], body.get("token_id", "*")))
                    return self.reply(200, {"ok": True})
                if u.path == "/__mock/fail":
                    state.failures.append({"match": body["match"], "status": int(body.get("status", 503)),
                                           "delay": float(body.get("delay", 0)),
                                           "count": int(body.get("count", -1))})
                    return self.reply(200, {"ok": True})
                if u.path == "/__mock/unfail":
                    state.failures = [f for f in state.failures if f["match"] != body["match"]]
                    return self.reply(200, {"ok": True})
                conduits = list(state.conduits)
            if u.path == "/__mock/conduit":
                sent = 0
                for c in conduits:
                    if c["alive"]["ok"]:
                        try:
                            c["send"](json.dumps(body))
                            sent += 1
                        except OSError:
                            pass
                return self.reply(200, {"sent": sent})
            return self.reply(404, {"error": "not found"})

    return Control


class DualStackServer(ThreadingHTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


class ControlServer(ThreadingHTTPServer):
    daemon_threads = True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=5800)
    ap.add_argument("--control", type=int, default=5801)
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--api-key", default="gs-test-key")
    args = ap.parse_args()

    state = State(args.api_key)
    try:
        api = DualStackServer(("::", args.port), make_handler(state))
    except OSError:
        api = ControlServer(("127.0.0.1", args.port), make_handler(state))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(args.cert, args.key)
    api.socket = ctx.wrap_socket(api.socket, server_side=True)
    control = ControlServer(("127.0.0.1", args.control), make_control(state))
    threading.Thread(target=control.serve_forever, daemon=True).start()
    print("mock api on https://localhost:%d, control on http://127.0.0.1:%d" % (args.port, args.control), flush=True)
    api.serve_forever()


if __name__ == "__main__":
    main()
