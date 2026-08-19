#!/usr/bin/env python3

"""Minimal local forward proxy (absolute-URI GET/POST + CONNECT tunnelling).

Used to prove that --proxy is actually honoured, for both http:// and
https:// targets. It records every request it relays so tests can assert
that traffic really went through it.
"""

import http.client
import http.server
import select
import socket
import threading
import urllib.parse


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *args):
        pass

    def do_CONNECT(self):
        self.server.requests.append(("CONNECT", self.path))
        host, _, port = self.path.partition(':')
        try:
            upstream = socket.create_connection((host, int(port or 443)), timeout=10)
        except Exception:
            self.send_error(502)
            return
        self.send_response(200, "Connection established")
        self.end_headers()
        self.connection.setblocking(False)
        upstream.setblocking(False)
        sockets = [self.connection, upstream]
        while True:
            readable, _, errored = select.select(sockets, [], sockets, 10)
            if errored or not readable:
                break
            for source in readable:
                try:
                    data = source.recv(65536)
                except Exception:
                    data = b""
                if not data:
                    upstream.close()
                    return
                (upstream if source is self.connection else self.connection).sendall(data)

    def _relay(self):
        self.server.requests.append((self.command, self.path))
        parsed = urllib.parse.urlsplit(self.path)
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0)) or None
        connection = http.client.HTTPConnection(self.server.target or parsed.netloc, timeout=10)
        headers = {key: value for key, value in self.headers.items() if key.lower() != "proxy-connection"}
        connection.request(self.command, urllib.parse.urlunsplit(("", "", parsed.path or '/', parsed.query, "")), body, headers)
        response = connection.getresponse()
        payload = response.read()
        self.send_response(response.status)
        for key, value in response.getheaders():
            if key.lower() not in ("transfer-encoding", "content-length", "connection"):
                self.send_header(key, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = _relay


class Proxy(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, target=None):
        super().__init__(("127.0.0.1", 0), Handler)
        self.requests = []
        self.target = target                                             # when set, every request is relayed here regardless of the URL host
        self.url = "http://127.0.0.1:%d" % self.server_address[1]
        threading.Thread(target=self.serve_forever, daemon=True).start()

    def stop(self):
        self.shutdown()
        self.server_close()
