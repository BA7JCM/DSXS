#!/usr/bin/env python3

"""
Deterministic local HTTP/HTTPS targets used by the DSXS regression suite.

No third-party targets are ever contacted: every scenario below is a small,
fully reproducible reflection sink served from localhost.

The first path segment selects the sink ("mode"), the optional second path
segment selects which request parameter gets reflected (default: "q").
"""

import gzip
import html
import http.server
import os
import socket
import ssl
import subprocess
import tempfile
import threading
import urllib.parse

HTML = "<html><head><title>fixture</title></head><body>\n%s\n</body></html>"

DOM_PAGE = HTML % "<script>document.write(location.href);</script>"


def _strip(value, chars="<>'\";`"):
    return "".join(_ for _ in value if _ not in chars)


def _escape_js(value):
    return "".join("\\" + _ if _ in "<>'\"" else _ for _ in value)


def _render(mode, value, handler):
    """Returns (body: bytes, content_type: str, status: int)."""

    text, ctype, status = None, "text/html; charset=utf-8", 200

    if mode == "plain":                                                     # raw reflection between tags
        text = HTML % ("<div>%s</div>" % value)
    elif mode == "escaped":                                                 # properly escaped (must NOT be reported)
        text = HTML % ("<div>%s</div>" % html.escape(value))
    elif mode == "strip":                                                   # all interesting characters removed
        text = HTML % ("<div>%s</div>" % _strip(value))
    elif mode == "stripangle":                                              # only < and > removed
        text = HTML % ("<input value='%s'>" % _strip(value, "<>"))
    elif mode == "text":                                                    # pure text response
        text, ctype = value, "text/plain; charset=utf-8"
    elif mode == "attr_sq":
        text = HTML % ("<input type=text value='%s'>" % value)
    elif mode == "attr_dq":
        text = HTML % ('<input type=text value="%s">' % value)
    elif mode == "attr_unq":
        text = HTML % ("<input type=text value=%s>" % value)
    elif mode == "script":
        text = HTML % ("<script>var x = %s;</script>" % value)
    elif mode == "script_sq":
        text = HTML % ("<script>var x = '%s';</script>" % value)
    elif mode == "script_dq":
        text = HTML % ('<script>var x = "%s";</script>' % value)
    elif mode == "script_bt":                                               # template literal, everything but ';' filtered
        text = HTML % ("<script>var x = `%s`;</script>" % _strip(value, "<>'\"`$"))
    elif mode == "jsescape":                                                # JS-style escaping used in an HTML context
        text = HTML % ("<div>%s</div>" % _escape_js(value))
    elif mode == "dom_quoted":                                              # DOM sink whose snippet contains string literals
        text = HTML % '<script>var p = location.search.substr(1);document.write("<b>" + p + "</b>");</script>'
    elif mode == "spacefilter":                                             # sanitizer that blanks out < and > instead of removing them
        text = HTML % ("<input type=text value='%s'>" % value.replace('<', ' ').replace('>', ' '))
    elif mode == "after_hash":                                              # '#' is an ordinary character inside a POST body
        text = HTML % ("<div>%s</div>" % value.split('#', 1)[-1])
    elif mode == "dom_hash":                                                # location.hash source, bare (no "window." prefix)
        text = HTML % "<script>var p = location.hash.substr(1);document.write(p);</script>"
    elif mode == "dom_outer":                                               # outerHTML sink
        text = HTML % "<script>document.body.outerHTML = location.search;</script>"
    elif mode == "dom_jquery":                                              # jQuery .html() sink fed from document.referrer
        text = HTML % "<script>var r = document.referrer;$(document.body).html(r);</script>"
    elif mode == "script_sq_esc":                                           # JS-safe quoting, but < and > pass through
        text = HTML % ("<script>var x = '%s';</script>" % "".join("\\" + _ if _ in "'\"" else _ for _ in value))
    elif mode == "dom_long":                                                # DOM sink buried in a large script
        text = HTML % ("<script>var p=location.search;document.write(p);//%s</script>" % ('A' * 3000))
    elif mode == "jsescape_text":
        text, ctype = _escape_js(value), "text/plain; charset=utf-8"
    elif mode == "jsescape_comment":
        text = HTML % ("<!-- %s -->" % _escape_js(value))
    elif mode == "script_bt_html":                                          # template literal, only < and > filtered
        text = HTML % ("<script>var x = `%s`;</script>" % _strip(value, "<>"))
    elif mode == "script_jsescape":                                         # JS-style escaping inside a JS string: genuinely safe
        text = HTML % ("<script>var x = '%s';</script>" % _escape_js(value))
    elif mode == "attr_sq_jsescape":                                        # ...the very same escaping inside an attribute is not
        text = HTML % ("<input type=text value='%s'>" % _escape_js(value))
    elif mode == "attr_unq_bt":                                             # unquoted attribute, back-tick survives
        text = HTML % ("<input type=text value=%s>" % _strip(value, "<>'\";"))
    elif mode == "attr_unq_strip":                                          # unquoted attribute, only whitespace survives
        text = HTML % ("<input type=text value=%s>" % _strip(value))
    elif mode == "textarea":
        text = HTML % ("<textarea>%s</textarea>" % value)
    elif mode == "title":
        text = "<html><head><title>%s</title></head><body>ok</body></html>" % value
    elif mode == "style":
        text = HTML % ("<style>/* %s */</style>" % value)
    elif mode == "attr_dq_entity":                                          # quotes entity encoded: < and > stay inert
        text = HTML % ('<input type=text value="%s">' % value.replace('"', "&quot;"))
    elif mode == "dom_string_literal":                                      # source name only inside a string literal
        text = HTML % '<script>var x = "location.href";document.write(x);</script>'
    elif mode == "dom_escaped":                                             # sink fed through escape()
        text = HTML % "<script>document.write(escape(location.href));</script>"
    elif mode == "comment":
        text = HTML % ("<!-- %s -->" % value)
    elif mode == "both":                                                    # echoes the GET and the POST value separately
        text = HTML % ("<div>%s</div>\n<div>%s</div>" % (handler.query_value, handler.body_value))
    elif mode == "dom":
        text = DOM_PAGE
    elif mode == "notfound":                                                # reflection inside an error page
        text, status = HTML % ("<div>not found: %s</div>" % value), 404
    elif mode == "escaped_then_raw":                                        # escaped reflection *precedes* the raw one
        text = HTML % ("<div>%s</div>\n<div>%s</div>" % (html.escape(value), value))
    elif mode == "numeric":                                                 # app-side cast: only digit-led values echo
        text = HTML % ("<div>%s</div>" % (value if value[:1].isdigit() else "invalid"))
    elif mode == "truncated":                                               # app-side length limit
        text = HTML % ("<div>%s</div>" % value[:48])
    elif mode == "utf16":                                                   # non-UTF8 charset declared in the header
        return (HTML % ("<div>%s</div>" % value)).encode("utf-16"), "text/html; charset=utf-16", status
    elif mode == "session":                                                 # reflection requires a session cookie
        if "sid=" not in (handler.headers.get("Cookie") or ""):
            handler.extra_headers.append(("Set-Cookie", "sid=fixture; Path=/"))
            text = HTML % "<div>please log in</div>"
        else:
            text = HTML % ("<div>%s</div>" % value)
    elif mode == "compressed":                                             # RFC 7231 5.3.4: absent Accept-Encoding
        text = HTML % ("<div>%s</div>" % value)                            # means *any* coding is acceptable
        if not handler.headers.get("Accept-Encoding"):
            handler.extra_headers.append(("Content-Encoding", "gzip"))
            return gzip.compress(text.encode("utf-8")), ctype, status
    elif mode == "echo":                                                    # echoes request metadata, no reflection
        text = HTML % ("<pre>%s</pre>" % html.escape("\n".join("%s: %s" % _ for _ in handler.headers.items())))
    else:
        text, status = HTML % "<div>unknown fixture mode</div>", 500

    return text.encode("utf-8"), ctype, status


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "DSXSFixture/1.0"

    def log_message(self, *args):
        pass

    def _params(self):
        parsed = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        body = {}
        if self.command == "POST":
            payload = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode("utf-8", "ignore")
            body = urllib.parse.parse_qs(payload, keep_blank_values=True)
        return parsed.path, query, body

    def _handle(self):
        path, query, body = self._params()
        self.server.requests.append((self.command, self.path, dict(self.headers)))
        segments = [urllib.parse.unquote(_) for _ in path.split('/') if _]
        mode = segments[0] if segments else "plain"
        name = segments[1] if len(segments) > 1 else "q"
        self.query_value = query.get(name, [""])[0]
        self.body_value = body.get(name, [""])[0]
        value = self.body_value or self.query_value                          # POST wins, like PHP's default $_REQUEST
        self.extra_headers = []
        body, ctype, status = _render(mode, value, self)
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for header, header_value in self.extra_headers:
            self.send_header(header, header_value)
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = _handle


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, https=False, host="127.0.0.1"):
        self.address_family = socket.AF_INET6 if ':' in host else socket.AF_INET
        super().__init__((host, 0), Handler)
        self.requests = []
        if https:
            self.socket = _tls_context().wrap_socket(self.socket, server_side=True)
        self.url = "%s://%s:%d" % ("https" if https else "http", "[%s]" % host if ':' in host else host, self.server_address[1])
        threading.Thread(target=self.serve_forever, daemon=True).start()

    def stop(self):
        self.shutdown()
        self.server_close()


_CERT = []


def _tls_context():
    """Self-signed certificate, generated once per test run."""

    if not _CERT:
        directory = tempfile.mkdtemp(prefix="dsxs-fixture-")
        key, cert = os.path.join(directory, "key.pem"), os.path.join(directory, "cert.pem")
        subprocess.check_output(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
                                 "-out", cert, "-days", "1", "-subj", "/CN=127.0.0.1"], stderr=subprocess.STDOUT)
        _CERT.extend((key, cert))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(_CERT[1], _CERT[0])
    return context
