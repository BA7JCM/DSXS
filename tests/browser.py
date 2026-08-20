#!/usr/bin/env python3

"""
Ground truth oracle: decides whether a reflection sink is *really* exploitable
by firing real breakout payloads at it inside headless Chromium.

Every payload sets ``document.title`` to a fixed marker (no quotes, no spaces,
so it survives unquoted HTML attributes and naive escapers). If the marker
shows up in the rendered DOM, script execution actually happened.
"""

import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
import urllib.parse

TITLE_REGEX = r"<title>900(\d{3})</title>"                                  # only a *mutated* title proves execution,
                                                                            # the payload text itself is not enough


def _mark(index):
    """Marker statement for payload `index` - quote and space free on purpose.

    It writes to `top` so that the very same payload works unchanged whether it
    runs in the page itself or inside one of the batch iframes below.
    """

    return "top.document.title=%d" % (900000 + index)


BREAKOUTS = ((
    "<svg onload=%s >",                                                     # straight into HTML text
    "1<svg onload=%s >",                                                    # ...for sinks that require a numeric prefix
    "'><svg onload=%s >",                                                   # out of a single quoted attribute
    '"><svg onload=%s >',                                                   # out of a double quoted attribute
    "><svg onload=%s >",                                                    # out of an unquoted attribute
    "1' autofocus onfocus=%s '",                                            # new attribute, single quoted value
    '1" autofocus onfocus=%s "',                                            # new attribute, double quoted value
    "1 autofocus onfocus=%s ",                                              # new attribute after an unquoted value
    "1 oncontentvisibilityautostatechange=%s style=content-visibility:auto ",
    "<img src=x onerror=%s >",                                              # for sinks that parse HTML but do not run <script>
    "0);%s;//",                                                             # JS code position, e.g. inside an event handler
    "--><svg onload=%s >",                                                  # out of an HTML comment
    "</textarea></title></style></script><svg onload=%s >",                 # out of any raw text element
    "1;%s;//",                                                              # unquoted JavaScript
    "1';%s;//",                                                             # out of a single quoted JavaScript string
    '1";%s;//',                                                             # out of a double quoted JavaScript string
    "1`;%s;//",                                                             # out of a template literal
    "1'-(%s)-'",                                                            # out of a single quoted string, without ";"
    '1"-(%s)-"',                                                            # out of a double quoted string, without ";"
    "javascript:%s",                                                        # whole attribute value is an URL
    "${%s}",                                                                # template literal interpolation
))

_BINARY = next(filter(None, (shutil.which(_) for _ in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser"))), None)

# a snap-packaged browser may only write inside its own confinement directory,
# and sees a private /tmp - so its profile cannot live in the usual temp dir
_PROFILE_ROOT = os.path.expanduser("~/snap/chromium/common") if _BINARY and "/snap/" in _BINARY else tempfile.gettempdir()

_local = threading.local()


def available():
    return _BINARY is not None


def version():
    """Path and version of the browser backing the oracle (for CI logs)."""

    if not available():
        return "no Chromium/Chrome binary found"
    reported = subprocess.run([_BINARY, "--version"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    return "%s (%s)" % (_BINARY, reported.stdout.decode("utf-8", "replace").strip())


def _profile():
    if not getattr(_local, "profile", None):
        os.makedirs(_PROFILE_ROOT, exist_ok=True)
        _local.profile = tempfile.mkdtemp(prefix="dsxs-oracle-", dir=_PROFILE_ROOT)
    return _local.profile


def _kill(process):
    """Kills the whole browser process tree.

    The crash handler Chrome spawns inherits our stdout pipe and can outlive
    the browser itself. Killing only the direct child therefore leaves the pipe
    open, and any further read on it blocks forever - which is exactly how this
    used to wedge a CI runner until the job was cancelled.
    """

    try:
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    except OSError:
        process.kill()
    for stream in (process.stdout, process.stderr):
        if stream is not None:
            stream.close()
    process.wait()


def render(url, timeout=30, attempts=3):
    """Returns the DOM of `url` after scripts had their chance to run.

    A browser that cannot start (profile lock, sandbox trouble, missing shared
    memory) prints nothing at all, so that is retried with a clean profile and
    ultimately reported with whatever it wrote to stderr - never silently, or
    the oracle would read a launch failure as "not exploitable".
    """

    reason = "no output"
    for attempt in range(attempts):
        process = subprocess.Popen([_BINARY, "--headless=new", "--disable-gpu", "--no-sandbox", "--no-first-run",
                                    "--disable-extensions", "--disable-background-networking", "--no-default-browser-check",
                                    "--disable-dev-shm-usage", "--disable-crash-reporter", "--disable-breakpad",
                                    "--user-data-dir=%s" % _profile(), "--dump-dom", url],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            out, err = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill(process)
            out, err = b"", b"produced no DOM within %ds" % timeout
        dom = out.decode("utf-8", "replace")
        if "</html>" in dom:
            return dom
        reason = err.decode("utf-8", "replace").strip().splitlines()[-1:] or [reason]
        reason = reason[0][:300]
        _local.profile = None                                               # forces a clean profile on the next try
    raise RuntimeError("headless browser produced no DOM for %r after %d attempts: %s" % (url, attempts, reason))


def selftest():
    """Proves the browser can actually produce DOM in this environment."""

    render("data:text/html,<html><body>ok</body></html>")
    return version()


DOM_BREAKOUTS = ((
    "<svg/onload=%s>",                                                      # space free: browsers percent encode spaces
    "<img/src=x/onerror=%s>",                                               # for sinks parsing HTML without running <script>
    "1;%s;//",                                                              # for eval()-like sinks, where no markup is needed
))


def _probe(template, urls):
    """Loads every URL in its own iframe of one aggregator page.

    Proving that a sink is *not* exploitable means trying the whole breakout
    set, so probing one payload per browser launch made the negative case cost
    as much as the entire rest of the suite. The aggregator collapses a set
    into a single launch; the iframes are same-origin, so a payload that fires
    can still stamp its index onto the top document's title.
    """

    parts = urllib.parse.urlsplit(template)
    query = urllib.parse.urlencode([("u", _) for _ in urls])
    match = re.search(TITLE_REGEX, render("%s://%s/_batch?%s" % (parts.scheme, parts.netloc, query)))
    return int(match.group(1)) if match else None


def dom_exploitable(template):
    """Like exploitable(), but the payload is inserted verbatim.

    location.hash / location.search reach the page *without* URL decoding, so
    a percent encoded payload would never make it to the sink - and browsers
    percent encode "<", ">" and spaces themselves, which is why these payloads
    have to avoid whitespace.
    """

    payloads = [_ % _mark(i) for i, _ in enumerate(DOM_BREAKOUTS)]
    found = _probe(template, [template % _ for _ in payloads])
    return payloads[found] if found is not None else None


def exploitable(template):
    """`template` must contain a single %s placeholder for the payload.

    Returns a payload that achieved script execution, or None.
    """

    payloads = [_ % _mark(i) for i, _ in enumerate(BREAKOUTS)]
    found = _probe(template, [template % urllib.parse.quote(_, safe="") for _ in payloads])
    return payloads[found] if found is not None else None
