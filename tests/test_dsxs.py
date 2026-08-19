#!/usr/bin/env python3

"""
Regression suite for dsxs.py.

Runs the real CLI as a subprocess against deterministic localhost fixtures
(see fixture_server.py / proxy_server.py). No third-party host is contacted.

    python3 -m unittest discover -s tests -v
"""

import os
import re
import socket
import subprocess
import sys
import concurrent.futures
import unittest
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import browser
import fixture_server
import proxy_server

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DSXS = os.path.join(ROOT, "dsxs.py")

VULNERABLE_REGEX = r"\(i\) (?P<phase>GET|POST) parameter '(?P<parameter>[^']+)' appears to be XSS vulnerable \((?P<info>.+)\)"


def run(*args, timeout=120):
    process = subprocess.run([sys.executable, DSXS] + list(args), stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, timeout=timeout)
    return process.stdout.decode("utf-8", "replace")


def findings(output):
    return [_.groupdict() for _ in re.finditer(VULNERABLE_REGEX, output)]


def closed_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = fixture_server.Server()
        cls.addClassCleanup(cls.server.stop)

    def setUp(self):
        self.server.requests.clear()

    def url(self, path):
        return self.server.url + path

    def scan(self, path, *args):
        return run("-u", self.url(path), *args)

    def assertVulnerable(self, output, parameter="q", phase="GET", info=None):
        found = findings(output)
        matching = [_ for _ in found if _["parameter"] == parameter and _["phase"] == phase]
        self.assertTrue(matching, "expected %s parameter %r to be reported; got %r\n%s" % (phase, parameter, found, output))
        if info:
            self.assertIn(info, matching[0]["info"])
        self.assertIn("possible vulnerabilities found", output)

    def assertNotVulnerable(self, output, parameter=None):
        found = findings(output)
        if parameter is None:
            self.assertEqual([], found, output)
            self.assertIn("no vulnerabilities found", output)
        else:
            self.assertEqual([], [_ for _ in found if _["parameter"] == parameter],
                             "parameter %r should not be reported\n%s" % (parameter, output))


class TestContexts(Base):
    """Baseline detection coverage: one case per REGULAR_PATTERNS entry."""

    def test_pure_text(self):
        self.assertVulnerable(self.scan("/text?q=1"), info="pure text response")

    def test_comment(self):
        self.assertVulnerable(self.scan("/comment?q=1"), info="inside the comment")

    def test_script_single_quotes(self):
        self.assertVulnerable(self.scan("/script_sq?q=1"), info="inside single-quotes")

    def test_script_double_quotes(self):
        self.assertVulnerable(self.scan("/script_dq?q=1"), info="inside double-quotes")

    def test_script(self):
        self.assertVulnerable(self.scan("/script?q=1"), info="enclosed by <script> tags")

    def test_outside_of_tags(self):
        self.assertVulnerable(self.scan("/plain?q=1"), info="outside of tags")

    def test_tag_single_quotes(self):
        self.assertVulnerable(self.scan("/attr_sq?q=1"), info="inside single-quotes")

    def test_tag_double_quotes(self):
        self.assertVulnerable(self.scan("/attr_dq?q=1"), info="inside double-quotes")

    def test_tag_outside_of_quotes(self):
        self.assertVulnerable(self.scan("/attr_unq?q=1"), info="outside of quotes")

    def test_tag_outside_of_quotes_fully_filtered(self):
        """Landing in an unquoted attribute is exploitable through a plain
        space alone, so it must be reported even when every special character
        was filtered away (confirmed by TestBrowserOracle)."""

        self.assertVulnerable(self.scan("/attr_unq_strip?q=1"), info="outside of quotes")

    def test_dom(self):
        output = self.scan("/dom")
        self.assertIn("page itself appears to be XSS vulnerable (DOM)", output)
        self.assertIn("no usable GET/POST parameters found", output)

    def test_error_page_reflection(self):
        self.assertVulnerable(self.scan("/notfound?q=1"), info="outside of tags")

    def test_post_parameter(self):
        self.assertVulnerable(run("-u", self.url("/plain"), "--data", "q=1"), phase="POST", info="outside of tags")

    def test_both_phases(self):
        output = run("-u", self.url("/both?q=1"), "--data", "q=1")
        self.assertVulnerable(output, phase="GET")
        self.assertVulnerable(output, phase="POST")

    def test_no_filtering_reported(self):
        self.assertVulnerable(self.scan("/plain?q=1"), info="no filtering")

    def test_partial_filtering_reported(self):
        self.assertVulnerable(self.scan("/stripangle?q=1"), info="some filtering")


class TestNoFalsePositives(Base):
    def test_html_escaped(self):
        self.assertNotVulnerable(self.scan("/escaped?q=1"))

    def test_all_characters_stripped(self):
        self.assertNotVulnerable(self.scan("/strip?q=1"))

    def test_no_parameters(self):
        output = self.scan("/escaped")
        self.assertIn("no usable GET/POST parameters found", output)
        self.assertNotVulnerable(output)

    def test_unrelated_parameter_not_blamed(self):
        """A parameter whose ``name=value`` text also occurs inside another
        parameter's value must not be blamed for the other one's reflection."""

        output = self.scan("/plain/b?a=1&b=?a=1")
        self.assertVulnerable(output, parameter="b")
        self.assertNotVulnerable(output, parameter="a")

    def test_fragment_parameters_not_scanned(self):
        output = self.scan("/plain?q=1#a=2&b=3")
        self.assertVulnerable(output, parameter="q")
        self.assertNotIn("parameter 'b'", output)
        self.assertNotIn("parameter 'a'", output)


class TestPatternSemantics(Base):
    def test_template_literal_is_not_a_naked_script_context(self):
        """A reflection trapped inside a `template literal` cannot be broken
        out of with ';' alone, so it must not be reported."""

        self.assertNotVulnerable(self.scan("/script_bt?q=1"))

    def test_backslash_is_not_an_escape_in_text(self):
        self.assertVulnerable(self.scan("/jsescape_text?q=1"), info="pure text response")

    def test_backslash_does_defuse_a_script_breakout(self):
        """"</script" only terminates a script when followed by whitespace, "/"
        or ">", so an escaped angle bracket really is inert there."""

        self.assertNotVulnerable(self.scan("/script_jsescape?q=1"))

    def test_backslash_does_not_protect_an_attribute(self):
        self.assertVulnerable(self.scan("/attr_sq_jsescape?q=1"), info="inside single-quotes")

    def test_backslash_does_defuse_a_comment_breakout(self):
        """Unlike HTML text, a comment can only be closed by a literal "-->",
        so escaping ">" is enough there (confirmed by TestBrowserOracle)."""

        self.assertNotVulnerable(self.scan("/jsescape_comment?q=1"))

    def test_backslash_is_not_an_html_escape(self):
        """JS-style escaping (\\<, \\>) does not neutralise anything in an
        HTML context, so such a reflection must still be reported."""

        self.assertVulnerable(self.scan("/jsescape?q=1"), info="outside of tags")

    def test_raw_angle_brackets_inside_a_js_string(self):
        """Correct JS string quoting does not help when < and > survive: the
        </script> terminator is still reachable."""

        self.assertVulnerable(self.scan("/script_sq_esc?q=1"), info="<script>")

    def test_template_literal_breakout(self):
        """HTML escaping of < and > does not protect a `template literal`:
        a back-tick still closes it."""

        self.assertVulnerable(self.scan("/script_bt_html?q=1"), info="back-ticks")

    def test_dom_snippet_is_bounded(self):
        output = self.scan("/dom_long")
        self.assertIn("XSS vulnerable (DOM)", output)
        evidence = [_ for _ in output.splitlines() if _.startswith("  (o)")][0]
        self.assertLess(len(evidence), 600, "evidence snippet is unbounded (%d chars)" % len(evidence))

    def test_dom_snippet_is_reported_verbatim(self):
        """The evidence snippet must come from the real response, not from the
        internally pre-filtered copy."""

        output = self.scan("/dom_quoted")
        self.assertIn("page itself appears to be XSS vulnerable (DOM)", output)
        self.assertIn('document.write("<b>" + p + "</b>")', output)


class TestDom(Base):
    def test_bare_location_hash_source(self):
        self.assertIn("XSS vulnerable (DOM)", self.scan("/dom_hash"))

    def test_outer_html_sink(self):
        self.assertIn("XSS vulnerable (DOM)", self.scan("/dom_outer"))

    def test_jquery_html_sink(self):
        self.assertIn("XSS vulnerable (DOM)", self.scan("/dom_jquery"))

    def test_source_name_inside_a_string_literal_is_ignored(self):
        self.assertNotIn("(DOM)", self.scan("/dom_string_literal"))

    def test_sink_behind_escape_is_ignored(self):
        self.assertNotIn("(DOM)", self.scan("/dom_escaped"))


class TestDetectionGaps(Base):
    def test_escaped_reflection_before_raw_one(self):
        """An earlier, harmless (escaped) reflection must not mask a later
        raw one inside the very same context."""

        self.assertVulnerable(self.scan("/escaped_then_raw?q=1"), info="outside of tags")

    def test_parameter_name_with_punctuation(self):
        for name in ("user-name", "user.name", "a-b.c", "a[b]", "first name"):
            with self.subTest(name=name):
                quoted = urllib.parse.quote(name)
                output = self.scan("/plain/%s?%s=1" % (quoted, quoted))
                self.assertIn("scanning GET parameter '%s'" % quoted, output)
                self.assertVulnerable(output, parameter=quoted)

    def test_non_utf8_charset(self):
        """Response charset from Content-Type must be honoured."""

        self.assertVulnerable(self.scan("/utf16?q=1"), info="outside of tags")

    def test_empty_parameter_before_fragment(self):
        """``?q=#frag`` leaves an empty value that must still be seeded."""

        self.assertVulnerable(self.scan("/numeric?q=#frag"), info="outside of tags")

    def test_empty_parameter(self):
        self.assertVulnerable(self.scan("/numeric?q="), info="outside of tags")

    def test_truncating_application(self):
        """When appending pushes the payload past a length limit, the value
        itself has to be replaced."""

        self.assertVulnerable(self.scan("/truncated?q=" + "a" * 48), info="outside of tags")

    def test_non_ascii_url(self):
        self.assertVulnerable(self.scan("/plain?q=café naïve"), info="outside of tags")

    def test_whitespace_substituting_sanitizer(self):
        """A sanitizer that blanks out < and > (instead of dropping them)
        leaves a reflection containing spaces, which must still be matched."""

        self.assertVulnerable(self.scan("/spacefilter?q=1"), info="inside single-quotes")

    def test_hash_inside_post_body(self):
        """'#' does not start a fragment in a POST body, so the payload has to
        go after the complete value."""

        self.assertVulnerable(run("-u", self.url("/after_hash"), "--data", "q=1#tail"), phase="POST")

    def test_compressed_response(self):
        """Absent Accept-Encoding lets a server pick any coding (RFC 7231
        5.3.4), so an explicit one must be requested."""

        self.assertVulnerable(self.scan("/compressed?q=1"), info="outside of tags")

    def test_session_cookie(self):
        """Cookies handed out by the target must be kept for the scan."""

        self.assertVulnerable(self.scan("/session?q=1"), info="outside of tags")


class TestTransport(Base):
    def test_connection_failure_is_reported(self):
        output = run("-u", "http://127.0.0.1:%d/plain?q=1" % closed_port())
        self.assertIn(" (x) ", output)
        self.assertRegex(output, r"(?i)refused|error|unreachable|timed out")

    def test_headers_are_sent(self):
        self.scan("/escaped?q=1", "--cookie", "PHPSESSID=42", "--user-agent", "dsxs-test-ua", "--referer", "http://ref.local/")
        headers = self.server.requests[0][2]
        self.assertEqual("PHPSESSID=42", headers.get("Cookie"))
        self.assertEqual("dsxs-test-ua", headers.get("User-Agent"))
        self.assertEqual("http://ref.local/", headers.get("Referer"))

    def test_default_user_agent(self):
        self.scan("/escaped?q=1")
        self.assertIn("Damn Small XSS Scanner", self.server.requests[0][2].get("User-Agent", ""))

    def test_scheme_is_optional(self):
        self.assertVulnerable(run("-u", self.server.url.replace("http://", "") + "/plain?q=1"))


class TestUrlNormalization(Base):
    def test_uppercase_scheme(self):
        self.assertVulnerable(run("-u", self.url("/plain?q=1").replace("http://", "HTTP://")))

    def test_protocol_relative_url(self):
        self.assertVulnerable(run("-u", self.url("/plain?q=1").replace("http://", "//")))

    def test_host_starting_with_http(self):
        """A bare host name that happens to begin with "http" is not a URL."""

        proxy = proxy_server.Proxy(target="127.0.0.1:%d" % self.server.server_address[1])
        self.addCleanup(proxy.stop)
        output = run("-u", "httpfixture.invalid/plain?q=1", "--proxy", proxy.url)
        self.assertNotIn("unknown url type", output)
        self.assertVulnerable(output)


class TestIPv6(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.server = fixture_server.Server(host="::1")
        except OSError as ex:
            raise unittest.SkipTest("no IPv6 loopback available (%s)" % ex)
        cls.addClassCleanup(cls.server.stop)

    def test_bracketed_ipv6_host(self):
        """The square brackets of an IPv6 authority must survive URL escaping."""

        self.assertIn("appears to be XSS vulnerable", run("-u", self.server.url + "/plain?q=1"))


class TestTLS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = fixture_server.Server(https=True)
        cls.addClassCleanup(cls.server.stop)

    def test_self_signed_certificate(self):
        output = run("-u", self.server.url + "/plain?q=1")
        self.assertIn("appears to be XSS vulnerable", output)


class TestProxy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proxy = proxy_server.Proxy()
        cls.http = fixture_server.Server()
        cls.https = fixture_server.Server(https=True)
        for server in (cls.proxy, cls.http, cls.https):
            cls.addClassCleanup(server.stop)

    def setUp(self):
        self.proxy.requests.clear()

    def test_http_through_proxy(self):
        output = run("-u", self.http.url + "/plain?q=1", "--proxy", self.proxy.url)
        self.assertIn("appears to be XSS vulnerable", output)
        self.assertTrue(self.proxy.requests, "proxy was bypassed")

    def test_https_through_proxy(self):
        output = run("-u", self.https.url + "/plain?q=1", "--proxy", self.proxy.url)
        self.assertIn("appears to be XSS vulnerable", output)
        self.assertTrue([_ for _ in self.proxy.requests if _[0] == "CONNECT"], "proxy was bypassed for https")


EXPLOITABLE = ("plain", "attr_sq", "attr_dq", "attr_unq", "script", "script_sq", "script_dq", "comment",
               "script_sq_esc", "script_bt_html", "spacefilter", "stripangle", "jsescape", "escaped_then_raw",
               "notfound", "utf16", "numeric", "truncated", "compressed", "attr_sq_jsescape", "attr_unq_bt", "attr_unq_strip", "textarea", "title", "style")

SAFE = ("escaped", "strip", "script_bt", "jsescape_comment", "script_jsescape", "attr_dq_entity")

SCAN_PATH = {"truncated": "/truncated?q=" + "a" * 48}


@unittest.skipUnless(browser.available(), "no Chromium/Chrome binary available")
class TestBrowserOracle(Base):
    """Cross-checks every verdict against what really happens in a browser."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        modes = EXPLOITABLE + SAFE
        with concurrent.futures.ThreadPoolExecutor(4) as pool:
            payloads = pool.map(lambda _: browser.exploitable("%s/%s?q=%%s" % (cls.server.url, _)), modes)
        cls.verdicts = dict(zip(modes, payloads))

    def test_fixtures_behave_as_documented(self):
        """Guards the oracle itself: the fixtures must really be (in)vulnerable."""

        for mode in EXPLOITABLE:
            with self.subTest(mode=mode):
                self.assertIsNotNone(self.verdicts[mode], "fixture %r turned out not to be exploitable" % mode)
        for mode in SAFE:
            with self.subTest(mode=mode):
                self.assertIsNone(self.verdicts[mode], "fixture %r is exploitable after all (via %r)" % (mode, self.verdicts[mode]))

    def test_verdicts_match_the_browser(self):
        for mode in EXPLOITABLE + SAFE:
            with self.subTest(mode=mode):
                reported = bool(findings(self.scan(SCAN_PATH.get(mode, "/%s?q=1" % mode))))
                self.assertEqual(self.verdicts[mode] is not None, reported,
                                 "%s: browser %s, dsxs %s" % (mode, "executed %r" % self.verdicts[mode] if self.verdicts[mode] else "found nothing",
                                                              "reported" if reported else "stayed silent"))

    def test_text_plain_is_a_deliberate_heuristic(self):
        """A reflection in a text/plain body is reported even though a modern
        browser will not render it; content sniffing and legacy clients still
        make it worth flagging."""

        self.assertVulnerable(self.scan("/text?q=1"), info="pure text response")
        self.assertIsNone(browser.exploitable("%s/text?q=%%s" % self.server.url))


class TestSourceConstraints(unittest.TestCase):
    def test_under_100_lines(self):
        with open(DSXS, "rb") as handle:
            lines = handle.read().decode("utf-8").splitlines()
        code = [_ for _ in lines if _.strip() and not _.strip().startswith('#')]
        self.assertLess(len(code), 100, "dsxs.py must stay under 100 lines of code (got %d)" % len(code))
        self.assertLessEqual(len(lines), 100, "dsxs.py grew to %d physical lines" % len(lines))

    def test_imports_without_warnings(self):
        process = subprocess.run([sys.executable, "-W", "error", "-c",
                                  "import importlib.util as u; s = u.spec_from_file_location('dsxs', %r); m = u.module_from_spec(s); s.loader.exec_module(m)" % DSXS],
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(0, process.returncode, process.stdout.decode("utf-8", "replace"))

    def test_cli_help(self):
        output = run("-h")
        for option in ("--url", "--data", "--cookie", "--user-agent", "--referer", "--proxy"):
            self.assertIn(option, output)

    def test_cli_version(self):
        self.assertRegex(run("--version"), r"\d+\.\d+")

    def test_no_arguments_prints_help(self):
        self.assertIn("--url", run())


if __name__ == "__main__":
    unittest.main()
