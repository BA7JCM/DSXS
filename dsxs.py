#!/usr/bin/python3
import optparse, random, re, ssl, string, urllib, urllib.parse, urllib.request  # Python 3 required

NAME, VERSION, AUTHOR, LICENSE = "Damn Small XSS Scanner (DSXS) < 100 LoC (Lines of Code)", "0.4a", "Miroslav Stampar (@stamparm)", "Public domain (FREE)"

SMALLER_CHAR_POOL    = ('<', '>')                                                           # characters used for XSS tampering of parameter values (smaller set - for avoiding possible SQLi errors)
LARGER_CHAR_POOL     = ('\'', '"', '>', '<', ';', '`')                                      # characters used for XSS tampering of parameter values (larger set)
GET, POST            = "GET", "POST"                                                        # enumerator-like values used for marking current phase
PREFIX_SUFFIX_LENGTH, MAX_REFLECTION_LENGTH, MAX_SNIPPET_LENGTH = 5, 100, 512               # length of random prefix/suffix, maximum length of a reflected payload and of a printed evidence snippet
COOKIE, UA, REFERER = "Cookie", "User-Agent", "Referer"                                     # optional HTTP header names
TIMEOUT, URL_SAFE = 30, "%/:?&=#+;@$,!*'()[]"                                               # connection timeout in seconds and URL characters kept as-is
DOM_FILTER_REGEX = r"(?s)<!--.*?-->|\bescape\([^)]+\)|\([^)]+==[^(]+\)|\"[^\"]+\"|'[^']+'"  # filtering regex used before DOM XSS search

REGULAR_PATTERNS = (                                                                        # each (regular pattern) item consists of (r"context regex", (prerequisite unfiltered characters), "info text", r"content removal regex")
    (r"\A[^<>]*%(chars)s[^<>]*\Z", ('<', '>'), "\".xss.\", pure text response, %(filtering)s filtering", r"\\"),
    (r"<!--[^>]*%(chars)s|%(chars)s[^<]*-->", ('<', '>'), "\"<!--.'.xss.'.-->\", inside the comment, %(filtering)s filtering", r"\\[<>]"),
    (r"(?s)<script[^>]*>[^<]*?'[^<']*%(chars)s|%(chars)s[^<']*'[^<]*</script>", ('\'', ';'), "\"<script>.'.xss.'.</script>\", enclosed by <script> tags, inside single-quotes, %(filtering)s filtering", r"\\'|{[^\n]+}"),
    (r'(?s)<script[^>]*>[^<]*?"[^<"]*%(chars)s|%(chars)s[^<"]*"[^<]*</script>', ('"', ';'), "'<script>.\".xss.\".</script>', enclosed by <script> tags, inside double-quotes, %(filtering)s filtering", r'\\"|{[^\n]+}'),
    (r"(?s)<script[^>]*>[^<]*?`[^<`]*%(chars)s|%(chars)s[^<`]*`[^<]*</script>", ('`', ';'), "\"<script>.`.xss.`.</script>\", enclosed by <script> tags, inside back-ticks, %(filtering)s filtering", r"\\`|{[^\n]+}"),
    (r"(?s)<script[^>]*>[^<]*?%(chars)s|%(chars)s[^<]*</script>", (';',), "\"<script>.xss.</script>\", enclosed by <script> tags, %(filtering)s filtering", r"&(#\d+|[a-z]+);|'[^'\s]+'|\"[^\"\s]+\"|`[^`\n]*`|{[^\n]+}"),
    (r"(?s)<script[^>]*>[^<]*?%(chars)s|%(chars)s[^<]*</script>", ('<', '>'), "\"<script>.xss.</script>\", enclosed by <script> tags, reaching the closing tag, %(filtering)s filtering", r"\\[<>]"),
    (r">[^<]*%(chars)s[^<]*(<|\Z)", ('<', '>'), "\">.xss.<\", outside of tags, %(filtering)s filtering", r"(?s)<script.+?</script>|<!--.*?-->|\\"),
    (r"<[^>]*=\s*'[^>']*%(chars)s[^>']*'[^>]*>", ('\'',), "\"<.'.xss.'.>\", inside the tag, inside single-quotes, %(filtering)s filtering", r"(?s)<script.+?</script>|<!--.*?-->|\\"),
    (r'<[^>]*=\s*"[^>"]*%(chars)s[^>"]*"[^>]*>', ('"',), "'<.\".xss.\".>', inside the tag, inside double-quotes, %(filtering)s filtering", r"(?s)<script.+?</script>|<!--.*?-->|\\"),
    (r"<[^>]*%(chars)s[^>]*>", (), "\"<.xss.>\", inside the tag, outside of quotes, %(filtering)s filtering", r"(?s)<script.+?</script>|<!--.*?-->|=\s*'[^']*'|=\s*\"[^\"]*\""),
)

DOM_PATTERNS = (                                                                            # each (dom pattern) item consists of r"recognition regex"
    r"(?s)<script[^>]*>[^<]*?(var|\n)\s*(\w+)\s*=[^;]*(document\.(location|URL|documentURI|baseURI|referrer)|location\.(href|search|hash|pathname)|window\.location|window\.name)[^;]*;[^<]*(document\.write(ln)?\(|\.innerHTML\s*=|eval\(|setTimeout\(|setInterval\(|location\.(replace|assign)\(|\.outerHTML\s*=|insertAdjacentHTML\(|\.html\(|setAttribute\()[^;]*\2.*?</script>",
    r"(?s)<script[^>]*>[^<]*?(document\.write(?:ln)?\(|\.innerHTML\s*=|eval\(|setTimeout\(|setInterval\(|location\.(replace|assign)\(|\.outerHTML\s*=|insertAdjacentHTML\(|\.html\(|setAttribute\()[^;]*(document\.(location|URL|documentURI|baseURI|referrer)|location\.(href|search|hash|pathname)|window\.location|window\.name).*?</script>",
)

_headers = {}                                                                               # used for storing dictionary with optional header values

def _retrieve_content(url, data=None):
    try:
        response = urllib.request.urlopen(urllib.request.Request(urllib.parse.quote(url, safe=URL_SAFE), data.encode("utf8", "ignore") if data else None, _headers), timeout=TIMEOUT)
    except Exception as ex:
        response = ex if hasattr(ex, "read") else print(" (x) %s" % ex)                     # e.g. connection failure (HTTP errors still carry a body)
    wide = re.search(r"(?i)utf-?(16|32)", response.headers.get_content_charset() or "") if response else None
    return (response.read() if response else b"").decode("utf-%s" % wide.group(1) if wide else "utf8", "ignore")

def scan_page(url, data=None):
    retval, usable = False, False
    url, data = re.sub(r"=([&#]|\Z)", r"=1\g<1>", url) if url else url, re.sub(r"=(&|\Z)", r"=1\g<1>", data) if data else data
    original = _retrieve_content(url, data)
    dom = next(filter(None, (re.search(_, re.sub(DOM_FILTER_REGEX, lambda match: ' ' * len(match.group(0)), original)) for _ in DOM_PATTERNS)), None)   # blanked out, not removed, to keep offsets
    if dom:
        print(" (i) page itself appears to be XSS vulnerable (DOM)")
        print("  (o) ...%s..." % original[dom.start():dom.end()][:MAX_SNIPPET_LENGTH])
        retval = True
    try:
        for phase in (GET, POST):
            current = url.split('#')[0] if phase is GET else (data or "")                   # fragments never reach the server
            for match in re.finditer(r"((\A|[?&])(?P<parameter>[\w.\[\]:%+-]+)=)(?P<value>[^&]*)", current):
                found, usable = False, True
                print("* scanning %s parameter '%s'" % (phase, match.group("parameter")))
                prefix, suffix = ("".join(random.sample(string.ascii_lowercase, PREFIX_SUFFIX_LENGTH)) for i in range(2))
                for pool, append in ((LARGER_CHAR_POOL, True), (SMALLER_CHAR_POOL, True), (LARGER_CHAR_POOL, False)):
                    if not found:
                        tampered = "%s%s%s" % (current[:match.end() if append else match.start("value")], urllib.parse.quote("%s%s%s%s" % ("'" if pool == LARGER_CHAR_POOL else "", prefix, "".join(random.sample(pool, len(pool))), suffix)), current[match.end():])
                        content = (_retrieve_content(tampered, data) if phase is GET else _retrieve_content(url, tampered)).replace("%s%s" % ("'" if pool == LARGER_CHAR_POOL else "", prefix), prefix)
                        for regex, condition, info, content_removal_regex in REGULAR_PATTERNS:
                            filtered = re.sub(content_removal_regex or "", "", content)
                            for sample in re.finditer("(?s)%s(.{0,%d}?)%s" % (prefix, MAX_REFLECTION_LENGTH, suffix), filtered, re.I):
                                context = re.search(regex % {"chars": re.escape(sample.group(0))}, filtered, re.I)
                                if context and not found and (sample.group(1).strip() or not condition) and all(char in sample.group(1) for char in condition):
                                    print(" (i) %s parameter '%s' appears to be XSS vulnerable (%s)" % (phase, match.group("parameter"), info % dict((("filtering", "no" if all(char in sample.group(1) for char in LARGER_CHAR_POOL) else "some"),))))
                                    found = retval = True
        if not usable:
            print(" (x) no usable GET/POST parameters found")
    except KeyboardInterrupt:
        print("\r (x) Ctrl-C pressed")
    return retval

def init_options(proxy=None, cookie=None, ua=None, referer=None):
    global _headers
    _headers = dict(filter(lambda _: _[1], ((COOKIE, cookie), (UA, ua or NAME), (REFERER, referer))))
    urllib.request.install_opener(urllib.request.build_opener(*filter(None, (urllib.request.ProxyHandler({'http': proxy, 'https': proxy}) if proxy else None, urllib.request.HTTPSHandler(context=ssl._create_unverified_context()), urllib.request.HTTPCookieProcessor()))))

if __name__ == "__main__":
    print("%s #v%s\n by: %s\n" % (NAME, VERSION, AUTHOR))
    parser = optparse.OptionParser(version=VERSION)
    parser.add_option("-u", "--url", dest="url", help="Target URL (e.g. \"http://www.target.com/page.php?id=1\")")
    parser.add_option("--data", dest="data", help="POST data (e.g. \"query=test\")")
    parser.add_option("--cookie", dest="cookie", help="HTTP Cookie header value")
    parser.add_option("--user-agent", dest="ua", help="HTTP User-Agent header value")
    parser.add_option("--referer", dest="referer", help="HTTP Referer header value")
    parser.add_option("--proxy", dest="proxy", help="HTTP proxy address (e.g. \"http://127.0.0.1:8080\")")
    options, _ = parser.parse_args()
    if options.url:
        init_options(options.proxy, options.cookie, options.ua, options.referer)
        result = scan_page(options.url if re.match(r"(?i)\Ahttps?://", options.url) else "http://%s" % options.url.lstrip('/'), options.data)
        print("\nscan results: %s vulnerabilities found" % ("possible" if result else "no"))
    else:
        parser.print_help()
