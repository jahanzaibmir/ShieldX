import ssl
from urllib.parse import urlparse, urljoin
from urllib.request import Request, urlopen
from html.parser import HTMLParser


SUSPICIOUS_KEYWORDS = [
    "verify",
    "account suspended",
    "update your account",
    "confirm identity",
    "security alert",
    "unusual activity",
    "login to continue",
    "banking verification",
]


class AdvancedHTMLParser(HTMLParser):
    def __init__(self, page_host):
        super().__init__()
        self.page_host = page_host
        self.has_password = False
        self.external_form = False
        self.insecure_form = False
        self.hidden_iframe = False
        self.external_scripts = 0
        self.js_redirect = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)

        if tag == "input":
            if attrs.get("type", "").lower() == "password":
                self.has_password = True

        if tag == "form":
            action = attrs.get("action", "")
            if action:
                parsed_action = urlparse(urljoin(f"https://{self.page_host}", action))
                if parsed_action.hostname and parsed_action.hostname != self.page_host:
                    self.external_form = True
                if parsed_action.scheme == "http":
                    self.insecure_form = True

        if tag == "iframe":
            style = attrs.get("style", "").lower()
            width = attrs.get("width", "")
            height = attrs.get("height", "")
            if "display:none" in style or width == "0" or height == "0":
                self.hidden_iframe = True

        if tag == "script":
            src = attrs.get("src", "")
            if src:
                parsed_src = urlparse(src)
                if parsed_src.hostname and parsed_src.hostname != self.page_host:
                    self.external_scripts += 1

    def handle_data(self, data):
        lower = data.lower()
        if "window.location" in lower or "document.location" in lower:
            self.js_redirect = True


def analyze_html(url: str):
    score = 0
    findings = []

    parsed = urlparse(url)
    host = parsed.hostname

    try:
        ctx = ssl.create_default_context()
        req = Request(url, headers={"User-Agent": "ShieldX-SOC/1.0"})

        with urlopen(req, context=ctx, timeout=6) as resp:
            if resp.status != 200:
                return 0, []

            html = resp.read(300000).decode("utf-8", errors="ignore")

    except Exception:
        return 0, []

    parser = AdvancedHTMLParser(host)
    parser.feed(html)

    if parser.has_password:
        score += 35
        findings.append("Password input field detected")

    if parser.external_form:
        score += 40
        findings.append("Form submits credentials to external domain")

    if parser.insecure_form:
        score += 25
        findings.append("Form submits over insecure HTTP")

    if parser.hidden_iframe:
        score += 20
        findings.append("Hidden iframe detected")

    if parser.external_scripts > 3:
        score += 15
        findings.append("Multiple external scripts loaded")

    if parser.js_redirect:
        score += 15
        findings.append("JavaScript-based redirection detected")

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in html.lower():
            score += 10
            findings.append(f"Phishing-related keyword detected: '{keyword}'")

    return score, findings
