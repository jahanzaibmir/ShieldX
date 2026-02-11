import ssl
import socket
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from html.parser import HTMLParser


class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.has_password = False
        self.external_action = False
        self.current_form_action = None
        self.page_host = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)

        if tag == "form":
            self.current_form_action = attrs.get("action", "")

        if tag == "input":
            if attrs.get("type", "").lower() == "password":
                self.has_password = True

    def handle_endtag(self, tag):
        if tag == "form":
            self.current_form_action = None


def analyze_html(url: str):
    score = 0
    findings = []

    parsed = urlparse(url)
    host = parsed.hostname

    try:
        ctx = ssl.create_default_context()
        req = Request(
            url,
            headers={"User-Agent": "ShieldX-SOC/1.0"}
        )

        with urlopen(req, context=ctx, timeout=5) as resp:
            if resp.status != 200:
                return 0, []

            html = resp.read(200000).decode("utf-8", errors="ignore")

    except Exception:
        return 0, []

    parser = FormParser()
    parser.page_host = host
    parser.feed(html)

    if parser.has_password:
        findings.append("Password input field detected (possible credential harvesting)")
        score += 50

    return score, findings
