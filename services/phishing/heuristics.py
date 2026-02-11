import re
import ipaddress
from urllib.parse import ParseResult


SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "update", "secure",
    "account", "bank", "wallet", "confirm",
    "reset", "password", "auth", "otp", "billing",
    "invoice", "support", "unlock", "suspend"
]


SUSPICIOUS_EXTENSIONS = [
    ".exe", ".zip", ".rar", ".scr", ".js"
]


HIGH_RISK_TLDS = [
    ".zip", ".mov", ".tk", ".ml", ".ga",
    ".cf", ".gq", ".xyz", ".top"
]


def analyze_heuristics(parsed: ParseResult):
    score = 0
    findings = []

    hostname = (parsed.hostname or "").lower()
    path = (parsed.path or "").lower()
    query = (parsed.query or "").lower()
    full = f"{hostname}{path}?{query}"

    if not hostname:
        score += 40
        findings.append("Missing hostname in URL")
        return score, findings

    try:
        ipaddress.ip_address(hostname)
        score += 35
        findings.append("Direct IP address used instead of domain name")
    except ValueError:
        pass

    if hostname.startswith("xn--") or ".xn--" in hostname:
        score += 25
        findings.append("Internationalized domain (punycode) detected")

    if hostname.count(".") >= 4:
        score += 15
        findings.append("Excessive number of subdomains")

    if hostname.count("-") >= 3:
        score += 10
        findings.append("Multiple hyphens in domain (common in phishing domains)")

    for tld in HIGH_RISK_TLDS:
        if hostname.endswith(tld):
            score += 20
            findings.append(f"High-risk top-level domain detected: {tld}")
            break

    for kw in SUSPICIOUS_KEYWORDS:
        if kw in full:
            score += 5
            findings.append(f"Suspicious keyword detected: {kw}")

    if len(full) > 90:
        score += 10
        findings.append("Unusually long URL structure")

    if "%" in full:
        score += 10
        findings.append("Encoded characters detected in URL")

    if re.search(r"[a-zA-Z0-9]{25,}", path):
        score += 15
        findings.append("Long random-looking path segment detected")

    if re.search(r"(.)\1{4,}", full):
        score += 10
        findings.append("Repeated character pattern detected")

    for ext in SUSPICIOUS_EXTENSIONS:
        if path.endswith(ext):
            score += 20
            findings.append(f"Suspicious file extension detected: {ext}")
            break

    if query.count("=") >= 4:
        score += 10
        findings.append("Excessive query parameters detected")

    return score, findings
