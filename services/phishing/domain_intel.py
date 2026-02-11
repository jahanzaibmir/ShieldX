import socket
import ipaddress
import re
import math


def shannon_entropy(data: str) -> float:
    """
    Calculate Shannon entropy of a string.
    Useful for detecting DGA-like random domains.
    """
    if not data:
        return 0

    entropy = 0
    for x in set(data):
        p_x = data.count(x) / len(data)
        entropy -= p_x * math.log2(p_x)
    return entropy


def analyze_domain(domain: str):
    """
    Advanced Domain Intelligence Engine
    Returns: (risk_score: int, findings: list[str])
    """

    score = 0
    findings = []

    if not domain or domain.startswith(".") or domain.endswith(".") or ".." in domain:
        score += 30
        findings.append("Malformed domain structure detected")
        return score, findings

    labels = domain.split(".")

    if len(labels) > 4:
        score += 10
        findings.append("Excessive subdomain depth detected")

    if re.fullmatch(r"[0-9\-\.]+", domain):
        score += 20
        findings.append("Domain consists primarily of numeric characters")

    if domain.startswith("xn--") or ".xn--" in domain:
        score += 25
        findings.append("Internationalized domain (punycode) detected")

    suspicious_tlds = [
        ".zip", ".mov", ".tk", ".ml",
        ".ga", ".cf", ".gq", ".xyz", ".top"
    ]

    for tld in suspicious_tlds:
        if domain.endswith(tld):
            score += 25
            findings.append(f"High-risk top-level domain used: {tld}")
            break

    # 2️⃣ Entropy Analysis (DGA detection)
    base_label = labels[0]
    entropy = shannon_entropy(base_label)

    if entropy > 4.0 and len(base_label) > 10:
        score += 20
        findings.append("High entropy domain label (possible DGA-generated domain)")
        
    try:
        ip = socket.gethostbyname(domain)
        findings.append(f"DNS resolved successfully to {ip}")

        ip_obj = ipaddress.ip_address(ip)

        if ip_obj.is_private:
            score += 20
            findings.append("Domain resolves to private IP address")

        if ip_obj.is_loopback:
            score += 25
            findings.append("Domain resolves to loopback address")

        if ip_obj.is_reserved:
            score += 15
            findings.append("Domain resolves to reserved IP space")

        if ip_obj.is_multicast:
            score += 15
            findings.append("Domain resolves to multicast address")

    except (socket.gaierror, UnicodeError):
        score += 35
        findings.append("DNS resolution failed (domain does not exist or unreachable)")
        return score, findings

    try:
        ip_check_2 = socket.gethostbyname(domain)
        if ip_check_2 != ip:
            score += 15
            findings.append("Inconsistent DNS resolution detected (possible fast-flux)")
    except Exception:
        pass

    return score, findings
