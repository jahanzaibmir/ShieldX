import whois
import socket
from urllib.parse import urlparse
from datetime import datetime, timezone

from normalize import normalize_url
from heuristics import analyze_heuristics
from domain_intel import analyze_domain
from tls_check import analyze_tls
from verdict import finalize_verdict

ENGINE_NAME = "ShieldX Phishing Engine"


def is_valid_hostname(hostname: str) -> bool:
    if not hostname:
        return False

    hostname = hostname.strip().lower()

    if (
        hostname.startswith(".") or
        hostname.endswith(".") or
        ".." in hostname or
        " " in hostname
    ):
        return False

    labels = hostname.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return False

    return True


def domain_resolves(domain: str) -> bool:
    if not is_valid_hostname(domain):
        return False

    try:
        socket.gethostbyname(domain)
        return True
    except (socket.gaierror, UnicodeError):
        return False

# WHOIS Intelligence

def analyze_whois(domain: str):
    signals = []
    score = 0
    intel = {}

    try:
        w = whois.whois(domain)

        creation = w.creation_date
        expiry = w.expiration_date
        registrar = w.registrar
        name_servers = w.name_servers

        if isinstance(creation, list):
            creation = creation[0]
        if isinstance(expiry, list):
            expiry = expiry[0]

        now = datetime.now(timezone.utc)

        if creation:
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)

            age_days = (now - creation).days
            age_years = round(age_days / 365, 1)

            intel["age_days"] = age_days
            intel["age_years"] = age_years
            intel["creation_date"] = creation

            if age_days < 30:
                score += 40
                signals.append("Domain registered less than 30 days ago (high phishing correlation)")
            elif age_days < 90:
                score += 20
                signals.append("Domain registered within last 90 days")

        if expiry:
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)

            remaining = (expiry - now).days
            intel["days_until_expiry"] = remaining
            intel["expiration_date"] = expiry

            if remaining < 15:
                score += 20
                signals.append("Domain expires in less than 15 days")
            elif remaining < 30:
                score += 10
                signals.append("Domain expires within 30 days")

        intel["registrar"] = registrar
        intel["name_servers"] = list(name_servers)[:3] if name_servers else []

    except Exception:
        signals.append("WHOIS data unavailable")
        score += 5

    return score, signals, intel


# Core Scan

def check_url(raw_url: str) -> dict:
    result = {
        "engine": ENGINE_NAME,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "input_url": raw_url,
        "normalized_url": None,
        "risk_score": 0,
        "verdict": "UNKNOWN",
        "signals": []
    }

    normalized = normalize_url(raw_url)
    if not normalized:
        result["risk_score"] = 100
        result["verdict"] = "INVALID"
        result["signals"].append("Invalid URL format")
        return result

    result["normalized_url"] = normalized
    parsed = urlparse(normalized)

    if not parsed.hostname or not is_valid_hostname(parsed.hostname):
        result["risk_score"] = 100
        result["verdict"] = "INVALID"
        result["signals"].append("Malformed hostname")
        return result

    if not domain_resolves(parsed.hostname):
        result["risk_score"] = 90
        result["verdict"] = "HIGH_RISK"
        result["signals"].append("Domain does not resolve")
        return result

    try:
        h_score, h_details = analyze_heuristics(parsed)
        d_score, d_details = analyze_domain(parsed.hostname)
        t_score, t_details = analyze_tls(parsed.hostname)
        w_score, w_signals, w_details = analyze_whois(parsed.hostname)

        result["risk_score"] = h_score + d_score + t_score + w_score
        result["signals"].extend(h_details + d_details + t_details + w_signals)
        result["verdict"] = finalize_verdict(result["risk_score"])
        result["whois"] = w_details

    except Exception:
        result["risk_score"] = 80
        result["verdict"] = "ERROR"
        result["signals"].append("Internal analysis module failure")

    return result

def render_output(res: dict) -> str:
    sep = "=" * 70
    lines = []

    lines.append(sep)
    lines.append("ShieldX SOC - Phishing Threat Intelligence Report")
    lines.append(sep)

    lines.append(f"Engine          : {res['engine']}")
    lines.append(f"Scan Time (UTC) : {res['scan_time']}")
    lines.append(f"Input URL       : {res['input_url']}")
    lines.append(f"Normalized URL  : {res['normalized_url']}")
    lines.append("")

    lines.append(f"Risk Score      : {res['risk_score']} / 100")
    lines.append(f"Verdict         : {res['verdict']}")
    lines.append("")

    lines.append("Detection Signals:")
    if res["signals"]:
        for s in res["signals"]:
            lines.append(f"  - {s}")
    else:
        lines.append("  - No malicious indicators detected")

    if "whois" in res and res["whois"]:
        w = res["whois"]
        lines.append("")
        lines.append("Domain Intelligence Summary")
        lines.append("-" * 50)

        if "age_years" in w:
            lines.append(f"Domain Age        : {w['age_years']} years ({w['age_days']} days)")
        if "creation_date" in w:
            lines.append(f"First Registered  : {w['creation_date']}")
        if "expiration_date" in w:
            lines.append(f"Expiration Date   : {w['expiration_date']}")
        if "days_until_expiry" in w:
            lines.append(f"Days Until Expiry : {w['days_until_expiry']} days")
        if "registrar" in w:
            lines.append(f"Registrar         : {w['registrar']}")
        if "name_servers" in w and w["name_servers"]:
            lines.append("Name Servers:")
            for ns in w["name_servers"]:
                lines.append(f"  - {ns}")

    lines.append(sep)
    return "\n".join(lines)

if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python checker.py <url>")
        sys.exit(1)

    report = check_url(sys.argv[1])

    try:
        print(render_output(report))
    except UnicodeEncodeError:
        print(render_output(report).encode("utf-8", errors="ignore").decode("utf-8"))
