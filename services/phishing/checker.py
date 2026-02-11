import socket
from urllib.parse import urlparse
from datetime import datetime, timezone

from normalize import normalize_url
from heuristics import analyze_heuristics
from domain_intel import analyze_domain
from tls_check import analyze_tls
from verdict import finalize_verdict

ENGINE_NAME = "ShieldX Phishing Engine"


def domain_resolves(domain: str) -> bool:
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False


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

    if not domain_resolves(parsed.hostname):
        result["risk_score"] = 90
        result["verdict"] = "HIGH_RISK"
        result["signals"].append("Domain does not resolve")
        return result

    h_score, h_details = analyze_heuristics(parsed)
    d_score, d_details = analyze_domain(parsed.hostname)
    t_score, t_details = analyze_tls(parsed.hostname)

    result["risk_score"] = h_score + d_score + t_score
    result["signals"].extend(h_details + d_details + t_details)
    result["verdict"] = finalize_verdict(result["risk_score"])

    return result


def render_output(res: dict) -> str:
    sep = "-" * 70
    lines = []

    lines.append(sep)
    lines.append(" ShieldX SOC - Phishing Analysis Report")
    lines.append(sep)
    lines.append(f" Engine        : {res['engine']}")
    lines.append(f" Scan Time     : {res['scan_time']}")
    lines.append(f" Input URL     : {res['input_url']}")
    lines.append(f" Normalized    : {res['normalized_url']}")
    lines.append("")
    lines.append(f" Risk Score    : {res['risk_score']}/100")
    lines.append(f" Verdict       : {res['verdict']}")
    lines.append("")
    lines.append(" Signals:")
    if res["signals"]:
        for s in res["signals"]:
            lines.append(f"  - {s}")
    else:
        lines.append("  - No malicious indicators detected")
    lines.append(sep)

    return "\n".join(lines)


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python checker.py <url>")
        sys.exit(1)

    report = check_url(sys.argv[1])
    print(render_output(report))
