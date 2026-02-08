import socket
import json
import logging
from urllib.parse import urlparse

from .normalize import normalize_url
from .heuristics import analyze_heuristics
from .domain_intel import analyze_domain
from .tls_check import analyze_tls
from .verdict import finalize_verdict

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | phishing | %(message)s"
)
logger = logging.getLogger("phishing")


def domain_resolves(domain: str) -> bool:
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False


def check_url(raw_url: str) -> dict:
    logger.info(f"Starting phishing scan for URL: {raw_url}")

    result = {
        "url": raw_url,
        "normalized": None,
        "score": 0,
        "verdict": None,
        "details": []
    }

    normalized = normalize_url(raw_url)
    if not normalized:
        result["score"] = 100
        result["verdict"] = "INVALID"
        result["details"].append("[URL] Invalid URL format")
        return result

    result["normalized"] = normalized
    parsed = urlparse(normalized)

    # 🔥 HARD STOP — SOC RULE
    if not domain_resolves(parsed.hostname):
        result["score"] = 90
        result["verdict"] = "HIGH RISK"
        result["details"].append("[DOMAIN] Domain does not resolve (dead infrastructure)")
        return result

    h_score, h_details = analyze_heuristics(parsed)
    result["score"] += h_score
    result["details"].extend(h_details)

    d_score, d_details = analyze_domain(parsed.hostname)
    result["score"] += d_score
    result["details"].extend(d_details)

    t_score, t_details = analyze_tls(parsed.hostname)
    result["score"] += t_score
    result["details"].extend(t_details)

    result["verdict"] = finalize_verdict(result["score"])

    logger.info(f"Phishing scan result: {result}")
    return result


if __name__ == "__main__":
    import sys
    res = check_url(sys.argv[1])
    print(json.dumps(res, indent=2))
