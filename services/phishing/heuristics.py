import re

def analyze_heuristics(parsed):
    score = 0
    details = []

    domain = parsed.hostname or ""

    if len(domain) > 35:
        score += 15
        details.append("[HEURISTIC] Unusually long domain")

    if re.search(r"[a-z]{10,}", domain.lower()):
        score += 20
        details.append("[HEURISTIC] Randomized domain string")

    if domain.count("-") >= 2:
        score += 10
        details.append("[HEURISTIC] Excessive hyphens in domain")

    if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
        score += 30
        details.append("[HEURISTIC] IP-based URL")

    return score, details
