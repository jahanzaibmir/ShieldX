from difflib import SequenceMatcher
import unicodedata

LEGIT_DOMAINS = [
    "google.com",
    "microsoft.com",
    "paypal.com",
    "apple.com",
    "amazon.com",
    "facebook.com"
]


def normalize_domain(domain: str) -> str:
    return unicodedata.normalize("NFKD", domain).encode("ascii", "ignore").decode()


def detect_typosquat(domain: str):
    score = 0
    findings = []

    clean = normalize_domain(domain)

    for legit in LEGIT_DOMAINS:
        ratio = SequenceMatcher(None, clean, legit).ratio()
        if 0.80 < ratio < 0.98:
            findings.append(f"Possible typosquatting of {legit}")
            score += 30

    return score, findings
