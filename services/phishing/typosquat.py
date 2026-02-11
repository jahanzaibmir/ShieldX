from difflib import SequenceMatcher
import unicodedata


LEGIT_DOMAINS = [

    "google.com", "bing.com", "yahoo.com", "duckduckgo.com",

    "gmail.com", "outlook.com", "hotmail.com", "proton.me", "icloud.com",

    "amazon.com", "aws.amazon.com", "azure.com", "microsoft.com",
    "cloudflare.com", "digitalocean.com",

    "facebook.com", "instagram.com", "twitter.com", "x.com",
    "linkedin.com", "tiktok.com", "snapchat.com",

    "paypal.com", "stripe.com", "visa.com", "mastercard.com",
    "americanexpress.com", "bankofamerica.com", "chase.com", "wellsfargo.com",

    "amazon.in", "ebay.com", "aliexpress.com", "flipkart.com",

    "github.com", "gitlab.com", "bitbucket.org",

    "salesforce.com", "slack.com", "zoom.us", "dropbox.com",

    "gov.in", "uidai.gov.in", "irs.gov", "gov.uk",

    "harvard.edu", "stanford.edu", "mit.edu"
]


def normalize_domain(domain: str) -> str:
    return unicodedata.normalize("NFKD", domain).encode("ascii", "ignore").decode().lower()


def extract_base_domain(domain: str) -> str:
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def similarity_ratio(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


def detect_typosquat(domain: str):
    score = 0
    findings = []

    clean = extract_base_domain(normalize_domain(domain))

    for legit in LEGIT_DOMAINS:
        legit_clean = extract_base_domain(legit)

        ratio = similarity_ratio(clean, legit_clean)

        if 0.85 <= ratio < 0.99:
            findings.append(f"Domain closely resembles trusted brand '{legit_clean}' (similarity {round(ratio, 2)})")
            score += 30

        if clean.replace("0", "o").replace("1", "l") == legit_clean:
            findings.append(f"Numeric substitution detected resembling '{legit_clean}'")
            score += 35

    return score, findings
