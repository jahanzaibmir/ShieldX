import whois
from datetime import datetime

KNOWN_TRUSTED_ASN = {
    "google",
    "youtube",
    "cloudflare",
    "github",
    "microsoft",
    "amazon",
    "facebook"
}

def analyze_domain(domain: str):
    score = 0
    details = []

    # Trust signal for known infra
    for brand in KNOWN_TRUSTED_ASN:
        if brand in domain.lower():
            details.append("[DOMAIN] Known trusted infrastructure")
            return 0, details

    try:
        data = whois.whois(domain)

        created = data.creation_date
        if isinstance(created, list):
            created = created[0]

        if not created:
            details.append("[DOMAIN] WHOIS incomplete")
            return 0, details

        age_days = (datetime.utcnow() - created).days

        if age_days < 14:
            score += 60
            details.append("[DOMAIN] Domain age < 14 days")
        elif age_days < 90:
            score += 30
            details.append("[DOMAIN] Domain age < 3 months")
        elif age_days < 365:
            score += 10
            details.append("[DOMAIN] Domain age < 1 year")
        else:
            details.append(f"[DOMAIN] Domain age: {age_days} days")

    except Exception:
        # WHOIS failure alone is NOT suspicious
        details.append("[DOMAIN] WHOIS unavailable (neutral signal)")

    return score, details
