from urllib.parse import urlparse

def normalize_url(raw: str) -> str | None:
    if not raw:
        return None

    raw = raw.strip()

    if raw.startswith(("http://", "https://")):
        parsed = urlparse(raw)
        if not parsed.hostname:
            return None
        return parsed.geturl()

    parsed = urlparse("https://" + raw)
    if parsed.hostname:
        return parsed.geturl()

    parsed = urlparse("http://" + raw)
    if parsed.hostname:
        return parsed.geturl()

    return None
