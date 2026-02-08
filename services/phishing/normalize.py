from urllib.parse import urlparse

def normalize_url(url: str) -> str | None:
    if not url:
        return None

    url = url.strip()

    if "://" not in url:
        url = "http://" + url

    parsed = urlparse(url)

    if not parsed.scheme or not parsed.netloc:
        return None

    return f"{parsed.scheme}://{parsed.netloc}"
