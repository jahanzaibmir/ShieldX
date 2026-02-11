import re
from urllib.parse import urlparse, urlunparse
from typing import Optional


def is_valid_hostname(hostname: str) -> bool:
    if not hostname:
        return False

    if hostname.startswith(".") or hostname.endswith("."):
        return False

    if len(hostname) > 253:
        return False

    pattern = re.compile(
        r"^(?=.{1,253}$)"
        r"(?!-)"
        r"[A-Za-z0-9-]{1,63}"
        r"(?<!-)"
        r"(\.[A-Za-z0-9-]{1,63})+$"
    )

    return bool(pattern.match(hostname))


def normalize_url(raw: str) -> Optional[str]:
    if not raw:
        return None

    raw = raw.strip()
    raw = raw.replace("\n", "").replace("\r", "")
    raw = raw.lstrip(".")

    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw

    try:
        parsed = urlparse(raw)
        hostname = parsed.hostname

        if not hostname:
            return None

        try:
            hostname = hostname.encode("idna").decode("ascii")
        except Exception:
            return None

        hostname = hostname.lower()

        if not is_valid_hostname(hostname):
            return None

        clean_url = urlunparse((
            parsed.scheme.lower(),
            hostname,
            parsed.path or "",
            "",
            parsed.query or "",
            ""
        ))

        return clean_url

    except Exception:
        return None
