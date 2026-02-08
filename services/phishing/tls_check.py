import ssl
import socket

def analyze_tls(domain: str):
    score = 0
    details = []

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()

        if cert:
            details.append("[TLS] Valid TLS certificate")
        else:
            score += 25
            details.append("[TLS] Missing TLS certificate")

    except Exception:
        score += 25
        details.append("[TLS] TLS handshake failed")

    return score, details
