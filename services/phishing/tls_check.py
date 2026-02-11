import ssl
import socket
from datetime import datetime, timezone


def analyze_tls(domain: str):
    score = 0
    findings = []

    try:
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                protocol = ssock.version()

        if not cert:
            score += 40
            findings.append("TLS certificate missing")
            return score, findings

        findings.append("Valid TLS certificate presented")

        not_before = cert.get("notBefore")
        not_after = cert.get("notAfter")

        if not_before:
            start = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
            start = start.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            if now < start:
                score += 30
                findings.append("TLS certificate not yet valid")

        if not_after:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            expiry = expiry.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_left = (expiry - now).days

            if days_left < 0:
                score += 40
                findings.append("TLS certificate expired")
            elif days_left < 15:
                score += 20
                findings.append("TLS certificate expires in less than 15 days")
            elif days_left < 30:
                score += 10
                findings.append("TLS certificate expires within 30 days")

        issuer = cert.get("issuer")
        subject = cert.get("subject")

        if issuer and subject and issuer == subject:
            score += 35
            findings.append("Self-signed TLS certificate detected")

        if protocol in ["SSLv3", "TLSv1", "TLSv1.1"]:
            score += 25
            findings.append(f"Weak TLS protocol in use: {protocol}")
        else:
            findings.append(f"TLS protocol: {protocol}")

        if cipher:
            cipher_name = cipher[0]
            findings.append(f"Cipher suite: {cipher_name}")

            weak_ciphers = ["RC4", "DES", "3DES", "MD5"]
            if any(w in cipher_name for w in weak_ciphers):
                score += 25
                findings.append("Weak cipher suite detected")

    except ssl.CertificateError:
        score += 40
        findings.append("TLS hostname mismatch detected")

    except Exception:
        score += 30
        findings.append("TLS handshake failed or HTTPS unavailable")

    return score, findings
