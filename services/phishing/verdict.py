def finalize_verdict(score: int) -> str:
    if score >= 80:
        return "HIGH RISK"
    if score >= 50:
        return "SUSPICIOUS"
    if score >= 20:
        return "LOW RISK"
    return "SAFE"
