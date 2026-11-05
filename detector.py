"""Educational phishing indicator checks. This is a heuristic demo, not a security product."""
from urllib.parse import urlparse
import re

URGENT_TERMS = (
    "urgent", "immediately", "verify now", "account suspended",
    "limited time", "action required", "unusual activity"
)
CREDENTIAL_TERMS = (
    "password", "login", "sign in", "credentials", "otp",
    "one-time password", "bank details"
)
PAYMENT_TERMS = ("payment", "invoice", "refund", "gift card", "wire transfer")
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy"}

def _risk_label(score):
    if score >= 6:
        return "High"
    if score >= 3:
        return "Medium"
    return "Low"

def analyze_email(sender, subject, body):
    text = f"{subject} {body}".lower()
    findings = []
    score = 0

    if not sender.strip():
        findings.append("Sender field is empty.")
    elif not re.search(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", sender.strip()):
        findings.append("Sender address does not look like a valid email format.")
        score += 1

    urgent_hits = [term for term in URGENT_TERMS if term in text]
    if urgent_hits:
        findings.append("Urgency or pressure language found: " + ", ".join(urgent_hits) + ".")
        score += min(3, len(urgent_hits))

    credential_hits = [term for term in CREDENTIAL_TERMS if term in text]
    if credential_hits:
        findings.append("Request related to credentials or authentication found: " + ", ".join(credential_hits) + ".")
        score += min(3, len(credential_hits))

    payment_hits = [term for term in PAYMENT_TERMS if term in text]
    if payment_hits:
        findings.append("Payment-related language found: " + ", ".join(payment_hits) + ".")
        score += 1

    urls = re.findall(r"https?://[^\s<>()\"']+", body, flags=re.IGNORECASE)
    if urls:
        findings.append(f"Message contains {len(urls)} URL(s). Inspect links independently before opening.")
        score += 1
        for url in urls:
            url_result = analyze_url(url)
            if url_result["score"] >= 3:
                findings.append(f"Potentially suspicious link indicator: {url} ({url_result['risk']} risk).")
                score += 2

    if not findings:
        findings.append("No obvious indicators were detected by these basic rules.")

    score = min(score, 10)
    return {
        "type": "Email analysis",
        "risk": _risk_label(score),
        "score": score,
        "findings": findings,
        "recommendation": (
            "Do not click links or provide sensitive information. Verify the request using an independently "
            "known official contact method." if score >= 3 else
            "Still verify unexpected requests. A low score does not prove that a message is safe."
        )
    }

def analyze_url(raw_url):
    value = raw_url.strip()
    findings = []
    score = 0
    if not value:
        return {"type": "URL analysis", "risk": "Low", "score": 0,
                "findings": ["Enter a URL to analyze."],
                "recommendation": "Do not open unknown links."}

    candidate = value if "://" in value else "https://" + value
    try:
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").lower()
    except ValueError:
        host = ""

    if not host or "." not in host:
        findings.append("URL could not be parsed as a normal hostname.")
        score += 2
    if parsed.scheme.lower() not in ("http", "https"):
        findings.append("Unexpected URL scheme.")
        score += 2
    if parsed.scheme.lower() == "http":
        findings.append("URL uses HTTP rather than encrypted HTTPS.")
        score += 1
    if host in URL_SHORTENERS:
        findings.append("Known URL-shortening domain detected. The final destination is hidden.")
        score += 2
    if "@" in candidate:
        findings.append("An @ symbol appears in the URL and may obscure the actual destination.")
        score += 2
    if len(host) > 35:
        findings.append("Unusually long hostname.")
        score += 1
    if host.count("-") >= 2:
        findings.append("Hostname contains multiple hyphens.")
        score += 1
    if re.search(r"\d+\.\d+\.\d+\.\d+", host):
        findings.append("URL uses an IP address instead of a typical domain name.")
        score += 2
    if any(word in host for word in ("login", "verify", "secure", "account", "update")):
        findings.append("Hostname contains a sensitive-action keyword. This alone does not prove phishing.")
        score += 1

    if not findings:
        findings.append("No obvious URL red flags were found by these basic checks.")

    score = min(score, 10)
    return {
        "type": "URL analysis",
        "risk": _risk_label(score),
        "score": score,
        "findings": findings,
        "recommendation": (
            "Do not visit this link unless you independently confirm the exact domain with the organisation."
            if score >= 3 else
            "No obvious red flags found, but this heuristic cannot certify a URL as safe."
        )
    }
