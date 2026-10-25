SECURITY_HEADERS = {
    "X-Content-Type-Options": ("nosniff", "Medium", "Set X-Content-Type-Options to nosniff."),
    "X-Frame-Options": (None, "Medium", "Set X-Frame-Options to DENY or SAMEORIGIN when appropriate."),
    "Content-Security-Policy": (None, "High", "Configure a Content-Security-Policy tailored to your application.")
}


def analyze_security_headers(headers):
    findings = []
    present_count = 0
    for name, (expected, severity, recommendation) in SECURITY_HEADERS.items():
        value = headers.get(name)
        present = bool(value)
        if name == "X-Content-Type-Options" and present and value.lower() != expected:
            present = False
        if present:
            present_count += 1
        findings.append({
            "header": name,
            "status": "Present" if present else "Missing",
            "severity": "Info" if present else severity,
            "recommendation": recommendation if not present else "Header is present; verify its value is appropriate."
        })
    score = 30 if present_count == 0 else round(30 + (70 * present_count / len(SECURITY_HEADERS)))
    risk = "Low" if score >= 80 else "Medium" if score >= 50 else "High"
    return {"security_score": score, "risk_level": risk, "findings": findings}


def check_https(url):
    secure = str(url).lower().startswith("https://")
    return {"status": "Secure" if secure else "Insecure", "message": "HTTPS is used." if secure else "Use HTTPS to protect traffic in transit."}


def check_server_disclosure(server):
    return {"status": "Detected" if server else "Not Detected", "message": "Server header is exposed." if server else "No Server header was disclosed."}
