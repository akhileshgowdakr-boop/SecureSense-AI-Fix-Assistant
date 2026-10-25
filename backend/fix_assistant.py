"""Rule-based remediation guidance for SecureSense AI findings.

This module deliberately does not claim to use a generative model. It provides
predictable, no-API-key remediation guidance based on the scanner's findings.
"""
from typing import Any, Dict, List

HEADER_FIXES = {
    "X-Content-Type-Options": {
        "title": "Prevent MIME-type sniffing",
        "why": "Browsers may guess a response's content type when this header is absent, which can create risk if untrusted content is served.",
        "steps": [
            "Set the response header X-Content-Type-Options to nosniff.",
            "Ensure each endpoint returns the correct Content-Type for its response.",
            "Rescan the endpoint and confirm the header is present."
        ],
        "examples": {
            "nginx": "add_header X-Content-Type-Options \"nosniff\" always;",
            "express": "app.use((req, res, next) => { res.setHeader('X-Content-Type-Options', 'nosniff'); next(); });",
            "fastapi": "from starlette.middleware.base import BaseHTTPMiddleware\n\nclass SecurityHeadersMiddleware(BaseHTTPMiddleware):\n    async def dispatch(self, request, call_next):\n        response = await call_next(request)\n        response.headers['X-Content-Type-Options'] = 'nosniff'\n        return response\n\napp.add_middleware(SecurityHeadersMiddleware)"
        }
    },
    "X-Frame-Options": {
        "title": "Reduce clickjacking risk",
        "why": "This header controls whether browsers can embed a page in a frame. It is especially relevant for browser-based pages and admin consoles.",
        "steps": [
            "If the page should never be framed, set X-Frame-Options to DENY.",
            "If same-origin framing is required, consider SAMEORIGIN instead.",
            "For modern applications, configure Content-Security-Policy frame-ancestors as well."
        ],
        "examples": {
            "nginx": "add_header X-Frame-Options \"DENY\" always;",
            "express": "app.use((req, res, next) => { res.setHeader('X-Frame-Options', 'DENY'); next(); });",
            "fastapi": "response.headers['X-Frame-Options'] = 'DENY'  # set on each response or in middleware"
        }
    },
    "Content-Security-Policy": {
        "title": "Add a Content Security Policy",
        "why": "A carefully designed CSP can limit the sources from which a browser loads scripts and other resources, reducing the impact of some injection attacks.",
        "steps": [
            "Start with a policy that reflects the assets your application actually needs.",
            "Test with Content-Security-Policy-Report-Only before enforcing it on a live site.",
            "Avoid copying a strict example blindly; validate scripts, styles, APIs, and required third-party resources."
        ],
        "examples": {
            "nginx": "add_header Content-Security-Policy \"default-src 'self'\" always;  # tailor before production",
            "express": "// Configure a tailored Content-Security-Policy using Helmet: helmet({ contentSecurityPolicy: { directives: { defaultSrc: [\"'self'\"] } } })",
            "fastapi": "response.headers['Content-Security-Policy'] = \"default-src 'self'\"  # tailor and test before production"
        }
    }
}


def build_fix_plan(scan: Dict[str, Any]) -> Dict[str, Any]:
    """Create actionable remediation guidance from a SecureSense scan result."""
    fixes: List[Dict[str, Any]] = []
    analysis = scan.get("security_analysis") or {}
    for finding in analysis.get("findings", []):
        header = str(finding.get("header", ""))
        status = str(finding.get("status", "")).lower()
        if header in HEADER_FIXES and any(word in status for word in ("missing", "not present", "absent", "fail", "insecure")):
            item = dict(HEADER_FIXES[header])
            item.update({"finding": header, "severity": finding.get("severity", "Review"), "detected_status": finding.get("status", "Unknown")})
            fixes.append(item)

    https = scan.get("https_analysis") or {}
    if str(https.get("status", "")).lower() in {"insecure", "failed", "not secure"}:
        fixes.append({
            "finding": "HTTPS", "title": "Serve the API over HTTPS", "severity": "High",
            "why": "Plain HTTP does not protect API traffic from being read or modified in transit.",
            "steps": ["Configure a valid TLS certificate on the server or trusted reverse proxy.", "Redirect HTTP requests to HTTPS where appropriate.", "Update clients and callbacks to use HTTPS, then verify certificate renewal and redirect behavior."],
            "examples": {"general": "Configure TLS at your web server, load balancer, or hosting provider; exact steps depend on your deployment."}
        })

    server = scan.get("server_analysis") or {}
    if str(server.get("status", "")).lower() in {"detected", "disclosed", "exposed"}:
        fixes.append({
            "finding": "Server banner", "title": "Minimize server version disclosure", "severity": "Low",
            "why": "Detailed server banners can help an attacker identify software versions to investigate. Hiding a banner is only a small hardening measure, not a substitute for patching.",
            "steps": ["Configure the web server or reverse proxy to suppress version details.", "Keep the server, framework, and dependencies patched regardless of banner settings.", "Rescan to verify what is exposed to unauthenticated clients."],
            "examples": {"nginx": "server_tokens off;", "apache": "ServerTokens Prod\nServerSignature Off"}
        })

    anomaly = scan.get("anomaly_analysis") or {}
    for item in anomaly.get("anomalies", []):
        kind = str(item.get("type", ""))
        advice = {
            "Slow Response": ("Investigate slow API responses", ["Measure latency across repeated requests and inspect server logs.", "Check database queries, external dependencies, and network latency.", "Set realistic timeouts and performance thresholds; a single slow request is not proof of a security flaw."]),
            "Server Error": ("Investigate server errors", ["Inspect server-side logs using the request timestamp and request ID.", "Return a generic error to clients and keep stack traces and secrets out of responses.", "Reproduce the issue in a test environment and add a regression test."]),
            "Rate Limit": ("Review rate limiting", ["Confirm whether the response is an expected rate limit.", "Apply per-client limits and suitable retry guidance where appropriate.", "Avoid retry loops; respect Retry-After when the server provides it."]),
            "Client Error": ("Check the endpoint and request", ["Confirm the URL, path, parameters, and HTTP method are correct.", "Check whether the endpoint requires authentication or a valid resource ID.", "Treat a 404 as an endpoint result, not by itself as a security vulnerability."]),
            "Redirect": ("Review redirect behavior", ["Inspect the Location header and confirm the destination is expected.", "Avoid redirecting users to destinations supplied without validation.", "If HTTP redirects to HTTPS, verify that the final destination uses HTTPS."])
        }
        if kind in advice:
            title, steps = advice[kind]
            fixes.append({"finding": kind, "title": title, "severity": item.get("severity", "Review"), "why": item.get("message", "The scanner flagged this response for review."), "steps": steps, "examples": {}})

    return {
        "url": scan.get("url", ""),
        "summary": f"Generated {len(fixes)} remediation item(s) from the current scan.",
        "fixes": fixes,
        "note": "Guidance is rule-based and should be reviewed against your framework and deployment. Test changes in a staging environment before production."
    }
