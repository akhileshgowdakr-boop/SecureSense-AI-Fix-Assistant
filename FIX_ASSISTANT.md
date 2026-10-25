# SecureSense AI — Fix Assistant

The Fix Assistant converts findings from a completed scan into actionable remediation guidance. It is intentionally rule-based and does not require an external AI provider or API key.

## Included

- Remediation steps for missing `X-Content-Type-Options`, `X-Frame-Options`, and `Content-Security-Policy` headers.
- HTTPS and server-banner hardening guidance.
- Advice for common anomaly types such as slow responses, server errors, rate limits, client errors, and redirects.
- Example configuration snippets for common server/framework choices where available.
- Copy buttons and HTML escaping for rendered guidance.

## Run locally

From the repository root:

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
uvicorn backend.main:app --reload
```

Open `frontend/index.html` in a browser. The frontend expects the backend at `http://127.0.0.1:8000`.

## Endpoint

`POST /fix-assistant`

Request body:

```json
{
  "scan": {
    "url": "https://example.com",
    "security_analysis": {
      "findings": [
        {"header": "Content-Security-Policy", "status": "Missing", "severity": "High"}
      ]
    },
    "https_analysis": {"status": "Secure"},
    "server_analysis": {"status": "Not Detected"},
    "anomaly_analysis": {"anomalies": []}
  }
}
```

The response contains `summary`, a `fixes` array, and a safety note. Guidance is rule-based, not a claim that a generative AI model has validated or automatically fixed the target system. Review snippets against your own framework and test in staging before production.
