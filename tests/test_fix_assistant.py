from backend.fix_assistant import build_fix_plan


def test_fix_assistant_explains_missing_csp():
    result = build_fix_plan({
        "url": "https://example.test",
        "security_analysis": {"findings": [
            {"header": "Content-Security-Policy", "status": "Missing", "severity": "High"}
        ]},
        "https_analysis": {"status": "Secure"},
        "server_analysis": {"status": "Not Detected"},
        "anomaly_analysis": {"anomalies": []}
    })
    assert len(result["fixes"]) == 1
    assert result["fixes"][0]["finding"] == "Content-Security-Policy"
    assert result["fixes"][0]["steps"]
    assert "staging" in result["note"]


def test_fix_assistant_handles_https_and_anomaly():
    result = build_fix_plan({
        "url": "http://example.test",
        "security_analysis": {"findings": []},
        "https_analysis": {"status": "Insecure"},
        "server_analysis": {"status": "Not Detected"},
        "anomaly_analysis": {"anomalies": [
            {"type": "Server Error", "message": "HTTP 500", "severity": "High"}
        ]}
    })
    assert {item["finding"] for item in result["fixes"]} == {"HTTPS", "Server Error"}
