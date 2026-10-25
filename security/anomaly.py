def detect_anomaly(status_code, response_time):
    anomalies = []
    if status_code == 500 or status_code >= 500:
        anomalies.append({"type": "Server Error", "message": f"The endpoint returned HTTP {status_code}.", "severity": "High"})
    elif status_code == 429:
        anomalies.append({"type": "Rate Limit", "message": "The endpoint returned HTTP 429; the request may have been rate limited.", "severity": "Medium"})
    elif 300 <= status_code < 400:
        anomalies.append({"type": "Redirect", "message": f"The endpoint returned HTTP {status_code}; review the redirect destination.", "severity": "Low"})
    elif 400 <= status_code < 500:
        anomalies.append({"type": "Client Error", "message": f"The endpoint returned HTTP {status_code}; check the URL and request requirements.", "severity": "Low"})
    if response_time >= 2:
        anomalies.append({"type": "Slow Response", "message": f"The response took {response_time} seconds.", "severity": "Medium"})
    return {"anomaly_detected": bool(anomalies), "anomalies": anomalies}
