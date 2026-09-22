def analyze_cors(response):
    cors_headers = {
        "allow_origin": response.headers.get(
            "access-control-allow-origin"
        ),
        "allow_credentials": response.headers.get(
            "access-control-allow-credentials"
        ),
        "allow_methods": response.headers.get(
            "access-control-allow-methods"
        ),
        "allow_headers": response.headers.get(
            "access-control-allow-headers"
        ),
    }

    findings = []

    origin = cors_headers["allow_origin"]
    credentials = cors_headers["allow_credentials"]

    if origin == "*":
        findings.append({
            "check": "CORS",
            "status": "REVIEW",
            "severity": "low",
            "message": "The server allows requests from any origin.",
            "recommendation": "Confirm that wildcard CORS is intentional."
        })

    elif origin:
        findings.append({
            "check": "CORS",
            "status": "INFO",
            "severity": "info",
            "message": f"CORS allows origin: {origin}"
        })

    if credentials and credentials.lower() == "true":
        findings.append({
            "check": "CORS Credentials",
            "status": "REVIEW",
            "severity": "low",
            "message": "The server allows credentials in CORS requests.",
            "recommendation": "Confirm that credentialed cross-origin access is intentional."
        })

    return cors_headers, findings
