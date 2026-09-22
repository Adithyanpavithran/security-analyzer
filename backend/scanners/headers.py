SECURITY_HEADERS = {
    "strict-transport-security": {
        "name": "HSTS",
        "description": "Helps enforce HTTPS connections.",
    },
    "content-security-policy": {
        "name": "Content Security Policy",
        "description": "Helps reduce certain browser-side injection risks.",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "description": "Helps prevent MIME-type sniffing.",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "description": "Helps control whether the site can be embedded in frames.",
    },
    "referrer-policy": {
        "name": "Referrer Policy",
        "description": "Controls how much referrer information browsers send.",
    },
}


def analyze_headers(response):
    headers = {}
    findings = []

    for header, info in SECURITY_HEADERS.items():
        value = response.headers.get(header)

        headers[info["name"]] = {
            "present": value is not None,
            "value": value,
            "description": info["description"],
        }

        if value:
            findings.append({
                "header": info["name"],
                "status": "PASS",
                "severity": "info",
                "message": f"{info['name']} is present.",
            })
        else:
            findings.append({
                "header": info["name"],
                "status": "MISSING",
                "severity": "low",
                "message": f"{info['name']} is missing.",
                "recommendation": info["description"],
            })

    return headers, findings
