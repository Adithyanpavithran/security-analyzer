def analyze_cookies(response):
    cookies = []
    findings = []

    for cookie_header in response.headers.get_list("set-cookie"):
        cookie_name = cookie_header.split("=", 1)[0].strip()
        lower_cookie = cookie_header.lower()

        secure = "secure" in lower_cookie
        httponly = "httponly" in lower_cookie
        samesite = "samesite=" in lower_cookie

        cookies.append({
            "name": cookie_name,
            "secure": secure,
            "httponly": httponly,
            "samesite": samesite,
        })

        if not secure:
            findings.append({
                "cookie": cookie_name,
                "status": "WARNING",
                "severity": "medium",
                "message": "Cookie does not have the Secure attribute.",
            })

        if not httponly:
            findings.append({
                "cookie": cookie_name,
                "status": "WARNING",
                "severity": "medium",
                "message": "Cookie does not have the HttpOnly attribute.",
            })

        if not samesite:
            findings.append({
                "cookie": cookie_name,
                "status": "WARNING",
                "severity": "low",
                "message": "Cookie does not explicitly define SameSite.",
            })

    return cookies, findings
