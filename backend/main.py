from fastapi import FastAPI
from pydantic import BaseModel
from urllib.parse import urlparse
import httpx

from scanners.headers import analyze_headers
from scanners.cookies import analyze_cookies
from scanners.tls import analyze_tls
from scanners.dns import analyze_dns
from scanners.cors import analyze_cors

app = FastAPI(
    title="11N11 Security Analyzer",
    version="1.0.0"
)


class ScanRequest(BaseModel):
    url: str


@app.get("/")
def home():
    return {
        "name": "11N11 Security Analyzer",
        "status": "running"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


@app.post("/scan")
def scan(request: ScanRequest):
    parsed = urlparse(request.url)

    if parsed.scheme not in ["http", "https"]:
        return {
            "error": "URL must start with http:// or https://"
        }

    if not parsed.hostname:
        return {
            "error": "Invalid hostname"
        }

    try:
        response = httpx.get(
            request.url,
            follow_redirects=True,
            timeout=10
        )

        headers, header_findings = analyze_headers(response)
        cookies, cookie_findings = analyze_cookies(response)
        cors, cors_findings = analyze_cors(response)

        findings = header_findings + cookie_findings + cors_findings

        tls = None

        if parsed.scheme == "https":
            try:
                tls = analyze_tls(parsed.hostname)

                if not tls["valid"]:
                    findings.append({
                        "check": "TLS Certificate",
                        "status": "WARNING",
                        "severity": "high",
                        "message": "TLS certificate appears to be expired."
                    })
                else:
                    findings.append({
                        "check": "TLS Certificate",
                        "status": "PASS",
                        "severity": "info",
                        "message": "TLS certificate is currently valid."
                    })

            except Exception as tls_error:
                findings.append({
                    "check": "TLS Certificate",
                    "status": "ERROR",
                    "severity": "high",
                    "message": "Unable to validate the TLS certificate.",
                    "error": str(tls_error)
                })

        dns_data, dns_findings = analyze_dns(parsed.hostname)
        findings.extend(dns_findings)

        return {
            "target": request.url,
            "hostname": parsed.hostname,
            "final_url": str(response.url),
            "status_code": response.status_code,
            "https": response.url.scheme == "https",
            "reachable": True,
            "security_headers": headers,
            "cookies": cookies,
            "tls": tls,
            "dns": dns_data,
            "cors": cors,
            "findings": findings
        }

    except Exception as e:
        return {
            "target": request.url,
            "reachable": False,
            "error": str(e)
        }
