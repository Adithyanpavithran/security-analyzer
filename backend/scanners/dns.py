import dns.resolver


def get_dns_records(hostname, record_type):
    try:
        answers = dns.resolver.resolve(
            hostname,
            record_type,
            lifetime=5
        )

        return [answer.to_text() for answer in answers]

    except Exception:
        return []


def analyze_dns(hostname):
    record_types = ["A", "AAAA", "MX", "NS", "CNAME", "TXT"]

    records = {}

    for record_type in record_types:
        records[record_type] = get_dns_records(
            hostname,
            record_type
        )

    txt_records = records.get("TXT", [])

    spf_present = any(
        "v=spf1" in record.lower()
        for record in txt_records
    )

    dmarc_records = get_dns_records(
        f"_dmarc.{hostname}",
        "TXT"
    )

    dmarc_present = any(
        "v=dmarc1" in record.lower()
        for record in dmarc_records
    )

    findings = []

    if spf_present:
        findings.append({
            "check": "SPF",
            "status": "PASS",
            "severity": "info",
            "message": "SPF record detected."
        })
    else:
        findings.append({
            "check": "SPF",
            "status": "INFO",
            "severity": "low",
            "message": "No SPF record was detected."
        })

    if dmarc_present:
        findings.append({
            "check": "DMARC",
            "status": "PASS",
            "severity": "info",
            "message": "DMARC record detected."
        })
    else:
        findings.append({
            "check": "DMARC",
            "status": "INFO",
            "severity": "low",
            "message": "No DMARC record was detected."
        })

    return {
        "records": records,
        "spf": {
            "present": spf_present
        },
        "dmarc": {
            "present": dmarc_present,
            "records": dmarc_records
        }
    }, findings
