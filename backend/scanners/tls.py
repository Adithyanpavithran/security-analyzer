import ssl
import socket
from datetime import datetime, timezone


def analyze_tls(hostname):
    context = ssl.create_default_context()

    with socket.create_connection((hostname, 443), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as tls_socket:

            certificate = tls_socket.getpeercert()

            issuer = certificate.get("issuer", [])
            subject = certificate.get("subject", [])

            def flatten_name(name):
                result = {}

                for section in name:
                    for key, value in section:
                        result[key] = value

                return result

            issuer_data = flatten_name(issuer)
            subject_data = flatten_name(subject)

            not_after = certificate.get("notAfter")

            expiry_date = None
            days_remaining = None

            if not_after:
                expiry_date = datetime.strptime(
                    not_after,
                    "%b %d %H:%M:%S %Y %Z"
                ).replace(tzinfo=timezone.utc)

                days_remaining = (
                    expiry_date - datetime.now(timezone.utc)
                ).days

            return {
                "tls_version": tls_socket.version(),
                "cipher": tls_socket.cipher()[0],
                "subject": subject_data,
                "issuer": issuer_data,
                "expires": (
                    expiry_date.isoformat()
                    if expiry_date else None
                ),
                "days_remaining": days_remaining,
                "valid": (
                    days_remaining is None
                    or days_remaining >= 0
                ),
            }
