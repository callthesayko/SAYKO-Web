
#!/usr/bin/env python3
"""
SAYKO - Python Security Assessment Toolkit
Version: 0.1.0
Python: 3.11+

For educational use and authorized security assessments only.
"""

import argparse
import json
import socket
import ssl
import sys
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


VERSION = "0.1.0"
USER_AGENT = f"SAYKO/{VERSION}"


def normalize_url(target):
    """Validate and normalize an HTTP or HTTPS URL."""
    target = target.strip()

    if "://" not in target:
        target = "https://" + target

    parsed = urlparse(target)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not parsed.hostname:
        raise ValueError("A valid hostname is required.")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing credentials are not supported.")

    if any(char in parsed.hostname for char in "\r\n\t "):
        raise ValueError("Invalid hostname.")

    return target, parsed


def get_tls_info(hostname, port=443, timeout=5):
    """Inspect a server's TLS certificate without disabling verification."""
    result = {
        "hostname": hostname,
        "port": port,
        "verified": False,
        "certificate_subject": None,
        "certificate_issuer": None,
        "expires_at": None,
        "error": None,
    }

    context = ssl.create_default_context()

    try:
        with socket.create_connection(
            (hostname, port), timeout=timeout
        ) as raw_socket:
            with context.wrap_socket(
                raw_socket, server_hostname=hostname
            ) as tls_socket:
                cert = tls_socket.getpeercert()

                result["verified"] = True
                result["certificate_subject"] = cert.get("subject")
                result["certificate_issuer"] = cert.get("issuer")
                result["expires_at"] = cert.get("notAfter")

    except (OSError, ssl.SSLError, ValueError) as exc:
        result["error"] = str(exc)

    return result


def inspect_http(url, timeout=10):
    """Retrieve basic HTTP response information."""
    request = Request(
        url,
        headers={"User-Agent": USER_AGENT},
        method="GET",
    )

    try:
        with urlopen(request, timeout=timeout) as response:
            return {
                "status_code": response.status,
                "final_url": response.geturl(),
                "headers": dict(response.headers.items()),
                "error": None,
            }

    except HTTPError as exc:
        return {
            "status_code": exc.code,
            "final_url": exc.geturl(),
            "headers": dict(exc.headers.items()),
            "error": None,
        }

    except (URLError, TimeoutError, OSError, ValueError) as exc:
        return {
            "status_code": None,
            "final_url": url,
            "headers": {},
            "error": str(exc),
        }


def inspect_dns(hostname, port=443):
    """Resolve a hostname to IP addresses."""
    try:
        results = socket.getaddrinfo(
            hostname, port, type=socket.SOCK_STREAM
        )
        addresses = sorted({item[4][0] for item in results})

        return {"hostname": hostname, "ip_addresses": addresses, "error": None}

    except socket.gaierror as exc:
        return {
            "hostname": hostname,
            "ip_addresses": [],
            "error": str(exc),
        }


def assess_security(parsed, http, tls):
    """Produce simple, non-invasive security observations."""
    findings = []

    def add(severity, title, detail):
        findings.append({
            "severity": severity,
            "title": title,
            "detail": detail,
        })

    if parsed.scheme == "http":
        add(
            "HIGH",
            "HTTP instead of HTTPS",
            "The URL uses unencrypted HTTP. Sensitive data may be exposed.",
        )

    headers = {
        key.lower(): value
        for key, value in http.get("headers", {}).items()
    }

    security_headers = {
        "strict-transport-security": "HSTS",
        "content-security-policy": "Content Security Policy",
        "x-content-type-options": "X-Content-Type-Options",
        "x-frame-options": "X-Frame-Options",
        "referrer-policy": "Referrer-Policy",
    }

    if http.get("status_code") is not None:
        for header, label in security_headers.items():
            if header not in headers:
                add(
                    "INFO",
                    f"Missing {label} header",
                    f"The response does not include {header}. "
                    "Whether this matters depends on the application.",
                )

    if parsed.scheme == "https" and tls and tls.get("error"):
        add(
            "HIGH",
            "TLS inspection failed",
            tls["error"],
        )

    if not findings:
        add(
            "INFO",
            "No basic issues detected",
            "This limited assessment does not establish that the "
            "target is secure.",
        )

    severity_scores = {"INFO": 5, "LOW": 19, "MEDIUM": 45,
                       "HIGH": 70, "CRITICAL": 95}

    score = max(
        (severity_scores[item["severity"]] for item in findings),
        default=0,
    )

    return {
        "risk_score": score,
        "risk_level": (
            "HIGH" if score >= 70 else
            "MEDIUM" if score >= 45 else
            "LOW"
        ),
        "findings": findings,
    }


def run_assessment(target, timeout=10):
    """Run the initial SAYKO assessment."""
    url, parsed = normalize_url(target)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    http = inspect_http(url, timeout=timeout)
    dns = inspect_dns(hostname, port=port)

    tls = None
    if parsed.scheme == "https":
        tls = get_tls_info(hostname, port=port, timeout=timeout)

    assessment = assess_security(parsed, http, tls)

    return {
        "tool": "SAYKO",
        "version": VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": {
            "url": url,
            "hostname": hostname,
            "scheme": parsed.scheme,
            "port": port,
        },
        "http": http,
        "dns": dns,
        "tls": tls,
        "assessment": assessment,
    }


def print_report(report):
    """Print a readable terminal report."""
    assessment = report["assessment"]

    print("\n" + "=" * 55)
    print(" SAYKO - Python Security Assessment Toolkit")
    print("=" * 55)
    print(f"Target : {report['target']['url']}")
    print(f"Risk   : {assessment['risk_level']} "
          f"({assessment['risk_score']}/100)")

    http = report["http"]
    if http["status_code"] is not None:
        print(f"HTTP   : {http['status_code']}")
    elif http["error"]:
        print(f"HTTP error: {http['error']}")

    print("\nFindings:")
    for finding in assessment["findings"]:
        print(f"- [{finding['severity']}] {finding['title']}")
        print(f"  {finding['detail']}")

    print("=" * 55)


def main():
    parser = argparse.ArgumentParser(
        description="SAYKO - Basic web security assessment toolkit"
    )
    parser.add_argument("target", help="Authorized URL or hostname")
    parser.add_argument(
        "--json", action="store_true",
        help="Print the complete report as JSON",
    )
    parser.add_argument(
        "--timeout", type=int, default=10,
        help="Network timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--output", metavar="FILE",
        help="Save the JSON report to a file",
    )

    args = parser.parse_args()

    if not 1 <= args.timeout <= 60:
        parser.error("--timeout must be between 1 and 60 seconds")

    try:
        report = run_assessment(args.target, args.timeout)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as file:
                json.dump(report, file, indent=2, ensure_ascii=False)
                file.write("\n")

        if args.json:
            print(json.dumps(report, indent=2, ensure_ascii=False))
        else:
            print_report(report)
            if args.output:
                print(f"\nJSON report saved to: {args.output}")

    except (ValueError, UnicodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nAssessment cancelled.", file=sys.stderr)
        return 130

    return 0


if __name__ == "__main__":
    sys.exit(main())
