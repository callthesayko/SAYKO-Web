# SAYKO 🛡️
### Python Security Assessment Toolkit

A Python-based command-line tool for basic web security assessment.

![Python](https://img.shields.io/badge/Python-3.11%2B-blue)
![Version](https://img.shields.io/badge/Version-0.1.0-green)
![Interface](https://img.shields.io/badge/Interface-CLI-black)
![Reports](https://img.shields.io/badge/Reports-JSON-orange)

**SAYKO** is a Python-based command-line tool designed to collect basic information about websites, inspect selected HTTP security headers, assess TLS connections, resolve domain names to IP addresses, and generate structured security reports.

The project aims to provide an initial overview of selected web security configurations and present the results in a simple, machine-readable format.

> ⚠️ **Disclaimer:** This tool is intended for educational purposes and authorized security assessments only. Assess only systems for which you have explicit permission.

## ✨ Features

- **HTTP Security Analyzer:** Inspects HTTP responses and identifies missing security headers.
- **TLS Inspector:** Attempts to establish a TLS connection with certificate verification and retrieves certificate subject, issuer, and expiration information.
- **DNS Resolution:** Retrieves IP addresses associated with a domain name.
- **Basic Risk Assessment:** Assigns a risk score and level based on predefined findings.
- **JSON Reporting:** Prints structured reports or saves them to a file for further analysis.
- **Configurable Timeout:** Allows users to configure network operation timeouts.

### Security Headers Checked

- `Strict-Transport-Security` (HSTS)
- `Content-Security-Policy` (CSP)
- `X-Content-Type-Options`
- `X-Frame-Options`
- `Referrer-Policy`

A missing header does not automatically indicate a confirmed vulnerability. Its significance depends on the application and its security requirements.

## ⚙️ Requirements

- Python 3.11 or later
- Network connectivity for online assessments
- Authorization to assess the target system

This version uses Python's standard library and does not require third-party packages for its current functionality.

## 📥 Installation and Usage

Clone the repository:

```bash
git clone https://github.com/YOUR-USERNAME/SAYKO.git
cd SAYKO
```

Replace `YOUR-USERNAME` with your GitHub username.

### 1. Run a basic assessment

```bash
python sayko.py https://example.com
```

### 2. Print the full JSON report

```bash
python sayko.py https://example.com --json
```

### 3. Save the report to a file

```bash
python sayko.py https://example.com --output report.json
```

### 4. Print and save the JSON report

```bash
python sayko.py https://example.com --json --output report.json
```

### 5. Configure the timeout

```bash
python sayko.py https://example.com --timeout 15
```

The timeout must be between 1 and 60 seconds.

> The filename `sayko.py` is used as an example. Replace it with the actual Python filename if it differs.

## 📊 Risk Scoring

SAYKO uses a simple scoring model. Each finding is assigned a predefined severity score, and the highest score among all findings becomes the final risk score.

| Severity | Base Score |
|---|---:|
| INFO | 5 |
| LOW | 19 |
| MEDIUM | 45 |
| HIGH | 70 |
| CRITICAL | 95 |

The final risk level is determined by the calculated score:

- Below 45: `LOW`
- From 45 to below 70: `MEDIUM`
- 70 or above: `HIGH`

This model provides a basic indicator for prioritizing further investigation. **The reported score is not a statistical probability of an attack and does not prove that a vulnerability exists.**

For example, a failed TLS inspection may result from a connectivity issue, an unavailable service, or certificate validation failure. Such a result does not, by itself, prove that the website is vulnerable.

## 🧾 JSON Report Structure

The generated report contains the following main sections:

- `tool` and `version`: Tool name and version
- `timestamp`: Assessment timestamp
- `target`: Target URL, hostname, scheme, and port
- `http`: HTTP status, final URL, response headers, and possible errors
- `dns`: Resolved IP addresses and possible errors
- `tls`: Certificate information and verification status, when HTTPS is assessed
- `assessment`: Risk score, risk level, and findings

The JSON output can be used for manual review or processed by other scripts and tools.

## ⚠️ Limitations — Version 0.1.0

SAYKO is a basic assessment tool and is not a replacement for comprehensive security scanners or professional penetration testing.

- HTTP header checks are limited to the headers listed in the source code.
- TLS inspection is limited to connection verification and certificate information retrieval.
- DNS functionality currently resolves IP addresses; it is not a comprehensive DNS record enumeration tool.
- This version does not test for application vulnerabilities such as SQL injection, XSS, authentication weaknesses, or business logic flaws.
- The scoring model is intentionally simple and may not fully reflect actual risk.
- Connection failures and network errors do not necessarily indicate vulnerabilities.
- A dedicated, comprehensive Scope Guard mechanism is not implemented in this version. Users must ensure that their selected targets are authorized.

## 🔐 Responsible Use

Use SAYKO in accordance with applicable laws and with authorization from the system owner.

- Assess only authorized targets.
- Obtain explicit permission before testing systems belonging to others.
- Interpret findings in the context of the tool's limitations.
- Independently validate findings before making important security decisions.

## 🚀 Project Status

**Current version:** `0.1.0` — Initial release

SAYKO is a project focused on learning Python programming and developing tools for basic web security assessment.

## 👨‍💻 Developer

**SAYKO**

Built with Python 🐍
