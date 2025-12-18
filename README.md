# Phishing URL Detection Tool (Rule-Based)

## Overview

A lightweight, rule-based Python tool that analyzes URLs to identify **potential phishing attempts** using explainable security signals. It avoids machine learning and focuses on how real security analysts reason about suspicious URLs.

## What It Checks

* **DNS Resolution (NXDOMAIN):** Flags domains that don’t resolve.
* **Domain Age:** New or unknown domains are riskier.
* **URL Length:** Very long URLs can hide intent.
* **Suspicious Keywords:** `login`, `verify`, `secure`, etc.
* **Brand Impersonation:** Detects brand names used on non-official domains.
* **HTTPS Capability (Informational):** Checks if the domain supports HTTPS (not used for phishing score).

## How It Works

1. Extracts the domain from the URL
2. Runs independent checks (DNS, age, keywords, brand misuse)
3. Assigns a risk score
4. Outputs a final verdict

## Risk Scoring

* NXDOMAIN: +4
* Domain age unknown / < 30 days: +3
* Suspicious keywords: +2
* Brand impersonation: +3
* Long URL (>75 chars): +2

**Verdict:**

* 0–2 → Low Risk
* 3–5 → Medium Risk
* 6+ → High Risk

## Installation

```bash
pip install python-whois dnspython
```

## Usage

```bash
python3 detector.py <url>
```

### Example

```bash
python3 detector.py https://google_security-login.com
```

## Notes

* The tool is **heuristic-based**, not a guarantee.
* HTTPS is treated as a security posture signal, not phishing intent.

## Disclaimer

For educational and authorized testing only.
