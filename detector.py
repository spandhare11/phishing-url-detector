#!/usr/bin/env python3

import sys
import datetime
import socket
import ssl
from urllib.parse import urlparse

import dns.resolver
import whois

# ============================
# Configuration
# ============================

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "update",
    "account", "password", "bank", "signin", "confirm"
]

# Brand → Official domains mapping
BRAND_DOMAINS = {
    "google": ["google.com"],
    "paypal": ["paypal.com"],
    "facebook": ["facebook.com"],
    "amazon": ["amazon.com", "amazon.in"]
}

# ============================
# Helper Functions
# ============================

def extract_domain(url):
    parsed = urlparse(url)
    return parsed.netloc.lower()


def dns_resolves(domain):
    """
    NXDOMAIN / DNS existence check
    """
    try:
        dns.resolver.resolve(domain, "A")
        return True
    except Exception:
        return False


def get_domain_age(domain):
    """
    Get domain age in days using WHOIS
    """
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return None

        return (datetime.datetime.now() - creation_date).days
    except Exception:
        return None


def https_supported(domain):
    """
    Actively checks HTTPS capability (TLS on port 443).
    Does NOT trust user input scheme.
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain):
                return True
    except Exception:
        return False


def check_keywords(url):
    return [kw for kw in SUSPICIOUS_KEYWORDS if kw in url.lower()]


def check_brand_misuse(domain):
    """
    Detect brand impersonation by validating domain ownership
    """
    misuse = []

    for brand, legit_domains in BRAND_DOMAINS.items():
        if brand in domain:
            legit = False
            for legit_domain in legit_domains:
                if domain == legit_domain or domain.endswith("." + legit_domain):
                    legit = True
                    break

            if not legit:
                misuse.append(brand)

    return misuse


# ============================
# Core Analysis Logic
# ============================

def analyze_url(url):
    report = {}
    score = 0

    domain = extract_domain(url)
    report["domain"] = domain

    # ---- DNS Resolution ----
    resolves = dns_resolves(domain)
    report["dns_resolves"] = resolves

    if not resolves:
        score += 4
        report["dns_risk"] = "+4 (domain does not resolve)"
    else:
        report["dns_risk"] = "+0"

    # ---- Domain Age ----
    age = get_domain_age(domain)
    report["domain_age_days"] = age

    if age is None:
        score += 3
        report["domain_age_risk"] = "+3 (unknown domain age)"
    elif age < 30:
        score += 3
        report["domain_age_risk"] = "+3 (new domain)"
    else:
        report["domain_age_risk"] = "+0"

    # ---- URL Length ----
    length = len(url)
    report["url_length"] = length

    if length > 75:
        score += 2
        report["url_length_risk"] = "+2 (long URL)"
    else:
        report["url_length_risk"] = "+0"

    # ---- Suspicious Keywords ----
    keywords_found = check_keywords(url)
    report["keywords_found"] = keywords_found

    if keywords_found:
        score += 2
        report["keyword_risk"] = "+2"
    else:
        report["keyword_risk"] = "+0"

    # ---- HTTPS Capability (Informational Only) ----
    https_ok = https_supported(domain)
    report["https_supported"] = https_ok

    if not https_ok:
        report["https_risk"] = "⚠ HTTPS not supported (security weakness)"
    else:
        report["https_risk"] = "OK"

    # ---- Brand Misuse ----
    brands = check_brand_misuse(domain)
    report["brand_misuse"] = brands

    if brands:
        score += 3
        report["brand_risk"] = "+3 (brand impersonation)"
    else:
        report["brand_risk"] = "+0"

    report["final_score"] = score
    return report


# ============================
# Output
# ============================

def print_report(url, report):
    print("\n🔍 Phishing URL Analysis\n")
    print(f"URL                : {url}")
    print(f"Domain             : {report['domain']}")
    print(f"DNS resolves       : {report['dns_resolves']} {report['dns_risk']}")
    print(f"Domain age         : {report['domain_age_days']} days {report['domain_age_risk']}")
    print(f"URL length         : {report['url_length']} {report['url_length_risk']}")
    print(f"Keywords           : {report['keywords_found']} {report['keyword_risk']}")
    print(f"HTTPS supported    : {report['https_supported']} {report['https_risk']}")
    print(f"Brand misuse       : {report['brand_misuse']} {report['brand_risk']}")

    print("\nFinal Risk Score:", report["final_score"])

    if report["final_score"] >= 6:
        print("Verdict: 🔴 HIGH RISK (Likely Phishing)")
    elif report["final_score"] >= 3:
        print("Verdict: 🟠 MEDIUM RISK")
    else:
        print("Verdict: 🟢 LOW RISK")


# ============================
# Entry Point
# ============================

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 detector.py <url>")
        sys.exit(1)

    target_url = sys.argv[1]
    result = analyze_url(target_url)
    print_report(target_url, result)
