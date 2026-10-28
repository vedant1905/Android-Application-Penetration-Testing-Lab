#!/usr/bin/env python3
"""
Static APK Scanner
Scans an APK file for hardcoded secrets, dangerous flags, credentials, and sensitive strings.
"""

import os
import sys
import zipfile
import re
import argparse
from utils.colors import header, info, success, warning, error, finding
from utils.report_generator import ReportGenerator

# Regex patterns for static analysis
SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"[0-9a-zA-Z/+]{40}",
    "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "Generic Private Key": r"-----BEGIN (RSA|EC|DSA|OPENSSH)? PRIVATE KEY-----",
    "Bearer / Auth Token": r"[bB]earer\s+[a-zA-Z0-9_\-\.]{20,}",
    "Generic Secret / Password Key": r"(?i)(api_key|apikey|secret|password|passwd|auth_token)\s*[:=]\s*['\"][^'\"]{4,}['\"]",
    "Hardcoded IP Address": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    "Insecure HTTP URL": r"http://[a-zA-Z0-9\-\.]+(?::[0-9]{1,5})?/[^\s\"']*",
}

SUSPICIOUS_EXTENSIONS = [".key", ".pem", ".p12", ".pfx", ".jks", ".bks", ".db", ".sqlite"]


def extract_strings_from_bytes(data, min_len=4):
    """Extract printable strings from raw binary data (DEX, resources, etc.)."""
    pattern = re.compile(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}")
    return [match.group(0).decode("ascii", errors="ignore") for match in pattern.finditer(data)]


def scan_apk(apk_path, report=None):
    if not os.path.exists(apk_path):
        error(f"APK file not found: {apk_path}")
        return None

    header(f"Scanning APK: {os.path.basename(apk_path)}")
    if report is None:
        report = ReportGenerator(app_name=os.path.basename(apk_path), tester="Static Scanner")

    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            file_list = zf.namelist()
            info(f"Total files in APK archive: {len(file_list)}")

            # 1. Check for suspicious bundled files
            for fname in file_list:
                for ext in SUSPICIOUS_EXTENSIONS:
                    if fname.lower().endswith(ext):
                        report.add_finding(
                            severity="HIGH",
                            title=f"Bundled Sensitive File: {fname}",
                            description=f"APK bundles potentially sensitive file '{fname}' with extension '{ext}'.",
                            evidence=f"Path in APK: {fname}",
                            remediation="Do not package sensitive databases, keystores, or private keys in the client APK."
                        )
                        finding("HIGH", f"Suspicious file found: {fname}")

            # 2. Inspect classes.dex & embedded resources for secrets
            dex_files = [f for f in file_list if f.endswith(".dex")]
            info(f"Found {len(dex_files)} DEX file(s). Searching for secrets and unencrypted URLs...")

            seen_findings = set()
            for dex_name in dex_files:
                dex_data = zf.read(dex_name)
                strings_list = extract_strings_from_bytes(dex_data)

                for s in strings_list:
                    for label, pattern in SECRET_PATTERNS.items():
                        match = re.search(pattern, s)
                        if match:
                            matched_str = match.group(0)
                            # Avoid duplicate findings
                            key = f"{label}:{matched_str}"
                            if key not in seen_findings:
                                seen_findings.add(key)
                                sev = "CRITICAL" if "Key" in label or "Password" in label or "Token" in label else "MEDIUM"
                                report.add_finding(
                                    severity=sev,
                                    title=f"Hardcoded {label}",
                                    description=f"Identified string matching pattern for {label} inside {dex_name}.",
                                    evidence=matched_str[:80] + ("..." if len(matched_str) > 80 else ""),
                                    remediation="Store secrets securely on a backend server or use Android Keystore."
                                )
                                finding(sev, f"Hardcoded {label}", matched_str[:70])

    except Exception as e:
        error(f"Error inspecting APK archive: {e}")

    report.generate_summary()
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Static APK Vulnerability Scanner")
    parser.add_argument("--apk", required=True, help="Path to APK file")
    parser.add_argument("--output", help="Optional output Markdown report path")
    args = parser.parse_args()

    rep = scan_apk(args.apk)
    if rep and args.output:
        rep.generate_markdown(args.output)
        success(f"Report written to {args.output}")
