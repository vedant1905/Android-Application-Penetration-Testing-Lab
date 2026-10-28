#!/usr/bin/env python3
"""
Manifest Security Auditor
Audits AndroidManifest.xml (from APK or uncompressed XML) for misconfigurations:
exported components, debuggable flag, allowBackup, cleartext traffic, dangerous permissions.
"""

import os
import sys
import zipfile
import re
import argparse
from utils.colors import header, info, success, warning, error, finding
from utils.report_generator import ReportGenerator

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_EXTERNAL_STORAGE": "Allows reading files from shared external storage.",
    "android.permission.WRITE_EXTERNAL_STORAGE": "Allows writing/modifying files on shared external storage.",
    "android.permission.RECORD_AUDIO": "Allows recording audio via microphone.",
    "android.permission.CAMERA": "Allows capturing photos and videos.",
    "android.permission.ACCESS_FINE_LOCATION": "Allows accessing precise GPS location.",
    "android.permission.READ_CONTACTS": "Allows reading user's address book.",
    "android.permission.READ_SMS": "Allows reading received SMS messages.",
    "android.permission.SEND_SMS": "Allows sending SMS without user confirmation.",
}


def audit_manifest_content(text_content, report):
    """Analyzes manifest text content for security anti-patterns."""
    # 1. allowBackup check
    if 'android:allowBackup="true"' in text_content or ('allowBackup' in text_content and 'android:allowBackup="false"' not in text_content):
        report.add_finding(
            severity="MEDIUM",
            title="Application Backup Enabled (android:allowBackup=true)",
            description="The application allows ADB backup extraction. An attacker with physical or USB debugging access can dump full internal app data.",
            evidence='android:allowBackup="true"',
            remediation='Set android:allowBackup="false" in AndroidManifest.xml.'
        )
        finding("MEDIUM", "Backup enabled (android:allowBackup=true)")

    # 2. debuggable check
    if 'android:debuggable="true"' in text_content:
        report.add_finding(
            severity="HIGH",
            title="Application is Debuggable (android:debuggable=true)",
            description="The application flag debuggable is true. Attackers can attach jdb/debugger and execute arbitrary code in the app context.",
            evidence='android:debuggable="true"',
            remediation='Set android:debuggable="false" for all production release builds.'
        )
        finding("HIGH", "Debuggable enabled (android:debuggable=true)")

    # 3. usesCleartextTraffic check
    if 'android:usesCleartextTraffic="true"' in text_content:
        report.add_finding(
            severity="HIGH",
            title="Cleartext HTTP Traffic Permitted",
            description="The application explicitly permits cleartext HTTP network communications, exposing requests to interception.",
            evidence='android:usesCleartextTraffic="true"',
            remediation='Set android:usesCleartextTraffic="false" and enforce TLS.'
        )
        finding("HIGH", "Cleartext traffic permitted (android:usesCleartextTraffic=true)")

    # 4. Exported components
    exported_matches = re.findall(r'<(activity|service|receiver|provider)[^>]*android:name="([^"]+)"[^>]*android:exported="true"', text_content)
    for comp_type, comp_name in exported_matches:
        sev = "HIGH" if comp_type in ["provider", "activity"] else "MEDIUM"
        report.add_finding(
            severity=sev,
            title=f"Exported Component: {comp_type.capitalize()} ({comp_name})",
            description=f"The {comp_type} '{comp_name}' is exported without required signature-level permissions.",
            evidence=f'<{comp_type} android:name="{comp_name}" android:exported="true">',
            remediation="Set android:exported=\"false\" unless the component is intended for inter-app IPC with strict permissions."
        )
        finding(sev, f"Exported {comp_type}: {comp_name}")

    # 5. Check permissions
    for perm, desc in DANGEROUS_PERMISSIONS.items():
        if perm in text_content:
            report.add_finding(
                severity="LOW",
                title=f"Dangerous Permission Requested: {perm}",
                description=f"Application requests sensitive runtime permission: {perm}. {desc}",
                evidence=f'<uses-permission android:name="{perm}" />',
                remediation="Ensure this permission follows the principle of least privilege."
            )
            finding("LOW", f"Requested permission: {perm}")


def check_manifest(target_path, report=None):
    if not os.path.exists(target_path):
        error(f"Target path not found: {target_path}")
        return None

    header(f"Auditing Manifest: {os.path.basename(target_path)}")
    if report is None:
        report = ReportGenerator(app_name=os.path.basename(target_path), tester="Manifest Auditor")

    # If an APK, extract AndroidManifest.xml binary or inspect raw strings
    if target_path.endswith(".apk"):
        try:
            with zipfile.ZipFile(target_path, "r") as zf:
                if "AndroidManifest.xml" in zf.namelist():
                    manifest_data = zf.read("AndroidManifest.xml")
                    # Extract readable ASCII/UTF strings from binary XML
                    raw_strings = " ".join([m.decode("ascii", errors="ignore") for m in re.finditer(rb"[\x20-\x7e]{3,}", manifest_data)])
                    audit_manifest_content(raw_strings, report)
        except Exception as e:
            error(f"Failed to read manifest from APK: {e}")
    else:
        # Direct XML file
        try:
            with open(target_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                audit_manifest_content(content, report)
        except Exception as e:
            error(f"Failed to read XML file: {e}")

    report.generate_summary()
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AndroidManifest Security Auditor")
    parser.add_argument("--apk", help="Path to APK file")
    parser.add_argument("--manifest", help="Direct path to AndroidManifest.xml file")
    parser.add_argument("--output", help="Optional output report path")
    args = parser.parse_args()

    target = args.apk or args.manifest
    if not target:
        parser.print_help()
        sys.exit(1)

    rep = check_manifest(target)
    if rep and args.output:
        rep.generate_markdown(args.output)
        success(f"Report written to {args.output}")
