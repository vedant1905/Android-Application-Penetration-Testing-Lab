#!/usr/bin/env python3
"""
Network Security Config & Transport Auditor
Audits network security configurations, cleartext traffic allowance,
custom trust anchors, and searches DEX code for certificate pinning bypasses or disabled trust managers.
"""

import os
import sys
import zipfile
import re
import argparse
from utils.colors import header, info, success, warning, error, finding
from utils.report_generator import ReportGenerator


def check_network_security(apk_path, report=None):
    if not os.path.exists(apk_path):
        error(f"APK file not found: {apk_path}")
        return None

    header(f"Auditing Network Security: {os.path.basename(apk_path)}")
    if report is None:
        report = ReportGenerator(app_name=os.path.basename(apk_path), tester="Network Auditor")

    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            file_list = zf.namelist()

            # 1. Look for network_security_config.xml
            net_configs = [f for f in file_list if "network_security_config" in f.lower()]
            if not net_configs:
                report.add_finding(
                    severity="MEDIUM",
                    title="Missing Explicit Network Security Config",
                    description="No network_security_config.xml detected in the APK. App defaults to platform network policy.",
                    evidence="No file matching *network_security_config*.xml in APK",
                    remediation="Add res/xml/network_security_config.xml and reference it in AndroidManifest.xml."
                )
                finding("MEDIUM", "No network security config found")
            else:
                for cfg in net_configs:
                    data = zf.read(cfg)
                    content = "".join([chr(b) for b in data if 32 <= b <= 126])
                    if "cleartextTrafficPermitted=\"true\"" in content:
                        report.add_finding(
                            severity="HIGH",
                            title="Cleartext Permitted in Network Config",
                            description="Network security configuration explicitly allows cleartext HTTP communication.",
                            evidence=content[:200],
                            remediation="Set cleartextTrafficPermitted=\"false\" across all domain configurations."
                        )
                        finding("HIGH", "cleartextTrafficPermitted=true in config")
                    if "certificates src=\"user\"" in content:
                        report.add_finding(
                            severity="HIGH",
                            title="User Installed Certificates Trusted in Production",
                            description="Network security configuration trusts user-installed CA certificates, facilitating MitM proxies.",
                            evidence=content[:200],
                            remediation="Do not trust user certificates in release builds; restrict to <debug-overrides> if needed."
                        )
                        finding("HIGH", "User CA certificates trusted")

            # 2. Inspect DEX for insecure TrustManager or HostnameVerifier
            dex_files = [f for f in file_list if f.endswith(".dex")]
            for dex_name in dex_files:
                dex_bytes = zf.read(dex_name)
                # Look for signature of TrustAllCertificates or AllowAllHostnameVerifier
                if b"checkServerTrusted" in dex_bytes and b"X509TrustManager" in dex_bytes:
                    if b"TrustAll" in dex_bytes or b"setDefaultSSLSocketFactory" in dex_bytes:
                        report.add_finding(
                            severity="CRITICAL",
                            title="Custom Insecure TrustManager / SSL Verification Bypass Found",
                            description="DEX code references custom TrustManager implementation that overrides default SSL validation.",
                            evidence=f"Identified in {dex_name}",
                            remediation="Always use system default TrustManagers with valid CA validation and implement certificate pinning."
                        )
                        finding("CRITICAL", "Custom TrustManager / SSL verification bypass found in bytecode")

    except Exception as e:
        error(f"Error auditing network security in APK: {e}")

    report.generate_summary()
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Security Config Auditor")
    parser.add_argument("--apk", required=True, help="Path to APK file")
    parser.add_argument("--output", help="Optional report output file")
    args = parser.parse_args()

    rep = check_network_security(args.apk)
    if rep and args.output:
        rep.generate_markdown(args.output)
        success(f"Report written to {args.output}")
