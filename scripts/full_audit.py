#!/usr/bin/env python3
"""
Full Security Audit Orchestrator
Runs static APK scans, manifest security checks, network configuration checks,
and optional runtime storage checks via ADB, then consolidates all findings into a single report.
"""

import os
import sys
import argparse
from utils.colors import banner, header, info, success, warning, error
from utils.report_generator import ReportGenerator
from scan_apk import scan_apk
from check_manifest import check_manifest
from check_network_security import check_network_security
from check_storage import check_storage


def run_full_audit(apk_path, package_name=None, device_id=None, output_dir=None):
    banner()

    app_name = os.path.basename(apk_path) if apk_path else (package_name or "Android Target")
    consolidated_report = ReportGenerator(app_name=app_name, tester="Automated Full Pentest Suite")

    header(f"Starting Complete Android Penetration Testing Audit: {app_name}")

    if apk_path and os.path.exists(apk_path):
        info("[Step 1/4] Running Static Analysis on APK...")
        scan_apk(apk_path, report=consolidated_report)

        info("[Step 2/4] Auditing AndroidManifest.xml...")
        check_manifest(apk_path, report=consolidated_report)

        info("[Step 3/4] Auditing Network Security Configuration...")
        check_network_security(apk_path, report=consolidated_report)
    else:
        warning(f"No local APK provided or file '{apk_path}' does not exist. Skipping static checks.")

    if package_name:
        info("[Step 4/4] Performing Runtime Storage and Logcat Audit via ADB...")
        check_storage(package_name, device_id=device_id, report=consolidated_report)
    else:
        info("[Step 4/4] No package name specified (--package). Skipping runtime ADB storage checks.")

    header("Consolidated Audit Completed")
    consolidated_report.generate_summary()

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        report_filename = f"{app_name.replace('.apk', '')}-Consolidated-Report.md"
        out_file = os.path.join(output_dir, report_filename)
        consolidated_report.generate_markdown(out_file)
        success(f"Consolidated Pentest Report saved to: {out_file}")

    return consolidated_report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Full Android Pentest Audit Orchestrator")
    parser.add_argument("--apk", help="Path to target APK file for static inspection")
    parser.add_argument("--package", help="Target package name on device for runtime checks (e.g. com.pentestlab.insecurevault)")
    parser.add_argument("--device", help="Specific ADB device or emulator identifier")
    parser.add_argument("--output", default="reports", help="Directory where markdown reports will be written")

    args = parser.parse_args()

    if not args.apk and not args.package:
        parser.print_help()
        sys.exit(1)

    run_full_audit(args.apk, package_name=args.package, device_id=args.device, output_dir=args.output)
