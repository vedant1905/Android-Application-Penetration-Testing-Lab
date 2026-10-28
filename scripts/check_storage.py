#!/usr/bin/env python3
"""
Runtime Storage Security Auditor
Audits an installed Android package on a device via ADB for insecure data storage:
- Plaintext SharedPreferences files
- Unencrypted SQLite databases
- Sensitive world-readable files in external storage
- Credential leaks in Logcat
"""

import os
import sys
import argparse
from utils.colors import header, info, success, warning, error, finding
from utils.adb_utils import check_adb, get_connected_devices, run_shell_command, get_logcat
from utils.report_generator import ReportGenerator


def check_storage(package_name, device_id=None, report=None):
    if not check_adb():
        error("ADB is not available on PATH. Please ensure Android SDK platform-tools are installed.")
        return None

    devices = get_connected_devices()
    if not devices:
        warning("No connected Android device/emulator detected via ADB.")
        warning("Please start an emulator or connect a device with USB debugging enabled.")
        return None

    header(f"Auditing Local & Runtime Storage for: {package_name}")
    if report is None:
        report = ReportGenerator(app_name=package_name, tester="Runtime Storage Auditor")

    # 1. Inspect SharedPreferences
    info("Inspecting SharedPreferences in app sandbox...")
    sp_cmd = f"run-as {package_name} sh -c 'ls -la shared_prefs/ 2>/dev/null && cat shared_prefs/*.xml 2>/dev/null'"
    sp_output = run_shell_command(sp_cmd, device=device_id)

    if sp_output and ("<string" in sp_output or "<map>" in sp_output):
        # Look for sensitive strings in shared preferences
        sens_keywords = ["password", "token", "secret", "user", "key", "auth"]
        found_keywords = [kw for kw in sens_keywords if kw in sp_output.lower()]
        if found_keywords:
            report.add_finding(
                severity="CRITICAL",
                title="Plaintext Credentials / Tokens in SharedPreferences",
                description=f"App stores unencrypted sensitive keys ({', '.join(found_keywords)}) inside SharedPreferences XML files.",
                evidence=sp_output[:300],
                remediation="Use AndroidX EncryptedSharedPreferences backed by Android Keystore."
            )
            finding("CRITICAL", "Plaintext sensitive data in SharedPreferences", sp_output[:120])
    else:
        info("No accessible plaintext SharedPreferences found via run-as.")

    # 2. Inspect SQLite Databases
    info("Inspecting SQLite databases...")
    db_cmd = f"run-as {package_name} ls -la databases/ 2>/dev/null"
    db_output = run_shell_command(db_cmd, device=device_id)
    if db_output and ".db" in db_output:
        report.add_finding(
            severity="HIGH",
            title="Unencrypted SQLite Database Present",
            description="Identified SQLite database file(s) in application private directory without obvious database-level encryption.",
            evidence=db_output,
            remediation="Use SQLCipher or room-encryption to encrypt mobile database files at rest."
        )
        finding("HIGH", "Unencrypted SQLite database found", db_output.strip())

    # 3. External storage inspection
    info("Checking external storage for leaked backup files...")
    ext_cmd = "ls -la /sdcard/ /sdcard/Download/ /sdcard/*Vault* 2>/dev/null"
    ext_output = run_shell_command(ext_cmd, device=device_id)
    if ext_output and ("InsecureVault" in ext_output or "backup.txt" in ext_output):
        report.add_finding(
            severity="HIGH",
            title="Sensitive Data Written to Shared External Storage",
            description="Application creates files or backups on public external storage (/sdcard/) accessible to any app with storage permission.",
            evidence=ext_output[:250],
            remediation="Store private application data solely inside getFilesDir() / internal sandboxed storage."
        )
        finding("HIGH", "External storage data leak detected", ext_output[:120])

    # 4. Check Logcat for sensitive leaks
    info("Checking recent Logcat entries for leaked credentials/tokens...")
    log_output = get_logcat(lines=300, device=device_id)
    leak_matches = []
    for line in log_output.split("\n"):
        if any(term in line.lower() for term in ["pass:", "password", "auth_tok", "master_key", "secret"]):
            leak_matches.append(line.strip())

    if leak_matches:
        report.add_finding(
            severity="HIGH",
            title="Sensitive Information Disclosed in System Logcat",
            description="Application logs sensitive credentials, keys, or auth data to system logcat.",
            evidence="\n".join(leak_matches[:5]),
            remediation="Remove verbose Log.d / Log.v calls from production code and use ProGuard rule '-assumenosideeffects class android.util.Log'."
        )
        finding("HIGH", "Sensitive data leaked in Logcat logs", leak_matches[0][:100])

    report.generate_summary()
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Runtime Storage Security Auditor")
    parser.add_argument("--package", required=True, help="Target application package name")
    parser.add_argument("--device", help="Specific ADB device ID")
    parser.add_argument("--output", help="Optional report output file")
    args = parser.parse_args()

    rep = check_storage(args.package, device_id=args.device)
    if rep and args.output:
        rep.generate_markdown(args.output)
        success(f"Report written to {args.output}")
