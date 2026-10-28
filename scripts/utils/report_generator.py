"""
Report Generator — Creates professional Markdown penetration testing reports.
Collects findings and generates formatted output.
"""

import os
from datetime import datetime


class Finding:
    """Represents a single security finding."""

    def __init__(self, severity, title, description, evidence="", remediation=""):
        self.severity = severity.upper()
        self.title = title
        self.description = description
        self.evidence = evidence
        self.remediation = remediation


class ReportGenerator:
    """Generates professional penetration testing reports in Markdown format."""

    SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    SEVERITY_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}

    def __init__(self, app_name="Unknown App", tester="Automated Scanner"):
        self.app_name = app_name
        self.tester = tester
        self.findings = []
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def add_finding(self, severity, title, description, evidence="", remediation=""):
        """Add a security finding to the report."""
        self.findings.append(Finding(severity, title, description, evidence, remediation))

    def _sorted_findings(self):
        """Sort findings by severity (Critical first)."""
        return sorted(self.findings, key=lambda f: self.SEVERITY_ORDER.get(f.severity, 99))

    def generate_summary(self):
        """Print a summary table to the terminal."""
        from .colors import CYAN, BOLD, RESET, RED, YELLOW, BLUE, GREEN

        counts = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        total = len(self.findings)
        print(f"\n{CYAN}{BOLD}╔══════════════════════════════════════╗")
        print(f"║         AUDIT SUMMARY                ║")
        print(f"╠══════════════════════════════════════╣")
        print(f"║  {RED}CRITICAL:  {counts.get('CRITICAL', 0):<25}{CYAN}║")
        print(f"║  {RED}HIGH:      {counts.get('HIGH', 0):<25}{CYAN}║")
        print(f"║  {YELLOW}MEDIUM:    {counts.get('MEDIUM', 0):<25}{CYAN}║")
        print(f"║  {BLUE}LOW:       {counts.get('LOW', 0):<25}{CYAN}║")
        print(f"║  INFO:     {counts.get('INFO', 0):<25}║")
        print(f"╠══════════════════════════════════════╣")
        print(f"║  Total Findings: {total:<19}  ║")
        print(f"╚══════════════════════════════════════╝{RESET}\n")

    def generate_markdown(self, output_path):
        """Generate a professional Markdown pentest report."""
        findings = self._sorted_findings()

        report = []
        report.append(f"# Penetration Testing Report — {self.app_name}\n")
        report.append(f"**Tester:** {self.tester}  ")
        report.append(f"**Date:** {self.timestamp}  ")
        report.append(f"**Total Findings:** {len(findings)}\n")

        # Executive Summary
        report.append("## Executive Summary\n")
        counts = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        report.append(f"The security assessment of **{self.app_name}** identified "
                       f"**{len(findings)}** findings:\n")
        report.append("| Severity | Count |")
        report.append("|----------|-------|")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if counts.get(sev, 0) > 0:
                emoji = self.SEVERITY_EMOJI.get(sev, "")
                report.append(f"| {emoji} {sev} | {counts[sev]} |")
        report.append("")

        # Findings Summary Table
        report.append("## Findings Summary\n")
        report.append("| # | Severity | Title |")
        report.append("|---|----------|-------|")
        for i, f in enumerate(findings, 1):
            emoji = self.SEVERITY_EMOJI.get(f.severity, "")
            report.append(f"| {i} | {emoji} {f.severity} | {f.title} |")
        report.append("")

        # Detailed Findings
        report.append("## Detailed Findings\n")
        for i, f in enumerate(findings, 1):
            emoji = self.SEVERITY_EMOJI.get(f.severity, "")
            report.append(f"### {i}. {emoji} [{f.severity}] {f.title}\n")
            report.append(f"**Severity:** {f.severity}\n")
            report.append(f"**Description:**\n{f.description}\n")
            if f.evidence:
                report.append(f"**Evidence:**\n```\n{f.evidence}\n```\n")
            if f.remediation:
                report.append(f"**Remediation:**\n{f.remediation}\n")
            report.append("---\n")

        # Write to file
        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(report))

        return output_path
