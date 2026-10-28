"""
Terminal color utilities for pentesting scripts.
Provides colored output for findings, headers, and status messages.
"""

import sys

# ANSI Color Codes
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

# Severity colors
SEVERITY_COLORS = {
    "CRITICAL": RED + BOLD,
    "HIGH": RED,
    "MEDIUM": YELLOW,
    "LOW": BLUE,
    "INFO": CYAN,
}


def success(msg):
    """Print a success message in green."""
    print(f"{GREEN}[+]{RESET} {msg}")


def warning(msg):
    """Print a warning message in yellow."""
    print(f"{YELLOW}[!]{RESET} {msg}")


def error(msg):
    """Print an error message in red."""
    print(f"{RED}[-]{RESET} {msg}")


def info(msg):
    """Print an info message in blue."""
    print(f"{BLUE}[*]{RESET} {msg}")


def header(msg):
    """Print a section header."""
    width = max(len(msg) + 4, 50)
    print(f"\n{CYAN}{BOLD}{'=' * width}")
    print(f"  {msg}")
    print(f"{'=' * width}{RESET}\n")


def finding(severity, title, description=""):
    """Print a formatted security finding."""
    color = SEVERITY_COLORS.get(severity.upper(), WHITE)
    print(f"  {color}[{severity.upper()}]{RESET} {BOLD}{title}{RESET}")
    if description:
        for line in description.split("\n"):
            print(f"          {DIM}{line}{RESET}")
    print()


def banner():
    """Print the tool banner."""
    print(f"""{CYAN}{BOLD}
    ╔══════════════════════════════════════════════════╗
    ║     Android Application Penetration Testing Lab  ║
    ║              Automated Security Scanner           ║
    ╚══════════════════════════════════════════════════╝{RESET}
    """)
