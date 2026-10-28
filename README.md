# 🔬 Android Application Penetration Testing Lab

[![OWASP](https://img.shields.io/badge/OWASP-Mobile_Top_10-blue)](https://owasp.org/www-project-mobile-top-10/)
[![Python](https://img.shields.io/badge/Python-3.8+-green)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Android-brightgreen)](https://developer.android.com)

> A hands-on penetration testing lab featuring intentionally vulnerable Android applications and automated security scanning tools. Built for learning, practicing, and demonstrating Android application security testing techniques aligned with the **OWASP Mobile Top 10**.

---

## ⚠️ Disclaimer

**This lab is for educational purposes only.** The vulnerable applications are intentionally insecure and must **never** be installed on production devices or connected to real networks. Use only in isolated lab environments (emulators or test devices).

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Vulnerable Applications](#vulnerable-applications)
- [Automated Scanning Scripts](#automated-scanning-scripts)
- [Quick Start](#quick-start)
- [Lab Exercises](#lab-exercises)
- [Tools Used](#tools-used)
- [Sample Reports](#sample-reports)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)

---

## 🏗️ Overview

This lab provides:

| Component | Description |
|-----------|-------------|
| **3 Vulnerable Apps** | Purpose-built Android apps with realistic security flaws |
| **5 Scanning Scripts** | Python-based automated security analysis tools |
| **3 Pentest Reports** | Professional sample reports demonstrating findings |
| **3 Cheatsheets** | Quick-reference guides for ADB, Frida, and common checks |
| **Full Documentation** | Setup guide, tools reference, OWASP mapping |

### OWASP Mobile Top 10 Coverage

| OWASP Category | Covered By |
|----------------|------------|
| M1 — Improper Platform Usage | ExposedApp |
| M2 — Insecure Data Storage | InsecureVault |
| M3 — Insecure Communication | LeakyAuth |
| M4 — Insecure Authentication | LeakyAuth |
| M5 — Insufficient Cryptography | InsecureVault |
| M6 — Insecure Authorization | ExposedApp |
| M7 — Client Code Quality | ExposedApp (WebView) |
| M8 — Code Tampering | All (debuggable, backup) |
| M9 — Reverse Engineering | All (no obfuscation) |
| M10 — Extraneous Functionality | LeakyAuth (master PIN) |

---

## 🏛️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    PENTESTING LAB                        │
├──────────────┬──────────────────┬────────────────────────┤
│              │                  │                        │
│  VULNERABLE  │   AUTOMATION     │   DOCUMENTATION        │
│  APPS        │   SCRIPTS        │                        │
│              │                  │                        │
│ ┌──────────┐ │ ┌──────────────┐ │ ┌────────────────────┐ │
│ │Insecure  │ │ │scan_apk.py   │ │ │ Pentest Reports    │ │
│ │Vault     │ │ │              │ │ │ (3 complete)       │ │
│ │(Storage) │ │ ├──────────────┤ │ ├────────────────────┤ │
│ ├──────────┤ │ │check_        │ │ │ Cheatsheets        │ │
│ │LeakyAuth │ │ │manifest.py   │ │ │ (ADB, Frida,       │ │
│ │(Auth)    │ │ ├──────────────┤ │ │  Common Checks)    │ │
│ ├──────────┤ │ │check_        │ │ ├────────────────────┤ │
│ │Exposed   │ │ │storage.py    │ │ │ Setup Guide        │ │
│ │App       │ │ ├──────────────┤ │ │ Tools Reference    │ │
│ │(Platform)│ │ │check_network │ │ │ OWASP Mapping      │ │
│ └──────────┘ │ │_security.py  │ │ └────────────────────┘ │
│              │ ├──────────────┤ │                        │
│              │ │full_audit.py │ │                        │
│              │ └──────────────┘ │                        │
├──────────────┴──────────────────┴────────────────────────┤
│                  Android Emulator / Test Device           │
└─────────────────────────────────────────────────────────┘
```

---

## 📱 Vulnerable Applications

### 1. InsecureVault — Insecure Data Storage
A "secure notes" app that stores everything insecurely.

| Vulnerability | OWASP | Severity |
|--------------|-------|----------|
| Plaintext credentials in SharedPreferences | M2 | 🔴 Critical |
| Unencrypted SQLite database | M2 | 🔴 High |
| Sensitive data in Logcat | M2 | 🔴 High |
| Hardcoded API keys in source | M9 | 🟡 Medium |
| Data backup enabled | M2 | 🟡 Medium |
| External storage data exposure | M2 | 🔴 High |

### 2. LeakyAuth — Insecure Authentication
A banking app with fundamentally broken authentication.

| Vulnerability | OWASP | Severity |
|--------------|-------|----------|
| Hardcoded admin credentials | M4 | 🔴 Critical |
| Trust-all-certificates TrustManager | M3 | 🔴 Critical |
| Client-side only authentication | M4 | 🔴 High |
| HTTP cleartext communication | M3 | 🔴 High |
| Plaintext auth token storage | M2 | 🔴 High |
| Master PIN backdoor | M10 | 🔴 High |

### 3. ExposedApp — Improper Platform Usage
A contacts app with dangerously exposed components.

| Vulnerability | OWASP | Severity |
|--------------|-------|----------|
| SQL injection in Content Provider | M1 | 🔴 Critical |
| WebView JavaScript Interface RCE | M7 | 🔴 Critical |
| Exported activities bypass auth | M6 | 🔴 High |
| Broadcast receiver data leakage | M1 | 🔴 High |
| Deep link command injection | M1 | 🔴 High |

---

## 🛠️ Automated Scanning Scripts

```bash
# Static APK analysis — find hardcoded secrets, URLs, keys
python scripts/scan_apk.py --apk path/to/app.apk

# Manifest security audit — check exported components, permissions
python scripts/check_manifest.py --apk path/to/app.apk

# Network security config analysis
python scripts/check_network_security.py --apk path/to/app.apk

# Runtime storage check (requires ADB + device)
python scripts/check_storage.py --package com.pentestlab.insecurevault

# Full audit — runs everything and generates a report
python scripts/full_audit.py --apk path/to/app.apk --package com.pentestlab.insecurevault --output reports/
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Android SDK (ADB)
- Android Emulator or rooted test device
- Android Studio (to build apps)

### Setup

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/android-pentest-lab.git
cd android-pentest-lab

# 2. Install Python dependencies
pip install -r scripts/requirements.txt

# 3. Start Android emulator
emulator -avd Pixel_4_API_30 -writable-system

# 4. Build and install vulnerable apps
cd vulnerable-apps/01-InsecureVault
./gradlew assembleDebug
adb install app/build/outputs/apk/debug/app-debug.apk

# 5. Run a scan
python scripts/full_audit.py --apk app-debug.apk --package com.pentestlab.insecurevault
```

> 📖 See [docs/setup-guide.md](docs/setup-guide.md) for detailed setup instructions.

---

## 🧪 Lab Exercises

### Beginner
1. Install InsecureVault and find the stored credentials using ADB
2. Pull the SQLite database and read the notes
3. Use Logcat to capture leaked credentials

### Intermediate
4. Bypass LeakyAuth's login using hardcoded credentials
5. Exploit ExposedApp's Content Provider via SQL injection
6. Launch ExposedApp's admin panel directly via ADB

### Advanced
7. Intercept LeakyAuth's traffic using Burp Suite (no cert pinning!)
8. Use Frida to hook and modify authentication logic
9. Exploit ExposedApp's WebView JavaScript interface
10. Write a custom Frida script to bypass PIN verification

---

## 🔧 Tools Used

| Tool | Purpose |
|------|---------|
| **ADB** | Android Debug Bridge — device communication |
| **JADX** | APK decompiler — static analysis |
| **Burp Suite** | HTTP proxy — traffic interception |
| **Frida** | Dynamic instrumentation — runtime hooking |
| **MobSF** | Mobile Security Framework — automated analysis |
| **SQLite Browser** | Database viewer — examining app databases |
| **APKTool** | APK disassembler — resource extraction |

> 📖 See [docs/tools-reference.md](docs/tools-reference.md) for installation guides.

---

## 📊 Sample Reports

Professional penetration testing reports are included for each app:

- [InsecureVault Report](reports/InsecureVault-Report.md) — 5 findings (2 Critical, 2 High, 1 Medium)
- [LeakyAuth Report](reports/LeakyAuth-Report.md) — 4 findings (2 Critical, 2 High)
- [ExposedApp Report](reports/ExposedApp-Report.md) — 4 findings (2 Critical, 2 High)
- [Report Template](reports/pentest-report-template.md) — Use for your own assessments

---

## 📁 Project Structure

```
.
├── README.md                    # This file
├── LICENSE                      # MIT License
├── .gitignore                   # Git ignore rules
├── vulnerable-apps/             # Intentionally vulnerable Android apps
│   ├── 01-InsecureVault/        # Insecure Data Storage demo
│   ├── 02-LeakyAuth/            # Insecure Auth demo
│   └── 03-ExposedApp/           # Exported Components demo
├── scripts/                     # Automated security scanning scripts
│   ├── scan_apk.py              # Static APK analysis
│   ├── check_manifest.py        # Manifest security audit
│   ├── check_storage.py         # Runtime storage check
│   ├── check_network_security.py # Network config analysis
│   ├── full_audit.py            # Full audit orchestrator
│   └── utils/                   # Shared utilities
├── reports/                     # Sample pentest reports
├── docs/                        # Documentation
│   ├── setup-guide.md           # Lab setup instructions
│   ├── tools-reference.md       # Tool installation guide
│   └── owasp-mobile-top10.md    # OWASP reference
└── cheatsheets/                 # Quick reference guides
    ├── adb-commands.md           # ADB cheatsheet
    ├── frida-scripts.md          # Frida scripts collection
    └── common-checks.md          # Testing checklist
```

---

## 📜 License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- [OWASP Mobile Security Testing Guide](https://mas.owasp.org/)
- [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/)
- [Android Security Documentation](https://developer.android.com/privacy-and-security)

---

**Built for educational purposes as part of learning Android application security testing.**
