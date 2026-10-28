# Android Penetration Testing Tools Reference

Essential tools utilized during mobile application security testing and reverse engineering.

| Tool Name | Purpose | Installation / Quick Command | Link |
|---|---|---|---|
| **Android Debug Bridge (ADB)** | Device communication, shell access, APK installation, package management | Included in Android SDK Platform-Tools (`winget install Google.PlatformTools`) | [developer.android.com](https://developer.android.com/tools/adb) |
| **JADX / JADX-GUI** | Dex to Java decompiler with cross-referencing and search capabilities | Download binary from GitHub releases (`jadx-gui`) | [github.com/skylot/jadx](https://github.com/skylot/jadx) |
| **APKTool** | Reverse engineer 3rd party, closed, binary Android apps (disassemble smali & resources) | `choco install apktool` or manual JAR download | [apktool.org](https://apktool.org/) |
| **Burp Suite** | Web proxy for intercepting and modifying HTTP/HTTPS network traffic | Community / Pro Installer | [portswigger.net](https://portswigger.net/burp) |
| **Frida** | Dynamic instrumentation toolkit for hooking Java and native APIs at runtime | `pip install frida-tools` | [frida.re](https://frida.re/) |
| **Objection** | Runtime mobile exploration toolkit powered by Frida (auto SSL bypass, root detection) | `pip install objection` | [github.com/sensepost/objection](https://github.com/sensepost/objection) |
| **MobSF (Mobile Security Framework)** | Automated static and dynamic all-in-one analysis framework | `docker run -it -p 8000:8000 opensecurity/mobsf:latest` | [github.com/MobSF/Mobile-Security-Framework-MobSF](https://github.com/MobSF) |
| **SQLite Browser (DB Browser)** | Visual interface for exploring dumped SQLite databases (`.db`, `.sqlite`) | `winget install DBBrowserForSQLite.DBBrowserForSQLite` | [sqlitebrowser.org](https://sqlitebrowser.org/) |
| **dex2jar & JD-GUI** | Tools to convert DEX to JAR format and inspect Java bytecode | GitHub release archives | [github.com/pxb1988/dex2jar](https://github.com/pxb1988/dex2jar) |
| **Drozer** | Android IPC security evaluation framework for inspecting providers, activities, and services | Python module / Docker container | [github.com/WithSecureLabs/drozer](https://github.com/WithSecureLabs/drozer) |
