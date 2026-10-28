# OWASP Mobile Top 10 (2024 Reference & Lab Mapping)

This reference outlines the current **OWASP Mobile Top 10** vulnerabilities and demonstrates how our pentest lab apps model and test each flaw.

---

## 1. M1: Improper Platform Usage
- **Description:** Misuse of Android platform features or failure to implement platform security controls (e.g., misconfigured Android intents, exported activities, vulnerable content providers, excessive permissions).
- **Lab Coverage:**
  - `ExposedApp`: Unprotected exported activities allowing authentication bypass (`ProfileActivity`, `AdminActivity`).
  - `ExposedApp`: Content Provider (`UserContentProvider`) without permission checks vulnerable to SQL injection.
- **Testing Approach:** Audit `AndroidManifest.xml` for `android:exported="true"`, attempt component launches via `adb shell am start` or `content query`.

---

## 2. M2: Insecure Data Storage
- **Description:** Storing sensitive information (passwords, tokens, PII) in plaintext inside SharedPreferences, unencrypted SQLite databases, or world-readable shared external storage (`/sdcard`).
- **Lab Coverage:**
  - `InsecureVault`: Plaintext user credentials in `UserPrefs.xml`.
  - `InsecureVault`: Unencrypted SQLite database `notes.db`.
  - `InsecureVault`: Notes backed up to external shared storage.
- **Testing Approach:** Inspect `/data/data/<package>/` sandbox via `adb shell "run-as ..."` and review SQLite structures.

---

## 3. M3: Insecure Communication
- **Description:** Transmitting unencrypted sensitive traffic over cleartext HTTP, using insecure TLS configurations, or failing to validate SSL certificates.
- **Lab Coverage:**
  - `LeakyAuth`: Cleartext HTTP transmission of login credentials.
  - `LeakyAuth`: Custom `TrustAllCertificates` TrustManager trusting all certificates without verification.
- **Testing Approach:** Route traffic through Burp Suite proxy, inspect network security configs, and test for SSL pinning bypass.

---

## 4. M4: Insecure Authentication
- **Description:** Performing authentication checks entirely client-side, hardcoding master credentials, or implementing flawed PIN verification logic.
- **Lab Coverage:**
  - `LeakyAuth`: Hardcoded admin credentials (`admin` / `admin@123`).
  - `LeakyAuth`: Client-side PIN verification logic with backdoor PIN `0000`.
- **Testing Approach:** Decompile APK using JADX to uncover hardcoded credentials; write Frida hooks to tamper with boolean return values.

---

## 5. M5: Insufficient Cryptography
- **Description:** Employing weak cryptographic algorithms, hardcoded encryption keys, or static initialization vectors (IV).
- **Lab Coverage:**
  - `InsecureVault`: Hardcoded master encryption key `SuperSecret123!` and static IV in strings resources.
- **Testing Approach:** Static code search with regular expressions for crypto keys, static IVs, or ECB mode usage.

---

## 6. M6: Insecure Authorization
- **Description:** Failure to verify user authorizations on the server side; allowing unauthorized users to execute administrative actions.
- **Lab Coverage:**
  - `ExposedApp`: Direct invocation of `AdminActivity` without role or permission checks.
  - `LeakyAuth`: Executing money transfers without step-up authentication.
- **Testing Approach:** Attempt direct intent invocations using ADB and analyze inter-component authorization boundaries.

---

## 7. M7: Client Code Quality
- **Description:** Vulnerabilities stemming from insecure coding practices such as enabling JavaScript in WebViews, exposing native Java objects via `addJavascriptInterface`, or format string/buffer issues.
- **Lab Coverage:**
  - `ExposedApp`: `InternalWebViewActivity` enables JavaScript and exposes `AndroidBridge` allowing command execution.
- **Testing Approach:** Inspect WebView settings, identify Javascript interfaces, and craft payload URLs.

---

## 8. M8: Code Tampering
- **Description:** The application does not detect runtime tampering, debugging hooks, or environment modifications (e.g. running under Frida, Magisk, or debuggers).
- **Lab Coverage:**
  - All apps: Shipped with `android:debuggable="true"` and `android:allowBackup="true"`.
- **Testing Approach:** Attach `jdb` debugger, inspect ADB backup behavior.

---

## 9. M9: Reverse Engineering
- **Description:** Bytecode can be decompiled into clean Java source code with no obfuscation (ProGuard/R8) or string encryption.
- **Lab Coverage:**
  - All apps: No ProGuard/R8 obfuscation applied; class and method names preserved intact.
- **Testing Approach:** Decompile with JADX and evaluate source code readability.

---

## 10. M10: Extraneous Functionality
- **Description:** Hidden backdoors, administrative consoles, or debug features accidentally left in production builds.
- **Lab Coverage:**
  - `LeakyAuth`: Hidden master PIN `0000`.
  - `ExposedApp`: Hidden `DeepLinkActivity` command processor.
- **Testing Approach:** Review manifest schemes and search decompiled codebase for development keywords.
