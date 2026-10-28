# Mobile Penetration Testing Report — LeakyAuth

| Metadata | Details |
|---|---|
| **Target App** | LeakyAuth v1.0 |
| **Package** | `com.pentestlab.leakyauth` |
| **Platform** | Android 5.0+ (API 21 - 33) |
| **Auditor** | Mobile Application Security Testing Lab |
| **Date** | 2026-10-28 |

---

## 1. Executive Summary
**LeakyAuth** represents a mobile financial/banking application with severe authentication and network communication weaknesses. The application relies on client-side authentication checks, contains hardcoded administrative credentials, bypasses SSL/TLS verification entirely, and transmits sensitive credentials over cleartext HTTP.

### Findings Breakdown
- 🔴 **Critical:** 2
- 🟠 **High:** 2
- 🟡 **Medium:** 2

---

## 2. Findings Summary Table

| ID | Title | OWASP Category | Severity |
|---|---|---|---|
| LA-01 | Hardcoded Administrative Credentials in Bytecode | M4: Insecure Authentication | 🔴 Critical |
| LA-02 | Insecure Custom TrustManager Disabling SSL/TLS Validation | M3: Insecure Communication | 🔴 Critical |
| LA-03 | Client-Side Only PIN Verification with Backdoor | M4: Insecure Authentication | 🟠 High |
| LA-04 | Cleartext HTTP Authentication Transmission | M3: Insecure Communication | 🟠 High |
| LA-05 | Insecure Plaintext Storage of Session Tokens | M2: Insecure Data Storage | 🟡 Medium |
| LA-06 | Missing Step-Up Re-Authentication for Financial Transactions | M6: Insecure Authorization | 🟡 Medium |

---

## 3. Detailed Technical Findings

### LA-01: Hardcoded Administrative Credentials in Bytecode
- **Severity:** 🔴 Critical (CVSS 9.1)
- **Component:** `LoginActivity.java`
- **Description:** Decompilation via JADX revealed embedded administrative credentials:
  ```java
  private static final String ADMIN_USERNAME = "admin";
  private static final String ADMIN_PASSWORD = "admin@123";
  ```
  Anyone decompiling the APK can gain unauthorized administrative access without contacting any remote server.
- **Remediation:** Remove static hardcoded credentials. All identity checks must validate against an authorized authentication server.

---

### LA-02: Insecure Custom TrustManager Disabling SSL/TLS Validation
- **Severity:** 🔴 Critical (CVSS 8.8)
- **Component:** `NetworkManager.java` (`TrustAllCertificates`)
- **Description:** The app initializes a custom `X509TrustManager` where `checkServerTrusted()` and `checkClientTrusted()` are completely empty methods, while `HostnameVerifier` returns `true` unconditionally. An attacker executing a Man-in-the-Middle (MitM) attack using tools like Burp Suite or mitmproxy can intercept and decrypt all HTTPS network requests seamlessly without certificate warnings.
- **Proof of Concept:**
  1. Route Android device network through Burp Suite proxy on port 8080.
  2. Perform login; requests and credentials are intercepted in plaintext despite using an `https://` protocol.
- **Remediation:** Remove custom TrustManagers. Use Android's platform default CA trust store and implement certificate pinning using `NetworkSecurityConfig` or OkHttp `CertificatePinner`.

---

### LA-03: Client-Side Only PIN Verification with Backdoor
- **Severity:** 🟠 High (CVSS 7.6)
- **Component:** `PinVerifier.java`
- **Description:** The PIN verification is executed entirely locally on the device rather than on the server. Furthermore, the master PIN `0000` is accepted unconditionally.
- **Frida Hooking Exploit:**
  ```javascript
  Java.perform(function() {
      var PinVerifier = Java.use('com.pentestlab.leakyauth.PinVerifier');
      PinVerifier.verifyPin.implementation = function(pin) {
          console.log('[+] Bypassing PIN check: ' + pin);
          return true;
      };
  });
  ```
- **Remediation:** Validate PINs on the backend server with rate limiting and lockout mechanisms.

---

### LA-04: Cleartext HTTP Authentication Transmission
- **Severity:** 🟠 High (CVSS 7.4)
- **Component:** `NetworkManager.java` & `AndroidManifest.xml`
- **Description:** Credentials are sent via unencrypted HTTP queries (`http://api.leakybank.com/auth/login?user=...&pass=...`), making them vulnerable to packet sniffing on public networks.
- **Remediation:** Enforce HTTPS exclusively and disallow cleartext traffic in `AndroidManifest.xml` (`android:usesCleartextTraffic="false"`).
