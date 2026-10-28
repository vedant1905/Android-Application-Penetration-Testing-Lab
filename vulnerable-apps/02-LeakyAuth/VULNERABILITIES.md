# LeakyAuth — Vulnerability Documentation

## App Description
LeakyAuth is a mock banking application that demonstrates **OWASP M4: Insecure Authentication** and **OWASP M3: Insecure Communication** vulnerabilities.

**Package:** `com.pentestlab.leakyauth`

---

## Planted Vulnerabilities

### 1. 🔴 CRITICAL — Hardcoded Admin Credentials
- **File:** `LoginActivity.java`
- **Description:** Admin username/password hardcoded as constants: `admin` / `admin@123`
- **Exploit:**
  ```bash
  jadx -d output/ leakyauth.apk
  grep -r "admin" output/sources/com/pentestlab/leakyauth/
  ```

### 2. 🔴 CRITICAL — Trust All Certificates
- **File:** `NetworkManager.java`
- **Description:** Custom `TrustAllCertificates` class accepts any SSL certificate
- **Exploit:** Configure Burp Suite as proxy → intercept all HTTPS traffic without certificate errors

### 3. 🔴 HIGH — Client-Side Authentication Bypass
- **File:** `PinVerifier.java`
- **Description:** PIN verified locally, never sent to server. Default PIN `1234` and master PIN `0000` hardcoded.
- **Exploit (Frida):**
  ```javascript
  Java.perform(function() {
      var PinVerifier = Java.use('com.pentestlab.leakyauth.PinVerifier');
      PinVerifier.verifyPin.implementation = function(pin) {
          return true;
      };
  });
  ```

### 4. 🔴 HIGH — Cleartext HTTP Communication
- **File:** `NetworkManager.java`, `AndroidManifest.xml`
- **Description:** Auth requests sent over HTTP with credentials in URL query parameters
- **Exploit:** Use Wireshark/tcpdump to capture plaintext credentials on the network

### 5. 🔴 HIGH — Plaintext Auth Token Storage
- **File:** `LoginActivity.java`
- **Location:** `/data/data/com.pentestlab.leakyauth/files/auth_token.txt`
- **Exploit:**
  ```bash
  adb shell "run-as com.pentestlab.leakyauth cat files/auth_token.txt"
  ```

### 6. 🟡 MEDIUM — No Re-authentication for Sensitive Actions
- **File:** `DashboardActivity.java`
- **Description:** Money transfer available without re-entering credentials or PIN

### 7. 🟡 MEDIUM — Master PIN Backdoor
- **File:** `PinVerifier.java`
- **Description:** PIN `0000` always grants access regardless of username
