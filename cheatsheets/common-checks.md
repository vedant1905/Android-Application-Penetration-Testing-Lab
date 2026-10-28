# Android Application Security Testing Checklist

A structured testing checklist aligned with the **OWASP Mobile Application Security Verification Standard (MASVS)** for tracking pentest coverage.

---

## 1. Information Gathering & Reverse Engineering
- [ ] Decompile APK using JADX / APKTool.
- [ ] Inspect `AndroidManifest.xml` for `android:debuggable="true"`.
- [ ] Inspect `AndroidManifest.xml` for `android:allowBackup="true"`.
- [ ] Inspect `AndroidManifest.xml` for `android:usesCleartextTraffic="true"`.
- [ ] Search bytecode and XML resources for hardcoded credentials, API keys, private keys, or endpoints.
- [ ] Check if code obfuscation (ProGuard / R8 / DexGuard) is applied.
- [ ] Check for presence of unencrypted SQLite databases or sensitive assets inside `/assets/` or `/res/raw/`.

---

## 2. Insecure Data Storage (MASVS-STORAGE)
- [ ] Audit `SharedPreferences` for plaintext storage of passwords, session tokens, or PII (`adb shell run-as ... cat shared_prefs/*.xml`).
- [ ] Check if internal SQLite databases use encryption (SQLCipher / encrypted Room).
- [ ] Verify that sensitive data is not written to shared public storage (`/sdcard/`).
- [ ] Inspect system `logcat` buffers for leaked authentication tokens, usernames, or responses (`adb logcat -d`).
- [ ] Check if keyboard cache / auto-complete is disabled on sensitive password inputs (`inputType="textPassword"`).
- [ ] Verify that sensitive screens prevent screenshot capture using `FLAG_SECURE`.

---

## 3. Cryptography & Key Management (MASVS-CRYPTO)
- [ ] Verify that cryptographic keys are stored securely using the Android Keystore rather than hardcoded strings.
- [ ] Ensure strong, modern encryption ciphers (e.g., AES-GCM) are used instead of legacy modes (DES, 3DES, AES-ECB).
- [ ] Verify initialization vectors (IVs) are cryptographically random and not reused.

---

## 4. Authentication & Session Management (MASVS-AUTH)
- [ ] Verify that all authentication logic and token evaluations occur server-side rather than client-side.
- [ ] Check for hardcoded credentials, backdoors, or default passwords in source code.
- [ ] Verify biometric or PIN authentication cannot be trivially bypassed via client-side Frida hooking.
- [ ] Verify step-up re-authentication is enforced prior to sensitive transactions.

---

## 5. Network Communication (MASVS-NETWORK)
- [ ] Verify all communications occur strictly over TLS (HTTPS).
- [ ] Inspect `res/xml/network_security_config.xml` to verify user CA certificates are not trusted in production builds.
- [ ] Test application traffic through an interception proxy (Burp Suite).
- [ ] Check whether SSL/TLS certificate pinning is implemented.
- [ ] Verify that custom TrustManagers validate certificates properly and do not accept untrusted CAs unconditionally.

---

## 6. Platform Interaction & IPC (MASVS-PLATFORM)
- [ ] Review all exported Activities, Services, and Broadcast Receivers (`android:exported="true"`).
- [ ] Test whether exported Activities bypass authentication workflows.
- [ ] Audit exported Content Providers for SQL Injection or permissionless data leakage.
- [ ] Verify that implicit Intents containing sensitive payloads are not broadcast across the system.
- [ ] Check WebViews:
  - [ ] Is JavaScript enabled (`setJavaScriptEnabled(true)`) unnecessarily?
  - [ ] Are native bridges exposed (`addJavascriptInterface`) allowing arbitrary code execution?
  - [ ] Is file access restricted (`setAllowFileAccess(false)`)?
- [ ] Test custom URI deep link schemes for parameter injection or command manipulation.
