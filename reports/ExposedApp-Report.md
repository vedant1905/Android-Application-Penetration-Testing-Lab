# Mobile Penetration Testing Report — ExposedApp

| Metadata | Details |
|---|---|
| **Target App** | ExposedApp v1.0 |
| **Package** | `com.pentestlab.exposedapp` |
| **Platform** | Android 5.0+ (API 21 - 33) |
| **Auditor** | Mobile Application Security Testing Lab |
| **Date** | 2026-10-28 |

---

## 1. Executive Summary
**ExposedApp** demonstrates critical Android platform misuse vulnerabilities. Due to improperly configured component export policies (`android:exported="true"`), lack of IPC permission validation, dangerous WebView JavaScript bridges, and unparameterized SQL queries in Content Providers, external applications can bypass all authentications, inject SQL queries, execute shell commands, and harvest personal user records.

### Findings Breakdown
- 🔴 **Critical:** 2
- 🟠 **High:** 2
- 🟡 **Medium:** 1

---

## 2. Findings Summary Table

| ID | Title | OWASP Category | Severity |
|---|---|---|---|
| EA-01 | SQL Injection in Exported Content Provider | M1: Improper Platform Usage | 🔴 Critical |
| EA-02 | Remote Command Execution via WebView JavaScript Interface | M7: Client Code Quality | 🔴 Critical |
| EA-03 | Exported Admin & Profile Activities Bypass Authentication | M6: Insecure Authorization | 🟠 High |
| EA-04 | Sensitive PII Exfiltrated via Unprotected Broadcast Intent | M1: Improper Platform Usage | 🟠 High |
| EA-05 | Insecure Deep Link Command Parameter Execution | M1: Improper Platform Usage | 🟠 High |

---

## 3. Detailed Technical Findings

### EA-01: SQL Injection in Exported Content Provider
- **Severity:** 🔴 Critical (CVSS 9.3)
- **Component:** `UserContentProvider.java` (`content://com.pentestlab.exposedapp.provider/users`)
- **Description:** The Content Provider is exported with no `readPermission` or `writePermission`. The `query()` method directly concatenates the caller-supplied `selection` argument into an unparameterized SQL query.
- **Proof of Concept:**
  ```bash
  # 1. Query full user directory including SSNs:
  adb shell content query --uri content://com.pentestlab.exposedapp.provider/users

  # 2. Exploit SQL Injection to extract schema:
  adb shell content query --uri content://com.pentestlab.exposedapp.provider/users \
      --where "1=1) UNION SELECT 1,sqlite_version(),sql,4,5,6 FROM sqlite_master--"
  ```
- **Remediation:** Parameterize SQL queries using `selectionArgs` instead of string concatenation, and restrict the provider with `android:exported="false"` or custom signature-level permissions.

---

### EA-02: Remote Command Execution via WebView JavaScript Interface
- **Severity:** 🔴 Critical (CVSS 8.9)
- **Component:** `InternalWebViewActivity.java` (`AndroidBridge`)
- **Description:** The application's WebView enables JavaScript execution and registers a native bridge (`addJavascriptInterface(new AndroidBridge(), "AndroidBridge")`) containing methods like `executeCommand()` and `readFile()`. Any webpage loaded in this WebView can execute arbitrary shell commands within the app sandbox.
- **Proof of Concept:**
  ```bash
  adb shell am start -n com.pentestlab.exposedapp/.InternalWebViewActivity \
      --es url "javascript:void(document.body.innerHTML=AndroidBridge.executeCommand('id'))"
  ```
- **Remediation:** Remove dangerous reflection/execution bridges, restrict loaded URLs to trusted origins, and avoid loading arbitrary external URLs passed via Intents.

---

### EA-03: Exported Activities Bypass Authentication
- **Severity:** 🟠 High (CVSS 7.8)
- **Component:** `ProfileActivity.java`, `AdminActivity.java`
- **Description:** Privileged activities are flagged `android:exported="true"` in `AndroidManifest.xml` and do not verify caller permissions or session validity on launch.
- **Proof of Concept:**
  ```bash
  # Launch Admin Activity directly:
  adb shell am start -n com.pentestlab.exposedapp/.AdminActivity
  ```
- **Remediation:** Mark internal activities with `android:exported="false"` unless intended for external cross-app invocations.

---

### EA-04: Sensitive PII Exfiltrated via Unprotected Broadcast Intent
- **Severity:** 🟠 High (CVSS 7.4)
- **Component:** `DataBroadcastReceiver.java`
- **Description:** Login flows broadcast implicit Intents with action `com.pentestlab.exposedapp.USER_DATA` containing sensitive extras including Social Security Numbers and phone numbers. Any untrusted third-party app installed on the device can register a broadcast receiver and silently collect this data.
- **Remediation:** Use explicit Intents targeting specific components, or migrate to `LocalBroadcastManager` / scoped flows.
