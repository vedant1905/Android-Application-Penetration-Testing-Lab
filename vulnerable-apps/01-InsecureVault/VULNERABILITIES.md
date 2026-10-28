# InsecureVault — Vulnerability Documentation

## App Description
InsecureVault is a "secure notes" application that demonstrates **OWASP M2: Insecure Data Storage** vulnerabilities. Despite its name, the app stores all data insecurely.

**Package:** `com.pentestlab.insecurevault`

---

## Planted Vulnerabilities

### 1. 🔴 CRITICAL — Plaintext Credentials in SharedPreferences
- **File:** `MainActivity.java`
- **Location on device:** `/data/data/com.pentestlab.insecurevault/shared_prefs/UserPrefs.xml`
- **Description:** Username and password stored as plaintext XML
- **Exploit:**
  ```bash
  adb shell "run-as com.pentestlab.insecurevault cat shared_prefs/UserPrefs.xml"
  ```
- **Remediation:** Use `EncryptedSharedPreferences` from AndroidX Security library

### 2. 🔴 HIGH — Unencrypted SQLite Database
- **File:** `DatabaseHelper.java`
- **Location on device:** `/data/data/com.pentestlab.insecurevault/databases/notes.db`
- **Description:** All notes stored in plaintext SQLite database
- **Exploit:**
  ```bash
  adb shell "run-as com.pentestlab.insecurevault cp databases/notes.db /sdcard/"
  adb pull /sdcard/notes.db
  sqlite3 notes.db "SELECT * FROM user_notes;"
  ```
- **Remediation:** Use SQLCipher for encrypted database storage

### 3. 🔴 HIGH — Sensitive Data Logged to Logcat
- **File:** `MainActivity.java`, `NotesActivity.java`
- **Description:** Credentials and note contents logged via `Log.d()`
- **Exploit:**
  ```bash
  adb logcat -d | grep -E "AUTH|NOTES"
  ```
- **Remediation:** Remove all `Log.d()` calls containing sensitive data; use ProGuard to strip logs in release builds

### 4. 🔴 HIGH — External Storage Data Exposure
- **File:** `NotesActivity.java`
- **Location on device:** `/sdcard/InsecureVault/backup.txt`
- **Description:** Notes backed up to external storage, readable by any app
- **Exploit:**
  ```bash
  adb shell "cat /sdcard/InsecureVault/backup.txt"
  ```
- **Remediation:** Use app-specific internal storage or encrypted file storage

### 5. 🟡 MEDIUM — Hardcoded API Keys in Source Code
- **File:** `AppConfig.java`
- **Description:** API keys, AWS secrets, and encryption keys hardcoded in Java source
- **Exploit:**
  ```bash
  jadx -d output/ app.apk
  grep -r "API_KEY\|SECRET\|MASTER_KEY" output/
  ```
- **Remediation:** Use Android Keystore, environment variables, or server-side key management

### 6. 🟡 MEDIUM — Hardcoded Secrets in strings.xml
- **File:** `res/values/strings.xml`
- **Description:** API secrets and Firebase keys stored in resources
- **Exploit:**
  ```bash
  aapt dump resources app.apk | grep -i "api\|key\|secret"
  ```
- **Remediation:** Never store secrets in resource files

### 7. 🟡 MEDIUM — Backup Enabled
- **File:** `AndroidManifest.xml`
- **Description:** `android:allowBackup="true"` allows full data extraction via `adb backup`
- **Exploit:**
  ```bash
  adb backup -f backup.ab com.pentestlab.insecurevault
  java -jar abe.jar unpack backup.ab backup.tar
  tar xvf backup.tar
  ```
- **Remediation:** Set `android:allowBackup="false"`

### 8. 🟡 MEDIUM — Debuggable Build
- **File:** `AndroidManifest.xml`
- **Description:** `android:debuggable="true"` allows debugger attachment
- **Remediation:** Never ship debuggable builds to production

### 9. 🟢 LOW — Cleartext Traffic Allowed
- **File:** `AndroidManifest.xml`
- **Description:** `android:usesCleartextTraffic="true"` allows unencrypted HTTP
- **Remediation:** Set to `false` and use HTTPS exclusively
