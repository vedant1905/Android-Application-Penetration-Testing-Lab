# Mobile Penetration Testing Report — InsecureVault

| Metadata | Details |
|---|---|
| **Target App** | InsecureVault v1.0 |
| **Package** | `com.pentestlab.insecurevault` |
| **Platform** | Android 5.0+ (API 21 - 33) |
| **Auditor** | Security Assessment Team |
| **Date** | 2026-10-28 |

---

## 1. Executive Summary
During the security assessment of **InsecureVault**, multiple high and critical severity flaws were identified violating the **OWASP Mobile Top 10 (2024)**. The application stores user credentials, notes, and sensitive API secrets without encryption at rest, transmits cleartext traffic, and writes sensitive backups to world-readable external storage.

### Findings Breakdown
- 🔴 **Critical:** 1
- 🟠 **High:** 3
- 🟡 **Medium:** 2

---

## 2. Findings Summary Table

| ID | Title | OWASP Category | Severity |
|---|---|---|---|
| IV-01 | Plaintext Credential Storage in SharedPreferences | M2: Insecure Data Storage | 🔴 Critical |
| IV-02 | Unencrypted SQLite Database Storage | M2: Insecure Data Storage | 🟠 High |
| IV-03 | Sensitive Data Leaked to System Logcat | M2: Insecure Data Storage | 🟠 High |
| IV-04 | User Notes Exported to World-Readable External Storage | M2: Insecure Data Storage | 🟠 High |
| IV-05 | Hardcoded Cloud & API Keys in Application Source & Resources | M9: Reverse Engineering | 🟡 Medium |
| IV-06 | Application Data Backup Enabled (`allowBackup=true`) | M8: Code Tampering | 🟡 Medium |

---

## 3. Detailed Technical Findings

### IV-01: Plaintext Credential Storage in SharedPreferences
- **Severity:** 🔴 Critical (CVSS 8.4)
- **Component:** `MainActivity.java` -> `/data/data/com.pentestlab.insecurevault/shared_prefs/UserPrefs.xml`
- **Description:** When a user logs in, the credentials (username, password, login session token) are written in unencrypted plaintext directly into the app's `SharedPreferences`. Any attacker with physical access, backup privileges, or a rooted device can extract valid user credentials immediately.
- **Proof of Concept:**
  ```bash
  adb shell "run-as com.pentestlab.insecurevault cat shared_prefs/UserPrefs.xml"
  ```
  **Observed Output:**
  ```xml
  <map>
      <string name="username">admin</string>
      <string name="password">SuperSecret123!</string>
      <string name="login_token">tok_admin_172900000</string>
  </map>
  ```
- **Remediation:** Adopt `EncryptedSharedPreferences` provided by AndroidX Security:
  ```java
  MasterKey masterKey = new MasterKey.Builder(context)
      .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
      .build();

  SharedPreferences sharedPreferences = EncryptedSharedPreferences.create(
      context,
      "secure_prefs",
      masterKey,
      EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
      EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
  );
  ```

---

### IV-02: Unencrypted SQLite Database Storage
- **Severity:** 🟠 High (CVSS 7.5)
- **Component:** `DatabaseHelper.java` (`/databases/notes.db`)
- **Description:** The internal SQLite database storing private personal notes is created using standard `SQLiteOpenHelper` without encryption at rest.
- **Proof of Concept:**
  ```bash
  adb shell "run-as com.pentestlab.insecurevault cp databases/notes.db /sdcard/notes.db"
  adb pull /sdcard/notes.db .
  sqlite3 notes.db "SELECT * FROM user_notes;"
  ```
- **Remediation:** Migrate the database to **SQLCipher** or Android Room with database encryption using keys stored in the Android Keystore.

---

### IV-03: Sensitive Data Leaked to System Logcat
- **Severity:** 🟠 High (CVSS 7.1)
- **Component:** `MainActivity.java` and `NotesActivity.java`
- **Description:** The app uses `Log.d("AUTH", ...)` to output user credentials and `Log.d("NOTES", ...)` to output note contents during regular runtime execution.
- **Proof of Concept:**
  ```bash
  adb logcat -d | grep -E "AUTH|NOTES"
  ```
- **Remediation:** Remove debug logs in production builds and configure ProGuard/R8 to strip `android.util.Log` invocations.

---

### IV-04: User Notes Exported to World-Readable External Storage
- **Severity:** 🟠 High (CVSS 7.2)
- **Component:** `NotesActivity.java` -> `/sdcard/InsecureVault/backup.txt`
- **Description:** Notes are duplicated to external shared storage (`/sdcard/InsecureVault/backup.txt`). Any third-party app installed on the device possessing `READ_EXTERNAL_STORAGE` permission can silently harvest all private notes.
- **Remediation:** Store private files only inside internal storage via `context.getFilesDir()`.

---

### IV-05: Hardcoded Cloud & API Keys
- **Severity:** 🟡 Medium (CVSS 5.8)
- **Component:** `AppConfig.java`, `res/values/strings.xml`
- **Description:** Static analysis with JADX decompilation revealed hardcoded credentials including AWS Secret keys (`wJalrXUtnFEMI...`), Google API Keys, and internal server endpoints.
- **Remediation:** Never embed production master keys or credentials directly within client-side binaries. Access protected APIs via authenticated backend proxies.
