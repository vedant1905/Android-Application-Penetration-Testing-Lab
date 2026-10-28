# Android Application Penetration Testing Lab — Setup Guide

This guide walks you through setting up a complete, professional Android application security testing environment on your local workstation.

---

## 1. Prerequisites

Ensure the following prerequisites are installed:
- **Java Development Kit (JDK 17 or JDK 11)**: Required by Android SDK & Gradle.
- **Android Studio & SDK Platform Tools**: Includes `adb`, `emulator`, and AVD Manager.
- **Python 3.8+**: To run automated scripts.
- **Git**: To version control your lab projects.

---

## 2. Setting Up the Android Emulator

### Option A: Official Android Studio AVD (Recommended for beginners)
1. Open Android Studio -> **Device Manager** -> **Create Device**.
2. Select **Pixel 4** or **Pixel 6**.
3. Choose a system image:
   - **Recommended:** **API 29 (Android 10)** or **API 30 (Android 11)** with **Google APIs** (NOT Google Play, so you can have root/writable access).
4. Launch the emulator with writable system support:
   ```bash
   emulator -avd <Your_AVD_Name> -writable-system -no-snapshot
   ```

### Option B: Genymotion / Corellium
Genymotion provides pre-rooted Android virtual devices that make dynamic security assessments and Burp CA installation seamless.

---

## 3. Configuring ADB & Root Access

1. Verify ADB detects your emulator:
   ```bash
   adb devices
   ```
2. Verify root permissions:
   ```bash
   adb root
   adb remount
   adb shell whoami  # Should output: root
   ```

---

## 4. Setting Up Python Environment & Automated Scripts

Install the minimal scanning dependencies:
```bash
cd "D:\project\Android Application Penetration Testing Lab\scripts"
pip install -r requirements.txt
```

Verify the scripts are operational:
```bash
python scan_apk.py --help
python check_manifest.py --help
```

---

## 5. Building and Installing the Vulnerable Lab Apps

Navigate to each app directory and build the debug APK:

### App 1: InsecureVault
```bash
cd "D:\project\Android Application Penetration Testing Lab\vulnerable-apps\01-InsecureVault"
# On Windows:
gradlew assembleDebug
adb install app/build/outputs/apk/debug/app-debug.apk
```

### App 2: LeakyAuth
```bash
cd "D:\project\Android Application Penetration Testing Lab\vulnerable-apps\02-LeakyAuth"
gradlew assembleDebug
adb install app/build/outputs/apk/debug/app-debug.apk
```

### App 3: ExposedApp
```bash
cd "D:\project\Android Application Penetration Testing Lab\vulnerable-apps\03-ExposedApp"
gradlew assembleDebug
adb install app/build/outputs/apk/debug/app-debug.apk
```

---

## 6. Configuring Burp Suite for HTTPS Interception

1. Export Burp CA Certificate in DER format: `Burp -> Proxy -> Proxy Settings -> Export CA certificate -> Certificate in DER format`.
2. Convert certificate to Android PEM format and install to system CA store:
   ```bash
   openssl x509 -inform DER -in cacert.der -out cacert.pem
   HASH=$(openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -1)
   mv cacert.pem ${HASH}.0

   adb root
   adb remount
   adb push ${HASH}.0 /system/etc/security/cacerts/
   adb shell "chmod 644 /system/etc/security/cacerts/${HASH}.0"
   ```
3. Set emulator global proxy:
   ```bash
   adb shell settings put global http_proxy <YOUR_HOST_IP>:8080
   ```

---

## 7. Installing Frida for Dynamic Instrumentation

1. Install Frida client tools on your host:
   ```bash
   pip install frida-tools
   ```
2. Download matching `frida-server` binary for Android x86/x86_64:
   ```bash
   # Push and execute on emulator
   adb push frida-server /data/local/tmp/
   adb shell "chmod 755 /data/local/tmp/frida-server"
   adb shell "/data/local/tmp/frida-server &"
   ```
3. Verify connection:
   ```bash
   frida-ps -U
   ```
