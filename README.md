# 🛡️ SentinelX Security Inspector

[![Android](https://img.shields.io/badge/Platform-Android-green.svg)](https://developer.android.com)
[![Kotlin](https://img.shields.io/badge/Language-Kotlin-purple.svg)](https://kotlinlang.org)
[![Jetpack Compose](https://img.shields.io/badge/UI-Jetpack%20Compose-blue.svg)](https://developer.android.com/jetpack/compose)
[![GitHub Repository](https://img.shields.io/badge/GitHub-SecurityInspector-black.svg)](https://github.com/ishanoshada/SecurityInspector)



**SentinelX Security Inspector** (Package: `com.ishanoshada.securityinspector`) is an open-source Android Runtime Application Self-Protection (RASP) & Environment Inspection Tool. Built natively using **Kotlin** and **Jetpack Compose**, it evaluates device security posture, dynamic analysis hooks, root status, emulators, virtual app cloners, runtime shell execution, dynamic code loading, memory integrity, SSL pinning, debugging environments, and interactive CTF challenges **without external dependencies**.


<center>


![1](/img/1.png)

</center>

> 🔗 **Repository**: [github.com/ishanoshada/SecurityInspector](https://github.com/ishanoshada/SecurityInspector)  
> 👤 **Author**: Ishan Oshada ([@ishanoshada](https://github.com/ishanoshada) | [ishanoshada.com](https://ishanoshada.com))

---

## 🌟 Key Features

* **65+ Total Inspection Rules**: Comprehensive inspection covering Frida, Root, LSPosed, Network & SSL Pinning, Virtual Apps, Runtime Shell Probes, Dynamic Code Loading, Memory Hook Integrity, Debuggers, ADB, Emulators, Firmware Build Integrity, System Mounts, and CTF Challenges.
* **Dedicated Dual-Page Section Tabs**:
  * **🛡️ Security Checks Tab**: Houses all 50+ system and RASP security inspections.
  * **🚩 CTF Flags Lab Tab**: Dedicated CTF challenges section featuring interactive reverse engineering and instrumentation labs.
* **Interactive CTF Lab with Auto-Solver**:
  * **Challenge Overview**: Explains deep technical concepts for each flag.
  * **Hint Levels**: Gentle (`💡`), Direct (`🔍`), and Solution (`🧠`) hints.
  * **Flag Submit & Match Check**: Type your guessed flag and verify correctness instantly.
  * **Auto-Solver Lab**: Step-by-step walkthrough & autoplay for learning static reversing (jadx) and dynamic instrumentation (Frida).
* **Live Counting Loading Screen**: Clean startup screen with live progress counting from `1 / 65` to `65 / 65`.
* **Interactive Code & API Popup**: Tap any check item in the dashboard to open a technical popup displaying exact function calls, inspected system APIs/files, deep technical mechanics, and Kotlin implementation snippets.
* **Floating Bottom Dashboard & White FAB**: Real-time fixed bottom floating summary bar displaying Total, Detected, and Clean metrics, alongside a floating circular white refresh button on the bottom right with zero overlap.
* **Auto-Responsive / Adaptive UI**: Automatically adjusts layouts for any phone, foldable, tablet, or landscape orientation using Compose `BoxWithConstraints`.
* **Zero External Dependencies**: Pure native Android SDK, Java, and Kotlin standard library implementation.

---


## 🚀 Building & Running

### Download the APK

Download the latest APK from the repository's [GitHub Releases](https://github.com/ishanoshada/SecurityInspector/releases). After a version tag is pushed, GitHub Actions builds the APK and attaches it to that release. The build usually takes a few minutes; completion time can vary.

To publish a release, create and push a version tag such as `v1.0.0`:

```bash
git tag v1.0.0
git push origin v1.0.0
```

When the workflow finishes, open the matching release and download `SentinelX-Security-Inspector-v1.0.0.apk` from its assets.

### Build locally

```bash
# Clone repository
git clone https://github.com/ishanoshada/SecurityInspector.git
cd SecurityInspector

# Build debug APK (Outputs: SentinelX-Security-Inspector-v1.0-debug.apk)
./gradlew assembleDebug
```

---



<center>


![2](/img/2.png)

</center>


## 🔒 Comprehensive Security Checks & CTF Lab

### 1. 🪝 Frida & Dynamic Hooking
* **TracerPid Non-Zero**: Inspects `/proc/self/status` for active `ptrace` attachment.
* **Frida Agent Memory Map**: Scans `/proc/self/maps` for `frida-agent.so`, `gadget.so`, `linjector`, `gum-js`.
* **Frida Memfd Handles**: Scans `/proc/self/fd/` file descriptors for `memfd:frida` handles.
* **Frida Worker Threads**: Inspects `/proc/self/task/*/comm` thread names for `frida`, `gmain`, `gdbus`, `pool-frida`, `gum`.
* **Frida Listening Ports (27042 - 27050)**: Scans `/proc/net/tcp` and `/proc/net/tcp6` for local listener sockets in HEX (`69A2` to `69AA`).
* **Frida Server Temp Files**: Checks `/data/local/tmp/` for `frida-server`, `re.frida.server`, `agent.so`, `hook.so`, `linjector`.
* **Inline Hook Frameworks**: Scans memory maps for ARM inline hooking libraries (`Dobby`, `ShadowHook`, `Whale`).
* **Executable RWX Memory**: Checks `/proc/self/maps` for anonymous readable/writable/executable memory pages (`rwxp`).

### 2. 🔓 Deep Root & Superuser
* **SU / Superuser Binaries**: Scans 20+ standard binary paths (`/system/bin/su`, `/system/xbin/su`, `/su/bin/su`, `/vendor/bin/su`, `/data/local/su`, etc.).
* **Magisk & KernelSU System Files**: Checks for `/data/adb/magisk`, `/sbin/.magisk`, `/data/adb/magisk.db`, `/data/adb/ksu`, `/data/adb/ksud`.
* **Magisk Mirror Mounts**: Inspects `/proc/self/mountinfo` for Magisk systemless loopback overlays and mirror mounts.
* **BusyBox Binary**: Checks `/system/bin/busybox` and `/system/xbin/busybox`.
* **SELinux Permissive Mode**: Executes native `getenforce` to verify SELinux mandatory access control state.

### 3. 📦 Root & Hiding Packages
* **Root / Hiding Packages**: Queries `PackageManager` for 19+ superuser manager & hiding apps (Magisk, KernelSU, SuperSU, LuckyPatcher, RootCloak, Xposed, Substrate).
* **Hide My Applist (HMA) Providers**: Resolves `com.tsng.hidemyapplist` and `org.frknkrc44.hma_oss` ContentProviders.

### 4. 💉 LSPosed & Xposed Framework
* **LSPosed Data Directory**: Direct accessibility check for `/data/adb/lspd/`.
* **Zygisk & LSPosed Modules**: Checks module paths under `/data/adb/modules/` (`lsposed`, `shamiko`, `hidemyapplist`, `zygisknext`).

### 5. 🔐 Network & SSL Security
* **User Installed CA Certificates**: Scans `/data/misc/user/0/cacerts-added/` for custom user-installed root CAs (Burp Suite, Charles Proxy, HTTPCanary).
* **System HTTP/HTTPS Proxy Set**: Reads Java System properties `http.proxyHost` and `https.proxyHost`.
* **Modified Default HostnameVerifier**: Inspects `HttpsURLConnection.getDefaultHostnameVerifier()` for dummy/allow-all verifiers.
* **OkHttp CertificatePinner**: Reflection check for `okhttp3.CertificatePinner`.
* **TrustKit Pinning Manager**: Reflection check for `com.datatheorem.android.trustkit.pinning.PinningTrustManager`.
* **Appmattus Certificate Transparency**: Reflection check for `com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyInterceptor`.
* **IBM MobileFirst / Worklight Pinning**: Reflection check for `com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning`.
* **CWAC / Conscrypt CertPinManager**: Reflection check for `com.commonsware.cwac.netsecurity.conscrypt.CertPinManager`.

### 6. 📦 Virtual App & App Cloning
* **Virtual App Packages Installed**: Scans `PackageManager` for Parallel Space, Dual Apps, VirtualXposed, and multi-account containers.
* **Process UID Mismatch**: Compares `Process.myUid()` to the application package's declared UID.
* **Virtual Container Data Path**: Checks if application `dataDir` points to a virtual sandbox path.

### 7. ⚙️ Runtime Execution Probes
* **Runtime `which su` Resolves**: Executes `which su` via kernel PATH search.
* **Runtime `su -c id` Grants Root**: Spawns a root shell and checks for `uid=0(root)` output.
* **Runtime `getenforce` Executes**: Executes native `getenforce` binary.
* **Runtime `which frida*` Resolves**: Resolves Frida CLI tools (`frida`, `frida-server`, `frida-ps`) in PATH.

### 8. 📥 Dynamic Code Loading (DCL)
* **DexClassLoader Present**: Scans the class loader chain for `DexClassLoader` or `BaseDexClassLoader` instances.
* **Executable Files in Cache/Files Dir**: Scans `cacheDir` and `filesDir` for unpacked `.dex`, `.apk`, `.jar`, or `.so` payloads.
* **ClassLoader Loads from `/data/local/tmp`**: Detects class loaders sourcing code from world-writable temporary directories.

### 9. 🧬 Memory & Hook Integrity
* **Anonymous RWX Memory Region**: Finds executable writable memory regions with no file backing (`rwxp`).
* **Executable Memfd or Deleted File Mapping**: Detects executable shared object mappings backed by `memfd:` or `(deleted)` files.
* **SO Loaded from Suspicious Path**: Detects native `.so` libraries mapped from `/data/local/tmp/`, `/sdcard/`, or `/dev/`.

### 10. 🐞 Debugger & Security Tools
* **Active Java Debugger Attached**: Queries `android.os.Debug.isDebuggerConnected()` and `waitingForDebugger()`.
* **Active VPN / Traffic Tunnel**: Inspects `ConnectivityManager` network capabilities for active `TRANSPORT_VPN` interfaces.
* **Injected System Properties**: Scans `System.getProperties()` for injected keys containing `frida`, `gum`, `linjector`, `talsec`, or `rasp`.
* **PairIP Licensing Client**: Reflection check for `com.pairip.licensecheck.LicenseClient`.
* **Crashlytics Security Utils**: Reflection check for `com.google.firebase.crashlytics.internal.common.CommonUtils`.

### 11. 🔌 ADB & Developer Options
* **ADBD Service Running**: Reads system property `init.svc.adbd`.
* **ADB Authorized Keys**: Checks `/data/misc/adb/adb_keys`.
* **ADB TCP Port 5037 Open**: Scans `/proc/net/tcp` for local socket bindings on port 5037 (HEX `13AD`).
* **Developer Options Enabled**: Queries `Settings.Global.DEVELOPMENT_SETTINGS_ENABLED`.
* **ADB USB Debugging Enabled**: Queries `Settings.Global.ADB_ENABLED`.
* **ro.debuggable Flag Set**: Reads system property `ro.debuggable == "1"`.
* **ro.secure Disabled**: Reads system property `ro.secure == "0"`.

### 12. 🤖 Android Emulator & QEMU
* **Emulator Build Properties**: Checks `Build.HARDWARE`, `FINGERPRINT`, `MODEL`, `PRODUCT` for `goldfish`, `ranchu`, `vbox86`, `sdk_gphone`.
* **ro.kernel.qemu Property**: Reads `ro.kernel.qemu == "1"`.
* **QEMU Drivers & Pipes**: Checks `/dev/qemu_pipe`, `/dev/socket/qemud`, `/sys/qemu_trace`.
* **Mock Telephony Values**: Queries `TelephonyManager` for mock operator signatures.

### 13. 🛠️ Build & Device Integrity
* **Test-Keys Build**: Checks `Build.TAGS` for `test-keys`.
* **Eng / Userdebug Build**: Checks `Build.TYPE` for `eng` or `userdebug`.
* **Bootloader Unlocked**: Checks `ro.boot.verifiedbootstate` for `orange` or `yellow`.
* **Bootloader Flash Unlocked**: Checks `ro.boot.flash.locked == "0"`.
* **VBMeta Digest Missing**: Checks if `ro.boot.vbmeta.digest` is empty.

### 14. 🌐 Environment & System Mounts
* **LD_PRELOAD Environment Variable**: Checks if `LD_PRELOAD` is active.
* **System Partition Mounted R/W**: Inspects `/proc/mounts` for `/system` mounted as read-write (`rw`).
* **Execution Timing Anomaly**: Runs a 100,000 iteration benchmark loop to detect artificial delays caused by active hooks or breakpoints.

### 15. 🚩 CTF Flags Lab (Reverse Engineering & Instrumentation)
* **Flag A — Static Analysis**: Recoverable via static decompilation (jadx) by decoding split Base64 chunks. Includes hint levels, flag submit match check, and step-by-step auto-solver.
* **Flag B — Dynamic Analysis**: Recoverable via dynamic instrumentation (Frida) by intercepting AES-256-GCM runtime decryption keyed against device properties. Includes hint levels, flag submit match check, and step-by-step auto-solver.

---

## 🏗️ Architecture & Package Structure

```
com.ishanoshada.securityinspector
├── models/
│   └── SecurityModels.kt            # SecurityCheckItem & SecurityCategory data classes
├── utils/
│   └── SystemUtils.kt               # Shared proc, mount, and system property helpers
├── checks/
│   ├── FridaChecker.kt              # Frida, Memfd, Thread, Port, & Hook checks
│   ├── RootChecker.kt               # SU binary, Magisk, SELinux, & Root Package checks
│   ├── LsposedChecker.kt            # LSPosed directory & Zygisk module checks
│   ├── NetworkSecurityChecker.kt    # User CAs, Proxies, HostnameVerifiers, & Pinning libraries
│   ├── VirtualAppChecker.kt         # Parallel Space, Dual Apps, & UID mismatch checks
│   ├── RuntimeExecChecker.kt        # 'which su', 'su -c id', 'getenforce', & 'which frida'
│   ├── DynamicLoadingChecker.kt     # DexClassLoader, cache dex/so files, & tmp loaders
│   ├── HookIntegrityChecker.kt      # Anonymous RWX, memfd exec, & suspicious .so paths
│   └── SystemEnvironmentChecker.kt  # Debugger, VPN, ADB, Emulator, Build, & Mount checks
├── flags/                           # CTF Flag A & B Vaults, Challenge Dialog, & Auto-Solver Lab
│   ├── StaticFlagVault.kt
│   ├── DynamicFlagVault.kt
│   ├── FlagSolver.kt
│   ├── FlagCategory.kt
│   ├── FlagChallengeDialog.kt
│   ├── FlagSolverDialog.kt
│   └── HintLevel.kt
├── ui/theme/                        # Material 3 Compose theme definitions
├── SecurityChecker.kt               # Central orchestrator facade
└── MainActivity.kt                  # Compose UI Dashboard, Tabs, Floating Bar, White FAB, & Dialogs
```

---

<p align="center">
  <a href="https://www.paypal.com/donate/?business=ic31908%40gmail.com&currency_code=USD">
    <img src="https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif" alt="Donate with PayPal" height="80">
  </a>
</p>

<p align="center">
  <a href="https://www.paypal.com/donate/?business=ic31908%40gmail.com&currency_code=USD">
    <img src="https://raw.githubusercontent.com/elestyle/elepay-payment-logos/master/payment_logos/svg/paypal.svg" alt="Donate with PayPal" height="100">
  </a>
</p>

## 📜 License & Credits

Created by **Ishan Oshada** ([@ishanoshada](https://github.com/ishanoshada)).  
Repository hosted at [github.com/ishanoshada/SecurityInspector](https://github.com/ishanoshada/SecurityInspector).
