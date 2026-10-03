package com.ishanoshada.securityinspector.checks

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Debug
import android.provider.Settings
import android.telephony.TelephonyManager
import com.ishanoshada.securityinspector.models.SecurityCategory
import com.ishanoshada.securityinspector.models.SecurityCheckItem
import com.ishanoshada.securityinspector.utils.SystemUtils
import java.io.File

object SystemEnvironmentChecker {

    fun getDebuggerAndToolsChecks(context: Context): SecurityCategory {
        val items = mutableListOf<SecurityCheckItem>()

        val isDebugger = Debug.isDebuggerConnected() || Debug.waitingForDebugger()
        items.add(
            SecurityCheckItem(
                id = "java_debugger",
                name = "Active Java Debugger Attached",
                description = "Checks android.os.Debug for active JDWP/Debugger attachment",
                isDetected = isDebugger,
                functionName = "SystemEnvironmentChecker.getDebuggerAndToolsChecks()",
                methodsAndApis = listOf("android.os.Debug.isDebuggerConnected()", "android.os.Debug.waitingForDebugger()"),
                technicalExplanation = "Queries official Android OS Debug API to determine if a JDWP debugger or IDE debugging session is currently attached to the process.",
                exampleCode = """
android.os.Debug.isDebuggerConnected() || android.os.Debug.waitingForDebugger()
                """.trimIndent()
            )
        )

        val vpnActive = checkVpnActive(context)
        items.add(
            SecurityCheckItem(
                id = "vpn_active",
                name = "Active VPN / Traffic Tunnel",
                description = "Checks if a VPN interface is active (Burp / Wireshark / Mitmproxy)",
                isDetected = vpnActive,
                functionName = "SystemEnvironmentChecker.checkVpnActive()",
                methodsAndApis = listOf("ConnectivityManager.activeNetwork", "NetworkCapabilities.hasTransport(TRANSPORT_VPN)"),
                technicalExplanation = "Inspects active network capabilities via ConnectivityManager to detect if network traffic is passing through a VPN tunnel interface (often used by Burp Suite, Wireshark, or Mitmproxy).",
                exampleCode = """
val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
val activeNet = cm.activeNetwork
val caps = cm.getNetworkCapabilities(activeNet)
caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
                """.trimIndent()
            )
        )

        val injectedSystemProps = checkSystemPropertiesInjected()
        items.add(
            SecurityCheckItem(
                id = "injected_sys_props",
                name = "Injected System Properties",
                description = "Checks System.getProperties() for frida, gum, or talsec keys",
                isDetected = injectedSystemProps,
                functionName = "SystemEnvironmentChecker.checkSystemPropertiesInjected()",
                methodsAndApis = listOf("System.getProperties()", "props.stringPropertyNames()"),
                technicalExplanation = "Scans all Java System properties for key names injected by Frida, Gum, or RASP agents containing frida, gum, linjector, talsec, or rasp.",
                exampleCode = """
val props = System.getProperties()
val keywords = listOf("frida", "gum", "linjector", "talsec", "rasp")
props.stringPropertyNames().any { key ->
    val lower = key.lowercase()
    keywords.any { lower.contains(it) }
}
                """.trimIndent()
            )
        )

        val pairipClass = isClassPresent("com.pairip.licensecheck.LicenseClient")
        items.add(
            SecurityCheckItem(
                id = "pairip_framework",
                name = "PairIP License Client Class",
                description = "Checks app classpath for PairIP anti-tamper library",
                isDetected = pairipClass,
                functionName = "SystemEnvironmentChecker.isClassPresent()",
                methodsAndApis = listOf("Class.forName(\"com.pairip.licensecheck.LicenseClient\")"),
                technicalExplanation = "Uses reflection Class.forName() to check if PairIP anti-tamper and licensing verification client is loaded into JVM runtime.",
                exampleCode = """
try {
    Class.forName("com.pairip.licensecheck.LicenseClient")
    true
} catch (e: Exception) { false }
                """.trimIndent()
            )
        )

        val crashlyticsClass = isClassPresent("com.google.firebase.crashlytics.internal.common.CommonUtils")
        items.add(
            SecurityCheckItem(
                id = "crashlytics_class",
                name = "Crashlytics Security Utils",
                description = "Checks app classpath for Firebase Crashlytics inspection utils",
                isDetected = crashlyticsClass,
                functionName = "SystemEnvironmentChecker.isClassPresent()",
                methodsAndApis = listOf("Class.forName(\"com.google.firebase.crashlytics.internal.common.CommonUtils\")"),
                technicalExplanation = "Checks for Firebase Crashlytics internal CommonUtils class which contains built-in environment and root checks.",
                exampleCode = """
try {
    Class.forName("com.google.firebase.crashlytics.internal.common.CommonUtils")
    true
} catch (e: Exception) { false }
                """.trimIndent()
            )
        )

        return SecurityCategory(
            categoryName = "Debugger & Security Libraries",
            iconEmoji = "🐞",
            items = items
        )
    }

    fun getAdbDeveloperChecks(context: Context): SecurityCategory {
        val items = mutableListOf<SecurityCheckItem>()

        val adbdState = SystemUtils.getSystemProperty("init.svc.adbd")
        items.add(
            SecurityCheckItem(
                id = "adbd_running",
                name = "ADBD Service Running",
                description = "Checks init.svc.adbd system property",
                isDetected = adbdState.equals("running", ignoreCase = true),
                functionName = "SystemUtils.getSystemProperty(\"init.svc.adbd\")",
                methodsAndApis = listOf("SystemProperties.get(\"init.svc.adbd\")", "getprop init.svc.adbd"),
                technicalExplanation = "Reads system property init.svc.adbd. Value 'running' indicates Android Debug Bridge background service daemon is active.",
                exampleCode = """
val adbdState = SystemUtils.getSystemProperty("init.svc.adbd")
adbdState.equals("running", ignoreCase = true)
                """.trimIndent()
            )
        )

        items.add(
            SecurityCheckItem(
                id = "adb_keys",
                name = "ADB Authorized Keys Exist",
                description = "Checks for /data/misc/adb/adb_keys presence",
                isDetected = File("/data/misc/adb/adb_keys").exists(),
                functionName = "SystemEnvironmentChecker.getAdbDeveloperChecks()",
                methodsAndApis = listOf("File(\"/data/misc/adb/adb_keys\").exists()"),
                technicalExplanation = "Checks for /data/misc/adb/adb_keys file which holds RSA public key signatures of host computers authorized for USB debugging.",
                exampleCode = """
File("/data/misc/adb/adb_keys").exists()
                """.trimIndent()
            )
        )

        items.add(
            SecurityCheckItem(
                id = "adb_port",
                name = "ADB TCP Port 5037 Open",
                description = "Scans /proc/net/tcp or tcp6 for port 5037",
                isDetected = SystemUtils.checkProcNetTcp(listOf("13AD")),
                functionName = "SystemUtils.checkProcNetTcp()",
                methodsAndApis = listOf("File(\"/proc/net/tcp\")", "Matching HEX port 13AD (5037)"),
                technicalExplanation = "Scans /proc/net/tcp for local socket bindings on port 5037 (HEX 13AD), indicating active ADB daemon network connections.",
                exampleCode = """
SystemUtils.checkProcNetTcp(listOf("13AD")) // 5037 in HEX
                """.trimIndent()
            )
        )

        val devOptions = try {
            Settings.Global.getInt(context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) != 0
        } catch (_: Exception) { false }

        items.add(
            SecurityCheckItem(
                id = "dev_settings",
                name = "Developer Options Enabled",
                description = "Checks Settings.Global DEVELOPMENT_SETTINGS_ENABLED",
                isDetected = devOptions,
                functionName = "SystemEnvironmentChecker.getAdbDeveloperChecks()",
                methodsAndApis = listOf("Settings.Global.getInt(resolver, DEVELOPMENT_SETTINGS_ENABLED)"),
                technicalExplanation = "Queries Settings.Global DEVELOPMENT_SETTINGS_ENABLED to check if Developer Options menu is turned on in Android system settings.",
                exampleCode = """
Settings.Global.getInt(context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) != 0
                """.trimIndent()
            )
        )

        val adbEnabled = try {
            Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) != 0
        } catch (_: Exception) { false }

        items.add(
            SecurityCheckItem(
                id = "adb_enabled",
                name = "ADB USB Debugging Enabled",
                description = "Checks Settings.Global ADB_ENABLED setting",
                isDetected = adbEnabled,
                functionName = "SystemEnvironmentChecker.getAdbDeveloperChecks()",
                methodsAndApis = listOf("Settings.Global.getInt(resolver, ADB_ENABLED)"),
                technicalExplanation = "Queries Settings.Global ADB_ENABLED flag to detect if USB Debugging mode is currently enabled on the device.",
                exampleCode = """
Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) != 0
                """.trimIndent()
            )
        )

        items.add(
            SecurityCheckItem(
                id = "debuggable_prop",
                name = "ro.debuggable Flag Set",
                description = "Checks if ro.debuggable system property equals 1",
                isDetected = SystemUtils.getSystemProperty("ro.debuggable") == "1",
                functionName = "SystemUtils.getSystemProperty(\"ro.debuggable\")",
                methodsAndApis = listOf("SystemProperties.get(\"ro.debuggable\")"),
                technicalExplanation = "Reads system property ro.debuggable. Value '1' indicates a debug build where native debuggers can attach to any app.",
                exampleCode = """
SystemUtils.getSystemProperty("ro.debuggable") == "1"
                """.trimIndent()
            )
        )

        val roSecure = SystemUtils.getSystemProperty("ro.secure")
        items.add(
            SecurityCheckItem(
                id = "ro_secure",
                name = "ro.secure Disabled",
                description = "Checks if ro.secure is set to 0 (insecure)",
                isDetected = roSecure == "0",
                functionName = "SystemUtils.getSystemProperty(\"ro.secure\")",
                methodsAndApis = listOf("SystemProperties.get(\"ro.secure\")"),
                technicalExplanation = "Reads system property ro.secure. Value '0' indicates an insecure kernel build with default root permissions.",
                exampleCode = """
SystemUtils.getSystemProperty("ro.secure") == "0"
                """.trimIndent()
            )
        )

        return SecurityCategory(
            categoryName = "ADB & Developer Options",
            iconEmoji = "🔌",
            items = items
        )
    }

    fun getEmulatorChecks(context: Context): SecurityCategory {
        val items = mutableListOf<SecurityCheckItem>()

        val hardware = Build.HARDWARE ?: ""
        val fingerprint = Build.FINGERPRINT ?: ""
        val model = Build.MODEL ?: ""
        val product = Build.PRODUCT ?: ""

        val isEmulatorBuild = hardware.lowercase().contains("goldfish") ||
                hardware.lowercase().contains("ranchu") ||
                hardware.lowercase().contains("vbox86") ||
                fingerprint.lowercase().contains("generic") ||
                model.lowercase().contains("emulator") ||
                product.lowercase().contains("sdk_gphone")

        items.add(
            SecurityCheckItem(
                id = "emulator_build_props",
                name = "Emulator Build Properties",
                description = "Checks Build.HARDWARE, FINGERPRINT, & MODEL for qemu/vbox",
                isDetected = isEmulatorBuild,
                functionName = "SystemEnvironmentChecker.getEmulatorChecks()",
                methodsAndApis = listOf("Build.HARDWARE", "Build.FINGERPRINT", "Build.MODEL", "Build.PRODUCT"),
                technicalExplanation = "Inspects Android Build class hardware, model, and fingerprint parameters for generic virtual machine strings (goldfish, ranchu, vbox86, sdk_gphone).",
                exampleCode = """
val hardware = Build.HARDWARE.lowercase()
val fingerprint = Build.FINGERPRINT.lowercase()
hardware.contains("goldfish") || hardware.contains("ranchu") || fingerprint.contains("generic")
                """.trimIndent()
            )
        )

        val qemuKernel = SystemUtils.getSystemProperty("ro.kernel.qemu") == "1"
        items.add(
            SecurityCheckItem(
                id = "qemu_kernel_prop",
                name = "ro.kernel.qemu Property Set",
                description = "Checks if ro.kernel.qemu property equals 1",
                isDetected = qemuKernel,
                functionName = "SystemUtils.getSystemProperty(\"ro.kernel.qemu\")",
                methodsAndApis = listOf("SystemProperties.get(\"ro.kernel.qemu\")"),
                technicalExplanation = "Reads system property ro.kernel.qemu. Value '1' signifies process is running inside QEMU hardware emulation mode.",
                exampleCode = """
SystemUtils.getSystemProperty("ro.kernel.qemu") == "1"
                """.trimIndent()
            )
        )

        val qemuFiles = listOf("/dev/qemu_pipe", "/dev/socket/qemud", "/sys/qemu_trace", "/system/lib/libc_malloc_debug_qemu.so")
        items.add(
            SecurityCheckItem(
                id = "qemu_drivers",
                name = "QEMU Drivers & Pipes",
                description = "Checks for /dev/qemu_pipe or qemud socket",
                isDetected = qemuFiles.any { File(it).exists() },
                functionName = "SystemEnvironmentChecker.getEmulatorChecks()",
                methodsAndApis = listOf("File(\"/dev/qemu_pipe\").exists()", "File(\"/dev/socket/qemud\").exists()"),
                technicalExplanation = "Checks for QEMU virtual driver pipes (/dev/qemu_pipe) and sockets (/dev/socket/qemud) used by Android emulators.",
                exampleCode = """
val qemuFiles = listOf("/dev/qemu_pipe", "/dev/socket/qemud", "/sys/qemu_trace")
qemuFiles.any { File(it).exists() }
                """.trimIndent()
            )
        )

        val mockTelephony = checkMockTelephony(context)
        items.add(
            SecurityCheckItem(
                id = "mock_telephony",
                name = "Mock Telephony / Carrier Values",
                description = "Checks TelephonyManager for mock carrier or emulator IDs",
                isDetected = mockTelephony,
                functionName = "SystemEnvironmentChecker.checkMockTelephony()",
                methodsAndApis = listOf("TelephonyManager.networkOperatorName"),
                technicalExplanation = "Queries TelephonyManager for network operator name to detect mock carrier values (e.g. Android or T-Mobile on goldfish hardware).",
                exampleCode = """
val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as TelephonyManager
val operator = tm.networkOperatorName.lowercase()
operator.contains("android") || (operator.contains("t-mobile") && Build.HARDWARE.lowercase().contains("goldfish"))
                """.trimIndent()
            )
        )

        return SecurityCategory(
            categoryName = "Android Emulator & QEMU",
            iconEmoji = "🤖",
            items = items
        )
    }

    fun getBuildIntegrityChecks(): SecurityCategory {
        val items = mutableListOf<SecurityCheckItem>()

        items.add(
            SecurityCheckItem(
                id = "test_keys",
                name = "Test-Keys Release Build",
                description = "Checks if system build tags contain 'test-keys'",
                isDetected = Build.TAGS?.contains("test-keys") == true,
                functionName = "SystemEnvironmentChecker.getBuildIntegrityChecks()",
                methodsAndApis = listOf("Build.TAGS"),
                technicalExplanation = "Checks android.os.Build.TAGS for 'test-keys' indicating an unofficial or custom ROM signed with public development keys.",
                exampleCode = """
Build.TAGS?.contains("test-keys") == true
                """.trimIndent()
            )
        )

        val buildType = Build.TYPE ?: ""
        items.add(
            SecurityCheckItem(
                id = "eng_userdebug",
                name = "Eng / Userdebug Build Type",
                description = "Checks if ro.build.type is eng or userdebug",
                isDetected = buildType.contains("eng") || buildType.contains("userdebug"),
                functionName = "SystemEnvironmentChecker.getBuildIntegrityChecks()",
                methodsAndApis = listOf("Build.TYPE"),
                technicalExplanation = "Checks android.os.Build.TYPE for 'eng' or 'userdebug' development firmware builds.",
                exampleCode = """
Build.TYPE.contains("eng") || Build.TYPE.contains("userdebug")
                """.trimIndent()
            )
        )

        val verifiedState = SystemUtils.getSystemProperty("ro.boot.verifiedbootstate")
        val bootloaderUnlocked = verifiedState.equals("orange", ignoreCase = true) || verifiedState.equals("yellow", ignoreCase = true)
        items.add(
            SecurityCheckItem(
                id = "bootloader_unlocked",
                name = "Bootloader Unlocked",
                description = "Checks ro.boot.verifiedbootstate for orange or yellow",
                isDetected = bootloaderUnlocked,
                functionName = "SystemUtils.getSystemProperty(\"ro.boot.verifiedbootstate\")",
                methodsAndApis = listOf("SystemProperties.get(\"ro.boot.verifiedbootstate\")"),
                technicalExplanation = "Reads ro.boot.verifiedbootstate. Values 'orange' or 'yellow' signify an unlocked bootloader or custom kernel boot verified state.",
                exampleCode = """
val verifiedState = SystemUtils.getSystemProperty("ro.boot.verifiedbootstate")
verifiedState.equals("orange", ignoreCase = true) || verifiedState.equals("yellow", ignoreCase = true)
                """.trimIndent()
            )
        )

        val flashLocked = SystemUtils.getSystemProperty("ro.boot.flash.locked")
        items.add(
            SecurityCheckItem(
                id = "flash_unlocked",
                name = "ro.boot.flash.locked Set to 0",
                description = "Checks if bootloader flash locking state is disabled (0)",
                isDetected = flashLocked == "0",
                functionName = "SystemUtils.getSystemProperty(\"ro.boot.flash.locked\")",
                methodsAndApis = listOf("SystemProperties.get(\"ro.boot.flash.locked\")"),
                technicalExplanation = "Reads ro.boot.flash.locked. Value '0' indicates partition flash locking is disabled.",
                exampleCode = """
SystemUtils.getSystemProperty("ro.boot.flash.locked") == "0"
                """.trimIndent()
            )
        )

        val vbmeta = SystemUtils.getSystemProperty("ro.boot.vbmeta.digest")
        items.add(
            SecurityCheckItem(
                id = "vbmeta_cleared",
                name = "VBMeta Digest Missing",
                description = "Checks if ro.boot.vbmeta.digest property is empty",
                isDetected = vbmeta.isBlank(),
                functionName = "SystemUtils.getSystemProperty(\"ro.boot.vbmeta.digest\")",
                methodsAndApis = listOf("SystemProperties.get(\"ro.boot.vbmeta.digest\")"),
                technicalExplanation = "Checks ro.boot.vbmeta.digest. An empty value indicates Android Verified Boot (AVB) digest validation was disabled or cleared.",
                exampleCode = """
SystemUtils.getSystemProperty("ro.boot.vbmeta.digest").isBlank()
                """.trimIndent()
            )
        )

        return SecurityCategory(
            categoryName = "Build & Device Integrity",
            iconEmoji = "🛠️",
            items = items
        )
    }

    fun getEnvironmentMountChecks(): SecurityCategory {
        val items = mutableListOf<SecurityCheckItem>()

        val ldPreload = System.getenv("LD_PRELOAD")
        items.add(
            SecurityCheckItem(
                id = "ld_preload",
                name = "LD_PRELOAD Environment Variable",
                description = "Checks if LD_PRELOAD environment variable is set",
                isDetected = !ldPreload.isNullOrBlank(),
                functionName = "SystemEnvironmentChecker.getEnvironmentMountChecks()",
                methodsAndApis = listOf("System.getenv(\"LD_PRELOAD\")"),
                technicalExplanation = "Checks environment variable LD_PRELOAD. If set, custom shared libraries are forcibly injected into every newly spawned process.",
                exampleCode = """
!System.getenv("LD_PRELOAD").isNullOrBlank()
                """.trimIndent()
            )
        )

        items.add(
            SecurityCheckItem(
                id = "system_rw",
                name = "System Partition Mounted R/W",
                description = "Checks if /system is mounted as read-write",
                isDetected = SystemUtils.checkMountsForKeywords(listOf("/system rw", "/system/ rw")),
                functionName = "SystemUtils.checkMountsForKeywords()",
                methodsAndApis = listOf("File(\"/proc/mounts\")", "Substring search for /system rw"),
                technicalExplanation = "Inspects /proc/mounts to detect if /system partition is remounted as read-write (rw) instead of read-only (ro).",
                exampleCode = """
File("/proc/mounts").useLines { lines ->
    lines.any { line -> line.contains("/system rw") || line.contains("/system/ rw") }
}
                """.trimIndent()
            )
        )

        items.add(
            SecurityCheckItem(
                id = "timing_anomaly",
                name = "Execution Timing Anomaly",
                description = "Detects artificial delays caused by active hooks or debuggers",
                isDetected = checkTimingAnomaly(),
                functionName = "SystemEnvironmentChecker.checkTimingAnomaly()",
                methodsAndApis = listOf("System.nanoTime()", "100,000 Iteration Loop Benchmark"),
                technicalExplanation = "Measures execution time for 100,000 tight iterations. If execution takes over 250ms, a heavy dynamic analysis tool, debugger breakpoint, or hook engine is causing significant latency.",
                exampleCode = """
val start = System.nanoTime()
var count = 0
for (i in 0 until 100_000) { count += i }
val elapsedMs = (System.nanoTime() - start) / 1_000_000
elapsedMs > 250
                """.trimIndent()
            )
        )

        return SecurityCategory(
            categoryName = "Environment & System Mounts",
            iconEmoji = "🌐",
            items = items
        )
    }

    private fun checkVpnActive(context: Context): Boolean {
        return try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            val activeNet = cm?.activeNetwork
            val caps = cm?.getNetworkCapabilities(activeNet)
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
        } catch (_: Exception) {
            false
        }
    }

    private fun checkSystemPropertiesInjected(): Boolean {
        return try {
            val props = System.getProperties()
            val keywords = listOf("frida", "gum", "linjector", "talsec", "rasp")
            props.keys().hasMoreElements() && props.stringPropertyNames().any { key ->
                val lower = key.lowercase()
                keywords.any { kw -> lower.contains(kw) }
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun isClassPresent(className: String): Boolean {
        return try {
            Class.forName(className)
            true
        } catch (_: Exception) {
            false
        }
    }

    private fun checkMockTelephony(context: Context): Boolean {
        return try {
            val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
            val operator = tm?.networkOperatorName?.lowercase() ?: ""
            operator.contains("android") || operator.contains("t-mobile") && (Build.HARDWARE.lowercase().contains("goldfish") || Build.HARDWARE.lowercase().contains("ranchu"))
        } catch (_: Exception) {
            false
        }
    }

    private fun checkTimingAnomaly(): Boolean {
        return try {
            val start = System.nanoTime()
            var count = 0
            for (i in 0 until 100_000) {
                count += i
            }
            val elapsedMs = (System.nanoTime() - start) / 1_000_000
            elapsedMs > 250
        } catch (_: Exception) {
            false
        }
    }
}
