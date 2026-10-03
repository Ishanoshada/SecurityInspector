package com.ishanoshada.securityinspector.checks

import android.content.Context
import com.ishanoshada.securityinspector.models.SecurityCategory
import com.ishanoshada.securityinspector.models.SecurityCheckItem
import com.ishanoshada.securityinspector.utils.SystemUtils
import java.io.File

object RootChecker {

    fun getDeepRootChecks(): SecurityCategory {
        val items = mutableListOf<SecurityCheckItem>()

        val suPaths = listOf(
            "/data/local/bin/su",
            "/data/local/su",
            "/data/local/xbin/su",
            "/dev/com.koushikdutta.superuser.daemon/",
            "/sbin/su",
            "/system/app/Superuser.apk",
            "/system/bin/failsafe/su",
            "/system/bin/su",
            "/su/bin/su",
            "/system/etc/init.d/99SuperSUDaemon",
            "/system/sd/xbin/su",
            "/system/xbin/busybox",
            "/system/xbin/daemonsu",
            "/system/xbin/su",
            "/system/sbin/su",
            "/vendor/bin/su",
            "/cache/su",
            "/data/su",
            "/dev/su",
            "/system/bin/.ext/su",
            "/system/usr/we-need-root/su"
        )
        items.add(
            SecurityCheckItem(
                id = "su_binary",
                name = "SU / Superuser Binaries",
                description = "Checks 20+ standard paths for su binary executables",
                isDetected = suPaths.any { File(it).exists() },
                functionName = "RootChecker.getDeepRootChecks()",
                methodsAndApis = listOf("File(suPath).exists()", "20+ system binary paths"),
                technicalExplanation = "Iterates through 20+ standard system binary locations (/system/bin/su, /system/xbin/su, /su/bin/su, /vendor/bin/su, etc.) to detect su binary execution files.",
                exampleCode = """
val suPaths = listOf("/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su", "/vendor/bin/su")
suPaths.any { File(it).exists() }
                """.trimIndent()
            )
        )

        val magiskPaths = listOf(
            "/data/adb/magisk",
            "/sbin/.magisk",
            "/cache/.disable_magisk",
            "/dev/.magisk.unblock",
            "/cache/magisk.log",
            "/data/adb/magisk.img",
            "/data/adb/magisk.db",
            "/init.magisk.rc",
            "/data/adb/ksu",
            "/data/adb/ksud"
        )
        items.add(
            SecurityCheckItem(
                id = "magisk_ksu_files",
                name = "Magisk / KernelSU System Files",
                description = "Checks for Magisk & KernelSU core system paths",
                isDetected = magiskPaths.any { File(it).exists() },
                functionName = "RootChecker.getDeepRootChecks()",
                methodsAndApis = listOf("File(\"/data/adb/magisk\").exists()", "File(\"/sbin/.magisk\").exists()", "File(\"/data/adb/ksu\").exists()"),
                technicalExplanation = "Checks for filesystem databases, daemons, and configuration paths created by Magisk systemless root and KernelSU kernel-level root.",
                exampleCode = """
val magiskPaths = listOf("/data/adb/magisk", "/sbin/.magisk", "/data/adb/magisk.db", "/data/adb/ksu")
magiskPaths.any { File(it).exists() }
                """.trimIndent()
            )
        )

        items.add(
            SecurityCheckItem(
                id = "magisk_mounts",
                name = "Magisk / Mirror Mounts",
                description = "Checks /proc/self/mountinfo for Magisk mountpoints",
                isDetected = SystemUtils.checkMountsForKeywords(listOf("magisk", "core/mirror")),
                functionName = "SystemUtils.checkMountsForKeywords()",
                methodsAndApis = listOf("File(\"/proc/self/mountinfo\")", "File(\"/proc/mounts\")", "Substring search for magisk, core/mirror"),
                technicalExplanation = "Reads mount entries in /proc/self/mountinfo. Magisk creates systemless loopback overlays and mirror mount points under /proc/mounts to hide root.",
                exampleCode = """
File("/proc/self/mountinfo").useLines { lines ->
    lines.any { line -> line.lowercase().contains("magisk") || line.lowercase().contains("core/mirror") }
}
                """.trimIndent()
            )
        )

        items.add(
            SecurityCheckItem(
                id = "busybox",
                name = "BusyBox Binary",
                description = "Checks for busybox installation in system paths",
                isDetected = listOf("/system/bin/busybox", "/system/xbin/busybox", "/sbin/busybox").any { File(it).exists() },
                functionName = "RootChecker.getDeepRootChecks()",
                methodsAndApis = listOf("File(\"/system/bin/busybox\").exists()", "File(\"/system/xbin/busybox\").exists()"),
                technicalExplanation = "Checks for the BusyBox multi-call shell utility suite often installed on rooted devices to provide elevated CLI tools.",
                exampleCode = """
listOf("/system/bin/busybox", "/system/xbin/busybox", "/sbin/busybox").any { File(it).exists() }
                """.trimIndent()
            )
        )

        items.add(
            SecurityCheckItem(
                id = "selinux_permissive",
                name = "SELinux Permissive Mode",
                description = "Checks if SELinux security enforcement is disabled",
                isDetected = isSelinuxPermissive(),
                functionName = "RootChecker.isSelinuxPermissive()",
                methodsAndApis = listOf("Runtime.getRuntime().exec(\"getenforce\")", "BufferedReader.use"),
                technicalExplanation = "Executes native getenforce command. If SELinux enforcement mode is set to Permissive, mandatory access control security checks are turned off.",
                exampleCode = """
val process = Runtime.getRuntime().exec("getenforce")
val output = process.inputStream.bufferedReader().use { it.readText() }.trim()
output.equals("Permissive", ignoreCase = true)
                """.trimIndent()
            )
        )

        return SecurityCategory(
            categoryName = "Deep Root & Superuser",
            iconEmoji = "🔓",
            items = items
        )
    }

    fun getRootPackagesChecks(context: Context): SecurityCategory {
        val items = mutableListOf<SecurityCheckItem>()

        val rootPackages = listOf(
            "com.noshufou.android.su",
            "com.noshufou.android.su.elite",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.yellowes.su",
            "com.koushikdutta.rommanager",
            "com.dimonvideo.luckypatcher",
            "com.chelpus.lackypatch",
            "com.ramdroid.appquarantine",
            "com.devadvance.rootcloak",
            "com.amphoras.hidemyroot",
            "com.formyhm.hideroot",
            "me.phh.superuser",
            "com.kingouser.com",
            "com.topjohnwu.magisk",
            "me.weishu.kernelsu",
            "de.robv.android.xposed.installer",
            "com.saurik.substrate"
        )

        var detectedPackageCount = 0
        rootPackages.forEach { pkg ->
            if (isPackageInstalled(context, pkg)) {
                detectedPackageCount++
            }
        }

        items.add(
            SecurityCheckItem(
                id = "root_packages",
                name = "Root / Hiding Package Installed",
                description = "Scans PackageManager for Magisk, SuperSU, LuckyPatcher, Xposed",
                isDetected = detectedPackageCount > 0,
                functionName = "RootChecker.isPackageInstalled()",
                methodsAndApis = listOf("context.packageManager.getPackageInfo(packageName, 0)"),
                technicalExplanation = "Queries Android PackageManager for 19+ superuser manager apps (Magisk, SuperSU, KernelSU, KingoRoot) and modification apps (LuckyPatcher, RootCloak, Xposed).",
                exampleCode = """
val rootPackages = listOf("com.topjohnwu.magisk", "eu.chainfire.supersu", "me.weishu.kernelsu", "com.dimonvideo.luckypatcher")
rootPackages.any { pkg ->
    try { context.packageManager.getPackageInfo(pkg, 0); true } catch (e: Exception) { false }
}
                """.trimIndent()
            )
        )

        val hmaProviders = listOf("com.tsng.hidemyapplist", "org.frknkrc44.hma_oss")
        var hmaDetected = false
        hmaProviders.forEach { authority ->
            try {
                val info = context.packageManager.resolveContentProvider(authority, 0)
                if (info != null) hmaDetected = true
            } catch (_: Exception) {}
        }

        items.add(
            SecurityCheckItem(
                id = "hma_providers",
                name = "Hide My Applist (HMA) Providers",
                description = "Checks PackageManager for Hide My Applist ContentProviders",
                isDetected = hmaDetected,
                functionName = "RootChecker.getRootPackagesChecks()",
                methodsAndApis = listOf("context.packageManager.resolveContentProvider(\"com.tsng.hidemyapplist\", 0)"),
                technicalExplanation = "Queries PackageManager for registered ContentProvider authorities used by Hide My Applist modules (com.tsng.hidemyapplist, org.frknkrc44.hma_oss).",
                exampleCode = """
val hmaProviders = listOf("com.tsng.hidemyapplist", "org.frknkrc44.hma_oss")
hmaProviders.any { authority -> context.packageManager.resolveContentProvider(authority, 0) != null }
                """.trimIndent()
            )
        )

        return SecurityCategory(
            categoryName = "Root & Hiding Packages",
            iconEmoji = "📦",
            items = items
        )
    }

    private fun isSelinuxPermissive(): Boolean {
        return try {
            val process = Runtime.getRuntime().exec("getenforce")
            val output = process.inputStream.bufferedReader().use { it.readText() }.trim()
            output.equals("Permissive", ignoreCase = true)
        } catch (_: Exception) {
            false
        }
    }

    private fun isPackageInstalled(context: Context, packageName: String): Boolean {
        return try {
            context.packageManager.getPackageInfo(packageName, 0)
            true
        } catch (_: Exception) {
            false
        }
    }
}
