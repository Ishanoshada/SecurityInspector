package com.ishanoshada.securityinspector.checks

import android.content.Context
import android.os.Process
import com.ishanoshada.securityinspector.models.SecurityCategory
import com.ishanoshada.securityinspector.models.SecurityCheckItem

object VirtualAppChecker {

    private val virtualPackages = listOf(
        "com.lbe.parallel.intl",
        "com.lbe.parallel",
        "com.excelliance.dualaid",
        "com.excelliance.multiaccounts",
        "com.parallel.space.lite",
        "com.polestar.multiaccount",
        "com.polestar.domultiple",
        "com.dual.space.multi.parallel.app",
        "io.va.exposed",
        "io.va.exposed64",
        "com.virtual.space",
        "com.clone.android.dual.space"
    )

    fun getVirtualAppChecks(context: Context): SecurityCategory {
        val items = mutableListOf<SecurityCheckItem>()

        val detected = virtualPackages.filter { isInstalled(context, it) }
        items.add(
            SecurityCheckItem(
                id = "virtual_app_packages",
                name = "Virtual App / App Cloner Installed",
                description = "Scans PackageManager for Parallel Space, Dual Apps, VirtualXposed",
                isDetected = detected.isNotEmpty(),
                functionName = "VirtualAppChecker.getVirtualAppChecks()",
                methodsAndApis = listOf("PackageManager.getPackageInfo(pkg, 0)"),
                technicalExplanation = "Virtual app engines (Parallel Space, Dual Apps, VirtualXposed) run a cloned copy of the target app in a container, bypassing signature checks and enabling hooking.",
                exampleCode = """
val virtuals = listOf("com.lbe.parallel.intl", "io.va.exposed", "com.polestar.multiaccount")
virtuals.any { pkg ->
    try { context.packageManager.getPackageInfo(pkg, 0); true } catch (e: Exception) { false }
}
                """.trimIndent()
            )
        )

        val uid = Process.myUid()
        val expectedUid = try {
            context.packageManager.getApplicationInfo(context.packageName, 0).uid
        } catch (_: Exception) { uid }
        items.add(
            SecurityCheckItem(
                id = "uid_mismatch",
                name = "Process UID Mismatch",
                description = "Compares Process.myUid() to the package's declared UID",
                isDetected = uid != expectedUid,
                functionName = "VirtualAppChecker.getVirtualAppChecks()",
                methodsAndApis = listOf("android.os.Process.myUid()", "ApplicationInfo.uid"),
                technicalExplanation = "In a virtual app container, the cloned process may run with a different UID than the original package. A mismatch indicates the app was launched inside a container.",
                exampleCode = """
val uid = Process.myUid()
val expected = context.packageManager
    .getApplicationInfo(context.packageName, 0).uid
uid != expected
                """.trimIndent()
            )
        )

        val dataDir = context.applicationInfo.dataDir
        val underVirtualPath = dataDir.contains("/virtual/") ||
                dataDir.contains("/parallel/") ||
                dataDir.contains("/clone/")
        items.add(
            SecurityCheckItem(
                id = "virtual_data_dir",
                name = "Virtual Container Data Path",
                description = "Checks if dataDir is inside a virtual container sandbox path",
                isDetected = underVirtualPath,
                functionName = "VirtualAppChecker.getVirtualAppChecks()",
                methodsAndApis = listOf("ApplicationInfo.dataDir"),
                technicalExplanation = "Virtual app engines redirect the app data directory to a container path such as /data/user/0/<virtual>/virtual/... instead of the normal /data/data/<pkg>/.",
                exampleCode = """
val dataDir = context.applicationInfo.dataDir
dataDir.contains("/virtual/") || dataDir.contains("/parallel/") || dataDir.contains("/clone/")
                """.trimIndent()
            )
        )

        return SecurityCategory(
            categoryName = "Virtual App & Cloning",
            iconEmoji = "📦",
            items = items
        )
    }

    private fun isInstalled(context: Context, pkg: String): Boolean = try {
        context.packageManager.getPackageInfo(pkg, 0)
        true
    } catch (_: Exception) { false }
}
