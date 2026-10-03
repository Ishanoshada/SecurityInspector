package com.ishanoshada.securityinspector.checks

import com.ishanoshada.securityinspector.models.SecurityCategory
import com.ishanoshada.securityinspector.models.SecurityCheckItem
import java.io.File

object HookIntegrityChecker {

    fun getHookIntegrityChecks(): SecurityCategory {
        val items = mutableListOf<SecurityCheckItem>()

        val anonRwx = scanMaps { line ->
            val perms = line.split("\\s+".toRegex()).getOrNull(1) ?: ""
            val name = line.substringAfterLast(" ", "")
            perms.contains("rwx") && name.isBlank()
        }
        items.add(
            SecurityCheckItem(
                id = "anon_rwx_no_name",
                name = "Anonymous RWX Memory Region",
                description = "Finds executable writable pages with no file backing",
                isDetected = anonRwx,
                functionName = "HookIntegrityChecker.scanMaps()",
                methodsAndApis = listOf("/proc/self/maps", "perms field (rwxp)", "anonymous mapping"),
                technicalExplanation = "Anonymous RWX pages are used by JIT engines and by inline hook trampolines. In release builds with no JIT, their presence strongly suggests a native hook engine (Dobby, ShadowHook, Frida Stalker) allocated executable memory.",
                exampleCode = """
File("/proc/self/maps").useLines { lines ->
    lines.any { line ->
        val parts = line.split("\\s+".toRegex())
        val perms = parts.getOrNull(1) ?: ""
        perms.contains("rwx") && parts.lastOrNull().isNullOrBlank()
    }
}
                """.trimIndent()
            )
        )

        val memfdExec = scanMaps { line ->
            val lower = line.lowercase()
            (lower.contains("memfd:") || lower.contains("(deleted)")) &&
                    line.split("\\s+".toRegex()).getOrNull(1)?.contains("x") == true
        }
        items.add(
            SecurityCheckItem(
                id = "memfd_exec",
                name = "Executable Memfd or Deleted File Mapping",
                description = "Finds executable mappings backed by memfd or deleted files",
                isDetected = memfdExec,
                functionName = "HookIntegrityChecker.scanMaps()",
                methodsAndApis = listOf("/proc/self/maps", "memfd:", "(deleted)"),
                technicalExplanation = "Frida and many injectors load shared objects from memfd or from files that were unlinked after mapping. Executable mappings backed by memfd or (deleted) files are a strong injection indicator.",
                exampleCode = """
File("/proc/self/maps").useLines { lines ->
    lines.any { line ->
        val lower = line.lowercase()
        (lower.contains("memfd:") || lower.contains("(deleted)")) &&
            line.split("\\s+".toRegex()).getOrNull(1)?.contains("x") == true
    }
}
                """.trimIndent()
            )
        )

        val badPaths = listOf(
            "/data/local/tmp/", "/dev/", "/proc/self/fd/",
            "/data/data/", "/sdcard/", "/storage/"
        )
        val loaderFromBadPath = scanMaps { line ->
            val path = line.substringAfterLast(" ", "")
            path.endsWith(".so") && badPaths.any { path.contains(it) }
        }
        items.add(
            SecurityCheckItem(
                id = "so_from_bad_path",
                name = "SO Loaded from Suspicious Path",
                description = "Detects .so libraries loaded from /data/local/tmp, /sdcard, /dev",
                isDetected = loaderFromBadPath,
                functionName = "HookIntegrityChecker.scanMaps()",
                methodsAndApis = listOf("/proc/self/maps", ".so path filtering"),
                technicalExplanation = "Legitimate app libraries load from /data/app/<pkg>/lib/ or /system/lib/. A .so mapped from /data/local/tmp, /sdcard, or /dev indicates a manually injected native payload.",
                exampleCode = """
val bad = listOf("/data/local/tmp/", "/sdcard/", "/dev/")
File("/proc/self/maps").useLines { lines ->
    lines.any { line ->
        val path = line.substringAfterLast(" ", "")
        path.endsWith(".so") && bad.any { path.contains(it) }
    }
}
                """.trimIndent()
            )
        )

        return SecurityCategory(
            categoryName = "Memory & Hook Integrity",
            iconEmoji = "🧬",
            items = items
        )
    }

    private fun scanMaps(predicate: (String) -> Boolean): Boolean = try {
        val f = File("/proc/self/maps")
        if (!f.exists()) false
        else f.useLines { lines -> lines.any(predicate) }
    } catch (_: Exception) { false }
}
