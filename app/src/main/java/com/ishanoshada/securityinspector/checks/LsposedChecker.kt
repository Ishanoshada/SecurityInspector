package com.ishanoshada.securityinspector.checks

import com.ishanoshada.securityinspector.models.SecurityCategory
import com.ishanoshada.securityinspector.models.SecurityCheckItem
import java.io.File

object LsposedChecker {

    fun getLsposedChecks(): SecurityCategory {
        val items = mutableListOf<SecurityCheckItem>()

        items.add(
            SecurityCheckItem(
                id = "lspd_dir",
                name = "LSPosed Data Directory",
                description = "Checks for direct accessibility of /data/adb/lspd",
                isDetected = File("/data/adb/lspd").exists(),
                functionName = "LsposedChecker.getLsposedChecks()",
                methodsAndApis = listOf("File(\"/data/adb/lspd\").exists()"),
                technicalExplanation = "Checks for presence of internal storage directory /data/adb/lspd/ created by LSPosed framework daemon.",
                exampleCode = """
File("/data/adb/lspd").exists()
                """.trimIndent()
            )
        )

        items.add(
            SecurityCheckItem(
                id = "module_lsposed",
                name = "LSPosed Module Path",
                description = "Checks for /data/adb/modules/lsposed/",
                isDetected = File("/data/adb/modules/lsposed").exists(),
                functionName = "LsposedChecker.getLsposedChecks()",
                methodsAndApis = listOf("File(\"/data/adb/modules/lsposed\").exists()"),
                technicalExplanation = "Checks for LSPosed Zygisk module directory installed under Magisk/KernelSU modules directory.",
                exampleCode = """
File("/data/adb/modules/lsposed").exists()
                """.trimIndent()
            )
        )

        items.add(
            SecurityCheckItem(
                id = "module_shamiko",
                name = "Shamiko Hiding Module",
                description = "Checks for /data/adb/modules/shamiko/",
                isDetected = File("/data/adb/modules/shamiko").exists(),
                functionName = "LsposedChecker.getLsposedChecks()",
                methodsAndApis = listOf("File(\"/data/adb/modules/shamiko\").exists()"),
                technicalExplanation = "Checks for Shamiko Zygisk module directory used to hide root and module traces from detection apps.",
                exampleCode = """
File("/data/adb/modules/shamiko").exists()
                """.trimIndent()
            )
        )

        items.add(
            SecurityCheckItem(
                id = "module_hma",
                name = "Hide My Applist (HMA)",
                description = "Checks for /data/adb/modules/hidemyapplist/",
                isDetected = File("/data/adb/modules/hidemyapplist").exists(),
                functionName = "LsposedChecker.getLsposedChecks()",
                methodsAndApis = listOf("File(\"/data/adb/modules/hidemyapplist\").exists()"),
                technicalExplanation = "Checks for Hide My Applist Zygisk module installation directory under /data/adb/modules/hidemyapplist/.",
                exampleCode = """
File("/data/adb/modules/hidemyapplist").exists()
                """.trimIndent()
            )
        )

        items.add(
            SecurityCheckItem(
                id = "module_zgnxt",
                name = "Zygisk Next Module",
                description = "Checks for /data/adb/modules/zygisknext/",
                isDetected = File("/data/adb/modules/zygisknext").exists(),
                functionName = "LsposedChecker.getLsposedChecks()",
                methodsAndApis = listOf("File(\"/data/adb/modules/zygisknext\").exists()"),
                technicalExplanation = "Checks for standalone Zygisk Next module implementation directory.",
                exampleCode = """
File("/data/adb/modules/zygisknext").exists()
                """.trimIndent()
            )
        )

        return SecurityCategory(
            categoryName = "LSPosed & Xposed Framework",
            iconEmoji = "💉",
            items = items
        )
    }
}
