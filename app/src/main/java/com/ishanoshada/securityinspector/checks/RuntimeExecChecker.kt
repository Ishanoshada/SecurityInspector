package com.ishanoshada.securityinspector.checks

import com.ishanoshada.securityinspector.models.SecurityCategory
import com.ishanoshada.securityinspector.models.SecurityCheckItem
import java.io.BufferedReader

object RuntimeExecChecker {

    fun getRuntimeExecChecks(): SecurityCategory {
        val items = mutableListOf<SecurityCheckItem>()

        val suPath = execAndRead("which su")
        items.add(
            SecurityCheckItem(
                id = "runtime_which_su",
                name = "Runtime 'which su' Resolves",
                description = "Executes 'which su' to find su in PATH",
                isDetected = !suPath.isNullOrBlank(),
                functionName = "RuntimeExecChecker.execAndRead()",
                methodsAndApis = listOf("Runtime.getRuntime().exec(\"which su\")", "PATH resolution"),
                technicalExplanation = "File checks can be fooled by inaccessible paths, but executing 'which su' uses the kernel's PATH resolution. A non-empty result proves a su binary is reachable from the app's environment.",
                exampleCode = """
val process = Runtime.getRuntime().exec(arrayOf("which", "su"))
val out = process.inputStream.bufferedReader().use { it.readText() }.trim()
out.isNotEmpty()
                """.trimIndent()
            )
        )

        val suResult = execAndRead("su -c id")
        val gotRoot = suResult?.contains("uid=0", ignoreCase = true) == true
        items.add(
            SecurityCheckItem(
                id = "runtime_su_id",
                name = "Runtime 'su -c id' Grants Root",
                description = "Attempts 'su -c id' and checks for uid=0",
                isDetected = gotRoot,
                functionName = "RuntimeExecChecker.execAndRead()",
                methodsAndApis = listOf("Runtime.exec(\"su\", \"-c\", \"id\")"),
                technicalExplanation = "Directly attempts to spawn a root shell and run 'id'. If the output contains uid=0(root), the device is rooted and the app can escalate privileges. This is stronger than file checks because it proves the root daemon is functional.",
                exampleCode = """
try {
    val p = Runtime.getRuntime().exec(arrayOf("su", "-c", "id"))
    val out = p.inputStream.bufferedReader().use { it.readText() }
    out.contains("uid=0")
} catch (e: Exception) { false }
                """.trimIndent()
            )
        )

        val enforce = execAndRead("getenforce")
        items.add(
            SecurityCheckItem(
                id = "runtime_getenforce",
                name = "Runtime 'getenforce' Executes",
                description = "Executes native getenforce to read SELinux mode",
                isDetected = enforce.equals("Permissive", ignoreCase = true),
                functionName = "RuntimeExecChecker.execAndRead()",
                methodsAndApis = listOf("Runtime.exec(\"getenforce\")"),
                technicalExplanation = "Runs the native getenforce binary instead of reading a hidden property. Permissive mode disables Mandatory Access Control enforcement.",
                exampleCode = """
Runtime.getRuntime().exec("getenforce")
    .inputStream.bufferedReader().use { it.readText() }
    .trim().equals("Permissive", ignoreCase = true)
                """.trimIndent()
            )
        )

        val fridaWhich = execAndRead("which frida frida-server frida-ps")
        items.add(
            SecurityCheckItem(
                id = "runtime_which_frida",
                name = "Runtime 'which frida*' Resolves",
                description = "Executes 'which frida frida-server frida-ps' to find Frida tools in PATH",
                isDetected = !fridaWhich.isNullOrBlank(),
                functionName = "RuntimeExecChecker.execAndRead()",
                methodsAndApis = listOf("Runtime.exec(\"which\", \"frida\", \"frida-server\", \"frida-ps\")"),
                technicalExplanation = "Resolves the Frida CLI tools using the kernel PATH search. Unlike map/port checks, this catches Frida installations on the device filesystem even if the agent isn't currently attached.",
                exampleCode = """
try {
    val p = Runtime.getRuntime().exec(arrayOf("which", "frida", "frida-server", "frida-ps"))
    p.inputStream.bufferedReader().use { it.readText() }.trim().isNotEmpty()
} catch (e: Exception) { false }
                """.trimIndent()
            )
        )

        return SecurityCategory(
            categoryName = "Runtime Execution Probes",
            iconEmoji = "⚙️",
            items = items
        )
    }

    private fun execAndRead(cmd: String): String? = try {
        val process = Runtime.getRuntime().exec(arrayOf("sh", "-c", cmd))
        val out = BufferedReader(process.inputStream.reader()).use { it.readText() }.trim()
        out.ifBlank { null }
    } catch (_: Exception) { null }
}
