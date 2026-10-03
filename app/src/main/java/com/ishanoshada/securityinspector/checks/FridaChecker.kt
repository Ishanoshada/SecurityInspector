package com.ishanoshada.securityinspector.checks

import com.ishanoshada.securityinspector.models.SecurityCategory
import com.ishanoshada.securityinspector.models.SecurityCheckItem
import com.ishanoshada.securityinspector.utils.SystemUtils
import java.io.File

object FridaChecker {

    fun getFridaChecks(): SecurityCategory {
        val items = mutableListOf<SecurityCheckItem>()

        items.add(
            SecurityCheckItem(
                id = "tracer_pid",
                name = "TracerPid Non-Zero",
                description = "Checks /proc/self/status for ptrace debugger",
                isDetected = checkTracerPid(),
                functionName = "FridaChecker.checkTracerPid()",
                methodsAndApis = listOf("File(\"/proc/self/status\")", "BufferedReader.useLines()", "String.startsWith(\"TracerPid:\")"),
                technicalExplanation = "Reads process status in /proc/self/status to extract the TracerPid field. When ptrace, a debugger, or Frida attaches to the process, the Linux kernel sets TracerPid to the tracing process PID.",
                exampleCode = """
val statusFile = File("/proc/self/status")
statusFile.useLines { lines ->
    lines.forEach { line ->
        if (line.startsWith("TracerPid:")) {
            val pid = line.substringAfter(":").trim().toIntOrNull() ?: 0
            return pid != 0
        }
    }
}
false
                """.trimIndent()
            )
        )

        items.add(
            SecurityCheckItem(
                id = "frida_maps",
                name = "Frida Agent Memory Map",
                description = "Checks /proc/self/maps for frida-agent or gadget",
                isDetected = SystemUtils.checkMapsForKeywords(listOf("frida", "gadget", "linjector", "gum-js")),
                functionName = "SystemUtils.checkMapsForKeywords()",
                methodsAndApis = listOf("File(\"/proc/self/maps\")", "useLines()", "String.lowercase().contains()"),
                technicalExplanation = "Inspects memory maps in /proc/self/maps for dynamically injected shared libraries containing frida-agent.so, gadget.so, linjector, or gum-js.",
                exampleCode = """
val mapsFile = File("/proc/self/maps")
mapsFile.useLines { lines ->
    lines.any { line ->
        val lower = line.lowercase()
        listOf("frida", "gadget", "linjector", "gum-js").any { lower.contains(it) }
    }
}
                """.trimIndent()
            )
        )

        items.add(
            SecurityCheckItem(
                id = "frida_memfd",
                name = "Frida Memfd File Descriptor",
                description = "Checks /proc/self/fd for frida memfd handles",
                isDetected = checkFridaMemfd(),
                functionName = "FridaChecker.checkFridaMemfd()",
                methodsAndApis = listOf("File(\"/proc/self/fd\")", "File.canonicalPath"),
                technicalExplanation = "Scans open file descriptor handles in /proc/self/fd/. Frida server creates anonymous in-memory file descriptors named memfd:frida or containing frida in target path.",
                exampleCode = """
val fdDir = File("/proc/self/fd")
val files = fdDir.listFiles() ?: arrayOf()
files.any { file ->
    val target = file.canonicalPath
    target.contains("frida") || target.contains("memfd:frida")
}
                """.trimIndent()
            )
        )

        items.add(
            SecurityCheckItem(
                id = "frida_threads",
                name = "Frida Worker Threads",
                description = "Checks /proc/self/task for frida, gmain, or gum threads",
                isDetected = checkFridaThreads(),
                functionName = "FridaChecker.checkFridaThreads()",
                methodsAndApis = listOf("File(\"/proc/self/task\")", "File(threadDir, \"comm\").readText()"),
                technicalExplanation = "Iterates through all task thread entries in /proc/self/task/ and reads comm thread names. Frida spawns worker threads named frida, gmain, gdbus, pool-frida, or gum.",
                exampleCode = """
val taskDir = File("/proc/self/task")
val threads = taskDir.listFiles() ?: arrayOf()
val fridaKeywords = listOf("frida", "gmain", "gdbus", "pool-frida", "gum")
threads.any { threadDir ->
    val commFile = File(threadDir, "comm")
    if (commFile.exists()) {
        val name = commFile.readText().trim().lowercase()
        fridaKeywords.any { name.contains(it) }
    } else false
}
                """.trimIndent()
            )
        )

        val fridaPortsHex = listOf("69A2", "69A3", "69A4", "69A5", "69A6", "69A7", "69A8", "69A9", "69AA")
        items.add(
            SecurityCheckItem(
                id = "frida_ports",
                name = "Frida Listening Ports (27042-27050)",
                description = "Scans local ports 27042 to 27050 in /proc/net/tcp",
                isDetected = SystemUtils.checkProcNetTcp(fridaPortsHex),
                functionName = "SystemUtils.checkProcNetTcp()",
                methodsAndApis = listOf("File(\"/proc/net/tcp\")", "File(\"/proc/net/tcp6\")", "Hex Port Matching (69A2-69AA)"),
                technicalExplanation = "Reads active local TCP socket listener entries in /proc/net/tcp and /proc/net/tcp6 for ports 27042 through 27050 (represented in HEX format).",
                exampleCode = """
val hexPorts = listOf("69A2", "69A3", "69A4", "69A5", "69A6", "69A7", "69A8", "69A9", "69AA")
File("/proc/net/tcp").useLines { lines ->
    lines.any { line ->
        val localAddr = line.trim().split("\\s+".toRegex()).getOrNull(1) ?: ""
        val portPart = localAddr.substringAfter(":", "")
        hexPorts.any { portPart.equals(it, ignoreCase = true) }
    }
}
                """.trimIndent()
            )
        )

        val fridaTmpFiles = listOf(
            "/data/local/tmp/frida-server",
            "/data/local/tmp/re.frida.server",
            "/data/local/tmp/frida",
            "/data/local/tmp/agent.so",
            "/data/local/tmp/hook.so",
            "/data/local/tmp/mytools",
            "/data/local/tmp/linjector"
        )
        items.add(
            SecurityCheckItem(
                id = "frida_tmp_files",
                name = "Frida Server Temp Files",
                description = "Checks /data/local/tmp/ for frida-server or agent binaries",
                isDetected = fridaTmpFiles.any { File(it).exists() },
                functionName = "FridaChecker.getFridaChecks()",
                methodsAndApis = listOf("File(\"/data/local/tmp/frida-server\").exists()", "File(\"/data/local/tmp/agent.so\").exists()"),
                technicalExplanation = "Checks world-writable temporary directory /data/local/tmp/ for frida-server executables or injected shared object agent payloads.",
                exampleCode = """
val fridaTmpFiles = listOf(
    "/data/local/tmp/frida-server",
    "/data/local/tmp/re.frida.server",
    "/data/local/tmp/frida",
    "/data/local/tmp/agent.so"
)
fridaTmpFiles.any { File(it).exists() }
                """.trimIndent()
            )
        )

        items.add(
            SecurityCheckItem(
                id = "hook_frameworks",
                name = "Inline Hook Frameworks",
                description = "Checks memory maps for Dobby, ShadowHook, or Whale",
                isDetected = SystemUtils.checkMapsForKeywords(listOf("dobby", "shadowhook", "libwhale")),
                functionName = "SystemUtils.checkMapsForKeywords()",
                methodsAndApis = listOf("File(\"/proc/self/maps\")", "Substring search for dobby, shadowhook, libwhale"),
                technicalExplanation = "Scans memory mappings for ARM inline hooking libraries such as Dobby, ShadowHook, or Whale commonly used for native function interception.",
                exampleCode = """
File("/proc/self/maps").useLines { lines ->
    lines.any { line ->
        val lower = line.lowercase()
        listOf("dobby", "shadowhook", "libwhale").any { lower.contains(it) }
    }
}
                """.trimIndent()
            )
        )

        items.add(
            SecurityCheckItem(
                id = "anon_rwx",
                name = "Executable RWX Memory",
                description = "Checks for anonymous readable/writable/executable memory",
                isDetected = checkAnonRwx(),
                functionName = "FridaChecker.checkAnonRwx()",
                methodsAndApis = listOf("File(\"/proc/self/maps\")", "String matching rwxp 00000000"),
                technicalExplanation = "Inspects /proc/self/maps for memory regions marked as rwxp (Readable, Writable, Executable). RWX memory violates security policies and is allocated by JIT hook trampolines.",
                exampleCode = """
File("/proc/self/maps").useLines { lines ->
    lines.any { line -> line.contains("rwxp") && line.contains("00000000 00:00 0") }
}
                """.trimIndent()
            )
        )

        return SecurityCategory(
            categoryName = "Frida & Dynamic Hooking",
            iconEmoji = "🪝",
            items = items
        )
    }

    private fun checkTracerPid(): Boolean {
        return try {
            val statusFile = File("/proc/self/status")
            if (!statusFile.exists()) return false
            statusFile.useLines { lines ->
                lines.forEach { line ->
                    if (line.startsWith("TracerPid:")) {
                        val pidStr = line.substringAfter(":").trim()
                        val pid = pidStr.toIntOrNull() ?: 0
                        return pid != 0
                    }
                }
            }
            false
        } catch (_: Exception) {
            false
        }
    }

    private fun checkFridaMemfd(): Boolean {
        return try {
            val fdDir = File("/proc/self/fd")
            if (!fdDir.exists() || !fdDir.isDirectory) return false
            val files = fdDir.listFiles() ?: return false
            files.any { file ->
                try {
                    val target = file.canonicalPath
                    target.contains("frida") || target.contains("memfd:frida")
                } catch (_: Exception) {
                    false
                }
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun checkFridaThreads(): Boolean {
        return try {
            val taskDir = File("/proc/self/task")
            if (!taskDir.exists() || !taskDir.isDirectory) return false
            val threads = taskDir.listFiles() ?: return false
            val fridaKeywords = listOf("frida", "gmain", "gdbus", "pool-frida", "gum")
            threads.any { threadDir ->
                val commFile = File(threadDir, "comm")
                if (commFile.exists()) {
                    val name = commFile.readText().trim().lowercase()
                    fridaKeywords.any { kw -> name.contains(kw) }
                } else false
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun checkAnonRwx(): Boolean {
        return try {
            val mapsFile = File("/proc/self/maps")
            if (!mapsFile.exists()) return false
            mapsFile.useLines { lines ->
                lines.any { line ->
                    line.contains("rwxp") && line.contains("00000000 00:00 0")
                }
            }
        } catch (_: Exception) {
            false
        }
    }
}
