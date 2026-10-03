package com.ishanoshada.securityinspector.utils

import java.io.File

object SystemUtils {

    fun checkMapsForKeywords(keywords: List<String>): Boolean {
        return try {
            val mapsFile = File("/proc/self/maps")
            if (!mapsFile.exists()) return false
            mapsFile.useLines { lines ->
                lines.any { line ->
                    val lower = line.lowercase()
                    keywords.any { kw -> lower.contains(kw.lowercase()) }
                }
            }
        } catch (_: Exception) {
            false
        }
    }

    fun checkProcNetTcp(hexPorts: List<String>): Boolean {
        listOf("/proc/net/tcp", "/proc/net/tcp6").forEach { path ->
            try {
                val file = File(path)
                if (file.exists()) {
                    file.useLines { lines ->
                        lines.forEach { line ->
                            val parts = line.trim().split("\\s+".toRegex())
                            if (parts.size > 1) {
                                val localAddr = parts[1]
                                val portPart = localAddr.substringAfter(":", "")
                                if (hexPorts.any { portPart.equals(it, ignoreCase = true) }) {
                                    return true
                                }
                            }
                        }
                    }
                }
            } catch (_: Exception) {
                // Ignore
            }
        }
        return false
    }

    fun checkMountsForKeywords(keywords: List<String>): Boolean {
        listOf("/proc/self/mountinfo", "/proc/mounts").forEach { path ->
            try {
                val file = File(path)
                if (file.exists()) {
                    file.useLines { lines ->
                        if (lines.any { line ->
                                keywords.any { kw -> line.lowercase().contains(kw.lowercase()) }
                            }) return true
                    }
                }
            } catch (_: Exception) {
                // Ignore
            }
        }
        return false
    }

    fun getSystemProperty(key: String): String {
        return try {
            val systemProperties = Class.forName("android.os.SystemProperties")
            val get = systemProperties.getMethod("get", String::class.java)
            get.invoke(null, key) as? String ?: ""
        } catch (_: Exception) {
            try {
                val process = Runtime.getRuntime().exec("getprop $key")
                process.inputStream.bufferedReader().use { it.readText() }.trim()
            } catch (_: Exception) {
                ""
            }
        }
    }
}
