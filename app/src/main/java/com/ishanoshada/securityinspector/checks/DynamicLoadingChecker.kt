package com.ishanoshada.securityinspector.checks

import android.content.Context
import com.ishanoshada.securityinspector.models.SecurityCategory
import com.ishanoshada.securityinspector.models.SecurityCheckItem
import dalvik.system.BaseDexClassLoader
import dalvik.system.DexClassLoader

object DynamicLoadingChecker {

    fun getDynamicLoadingChecks(context: Context): SecurityCategory {
        val items = mutableListOf<SecurityCheckItem>()

        val loaders = collectClassLoaders()
        val hasDexLoader = loaders.any { it is DexClassLoader }
        items.add(
            SecurityCheckItem(
                id = "dex_class_loader",
                name = "DexClassLoader Present",
                description = "Scans the class loader chain for DexClassLoader instances",
                isDetected = hasDexLoader,
                functionName = "DynamicLoadingChecker.collectClassLoaders()",
                methodsAndApis = listOf(
                    "ClassLoader.getParent()",
                    "dalvik.system.DexClassLoader",
                    "dalvik.system.BaseDexClassLoader"
                ),
                technicalExplanation = "DexClassLoader loads DEX files from outside the APK. Malware and packers use it to decrypt and execute a payload at runtime, evading static analysis. Its presence is a strong indicator of dynamic code loading.",
                exampleCode = """
var cl: ClassLoader? = javaClass.classLoader
while (cl != null) {
    if (cl is DexClassLoader) return true
    cl = cl.parent
}
false
                """.trimIndent()
            )
        )

        val suspicious = listOf(
            context.cacheDir, context.filesDir, context.getDir("dex", Context.MODE_PRIVATE)
        ).flatMap { dir ->
            dir.walkTopDown().filter {
                it.isFile && (it.name.endsWith(".dex") || it.name.endsWith(".apk") ||
                        it.name.endsWith(".jar") || it.name.endsWith(".so"))
            }.take(5).toList()
        }
        items.add(
            SecurityCheckItem(
                id = "dex_files_in_cache",
                name = "Executable Files in Cache/Files Dir",
                description = "Scans cacheDir and filesDir for .dex, .apk, .jar, .so files",
                isDetected = suspicious.isNotEmpty(),
                functionName = "DynamicLoadingChecker.getDynamicLoadingChecks()",
                methodsAndApis = listOf("context.cacheDir.walkTopDown()", "File.name.endsWith(\".dex\")"),
                technicalExplanation = "Legitimate apps rarely write DEX/APK/SO files into their own cache or files directory. Packers and droppers drop encrypted payloads there before loading them with DexClassLoader.",
                exampleCode = """
context.cacheDir.walkTopDown()
    .filter { it.isFile && it.name.endsWith(".dex") }
    .take(1).toList().isNotEmpty()
                """.trimIndent()
            )
        )

        val badLoader = loaders.any {
            it is BaseDexClassLoader && it.toString().contains("/data/local/tmp")
        }
        items.add(
            SecurityCheckItem(
                id = "loader_from_tmp",
                name = "ClassLoader Loads from /data/local/tmp",
                description = "Checks if a BaseDexClassLoader references /data/local/tmp",
                isDetected = badLoader,
                functionName = "DynamicLoadingChecker.collectClassLoaders()",
                methodsAndApis = listOf("BaseDexClassLoader.toString()", "/data/local/tmp path"),
                technicalExplanation = "/data/local/tmp is world-writable and a common drop location for injected DEX payloads. A class loader sourcing from there indicates runtime code injection.",
                exampleCode = """
var cl: ClassLoader? = javaClass.classLoader
while (cl != null) {
    if (cl is BaseDexClassLoader && cl.toString().contains("/data/local/tmp")) return true
    cl = cl.parent
}
false
                """.trimIndent()
            )
        )

        return SecurityCategory(
            categoryName = "Dynamic Code Loading",
            iconEmoji = "📥",
            items = items
        )
    }

    private fun collectClassLoaders(): List<ClassLoader> {
        val list = mutableListOf<ClassLoader>()
        var cl: ClassLoader? = DynamicLoadingChecker::class.java.classLoader
        while (cl != null) {
            list.add(cl)
            cl = cl.parent
        }
        return list
    }
}
