package com.ishanoshada.securityinspector.flags

import com.ishanoshada.securityinspector.models.SecurityCategory
import com.ishanoshada.securityinspector.models.SecurityCheckItem

object FlagCategory {
    fun getFlagChecks(): SecurityCategory {
        val items = listOf(
            SecurityCheckItem(
                id = FlagSolver.FLAG_STATIC,
                name = "🏴 Flag A — Static Analysis",
                description = "Recover via jadx — or tap Solve Step-by-Step",
                isDetected = false,
                functionName = "StaticFlagVault.reveal()",
                methodsAndApis = listOf(
                    "jadx-gui / apktool / strings",
                    "Base64 + rolling XOR decoder",
                    "Split constants C1..C4"
                ),
                technicalExplanation = "Read the decompiled StaticFlagVault class. The flag is split into 4 chunks, Base64 encoded, and obfuscated with a 5-byte rolling XOR key.",
                exampleCode = "// See docs/WALKTHROUGH_STATIC.md"
            ),
            SecurityCheckItem(
                id = FlagSolver.FLAG_DYNAMIC,
                name = "🏴 Flag B — Dynamic Analysis",
                description = "Recover via Frida — or tap Solve Step-by-Step",
                isDetected = false,
                functionName = "DynamicFlagVault.getFlag()",
                methodsAndApis = listOf(
                    "AES/GCM/NoPadding decrypt",
                    "SHA-256(device fingerprint + hardware + salt)",
                    "Frida: Java.use(...).getFlag()"
                ),
                technicalExplanation = "The ciphertext is static; the decryption key is derived at runtime from running device properties (Build.FINGERPRINT + Build.HARDWARE). Requires Frida to intercept runtime decryption.",
                exampleCode = "// See docs/WALKTHROUGH_DYNAMIC.md"
            )
        )
        return SecurityCategory(
            categoryName = "🏁 CTF Flags",
            iconEmoji = "🚩",
            items = items
        )
    }
}
