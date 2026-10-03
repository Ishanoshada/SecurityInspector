package com.ishanoshada.securityinspector.flags

enum class HintLevel(val label: String, val emoji: String) {
    GENTLE("Gentle", "💡"),
    DIRECT("Direct", "🔍"),
    SOLUTION("Solution", "🧠")
}

object FlagHints {
    fun hintFor(flagId: String, level: HintLevel): String = when (flagId to level) {
        "flag_static" to HintLevel.GENTLE ->
            "Look for a class named *FlagVault in the decompiled bytecode. What does reveal() do?"
        "flag_static" to HintLevel.DIRECT ->
            "The flag is split into 4 parts (C1..C4), Base64 encoded, and obfuscated with a rolling XOR key."
        "flag_static" to HintLevel.SOLUTION ->
            "Concatenate C1..C4 -> Base64 decode -> XOR with {0x42, 0x13, 0x37, 0x5A, 0x21} -> UTF-8 String."

        "flag_dynamic" to HintLevel.GENTLE ->
            "The ciphertext is stored in the APK, but the AES key is dynamically computed at runtime."
        "flag_dynamic" to HintLevel.DIRECT ->
            "Key = SHA-256(Build.FINGERPRINT + '|' + Build.HARDWARE + '|' + SALT). Use Frida to hook deriveKey()."
        "flag_dynamic" to HintLevel.SOLUTION ->
            "Frida: Java.use('com.ishanoshada.securityinspector.flags.DynamicFlagVault').getFlag()"
        else -> "No hint at this level."
    }
}
