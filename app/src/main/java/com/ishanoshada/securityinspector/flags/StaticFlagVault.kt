package com.ishanoshada.securityinspector.flags

import android.util.Base64

object StaticFlagVault {

    // Split Base64 chunks for "SentinelX{st4t1c_4n4lys1s_w1ns}"
    // Base64 string: "U2VudGluZWxYe3N0NHQxY180bjRseXMxc193MW5zfQ=="
    private const val C1 = "U2VudGlu"
    private const val C2 = "ZWxYe3N0"
    private const val C3 = "NHQxY180"
    private const val C4 = "bjRseXMxc193MW5zfQ=="

    fun reveal(): String {
        return try {
            val joined = C1 + C2 + C3 + C4
            val decoded = Base64.decode(joined, Base64.DEFAULT)
            String(decoded, Charsets.UTF_8)
        } catch (e: Exception) {
            "decode_error: ${e.message}"
        }
    }

    internal fun trace(): List<FlagStep> {
        val cCombined = C1 + C2 + C3 + C4
        val rawDecoded = try { Base64.decode(cCombined, Base64.DEFAULT) } catch (_: Exception) { ByteArray(0) }
        val finalStr = String(rawDecoded, Charsets.UTF_8)

        return listOf(
            FlagStep(
                index = 1,
                title = "1. Read Obfuscated Chunks",
                input = "C1=\"$C1\", C2=\"$C2\", C3=\"$C3\", C4=\"$C4\"",
                operation = "String Concatenation",
                output = cCombined,
                explanation = "Static analysis (jadx) reveals four split string constants designed to defeat simple 'strings' or 'grep' signature searches.",
                toolHint = "jadx-gui -> StaticFlagVault.class"
            ),
            FlagStep(
                index = 2,
                title = "2. Base64 Decoding",
                input = cCombined,
                operation = "Base64.decode()",
                output = "Decoded bytes length: ${rawDecoded.size}",
                explanation = "Decoding the Base64 ASCII string restores the raw flag byte sequence.",
                toolHint = "python3 -m base64 -d"
            ),
            FlagStep(
                index = 3,
                title = "3. UTF-8 String Reconstruction",
                input = "Decrypted byte array",
                operation = "String(bytes, UTF_8)",
                output = finalStr,
                explanation = "Converting the decoded byte sequence into a readable UTF-8 string reveals the static CTF flag.",
                toolHint = "Success! Flag A recovered."
            )
        )
    }
}
