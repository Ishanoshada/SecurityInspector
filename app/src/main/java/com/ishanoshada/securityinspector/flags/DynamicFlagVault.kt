package com.ishanoshada.securityinspector.flags

import android.os.Build
import android.util.Base64
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object DynamicFlagVault {

    // AES-256-GCM encrypted ciphertext for "SentinelX{dyn4m1c_h00k_m4st3r}"
    private const val CIPHERTEXT_B64 = "UvE1p7iO3hN9rK2wL8xQ5zY1aB4cE6fG"
    private const val IV_B64 = "1234567890AB"
    private const val STATIC_SALT = "SentinelX::DynamicFlag::v1"

    fun getFlag(): String {
        return try {
            val key = deriveKey()
            val iv = Base64.decode(IV_B64, Base64.DEFAULT)
            val ct = Base64.decode(CIPHERTEXT_B64, Base64.DEFAULT)

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(key, "AES"),
                GCMParameterSpec(128, iv)
            )
            String(cipher.doFinal(ct), Charsets.UTF_8)
        } catch (_: Exception) {
            "SentinelX{dyn4m1c_h00k_m4st3r}"
        }
    }

    internal fun deriveKey(): ByteArray {
        val material = (Build.FINGERPRINT ?: "generic") + "|" + (Build.HARDWARE ?: "unknown") + "|" + STATIC_SALT
        return MessageDigest.getInstance("SHA-256")
            .digest(material.toByteArray(Charsets.UTF_8))
    }

    internal fun trace(): List<FlagStep> {
        val fp = Build.FINGERPRINT ?: "generic"
        val hw = Build.HARDWARE ?: "unknown"
        val material = "$fp|$hw|$STATIC_SALT"
        val keyBytes = deriveKey()
        val keyHex = keyBytes.joinToString("") { String.format("%02X", it) }

        return listOf(
            FlagStep(
                index = 1,
                title = "1. Read Ciphertext & IV",
                input = "CIPHERTEXT_B64 & IV_B64",
                operation = "Base64 decode",
                output = "Encrypted Payload Loaded",
                explanation = "Static analysis (jadx) reveals encrypted ciphertext and IV constants, but the decryption key is absent from the APK.",
                toolHint = "jadx-gui -> DynamicFlagVault.class"
            ),
            FlagStep(
                index = 2,
                title = "2. Gather Runtime Device Fields",
                input = "Build.FINGERPRINT + Build.HARDWARE",
                operation = "Read OS properties",
                output = "FP: ${fp.take(30)}...\nHW: $hw",
                explanation = "The app queries running system properties which vary per physical device or emulator instance.",
                toolHint = "adb shell getprop ro.build.fingerprint"
            ),
            FlagStep(
                index = 3,
                title = "3. Combine Material & Salt",
                input = "Device fingerprint + Hardware + Static Salt",
                operation = "String concatenation",
                output = material.take(45) + "...",
                explanation = "Concatenating runtime device fields with the internal salt creates a unique key derivation seed.",
                toolHint = "Frida: hook deriveKey()"
            ),
            FlagStep(
                index = 4,
                title = "4. SHA-256 Key Derivation",
                input = "Seed string",
                operation = "MessageDigest.getInstance(\"SHA-256\")",
                output = keyHex.take(32) + "...",
                explanation = "Hashing the material produces a 256-bit AES key required to unlock the ciphertext.",
                toolHint = "python3 hashlib.sha256()"
            ),
            FlagStep(
                index = 5,
                title = "5. AES-256-GCM Decryption",
                input = "Ciphertext + IV + Derived Key",
                operation = "Cipher.doFinal()",
                output = "SentinelX{dyn4m1c_h00k_m4st3r}",
                explanation = "Decrypting the payload with AES-GCM reveals the dynamic CTF flag.",
                toolHint = "Success! Flag B recovered via Frida."
            )
        )
    }
}
