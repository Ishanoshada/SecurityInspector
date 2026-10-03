package com.ishanoshada.securityinspector.checks

import com.ishanoshada.securityinspector.models.SecurityCategory
import com.ishanoshada.securityinspector.models.SecurityCheckItem
import java.io.File
import javax.net.ssl.HttpsURLConnection

object NetworkSecurityChecker {

    fun getNetworkSecurityChecks(): SecurityCategory {
        val items = mutableListOf<SecurityCheckItem>()

        items.add(
            SecurityCheckItem(
                id = "user_ca_certs",
                name = "User Installed CA Certificates",
                description = "Checks for user-installed trusted CAs (Burp/Charles/Mitmproxy) in /data/misc/user/0/cacerts-added/",
                isDetected = checkUserCaCerts(),
                functionName = "NetworkSecurityChecker.checkUserCaCerts()",
                methodsAndApis = listOf("File(\"/data/misc/user/0/cacerts-added/\").listFiles()", "AndroidCAStore KeyStore"),
                technicalExplanation = "Scans /data/misc/user/0/cacerts-added/ for user-installed X.509 CA certificate files. Man-in-the-Middle (MitM) tools require installing a custom root CA in this path.",
                exampleCode = """
val userCaDir = File("/data/misc/user/0/cacerts-added")
userCaDir.exists() && (userCaDir.listFiles()?.isNotEmpty() == true)
                """.trimIndent()
            )
        )

        items.add(
            SecurityCheckItem(
                id = "system_proxy",
                name = "System HTTP/HTTPS Proxy Set",
                description = "Checks System.getProperty(\"http.proxyHost\") and https.proxyHost",
                isDetected = checkSystemProxy(),
                functionName = "NetworkSecurityChecker.checkSystemProxy()",
                methodsAndApis = listOf("System.getProperty(\"http.proxyHost\")", "System.getProperty(\"https.proxyHost\")"),
                technicalExplanation = "Queries Java System properties for active proxy host and port settings used to route app network traffic through packet inspection tools.",
                exampleCode = """
val httpProxy = System.getProperty("http.proxyHost")
val httpsProxy = System.getProperty("https.proxyHost")
!httpProxy.isNullOrBlank() || !httpsProxy.isNullOrBlank()
                """.trimIndent()
            )
        )

        items.add(
            SecurityCheckItem(
                id = "custom_hostname_verifier",
                name = "Modified Default HostnameVerifier",
                description = "Checks HttpsURLConnection.getDefaultHostnameVerifier() for custom/dummy implementations",
                isDetected = checkCustomHostnameVerifier(),
                functionName = "NetworkSecurityChecker.checkCustomHostnameVerifier()",
                methodsAndApis = listOf("HttpsURLConnection.getDefaultHostnameVerifier()"),
                technicalExplanation = "Inspects default HttpsURLConnection HostnameVerifier class name. SSL unpinning scripts override this with dummy verifiers returning true for all hosts.",
                exampleCode = """
val verifier = HttpsURLConnection.getDefaultHostnameVerifier()
val name = verifier.javaClass.name.lowercase()
name.contains("dummy") || name.contains("trust") || name.contains("allowall")
                """.trimIndent()
            )
        )

        items.add(
            SecurityCheckItem(
                id = "okhttp_cert_pinner",
                name = "OkHttp CertificatePinner Class",
                description = "Checks if okhttp3.CertificatePinner class exists in classpath",
                isDetected = isClassPresent("okhttp3.CertificatePinner"),
                functionName = "NetworkSecurityChecker.isClassPresent()",
                methodsAndApis = listOf("Class.forName(\"okhttp3.CertificatePinner\")"),
                technicalExplanation = "Checks if OkHttp 3/4 CertificatePinner library is present in runtime classpath for network certificate binding.",
                exampleCode = """
try { Class.forName("okhttp3.CertificatePinner"); true } catch (e: Exception) { false }
                """.trimIndent()
            )
        )

        items.add(
            SecurityCheckItem(
                id = "trustkit_pinning",
                name = "TrustKit Pinning Manager",
                description = "Checks if com.datatheorem.android.trustkit.pinning.PinningTrustManager exists",
                isDetected = isClassPresent("com.datatheorem.android.trustkit.pinning.PinningTrustManager"),
                functionName = "NetworkSecurityChecker.isClassPresent()",
                methodsAndApis = listOf("Class.forName(\"com.datatheorem.android.trustkit.pinning.PinningTrustManager\")"),
                technicalExplanation = "Checks for Data Theorem's TrustKit SSL pinning framework in the app runtime classpath.",
                exampleCode = """
try { Class.forName("com.datatheorem.android.trustkit.pinning.PinningTrustManager"); true } catch (e: Exception) { false }
                """.trimIndent()
            )
        )

        items.add(
            SecurityCheckItem(
                id = "appmattus_transparency",
                name = "Appmattus Certificate Transparency",
                description = "Checks for com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyInterceptor",
                isDetected = isClassPresent("com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyInterceptor"),
                functionName = "NetworkSecurityChecker.isClassPresent()",
                methodsAndApis = listOf("Class.forName(\"com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyInterceptor\")"),
                technicalExplanation = "Detects Appmattus Certificate Transparency enforcement library in application classpath.",
                exampleCode = """
try { Class.forName("com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyInterceptor"); true } catch (e: Exception) { false }
                """.trimIndent()
            )
        )

        items.add(
            SecurityCheckItem(
                id = "worklight_pinning",
                name = "IBM MobileFirst / Worklight Pinning",
                description = "Checks for com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning",
                isDetected = isClassPresent("com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning"),
                functionName = "NetworkSecurityChecker.isClassPresent()",
                methodsAndApis = listOf("Class.forName(\"com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning\")"),
                technicalExplanation = "Detects IBM MobileFirst/Worklight enterprise SSL certificate pinning verifier class.",
                exampleCode = """
try { Class.forName("com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning"); true } catch (e: Exception) { false }
                """.trimIndent()
            )
        )

        items.add(
            SecurityCheckItem(
                id = "cwac_conscrypt_pinning",
                name = "CWAC / Conscrypt CertPinManager",
                description = "Checks for com.commonsware.cwac.netsecurity.conscrypt.CertPinManager",
                isDetected = isClassPresent("com.commonsware.cwac.netsecurity.conscrypt.CertPinManager"),
                functionName = "NetworkSecurityChecker.isClassPresent()",
                methodsAndApis = listOf("Class.forName(\"com.commonsware.cwac.netsecurity.conscrypt.CertPinManager\")"),
                technicalExplanation = "Detects CommonsWare CWAC NetSecurity Conscrypt certificate pin manager in application classpath.",
                exampleCode = """
try { Class.forName("com.commonsware.cwac.netsecurity.conscrypt.CertPinManager"); true } catch (e: Exception) { false }
                """.trimIndent()
            )
        )

        return SecurityCategory(
            categoryName = "Network & SSL Security",
            iconEmoji = "🔐",
            items = items
        )
    }

    private fun checkUserCaCerts(): Boolean {
        return try {
            val userCaDir = File("/data/misc/user/0/cacerts-added")
            userCaDir.exists() && (userCaDir.listFiles()?.isNotEmpty() == true)
        } catch (_: Exception) {
            false
        }
    }

    private fun checkSystemProxy(): Boolean {
        return try {
            val httpProxy = System.getProperty("http.proxyHost")
            val httpsProxy = System.getProperty("https.proxyHost")
            !httpProxy.isNullOrBlank() || !httpsProxy.isNullOrBlank()
        } catch (_: Exception) {
            false
        }
    }

    private fun checkCustomHostnameVerifier(): Boolean {
        return try {
            val verifier = HttpsURLConnection.getDefaultHostnameVerifier()
            val className = verifier.javaClass.name.lowercase()
            className.contains("dummy") || className.contains("trust") || className.contains("allowall") || className.contains("alwaystrue")
        } catch (_: Exception) {
            false
        }
    }

    private fun isClassPresent(className: String): Boolean {
        return try {
            Class.forName(className)
            true
        } catch (_: Exception) {
            false
        }
    }
}
