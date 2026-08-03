package org.kotlintor.link

import org.conscrypt.Conscrypt
import java.security.SecureRandom
import java.security.Security
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.X509TrustManager

/**
 * Tor OR TLS does not use public CAs. Identity is established via the in-protocol CERTS
 * cell (and key binding). This TrustManager accepts the peer certificate during the TLS
 * handshake; callers must still validate CERTS against the expected relay identity.
 *
 * Prefer Conscrypt so AUTHENTICATE can use RFC5705 keying-material export on JDK 21.
 */
object TorSsl {
    private val trustAll = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) = Unit
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }

    @Volatile var usingConscrypt: Boolean = false
        private set

    val socketFactory: SSLSocketFactory by lazy {
        installConscrypt()
        val ctx = if (usingConscrypt) {
            runCatching { SSLContext.getInstance("TLS", "Conscrypt") }.getOrElse {
                SSLContext.getInstance("TLS")
            }
        } else {
            SSLContext.getInstance("TLS")
        }
        ctx.init(null, arrayOf(trustAll), SecureRandom())
        ctx.socketFactory
    }

    fun installConscrypt(): Boolean {
        if (usingConscrypt) return true
        return try {
            if (Security.getProvider("Conscrypt") == null) {
                Security.insertProviderAt(Conscrypt.newProvider(), 1)
            }
            usingConscrypt = true
            true
        } catch (_: Throwable) {
            usingConscrypt = false
            false
        }
    }
}
