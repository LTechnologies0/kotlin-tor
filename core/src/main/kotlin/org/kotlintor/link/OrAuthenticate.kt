package org.kotlintor.link

import org.kotlintor.cell.Cell
import org.kotlintor.cell.CellCommand
import org.kotlintor.crypto.Digests
import org.kotlintor.crypto.Ed25519Keys
import org.kotlintor.util.SecureRandomSource
import org.kotlintor.util.concat
import org.kotlintor.util.u16be
import java.security.cert.X509Certificate
import javax.net.ssl.SSLSocket

/**
 * Link AUTHENTICATE AuthType=3 (Ed25519-SHA256-RFC5705).
 *
 * TLSSECRETS requires a keying-material exporter (JDK 25+ `ExtendedSSLSession`,
 * or an injected [TlsExporter]). On JDK 21 without an exporter, callers may still
 * build/verify the cell structure in tests with explicit secrets.
 */
object OrAuthenticate {
    const val AUTH_TYPE: Int = 3
    private val TYPE = "AUTH0003".toByteArray(Charsets.US_ASCII)
    private const val LABEL = "EXPORTER FOR TOR TLS CLIENT BINDING AUTH0003"

    data class AuthBody(
        val cid: ByteArray,
        val sid: ByteArray,
        val cidEd: ByteArray,
        val sidEd: ByteArray,
        val slog: ByteArray,
        val clog: ByteArray,
        val scert: ByteArray,
        val tlsSecrets: ByteArray,
        val rand: ByteArray,
        val sig: ByteArray,
    ) {
        fun signedPrefix(): ByteArray =
            concat(TYPE, cid, sid, cidEd, sidEd, slog, clog, scert, tlsSecrets, rand)

        fun encode(): ByteArray = concat(signedPrefix(), sig)
    }

    fun interface TlsExporter {
        fun export(label: String, context: ByteArray, length: Int): ByteArray
    }

    /** Try JDK 25+ ExtendedSSLSession, then Conscrypt OpenSSLSessionImpl, via reflection. */
    fun exporterFromSsl(socket: SSLSocket): TlsExporter? {
        val session = socket.session ?: return null
        // JDK 25+: exportKeyingMaterialData(String, byte[], int)
        tryMethod(session, "exportKeyingMaterialData", 3)?.let { return it }
        // Conscrypt: exportKeyingMaterial(String, byte[], int)
        tryMethod(session, "exportKeyingMaterial", 3)?.let { return it }
        // Some providers: exportKeyingMaterial(label, context, length) on SSLEngine session
        val engineSession = runCatching {
            socket.javaClass.methods.firstOrNull { it.name == "getHandshakeSession" }
                ?.invoke(socket)
        }.getOrNull()
        if (engineSession != null) {
            tryMethod(engineSession, "exportKeyingMaterial", 3)?.let { return it }
            tryMethod(engineSession, "exportKeyingMaterialData", 3)?.let { return it }
        }
        return null
    }

    private fun tryMethod(target: Any, name: String, paramCount: Int): TlsExporter? {
        return try {
            val m = target.javaClass.methods.firstOrNull {
                it.name == name && it.parameterCount == paramCount
            } ?: return null
            TlsExporter { label, ctx, len ->
                m.invoke(target, label, ctx, len) as ByteArray
            }
        } catch (_: Exception) {
            null
        }
    }

    fun sha256DerRsa(cert: X509Certificate): ByteArray =
        Digests.sha256(cert.publicKey.encoded)

    fun sha256TlsCert(cert: X509Certificate): ByteArray =
        Digests.sha256(cert.encoded)

    fun build(
        cidRsaSha256: ByteArray,
        sidRsaSha256: ByteArray,
        cidEd: ByteArray,
        sidEd: ByteArray,
        slog: ByteArray,
        clog: ByteArray,
        scertSha256: ByteArray,
        tlsSecrets: ByteArray,
        linkEdPrivate: ByteArray,
        rand: ByteArray = SecureRandomSource.nextBytes(24),
    ): AuthBody {
        require(cidRsaSha256.size == 32 && sidRsaSha256.size == 32)
        require(cidEd.size == 32 && sidEd.size == 32)
        require(slog.size == 32 && clog.size == 32 && scertSha256.size == 32)
        require(tlsSecrets.size == 32 && rand.size == 24)
        val prefix = concat(
            TYPE, cidRsaSha256, sidRsaSha256, cidEd, sidEd,
            slog, clog, scertSha256, tlsSecrets, rand,
        )
        val sig = Ed25519Keys.sign(linkEdPrivate, prefix)
        return AuthBody(
            cid = cidRsaSha256, sid = sidRsaSha256,
            cidEd = cidEd, sidEd = sidEd,
            slog = slog, clog = clog, scert = scertSha256,
            tlsSecrets = tlsSecrets, rand = rand, sig = sig,
        )
    }

    fun toCell(body: AuthBody): Cell {
        val auth = body.encode()
        val payload = concat(u16be(AUTH_TYPE), u16be(auth.size), auth)
        return Cell(0, CellCommand.AUTHENTICATE, payload)
    }

    fun parse(payload: ByteArray): AuthBody {
        require(payload.size >= 4)
        val type = ((payload[0].toInt() and 0xff) shl 8) or (payload[1].toInt() and 0xff)
        require(type == AUTH_TYPE) { "unsupported AuthType=$type" }
        val len = ((payload[2].toInt() and 0xff) shl 8) or (payload[3].toInt() and 0xff)
        val auth = payload.copyOfRange(4, 4 + len)
        require(auth.size >= 8 + 32 * 8 + 24 + 64)
        var o = 0
        require(auth.copyOfRange(0, 8).contentEquals(TYPE))
        o = 8
        fun take(n: Int): ByteArray {
            val b = auth.copyOfRange(o, o + n); o += n; return b
        }
        return AuthBody(
            cid = take(32), sid = take(32), cidEd = take(32), sidEd = take(32),
            slog = take(32), clog = take(32), scert = take(32), tlsSecrets = take(32),
            rand = take(24), sig = take(64),
        )
    }

    fun verify(body: AuthBody, linkEdPublic: ByteArray): Boolean {
        return Ed25519Keys.verify(linkEdPublic, body.signedPrefix(), body.sig)
    }

    fun exportTlsSecrets(exporter: TlsExporter, cid: ByteArray): ByteArray =
        exporter.export(LABEL, cid, 32)
}
