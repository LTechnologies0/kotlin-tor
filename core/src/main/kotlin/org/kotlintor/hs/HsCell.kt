package org.kotlintor.hs

import org.kotlintor.crypto.Digests
import org.kotlintor.crypto.Ed25519Keys
import org.kotlintor.util.concat
import org.kotlintor.util.u64be

/**
 * HS cell codecs (C Tor `hs_cell.c` / rend-spec introduction-protocol).
 *
 * Inventory: `L1:feature/hs/hs_cell.c`
 */
object HsCell {
    const val ESTABLISH_INTRO: String = "ESTABLISH_INTRO"
    const val INTRODUCE1: String = "INTRODUCE1"
    const val INTRODUCE2: String = "INTRODUCE2"
    const val RENDEZVOUS1: String = "RENDEZVOUS1"

    /** ESTABLISH_INTRO DoS extension type (rend-spec). */
    const val EST_INTRO_DOS_EXT: Int = 1
    const val AUTH_KEY_TYPE_ED25519: Int = 0x02
    const val MAC_LEN: Int = 32
    const val SIG_LEN: Int = 64
    /** Circuit KH / circ_nonce length (tor-spec DIGEST_LEN). */
    const val CIRC_NONCE_LEN: Int = 20
    val ESTABLISH_INTRO_SIG_PREFIX: ByteArray =
        "Tor establish-intro cell v1".toByteArray(Charsets.US_ASCII)

    data class Introduce1Data(
        var authKey: ByteArray? = null,
        var encKey: ByteArray? = null,
        var onionKey: ByteArray? = null,
        var linkSpecifiers: ByteArray? = null,
        var encrypted: ByteArray? = null,
    )

    fun knownCommands(): Set<String> = setOf(ESTABLISH_INTRO, INTRODUCE1, INTRODUCE2, RENDEZVOUS1)

    /**
     * C Tor `build_establish_intro_extensions` — optional DoS rate/burst fields only
     * (TYPE+LEN+BODY, without N_EXTENSIONS — caller prepends count).
     */
    fun buildEstablishIntroExtensions(intro2Rate: Int = 0, intro2Burst: Int = 0): ByteArray {
        if (intro2Rate <= 0 && intro2Burst <= 0) return ByteArray(0)
        val body = ByteArray(8)
        fun putU32(off: Int, v: Int) {
            body[off] = ((v ushr 24) and 0xff).toByte()
            body[off + 1] = ((v ushr 16) and 0xff).toByte()
            body[off + 2] = ((v ushr 8) and 0xff).toByte()
            body[off + 3] = (v and 0xff).toByte()
        }
        putU32(0, intro2Rate.coerceAtLeast(0))
        putU32(4, intro2Burst.coerceAtLeast(0))
        return byteArrayOf(EST_INTRO_DOS_EXT.toByte(), 8) + body
    }

    /** C Tor `crypto_mac_sha3_256` / HsNtor.hsMac over circuit KH. */
    fun establishIntroMac(circuitKh: ByteArray, msgThroughExtensions: ByteArray): ByteArray =
        Digests.sha3_256(concat(u64be(circuitKh.size.toLong()), circuitKh, msgThroughExtensions))

    /**
     * C Tor `hs_cell_build_establish_intro` — full wire cell:
     * AUTH_KEY_TYPE|LEN|KEY | N_EXTENSIONS|exts | HANDSHAKE_AUTH | SIG_LEN|SIG
     */
    fun hsCellBuildEstablishIntro(
        authKeyPublic: ByteArray,
        authKeyPrivate: ByteArray,
        circuitKh: ByteArray,
        intro2Rate: Int = 0,
        intro2Burst: Int = 0,
    ): ByteArray {
        require(authKeyPublic.size == 32)
        require(authKeyPrivate.size == 32)
        require(circuitKh.size == CIRC_NONCE_LEN) { "circ_nonce/KH must be $CIRC_NONCE_LEN bytes" }

        val extFields = buildEstablishIntroExtensions(intro2Rate, intro2Burst)
        val nExt = if (extFields.isEmpty()) 0 else 1
        val head = ByteArray(1 + 2 + 32 + 1 + extFields.size)
        var i = 0
        head[i++] = AUTH_KEY_TYPE_ED25519.toByte()
        head[i++] = 0
        head[i++] = 32
        authKeyPublic.copyInto(head, i); i += 32
        head[i++] = nExt.toByte()
        if (extFields.isNotEmpty()) {
            extFields.copyInto(head, i)
        }

        val mac = establishIntroMac(circuitKh, head)
        val preSig = head + mac
        val toSign = ESTABLISH_INTRO_SIG_PREFIX + preSig
        val sig = Ed25519Keys.sign(authKeyPrivate, toSign)
        require(sig.size == SIG_LEN)
        return preSig + byteArrayOf(0, SIG_LEN.toByte()) + sig
    }

    /**
     * Legacy elevation helper: public key only — builds **unsigned** structural prefix
     * (no MAC/SIG). Prefer the full [hsCellBuildEstablishIntro] overload for wire use.
     */
    fun hsCellBuildEstablishIntro(
        authKey: ByteArray,
        intro2Rate: Int = 0,
        intro2Burst: Int = 0,
    ): ByteArray {
        require(authKey.size == 32)
        val extFields = buildEstablishIntroExtensions(intro2Rate, intro2Burst)
        val nExt = if (extFields.isEmpty()) 0 else 1
        return byteArrayOf(AUTH_KEY_TYPE_ED25519.toByte(), 0, 32) +
            authKey +
            byteArrayOf(nExt.toByte()) +
            extFields
    }

    /** C Tor `hs_cell_build_establish_rendezvous` — 20-byte rend cookie. */
    fun hsCellBuildEstablishRendezvous(rendCookie: ByteArray): ByteArray {
        require(rendCookie.size == 20)
        return rendCookie.copyOf()
    }

    /** C Tor `hs_cell_build_introduce1` — legacy_key_id(20) + AUTH_KEY_TYPE(1) + AUTH_KEYLEN(2) + auth. */
    fun hsCellBuildIntroduce1(
        legacyKeyId: ByteArray = ByteArray(20),
        authKey: ByteArray,
        encryptedBody: ByteArray = ByteArray(0),
    ): ByteArray {
        require(legacyKeyId.size == 20)
        require(authKey.size == 32)
        val lenHi = ((authKey.size ushr 8) and 0xff).toByte()
        val lenLo = (authKey.size and 0xff).toByte()
        return legacyKeyId + byteArrayOf(2, lenHi, lenLo) + authKey + encryptedBody
    }

    /** C Tor `hs_cell_build_rendezvous1` — cookie(20) + handshake. */
    fun hsCellBuildRendezvous1(rendCookie: ByteArray, handshake: ByteArray): ByteArray {
        require(rendCookie.size == 20)
        return rendCookie + handshake
    }

    /** C Tor `hs_cell_introduce1_data_clear`. */
    fun hsCellIntroduce1DataClear(data: Introduce1Data) {
        data.authKey = null
        data.encKey = null
        data.onionKey = null
        data.linkSpecifiers = null
        data.encrypted = null
    }

    /**
     * C Tor `hs_cell_parse_intro_established` —
     * INTRO_ESTABLISHED is N_EXTENSIONS + extensions (may be empty / N=0).
     */
    fun hsCellParseIntroEstablished(payload: ByteArray): Boolean {
        if (payload.isEmpty()) return true // ACK with no body
        var i = 0
        if (i >= payload.size) return false
        val n = payload[i++].toInt() and 0xff
        repeat(n) {
            if (i + 2 > payload.size) return false
            i++ // type
            val len = payload[i++].toInt() and 0xff
            if (i + len > payload.size) return false
            i += len
        }
        return true
    }

    /**
     * C Tor `hs_cell_parse_introduce2` — require non-empty encrypted payload.
     */
    fun hsCellParseIntroduce2(payload: ByteArray): ByteArray? =
        payload.takeIf { it.isNotEmpty() }

    /** C Tor `hs_cell_parse_introduce_ack` — status byte 0 = success. */
    fun hsCellParseIntroduceAck(payload: ByteArray): Int =
        if (payload.isEmpty()) 0 else (payload[0].toInt() and 0xff)

    /** C Tor `hs_cell_parse_rendezvous2` — handshake after empty ESTABLISH ack path. */
    fun hsCellParseRendezvous2(payload: ByteArray): ByteArray? =
        payload.takeIf { it.size >= 32 }

    /**
     * Parse ESTABLISH_INTRO layout; returns offsets for MAC/SIG verification.
     * @return Triple(headThroughExts, mac, sig) or null if malformed.
     */
    fun parseEstablishIntro(payload: ByteArray): EstablishIntroParsed? {
        if (payload.size < 1 + 2 + 32 + 1 + MAC_LEN + 2 + SIG_LEN) return null
        if ((payload[0].toInt() and 0xff) != AUTH_KEY_TYPE_ED25519) return null
        val keyLen = ((payload[1].toInt() and 0xff) shl 8) or (payload[2].toInt() and 0xff)
        if (keyLen != 32) return null
        var i = 3 + 32
        if (i >= payload.size) return null
        val nExt = payload[i++].toInt() and 0xff
        repeat(nExt) {
            if (i + 2 > payload.size) return null
            i++ // type
            val len = payload[i++].toInt() and 0xff
            if (i + len > payload.size) return null
            i += len
        }
        if (i + MAC_LEN + 2 + SIG_LEN > payload.size) return null
        val head = payload.copyOfRange(0, i)
        val mac = payload.copyOfRange(i, i + MAC_LEN)
        i += MAC_LEN
        val sigLen = ((payload[i].toInt() and 0xff) shl 8) or (payload[i + 1].toInt() and 0xff)
        i += 2
        if (sigLen != SIG_LEN || i + sigLen > payload.size) return null
        val sig = payload.copyOfRange(i, i + sigLen)
        val authKey = payload.copyOfRange(3, 35)
        return EstablishIntroParsed(head, mac, sig, authKey)
    }

    data class EstablishIntroParsed(
        val headThroughExtensions: ByteArray,
        val handshakeMac: ByteArray,
        val signature: ByteArray,
        val authKeyPublic: ByteArray,
    )
}
