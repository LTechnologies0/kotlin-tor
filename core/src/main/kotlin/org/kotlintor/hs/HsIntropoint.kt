package org.kotlintor.hs

/**
 * Intro-point bookkeeping (C Tor `hs_intropoint.c`).
 *
 * Inventory: `L1:feature/hs/hs_intropoint.c`
 *
 * Implementation: [HsIntroPointTable].
 */
object HsIntropoint {
    fun table(): HsIntroPointTable = HsIntroPointTable()
    fun beginEstablish(table: HsIntroPointTable, authKeyHex: String, circuitIdHint: String? = null) =
        table.beginEstablish(authKeyHex, circuitIdHint)

    /**
     * C Tor `cell_dos_extension_parameters_are_valid`.
     */
    fun cellDosExtensionParametersAreValid(intro2Rate: Int, intro2Burst: Int): Boolean {
        if (intro2Rate < 0 || intro2Burst < 0) return false
        if (intro2Rate == 0 && intro2Burst == 0) return true
        return intro2Burst >= intro2Rate
    }

    /**
     * C Tor `circuit_is_suitable_for_introduce1` — purpose / open heuristic.
     */
    fun circuitIsSuitableForIntroduce1(purpose: String, open: Boolean): Boolean =
        open && (purpose == HsCircuit.PURPOSE_CLIENT_INTRO || purpose == "HS_CLIENT_INTRO")

    /** C Tor `get_auth_key_from_cell` — ESTABLISH_INTRO wire: TYPE(1)+LEN(2)+key. */
    fun getAuthKeyFromCell(payload: ByteArray): ByteArray? {
        if (payload.size < 3) return null
        val authKeyType = payload[0].toInt() and 0xff
        if (authKeyType != 0x02) return null // Ed25519 only
        val authKeyLen = ((payload[1].toInt() and 0xff) shl 8) or (payload[2].toInt() and 0xff)
        if (authKeyLen != 32) return null
        if (payload.size < 3 + authKeyLen) return null
        return payload.copyOfRange(3, 3 + authKeyLen)
    }

    /**
     * C Tor `handle_introduce1` — note INTRODUCE1 against established intro.
     */
    fun handleIntroduce1(table: HsIntroPointTable, authKeyHex: String): Boolean {
        val st = table.get(authKeyHex) ?: return false
        if (!st.established && st.fsm != HsIntroFsm.ESTABLISHED) return false
        table.noteIntroduce(authKeyHex)
        return true
    }

    /** Shared process table for intropoint clear/init paths. */
    private val processTable = HsIntroPointTable()

    /** C Tor `hs_intro_circuit_is_suitable_for_establish_intro`. */
    fun hsIntroCircuitIsSuitableForEstablishIntro(purpose: String, open: Boolean): Boolean =
        open && (purpose == HsCircuit.PURPOSE_INTRO_POINT || purpose == "HS_SERVICE_INTRO")

    /** C Tor `hs_intro_new`. */
    fun hsIntroNew(authKeyHex: String, circuitIdHint: String? = null): HsIntroPointState =
        processTable.beginEstablish(authKeyHex, circuitIdHint)

    /** C Tor `hs_intro_received_establish_intro`. */
    fun hsIntroReceivedEstablishIntro(authKeyHex: String, payload: ByteArray = ByteArray(0)): Boolean {
        if (payload.isNotEmpty() && !verifyEstablishIntroCell(payload)) return false
        processTable.noteEstablished(authKeyHex)
        return true
    }

    /** C Tor `hs_intro_received_introduce1`. */
    fun hsIntroReceivedIntroduce1(authKeyHex: String): Boolean =
        handleIntroduce1(processTable, authKeyHex)

    /** C Tor `hs_intropoint_clear`. */
    fun hsIntropointClear() = processTable.clear()

    /** C Tor `validate_introduce1_parsed_cell`. */
    fun validateIntroduce1ParsedCell(payload: ByteArray): Boolean {
        // legacy_key_id(20) + AUTH_KEY_TYPE(1) + AUTH_KEYLEN(2) + auth(32) minimum
        if (payload.size < 55) return false
        val authKeyLen = ((payload[21].toInt() and 0xff) shl 8) or (payload[22].toInt() and 0xff)
        return authKeyLen in 1..64 && payload.size >= 23 + authKeyLen
    }

    /** C Tor `verify_establish_intro_cell` — structure + optional MAC/Ed25519. */
    fun verifyEstablishIntroCell(
        payload: ByteArray,
        circuitKh: ByteArray? = null,
    ): Boolean {
        val parsed = HsCell.parseEstablishIntro(payload)
        if (parsed != null) {
            if (circuitKh == null) return true // structural OK
            if (circuitKh.size != HsCell.CIRC_NONCE_LEN) return false
            val expectMac = HsCell.establishIntroMac(circuitKh, parsed.headThroughExtensions)
            if (!expectMac.contentEquals(parsed.handshakeMac)) return false
            val toVerify = HsCell.ESTABLISH_INTRO_SIG_PREFIX + parsed.headThroughExtensions + parsed.handshakeMac
            return org.kotlintor.crypto.Ed25519Keys.verify(
                parsed.authKeyPublic,
                toVerify,
                parsed.signature,
            )
        }
        // Partial cells without MAC/SIG: require AUTH_KEY_TYPE+LEN+key only (build helper path).
        val key = getAuthKeyFromCell(payload) ?: return false
        return key.any { it != 0.toByte() }
    }

    fun processTable(): HsIntroPointTable = processTable
}
