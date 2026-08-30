package org.kotlintor.circuit

import java.util.ArrayDeque

/**
 * Circuit/stream SENDME windows and authenticated v1 cells (C Tor `sendme.c`).
 *
 * Inventory: `L1:core/or/sendme.c`
 *
 * C Tor APIs: `sendme_is_valid`, `build_cell_payload_v1`,
 * `sendme_circuit_data_received`, `sendme_note_circuit_data_packaged`,
 * `sendme_record_cell_digest_on_circ`, stream window helpers.
 */
object Sendme {
    const val MAX_SUPPORTED_VERSION: Int = 1
    const val CIRCWINDOW_START: Int = 1000
    const val CIRCWINDOW_INCREMENT: Int = 100
    const val STREAMWINDOW_START: Int = 500
    const val STREAMWINDOW_INCREMENT: Int = 50

    /** Tor1 digest tag length; CGO uses 16. */
    const val DIGEST_LEN_TOR1: Int = 20
    const val DIGEST_LEN_CGO: Int = 16

    @Volatile var emitMinVersion: Int = 1
    @Volatile var acceptMinVersion: Int = 0

    /** C Tor `get_emit_min_version` / consensus `sendme_emit_min_version`. */
    fun emitMinVersionResolved(): Int = emitMinVersion.coerceIn(0, 255)

    /** C Tor `get_accept_min_version` / consensus `sendme_accept_min_version`. */
    fun acceptMinVersionResolved(): Int = acceptMinVersion.coerceIn(0, 255)

    fun newConsensusParams(ns: Map<String, Long>) {
        fun p(name: String, dflt: Long, min: Long, max: Long): Int =
            (ns[name] ?: dflt).coerceIn(min, max).toInt()
        emitMinVersion = p("sendme_emit_min_version", 1, 0, 255)
        acceptMinVersion = p("sendme_accept_min_version", 0, 0, 255)
    }

    /** C Tor `cell_version_can_be_handled`. */
    fun cellVersionCanBeHandled(cellVersion: Int): Boolean {
        val accept = acceptMinVersionResolved()
        if (accept > MAX_SUPPORTED_VERSION) return false
        if (cellVersion < accept) return false
        if (cellVersion > MAX_SUPPORTED_VERSION) return false
        return true
    }

    fun tagLenOk(tagLen: Int): Boolean =
        tagLen == DIGEST_LEN_TOR1 || tagLen == DIGEST_LEN_CGO

    /**
     * C Tor `build_cell_payload_v1` — version(1) + data_len(u16be) + digest.
     * Matches existing [buildSendmeV1] layout used on the wire.
     */
    fun buildCellPayloadV1(cellTag: ByteArray): ByteArray {
        require(tagLenOk(cellTag.size)) { "SENDME tag length ${cellTag.size}" }
        return byteArrayOf(
            0x01,
            ((cellTag.size ushr 8) and 0xff).toByte(),
            (cellTag.size and 0xff).toByte(),
        ) + cellTag
    }

    /** Parse SENDME payload; empty ⇒ version 0. */
    data class ParsedCell(val version: Int, val digest: ByteArray?)

    fun parseCell(payload: ByteArray): ParsedCell {
        if (payload.isEmpty()) return ParsedCell(0, null)
        val version = payload[0].toInt() and 0xff
        if (version == 0) return ParsedCell(0, null)
        if (payload.size < 3) return ParsedCell(version, null)
        val len = ((payload[1].toInt() and 0xff) shl 8) or (payload[2].toInt() and 0xff)
        if (payload.size < 3 + len) return ParsedCell(version, null)
        return ParsedCell(version, payload.copyOfRange(3, 3 + len))
    }

    /**
     * C Tor `sendme_is_valid` (digest queue pop + v0/v1 rules).
     * @return true if the cell is acceptable; pops matching digest on v1 success.
     */
    fun isValid(circDigests: DigestQueue, payload: ByteArray): Boolean {
        val cell = parseCell(payload)
        if (!cellVersionCanBeHandled(cell.version)) return false
        if (cell.version == 0) return true
        if (cell.version != 1) return false
        val expected = circDigests.popFirst() ?: return false
        val got = cell.digest ?: return false
        if (got.size != expected.size) return false
        return got.contentEquals(expected)
    }

    /** C Tor `sendme_circuit_data_received` — returns SENDME payload if due. */
    fun circuitDataReceived(
        deliverWindow: Int,
        lastDigest: ByteArray?,
        increment: Int = CIRCWINDOW_INCREMENT,
    ): Pair<Int, ByteArray?> {
        val next = deliverWindow - 1
        check(next >= 0) { "circuit deliver window underflow" }
        if (next % increment == 0 && lastDigest != null && tagLenOk(lastDigest.size)) {
            return next to emitPayload(lastDigest)
        }
        return next to null
    }

    /** C Tor emit path — version from consensus. */
    fun emitPayload(cellTag: ByteArray): ByteArray =
        when (emitMinVersionResolved()) {
            1 -> buildCellPayloadV1(cellTag)
            else -> ByteArray(0) // v0
        }

    /** C Tor `sendme_note_circuit_data_packaged` — returns new package window. */
    fun noteCircuitDataPackaged(packageWindow: Int): Int {
        check(packageWindow > 0) { "circuit package window underflow" }
        return packageWindow - 1
    }

    /** C Tor circuit-level SENDME processed — bump package window. */
    fun processCircuitLevel(packageWindow: Int, increment: Int = CIRCWINDOW_INCREMENT): Int =
        packageWindow + increment

    /** C Tor `sendme_stream_data_received`. */
    fun streamDataReceived(deliverWindow: Int): Pair<Int, Boolean> {
        val next = deliverWindow - 1
        check(next >= 0) { "stream deliver window underflow" }
        val sendmeDue = next % STREAMWINDOW_INCREMENT == 0
        return next to sendmeDue
    }

    fun noteStreamDataPackaged(packageWindow: Int, len: Int = 1): Int {
        val next = packageWindow - len
        check(next >= 0) { "stream package window underflow" }
        return next
    }

    fun processStreamLevel(packageWindow: Int): Int =
        packageWindow + STREAMWINDOW_INCREMENT

    /** C Tor-named aliases for SENDME window ops. */
    fun sendmeIsValid(circDigests: DigestQueue, payload: ByteArray): Boolean =
        isValid(circDigests, payload)

    fun sendmeCircuitDataReceived(
        deliverWindow: Int,
        lastDigest: ByteArray?,
        increment: Int = CIRCWINDOW_INCREMENT,
    ): Pair<Int, ByteArray?> = circuitDataReceived(deliverWindow, lastDigest, increment)

    fun sendmeNoteCircuitDataPackaged(packageWindow: Int): Int =
        noteCircuitDataPackaged(packageWindow)

    fun sendmeProcessCircuitLevel(packageWindow: Int, increment: Int = CIRCWINDOW_INCREMENT): Int =
        processCircuitLevel(packageWindow, increment)

    fun sendmeProcessCircuitLevelImpl(packageWindow: Int, increment: Int = CIRCWINDOW_INCREMENT): Int =
        processCircuitLevel(packageWindow, increment)

    fun sendmeStreamDataReceived(deliverWindow: Int): Pair<Int, Boolean> =
        streamDataReceived(deliverWindow)

    fun sendmeNoteStreamDataPackaged(packageWindow: Int, len: Int = 1): Int =
        noteStreamDataPackaged(packageWindow, len)

    fun sendmeProcessStreamLevel(packageWindow: Int): Int = processStreamLevel(packageWindow)

    fun sendmeRecordCellDigestOnCirc(q: DigestQueue, digest: ByteArray) = q.record(digest)

    fun sendmeCircuitConsiderSending(deliverWindow: Int): Boolean =
        deliverWindow > 0 && deliverWindow % CIRCWINDOW_INCREMENT == 0

    fun sendmeConnectionEdgeConsiderSending(deliverWindow: Int): Boolean =
        deliverWindow > 0 && deliverWindow % STREAMWINDOW_INCREMENT == 0

    /** Expected SENDME digests (C Tor `sendme_record_cell_digest_on_circ` queue). */
    class DigestQueue(private val max: Int = 64) {
        private val q = ArrayDeque<ByteArray>()

        fun record(digest: ByteArray) {
            val tag = Sendme.normalizeSendmeTag(digest) ?: return
            if (q.size >= max) q.removeFirst()
            q.addLast(tag)
        }

        fun popFirst(): ByteArray? = if (q.isEmpty()) null else q.removeFirst()

        fun size(): Int = q.size

        fun clear() = q.clear()
    }

    /** Truncate/accept digests to tor1 (20) or CGO (16) SENDME tag lengths. */
    fun normalizeSendmeTag(digest: ByteArray): ByteArray? = when {
        digest.size == DIGEST_LEN_CGO -> digest.copyOf()
        digest.size >= DIGEST_LEN_TOR1 -> digest.copyOf(DIGEST_LEN_TOR1)
        else -> null
    }
}

/** Wire helper — tor1 (20) or CGO (16) SENDME tags. */
fun buildSendmeV1(digest: ByteArray): ByteArray {
    val tag = Sendme.normalizeSendmeTag(digest)
        ?: error("SENDME tag length ${digest.size}; need 16 (CGO) or ≥20 (tor1)")
    return Sendme.buildCellPayloadV1(tag)
}
