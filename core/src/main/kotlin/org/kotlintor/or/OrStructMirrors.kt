package org.kotlintor.or

import org.kotlintor.cell.Cell
import org.kotlintor.config.ListenSpec
import org.kotlintor.dir.DetachedSignatures
import org.kotlintor.dir.DirVote
import org.kotlintor.dir.RouterStatus
import org.kotlintor.dir.SharedRandom
import java.util.concurrent.ConcurrentHashMap

/**
 * Thin mirrors for C Tor struct types that are inventory D1/D2 nameplates.
 * Field coverage is deliberately partial (lite); raise depth via STRUCT_HINTS only to D1/D2.
 *
 * Inventory (selected L2 core/or struct rows): cached_dir_t, channel_listener_t, channel_tls_t,
 * circuit_build_times_t, conflux_leg_t, conflux_params_t, cpath_build_state_t,
 * crypt_path_reference_t, desc_store_t, destroy_cell_t, document_signature_t, entry_port_cfg_t,
 * ext_or_cmd_t, extrainfo_t, hsdir_index_t, microdesc_cache_t, networkstatus_sr_info_t,
 * networkstatus_voter_info_t, onion_handshake_state_t, or_handshake_certs_t,
 * or_handshake_state_t, packed_cell_t, port_cfg_t, relay_msg_t, server_port_cfg_t,
 * signed_descriptor_t, socks_request_t, tor_version_t, var_cell_t, vegas_params_t,
 * vote_microdesc_hash_t, vote_routerstatus_t, vote_timing_t
 */

/** C Tor `cached_dir_t` lite. */
data class CachedDir(
    val dir: String,
    val publishedMs: Long = System.currentTimeMillis(),
    val digestsSha1Hex: String? = null,
)

/** C Tor `channel_listener_t` lite — OR listener bookkeeping. */
data class ChannelListener(
    val listen: ListenSpec,
    var accepted: Long = 0,
)

/** C Tor `channel_tls_t` lite — TLS OR channel tag. */
data class ChannelTls(
    val peerHost: String,
    val peerPort: Int,
    var linkProtocol: Int = 4,
)

/** C Tor `circuit_build_times_t` lite. */
data class CircuitBuildTimes(
    var timeoutMs: Long = 60_000,
    var closeMs: Long = 60_000,
    var numCircs: Int = 0,
)

/** C Tor `conflux_leg_t` lite. */
data class ConfluxLeg(
    val circId: Long,
    var lastSeqSent: Long = 0,
    var lastSeqRecv: Long = 0,
)

/** C Tor `conflux_params_t` lite. */
data class ConfluxParams(
    val enabled: Boolean = false,
    val maxLegs: Int = 2,
    val desiredUx: Int = 0,
)

/** C Tor `cpath_build_state_t` lite. */
data class CpathBuildState(
    val desiredPathLen: Int = 3,
    val exitFingerprintHex: String? = null,
    val isInternal: Boolean = false,
)

/** C Tor `crypt_path_reference_t` lite. */
data class CryptPathReference(
    val hopIndex: Int,
    val circuitId: Long,
)

/** C Tor `desc_store_t` lite. */
class DescStore {
    private val byDigest = ConcurrentHashMap<String, String>()
    fun store(digestHex: String, body: String) {
        byDigest[digestHex.uppercase()] = body
    }
    fun lookup(digestHex: String): String? = byDigest[digestHex.uppercase()]
    fun size(): Int = byDigest.size
}

/** C Tor `destroy_cell_t` lite. */
data class DestroyCell(
    val circId: Long,
    val reason: Int = 0,
)

/** Alias mirror for C Tor `document_signature_t`. */
typealias DocumentSignature = DetachedSignatures.DocumentSignature

/** C Tor `entry_port_cfg_t` / `port_cfg_t` / `server_port_cfg_t` lite. */
data class PortCfg(
    val listen: ListenSpec,
    val isolationFlags: Int = 0,
    val sessionGroup: Int = 0,
    val isServer: Boolean = false,
)

typealias EntryPortCfg = PortCfg
typealias ServerPortCfg = PortCfg

/** C Tor `ext_or_cmd_t` lite. */
data class ExtOrCmd(
    val command: String,
    val body: String = "",
)

/** C Tor `extrainfo_t` lite. */
data class ExtraInfo(
    val nickname: String,
    val identityHex: String,
    val body: String,
)

/** C Tor `hsdir_index_t` lite. */
data class HsDirIndex(
    val first: ByteArray,
    val second: ByteArray,
) {
    override fun equals(other: Any?): Boolean =
        other is HsDirIndex && first.contentEquals(other.first) && second.contentEquals(other.second)
    override fun hashCode(): Int = first.contentHashCode() xor second.contentHashCode()
}

/** C Tor `microdesc_cache_t` lite. */
class MicrodescCache {
    private val byDigest = ConcurrentHashMap<String, String>()
    fun put(digestHex: String, body: String) {
        byDigest[digestHex.lowercase()] = body
    }
    fun get(digestHex: String): String? = byDigest[digestHex.lowercase()]
    fun size(): Int = byDigest.size
}

/** C Tor `networkstatus_sr_info_t` lite. */
data class NetworkstatusSrInfo(
    val current: SharedRandom.Srv? = null,
    val previous: SharedRandom.Srv? = null,
)

/** C Tor `networkstatus_voter_info_t` lite. */
data class NetworkstatusVoterInfo(
    val nickname: String,
    val identityHex: String,
    val address: String,
    val dirPort: Int,
    val orPort: Int,
)

/** C Tor `onion_handshake_state_t` lite. */
data class OnionHandshakeState(
    val circId: Long,
    val handshakeType: Int,
    val state: ByteArray = ByteArray(0),
) {
    override fun equals(other: Any?): Boolean =
        other is OnionHandshakeState && circId == other.circId && handshakeType == other.handshakeType &&
            state.contentEquals(other.state)
    override fun hashCode(): Int = circId.hashCode() xor handshakeType xor state.contentHashCode()
}

/** C Tor `or_handshake_certs_t` lite. */
data class OrHandshakeCerts(
    val idCert: ByteArray? = null,
    val authCert: ByteArray? = null,
    val linkCert: ByteArray? = null,
) {
    override fun equals(other: Any?): Boolean =
        other is OrHandshakeCerts &&
            idCert.contentEq(other.idCert) &&
            authCert.contentEq(other.authCert) &&
            linkCert.contentEq(other.linkCert)
    override fun hashCode(): Int =
        (idCert?.contentHashCode() ?: 0) xor (authCert?.contentHashCode() ?: 0) xor
            (linkCert?.contentHashCode() ?: 0)
}

private fun ByteArray?.contentEq(other: ByteArray?): Boolean =
    when {
        this == null && other == null -> true
        this == null || other == null -> false
        else -> contentEquals(other)
    }

/** C Tor `or_handshake_state_t` lite. */
data class OrHandshakeState(
    var receivedVersions: Boolean = false,
    var receivedCerts: Boolean = false,
    var receivedAuthChallenge: Boolean = false,
    var receivedNetinfo: Boolean = false,
    var startedHere: Boolean = true,
)

/** C Tor `packed_cell_t` lite — queued encoded cell bytes. */
data class PackedCell(
    val body: ByteArray,
    val insertedMs: Long = System.currentTimeMillis(),
) {
    override fun equals(other: Any?): Boolean =
        other is PackedCell && body.contentEquals(other.body)
    override fun hashCode(): Int = body.contentHashCode()
}

/** C Tor `relay_msg_t` lite — decoded relay message. */
data class RelayMsg(
    val command: Int,
    val streamId: Int,
    val length: Int,
    val body: ByteArray,
) {
    override fun equals(other: Any?): Boolean =
        other is RelayMsg && command == other.command && streamId == other.streamId &&
            length == other.length && body.contentEquals(other.body)
    override fun hashCode(): Int =
        command xor streamId xor length xor body.contentHashCode()
}

/** C Tor `signed_descriptor_t` lite. */
data class SignedDescriptor(
    val body: String,
    val identityHex: String,
    val publishedMs: Long = 0,
)

/** C Tor `socks_request_t` lite. */
data class SocksRequest(
    val command: Int,
    val host: String,
    val port: Int,
    val username: String? = null,
    val password: String? = null,
)

/** C Tor `tor_version_t` lite. */
data class TorVersion(
    val major: Int,
    val minor: Int,
    val micro: Int,
    val status: String = "stable",
) {
    override fun toString(): String = "$major.$minor.$micro-$status"
    companion object {
        fun parse(s: String): TorVersion? {
            val m = Regex("""(\d+)\.(\d+)\.(\d+)(?:-(\w+))?""").matchEntire(s.trim()) ?: return null
            return TorVersion(
                m.groupValues[1].toInt(),
                m.groupValues[2].toInt(),
                m.groupValues[3].toInt(),
                m.groupValues[4].ifEmpty { "stable" },
            )
        }
    }
}

/** C Tor `var_cell_t` lite — variable-length cell wrapper. */
data class VarCell(
    val circId: Long,
    val command: Int,
    val payload: ByteArray,
) {
    fun toCell(cmd: org.kotlintor.cell.CellCommand): Cell = Cell(circId, cmd, payload)
    override fun equals(other: Any?): Boolean =
        other is VarCell && circId == other.circId && command == other.command &&
            payload.contentEquals(other.payload)
    override fun hashCode(): Int = circId.hashCode() xor command xor payload.contentHashCode()
}

/** C Tor `vegas_params_t` lite. */
data class VegasParams(
    val alpha: Int = 3 * 31,
    val beta: Int = 4 * 31,
    val delta: Int = 5 * 31,
    val gamma: Int = 3 * 31,
    val ssCap: Int = 5_000,
)

/** C Tor `vote_microdesc_hash_t` lite. */
data class VoteMicrodescHash(
    val method: Int,
    val digestHex: String,
)

/** C Tor `vote_routerstatus_t` lite. */
data class VoteRouterstatus(
    val status: RouterStatus,
    val flags: Set<String> = emptySet(),
    val measuredBw: Int? = null,
)

/** C Tor `vote_timing_t` → [DirVote.Timing]. */
typealias VoteTiming = DirVote.Timing

/** C Tor `control_cmd_args_t` lite. */
data class ControlCmdArgs(
    val keywords: Map<String, String> = emptyMap(),
    val args: List<String> = emptyList(),
    val rawBody: String? = null,
)
