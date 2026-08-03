package org.kotlintor.dir

import java.util.concurrent.ConcurrentHashMap

/**
 * Directory authority mode predicates (C Tor `authmode.c` / `authmode.h`).
 */
data class AuthModeOptions(
    val authoring: Boolean = false,
    val v3: Boolean = true,
    val bridgeAuthority: Boolean = false,
    val publishStatuses: Boolean = true,
    val testReachability: Boolean = true,
    val handleDescriptors: Boolean = true,
)

object AuthMode {
    fun isAuthority(opts: AuthModeOptions): Boolean = opts.authoring
    fun isV3(opts: AuthModeOptions): Boolean = opts.authoring && opts.v3
    fun isBridge(opts: AuthModeOptions): Boolean = opts.authoring && opts.bridgeAuthority
    fun handlesDescs(opts: AuthModeOptions, purpose: Int = PURPOSE_GENERAL): Boolean {
        if (!opts.authoring || !opts.handleDescriptors) return false
        if (opts.bridgeAuthority) return purpose == PURPOSE_BRIDGE
        return purpose == PURPOSE_GENERAL || purpose == PURPOSE_BRIDGE
    }
    fun publishesStatuses(opts: AuthModeOptions): Boolean =
        opts.authoring && opts.publishStatuses
    fun testsReachability(opts: AuthModeOptions): Boolean =
        opts.authoring && opts.testReachability

    const val PURPOSE_GENERAL: Int = 0
    const val PURPOSE_BRIDGE: Int = 1
}

/**
 * Auth fingerprint / reject lists + descriptor admission (C Tor `process_descs.c` lite).
 */
class ProcessDescs {
    companion object {
        const val RTR_INVALID: Int = 2
        const val RTR_REJECT: Int = 4
        const val RTR_BADEXIT: Int = 16
        const val RTR_MIDDLEONLY: Int = 32
        const val RTR_STRIPGUARD: Int = 64
        const val RTR_STRIPHSDIR: Int = 128
        const val RTR_STRIPV2DIR: Int = 256
    }

    enum class Added {
        ADDED,
        REJECTED,
        ALREADY,
        IGNORED,
    }

    data class Descriptor(
        val nickname: String,
        val identityHex: String,
        val ed25519Hex: String? = null,
        val ip: String = "0.0.0.0",
        val orPort: Int = 0,
        val publishedEpochSec: Long = 0,
        val bandwidthKb: Int = 0,
        val purpose: Int = AuthMode.PURPOSE_GENERAL,
        val hibernating: Boolean = false,
        val body: String = "",
    )

    private val statusByDigest = ConcurrentHashMap<String, Int>()
    private val fpByName = ConcurrentHashMap<String, String>()
    private val descriptors = ConcurrentHashMap<String, Descriptor>()

    fun addRsaFingerprint(fpHex: String, flags: Int) {
        statusByDigest[fpHex.lowercase()] = flags
    }

    fun addEd25519(edHex: String, flags: Int) {
        statusByDigest["ed:" + edHex.lowercase()] = flags
    }

    fun loadApprovedRouters(text: String) {
        for (raw in text.lineSequence()) {
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("#")) continue
            // !reject / !badexit / !invalid fingerprint  OR  nickname fingerprint
            val parts = line.split(Regex("\\s+"))
            when {
                parts[0].equals("!reject", true) && parts.size >= 2 ->
                    addRsaFingerprint(parts[1], RTR_REJECT)
                parts[0].equals("!badexit", true) && parts.size >= 2 ->
                    addRsaFingerprint(parts[1], RTR_BADEXIT)
                parts[0].equals("!invalid", true) && parts.size >= 2 ->
                    addRsaFingerprint(parts[1], RTR_INVALID)
                parts[0].equals("!middleonly", true) && parts.size >= 2 ->
                    addRsaFingerprint(parts[1], RTR_MIDDLEONLY)
                parts.size >= 2 && parts[1].length == 40 -> {
                    fpByName[parts[0].lowercase()] = parts[1].lowercase()
                    addRsaFingerprint(parts[1], 0)
                }
            }
        }
    }

    fun flagsFor(identityHex: String): Int =
        statusByDigest[identityHex.lowercase()] ?: 0

    fun wouldReject(identityHex: String): Boolean {
        val f = flagsFor(identityHex)
        return (f and RTR_REJECT) != 0 || (f and RTR_INVALID) != 0
    }

    fun addDescriptor(
        ri: Descriptor,
        opts: AuthModeOptions = AuthModeOptions(authoring = true),
        source: String = "upload",
    ): Pair<Added, String?> {
        if (!AuthMode.handlesDescs(opts, ri.purpose)) {
            return Added.IGNORED to "not handling this purpose"
        }
        if (wouldReject(ri.identityHex)) {
            return Added.REJECTED to "fingerprint rejected"
        }
        val named = fpByName[ri.nickname.lowercase()]
        if (named != null && !named.equals(ri.identityHex, ignoreCase = true)) {
            return Added.REJECTED to "nickname/fingerprint mismatch"
        }
        val id = ri.identityHex.lowercase()
        val prev = descriptors[id]
        if (prev != null && prev.publishedEpochSec >= ri.publishedEpochSec &&
            prev.body == ri.body
        ) {
            return Added.ALREADY to null
        }
        descriptors[id] = ri
        return Added.ADDED to null
    }

    fun get(identityHex: String): Descriptor? = descriptors[identityHex.lowercase()]
    fun size(): Int = descriptors.size
    fun all(): Collection<Descriptor> = descriptors.values
}
