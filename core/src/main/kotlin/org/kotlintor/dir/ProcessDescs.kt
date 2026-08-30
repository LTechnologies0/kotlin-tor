package org.kotlintor.dir

import java.util.concurrent.ConcurrentHashMap

/**
 * Auth fingerprint / reject lists + descriptor admission (C Tor `process_descs.c`).
 *
 * Inventory: `L1:feature/dirauth/process_descs.c`
 *
 * Auth mode predicates live in [AuthMode].
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

        /** Process-wide fingerprint list (C Tor static `fingerprint_list`). */
        @Volatile
        private var globalList: ProcessDescs? = null

        /** C Tor `authdir_init_fingerprint_list`. */
        fun authdirInitFingerprintList(): ProcessDescs {
            val pd = ProcessDescs()
            globalList = pd
            return pd
        }

        /** C Tor `authdir_return_fingerprint_list`. */
        fun authdirReturnFingerprintList(): ProcessDescs? = globalList

        /** C Tor `dirserv_free_fingerprint_list`. */
        fun dirservFreeFingerprintList() {
            globalList = null
        }

        /** C Tor `add_rsa_fingerprint_to_dir` against the global list (creates if needed). */
        fun addRsaFingerprintToDir(fpHex: String, flags: Int): Int {
            val list = globalList ?: authdirInitFingerprintList()
            list.addRsaFingerprint(fpHex, flags)
            return 0
        }

        /** C Tor `add_ed25519_to_dir` against the global list. */
        fun addEd25519ToDir(edHex: String, flags: Int): Int {
            val list = globalList ?: authdirInitFingerprintList()
            list.addEd25519(edHex, flags)
            return 0
        }
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

    /** Instance aliases matching C Tor names. */
    fun addRsaFingerprintToDir(fpHex: String, flags: Int): Int {
        addRsaFingerprint(fpHex, flags)
        return 0
    }

    fun addEd25519ToDir(edHex: String, flags: Int): Int {
        addEd25519(edHex, flags)
        return 0
    }

    fun loadApprovedRouters(text: String) {
        for (raw in text.lineSequence()) {
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("#")) continue
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

    /** C Tor `dirserv_load_fingerprint_file` — load approved-routers text. */
    fun dirservLoadFingerprintFile(text: String): Int {
        loadApprovedRouters(text)
        return fingerprintCount()
    }

    /**
     * C Tor `dirserv_rejects_tor_version` — true if [platform] is older than [minVersion].
     * Simplified dotted numeric compare (e.g. `0.4.7.0` vs `0.4.8.0`).
     */
    fun dirservRejectsTorVersion(platform: String, minVersion: String = "0.4.8.0"): Boolean {
        fun parts(v: String): List<Int> =
            v.trim().removePrefix("Tor").trim().split(Regex("[^0-9]+"))
                .filter { it.isNotEmpty() }
                .map { it.toIntOrNull() ?: 0 }
        val a = parts(platform)
        val b = parts(minVersion)
        val n = maxOf(a.size, b.size)
        for (i in 0 until n) {
            val x = a.getOrElse(i) { 0 }
            val y = b.getOrElse(i) { 0 }
            if (x != y) return x < y
        }
        return false
    }

    /** C Tor `dirserv_router_get_status` — fingerprint status bits. */
    fun dirservRouterGetStatus(identityHex: String): Int = flagsFor(identityHex)

    /** C Tor `dirserv_router_has_valid_address`. */
    fun dirservRouterHasValidAddress(ri: Descriptor): Boolean {
        if (ri.orPort <= 0 || ri.orPort > 65535) return false
        if (ri.ip.isBlank() || ri.ip == "0.0.0.0" || ri.ip == "::") return false
        return true
    }

    /**
     * C Tor `dirserv_set_node_flags_from_authoritative_status` — store auth status bits.
     */
    fun dirservSetNodeFlagsFromAuthoritativeStatus(identityHex: String, statusBits: Int) {
        statusByDigest[identityHex.lowercase()] = statusBits
    }

    fun flagsFor(identityHex: String): Int =
        statusByDigest[identityHex.lowercase()] ?: 0

    fun wouldReject(identityHex: String): Boolean {
        val f = flagsFor(identityHex)
        return (f and RTR_REJECT) != 0 || (f and RTR_INVALID) != 0
    }

    /**
     * C Tor `authdir_wants_to_reject_router` — 1 if reject/invalid fingerprint.
     * [validOut] set false when rejected.
     */
    fun authdirWantsToRejectRouter(
        identityHex: String,
        complain: Boolean = false,
    ): Pair<Int, Boolean> {
        val reject = wouldReject(identityHex)
        if (reject && complain) {
            // measure-only; callers may log
        }
        return if (reject) 1 to false else 0 to true
    }

    /** C Tor `dirserv_would_reject_router`. */
    fun dirservWouldRejectRouter(identityHex: String): Int =
        if (wouldReject(identityHex)) 1 else 0

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

    /** C Tor `dirserv_add_descriptor`. */
    fun dirservAddDescriptor(
        ri: Descriptor,
        opts: AuthModeOptions = AuthModeOptions(authoring = true),
        source: String = "upload",
    ): Pair<Added, String?> = addDescriptor(ri, opts, source)

    /**
     * C Tor `dirserv_add_multiple_descriptors` — parse simple `nickname identity` lines.
     * Returns count of ADDED descriptors.
     */
    fun dirservAddMultipleDescriptors(
        text: String,
        purpose: Int = AuthMode.PURPOSE_GENERAL,
        source: String = "upload",
        opts: AuthModeOptions = AuthModeOptions(authoring = true),
    ): Int {
        var added = 0
        for (raw in text.lineSequence()) {
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("#")) continue
            val parts = line.split(Regex("\\s+"))
            if (parts.size < 2 || parts[1].length != 40) continue
            val ri = Descriptor(
                nickname = parts[0],
                identityHex = parts[1],
                purpose = purpose,
                body = line,
                publishedEpochSec = System.currentTimeMillis() / 1000,
            )
            if (dirservAddDescriptor(ri, opts, source).first == Added.ADDED) added++
        }
        return added
    }

    /** C Tor `dirserv_add_own_fingerprint`. */
    fun dirservAddOwnFingerprint(rsaFpHex: String, ed25519Hex: String? = null): Int {
        addRsaFingerprint(rsaFpHex, 0)
        if (ed25519Hex != null) addEd25519(ed25519Hex, 0)
        return 0
    }

    fun get(identityHex: String): Descriptor? = descriptors[identityHex.lowercase()]
    fun size(): Int = descriptors.size
    fun all(): Collection<Descriptor> = descriptors.values
    fun fingerprintCount(): Int = statusByDigest.size
}
