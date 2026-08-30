package org.kotlintor.dir

/**
 * Router / node list index (C Tor `nodelist.c`).
 *
 * Inventory: `L1:feature/nodelist/nodelist.c`
 *
 * Implementation: [RouterList].
 */
object NodeList {
    private val process = RouterList()
    @Volatile private var loadingHave: Int = 0
    @Volatile private var loadingWant: Int = 0

    fun create(): RouterList = RouterList()

    fun processList(): RouterList = process

    /** C Tor `count_loading_descriptors_progress` — 0..100. */
    fun countLoadingDescriptorsProgress(have: Int = loadingHave, want: Int = loadingWant): Int {
        if (want <= 0) return 100
        return ((have.coerceAtLeast(0).toDouble() / want) * 100.0).toInt().coerceIn(0, 100)
    }

    fun noteLoadingProgress(have: Int, want: Int) {
        loadingHave = have
        loadingWant = want
    }

    /** C Tor `get_dir_info_status_string`. */
    fun getDirInfoStatusString(): String =
        "have=${loadingHave} want=${loadingWant} pct=${countLoadingDescriptorsProgress()}"

    /** C Tor `link_specifier_smartlist_free_`. */
    fun linkSpecifierSmartlistFree_(specs: List<ByteArray>?): List<ByteArray>? = null

    /** C Tor `node_describe`. */
    fun nodeDescribe(rs: RouterStatus): String = Describe.routerStatus(rs)

    /** C Tor `node_get_addr` / address string. */
    fun nodeGetAddr(rs: RouterStatus): String = rs.ip

    fun nodeGetAddressString(rs: RouterStatus): String = "${rs.ip}:${rs.orPort}"

    /** C Tor `node_get_all_orports`. */
    fun nodeGetAllOrports(rs: RouterStatus): List<Pair<String, Int>> =
        listOf(rs.ip to rs.orPort)

    /** C Tor `node_get_by_hex_id`. */
    fun nodeGetByHexId(hex: String): RouterStatus? = process.byFingerprint(hex)

    /** C Tor `node_get_nickname`. */
    fun nodeGetNickname(rs: RouterStatus): String = rs.nickname

    /** C Tor `node_get_platform`. */
    fun nodeGetPlatform(rs: RouterStatus): String? = rs.version

    /** C Tor `node_get_pref_orport` / prim. */
    fun nodeGetPrefOrport(rs: RouterStatus): Pair<String, Int> = rs.ip to rs.orPort

    fun nodeGetPrimOrport(rs: RouterStatus): Pair<String, Int> = nodeGetPrefOrport(rs)

    fun nodeGetPrefDirport(rs: RouterStatus): Pair<String, Int> = rs.ip to rs.dirPort

    fun nodeGetPrimDirport(rs: RouterStatus): Pair<String, Int> = nodeGetPrefDirport(rs)

    fun nodeGetPrefIpv6Orport(rs: RouterStatus): Pair<String, Int>? = null

    fun nodeGetPrefIpv6Dirport(rs: RouterStatus): Pair<String, Int>? = null

    /** C Tor `node_get_rsa_id_digest`. */
    fun nodeGetRsaIdDigest(rs: RouterStatus): ByteArray = rs.identity

    /** C Tor `node_get_curve25519_onion_key`. */
    fun nodeGetCurve25519OnionKey(rs: RouterStatus): ByteArray? = rs.ntorOnionKey

    /** C Tor `node_ed25519_id_matches`. */
    fun nodeEd25519IdMatches(rs: RouterStatus, ed: ByteArray): Boolean =
        rs.ed25519Identity?.contentEquals(ed) == true

    /** C Tor `node_allows_single_hop_exits`. */
    fun nodeAllowsSingleHopExits(rs: RouterStatus): Boolean = false

    /** C Tor `node_get_purpose`. */
    fun nodeGetPurpose(rs: RouterStatus): String = "general"

    /** C Tor `node_get_declared_uptime`. */
    fun nodeGetDeclaredUptime(rs: RouterStatus): Long = 0L

    /** C Tor `node_get_mutable_by_ed25519_id`. */
    fun nodeGetMutableByEd25519Id(edHex: String): RouterStatus? {
        val want = edHex.lowercase()
        return process.all().firstOrNull { rs ->
            rs.ed25519Identity?.joinToString("") { "%02x".format(it) } == want
        }
    }

    /** C Tor `node_family_list_contains`. */
    fun nodeFamilyListContains(familyLine: String, fingerprintHex: String): Boolean =
        familyLine.contains(fingerprintHex, ignoreCase = true)
}
