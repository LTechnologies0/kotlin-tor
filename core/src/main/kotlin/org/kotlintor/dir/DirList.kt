package org.kotlintor.dir

/**
 * Trusted / fallback directory server list (C Tor `dirlist.c` / `dir_server_t`).
 *
 * Mirrors digests, addr trust, auth DirPorts (exact + legacy), and mark-all-up.
 * Inventory: `L1:feature/nodelist/dirlist.c`, `L2:core/or/dir_server_t`
 */
data class DirServer(
    val nickname: String,
    val address: String,
    val dirPort: Int,
    val orPort: Int,
    /** v3 authority identity (hex) when this is a dirauth. */
    val v3IdentityHex: String? = null,
    /** RSA identity digest hex (optional). */
    val identityHex: String? = null,
    val isAuthority: Boolean = false,
    val isFallback: Boolean = false,
    val weight: Double = 1.0,
    /** C Tor `dir_server_t.is_running`. */
    var isRunning: Boolean = true,
    /**
     * Extra auth DirPorts: usage → list of (host, port) in insertion order.
     * Usage strings: `legacy`, `begin_dir`, `upload`, etc.
     */
    val authDirports: MutableList<AuthDirPort> = mutableListOf(),
) {
    data class AuthDirPort(val usage: String, val host: String, val port: Int)

    fun dirPortPair(): Pair<String, Int> = address to dirPort
    fun orPortPair(): Pair<String, Int> = address to orPort

    /** C Tor `trusted_dir_server_add_dirport`. */
    fun addDirport(usage: String, host: String, port: Int) {
        if (!isAuthority) return
        authDirports += AuthDirPort(usage.lowercase(), host, port)
    }

    /**
     * C Tor `trusted_dir_server_get_dirport_exact` —
     * first port matching [usage] and IPv6-ness of [preferIpv6].
     */
    fun getDirportExact(usage: String, preferIpv6: Boolean = false): Pair<String, Int>? {
        val u = usage.lowercase()
        return authDirports.firstOrNull { p ->
            p.usage == u && p.host.contains(':') == preferIpv6
        }?.let { it.host to it.port }
    }

    /**
     * C Tor `trusted_dir_server_get_dirport` — try [usage], then `legacy`.
     * No fallback to primary [dirPort] (C Tor only walks auth_dirports).
     */
    fun getDirport(usage: String, preferIpv6: Boolean = false): Pair<String, Int>? {
        getDirportExact(usage, preferIpv6)?.let { return it }
        if (!usage.equals("legacy", true)) {
            getDirportExact("legacy", preferIpv6)?.let { return it }
        }
        return null
    }
}

class DirList {
    private val trusted = ArrayList<DirServer>()
    /** Non-authority fallback dirs only; authorities appear via [fallbacks]. */
    private val fallbackOnly = ArrayList<DirServer>()

    fun trusted(): List<DirServer> = trusted.toList()
    /** C Tor `router_get_fallback_dir_servers` — includes authorities. */
    fun fallbacks(): List<DirServer> = trusted + fallbackOnly
    fun all(): List<DirServer> = trusted + fallbackOnly
    fun size(): Int = trusted.size + fallbackOnly.size
    fun authorityCount(): Int = trusted.size

    fun removeByIdentity(hex: String): Boolean {
        val key = hex.uppercase()
        val before = size()
        trusted.removeAll {
            it.identityHex?.uppercase() == key || it.v3IdentityHex?.uppercase() == key
        }
        fallbackOnly.removeAll {
            it.identityHex?.uppercase() == key || it.v3IdentityHex?.uppercase() == key
        }
        return size() < before
    }

    fun clear() {
        trusted.clear()
        fallbackOnly.clear()
    }

    /** C Tor `clear_dir_servers` / `dirlist_free_all`. */
    fun clearDirServers() = clear()

    fun add(server: DirServer) {
        when {
            server.isAuthority -> {
                trusted.removeAll { sameKey(it, server) }
                trusted += server
            }
            server.isFallback -> {
                fallbackOnly.removeAll { sameKey(it, server) }
                fallbackOnly += server
            }
            else -> {
                fallbackOnly.removeAll { sameKey(it, server) }
                fallbackOnly += server.copy(isFallback = true)
            }
        }
    }

    fun trustedByV3Digest(hex: String): DirServer? {
        val key = hex.uppercase()
        return trusted.firstOrNull { it.v3IdentityHex?.uppercase() == key }
    }

    fun byIdentity(hex: String): DirServer? {
        val key = hex.uppercase()
        return all().firstOrNull {
            it.identityHex?.uppercase() == key || it.v3IdentityHex?.uppercase() == key
        }
    }

    /** C Tor `router_get_trusteddirserver_by_digest` (RSA id hex). */
    fun trustedByDigest(hex: String): DirServer? {
        val key = hex.uppercase()
        return trusted.firstOrNull { it.identityHex?.uppercase() == key }
    }

    /** C Tor `router_digest_is_trusted_dir` (RSA id hex only). */
    fun digestIsTrusted(hex: String): Boolean = trustedByDigest(hex) != null

    /** C Tor `router_digest_is_fallback_dir` (RSA id hex only). */
    fun digestIsFallback(hex: String): Boolean {
        val key = hex.uppercase()
        return fallbacks().any { it.identityHex?.uppercase() == key }
    }

    /** C Tor `router_get_fallback_dirserver_by_digest`. */
    fun fallbackByDigest(hex: String): DirServer? {
        val key = hex.uppercase()
        return fallbacks().firstOrNull { it.identityHex?.uppercase() == key }
    }

    /** C Tor `router_addr_is_trusted_dir`. */
    fun addrIsTrusted(address: String): Boolean =
        trusted.any { it.address.equals(address, ignoreCase = true) }

    /** C Tor `mark_all_dirservers_up`. */
    fun markAllUp(includeFallbacks: Boolean = true) {
        trusted.forEach { it.isRunning = true }
        if (includeFallbacks) fallbackOnly.forEach { it.isRunning = true }
    }

    fun loadDefaults(
        authorities: List<DirectoryAuthority> = DefaultAuthorities.ALL,
        extraFallbacks: List<DirServer> = emptyList(),
    ) {
        clear()
        for (a in authorities) {
            add(
                DirServer(
                    nickname = a.nickname,
                    address = a.address,
                    dirPort = a.dirPort,
                    orPort = a.orPort,
                    v3IdentityHex = a.v3Ident,
                    isAuthority = true,
                ),
            )
        }
        for (f in extraFallbacks) add(f.copy(isFallback = true, isAuthority = false))
    }

    /** Parse torrc `FallbackDir` / `DirAuthority` style: addr:dirport orPort=N [id=HEX] [weight=W] nickname? */
    fun parseFallbackLine(line: String): DirServer? {
        val toks = line.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }
        if (toks.isEmpty()) return null
        val addrPort = toks[0]
        val host = addrPort.substringBeforeLast(':')
        val dirPort = addrPort.substringAfterLast(':').toIntOrNull() ?: return null
        var orPort = dirPort
        var id: String? = null
        var weight = 1.0
        var nick = "fallback"
        for (t in toks.drop(1)) {
            when {
                t.startsWith("orport=", true) -> orPort = t.substringAfter('=').toIntOrNull() ?: orPort
                t.startsWith("id=", true) -> id = t.substringAfter('=').uppercase()
                t.startsWith("weight=", true) -> weight = t.substringAfter('=').toDoubleOrNull() ?: weight
                !t.contains('=') -> nick = t
            }
        }
        return DirServer(
            nickname = nick,
            address = host,
            dirPort = dirPort,
            orPort = orPort,
            identityHex = id,
            v3IdentityHex = null,
            isFallback = true,
            weight = weight,
        )
    }

    private fun sameKey(a: DirServer, b: DirServer): Boolean {
        if (a.v3IdentityHex != null && b.v3IdentityHex != null) {
            return a.v3IdentityHex.equals(b.v3IdentityHex, true)
        }
        if (a.identityHex != null && b.identityHex != null) {
            return a.identityHex.equals(b.identityHex, true)
        }
        return a.address == b.address && a.dirPort == b.dirPort
    }

    companion object {
        private val process = DirList()

        fun processList(): DirList = process

        fun withDefaults(): DirList = DirList().also { it.loadDefaults() }

        /** C Tor `trusted_dir_server_new` constructor helper. */
        fun trustedDirServerNew(
            nickname: String,
            address: String,
            dirPort: Int,
            orPort: Int,
            v3IdentityHex: String?,
            identityHex: String? = null,
        ): DirServer =
            DirServer(
                nickname = nickname,
                address = address,
                dirPort = dirPort,
                orPort = orPort,
                v3IdentityHex = v3IdentityHex,
                identityHex = identityHex,
                isAuthority = true,
            )

        /** C Tor `fallback_dir_server_new` constructor helper. */
        fun fallbackDirServerNew(
            address: String,
            dirPort: Int,
            orPort: Int,
            identityHex: String?,
            weight: Double = 1.0,
            nickname: String = "fallback",
        ): DirServer =
            DirServer(
                nickname = nickname,
                address = address,
                dirPort = dirPort,
                orPort = orPort,
                identityHex = identityHex,
                v3IdentityHex = null,
                isFallback = true,
                weight = weight,
            )

        /**
         * C Tor `auth_dirport_usage_for_purpose` —
         * map connection purpose → auth DirPort usage label.
         */
        fun authDirportUsageForPurpose(purpose: String): String =
            when (purpose.lowercase()) {
                "fetch", "download", "fetch_serverdesc", "fetch_extrainfo",
                "fetch_consensus", "fetch_certificate", "fetch_microdesc",
                -> "download"
                "upload", "upload_dir", "post" -> "upload"
                "vote", "upload_vote", "upload_signatures",
                "fetch_detached_signatures", "fetch_status_vote",
                -> "voting"
                else -> "legacy"
            }

        /** C Tor `clear_dir_servers`. */
        fun clearDirServers() = process.clearDirServers()

        /** C Tor `dirlist_free_all`. */
        fun dirlistFreeAll() = process.clearDirServers()

        /** C Tor `dir_server_add`. */
        fun dirServerAdd(server: DirServer) = process.add(server)

        /** C Tor `fallback_dir_server_new` then add. */
        fun fallbackDirServerNewAndAdd(
            address: String,
            dirPort: Int,
            orPort: Int,
            identityHex: String?,
            weight: Double = 1.0,
            nickname: String = "fallback",
        ): DirServer {
            val s = fallbackDirServerNew(address, dirPort, orPort, identityHex, weight, nickname)
            process.add(s)
            return s
        }

        /** C Tor `get_n_authorities`. */
        fun getNAuthorities(): Int = process.authorityCount()

        /** C Tor `mark_all_dirservers_up`. */
        fun markAllDirserversUp(includeFallbacks: Boolean = true) =
            process.markAllUp(includeFallbacks)
    }
}
