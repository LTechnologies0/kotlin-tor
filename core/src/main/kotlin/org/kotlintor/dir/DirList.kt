package org.kotlintor.dir

/**
 * Trusted / fallback directory server list (C Tor `dirlist.c` / `dir_server_t` lite).
 *
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
) {
    fun dirPortPair(): Pair<String, Int> = address to dirPort
    fun orPortPair(): Pair<String, Int> = address to orPort
}

class DirList {
    private val trusted = ArrayList<DirServer>()
    private val fallbacks = ArrayList<DirServer>()

    fun trusted(): List<DirServer> = trusted.toList()
    fun fallbacks(): List<DirServer> = fallbacks.toList()
    fun all(): List<DirServer> = trusted + fallbacks
    fun size(): Int = trusted.size + fallbacks.size

    fun removeByIdentity(hex: String): Boolean {
        val key = hex.uppercase()
        val before = size()
        trusted.removeAll {
            it.identityHex?.uppercase() == key || it.v3IdentityHex?.uppercase() == key
        }
        fallbacks.removeAll {
            it.identityHex?.uppercase() == key || it.v3IdentityHex?.uppercase() == key
        }
        return size() < before
    }

    fun clear() {
        trusted.clear()
        fallbacks.clear()
    }

    fun add(server: DirServer) {
        when {
            server.isAuthority -> {
                trusted.removeAll { sameKey(it, server) }
                trusted += server
            }
            server.isFallback -> {
                fallbacks.removeAll { sameKey(it, server) }
                fallbacks += server
            }
            else -> {
                fallbacks.removeAll { sameKey(it, server) }
                fallbacks += server.copy(isFallback = true)
            }
        }
    }

    fun trustedByV3Digest(hex: String): DirServer? {
        val key = hex.uppercase()
        return trusted.firstOrNull { it.v3IdentityHex?.uppercase() == key }
    }

    fun byIdentity(hex: String): DirServer? {
        val key = hex.uppercase()
        return (trusted + fallbacks).firstOrNull {
            it.identityHex?.uppercase() == key || it.v3IdentityHex?.uppercase() == key
        }
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
            v3IdentityHex = id,
            isFallback = true,
        )
    }

    private fun sameKey(a: DirServer, b: DirServer): Boolean {
        if (a.v3IdentityHex != null && b.v3IdentityHex != null) {
            return a.v3IdentityHex.equals(b.v3IdentityHex, true)
        }
        return a.address == b.address && a.dirPort == b.dirPort
    }

    companion object {
        fun withDefaults(): DirList = DirList().also { it.loadDefaults() }
    }
}
