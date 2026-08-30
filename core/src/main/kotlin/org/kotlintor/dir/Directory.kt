package org.kotlintor.dir

import java.nio.file.Path

/**
 * Directory protocol client entry (C Tor `directory.c`).
 *
 * Inventory: `L1:feature/dircommon/directory.c`
 *
 * HTTP fetch client: [DirectoryClient].
 */
object Directory {
    const val PURPOSE_FETCH_CONSENSUS: String = "fetch_consensus"
    const val PURPOSE_FETCH_CERT: String = "fetch_cert"
    const val PURPOSE_FETCH_DESC: String = "fetch_desc"

    fun client(cacheDir: Path, authorities: List<DirectoryAuthority> = DefaultAuthorities.ALL): DirectoryClient =
        DirectoryClient(cacheDir, authorities)
}
