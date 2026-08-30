package org.kotlintor.dir

import java.nio.file.Path

/**
 * Directory client downloads (C Tor `dirclient.c`).
 *
 * Inventory: `L1:feature/dirclient/dirclient.c`
 *
 * Modes: [DirClientModes]. Fetcher: [DirectoryClient].
 */
object DirClient {
    fun modes(): DirClientModes = DirClientModes

    fun open(cacheDir: Path): DirectoryClient = DirectoryClient(cacheDir)
}
