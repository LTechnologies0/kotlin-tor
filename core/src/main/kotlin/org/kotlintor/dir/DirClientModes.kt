package org.kotlintor.dir

import org.kotlintor.config.TorConfig
import org.kotlintor.relay.RouterMode

/**
 * Directory client fetch-mode questions (C Tor `dirclient_modes.c`).
 *
 * Inventory: `L1:feature/dirclient/dirclient_modes.c`
 */
object DirClientModes {
    fun mustUseBegindir(config: TorConfig): Boolean = !RouterMode.publicServerMode(config)

    fun fetchesFromAuthorities(config: TorConfig): Boolean {
        if (config.fetchDirInfoEarly || config.fetchDirInfoExtraEarly) return true
        if (config.bridgeRelay) return false
        if (RouterMode.dirServerMode(config)) return true
        return false
    }

    fun fetchesDirInfoEarly(config: TorConfig): Boolean = fetchesFromAuthorities(config)

    fun fetchesDirInfoLater(config: TorConfig): Boolean = config.useBridges

    fun directoryFetchesV2(config: TorConfig): Boolean = false

    fun directoryFetchesV3(config: TorConfig): Boolean = true
}
