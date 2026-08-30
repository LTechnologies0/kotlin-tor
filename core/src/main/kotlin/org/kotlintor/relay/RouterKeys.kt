package org.kotlintor.relay

import java.nio.file.Path

/**
 * Relay onion / identity key helpers (C Tor `routerkeys.c`).
 *
 * Inventory: `L1:feature/relay/routerkeys.c`
 *
 * Rotation: [OnionKeyRotator]; load: [org.kotlintor.keymgt.LoadKey].
 */
object RouterKeys {
    fun rotator(
        keysDir: Path,
        lifetimeDays: Int = 28,
        gracePeriodDays: Int = 7,
    ): OnionKeyRotator = OnionKeyRotator(keysDir, lifetimeDays, gracePeriodDays)
}
