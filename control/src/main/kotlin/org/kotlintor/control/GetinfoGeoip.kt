package org.kotlintor.control

import org.kotlintor.dir.GeoIp
import org.kotlintor.stats.GeoIpStats

/**
 * GETINFO ip-to-country / geoip helpers (C Tor `getinfo_geoip.c`).
 *
 * Inventory: `L1:feature/control/getinfo_geoip.c`
 */
object GetinfoGeoip {
    fun countryForAddress(ip: String, db: GeoIp.Database? = null): String {
        val database = db ?: return "??"
        return database.country(ip) ?: "??"
    }

    fun noteClientSeen(ip: String) {
        GeoIpStats.noteClientSeen(GeoIpStats.ClientAction.CONNECT, ip)
    }
}
