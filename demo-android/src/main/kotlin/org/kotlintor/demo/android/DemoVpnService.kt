package org.kotlintor.demo.android

import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import org.kotlintor.android.KotlinTorVpnService

/**
 * Demo VpnService: full-tunnel IPv4 → OnionTunnel → Tor.
 * Consent via [VpnService.prepare] from [DemoActivity].
 */
class DemoVpnService : KotlinTorVpnService() {
    override fun sessionName(): String = "kotlin-tor demo VPN"

    /**
     * Keep Waydroid/QEMU host bridges off-TUN so TCP ADB (and the host) stay reachable
     * under full-tunnel IPv4. Fake-IP cookies remain in 10/8 and still enter the TUN.
     */
    override fun excludedIpv4Prefixes(): List<Pair<String, Int>> = listOf(
        "192.168.0.0" to 16,
    )

    override fun configureIntent(): PendingIntent? {
        val launch = Intent(this, DemoActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
        val flags = PendingIntent.FLAG_UPDATE_CURRENT or
            if (Build.VERSION.SDK_INT >= 23) PendingIntent.FLAG_IMMUTABLE else 0
        return PendingIntent.getActivity(this, 0, launch, flags)
    }
}
