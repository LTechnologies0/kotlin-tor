package org.kotlintor.android

import android.content.Context
import android.content.Intent

/**
 * Orbot-compatible control surface (status broadcasts + start/stop intents).
 *
 * Apps can listen for [ACTION_STATUS] and drive kotlin-tor with the same extras
 * Orbot documents for VPN/embedders.
 */
object OrbotCompat {
    const val ACTION_START = "org.torproject.android.intent.action.START"
    const val ACTION_STOP = "org.torproject.android.intent.action.STOP"
    const val ACTION_STATUS = "org.torproject.android.intent.action.STATUS"
    const val ACTION_ERROR = "org.torproject.android.intent.action.ERROR"

    const val EXTRA_STATUS = "org.torproject.android.intent.extra.STATUS"
    const val EXTRA_SOCKS_PROXY = "org.torproject.android.intent.extra.SOCKS_PROXY"
    const val EXTRA_SOCKS_PROXY_HOST = "org.torproject.android.intent.extra.SOCKS_PROXY_HOST"
    const val EXTRA_SOCKS_PROXY_PORT = "org.torproject.android.intent.extra.SOCKS_PROXY_PORT"
    const val EXTRA_HTTP_PROXY_HOST = "org.torproject.android.intent.extra.HTTP_PROXY_HOST"
    const val EXTRA_HTTP_PROXY_PORT = "org.torproject.android.intent.extra.HTTP_PROXY_PORT"
    const val EXTRA_PACKAGE_NAME = "org.torproject.android.intent.extra.PACKAGE_NAME"
    const val EXTRA_STATUS_PACKAGE_NAME = "org.torproject.android.intent.extra.STATUS_PACKAGE_NAME"
    const val EXTRA_ERROR = "org.torproject.android.intent.extra.ERROR"

    const val STATUS_ON = "ON"
    const val STATUS_OFF = "OFF"
    const val STATUS_STARTING = "STARTING"
    const val STATUS_STOPPING = "STOPPING"

    fun statusExtra(running: Boolean, starting: Boolean = false, stopping: Boolean = false): String = when {
        starting -> STATUS_STARTING
        stopping -> STATUS_STOPPING
        running -> STATUS_ON
        else -> STATUS_OFF
    }

    fun statusIntent(
        context: Context,
        engine: KotlinTorEngine,
        status: String = statusExtra(engine.isRunning),
    ): Intent = Intent(ACTION_STATUS).apply {
        setPackage(context.packageName)
        putExtra(EXTRA_STATUS, status)
        putExtra(EXTRA_PACKAGE_NAME, context.packageName)
        if (engine.socksPort > 0) {
            putExtra(EXTRA_SOCKS_PROXY_HOST, "127.0.0.1")
            putExtra(EXTRA_SOCKS_PROXY_PORT, engine.socksPort)
            putExtra(EXTRA_SOCKS_PROXY, "socks5://127.0.0.1:${engine.socksPort}")
        }
        if (engine.httpConnectPort > 0) {
            putExtra(EXTRA_HTTP_PROXY_HOST, "127.0.0.1")
            putExtra(EXTRA_HTTP_PROXY_PORT, engine.httpConnectPort)
        }
    }

    fun broadcastStatus(context: Context, engine: KotlinTorEngine, status: String) {
        context.sendBroadcast(statusIntent(context, engine, status))
    }

    fun errorIntent(context: Context, message: String): Intent =
        Intent(ACTION_ERROR).apply {
            setPackage(context.packageName)
            putExtra(EXTRA_ERROR, message)
            putExtra(EXTRA_PACKAGE_NAME, context.packageName)
        }
}
