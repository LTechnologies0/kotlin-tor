package org.kotlintor.mainloop

import java.util.concurrent.CopyOnWriteArrayList

/**
 * Mainloop pubsub / message bus (C Tor `mainloop_pubsub.c`).
 *
 * Inventory: `L1:core/mainloop/mainloop_pubsub.c`
 */
object MainloopPubsub {
    data class Msg(val channel: String, val payload: Any?)

    private val subscribers = CopyOnWriteArrayList<Pair<String, (Msg) -> Unit>>()

    fun clear() = subscribers.clear()

    fun subscribe(channel: String, handler: (Msg) -> Unit) {
        subscribers += channel to handler
    }

    fun unsubscribeAll(channel: String) {
        subscribers.removeAll { it.first == channel }
    }

    fun publish(channel: String, payload: Any? = null): Int {
        val msg = Msg(channel, payload)
        var n = 0
        for ((ch, h) in subscribers) {
            if (ch == channel || ch == "*") {
                h(msg)
                n++
            }
        }
        return n
    }

    fun subscriberCount(channel: String? = null): Int =
        if (channel == null) subscribers.size else subscribers.count { it.first == channel }
}
