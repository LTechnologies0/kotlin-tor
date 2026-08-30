package org.kotlintor.hs

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * HS metrics counters (C Tor `hs_metrics.c`).
 *
 * Inventory: `L1:feature/hs/hs_metrics.c`
 */
object HsMetrics {
    private val introReceived = AtomicInteger(0)
    private val introRejected = AtomicInteger(0)
    private val descFetches = AtomicInteger(0)
    private val descUploads = AtomicInteger(0)
    private val rendezvousOk = AtomicInteger(0)

    fun noteIntroReceived() { introReceived.incrementAndGet() }
    fun noteIntroRejected() { introRejected.incrementAndGet() }
    fun noteDescFetch() { descFetches.incrementAndGet() }
    fun noteDescUpload() { descUploads.incrementAndGet() }
    fun noteRendezvousOk() { rendezvousOk.incrementAndGet() }

    fun snapshot(): Map<String, Int> = mapOf(
        "hs_intro_received" to introReceived.get(),
        "hs_intro_rejected" to introRejected.get(),
        "hs_desc_fetches" to descFetches.get(),
        "hs_desc_uploads" to descUploads.get(),
        "hs_rendezvous_ok" to rendezvousOk.get(),
    )

    fun exportPrometheus(): String = buildString {
        for ((k, v) in snapshot()) {
            append("tor_hs_").append(k).append(' ').append(v).append('\n')
        }
    }

    fun reset() {
        introReceived.set(0)
        introRejected.set(0)
        descFetches.set(0)
        descUploads.set(0)
        rendezvousOk.set(0)
    }

    private val serviceStores = ConcurrentHashMap<String, ConcurrentHashMap<String, AtomicInteger>>()

    /** C Tor `hs_metrics_get_stores`. */
    fun hsMetricsGetStores(): Map<String, Map<String, Int>> =
        serviceStores.mapValues { (_, m) -> m.mapValues { it.value.get() } }

    /** C Tor `hs_metrics_service_init`. */
    fun hsMetricsServiceInit(onionAddress: String) {
        serviceStores[onionAddress.lowercase()] = ConcurrentHashMap<String, AtomicInteger>().also {
            it["intro_received"] = AtomicInteger(0)
            it["rendezvous_ok"] = AtomicInteger(0)
        }
    }

    /** C Tor `hs_metrics_service_free`. */
    fun hsMetricsServiceFree(onionAddress: String) {
        serviceStores.remove(onionAddress.lowercase())
    }

    /** C Tor `hs_metrics_update_by_service`. */
    fun hsMetricsUpdateByService(onionAddress: String, metric: String = "intro_received") {
        val store = serviceStores.getOrPut(onionAddress.lowercase()) {
            ConcurrentHashMap()
        }
        store.getOrPut(metric) { AtomicInteger(0) }.incrementAndGet()
        when (metric) {
            "intro_received" -> noteIntroReceived()
            "intro_rejected" -> noteIntroRejected()
            "desc_fetch" -> noteDescFetch()
            "desc_upload" -> noteDescUpload()
            "rendezvous_ok" -> noteRendezvousOk()
        }
    }

    /** C Tor `hs_metrics_update_by_ident`. */
    fun hsMetricsUpdateByIdent(ident: HsIdentCircuit, metric: String = "intro_received") {
        val key = ident.serviceIdentityHex ?: "unknown"
        hsMetricsUpdateByService(key, metric)
    }
}
