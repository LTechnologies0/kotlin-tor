package org.kotlintor.circuit

/**
 * Layered circuit encryption path (C Tor `crypt_path.c` / `crypt_path_t`).
 *
 * Inventory: `L1:core/or/crypt_path.c`
 *
 * C Tor APIs: `cpath_extend_linked_list`, `cpath_append_hop`,
 * `cpath_get_next_non_open_hop`, `cpath_get_n_hops`, `cpath_assert_ok`.
 * Relay crypto material lives in [HopCrypto] / [RelayCryptoCgo] layers.
 */
object CryptPath {
    const val MAGIC: Int = 0x68706f70 // 'hop\0'-ish sentinel for asserts
    const val C_TOR_UNIT: String = "crypt_path.c"

    enum class State {
        CLOSED,
        AWAITING_KEYS,
        OPEN,
    }

    class Hop(
        var extendInfo: ExtendInfo? = null,
        var state: State = State.CLOSED,
        var packageWindow: Int = Sendme.CIRCWINDOW_START,
        var deliverWindow: Int = Sendme.CIRCWINDOW_START,
        var relayCellFormatV1: Boolean = false,
        var crypto: HopCrypto? = null,
        var cgoLayer: CgoClientHopLayer? = null,
    ) {
        val magic: Int = MAGIC
        var next: Hop = this
        var prev: Hop = this

        /** C Tor `cpath_get_sendme_tag`. */
        fun sendmeTag(): ByteArray? =
            cgoLayer?.inboundSendmeTag() ?: crypto?.inboundDigest()
    }

    /**
     * Circular doubly-linked cpath head. Empty when [head] is null.
     */
    class Path {
        var head: Hop? = null

        /** C Tor `cpath_get_n_hops`. */
        fun nHops(): Int {
            val h = head ?: return 0
            var n = 0
            var cur = h
            do {
                n++
                cur = cur.next
            } while (cur !== h)
            return n
        }

        /** C Tor `cpath_extend_linked_list`. */
        fun extendLinkedList(newHop: Hop) {
            val h = head
            if (h == null) {
                head = newHop
                newHop.next = newHop
                newHop.prev = newHop
            } else {
                newHop.next = h
                newHop.prev = h.prev
                h.prev.next = newHop
                h.prev = newHop
            }
        }

        /** C Tor `cpath_append_hop`. */
        fun appendHop(choice: ExtendInfo): Hop {
            val hop = Hop(
                extendInfo = choice,
                state = State.CLOSED,
                packageWindow = Sendme.CIRCWINDOW_START,
                deliverWindow = Sendme.CIRCWINDOW_START,
            )
            extendLinkedList(hop)
            return hop
        }

        /** C Tor `cpath_get_next_non_open_hop`. */
        fun nextNonOpenHop(): Hop? {
            val h = head ?: return null
            var cur = h
            do {
                if (cur.state != State.OPEN) return cur
                cur = cur.next
            } while (cur !== h)
            return null
        }

        /**
         * C Tor `cpath_assert_ok` — layers must be `open* awaiting? closed*`.
         * @throws IllegalStateException on invariant break
         */
        fun assertOk() {
            val h = head ?: return
            var cur = h
            do {
                assertLayerOk(cur)
                if (cur !== h) {
                    when (cur.state) {
                        State.AWAITING_KEYS ->
                            check(cur.prev.state == State.OPEN) {
                                "awaiting hop must follow open"
                            }
                        State.OPEN ->
                            check(cur.prev.state == State.OPEN) {
                                "open hop must follow open"
                            }
                        State.CLOSED -> { /* ok after awaiting/closed */ }
                    }
                }
                cur = cur.next
            } while (cur !== h)
        }

        fun assertLayerOk(hop: Hop) {
            check(hop.magic == MAGIC)
            when (hop.state) {
                State.OPEN ->
                    check(hop.crypto != null || hop.cgoLayer != null) {
                        "open hop requires crypto"
                    }
                State.CLOSED, State.AWAITING_KEYS -> { }
            }
        }

        fun clear() {
            head = null
        }
    }

    /** C Tor `cpath_append_hop`. */
    fun cpathAppendHop(path: Path, choice: ExtendInfo): Hop = path.appendHop(choice)

    /** C Tor `cpath_assert_layer_ok`. */
    fun cpathAssertLayerOk(hop: Hop) = Path().assertLayerOk(hop)

    /** C Tor `cpath_assert_ok`. */
    fun cpathAssertOk(path: Path) = path.assertOk()

    /** C Tor `cpath_extend_linked_list`. */
    fun cpathExtendLinkedList(path: Path, hop: Hop) = path.extendLinkedList(hop)

    /** C Tor `cpath_free`. */
    fun cpathFree(path: Path) = path.clear()

    /** C Tor `cpath_get_n_hops`. */
    fun cpathGetNHops(path: Path): Int = path.nHops()

    /** C Tor `cpath_get_next_non_open_hop`. */
    fun cpathGetNextNonOpenHop(path: Path): Hop? = path.nextNonOpenHop()

    /** C Tor `cpath_get_sendme_tag`. */
    fun cpathGetSendmeTag(hop: Hop): ByteArray? = hop.sendmeTag()

    /** C Tor `cpath_init_circuit_crypto` — attach hop crypto material. */
    fun cpathInitCircuitCrypto(hop: Hop, crypto: HopCrypto?): Hop {
        hop.crypto = crypto
        if (crypto != null) hop.state = State.AWAITING_KEYS
        return hop
    }

    /** C Tor `cpath_sendme_circuit_record_inbound_cell`. */
    fun cpathSendmeCircuitRecordInboundCell(hop: Hop): Int {
        hop.deliverWindow = (hop.deliverWindow - 1).coerceAtLeast(0)
        return hop.deliverWindow
    }
}
