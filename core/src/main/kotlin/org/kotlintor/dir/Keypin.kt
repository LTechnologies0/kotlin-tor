package org.kotlintor.dir

import org.kotlintor.util.toHex
import java.util.concurrent.ConcurrentHashMap

/**
 * RSA↔Ed25519 identity keypin journal (C Tor `keypin.c` / `keypin.h`).
 *
 * Status codes match C Tor: FOUND=0, ADDED=1, MISMATCH=-1, NOT_FOUND=-2.
 * Inventory: `L1:feature/dirauth/keypin.c`
 */
object Keypin {
    /** C Tor `KEYPIN_*` return codes (plus [REPLACED] for replace-path clarity). */
    enum class Result(val code: Int) {
        FOUND(0),
        ADDED(1),
        MISMATCH(-1),
        NOT_FOUND(-2),
        /** Same wire code as ADDED when replace_existing forced a map update. */
        REPLACED(1),
        ;

        /** Legacy alias used by older call sites for [FOUND]. */
        companion object {
            @JvmField
            val OK: Result = FOUND

            @JvmField
            val CONFLICT: Result = MISMATCH
        }
    }

    data class Entry(val rsaIdHex: String, val ed25519Hex: String)

    class Journal {
        private val byRsa = ConcurrentHashMap<String, String>()
        private val byEd = ConcurrentHashMap<String, String>()
        private val journalLines = ArrayList<String>()

        /**
         * C Tor `keypin_check` — do not add.
         * FOUND / MISMATCH / NOT_FOUND.
         */
        fun check(rsaId: ByteArray, ed25519: ByteArray): Result {
            require(rsaId.size == 20)
            require(ed25519.size == 32)
            val r = rsaId.toHex().lowercase()
            val e = ed25519.toHex().lowercase()
            val existingEd = byRsa[r]
            if (existingEd != null) {
                return if (existingEd == e) Result.FOUND else Result.MISMATCH
            }
            val existingRsa = byEd[e]
            if (existingRsa != null) {
                return if (existingRsa == r) Result.FOUND else Result.MISMATCH
            }
            return Result.NOT_FOUND
        }

        /**
         * C Tor `keypin_check_and_add`.
         * FOUND (already pinned), ADDED, MISMATCH, or REPLACED when [replace].
         */
        fun checkAndAdd(rsaId: ByteArray, ed25519: ByteArray, replace: Boolean = false): Result {
            require(rsaId.size == 20)
            require(ed25519.size == 32)
            val r = rsaId.toHex().lowercase()
            val e = ed25519.toHex().lowercase()
            when (val st = check(rsaId, ed25519)) {
                Result.FOUND -> {
                    if (!replace) return Result.FOUND
                    // replace_existing: force rewrite + journal (C Tor returns KEYPIN_ADDED)
                    removeBinding(r, e)
                    putBinding(r, e)
                    appendJournal(r, e)
                    return Result.REPLACED
                }
                Result.MISMATCH -> {
                    if (!replace) return Result.MISMATCH
                    removeBinding(r, e)
                    putBinding(r, e)
                    appendJournal(r, e)
                    return Result.REPLACED
                }
                Result.NOT_FOUND -> {
                    putBinding(r, e)
                    appendJournal(r, e)
                    return Result.ADDED
                }
                else -> return st
            }
        }

        /**
         * C Tor `keypin_check_lone_rsa` —
         * MISMATCH if RSA already pinned; NOT_FOUND otherwise.
         */
        fun checkLoneRsaStatus(rsaId: ByteArray): Result {
            require(rsaId.size == 20)
            val r = rsaId.toHex().lowercase()
            return if (byRsa.containsKey(r)) Result.MISMATCH else Result.NOT_FOUND
        }

        /** True when RSA is not yet pinned (inverse of C Tor MISMATCH). */
        fun checkLoneRsa(rsaId: ByteArray): Boolean =
            checkLoneRsaStatus(rsaId) == Result.NOT_FOUND

        fun verifyAll(): Boolean {
            if (byRsa.size != byEd.size) return false
            for ((r, e) in byRsa) {
                if (byEd[e] != r) return false
            }
            return true
        }

        fun entries(): List<Entry> = byRsa.map { Entry(it.key, it.value) }

        fun formatJournal(): String = buildString {
            appendLine("keypin-journal-version 1")
            for (e in entries().sortedBy { it.rsaIdHex }) {
                appendLine("rsa-ed ${e.rsaIdHex} ${e.ed25519Hex}")
            }
        }

        /** Lines appended since open (C Tor journal append stream). */
        fun pendingJournalLines(): List<String> = journalLines.toList()

        fun loadJournal(text: String) {
            for (line in text.lineSequence()) {
                val p = line.trim().split(Regex("\\s+"))
                if (p.size >= 3 && p[0] == "rsa-ed") {
                    byRsa[p[1].lowercase()] = p[2].lowercase()
                    byEd[p[2].lowercase()] = p[1].lowercase()
                }
            }
        }

        fun saveTo(path: java.nio.file.Path) {
            java.nio.file.Files.createDirectories(path.parent)
            java.nio.file.Files.writeString(path, formatJournal())
        }

        fun loadFrom(path: java.nio.file.Path): Boolean {
            if (!java.nio.file.Files.isRegularFile(path)) return false
            loadJournal(java.nio.file.Files.readString(path))
            return verifyAll()
        }

        fun clear() {
            byRsa.clear()
            byEd.clear()
            journalLines.clear()
        }

        fun size(): Int = byRsa.size

        /** C Tor `keypin_check`. */
        fun keypinCheck(rsaId: ByteArray, ed25519: ByteArray): Result = check(rsaId, ed25519)

        /** C Tor `keypin_check_and_add`. */
        fun keypinCheckAndAdd(rsaId: ByteArray, ed25519: ByteArray, replace: Boolean = false): Result =
            checkAndAdd(rsaId, ed25519, replace)

        /** C Tor `keypin_check_lone_rsa`. */
        fun keypinCheckLoneRsa(rsaId: ByteArray): Result = checkLoneRsaStatus(rsaId)

        /** C Tor `keypin_clear`. */
        fun keypinClear() {
            clear()
        }

        /** C Tor `keypin_load_journal` / `keypin_load_journal_impl`. */
        fun keypinLoadJournal(text: String) {
            loadJournal(text)
        }

        fun keypinLoadJournalImpl(text: String) {
            loadJournal(text)
        }

        /** C Tor `keypin_parse_journal_line` — returns true if line applied. */
        fun keypinParseJournalLine(line: String): Boolean {
            val p = line.trim().split(Regex("\\s+"))
            if (p.size >= 3 && p[0] == "rsa-ed") {
                byRsa[p[1].lowercase()] = p[2].lowercase()
                byEd[p[2].lowercase()] = p[1].lowercase()
                return true
            }
            return false
        }

        private fun putBinding(r: String, e: String) {
            byRsa[r] = e
            byEd[e] = r
        }

        private fun removeBinding(r: String, e: String) {
            byRsa[r]?.let { byEd.remove(it) }
            byEd[e]?.let { byRsa.remove(it) }
            byRsa.remove(r)
            byEd.remove(e)
        }

        private fun appendJournal(r: String, e: String) {
            journalLines += "rsa-ed $r $e"
        }
    }

    @Volatile
    private var active: Journal? = null

    /** C Tor `keypin_open_journal` — process-wide journal handle. */
    fun keypinOpenJournal(): Journal {
        val j = active ?: Journal().also { active = it }
        return j
    }

    /** C Tor `keypin_close_journal`. */
    fun keypinCloseJournal() {
        active = null
    }

    fun keypinActiveJournal(): Journal? = active

    fun keypinCheck(rsaId: ByteArray, ed25519: ByteArray): Result =
        keypinOpenJournal().keypinCheck(rsaId, ed25519)

    fun keypinCheckAndAdd(rsaId: ByteArray, ed25519: ByteArray, replace: Boolean = false): Result =
        keypinOpenJournal().keypinCheckAndAdd(rsaId, ed25519, replace)

    fun keypinCheckLoneRsa(rsaId: ByteArray): Result =
        keypinOpenJournal().keypinCheckLoneRsa(rsaId)

    fun keypinClear() {
        keypinOpenJournal().keypinClear()
    }

    fun keypinLoadJournal(text: String) {
        keypinOpenJournal().keypinLoadJournal(text)
    }

    fun keypinLoadJournalImpl(text: String) {
        keypinOpenJournal().keypinLoadJournalImpl(text)
    }

    fun keypinParseJournalLine(line: String): Boolean =
        keypinOpenJournal().keypinParseJournalLine(line)
}
