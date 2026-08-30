package org.kotlintor.net.dns

import java.nio.file.Files
import java.nio.file.Path

/**
 * DNSSEC trust anchors. Default embeds IANA root KSK-2017 DS (RFC 7958 style).
 * Optional file format: one DS per line — `owner keyTag alg digestType hexDigest`
 * (owner usually `.`).
 */
data class TrustAnchor(
    val owner: String,
    val ds: DsRdata,
)

object TrustAnchors {
    /** Root KSK-2017 (20326). */
    val ROOT_KSK_2017: TrustAnchor = TrustAnchor(
        owner = "",
        ds = DsRdata(
            keyTag = 20326,
            algorithm = DnsTypes.ALG_RSASHA256,
            digestType = DsRdata.DIGEST_SHA256,
            digest = hex("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"),
        ),
    )

    /** Root KSK-2024 (38696) — present for rollover windows. */
    val ROOT_KSK_2024: TrustAnchor = TrustAnchor(
        owner = "",
        ds = DsRdata(
            keyTag = 38696,
            algorithm = DnsTypes.ALG_RSASHA256,
            digestType = DsRdata.DIGEST_SHA256,
            digest = hex("683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"),
        ),
    )

    fun defaultRoot(): List<TrustAnchor> = listOf(ROOT_KSK_2017, ROOT_KSK_2024)

    fun load(path: Path?): List<TrustAnchor> {
        if (path != null && Files.isRegularFile(path)) {
            return parseLines(Files.readAllLines(path)).ifEmpty { defaultRoot() }
        }
        val resource = TrustAnchors::class.java.classLoader.getResourceAsStream("dns/root.key")
        if (resource != null) {
            return resource.bufferedReader().use { parseLines(it.readLines()) }.ifEmpty { defaultRoot() }
        }
        return defaultRoot()
    }

    private fun parseLines(lines: List<String>): List<TrustAnchor> {
        val out = ArrayList<TrustAnchor>()
        for (line in lines) {
            val t = line.trim()
            if (t.isEmpty() || t.startsWith("#") || t.startsWith(";")) continue
            val parts = t.split(Regex("\\s+"))
            if (parts.size < 5) continue
            val owner = DnsMessage.canonicalizeName(parts[0].let { if (it == ".") "" else it })
            val keyTag = parts[1].toInt()
            val alg = parts[2].toInt()
            val dt = parts[3].toInt()
            val dig = hex(parts[4])
            out += TrustAnchor(owner, DsRdata(keyTag, alg, dt, dig))
        }
        return out
    }

    fun hex(s: String): ByteArray {
        val clean = s.replace(" ", "").replace(":", "")
        require(clean.length % 2 == 0)
        return ByteArray(clean.length / 2) { i ->
            clean.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }
}
