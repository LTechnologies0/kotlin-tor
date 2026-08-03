package org.kotlintor.dir

/**
 * Multi-authority signature quorum (C Tor majority among known authorities).
 *
 * A consensus (or detached-signatures document) is acceptable when at least
 * `ceil(nAuthorities/2)` distinct identity fingerprints have valid signatures.
 */
object DirAuthQuorum {
    fun requiredSignatures(nAuthorities: Int): Int {
        require(nAuthorities > 0)
        return (nAuthorities + 1) / 2
    }

    fun hasQuorum(
        signatureIdentityHexes: Collection<String>,
        knownAuthorityFingerprints: Set<String>,
        nAuthorities: Int = knownAuthorityFingerprints.size,
    ): Boolean {
        val distinct = signatureIdentityHexes
            .map { it.replace(" ", "").lowercase() }
            .filter { it in knownAuthorityFingerprints.map { k -> k.lowercase() }.toSet() }
            .toSet()
        return distinct.size >= requiredSignatures(nAuthorities)
    }

    fun fromDetached(
        detached: DetachedSignatures.Detached,
        knownAuthorityFingerprints: Set<String>,
    ): Boolean =
        hasQuorum(
            detached.signatures.map { it.identityHex },
            knownAuthorityFingerprints,
        )
}
