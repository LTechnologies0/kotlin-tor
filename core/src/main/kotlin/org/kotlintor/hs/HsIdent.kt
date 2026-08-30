package org.kotlintor.hs

/**
 * HS identity tags (C Tor `hs_ident.c`).
 *
 * Inventory: `L1:feature/hs/hs_ident.c`
 */
object HsIdent {
    data class EdgeConn(
        val serviceIdentityHex: String?,
        val isClient: Boolean = true,
        val purpose: String = "HS_CLIENT_REND",
    )

    fun circuit(
        serviceIdentityHex: String? = null,
        blindedHex: String? = null,
        introAuthKeyHex: String? = null,
        isClient: Boolean = true,
        purpose: String = "general",
    ): HsIdentCircuit = HsIdentCircuit(serviceIdentityHex, blindedHex, introAuthKeyHex, isClient, purpose)

    fun dirConn(
        serviceIdentityHex: String,
        hsDirIndexHint: String? = null,
        purpose: String = "HS_HSDIR_FETCH",
    ): HsIdentDirConn = HsIdentDirConn(serviceIdentityHex, hsDirIndexHint, purpose)

    /** C Tor `hs_ident_circuit_new`. */
    fun hsIdentCircuitNew(
        serviceIdentityHex: String? = null,
        blindedHex: String? = null,
        introAuthKeyHex: String? = null,
        isClient: Boolean = true,
        purpose: String = "general",
    ): HsIdentCircuit = circuit(serviceIdentityHex, blindedHex, introAuthKeyHex, isClient, purpose)

    /** C Tor `hs_ident_circuit_dup`. */
    fun hsIdentCircuitDup(ident: HsIdentCircuit): HsIdentCircuit =
        ident.copy()

    /** C Tor `hs_ident_circuit_free_`. */
    fun hsIdentCircuitFree_(ident: HsIdentCircuit?): HsIdentCircuit? = null

    /** C Tor `hs_ident_dir_conn_init` / new. */
    fun hsIdentDirConnInit(
        serviceIdentityHex: String,
        hsDirIndexHint: String? = null,
        purpose: String = "HS_HSDIR_FETCH",
    ): HsIdentDirConn = dirConn(serviceIdentityHex, hsDirIndexHint, purpose)

    /** C Tor `hs_ident_dir_conn_dup`. */
    fun hsIdentDirConnDup(ident: HsIdentDirConn): HsIdentDirConn = ident.copy()

    /** C Tor `hs_ident_dir_conn_free_`. */
    fun hsIdentDirConnFree_(ident: HsIdentDirConn?): HsIdentDirConn? = null

    /** C Tor `hs_ident_edge_conn_new`. */
    fun hsIdentEdgeConnNew(
        serviceIdentityHex: String? = null,
        isClient: Boolean = true,
        purpose: String = "HS_CLIENT_REND",
    ): EdgeConn = EdgeConn(serviceIdentityHex, isClient, purpose)

    /** C Tor `hs_ident_edge_conn_free_`. */
    fun hsIdentEdgeConnFree_(ident: EdgeConn?): EdgeConn? = null

    /** C Tor `hs_ident_intro_circ_is_valid` — identity_pk AND intro_auth_pk. */
    fun hsIdentIntroCircIsValid(ident: HsIdentCircuit): Boolean =
        !ident.serviceIdentityHex.isNullOrBlank() && !ident.introAuthKeyHex.isNullOrBlank()

    /** C Tor `hs_ident_server_dir_conn_new` — copies blinded_pk only. */
    fun hsIdentServerDirConnNew(blindedHex: String): HsIdentDirConn =
        HsIdentDirConn(serviceIdentityHex = "", hsDirIndexHint = blindedHex, purpose = "HS_HSDIR_STORE")
}
