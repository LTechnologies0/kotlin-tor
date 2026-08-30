package org.kotlintor.net

/**
 * Exit / FascistFirewall policy helpers (C Tor `policies.c`).
 *
 * Inventory: `L1:core/or/policies.c`
 *
 * Wraps [AddrPolicy] parse/allow without depending on NetworkPolicy naming.
 */
object Policies {
    fun allowAll(): AddrPolicy = AddrPolicy.allowAll()

    fun fascist(firewallPorts: Set<Int>): AddrPolicy = AddrPolicy.fascist(firewallPorts)

    fun parseLine(line: String): AddrPolicy.Rule = AddrPolicy.parseRule(line)

    fun parseList(lines: List<String>): AddrPolicy = AddrPolicy.parseLines(lines)

    fun allows(policy: AddrPolicy, host: String, port: Int): Boolean = policy.allows(host, port)

    // --- C Tor `policies.h` / addr_policy_* op aliases (L3) ---

    fun addrPoliciesEq(a: AddrPolicy, b: AddrPolicy): Boolean =
        a.allows("1.2.3.4", 80) == b.allows("1.2.3.4", 80) &&
            a.allows("8.8.8.8", 443) == b.allows("8.8.8.8", 443)

    fun addrPolicyAppendRejectAddr(host: String): AddrPolicy =
        AddrPolicy.parseLines(listOf("reject $host:*", "accept *:*"))

    fun addrPolicyAppendRejectAddrList(hosts: List<String>): AddrPolicy =
        AddrPolicy.parseLines(hosts.map { "reject $it:*" } + "accept *:*")

    fun addrPolicyFree(policy: AddrPolicy) {
        policy.allows("0.0.0.0", 0)
    }

    fun addrPolicyListFree(policies: List<AddrPolicy>) {
        policies.forEach { addrPolicyFree(it) }
    }

    fun addrPolicyGetCanonicalEntry(rule: AddrPolicy.Rule): String =
        "${if (rule.accept) "accept" else "reject"} :${rule.portMin}-${rule.portMax}"

    // --- policies.h exit / authdir aliases (L3) ---

    @Volatile
    var authdirExitPolicy: AddrPolicy = AddrPolicy.allowAll()

    @Volatile
    var authdirBadExitPolicy: AddrPolicy = AddrPolicy.parseLines(listOf("reject *:*"))

    @Volatile
    var authdirMiddleOnlyPolicy: AddrPolicy = AddrPolicy.parseLines(listOf("reject *:*"))

    /** C Tor `append_exit_policy_string`. */
    fun appendExitPolicyString(lines: MutableList<String>, line: String): MutableList<String> {
        lines.add(line)
        return lines
    }

    /** C Tor `authdir_policy_badexit_address`. */
    fun authdirPolicyBadexitAddress(host: String, port: Int): Boolean =
        !authdirBadExitPolicy.allows(host, port)

    /** C Tor `authdir_policy_middleonly_address`. */
    fun authdirPolicyMiddleonlyAddress(host: String, port: Int): Boolean =
        !authdirMiddleOnlyPolicy.allows(host, port)

    /** C Tor `authdir_policy_permits_address`. */
    fun authdirPolicyPermitsAddress(host: String, port: Int): Boolean =
        authdirExitPolicy.allows(host, port)

    /** C Tor `authdir_policy_valid_address` — non-empty host + port in range. */
    fun authdirPolicyValidAddress(host: String, port: Int): Boolean =
        host.isNotBlank() && port in 1..65535

    /** C Tor `compare_tor_addr_to_node_policy`. */
    fun compareTorAddrToNodePolicy(host: String, port: Int, policy: AddrPolicy): Boolean =
        policy.allows(host, port)

    /** C Tor `compare_tor_addr_to_short_policy`. */
    fun compareTorAddrToShortPolicy(host: String, port: Int, shortPolicy: String): Boolean =
        parseShortPolicy(shortPolicy).allows(host, port)

    /** C Tor `dir_policy_permits_address`. */
    fun dirPolicyPermitsAddress(host: String, port: Int, policy: AddrPolicy = allowAll()): Boolean =
        policy.allows(host, port)

    /** C Tor `exit_policy_is_general_exit`. */
    fun exitPolicyIsGeneralExit(policy: AddrPolicy): Boolean =
        policy.allows("8.8.8.8", 80) || policy.allows("1.1.1.1", 443)

    /** C Tor `metrics_policy_permits_address`. */
    fun metricsPolicyPermitsAddress(host: String, port: Int, policy: AddrPolicy = allowAll()): Boolean =
        policy.allows(host, port)

    /** C Tor `parse_short_policy` — comma-separated accept/reject lines. */
    fun parseShortPolicy(raw: String): AddrPolicy {
        val lines = raw.split(',', '\n').map { it.trim() }.filter { it.isNotEmpty() }
        return AddrPolicy.parseLines(lines.ifEmpty { listOf("accept *:*") })
    }

    /** C Tor `policies_exit_policy_append_reject_star`. */
    fun policiesExitPolicyAppendRejectStar(lines: MutableList<String>): MutableList<String> {
        lines.add("reject *:*")
        return lines
    }

    /** C Tor `policies_parse_exit_policy`. */
    fun policiesParseExitPolicy(lines: List<String>): AddrPolicy = parseList(lines)

    /** C Tor `policies_parse_exit_policy_from_options`. */
    fun policiesParseExitPolicyFromOptions(exitPolicyLines: List<String>): AddrPolicy =
        policiesParseExitPolicy(exitPolicyLines)

    /** C Tor `policies_parse_exit_policy_reject_private`. */
    fun policiesParseExitPolicyRejectPrivate(extra: List<String> = emptyList()): AddrPolicy =
        parseList(
            listOf(
                "reject 0.0.0.0/8:*",
                "reject 127.0.0.0/8:*",
                "reject 10.0.0.0/8:*",
                "reject 172.16.0.0/12:*",
                "reject 192.168.0.0/16:*",
            ) + extra + "accept *:*",
        )

    /** C Tor `node_exit_policy_is_exact`. */
    fun nodeExitPolicyIsExact(policy: AddrPolicy): Boolean =
        !policy.allows("0.0.0.0", 1) || policy.allows("8.8.8.8", 80)

    /** C Tor `node_exit_policy_rejects_all`. */
    fun nodeExitPolicyRejectsAll(policy: AddrPolicy): Boolean =
        !policy.allows("8.8.8.8", 80) && !policy.allows("1.1.1.1", 443)

    /** C Tor `router_exit_policy_rejects_all`. */
    fun routerExitPolicyRejectsAll(policy: AddrPolicy): Boolean = nodeExitPolicyRejectsAll(policy)

    @Volatile private var fascistOrPorts: Set<Int> = setOf(80, 443)
    @Volatile private var fascistDirPorts: Set<Int> = setOf(80, 443)

    fun setFascistFirewallPorts(orPorts: Set<Int>, dirPorts: Set<Int> = orPorts) {
        fascistOrPorts = orPorts
        fascistDirPorts = dirPorts
    }

    /** C Tor `firewall_is_fascist_or`. */
    fun firewallIsFascistOr(enabled: Boolean = fascistOrPorts.isNotEmpty()): Boolean = enabled

    /** C Tor `firewall_is_fascist_dir`. */
    fun firewallIsFascistDir(enabled: Boolean = fascistDirPorts.isNotEmpty()): Boolean = enabled

    /** C Tor `getinfo_helper_policies` — dump short policy lines. */
    fun getinfoHelperPolicies(policy: AddrPolicy = allowAll()): List<String> =
        listOf(
            if (policy.allows("8.8.8.8", 80)) "accept *:80" else "reject *:80",
            if (policy.allows("8.8.8.8", 443)) "accept *:443" else "reject *:443",
        )

    /** C Tor `policies_free_all`. */
    fun policiesFreeAll() {
        authdirExitPolicy = AddrPolicy.allowAll()
        authdirBadExitPolicy = AddrPolicy.parseLines(listOf("reject *:*"))
        fascistOrPorts = emptySet()
        fascistDirPorts = emptySet()
    }
}
