package com.v2ray.ang.root

import android.os.Process
import com.v2ray.ang.AppConfig

/** Deterministic device-capture rules. Android netId/permission bits remain intact. */
internal object RootRulePlan {
    /** One root service acquisition owns this snapshot, including later DNS reconciliations. */
    class AppPolicy(val enabled: Boolean, val bypass: Boolean, selected: List<String>) {
        val selectedUids: List<String> = selected.mapNotNull { it.toIntOrNull() }
            .filter { it >= 0 }.distinct().sorted().map { it.toString() }
        val dnsBypassUids: List<String>
            get() = if (enabled && bypass) selectedUids else emptyList()
    }

    private val markHex = AppConfig.ROOT_MARK_ROUTE.toString(16).padStart(8, '0')
    val MARK = "0x$markHex/0x$markHex"
    const val DNS_CHAIN = AppConfig.ROOT_DNS_OUTPUT_CHAIN
    val bypassCidrsV4 = listOf("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
        "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4")
    val bypassCidrsV6 = listOf("::1/128", "fe80::/10", "fc00::/7", "ff00::/8")

    fun operationPreamble(lockPath: String = "/data/local/tmp/v2rayng-root.lock"): String = """
        set -e
        umask 077
        iptables() { command iptables -w 5 "${'$'}@"; }
        ip6tables() { command ip6tables -w 5 "${'$'}@"; }
        exec 9>'$lockPath'
        attempt=0
        # Android mksh closes internal descriptors unless explicitly inherited by flock.
        until flock -n 9 9>&9; do
            attempt=${'$'}((attempt + 1))
            [ "${'$'}attempt" -lt 40 ] || { echo 'root operation lock timed out'; exit 1; }
            sleep 0.5
        done
    """.trimIndent() + "\n"


    /** Reject collisions before writing an ownership marker or modifying shared kernel state. */
    fun preflight(): String = buildString {
        appendLine("ip link show ${AppConfig.ROOT_TUN_NAME} >/dev/null 2>&1 && { echo 'root tunnel already exists'; exit 1; }")
        for (family in listOf("", "-6 ")) {
            appendLine("[ -z \"${'$'}(ip ${family}route show table ${AppConfig.ROOT_ROUTE_TABLE} 2>/dev/null || true)\" ] || { echo 'root routing table already in use'; exit 1; }")
            appendLine("[ -z \"${'$'}(ip ${family}rule show | awk '${'$'}1 == \"${AppConfig.ROOT_RULE_PRIORITY}:\"')\" ] || { echo 'root rule priority already in use'; exit 1; }")
        }
        val chains = listOf(
            "iptables nat $DNS_CHAIN", "iptables mangle ${AppConfig.ROOT_IPTABLES_CHAIN}",
            "ip6tables mangle ${AppConfig.ROOT_IPTABLES_CHAIN}",
            "ip6tables filter ${AppConfig.ROOT_V6_CHAIN}",
            "iptables filter ${AppConfig.ROOT_FWD_CHAIN}", "iptables nat ${AppConfig.ROOT_DNS_CHAIN}",
            "ip6tables filter ${AppConfig.ROOT_V6_FWD_CHAIN}", "ip6tables mangle ${AppConfig.ROOT_V6_PRE_CHAIN}",
        )
        appendLine("unused_chain() { if \"${'$'}1\" -t \"${'$'}2\" -S \"${'$'}3\" >/dev/null 2>&1; then echo 'root firewall chain already exists'; return 1; else code=${'$'}?; [ \"${'$'}code\" = 1 ]; fi; }")
        chains.forEach { appendLine("unused_chain $it") }
    }


    // Android's bundled ip can ignore a trailing "default" route selector. Inspect the
    // destination explicitly until supported Android ip implementations honor that filter.
    fun mainDefaultRouteCount(ipv6: Boolean): String =
        "ip ${if (ipv6) "-6 " else ""}route show table main | " +
            "awk '${'$'}1 == \"default\" || ${'$'}1 == \"0.0.0.0/0\" || ${'$'}1 == \"::/0\" {n++} END {print n+0}'"

    /**
     * Linux tailscaled expects a main-table default route; Android instead uses netd tables.
     * Its outer sockets then hit its own unreachable rule before Android can select Wi-Fi/cell.
     * Match only the documented LinuxBypassMark sequence and a system-owned daemon. The
     * UID, priorities and Android continuation are discovered, not tied to a phone/network.
     * Remove when that daemon uses Android-aware socket routing (tailscale/tsconst/linuxfw.go).
     */
    fun tailnetBypass(rules: String, daemonUid: Int, mainHasDefault: Boolean): String? {
        if (mainHasDefault || daemonUid !in 0 until Process.FIRST_APPLICATION_UID) return null
        val entries = rules.lineSequence().mapNotNull { line ->
            val parts = line.trim().split(Regex(":\\s+"), limit = 2)
            val priority = parts.firstOrNull()?.toIntOrNull() ?: return@mapNotNull null
            parts.getOrNull(1)?.replace(Regex("\\s+"), " ")?.let { priority to it }
        }.toList()
        // Protocol constants from tailscale/tsconst/linuxfw.go, not a configurable app mark.
        val mark = "0x80000/0xff0000"
        val start = entries.indexOfFirst { it.second == "from all fwmark $mark lookup main" }
        if (start < 0 || entries.size <= start + 4) return null
        if (entries[start + 1].second != "from all fwmark $mark lookup default" ||
            entries[start + 2].second != "from all fwmark $mark unreachable" ||
            !entries[start + 3].second.matches(Regex("from all lookup \\S+")) ||
            !entries[start + 4].second.endsWith("lookup legacy_system")) return null
        val priority = entries[start + 2].first - 1
        if (entries.any { it.first == priority }) return null
        val target = entries[start + 4].first
        return "fwmark $mark iif lo uidrange $daemonUid-$daemonUid goto $target pref $priority"
    }

    fun capture(
        ipv6: Boolean, rejectV6: Boolean, chain: String, appUid: Int,
        perApp: Boolean, bypass: Boolean, selected: List<String>,
    ): String {
        val table = if (rejectV6) "filter" else "mangle"
        val command = if (ipv6) "ip6tables-restore" else "iptables-restore"
        val selectedUids = selected.filter { (it.toIntOrNull() ?: -1) >= 0 }.distinct().sortedBy { it.toInt() }
        val targets = if (rejectV6) listOf(
            "-p tcp -j REJECT --reject-with tcp-reset",
            "-j REJECT --reject-with icmp6-adm-prohibited",
        ) else listOf("-j MARK --set-xmark $MARK")
        return batch(command, table, chain) {
            if (rejectV6) {
                // Linux sends local rejection replies through OUTPUT without an app socket.
                // Preserve their loopback path while blocking IPv6, or this chain drops its
                // own replies and TCP waits for retransmission timeouts instead of failing.
                appendLine("-A $chain -o lo -j RETURN")
            }
            appendLine("-A $chain -m owner --uid-owner $appUid -j RETURN")
            // Android's protected sockets and explicit infrastructure UIDs must retain their network.
            appendLine("-A $chain -m mark --mark 0x20000/0x20000 -j RETURN")
            appendLine("-A $chain -m owner --uid-owner 0-${Process.FIRST_APPLICATION_UID - 1} -j RETURN")
            (if (ipv6) bypassCidrsV6 else bypassCidrsV4).forEach { appendLine("-A $chain -d $it -j RETURN") }
            if (perApp && bypass) selectedUids.forEach {
                appendLine("-A $chain -m owner --uid-owner $it -j RETURN")
            }
            if (perApp && !bypass) selectedUids.forEach { uid ->
                targets.forEach { appendLine("-A $chain -m owner --uid-owner $uid $it") }
            } else targets.forEach { appendLine("-A $chain $it") }
            appendLine("-A OUTPUT -j $chain")
        }
    }

    fun dns(
        appUid: Int, port: Int, netId: Int, appendHook: Boolean,
        policy: AppPolicy,
    ): String =
        batch("iptables-restore", "nat", DNS_CHAIN) {
            appendLine("-A $DNS_CHAIN -m owner --uid-owner $appUid -j RETURN")
            // Only app-owned DNS sockets carry this UID. Android netd's shared queries
            // retain the core's ordered domain policy, not an inferred originating app.
            policy.dnsBypassUids.forEach {
                appendLine("-A $DNS_CHAIN -m owner --uid-owner $it -j RETURN")
            }
            appendLine("-A $DNS_CHAIN -d 100.64.0.0/10 -j RETURN")
            appendLine("-A $DNS_CHAIN -d 127.0.0.0/8 -j RETURN")
            // netd carries the requesting network's netId. Leave IMS/non-default networks alone.
            for (protocol in listOf("udp", "tcp")) {
                for (network in listOf(0, netId).distinct()) {
                    appendLine("-A $DNS_CHAIN -m mark --mark $network/0xffff -p $protocol --dport ${AppConfig.PORT_DNS} -j DNAT --to-destination ${AppConfig.LOOPBACK}:$port")
                }
            }
            if (appendHook) appendLine("-A OUTPUT -j $DNS_CHAIN")
        }

    private fun batch(command: String, table: String, chain: String, rules: StringBuilder.() -> Unit) = buildString {
        appendLine("$command -w 5 --noflush <<'V2NG_RULES'")
        appendLine("*$table")
        appendLine(":$chain - [0:0]")
        appendLine("-F $chain")
        rules()
        appendLine("COMMIT")
        appendLine("V2NG_RULES")
    }
}
