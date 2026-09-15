package com.v2ray.ang.root

import android.os.Process
import com.v2ray.ang.AppConfig

/** Deterministic device-capture rules. Android netId/permission bits remain intact. */
internal object RootRulePlan {
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


    fun capture(
        ipv6: Boolean, rejectV6: Boolean, chain: String, appUid: Int,
        perApp: Boolean, bypass: Boolean, selected: List<String>,
    ): String {
        val table = if (rejectV6) "filter" else "mangle"
        val command = if (ipv6) "ip6tables-restore" else "iptables-restore"
        val selectedUids = selected.filter { (it.toIntOrNull() ?: -1) >= 0 }.distinct().sortedBy { it.toInt() }
        val target = if (rejectV6) "REJECT --reject-with icmp6-adm-prohibited" else "MARK --set-xmark $MARK"
        return batch(command, table, chain) {
            appendLine("-A $chain -m owner --uid-owner $appUid -j RETURN")
            // Android's protected sockets and explicit infrastructure UIDs must retain their network.
            appendLine("-A $chain -m mark --mark 0x20000/0x20000 -j RETURN")
            appendLine("-A $chain -m owner --uid-owner 0-${Process.FIRST_APPLICATION_UID - 1} -j RETURN")
            (if (ipv6) bypassCidrsV6 else bypassCidrsV4).forEach { appendLine("-A $chain -d $it -j RETURN") }
            if (perApp && bypass) selectedUids.forEach {
                appendLine("-A $chain -m owner --uid-owner $it -j RETURN")
            }
            if (perApp && !bypass) selectedUids.forEach {
                appendLine("-A $chain -m owner --uid-owner $it -j $target")
            } else appendLine("-A $chain -j $target")
            appendLine("-A OUTPUT -j $chain")
        }
    }

    fun dns(appUid: Int, port: Int, netId: Int, appendHook: Boolean): String =
        batch("iptables-restore", "nat", DNS_CHAIN) {
            appendLine("-A $DNS_CHAIN -m owner --uid-owner $appUid -j RETURN")
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
