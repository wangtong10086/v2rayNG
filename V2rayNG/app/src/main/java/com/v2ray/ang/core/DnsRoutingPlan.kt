package com.v2ray.ang.core

import com.v2ray.ang.AppConfig
import com.v2ray.ang.dto.CoreConfigContext
import com.v2ray.ang.dto.V2rayConfig
import com.v2ray.ang.dto.entities.RulesetItem

/** Pure DNS policy compiler. DNS questions have no application port or transport selector. */
internal object DnsRoutingPlan {
    private const val UPSTREAM_TIMEOUT_MS = 2000
    fun canSelectResolver(rule: RulesetItem): Boolean = rule.enabled &&
        !rule.domain.isNullOrEmpty() && rule.ip.isNullOrEmpty() &&
        rule.process.isNullOrEmpty() && rule.port.isNullOrBlank() &&
        rule.network.isNullOrBlank() && rule.protocol.isNullOrEmpty() &&
        rule.outboundTag != AppConfig.TAG_BLOCKED

    data class Plan(val servers: ArrayList<Any>, val directTags: List<String>)

    fun build(
        rules: List<CoreConfigContext.RoutingDomainRule>,
        domestic: List<String>,
        remote: List<String>,
        local: List<String> = emptyList(),
    ): Plan {
        require(domestic.isNotEmpty() && remote.isNotEmpty()) { "DNS upstream list is empty" }
        val servers = arrayListOf<Any>()
        val directTags = mutableListOf<String>()
        val expanded = rules.filter { it.outboundTag != AppConfig.TAG_BLOCKED }.flatMap { rule ->
            if (rule.outboundTag == AppConfig.TAG_DIRECT && local.isNotEmpty()) {
                val (privateDomains, otherDomains) = rule.domain.partition { it == AppConfig.GEOSITE_PRIVATE }
                listOfNotNull(
                    privateDomains.takeIf { it.isNotEmpty() }?.let { rule.copy(domain = it) },
                    otherDomains.takeIf { it.isNotEmpty() }?.let { rule.copy(domain = it) },
                )
            } else listOf(rule)
        }
        expanded.forEachIndexed { index, rule ->
            val direct = rule.outboundTag == AppConfig.TAG_DIRECT
            val addresses = when {
                direct && local.isNotEmpty() && rule.domain == listOf(AppConfig.GEOSITE_PRIVATE) -> local
                direct -> domestic
                else -> remote
            }.distinct()
            val tag = if (direct) "${AppConfig.TAG_DOMESTIC_DNS}_$index" else AppConfig.TAG_DNS
            if (direct) directTags.add(tag)
            addresses.forEachIndexed { serverIndex, address ->
                servers.add(V2rayConfig.DnsBean.ServersBean(
                    address = address,
                    domains = rule.domain.distinct(),
                    skipFallback = true,
                    // Xray stops collecting matching servers here, preserving routing order
                    // while still allowing every upstream in this rule's group to fail over.
                    finalQuery = serverIndex == addresses.lastIndex,
                    timeoutMs = UPSTREAM_TIMEOUT_MS,
                    tag = tag,
                ))
            }
        }
        remote.distinct().forEach { address ->
            servers.add(V2rayConfig.DnsBean.ServersBean(address = address, timeoutMs = UPSTREAM_TIMEOUT_MS, tag = AppConfig.TAG_DNS))
        }
        return Plan(servers, directTags)
    }

    fun rootInbound(port: Int) = V2rayConfig.InboundBean(
        tag = AppConfig.TAG_ROOT_DNS_IN,
        port = port,
        protocol = "dokodemo-door",
        listen = AppConfig.LOOPBACK,
        settings = V2rayConfig.InboundBean.InSettingsBean(
            address = AppConfig.DNS_VPN, port = AppConfig.PORT_DNS, network = "tcp,udp",
        ),
        // DNS must not wait for the SOCKS inbound's TLS/HTTP sniffer.
        sniffing = null,
    )
}
