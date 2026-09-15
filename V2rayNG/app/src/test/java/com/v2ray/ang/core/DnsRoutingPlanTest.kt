package com.v2ray.ang.core

import com.google.gson.Gson
import com.v2ray.ang.dto.CoreConfigContext.RoutingDomainRule
import com.v2ray.ang.dto.V2rayConfig
import com.v2ray.ang.dto.entities.RulesetItem
import org.junit.Assert.*
import org.junit.Test

class DnsRoutingPlanTest {
    @Test fun `private names use network DNS without sending public China names there`() {
        val plan = DnsRoutingPlan.build(listOf(RoutingDomainRule(listOf("geosite:private", "geosite:cn"), "direct")),
            listOf("223.5.5.5"), listOf("https://1.1.1.1/dns-query"), listOf("192.168.1.1"))
        val servers = plan.servers.map { it as V2rayConfig.DnsBean.ServersBean }
        assertEquals("192.168.1.1", servers[0].address)
        assertEquals(listOf("geosite:private"), servers[0].domains)
        assertEquals("223.5.5.5", servers[1].address)
        assertEquals(listOf("geosite:cn"), servers[1].domains)
    }
    @Test fun `compound traffic rules cannot become DNS rules`() {
        val domain = RulesetItem(domain = listOf("domain:example.com"), outboundTag = "direct")
        assertTrue(DnsRoutingPlan.canSelectResolver(domain))
        for (rule in listOf(domain.copy(port = "443"), domain.copy(network = "udp"),
            domain.copy(ip = listOf("geoip:cn")), domain.copy(process = listOf("10221")),
            domain.copy(protocol = listOf("bittorrent")), domain.copy(outboundTag = "block"),
            domain.copy(enabled = false))) {
            assertFalse(DnsRoutingPlan.canSelectResolver(rule))
        }
    }
    @Test fun `specific proxy exception precedes broader China rule with complete failover groups`() {
        val plan = DnsRoutingPlan.build(listOf(
            RoutingDomainRule(listOf("full:short.weixin.qq.com"), "proxy"),
            RoutingDomainRule(listOf("geosite:cn"), "direct")),
            listOf("223.5.5.5", "119.29.29.29", "223.5.5.5"),
            listOf("https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"))
        val servers = plan.servers.map { it as V2rayConfig.DnsBean.ServersBean }
        assertEquals(6, servers.size)
        assertEquals("full:short.weixin.qq.com", servers[0].domains!!.single())
        assertEquals(false, servers[0].finalQuery)
        assertEquals(true, servers[1].finalQuery)
        assertEquals("geosite:cn", servers[2].domains!!.single())
        assertEquals(true, servers[3].finalQuery)
        assertEquals(servers[2].tag, servers[3].tag)
        assertEquals(listOf(servers[2].tag), plan.directTags)
        assertNull(servers[2].expectIPs)
        assertNull(servers[4].domains)
        assertTrue(servers.take(4).all { it.skipFallback == true })
    }
    @Test fun `root DNS listener handles TCP and UDP without sniffing`() {
        val inbound = DnsRoutingPlan.rootInbound(10853)
        assertEquals("127.0.0.1", inbound.listen)
        assertEquals("tcp,udp", inbound.settings!!.network)
        assertEquals(53, inbound.settings!!.port)
        assertNull(inbound.sniffing)
    }
    @Test fun `previous DNS and inbound serialized formats remain readable`() {
        val gson = Gson()
        val oldDns = gson.fromJson("""{"servers":["1.1.1.1"],"queryStrategy":"UseIP"}""", V2rayConfig.DnsBean::class.java)
        assertEquals("UseIP", oldDns.queryStrategy)
        val oldInbound = gson.fromJson("""{"tag":"socks","port":10808,"protocol":"socks","settings":{"udp":false,"auth":"noauth"}}""", V2rayConfig.InboundBean::class.java)
        assertEquals(false, oldInbound.settings!!.udp)
        assertNull(oldInbound.settings!!.network)
        val oldRule = gson.fromJson("""{"domain":["domain:example.com"],"outboundTag":"block","port":"443","network":"udp"}""", RulesetItem::class.java)
        assertFalse(DnsRoutingPlan.canSelectResolver(oldRule))
    }
}
