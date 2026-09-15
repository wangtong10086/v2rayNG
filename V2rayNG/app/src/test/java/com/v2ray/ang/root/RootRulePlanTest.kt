package com.v2ray.ang.root

import org.junit.Assert.*
import org.junit.Test

class RootRulePlanTest {
    @Test fun `UID rules are unique and keep Android marks`() {
        val script = RootRulePlan.capture(false, false, "TEST", 10208, true, false,
            listOf("10221", "10221", "1001", "invalid"))
        assertEquals(1, script.lines().count { it.contains("uid-owner 10221") })
        assertTrue(script.contains("--set-xmark 0x08000000/0x08000000"))
        assertTrue(script.contains("iptables-restore -w 5 --noflush"))
        assertTrue(script.indexOf("100.64.0.0/10 -j RETURN") < script.indexOf("uid-owner 10221"))
        assertTrue(script.indexOf("uid-owner 0-9999 -j RETURN") < script.indexOf("uid-owner 10221"))
    }
    @Test fun `empty allowlist never turns into all apps capture`() {
        val script = RootRulePlan.capture(false, false, "TEST", 10208, true, false, emptyList())
        assertFalse(script.contains("--set-xmark"))
    }
    @Test fun `bypass takes precedence over all apps capture`() {
        val script = RootRulePlan.capture(true, true, "TEST6", 10208, true, true, listOf("10221"))
        assertTrue(script.indexOf("uid-owner 10221 -j RETURN") < script.indexOf("-j REJECT"))
        assertFalse(script.contains("MARK"))
    }
    @Test fun `DNS captures both transports but leaves tailnet and other network IDs alone`() {
        val script = RootRulePlan.dns(10208, 10853, 106, false)
        assertTrue(script.contains("--mark 106/0xffff -p udp --dport 53"))
        assertTrue(script.contains("--mark 106/0xffff -p tcp --dport 53"))
        assertTrue(script.contains("--mark 0/0xffff"))
        assertTrue(script.contains("-d 100.64.0.0/10 -j RETURN"))
        assertFalse(script.contains("-A OUTPUT"))
        assertFalse(script.contains("MARK --set"))
    }
    @Test fun `preflight rejects foreign state and lock errors before acquisition`() {
        fun run(ip: String, firewallStatus: Int) = RootProcessRunner.run(
            listOf("sh", "-c", "set -e\nip() { $ip; }\n" +
                "iptables() { return $firewallStatus; }; ip6tables() { return $firewallStatus; }\n" +
                RootRulePlan.preflight() + "echo acquired"), 1000)
        assertTrue(run("return 1", 1).output.contains("acquired"))
        assertFalse(run("return 1", 0).output.contains("acquired"))
        assertFalse(run("return 1", 4).output.contains("acquired"))
        val foreignRoute = run("case \"${'$'}*\" in *'route show'*) echo foreign-route;; *) return 1;; esac", 1)
        assertEquals(1, foreignRoute.code)
        assertTrue(foreignRoute.output.contains("routing table already in use"))
    }
    @Test fun `operation lock releases when its owning script exits`() {
        val lock = java.io.File.createTempFile("root-rule-plan", ".lock")
        try {
            repeat(2) {
                val result = RootProcessRunner.run(listOf("sh", "-c",
                    RootRulePlan.operationPreamble(lock.absolutePath) + "echo acquired"), 2000)
                assertEquals(0, result.code)
                assertTrue(result.output.contains("acquired"))
            }
        } finally { lock.delete() }
    }

}
