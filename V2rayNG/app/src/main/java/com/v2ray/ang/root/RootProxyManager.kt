package com.v2ray.ang.root

import android.content.Context
import android.net.ConnectivityManager
import android.util.AtomicFile
import com.v2ray.ang.AppConfig
import com.v2ray.ang.handler.MmkvManager
import com.v2ray.ang.handler.SettingsManager
import com.v2ray.ang.root.RootProxyManager.TABLE
import com.v2ray.ang.root.RootProxyManager.TUN
import com.v2ray.ang.root.RootProxyManager.teardown
import com.v2ray.ang.util.LogUtil
import com.v2ray.ang.util.PackageUidResolver
import com.v2ray.ang.util.Utils
import java.io.File

/**
 * Installs and removes the iptables / ip-rule routing that pushes system-wide traffic
 *
 * A bundled `hev-socks5-tunnel` binary (run as root) creates a tun device and forwards it to
 * the in-process core's SOCKS inbound; a mangle MARK chain plus a dedicated routing table /
 * ip rule steer all traffic into the tun. Full TCP + UDP.
 *
 * All rules live in dedicated chains ([AppConfig.ROOT_IPTABLES_CHAIN] in the mangle
 * table, [AppConfig.ROOT_FWD_CHAIN] for LAN sharing) plus a dedicated routing table, so
 * [teardown] is a clean, bounded flush. Teardown runs before every setup (to clear stale
 * rules) and on every stop path — leaving rules behind after the core dies would break
 * the device's connectivity.
 */
object RootProxyManager {

    private const val CHAIN = AppConfig.ROOT_IPTABLES_CHAIN
    private const val TUN = AppConfig.ROOT_TUN_NAME
    private const val TABLE = AppConfig.ROOT_ROUTE_TABLE
    private const val PRIORITY = AppConfig.ROOT_RULE_PRIORITY
    private val MARK = RootRulePlan.MARK

    private val bypassCidrs = RootRulePlan.bypassCidrsV4
    private val bypassCidrsV6 = RootRulePlan.bypassCidrsV6

    fun start(context: Context): Boolean {
        if (!teardown(context)) return false
        val script = buildTun2socksSetup(context) ?: return false
        val result = RootShell.runScript(context, "setup_rules.sh", script)
        if (!result.success) {
            LogUtil.e(AppConfig.TAG, "RootProxyManager: setup failed, rolling back:\n${result.output}")
            teardown(context)
            return false
        }
        return true
    }

    /**
     * Set up LAN/tethering sharing while the device itself uses another mode (e.g. VPN
     * mode). Runs a dedicated client tun2socks into the in-process core's SOCKS inbound
     * and forwards tethered clients into it, WITHOUT capturing the device's own traffic
     * (that keeps flowing through the VpnService). Requires root.
     */
    fun startClientSharing(context: Context): Boolean {
        if (!teardown(context)) return false
        val script = buildTun2socksSetup(context, captureDeviceTraffic = false, forceLanShare = true)
            ?: return false
        val result = RootShell.runScript(context, "setup_rules.sh", script)
        if (!result.success) {
            LogUtil.e(AppConfig.TAG, "RootProxyManager: client sharing setup failed:\n${result.output}")
            teardown(context)
            return false
        }
        LogUtil.i(AppConfig.TAG, "RootProxyManager: LAN client sharing installed")
        return true
    }

    /** Remove all rules and stop helper processes. Safe to call repeatedly. */
    fun stop(context: Context): Boolean = teardown(context)

    fun prepare(context: Context) {
        val directory = File(context.filesDir, AppConfig.ROOT_RUNTIME_DIR).apply { mkdirs() }
        File(directory, "teardown_rules.sh").writeText(buildTeardown(context))
    }

    fun refreshDns(context: Context, netId: Int): Boolean = RootShell.runScript(
        context, "refresh_dns.sh", RootRulePlan.operationPreamble() + RootRulePlan.dns(
            context.applicationInfo.uid, SettingsManager.getLocalDnsPort(), netId, appendHook = false),
    ).success

    private fun teardown(context: Context): Boolean {
        val result = RootShell.runScript(context, "teardown_rules.sh", buildTeardown(context))
        if (!result.success) LogUtil.e(AppConfig.TAG, "RootProxyManager: root cleanup failed: ${result.output}")
        return result.success
    }

    // --------------------------------------------------------------- TUN2SOCKS

    /**
     * @param captureDeviceTraffic when true (Root mode) the device's own OUTPUT traffic is
     *   marked into the tun. When false (VPN-mode LAN sharing) the device keeps using the
     *   VpnService and only forwarded clients are routed into this tun.
     * @param forceLanShare force the LAN/tethering forward rules on regardless of the pref
     *   (used by VPN-mode sharing, where the whole point is forwarding clients).
     */
    private fun buildTun2socksSetup(
        context: Context,
        captureDeviceTraffic: Boolean = true,
        forceLanShare: Boolean = false,
    ): String? {
        val bin = File(context.applicationInfo.nativeLibraryDir, AppConfig.ROOT_TUN2SOCKS_BIN)
        if (!bin.exists()) {
            LogUtil.e(AppConfig.TAG, "RootProxyManager: hev-socks5-tunnel binary missing at ${bin.absolutePath}")
            return null
        }
        val appUid = context.applicationInfo.uid
        val socksUsername = SettingsManager.getSocksUsername()
        val socksPassword = SettingsManager.getSocksPassword()
        val port = SettingsManager.getSocksPort()
        val runDir = File(context.filesDir, AppConfig.ROOT_RUNTIME_DIR)
        if (!runDir.isDirectory && !runDir.mkdirs()) {
            LogUtil.e(AppConfig.TAG, "RootProxyManager: failed to create runtime directory at ${runDir.absolutePath}")
            return null
        }
        val pidFile = File(runDir, "tun2socks.pid").absolutePath
        val logFile = File(runDir, "tun2socks.log").absolutePath
        val cfgFile = File(runDir, "tun2socks.yml")
        val ipv6 = MmkvManager.decodeSettingsBool(AppConfig.PREF_IPV6_ENABLED)
        val lanShare = forceLanShare || MmkvManager.decodeSettingsBool(AppConfig.PREF_ROOT_LAN_SHARING)

        val config = buildHevConfig(socksUsername, socksPassword, port, ipv6)
        if (!writeHevConfig(cfgFile, config)) {
            return null
        }
        val cfgPath = cfgFile.absolutePath

        // Per-app proxy/bypass (mirrors what VpnService does via allowed/disallowed apps).
        val perAppEnabled = MmkvManager.decodeSettingsBool(AppConfig.PREF_PER_APP_PROXY)
        val bypassApps = MmkvManager.decodeSettingsBool(AppConfig.PREF_BYPASS_APPS)
        val selectedUids = if (perAppEnabled) {
            val pkgs = MmkvManager.decodeSettingsStringSet(AppConfig.PREF_PER_APP_PROXY_SET)?.toList().orEmpty()
            if (pkgs.isNotEmpty()) PackageUidResolver.packageNamesToUids(context, pkgs) else emptyList()
        } else {
            emptyList()
        }

        val connectivity = context.getSystemService(ConnectivityManager::class.java)
        val netId = connectivity.activeNetwork?.toString()?.toIntOrNull() ?: 0
        val owned = File(runDir, "owned").absolutePath

        return buildString {
            append(RootRulePlan.operationPreamble())
            append(RootRulePlan.preflight())
            appendLine("echo 1 > '$owned'")
            appendLine("cat /proc/sys/net/ipv4/conf/all/rp_filter > '${runDir.absolutePath}/rp_filter.before'")
            appendLine("cat /proc/sys/net/ipv4/ip_forward > '${runDir.absolutePath}/ip_forward.before'")
            appendLine("BIN='${bin.absolutePath}'")
            // tun device node
            appendLine("if [ ! -e /dev/net/tun ]; then mkdir -p /dev/net; mknod /dev/net/tun c 10 200; chmod 666 /dev/net/tun; fi")
            // The HEV config is written separately by the app process. Never place credentials
            // in this root shell script, even when YAML quoting would otherwise be valid.
            appendLine("nohup \"\$BIN\" '$cfgPath' >'$logFile' 2>&1 9>&- &")
            appendLine("T2S_PID=\$!")
            appendLine("echo \$T2S_PID \$(awk '{print \$22}' /proc/\$T2S_PID/stat) > '$pidFile'")
            appendLine("echo ${AppConfig.ROOT_OOM_SCORE} > /proc/\$T2S_PID/oom_score_adj 2>/dev/null || true")
            // wait for the interface hev creates to appear
            appendLine("i=0; while [ \$i -lt 20 ]; do ip link show $TUN >/dev/null 2>&1 && break; sleep 0.3; i=\$((i+1)); done")
            appendLine("ip link show $TUN >/dev/null 2>&1 || { echo 'tun device did not come up'; cat '$logFile' 2>/dev/null; exit 1; }")
            // relax reverse-path filtering for the tun
            appendLine("echo 0 > /proc/sys/net/ipv4/conf/$TUN/rp_filter 2>/dev/null || true")
            appendLine("echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null || true")
            // address + default route in a dedicated table
            appendLine("ip addr add ${AppConfig.ROOT_TUN_ADDR_V4} dev $TUN 2>/dev/null || true")
            appendLine("ip link set dev $TUN up")
            appendLine("ip route replace default dev $TUN table $TABLE")
            appendLine("ip rule add fwmark $MARK table $TABLE priority $PRIORITY")
            // mark the device's own packets into the tun (Root mode only)
            if (captureDeviceTraffic) {
                append(RootRulePlan.dns(appUid, SettingsManager.getLocalDnsPort(), netId, appendHook = true))
                append(RootRulePlan.capture(false, false, CHAIN, appUid,
                    perAppEnabled, bypassApps, selectedUids))
            }
            // optionally route hotspot / USB-tethered clients through the tun too
            if (lanShare) {
                appendLine("echo 1 > '${runDir.absolutePath}/lan-owned'")
                append(buildLanShareSetup(captureDeviceTraffic, ipv6))
            }
            if (captureDeviceTraffic) {
                // A failed IPv6 capture/reject rule must roll back instead of reporting success.
                if (ipv6) {
                    // route the device's v6 into the tun, same as v4
                    appendLine("ip -6 addr add ${AppConfig.ROOT_TUN_ADDR_V6} dev $TUN 2>/dev/null || true")
                    appendLine("ip -6 route replace default dev $TUN table $TABLE 2>/dev/null || true")
                    appendLine("ip -6 rule add fwmark $MARK table $TABLE priority $PRIORITY 2>/dev/null || true")
                    append(RootRulePlan.capture(true, false, CHAIN, appUid, perAppEnabled, bypassApps, selectedUids))
                } else {
                    // v6 disabled: blackhole native v6 egress for the captured apps so they
                    // fall back to v4-through-proxy, matching what a v4-only VpnService does.
                    append(RootRulePlan.capture(true, true, AppConfig.ROOT_V6_CHAIN, appUid, perAppEnabled, bypassApps, selectedUids))
                }
            }
        }
    }

    /**
     * hev-socks5-tunnel YAML config. hev creates the tun device named [TUN] itself, assigns it
     * the tun addresses, and forwards everything it receives to the core's SOCKS inbound on
     * loopback (TCP + UDP). MTU is taken from the existing VPN MTU setting. v6 is only given a
     * tun address when IPv6 is enabled; whether v6 actually flows in is decided separately by
     * the v6 route into [TABLE].
     */
    private fun buildHevConfig(socksUsername: String?, socksPassword: String?, socksPort: Int, ipv6: Boolean): String {
        val v4 = AppConfig.ROOT_TUN_ADDR_V4.substringBefore("/")
        val v6 = AppConfig.ROOT_TUN_ADDR_V6.substringBefore("/")
        return buildString {
            appendLine("tunnel:")
            appendLine("  name: '$TUN'")
            appendLine("  mtu: ${SettingsManager.getVpnMtu()}")
            appendLine("  multi-queue: true")
            appendLine("  ipv4: '$v4'")
            if (ipv6) appendLine("  ipv6: '$v6'")
            appendLine("socks5:")
            appendLine("  port: $socksPort")
            appendLine("  address: '${AppConfig.LOOPBACK}'")
            appendLine("  udp: 'udp'")
            if (socksUsername != null && socksPassword != null) {
                appendLine("  username: ${socksUsername.toSingleQuotedYamlScalar()}")
                appendLine("  password: ${socksPassword.toSingleQuotedYamlScalar()}")
            }
            appendLine("  tcp-fastopen: true")
        }
    }

    private fun writeHevConfig(file: File, config: String): Boolean {
        val atomicFile = AtomicFile(file)
        val output = try {
            atomicFile.startWrite()
        } catch (e: Exception) {
            LogUtil.e(AppConfig.TAG, "RootProxyManager: failed to open HEV config at ${file.absolutePath}", e)
            return false
        }

        return try {
            output.write(config.toByteArray(Charsets.UTF_8))
            atomicFile.finishWrite(output)
            true
        } catch (e: Exception) {
            atomicFile.failWrite(output)
            LogUtil.e(AppConfig.TAG, "RootProxyManager: failed to write HEV config at ${file.absolutePath}", e)
            false
        }
    }

    // -------------------------------------------------- LAN / tethering sharing

    /**
     * Route Wi-Fi-hotspot / USB-tethered clients through the tun as well (ipv4).
     * Best-effort: wrapped in `set +e` so a failure here never breaks the working proxy.
     * Mirrors Magic_V2Ray's hotspot rules (FORWARD accept, DNS DNAT, source-based policy
     * routing for private client ranges, MSS clamp).
     */
    private fun buildLanShareSetup(captureDeviceTraffic: Boolean, ipv6: Boolean): String {
        val fwd = AppConfig.ROOT_FWD_CHAIN
        val dnsChain = AppConfig.ROOT_DNS_CHAIN
        val v6fwd = AppConfig.ROOT_V6_FWD_CHAIN
        val v6pre = AppConfig.ROOT_V6_PRE_CHAIN
        // Use the app's configured remote DNS (first plain IPv4) as the DNAT target for
        // tethered clients; fall back to the default when it's a DoH/DoT/IPv6 value that
        // can't be a DNAT target.
        val dns = SettingsManager.getRemoteDnsServers()
            .firstOrNull { Utils.isPureIpAddress(it) && !it.contains(":") }
            ?: AppConfig.ROOT_LAN_DNS
        val lanCidrs = listOf("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
        return buildString {
            appendLine("set -e")
            appendLine("echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true")
            // forward traffic to/from the tun
            appendLine("iptables -N $fwd 2>/dev/null || true")
            appendLine("iptables -F $fwd")
            appendLine("iptables -A $fwd -i $TUN -j ACCEPT")
            appendLine("iptables -A $fwd -o $TUN -j ACCEPT")
            appendLine("iptables -D FORWARD -j $fwd 2>/dev/null || true")
            appendLine("iptables -I FORWARD -j $fwd")
            // clamp MSS to avoid TLS fragmentation overhead through the tunnel
            appendLine("iptables -t mangle -D FORWARD -o $TUN -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1350 2>/dev/null || true")
            appendLine("iptables -t mangle -A FORWARD -o $TUN -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1350")
            // hijack tethered clients' DNS into a dedicated chain so it resolves through the
            // tunnel; the chain keeps teardown independent of the resolver IP
            appendLine("iptables -t nat -N $dnsChain 2>/dev/null || true")
            appendLine("iptables -t nat -F $dnsChain")
            lanCidrs.forEach {
                appendLine("iptables -t nat -A $dnsChain ! -i $TUN -d $it -p udp --dport 53 -j DNAT --to $dns")
            }
            appendLine("iptables -t nat -D PREROUTING -j $dnsChain 2>/dev/null || true")
            appendLine("iptables -t nat -A PREROUTING -j $dnsChain")
            // policy routing: return-path via main, LAN direct, the rest via the tun table
            appendLine("ip rule add iif lo goto 7100 pref 6100 2>/dev/null || true")
            appendLine("ip rule add iif $TUN lookup main suppress_prefixlength 0 pref 6110 2>/dev/null || true")
            appendLine("ip rule add iif $TUN goto 7100 pref 6120 2>/dev/null || true")
            appendLine("ip rule add to 10.0.0.0/8 lookup main pref 6125 2>/dev/null || true")
            appendLine("ip rule add to 172.16.0.0/12 lookup main pref 6126 2>/dev/null || true")
            appendLine("ip rule add to 192.168.0.0/16 lookup main pref 6127 2>/dev/null || true")
            appendLine("ip rule add from 10.0.0.0/8 lookup $TABLE pref 6130 2>/dev/null || true")
            appendLine("ip rule add from 172.16.0.0/12 lookup $TABLE pref 6140 2>/dev/null || true")
            appendLine("ip rule add from 192.168.0.0/16 lookup $TABLE pref 6150 2>/dev/null || true")
            appendLine("ip rule add nop pref 7100 2>/dev/null || true")

            // ---------------------------------------------------------- IPv6 clients
            // Tethered/hotspot clients get a native (RA-assigned) global IPv6. The IPv4 rules
            // above don't touch it, so it egresses the upstream interface directly, bypassing
            // the proxy = IPv6 leak. Handle it explicitly (mirrors vincentng295/Magic_V2Ray
            // cae4f7f): route it through the tun when v6 is enabled, reject it when it isn't.
            appendLine("ip6tables -N $v6fwd 2>/dev/null || true")
            appendLine("ip6tables -F $v6fwd")
            appendLine("ip6tables -D FORWARD -j $v6fwd 2>/dev/null || true")
            appendLine("ip6tables -I FORWARD -j $v6fwd")
            if (ipv6) {
                // When the device itself isn't capturing v6 (VPN-mode sharing) the tun table
                // has no v6 default and the tun has no v6 address — add them so marked client
                // v6 has somewhere to go. In Root mode the device-capture block already did.
                if (!captureDeviceTraffic) {
                    appendLine("ip -6 addr add ${AppConfig.ROOT_TUN_ADDR_V6} dev $TUN 2>/dev/null || true")
                    appendLine("ip -6 route replace default dev $TUN table $TABLE 2>/dev/null || true")
                    appendLine("ip -6 rule add fwmark $MARK table $TABLE priority $PRIORITY 2>/dev/null || true")
                }
                // allow forwarding to/from the tun
                appendLine("ip6tables -A $v6fwd -i $TUN -j ACCEPT")
                appendLine("ip6tables -A $v6fwd -o $TUN -j ACCEPT")
                // mark forwarded (non-locally-sourced) client v6 into the tun table. DNS first
                // so a query to a LAN/router resolver is still tunneled (MARK survives RETURN);
                // keep loopback, link-local (NDP/RA) and ULA/multicast direct.
                appendLine("ip6tables -t mangle -N $v6pre 2>/dev/null || true")
                appendLine("ip6tables -t mangle -F $v6pre")
                appendLine("ip6tables -t mangle -A $v6pre ! -i $TUN -p udp --dport 53 -j MARK --set-xmark $MARK")
                appendLine("ip6tables -t mangle -A $v6pre ! -i $TUN -p tcp --dport 53 -j MARK --set-xmark $MARK")
                bypassCidrsV6.forEach { appendLine("ip6tables -t mangle -A $v6pre ! -i $TUN -d $it -j RETURN") }
                appendLine("ip6tables -t mangle -A $v6pre ! -i $TUN -j MARK --set-xmark $MARK")
                appendLine("ip6tables -t mangle -D PREROUTING -j $v6pre 2>/dev/null || true")
                appendLine("ip6tables -t mangle -A PREROUTING -j $v6pre")
                // fail closed: any forwarded v6 that wasn't marked into the tun (e.g. the
                // addrtype match is unavailable, or marking failed) is rejected rather than
                // leaked straight out the upstream interface.
                appendLine("ip6tables -A $v6fwd -j REJECT --reject-with icmp6-no-route")
            } else {
                // v6 disabled: reject forwarded clients' native v6 so it can't leak past the
                // proxy (the device's own v6 is blackholed separately in OUTPUT).
                appendLine("ip6tables -A $v6fwd -j REJECT --reject-with icmp6-no-route")
            }
        }
    }

    // ---------------------------------------------------------------- teardown

    private fun buildTeardown(context: Context): String {
        val runDir = File(context.filesDir, AppConfig.ROOT_RUNTIME_DIR)
        val pidFile = File(runDir, "tun2socks.pid").absolutePath
        return buildString {
            appendLine("[ -f '${runDir.absolutePath}/owned' ] || exit 0")
            append(RootRulePlan.operationPreamble())
            appendLine("if [ -f '$pidFile' ]; then read helper_pid helper_start < '$pidFile'; else helper_pid=0; helper_start=0; fi")
            appendLine("actual_start=\$(awk '{print \$22}' /proc/\$helper_pid/stat 2>/dev/null || true)")
            appendLine("if ip link show $TUN >/dev/null 2>&1 && [ \"\$actual_start\" != \"\$helper_start\" ]; then echo 'refusing to remove a foreign root tunnel'; exit 1; fi")
            appendLine("cleanup_failed=0")
            appendLine("remove_chain() {")
            appendLine("  tool=\$1; table=\$2; hook=\$3; chain=\$4")
            appendLine("  if \"\$tool\" -t \"\$table\" -S \"\$chain\" >/dev/null 2>&1; then")
            appendLine("    while true; do")
            appendLine("      if \"\$tool\" -t \"\$table\" -C \"\$hook\" -j \"\$chain\" >/dev/null 2>&1; then")
            appendLine("        \"\$tool\" -t \"\$table\" -D \"\$hook\" -j \"\$chain\" || return \$?")
            appendLine("      else code=\$?; [ \"\$code\" = 1 ] || return \"\$code\"; break; fi")
            appendLine("    done")
            appendLine("    \"\$tool\" -t \"\$table\" -F \"\$chain\" && \"\$tool\" -t \"\$table\" -X \"\$chain\"")
            appendLine("  else code=\$?; [ \"\$code\" = 1 ]; fi")
            appendLine("}")
            val chains = listOf(
                "iptables nat OUTPUT ${RootRulePlan.DNS_CHAIN}",
                "iptables mangle OUTPUT $CHAIN",
                "ip6tables mangle OUTPUT $CHAIN",
                "ip6tables filter OUTPUT ${AppConfig.ROOT_V6_CHAIN}",
                "iptables filter FORWARD ${AppConfig.ROOT_FWD_CHAIN}",
                "iptables nat PREROUTING ${AppConfig.ROOT_DNS_CHAIN}",
                "ip6tables filter FORWARD ${AppConfig.ROOT_V6_FWD_CHAIN}",
                "ip6tables mangle PREROUTING ${AppConfig.ROOT_V6_PRE_CHAIN}",
            )
            chains.forEach { appendLine("remove_chain $it || cleanup_failed=1") }
            appendLine("[ \"\$cleanup_failed\" = 0 ] || { echo 'root firewall cleanup failed'; exit 1; }")
            // routing rule + table
            appendLine("ip rule del fwmark $MARK table $TABLE priority $PRIORITY 2>/dev/null || true")
            appendLine("ip -6 rule del fwmark $MARK table $TABLE priority $PRIORITY 2>/dev/null || true")
            appendLine("ip route flush table $TABLE 2>/dev/null || true")
            appendLine("ip -6 route flush table $TABLE 2>/dev/null || true")
            appendLine("if [ -f '${runDir.absolutePath}/lan-owned' ]; then")
            appendLine("iptables -t mangle -D FORWARD -o $TUN -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1350 2>/dev/null || true")
            run {
                val policies = listOf(
                    "iif lo goto 7100 pref 6100",
                    "iif $TUN lookup main suppress_prefixlength 0 pref 6110",
                    "iif $TUN goto 7100 pref 6120",
                    "to 10.0.0.0/8 lookup main pref 6125",
                    "to 172.16.0.0/12 lookup main pref 6126",
                    "to 192.168.0.0/16 lookup main pref 6127",
                    "from 10.0.0.0/8 lookup $TABLE pref 6130",
                    "from 172.16.0.0/12 lookup $TABLE pref 6140",
                    "from 192.168.0.0/16 lookup $TABLE pref 6150",
                    "nop pref 7100",
                )
                policies.forEach { appendLine("ip rule del $it 2>/dev/null || true") }
            }
            appendLine("fi")
            // tun device down + helper process
            appendLine("ip link set dev $TUN down 2>/dev/null || true")
            appendLine("[ \"\$actual_start\" = \"\$helper_start\" ] && [ \"\$helper_pid\" -gt 1 ] && kill \$helper_pid 2>/dev/null || true")
            appendLine("rm -f '$pidFile'")
            appendLine("if [ -f '${runDir.absolutePath}/rp_filter.before' ] && [ \"\$(cat /proc/sys/net/ipv4/conf/all/rp_filter)\" = 0 ]; then cat '${runDir.absolutePath}/rp_filter.before' > /proc/sys/net/ipv4/conf/all/rp_filter; fi")
            appendLine("if [ -f '${runDir.absolutePath}/ip_forward.before' ] && [ \"\$(cat /proc/sys/net/ipv4/ip_forward)\" = 1 ]; then cat '${runDir.absolutePath}/ip_forward.before' > /proc/sys/net/ipv4/ip_forward; fi")
            appendLine("rm -f '${runDir.absolutePath}/owned' '${runDir.absolutePath}/lan-owned'")
        }
    }
}

internal fun String.toSingleQuotedYamlScalar(): String = "'${replace("'", "''")}'"
