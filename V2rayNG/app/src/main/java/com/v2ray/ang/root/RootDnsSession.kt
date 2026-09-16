package com.v2ray.ang.root

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.provider.Settings
import com.v2ray.ang.AppConfig
import com.v2ray.ang.handler.SettingsManager
import com.v2ray.ang.util.Utils
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/** One root helper, owned and closed by CoreRootService. All calls run on its serialized IO job. */
internal class RootDnsSession(
    private val context: Context,
    private val appPolicy: RootRulePlan.AppPolicy,
    private val onFailure: () -> Unit,
) : AutoCloseable {
    @Volatile private var process: Process? = null
    private var reader: Thread? = null
    private val replies = LinkedBlockingQueue<String>(16)
    private var fingerprint: String? = null

    fun start() {
        check(Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) { "Managed root DNS requires Android 10 or later" }
        check(process == null)
        val directory = File(context.filesDir, AppConfig.ROOT_RUNTIME_DIR)
        val args = listOf(context.applicationInfo.sourceDir, directory.absolutePath,
            File(directory, "teardown_rules.sh").absolutePath).map { "'${it.replace("'", "'\\''")}'" }
        val command = "CLASSPATH=${args[0]} app_process /system/bin ${RootDnsHelper::class.java.name} ${args[1]} ${args[2]}"
        val child = ProcessBuilder("su", "-c", command).redirectErrorStream(true).start()
        process = child
        reader = thread(name = "root-dns-session", isDaemon = true) {
            try {
                child.inputStream.bufferedReader().useLines { lines ->
                    lines.forEach { if (it.startsWith("V2NG:")) replies.offer(it) }
                }
            } catch (_: java.io.IOException) {
                // close() can interrupt this session's output stream.
            } finally {
                replies.offer("V2NG:EOF")
                if (process === child) onFailure()
            }
        }
        val ready = response()
        check(ready == "V2NG:READY") { "Root DNS helper start: $ready" }
    }

    /** Reconcile only changed physical-network properties; no timer rewrites system DNS. */
    fun refresh(): Boolean {
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
        val network = connectivity.activeNetwork ?: return false
        val properties = connectivity.getLinkProperties(network) ?: return false
        val capabilities = connectivity.getNetworkCapabilities(network) ?: return false
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return false
        val netId = network.toString().toIntOrNull() ?: error("Invalid physical network ID")
        // NetworkCapabilities does not expose getTransportTypes in the public SDK.
        // Read its public platform constants so newer transports are not silently discarded.
        val transports = NetworkCapabilities::class.java.fields
            .filter { it.name.startsWith("TRANSPORT_") && it.type == Int::class.javaPrimitiveType }
            .map { it.getInt(null) }.distinct().filter { capabilities.hasTransport(it) }
        val privateDns = Settings.Global.getString(context.contentResolver, "private_dns_mode")
        val managedAddress = properties.dnsServers.filterIsInstance<java.net.Inet4Address>()
            .firstOrNull()?.hostAddress ?: SettingsManager.getVpnDnsServers()
            .firstOrNull { Utils.isPureIpAddress(it) && !it.contains(':') } ?: AppConfig.DNS_VPN
        val command = JSONObject().put("operation", "apply").put("netId", netId)
            .put("managedServers", JSONArray(listOf(managedAddress)))
            .put("interfaces", JSONArray(listOfNotNull(properties.interfaceName)))
            .put("transports", JSONArray(transports))
            .put("metered", !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED))
            .put("privateDnsOff", privateDns == "off")
        val signature = command.toString() + properties.dnsServers.joinToString { it.hostAddress.orEmpty() }
        if (signature == fingerprint) return true
        check(RootProxyManager.refreshDns(context, netId, appPolicy)) { "Root DNS routing update failed" }
        request(command)
        fingerprint = signature
        return true
    }

    private fun response(): String = replies.poll(12, TimeUnit.SECONDS) ?: error("Root DNS helper response timeout")

    private fun request(command: JSONObject) {
        val child = checkNotNull(process)
        child.outputStream.write((command.toString() + "\n").toByteArray())
        child.outputStream.flush()
        val result = response()
        check(result == "V2NG:OK") { "Root DNS helper operation: $result" }
    }

    override fun close() {
        val child = process ?: return
        process = null
        // EOF is also used when Android kills the daemon: restore DNS, then remove capture rules.
        child.outputStream.close()
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30)
        while (System.nanoTime() < deadline) {
            try { child.exitValue(); break } catch (_: IllegalThreadStateException) { Thread.sleep(20) }
        }
        try { child.exitValue() } catch (_: IllegalThreadStateException) { child.destroy() }
        child.inputStream.close()
        reader?.join(200)
        reader = null
        fingerprint = null
    }
}
