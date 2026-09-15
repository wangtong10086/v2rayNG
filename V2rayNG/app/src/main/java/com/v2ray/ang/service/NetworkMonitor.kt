package com.v2ray.ang.service

import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import com.v2ray.ang.AppConfig
import com.v2ray.ang.util.LogUtil
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/** Watches one physical upstream. Callbacks only enqueue work; unregister closes their admission gate. */
class NetworkMonitor(
    private val connectivity: ConnectivityManager,
    private val onUnderlyingNetworksChanged: (Array<Network>?) -> Unit,
    private val onHandover: () -> Unit,
    private val onDnsChanged: () -> Unit = {},
) {
    private val gate = NetworkCallbackGate()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var upstream: Network? = null
    private var handoverJob: Job? = null
    private var registered = false
    private val request = NetworkRequest.Builder()
        .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
        .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        .build()

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) = gate.dispatch {
            val previous = upstream
            upstream = network
            onUnderlyingNetworksChanged(arrayOf(network))
            if (previous != null && previous != network) scheduleHandover(network)
        }

        override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) = gate.dispatch {
            if (network == upstream) onUnderlyingNetworksChanged(arrayOf(network))
        }

        override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) = gate.dispatch {
            if (network == upstream) onDnsChanged()
        }

        override fun onLost(network: Network) = gate.dispatch {
            // A late loss from the old Wi-Fi must not clear the new cellular upstream.
            if (network == upstream) onUnderlyingNetworksChanged(null)
        }
    }

    fun register() = gate.dispatch {
        if (registered) return@dispatch
        try {
            connectivity.requestNetwork(request, callback)
            registered = true
        } catch (e: Exception) {
            LogUtil.e(AppConfig.TAG, "NetworkMonitor: register physical upstream failed", e)
        }
    }

    fun unregister() {
        gate.close()
        scope.cancel()
        handoverJob = null
        upstream = null
        if (!registered) return
        registered = false
        try {
            connectivity.unregisterNetworkCallback(callback)
        } catch (e: Exception) {
            LogUtil.w(AppConfig.TAG, "NetworkMonitor: unregister physical upstream failed", e)
        }
    }

    private fun scheduleHandover(network: Network) {
        handoverJob?.cancel()
        handoverJob = scope.launch {
            delay(1000)
            gate.dispatch {
                if (network == upstream) onHandover()
            }
        }
    }
}
