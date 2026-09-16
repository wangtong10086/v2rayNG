package com.v2ray.ang.service

import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.IBinder
import com.v2ray.ang.AppConfig
import com.v2ray.ang.contracts.ServiceControl
import com.v2ray.ang.core.CoreServiceManager
import com.v2ray.ang.handler.AppLocaleManager
import com.v2ray.ang.handler.NotificationManager
import com.v2ray.ang.helper.MessageHelper
import com.v2ray.ang.root.RootDnsSession
import com.v2ray.ang.root.RootProxyManager
import com.v2ray.ang.util.LogUtil
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.withContext
import java.lang.ref.SoftReference

/** Owns root setup, DNS lease and teardown in one serialized service lifetime. */
class CoreRootService : Service(), ServiceControl {
    private val owner = SupervisorJob()
    private val scope = CoroutineScope(owner + Dispatchers.IO)
    private val operations = Mutex()
    private val gate = RootLifecycleGate()
    private var setupJob: Job? = null
    private var stopJob: Job? = null
    private var dns: RootDnsSession? = null

    override fun restartService(): Boolean {
        requestStop(restart = true)
        return true
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        NotificationManager.ensureForeground(this)
        startSetup()
        // Native startup alone is not proof that root resources are owned and usable.
        return START_NOT_STICKY
    }

    @Synchronized private fun startSetup() {
        if (!gate.beginStart()) return
        setupJob = scope.launch {
            operations.withLock {
                try {
                    CoreServiceManager.serviceControl = SoftReference(this@CoreRootService)
                    check(CoreServiceManager.startCoreLoop(null)) { "Root core start failed" }
                    ensureActive()
                    RootProxyManager.prepare(this@CoreRootService)
                    val appPolicy = RootProxyManager.resolveAppPolicy(this@CoreRootService)
                    dns = RootDnsSession(this@CoreRootService, appPolicy) { stopService() }
                    dns?.start()
                    ensureActive()
                    check(RootProxyManager.start(this@CoreRootService, appPolicy)) { "Root rule setup failed" }
                    ensureActive()
                    check(dns?.refresh() == true) { "Root network DNS unavailable" }
                    ensureActive()
                    if (gate.ready()) {
                        MessageHelper.sendMsg2UI(this@CoreRootService, AppConfig.MSG_STATE_START_SUCCESS, "")
                        LogUtil.i(AppConfig.TAG, "Root mode: RUNNING; routing and DNS ready")
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    LogUtil.e(AppConfig.TAG, "Root mode: STARTING setup failed", e)
                    MessageHelper.sendMsg2UI(this@CoreRootService, AppConfig.MSG_STATE_START_FAILURE, e.javaClass.simpleName)
                    stopService()
                }
            }
        }
    }

    override fun onNetworkChanged(reload: Boolean): Boolean {
        if (!gate.acceptsNetworkChange()) return true
        scope.launch {
            operations.withLock {
                if (!gate.acceptsNetworkChange()) return@withLock
                try {
                    dns?.refresh()
                    if (reload && gate.acceptsNetworkChange()) check(CoreServiceManager.reloadCore()) { "Root core reload failed" }
                } catch (e: Exception) {
                    LogUtil.e(AppConfig.TAG, "Root mode: RUNNING network reconciliation failed", e)
                    stopService()
                }
            }
        }
        return true
    }

    override fun stopService() = requestStop(restart = false)

    @Synchronized private fun requestStop(restart: Boolean) {
        if (!gate.beginStop(restart)) return
        CoreServiceManager.cancelNetworkMonitor()
        setupJob?.cancel()
        stopJob = scope.launch {
            // Cancellation may stop acquisition, but must not cancel resource release when
            // Android destroys the service during an in-flight setup. Root commands and the
            // helper close have their own deadlines. A requested restart is enqueued back
            // into the cancellable service scope only after release completes.
            withContext(NonCancellable) {
                setupJob?.join()
                operations.withLock {
                    try {
                        dns?.close()
                        dns = null
                        check(RootProxyManager.stop(this@CoreRootService)) { "Root routing cleanup failed" }
                        check(CoreServiceManager.stopCoreLoopAndJoin(keepForeground = gate.restartRequested)) { "Root core stop failed" }
                        if (gate.restartAfterCleanup()) {
                            // Android 12+ may reject creating a new foreground service after
                            // stopping the old one in the background. Rebuild inside this owner;
                            // initial app starts still go through LauncherManager.
                            startSetup()
                        } else {
                            gate.stopped()
                            stopSelf()
                        }
                    } catch (e: Exception) {
                        LogUtil.e(AppConfig.TAG, "Root mode: STOPPING cleanup failed", e)
                        // Keep the listener and foreground owner alive if capture could not be
                        // removed. A repeated stop can retry; do not report a successful stop.
                        gate.stopFailed()
                        MessageHelper.sendMsg2UI(this@CoreRootService, AppConfig.MSG_STATE_START_FAILURE, e.javaClass.simpleName)
                    }
                }
            }
        }
    }

    override fun onDestroy() {
        if (gate.phase != RootLifecycleGate.Phase.STOPPED) stopService()
        // Keep root capture ahead of core teardown. Normal stopSelf follows cleanup; only
        // unexpected Android destruction waits here, bounded to avoid ANR. Daemon EOF also
        // tells the root helper to restore DNS and remove routing if Android kills the process.
        runBlocking { withTimeoutOrNull(4000) { stopJob?.join() } }
        scope.cancel()
        super.onDestroy()
    }

    override fun getService(): Service = this
    override fun startService() = Unit
    override fun vpnProtect(socket: Int): Boolean = true
    override fun onBind(intent: Intent?): IBinder? = null
    override fun attachBaseContext(newBase: Context?) {
        super.attachBaseContext(newBase?.let(AppLocaleManager::localizedContext))
    }
}
