package com.v2ray.ang.service

/** Command admission only; native running state remains authoritative in CoreServiceManager. */
internal class RootLifecycleGate {
    enum class Phase { IDLE, STARTING, RUNNING, STOPPING, STOP_FAILED, STOPPED }
    @Volatile var phase: Phase = Phase.IDLE
        private set

    @Volatile var restartRequested: Boolean = false
        private set

    @Synchronized fun beginStart(): Boolean {
        if (phase != Phase.IDLE) return false
        phase = Phase.STARTING
        return true
    }

    @Synchronized fun ready(): Boolean {
        if (phase != Phase.STARTING) return false
        phase = Phase.RUNNING
        return true
    }

    @Synchronized fun beginStop(restart: Boolean = false): Boolean {
        // A later explicit stop supersedes a restart even while cleanup is in flight.
        if (phase == Phase.STOPPING || phase == Phase.STOPPED) {
            if (!restart) restartRequested = false
            return false
        }
        restartRequested = restart
        phase = Phase.STOPPING
        return true
    }

    @Synchronized fun restartAfterCleanup(): Boolean {
        if (phase != Phase.STOPPING || !restartRequested) return false
        restartRequested = false
        phase = Phase.IDLE
        return true
    }

    @Synchronized fun stopped() { phase = Phase.STOPPED }
    @Synchronized fun stopFailed() { phase = Phase.STOP_FAILED }
    fun acceptsNetworkChange(): Boolean = phase == Phase.RUNNING
}
