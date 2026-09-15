package com.v2ray.ang.service

import org.junit.Assert.*
import org.junit.Test

class RootLifecycleGateTest {
    @Test fun `failed cleanup can be retried without admitting starts or handovers`() {
        val gate = RootLifecycleGate()
        gate.beginStart()
        gate.ready()
        gate.beginStop()
        gate.stopFailed()
        assertFalse(gate.beginStart())
        assertFalse(gate.acceptsNetworkChange())
        assertTrue(gate.beginStop())
    }
    @Test fun `duplicate start is rejected during setup and while running`() {
        val gate = RootLifecycleGate()
        assertTrue(gate.beginStart())
        assertFalse(gate.beginStart())
        assertFalse(gate.acceptsNetworkChange())
        assertTrue(gate.ready())
        assertFalse(gate.beginStart())
        assertTrue(gate.acceptsNetworkChange())
    }
    @Test fun `stop during setup prevents late success and repeated cleanup`() {
        val gate = RootLifecycleGate()
        gate.beginStart()
        assertTrue(gate.beginStop())
        assertFalse(gate.ready())
        assertFalse(gate.acceptsNetworkChange())
        assertFalse(gate.beginStop())
        gate.stopped()
        assertFalse(gate.beginStart())
        assertFalse(gate.beginStop())
    }
    @Test fun `unregistered callbacks cannot schedule new work`() {
        val gate = NetworkCallbackGate()
        var calls = 0
        gate.dispatch { calls++ }
        gate.close()
        repeat(100) { gate.dispatch { calls++ } }
        assertEquals(1, calls)
    }
    @Test fun `stop racing a pending restart cancels the later start`() {
        val gate = RootLifecycleGate()
        gate.beginStart()
        gate.ready()
        assertTrue(gate.beginStop(restart = true))
        assertTrue(gate.restartRequested)
        assertFalse(gate.beginStop())
        assertFalse(gate.beginStop(restart = true))
        assertFalse(gate.restartAfterCleanup())
        gate.stopped()
        assertFalse(gate.restartRequested)
    }
    @Test fun `successful restart preserves intent through completed cleanup`() {
        val gate = RootLifecycleGate()
        gate.beginStart()
        gate.ready()
        gate.beginStop(restart = true)
        assertTrue(gate.restartAfterCleanup())
        assertTrue(gate.beginStart())
        assertFalse(gate.restartAfterCleanup())
    }

}
