package com.v2ray.ang.service

/** Callbacks enqueue bounded work under this gate. Close waits for admission, never native I/O. */
internal class NetworkCallbackGate {
    private var open = true
    @Synchronized fun dispatch(callback: () -> Unit) { if (open) callback() }
    @Synchronized fun close() { open = false }
}
