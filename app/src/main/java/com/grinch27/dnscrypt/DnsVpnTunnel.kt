// Experimental split-route DNS-only VPN: only the synthetic DNS /32 route enters TUN.
// Other destinations stay on Wi-Fi or cellular. IPv4 UDP/53 only; TCP/53 fails closed.
// Verification pending: packet capture, Android Private DNS interaction, IPv6-only networks.
package com.grinch27.dnscrypt

import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.Executors
import java.util.concurrent.Semaphore
import java.util.concurrent.atomic.AtomicBoolean

internal class DnsVpnTunnel(
    private val vpn: VpnService,
    private val interfaceFd: ParcelFileDescriptor,
    private val onError: (String) -> Unit
) : AutoCloseable {
    private val running = AtomicBoolean(true)
    private val slots = Semaphore(24)
    private val workers = Executors.newFixedThreadPool(6)
    private val writerLock = Any()
    private val output = FileOutputStream(interfaceFd.fileDescriptor)
    private val input = FileInputStream(interfaceFd.fileDescriptor)
    private val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
    private val reader = Thread({ readLoop() }, "dnscrypt-tun-reader")

    fun start() { reader.start() }

    private fun readLoop() {
        val buffer = ByteArray(1500)
        try {
            while (running.get()) {
                val length = input.read(buffer)
                if (length < 0) break
                if (length == 0) continue
                val request = DnsTunPackets.parse(buffer, length) ?: continue
                if (!slots.tryAcquire()) continue
                try {
                    workers.execute {
                        try { forward(request) }
                        finally { slots.release() }
                    }
                } catch (_: java.util.concurrent.RejectedExecutionException) {
                    slots.release()
                }
            }
        } catch (e: Exception) {
            if (running.get()) onError("TUN read failed: ${e.javaClass.simpleName}")
        }
    }

    private fun forward(request: DnsTunPackets.Request) {
        if (!running.get()) return
        try {
            DatagramSocket().use { socket ->
                check(vpn.protect(socket)) { "VPN socket protection failed" }
                socket.soTimeout = 3500
                socket.connect(loopback, 15353)
                socket.send(DatagramPacket(request.dns, request.dns.size))
                val replyBuffer = ByteArray(4096)
                val reply = DatagramPacket(replyBuffer, replyBuffer.size)
                socket.receive(reply)
                val packet = DnsTunPackets.response(request, reply.data.copyOfRange(0, reply.length))
                    ?: return
                if (running.get()) synchronized(writerLock) {
                    if (running.get()) output.write(packet)
                }
            }
        } catch (_: Exception) {
            // Intentionally fail closed: no OS DNS or plaintext DNS fallback.
        }
    }

    override fun close() {
        if (running.getAndSet(false)) {
            try { interfaceFd.close() } catch (_: Exception) { }
            workers.shutdownNow()
            reader.interrupt()
        }
    }
}
