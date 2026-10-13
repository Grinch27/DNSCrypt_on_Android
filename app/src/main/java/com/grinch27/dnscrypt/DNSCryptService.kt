// TODO: Validate FGS process longevity, service stop and crash recovery on Android 10–17.
// Risks: executable-as-.so is not guaranteed by Android; no silent system DNS fallback is permitted.
// Verification: UDP health probe must receive an actual DNS response, not merely an open socket.
package com.grinch27.dnscrypt

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.net.VpnService
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import java.io.File
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.security.SecureRandom
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class DNSCryptService : VpnService() {
    companion object {
        const val START = "com.grinch27.dnscrypt.START"
        const val STOP = "com.grinch27.dnscrypt.STOP"
        private const val CHANNEL = "dnscrypt-service"
    }

    private val worker = Executors.newSingleThreadExecutor()
    @Volatile private var process: Process? = null
    @Volatile private var checkProcess: Process? = null
    @Volatile private var starting = false
    @Volatile private var stopping = false
    @Volatile private var tunnel: DnsVpnTunnel? = null
    @Volatile private var vpnFd: ParcelFileDescriptor? = null

    // VpnService.onBind() must be inherited; it provides the system VPN control binder.

    override fun onCreate() {
        super.onCreate()
        val notifications = getSystemService(NotificationManager::class.java)
        notifications.createNotificationChannel(
            NotificationChannel(CHANNEL, "Local encrypted DNS", NotificationManager.IMPORTANCE_LOW)
        )
        val notice = Notification.Builder(this, CHANNEL)
            .setSmallIcon(android.R.drawable.stat_sys_download_done)
            .setContentTitle("DNSCrypt local resolver")
            .setContentText("Experimental — localhost:15353").setOngoing(true).build()
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(1, notice, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else startForeground(1, notice)
        report("STARTING", "Foreground service created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            STOP -> {
                stopping = true
                tunnel?.close()
                tunnel = null
                vpnFd = null
                checkProcess?.destroy()
                val old = process
                process = null
                old?.destroy()
                report("STOPPED", "User stopped")
                stopSelf()
            }
            START -> {
                if (starting || process?.isAlive == true) {
                    report(if (starting) "STARTING" else "READY", "Stop before changing the DNS mode")
                } else {
                    val mode = intent.getStringExtra("mode") ?: "opendns"
                    if (mode != "opendns" && mode != "quad9") {
                        report("ERROR", "Invalid mode")
                        stopSelf()
                        return START_NOT_STICKY
                    }
                    getSharedPreferences("dnscrypt", MODE_PRIVATE).edit().putString("mode", mode).apply()
                    starting = true
                    stopping = false
                    report("STARTING", "Checking signed DNS settings")
                    worker.execute { establishDnsVpnAndLaunch() }
                }
            }
        }
        return START_NOT_STICKY
    }

    private fun report(state: String, detail: String) {
        getSharedPreferences("dnscrypt", MODE_PRIVATE).edit()
            .putString("state", state).putString("detail", detail).apply()
    }

    private fun establishDnsVpnAndLaunch() {
        try {
            check(VpnService.prepare(this) == null) { "Android VPN permission missing" }
            val fd = Builder()
                .setSession("DNSCrypt DNS-only")
                .setMtu(1500)
                .addAddress(DnsTunPackets.LOCAL_IP, 32)
                .addDnsServer(DnsTunPackets.DNS_IP)
                .addRoute(DnsTunPackets.DNS_IP, 32)
                .setBlocking(true)
                .establish() ?: error("Android refused DNS-only VPN tunnel")
            if (stopping) {
                fd.close()
                return
            }
            vpnFd = fd
            val forwarding = DnsVpnTunnel(this, fd) { detail ->
                if (!stopping) report("DEGRADED", detail)
            }
            tunnel = forwarding
            forwarding.start()
            report("STARTING", "DNS-only VPN established; validating encrypted resolver")
            val binary = File(applicationInfo.nativeLibraryDir, "libdnscryptproxy.so")
            require(binary.isFile) { "Extracted native executable missing" }
            val mode = getSharedPreferences("dnscrypt", MODE_PRIVATE).getString("mode", "opendns")!!
            val config = DNSCryptConfig.prepare(this, mode)
            val check = ProcessBuilder(binary.absolutePath, "-config", config.absolutePath, "-check")
                .directory(config.parentFile).redirectErrorStream(true)
                .redirectOutput(File(config.parentFile, "check.log")).start()
            checkProcess = check
            if (!check.waitFor(30, TimeUnit.SECONDS)) {
                check.destroyForcibly()
                error("Config check timed out")
            }
            checkProcess = null
            if (stopping) return
            check.exitValue().let { require(it == 0) { "Config validation failed: $it" } }
            val child = ProcessBuilder(binary.absolutePath, "-config", config.absolutePath)
                .directory(config.parentFile).redirectErrorStream(true)
                .redirectOutput(ProcessBuilder.Redirect.appendTo(File(config.parentFile, "proxy.log"))).start()
            if (stopping) {
                child.destroy()
                return
            }
            process = child
            var healthy = false
            for (attempt in 0 until 16) {
                if (stopping || !child.isAlive) break
                if (probe()) { healthy = true; break }
                Thread.sleep(500)
            }
            if (stopping) return
            if (!healthy) {
                report("DEGRADED", "VPN connected; encrypted DNS unavailable (blocked; no fallback)")
            } else {
                report("READY", "DNS-only VPN connected; upstream UDP DNS query passed")
            }
            Thread {
                val code = child.waitFor()
                if (process === child && !stopping) {
                    process = null
                    report("DEGRADED", "VPN remains active; proxy exited ($code); DNS blocked")
                }
            }.start()
        } catch (e: Exception) {
            if (!stopping) {
                report(if (tunnel != null) "DEGRADED" else "ERROR",
                    (e.message ?: e.javaClass.simpleName) +
                    if (tunnel != null) " — VPN keeps DNS blocked" else "")
                if (tunnel == null) stopSelf()
            }
        } finally {
            checkProcess = null
            starting = false
        }
    }

    private fun probe(): Boolean = try {
        val id = SecureRandom().nextInt(65536)
        val bytes = byteArrayOf(
            (id ushr 8).toByte(), id.toByte(), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
            7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1
        )
        DatagramSocket().use { socket ->
            socket.soTimeout = 1500
            val host = InetAddress.getByName("127.0.0.1")
            socket.send(DatagramPacket(bytes, bytes.size, host, 15353))
            val buffer = ByteArray(4096)
            val response = DatagramPacket(buffer, buffer.size)
            socket.receive(response)
            response.length >= 12 &&
                (buffer[0].toInt() and 255) == (id ushr 8) &&
                (buffer[1].toInt() and 255) == (id and 255) &&
                (buffer[2].toInt() and 0x80) != 0 &&
                (buffer[3].toInt() and 0x0f) == 0 &&
                (((buffer[6].toInt() and 255) shl 8) or (buffer[7].toInt() and 255)) > 0
        }
    } catch (_: Exception) { false }

    override fun onRevoke() {
        stopping = true
        report("STOPPED", "VPN permission revoked; Android may resume system DNS")
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopping = true
        tunnel?.close()
        tunnel = null
        vpnFd = null
        checkProcess?.destroy()
        process?.destroy()
        worker.shutdownNow()
        super.onDestroy()
    }
}
