// TODO: Verify Android 10–17 user-start restrictions and display accuracy on real devices.
// Risk: foreground service and Go subprocess can be terminated independently; UI is observational.
package com.grinch27.dnscrypt

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.net.VpnService
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

class MainActivity : Activity() {
    private lateinit var status: TextView
    private var pendingMode: String? = null
    private val vpnPermissionCode = 6083

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(28, 32, 28, 20)
        }
        status = TextView(this)
        layout.addView(TextView(this).apply { text = "DNSCrypt Android — DNS-only VPN (experimental)\nIntercepts Android DNS only; other internet traffic stays direct.\nInternal DNS: 127.0.0.1:15353" })
        layout.addView(status)
        addButton(layout, "Connect DNS-only VPN · OpenDNS DoH") {
            authorizeVpn("opendns")
        }
        addButton(layout, "Connect DNS-only VPN · Quad9 DNSCrypt") {
            authorizeVpn("quad9")
        }
        addButton(layout, "Disconnect VPN") { send(DNSCryptService.STOP) }
        addButton(layout, "Refresh state") { refresh() }
        setContentView(layout)
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
        }
        refresh()
    }

    private fun addButton(layout: LinearLayout, label: String, action: () -> Unit) {
        layout.addView(Button(this).apply { text = label; setOnClickListener { action() } })
    }

    private fun authorizeVpn(mode: String) {
        val permission = VpnService.prepare(this)
        if (permission != null) {
            pendingMode = mode
            startActivityForResult(permission, vpnPermissionCode)
        } else {
            send(DNSCryptService.START, mode)
        }
    }

    @Deprecated("Uses platform VPN consent activity on supported Android 10–17")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == vpnPermissionCode) {
            val mode = pendingMode
            pendingMode = null
            if (resultCode == RESULT_OK && mode != null && VpnService.prepare(this) == null) {
                send(DNSCryptService.START, mode)
            } else {
                status.text = "VPN permission declined. Nothing changed."
            }
        }
    }

    private fun send(action: String, mode: String? = null) {
        val intent = Intent(this, DNSCryptService::class.java).setAction(action)
        if (mode != null) intent.putExtra("mode", mode)
        if (action == DNSCryptService.START) startForegroundService(intent) else startService(intent)
        refresh()
    }

    private fun refresh() {
        val prefs = getSharedPreferences("dnscrypt", MODE_PRIVATE)
        status.text = "Last reported state: ${prefs.getString("state", "UNKNOWN")}\n" +
            "Mode: ${prefs.getString("mode", "opendns")}\n" +
            "Detail: ${prefs.getString("detail", "Not started")}"
    }
}
