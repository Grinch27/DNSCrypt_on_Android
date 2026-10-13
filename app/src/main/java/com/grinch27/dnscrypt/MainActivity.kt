// TODO: Verify Android 10–17 user-start restrictions and display accuracy on real devices.
// Risk: foreground service and Go subprocess can be terminated independently; UI is observational.
package com.grinch27.dnscrypt

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

class MainActivity : Activity() {
    private lateinit var status: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(28, 32, 28, 20)
        }
        status = TextView(this)
        layout.addView(TextView(this).apply { text = "DNSCrypt Android — EXPERIMENTAL\nLocal DNS: 127.0.0.1:15353" })
        layout.addView(status)
        addButton(layout, "Start OpenDNS DoH (default)") {
            send(DNSCryptService.START, "opendns")
        }
        addButton(layout, "Start Quad9 DNSCrypt (4 ECS nodes)") {
            send(DNSCryptService.START, "quad9")
        }
        addButton(layout, "Stop") { send(DNSCryptService.STOP) }
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
