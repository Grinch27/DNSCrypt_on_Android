// TODO: Replace this locked template only after a TOML parser and strict policy validator are added.
// Risk: OpenDNS IP or service changes can cause fail-closed outages. Never use OS DNS as backup.
// Verify the OpenDNS IPv4 stamp TLS host and IP, and all Quad9 signatures during CI.
package com.grinch27.dnscrypt

import android.content.Context
import java.io.File

object DNSCryptConfig {
    private const val OPENDNS_STAMP =
        "sdns://AgAAAAAAAAAADDE0Ni4xMTIuNDEuMgAPZG9oLm9wZW5kbnMuY29tCi9kbnMtcXVlcnk"
    private const val QUAD9_KEY =
        "RWTp2E4t64BrL651lEiDLNon+DqzPG4jhZ97pfdNkcq1VDdocLKvl5FW"

    fun prepare(context: Context, mode: String): File {
        require(mode == "opendns" || mode == "quad9")
        val dir = File(context.filesDir, "dnscrypt").apply { mkdirs() }
        for (name in listOf("quad9-resolvers.md", "quad9-resolvers.md.minisig")) {
            val target = File(dir, name)
            if (!target.exists()) {
                context.assets.open(name).use { input ->
                    val temp = File(dir, "$name.tmp")
                    temp.outputStream().use { input.copyTo(it) }
                    require(temp.renameTo(target)) { "Failed to write signed source $name" }
                }
            }
        }
        val servers = if (mode == "opendns") "'cisco-doh'" else listOf(
            "quad9-dnscrypt-ip4-nofilter-ecs-pri",
            "quad9-dnscrypt-ip4-nofilter-ecs-alt",
            "quad9-dnscrypt-ip6-nofilter-ecs-pri",
            "quad9-dnscrypt-ip6-nofilter-ecs-alt"
        ).joinToString(", ") { "'$it'" }
        val ecs = if (mode == "quad9")
            "edns_client_subnet = ['14.120.113.0/24', '240e:3b4:d030:7500::/56']"
        else ""
        val toml = """
            server_names = [$servers]
            listen_addresses = ['127.0.0.1:15353']
            max_clients = 256
            ipv4_servers = true
            ipv6_servers = true
            dnscrypt_servers = true
            doh_servers = true
            odoh_servers = false
            require_dnssec = false
            require_nolog = false
            require_nofilter = false
            ignore_system_dns = true
            bootstrap_resolvers = []
            netprobe_timeout = 0
            timeout = 5000
            cache = true
            $ecs

            [static.cisco-doh]
            stamp = '$OPENDNS_STAMP'

            [sources.quad9-resolvers]
            urls = ['https://raw.githubusercontent.com/Quad9DNS/dnscrypt-settings/main/dnscrypt/quad9-resolvers.md']
            minisign_key = '$QUAD9_KEY'
            cache_file = 'quad9-resolvers.md'
            refresh_delay = 72
            prefix = 'quad9-'
        """.trimIndent() + "\n"
        return File(dir, "dnscrypt-proxy.toml").apply { writeText(toml) }
    }
}
