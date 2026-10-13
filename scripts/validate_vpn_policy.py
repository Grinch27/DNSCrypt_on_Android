#!/usr/bin/env python3
"""Static regression guard for the DNS-only VPN's narrow route and upstream policy.

This is intentionally not a packet-capture proof of DNS leak prevention.
"""
from pathlib import Path

vpn = Path("app/src/main/java/com/grinch27/dnscrypt/DNSCryptService.kt").read_text()
tun = Path("app/src/main/java/com/grinch27/dnscrypt/DnsVpnTunnel.kt").read_text()
config = Path("app/src/main/java/com/grinch27/dnscrypt/DNSCryptConfig.kt").read_text()
packets = Path("app/src/main/java/com/grinch27/dnscrypt/DnsTunPackets.kt").read_text()

checks = {
    "VPN route remains an exact DNS /32": '.addRoute(DnsTunPackets.DNS_IP, 32)' in vpn,
    "IPv6 passthrough declared": '.allowFamily(OsConstants.AF_INET6)' in vpn,
    "only one route configured": vpn.count(".addRoute(") == 1,
    "no full IPv4/IPv6 default route": not any(
        x in vpn for x in ('"0.0.0.0"', '"::"', '.addRoute("0.0.0.0"', '.addRoute("::"')
    ),
    "TUN accepts UDP 53 only": 'u8(data, 9) != 17' in packets and 'u16(data, ihl + 2) != 53' in packets,
    "TUN destination is synthetic DNS": 'contentEquals(dnsAddress)' in packets,
    "VPN relay protects its loopback socket": 'vpn.protect(socket)' in tun,
    "DNS strict upstream flag": 'ignore_system_dns = true' in config,
    "plaintext DNS bootstrap disabled": 'bootstrap_resolvers = []' in config,
    "local dnscrypt-proxy stays bound to loopback": "listen_addresses = ['127.0.0.1:15353']" in config,
}
for desc, ok in checks.items():
    print(("PASS" if ok else "FAIL") + ": " + desc)
assert all(checks.values()), "DNS-only VPN static security policy regression"
