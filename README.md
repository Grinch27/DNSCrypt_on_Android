# DNSCrypt on Android

Standalone Android DNSCrypt client. Initial GitHub Actions build is experimental and **not a validated production DNS service**. Android 10–17, ARM64 first; no Root or VPNService.

Security requirement: reject plaintext bootstrap and system-DNS fallback; signed Quad9 resolver list; OpenDNS DoH is the default upstream. Refer to workflow and source for build-time security gates.

This repository is independent of `Grinch27/awara`.
