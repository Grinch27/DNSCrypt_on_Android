#!/usr/bin/env python3
# TODO: Audit all new upstream name-resolution paths on every dnscrypt-proxy update.
# Risk: this intentionally diverges from upstream only in strict internal resolution policy.
# Verification: exact source match, gofmt, Go compilation and packet captures on real devices.
"""Replace only the internal hostname resolver; never use system DNS or plaintext bootstrap."""
from pathlib import Path
import sys

path = Path(sys.argv[1])
source = path.read_text(encoding="utf-8")
start = source.index("func (xTransport *XTransport) resolve(host string, returnIPv4, returnIPv6 bool)")
end = source.index("// If a name is not present in the cache", start)
old = source[start:end]
assert "resolveUsingSystem" in old
assert "bootstrapResolvers" in old
replacement = """func (xTransport *XTransport) resolve(host string, returnIPv4, returnIPv6 bool) (ips []net.IP, ttl time.Duration, err error) {
    if !xTransport.ignoreSystemDNS {
        return nil, 0, errors.New("strict mode: system DNS forbidden")
    }
    if !xTransport.internalResolverReady.Load() {
        return nil, 0, errors.New("strict mode: encrypted resolver is not ready")
    }
    protos := []string{"udp", "tcp"}
    if xTransport.mainProto == "tcp" {
        protos = []string{"tcp", "udp"}
    }
    for _, proto := range protos {
        ips, ttl, err = xTransport.resolveUsingServers(proto, host, xTransport.internalResolvers, returnIPv4, returnIPv6)
        if err == nil {
            return ips, ttl, nil
        }
    }
    return nil, 0, err
}

"""
source = source[:start] + replacement + source[end:]
assert source.count('strict mode: system DNS forbidden') == 1
path.write_text(source, encoding="utf-8")
print("Strict internal resolver policy applied")
