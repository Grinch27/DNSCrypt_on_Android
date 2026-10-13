// DNS-only TUN framing. Strictly accepts IPv4 UDP:53 addressed to the VPN's synthetic DNS IP.
// TODO: TCP/53 support (including EDNS truncation recovery) requires a verified TCP state machine.
// Fail closed on unsupported packets; never route them to the system resolver.
package com.grinch27.dnscrypt

internal object DnsTunPackets {
    const val DNS_IP = "10.111.0.1"
    const val LOCAL_IP = "10.111.0.2"
    private val dnsAddress = byteArrayOf(10, 111, 0, 1)

    data class Request(
        val src: ByteArray,
        val dst: ByteArray,
        val srcPort: Int,
        val dns: ByteArray,
        val identification: Int
    )

    private fun u8(data: ByteArray, at: Int) = data[at].toInt() and 0xff
    private fun u16(data: ByteArray, at: Int) = (u8(data, at) shl 8) or u8(data, at + 1)
    private fun put16(data: ByteArray, at: Int, value: Int) {
        data[at] = (value ushr 8).toByte()
        data[at + 1] = value.toByte()
    }

    fun parse(data: ByteArray, size: Int): Request? {
        if (size < 40 || (u8(data, 0) ushr 4) != 4) return null
        val ihl = (u8(data, 0) and 15) * 4
        if (ihl < 20 || size < ihl + 20 || ihl > 60) return null
        val total = u16(data, 2)
        if (total > size || total < ihl + 8 + 12 || total > 1500) return null
        if ((u16(data, 6) and 0x3fff) != 0 || u8(data, 9) != 17) return null
        if (!data.copyOfRange(16, 20).contentEquals(dnsAddress)) return null
        if (u16(data, ihl + 2) != 53) return null
        val udpLength = u16(data, ihl + 4)
        if (udpLength < 20 || ihl + udpLength != total) return null
        val dns = data.copyOfRange(ihl + 8, ihl + udpLength)
        if (dns.size > 1472 || (u8(dns, 2) and 0x80) != 0) return null
        return Request(
            src = data.copyOfRange(12, 16),
            dst = data.copyOfRange(16, 20),
            srcPort = u16(data, ihl),
            dns = dns,
            identification = u16(data, 4)
        )
    }

    fun response(request: Request, dns: ByteArray): ByteArray? {
        if (dns.size < 12 || dns.size > 1472) return null
        if (!dns.copyOfRange(0, 2).contentEquals(request.dns.copyOfRange(0, 2))) return null
        if ((u8(dns, 2) and 0x80) == 0) return null
        val total = 28 + dns.size
        val result = ByteArray(total)
        result[0] = 0x45
        put16(result, 2, total)
        put16(result, 4, request.identification)
        result[8] = 64
        result[9] = 17
        request.dst.copyInto(result, 12)
        request.src.copyInto(result, 16)
        put16(result, 10, checksum(result, 0, 20))
        put16(result, 20, 53)
        put16(result, 22, request.srcPort)
        put16(result, 24, 8 + dns.size)
        dns.copyInto(result, 28)
        val pseudo = ByteArray(12 + 8 + dns.size)
        request.dst.copyInto(pseudo, 0)
        request.src.copyInto(pseudo, 4)
        pseudo[9] = 17
        put16(pseudo, 10, 8 + dns.size)
        result.copyInto(pseudo, 12, 20, total)
        val udpChecksum = checksum(pseudo, 0, pseudo.size)
        put16(result, 26, if (udpChecksum == 0) 0xffff else udpChecksum)
        return result
    }

    private fun checksum(data: ByteArray, start: Int, length: Int): Int {
        var sum = 0L
        var position = start
        val end = start + length
        while (position + 1 < end) {
            sum += (u8(data, position) shl 8) or u8(data, position + 1)
            position += 2
        }
        if (position < end) sum += u8(data, position) shl 8
        while (sum > 0xffff) sum = (sum and 0xffff) + (sum ushr 16)
        return sum.toInt().inv() and 0xffff
    }
}
