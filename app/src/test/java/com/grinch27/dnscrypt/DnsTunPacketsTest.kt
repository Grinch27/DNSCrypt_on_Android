package com.grinch27.dnscrypt

import org.junit.Assert.*
import org.junit.Test

class DnsTunPacketsTest {
    private fun put16(data: ByteArray, offset: Int, value: Int) {
        data[offset] = (value ushr 8).toByte()
        data[offset + 1] = value.toByte()
    }
    private fun u8(b: Byte) = b.toInt() and 255
    private fun u16(data: ByteArray, index: Int) = (u8(data[index]) shl 8) or u8(data[index + 1])
    private fun query() = byteArrayOf(0x17, 0x31, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0)
    private fun packet(): ByteArray {
        val dns = query()
        val p = ByteArray(28 + dns.size)
        p[0] = 0x45
        put16(p, 2, p.size)
        put16(p, 4, 0x2301)
        p[8] = 64
        p[9] = 17
        byteArrayOf(10, 111, 0, 2).copyInto(p, 12)
        byteArrayOf(10, 111, 0, 1).copyInto(p, 16)
        put16(p, 20, 46555)
        put16(p, 22, 53)
        put16(p, 24, 8 + dns.size)
        dns.copyInto(p, 28)
        return p
    }

    @Test fun onlySyntheticDnsUdpCaptured() {
        val p = packet()
        val decoded = DnsTunPackets.parse(p, p.size)
        assertNotNull(decoded)
        assertEquals(46555, decoded!!.srcPort)
        assertArrayEquals(query(), decoded.dns)

        val notDns = p.clone()
        notDns[19] = 9
        assertNull(DnsTunPackets.parse(notDns, notDns.size))
        val tcp = p.clone()
        tcp[9] = 6
        assertNull(DnsTunPackets.parse(tcp, tcp.size))
        val tls = p.clone()
        put16(tls, 22, 443)
        assertNull(DnsTunPackets.parse(tls, tls.size))
        val fragmented = p.clone()
        fragmented[6] = 0x20
        assertNull(DnsTunPackets.parse(fragmented, fragmented.size))
    }

    @Test fun responseUsesSwappedIpsPortsAndChecksums() {
        val p = packet()
        val request = DnsTunPackets.parse(p, p.size)!!
        val dns = query()
        dns[2] = 0x81.toByte()
        dns[3] = 0x80.toByte()
        val reply = DnsTunPackets.response(request, dns)!!
        assertEquals(0x45, u8(reply[0]))
        assertEquals(reply.size, u16(reply, 2))
        assertEquals(53, u16(reply, 20))
        assertEquals(46555, u16(reply, 22))
        assertArrayEquals(byteArrayOf(10, 111, 0, 1), reply.copyOfRange(12, 16))
        assertArrayEquals(byteArrayOf(10, 111, 0, 2), reply.copyOfRange(16, 20))
        assertArrayEquals(dns, reply.copyOfRange(28, reply.size))
        assertEquals(0xffff, onesComplementSum(reply.copyOfRange(0, 20)))
        val pseudo = ByteArray(12 + reply.size - 20)
        reply.copyInto(pseudo, 0, 12, 20)
        reply.copyInto(pseudo, 4, 16, 20)
        pseudo[9] = 17
        put16(pseudo, 10, reply.size - 20)
        reply.copyInto(pseudo, 12, 20, reply.size)
        assertEquals(0xffff, onesComplementSum(pseudo))
    }

    @Test fun rejectedMalformedOrOversizeResponses() {
        val req = DnsTunPackets.parse(packet(), packet().size)!!
        assertNull(DnsTunPackets.response(req, ByteArray(1473)))
        val wrongId = query()
        wrongId[0] = 3
        wrongId[2] = 0x81.toByte()
        assertNull(DnsTunPackets.response(req, wrongId))
    }

    private fun onesComplementSum(data: ByteArray): Int {
        var sum = 0L
        var i = 0
        while (i + 1 < data.size) {
            sum += (u8(data[i]) shl 8) or u8(data[i + 1])
            i += 2
        }
        if (i < data.size) sum += u8(data[i]) shl 8
        while (sum > 0xffff) sum = (sum and 0xffffL) + (sum ushr 16)
        return sum.toInt()
    }
}
