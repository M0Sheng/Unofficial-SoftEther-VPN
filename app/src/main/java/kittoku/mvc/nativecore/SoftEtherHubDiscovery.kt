package kittoku.mvc.nativecore

import kittoku.mvc.R
import kittoku.mvc.i18n.appText
import java.io.BufferedInputStream
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.util.Locale

/** The SoftEther client manager's pre-login Hub lookup, over an already verified TLS stream. */
internal object SoftEtherHubDiscovery {
    private const val PACK_CONTENT_TYPE = "application/octet-stream"
    private const val MAX_HEADER_BYTES = 8_192
    private const val MAX_PACK_BYTES = 2 * 1024 * 1024
    private const val MAX_PACK_FIELDS = 64
    private const val MAX_HUBS = 4_096
    private const val MAX_HUB_NAME_BYTES = 255
    private const val TYPE_INT = 0
    private const val TYPE_DATA = 1
    private const val TYPE_STRING = 2
    private const val TYPE_UNICODE = 3
    private const val TYPE_LONG = 4

    fun fetch(input: InputStream, output: OutputStream, authority: String): List<String> {
        expect(authority.length in 1..300 && authority.all { it in '!'..'~' && it !in "/\\@?#" })
        val source = DataInputStream(BufferedInputStream(input))
        // Protocol.c accepts the VPNCONNECT signature on the same path as the native JPEG watermark.
        post(output, authority, "/vpnsvc/connect.cgi", "image/jpeg", "VPNCONNECT".toByteArray(Charsets.US_ASCII))
        verifyHello(readResponse(source))
        post(output, authority, "/vpnsvc/vpn.cgi", PACK_CONTENT_TYPE, hubRequest())
        return readHubs(readResponse(source))
    }

    private fun post(output: OutputStream, authority: String, path: String, type: String, body: ByteArray) {
        val header = "POST $path HTTP/1.1\r\nHost: $authority\r\nConnection: Keep-Alive\r\n" +
            "Content-Type: $type\r\nContent-Length: ${body.size}\r\n\r\n"
        output.write(header.toByteArray(Charsets.US_ASCII))
        output.write(body)
        output.flush()
    }

    private fun readResponse(source: DataInputStream): ByteArray {
        val end = byteArrayOf(13, 10, 13, 10)
        val header = ByteArrayOutputStream()
        var matched = 0
        while (matched < end.size) {
            expect(header.size() < MAX_HEADER_BYTES)
            val next = source.readUnsignedByte()
            expect(next == 9 || next == 10 || next == 13 || next in 32..126)
            header.write(next)
            matched = when (next.toByte()) {
                end[matched] -> matched + 1
                end[0] -> 1
                else -> 0
            }
        }
        val lines = header.toString(Charsets.US_ASCII.name()).dropLast(end.size).split("\r\n")
        expect(lines.first() == "HTTP/1.1 200" || lines.first().startsWith("HTTP/1.1 200 "))
        var length: Int? = null
        var hasPackType = false
        for (line in lines.drop(1)) {
            val delimiter = line.indexOf(':')
            expect(delimiter > 0 && line.none { it == '\r' || it == '\n' })
            val value = line.substring(delimiter + 1).trim()
            when (line.substring(0, delimiter).lowercase(Locale.ROOT)) {
                "content-length" -> {
                    expect(length == null && value.isNotEmpty() && value.all { it in '0'..'9' })
                    length = value.toIntOrNull() ?: malformed()
                }
                "content-type" -> {
                    expect(!hasPackType && value.equals(PACK_CONTENT_TYPE, ignoreCase = true))
                    hasPackType = true
                }
                "transfer-encoding" -> malformed()
            }
        }
        val size = length ?: malformed()
        expect(hasPackType && size in 1..MAX_PACK_BYTES)
        return source.readBytesExactly(size)
    }

    private fun hubRequest() = ByteArrayOutputStream().apply {
        DataOutputStream(this).apply {
            writeInt(4)
            writeField("method", TYPE_STRING) { writeString("enum_hub") }
            writeField("client_str", TYPE_STRING) { writeString("SoftEther VPN Client") }
            writeField("client_ver", TYPE_INT) { writeInt(444) }
            writeField("client_build", TYPE_INT) { writeInt(9807) }
        }
    }.toByteArray()

    private fun DataOutputStream.writeField(name: String, type: Int, value: DataOutputStream.() -> Unit) {
        // PACK field names include one in their length but carry no terminating NUL.
        writeInt(name.length + 1)
        write(name.toByteArray(Charsets.US_ASCII))
        writeInt(type)
        writeInt(1)
        value()
    }

    private fun DataOutputStream.writeString(value: String) {
        val bytes = value.toByteArray(Charsets.US_ASCII)
        writeInt(bytes.size)
        write(bytes)
    }

    private fun verifyHello(payload: ByteArray) {
        var hasHello = false
        var hasRandom = false
        fields(payload) { name, type, count ->
            when (name) {
                "hello" -> {
                    expect(type == TYPE_STRING && count == 1)
                    skipExactly(readIntIn(1..255))
                    hasHello = true
                }
                "random" -> {
                    expect(type == TYPE_DATA && count == 1 && readInt() == 20)
                    skipExactly(20)
                    hasRandom = true
                }
                "error" -> expect(type == TYPE_INT && count == 1 && readInt() == 0)
                else -> skipField(type, count)
            }
        }
        expect(hasHello && hasRandom)
    }

    private fun readHubs(payload: ByteArray): List<String> {
        var declaredCount: Int? = null
        var hubs = emptyList<String>()
        fields(payload) { name, type, count ->
            when (name) {
                "numhub" -> {
                    expect(type == TYPE_INT && count == 1)
                    declaredCount = readIntIn(0..MAX_HUBS)
                }
                "hubname" -> {
                    expect(type == TYPE_STRING)
                    hubs = List(count) {
                        val raw = readBytesExactly(readIntIn(1..MAX_HUB_NAME_BYTES))
                        val hub = Charsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(raw)).toString()
                        expect(hub.isNotBlank() && hub.none(Char::isISOControl))
                        hub
                    }
                }
                "error" -> expect(type == TYPE_INT && count == 1 && readInt() == 0)
                else -> skipField(type, count)
            }
        }
        expect(declaredCount == hubs.size)
        return hubs.distinctBy { it.lowercase(Locale.ROOT) }
    }

    private fun fields(payload: ByteArray, consume: DataInputStream.(String, Int, Int) -> Unit) {
        val packet = DataInputStream(ByteArrayInputStream(payload))
        val names = HashSet<String>()
        repeat(packet.readIntIn(1..MAX_PACK_FIELDS)) {
            val raw = packet.readBytesExactly(packet.readIntIn(2..64) - 1)
            val name = raw.toString(Charsets.US_ASCII).lowercase(Locale.ROOT)
            expect(name.all { it in '!'..'~' } && names.add(name))
            val type = packet.readIntIn(TYPE_INT..TYPE_LONG)
            val count = packet.readIntIn(1..MAX_HUBS)
            packet.consume(name, type, count)
        }
        expect(packet.available() == 0)
    }

    private fun DataInputStream.skipField(type: Int, count: Int) {
        when (type) {
            TYPE_INT -> skipExactly(count * 4)
            TYPE_LONG -> skipExactly(count * 8)
            TYPE_DATA, TYPE_STRING, TYPE_UNICODE -> repeat(count) { skipExactly(readIntIn(0..MAX_PACK_BYTES)) }
        }
    }

    private fun DataInputStream.readIntIn(allowed: IntRange) = readInt().also { expect(it in allowed) }

    private fun DataInputStream.readBytesExactly(size: Int) = ByteArray(size).also { readFully(it) }

    private fun DataInputStream.skipExactly(size: Int) {
        expect(skipBytes(size) == size)
    }

    private fun expect(valid: Boolean) {
        if (!valid) malformed()
    }

    private fun malformed(): Nothing = throw IOException(appText(R.string.network_runtime_error_hub_discovery_response_invalid))
}
