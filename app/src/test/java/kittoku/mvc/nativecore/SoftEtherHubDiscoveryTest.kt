package kittoku.mvc.nativecore

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.io.IOException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class SoftEtherHubDiscoveryTest {
    @Test fun requestsPublicHubListOnOneStreamAndKeepsServerOrder() {
        val response = helloResponse() + response(pack(
            stringField("HubName", "Second Hub", "WORK", "work"),
            intField("NumHub", 3),
            field("pencore", 1, listOf(int(3) + byteArrayOf(0, 1, 2))),
        ))
        val output = ByteArrayOutputStream()
        val hubs = SoftEtherHubDiscovery.fetch(response.inputStream(), output, "[2001:db8::1]:5555")
        assertEquals(listOf("Second Hub", "WORK"), hubs)
        val expectedPack = hex(
            "00000004 00000007 6d6574686f64 00000002 00000001 00000008 656e756d5f687562 " +
                "0000000b 636c69656e745f737472 00000002 00000001 00000014 536f667445746865722056504e20436c69656e74 " +
                "0000000b 636c69656e745f766572 00000000 00000001 000001bc " +
                "0000000d 636c69656e745f6275696c64 00000000 00000001 0000264f",
        )
        assertArrayEquals(
            ("POST /vpnsvc/connect.cgi HTTP/1.1\r\nHost: [2001:db8::1]:5555\r\nConnection: Keep-Alive\r\n" +
                "Content-Type: image/jpeg\r\nContent-Length: 10\r\n\r\nVPNCONNECT" +
                "POST /vpnsvc/vpn.cgi HTTP/1.1\r\nHost: [2001:db8::1]:5555\r\nConnection: Keep-Alive\r\n" +
                "Content-Type: application/octet-stream\r\nContent-Length: ${expectedPack.size}\r\n\r\n")
                .toByteArray(Charsets.US_ASCII) + expectedPack,
            output.toByteArray(),
        )
    }

    @Test fun acceptsAnEmptyAdvertisedList() {
        val reply = response(pack(intField("NumHub", 0)))
        assertEquals(emptyList<String>(), fetch(helloResponse() + reply))
    }

    @Test fun rejectsAReplyWithAnInvalidHubCountOrTruncatedValue() {
        val wrongCount = response(pack(intField("NumHub", 2), stringField("HubName", "WORK")))
        assertThrows(IOException::class.java) { fetch(helloResponse() + wrongCount) }
        val malformed = response(pack(intField("NumHub", 1), field("HubName", 2, listOf(int(512) + ascii("WORK")))))
        assertThrows(IOException::class.java) { fetch(helloResponse() + malformed) }
        assertThrows(IOException::class.java) { fetch(helloResponse() + wrongCount.copyOf(wrongCount.size - 1)) }
    }

    @Test fun rejectsAmbiguousHttpFramingAndInvalidHelloBeforeSendingTheRequest() {
        val badHello = pack(stringField("hello", "SoftEther VPN Server"))
        val noChallenge = response(badHello)
        val duplicateLength = response(badHello, "content-length: ${badHello.size}\r\n")
        val oversized = ascii("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 999999999\r\n\r\n")
        for (reply in listOf(noChallenge, duplicateLength, oversized)) {
            val output = ByteArrayOutputStream()
            assertThrows(IOException::class.java) {
                SoftEtherHubDiscovery.fetch(reply.inputStream(), output, "vpn.example:5555")
            }
            val requests = output.toString(Charsets.US_ASCII.name())
            assertEquals(1, "POST /vpnsvc/".toRegex().findAll(requests).count())
        }
    }

    @Test fun rejectsNonAsciiOrHeaderControlInAuthorityWithoutSendingBytes() {
        val output = ByteArrayOutputStream()
        assertThrows(IOException::class.java) {
            SoftEtherHubDiscovery.fetch(helloResponse().inputStream(), output, "vpn.example\r\nInjected: yes")
        }
        assertEquals(0, output.size())
    }

    private fun fetch(replies: ByteArray): List<String> =
        SoftEtherHubDiscovery.fetch(replies.inputStream(), ByteArrayOutputStream(), "vpn.example:5555")

    private fun helloResponse() = response(pack(
        stringField("hello", "SoftEther VPN Server"),
        intField("build", 9807),
        intField("version", 444),
        field("random", 1, listOf(int(20) + ByteArray(20) { it.toByte() })),
    ))

    private fun response(payload: ByteArray, extraHeader: String = "") = ascii(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n" +
            "Content-Length: ${payload.size}\r\n$extraHeader\r\n",
    ) + payload

    private fun intField(name: String, value: Int) = field(name, 0, listOf(int(value)))

    private fun stringField(name: String, vararg values: String) =
        field(name, 2, values.map { int(it.length) + ascii(it) })

    private fun field(name: String, type: Int, values: List<ByteArray>) = bytes {
        writeInt(name.length + 1)
        write(ascii(name))
        writeInt(type)
        writeInt(values.size)
        values.forEach { write(it) }
    }

    private fun pack(vararg fields: ByteArray) = bytes {
        writeInt(fields.size)
        fields.forEach { write(it) }
    }

    private fun int(value: Int) = bytes { writeInt(value) }

    private fun ascii(text: String) = text.toByteArray(Charsets.US_ASCII)

    private fun bytes(body: DataOutputStream.() -> Unit) = ByteArrayOutputStream().apply {
        DataOutputStream(this).use(body)
    }.toByteArray()

    private fun hex(text: String) =
        text.replace(" ", "").chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
