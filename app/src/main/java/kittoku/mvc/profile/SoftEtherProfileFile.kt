package kittoku.mvc.profile

import kittoku.mvc.R
import kittoku.mvc.i18n.appText
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import kittoku.mvc.routing.TunDestinationMode
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.Collections
import java.util.Locale
import kittoku.mvc.backend.BackendModePolicy
import kittoku.mvc.nativecore.NativeAuthMode
import kittoku.mvc.tls.CertificateEndpoint

/** Deliberately carries no parsed values in its message or cause. */
internal class UnsupportedSoftEtherProfileException :
    IllegalArgumentException(appText(R.string.profile_runtime_softether_requirements_unsupported))

/** Credential hashes and private keys from the input are never retained here. */
internal class ImportedSoftEtherProfile(
    val name: String,
    values: Map<String, Any>,
    val certificatePin: String,
    certificateDer: ByteArray?,
) {
    val values: Map<String, Any> = Collections.unmodifiableMap(values.mapValues { (_, value) ->
        if (value is Set<*>) Collections.unmodifiableSet(value.toSet()) else value
    })
    private val der = certificateDer?.copyOf()
    val certificateDer: ByteArray? get() = der?.copyOf()
    override fun toString() = "ImportedSoftEtherProfile(fields=${values.size}, certificate=${certificatePin.isNotEmpty()})"
}

/** The official Cfg text format; never interprets commands, filenames or password blobs. */
internal object SoftEtherProfileFile {
    private const val LIMIT = 2 * 1024 * 1024
    private const val MAX_DEPTH = 8
    private const val MAX_NODES = 512
    private const val CERT_LIMIT = 128 * 1024
    private val authenticationModes = mapOf(
        0L to NativeAuthMode.ANONYMOUS,
        1L to NativeAuthMode.STANDARD_PASSWORD,
        2L to NativeAuthMode.EXTERNAL_PASSWORD,
        3L to NativeAuthMode.CLIENT_CERTIFICATE,
    )
    private val extraKeys = setOf(
        "AUTH_PASSWORD_ENCODING", "BACKEND_MODE", "ROUTE_MODE", "LAN_ROUTES", "SSL_VERSION",
        "SSL_DO_SELECT_SUITES", "SSL_SUITES", "ETHERNET_MTU", "ETHERNET_MAC_ADDRESS", "VPN_FORWARD_IPV6", "TUN_FORWARD_IPV6",
        "TUN_DESTINATION_MODE", "TUN_DESTINATION_INCLUDE", "TUN_DESTINATION_EXCLUDE",
    )

    fun read(input: InputStream, defaultProfileName: String = "Imported profile"): ImportedSoftEtherProfile = try {
        readProfile(parse(readBounded(input)), defaultProfileName)
    } catch (error: UnsupportedSoftEtherProfileException) {
        throw error
    } catch (_: Exception) {
        // Base64/UTF decoders and certificate parsers may put input bytes in errors.
        throw IllegalArgumentException(appText(R.string.profile_runtime_softether_file_invalid))
    }

    fun write(output: OutputStream, profile: StoredProfile, certificatePin: String = "", certificateDer: ByteArray? = null) {
        val bytes = try {
            encodeProfile(profile, certificatePin, certificateDer)
        } catch (_: Exception) {
            throw IllegalArgumentException(appText(R.string.profile_runtime_softether_configuration_invalid))
        }
        // Validate everything before touching the caller's document. Neither stream is closed.
        output.write(bytes)
        output.flush()
    }

    private fun readProfile(root: Section, defaultProfileName: String): ImportedSoftEtherProfile {
        val option = root.section("ClientOption") ?: invalid()
        val auth = root.section("ClientAuth") ?: invalid()
        val stockAuthentication = authenticationModes[auth.uint("AuthType")] ?: throw UnsupportedSoftEtherProfileException()
        if (option.uint("ProxyType", 0) != 0L ||
            option.bool("RequireMonitorMode", false) || option.bool("RequireBridgeRoutingMode", false)) {
            throw UnsupportedSoftEtherProfileException()
        }
        val metadata = root.section("HomeVpnAndroid")
        val passwordHash = if (stockAuthentication == NativeAuthMode.STANDARD_PASSWORD) {
            auth.bytes("HashedPassword")?.also { require(it.size == 20) }
        } else null
        val authentication = if (metadata?.bool("ClientCertificateRequired", false) == true) {
            require(passwordHash != null && passwordHash.all { it == 0.toByte() })
            NativeAuthMode.CLIENT_CERTIFICATE
        } else stockAuthentication
        val endpoint = endpoint(option.string("Hostname") ?: invalid(), option.uint("Port", 5555)!!)
        val name = profileName(option.string("AccountName") ?: defaultProfileName)
        val values = linkedMapOf<String, Any>(
            "BACKEND_MODE" to BackendModePolicy.TUN,
            "HOME_HOSTNAME" to endpoint.host,
            "SSL_PORT" to endpoint.port.toString(),
            "HOME_HUB" to identifier(option.string("HubName").orEmpty(), 255, true),
            "HOME_USERNAME" to identifier(auth.string("Username") ?: "", 255, true),
            "HOME_AUTH_TYPE" to authentication.name,
            "UDP_ENABLE_ACCELERATION" to !option.bool("NoUdpAcceleration", false),
        )
        if (metadata != null) {
            require(metadata.uint("Version") == 1L)
            metadata.string("ProfileData")?.let { encoded ->
                val profiles = ProfileCodec.decode(encoded)
                require(profiles.size == 1)
                profiles.single().values.forEach { (key, value) ->
                    require(key in extraKeys && ProfileCodec.validValue(key, value))
                    validateExtra(key, value)
                    values[key] = normalizedExtra(key, value)
                }
            }
        }
        val der = root.bytes("ServerCert")?.also { validateCertificate(it) }
        val derivedPin = der?.let(::fingerprint).orEmpty()
        val metadataPin = metadata?.string("ServerCertSha256")?.let(::pin).orEmpty()
        require(derivedPin.isEmpty() || metadataPin.isEmpty() || derivedPin == metadataPin)
        var bindingMatches = true
        if (metadataPin.isNotEmpty()) {
            val certificateHost = metadata?.string("CertificateHost") ?: invalid()
            val certificatePort = metadata!!.uint("CertificatePort") ?: invalid()
            bindingMatches = endpoint(certificateHost, certificatePort) == endpoint
        } else if (metadata != null) {
            // A stale/incomplete Android trust binding must never adopt a new endpoint.
            require(metadata.string("CertificateHost") == null && metadata.uint("CertificatePort") == null)
        }
        return ImportedSoftEtherProfile(name, values,
            if (bindingMatches) derivedPin.ifEmpty { metadataPin } else "",
            if (bindingMatches) der else null)
    }

    private fun encodeProfile(profile: StoredProfile, certificatePin: String, certificateDer: ByteArray?): ByteArray {
        val values = profile.values
        fun string(key: String, default: String) = (values[key] ?: default).also { require(it is String) } as String
        val portText = string("SSL_PORT", "5555").trim()
        require(portText.matches(Regex("[0-9]{1,5}")))
        val endpoint = endpoint(string("HOME_HOSTNAME", ""), portText.toLong())
        val name = profileName(profile.name)
        val username = identifier(string("HOME_USERNAME", ""), 255, true)
        val hub = identifier(string("HOME_HUB", "DEFAULT"), 255, false)
        val authentication = NativeAuthMode.from(values["HOME_AUTH_TYPE"] as String?)
        // The official manager rejects certificate-mode accounts without a private key.
        // Export a credential-free account it can open and keep the intended mode in Android metadata.
        val needsClientCertificate = authentication == NativeAuthMode.CLIENT_CERTIFICATE
        val stockAuthentication = if (needsClientCertificate) NativeAuthMode.STANDARD_PASSWORD else authentication
        val nativeAuthentication = authenticationModes.entries.single { it.value == stockAuthentication }.key
        val udp = (values["UDP_ENABLE_ACCELERATION"] ?: false).also { require(it is Boolean) } as Boolean
        val savedPin = pin(certificatePin)
        val der = certificateDer?.copyOf()?.also {
            validateCertificate(it)
            require(savedPin.isNotEmpty() && fingerprint(it) == savedPin)
        }
        val extras = values.filterKeys { it in extraKeys }.mapValues { (key, value) ->
            require(ProfileCodec.validValue(key, value)); validateExtra(key, value)
            normalizedExtra(key, value)
        }
        val extension = ProfileCodec.encode(listOf(StoredProfile("android", "Android", extras)))
        val text = buildString {
            append("\uFEFF# SoftEther VPN connection settings. Enter any required credentials after import.\r\n")
            append("declare root\r\n{\r\n")
            append("\tbool CheckServerCert true\r\n\tbool StartupAccount false\r\n")
            if (der != null) field("byte", "ServerCert", Base64.getEncoder().encodeToString(der))
            append("\tdeclare ClientAuth\r\n\t{\r\n")
            field("uint", "AuthType", nativeAuthentication.toString(), 2)
            if (stockAuthentication == NativeAuthMode.STANDARD_PASSWORD) {
                field("byte", "HashedPassword", Base64.getEncoder().encodeToString(ByteArray(20)), 2)
            }
            field("string", "Username", username, 2)
            append("\t}\r\n\tdeclare ClientOption\r\n\t{\r\n")
            field("string", "AccountName", name, 2)
            field("string", "DeviceName", "home", 2)
            field("string", "Hostname", endpoint.host, 2)
            field("uint", "Port", endpoint.port.toString(), 2)
            field("string", "HubName", hub, 2)
            field("uint", "ProxyType", "0", 2)
            field("uint", "MaxConnection", "1", 2)
            field("bool", "UseEncrypt", "true", 2)
            field("bool", "UseCompress", "false", 2)
            field("bool", "NoUdpAcceleration", (!udp).toString(), 2)
            field("bool", "RequireMonitorMode", "false", 2)
            field("bool", "RequireBridgeRoutingMode", "false", 2)
            append("\t}\r\n\tdeclare HomeVpnAndroid\r\n\t{\r\n")
            field("uint", "Version", "1", 2)
            field("string", "ProfileData", extension, 2)
            if (needsClientCertificate) field("bool", "ClientCertificateRequired", "true", 2)
            // No binding without a pin: a later official ServerCert can then be imported.
            if (savedPin.isNotEmpty()) {
                field("string", "CertificateHost", endpoint.host, 2)
                field("uint", "CertificatePort", endpoint.port.toString(), 2)
                field("string", "ServerCertSha256", savedPin, 2)
            }
            append("\t}\r\n}\r\n")
        }
        return encodeUtf8(text).also { require(it.size <= LIMIT) }
    }

    private fun validateExtra(key: String, value: Any) {
        if (value is String) {
            val limit = if (key == "TUN_DESTINATION_INCLUDE" || key == "TUN_DESTINATION_EXCLUDE") 16_384 else 16_000
            require(value.length <= limit && value.none { it == '\u0000' || (it.isISOControl() && it != '\n' && it != '\r' && it != '\t') })
            encodeUtf8(value)
        }
        if (value is Set<*>) {
            require(value.size <= 1000 && value.all { it is String && it.length <= 255 && it.none(Char::isISOControl) })
        }
        if (key == "BACKEND_MODE") BackendModePolicy.effective(value as String)
        if (key == "TUN_DESTINATION_MODE") require(TunDestinationMode.entries.any { it.name == value }) {
            appText(R.string.profile_runtime_invalid_destination_mode)
        }
    }

    private fun normalizedExtra(key: String, value: Any): Any = when {
        key == "BACKEND_MODE" -> BackendModePolicy.effective(value as String)
        value is Set<*> -> value.toSet()
        else -> value
    }

    private fun endpoint(host: String, port: Long): CertificateEndpoint {
        require(port in 1..65535)
        val result = CertificateEndpoint.of(host, port.toInt())
        require(result.host.length <= 253 && result.host.none { it.isWhitespace() || it.isISOControl() || it in "/\\@?#[]" })
        // Brackets are accepted only around an IPv6 literal, not arbitrary host syntax.
        if (host.trim().startsWith("[")) require(host.trim().endsWith("]") && ':' in result.host)
        return result
    }

    private fun profileName(value: String) = value.trim().also {
        require(it.isNotBlank() && it.length <= 64 && it.none(Char::isISOControl)); encodeUtf8(it)
    }

    private fun identifier(value: String, limit: Int, empty: Boolean) = value.also {
        require((empty || it.isNotBlank()) && encodeUtf8(it).size <= limit && it.none(Char::isISOControl))
    }

    private fun pin(value: String) = value.trim().lowercase(Locale.ROOT).also {
        require(it.isEmpty() || it.matches(Regex("[a-f0-9]{64}")))
    }

    private fun validateCertificate(bytes: ByteArray) {
        require(bytes.isNotEmpty() && bytes.size <= CERT_LIMIT && bytes[0] == 0x30.toByte())
        val input = ByteArrayInputStream(bytes)
        val cert = CertificateFactory.getInstance("X.509").generateCertificate(input) as X509Certificate
        require(input.available() == 0 && cert.encoded.contentEquals(bytes))
    }

    private fun fingerprint(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
        .joinToString("") { "%02x".format(it.toInt() and 255) }

    private fun StringBuilder.field(type: String, name: String, value: String, depth: Int = 1) {
        repeat(depth) { append('\t') }
        append(type).append(' ').append(name).append(' ').append(escape(value)).append("\r\n")
    }

    private fun escape(value: String): String {
        encodeUtf8(value)
        if (value.isEmpty()) return "$"
        return buildString {
            value.forEach { char ->
                if (char.code <= 32 || char == '$' || char.code == 127) {
                    append('$').append("0123456789ABCDEF"[char.code ushr 4]).append("0123456789ABCDEF"[char.code and 15])
                } else append(char)
            }
        }
    }

    private fun readBounded(input: InputStream): ByteArray {
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            if (count == 0) {
                val single = input.read()
                if (single < 0) break
                require(output.size() < LIMIT); output.write(single)
            } else {
                require(count <= LIMIT - output.size()); output.write(buffer, 0, count)
            }
        }
        return output.toByteArray()
    }

    private class Field(val type: String, val value: Any)
    private class Section {
        val fields = linkedMapOf<String, Field>()
        val children = linkedMapOf<String, Section>()
        fun section(name: String) = children[name.lowercase(Locale.ROOT)]
        fun string(name: String): String? = field(name, "string")?.value as String?
        fun bytes(name: String): ByteArray? = field(name, "byte")?.value as ByteArray?
        fun uint(name: String, default: Long? = null): Long? = (field(name, "uint")?.value as Long?) ?: default
        fun bool(name: String, default: Boolean) = (field(name, "bool")?.value as Boolean?) ?: default
        private fun field(name: String, type: String): Field? = fields[name.lowercase(Locale.ROOT)]?.also { require(it.type == type) }
        fun unused(name: String) = name !in fields && name !in children
    }

    private fun parse(bytes: ByteArray): Section {
        val text = decodeUtf8(bytes).removePrefix("\uFEFF")
        require(text.none { it.isISOControl() && it != '\r' && it != '\n' && it != '\t' })
        val document = Section()
        val stack = ArrayDeque<Section>().apply { addLast(document) }
        var pending: Section? = null
        var nodes = 0
        text.lineSequence().forEach { raw ->
            val line = raw.trim(' ', '\t')
            if (line.isEmpty() || line.startsWith("#") || line.startsWith("//")) return@forEach
            if (pending != null) {
                require(line == "{" && stack.size < MAX_DEPTH)
                stack.addLast(pending!!); pending = null
                return@forEach
            }
            if (line == "}") {
                require(stack.size > 1); stack.removeLast()
                return@forEach
            }
            val tokens = line.split(Regex("[ \t]+"), limit = 4)
            require(++nodes <= MAX_NODES)
            val section = stack.last()
            val kind = tokens.first().lowercase(Locale.ROOT)
            if (kind == "declare") {
                require(tokens.size == 2 || (tokens.size == 3 && tokens[2] == "{"))
                val name = unescape(tokens[1]).lowercase(Locale.ROOT)
                require(name.isNotEmpty() && name.length <= 128 && name.none(Char::isISOControl) && section.unused(name))
                val next = Section(); section.children[name] = next
                if (tokens.size == 3) { require(stack.size < MAX_DEPTH); stack.addLast(next) } else pending = next
            } else {
                require(stack.size > 1 && tokens.size == 3)
                val name = unescape(tokens[1]).lowercase(Locale.ROOT)
                require(name.isNotEmpty() && name.length <= 128 && name.none(Char::isISOControl) && section.unused(name))
                val value = unescape(tokens[2])
                val parsed: Any = when (kind) {
                    "string" -> value
                    "byte" -> Base64.getDecoder().decode(value)
                    "uint" -> { require(value.matches(Regex("[0-9]{1,10}"))); value.toLong().also { require(it <= 0xffffffffL) } }
                    "uint64" -> { require(value.matches(Regex("[0-9]{1,20}"))); BigInteger(value).also { require(it.bitLength() <= 64) } }
                    "bool" -> when (value.lowercase(Locale.ROOT)) {
                        "true" -> true
                        "false" -> false
                        else -> { require(value.matches(Regex("[0-9]{1,10}"))); value.toLong().also { require(it <= 0xffffffffL) } != 0L }
                    }
                    else -> invalid()
                }
                section.fields[name] = Field(kind, parsed)
            }
        }
        require(pending == null && stack.size == 1 && document.fields.isEmpty() && document.children.size == 1)
        return document.section("root") ?: invalid()
    }

    private fun unescape(token: String): String {
        if (token == "$") return ""
        val bytes = encodeUtf8(token)
        val decoded = ByteArrayOutputStream(bytes.size)
        var index = 0
        while (index < bytes.size) {
            val value = bytes[index++].toInt() and 255
            if (value != 36) decoded.write(value) else {
                require(index + 1 < bytes.size)
                val high = Character.digit(bytes[index++].toInt().toChar(), 16)
                val low = Character.digit(bytes[index++].toInt().toChar(), 16)
                require(high >= 0 && low >= 0); decoded.write(high * 16 + low)
            }
        }
        return decodeUtf8(decoded.toByteArray()).also { require('\u0000' !in it) }
    }

    private fun decodeUtf8(bytes: ByteArray) = Charsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(bytes)).toString()

    private fun encodeUtf8(text: String): ByteArray {
        val buffer = Charsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).encode(java.nio.CharBuffer.wrap(text))
        return ByteArray(buffer.remaining()).also { buffer.get(it) }
    }

    private fun invalid(): Nothing = throw IllegalArgumentException(appText(R.string.profile_runtime_softether_file_invalid))
}
