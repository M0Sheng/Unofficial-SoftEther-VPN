package kittoku.mvc.profile

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.KeyStore
import java.security.MessageDigest
import java.util.Base64
import org.junit.Assert.*
import org.junit.Test

class SoftEtherProfileFileTest {
    @Test fun importsBomUtf8EscapesAndDropsPasswordEquivalentHash() {
        val text = "\uFEFF# Official banner\r\n" + official()
            .replace("string AccountName Sample", "string AccountName \u914d\u7f6e\u540d\$20\$E4\$B8\$80")
            .replace("string Username Alice", "string Username Alice\$20Smith\$24")
        val imported = read(text)
        assertEquals("配置名 一", imported.name)
        assertEquals("vpn.example.test", imported.values["HOME_HOSTNAME"])
        assertEquals("TUN", imported.values["BACKEND_MODE"])
        assertEquals("Alice Smith$", imported.values["HOME_USERNAME"])
        assertEquals("5555", imported.values["SSL_PORT"])
        assertEquals("STANDARD_PASSWORD", imported.values["HOME_AUTH_TYPE"])
        assertFalse(imported.values.containsKey("HOME_PASSWORD"))
        assertFalse(imported.toString().contains("Alice"))
        assertFalse(imported.values.values.contains(Base64.getEncoder().encodeToString(ByteArray(20) { 79 })))
    }

    @Test fun usesTheSuppliedNameForAnUnnamedImport() {
        val input = official().lineSequence().filterNot { "string AccountName " in it }.joinToString("\n")
        val imported = SoftEtherProfileFile.read(ByteArrayInputStream(input.toByteArray()), "Test import name")
        assertEquals("Test import name", imported.name)
    }

    @Test fun blankUsernameAndMissingOptionalFieldsRemainEditable() {
        val imported = read(official().replace("string Username Alice", "string Username $"))
        assertEquals("", imported.values["HOME_USERNAME"])
        assertEquals("", imported.values["HOME_HUB"])
        assertEquals("Research", read(official(optionExtra = "string HubName Research")).values["HOME_HUB"])
        assertEquals(true, imported.values["UDP_ENABLE_ACCELERATION"])
        val noHash = official().lineSequence().filterNot { "HashedPassword" in it }.joinToString("\n")
        assertFalse(read(noHash).values.containsKey("HOME_PASSWORD"))
    }

    @Test fun fieldsAreReadOnlyFromTheirCorrectNestedSection() {
        val imported = read(official(rootExtra = "string Hostname decoy.invalid\nuint Port 1", authExtra = "uint Port 2"))
        assertEquals("vpn.example.test", imported.values["HOME_HOSTNAME"])
        assertEquals("5555", imported.values["SSL_PORT"])
    }

    @Test fun passwordFreeOfficialExportPreservesUsernameAndSafeSecurityFlags() {
        val password = "UNIQUE_PASSWORD_MUST_NOT_EXPORT_6161"
        val bytes = write(profile(mapOf("HOME_PASSWORD" to password, "HOME_USERNAME" to "Alice Smith$",
            "NATIVE_MANAGEMENT_ONLY" to true, "UDP_ENABLE_ACCELERATION" to true)))
        val text = bytes.toString(Charsets.UTF_8)
        assertTrue(text.startsWith("\uFEFF"))
        assertFalse(text.contains(password))
        assertFalse(text.contains("HOME_PASSWORD"))
        assertFalse(text.contains("NATIVE_MANAGEMENT_ONLY"))
        assertTrue(text.contains("bool CheckServerCert true"))
        assertTrue(text.contains("bool UseEncrypt true"))
        assertTrue(text.contains("bool StartupAccount false"))
        assertTrue(text.contains("string DeviceName home"))
        assertTrue(text.contains("byte HashedPassword " + Base64.getEncoder().encodeToString(ByteArray(20))))
        val imported = SoftEtherProfileFile.read(ByteArrayInputStream(bytes))
        assertEquals("Alice Smith$", imported.values["HOME_USERNAME"])
        assertEquals(true, imported.values["UDP_ENABLE_ACCELERATION"])
        assertFalse(imported.values.containsKey("HOME_PASSWORD"))
        assertFalse(imported.values.containsKey("NATIVE_MANAGEMENT_ONLY"))
    }

    @Test fun safeAndroidExtrasRoundTripAndSetsAreDetached() {
        val suites = linkedSetOf("TLS_AES_128_GCM_SHA256")
        val result = SoftEtherProfileFile.read(ByteArrayInputStream(write(profile(mapOf(
            "BACKEND_MODE" to "TUN", "ROUTE_MODE" to "LAN", "LAN_ROUTES" to "10.0.0.0/8\n192.168.0.0/16",
            "VPN_FORWARD_IPV6" to false, "SSL_DO_SELECT_SUITES" to true, "SSL_SUITES" to suites,
        )))))
        suites.clear()
        assertEquals("TUN", result.values["BACKEND_MODE"])
        assertEquals("10.0.0.0/8\n192.168.0.0/16", result.values["LAN_ROUTES"])
        assertEquals(setOf("TLS_AES_128_GCM_SHA256"), result.values["SSL_SUITES"])
        assertEquals(false, result.values["VPN_FORWARD_IPV6"])
    }

    @Test fun supportedOfficialAuthenticationModesRoundTripWithoutCredentials() {
        val modes = mapOf(0 to "ANONYMOUS", 1 to "STANDARD_PASSWORD", 2 to "EXTERNAL_PASSWORD", 3 to "CLIENT_CERTIFICATE")
        val password = "synthetic-external-password"
        val key = "synthetic-protected-private-key"
        val certificate = b64(publicCertificate())
        modes.forEach { (id, mode) ->
            val exported = write(profile(mapOf("HOME_AUTH_TYPE" to mode, "HOME_PASSWORD" to password,
                "HOME_CLIENT_CERT" to certificate, "HOME_CLIENT_KEY" to key))).toString(Charsets.UTF_8)
            val stockId = if (id == 3) 1 else id
            assertTrue(exported.contains("uint AuthType $stockId\r\n"))
            assertTrue(exported.contains("bool StartupAccount false"))
            assertEquals(stockId == 1, exported.contains("byte HashedPassword"))
            assertEquals(id == 3, exported.contains("bool ClientCertificateRequired true"))
            listOf(password, key, certificate, "EncryptedPassword", "byte ClientCert ", "ClientKey").forEach {
                assertFalse(exported.contains(it))
            }
            val imported = read(exported)
            assertEquals(mode, imported.values["HOME_AUTH_TYPE"])
            assertEquals("Alice", imported.values["HOME_USERNAME"])
            assertFalse(imported.values.keys.any { it in setOf("HOME_PASSWORD", "HOME_CLIENT_CERT", "HOME_CLIENT_KEY") })
        }
    }

    @Test fun officialExternalPasswordAndClientKeyAreDiscardedOnImport() {
        val encryptedPassword = b64("synthetic-password".toByteArray())
        val key = b64("synthetic-private-key".toByteArray())
        val external = read(official(authType = 2, authExtra = "byte EncryptedPassword $encryptedPassword"))
        val certificate = read(official(authType = 3, authExtra = "byte ClientCert ${b64(publicCertificate())}\nbyte ClientKey $key"))
        assertEquals("EXTERNAL_PASSWORD", external.values["HOME_AUTH_TYPE"])
        assertEquals("CLIENT_CERTIFICATE", certificate.values["HOME_AUTH_TYPE"])
        assertFalse(external.values.containsKey("HOME_PASSWORD"))
        assertFalse(certificate.values.containsKey("HOME_CLIENT_KEY"))
        assertFalse(certificate.values.containsKey("HOME_CLIENT_CERT"))
    }

    @Test fun androidCertificateMetadataOnlyOverridesTheCredentialFreeStockPlaceholder() {
        val flag = "declare HomeVpnAndroid\n{\nuint Version 1\nbool ClientCertificateRequired true\n}"
        rejects(official(rootExtra = flag))
        rejects(official(rootExtra = flag, authType = 0))
        rejects(official(rootExtra = flag, authType = 2))
        assertEquals("CLIENT_CERTIFICATE", read(official(rootExtra = flag)
            .replace(b64(ByteArray(20) { 79 }), b64(ByteArray(20)))).values["HOME_AUTH_TYPE"])
    }

    @Test fun tunIpv6OptInRoundTripsWithoutEnablingLegacyImports() {
        val legacy = read(official())
        assertFalse(legacy.values.containsKey("TUN_FORWARD_IPV6"))
        for (enabled in listOf(false, true)) {
            val result = SoftEtherProfileFile.read(ByteArrayInputStream(write(profile(mapOf(
                "BACKEND_MODE" to "TUN", "TUN_FORWARD_IPV6" to enabled, "VPN_FORWARD_IPV6" to !enabled,
            )))))
            assertEquals(enabled, result.values["TUN_FORWARD_IPV6"])
            assertEquals(!enabled, result.values["VPN_FORWARD_IPV6"])
        }
    }

    @Test fun destinationModeAndBothListsRoundTripWithoutOptingLegacyFilesIn() {
        assertFalse(read(official()).values.containsKey("TUN_DESTINATION_MODE"))
        for (mode in listOf("EXCLUDE", "INCLUDE", "ALL")) {
            val extras = mapOf("TUN_DESTINATION_MODE" to mode,
                "TUN_DESTINATION_INCLUDE" to "10.0.0.0/8\n2001:db8::/32\nexample.test",
                "TUN_DESTINATION_EXCLUDE" to "192.0.2.1")
            val result = SoftEtherProfileFile.read(ByteArrayInputStream(write(profile(extras))))
            extras.forEach { (key, value) -> assertEquals(value, result.values[key]) }
        }
        rejects(official(rootExtra = metadata(mapOf("TUN_DESTINATION_MODE" to "UNKNOWN"))))
    }

    @Test fun supportedRetiredBackendNormalizesButUnknownBackendIsRejected() {
        assertEquals("ROOT_NATIVE", read(official(rootExtra = metadata(mapOf("BACKEND_MODE" to "ROOT_TAP")))).values["BACKEND_MODE"])
        rejects(official(rootExtra = metadata(mapOf("BACKEND_MODE" to "ROOT_LEGACY"))))
    }

    @Test fun metadataCannotSmugglePasswordManagementOrOverrideOfficialCore() {
        listOf("HOME_PASSWORD" to "synthetic-secret", "NATIVE_MANAGEMENT_ONLY" to true,
            "HOME_HOSTNAME" to "other.invalid", "HOME_USERNAME" to "other", "HOME_AUTH_TYPE" to "ANONYMOUS").forEach { (key, value) ->
            rejects(official(rootExtra = metadata(mapOf(key to value))))
        }
        rejects(official(rootExtra = "declare HomeVpnAndroid\n{\nuint Version 2\n}"))
    }

    @Test fun unsupportedAuthenticationProxyAndRequiredModesHaveDistinctException() {
        listOf(4, 99).forEach { auth ->
            assertThrows(UnsupportedSoftEtherProfileException::class.java) { read(official(authType = auth)) }
        }
        listOf("uint ProxyType 1", "uint ProxyType 2", "bool RequireMonitorMode true", "bool RequireBridgeRoutingMode true").forEach {
            assertThrows(UnsupportedSoftEtherProfileException::class.java) { read(official(optionExtra = it)) }
        }
    }

    @Test fun malformedTypesDuplicateNamesAndStructuresAreRejected() {
        listOf(
            official().replace("uint AuthType 1", "string AuthType 1"),
            official().replace("uint AuthType 1", "uint AuthType 1\nuint AUTHTYPE 1"),
            official().replace("string Hostname VPN.Example.Test", "uint Hostname 8"),
            official().replace("string Hostname VPN.Example.Test", "string Hostname VPN.Example.Test\nstring HOSTNAME other.invalid"),
            official().replace("declare ClientAuth", "declare ClientOption"),
            official().dropLast(1),
            official() + "\n}\n",
            official() + "\ndeclare second\n{\n}\n",
            official(rootExtra = "declare " + "a\n{\ndeclare ".repeat(9) + "z\n{\n" + "}\n".repeat(10)),
            official(rootExtra = "bool Extra notabool"),
            official(rootExtra = "uint64 Extra 18446744073709551616"),
        ).forEach(::rejects)
    }

    @Test fun malformedEscapesUtf8AndIdentifiersNeverReachConnectionSettings() {
        listOf("bad\$GG", "bad\$2", "bad\$00name", "bad\$C3", "https://vpn.example.test", "a\$20b", "bad/name", "a@b").forEach {
            rejects(official().replace("VPN.Example.Test", it))
        }
        listOf("0", "65536", "4294967296", "-1", "12345678901234567890").forEach {
            rejects(official(optionExtra = "uint Port $it"))
        }
        val invalidUtf8 = official().toByteArray() + byteArrayOf(0xc3.toByte(), 0x28)
        assertThrows(IllegalArgumentException::class.java) { SoftEtherProfileFile.read(ByteArrayInputStream(invalidUtf8)) }
    }

    @Test fun oversizedInputTooManyFieldsAndManyTokensAreBounded() {
        assertThrows(IllegalArgumentException::class.java) {
            SoftEtherProfileFile.read(ByteArrayInputStream(ByteArray(2 * 1024 * 1024 + 1) { 32 }))
        }
        rejects(official(rootExtra = (0..512).joinToString("\n") { "uint Field$it 0" }))
        rejects(official(rootExtra = "string Field " + "a ".repeat(100000)))
    }

    @Test fun originalServerCertificateImportsAndExportsAsSingleDer() {
        val der = publicCertificate()
        val hash = fingerprint(der)
        val imported = read(official(rootExtra = "byte ServerCert " + b64(der)))
        assertEquals(hash, imported.certificatePin)
        assertArrayEquals(der, imported.certificateDer)
        val copy = imported.certificateDer!!; copy.fill(0)
        assertArrayEquals(der, imported.certificateDer)
        val exported = SoftEtherProfileFile.read(ByteArrayInputStream(write(profile(), hash, der)))
        assertEquals(hash, exported.certificatePin)
        assertArrayEquals(der, exported.certificateDer)
    }

    @Test fun metadataPinBindingDoesNotFollowEditedOfficialEndpoint() {
        val hash = "ab".repeat(32)
        val text = write(profile(), hash).toString(Charsets.UTF_8)
        assertEquals(hash, read(text).certificatePin)
        assertEquals("", read(text.replace("string Hostname vpn.example.test", "string Hostname other.invalid")).certificatePin)
        assertEquals("", read(text.replace("uint Port 5555", "uint Port 443")).certificatePin)
        assertEquals(hash, read(text.replace("string Hostname vpn.example.test", "string Hostname VPN.EXAMPLE.TEST")).certificatePin)
    }

    @Test fun changedEndpointDropsBundledAndroidDerButNativeCertificateCanBeAddedLater() {
        val der = publicCertificate(); val hash = fingerprint(der)
        val text = write(profile(), hash, der).toString(Charsets.UTF_8)
        val edited = read(text.replace("string Hostname vpn.example.test", "string Hostname other.invalid"))
        assertEquals("", edited.certificatePin)
        assertNull(edited.certificateDer)
        val withoutPin = write(profile()).toString(Charsets.UTF_8)
        assertFalse(withoutPin.contains("CertificateHost"))
        val later = read(withoutPin.replace("\tbool CheckServerCert true", "\tbyte ServerCert ${b64(der)}\r\n\tbool CheckServerCert true"))
        assertEquals(hash, later.certificatePin)
    }

    @Test fun badOrConflictingCertificateInputAndExportAreRejectedAtomically() {
        val der = publicCertificate(); val hash = fingerprint(der)
        listOf(der + byteArrayOf(0), der + der, "not a certificate".toByteArray()).forEach {
            rejects(official(rootExtra = "byte ServerCert " + b64(it)))
        }
        val text = write(profile(), hash, der).toString(Charsets.UTF_8)
        rejects(text.replace("string ServerCertSha256 $hash", "string ServerCertSha256 " + "00".repeat(32)))
        listOf("" to der, "00".repeat(32) to der, hash to (der + byteArrayOf(1))).forEach { (pin, certificate) ->
            val output = ByteArrayOutputStream()
            assertThrows(IllegalArgumentException::class.java) { SoftEtherProfileFile.write(output, profile(), pin, certificate) }
            assertEquals(0, output.size())
        }
    }

    @Test fun errorsDoNotRetainOrPrintParsedSecrets() {
        val secret = "SECRET_NEVER_IN_STACK_TRACE_7237"
        val input = official(rootExtra = "byte Unknown $secret")
        val failure = assertThrows(IllegalArgumentException::class.java) { read(input) }
        assertFalse(failure.stackTraceToString().contains(secret))
        assertNull(failure.cause)
        val invalid = profile(mapOf("HOME_HOSTNAME" to "https://$secret.invalid", "HOME_PASSWORD" to secret))
        val output = ByteArrayOutputStream()
        val exportFailure = assertThrows(IllegalArgumentException::class.java) { SoftEtherProfileFile.write(output, invalid) }
        assertFalse(exportFailure.stackTraceToString().contains(secret))
        assertNull(exportFailure.cause)
        assertEquals(0, output.size())
    }

    @Test fun callerStreamsRemainOpen() {
        val input = object : ByteArrayInputStream(official().toByteArray()) {
            var closed = false
            override fun close() { closed = true; super.close() }
        }
        SoftEtherProfileFile.read(input)
        assertFalse(input.closed)
        val output = object : ByteArrayOutputStream() {
            var closed = false
            override fun close() { closed = true; super.close() }
        }
        SoftEtherProfileFile.write(output, profile())
        assertFalse(output.closed)
    }

    private fun profile(extra: Map<String, Any> = emptyMap()) = StoredProfile("synthetic", "Sample 配置 $", mapOf<String, Any>(
        "HOME_HOSTNAME" to "vpn.example.test", "SSL_PORT" to "5555", "HOME_HUB" to "DEFAULT", "HOME_USERNAME" to "Alice",
    ) + extra)

    private fun official(rootExtra: String = "", optionExtra: String = "", authExtra: String = "", authType: Int = 1) = """
        declare root
        {
          bool CheckServerCert false
          bool StartupAccount true
          uint64 CreateDateTime 18446744073709551615
          declare ClientAuth
          {
            uint AuthType $authType
            ${if (authType == 1) "byte HashedPassword ${b64(ByteArray(20) { 79 })}" else ""}
            string Username Alice
            $authExtra
          }
          declare ClientOption
          {
            string Hostname VPN.Example.Test
            string AccountName Sample
            $optionExtra
          }
          $rootExtra
        }
    """.trimIndent()

    private fun metadata(values: Map<String, Any>) = "declare HomeVpnAndroid\n{\nuint Version 1\nstring ProfileData " +
        ProfileCodec.encode(listOf(StoredProfile("extra", "Extra", values))) + "\n}"

    private fun read(text: String) = SoftEtherProfileFile.read(ByteArrayInputStream(text.toByteArray(Charsets.UTF_8)))
    private fun write(profile: StoredProfile, pin: String = "", der: ByteArray? = null) = ByteArrayOutputStream().also {
        SoftEtherProfileFile.write(it, profile, pin, der)
    }.toByteArray()
    private fun rejects(text: String) { assertThrows(IllegalArgumentException::class.java) { read(text) } }
    private fun b64(bytes: ByteArray) = Base64.getEncoder().encodeToString(bytes)
    private fun fingerprint(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it.toInt() and 255) }

    private fun publicCertificate(): ByteArray {
        val store = KeyStore.getInstance("PKCS12")
        val stream = javaClass.getResourceAsStream("/tls/localhost.p12") ?: error("Missing public TLS test fixture")
        stream.use { store.load(it, "test-only".toCharArray()) }
        return store.getCertificate("test-server").encoded
    }
}
