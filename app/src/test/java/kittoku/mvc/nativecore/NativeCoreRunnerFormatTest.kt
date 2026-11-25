package kittoku.mvc.nativecore

import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.Rule
import org.junit.rules.TemporaryFolder
import java.io.File
import java.util.concurrent.TimeUnit
import kittoku.mvc.cipher.hashSha0

class NativeCoreRunnerFormatTest {
    @Test fun recognizesManagedSessionFailureMarkersIncludingUnknownCodes() {
        for (code in listOf(1, 8, 9, 13, 19, 85, 149, 1000)) {
            assertEquals(code, nativeSessionFailure("SoftEther managed_session_failed code=$code")?.code)
        }
    }

    @Test fun ignoresSuccessCancellationAndUnrelatedOutput() {
        for (value in listOf("0", "6", "-9", "09", "+9", "9 ", "9 retry", "2147483648")) {
            assertNull(nativeSessionFailure("SoftEther managed_session_failed code=$value"))
        }
        assertNull(nativeSessionFailure("prefix SoftEther managed_session_failed code=9"))
        assertNull(nativeSessionFailure("SoftEther server_error phase=authentication_response code=9"))
        assertNull(nativeSessionFailure("SoftEther session ended (error 9)"))
        assertNull(nativeSessionFailure("vpncmd exited with error 9"))
    }

    @Test fun nicListIgnoresEchoedHomevpnPathAndUnixDefaultAdapter() {
        val output = "Input file: /data/user/0/io.github.m0sheng.unofficialsoftethervpn/files/official-native-core/command-123.in\n" +
            "VPN Client>NicList\nVirtual Network Adapter Name,Status,MAC Address,Version\n" +
            "vpn,Enabled,5E-14-00-11-22-33,Version 4.44 Build 9807\n"
        assertFalse(NativeCoreRunner.nicListContains(output, "home"))
        assertTrue(NativeCoreRunner.nicListContains(output, "vpn"))
    }

    @Test fun nicListMatchesCompleteNameCaseInsensitivelyInOfficialFourColumnCsv() {
        val other = "\"workhome\",\"Enabled\",\"5E-00-11-22-33-44\",\"home version\"\r\n" +
            "\"home-office\",\"Enabled\",\"5E-00-11-22-33-55\",\"4.44\"\r\n"
        assertFalse(NativeCoreRunner.nicListContains(other, "home"))
        assertTrue(NativeCoreRunner.nicListContains(other + "\"HOME\",\"Enabled\",\"5E-00-11-22-33-66\",\"Version 4.44, Build 9807\"\r\n", "home"))
    }

    @Test fun nicListRejectsNonTableAndMalformedRows() {
        assertFalse(NativeCoreRunner.nicListContains("home\nhome,Enabled\n\"home,Enabled,5E-00,4.44\n", "home"))
    }

    @Test fun managementHashMatchesIndependentOfficialCVector() {
        // MY_SHA0_hash from pinned official Encrypt.c, compiled and called as C.
        val digest = hashSha0("abcdefghijkl".toByteArray(Charsets.US_ASCII))
        assertEquals("46ec20a71c8d17d44ff61b590205f466a58081aa", digest.joinToString("") { "%02x".format(it.toInt() and 255) })
        assertTrue(NativeCoreRunner.isUsableRemoteHash(digest))
    }
    @get:Rule val temporary = TemporaryFolder()

    private fun posixShell(): File? {
        File("/bin/sh").takeIf(File::isFile)?.let { return it }
        return System.getenv("PATH").orEmpty().split(File.pathSeparatorChar).asSequence()
            .filter(String::isNotBlank)
            .map { File(it.trim('"')) }
            .filter { File(it, "git.exe").isFile }
            .flatMap { sequenceOf(File(it, "bash.exe"), File(it.parentFile, "bin/bash.exe")) }
            .firstOrNull(File::isFile)
    }

    @Test fun executablePathContainingApkEqualsSegmentsRunsWithLiteralEnvironmentAndArguments() {
        val shell = posixShell()
        assumeTrue("A POSIX shell is required for the real launch boundary test", shell != null)
        val executable = File(temporary.root, "~~install-token==/io.github.m0sheng.unofficialsoftethervpn-package-token==/lib/arm64/libhomevpn_test.so")
        assertTrue(requireNotNull(executable.parentFile).mkdirs())
        executable.writeText("#!/bin/sh\nprintf '%s|%s|%s|%s' \"\$HOMEVPN_DATA_DIR\" \"\$HOMEVPN_MANAGED_HOME\" \"\$1\" \"\$2\"\n")
        executable.setExecutable(true)
        val directory = "private directory=42 with 'quotes'"
        val argument = "literal \$(printf INJECTED); command"
        val invocation = NativeCoreRunner.rootInvocation(
            linkedMapOf("HOMEVPN_DATA_DIR" to directory, "HOMEVPN_MANAGED_HOME" to "1"),
            listOf(executable.absolutePath.replace('\\', '/'), "androidsvc", argument))
        val process = ProcessBuilder(shell!!.path).redirectErrorStream(true).start()
        process.outputStream.use { it.write((invocation + "\n").toByteArray(Charsets.UTF_8)) }
        assertTrue(process.waitFor(5, TimeUnit.SECONDS))
        val output = process.inputStream.readBytes().toString(Charsets.UTF_8)
        assertEquals(output, 0, process.exitValue())
        assertEquals("$directory|1|androidsvc|$argument", output)
    }

    @Test fun rootInvocationRejectsInvalidExportNamesAndNulValues() {
        for (environment in listOf(mapOf("NAME;printf INJECTED" to "x"), mapOf("OK" to "bad\u0000value"))) {
            try { NativeCoreRunner.rootInvocation(environment, listOf("/bin/true")); fail("Accepted an unsafe environment assignment") }
            catch (_: IllegalArgumentException) {}
        }
    }

    @Test fun remoteHashRejectsEmptyCredentialZeroAndHexTextInsteadOfRawBytes() {
        val emptyPasswordSha0 = "f96cea198ad1dd5617ac084a3d92c6107708c0ef".chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        assertFalse(NativeCoreRunner.isUsableRemoteHash(emptyPasswordSha0))
        assertFalse(NativeCoreRunner.isUsableRemoteHash(ByteArray(20)))
        assertFalse(NativeCoreRunner.isUsableRemoteHash("a".repeat(40).toByteArray()))
        assertTrue(NativeCoreRunner.isUsableRemoteHash(ByteArray(20) { 0x5a }))
    }
    @Test fun shellArgumentsRemainLiteralInARealPosixShell() {
        val shell = posixShell()
        assumeTrue("A POSIX shell is required for the argv boundary test", shell != null)
        val values = listOf("", "a b", "a'b", "\"quoted\"", "\$(printf INJECTED)", "`printf INJECTED`", "x;y", "line1\nline2", "a\\b")
        for (value in values) {
            // Feed the exact script bytes: Windows java->MSYS argv conversion
            // applies an additional quoting layer absent on Android/Linux.
            val process = ProcessBuilder(shell!!.path).redirectErrorStream(true).start()
            process.outputStream.use { it.write(("printf %s " + NativeCoreRunner.shellQuote(value) + "\n").toByteArray(Charsets.UTF_8)) }
            assertTrue(process.waitFor(5, TimeUnit.SECONDS))
            assertEquals(0, process.exitValue())
            assertEquals(value, process.inputStream.readBytes().toString(Charsets.UTF_8))
        }
    }

    @Test fun commandTokensRejectExtraLinesAndKeepQuotesInsideOneArgument() {
        assertEquals("\"a\"\"b c\"", NativeCoreRunner.token("a\"b c"))
        for (bad in listOf("a\nAccountDelete home", "a\rb", "a\u0000b")) {
            try { NativeCoreRunner.token(bad); fail("Accepted a command boundary character") }
            catch (_: IllegalArgumentException) {}
        }
    }

    @Test fun officialCsvCountersWithQuotedThousandsAndEscapedQuotesAreParsed() {
        val rows = NativeCoreRunner.csvRows(
            "Item,Value\n\"Session Status\",\"Connection Completed (Session Established)\"\n" +
                "\"Incoming Data Size\",\"1,234,567 bytes\"\n\"Description\",\"a \"\"quoted\"\" value\"\n")
        assertEquals("a \"quoted\" value", rows["Description"])
        assertEquals(1_234_567L, NativeCoreRunner.byteCount(rows["Incoming Data Size"]))
        assertEquals("Connection Completed (Session Established)", rows["Session Status"])
    }

    @Test fun missingAndOverflowTrafficRemainUnknownRatherThanInventingZero() {
        assertNull(NativeCoreRunner.byteCount(null))
        assertNull(NativeCoreRunner.byteCount("Unknown"))
        assertNull(NativeCoreRunner.byteCount("999999999999999999999999 bytes"))
        assertEquals(0L, NativeCoreRunner.byteCount("0 bytes"))
    }

    @Test fun sessionKeysPasswordsPrivateKeysAndKnownSecretsAreRemoved() {
        val raw = "Session Key (160 bit),0123456789abcdef\n" +
            "VPN Client>AccountPasswordSet other /PASSWORD:unrelated-new-secret /TYPE:standard\n" +
            "VPN Client>PasswordSet positional-remote-secret /REMOTEONLY:no\n" +
            "-----BEGIN PRIVATE KEY-----\nPRIVATE-PAYLOAD\n-----END PRIVATE KEY-----\n" +
            "safe status host=example.org known-password"
        val safe = NativeCoreRunner.sanitizeOutput(raw, listOf("known-password", ""))
        for (secret in listOf("0123456789abcdef", "unrelated-new-secret", "positional-remote-secret", "PRIVATE-PAYLOAD", "known-password")) assertFalse(safe.contains(secret))
        assertTrue(safe.contains("example.org"))
    }
}

