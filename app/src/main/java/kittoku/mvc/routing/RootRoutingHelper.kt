package kittoku.mvc.routing

import java.io.BufferedReader
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.io.InputStreamReader
import java.io.RandomAccessFile
import java.lang.reflect.Array as ReflectArray
import java.lang.reflect.Constructor
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Method
import java.net.Inet6Address
import java.net.InetAddress
import java.net.NetworkInterface
import java.net.UnknownHostException
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.StandardOpenOption
import java.util.Base64
import java.util.TreeMap
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import java.util.zip.CRC32
import kotlin.system.exitProcess

/** Android root process that owns the netd and kernel changes for a TAP routing session. */
class RootRoutingHelper private constructor(
    private val directory: File,
    private val netd: Netd,
    private val journal: RandomAccessFile,
) {
    private val actions = ArrayList<Action>()
    private var closing = false
    private var journalTrusted = false

    internal class Config(line: String) {
        val uid: Int
        val netId: Int
        val iface: String
        val token: String
        val tapName: String
        val namedTap: Boolean
        val ranges: List<String>
        val cidrs: List<String>

        init {
            val fields = line.split('\t')
            require((fields.size == 7 || fields.size == 8) && fields[0] == "V1") {
                "Invalid routing configuration"
            }
            uid = number(fields[1], 10000, Int.MAX_VALUE)
            netId = number(fields[2], 100, 65535)
            iface = fields[3]
            token = fields[4]
            namedTap = fields.size == 8
            tapName = if (namedTap) fields[7] else LEGACY_TAP_NAME
            validateTapName(tapName)
            require(IFACE_NAME.matches(iface) && iface != tapName && TOKEN.matches(token)) {
                "Invalid session/interface"
            }
            ranges = boundedList(fields[5], 1024)
            var previous = -1
            val userBase = uid / 100000 * 100000
            for (range in ranges) {
                val ends = range.split('-')
                require(ends.size == 2) { "Invalid UID range" }
                val first = number(ends[0], userBase + 10000, userBase + 29999)
                val last = number(ends[1], first, userBase + 29999)
                require(first > previous) { "Unsorted/overlapping UID ranges" }
                previous = last
            }
            cidrs = boundedList(fields[6], 256)
            cidrs.forEach(::numericCidr)
        }

        fun wire(): String {
            val fields = listOf("V1", uid.toString(), netId.toString(), iface, token, listWire(ranges), listWire(cidrs))
            return (if (namedTap) fields + tapName else fields).joinToString("\t")
        }
    }

    internal class Attach(line: String, config: Config) {
        val netId: Int
        val index: Int
        val iface: String

        init {
            val words = line.split('\t')
            if ((words.size != 3 && words.size != 4) || words[0] != "ATTACH" || (config.namedTap && words.size != 4)) {
                throw IOException("Invalid owned TAP routing command")
            }
            netId = number(words[1], 100, 65535)
            index = number(words[2], 1, Int.MAX_VALUE)
            iface = words.getOrElse(3) { LEGACY_TAP_NAME }
            validateTapName(iface)
            if (iface != config.tapName || iface == config.iface || netId == config.netId) {
                throw IOException("Owned TAP differs from its configuration or underlay")
            }
        }
    }

    private class Netd {
        private val binderProxy: Any?
        private val addRanges: Method
        private val removeRanges: Method
        private val rangeConstructor: Constructor<*>
        private val configConstructor: Constructor<*>
        private val rangeType: Class<*>

        init {
            if (call(Class.forName("android.os.Process").getMethod("myUid"), null) != 0) {
                throw IOException("Root helper is not UID 0")
            }
            val binderType = Class.forName("android.os.IBinder")
            val binder = call(Class.forName("android.os.ServiceManager").getMethod("getService", String::class.java), null, "netd")
            if (binder == null || call(binderType.getMethod("getInterfaceDescriptor"), binder) != "android.net.INetd") {
                throw IOException("Unexpected netd Binder")
            }
            val type = Class.forName("android.net.INetd")
            binderProxy = call(Class.forName("android.net.INetd\$Stub").getMethod("asInterface", binderType), null, binder)
            val version = call(type.getMethod("getInterfaceVersion"), binderProxy) as Int
            val hash = call(type.getMethod("getInterfaceHash"), binderProxy) as String?
            if (version != 17 || hash != HASH_17 || call(type.getMethod("isAlive"), binderProxy) != true) {
                throw IOException("Unsupported netd interface: $version/$hash")
            }
            rangeType = Class.forName("android.net.UidRangeParcel")
            rangeConstructor = rangeType.getConstructor(Integer.TYPE, Integer.TYPE)
            val configType = Class.forName("android.net.netd.aidl.NativeUidRangeConfig")
            configConstructor = configType.getConstructor(Integer.TYPE, ReflectArray.newInstance(rangeType, 0).javaClass, Integer.TYPE)
            addRanges = type.getMethod("networkAddUidRangesParcel", configType)
            removeRanges = type.getMethod("networkRemoveUidRangesParcel", configType)
            if (addRanges.returnType != Void.TYPE || removeRanges.returnType != Void.TYPE) {
                throw IOException("Unexpected netd method signature")
            }
            output("INTERFACE netd_version=$version hash=$hash")
        }

        private fun parcel(config: Config): Any {
            val ranges = ReflectArray.newInstance(rangeType, config.ranges.size)
            config.ranges.forEachIndexed { index, range ->
                val ends = range.split('-')
                ReflectArray.set(ranges, index, rangeConstructor.newInstance(ends[0].toInt(), ends[1].toInt()))
            }
            return configConstructor.newInstance(config.netId, ranges, SUB_PRIORITY)
        }

        fun add(config: Config) {
            if (config.ranges.isNotEmpty()) call(addRanges, binderProxy, parcel(config))
        }

        fun remove(config: Config) {
            if (config.ranges.isEmpty()) return
            if (!hasExactUidMapping(config)) {
                if (hasUidRules(config)) {
                    throw IOException("UID kernel rules remain without their netd mapping; journal retained for explicit recovery")
                }
                return
            }
            try {
                call(removeRanges, binderProxy, parcel(config))
            } catch (error: Exception) {
                // A destroyed physical network has already discarded its UID defaults and rules.
                if (!isErrno(error, 64 /* ENONET */)) throw error
            }
        }
    }

    internal class Action(val kind: String, val value: String) {
        fun wire(): String = "$kind\t$value"
    }

    private fun serve() {
        val input = BufferedReader(InputStreamReader(System.`in`, Charsets.UTF_8))
        val initial = boundedLine(input) ?: return
        val fields = initial.split('\t')
        if (fields.size != 2 || fields[0] != "INIT_FILE") {
            throw IOException("Expected private INIT_FILE configuration")
        }
        val config = Config(readInitialFile(fields[1]))
        val table = tableFor(config.iface)
        verifyPhysicalNetwork(config.netId, config.iface)
        verifyFamilies(config, table)
        preflight()
        remember(Action("BOOT", bootId()))
        if (config.ranges.isNotEmpty()) installUid(config)
        output("READY_INITIAL netId=${config.netId} uid_ranges=${config.ranges.size} cidrs=${config.cidrs.size} table=$table")

        var attached = 0
        var attachedIndex = 0
        while (true) {
            val line = boundedLine(input) ?: return
            if (line == "STOP") return
            val attach = Attach(line, config)
            val netId = attach.netId
            val tap = NetworkInterface.getByName(attach.iface)
            verifyTapGeneration(attach, tap?.name, tap?.index ?: -1, attached, attachedIndex)
            verifyPhysicalNetwork(netId, attach.iface)
            if (attached == netId) continue
            attached = netId
            attachedIndex = attach.index

            for (range in config.ranges) {
                for (family in IP_FAMILIES) installRule(family, UID_PRIORITY, netId, table, "uidrange", range)
            }
            for (cidr in config.cidrs) {
                installRule(if (':' in cidr) "-6" else "-4", CIDR_PRIORITY, netId, table, "to", cidr)
            }
            output("READY_ATTACH tap=${attach.iface} ifIndex=${attach.index} netId=$netId " +
                "uid_explicit_rules=${config.ranges.size * 2} cidrs=${config.cidrs.size}")
        }
    }

    private fun readInitialFile(name: String): String {
        validateInitName(name)
        val file = checkedFile(directory, name)
        val contents = ByteArrayOutputStream()
        // Check for symlinks at open time as well as when validating the basename.
        FileChannel.open(file.toPath(), StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { input ->
            if (input.size() !in 1..MAX_CONTROL_BYTES.toLong()) {
                throw IOException("Private configuration exceeds size bound")
            }
            val buffer = ByteBuffer.allocate(4096)
            while (input.read(buffer) >= 0) {
                val count = buffer.position()
                if (contents.size() + count > MAX_CONTROL_BYTES) {
                    throw IOException("Private configuration grew beyond bound")
                }
                contents.write(buffer.array(), 0, count)
                buffer.clear()
            }
        }
        Files.delete(file.toPath())
        val value = contents.toByteArray().toString(Charsets.UTF_8)
        if ('\n' in value || '\r' in value || '\u0000' in value) {
            throw IOException("Invalid private configuration record")
        }
        return value
    }

    @Synchronized
    private fun remember(action: Action) {
        if (closing) throw IOException("Routing guardian is closing")
        journal.seek(journal.length())
        journal.write((checkedRecord(action.wire()) + "\n").toByteArray(Charsets.UTF_8))
        journal.fd.sync()
        actions.add(action)
    }

    @Synchronized
    private fun recover() {
        val size = journal.length()
        if (size > 1024 * 1024) throw IOException("Routing journal exceeds recovery bound")
        journal.seek(0)
        val data = ByteArray(size.toInt())
        journal.readFully(data)
        val text = data.toString(Charsets.UTF_8)
        val end = text.lastIndexOf('\n')
        val recovered = ArrayList<Action>()
        if (end >= 0) {
            for (line in text.substring(0, end).split('\n')) {
                if (line.isEmpty()) continue
                val payload = readRecord(line)
                val separator = payload.indexOf('\t')
                if (separator < 0) throw IOException("Invalid routing journal record")
                val action = Action(payload.substring(0, separator), payload.substring(separator + 1))
                validateAction(action)
                recovered.add(action)
            }
        }
        actions.addAll(recovered)
        journalTrusted = true
        if (recovered.any { it.kind == "BOOT" && it.value != bootId() }) {
            // Kernel routing state and netd UID maps do not survive a device reboot.
            actions.clear()
            output("RECOVER previous_boot_no_kernel_state")
        }
        if (actions.isNotEmpty()) {
            output("RECOVER pending_actions=${actions.size}")
            cleanup()
        }
        // A torn final record never reached fsync, so its mutation was not started.
        journal.setLength(0)
        journal.fd.sync()
        closing = false
    }

    @Synchronized
    private fun installUid(config: Config) {
        remember(Action("NETD", config.wire()))
        netd.add(config)
    }

    @Synchronized
    private fun installRule(family: String, priority: Int, netId: Int, table: Int, selector: String, value: String) {
        val action = Action("RULE", "$family\t$priority\t$netId\t$table\t$selector\t$value")
        validateAction(action)
        remember(action)
        command(*ruleCommand("add", action.value)).requireSuccess()
    }

    @Synchronized
    private fun cleanup() {
        closing = true
        if (!journalTrusted) throw IOException("Routing journal was not validated; retained without recovery mutation")
        var failure: Exception? = null
        for (action in actions.asReversed()) {
            try {
                when (action.kind) {
                    "BOOT" -> continue
                    "NETD" -> netd.remove(Config(action.value))
                    else -> {
                        val result = command(*ruleCommand("del", action.value))
                        if (result.code != 0 && exactRuleExists(action.value)) {
                            throw IOException("Cannot remove owned rule: ${result.text}")
                        }
                    }
                }
            } catch (error: Exception) {
                if (failure == null) failure = error
            }
        }
        if (failure != null) throw IOException("Routing cleanup incomplete; journal retained", failure)
        actions.clear()
        journal.setLength(0)
        journal.fd.sync()
    }

    private class Result(val code: Int, val text: String) {
        fun requireSuccess() {
            if (code != 0) throw IOException("Routing command failed ($code): $text")
        }
    }

    companion object {
        private const val SUB_PRIORITY = 998
        private const val UID_PRIORITY = 14500
        private const val CIDR_PRIORITY = 14510
        private const val HASH_17 = "a786da2fe41bda627a8c1e63b99264a415e769c8"
        private const val IP = "/system/bin/ip"
        private const val MAX_CONTROL_BYTES = 131072
        // Compatibility for persisted V1 recovery records created before named TAP.
        private const val LEGACY_TAP_NAME = "eth9"

        private val IP_FAMILIES = listOf("-4", "-6")
        private val IFACE_NAME = Regex("[A-Za-z0-9_.:-]{1,15}")
        private val TAP_NAME = Regex("(?:eth|usb)[0-9]{1,12}")
        private val TOKEN = Regex("[A-Za-z0-9-]{1,64}")
        private val PACKAGE_NAME = Regex("[A-Za-z0-9_]+(?:\\.[A-Za-z0-9_]+)*")
        private val UID_RANGE = Regex("[0-9]+-[0-9]+")
        private val NUMBER = Regex("[0-9]+")
        private val IP_LITERAL = Regex("[0-9a-fA-F:.]+")
        private val BOOT_ID = Regex("[0-9a-fA-F-]{36}")
        private val INIT_NAME = Regex("init-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\.cfg")
        private val WHITESPACE = Regex("\\s+")
        private val RULE_PRIORITY = Regex("(?m)^\\s*(\\d+):")
        private val DEFAULT_ROUTE = Regex("(?m)^default(?:\\s|$)")
        private val UID_PRIORITY_ENTRY = Regex("(?:^|[;:])\\s*prio $SUB_PRIORITY ([^;]+)")
        private val UID_ENTRY = Regex("[0-9]+(?:-[0-9]+)?")
        private val RULE_TOKENS = setOf("fwmark", "iif", "lookup", "uidrange", "to")

        @JvmStatic
        @Throws(Exception::class)
        fun main(args: Array<String>) {
            if (args.size == 2 && args[0] == "--packages") {
                val userId = number(args[1], 0, 21473)
                Thread({
                    try {
                        while (System.`in`.read() >= 0) { /* Wait for the parent process to close the pipe. */ }
                    } catch (_: IOException) {
                        // An unreadable pipe also means the caller cannot use the snapshot.
                    }
                    exitProcess(0)
                }, "read-only-package-eof").apply { isDaemon = true }.start()
                emitPackages(userId)
                return
            }

            require(args.size == 4 && args[0] == "--directory" && args[2] == "--user") {
                "Expected --directory private_directory --user user_id"
            }
            val userId = number(args[3], 0, 21473)
            val directory = File(args[1])
            if (!directory.isAbsolute || directory.canonicalFile != directory || !directory.isDirectory) {
                throw IOException("Invalid private routing directory")
            }
            val lockFile = checkedFile(directory, "owner.lock")
            val journalFile = checkedFile(directory, "journal.v1")
            RandomAccessFile(lockFile, "rw").use { lock ->
                val ownership = lock.channel.tryLock()
                    ?: throw IOException("Another routing guardian still owns this directory")
                ownership.use {
                    val netd = Netd()
                    RandomAccessFile(journalFile, "rw").use { journal ->
                        val helper = RootRoutingHelper(directory, netd, journal)
                        runGuardian(helper, userId)
                    }
                }
            }
        }

        private fun runGuardian(helper: RootRoutingHelper, userId: Int) {
            val hook = Thread({
                try {
                    helper.cleanup()
                } catch (error: Exception) {
                    System.err.println("CLEANUP_REQUIRED $error")
                }
            }, "root-routing-cleanup")
            Runtime.getRuntime().addShutdownHook(hook)
            var clean = false
            try {
                helper.recover()
                emitPackages(userId)
                output("READY_FOR_CONFIG")
                helper.serve()
            } catch (error: Throwable) {
                System.err.println("ROUTING_ERROR $error")
                throw error
            } finally {
                try {
                    helper.cleanup()
                    clean = true
                    output("CLEAN")
                } finally {
                    if (clean) Runtime.getRuntime().removeShutdownHook(hook)
                }
            }
        }

        private fun emitPackages(userId: Int) {
            if (call(Class.forName("android.os.Process").getMethod("myUid"), null) != 0) {
                throw IOException("Root package snapshot requires UID 0")
            }
            val binderType = Class.forName("android.os.IBinder")
            val binder = call(Class.forName("android.os.ServiceManager").getMethod("getService", String::class.java), null, "package")
            if (binder == null || call(binderType.getMethod("getInterfaceDescriptor"), binder) != "android.content.pm.IPackageManager") {
                throw IOException("Unexpected package manager Binder")
            }
            val type = Class.forName("android.content.pm.IPackageManager")
            val manager = call(Class.forName("android.content.pm.IPackageManager\$Stub").getMethod("asInterface", binderType), null, binder)
            val slice = call(type.getMethod("getInstalledApplications", java.lang.Long.TYPE, Integer.TYPE), manager, 0L, userId)
                ?: throw IOException("Missing package manager snapshot")
            val applications = call(slice.javaClass.getMethod("getList"), slice) as List<*>
            if (applications.size > 12000) throw IOException("Root package snapshot exceeded bound")
            val packages = TreeMap<String, Pair<Int, Int>>()
            for (application in applications) {
                val applicationType = application?.javaClass ?: throw IOException("Missing package metadata")
                val name = applicationType.getField("packageName").get(application) as String?
                val uid = applicationType.getField("uid").getInt(application)
                val flags = applicationType.getField("flags").getInt(application)
                if (name == null || !PACKAGE_NAME.matches(name) || uid < 0 || uid / 100000 != userId) {
                    throw IOException("Invalid/cross-user package metadata")
                }
                if (packages.put(name, uid to if ((flags and 129) == 0) 0 else 1) != null) {
                    throw IOException("Duplicate package metadata")
                }
            }
            output("PACKAGE_MAP_BEGIN\t$userId")
            for ((name, metadata) in packages) output("PACKAGE_MAP\t$name\t${metadata.first}\t${metadata.second}")
            output("PACKAGE_MAP_END\t$userId\t${packages.size}")
        }

        private fun preflight() {
            val netdState = command("/system/bin/dumpsys", "netd", "--short")
            netdState.requireSuccess()
            if ("Per-app UID ranges:" in netdState.text) {
                throw IOException("Another per-app network/VPN policy is active; no UID mappings changed")
            }
            for (family in IP_FAMILIES) {
                val result = command(IP, family, "rule", "show")
                result.requireSuccess()
                for (match in RULE_PRIORITY.findAll(result.text)) {
                    val priority = match.groupValues[1].toInt()
                    if (priority % 1000 == SUB_PRIORITY || priority == UID_PRIORITY || priority == CIDR_PRIORITY) {
                        throw IOException("Routing policy conflict in $family at priority $priority; no existing rules changed")
                    }
                }
            }
        }

        private fun ruleCommand(operation: String, wire: String): Array<String> {
            val fields = wire.split('\t')
            return arrayOf(
                IP, fields[0], "rule", operation, "priority", fields[1], "iif", "lo", "fwmark",
                "0x" + fields[2].toInt().toString(16) + "/0xffff", fields[4], fields[5], "lookup", fields[3],
            )
        }

        private fun exactRuleExists(wire: String): Boolean {
            val fields = wire.split('\t')
            val result = command(IP, fields[0], "rule", "show")
            result.requireSuccess()
            val tables = hashSetOf(fields[3])
            for (line in routeTableLines()) {
                val words = line.trim().split(WHITESPACE)
                if (words.size == 2 && words[0] == fields[3]) tables.add(words[1])
            }
            return result.text.splitToSequence('\n').any { line ->
                ruleLineMatches(line.trim().replace(WHITESPACE, " "), fields, tables)
            }
        }

        internal fun ruleLineMatches(line: String, fields: List<String>, tables: Set<String>): Boolean {
            if (!line.startsWith(fields[1] + ":")) return false
            val words = line.split(WHITESPACE)
            val values = HashMap<String, String>()
            var index = 1
            while (index + 1 < words.size) {
                val word = words[index++]
                if (word in RULE_TOKENS) values[word] = words[index++]
            }
            if (values["iif"] != "lo" || values["lookup"] !in tables) return false
            val mark = values.getOrDefault("fwmark", "").split('/')
            return try {
                if (mark.size != 2 || java.lang.Long.decode(mark[0]) != fields[2].toLong() ||
                    java.lang.Long.decode(mark[1]) != 65535L
                ) return false
                if (fields[4] == "uidrange") return fields[5] == values["uidrange"]
                val actual = values.getOrDefault("to", if (fields[0] == "-6") "::/0" else "0.0.0.0/0")
                samePrefix(actual, fields[5])
            } catch (_: Exception) {
                false
            }
        }

        private fun samePrefix(left: String, right: String): Boolean {
            val a = left.split('/')
            val b = right.split('/')
            val first = InetAddress.getByName(a[0]).address
            val second = InetAddress.getByName(b[0]).address
            val ap = a.getOrNull(1)?.toInt() ?: first.size * 8
            val bp = b.getOrNull(1)?.toInt() ?: second.size * 8
            if (ap != bp || first.size != second.size) return false
            return first.indices.all { index ->
                val bits = (ap - index * 8).coerceIn(0, 8)
                val mask = (0xff shl (8 - bits)) and 255
                (first[index].toInt() and mask) == (second[index].toInt() and mask)
            }
        }

        internal fun validateAction(action: Action) {
            when (action.kind) {
                "BOOT" -> {
                    if (!BOOT_ID.matches(action.value)) throw IOException("Invalid journal boot identity")
                    return
                }
                "NETD" -> {
                    Config(action.value)
                    return
                }
                "RULE" -> Unit
                else -> throw IOException("Unknown journal operation")
            }

            val fields = action.value.split('\t')
            if (fields.size != 6 || fields[0] !in IP_FAMILIES) throw IOException("Invalid rule family")
            val priority = number(fields[1], UID_PRIORITY, CIDR_PRIORITY)
            number(fields[2], 100, 65535)
            number(fields[3], 1000, Int.MAX_VALUE)
            when {
                fields[4] == "uidrange" && priority == UID_PRIORITY -> {
                    if (!UID_RANGE.matches(fields[5])) throw IOException("Invalid rule UID selector")
                    val ends = fields[5].split('-')
                    val first = number(ends[0], 10000, Int.MAX_VALUE)
                    val last = number(ends[1], first, Int.MAX_VALUE)
                    if (first / 100000 != last / 100000 || first % 100000 < 10000 || last % 100000 > 29999) {
                        throw IOException("System UID rule forbidden")
                    }
                }
                fields[4] == "to" && priority == CIDR_PRIORITY -> {
                    numericCidr(fields[5])
                    if ((fields[0] == "-6") != (':' in fields[5])) throw IOException("Rule address family mismatch")
                }
                else -> throw IOException("Invalid rule selector/priority")
            }
        }

        internal fun checkedRecord(payload: String): String {
            val bytes = payload.toByteArray(Charsets.UTF_8)
            val crc = CRC32().apply { update(bytes) }
            return crc.value.toString(16) + " " + Base64.getEncoder().encodeToString(bytes)
        }

        internal fun readRecord(line: String): String {
            val separator = line.indexOf(' ')
            if (separator < 1) throw IOException("Invalid journal checksum")
            try {
                val bytes = Base64.getDecoder().decode(line.substring(separator + 1))
                val crc = CRC32().apply { update(bytes) }
                if (crc.value.toString(16) != line.substring(0, separator)) {
                    throw IOException("Journal checksum mismatch; refusing recovery mutation")
                }
                return bytes.toString(Charsets.UTF_8)
            } catch (error: IllegalArgumentException) {
                throw IOException("Invalid journal encoding", error)
            }
        }

        internal fun numericCidr(text: String) {
            val fields = text.split('/')
            require(fields.size == 2 && IP_LITERAL.matches(fields[0])) { "Numeric CIDR required" }
            val ipv6 = ':' in fields[0]
            if (!ipv6) {
                val bytes = fields[0].split('.')
                require(bytes.size == 4) { "Invalid IPv4" }
                for (byte in bytes) number(byte, 0, 255)
            }
            try {
                val address = InetAddress.getByName(fields[0])
                require((address is Inet6Address) == ipv6) { "Invalid numeric family" }
                number(fields[1], 0, if (ipv6) 128 else 32)
            } catch (error: UnknownHostException) {
                throw IllegalArgumentException("Invalid numeric CIDR", error)
            }
        }

        internal fun validateTapName(name: String?) {
            require(name != null && TAP_NAME.matches(name)) { "Invalid owned TAP interface name" }
        }

        internal fun verifyTapGeneration(
            attach: Attach,
            actualName: String?,
            actualIndex: Int,
            previousNetId: Int,
            previousIndex: Int,
        ) {
            if (attach.iface != actualName || actualIndex != attach.index) {
                throw IOException("Owned TAP interface generation changed")
            }
            if (previousNetId != 0 && (previousNetId != attach.netId || previousIndex != attach.index)) {
                throw IOException("Owned TAP network/interface generation changed; reconnect required")
            }
        }

        internal fun validateInitName(name: String) {
            if (!INIT_NAME.matches(name)) throw IOException("Invalid private configuration basename")
        }

        private fun routeTableLines(): List<String> =
            Files.readAllLines(File("/data/misc/net/rt_tables").toPath(), Charsets.UTF_8)

        private fun tableFor(iface: String): Int {
            for (line in routeTableLines()) {
                val words = line.trim().split(WHITESPACE)
                if (words.size == 2 && words[1] == iface) return number(words[0], 1000, Int.MAX_VALUE)
            }
            throw IOException("Cannot resolve numeric underlay routing table for $iface")
        }

        private fun verifyFamilies(config: Config, table: Int) {
            val ipv4 = config.ranges.isNotEmpty() || config.cidrs.any { ':' !in it }
            val ipv6 = config.ranges.isNotEmpty() || config.cidrs.any { ':' in it }
            for (family in IP_FAMILIES) {
                if ((family == "-4" && !ipv4) || (family == "-6" && !ipv6)) continue
                val result = command(IP, family, "route", "show", "table", table.toString())
                result.requireSuccess()
                if (!DEFAULT_ROUTE.containsMatchIn(result.text)) {
                    throw IOException("Root routing requires a default route in the original interface's $family table; " +
                        "IPv4-only/IPv6-only or CLAT stacked underlays are not supported for this policy yet")
                }
            }
        }

        private fun bootId(): String {
            val value = String(Files.readAllBytes(File("/proc/sys/kernel/random/boot_id").toPath()), Charsets.US_ASCII).trim()
            if (!BOOT_ID.matches(value)) throw IOException("Cannot read device boot identity")
            return value
        }

        /** AOSP's per-network UID map is separate from its access allowlist. */
        private fun hasExactUidMapping(config: Config): Boolean {
            val result = command("/system/bin/dumpsys", "netd", "--short")
            result.requireSuccess()
            val marker = Regex("\\s*${config.netId} PHYSICAL(?:[ \\t].*)?")
            var inNetwork = false
            for (line in result.text.splitToSequence('\n')) {
                if (marker.matches(line)) {
                    inNetwork = true
                    continue
                }
                if (!inNetwork) continue
                if (line.trim().isEmpty()) break
                if ("Per-app UID ranges:" in line) {
                    val priority = UID_PRIORITY_ENTRY.find(line) ?: return false
                    val actual = UID_ENTRY.findAll(priority.groupValues[1])
                        .map { if ('-' in it.value) it.value else "${it.value}-${it.value}" }.toSet()
                    if (actual != config.ranges.toSet()) {
                        throw IOException("Journal UID ranges conflict with the live netd owner")
                    }
                    return true
                }
            }
            return false
        }

        private fun hasUidRules(config: Config): Boolean {
            for (family in IP_FAMILIES) {
                val result = command(IP, family, "rule", "show")
                result.requireSuccess()
                for (range in config.ranges) {
                    val rule = Regex("(?m)^.*\\buidrange ${Regex.escape(range)}(?:\\s|$).*$")
                    if (rule.containsMatchIn(result.text)) return true
                }
            }
            return false
        }

        private fun verifyPhysicalNetwork(netId: Int, iface: String) {
            val result = command("/system/bin/dumpsys", "netd", "--short")
            result.requireSuccess()
            val network = Regex("(?m)^\\s*$netId PHYSICAL ${Regex.escape(iface)}\\s*$")
            if (!network.containsMatchIn(result.text)) {
                throw IOException("Physical network ID no longer matches its configured interface")
            }
        }

        private fun command(vararg arguments: String): Result {
            val process = ProcessBuilder(*arguments).redirectErrorStream(true).start()
            val output = ByteArrayOutputStream()
            val readError = AtomicReference<Throwable>()
            val reader = Thread({
                try {
                    process.inputStream.use { input ->
                        val buffer = ByteArray(4096)
                        while (true) {
                            val size = input.read(buffer)
                            if (size < 0) break
                            if (output.size() + size > 512 * 1024) {
                                throw IOException("Routing command output exceeded bound")
                            }
                            output.write(buffer, 0, size)
                        }
                    }
                } catch (error: Throwable) {
                    readError.set(error)
                }
            }, "root-routing-command").apply { isDaemon = true }
            reader.start()
            val timeout = !process.waitFor(5, TimeUnit.SECONDS)
            if (timeout) {
                process.destroy()
                if (!process.waitFor(500, TimeUnit.MILLISECONDS)) process.destroyForcibly()
                // Never begin rollback while an earlier mutation can still complete late.
                while (!process.waitFor(250, TimeUnit.MILLISECONDS)) {
                    System.err.println("COMMAND_STILL_EXITING cleanup_waits_for_owned_child")
                }
            }
            reader.join(1000)
            if (timeout) throw IOException("Routing command timed out; owned child has exited before rollback")
            val error = readError.get()
            if (reader.isAlive || error != null) throw IOException("Cannot read routing command result", error)
            return Result(process.exitValue(), output.toByteArray().toString(Charsets.UTF_8))
        }

        private fun checkedFile(directory: File, name: String): File {
            val file = File(directory, name)
            if (file.canonicalFile != file || !file.isFile) {
                throw IOException("Private routing files must be pre-created and cannot be symlinks")
            }
            return file
        }

        private fun number(value: String, first: Int, last: Int): Int {
            require(NUMBER.matches(value)) { "Numeric value required" }
            val result = value.toInt()
            require(result in first..last) { "Value outside permitted range" }
            return result
        }

        private fun boundedList(value: String, maximum: Int): List<String> {
            val values = if (value == "-") emptyList() else value.split(',')
            require(values.size <= maximum && "" !in values) { "Routing configuration exceeded bound" }
            return values
        }

        private fun listWire(values: List<String>): String = if (values.isEmpty()) "-" else values.joinToString(",")

        private fun boundedLine(input: BufferedReader): String? {
            val line = StringBuilder()
            while (true) {
                val character = input.read()
                if (character < 0) return line.toString().takeIf { it.isNotEmpty() }
                if (character == '\n'.code) return line.toString()
                if (line.length >= MAX_CONTROL_BYTES || character == '\r'.code || character == 0) {
                    throw IOException("Invalid or oversized routing command")
                }
                line.append(character.toChar())
            }
        }

        private fun call(method: Method, target: Any?, vararg args: Any?): Any? {
            try {
                return method.invoke(target, *args)
            } catch (error: InvocationTargetException) {
                val cause = error.cause
                if (cause is Exception) throw cause
                throw RuntimeException(cause)
            }
        }

        private fun isErrno(error: Exception, errno: Int): Boolean = try {
            Class.forName("android.os.ServiceSpecificException").getField("errorCode").getInt(error) == errno
        } catch (_: Exception) {
            false
        }

        private fun output(value: String) {
            System.out.println(value)
            System.out.flush()
        }
    }
}
