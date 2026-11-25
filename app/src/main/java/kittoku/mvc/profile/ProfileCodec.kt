package kittoku.mvc.profile

import kittoku.mvc.R
import kittoku.mvc.i18n.appText
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.util.Base64

internal data class StoredProfile(val id: String, val name: String, val values: Map<String, Any>) {
    // Never accidentally log the credential-bearing map via a generated data-class string.
    override fun toString() = "StoredProfile(id=$id, fields=${values.size})"
}

/** A bounded, typed format independent of Android's JSON stubs in JVM tests. */
internal object ProfileCodec {
    private const val LIMIT = 2 * 1024 * 1024
    fun validValue(key: String, value: Any): Boolean = when (key) {
        in ProfileStore.STRING_KEYS -> value is String
        in ProfileStore.BOOLEAN_KEYS -> value is Boolean
        in ProfileStore.SET_KEYS -> value is Set<*> && value.all { it is String }
        else -> false
    }

    fun encode(profiles: List<StoredProfile>): String {
        require(profiles.size <= 100 && profiles.map { it.id }.distinct().size == profiles.size) { appText(R.string.profile_runtime_profile_count) }
        val bytes = ByteArrayOutputStream()
        DataOutputStream(bytes).use { output ->
            output.writeInt(1)
            output.writeInt(profiles.size)
            profiles.forEach { profile ->
                writeText(output, profile.id); writeText(output, profile.name)
                output.writeInt(profile.values.size)
                profile.values.toSortedMap().forEach { (key, value) ->
                    require(validValue(key, value))
                    writeText(output, key)
                    when (value) {
                        is String -> { output.writeByte(1); writeText(output, value) }
                        is Boolean -> { output.writeByte(2); output.writeBoolean(value) }
                        is Set<*> -> {
                            require(value.size <= 1000) { appText(R.string.profile_runtime_cipher_list_too_large) }
                            output.writeByte(3); output.writeInt(value.size)
                            value.map { it as String }.sorted().forEach { writeText(output, it) }
                        }
                    }
                }
            }
        }
        require(bytes.size() <= LIMIT) { appText(R.string.profile_runtime_profile_data_too_large) }
        return Base64.getEncoder().encodeToString(bytes.toByteArray())
    }

    private fun writeText(output: DataOutputStream, value: String) {
        // Some JDK implementations include the string's head/tail in writeUTF's
        // overflow exception. Reject before that API can expose credential bytes.
        val size = value.sumOf { if (it.code in 1..127) 1L else if (it.code <= 0x7ff) 2L else 3L }
        require(size <= 65535L) { appText(R.string.profile_runtime_profile_field_too_long) }
        output.writeUTF(value)
    }

    fun decode(encoded: String): List<StoredProfile> {
        require(encoded.length <= LIMIT * 4 / 3 + 4)
        val bytes = Base64.getDecoder().decode(encoded)
        require(bytes.size <= LIMIT)
        DataInputStream(ByteArrayInputStream(bytes)).use { input ->
            require(input.readInt() == 1)
            val count = input.readInt().also { require(it in 0..100) }
            val profiles = List(count) {
                val id = input.readUTF().also { require(it.matches(Regex("[A-Za-z0-9_-]{1,80}"))) }
                val name = input.readUTF().also { require(it.isNotBlank() && it.length <= 64 && it.none(Char::isISOControl)) }
                val fields = input.readInt().also { require(it in 0..ProfileStore.PROFILE_KEYS.size) }
                val values = linkedMapOf<String, Any>()
                repeat(fields) {
                    val key = input.readUTF()
                    val value: Any = when (input.readByte().toInt()) {
                        1 -> input.readUTF()
                        2 -> input.readBoolean()
                        3 -> {
                            val size = input.readInt().also { require(it in 0..1000) }
                            List(size) { input.readUTF() }.toSet()
                        }
                        else -> error(appText(R.string.profile_runtime_invalid_value_type))
                    }
                    require(key !in values && validValue(key, value))
                    values[key] = value
                }
                StoredProfile(id, name, values)
            }
            require(input.read() == -1 && profiles.map { it.id }.distinct().size == count)
            return profiles
        }
    }
}
