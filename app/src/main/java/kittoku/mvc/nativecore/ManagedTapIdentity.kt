package kittoku.mvc.nativecore

import android.content.Context
import android.provider.Settings
import java.net.NetworkInterface

/** An interface created by this daemon with an exclusive TAP descriptor. */
internal data class ManagedTapIdentity(val name: String, val index: Int) {
    fun isCurrent() = NetworkInterface.getByName(name)?.index == index

    fun remember(context: Context): Boolean = preferences(context).edit()
        .putString("name", name)
        .putInt("index", index)
        .putInt("boot", bootCount(context))
        .commit()

    companion object {
        const val CREATION_PREFIX = "HOMEVPN_TAP_CREATED "

        fun parseCreation(line: String, token: String, expectedName: String): ManagedTapIdentity? {
            if (!line.startsWith(CREATION_PREFIX)) return null
            val fields = line.removePrefix(CREATION_PREFIX).split(' ', limit = 4)
            if (fields.size != 3 || fields[0] != token || fields[1] != expectedName) return null
            val index = fields[2]
            if (index.isEmpty() || index.any { it !in '0'..'9' }) return null
            return parseIdentity(fields[1], index.toIntOrNull())
        }

        fun previous(context: Context): ManagedTapIdentity? {
            val settings = preferences(context)
            val savedBoot = settings.getInt("boot", -1)
            val currentBoot = bootCount(context)
            if (savedBoot >= 0 && currentBoot >= 0 && savedBoot != currentBoot) return null
            return parseIdentity(settings.getString("name", null), settings.getInt("index", 0))
        }

        private fun parseIdentity(name: String?, index: Int?): ManagedTapIdentity? =
            if (name != null && index != null && index > 0 && ManagedTapName.isValid(name)) ManagedTapIdentity(name, index)
            else null

        private fun preferences(context: Context) = context.getSharedPreferences("native_tap_identity", Context.MODE_PRIVATE)
        private fun bootCount(context: Context) = runCatching {
            Settings.Global.getInt(context.contentResolver, "boot_count", -1)
        }.getOrDefault(-1)
    }
}
