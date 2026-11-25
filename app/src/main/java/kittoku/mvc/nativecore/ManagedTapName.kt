package kittoku.mvc.nativecore

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.content.res.Resources
import kittoku.mvc.R
import kittoku.mvc.i18n.appText

/** Chooses a new name only; existence/matching never proves ownership of an existing TAP. */
internal object ManagedTapName {
    private const val RESOURCES_ACTION =
        "com.android.server.connectivity.intent.action.SERVICE_CONNECTIVITY_RESOURCES_APK"
    private const val RESOURCE_APEX = "/apex/com.android.tethering/"
    private val safeName = Regex("(?:eth|usb)[0-9]{1,12}")

    fun isValid(name: String): Boolean = safeName.matches(name)

    fun select(context: Context, occupied: Set<String>): String {
        val policy = readPolicy(context)
        return selectFromPolicy(occupied, policy.regex, policy.configuredInterfaces)
    }

    /** Null means the effective resource could not be read, not an empty OEM policy. */
    internal fun selectFromPolicy(occupied: Set<String>, effectiveRegex: String?,
                                  configuredInterfaces: List<String> = emptyList()): String {
        val reserved = configuredInterfaces.map { it.substringBefore(';').trim() }.toSet()
        val unavailable = occupied + reserved
        if (effectiveRegex == null) {
            // Also works with the older OEM eth\\d default. Never assume an unread
            // policy permits multi-digit or USB names.
            return (0..9).asSequence().map { "eth$it" }.firstOrNull { it !in unavailable }
                ?: throw IllegalStateException(appText(R.string.network_runtime_error_tap_naming_conservative_exhausted))
        }
        check(effectiveRegex.length <= 4096) { appText(R.string.network_runtime_error_tap_naming_rule_length) }
        val regex = try {
            // AOSP Android V+ expands this sentinel before matching interface names.
            Regex(if (effectiveRegex == "*") "(?:eth|usb)[0-9]+" else effectiveRegex)
        } catch (error: IllegalArgumentException) {
            throw IllegalStateException(appText(R.string.network_runtime_error_tap_naming_rule_invalid), error)
        }
        return candidates(effectiveRegex).firstOrNull {
            isValid(it) && it !in unavailable && regex.matches(it)
        } ?: throw IllegalStateException(appText(R.string.network_runtime_error_tap_naming_no_available_interface))
    }

    private fun candidates(rule: String): Sequence<String> = sequence {
        // Ordinary platform/OEM patterns are covered without parsing the regex.
        for (prefix in listOf("eth", "usb")) {
            for (number in 0..9999) yield("$prefix$number")
        }
        // Preserve exact large/zero-padded numeric alternatives in OEM rules and
        // offer bounded long-name candidates. This is not arbitrary regex inversion.
        val extras = linkedSetOf<String>()
        Regex("[0-9]{1,12}").findAll(rule).forEach { extras.add(it.value) }
        for (width in 2..12) {
            for (number in 0..99) extras.add(number.toString().padStart(width, '0'))
            for (digit in '1'..'9') extras.add(digit.toString().repeat(width))
        }
        for (prefix in listOf("eth", "usb")) for (number in extras) yield(prefix + number)
    }

    private data class Policy(val regex: String?, val configuredInterfaces: List<String>)

    @Suppress("DEPRECATION")
    private fun readPolicy(context: Context): Policy {
        val manager = context.packageManager
        val resolved = try {
            manager.queryIntentActivities(Intent(RESOURCES_ACTION), PackageManager.MATCH_SYSTEM_ONLY)
        } catch (_: RuntimeException) {
            return Policy(null, emptyList())
        }
        // Mirror ConnectivityResources' module-path check. Marker actions and package
        // names by themselves are forgeable; do not load another app's resources.
        val packages = resolved.mapNotNull { it.activityInfo?.applicationInfo }
            .filter { isTrustedPackage(it.flags, it.sourceDir) }.distinctBy { it.packageName }
        check(packages.size <= 1) { appText(R.string.network_runtime_error_tap_naming_package_ambiguous) }
        val info = packages.singleOrNull() ?: return Policy(null, emptyList())
        val resources = try {
            manager.getResourcesForApplication(info)
        } catch (_: PackageManager.NameNotFoundException) {
            return Policy(null, emptyList())
        } catch (_: RuntimeException) {
            return Policy(null, emptyList())
        }
        val namespaces = listOf(info.packageName, "com.android.connectivity.resources",
            "com.google.android.connectivity.resources").distinct()
        val regex = readResource(resources, namespaces, "config_ethernet_iface_regex", "string") {
            resources.getString(it)
        }
        val configured = readResource(resources, namespaces, "config_ethernet_interfaces", "array") {
            resources.getStringArray(it).toList()
        }.orEmpty()
        return Policy(regex, configured)
    }

    private fun <T> readResource(resources: Resources, namespaces: List<String>, name: String,
                                 type: String, read: (Int) -> T): T? {
        val values = namespaces.mapNotNull { namespace ->
            try {
                @Suppress("DiscouragedApi")
                val id = resources.getIdentifier(name, type, namespace)
                if (id == 0) null else read(id)
            } catch (_: Resources.NotFoundException) {
                null
            } catch (_: SecurityException) {
                null
            }
        }.distinct()
        check(values.size <= 1) { appText(R.string.network_runtime_error_tap_naming_rules_conflict) }
        return values.singleOrNull()
    }

    internal fun isTrustedPackage(flags: Int, sourceDir: String?): Boolean =
        flags and ApplicationInfo.FLAG_SYSTEM != 0 && sourceDir != null &&
            sourceDir.startsWith(RESOURCE_APEX) && sourceDir.endsWith(".apk") &&
            sourceDir.removePrefix(RESOURCE_APEX).split('/').none { it.isEmpty() || it == "." || it == ".." }
}
