package kittoku.mvc.routing.root

import kittoku.mvc.R
import kittoku.mvc.i18n.appText
import kittoku.mvc.routing.AppRoutingConfiguration
import kittoku.mvc.routing.AppRoutingMode

internal data class RootUidRange(val first: Int, val last: Int) {
    init { require(first >= 0 && last >= first) }
    override fun toString(): String = "$first-$last"
}

internal data class RootUidPlan(
    val bypassRanges: List<RootUidRange>,
    val missingPackages: Set<String>,
    val sharedUidPackages: Set<String>,
    val selectedAppUids: Set<Int>,
)

/** Policy applies to ordinary current-user application sockets, not Ethernet link control. */
internal object RootUidPlanner {
    const val MAX_RANGES = 1024
    val criticalPackages = setOf("android", "com.android.networkstack", "com.google.android.networkstack",
        "com.android.networkstack.tethering", "com.google.android.networkstack.tethering",
        "com.android.captiveportallogin", "com.google.android.captiveportallogin")

    fun plan(configuration: AppRoutingConfiguration, installed: Map<String, Int>, ownUid: Int): RootUidPlan {
        require(ownUid >= 10000) { appText(R.string.route_error_root_app_uid) }
        if (configuration.mode == AppRoutingMode.ALL) return RootUidPlan(emptyList(), emptySet(), emptySet(), emptySet())
        val userBase = ownUid / 100000 * 100000
        fun application(uid: Int) = uid in userBase + 10000..userBase + 19999
        require(configuration.packages.all { Regex("[A-Za-z0-9_]+(?:\\.[A-Za-z0-9_]+)*").matches(it) }) { appText(R.string.route_error_app_package_invalid) }
        val missing = configuration.packages - installed.keys
        val criticalUids = installed.filterKeys { it in criticalPackages }.values.toSet()
        val chosen = configuration.packages.mapNotNull(installed::get).toSet() - ownUid
        require(chosen.none { it in criticalUids || !application(it) }) {
            appText(R.string.route_error_root_uid_restricted)
        }
        if (configuration.mode == AppRoutingMode.INCLUDE) require(chosen.isNotEmpty()) {
            appText(R.string.route_error_root_app_allowlist_empty)
        }
        val shared = installed.filterValues { it in chosen }.keys - configuration.packages
        fun sandbox(uid: Int) = uid + 10000
        val protected = criticalUids.filter(::application).flatMap { listOf(it, sandbox(it)) }.toSet()
        val selected = chosen.flatMap { listOf(it, sandbox(it)) }.toSet()
        val bypass = when (configuration.mode) {
            AppRoutingMode.INCLUDE -> complement(userBase + 10000, userBase + 29999, selected + protected)
            AppRoutingMode.EXCLUDE -> compact((selected + ownUid + sandbox(ownUid)) - protected)
            AppRoutingMode.ALL -> emptyList()
        }
        require(bypass.size <= MAX_RANGES) { appText(R.string.route_error_root_uid_ranges) }
        return RootUidPlan(bypass, missing, shared, chosen)
    }

    private fun complement(start: Int, stop: Int, excluded: Set<Int>): List<RootUidRange> {
        val result = mutableListOf<RootUidRange>()
        var next = start
        excluded.filter { it in start..stop }.sorted().forEach {
            if (next < it) result += RootUidRange(next, it - 1)
            next = it + 1
        }
        if (next <= stop) result += RootUidRange(next, stop)
        return result
    }

    private fun compact(values: Set<Int>): List<RootUidRange> {
        val result = mutableListOf<RootUidRange>()
        values.sorted().forEach { uid ->
            val last = result.lastOrNull()
            if (last != null && uid == last.last + 1) result[result.lastIndex] = RootUidRange(last.first, uid)
            else result += RootUidRange(uid, uid)
        }
        return result
    }
}
