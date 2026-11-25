package kittoku.mvc.routing.root

import kittoku.mvc.routing.AppRoutingConfiguration
import kittoku.mvc.routing.AppRoutingMode

private var count = 0
private fun checkCase(block: () -> Unit) { block(); count++ }
private fun fails(block: () -> Unit) { try { block() } catch (_: IllegalArgumentException) { count++; return }; error("Expected failure") }
private fun List<RootUidRange>.has(uid: Int) = any { uid in it.first..it.last }

fun main() {
    val installed = mapOf("app.first" to 10100, "app.shared" to 10100, "app.second" to 10101,
        "io.github.m0sheng.unofficialsoftethervpn" to 10425, "android" to 1000, "com.android.networkstack" to 1073)
    fun plan(mode: AppRoutingMode, vararg packages: String) = RootUidPlanner.plan(AppRoutingConfiguration(mode, packages.toSet()), installed, 10425)
    checkCase { check(plan(AppRoutingMode.ALL).bypassRanges.isEmpty()) }
    checkCase { val p = plan(AppRoutingMode.EXCLUDE, "app.first"); check(p.bypassRanges.has(10100) && p.bypassRanges.has(20100)); check(!p.bypassRanges.has(10101)) }
    checkCase { check(plan(AppRoutingMode.EXCLUDE, "app.first").sharedUidPackages == setOf("app.shared")) }
    checkCase { val p = plan(AppRoutingMode.INCLUDE, "app.first"); check(!p.bypassRanges.has(10100) && !p.bypassRanges.has(20100)); check(p.bypassRanges.has(10101) && p.bypassRanges.has(20101)) }
    checkCase { val p = plan(AppRoutingMode.INCLUDE, "app.first"); check(!p.bypassRanges.has(1000)); check(!p.bypassRanges.has(99000)) }
    checkCase { val p = plan(AppRoutingMode.INCLUDE, "app.first"); check(p.bypassRanges.has(10425) && p.bypassRanges.has(20425)) }
    checkCase { val p = plan(AppRoutingMode.INCLUDE, "app.first"); check(p.bypassRanges.has(19999) && p.bypassRanges.has(29999)) }
    checkCase { val p = plan(AppRoutingMode.EXCLUDE, "app.missing"); check(p.missingPackages == setOf("app.missing")); check(p.bypassRanges.has(10425)) }
    fails { plan(AppRoutingMode.INCLUDE) }
    fails { plan(AppRoutingMode.INCLUDE, "app.missing") }
    fails { plan(AppRoutingMode.INCLUDE, "io.github.m0sheng.unofficialsoftethervpn") }
    fails { plan(AppRoutingMode.EXCLUDE, "android") }
    fails { plan(AppRoutingMode.EXCLUDE, "com.android.networkstack") }
    checkCase {
        val p = RootUidPlanner.plan(AppRoutingConfiguration(AppRoutingMode.EXCLUDE, setOf("app.first")), mapOf("app.first" to 1010100), 1010425)
        check(p.bypassRanges.has(1010100) && p.bypassRanges.has(1020100)); check(!p.bypassRanges.has(10100))
    }
    checkCase {
        val p = RootUidPlanner.plan(AppRoutingConfiguration(AppRoutingMode.INCLUDE, setOf("app.first")), installed + ("com.google.android.networkstack" to 10108), 10425)
        check(!p.bypassRanges.has(10108) && !p.bypassRanges.has(20108))
    }
    fails {
        RootUidPlanner.plan(AppRoutingConfiguration(AppRoutingMode.EXCLUDE, setOf("app.shared")), installed + ("com.google.android.networkstack" to 10100), 10425)
    }
    checkCase { check(RootRoutingWire.initial(10425, 294, "rmnet_data4", "token", listOf(RootUidRange(10100, 10100)), listOf("192.168.0.0/16")).startsWith("V1\t10425\t294")) }
    fails { RootRoutingWire.initial(10425, 294, "eth9", "token", emptyList(), emptyList()) }
    fails { RootRoutingWire.initial(10425, 294, "rmnet_data4", "token", emptyList(), listOf("evil;id/32")) }
    checkCase {
        val named = RootRoutingWire.initial(10425, 294, "rmnet_data4", "token", emptyList(), emptyList(), "usb3")
        check(named.split('\t').size == 8 && named.endsWith("\tusb3"))
    }
    checkCase { check(RootRoutingWire.initial(10425, 294, "rmnet_data4", "token", emptyList(), emptyList()).split('\t').size == 7) }
    checkCase { check(RootRoutingWire.initial(10425, 294, "eth9", "token", emptyList(), emptyList(), "eth10").endsWith("eth10")) }
    fails { RootRoutingWire.initial(10425, 294, "usb3", "token", emptyList(), emptyList(), "usb3") }
    checkCase { check(RootRoutingWire.attach(298, 67, "usb3") == "ATTACH\t298\t67\tusb3") }
    checkCase { RootRoutingWire.validateTapName("eth123456789012") }
    checkCase { RootRoutingWire.validateTapName("usb0") }
    fails { RootRoutingWire.attach(298, 0, "eth3") }
    fails { RootRoutingWire.attach(99, 67, "eth3") }
    for (name in listOf("eth", "usb", "wlan0", "tap0", "eth1;id", "usb1\nSTOP", "eth1234567890123", "eth１", "../eth1")) {
        fails { RootRoutingWire.validateTapName(name) }
    }
    checkCase {
        val parser = RootPackageSnapshotParser(0)
        check(!parser.consume("READY_FOR_CONFIG"))
        parser.consume("PACKAGE_MAP_BEGIN\t0")
        parser.consume("PACKAGE_MAP\tcom.microsoft.emmx\t10316\t0")
        parser.consume("PACKAGE_MAP\tandroid\t1000\t1")
        parser.consume("PACKAGE_MAP_END\t0\t2")
        check(parser.snapshot() == listOf(RootPackageEntry("com.microsoft.emmx", 10316, false), RootPackageEntry("android", 1000, true)))
    }
    fails { RootPackageSnapshotParser(0).consume("PACKAGE_MAP_BEGIN\t10") }
    fails { RootPackageSnapshotParser(0).consume("PACKAGE_MAP\tapp.first\t10100\t0") }
    fails {
        val parser = RootPackageSnapshotParser(0); parser.consume("PACKAGE_MAP_BEGIN\t0")
        parser.consume("PACKAGE_MAP\tapp.first\t10100\t0"); parser.consume("PACKAGE_MAP\tapp.first\t10100\t0")
    }
    fails {
        val parser = RootPackageSnapshotParser(0); parser.consume("PACKAGE_MAP_BEGIN\t0")
        parser.consume("PACKAGE_MAP\tapp.first\t1010100\t0")
    }
    fails {
        val parser = RootPackageSnapshotParser(0); parser.consume("PACKAGE_MAP_BEGIN\t0")
        parser.consume("PACKAGE_MAP_END\t0\t1")
    }
    fails {
        val parser = RootPackageSnapshotParser(0); parser.consume("PACKAGE_MAP_BEGIN\t0")
        parser.consume("PACKAGE_MAP\tapp.first\t10100\t2")
    }
    println("$count UID/shared/sandbox/wire scenarios passed")
}
