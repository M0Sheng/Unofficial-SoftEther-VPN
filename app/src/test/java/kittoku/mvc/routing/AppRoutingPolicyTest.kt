package kittoku.mvc.routing

import org.junit.Assert.*
import org.junit.Test

class AppRoutingPolicyTest {
    private val ownPackage = "io.github.m0sheng.unofficialsoftethervpn"
    private val ownUid = 10425
    private val installed = mapOf(ownPackage to ownUid, "owner.shared" to ownUid,
        "app.alpha" to 10101, "app.beta" to 10102, "app.beta.shared" to 10102)

    private fun plan(mode: AppRoutingMode, packages: Set<String>) = AppRoutingPolicy.plan(
        AppRoutingConfiguration(mode, packages), installed, ownPackage, ownUid)

    @Test fun allAppsUsesOnlySelfUidExclusionAndIgnoresSavedSelection() {
        val result = plan(AppRoutingMode.ALL, setOf("app.alpha"))
        assertTrue(result.allowedPackages.isEmpty())
        assertEquals(listOf(ownPackage), result.disallowedPackages)
    }

    @Test fun includeAppliesActualAllowedPackagesAndNoDisallowedList() {
        val result = plan(AppRoutingMode.INCLUDE, setOf("app.alpha"))
        assertEquals(listOf("app.alpha"), result.allowedPackages)
        assertTrue(result.disallowedPackages.isEmpty())
    }

    @Test fun emptyIncludeCannotBecomeTheDefaultAllApplicationVpn() {
        assertRejected { plan(AppRoutingMode.INCLUDE, emptySet()) }
    }

    @Test fun includeWhoseApplicationsWereAllUninstalledIsRejected() {
        assertRejected { plan(AppRoutingMode.INCLUDE, setOf("removed.app")) }
    }

    @Test fun includeContainingOnlyOwnUidIsRejectedEvenThroughSharedUidAlias() {
        assertRejected { plan(AppRoutingMode.INCLUDE, setOf(ownPackage)) }
        assertRejected { plan(AppRoutingMode.INCLUDE, setOf("owner.shared")) }
    }

    @Test fun includeKeepsInstalledApplicationsAndReportsRemovedOnes() {
        val result = plan(AppRoutingMode.INCLUDE, setOf("app.alpha", "removed.app"))
        assertEquals(listOf("app.alpha"), result.allowedPackages)
        assertEquals(setOf("removed.app"), result.missingPackages)
    }

    @Test fun sharedUidApplicationsAreExplicitlyExpanded() {
        val result = plan(AppRoutingMode.INCLUDE, setOf("app.beta"))
        assertEquals(listOf("app.beta", "app.beta.shared"), result.allowedPackages)
        assertEquals(setOf("app.beta.shared"), result.sharedUidPackages)
    }

    @Test fun excludeAppliesActualDisallowedPackagesIncludingSelf() {
        val result = plan(AppRoutingMode.EXCLUDE, setOf("app.alpha"))
        assertTrue(result.allowedPackages.isEmpty())
        assertEquals(listOf("app.alpha", ownPackage).sorted(), result.disallowedPackages)
    }

    @Test fun emptyExcludeStillExcludesVpnOwnerAndDoesNotCreateAnAllowedList() {
        val result = plan(AppRoutingMode.EXCLUDE, emptySet())
        assertEquals(listOf(ownPackage), result.disallowedPackages)
        assertTrue(result.allowedPackages.isEmpty())
    }

    @Test fun excludeExpandsSharedUidsAndIgnoresRemovedPackages() {
        val result = plan(AppRoutingMode.EXCLUDE, setOf("app.beta", "removed.app"))
        assertEquals(listOf("app.beta", "app.beta.shared", ownPackage).sorted(), result.disallowedPackages)
        assertEquals(setOf("removed.app"), result.missingPackages)
    }

    @Test fun eachBackendCanDispatchAllModesToItsOwnPolicyImplementation() {
        for (backend in listOf("TUN", "ROOT_NATIVE")) {
            AppRoutingMode.entries.forEach { AppRoutingPolicy.requireSupportedBackend(it, backend) }
        }
    }

    @Test fun invalidSavedModesBackendsAndPackageNamesFailClosed() {
        assertRejected { AppRoutingPolicy.parseMode("INVALID") }
        assertRejected { AppRoutingPolicy.requireSupportedBackend(AppRoutingMode.ALL, "ROOT_TAP") }
        assertRejected { AppRoutingPolicy.requireSupportedBackend(AppRoutingMode.ALL, "INVALID") }
        assertRejected { plan(AppRoutingMode.INCLUDE, setOf("app.alpha; command")) }
    }

    private fun assertRejected(operation: () -> Unit) {
        try { operation(); fail("Expected invalid application policy to be rejected") }
        catch (_: IllegalArgumentException) { }
    }
}
