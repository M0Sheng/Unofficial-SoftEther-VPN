package kittoku.mvc.routing

import kittoku.mvc.routing.root.main as runUidPlannerScenarios
import org.junit.Test

/** Run the standalone guardian safety and UID-planning scenarios in the release regression suite. */
class RootRoutingScenariosTest {
    @Test fun validatesGuardianConfigurationAndRecoveryRecords() {
        RootRoutingHelperTest.main(emptyArray())
    }

    @Test fun plansSharedUidsSandboxUidsAndCurrentUserBoundaries() {
        runUidPlannerScenarios()
    }
}
