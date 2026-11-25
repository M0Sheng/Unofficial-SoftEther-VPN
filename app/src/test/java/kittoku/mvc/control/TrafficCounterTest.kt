package kittoku.mvc.control

import org.junit.Assert.*
import org.junit.Test

class TrafficCounterTest {
    @Test fun ratesUseElapsedTimeAndIdleBecomesZero() {
        val counter = TrafficCounter()
        counter.reset(1000); counter.useSession("a")
        counter.received("a", 2048); counter.sent("a", 512)
        val first = counter.sample(2000)
        assertEquals(2048L, first.received); assertEquals(512L, first.sent)
        assertEquals(2048.0, first.receiveRate, 0.0); assertEquals(512.0, first.sendRate, 0.0)
        assertEquals(0.0, counter.sample(3000).receiveRate, 0.0)
        assertTrue(first.notificationText().contains("2.0 KiB/s"))
    }
    @Test fun oldSessionCannotCountAfterReconnectAndTotalsContinue() {
        val counter = TrafficCounter(); counter.reset(0); counter.useSession("first")
        counter.received("first", 12); counter.useSession("second")
        counter.received("first", 9000); counter.received("second", 8)
        assertEquals(20L, counter.sample(1000).received)
        counter.useSession(""); counter.sent("", 10); counter.sent("second", 100)
        assertEquals(0L, counter.sample(2000).sent)
    }
    @Test fun resetInvalidatesOwnersAndNegativeBytesCannotDecreaseTotals() {
        val counter = TrafficCounter(); counter.reset(0); counter.useSession("a")
        counter.sent("a", 99); counter.sent("a", -55)
        assertEquals(99L, counter.sample(1000).sent)
        counter.reset(2000); counter.sent("a", 123)
        assertEquals(TrafficSnapshot(0, 0, 0.0, 0.0), counter.sample(2500))
    }
    @Test fun repeatedSnapshotsDoNotResetTheRateWindow() {
        val counter = TrafficCounter(); counter.reset(0); counter.useSession("a")
        counter.received("a", 1000)
        assertEquals(1000.0, counter.sample(1000).receiveRate, 0.0)
        assertEquals(1000.0, counter.sample(1100).receiveRate, 0.0)
        assertEquals(0.0, counter.sample(1600).receiveRate, 0.0)
        assertEquals(0.0, counter.sample(100).receiveRate, 0.0)
    }
    @Test fun countersSaturateInsteadOfOverflowing() {
        val counter = TrafficCounter(); counter.reset(0); counter.useSession("a")
        counter.received("a", Long.MAX_VALUE); counter.received("a", 1)
        assertEquals(Long.MAX_VALUE, counter.sample(1000).received)
    }
    @Test fun nativeStatisticsRemainUnavailableUntilCurrentOwnerReports() {
        val counter = TrafficCounter(); counter.reset(0); counter.useSession("native", available = false)
        assertFalse(counter.sample(1000).available)
        counter.markAvailable("old")
        assertFalse(counter.sample(2000).available)
        counter.markAvailable("native")
        assertTrue(counter.sample(3000).available)
    }
}
