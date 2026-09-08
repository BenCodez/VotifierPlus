package com.bencodez.votifierplus.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.Test;

import com.vexsoftware.votifier.net.ThrottleConfig;
import com.vexsoftware.votifier.net.VoteThrottleService;

/**
 * Unit tests for VoteThrottleService after throttling was moved out of VoteReceiver.
 */
public class VoteReceiverThrottleTest {

	@Test
	public void testLogLimiterSuppressesWithinWindowAndReportsSuppressedCount() throws Exception {
		VoteThrottleService service = new VoteThrottleService(
				new ThrottleConfig(true, Collections.<String>emptySet(), "5s", 3, "10s", 2, "10s", false, 999, "1s",
						"200ms"));

		String first = service.allowLog("k", "hello");
		assertEquals("hello", first);

		assertNull(service.allowLog("k", "hello2"));
		assertNull(service.allowLog("k", "hello3"));

		long deadline = System.currentTimeMillis() + 1500;
		String next = null;

		while (System.currentTimeMillis() < deadline) {
			next = service.allowLog("k", "hello-again");
			if (next != null) {
				break;
			}
			Thread.sleep(10);
		}

		assertNotNull(next, "Expected limiter to allow after window elapsed, but it never did");
		assertTrue(next.startsWith("hello-again"));
		assertTrue(next.contains("suppressed 2"), "Expected suppressed count, got: " + next);
	}

	@Test
	public void testLogLimiterIndependentKeys() {
		VoteThrottleService service = new VoteThrottleService(
				new ThrottleConfig(true, Collections.<String>emptySet(), "5s", 3, "10s", 2, "10s", false, 999, "1s",
						"10s"));

		assertNotNull(service.allowLog("a", "a1"));
		assertNotNull(service.allowLog("b", "b1"));

		assertNull(service.allowLog("a", "a2"));
		assertNull(service.allowLog("b", "b2"));
	}

	private static ThrottleConfig cfg(String window, int failures, String throttleFor, int tunnelFailures,
			String tunnelThrottleFor, boolean perClientEnabled, int perClientFailures, String perClientFor) {
		return new ThrottleConfig(true, Collections.<String>emptySet(), window, failures, throttleFor, tunnelFailures,
				tunnelThrottleFor, perClientEnabled, perClientFailures, perClientFor, "60s");
	}

	@Test
	public void testThrottleHardBlocksAfterThresholdWithinWindow() {
		VoteThrottleService service = new VoteThrottleService(
				cfg("5s", 3, "10s", 2, "10s", false, 999, "1s"));

		String key = "tunnel:1.2.3.4";

		assertFalse(service.isBlocked(key));

		service.fail(key, false, false);
		assertFalse(service.isBlocked(key));

		service.fail(key, false, false);
		assertFalse(service.isBlocked(key));

		service.fail(key, false, false);
		assertTrue(service.isBlocked(key));
		assertTrue(service.retryAfterMs(key) > 0);
	}

	@Test
	public void testThrottleUsesTunnelThresholdsWhenTunnelModeTrue() {
		VoteThrottleService service = new VoteThrottleService(
				cfg("5s", 10, "10s", 2, "10s", false, 999, "1s"));

		String key = "tunnel:playit";

		service.fail(key, true, false);
		assertFalse(service.isBlocked(key));

		service.fail(key, true, false);
		assertTrue(service.isBlocked(key));
	}

	@Test
	public void testPerClientBanOnlyWhenRealIpKnown() {
		VoteThrottleService service = new VoteThrottleService(
				cfg("5s", 999, "10s", 999, "10s", true, 2, "30s"));

		String key = "ip:9.9.9.9";

		service.fail(key, false, false);
		service.fail(key, false, false);
		assertFalse(service.isBlocked(key), "Should not ban when realIpKnown=false");

		service.fail(key, false, true);
		assertTrue(service.isBlocked(key), "Expected ban when realIpKnown=true");
		assertTrue(service.retryAfterMs(key) > 0);
	}

	@Test
	public void testSuccessResetsFailureCounter() {
		VoteThrottleService service = new VoteThrottleService(
				cfg("10s", 3, "10s", 3, "10s", false, 999, "1s"));

		String key = "tunnel:reset";

		service.fail(key, false, false);
		service.fail(key, false, false);

		service.success(key);

		service.fail(key, false, false);
		assertFalse(service.isBlocked(key));

		service.fail(key, false, false);
		assertFalse(service.isBlocked(key));

		service.fail(key, false, false);
		assertTrue(service.isBlocked(key));
	}

	@Test
	public void testSuccessImmediatelyReclaimsPrimaryCapacity() throws Exception {
		VoteThrottleService service = new VoteThrottleService(
				cfg("5s", 3, "10s", 3, "10s", false, 999, "1s"));
		for (int index = 0; index < 4096; index++) service.fail("ip:active:" + index, false, true);

		service.fail("ip:overflow", false, true);
		assertTrue(longField(service, "nextThrottleSweepMs") > System.currentTimeMillis());
		service.success("ip:active:0");

		assertEquals(4095, mapSize(service, "throttleStates"));
		assertEquals(0L, longField(service, "nextThrottleSweepMs"));
		service.fail("ip:replacement", false, true);
		assertTrue(stateMap(service, "throttleStates").containsKey("ip:replacement"),
				"a successful identity must release its primary slot immediately");
	}

	@Test
	public void testSuccessResetsOverflowAggregateForDirectPeer() {
		VoteThrottleService service = new VoteThrottleService(
				cfg("5s", 2, "10s", 2, "10s", false, 999, "1s"));
		for (int i = 0; i < 4096; i++) {
			service.fail("ip:" + i, false, false);
		}
		String key = "tunnel:direct";
		service.fail(key, key, false, false);
		service.success(key, key);
		service.fail(key, key, false, false);
		assertFalse(service.isBlocked(key, key));
	}

	@Test
	public void testWindowExpiryResetsFailureCounter() throws Exception {
		VoteThrottleService service = new VoteThrottleService(
				cfg("150ms", 2, "1s", 2, "1s", false, 999, "1s"));

		String key = "tunnel:window";

		service.fail(key, false, false);
		assertFalse(service.isBlocked(key));

		Thread.sleep(200);

		service.fail(key, false, false);
		assertFalse(service.isBlocked(key));

		service.fail(key, false, false);
		assertTrue(service.isBlocked(key));
	}

	@Test
	public void testTunnelModeDetection() {
		ThrottleConfig config = new ThrottleConfig(true, Collections.singleton("10.0.0.1"), "5s", 3, "10s", 2,
				"20s", false, 999, "1s", "60s");
		VoteThrottleService service = new VoteThrottleService(config);

		assertTrue(service.isTunnelMode("10.0.0.1"));
		assertFalse(service.isTunnelMode("10.0.0.2"));
	}

	@Test
	public void testAttackerControlledKeysAreBounded() throws Exception {
		VoteThrottleService service = new VoteThrottleService(
				cfg("5s", 3, "10s", 2, "10s", false, 999, "1s"));
		for (int i = 0; i < 5000; i++) {
			service.fail("ip:" + i, false, true);
			service.allowLog("log:" + i, "message");
		}
		assertTrue(mapSize(service, "throttleStates") <= 4096);
		assertTrue(mapSize(service, "logStates") <= 4096);
	}

	@Test
	public void testConcurrentNewLogKeysStayWithinBound() throws Exception {
		VoteThrottleService service = new VoteThrottleService(
				cfg("5s", 3, "10s", 2, "10s", false, 999, "1s"));
		int workers = 16;
		int keysPerWorker = 512;
		ExecutorService executor = Executors.newFixedThreadPool(workers);
		CountDownLatch ready = new CountDownLatch(workers);
		CountDownLatch start = new CountDownLatch(1);
		CountDownLatch finished = new CountDownLatch(workers);
		try {
			for (int worker = 0; worker < workers; worker++) {
				final int workerId = worker;
				executor.execute(() -> {
					ready.countDown();
					try {
						start.await();
						for (int key = 0; key < keysPerWorker; key++) {
							service.allowLog("concurrent-log:" + workerId + ':' + key, "message");
						}
					} catch (InterruptedException ex) {
						Thread.currentThread().interrupt();
					} finally {
						finished.countDown();
					}
				});
			}
			assertTrue(ready.await(5, TimeUnit.SECONDS));
			start.countDown();
			assertTrue(finished.await(10, TimeUnit.SECONDS));
		} finally {
			executor.shutdownNow();
		}
		assertEquals(4096, mapSize(service, "logStates"));
	}

	@Test
	public void testConcurrentFailuresUpdateStateAtomically() throws Exception {
		VoteThrottleService service = new VoteThrottleService(
				cfg("60s", 100000, "10s", 100000, "10s", false, 999, "1s"));
		int workers = 16;
		int failuresPerWorker = 256;
		ExecutorService executor = Executors.newFixedThreadPool(workers);
		CountDownLatch ready = new CountDownLatch(workers);
		CountDownLatch start = new CountDownLatch(1);
		CountDownLatch finished = new CountDownLatch(workers);
		try {
			for (int worker = 0; worker < workers; worker++) {
				executor.execute(() -> {
					ready.countDown();
					try {
						start.await();
						for (int failure = 0; failure < failuresPerWorker; failure++) {
							service.fail("concurrent-failure", false, false);
						}
					} catch (InterruptedException ex) {
						Thread.currentThread().interrupt();
					} finally {
						finished.countDown();
					}
				});
			}
			assertTrue(ready.await(5, TimeUnit.SECONDS));
			start.countDown();
			assertTrue(finished.await(10, TimeUnit.SECONDS));
		} finally {
			executor.shutdownNow();
		}
		Field statesField = VoteThrottleService.class.getDeclaredField("throttleStates");
		statesField.setAccessible(true);
		Map<?, ?> states = (Map<?, ?>) statesField.get(service);
		Object state = states.get("concurrent-failure");
		Field failuresField = state.getClass().getDeclaredField("failures");
		failuresField.setAccessible(true);
		assertEquals(workers * failuresPerWorker, failuresField.getInt(state));
	}

	@Test
	public void testExistingKeyDoesNotEvictAnotherStateAtCapacity() throws Exception {
		VoteThrottleService service = new VoteThrottleService(
				cfg("5s", 2, "10s", 2, "10s", false, 999, "1s"));
		for (int i = 0; i < 4096; i++) {
			service.fail("ip:" + i, false, false);
		}
		Map<?, ?> states = stateMap(service, "throttleStates");
		Object existing = states.get("ip:100");
		service.fail("ip:100", false, false);
		assertTrue(existing == states.get("ip:100"));
		assertEquals(4096, states.size());
	}

	@Test
	public void testExistingLogKeyDoesNotEvictAnotherStateAtCapacity() throws Exception {
		VoteThrottleService service = new VoteThrottleService(
				cfg("5s", 2, "10s", 2, "10s", false, 999, "1s"));
		for (int i = 0; i < 4096; i++) {
			service.allowLog("log:" + i, "message");
		}
		Map<?, ?> states = stateMap(service, "logStates");
		Object existing = states.get("log:100");
		assertNull(service.allowLog("log:100", "message-again"));
		assertTrue(existing == states.get("log:100"));
		assertEquals(4096, states.size());
	}

	@Test
	public void testSaturatedLogStateCachesExpiryAndEvictsWithoutRescanning() throws Exception {
		VoteThrottleService service = new VoteThrottleService(
				cfg("5s", 2, "10s", 2, "10s", false, 999, "1s"));
		for (int i = 0; i < 4096; i++) {
			service.allowLog("log:saturated:" + i, "message");
		}

		service.allowLog("log:saturated:first-miss", "message");
		long nextSweep = longField(service, "nextLogSweepMs");
		assertTrue(nextSweep > System.currentTimeMillis());
		service.allowLog("log:saturated:second-miss", "message");

		assertEquals(nextSweep, longField(service, "nextLogSweepMs"),
				"saturated log misses before expiry must reuse the cached sweep deadline");
		assertEquals(4096, mapSize(service, "logStates"));
	}

	@Test
	public void testOverflowDoesNotEvictActiveBan() throws Exception {
		VoteThrottleService service = new VoteThrottleService(
				cfg("5s", 1, "10s", 1, "10s", true, 1, "60s"));
		for (int i = 0; i < 4096; i++) {
			service.fail("ip:" + i, false, true);
		}
		assertTrue(service.isBlocked("ip:100"));
		service.fail("overflow", false, true);
		assertTrue(service.isBlocked("ip:100"));
		assertEquals(4096, mapSize(service, "throttleStates"));
	}

	@Test
	public void testFullThrottleMapAccountsNewIdentityAgainstAggregateTunnel() throws Exception {
		VoteThrottleService service = new VoteThrottleService(tunnelCfg("proxy"));
		for (int i = 0; i < 4096; i++) {
			service.fail("ip:" + i, false, true);
		}

		String aggregateKey = "tunnel:proxy";
		String newIdentity = "ip:new";
		service.fail(newIdentity, aggregateKey, false, true);

		assertTrue(service.isBlocked(newIdentity, aggregateKey));
		assertTrue(service.retryAfterMs(newIdentity, aggregateKey) > 0);
		assertEquals(4096, mapSize(service, "throttleStates"));
	}

	@Test
	public void testAggregateFallbackRemainsBoundAfterPrimaryCapacityRecovers() throws Exception {
		VoteThrottleService service = new VoteThrottleService(
				cfg("5s", 3, "10s", 3, "10s", false, 999, "1s"));
		String aggregateKey = "tunnel:proxy";
		for (int i = 0; i < 4096; i++) {
			service.fail("ip:" + i, false, false);
		}

		service.fail("ip:reused", aggregateKey, false, false);
		service.fail("ip:reused", aggregateKey, false, false);
		stateMap(service, "throttleStates").remove("ip:0");

		service.fail("ip:reused", aggregateKey, false, false);

		assertTrue(service.isBlocked("ip:reused", aggregateKey),
				"an identity that used aggregate fallback must not split its failure counter after capacity recovers");
		assertFalse(stateMap(service, "throttleStates").containsKey("ip:reused"));
	}

	@Test
	public void testAggregateBlockUsesAggregateLogKey() {
		VoteThrottleService service = new VoteThrottleService(
				cfg("5s", 1, "10s", 1, "10s", false, 999, "1s"));
		for (int i = 0; i < 4096; i++) {
			service.fail("ip:" + i, false, false);
		}
		String aggregateKey = "tunnel:proxy";
		service.fail("ip:rotated", aggregateKey, false, false);
		assertEquals(aggregateKey, service.blockedKey("ip:another", aggregateKey));
	}

	@Test
	public void testAggregateBlockAppliesToExistingPrimaryIdentity() {
		VoteThrottleService service = new VoteThrottleService(
				cfg("5s", 2, "10s", 2, "10s", false, 999, "1s"));
		String primaryKey = "ip:existing";
		String aggregateKey = "tunnel:proxy";
		service.fail(primaryKey, false, false);
		for (int i = 0; i < 4095; i++) {
			service.fail("ip:filler:" + i, false, false);
		}
		service.fail("ip:proxied", aggregateKey, false, false);
		service.fail("ip:proxied", aggregateKey, false, false);

		assertTrue(service.isBlocked(primaryKey, aggregateKey));
		assertEquals(aggregateKey, service.blockedKey(primaryKey, aggregateKey));
		assertTrue(service.retryAfterMs(primaryKey, aggregateKey) > 0);
	}

	@Test
	public void testProxiedSuccessDoesNotClearSharedAggregateFailures() {
		VoteThrottleService service = new VoteThrottleService(
				cfg("5s", 2, "10s", 2, "10s", false, 999, "1s"));
		String aggregateKey = "tunnel:proxy";
		for (int i = 0; i < 4096; i++) {
			service.fail("ip:filler:" + i, false, false);
		}
		service.fail("ip:proxied", aggregateKey, false, false);
		service.success("ip:proxied", aggregateKey);
		service.fail("ip:rotated", aggregateKey, false, false);

		assertTrue(service.isBlocked("ip:another", aggregateKey),
				"a proxied success must not erase another identity's aggregate failure");
	}

	@Test
	public void testFullMapPreservesInWindowCountersAndUsesAggregateTunnel() throws Exception {
		ThrottleConfig config = new ThrottleConfig(true, Collections.singleton("proxy"), "5s", 2, "10s", 2,
				"10s", false, 999, "1s", "60s");
		VoteThrottleService service = new VoteThrottleService(config);
		for (int i = 0; i < 4096; i++) {
			service.fail("ip:" + i, false, true);
		}

		service.fail("ip:new", "tunnel:proxy", false, true);
		assertFalse(service.isBlocked("ip:new", "tunnel:proxy"));
		service.fail("ip:new", "tunnel:proxy", false, true);

		assertTrue(service.isBlocked("ip:new", "tunnel:proxy"));
		assertEquals(4096, mapSize(service, "throttleStates"));
	}

	@Test
	public void testFullThrottleMapAccountsNewIdentityAgainstNonTunnelAggregate() throws Exception {
		VoteThrottleService service = new VoteThrottleService(
				cfg("5s", 1, "10s", 1, "10s", false, 999, "1s"));
		for (int i = 0; i < 4096; i++) {
			service.fail("ip:" + i, false, true);
		}

		String aggregateKey = "tunnel:proxy";
		String newIdentity = "ip:new";
		service.fail(newIdentity, aggregateKey, false, true);

		assertTrue(service.isBlocked(newIdentity, aggregateKey));
		assertTrue(service.retryAfterMs(newIdentity, aggregateKey) > 0);
		assertEquals(4096, mapSize(service, "throttleStates"));
		assertEquals(1, mapSize(service, "aggregateStates"));
	}

	@Test
	public void testOverflowThrottleDoesNotBecomeGlobalAcrossTunnels() {
		VoteThrottleService service = new VoteThrottleService(tunnelCfg("proxy-a", "proxy-b"));
		for (int i = 0; i < 4096; i++) {
			service.fail("ip:" + i, false, true);
		}

		service.fail("ip:new-a", "tunnel:proxy-a", false, true);

		assertTrue(service.isBlocked("ip:new-a", "tunnel:proxy-a"));
		assertFalse(service.isBlocked("ip:new-b", "tunnel:proxy-b"));
	}

	@Test
	public void testOverflowFallbackIgnoresPrimaryTunnelState() {
		VoteThrottleService service = new VoteThrottleService(tunnelCfg("proxy"));
		service.fail("tunnel:proxy", true, false);
		for (int i = 0; i < 4095; i++) {
			service.fail("ip:" + i, false, true);
		}

		assertFalse(service.isBlocked("ip:new", "tunnel:proxy"));
		assertEquals(0L, service.retryAfterMs("ip:new", "tunnel:proxy"));
		service.fail("ip:new", "tunnel:proxy", false, true);
		assertTrue(service.isBlocked("ip:new", "tunnel:proxy"));
	}

	@Test
	public void testAggregateCapacityUsesBoundedOverflowBuckets() throws Exception {
		VoteThrottleService service = new VoteThrottleService(
				cfg("5s", 2, "10s", 2, "10s", false, 999, "1s"));
		for (int i = 0; i < 4096; i++) {
			service.fail("ip:" + i, false, false);
		}
		for (int i = 0; i < 4096; i++) {
			service.fail("ip:overflow:" + i, "remote:" + i, false, false);
		}
		String aggregateKey = "remote:overflow";
		service.fail("ip:new", aggregateKey, false, false);
		service.fail("ip:new", aggregateKey, false, false);
		assertTrue(service.isBlocked("ip:new", aggregateKey));
		assertEquals(4096, mapSize(service, "aggregateStates"));
	}

	@Test
	public void testOverflowBucketIsIgnoredAfterAggregateCapacityRecovers() throws Exception {
		VoteThrottleService service = new VoteThrottleService(
				cfg("5s", 2, "10s", 2, "10s", false, 999, "1s"));
		for (int i = 0; i < 4096; i++) service.fail("ip:" + i, false, false);
		for (int i = 0; i < 4096; i++) service.fail("ip:overflow:" + i, "remote:" + i, false, false);
		assertEquals("Aa".hashCode(), "BB".hashCode());
		service.fail("ip:overflow-a", "Aa", false, false);
		service.fail("ip:overflow-a", "Aa", false, false);
		assertTrue(service.isBlocked("ip:overflow-b", "BB"));
		assertEquals("aggregate-overflow:" + Math.floorMod("BB".hashCode(), 64),
				service.blockedKey("ip:overflow-b", "BB"),
				"all remotes rejected by one overflow bucket must share its log key");
		assertEquals("aggregate-overflow:" + Math.floorMod("BB".hashCode(), 64),
				service.aggregateBlockedKey("BB"),
				"pre-handshake aggregate rejection must use the same bounded log key");

		Map<?, ?> aggregates = stateMap(service, "aggregateStates");
		aggregates.remove(aggregates.keySet().iterator().next());
		assertFalse(service.isBlocked("ip:overflow-b", "BB"),
				"stale overflow state must not shadow a newly available aggregate slot");
	}

	@Test
	public void testDirectSuccessDoesNotResetSharedAggregateOverflowBucket() throws Exception {
		VoteThrottleService service = new VoteThrottleService(
				cfg("5s", 2, "10s", 2, "10s", false, 999, "1s"));
		for (int i = 0; i < 4096; i++) service.fail("ip:" + i, false, false);
		for (int i = 0; i < 4096; i++) service.fail("ip:overflow:" + i, "remote:" + i, false, false);
		assertEquals("Aa".hashCode(), "BB".hashCode());
		service.fail("ip:overflow-a", "Aa", false, false);
		service.success("Aa", "Aa");
		service.fail("ip:overflow-b", "BB", false, false);

		assertTrue(service.isBlocked("ip:overflow-c", "BB"),
				"a direct success must not erase failures belonging to a shared overflow bucket");
	}

	@Test
	public void testBlockedCheckRechecksPrimaryAfterWaitingForFailureUpdate() throws Exception {
		VoteThrottleService service = new VoteThrottleService(
				cfg("5s", 2, "10s", 2, "10s", false, 999, "1s"));
		String key = "ip:concurrent";
		service.fail(key, false, true);
		AtomicBoolean blocked = new AtomicBoolean();
		Thread check = new Thread(() -> blocked.set(service.isBlocked(key, "tunnel:other")));
		Field lockField = VoteThrottleService.class.getDeclaredField("throttleStateLock");
		lockField.setAccessible(true);
		Object lock = lockField.get(service);

		synchronized (lock) {
			check.start();
			long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
			while (check.getState() != Thread.State.BLOCKED && System.nanoTime() < deadline) Thread.onSpinWait();
			assertEquals(Thread.State.BLOCKED, check.getState());
			service.fail(key, false, true);
		}
		check.join(TimeUnit.SECONDS.toMillis(2));

		assertTrue(blocked.get(), "the primary throttle applied while waiting must not be bypassed");
	}

	@Test
	public void testSaturatedPrimaryStateCachesItsNextPossibleSweep() throws Exception {
		VoteThrottleService service = new VoteThrottleService(
				cfg("5s", 2, "10s", 2, "10s", false, 999, "1s"));
		for (int index = 0; index < 4096; index++) service.fail("ip:active:" + index, false, true);

		service.fail("ip:overflow:first", false, true);
		long nextSweep = longField(service, "nextThrottleSweepMs");
		assertTrue(nextSweep > System.currentTimeMillis());
		service.fail("ip:overflow:second", false, true);
		assertEquals(nextSweep, longField(service, "nextThrottleSweepMs"),
				"a miss before the earliest expiry must reuse the saturated-state decision");
	}

	@Test
	public void testAggregateLookupReclaimsExpiredEntryBeforeUsingOverflowBucket() throws Exception {
		VoteThrottleService service = new VoteThrottleService(
				cfg("5s", 2, "10s", 2, "10s", false, 999, "1s"));
		for (int i = 0; i < 4096; i++) {
			service.fail("ip:primary:" + i, false, false);
		}
		for (int i = 0; i < 4096; i++) {
			service.fail("ip:aggregate:" + i, "remote:" + i, false, false);
		}

		Map<?, ?> aggregates = stateMap(service, "aggregateStates");
		Object expired = aggregates.get("remote:0");
		assertNotNull(expired);
		Field windowStartField = expired.getClass().getDeclaredField("windowStartMs");
		windowStartField.setAccessible(true);
		windowStartField.setLong(expired, System.currentTimeMillis() - 6000L);
		Field nextSweepField = VoteThrottleService.class.getDeclaredField("nextAggregateSweepMs");
		nextSweepField.setAccessible(true);
		nextSweepField.setLong(service, 0L);

		assertFalse(service.isAggregateBlocked("remote:not-yet-tracked"));
		assertEquals(4095, aggregates.size(),
				"an expired aggregate must be reclaimed before an overflow bucket is consulted");
	}

	private static ThrottleConfig tunnelCfg(String... remoteIps) {
		return new ThrottleConfig(true, new java.util.HashSet<String>(java.util.Arrays.asList(remoteIps)), "5s", 1,
				"10s", 1, "10s", true, 1, "60s", "60s");
	}

	private static int mapSize(VoteThrottleService service, String fieldName) throws Exception {
		return stateMap(service, fieldName).size();
	}

	private static Map<?, ?> stateMap(VoteThrottleService service, String fieldName) throws Exception {
		Field field = VoteThrottleService.class.getDeclaredField(fieldName);
		field.setAccessible(true);
		return (Map<?, ?>) field.get(service);
	}

	private static long longField(VoteThrottleService service, String fieldName) throws Exception {
		Field field = VoteThrottleService.class.getDeclaredField(fieldName);
		field.setAccessible(true);
		return field.getLong(service);
	}
}
