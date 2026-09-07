package com.bencodez.votifierplus.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Collections;
	import java.lang.reflect.Field;
	import java.util.Map;

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

	private static int mapSize(VoteThrottleService service, String fieldName) throws Exception {
		return stateMap(service, fieldName).size();
	}

	private static Map<?, ?> stateMap(VoteThrottleService service, String fieldName) throws Exception {
		Field field = VoteThrottleService.class.getDeclaredField(fieldName);
		field.setAccessible(true);
		return (Map<?, ?>) field.get(service);
	}
}
