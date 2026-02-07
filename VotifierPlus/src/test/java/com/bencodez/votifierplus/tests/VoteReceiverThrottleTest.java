package com.bencodez.votifierplus.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Collections;

import org.junit.jupiter.api.Test;

import com.vexsoftware.votifier.net.VoteReceiver;

/**
 * Unit tests for VoteReceiver throttling components:
 * - LogLimiter: rate-limited logging with suppressed counts
 * - ThrottleManager: failures-in-window -> hard throttle + optional per-client ban
 *
 * NOTE:
 * These tests require VoteReceiver.LogLimiter and VoteReceiver.ThrottleManager to be
 * package-visible (not private) or moved to their own package-visible classes.
 */
public class VoteReceiverThrottleTest {

  // ---------------------------------------------------------------------------
  // LogLimiter tests
  // ---------------------------------------------------------------------------

	@Test
	public void testLogLimiterSuppressesWithinWindowAndReportsSuppressedCount() throws Exception {
	  VoteReceiver.LogLimiter limiter = new VoteReceiver.LogLimiter(200); // 200ms window

	  String first = limiter.allow("k", "hello");
	  assertEquals("hello", first);

	  // Immediately repeated -> suppressed
	  assertNull(limiter.allow("k", "hello2"));
	  assertNull(limiter.allow("k", "hello3"));

	  // Poll until window has elapsed (avoid flaky sleep timing)
	  long deadline = System.currentTimeMillis() + 1500; // 1.5s should be plenty
	  String next = null;

	  while (System.currentTimeMillis() < deadline) {
	    next = limiter.allow("k", "hello-again");
	    if (next != null) break;
	    Thread.sleep(10);
	  }

	  assertNotNull(next, "Expected limiter to allow after window elapsed, but it never did");
	  assertTrue(next.startsWith("hello-again"));
	  assertTrue(next.contains("suppressed 2"), "Expected suppressed count, got: " + next);
	}


  @Test
  public void testLogLimiterIndependentKeys() {
    VoteReceiver.LogLimiter limiter = new VoteReceiver.LogLimiter(10_000);

    assertNotNull(limiter.allow("a", "a1"));
    assertNotNull(limiter.allow("b", "b1"));

    // Each key suppresses independently
    assertNull(limiter.allow("a", "a2"));
    assertNull(limiter.allow("b", "b2"));
  }

  // ---------------------------------------------------------------------------
  // ThrottleManager tests
  // ---------------------------------------------------------------------------

  private static VoteReceiver.ThrottleConfig cfg(
      String window,
      int failures,
      String throttleFor,
      int tunnelFailures,
      String tunnelThrottleFor,
      boolean perClientEnabled,
      int perClientFailures,
      String perClientFor) {

    return new VoteReceiver.ThrottleConfig(
        true,
        Collections.<String>emptySet(), // tunnelRemoteIps not needed here
        window, failures, throttleFor,
        tunnelFailures, tunnelThrottleFor,
        perClientEnabled, perClientFailures, perClientFor,
        "60s" // logWindow not used in manager tests
    );
  }

  @Test
  public void testThrottleHardBlocksAfterThresholdWithinWindow() {
    VoteReceiver.ThrottleManager tm = new VoteReceiver.ThrottleManager(
        cfg("5s", 3, "10s", 2, "10s", false, 999, "1s")
    );

    String key = "tunnel:1.2.3.4";

    assertFalse(tm.isBlocked(key));

    tm.fail(key, false, false);
    assertFalse(tm.isBlocked(key));

    tm.fail(key, false, false);
    assertFalse(tm.isBlocked(key));

    // 3rd failure triggers hard throttle (failures=3)
    tm.fail(key, false, false);
    assertTrue(tm.isBlocked(key));
    assertTrue(tm.retryAfterMs(key) > 0);
  }

  @Test
  public void testThrottleUsesTunnelThresholdsWhenTunnelModeTrue() {
    // normal failures=10, tunnelFailures=2 -> tunnel should block quickly
    VoteReceiver.ThrottleManager tm = new VoteReceiver.ThrottleManager(
        cfg("5s", 10, "10s", 2, "10s", false, 999, "1s")
    );

    String key = "tunnel:playit";

    tm.fail(key, true, false);
    assertFalse(tm.isBlocked(key));

    // 2nd failure triggers tunnel throttle
    tm.fail(key, true, false);
    assertTrue(tm.isBlocked(key));
  }

  @Test
  public void testPerClientBanOnlyWhenRealIpKnown() {
    // per-client ban: 2 failures -> ban
    VoteReceiver.ThrottleManager tm = new VoteReceiver.ThrottleManager(
        cfg("5s", 999, "10s", 999, "10s", true, 2, "30s")
    );

    String key = "ip:9.9.9.9";

    // same failure count, but realIpKnown=false should NOT ban
    tm.fail(key, false, false);
    tm.fail(key, false, false);
    assertFalse(tm.isBlocked(key), "Should not ban when realIpKnown=false");

    // now realIpKnown=true should ban on threshold
    tm.fail(key, false, true); // 3rd failure
    assertTrue(tm.isBlocked(key), "Expected ban when realIpKnown=true");
    assertTrue(tm.retryAfterMs(key) > 0);
  }

  @Test
  public void testSuccessResetsFailureCounter() {
    VoteReceiver.ThrottleManager tm = new VoteReceiver.ThrottleManager(
        cfg("10s", 3, "10s", 3, "10s", false, 999, "1s")
    );

    String key = "tunnel:reset";

    tm.fail(key, false, false);
    tm.fail(key, false, false);

    // Reset due to successful vote
    tm.success(key);

    // Two more failures should NOT immediately trigger throttle (needs 3 again)
    tm.fail(key, false, false);
    assertFalse(tm.isBlocked(key));

    tm.fail(key, false, false);
    assertFalse(tm.isBlocked(key));

    tm.fail(key, false, false);
    assertTrue(tm.isBlocked(key));
  }

  @Test
  public void testWindowExpiryResetsFailureCounter() throws Exception {
    // very short window to make test fast
    VoteReceiver.ThrottleManager tm = new VoteReceiver.ThrottleManager(
        cfg("150ms", 2, "1s", 2, "1s", false, 999, "1s")
    );

    String key = "tunnel:window";

    tm.fail(key, false, false);
    assertFalse(tm.isBlocked(key));

    // wait for window to expire so failures reset
    Thread.sleep(200);

    // Failure count should have reset; one failure won't throttle
    tm.fail(key, false, false);
    assertFalse(tm.isBlocked(key));

    // second within new window should throttle
    tm.fail(key, false, false);
    assertTrue(tm.isBlocked(key));
  }
}
