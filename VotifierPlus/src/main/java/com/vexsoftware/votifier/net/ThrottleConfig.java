package com.vexsoftware.votifier.net;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import com.bencodez.simpleapi.time.ParsedDuration;

public class ThrottleConfig {

	public final boolean enabled;
	public final Set<String> tunnelRemoteIps;
	public final long windowMs;
	public final int failures;
	public final long throttleForMs;
	public final int tunnelFailures;
	public final long tunnelThrottleForMs;
	public final boolean perClientBanEnabled;
	public final int perClientBanFailures;
	public final long perClientBanForMs;
	public final long logWindowMs;

	public ThrottleConfig(boolean enabled, Set<String> tunnelRemoteIps, String window, int failures,
			String throttleFor, int tunnelFailures, String tunnelThrottleFor, boolean perClientBanEnabled,
			int perClientBanFailures, String perClientBanFor, String logWindow) {
		this.enabled = enabled;

		if (tunnelRemoteIps == null || tunnelRemoteIps.isEmpty()) {
			this.tunnelRemoteIps = Collections.emptySet();
		} else {
			this.tunnelRemoteIps = Collections.unmodifiableSet(new HashSet<String>(tunnelRemoteIps));
		}

		this.windowMs = safeDurationMs(window, 2 * 60_000L);
		this.failures = failures;
		this.throttleForMs = safeDurationMs(throttleFor, 5 * 60_000L);
		this.tunnelFailures = tunnelFailures;
		this.tunnelThrottleForMs = safeDurationMs(tunnelThrottleFor, 10 * 60_000L);
		this.perClientBanEnabled = perClientBanEnabled;
		this.perClientBanFailures = perClientBanFailures;
		this.perClientBanForMs = safeDurationMs(perClientBanFor, 15 * 60_000L);
		this.logWindowMs = safeDurationMs(logWindow, 60_000L);
	}

	private static long safeDurationMs(String raw, long fallback) {
		try {
			if (raw == null || raw.isEmpty()) {
				return fallback;
			}

			ParsedDuration duration = ParsedDuration.parse(raw, TimeUnit.MINUTES);
			long ms = duration.getMillis();
			return ms > 0 ? ms : fallback;
		} catch (Exception ignored) {
			return fallback;
		}
	}
}