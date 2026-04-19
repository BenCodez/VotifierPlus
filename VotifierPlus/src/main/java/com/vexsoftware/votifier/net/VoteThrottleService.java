package com.vexsoftware.votifier.net;

import java.net.SocketException;
import java.util.concurrent.ConcurrentHashMap;

public class VoteThrottleService {

	private static final class LogState {
		private volatile long lastLogMs;
		private volatile int suppressed;
	}

	private static final class ThrottleState {
		private volatile long windowStartMs;
		private volatile int failures;
		private volatile long throttledUntilMs;
		private volatile long bannedUntilMs;
	}

	private final ThrottleConfig config;
	private final ConcurrentHashMap<String, LogState> logStates = new ConcurrentHashMap<String, LogState>();
	private final ConcurrentHashMap<String, ThrottleState> throttleStates = new ConcurrentHashMap<String, ThrottleState>();

	public VoteThrottleService(ThrottleConfig config) {
		this.config = config;
	}

	public ThrottleConfig getConfig() {
		return config;
	}

	public boolean isTunnelMode(String remoteIp) {
		return config != null && config.enabled && config.tunnelRemoteIps.contains(remoteIp);
	}

	public boolean isBlocked(String key) {
		if (config == null || !config.enabled) {
			return false;
		}

		ThrottleState state = throttleStates.get(key);
		if (state == null) {
			return false;
		}

		long now = System.currentTimeMillis();
		return state.bannedUntilMs > now || state.throttledUntilMs > now;
	}

	public long retryAfterMs(String key) {
		ThrottleState state = throttleStates.get(key);
		if (state == null) {
			return 0L;
		}

		long now = System.currentTimeMillis();
		return Math.max(state.bannedUntilMs, state.throttledUntilMs) - now;
	}

	public void fail(String key, boolean tunnelMode, boolean realIpKnown) {
		if (config == null || !config.enabled) {
			return;
		}

		long now = System.currentTimeMillis();
		ThrottleState state = getThrottleState(key);

		if (now - state.windowStartMs > config.windowMs) {
			state.windowStartMs = now;
			state.failures = 0;
		}

		state.failures++;

		if (config.perClientBanEnabled && realIpKnown && state.failures >= config.perClientBanFailures) {
			state.bannedUntilMs = now + config.perClientBanForMs;
			return;
		}

		int threshold = tunnelMode ? config.tunnelFailures : config.failures;
		long duration = tunnelMode ? config.tunnelThrottleForMs : config.throttleForMs;

		if (state.failures >= threshold) {
			state.throttledUntilMs = now + duration;
		}
	}

	public void success(String key) {
		ThrottleState state = throttleStates.get(key);
		if (state != null) {
			state.failures = 0;
			state.windowStartMs = System.currentTimeMillis();
		}
	}

	public String allowLog(String key, String msg) {
		long now = System.currentTimeMillis();
		long windowMs = config != null ? Math.max(250L, config.logWindowMs) : 60_000L;

		LogState state = logStates.get(key);
		if (state == null) {
			LogState created = new LogState();
			LogState existing = logStates.putIfAbsent(key, created);
			state = existing == null ? created : existing;
		}

		if (now - state.lastLogMs >= windowMs) {
			int suppressed = state.suppressed;
			state.suppressed = 0;
			state.lastLogMs = now;

			if (suppressed > 0) {
				return msg + " (suppressed " + suppressed + " similar in last " + windowMs + "ms)";
			}
			return msg;
		}

		state.suppressed++;
		return null;
	}

	public void logWarning(VoteReceiver receiver, String key, String message) {
		String allowed = allowLog(key, message);
		if (allowed != null) {
			receiver.logWarning(allowed);
		}
	}

	public void logSocketError(String remoteIp, SocketException ex) {
	}

	public void logGenericError(String remoteIp, Exception ex) {
	}

	private ThrottleState getThrottleState(String key) {
		ThrottleState state = throttleStates.get(key);
		if (state == null) {
			ThrottleState created = new ThrottleState();
			created.windowStartMs = System.currentTimeMillis();
			ThrottleState existing = throttleStates.putIfAbsent(key, created);
			state = existing == null ? created : existing;
		}
		return state;
	}
}