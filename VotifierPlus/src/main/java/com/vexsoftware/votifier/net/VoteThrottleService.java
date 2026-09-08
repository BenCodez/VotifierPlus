/*
 * Derived from original Votifier VoteReceiver (GPLv3).
 * Refactored into a dedicated component by BenCodez.
 *
 * See VoteReceiver for full modification summary.
 */
package com.vexsoftware.votifier.net;

import java.net.SocketException;
import java.util.concurrent.ConcurrentHashMap;

public class VoteThrottleService {
	private static final int MAX_TRACKED_KEYS = 4096;

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
	private final ConcurrentHashMap<String, ThrottleState> aggregateStates =
			new ConcurrentHashMap<String, ThrottleState>();
	private final Object logStateLock = new Object();
	private final Object throttleStateLock = new Object();
	/* Configured tunnel remotes are finite, trusted aggregate identities. */

	public VoteThrottleService(ThrottleConfig config) {
		this.config = config;
		if (config != null) {
			for (String remoteIp : config.tunnelRemoteIps) {
				aggregateStates.put("tunnel:" + remoteIp, new ThrottleState());
			}
		}
	}

	public ThrottleConfig getConfig() {
		return config;
	}

	public boolean isTunnelMode(String remoteIp) {
		return config != null && config.enabled && config.tunnelRemoteIps.contains(remoteIp);
	}

	public boolean isBlocked(String key) {
		return isBlocked(key, null);
	}

	public boolean isBlocked(String key, String aggregateKey) {
		if (config == null || !config.enabled) {
			return false;
		}

		ThrottleState state = throttleStates.get(key);
		if (isBlocked(state)) {
			return true;
		}
		synchronized (throttleStateLock) {
			if (aggregateKey != null && throttleStates.get(key) == null)
				return isBlocked(aggregateStates.get(aggregateKey));
		}
		return false;
	}

	private boolean isBlocked(ThrottleState state) {
		if (state == null) {
			return false;
		}
		long now = System.currentTimeMillis();
		return state.bannedUntilMs > now || state.throttledUntilMs > now;
	}

	public long retryAfterMs(String key) {
		return retryAfterMs(key, null);
	}

	public long retryAfterMs(String key, String aggregateKey) {
		ThrottleState state = throttleStates.get(key);
		long retry = retryAfterMs(state);
		synchronized (throttleStateLock) {
			if (aggregateKey != null && throttleStates.get(key) == null)
				retry = Math.max(retry, retryAfterMs(aggregateStates.get(aggregateKey)));
		}
		return retry;
	}

	private long retryAfterMs(ThrottleState state) {
		if (state == null) {
			return 0L;
		}
		long now = System.currentTimeMillis();
		return Math.max(state.bannedUntilMs, state.throttledUntilMs) - now;
	}

	public void fail(String key, boolean tunnelMode, boolean realIpKnown) {
		fail(key, null, tunnelMode, realIpKnown);
	}

	public void fail(String key, String aggregateKey, boolean tunnelMode, boolean realIpKnown) {
		if (config == null || !config.enabled) {
			return;
		}

		synchronized (throttleStateLock) {
			long now = System.currentTimeMillis();
			ThrottleState state = getThrottleState(key);
			boolean aggregate = false;
			if (state == null && aggregateKey != null) {
				state = aggregateStates.get(aggregateKey);
				aggregate = state != null;
			}
			if (state == null) {
				return;
			}

			if (now - state.windowStartMs > config.windowMs) {
				state.windowStartMs = now;
				state.failures = 0;
			}

			state.failures++;

			if (!aggregate && config.perClientBanEnabled && realIpKnown
					&& state.failures >= config.perClientBanFailures) {
				state.bannedUntilMs = now + config.perClientBanForMs;
				return;
			}

			int threshold = tunnelMode ? config.tunnelFailures : config.failures;
			long duration = tunnelMode ? config.tunnelThrottleForMs : config.throttleForMs;

			if (state.failures >= threshold) {
				state.throttledUntilMs = now + duration;
			}
		}
	}

	public void success(String key) {
		synchronized (throttleStateLock) {
			ThrottleState state = throttleStates.get(key);
			if (state != null) {
				state.failures = 0;
				state.windowStartMs = System.currentTimeMillis();
			}
		}
	}

	public String allowLog(String key, String msg) {
		synchronized (logStateLock) {
			long now = System.currentTimeMillis();
			long windowMs = config != null ? Math.max(250L, config.logWindowMs) : 60_000L;
			LogState state = logStates.get(key);
			if (state == null) {
				trimLogStates(now);
				state = new LogState();
				logStates.put(key, state);
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
			if (!trimThrottleStates(System.currentTimeMillis())) {
				return null;
			}
			ThrottleState created = new ThrottleState();
			created.windowStartMs = System.currentTimeMillis();
			ThrottleState existing = throttleStates.putIfAbsent(key, created);
			state = existing == null ? created : existing;
		}
		return state;
	}

	private void trimLogStates(long now) {
		if (logStates.size() < MAX_TRACKED_KEYS) {
			return;
		}
		long expiry = config != null ? Math.max(250L, config.logWindowMs) : 60_000L;
		for (java.util.Map.Entry<String, LogState> entry : logStates.entrySet()) {
			if (now - entry.getValue().lastLogMs >= expiry) {
				logStates.remove(entry.getKey(), entry.getValue());
			}
		}
		removeOneIfFull(logStates);
	}

	private boolean trimThrottleStates(long now) {
		if (throttleStates.size() < MAX_TRACKED_KEYS) {
			return true;
		}
		for (java.util.Map.Entry<String, ThrottleState> entry : throttleStates.entrySet()) {
			ThrottleState state = entry.getValue();
			if (state.bannedUntilMs <= now && state.throttledUntilMs <= now
					&& now - state.windowStartMs > config.windowMs) {
				throttleStates.remove(entry.getKey(), state);
			}
		}
		if (throttleStates.size() < MAX_TRACKED_KEYS) {
			return true;
		}
		for (java.util.Map.Entry<String, ThrottleState> entry : throttleStates.entrySet()) {
			ThrottleState state = entry.getValue();
			if (state.bannedUntilMs <= now && state.throttledUntilMs <= now
					&& throttleStates.remove(entry.getKey(), state)) {
				return true;
			}
		}
		return false;
	}

	private static <T> void removeOneIfFull(ConcurrentHashMap<String, T> states) {
		if (states.size() >= MAX_TRACKED_KEYS) {
			java.util.Iterator<String> iterator = states.keySet().iterator();
			if (iterator.hasNext()) {
				states.remove(iterator.next());
			}
		}
	}
}
