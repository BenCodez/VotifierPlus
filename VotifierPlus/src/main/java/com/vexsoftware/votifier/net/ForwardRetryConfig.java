package com.vexsoftware.votifier.net;

/** Settings for the receiver-owned, in-memory forwarding retry queue. */
public record ForwardRetryConfig(int retryIntervalSeconds, int maxRetries, boolean requirePreviousSuccessBeforeRetry) {
	private static final int DEFAULT_INTERVAL_SECONDS = 300;
	private static final int DEFAULT_MAX_RETRIES = 12;
	private static final int MAX_SETTING = 3600;

	public static final ForwardRetryConfig DEFAULT = new ForwardRetryConfig(DEFAULT_INTERVAL_SECONDS, DEFAULT_MAX_RETRIES, true);

	public ForwardRetryConfig {
		retryIntervalSeconds = validate(retryIntervalSeconds, 1, DEFAULT_INTERVAL_SECONDS);
		maxRetries = validate(maxRetries, 0, DEFAULT_MAX_RETRIES);
	}

	public static ForwardRetryConfig parse(Object interval, Object count, Object requireSuccess) {
		return DEFAULT.withOverrides(interval, count, requireSuccess);
	}

	public ForwardRetryConfig withOverrides(Object interval, Object count, Object requireSuccess) {
		return new ForwardRetryConfig(
				validate(parseInt(interval, retryIntervalSeconds), 1, retryIntervalSeconds),
				validate(parseInt(count, maxRetries), 0, maxRetries),
				parseBoolean(requireSuccess, requirePreviousSuccessBeforeRetry));
	}

	private static boolean parseBoolean(Object value, boolean fallback) {
		if (value instanceof Boolean option) {
			return option;
		}
		if (value instanceof String text) {
			return switch (text.trim().toLowerCase(java.util.Locale.ROOT)) {
				case "true" -> true;
				case "false" -> false;
				default -> fallback;
			};
		}
		return fallback;
	}

	private static int validate(int value, int minimum, int fallback) {
		return value >= minimum && value <= MAX_SETTING ? value : fallback;
	}

	private static int parseInt(Object value, int fallback) {
		if (value instanceof Number || value instanceof String) {
			try {
				return Integer.parseInt(value.toString().trim());
			} catch (NumberFormatException ignored) {
				return fallback;
			}
		}
		return fallback;
	}
}
