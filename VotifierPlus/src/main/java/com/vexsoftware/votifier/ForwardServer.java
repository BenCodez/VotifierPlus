package com.vexsoftware.votifier;

import java.security.Key;

import com.vexsoftware.votifier.net.ForwardRetryConfig;

import lombok.Getter;
import lombok.Setter;

public class ForwardServer {
	@Getter
	private String host;
	@Getter
	private int port;
	@Getter
	private String key;
	@Getter
	private boolean enabled;

	@Getter
	@Setter
	private Key Token;
	@Getter
	private final ForwardRetryConfig retryConfig;

	public ForwardServer(boolean enabled, String host, int port, String key, Key token) {
		this(enabled, host, port, key, token, null);
	}

	public ForwardServer(boolean enabled, String host, int port, String key, Key token, ForwardRetryConfig retryConfig) {
		this.enabled = enabled;
		this.host = host;
		this.port = port;
		this.key = key;
		this.Token = token;
		this.retryConfig = retryConfig;
	}

	public boolean isUseTokens() {
		return Token != null;
	}
}
